//! Workspace operativi (WS-01).
//!
//! # Che cosa questo modulo non scrive mai
//!
//! Il testo del materiale referenziato. La tabella `workspace_items` non ha una
//! colonna in cui possa stare, e [`lisi_core::model::reference::ArchiveRef`]
//! è `Copy`, quindi non può portarlo. Qui non c'è nulla da ricordarsi.
//!
//! # Un riferimento appeso si dichiara
//!
//! Il riferimento è polimorfico e non ha una chiave esterna: ciò a cui punta
//! può essere stato cancellato. Leggere gli elementi di un workspace restituisce
//! quindi, per ciascuno, **o l'etichetta risolta o la dichiarazione che non è
//! più nell'archivio**. Mai una riga che sparisce senza che nulla lo dica.

use core::str::FromStr;

use lisi_core::model::workspace::{
    ArchiveRef, ArchiveRefKind, NewWorkspace, Workspace, WorkspaceClosure, WorkspaceEntry,
    WorkspaceState,
};
use lisi_core::text::{Actor, DisplayName, Note};
use lisi_core::{ContentId, Timestamp, WorkspaceId};
use rusqlite::{OptionalExtension, Row};

use crate::database::Database;
use crate::error::{StorageError, StorageResult};
use crate::repository::{instant, millis};

/// Riga grezza della tabella `workspaces`.
struct WorkspaceRow {
    id: i64,
    name: String,
    description: Option<String>,
    state: String,
    created_by: String,
    created_at: i64,
    closed_by: Option<String>,
    closed_at: Option<i64>,
}

impl WorkspaceRow {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            name: row.get(1)?,
            description: row.get(2)?,
            state: row.get(3)?,
            created_by: row.get(4)?,
            created_at: row.get(5)?,
            closed_by: row.get(6)?,
            closed_at: row.get(7)?,
        })
    }

    fn into_domain(self) -> StorageResult<Workspace> {
        let description = match self.description {
            Some(ref raw) => Some(Note::try_new(raw)?),
            None => None,
        };

        // CHI HA CHIUSO E QUANDO STANNO INSIEME.
        //
        // L'archivio lo impone con un vincolo; qui si legge, e una riga che
        // portasse solo uno dei due sarebbe un ciclo di vita a meta'. Non si
        // indovina l'altro.
        let closure = match (self.closed_by, self.closed_at) {
            (None, None) => None,
            (Some(ref chi), Some(quando)) => Some(WorkspaceClosure {
                by: Actor::try_new(chi)?,
                at: instant(quando),
            }),
            _ => {
                return Err(StorageError::CorruptedRow {
                    detail: "un workspace porta una chiusura scritta a met\u{e0}: o entrambi i \
                             valori sono assenti, o entrambi sono presenti",
                });
            }
        };

        Ok(Workspace {
            id: WorkspaceId::new(self.id),
            name: DisplayName::try_new(&self.name)?,
            description,
            state: WorkspaceState::from_str(&self.state)?,
            created_by: Actor::try_new(&self.created_by)?,
            created_at: instant(self.created_at),
            closure,
        })
    }
}

/// Riesportati: da NOTE-01 la risoluzione di un riferimento vive in
/// [`crate::repository::reference`], perche' serve a tre cose — workspace,
/// segnalibri, note — e la frase che dichiarava un riferimento appeso nominava
/// il workspace anche sotto un segnalibro.
///
/// Restano nominabili da qui perche' nessun chiamante debba cambiare.
pub use crate::repository::reference::ResolvedTarget;

/// Un elemento di workspace, con ciò che il suo riferimento raggiunge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEntry {
    /// Il riferimento, con chi lo ha aggiunto e quando.
    pub entry: WorkspaceEntry,
    /// Che cosa raggiunge.
    pub target: ResolvedTarget,
}

impl Database {
    /// Apre un workspace.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se esiste già un workspace **aperto** con lo stesso
    /// nome, o se la scrittura non riesce.
    pub fn insert_workspace(
        &self,
        workspace: &NewWorkspace,
        created_at: Timestamp,
    ) -> StorageResult<WorkspaceId> {
        self.connection.execute(
            "INSERT INTO workspaces (name, description, state, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                workspace.name.as_str(),
                workspace.description.as_ref().map(Note::as_str),
                WorkspaceState::Open.as_str(),
                workspace.created_by.as_str(),
                millis(created_at),
            ],
        )?;
        Ok(WorkspaceId::new(self.connection.last_insert_rowid()))
    }

    /// Chiude un workspace.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il workspace non esiste o se la scrittura non
    /// riesce. Riaprirne uno chiuso è rifiutato dall'archivio con un trigger.
    pub fn close_workspace(
        &self,
        id: WorkspaceId,
        closed_by: &Actor,
        closed_at: Timestamp,
    ) -> StorageResult<()> {
        let toccate = self.connection.execute(
            "UPDATE workspaces
                SET state = ?2, closed_by = ?3, closed_at = ?4
              WHERE id = ?1 AND state = ?5",
            rusqlite::params![
                id.get(),
                WorkspaceState::Closed.as_str(),
                closed_by.as_str(),
                millis(closed_at),
                WorkspaceState::Open.as_str(),
            ],
        )?;

        if toccate == 0 {
            // O non esiste, o era gia' chiuso. In entrambi i casi non c'e' nulla
            // da chiudere, e dirlo e' meglio che restituire un successo che non
            // corrisponde a nulla.
            return Err(StorageError::NotFound {
                entity: "workspace da chiudere",
                id: id.get(),
            });
        }
        Ok(())
    }

    /// I workspace, dal più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn workspaces(&self) -> StorageResult<Vec<Workspace>> {
        let mut statement = self.connection.prepare(
            "SELECT id, name, description, state, created_by, created_at, closed_by, closed_at
             FROM workspaces
             ORDER BY created_at DESC, id DESC",
        )?;
        let righe: Vec<WorkspaceRow> = statement
            .query_map([], WorkspaceRow::read)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        righe.into_iter().map(WorkspaceRow::into_domain).collect()
    }

    /// Un workspace.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se non esiste.
    pub fn workspace(&self, id: WorkspaceId) -> StorageResult<Workspace> {
        let riga = self
            .connection
            .query_row(
                "SELECT id, name, description, state, created_by, created_at, closed_by, closed_at
                 FROM workspaces WHERE id = ?1",
                [id.get()],
                WorkspaceRow::read,
            )
            .optional()?;
        match riga {
            Some(riga) => riga.into_domain(),
            None => Err(StorageError::NotFound {
                entity: "workspace",
                id: id.get(),
            }),
        }
    }

    /// Aggiunge un riferimento a un workspace.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il workspace è **chiuso** — lo rifiuta un
    /// trigger dell'archivio — o se il riferimento c'è già.
    pub fn add_workspace_item(
        &self,
        workspace_id: WorkspaceId,
        item: ArchiveRef,
        added_by: &Actor,
        added_at: Timestamp,
    ) -> StorageResult<()> {
        self.connection.execute(
            "INSERT INTO workspace_items (workspace_id, kind, target_id, added_by, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                workspace_id.get(),
                item.kind().as_str(),
                item.target_id(),
                added_by.as_str(),
                millis(added_at),
            ],
        )?;
        Ok(())
    }

    /// Se un riferimento è già in un workspace.
    ///
    /// Serve a dire all'operatore «c'è già» prima di provare a scriverlo: il
    /// vincolo d'unicità della tabella resta la protezione vera, ma il suo
    /// rifiuto arriva come errore dell'archivio, e un errore dell'archivio si
    /// legge «problema tecnico» (UX-EXCELLENCE-02, SIM3-02).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn has_workspace_item(
        &self,
        workspace_id: WorkspaceId,
        item: ArchiveRef,
    ) -> StorageResult<bool> {
        let presente: i64 = self.connection.query_row(
            "SELECT EXISTS (SELECT 1 FROM workspace_items
                             WHERE workspace_id = ?1 AND kind = ?2 AND target_id = ?3)",
            rusqlite::params![workspace_id.get(), item.kind().as_str(), item.target_id()],
            |row| row.get(0),
        )?;
        Ok(presente != 0)
    }

    /// Toglie un riferimento da un workspace.
    ///
    /// # Che cosa NON tocca
    ///
    /// La cosa referenziata. Togliere un contenuto da un workspace **non**
    /// cancella il contenuto: l'istruzione insiste su `workspace_items` e su
    /// null'altro, e una prova lo verifica leggendo il sorgente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il workspace è **chiuso** — lo rifiuta un
    /// trigger — e [`StorageError::NotFound`] se il riferimento non c'era.
    pub fn remove_workspace_item(
        &self,
        workspace_id: WorkspaceId,
        item: ArchiveRef,
    ) -> StorageResult<()> {
        let toccate = self.connection.execute(
            "DELETE FROM workspace_items
              WHERE workspace_id = ?1 AND kind = ?2 AND target_id = ?3",
            rusqlite::params![workspace_id.get(), item.kind().as_str(), item.target_id()],
        )?;
        if toccate == 0 {
            return Err(StorageError::NotFound {
                entity: "riferimento da togliere dal workspace",
                id: item.target_id(),
            });
        }
        Ok(())
    }

    /// Gli elementi di un workspace, **con ciò che i riferimenti raggiungono**.
    ///
    /// Ogni riferimento porta o l'etichetta con cui la cosa si riconosce adesso,
    /// o la dichiarazione che non è più nell'archivio. Mai il silenzio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn workspace_items(&self, workspace_id: WorkspaceId) -> StorageResult<Vec<ResolvedEntry>> {
        let mut statement = self.connection.prepare(
            "SELECT kind, target_id, added_by, added_at
             FROM workspace_items
             WHERE workspace_id = ?1
             ORDER BY added_at ASC, kind ASC, target_id ASC",
        )?;
        let grezze: Vec<(String, i64, String, i64)> = statement
            .query_map([workspace_id.get()], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut elementi = Vec::with_capacity(grezze.len());
        for (genere, identificativo, chi, quando) in grezze {
            let kind = ArchiveRefKind::from_str(&genere)?;
            let item = ArchiveRef::to(kind, identificativo)?;
            let target = self.resolve_reference(kind, identificativo)?;
            elementi.push(ResolvedEntry {
                entry: WorkspaceEntry {
                    item,
                    added_by: Actor::try_new(&chi)?,
                    added_at: instant(quando),
                },
                target,
            });
        }
        Ok(elementi)
    }

    /// Quali workspace raccolgono un certo contenuto (PERS-03).
    ///
    /// # Perché una lettura all'indietro, e perché solo i contenuti
    ///
    /// Perché le associazioni di una persona partono dal fatto «ha scritto
    /// questo contenuto», e da lì guardano che cosa quel contenuto tocca. La
    /// domanda è quindi «chi raccoglie *questo*», non «che cosa raccoglie
    /// quello»: è l'unico verso in cui l'indice serve.
    ///
    /// Si limita ai contenuti perché è l'unico genere che una persona può aver
    /// **scritto**. Una fonte o un rapporto non hanno un autore osservato, e
    /// aggiungerli qui sarebbe una capacità che nulla raggiunge — il debito che
    /// questo progetto ha già pagato una volta con LAB-01.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'archivio non è leggibile.
    pub fn workspaces_holding_content(
        &self,
        content_id: ContentId,
    ) -> StorageResult<Vec<WorkspaceId>> {
        let mut statement = self.connection.prepare(
            "SELECT workspace_id
             FROM workspace_items
             WHERE kind = 'contenuto' AND target_id = ?1
             ORDER BY workspace_id ASC",
        )?;
        // ORDINE ESPLICITO, perche' una lettura senza ORDER BY puo' cambiare
        // ordine fra due esecuzioni, e due letture darebbero due elenchi.
        let identificativi: Vec<WorkspaceId> = statement
            .query_map([content_id.get()], |row| row.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(WorkspaceId::new)
            .collect();
        Ok(identificativi)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::workspace::{ArchiveRef, ArchiveRefKind, NewWorkspace, WorkspaceState};
    use lisi_core::text::{DisplayName, Note};
    use lisi_core::{Timestamp, WorkspaceId};

    use super::ResolvedTarget;
    use crate::test_support::{actor, database_with_session, new_content};

    const ORA: i64 = 1_700_000_000_000;

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    fn nome(testo: &str) -> DisplayName {
        let Ok(nome) = DisplayName::try_new(testo) else {
            panic!("il nome di prova deve essere valido");
        };
        nome
    }

    fn riferimento(kind: ArchiveRefKind, id: i64) -> ArchiveRef {
        let Ok(item) = ArchiveRef::to(kind, id) else {
            panic!("il riferimento di prova deve essere valido");
        };
        item
    }

    fn nuovo(nome_testo: &str, descrizione: Option<&str>) -> NewWorkspace {
        let descrizione = descrizione.map(|testo| {
            let Ok(nota) = Note::try_new(testo) else {
                panic!("la descrizione di prova deve essere valida");
            };
            nota
        });
        NewWorkspace {
            name: nome(nome_testo),
            description: descrizione,
            created_by: actor("operatore.prova"),
        }
    }

    /// **Un workspace si apre e si rilegge identico.**
    #[test]
    fn un_workspace_si_apre_e_si_rilegge() {
        let (database, _, _) = database_with_session();
        let Ok(id) =
            database.insert_workspace(&nuovo("Indagine di marzo", Some("le fonti")), istante(ORA))
        else {
            panic!("il workspace deve potersi aprire");
        };

        let Ok(riletto) = database.workspace(id) else {
            panic!("il workspace deve potersi rileggere");
        };
        assert_eq!(riletto.name.as_str(), "Indagine di marzo");
        assert_eq!(
            riletto.description.as_ref().map(Note::as_str),
            Some("le fonti")
        );
        assert_eq!(riletto.state, WorkspaceState::Open);
        assert_eq!(riletto.created_by.as_str(), "operatore.prova");
        assert_eq!(riletto.created_at.as_millis(), ORA);
        assert!(riletto.closure.is_none());
        assert!(riletto.accepts_items());
    }

    /// **Due workspace aperti non possono chiamarsi allo stesso modo.**
    ///
    /// Chi lavora li chiama per nome, e due contenitori aperti con lo stesso
    /// nome sono una trappola: si mette una cosa nell'uno credendo di metterla
    /// nell'altro.
    #[test]
    fn due_workspace_aperti_non_hanno_lo_stesso_nome() {
        let (database, _, _) = database_with_session();
        let Ok(_) = database.insert_workspace(&nuovo("Indagine", None), istante(ORA)) else {
            panic!("il primo deve potersi aprire");
        };
        assert!(
            database
                .insert_workspace(&nuovo("Indagine", None), istante(ORA + 1))
                .is_err(),
            "il secondo con lo stesso nome deve essere rifiutato"
        );
    }

    /// **Un nome torna libero dopo la chiusura.**
    ///
    /// «Indagine marzo» chiusa non impedisce «Indagine marzo» dell'anno dopo.
    #[test]
    fn un_nome_torna_libero_dopo_la_chiusura() {
        let (database, _, _) = database_with_session();
        let Ok(primo) = database.insert_workspace(&nuovo("Indagine", None), istante(ORA)) else {
            panic!("il primo deve potersi aprire");
        };
        let Ok(()) = database.close_workspace(primo, &actor("operatore.prova"), istante(ORA + 100))
        else {
            panic!("il primo deve potersi chiudere");
        };
        assert!(
            database
                .insert_workspace(&nuovo("Indagine", None), istante(ORA + 200))
                .is_ok(),
            "chiuso il primo, il nome torna disponibile"
        );
    }

    /// **Chiudere registra chi e quando, e li tiene insieme.**
    #[test]
    fn chiudere_registra_chi_e_quando() {
        let (database, _, _) = database_with_session();
        let Ok(id) = database.insert_workspace(&nuovo("Indagine", None), istante(ORA)) else {
            panic!("il workspace deve potersi aprire");
        };
        let Ok(()) =
            database.close_workspace(id, &actor("responsabile.ufficio"), istante(ORA + 500))
        else {
            panic!("il workspace deve potersi chiudere");
        };

        let Ok(riletto) = database.workspace(id) else {
            panic!("il workspace deve potersi rileggere");
        };
        assert_eq!(riletto.state, WorkspaceState::Closed);
        let Some(chiusura) = riletto.closure.as_ref() else {
            panic!("un workspace chiuso deve portare la sua chiusura");
        };
        assert_eq!(chiusura.by.as_str(), "responsabile.ufficio");
        assert_eq!(chiusura.at.as_millis(), ORA + 500);
        assert!(!riletto.accepts_items());
    }

    /// **Un workspace chiuso non si riapre: lo rifiuta l'archivio.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che la chiusura diventi una parentesi invece di un fatto, e che ciò che
    /// si è scritto «concluso il …» torni in lavorazione senza che nulla lo
    /// dica.
    #[test]
    fn un_workspace_chiuso_non_si_riapre() {
        let (database, _, _) = database_with_session();
        let Ok(id) = database.insert_workspace(&nuovo("Indagine", None), istante(ORA)) else {
            panic!("il workspace deve potersi aprire");
        };
        let Ok(()) = database.close_workspace(id, &actor("operatore.prova"), istante(ORA + 100))
        else {
            panic!("il workspace deve potersi chiudere");
        };

        // LA RIAPERTURA VA TENTATA NELLA FORMA CHE IL RESTO DELLO SCHEMA
        // AMMETTEREBBE.
        //
        // Un `UPDATE` che lasciasse `closed_by` e `closed_at` valorizzati
        // sarebbe respinto dal vincolo CHECK, e la prova passerebbe PER LA
        // RAGIONE SBAGLIATA: un controllo negativo lo ha dimostrato togliendo
        // il trigger e trovandola ancora verde.
        //
        // Chi riaprisse davvero un workspace svuoterebbe anche quei due campi,
        // ed e' quella la forma che solo il trigger puo' fermare.
        let riapertura = database.connection.execute(
            "UPDATE workspaces SET state = 'aperto', closed_by = NULL, closed_at = NULL \
             WHERE id = ?1",
            [id.get()],
        );
        assert!(
            riapertura.is_err(),
            "l'archivio deve rifiutare la riapertura"
        );

        // E chiuderlo di nuovo non riesce, perche' non e' aperto.
        assert!(
            database
                .close_workspace(id, &actor("operatore.prova"), istante(ORA + 200))
                .is_err()
        );
    }

    /// **Un workspace chiuso non accetta né perde elementi.**
    ///
    /// Uno stato del ciclo di vita che non impedisce nulla è una decorazione, e
    /// il rifiuto è dell'archivio, non di un servizio che deve ricordarsene.
    #[test]
    fn un_workspace_chiuso_non_accetta_ne_perde_elementi() {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(inserimento) =
            database.insert_content(&new_content(session_id, source_id, "500", "testo"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let Ok(id) = database.insert_workspace(&nuovo("Indagine", None), istante(ORA)) else {
            panic!("il workspace deve potersi aprire");
        };

        let contenuto = riferimento(ArchiveRefKind::Content, inserimento.content_id().get());
        let Ok(()) = database.add_workspace_item(
            id,
            contenuto,
            &actor("operatore.prova"),
            istante(ORA + 10),
        ) else {
            panic!("aperto, il workspace deve accettare");
        };

        let Ok(()) = database.close_workspace(id, &actor("operatore.prova"), istante(ORA + 100))
        else {
            panic!("il workspace deve potersi chiudere");
        };

        let fonte = riferimento(ArchiveRefKind::Source, source_id.get());
        assert!(
            database
                .add_workspace_item(id, fonte, &actor("operatore.prova"), istante(ORA + 200))
                .is_err(),
            "un workspace chiuso non accetta nuovi elementi"
        );
        assert!(
            database.remove_workspace_item(id, contenuto).is_err(),
            "un workspace chiuso non perde elementi"
        );
    }

    /// **La stessa cosa non si raccoglie due volte.**
    #[test]
    fn la_stessa_cosa_non_si_raccoglie_due_volte() {
        let (database, source_id, _) = database_with_session();
        let Ok(id) = database.insert_workspace(&nuovo("Indagine", None), istante(ORA)) else {
            panic!("il workspace deve potersi aprire");
        };
        let fonte = riferimento(ArchiveRefKind::Source, source_id.get());
        let Ok(()) =
            database.add_workspace_item(id, fonte, &actor("operatore.prova"), istante(ORA))
        else {
            panic!("la prima aggiunta deve riuscire");
        };
        assert!(
            database
                .add_workspace_item(id, fonte, &actor("operatore.prova"), istante(ORA + 1))
                .is_err(),
            "due righe identiche non direbbero nulla di piu'"
        );
    }

    /// **Un riferimento porta l'etichetta con cui la cosa si riconosce adesso.**
    #[test]
    fn un_riferimento_porta_l_etichetta_di_adesso() {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(inserimento) =
            database.insert_content(&new_content(session_id, source_id, "777", "testo"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let Ok(id) = database.insert_workspace(&nuovo("Indagine", None), istante(ORA)) else {
            panic!("il workspace deve potersi aprire");
        };

        let Ok(()) = database.add_workspace_item(
            id,
            riferimento(ArchiveRefKind::Source, source_id.get()),
            &actor("operatore.prova"),
            istante(ORA + 10),
        ) else {
            panic!("la fonte deve potersi aggiungere");
        };
        let Ok(()) = database.add_workspace_item(
            id,
            riferimento(ArchiveRefKind::Content, inserimento.content_id().get()),
            &actor("operatore.prova"),
            istante(ORA + 20),
        ) else {
            panic!("il contenuto deve potersi aggiungere");
        };

        let Ok(elementi) = database.workspace_items(id) else {
            panic!("gli elementi devono potersi leggere");
        };
        assert_eq!(elementi.len(), 2);
        // L'ordine e' quello in cui sono stati raccolti.
        assert_eq!(elementi[0].entry.item.kind(), ArchiveRefKind::Source);
        assert_eq!(elementi[1].entry.item.kind(), ArchiveRefKind::Content);
        assert_eq!(elementi[0].entry.added_by.as_str(), "operatore.prova");
        assert_eq!(elementi[0].entry.added_at.as_millis(), ORA + 10);

        let ResolvedTarget::Present { label } = &elementi[1].target else {
            panic!("il contenuto esiste, e deve risolversi");
        };
        // Con il testo e la fonte, non più il solo numero (OS-02).
        assert!(label.ends_with(", messaggio 777"), "{label}");
        assert!(label.len() > "messaggio 777".len() + 2, "{label}");
    }

    /// **Un riferimento che non arriva più a nulla lo dichiara.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che la riga sparisca. Un elenco che lasciasse cadere il riferimento
    /// direbbe che quella cosa non è mai stata raccolta, e chi lo rilegge non
    /// avrebbe modo di accorgersene.
    #[test]
    fn un_riferimento_appeso_si_dichiara() {
        let (database, _, _) = database_with_session();
        let Ok(id) = database.insert_workspace(&nuovo("Indagine", None), istante(ORA)) else {
            panic!("il workspace deve potersi aprire");
        };
        // Un contenuto che non esiste: il riferimento e' polimorfico e non ha
        // una chiave esterna, quindi si scrive.
        let Ok(()) = database.add_workspace_item(
            id,
            riferimento(ArchiveRefKind::Content, 999_999),
            &actor("operatore.prova"),
            istante(ORA + 10),
        ) else {
            panic!("il riferimento deve potersi scrivere");
        };

        let Ok(elementi) = database.workspace_items(id) else {
            panic!("gli elementi devono potersi leggere");
        };
        assert_eq!(elementi.len(), 1, "la riga NON sparisce");
        assert_eq!(elementi[0].target, ResolvedTarget::NoLongerInArchive);

        let frase = elementi[0].target.as_sentence(ArchiveRefKind::Content);
        assert!(
            frase.contains("non \u{e8} pi\u{f9} nell'archivio"),
            "{frase}"
        );
        assert!(frase.contains("Il riferimento resta"), "{frase}");
    }

    /// **Togliere un riferimento non tocca la cosa referenziata.**
    #[test]
    fn togliere_un_riferimento_non_cancella_nulla() {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(inserimento) =
            database.insert_content(&new_content(session_id, source_id, "500", "testo"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = inserimento.content_id();
        let Ok(id) = database.insert_workspace(&nuovo("Indagine", None), istante(ORA)) else {
            panic!("il workspace deve potersi aprire");
        };
        let contenuto = riferimento(ArchiveRefKind::Content, content_id.get());
        let Ok(()) =
            database.add_workspace_item(id, contenuto, &actor("operatore.prova"), istante(ORA))
        else {
            panic!("l'aggiunta deve riuscire");
        };

        let Ok(()) = database.remove_workspace_item(id, contenuto) else {
            panic!("la rimozione deve riuscire");
        };

        let Ok(elementi) = database.workspace_items(id) else {
            panic!("gli elementi devono potersi leggere");
        };
        assert!(elementi.is_empty());

        // E IL CONTENUTO C'E' ANCORA.
        assert!(
            database.content(content_id).is_ok(),
            "togliere da un workspace non cancella la prova"
        );
    }

    /// **Togliere ciò che non c'era lo dice.**
    #[test]
    fn togliere_cio_che_non_c_era_lo_dice() {
        let (database, source_id, _) = database_with_session();
        let Ok(id) = database.insert_workspace(&nuovo("Indagine", None), istante(ORA)) else {
            panic!("il workspace deve potersi aprire");
        };
        assert!(
            database
                .remove_workspace_item(id, riferimento(ArchiveRefKind::Source, source_id.get()))
                .is_err()
        );
    }

    /// **Un workspace che non esiste non si legge in silenzio.**
    #[test]
    fn un_workspace_inesistente_non_si_legge() {
        let (database, _, _) = database_with_session();
        assert!(database.workspace(WorkspaceId::new(999_999)).is_err());
    }

    /// **L'elenco dei workspace parte dal più recente.**
    #[test]
    fn l_elenco_parte_dal_piu_recente() {
        let (database, _, _) = database_with_session();
        let Ok(_) = database.insert_workspace(&nuovo("Primo", None), istante(ORA)) else {
            panic!("il primo deve potersi aprire");
        };
        let Ok(_) = database.insert_workspace(&nuovo("Secondo", None), istante(ORA + 1_000)) else {
            panic!("il secondo deve potersi aprire");
        };

        let Ok(elenco) = database.workspaces() else {
            panic!("l'elenco deve potersi leggere");
        };
        assert_eq!(elenco.len(), 2);
        assert_eq!(elenco[0].name.as_str(), "Secondo");
        assert_eq!(elenco[1].name.as_str(), "Primo");
    }

    /// **La tabella dei riferimenti non ha alcuna colonna di testo.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che qualcuno aggiunga un `body`, un `titolo` o un'anteprima «per non
    /// dover rileggere». Da quel momento il workspace avrebbe una seconda copia
    /// del materiale, e una seconda copia diverge: il congelamento lo vieta con
    /// tre parole, «riferisce senza copiare».
    #[test]
    fn la_tabella_dei_riferimenti_non_ha_colonne_di_testo() {
        const MIGRAZIONE: &str = include_str!("../../migrations/0026_workspaces.sql");

        let Some(inizio) = MIGRAZIONE.find("CREATE TABLE workspace_items (") else {
            panic!("la tabella deve esistere");
        };
        let Some(fine) = MIGRAZIONE[inizio..].find("\n);") else {
            panic!("la tabella deve chiudersi");
        };
        let corpo = &MIGRAZIONE[inizio..inizio + fine];

        for copia in [
            "body",
            "testo",
            "text",
            "titolo",
            "title",
            "anteprima",
            "preview",
            "snippet",
            "contenuto TEXT",
            "label TEXT",
        ] {
            assert!(
                !corpo.contains(copia),
                "la tabella dei riferimenti dichiara «{copia}»: sarebbe una copia della prova, e \
                 una seconda copia diverge"
            );
        }

        // Le sole colonne di testo ammesse sono il GENERE e CHI ha aggiunto:
        // nessuna delle due e' materiale referenziato.
        let colonne_di_testo: Vec<&str> = corpo
            .lines()
            .map(str::trim)
            .filter(|riga| riga.contains(" TEXT"))
            .collect();
        assert_eq!(
            colonne_di_testo.len(),
            2,
            "le colonne di testo devono essere due, il genere e chi ha aggiunto \u{2014} \
             {colonne_di_testo:?}"
        );
    }

    /// **La lettura all'indietro trova chi raccoglie un contenuto (PERS-03).**
    ///
    /// # Perché anche il caso vuoto
    ///
    /// Perché è quello **ordinario**: la stragrande maggioranza dei contenuti
    /// non sta in nessun workspace, e una lettura che restituisse una riga
    /// inventata invece di un elenco vuoto produrrebbe un'associazione che
    /// nessun fatto sostiene.
    #[test]
    fn si_legge_quali_workspace_raccolgono_un_contenuto() {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(inserimento) =
            database.insert_content(&new_content(session_id, source_id, "700", "testo"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = inserimento.content_id();

        // NESSUN WORKSPACE: e' il caso ordinario, e si legge come elenco vuoto.
        let Ok(nessuno) = database.workspaces_holding_content(content_id) else {
            panic!("la lettura deve riuscire anche senza workspace");
        };
        assert!(
            nessuno.is_empty(),
            "un contenuto che nessuno raccoglie non ha workspace"
        );

        let Ok(primo) = database.insert_workspace(&nuovo("Indagine", None), istante(ORA)) else {
            panic!("il workspace deve potersi aprire");
        };
        let Ok(secondo) = database.insert_workspace(&nuovo("Verifica", None), istante(ORA + 1))
        else {
            panic!("il secondo workspace deve potersi aprire");
        };
        let contenuto = riferimento(ArchiveRefKind::Content, content_id.get());
        for (workspace, quando) in [(primo, ORA + 10), (secondo, ORA + 20)] {
            let Ok(()) = database.add_workspace_item(
                workspace,
                contenuto,
                &actor("operatore.prova"),
                istante(quando),
            ) else {
                panic!("il riferimento deve potersi scrivere");
            };
        }

        let Ok(trovati) = database.workspaces_holding_content(content_id) else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(trovati, vec![primo, secondo], "entrambi, in ordine stabile");

        // UNA FONTE CON LO STESSO NUMERO NON SI CONFONDE CON UN CONTENUTO.
        //
        // Il riferimento e' polimorfico: senza il filtro sul genere, un
        // workspace che raccoglie la fonte #N comparirebbe fra quelli che
        // raccolgono il contenuto #N, che e' un'altra cosa.
        let Ok(()) = database.add_workspace_item(
            primo,
            riferimento(ArchiveRefKind::Source, content_id.get()),
            &actor("operatore.prova"),
            istante(ORA + 30),
        ) else {
            panic!("il riferimento alla fonte deve potersi scrivere");
        };
        let Ok(ancora) = database.workspaces_holding_content(content_id) else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(
            ancora,
            vec![primo, secondo],
            "una fonte con lo stesso numero non e' quel contenuto"
        );
    }
}

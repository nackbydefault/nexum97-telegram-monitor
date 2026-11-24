//! Aprire, riempire e chiudere un workspace operativo (WS-01).
//!
//! # Che cosa questo servizio garantisce, e che cosa garantisce l'archivio
//!
//! Le regole che **non si possono dimenticare** stanno nell'archivio, non qui:
//! un workspace chiuso non accetta né perde elementi, non si riapre, e due
//! aperti non hanno lo stesso nome. Sono trigger e vincoli, e valgono anche per
//! chi scrivesse un secondo servizio domani.
//!
//! Qui sta ciò che un archivio non può fare: **tradurre il rifiuto in una frase
//! che dice perché**, e registrare nell'audit chi ha fatto che cosa.
//!
//! # Riferisce senza copiare
//!
//! Questo servizio non ha alcun modo di conservare il testo del materiale
//! raccolto: [`lisi_core::model::reference::ArchiveRef`] è `Copy`, e la
//! tabella non ha una colonna in cui una copia possa stare. Non è una
//! disciplina di questo modulo — è una proprietà dei tipi che usa.

use lisi_core::model::audit::NewAuditEntry;
use lisi_core::model::workspace::{ArchiveRef, NewWorkspace, Workspace};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{Timestamp, WorkspaceId};
use lisi_storage::Database;
/// Riesportati perche' l'interfaccia dipenda SOLTANTO dai servizi (ADR-0010):
/// una schermata che nominasse `lisi_storage` avrebbe attraversato il confine
/// che quel documento tiene chiuso, e il compilatore lo rifiuta.
pub use lisi_storage::repository::workspace::{ResolvedEntry, ResolvedTarget};

use crate::error::{ServiceError, ServiceResult};

/// Servizio dei workspace operativi.
#[derive(Debug)]
pub struct WorkspaceService {
    database: Database,
}

impl WorkspaceService {
    /// Costruisce il servizio sull'archivio indicato.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// L'archivio, in sola lettura.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Restituisce l'archivio al chiamante.
    #[must_use]
    pub fn into_database(self) -> Database {
        self.database
    }

    /// Apre un workspace.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::WorkspaceNameTaken`] se un workspace
    /// **aperto** ha già quel nome, e un errore di archivio se la scrittura non
    /// riesce.
    pub fn open(&self, workspace: &NewWorkspace, now: Timestamp) -> ServiceResult<WorkspaceId> {
        // IL NOME DUPLICATO LO RIFIUTA L'ARCHIVIO, con un indice unico parziale.
        //
        // Qui non si ricontrolla prima di scrivere: fra il controllo e la
        // scrittura ci sarebbe una fessura, e due processi potrebbero passarci
        // entrambi. Si scrive, e si traduce il rifiuto.
        let id = self
            .database
            .insert_workspace(workspace, now)
            .map_err(|errore| Self::nome_gia_preso(errore, workspace))?;

        self.database.append_audit(&NewAuditEntry {
            actor: workspace.created_by.clone(),
            action: AuditAction::try_new("workspace_aperto")?,
            entity: AuditEntity::try_new("workspace")?,
            entity_id: Some(id.get()),
            actor_mode: None,
            detail: Some(AuditDetail::try_new(workspace.name.as_str())?),
            recorded_at: now,
        })?;

        Ok(id)
    }

    /// Traduce il rifiuto dell'indice unico in una frase che dice perché.
    fn nome_gia_preso(
        errore: lisi_storage::StorageError,
        workspace: &NewWorkspace,
    ) -> ServiceError {
        if matches!(errore, lisi_storage::StorageError::Sqlite(_)) {
            return ServiceError::WorkspaceNameTaken {
                name: workspace.name.as_str().to_owned(),
            };
        }
        ServiceError::Storage(errore)
    }

    /// Chiude un workspace.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il workspace non esiste o **era già chiuso**:
    /// in entrambi i casi non c'è nulla da chiudere, e un successo direbbe che
    /// qualcosa è avvenuto.
    pub fn close(&self, id: WorkspaceId, closed_by: &Actor, now: Timestamp) -> ServiceResult<()> {
        self.database.close_workspace(id, closed_by, now)?;

        self.database.append_audit(&NewAuditEntry {
            actor: closed_by.clone(),
            action: AuditAction::try_new("workspace_chiuso")?,
            entity: AuditEntity::try_new("workspace")?,
            entity_id: Some(id.get()),
            actor_mode: None,
            detail: None,
            recorded_at: now,
        })?;

        Ok(())
    }

    /// Raccoglie un riferimento in un workspace.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::WorkspaceClosed`] se il workspace è chiuso —
    /// il rifiuto viene dall'archivio — e [`ServiceError::AlreadyInWorkspace`]
    /// se il riferimento c'è già.
    pub fn add(
        &self,
        id: WorkspaceId,
        item: ArchiveRef,
        added_by: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        // SE E' CHIUSO LO DICE PRIMA, per poterlo dire con parole utili.
        //
        // Il rifiuto vero resta dell'archivio: questa lettura serve alla frase,
        // non alla protezione, e se le due divergessero vincerebbe il trigger.
        let workspace = self.database.workspace(id)?;
        if !workspace.accepts_items() {
            return Err(ServiceError::WorkspaceClosed {
                name: workspace.name.as_str().to_owned(),
            });
        }

        // UN DOPPIONE NON E' UN GUASTO (UX-EXCELLENCE-02, SIM3-02).
        //
        // Il vincolo d'unicita' della tabella lo rifiutava comunque, ma come
        // errore dell'archivio: l'operatore leggeva «Si è verificato un problema
        // tecnico» per un'azione normale, e chi cercava il dettaglio nel registro
        // non lo trovava. Si dice prima, con il nome del raccoglitore; nulla si
        // scrive e nulla si registra nell'audit, perche' nulla e' avvenuto. Il
        // vincolo resta la protezione vera, se le due letture divergessero.
        if self.database.has_workspace_item(id, item)? {
            return Err(ServiceError::AlreadyInWorkspace {
                name: workspace.name.as_str().to_owned(),
            });
        }

        self.database.add_workspace_item(id, item, added_by, now)?;

        // L'AUDIT DICE CHE COSA E QUALE, NON CHE COSA DICEVA.
        //
        // L'audit documenta le azioni, non i dati su cui insistono — ed e' anche
        // la stessa ragione per cui la tabella non conserva il testo.
        self.database.append_audit(&NewAuditEntry {
            actor: added_by.clone(),
            action: AuditAction::try_new("workspace_elemento_aggiunto")?,
            entity: AuditEntity::try_new("workspace")?,
            entity_id: Some(id.get()),
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&format!(
                "{} {}",
                item.kind().as_str(),
                item.target_id()
            ))?),
            recorded_at: now,
        })?;

        Ok(())
    }

    /// Toglie un riferimento da un workspace.
    ///
    /// # Che cosa NON tocca
    ///
    /// La cosa referenziata. Togliere un contenuto da un workspace non cancella
    /// il contenuto.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::WorkspaceClosed`] se il workspace è chiuso, e
    /// un errore se il riferimento non c'era.
    pub fn remove(
        &self,
        id: WorkspaceId,
        item: ArchiveRef,
        removed_by: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let workspace = self.database.workspace(id)?;
        if !workspace.accepts_items() {
            return Err(ServiceError::WorkspaceClosed {
                name: workspace.name.as_str().to_owned(),
            });
        }

        self.database.remove_workspace_item(id, item)?;

        self.database.append_audit(&NewAuditEntry {
            actor: removed_by.clone(),
            action: AuditAction::try_new("workspace_elemento_tolto")?,
            entity: AuditEntity::try_new("workspace")?,
            entity_id: Some(id.get()),
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&format!(
                "{} {}",
                item.kind().as_str(),
                item.target_id()
            ))?),
            recorded_at: now,
        })?;

        Ok(())
    }

    /// I workspace, dal più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn all(&self) -> ServiceResult<Vec<Workspace>> {
        Ok(self.database.workspaces()?)
    }

    /// Un workspace e ciò che ha raccolto.
    ///
    /// Ogni riferimento porta o l'etichetta con cui la cosa si riconosce
    /// **adesso**, o la dichiarazione che non è più nell'archivio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il workspace non esiste o se la lettura non
    /// riesce.
    pub fn contents(&self, id: WorkspaceId) -> ServiceResult<(Workspace, Vec<ResolvedEntry>)> {
        let workspace = self.database.workspace(id)?;
        let elementi = self.database.workspace_items(id)?;
        Ok((workspace, elementi))
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::workspace::{ArchiveRef, ArchiveRefKind, NewWorkspace, WorkspaceState};
    use lisi_core::text::{Actor, DisplayName, Note};
    use lisi_core::{Timestamp, WorkspaceId};
    use lisi_storage::repository::workspace::ResolvedTarget;

    use super::WorkspaceService;
    use crate::error::ServiceError;

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("workspace.rs");

    const ORA: i64 = 1_700_000_000_000;

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    fn attore(nome: &str) -> Actor {
        let Ok(attore) = Actor::try_new(nome) else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn nuovo(nome: &str) -> NewWorkspace {
        let Ok(nome) = DisplayName::try_new(nome) else {
            panic!("il nome di prova deve essere valido");
        };
        NewWorkspace {
            name: nome,
            description: None,
            created_by: attore("operatore.prova"),
        }
    }

    fn riferimento(kind: ArchiveRefKind, id: i64) -> ArchiveRef {
        let Ok(item) = ArchiveRef::to(kind, id) else {
            panic!("il riferimento di prova deve essere valido");
        };
        item
    }

    fn servizio() -> WorkspaceService {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        WorkspaceService::new(database)
    }

    /// Il codice di produzione senza i commenti.
    fn codice_senza_commenti() -> String {
        let Some((produzione, prove)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        for riga in prove.lines() {
            let e_codice = ["impl ", "fn ", "struct ", "enum ", "const ", "use ", "pub "]
                .iter()
                .any(|inizio| riga.starts_with(inizio));
            assert!(
                !e_codice,
                "c'e' del codice dopo il blocco di prove, invisibile a ogni guardia: «{riga}»"
            );
        }
        produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// **Aprire, riempire, leggere.**
    #[test]
    fn un_workspace_si_apre_si_riempie_e_si_legge() {
        let servizio = servizio();
        let Ok(id) = servizio.open(&nuovo("Indagine"), istante(ORA)) else {
            panic!("il workspace deve potersi aprire");
        };

        let Ok(()) = servizio.add(
            id,
            riferimento(ArchiveRefKind::Content, 42),
            &attore("operatore.prova"),
            istante(ORA + 10),
        ) else {
            panic!("l'aggiunta deve riuscire");
        };

        let Ok((workspace, elementi)) = servizio.contents(id) else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(workspace.state, WorkspaceState::Open);
        assert_eq!(elementi.len(), 1);
        // Il contenuto 42 non esiste in questo archivio vuoto: il riferimento
        // resta e lo dichiara.
        assert_eq!(elementi[0].target, ResolvedTarget::NoLongerInArchive);
    }

    /// **Due workspace aperti con lo stesso nome: la frase dice perché.**
    #[test]
    fn un_nome_gia_preso_produce_una_frase_che_spiega() {
        let servizio = servizio();
        let Ok(_) = servizio.open(&nuovo("Indagine"), istante(ORA)) else {
            panic!("il primo deve potersi aprire");
        };

        let esito = servizio.open(&nuovo("Indagine"), istante(ORA + 1));
        let Err(ServiceError::WorkspaceNameTaken { name }) = esito else {
            panic!("il secondo deve essere rifiutato con la frase giusta");
        };
        assert_eq!(name, "Indagine");

        let frase = ServiceError::WorkspaceNameTaken {
            name: String::from("Indagine"),
        }
        .operator_message();
        assert!(frase.contains("aperto"), "{frase}");
        assert!(frase.contains("Indagine"), "{frase}");
    }

    /// **Un workspace chiuso lo dice con il suo nome.**
    #[test]
    fn un_workspace_chiuso_lo_dice_con_il_suo_nome() {
        let servizio = servizio();
        let Ok(id) = servizio.open(&nuovo("Indagine"), istante(ORA)) else {
            panic!("il workspace deve potersi aprire");
        };
        let Ok(()) = servizio.close(id, &attore("operatore.prova"), istante(ORA + 100)) else {
            panic!("la chiusura deve riuscire");
        };

        let esito = servizio.add(
            id,
            riferimento(ArchiveRefKind::Source, 1),
            &attore("operatore.prova"),
            istante(ORA + 200),
        );
        let Err(ServiceError::WorkspaceClosed { name }) = esito else {
            panic!("un workspace chiuso deve rifiutare, dicendo quale");
        };
        assert_eq!(name, "Indagine");

        let frase = ServiceError::WorkspaceClosed {
            name: String::from("Indagine"),
        }
        .operator_message();
        assert!(frase.contains("chiuso"), "{frase}");
        assert!(
            frase.contains("aprirne un altro") || frase.contains("un altro"),
            "la frase deve dire che cosa fare \u{2014} {frase}"
        );
    }

    /// **Un doppione non è un guasto: lo dice, con il nome, e non scrive nulla**
    /// (UX-EXCELLENCE-02, SIM3-02).
    ///
    /// Prima rispondeva «Si è verificato un problema tecnico», perché il rifiuto
    /// arrivava dal vincolo d'unicità dell'archivio.
    #[test]
    fn un_doppione_lo_dice_e_non_scrive_nulla() {
        let servizio = servizio();
        let Ok(id) = servizio.open(&nuovo("Indagine"), istante(ORA)) else {
            panic!("il workspace deve potersi aprire");
        };
        let contenuto = riferimento(ArchiveRefKind::Content, 42);
        let Ok(()) = servizio.add(id, contenuto, &attore("operatore.prova"), istante(ORA + 10))
        else {
            panic!("la prima aggiunta deve riuscire");
        };
        let Ok(voci_prima) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };

        let esito = servizio.add(id, contenuto, &attore("operatore.prova"), istante(ORA + 20));
        let Err(errore) = esito else {
            panic!("la seconda aggiunta dello stesso elemento non deve riuscire");
        };
        let ServiceError::AlreadyInWorkspace { name } = &errore else {
            panic!("il doppione deve avere il suo errore, non quello dell'archivio: {errore:?}");
        };
        assert_eq!(name, "Indagine");

        let frase = errore.operator_message();
        assert!(frase.contains("già nel raccoglitore «Indagine»"), "{frase}");
        assert!(
            !frase.contains("problema tecnico"),
            "un doppione non è un guasto \u{2014} {frase}"
        );

        // Nulla è avvenuto: nessun elemento in più, nessuna voce d'audit in più.
        let Ok((_, elementi)) = servizio.contents(id) else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(elementi.len(), 1);
        let Ok(voci_dopo) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert_eq!(voci_prima.len(), voci_dopo.len());

        // Lo stesso elemento in un altro raccoglitore, invece, si aggiunge.
        let Ok(altro) = servizio.open(&nuovo("Altro caso"), istante(ORA + 30)) else {
            panic!("il secondo workspace deve potersi aprire");
        };
        assert!(
            servizio
                .add(
                    altro,
                    contenuto,
                    &attore("operatore.prova"),
                    istante(ORA + 40)
                )
                .is_ok(),
            "il doppione è per raccoglitore, non per archivio"
        );
    }

    /// **Ogni atto lascia traccia nell'audit.**
    #[test]
    fn ogni_atto_lascia_traccia() {
        let servizio = servizio();
        let Ok(id) = servizio.open(&nuovo("Indagine"), istante(ORA)) else {
            panic!("il workspace deve potersi aprire");
        };
        let contenuto = riferimento(ArchiveRefKind::Content, 42);
        let Ok(()) = servizio.add(id, contenuto, &attore("operatore.prova"), istante(ORA + 10))
        else {
            panic!("l'aggiunta deve riuscire");
        };
        let Ok(()) = servizio.remove(id, contenuto, &attore("operatore.prova"), istante(ORA + 20))
        else {
            panic!("la rimozione deve riuscire");
        };
        let Ok(()) = servizio.close(id, &attore("operatore.prova"), istante(ORA + 30)) else {
            panic!("la chiusura deve riuscire");
        };

        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        for azione in [
            "workspace_aperto",
            "workspace_elemento_aggiunto",
            "workspace_elemento_tolto",
            "workspace_chiuso",
        ] {
            assert!(
                voci.iter().any(|voce| voce.action.as_str() == azione),
                "l'azione «{azione}» deve comparire nell'audit"
            );
        }
    }

    /// **L'audit dice che cosa e quale, non che cosa diceva.**
    ///
    /// L'audit documenta le azioni, non i dati su cui insistono — ed è la stessa
    /// ragione per cui la tabella non conserva il testo.
    #[test]
    fn l_audit_non_porta_il_materiale() {
        let codice = codice_senza_commenti();
        let Some(inizio) = codice.find("pub fn add(") else {
            panic!("la funzione deve esistere");
        };
        let Some(fine) = codice[inizio..].find("\n    }\n") else {
            panic!("la funzione deve chiudersi");
        };
        let corpo = &codice[inizio..inizio + fine];
        for materiale in [".body", ".text", "label", "remote_message_id"] {
            assert!(
                !corpo.contains(materiale),
                "l'audit porta «{materiale}»: documenta le azioni, non i dati"
            );
        }
    }

    /// **Il servizio non conserva copie: non ha nulla con cui farlo.**
    ///
    /// # Perché una guardia sul sorgente, oltre al tipo
    ///
    /// Perché il tipo impedisce di mettere una copia **dentro il riferimento**,
    /// e questa impedisce di metterla accanto — una mappa da identificativo a
    /// testo, un campo nel servizio, una struttura di comodo.
    #[test]
    fn il_servizio_non_tiene_copie_del_materiale() {
        let codice = codice_senza_commenti();
        let Some(inizio) = codice.find("pub struct WorkspaceService {") else {
            panic!("il servizio deve esistere");
        };
        let Some(fine) = codice[inizio..].find("\n}\n") else {
            panic!("la struttura deve chiudersi");
        };
        let campi: Vec<&str> = codice[inizio..inizio + fine]
            .lines()
            .map(str::trim)
            .filter(|riga| riga.contains(':'))
            .collect();
        assert_eq!(
            campi.len(),
            1,
            "il servizio ha un campo solo, l'archivio: qualunque altro sarebbe un posto dove \
             una copia puo' stare \u{2014} {campi:?}"
        );
        assert!(campi[0].starts_with("database:"));
    }

    /// **Chiudere due volte non riesce.**
    #[test]
    fn chiudere_due_volte_non_riesce() {
        let servizio = servizio();
        let Ok(id) = servizio.open(&nuovo("Indagine"), istante(ORA)) else {
            panic!("il workspace deve potersi aprire");
        };
        let Ok(()) = servizio.close(id, &attore("operatore.prova"), istante(ORA + 100)) else {
            panic!("la prima chiusura deve riuscire");
        };
        assert!(
            servizio
                .close(id, &attore("operatore.prova"), istante(ORA + 200))
                .is_err(),
            "non c'e' nulla da chiudere, e un successo direbbe che qualcosa e' avvenuto"
        );
    }

    /// **Un workspace che non esiste non si legge in silenzio.**
    #[test]
    fn un_workspace_inesistente_non_si_legge() {
        let servizio = servizio();
        assert!(servizio.contents(WorkspaceId::new(999_999)).is_err());
    }

    /// **La descrizione, quando c'è, si conserva.**
    #[test]
    fn la_descrizione_si_conserva() {
        let servizio = servizio();
        let Ok(nome) = DisplayName::try_new("Indagine") else {
            panic!("il nome di prova deve essere valido");
        };
        let Ok(descrizione) = Note::try_new("le fonti del marzo 2026") else {
            panic!("la descrizione di prova deve essere valida");
        };
        let Ok(id) = servizio.open(
            &NewWorkspace {
                name: nome,
                description: Some(descrizione),
                created_by: attore("operatore.prova"),
            },
            istante(ORA),
        ) else {
            panic!("il workspace deve potersi aprire");
        };

        let Ok((workspace, _)) = servizio.contents(id) else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(
            workspace.description.as_ref().map(Note::as_str),
            Some("le fonti del marzo 2026")
        );
    }
}

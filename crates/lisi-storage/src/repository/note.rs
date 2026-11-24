//! Note dell'operatore (NOTE-01).
//!
//! # Che cosa questo modulo non scrive mai
//!
//! La prova. Le sole istruzioni di scrittura qui insistono su `notes`, e il
//! riferimento è polimorfico — nessuna chiave esterna verso `contents`, e
//! nessuna riga di questo modulo nomina quella tabella se non per **leggerne**
//! l'etichetta, cosa che fa il risolutore condiviso.
//!
//! # Che cosa non si può fare, e chi lo impedisce
//!
//! Riscrivere una nota, annullare un ritiro, cancellare una nota: li rifiuta
//! l'archivio con tre trigger, e valgono anche per chi scrivesse un secondo
//! servizio domani. Qui non c'è una funzione che ci provi — l'assenza è la
//! prima difesa, il trigger è la seconda.
//!
//! # Un riferimento appeso si dichiara
//!
//! Come per workspace e segnalibri. Leggere le note restituisce, per ciascuna,
//! **o l'etichetta risolta o la dichiarazione che non è più nell'archivio**.

use core::str::FromStr;

use lisi_core::model::note::{NewOperatorNote, NoteWithdrawal, OperatorNote};
use lisi_core::model::reference::{ArchiveRef, ArchiveRefKind};
use lisi_core::text::{Actor, Note};
use lisi_core::{NoteId, Timestamp};

use crate::database::Database;
use crate::error::{StorageError, StorageResult};
use crate::repository::reference::ResolvedTarget;
use crate::repository::{instant, millis};

/// Una nota riletta, con ciò che il suo riferimento raggiunge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNote {
    /// La nota.
    pub note: OperatorNote,
    /// Che cosa raggiunge.
    pub target: ResolvedTarget,
}

impl Database {
    /// Scrive una nota.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce, o se l'archivio
    /// rifiuta il genere.
    pub fn insert_note(
        &self,
        note: &NewOperatorNote,
        author: &Actor,
        written_at: Timestamp,
    ) -> StorageResult<NoteId> {
        self.connection.execute(
            "INSERT INTO notes (kind, target_id, body, author, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                note.reference().kind().as_str(),
                note.reference().target_id(),
                note.body().as_str(),
                author.as_str(),
                millis(written_at),
            ],
        )?;
        Ok(NoteId::new(self.connection.last_insert_rowid()))
    }

    /// Ritira una nota.
    ///
    /// # Che cosa NON fa
    ///
    /// Non la cancella e non ne cambia il testo. Dopo il ritiro la nota **si
    /// legge ancora**, e dice chi l'aveva scritta, quando, e chi l'ha ritirata:
    /// qualcuno può averci lavorato sopra, e farla sparire riscriverebbe che
    /// cosa quella persona aveva davanti.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se la nota non esiste o **era già
    /// ritirata**: in entrambi i casi non c'è nulla da ritirare, e un successo
    /// direbbe che qualcosa è avvenuto.
    pub fn withdraw_note(
        &self,
        id: NoteId,
        withdrawn_by: &Actor,
        withdrawn_at: Timestamp,
    ) -> StorageResult<()> {
        let toccate = self.connection.execute(
            "UPDATE notes
                SET withdrawn_by = ?2, withdrawn_at = ?3
              WHERE id = ?1 AND withdrawn_at IS NULL",
            rusqlite::params![id.get(), withdrawn_by.as_str(), millis(withdrawn_at)],
        )?;
        if toccate == 0 {
            return Err(StorageError::NotFound {
                entity: "nota da ritirare",
                id: id.get(),
            });
        }
        Ok(())
    }

    /// Le note su una cosa, dalla più recente.
    ///
    /// # Perché le ritirate ci sono
    ///
    /// Perché una nota ritirata **non è una nota che non è mai esistita**.
    /// Filtrarla direbbe che nessuno aveva annotato quella cosa, e chi lavora
    /// su un materiale deve poter vedere che qualcuno ci aveva scritto sopra e
    /// poi si è corretto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn notes_about(&self, reference: ArchiveRef) -> StorageResult<Vec<OperatorNote>> {
        let mut statement = self.connection.prepare(
            "SELECT id, kind, target_id, body, author, created_at, withdrawn_by, withdrawn_at
             FROM notes
             WHERE kind = ?1 AND target_id = ?2
             ORDER BY created_at DESC, id DESC",
        )?;
        let righe: Vec<NoteRow> = statement
            .query_map(
                rusqlite::params![reference.kind().as_str(), reference.target_id()],
                NoteRow::from_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        righe.into_iter().map(NoteRow::into_note).collect()
    }

    /// Tutte le note, dalla più recente, **con ciò che i riferimenti
    /// raggiungono**.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn notes(&self) -> StorageResult<Vec<ResolvedNote>> {
        let mut statement = self.connection.prepare(
            "SELECT id, kind, target_id, body, author, created_at, withdrawn_by, withdrawn_at
             FROM notes
             ORDER BY created_at DESC, id DESC",
        )?;
        let righe: Vec<NoteRow> = statement
            .query_map([], NoteRow::from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut note = Vec::with_capacity(righe.len());
        for riga in righe {
            let letta = riga.into_note()?;
            let target =
                self.resolve_reference(letta.reference.kind(), letta.reference.target_id())?;
            note.push(ResolvedNote {
                note: letta,
                target,
            });
        }
        Ok(note)
    }

    /// Quante note **valide** ci sono su una cosa.
    ///
    /// # Perché soltanto le valide
    ///
    /// Perché questo numero serve a dire, accanto a un materiale, «qui c'è
    /// scritto qualcosa». Una nota ritirata non è più qualcosa di scritto: chi
    /// vedesse «3 note» e ne trovasse tre ritirate penserebbe a un difetto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn standing_note_count(&self, reference: ArchiveRef) -> StorageResult<usize> {
        let quante: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM notes
             WHERE kind = ?1 AND target_id = ?2 AND withdrawn_at IS NULL",
            rusqlite::params![reference.kind().as_str(), reference.target_id()],
            |row| row.get(0),
        )?;
        Ok(usize::try_from(quante).unwrap_or(0))
    }
}

/// Riga grezza della tabella `notes`.
struct NoteRow {
    id: i64,
    kind: String,
    target_id: i64,
    body: String,
    author: String,
    created_at: i64,
    withdrawn_by: Option<String>,
    withdrawn_at: Option<i64>,
}

impl NoteRow {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            kind: row.get(1)?,
            target_id: row.get(2)?,
            body: row.get(3)?,
            author: row.get(4)?,
            created_at: row.get(5)?,
            withdrawn_by: row.get(6)?,
            withdrawn_at: row.get(7)?,
        })
    }

    fn into_note(self) -> StorageResult<OperatorNote> {
        let kind = ArchiveRefKind::from_str(&self.kind)?;
        // IL RITIRO SI RICOSTRUISCE SOLO SE CI SONO ENTRAMBI.
        //
        // L'archivio lo impone con un vincolo; qui la coppia diventa un tipo,
        // cosi' che nessun chiamante possa leggere l'uno senza l'altro.
        let withdrawal = match (self.withdrawn_by, self.withdrawn_at) {
            (Some(chi), Some(quando)) => Some(NoteWithdrawal {
                by: Actor::try_new(&chi)?,
                at: instant(quando),
            }),
            _ => None,
        };
        Ok(OperatorNote {
            id: NoteId::new(self.id),
            reference: ArchiveRef::to(kind, self.target_id)?,
            body: Note::try_new(&self.body)?,
            author: Actor::try_new(&self.author)?,
            written_at: instant(self.created_at),
            withdrawal,
        })
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::note::NewOperatorNote;
    use lisi_core::model::reference::{ArchiveRef, ArchiveRefKind};
    use lisi_core::text::Note;
    use lisi_core::{NoteId, Timestamp};

    use crate::repository::reference::ResolvedTarget;
    use crate::test_support::{actor, database_with_session, new_content};

    const ORA: i64 = 1_700_000_000_000;

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    fn testo(raw: &str) -> Note {
        let Ok(nota) = Note::try_new(raw) else {
            panic!("il testo di prova deve essere valido");
        };
        nota
    }

    fn riferimento(kind: ArchiveRefKind, id: i64) -> ArchiveRef {
        let Ok(riferimento) = ArchiveRef::to(kind, id) else {
            panic!("il riferimento di prova deve essere valido");
        };
        riferimento
    }

    fn nuova(kind: ArchiveRefKind, id: i64, corpo: &str) -> NewOperatorNote {
        let Ok(nota) = NewOperatorNote::about(riferimento(kind, id), &testo(corpo)) else {
            panic!("la nota di prova deve essere valida");
        };
        nota
    }

    /// **Una nota si scrive e si rilegge, con ciò a cui punta.**
    #[test]
    fn una_nota_si_scrive_e_si_rilegge() {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(inserimento) =
            database.insert_content(&new_content(session_id, source_id, "777", "testo"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let contenuto = inserimento.content_id();

        let Ok(_) = database.insert_note(
            &nuova(
                ArchiveRefKind::Content,
                contenuto.get(),
                "ripubblicato tre volte",
            ),
            &actor("operatore.prova"),
            istante(ORA),
        ) else {
            panic!("la nota deve potersi scrivere");
        };

        let Ok(elenco) = database.notes() else {
            panic!("le note devono potersi leggere");
        };
        assert_eq!(elenco.len(), 1);
        assert_eq!(elenco[0].note.body.as_str(), "ripubblicato tre volte");
        assert_eq!(elenco[0].note.author.as_str(), "operatore.prova");
        assert!(elenco[0].note.stands());
        let ResolvedTarget::Present { label } = &elenco[0].target else {
            panic!("il contenuto esiste, e deve risolversi");
        };
        // Con il testo e la fonte, non più il solo numero (OS-02).
        assert!(label.ends_with(", messaggio 777"), "{label}");
        assert!(label.len() > "messaggio 777".len() + 2, "{label}");
    }

    /// **Il testo di una nota non si riscrive.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Qualcuno che «corregge un refuso» e senza volerlo fa dire all'autore e
    /// all'istante una cosa falsa: che quella persona ha scritto *quella* frase
    /// quel giorno.
    #[test]
    fn il_testo_di_una_nota_non_si_riscrive() {
        let (database, source_id, _) = database_with_session();
        let Ok(id) = database.insert_note(
            &nuova(ArchiveRefKind::Source, source_id.get(), "prima versione"),
            &actor("operatore.prova"),
            istante(ORA),
        ) else {
            panic!("la nota deve potersi scrivere");
        };

        let esito = database.connection.execute(
            "UPDATE notes SET body = 'seconda versione' WHERE id = ?1",
            [id.get()],
        );
        assert!(esito.is_err(), "una nota non si riscrive");

        let Ok(note) = database.notes_about(riferimento(ArchiveRefKind::Source, source_id.get()))
        else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(note[0].body.as_str(), "prima versione");
    }

    /// **Una nota si ritira, e resta visibile.**
    #[test]
    fn una_nota_si_ritira_e_resta_visibile() {
        let (database, source_id, _) = database_with_session();
        let Ok(id) = database.insert_note(
            &nuova(ArchiveRefKind::Source, source_id.get(), "da rivedere"),
            &actor("operatore.prova"),
            istante(ORA),
        ) else {
            panic!("la nota deve potersi scrivere");
        };

        let Ok(()) = database.withdraw_note(id, &actor("altro.operatore"), istante(ORA + 100))
        else {
            panic!("il ritiro deve riuscire");
        };

        let Ok(note) = database.notes_about(riferimento(ArchiveRefKind::Source, source_id.get()))
        else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(note.len(), 1, "la nota ritirata resta");
        assert!(!note[0].stands());
        let Some(ritiro) = note[0].withdrawal.as_ref() else {
            panic!("il ritiro deve esserci");
        };
        assert_eq!(ritiro.by.as_str(), "altro.operatore");
        assert_eq!(ritiro.at.as_millis(), ORA + 100);
        assert_eq!(note[0].body.as_str(), "da rivedere", "il testo non cambia");
    }

    /// **Un ritiro non si ripete e non si annulla.**
    #[test]
    fn un_ritiro_non_si_ripete_e_non_si_annulla() {
        let (database, source_id, _) = database_with_session();
        let Ok(id) = database.insert_note(
            &nuova(ArchiveRefKind::Source, source_id.get(), "da rivedere"),
            &actor("operatore.prova"),
            istante(ORA),
        ) else {
            panic!("la nota deve potersi scrivere");
        };
        let Ok(()) = database.withdraw_note(id, &actor("operatore.prova"), istante(ORA + 100))
        else {
            panic!("il primo ritiro deve riuscire");
        };

        assert!(
            database
                .withdraw_note(id, &actor("operatore.prova"), istante(ORA + 200))
                .is_err(),
            "non c'e' nulla da ritirare due volte"
        );

        let esito = database.connection.execute(
            "UPDATE notes SET withdrawn_by = NULL, withdrawn_at = NULL WHERE id = ?1",
            [id.get()],
        );
        assert!(esito.is_err(), "un ritiro non si annulla");
    }

    /// **Una nota non si cancella.**
    #[test]
    fn una_nota_non_si_cancella() {
        let (database, source_id, _) = database_with_session();
        let Ok(id) = database.insert_note(
            &nuova(ArchiveRefKind::Source, source_id.get(), "qualcosa"),
            &actor("operatore.prova"),
            istante(ORA),
        ) else {
            panic!("la nota deve potersi scrivere");
        };

        let esito = database
            .connection
            .execute("DELETE FROM notes WHERE id = ?1", [id.get()]);
        assert!(esito.is_err(), "una nota non si cancella: si ritira");
    }

    /// **L'archivio rifiuta una nota vuota e una nota su un segnalibro.**
    ///
    /// Il dominio le rifiuta nel costruttore; qui si verifica che le rifiuti
    /// anche l'archivio, per chi scrivesse un secondo servizio domani.
    #[test]
    fn l_archivio_rifiuta_una_nota_vuota_e_una_su_un_segnalibro() {
        let (database, _, _) = database_with_session();
        let vuota = database.connection.execute(
            "INSERT INTO notes (kind, target_id, body, author, created_at)
             VALUES ('contenuto', 1, '   ', 'operatore.prova', 0)",
            [],
        );
        assert!(vuota.is_err(), "una nota senza parole non e' una nota");

        let sul_dito = database.connection.execute(
            "INSERT INTO notes (kind, target_id, body, author, created_at)
             VALUES ('segnalibro', 1, 'qualcosa', 'operatore.prova', 0)",
            [],
        );
        assert!(
            sul_dito.is_err(),
            "annotare un segnalibro sarebbe annotare il dito"
        );
    }

    /// **Un riferimento appeso si dichiara, e la nota non sparisce.**
    #[test]
    fn una_nota_su_qualcosa_che_non_c_e_piu_si_dichiara() {
        let (database, _, _) = database_with_session();
        let Ok(_) = database.insert_note(
            &nuova(
                ArchiveRefKind::Content,
                9_999,
                "annotata prima che sparisse",
            ),
            &actor("operatore.prova"),
            istante(ORA),
        ) else {
            panic!("la nota deve potersi scrivere");
        };

        let Ok(elenco) = database.notes() else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(elenco.len(), 1, "la nota resta");
        assert_eq!(elenco[0].target, ResolvedTarget::NoLongerInArchive);
    }

    /// **Il conteggio dice le note valide, non tutte.**
    ///
    /// # Perché
    ///
    /// Perché serve a dire, accanto a un materiale, «qui c'è scritto
    /// qualcosa». Chi vedesse «3 note» e ne trovasse tre ritirate penserebbe a
    /// un difetto.
    #[test]
    fn il_conteggio_dice_le_note_valide() {
        let (database, source_id, _) = database_with_session();
        let fonte = riferimento(ArchiveRefKind::Source, source_id.get());

        let Ok(prima) = database.insert_note(
            &nuova(ArchiveRefKind::Source, source_id.get(), "una"),
            &actor("operatore.prova"),
            istante(ORA),
        ) else {
            panic!("la nota deve potersi scrivere");
        };
        let Ok(_) = database.insert_note(
            &nuova(ArchiveRefKind::Source, source_id.get(), "due"),
            &actor("operatore.prova"),
            istante(ORA + 10),
        ) else {
            panic!("la nota deve potersi scrivere");
        };

        let Ok(quante) = database.standing_note_count(fonte) else {
            panic!("il conteggio deve riuscire");
        };
        assert_eq!(quante, 2);

        let Ok(()) = database.withdraw_note(prima, &actor("operatore.prova"), istante(ORA + 20))
        else {
            panic!("il ritiro deve riuscire");
        };
        let Ok(dopo) = database.standing_note_count(fonte) else {
            panic!("il conteggio deve riuscire");
        };
        assert_eq!(dopo, 1, "la ritirata non conta piu'");

        let Ok(tutte) = database.notes_about(fonte) else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(tutte.len(), 2, "ma resta leggibile");
    }

    /// **Ritirare una nota che non c'è lo dichiara.**
    #[test]
    fn ritirare_una_nota_che_non_c_e_lo_dichiara() {
        let (database, _, _) = database_with_session();
        assert!(
            database
                .withdraw_note(NoteId::new(999), &actor("operatore.prova"), istante(ORA))
                .is_err(),
            "non c'e' nulla da ritirare"
        );
    }

    /// **Una nota su un workspace si risolve col nome del workspace.**
    #[test]
    fn una_nota_su_un_workspace_si_risolve_col_nome() {
        use lisi_core::model::workspace::NewWorkspace;
        use lisi_core::text::DisplayName;

        let (database, _, _) = database_with_session();
        let Ok(nome) = DisplayName::try_new("Indagine di marzo") else {
            panic!("il nome di prova deve essere valido");
        };
        let Ok(workspace) = database.insert_workspace(
            &NewWorkspace {
                name: nome,
                description: None,
                created_by: actor("operatore.prova"),
            },
            istante(ORA),
        ) else {
            panic!("il workspace deve potersi aprire");
        };

        let Ok(_) = database.insert_note(
            &nuova(
                ArchiveRefKind::Workspace,
                workspace.get(),
                "questo filone non ha portato a nulla",
            ),
            &actor("operatore.prova"),
            istante(ORA + 10),
        ) else {
            panic!("la nota deve potersi scrivere");
        };

        let Ok(elenco) = database.notes() else {
            panic!("la lettura deve riuscire");
        };
        let ResolvedTarget::Present { label } = &elenco[0].target else {
            panic!("il workspace esiste, e deve risolversi");
        };
        assert_eq!(label, "Indagine di marzo");
    }
}

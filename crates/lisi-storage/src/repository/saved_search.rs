//! Ricerche salvate (SEARCH-01).
//!
//! # Che cosa questo modulo non conserva
//!
//! I risultati. Solo la domanda, chi l'ha posta, quando, e **la versione del
//! motore in forza allora**. Conservare le righe trovate darebbe una fotografia
//! che invecchia e che, riaperta, sembrerebbe attuale.
//!
//! # Che cosa non si può fare, e chi lo impedisce
//!
//! Modificare una ricerca salvata: lo rifiuta un trigger, e vale anche per chi
//! scrivesse un secondo servizio domani. Qui non c'è una funzione che ci provi —
//! l'assenza è la prima difesa, il trigger è la seconda.

use lisi_core::model::saved_search::{NewSavedSearch, SavedQuery, SavedSearch};
use lisi_core::text::{Actor, DisplayName};
use lisi_core::{SavedSearchId, SessionId, Timestamp};

use crate::database::Database;
use crate::error::{StorageError, StorageResult};
use crate::repository::{instant, millis};

impl Database {
    /// Salva una ricerca.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se una ricerca con quel nome esiste già, o se la
    /// scrittura non riesce.
    pub fn insert_saved_search(
        &self,
        search: &NewSavedSearch,
        engine_version: u32,
        created_at: Timestamp,
    ) -> StorageResult<SavedSearchId> {
        let query = search.query();
        self.connection.execute(
            "INSERT INTO saved_searches
                (name, query, minimum_level, only_pending, session_id,
                 engine_version, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                search.name().as_str(),
                query.query.as_str(),
                i64::from(query.minimum_level),
                i64::from(query.only_pending),
                query.session.map(SessionId::get),
                i64::from(engine_version),
                search.created_by().as_str(),
                millis(created_at),
            ],
        )?;
        Ok(SavedSearchId::new(self.connection.last_insert_rowid()))
    }

    /// Le ricerche salvate, in ordine di nome.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn saved_searches(&self) -> StorageResult<Vec<SavedSearch>> {
        let mut statement = self.connection.prepare(
            "SELECT id, name, query, minimum_level, only_pending, session_id,
                    engine_version, created_by, created_at
             FROM saved_searches
             ORDER BY name ASC",
        )?;
        let righe: Vec<SavedSearchRow> = statement
            .query_map([], SavedSearchRow::from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        righe.into_iter().map(SavedSearchRow::into_search).collect()
    }

    /// Una ricerca salvata.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se non esiste.
    pub fn saved_search(&self, id: SavedSearchId) -> StorageResult<SavedSearch> {
        let mut statement = self.connection.prepare(
            "SELECT id, name, query, minimum_level, only_pending, session_id,
                    engine_version, created_by, created_at
             FROM saved_searches
             WHERE id = ?1",
        )?;
        let mut righe = statement.query_map([id.get()], SavedSearchRow::from_row)?;
        match righe.next() {
            Some(riga) => riga?.into_search(),
            None => Err(StorageError::NotFound {
                entity: "ricerca salvata",
                id: id.get(),
            }),
        }
    }

    /// Cancella una ricerca salvata.
    ///
    /// # Perché cancellare è ammesso, e modificare no
    ///
    /// Perché una ricerca salvata è uno **strumento**, non l'affermazione di
    /// una persona su un fatto: nessuna decisione poggia sulla sua esistenza, e
    /// un elenco che si riempie di ricerche morte è un elenco che non si usa.
    ///
    /// Modificarla invece farebbe mentire chi l'ha salvata e quando — ed è la
    /// stessa ragione per cui una nota non si riscrive (NOTE-01).
    ///
    /// L'audit registra comunque che c'era.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se non c'era.
    pub fn delete_saved_search(&self, id: SavedSearchId) -> StorageResult<()> {
        let toccate = self
            .connection
            .execute("DELETE FROM saved_searches WHERE id = ?1", [id.get()])?;
        if toccate == 0 {
            return Err(StorageError::NotFound {
                entity: "ricerca salvata",
                id: id.get(),
            });
        }
        Ok(())
    }
}

/// Riga grezza della tabella `saved_searches`.
struct SavedSearchRow {
    id: i64,
    name: String,
    query: String,
    minimum_level: i64,
    only_pending: i64,
    session_id: Option<i64>,
    engine_version: i64,
    created_by: String,
    created_at: i64,
}

impl SavedSearchRow {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            name: row.get(1)?,
            query: row.get(2)?,
            minimum_level: row.get(3)?,
            only_pending: row.get(4)?,
            session_id: row.get(5)?,
            engine_version: row.get(6)?,
            created_by: row.get(7)?,
            created_at: row.get(8)?,
        })
    }

    fn into_search(self) -> StorageResult<SavedSearch> {
        Ok(SavedSearch {
            id: SavedSearchId::new(self.id),
            name: DisplayName::try_new(&self.name)?,
            query: SavedQuery {
                query: self.query,
                // I VINCOLI DELL'ARCHIVIO GARANTISCONO L'INTERVALLO.
                //
                // `CHECK (minimum_level BETWEEN 0 AND 4)`: una conversione che
                // fallisse qui vorrebbe dire un archivio manomesso, e allora il
                // valore prudente e' quello che NON esclude nulla — mostrare
                // troppo si vede, mostrare troppo poco no.
                minimum_level: u8::try_from(self.minimum_level).unwrap_or(0),
                only_pending: self.only_pending != 0,
                session: self.session_id.map(SessionId::new),
            },
            engine_version: u32::try_from(self.engine_version).unwrap_or(0),
            created_by: Actor::try_new(&self.created_by)?,
            created_at: instant(self.created_at),
        })
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::saved_search::{NewSavedSearch, SavedQuery};
    use lisi_core::text::DisplayName;
    use lisi_core::{SavedSearchId, SessionId, Timestamp};

    use crate::test_support::{actor, database_with_session};

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

    fn ricerca(
        etichetta: &str,
        testo: &str,
        livello: u8,
        sessione: Option<SessionId>,
    ) -> NewSavedSearch {
        let Ok(ricerca) = NewSavedSearch::of(
            nome(etichetta),
            SavedQuery {
                query: String::from(testo),
                minimum_level: livello,
                only_pending: false,
                session: sessione,
            },
            actor("operatore.prova"),
        ) else {
            panic!("la ricerca di prova deve essere valida");
        };
        ricerca
    }

    /// **Una ricerca si salva e si rilegge identica.**
    #[test]
    fn una_ricerca_si_salva_e_si_rilegge_identica() {
        let (database, _, session_id) = database_with_session();
        let Ok(id) = database.insert_saved_search(
            &ricerca("Droga di marzo", "droga", 3, Some(session_id)),
            1,
            istante(ORA),
        ) else {
            panic!("la ricerca deve potersi salvare");
        };

        let Ok(letta) = database.saved_search(id) else {
            panic!("la ricerca deve potersi rileggere");
        };
        assert_eq!(letta.name.as_str(), "Droga di marzo");
        assert_eq!(letta.query.query, "droga");
        assert_eq!(letta.query.minimum_level, 3);
        assert!(!letta.query.only_pending);
        assert_eq!(letta.query.session, Some(session_id));
        assert_eq!(letta.engine_version, 1);
        assert_eq!(letta.created_by.as_str(), "operatore.prova");
    }

    /// **Due ricerche non hanno lo stesso nome.**
    #[test]
    fn due_ricerche_non_hanno_lo_stesso_nome() {
        let (database, _, _) = database_with_session();
        let Ok(_) =
            database.insert_saved_search(&ricerca("Droga", "droga", 0, None), 1, istante(ORA))
        else {
            panic!("la prima deve potersi salvare");
        };
        assert!(
            database
                .insert_saved_search(&ricerca("Droga", "altro", 0, None), 1, istante(ORA + 1))
                .is_err(),
            "due ricerche omonime sono una trappola"
        );
    }

    /// **Una ricerca salvata non si modifica.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una ricerca salvata che porta «salvata da Tizio il 3 marzo» e una query
    /// che qualcuno ha cambiato ieri. È la stessa disciplina delle note.
    #[test]
    fn una_ricerca_salvata_non_si_modifica() {
        let (database, _, _) = database_with_session();
        let Ok(id) =
            database.insert_saved_search(&ricerca("Droga", "droga", 0, None), 1, istante(ORA))
        else {
            panic!("la ricerca deve potersi salvare");
        };

        for istruzione in [
            "UPDATE saved_searches SET query = 'altro' WHERE id = ?1",
            "UPDATE saved_searches SET name = 'Altro nome' WHERE id = ?1",
            "UPDATE saved_searches SET minimum_level = 4 WHERE id = ?1",
            "UPDATE saved_searches SET engine_version = 99 WHERE id = ?1",
        ] {
            assert!(
                database.connection.execute(istruzione, [id.get()]).is_err(),
                "«{istruzione}» deve essere rifiutata"
            );
        }

        let Ok(letta) = database.saved_search(id) else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(letta.query.query, "droga");
    }

    /// **Una ricerca salvata si cancella.**
    ///
    /// # Perché qui sì e per una nota no
    ///
    /// Perché una ricerca salvata è uno **strumento**: nessuna decisione poggia
    /// sulla sua esistenza. Una nota è l'affermazione di una persona su un
    /// fatto, e qualcuno può averci lavorato sopra.
    #[test]
    fn una_ricerca_salvata_si_cancella() {
        let (database, _, _) = database_with_session();
        let Ok(id) =
            database.insert_saved_search(&ricerca("Droga", "droga", 0, None), 1, istante(ORA))
        else {
            panic!("la ricerca deve potersi salvare");
        };

        let Ok(()) = database.delete_saved_search(id) else {
            panic!("la cancellazione deve riuscire");
        };
        let Ok(elenco) = database.saved_searches() else {
            panic!("la lettura deve riuscire");
        };
        assert!(elenco.is_empty());

        assert!(
            database.delete_saved_search(id).is_err(),
            "non c'e' nulla da cancellare due volte"
        );
    }

    /// **L'archivio rifiuta una ricerca che non chiede niente.**
    ///
    /// Il dominio la rifiuta nel costruttore; qui si verifica che la rifiuti
    /// anche l'archivio, per chi scrivesse un secondo servizio domani.
    #[test]
    fn l_archivio_rifiuta_una_ricerca_che_non_chiede_niente() {
        let (database, _, _) = database_with_session();
        let esito = database.connection.execute(
            "INSERT INTO saved_searches
                (name, query, minimum_level, only_pending, engine_version, created_by, created_at)
             VALUES ('Vuota', '   ', 0, 0, 1, 'operatore.prova', 0)",
            [],
        );
        assert!(esito.is_err(), "restituirebbe tutto");
    }

    /// **L'archivio rifiuta un livello fuori dai cinque che esistono.**
    #[test]
    fn l_archivio_rifiuta_un_livello_che_non_esiste() {
        let (database, _, _) = database_with_session();
        let esito = database.connection.execute(
            "INSERT INTO saved_searches
                (name, query, minimum_level, only_pending, engine_version, created_by, created_at)
             VALUES ('Impossibile', 'droga', 9, 0, 1, 'operatore.prova', 0)",
            [],
        );
        assert!(esito.is_err(), "i livelli sono cinque, da 0 a 4");
    }

    /// **Leggere una ricerca che non c'è lo dichiara.**
    #[test]
    fn leggere_una_ricerca_che_non_c_e_lo_dichiara() {
        let (database, _, _) = database_with_session();
        assert!(database.saved_search(SavedSearchId::new(999)).is_err());
    }

    /// **L'ambito resta anche se la sessione sparisce.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una ricerca salvata che sparisce insieme alla sessione. Farla sparire
    /// direbbe che nessuno l'aveva mai salvata; resta, e chi la rilegge scopre
    /// che il suo ambito non è più nell'archivio.
    #[test]
    fn l_ambito_resta_anche_se_la_sessione_sparisce() {
        let (database, _, session_id) = database_with_session();
        let Ok(_) = database.insert_saved_search(
            &ricerca("In sessione", "droga", 0, Some(session_id)),
            1,
            istante(ORA),
        ) else {
            panic!("la ricerca deve potersi salvare");
        };

        let Ok(_) = database
            .connection
            .execute("DELETE FROM sessions WHERE id = ?1", [session_id.get()])
        else {
            panic!("la sessione di prova deve potersi cancellare");
        };

        let Ok(elenco) = database.saved_searches() else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(elenco.len(), 1, "la ricerca salvata resta");
        assert_eq!(elenco[0].query.session, Some(session_id));
    }
}

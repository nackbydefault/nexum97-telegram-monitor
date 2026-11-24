//! Soggetti investigativi (PERS-01).
//!
//! # Che cosa questo modulo non fa
//!
//! Non crea soggetti da osservazioni. Non legge `contents`, non legge gli
//! autori, e non ha alcuna funzione che prenda un partecipante osservato e ne
//! faccia un soggetto: **un soggetto ci finisce perché qualcuno ha deciso di
//! aprirlo**, e ha scritto perché.
//!
//! È la guardia che il congelamento scrive per esteso — «nessun profilo creato
//! automaticamente per ogni utente che compare in una fonte monitorata» — e qui
//! è l'assenza di una capacità, non una disciplina da ricordare.
//!
//! # Che cosa non si può fare, e chi lo impedisce
//!
//! Riscrivere ciò che è stato scritto aprendo un soggetto, e riaprirne uno
//! chiuso: li rifiutano due trigger, e valgono anche per chi scrivesse un
//! secondo servizio domani.

use lisi_core::model::person::{NewPerson, Person, PersonClosure};
use lisi_core::model::reason::OperationalReason;
use lisi_core::text::{Actor, DisplayName};
use lisi_core::{PersonId, Timestamp};

use crate::database::Database;
use crate::error::{StorageError, StorageResult};
use crate::repository::{instant, millis};

impl Database {
    /// Apre un soggetto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn insert_person(
        &self,
        person: &NewPerson,
        opened_by: &Actor,
        opened_at: Timestamp,
    ) -> StorageResult<PersonId> {
        self.connection.execute(
            "INSERT INTO persons (label, reason, opened_by, opened_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                person.label().as_str(),
                person.reason().as_str(),
                opened_by.as_str(),
                millis(opened_at),
            ],
        )?;
        Ok(PersonId::new(self.connection.last_insert_rowid()))
    }

    /// I soggetti, in ordine di etichetta.
    ///
    /// # Perché anche quelli chiusi
    ///
    /// Perché un soggetto chiuso **non è un soggetto che non è mai stato
    /// aperto**. Filtrarlo direbbe che nessuno ha mai aperto un fascicolo su
    /// quella persona, e chi rilegge non avrebbe modo di accorgersene.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn persons(&self) -> StorageResult<Vec<Person>> {
        let mut statement = self.connection.prepare(
            "SELECT id, label, reason, opened_by, opened_at,
                    closed_by, closed_at, closure_reason
             FROM persons
             ORDER BY label ASC",
        )?;
        let righe: Vec<PersonRow> = statement
            .query_map([], PersonRow::from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        righe.into_iter().map(PersonRow::into_person).collect()
    }

    /// Un soggetto.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se non esiste.
    pub fn person(&self, id: PersonId) -> StorageResult<Person> {
        let mut statement = self.connection.prepare(
            "SELECT id, label, reason, opened_by, opened_at,
                    closed_by, closed_at, closure_reason
             FROM persons
             WHERE id = ?1",
        )?;
        let mut righe = statement.query_map([id.get()], PersonRow::from_row)?;
        match righe.next() {
            Some(riga) => riga?.into_person(),
            None => Err(StorageError::NotFound {
                entity: "soggetto",
                id: id.get(),
            }),
        }
    }

    /// Chiude un soggetto.
    ///
    /// # Che cosa NON fa
    ///
    /// Non lo cancella. Un fascicolo chiuso resta leggibile: dice chi lo aveva
    /// aperto, perché, chi lo ha chiuso e perché. Farlo sparire riscriverebbe
    /// che qualcuno era stato investigato.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se il soggetto non esiste o **era
    /// già chiuso**: in entrambi i casi non c'è nulla da chiudere, e un successo
    /// direbbe che qualcosa è avvenuto.
    pub fn close_person(
        &self,
        id: PersonId,
        closed_by: &Actor,
        reason: &OperationalReason,
        closed_at: Timestamp,
    ) -> StorageResult<()> {
        let toccate = self.connection.execute(
            "UPDATE persons
                SET closed_by = ?2, closed_at = ?3, closure_reason = ?4
              WHERE id = ?1 AND closed_at IS NULL",
            rusqlite::params![
                id.get(),
                closed_by.as_str(),
                millis(closed_at),
                reason.as_str(),
            ],
        )?;
        if toccate == 0 {
            return Err(StorageError::NotFound {
                entity: "soggetto da chiudere",
                id: id.get(),
            });
        }
        Ok(())
    }
}

/// Riga grezza della tabella `persons`.
struct PersonRow {
    id: i64,
    label: String,
    reason: String,
    opened_by: String,
    opened_at: i64,
    closed_by: Option<String>,
    closed_at: Option<i64>,
    closure_reason: Option<String>,
}

impl PersonRow {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            label: row.get(1)?,
            reason: row.get(2)?,
            opened_by: row.get(3)?,
            opened_at: row.get(4)?,
            closed_by: row.get(5)?,
            closed_at: row.get(6)?,
            closure_reason: row.get(7)?,
        })
    }

    fn into_person(self) -> StorageResult<Person> {
        // LA CHIUSURA SI RICOSTRUISCE SOLO SE CI SONO TUTTI E TRE.
        //
        // L'archivio lo impone con un vincolo; qui la terna diventa un tipo,
        // cosi' che nessun chiamante possa leggerne uno senza gli altri.
        let closure = match (self.closed_by, self.closed_at, self.closure_reason) {
            (Some(chi), Some(quando), Some(perche)) => Some(PersonClosure {
                by: Actor::try_new(&chi)?,
                at: instant(quando),
                reason: OperationalReason::try_new(&perche)?,
            }),
            _ => None,
        };

        Ok(Person {
            id: PersonId::new(self.id),
            label: DisplayName::try_new(&self.label)?,
            reason: OperationalReason::try_new(&self.reason)?,
            opened_by: Actor::try_new(&self.opened_by)?,
            opened_at: instant(self.opened_at),
            closure,
        })
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::PersonId;
    use lisi_core::Timestamp;
    use lisi_core::model::person::NewPerson;
    use lisi_core::model::reason::OperationalReason;
    use lisi_core::text::DisplayName;

    use crate::test_support::{actor, database_with_session};

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("person.rs");

    const ORA: i64 = 1_700_000_000_000;

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    fn ragione(testo: &str) -> OperationalReason {
        let Ok(ragione) = OperationalReason::try_new(testo) else {
            panic!("la ragione di prova deve essere valida");
        };
        ragione
    }

    fn soggetto(etichetta: &str) -> NewPerson {
        let Ok(nome) = DisplayName::try_new(etichetta) else {
            panic!("l'etichetta di prova deve essere valida");
        };
        NewPerson::open(
            nome,
            ragione("richiesta della procura del 3 marzo, fascicolo 123/2026"),
        )
    }

    /// **Un soggetto si apre e si rilegge, con la sua ragione.**
    #[test]
    fn un_soggetto_si_apre_e_si_rilegge() {
        let (database, _, _) = database_with_session();
        let Ok(id) = database.insert_person(
            &soggetto("Soggetto A"),
            &actor("operatore.prova"),
            istante(ORA),
        ) else {
            panic!("il soggetto deve potersi aprire");
        };

        let Ok(letto) = database.person(id) else {
            panic!("il soggetto deve potersi rileggere");
        };
        assert_eq!(letto.label.as_str(), "Soggetto A");
        assert!(letto.reason.as_str().contains("procura"));
        assert_eq!(letto.opened_by.as_str(), "operatore.prova");
        assert!(letto.is_open());
    }

    /// **L'archivio rifiuta un soggetto senza ragione.**
    ///
    /// Il dominio lo rende impossibile per costruzione; qui si verifica che lo
    /// rifiuti anche l'archivio, per chi scrivesse un secondo servizio domani.
    #[test]
    fn l_archivio_rifiuta_un_soggetto_senza_ragione() {
        let (database, _, _) = database_with_session();
        for ragione in ["", "   ", "ok", "serve"] {
            let esito = database.connection.execute(
                "INSERT INTO persons (label, reason, opened_by, opened_at)
                 VALUES ('Soggetto', ?1, 'operatore.prova', 0)",
                [ragione],
            );
            assert!(esito.is_err(), "«{ragione}» non e' una ragione documentata");
        }
    }

    /// **Ciò che è stato scritto aprendo un soggetto non si riscrive.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una ragione cambiata dopo. Il soggetto porta chi lo ha aperto, quando e
    /// perché: se la ragione potesse cambiare, quei tre valori direbbero che
    /// quella persona ha aperto quel fascicolo per quel motivo quel giorno, e
    /// sarebbe falso.
    #[test]
    fn cio_che_e_stato_scritto_aprendo_non_si_riscrive() {
        let (database, _, _) = database_with_session();
        let Ok(id) = database.insert_person(
            &soggetto("Soggetto A"),
            &actor("operatore.prova"),
            istante(ORA),
        ) else {
            panic!("il soggetto deve potersi aprire");
        };

        for istruzione in [
            "UPDATE persons SET reason = 'un altro motivo lungo abbastanza da passare' WHERE id = ?1",
            "UPDATE persons SET label = 'Soggetto B' WHERE id = ?1",
            "UPDATE persons SET opened_by = 'altro.operatore' WHERE id = ?1",
        ] {
            assert!(
                database.connection.execute(istruzione, [id.get()]).is_err(),
                "«{istruzione}» deve essere rifiutata"
            );
        }
    }

    /// **Un soggetto si chiude, resta leggibile, e non si riapre.**
    #[test]
    fn un_soggetto_si_chiude_resta_e_non_si_riapre() {
        let (database, _, _) = database_with_session();
        let Ok(id) = database.insert_person(
            &soggetto("Soggetto A"),
            &actor("operatore.prova"),
            istante(ORA),
        ) else {
            panic!("il soggetto deve potersi aprire");
        };

        let Ok(()) = database.close_person(
            id,
            &actor("altro.operatore"),
            &ragione("archiviato: nessun elemento utile emerso dal monitoraggio"),
            istante(ORA + 100),
        ) else {
            panic!("la chiusura deve riuscire");
        };

        let Ok(letto) = database.person(id) else {
            panic!("il soggetto chiuso deve restare leggibile");
        };
        assert!(!letto.is_open());
        let Some(chiusura) = letto.closure.as_ref() else {
            panic!("la chiusura deve esserci");
        };
        assert_eq!(chiusura.by.as_str(), "altro.operatore");
        assert!(chiusura.reason.as_str().contains("archiviato"));

        // NON SI CHIUDE DUE VOLTE.
        assert!(
            database
                .close_person(
                    id,
                    &actor("terzo.operatore"),
                    &ragione("un secondo motivo lungo abbastanza da essere accettato"),
                    istante(ORA + 200),
                )
                .is_err()
        );

        // E NON SI RIAPRE.
        assert!(
            database
                .connection
                .execute(
                    "UPDATE persons SET closed_by = NULL, closed_at = NULL,
                            closure_reason = NULL WHERE id = ?1",
                    [id.get()],
                )
                .is_err(),
            "riaprirlo renderebbe la chiusura una parentesi invece che un fatto"
        );
    }

    /// **L'archivio rifiuta una chiusura senza ragione.**
    #[test]
    fn l_archivio_rifiuta_una_chiusura_senza_ragione() {
        let (database, _, _) = database_with_session();
        let Ok(id) = database.insert_person(
            &soggetto("Soggetto A"),
            &actor("operatore.prova"),
            istante(ORA),
        ) else {
            panic!("il soggetto deve potersi aprire");
        };

        let esito = database.connection.execute(
            "UPDATE persons SET closed_by = 'x', closed_at = 1 WHERE id = ?1",
            [id.get()],
        );
        assert!(
            esito.is_err(),
            "una chiusura senza motivo non dice se il fascicolo sia stato chiuso perche' non \
             c'era niente o perche' nessuno se ne occupava piu'"
        );
    }

    /// **I soggetti chiusi restano nell'elenco.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un elenco che nasconde i fascicoli chiusi. Direbbe che nessuno ha mai
    /// aperto un fascicolo su quella persona, e chi rilegge non avrebbe modo di
    /// accorgersene.
    #[test]
    fn i_soggetti_chiusi_restano_nell_elenco() {
        let (database, _, _) = database_with_session();
        let Ok(id) = database.insert_person(
            &soggetto("Soggetto A"),
            &actor("operatore.prova"),
            istante(ORA),
        ) else {
            panic!("il soggetto deve potersi aprire");
        };
        let Ok(()) = database.close_person(
            id,
            &actor("operatore.prova"),
            &ragione("archiviato: nessun elemento utile emerso dal monitoraggio"),
            istante(ORA + 100),
        ) else {
            panic!("la chiusura deve riuscire");
        };

        let Ok(elenco) = database.persons() else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(elenco.len(), 1, "il soggetto chiuso resta");
        assert!(!elenco[0].is_open());
    }

    /// **Leggere un soggetto che non c'è lo dichiara.**
    #[test]
    fn leggere_un_soggetto_che_non_c_e_lo_dichiara() {
        let (database, _, _) = database_with_session();
        assert!(database.person(PersonId::new(999)).is_err());
    }

    /// **Questo modulo non sa costruire un soggetto da un'osservazione.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Il solo che la Fase 6 nomina nella propria intestazione: «non si crea un
    /// profilo per ogni utente Telegram solo perché compare in una fonte
    /// monitorata».
    ///
    /// Una funzione che legga gli autori e ne apra i soggetti sembrerebbe una
    /// comodità, e sarebbe l'esatto contrario di ciò che il prodotto promette.
    #[test]
    fn questo_modulo_non_sa_costruire_un_soggetto_da_una_osservazione() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let codice: String = produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        for osservazione in [
            "FROM contents",
            "author",
            "Participant",
            "session_id",
            "remote_message_id",
        ] {
            assert!(
                !codice.contains(osservazione),
                "il modulo nomina «{osservazione}»: un soggetto si apre perche' qualcuno lo \
                 decide, non perche' qualcuno ha scritto in un gruppo"
            );
        }
    }
}

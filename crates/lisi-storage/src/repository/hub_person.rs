//! Le persone dell'ufficio, dal lato dell'Hub (TEAM-ASSIGN-01, ADR-0097).
//!
//! # Che cosa esce di qui
//!
//! Una [`Person`] e, **separatamente**, il verificatore. Sono due letture
//! diverse apposta: la prima serve a mostrare un elenco, la seconda serve solo
//! a chi sta verificando una frase in quell'istante. Portarli insieme
//! significherebbe far girare per il programma un valore da cui si provano le
//! frasi offline, in ogni posto in cui serve un nome.

use lisi_core::Timestamp;
use lisi_core::model::hub_access::HubRole;
use lisi_core::model::hub_person::{
    MAX_PERSON_ID_CHARS, PassphraseVerifier, Person, PersonId, PersonState,
};
use lisi_core::text::DisplayName;
use rusqlite::{OptionalExtension, params};

use crate::database::Database;
use crate::error::{StorageError, StorageResult};
use crate::repository::millis;

/// Una persona da creare.
#[derive(Debug)]
pub struct NewPerson<'dati> {
    /// Come si chiamerà negli atti.
    pub id: &'dati PersonId,
    /// Come la chiama l'ufficio.
    pub label: &'dati DisplayName,
    /// Che cosa le è consentito.
    pub role: HubRole,
    /// Il verificatore della sua frase. **Mai la frase.**
    pub verifier: &'dati PassphraseVerifier,
    /// Chi l'ha creata.
    pub created_by: &'dati str,
    /// Quando.
    pub created_at: Timestamp,
}

impl Database {
    /// Registra una persona.
    ///
    /// # Errori
    ///
    /// [`StorageError::DuplicatePerson`] se l'identificativo è già in uso, o un
    /// errore di scrittura.
    pub fn insert_hub_person(&self, person: &NewPerson<'_>) -> StorageResult<()> {
        let inserite = self
            .connection
            .execute(
                "INSERT OR IGNORE INTO hub_people
                    (person_id, label, role, state, verifier, created_at, created_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    person.id.as_str(),
                    person.label.as_str(),
                    person.role.as_str(),
                    PersonState::Active.as_str(),
                    person.verifier.as_str(),
                    millis(person.created_at),
                    person.created_by,
                ],
            )
            .map_err(StorageError::Sqlite)?;
        if inserite == 0 {
            return Err(StorageError::DuplicatePerson);
        }
        Ok(())
    }

    /// Una persona, se esiste.
    ///
    /// # Errori
    ///
    /// Un errore di lettura, o se una riga conservata non è interpretabile.
    pub fn hub_person(&self, id: &PersonId) -> StorageResult<Option<Person>> {
        let riga = self
            .connection
            .query_row(
                "SELECT person_id, label, role, state, created_at
                   FROM hub_people WHERE person_id = ?1",
                params![id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(StorageError::Sqlite)?;

        let Some((identificativo, etichetta, ruolo, stato, creata)) = riga else {
            return Ok(None);
        };
        Ok(Some(Person {
            id: PersonId::parse(&identificativo)?,
            label: DisplayName::try_new(&etichetta)?,
            role: HubRole::parse(&ruolo)?,
            state: PersonState::parse(&stato)?,
            created_at: Timestamp::from_millis(creata),
        }))
    }

    /// Il verificatore di una persona, se esiste.
    ///
    /// Lettura separata apposta: vedere la nota del modulo.
    ///
    /// # Errori
    ///
    /// Un errore di lettura, o se il verificatore conservato non ha la forma
    /// prevista.
    pub fn hub_person_verifier(&self, id: &PersonId) -> StorageResult<Option<PassphraseVerifier>> {
        let conservato = self
            .connection
            .query_row(
                "SELECT verifier FROM hub_people WHERE person_id = ?1",
                params![id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(StorageError::Sqlite)?;

        let Some(conservato) = conservato else {
            return Ok(None);
        };
        Ok(Some(PassphraseVerifier::try_new(&conservato)?))
    }

    /// Le persone dell'ufficio, per identificativo.
    ///
    /// # Errori
    ///
    /// Un errore di lettura, o se una riga conservata non è interpretabile.
    pub fn hub_people(&self) -> StorageResult<Vec<Person>> {
        let mut statement = self.connection.prepare(
            "SELECT person_id, label, role, state, created_at
               FROM hub_people ORDER BY person_id ASC",
        )?;
        let righe = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;

        let mut persone = Vec::new();
        for riga in righe {
            let (identificativo, etichetta, ruolo, stato, creata) = riga?;
            persone.push(Person {
                id: PersonId::parse(&identificativo)?,
                label: DisplayName::try_new(&etichetta)?,
                role: HubRole::parse(&ruolo)?,
                state: PersonState::parse(&stato)?,
                created_at: Timestamp::from_millis(creata),
            });
        }
        Ok(persone)
    }

    /// Cambia lo stato di una persona.
    ///
    /// **Non cancella**: sospendere non è cancellare, e gli atti già compiuti
    /// restano suoi (ADR-0097, decisione 7).
    ///
    /// # Errori
    ///
    /// [`StorageError::NotFound`] se la persona non esiste.
    pub fn set_hub_person_state(&self, id: &PersonId, state: PersonState) -> StorageResult<()> {
        let cambiate = self
            .connection
            .execute(
                "UPDATE hub_people SET state = ?2 WHERE person_id = ?1",
                params![id.as_str(), state.as_str()],
            )
            .map_err(StorageError::Sqlite)?;
        if cambiate == 0 {
            return Err(StorageError::NotFound {
                entity: "persona dell'ufficio",
                id: 0,
            });
        }
        Ok(())
    }

    /// Rimette la frase di una persona.
    ///
    /// # Errori
    ///
    /// [`StorageError::NotFound`] se la persona non esiste.
    pub fn set_hub_person_verifier(
        &self,
        id: &PersonId,
        verifier: &PassphraseVerifier,
    ) -> StorageResult<()> {
        let cambiate = self
            .connection
            .execute(
                "UPDATE hub_people SET verifier = ?2 WHERE person_id = ?1",
                params![id.as_str(), verifier.as_str()],
            )
            .map_err(StorageError::Sqlite)?;
        if cambiate == 0 {
            return Err(StorageError::NotFound {
                entity: "persona dell'ufficio",
                id: 0,
            });
        }
        Ok(())
    }

    /// Se una persona esiste **ed è attiva**, dentro una transazione in corso.
    ///
    /// Serve all'assegnazione, che deve verificarla **nella stessa
    /// transazione** che scrive: verificarla prima lascerebbe una finestra in
    /// cui viene sospesa fra il controllo e la scrittura (ADR-0098,
    /// decisione 4).
    ///
    /// # Errori
    ///
    /// Un errore di lettura.
    pub fn hub_person_is_active_in(
        transaction: &rusqlite::Transaction<'_>,
        id: &str,
    ) -> StorageResult<bool> {
        if id.chars().count() > MAX_PERSON_ID_CHARS {
            return Ok(false);
        }
        let stato: Option<String> = transaction
            .query_row(
                "SELECT state FROM hub_people WHERE person_id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()
            .map_err(StorageError::Sqlite)?;
        Ok(stato.as_deref() == Some(PersonState::Active.as_str()))
    }
}

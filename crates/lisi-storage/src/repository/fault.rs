//! Errori operativi.

use core::str::FromStr;

use lisi_core::model::{Fault, FaultKind, NewFault};
use lisi_core::text::FaultMessage;
use lisi_core::{FaultId, SessionId, SourceId};
use rusqlite::Row;

use crate::database::Database;
use crate::error::{ConstraintKind, StorageError, StorageResult, constraint_kind};
use crate::repository::{instant, millis};

/// Riga grezza della tabella `faults`.
struct FaultRow {
    id: i64,
    session_id: Option<i64>,
    source_id: Option<i64>,
    kind: String,
    message: String,
    occurred_at: i64,
}

impl FaultRow {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            session_id: row.get(1)?,
            source_id: row.get(2)?,
            kind: row.get(3)?,
            message: row.get(4)?,
            occurred_at: row.get(5)?,
        })
    }

    fn into_domain(self) -> StorageResult<Fault> {
        Ok(Fault {
            id: FaultId::new(self.id),
            session_id: self.session_id.map(SessionId::new),
            source_id: self.source_id.map(SourceId::new),
            kind: FaultKind::from_str(&self.kind)?,
            message: FaultMessage::try_new(&self.message)?,
            occurred_at: instant(self.occurred_at),
        })
    }
}

impl Database {
    /// Registra un errore operativo.
    ///
    /// Un errore che non lascia traccia rende lo storico ingannevole: un
    /// intervallo senza contenuti potrebbe voler dire che non è stato pubblicato
    /// nulla oppure che l'acquisizione era interrotta.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se la sessione o la fonte indicate
    /// non esistono.
    pub fn insert_fault(&self, fault: &NewFault) -> StorageResult<FaultId> {
        let id: i64 = self
            .connection
            .query_row(
                "INSERT INTO faults (session_id, source_id, kind, message, occurred_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 RETURNING id",
                rusqlite::params![
                    fault.session_id.map(SessionId::get),
                    fault.source_id.map(SourceId::get),
                    fault.kind.as_str(),
                    fault.message.as_str(),
                    millis(fault.occurred_at),
                ],
                |row| row.get(0),
            )
            .map_err(|error| {
                if constraint_kind(&error) == Some(ConstraintKind::ForeignKey) {
                    StorageError::NotFound {
                        entity: "sessione o fonte",
                        id: fault.session_id.map_or(-1, SessionId::get),
                    }
                } else {
                    StorageError::Sqlite(error)
                }
            })?;

        Ok(FaultId::new(id))
    }

    /// Errori registrati, dal più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// valore non conforme al dominio.
    pub fn faults(&self) -> StorageResult<Vec<Fault>> {
        let mut statement = self.connection.prepare(
            "SELECT id, session_id, source_id, kind, message, occurred_at
             FROM faults
             ORDER BY occurred_at DESC, id DESC",
        )?;

        let rows = statement.query_map([], FaultRow::read)?;

        let mut faults = Vec::new();
        for row in rows {
            faults.push(row?.into_domain()?);
        }
        Ok(faults)
    }

    /// Errori registrati durante una sessione, dal più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// valore non conforme al dominio.
    pub fn session_faults(&self, session_id: SessionId) -> StorageResult<Vec<Fault>> {
        let mut statement = self.connection.prepare(
            "SELECT id, session_id, source_id, kind, message, occurred_at
             FROM faults
             WHERE session_id = ?1
             ORDER BY occurred_at DESC, id DESC",
        )?;

        let rows = statement.query_map([session_id.get()], FaultRow::read)?;

        let mut faults = Vec::new();
        for row in rows {
            faults.push(row?.into_domain()?);
        }
        Ok(faults)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::{FaultKind, NewFault};
    use lisi_core::text::FaultMessage;
    use lisi_core::{SessionId, SourceId};

    use crate::error::StorageError;
    use crate::test_support::{database, database_with_session, later};

    fn new_fault(
        session_id: Option<SessionId>,
        source_id: Option<SourceId>,
        kind: FaultKind,
    ) -> NewFault {
        let Ok(message) = FaultMessage::try_new("Connessione interrotta durante l'acquisizione")
        else {
            panic!("il messaggio di prova deve essere valido");
        };

        NewFault {
            session_id,
            source_id,
            kind,
            message,
            occurred_at: later(15),
        }
    }

    #[test]
    fn a_fault_is_written_and_read_back_unchanged() {
        let (database, source_id, session_id) = database_with_session();

        let Ok(id) = database.insert_fault(&new_fault(
            Some(session_id),
            Some(source_id),
            FaultKind::Network,
        )) else {
            panic!("l'errore deve potersi registrare");
        };

        let Ok(faults) = database.session_faults(session_id) else {
            panic!("gli errori devono potersi leggere");
        };
        assert_eq!(faults.len(), 1);
        assert_eq!(faults[0].id, id);
        assert_eq!(faults[0].kind, FaultKind::Network);
        assert_eq!(faults[0].session_id, Some(session_id));
        assert_eq!(faults[0].source_id, Some(source_id));
        assert_eq!(faults[0].occurred_at, later(15));
    }

    #[test]
    fn a_fault_without_a_session_or_a_source_is_accepted() {
        let database = database();

        let Ok(_) = database.insert_fault(&new_fault(None, None, FaultKind::Internal)) else {
            panic!("un errore non riferito ad alcuna sessione deve potersi registrare");
        };

        let Ok(faults) = database.faults() else {
            panic!("gli errori devono potersi leggere");
        };
        assert_eq!(faults.len(), 1);
        assert_eq!(faults[0].session_id, None);
        assert_eq!(faults[0].source_id, None);
    }

    #[test]
    fn every_kind_is_accepted_by_the_schema() {
        let database = database();

        for kind in FaultKind::all() {
            let Ok(_) = database.insert_fault(&new_fault(None, None, *kind)) else {
                panic!("la natura {kind} deve essere ammessa dallo schema");
            };
        }

        assert_eq!(
            database.faults().map(|found| found.len()).ok(),
            Some(FaultKind::all().len())
        );
    }

    #[test]
    fn a_fault_on_a_missing_session_is_refused() {
        let database = database();
        assert!(matches!(
            database.insert_fault(&new_fault(
                Some(SessionId::new(404)),
                None,
                FaultKind::Storage
            )),
            Err(StorageError::NotFound { .. })
        ));
    }

    #[test]
    fn the_faults_of_another_session_are_not_returned() {
        let (database, _source_id, session_id) = database_with_session();
        let Ok(_) = database.insert_fault(&new_fault(Some(session_id), None, FaultKind::Analysis))
        else {
            panic!("l'errore deve potersi registrare");
        };

        assert_eq!(
            database
                .session_faults(SessionId::new(999))
                .map(|found| found.len())
                .ok(),
            Some(0)
        );
    }
}

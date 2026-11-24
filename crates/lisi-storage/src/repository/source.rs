//! Fonti monitorate.

use core::str::FromStr;

use lisi_core::model::{NewSource, Source, SourceKind};
use lisi_core::text::{Actor, DisplayName, SourceIdentifier};
use lisi_core::{SourceId, Timestamp};
use rusqlite::{OptionalExtension, Row};

use crate::database::Database;
use crate::error::{ConstraintKind, StorageError, StorageResult, classify};
use crate::repository::{instant, millis};

/// Riga grezza della tabella `sources`.
struct SourceRow {
    id: i64,
    kind: String,
    identifier: String,
    display_name: String,
    authorized_by: String,
    active: bool,
    created_at: i64,
    updated_at: i64,
}

impl SourceRow {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            kind: row.get(1)?,
            identifier: row.get(2)?,
            display_name: row.get(3)?,
            authorized_by: row.get(4)?,
            active: row.get(5)?,
            created_at: row.get(6)?,
            updated_at: row.get(7)?,
        })
    }

    fn into_domain(self) -> StorageResult<Source> {
        Ok(Source {
            id: SourceId::new(self.id),
            kind: SourceKind::from_str(&self.kind)?,
            identifier: SourceIdentifier::try_new(&self.identifier)?,
            display_name: DisplayName::try_new(&self.display_name)?,
            authorized_by: Actor::try_new(&self.authorized_by)?,
            active: self.active,
            created_at: instant(self.created_at),
            updated_at: instant(self.updated_at),
        })
    }
}

impl Database {
    /// Registra una fonte.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::DuplicateSource`] se una fonte con lo stesso
    /// tipo e identificativo è già presente.
    pub fn insert_source(&self, source: &NewSource, now: Timestamp) -> StorageResult<SourceId> {
        let id: i64 = self
            .connection
            .query_row(
                "INSERT INTO sources (
                     kind, identifier, display_name, authorized_by, active, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 RETURNING id",
                rusqlite::params![
                    source.kind.as_str(),
                    source.identifier.as_str(),
                    source.display_name.as_str(),
                    source.authorized_by.as_str(),
                    source.active,
                    millis(now),
                    millis(now),
                ],
                |row| row.get(0),
            )
            .map_err(|error| {
                classify(error, ConstraintKind::Unique, StorageError::DuplicateSource)
            })?;

        Ok(SourceId::new(id))
    }

    /// Legge una fonte.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se la fonte non esiste.
    pub fn source(&self, id: SourceId) -> StorageResult<Source> {
        let row = self
            .connection
            .query_row(
                "SELECT id, kind, identifier, display_name, authorized_by, active,
                        created_at, updated_at
                 FROM sources
                 WHERE id = ?1",
                [id.get()],
                SourceRow::read,
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound {
                    entity: "fonte",
                    id: id.get(),
                },
                other => StorageError::Sqlite(other),
            })?;

        row.into_domain()
    }

    /// Elenca tutte le fonti, ordinate per nome visualizzato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// valore non conforme al dominio.
    pub fn sources(&self) -> StorageResult<Vec<Source>> {
        let mut statement = self.connection.prepare(
            "SELECT id, kind, identifier, display_name, authorized_by, active,
                    created_at, updated_at
             FROM sources
             ORDER BY display_name, id",
        )?;

        let rows = statement.query_map([], SourceRow::read)?;

        let mut sources = Vec::new();
        for row in rows {
            sources.push(row?.into_domain()?);
        }
        Ok(sources)
    }

    /// Attiva o disattiva una fonte.
    ///
    /// Le fonti non si cancellano: una fonte già usata in una sessione deve
    /// restare leggibile per lo storico. Disattivarla la esclude dalle nuove
    /// sessioni senza intaccare quelle passate.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se la fonte non esiste.
    pub fn set_source_active(
        &self,
        id: SourceId,
        active: bool,
        now: Timestamp,
    ) -> StorageResult<()> {
        let updated = self.connection.execute(
            "UPDATE sources SET active = ?2, updated_at = ?3 WHERE id = ?1",
            rusqlite::params![id.get(), active, millis(now)],
        )?;

        if updated == 0 {
            return Err(StorageError::NotFound {
                entity: "fonte",
                id: id.get(),
            });
        }
        Ok(())
    }

    /// Se la fonte è stata selezionata da almeno una sessione.
    ///
    /// Serve a distinguere una fonte configurata per errore, che si può
    /// rimuovere davvero, da una che ha già partecipato a un monitoraggio e la
    /// cui cancellazione renderebbe lo storico non più interpretabile.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn source_is_used(&self, id: SourceId) -> StorageResult<bool> {
        let count: i64 = self.connection.query_row(
            "SELECT count(*) FROM session_sources WHERE source_id = ?1",
            [id.get()],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Rimuove una fonte mai usata in alcuna sessione.
    ///
    /// Una fonte già usata **non** viene cancellata: la foreign key la
    /// protegge, e cancellarla renderebbe lo storico non interpretabile.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se la fonte non esiste e
    /// [`StorageError::SourceStillInUse`] se è stata usata in una sessione.
    pub fn delete_unused_source(&self, id: SourceId) -> StorageResult<()> {
        if self.source_is_used(id)? {
            return Err(StorageError::SourceStillInUse);
        }

        let removed = self
            .connection
            .execute("DELETE FROM sources WHERE id = ?1", [id.get()])
            .map_err(|error| {
                classify(
                    error,
                    ConstraintKind::ForeignKey,
                    StorageError::SourceStillInUse,
                )
            })?;

        if removed == 0 {
            return Err(StorageError::NotFound {
                entity: "fonte",
                id: id.get(),
            });
        }
        Ok(())
    }

    /// Cerca una fonte per tipo e identificativo.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se la riga contiene un
    /// valore non conforme al dominio.
    pub fn find_source(&self, kind: SourceKind, identifier: &str) -> StorageResult<Option<Source>> {
        let row = self
            .connection
            .query_row(
                "SELECT id, kind, identifier, display_name, authorized_by, active,
                        created_at, updated_at
                 FROM sources
                 WHERE kind = ?1 AND identifier = ?2",
                rusqlite::params![kind.as_str(), identifier],
                SourceRow::read,
            )
            .optional()?;

        row.map(SourceRow::into_domain).transpose()
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::SourceKind;
    use lisi_core::{SourceId, Timestamp};

    use crate::error::StorageError;
    use crate::test_support::{database, new_source, now};

    #[test]
    fn a_source_is_written_and_read_back_unchanged() {
        let database = database();
        let new = new_source("canale_uno");

        let Ok(id) = database.insert_source(&new, now()) else {
            panic!("la fonte deve potersi registrare");
        };
        let Ok(source) = database.source(id) else {
            panic!("la fonte deve potersi rileggere");
        };

        assert_eq!(source.id, id);
        assert_eq!(source.kind, new.kind);
        assert_eq!(source.identifier, new.identifier);
        assert_eq!(source.display_name, new.display_name);
        assert_eq!(source.authorized_by, new.authorized_by);
        assert!(source.active);
        assert_eq!(source.created_at, now());
        assert_eq!(source.updated_at, now());
    }

    #[test]
    fn the_same_identifier_cannot_be_registered_twice_for_the_same_kind() {
        let database = database();
        let new = new_source("canale_uno");

        let Ok(_) = database.insert_source(&new, now()) else {
            panic!("la prima registrazione deve riuscire");
        };

        assert!(matches!(
            database.insert_source(&new, now()),
            Err(StorageError::DuplicateSource)
        ));
    }

    #[test]
    fn the_same_identifier_is_allowed_for_a_different_kind() {
        let database = database();
        let mut group = new_source("canale_uno");
        group.kind = SourceKind::Group;

        let Ok(_) = database.insert_source(&new_source("canale_uno"), now()) else {
            panic!("la prima registrazione deve riuscire");
        };
        assert!(database.insert_source(&group, now()).is_ok());
    }

    #[test]
    fn a_missing_source_is_reported_as_not_found() {
        let database = database();
        assert!(matches!(
            database.source(SourceId::new(404)),
            Err(StorageError::NotFound {
                entity: "fonte",
                id: 404
            })
        ));
    }

    #[test]
    fn a_source_can_be_deactivated_without_being_removed() {
        let database = database();
        let Ok(id) = database.insert_source(&new_source("canale_uno"), now()) else {
            panic!("la fonte deve potersi registrare");
        };

        let later = Timestamp::from_millis(now().as_millis() + 1_000);
        let Ok(()) = database.set_source_active(id, false, later) else {
            panic!("la disattivazione deve riuscire");
        };

        let Ok(source) = database.source(id) else {
            panic!("la fonte deve restare leggibile");
        };
        assert!(!source.active);
        assert_eq!(source.updated_at, later);
    }

    #[test]
    fn deactivating_a_missing_source_is_reported_as_not_found() {
        let database = database();
        assert!(matches!(
            database.set_source_active(SourceId::new(404), false, now()),
            Err(StorageError::NotFound { .. })
        ));
    }

    #[test]
    fn sources_are_listed_in_a_stable_order() {
        let database = database();
        for identifier in ["canale_uno", "canale_due", "canale_tre"] {
            let Ok(_) = database.insert_source(&new_source(identifier), now()) else {
                panic!("le fonti di prova devono potersi registrare");
            };
        }

        let Ok(sources) = database.sources() else {
            panic!("l'elenco deve potersi leggere");
        };
        assert_eq!(sources.len(), 3);

        let identifiers: Vec<&str> = sources
            .iter()
            .map(|source| source.identifier.as_str())
            .collect();
        assert_eq!(identifiers, ["canale_uno", "canale_due", "canale_tre"]);
    }

    #[test]
    fn a_source_identifier_with_sql_metacharacters_is_stored_verbatim() {
        let database = database();
        let hostile = "'; DROP TABLE sources; --";
        let new = new_source(hostile);

        let Ok(id) = database.insert_source(&new, now()) else {
            panic!("l'identificativo ostile deve essere trattato come dato");
        };
        let Ok(source) = database.source(id) else {
            panic!("la fonte deve potersi rileggere");
        };

        assert_eq!(source.identifier.as_str(), hostile);
        let Ok(sources) = database.sources() else {
            panic!("la tabella deve esistere ancora");
        };
        assert_eq!(sources.len(), 1);
    }
}

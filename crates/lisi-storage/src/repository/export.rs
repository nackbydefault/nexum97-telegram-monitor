//! Export prodotti.

use core::str::FromStr;

use lisi_core::digest::Sha256Digest;
use lisi_core::model::{Export, ExportFormat, NewExport};
use lisi_core::text::{Actor, ExportPath};
use lisi_core::{ExportId, SessionId};
use rusqlite::Row;

use crate::database::Database;
use crate::error::{ConstraintKind, StorageError, StorageResult, constraint_kind};
use crate::repository::{instant, millis};

/// Riga grezza della tabella `exports`.
struct ExportRow {
    id: i64,
    session_id: i64,
    format: String,
    path: String,
    sha256: String,
    requested_by: String,
    created_at: i64,
}

impl ExportRow {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            session_id: row.get(1)?,
            format: row.get(2)?,
            path: row.get(3)?,
            sha256: row.get(4)?,
            requested_by: row.get(5)?,
            created_at: row.get(6)?,
        })
    }

    fn into_domain(self) -> StorageResult<Export> {
        Ok(Export {
            id: ExportId::new(self.id),
            session_id: SessionId::new(self.session_id),
            format: ExportFormat::from_str(&self.format)?,
            path: ExportPath::try_new(&self.path)?,
            sha256: Sha256Digest::from_hex(&self.sha256)?,
            requested_by: Actor::try_new(&self.requested_by)?,
            created_at: instant(self.created_at),
        })
    }
}

impl Database {
    /// Registra un export prodotto.
    ///
    /// L'impronta del file è conservata insieme al percorso: serve a verificare
    /// in seguito che il documento consegnato sia esattamente quello generato.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se la sessione non esiste.
    pub fn insert_export(&self, export: &NewExport) -> StorageResult<ExportId> {
        let id: i64 = self
            .connection
            .query_row(
                "INSERT INTO exports (
                     session_id, format, path, sha256, requested_by, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 RETURNING id",
                rusqlite::params![
                    export.session_id.get(),
                    export.format.as_str(),
                    export.path.as_str(),
                    export.sha256.as_str(),
                    export.requested_by.as_str(),
                    millis(export.created_at),
                ],
                |row| row.get(0),
            )
            .map_err(|error| {
                if constraint_kind(&error) == Some(ConstraintKind::ForeignKey) {
                    StorageError::NotFound {
                        entity: "sessione",
                        id: export.session_id.get(),
                    }
                } else {
                    StorageError::Sqlite(error)
                }
            })?;

        Ok(ExportId::new(id))
    }

    /// Export di una sessione, dal più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// valore non conforme al dominio.
    pub fn session_exports(&self, session_id: SessionId) -> StorageResult<Vec<Export>> {
        let mut statement = self.connection.prepare(
            "SELECT id, session_id, format, path, sha256, requested_by, created_at
             FROM exports
             WHERE session_id = ?1
             ORDER BY created_at DESC, id DESC",
        )?;

        let rows = statement.query_map([session_id.get()], ExportRow::read)?;

        let mut exports = Vec::new();
        for row in rows {
            exports.push(row?.into_domain()?);
        }
        Ok(exports)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::SessionId;
    use lisi_core::digest::Sha256Digest;
    use lisi_core::model::{ExportFormat, NewExport};
    use lisi_core::text::ExportPath;

    use crate::error::StorageError;
    use crate::test_support::{actor, database_with_session, later};

    fn new_export(session_id: SessionId, format: ExportFormat) -> NewExport {
        let Ok(path) = ExportPath::try_new(&format!(
            "C:\\Users\\operatore\\Documenti\\sessione.{}",
            format.extension()
        )) else {
            panic!("il percorso di prova deve essere valido");
        };

        NewExport {
            session_id,
            format,
            path,
            sha256: Sha256Digest::of_text("contenuto del documento"),
            requested_by: actor("operatore.prova"),
            created_at: later(120),
        }
    }

    #[test]
    fn an_export_is_written_and_read_back_unchanged() {
        let (database, _source_id, session_id) = database_with_session();

        let Ok(id) = database.insert_export(&new_export(session_id, ExportFormat::Pdf)) else {
            panic!("l'export deve potersi registrare");
        };

        let Ok(exports) = database.session_exports(session_id) else {
            panic!("gli export devono potersi leggere");
        };
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].id, id);
        assert_eq!(exports[0].format, ExportFormat::Pdf);
        assert_eq!(
            exports[0].sha256,
            Sha256Digest::of_text("contenuto del documento")
        );
        assert_eq!(exports[0].created_at, later(120));
    }

    #[test]
    fn every_format_is_accepted_by_the_schema() {
        let (database, _source_id, session_id) = database_with_session();

        for format in ExportFormat::all() {
            let Ok(_) = database.insert_export(&new_export(session_id, *format)) else {
                panic!("il formato {format} deve essere ammesso dallo schema");
            };
        }

        assert_eq!(
            database.session_exports(session_id).map(|e| e.len()).ok(),
            Some(ExportFormat::all().len())
        );
    }

    #[test]
    fn an_export_on_a_missing_session_is_refused() {
        let (database, _source_id, _session_id) = database_with_session();
        assert!(matches!(
            database.insert_export(&new_export(SessionId::new(404), ExportFormat::Txt)),
            Err(StorageError::NotFound {
                entity: "sessione",
                id: 404
            })
        ));
    }

    #[test]
    fn a_windows_path_with_backslashes_is_stored_verbatim() {
        let (database, _source_id, session_id) = database_with_session();
        let export = new_export(session_id, ExportFormat::Xlsx);
        let expected = export.path.as_str().to_owned();

        let Ok(_) = database.insert_export(&export) else {
            panic!("l'export deve potersi registrare");
        };

        let Ok(exports) = database.session_exports(session_id) else {
            panic!("gli export devono potersi leggere");
        };
        assert_eq!(exports[0].path.as_str(), expected);
        assert!(expected.contains('\\'));
    }
}

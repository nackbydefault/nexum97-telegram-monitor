//! A chi è il lavoro, dal lato dell'Hub (TEAM-ASSIGN-01, ADR-0098).
//!
//! # Due tabelle, due domande
//!
//! `hub_assignments` risponde a «di chi è **adesso**», e si sovrascrive.
//! `hub_assignment_log` risponde a «come ci si è arrivati», ed è append-only.
//!
//! Senza la prima, ogni riga della coda costringerebbe a rileggere tutta la
//! storia. Senza la seconda, una riassegnazione cancellerebbe chi ce l'aveva
//! prima, e **«revocato» non si distinguerebbe da «mai assegnato»**.
//!
//! # La versione è quanti cambi sono stati fatti
//!
//! Si conta dal registro, come la versione della revisione si conta dalle
//! revisioni (ADR-0094): cresce di uno a ogni cambio, e la concorrenza
//! ottimistica di ADR-0089 ci si appoggia senza aggiungere colonne.

use std::collections::BTreeMap;

use lisi_core::model::hub_person::PersonId;
use lisi_core::{ContentId, Timestamp};
use rusqlite::{OptionalExtension, params};

use crate::database::Database;
use crate::error::{StorageError, StorageResult};
use crate::repository::millis;

/// A chi è un contenuto, e da quando.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentRow {
    /// A chi, oppure a nessuno dopo una revoca.
    pub assigned_to: Option<PersonId>,
    /// Chi ha deciso: `persona.<id>` o `postazione.<id>`.
    pub decided_by: String,
    /// Quando.
    pub decided_at: Timestamp,
}

impl Database {
    /// A chi è un contenuto adesso, se qualcuno ci ha mai messo mano.
    ///
    /// # Errori
    ///
    /// Un errore di lettura, o se una riga conservata non è interpretabile.
    pub fn hub_assignment(&self, content_id: ContentId) -> StorageResult<Option<AssignmentRow>> {
        let riga = self
            .connection
            .query_row(
                "SELECT assigned_to, decided_by, decided_at
                   FROM hub_assignments WHERE content_id = ?1",
                params![content_id.get()],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(StorageError::Sqlite)?;

        let Some((a_chi, da_chi, quando)) = riga else {
            return Ok(None);
        };
        Ok(Some(AssignmentRow {
            assigned_to: a_chi.as_deref().map(PersonId::parse).transpose()?,
            decided_by: da_chi,
            decided_at: Timestamp::from_millis(quando),
        }))
    }

    /// Quanti cambi di assegnazione ha avuto un contenuto.
    ///
    /// # Errori
    ///
    /// Un errore di lettura.
    pub fn hub_assignment_version(&self, content_id: ContentId) -> StorageResult<u64> {
        let quanti: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM hub_assignment_log WHERE content_id = ?1",
                params![content_id.get()],
                |row| row.get(0),
            )
            .map_err(StorageError::Sqlite)?;
        Ok(u64::try_from(quanti).unwrap_or_default())
    }

    /// A chi sono i contenuti indicati, per quelli che hanno un'assegnazione
    /// viva.
    ///
    /// Una lettura sola per una pagina della coda: una per riga
    /// moltiplicherebbe le interrogazioni per il numero di righe mostrate.
    ///
    /// # Errori
    ///
    /// Un errore di lettura, o se una riga conservata non è interpretabile.
    pub fn hub_assignments_of(
        &self,
        contents: &[ContentId],
    ) -> StorageResult<BTreeMap<i64, PersonId>> {
        let mut assegnati = BTreeMap::new();
        if contents.is_empty() {
            return Ok(assegnati);
        }

        // I segnaposto si compongono dal numero di elementi, non dai valori:
        // gli identificativi restano parametri legati.
        let segnaposto = (1..=contents.len())
            .map(|indice| format!("?{indice}"))
            .collect::<Vec<_>>()
            .join(", ");
        let query = format!(
            "SELECT content_id, assigned_to FROM hub_assignments
              WHERE assigned_to IS NOT NULL AND content_id IN ({segnaposto})"
        );
        let mut statement = self.connection.prepare(&query)?;
        let valori: Vec<i64> = contents.iter().map(|contenuto| contenuto.get()).collect();
        let righe = statement.query_map(rusqlite::params_from_iter(valori), |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;

        for riga in righe {
            let (contenuto, persona) = riga?;
            assegnati.insert(contenuto, PersonId::parse(&persona)?);
        }
        Ok(assegnati)
    }

    /// Scrive un cambio di assegnazione, dentro una transazione in corso.
    ///
    /// Scrive **il fatto e la sua storia** nella stessa transazione: se una
    /// delle due mancasse, la versione non corrisponderebbe più a ciò che la
    /// riga dice.
    ///
    /// # Errori
    ///
    /// [`StorageError::NotFound`] se il contenuto non esiste, o un errore di
    /// scrittura.
    pub fn set_hub_assignment_in(
        transaction: &rusqlite::Transaction<'_>,
        content_id: ContentId,
        assigned_to: Option<&str>,
        decided_by: &str,
        decided_at: Timestamp,
    ) -> StorageResult<()> {
        transaction
            .execute(
                "INSERT INTO hub_assignment_log (content_id, assigned_to, decided_by, decided_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    content_id.get(),
                    assigned_to,
                    decided_by,
                    millis(decided_at)
                ],
            )
            .map_err(|errore| match errore {
                rusqlite::Error::SqliteFailure(codice, _)
                    if codice.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    StorageError::NotFound {
                        entity: "contenuto",
                        id: content_id.get(),
                    }
                }
                altro => StorageError::Sqlite(altro),
            })?;

        transaction
            .execute(
                "INSERT INTO hub_assignments (content_id, assigned_to, decided_by, decided_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (content_id) DO UPDATE SET
                    assigned_to = excluded.assigned_to,
                    decided_by = excluded.decided_by,
                    decided_at = excluded.decided_at",
                params![
                    content_id.get(),
                    assigned_to,
                    decided_by,
                    millis(decided_at)
                ],
            )
            .map_err(StorageError::Sqlite)?;
        Ok(())
    }

    /// Quanti cambi ha avuto un contenuto, dentro una transazione in corso.
    ///
    /// # Errori
    ///
    /// Un errore di lettura.
    pub fn hub_assignment_version_in(
        transaction: &rusqlite::Transaction<'_>,
        content_id: ContentId,
    ) -> StorageResult<u64> {
        let quanti: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM hub_assignment_log WHERE content_id = ?1",
                params![content_id.get()],
                |row| row.get(0),
            )
            .map_err(StorageError::Sqlite)?;
        Ok(u64::try_from(quanti).unwrap_or_default())
    }

    /// A chi è un contenuto, dentro una transazione in corso.
    ///
    /// # Errori
    ///
    /// Un errore di lettura.
    pub fn hub_assigned_to_in(
        transaction: &rusqlite::Transaction<'_>,
        content_id: ContentId,
    ) -> StorageResult<Option<String>> {
        let a_chi: Option<Option<String>> = transaction
            .query_row(
                "SELECT assigned_to FROM hub_assignments WHERE content_id = ?1",
                params![content_id.get()],
                |row| row.get(0),
            )
            .optional()
            .map_err(StorageError::Sqlite)?;
        Ok(a_chi.flatten())
    }
}

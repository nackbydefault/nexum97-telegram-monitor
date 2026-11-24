//! La pianificazione delle copie di sicurezza e il registro dei suoi tentativi
//! (BACKUP-SCHEDULE-01, ADR-0191, migrazione 0086).
//!
//! Ogni scrittura porta la sua riga d'audit nella stessa transazione. Il
//! registro dice i nomi delle copie, mai la cartella.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::text::Actor;
use rusqlite::{OptionalExtension, Row};

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// La pianificazione della postazione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBackupSchedule {
    /// La cartella in cui escono le copie.
    pub destination: String,
    /// Ogni quanti giorni.
    pub interval_days: u32,
    /// Quante copie pianificate tenere.
    pub keep: u32,
}

/// Un tentativo da registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewScheduledBackup {
    /// Quando.
    pub attempted_at: Timestamp,
    /// `riuscita` o `fallita`.
    pub outcome: String,
    /// Il nome della copia scritta.
    pub file_name: Option<String>,
    /// Perché no, o che cosa si sa.
    pub detail: Option<String>,
}

/// Un tentativo registrato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredScheduledBackup {
    /// L'identificativo della riga.
    pub id: i64,
    /// Il tentativo.
    pub attempt: NewScheduledBackup,
    /// Quando la conservazione ha tolto la copia, se l'ha tolta.
    pub removed_at: Option<Timestamp>,
}

impl StoredScheduledBackup {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            attempt: NewScheduledBackup {
                attempted_at: instant(row.get(1)?),
                outcome: row.get(2)?,
                file_name: row.get(3)?,
                detail: row.get(4)?,
            },
            removed_at: row.get::<_, Option<i64>>(5)?.map(instant),
        })
    }
}

/// L'esito di una copia riuscita, come lo conserva lo schema.
const RIUSCITA: &str = "riuscita";

const COLONNE: &str = "id, attempted_at, outcome, file_name, detail, removed_at";

fn scrivi_audit(
    transazione: &rusqlite::Transaction<'_>,
    audit: &NewAuditEntry,
    entity_id: Option<i64>,
) -> rusqlite::Result<usize> {
    transazione.execute(
        "INSERT INTO audit (actor, action, entity, entity_id, detail, recorded_at, actor_mode)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            audit.actor.as_str(),
            audit.action.as_str(),
            audit.entity.as_str(),
            entity_id,
            audit
                .detail
                .as_ref()
                .map(|dettaglio| dettaglio.as_str().to_owned()),
            millis(audit.recorded_at),
            audit.actor_mode.map(|modo| modo.as_str()),
        ],
    )
}

impl Database {
    /// La pianificazione, se accesa.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn backup_schedule(&self) -> StorageResult<Option<StoredBackupSchedule>> {
        let (cartella, giorni, quante) = self.connection.query_row(
            "SELECT destination, interval_days, keep FROM backup_schedule WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            },
        )?;
        Ok(match (cartella, giorni, quante) {
            (Some(destination), Some(giorni), Some(quante)) => Some(StoredBackupSchedule {
                destination,
                interval_days: u32::try_from(giorni).unwrap_or(1),
                keep: u32::try_from(quante).unwrap_or(1),
            }),
            _ => None,
        })
    }

    /// Accende, cambia o spegne la pianificazione, con la sua riga d'audit.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se i valori non rispettano lo schema o la
    /// scrittura non riesce: in quel caso non cambia niente.
    pub fn save_backup_schedule(
        &mut self,
        schedule: Option<&StoredBackupSchedule>,
        actor: &Actor,
        audit: &NewAuditEntry,
    ) -> StorageResult<()> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "UPDATE backup_schedule
             SET destination = ?1, interval_days = ?2, keep = ?3, updated_at = ?4, updated_by = ?5
             WHERE id = 1",
            rusqlite::params![
                schedule.map(|s| s.destination.as_str()),
                schedule.map(|s| i64::from(s.interval_days)),
                schedule.map(|s| i64::from(s.keep)),
                millis(audit.recorded_at),
                actor.as_str(),
            ],
        )?;
        scrivi_audit(&transazione, audit, None)?;
        transazione.commit()?;
        Ok(())
    }

    /// Registra un tentativo pianificato, con la sua riga d'audit.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la riga non rispetta lo schema o la scrittura
    /// non riesce: in quel caso non resta né la riga né l'audit.
    pub fn insert_scheduled_backup(
        &mut self,
        attempt: &NewScheduledBackup,
        audit: &NewAuditEntry,
    ) -> StorageResult<i64> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO scheduled_backups (attempted_at, outcome, file_name, detail)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                millis(attempt.attempted_at),
                attempt.outcome,
                attempt.file_name,
                attempt.detail,
            ],
        )?;
        let id = transazione.last_insert_rowid();
        scrivi_audit(&transazione, audit, Some(id))?;
        transazione.commit()?;
        Ok(id)
    }

    /// Dice che la conservazione ha tolto la copia di un tentativo riuscito.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la riga non c'è, è già segnata o non è una
    /// copia riuscita.
    pub fn mark_scheduled_backup_removed(
        &mut self,
        id: i64,
        audit: &NewAuditEntry,
    ) -> StorageResult<()> {
        let transazione = self.connection.transaction()?;
        let cambiate = transazione.execute(
            "UPDATE scheduled_backups SET removed_at = ?1
             WHERE id = ?2 AND outcome = ?3 AND removed_at IS NULL",
            rusqlite::params![millis(audit.recorded_at), id, RIUSCITA],
        )?;
        if cambiate != 1 {
            return Err(crate::error::StorageError::CorruptedRow {
                detail: "tentativo pianificato da togliere non trovato",
            });
        }
        scrivi_audit(&transazione, audit, Some(id))?;
        transazione.commit()?;
        Ok(())
    }

    /// I tentativi pianificati, i più recenti prima, al più `limit`.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn scheduled_backups(&self, limit: usize) -> StorageResult<Vec<StoredScheduledBackup>> {
        let mut richiesta = self.connection.prepare(&format!(
            "SELECT {COLONNE} FROM scheduled_backups
             ORDER BY attempted_at DESC, id DESC LIMIT ?1"
        ))?;
        let righe = richiesta.query_map(
            [i64::try_from(limit).unwrap_or(i64::MAX)],
            StoredScheduledBackup::read,
        )?;
        let mut tentativi = Vec::new();
        for riga in righe {
            tentativi.push(riga?);
        }
        Ok(tentativi)
    }

    /// Le copie pianificate riuscite e ancora non tolte, le più recenti prima.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn kept_scheduled_backups(&self) -> StorageResult<Vec<StoredScheduledBackup>> {
        let mut richiesta = self.connection.prepare(&format!(
            "SELECT {COLONNE} FROM scheduled_backups
             WHERE outcome = ?1 AND removed_at IS NULL
             ORDER BY attempted_at DESC, id DESC"
        ))?;
        let righe = richiesta.query_map([RIUSCITA], StoredScheduledBackup::read)?;
        let mut tentativi = Vec::new();
        for riga in righe {
            tentativi.push(riga?);
        }
        Ok(tentativi)
    }

    /// L'ultimo tentativo pianificato, se c'è.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn last_scheduled_backup(&self) -> StorageResult<Option<StoredScheduledBackup>> {
        Ok(self
            .connection
            .query_row(
                &format!(
                    "SELECT {COLONNE} FROM scheduled_backups
                     ORDER BY attempted_at DESC, id DESC LIMIT 1"
                ),
                [],
                StoredScheduledBackup::read,
            )
            .optional()?)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::NewAuditEntry;
    use lisi_core::text::{AuditAction, AuditDetail, AuditEntity};

    use super::{NewScheduledBackup, StoredBackupSchedule};
    use crate::test_support::{actor, database, later, now};

    fn audit(azione: &str) -> NewAuditEntry {
        let (Ok(azione), Ok(entita), Ok(dettaglio)) = (
            AuditAction::try_new(azione),
            AuditEntity::try_new("archivio"),
            AuditDetail::try_new("prova"),
        ) else {
            panic!("i valori dell'audit di prova devono essere validi");
        };
        NewAuditEntry {
            actor: actor("amministratore.prova"),
            action: azione,
            entity: entita,
            entity_id: None,
            actor_mode: None,
            detail: Some(dettaglio),
            recorded_at: now(),
        }
    }

    #[test]
    fn la_pianificazione_si_accende_e_si_spegne() {
        let mut database = database();
        assert_eq!(
            database.backup_schedule().ok(),
            Some(None),
            "spenta di fabbrica"
        );
        let pianificazione = StoredBackupSchedule {
            destination: String::from("D:\\copie"),
            interval_days: 7,
            keep: 4,
        };
        let Ok(()) = database.save_backup_schedule(
            Some(&pianificazione),
            &actor("amministratore.prova"),
            &audit("copie_pianificate_scelte"),
        ) else {
            panic!("la pianificazione si deve scrivere");
        };
        assert_eq!(database.backup_schedule().ok(), Some(Some(pianificazione)));
        let fuori = StoredBackupSchedule {
            destination: String::from("D:\\copie"),
            interval_days: 31,
            keep: 4,
        };
        assert!(
            database
                .save_backup_schedule(
                    Some(&fuori),
                    &actor("a"),
                    &audit("copie_pianificate_scelte")
                )
                .is_err()
        );
        let Ok(()) = database.save_backup_schedule(
            None,
            &actor("amministratore.prova"),
            &audit("copie_pianificate_scelte"),
        ) else {
            panic!("la pianificazione si deve spegnere");
        };
        assert_eq!(database.backup_schedule().ok(), Some(None));
    }

    #[test]
    fn i_tentativi_si_registrano_e_si_toglie_soltanto_una_copia_riuscita() {
        let mut database = database();
        let riuscita = NewScheduledBackup {
            attempted_at: now(),
            outcome: String::from("riuscita"),
            file_name: Some(String::from("copia-1.sqlite3")),
            detail: None,
        };
        let fallita = NewScheduledBackup {
            attempted_at: later(60),
            outcome: String::from("fallita"),
            file_name: None,
            detail: Some(String::from("la cartella non c'è")),
        };
        let (Ok(prima), Ok(seconda)) = (
            database.insert_scheduled_backup(&riuscita, &audit("copia_pianificata")),
            database.insert_scheduled_backup(&fallita, &audit("copia_pianificata_fallita")),
        ) else {
            panic!("i tentativi devono registrarsi");
        };
        let Ok(Some(ultimo)) = database.last_scheduled_backup() else {
            panic!("l'ultimo tentativo si deve leggere");
        };
        assert_eq!(ultimo.id, seconda);
        assert_eq!(
            database.kept_scheduled_backups().map(|v| v.len()).ok(),
            Some(1)
        );

        assert!(
            database
                .mark_scheduled_backup_removed(seconda, &audit("copia_pianificata_tolta"))
                .is_err(),
            "un fallimento non ha niente da togliere"
        );
        let Ok(()) =
            database.mark_scheduled_backup_removed(prima, &audit("copia_pianificata_tolta"))
        else {
            panic!("la copia si deve poter segnare tolta");
        };
        assert!(
            database
                .mark_scheduled_backup_removed(prima, &audit("copia_pianificata_tolta"))
                .is_err(),
            "si toglie una volta"
        );
        assert_eq!(
            database.kept_scheduled_backups().map(|v| v.len()).ok(),
            Some(0)
        );
        assert!(
            database
                .connection
                .execute("UPDATE scheduled_backups SET detail = 'altro'", [])
                .is_err()
        );
        assert!(
            database
                .connection
                .execute("DELETE FROM scheduled_backups", [])
                .is_err()
        );
        let Ok(tutti) = database.scheduled_backups(10) else {
            panic!("il registro si deve leggere");
        };
        assert_eq!(tutti.len(), 2);
    }
}

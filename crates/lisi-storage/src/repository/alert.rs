//! Alert.

use lisi_core::model::{Alert, AlertLevel, AnalysisLevel, NewAlert};
use lisi_core::text::AlertReason;
use lisi_core::{AlertId, ContentId, DomainError, SessionId};
use rusqlite::{OptionalExtension, Row};

use crate::database::Database;
use crate::error::{ConstraintKind, StorageError, StorageResult, constraint_kind};
use crate::repository::{instant, millis};

/// Riga grezza della tabella `alerts`.
struct AlertRow {
    id: i64,
    content_id: i64,
    level: i64,
    reason: String,
    raised_at: i64,
}

impl AlertRow {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            content_id: row.get(1)?,
            level: row.get(2)?,
            reason: row.get(3)?,
            raised_at: row.get(4)?,
        })
    }

    fn into_domain(self) -> StorageResult<Alert> {
        let level =
            u8::try_from(self.level).map_err(|_| DomainError::InvalidAnalysisLevel(u8::MAX))?;

        Ok(Alert {
            id: AlertId::new(self.id),
            content_id: ContentId::new(self.content_id),
            level: AlertLevel::try_new(AnalysisLevel::try_new(level)?)?,
            reason: AlertReason::try_new(&self.reason)?,
            raised_at: instant(self.raised_at),
        })
    }
}

impl Database {
    /// Registra l'alert di un contenuto.
    ///
    /// Un contenuto ha al più un alert: l'alert riassume l'esito dell'analisi,
    /// e due esiti diversi per lo stesso contenuto sarebbero una contraddizione.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se il contenuto non esiste e
    /// [`StorageError::DuplicateAlert`] se il contenuto ha già un alert.
    pub fn insert_alert(&self, alert: &NewAlert) -> StorageResult<AlertId> {
        let id: i64 = self
            .connection
            .query_row(
                "INSERT INTO alerts (content_id, level, reason, raised_at)
                 VALUES (?1, ?2, ?3, ?4)
                 RETURNING id",
                rusqlite::params![
                    alert.content_id.get(),
                    i64::from(alert.level.get()),
                    alert.reason.as_str(),
                    millis(alert.raised_at),
                ],
                |row| row.get(0),
            )
            .map_err(|error| match constraint_kind(&error) {
                Some(ConstraintKind::ForeignKey) => StorageError::NotFound {
                    entity: "contenuto",
                    id: alert.content_id.get(),
                },
                Some(ConstraintKind::Unique) => StorageError::DuplicateAlert,
                _ => StorageError::Sqlite(error),
            })?;

        Ok(AlertId::new(id))
    }

    /// Registra un alert **e** la sua riga d'audit, insieme (FINAL-REVIEW-01,
    /// FR-015).
    ///
    /// Erano due scritture separate: un'interruzione fra le due lasciava un
    /// alert senza la riga che lo dichiara, e alla ripresa — trovato l'alert —
    /// la riga non si scriveva più. Ora o ci sono entrambe, o nessuna.
    ///
    /// # Errori
    ///
    /// Come [`Self::insert_alert`]; in caso d'errore non resta nulla.
    pub fn insert_alert_with_audit(
        &mut self,
        alert: &NewAlert,
        audit: &lisi_core::model::NewAuditEntry,
    ) -> StorageResult<AlertId> {
        let transazione = self.connection.transaction()?;
        let id: i64 = transazione
            .query_row(
                "INSERT INTO alerts (content_id, level, reason, raised_at)
                 VALUES (?1, ?2, ?3, ?4)
                 RETURNING id",
                rusqlite::params![
                    alert.content_id.get(),
                    i64::from(alert.level.get()),
                    alert.reason.as_str(),
                    millis(alert.raised_at),
                ],
                |row| row.get(0),
            )
            .map_err(|error| match constraint_kind(&error) {
                Some(ConstraintKind::ForeignKey) => StorageError::NotFound {
                    entity: "contenuto",
                    id: alert.content_id.get(),
                },
                Some(ConstraintKind::Unique) => StorageError::DuplicateAlert,
                _ => StorageError::Sqlite(error),
            })?;
        transazione.execute(
            "INSERT INTO audit (actor, action, entity, entity_id, actor_mode, detail, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                audit.actor.as_str(),
                audit.action.as_str(),
                audit.entity.as_str(),
                audit.entity_id,
                audit.actor_mode.map(|modo| modo.as_str()),
                audit.detail.as_ref().map(|dettaglio| dettaglio.as_str()),
                millis(audit.recorded_at),
            ],
        )?;
        transazione.commit()?;
        Ok(AlertId::new(id))
    }

    /// Alert di un contenuto, se presente.
    ///
    /// L'assenza non è un errore: significa che il contenuto è stato analizzato
    /// e giudicato non rilevante.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se la riga contiene un
    /// valore non conforme al dominio.
    pub fn content_alert(&self, content_id: ContentId) -> StorageResult<Option<Alert>> {
        let row = self
            .connection
            .query_row(
                "SELECT id, content_id, level, reason, raised_at
                 FROM alerts
                 WHERE content_id = ?1",
                [content_id.get()],
                AlertRow::read,
            )
            .optional()?;

        row.map(AlertRow::into_domain).transpose()
    }

    /// Alert di una sessione, dal più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// valore non conforme al dominio.
    pub fn session_alerts(&self, session_id: SessionId) -> StorageResult<Vec<Alert>> {
        let mut statement = self.connection.prepare(
            "SELECT alerts.id, alerts.content_id, alerts.level, alerts.reason, alerts.raised_at
             FROM alerts
             JOIN contents ON contents.id = alerts.content_id
             WHERE contents.session_id = ?1
             ORDER BY alerts.raised_at DESC, alerts.id DESC",
        )?;

        let rows = statement.query_map([session_id.get()], AlertRow::read)?;

        let mut alerts = Vec::new();
        for row in rows {
            alerts.push(row?.into_domain()?);
        }
        Ok(alerts)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::{AlertLevel, NewAlert};
    use lisi_core::text::AlertReason;
    use lisi_core::{ContentId, SessionId};

    use crate::error::StorageError;
    use crate::test_support::{database_with_session, later, level, new_content};

    fn new_alert(content_id: ContentId, value: u8) -> NewAlert {
        let (Ok(alert_level), Ok(reason)) = (
            AlertLevel::try_new(level(value)),
            AlertReason::try_new("Riscontro su termine sorvegliato"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };

        NewAlert {
            content_id,
            level: alert_level,
            reason,
            raised_at: later(5),
        }
    }

    /// **Un alert senza la sua riga d'audit non resta** (FINAL-REVIEW-01,
    /// FR-015). La scrittura dell'audit è fatta fallire da un trigger
    /// temporaneo: l'alert scritto prima nella stessa transazione deve sparire.
    #[test]
    fn an_alert_and_its_audit_row_are_written_together_or_not_at_all() {
        let (mut database, source_id, session_id) = database_with_session();
        let mut content = new_content(session_id, source_id, "1", "messaggio");
        content.analysis_level = level(3);
        let Ok(insertion) = database.insert_content(&content) else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = insertion.content_id();
        if database
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER audit_rotto BEFORE INSERT ON audit
                 BEGIN SELECT RAISE(ABORT, 'audit non scrivibile'); END;",
            )
            .is_err()
        {
            panic!("il trigger di prova deve potersi creare");
        }

        let (Ok(actor), Ok(action), Ok(entity)) = (
            lisi_core::text::Actor::try_new("analisi"),
            lisi_core::text::AuditAction::try_new("alert_generato"),
            lisi_core::text::AuditEntity::try_new("content"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let riga = lisi_core::model::NewAuditEntry {
            actor,
            action,
            entity,
            entity_id: Some(content_id.get()),
            actor_mode: None,
            detail: None,
            recorded_at: later(5),
        };
        assert!(
            database
                .insert_alert_with_audit(&new_alert(content_id, 3), &riga)
                .is_err()
        );
        assert!(
            matches!(database.content_alert(content_id), Ok(None)),
            "l'alert non deve restare senza la sua riga d'audit"
        );
    }

    #[test]
    fn an_alert_is_written_and_read_back_unchanged() {
        let (mut database, source_id, session_id) = database_with_session();
        let mut content = new_content(session_id, source_id, "1", "messaggio");
        content.analysis_level = level(3);

        let Ok(insertion) = database.insert_content(&content) else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = insertion.content_id();

        let Ok(id) = database.insert_alert(&new_alert(content_id, 3)) else {
            panic!("l'alert deve potersi registrare");
        };

        let Ok(Some(alert)) = database.content_alert(content_id) else {
            panic!("l'alert deve potersi rileggere");
        };
        assert_eq!(alert.id, id);
        assert_eq!(alert.content_id, content_id);
        assert_eq!(alert.level.get(), 3);
        assert_eq!(alert.reason.as_str(), "Riscontro su termine sorvegliato");
        assert_eq!(alert.raised_at, later(5));
    }

    #[test]
    fn a_content_of_level_zero_stays_recorded_without_any_alert() {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(insertion) =
            database.insert_content(&new_content(session_id, source_id, "1", "messaggio"))
        else {
            panic!("il contenuto deve potersi registrare");
        };

        assert_eq!(
            database.content_alert(insertion.content_id()).ok(),
            Some(None)
        );
        assert_eq!(
            database.session_contents(session_id).map(|c| c.len()).ok(),
            Some(1)
        );
        assert_eq!(
            database.session_alerts(session_id).map(|a| a.len()).ok(),
            Some(0)
        );
    }

    #[test]
    fn a_content_cannot_carry_two_alerts() {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(insertion) =
            database.insert_content(&new_content(session_id, source_id, "1", "messaggio"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = insertion.content_id();

        let Ok(_) = database.insert_alert(&new_alert(content_id, 2)) else {
            panic!("il primo alert deve potersi registrare");
        };

        assert!(matches!(
            database.insert_alert(&new_alert(content_id, 4)),
            Err(StorageError::DuplicateAlert)
        ));
    }

    #[test]
    fn an_alert_on_a_missing_content_is_refused() {
        let (database, _source_id, _session_id) = database_with_session();
        assert!(matches!(
            database.insert_alert(&new_alert(ContentId::new(404), 1)),
            Err(StorageError::NotFound {
                entity: "contenuto",
                id: 404
            })
        ));
    }

    #[test]
    fn the_alerts_of_a_session_are_listed_from_the_most_recent() {
        let (mut database, source_id, session_id) = database_with_session();

        for (index, seconds) in [(1_u8, 30_i64), (2, 10), (3, 20)] {
            let Ok(insertion) = database.insert_content(&new_content(
                session_id,
                source_id,
                &format!("m{index}"),
                &format!("messaggio {index}"),
            )) else {
                panic!("il contenuto deve potersi registrare");
            };
            let mut alert = new_alert(insertion.content_id(), 1);
            alert.raised_at = later(seconds);
            let Ok(_) = database.insert_alert(&alert) else {
                panic!("l'alert deve potersi registrare");
            };
        }

        let Ok(alerts) = database.session_alerts(session_id) else {
            panic!("gli alert devono potersi leggere");
        };
        let times: Vec<i64> = alerts
            .iter()
            .map(|alert| alert.raised_at.as_millis())
            .collect();
        assert_eq!(
            times,
            [
                later(30).as_millis(),
                later(20).as_millis(),
                later(10).as_millis()
            ]
        );
    }

    #[test]
    fn the_alerts_of_another_session_are_not_returned() {
        let (database, _source_id, _session_id) = database_with_session();
        assert_eq!(
            database
                .session_alerts(SessionId::new(999))
                .map(|found| found.len())
                .ok(),
            Some(0)
        );
    }
}

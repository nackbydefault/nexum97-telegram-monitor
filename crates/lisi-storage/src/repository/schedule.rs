//! L'inizio programmato di un monitoraggio (SCHEDULE-01, ADR-0171,
//! migrazione 0070).
//!
//! Una riga per monitoraggio programmato: l'inizio, chi e quando, e l'avvio
//! mancato se c'è stato. L'inizio non si riscrive e la riga non si cancella:
//! lo schema lo impone.

use core::str::FromStr;

use lisi_core::SessionId;
use lisi_core::model::schedule::{MissedStart, MissedStartReason, ScheduledStart};
use lisi_core::text::Actor;
use lisi_core::time::Timestamp;

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// Le colonne di una riga, nell'ordine delle letture.
const COLONNE: &str = "s.session_id, s.start_at, s.scheduled_by, s.scheduled_at, s.missed_at, \
                       s.missed_reason";

/// Una riga letta, prima di diventare dominio.
type Riga = (i64, i64, String, i64, Option<i64>, Option<String>);

/// Legge una riga.
fn leggi(row: &rusqlite::Row<'_>) -> rusqlite::Result<Riga> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

/// La riga nel dominio. Un attore o una ragione che l'archivio conserva in una
/// forma sconosciuta non si indovinano: la riga si salta.
fn dominio((session_id, start_at, by, at, missed_at, reason): Riga) -> Option<ScheduledStart> {
    let scheduled_by = Actor::try_new(&by).ok()?;
    let missed = match (missed_at, reason) {
        (Some(quando), Some(ragione)) => Some(MissedStart {
            at: instant(quando),
            reason: MissedStartReason::from_str(&ragione).ok()?,
        }),
        _ => None,
    };
    Some(ScheduledStart {
        session_id: SessionId::new(session_id),
        start_at: instant(start_at),
        scheduled_by,
        scheduled_at: instant(at),
        missed,
    })
}

impl Database {
    /// Registra l'inizio programmato di un monitoraggio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il monitoraggio non esiste, se ne ha già uno,
    /// se l'inizio non segue la programmazione, o se la scrittura non riesce.
    pub fn insert_session_schedule(
        &self,
        session_id: SessionId,
        start_at: Timestamp,
        scheduled_by: &Actor,
        scheduled_at: Timestamp,
    ) -> StorageResult<()> {
        self.connection.execute(
            "INSERT INTO session_schedules (session_id, start_at, scheduled_by, scheduled_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                session_id.get(),
                millis(start_at),
                scheduled_by.as_str(),
                millis(scheduled_at),
            ],
        )?;
        Ok(())
    }

    /// L'inizio programmato di un monitoraggio, se ne ha uno.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn session_schedule(&self, session_id: SessionId) -> StorageResult<Option<ScheduledStart>> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT {COLONNE} FROM session_schedules s WHERE s.session_id = ?1"
        ))?;
        let mut righe = statement.query_map([session_id.get()], leggi)?;
        match righe.next() {
            Some(riga) => Ok(dominio(riga?)),
            None => Ok(None),
        }
    }

    /// Gli inizi da decidere adesso: il monitoraggio è ancora pianificato,
    /// nessun avvio mancato è registrato, e l'inizio non segue `now`. Dal più
    /// vecchio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn due_schedules(&self, now: Timestamp) -> StorageResult<Vec<ScheduledStart>> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT {COLONNE} FROM session_schedules s
             JOIN sessions x ON x.id = s.session_id
             WHERE x.state = 'planned' AND s.missed_at IS NULL AND s.start_at <= ?1
             ORDER BY s.start_at, s.session_id"
        ))?;
        let righe = statement.query_map([millis(now)], leggi)?;
        let mut inizi = Vec::new();
        for riga in righe {
            if let Some(inizio) = dominio(riga?) {
                inizi.push(inizio);
            }
        }
        Ok(inizi)
    }

    /// Registra un avvio mancato, una volta sola.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il monitoraggio non ha un inizio programmato,
    /// se un avvio mancato era già registrato, o se la scrittura non riesce.
    pub fn record_missed_start(
        &self,
        session_id: SessionId,
        at: Timestamp,
        reason: MissedStartReason,
    ) -> StorageResult<()> {
        let quante = self.connection.execute(
            "UPDATE session_schedules SET missed_at = ?2, missed_reason = ?3
             WHERE session_id = ?1",
            rusqlite::params![session_id.get(), millis(at), reason.as_str()],
        )?;
        if quante == 0 {
            return Err(crate::error::StorageError::NotFound {
                entity: "session_schedule",
                id: session_id.get(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::SessionId;
    use lisi_core::model::SessionState;
    use lisi_core::model::schedule::MissedStartReason;

    use crate::test_support::{actor, database_with_session, later, new_session};

    /// **L'inizio si scrive una volta e non si riscrive; l'avvio mancato si
    /// scrive una volta; la riga non si cancella; da decidere c'è soltanto un
    /// pianificato senza avvio mancato** (SCHEDULE-01, criterio 4; prova
    /// negativa: il divieto tolto → rossa).
    #[test]
    fn l_inizio_si_scrive_una_volta() {
        let (mut database, fonte, prima) = database_with_session();
        let Ok(seconda) = database.insert_session(&new_session(vec![fonte]), later(0)) else {
            panic!("la seconda sessione di prova deve nascere");
        };
        let chi = actor("operatore.prova");
        let Ok(()) = database.insert_session_schedule(prima, later(100), &chi, later(1)) else {
            panic!("l'inizio deve scriversi");
        };
        let Ok(()) = database.insert_session_schedule(seconda, later(200), &chi, later(1)) else {
            panic!("l'inizio deve scriversi");
        };
        assert!(
            database
                .insert_session_schedule(prima, later(300), &chi, later(2))
                .is_err(),
            "un secondo inizio per lo stesso monitoraggio"
        );
        assert!(
            database
                .insert_session_schedule(seconda, later(1), &chi, later(5))
                .is_err()
        );

        // Da decidere: soltanto ciò che è giunto all'ora.
        assert_eq!(
            database.due_schedules(later(99)).map(|v| v.len()).ok(),
            Some(0)
        );
        assert_eq!(
            database.due_schedules(later(150)).map(|v| v.len()).ok(),
            Some(1)
        );

        // L'inizio non si riscrive, la riga non si cancella.
        assert!(
            database
                .connection
                .execute("UPDATE session_schedules SET start_at = 500", [])
                .is_err()
        );
        assert!(
            database
                .connection
                .execute("DELETE FROM session_schedules", [])
                .is_err()
        );

        // L'avvio mancato si scrive una volta, e toglie l'inizio dai da decidere.
        let Ok(()) =
            database.record_missed_start(prima, later(170), MissedStartReason::ProgramClosed)
        else {
            panic!("l'avvio mancato deve scriversi");
        };
        assert!(
            database
                .record_missed_start(prima, later(171), MissedStartReason::AccountNotConnected)
                .is_err(),
            "un avvio mancato non si riscrive"
        );
        let Ok(Some(letto)) = database.session_schedule(prima) else {
            panic!("l'inizio deve rileggersi");
        };
        assert_eq!(letto.start_at, later(100));
        assert_eq!(
            letto.missed.map(|m| (m.at, m.reason)),
            Some((later(170), MissedStartReason::ProgramClosed))
        );
        assert_eq!(
            database.due_schedules(later(250)).map(|v| v.len()).ok(),
            Some(1)
        );

        // Un monitoraggio avviato non è più da decidere.
        let Ok(()) = database.update_session_state(seconda, SessionState::Running, later(201))
        else {
            panic!("l'avvio deve scriversi");
        };
        assert_eq!(
            database.due_schedules(later(250)).map(|v| v.len()).ok(),
            Some(0)
        );
        assert_eq!(
            database.session_schedule(SessionId::new(999)).ok(),
            Some(None)
        );
    }
}

//! Sessioni di monitoraggio e fonti selezionate.

use core::str::FromStr;

use lisi_core::model::{NewSession, Session, SessionDuration, SessionDurationMode, SessionState};
use lisi_core::text::{Actor, DisplayName};
use lisi_core::{SessionId, SourceId, Timestamp};
use rusqlite::Row;

use crate::database::Database;
use crate::error::{ConstraintKind, StorageError, StorageResult, constraint_kind};
use crate::repository::{instant, millis};

/// Riga grezza della tabella `sessions`.
struct SessionRow {
    id: i64,
    label: String,
    started_by: String,
    duration_mode: String,
    planned_seconds: Option<i64>,
    state: String,
    created_at: i64,
    started_at: Option<i64>,
    ended_at: Option<i64>,
}

impl SessionRow {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            label: row.get(1)?,
            started_by: row.get(2)?,
            duration_mode: row.get(3)?,
            planned_seconds: row.get(4)?,
            state: row.get(5)?,
            created_at: row.get(6)?,
            started_at: row.get(7)?,
            ended_at: row.get(8)?,
        })
    }

    fn into_domain(self) -> StorageResult<Session> {
        let mode = SessionDurationMode::from_str(&self.duration_mode)?;

        Ok(Session {
            id: SessionId::new(self.id),
            label: DisplayName::try_new(&self.label)?,
            started_by: Actor::try_new(&self.started_by)?,
            duration: SessionDuration::try_from_parts(mode, self.planned_seconds)?,
            state: SessionState::from_str(&self.state)?,
            created_at: instant(self.created_at),
            started_at: self.started_at.map(instant),
            ended_at: self.ended_at.map(instant),
        })
    }
}

impl Database {
    /// Crea una sessione insieme alle fonti selezionate.
    ///
    /// La sessione e le sue fonti sono scritte in un'unica transazione: una
    /// sessione senza le proprie fonti non potrebbe acquisire nulla e non deve
    /// esistere nemmeno per un istante. Se una delle fonti non esiste, nulla
    /// viene scritto.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se una delle fonti indicate non
    /// esiste, e un errore del motore negli altri casi.
    pub fn insert_session(
        &mut self,
        session: &NewSession,
        now: Timestamp,
    ) -> StorageResult<SessionId> {
        let transaction = self.connection.transaction()?;

        let session_id: i64 = transaction.query_row(
            "INSERT INTO sessions (
                 label, started_by, duration_mode, planned_seconds, state, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             RETURNING id",
            rusqlite::params![
                session.label.as_str(),
                session.started_by.as_str(),
                session.duration.mode().as_str(),
                session.duration.planned_seconds(),
                SessionState::Planned.as_str(),
                millis(now),
            ],
            |row| row.get(0),
        )?;

        {
            let mut statement = transaction.prepare(
                "INSERT OR IGNORE INTO session_sources (session_id, source_id, selected_at)
                 VALUES (?1, ?2, ?3)",
            )?;

            for source_id in &session.source_ids {
                // `OR IGNORE` riguarda soltanto la ripetizione della stessa
                // fonte nell'elenco, che è una svista innocua del chiamante.
                // La foreign key verso `sources` resta attiva e una fonte
                // inesistente fa fallire l'intera transazione.
                statement
                    .execute(rusqlite::params![session_id, source_id.get(), millis(now)])
                    .map_err(|error| {
                        if constraint_kind(&error) == Some(ConstraintKind::ForeignKey) {
                            StorageError::NotFound {
                                entity: "fonte",
                                id: source_id.get(),
                            }
                        } else {
                            StorageError::Sqlite(error)
                        }
                    })?;
            }
        }

        transaction.commit()?;
        Ok(SessionId::new(session_id))
    }

    /// Legge una sessione.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se la sessione non esiste.
    pub fn session(&self, id: SessionId) -> StorageResult<Session> {
        let row = self
            .connection
            .query_row(
                "SELECT id, label, started_by, duration_mode, planned_seconds, state,
                        created_at, started_at, ended_at
                 FROM sessions
                 WHERE id = ?1",
                [id.get()],
                SessionRow::read,
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound {
                    entity: "sessione",
                    id: id.get(),
                },
                other => StorageError::Sqlite(other),
            })?;

        row.into_domain()
    }

    /// Elenca le sessioni, dalla più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// valore non conforme al dominio.
    /// **Quanti** monitoraggi stanno acquisendo in questo momento.
    ///
    /// Acquisire è `in corso` **oppure** `sospesa`: «sospendi avvisi» tacita le
    /// notifiche, non l'acquisizione (DEC-098).
    ///
    /// # Perché un conteggio, e perché serve
    ///
    /// Perché con più monitoraggi (ADR-0065) la veglia della postazione è un
    /// **conteggio e non un interruttore**: spegnerla alla fine del primo
    /// addormenterebbe la macchina mentre un altro osserva, e il prodotto se ne
    /// accorgerebbe solo dal buco.
    ///
    /// È anche il numero che le superfici con posto per una riga sola mostrano:
    /// **quanti**, mai quali.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il conteggio non riesce.
    pub fn acquiring_session_count(&self) -> StorageResult<usize> {
        let quanti: i64 = self.connection.query_row(
            "SELECT count(*) FROM sessions WHERE state IN ('running', 'paused')",
            [],
            |row| row.get(0),
        )?;
        Ok(usize::try_from(quanti).unwrap_or(0))
    }

    /// **Quanti** monitoraggi risultano `in corso`.
    ///
    /// Distinto da [`Self::acquiring_session_count`], che conta anche i
    /// sospesi: questo è il numero che si scrive quando si dice «in corso».
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il conteggio non riesce.
    pub fn running_session_count(&self) -> StorageResult<usize> {
        let quanti: i64 = self.connection.query_row(
            "SELECT count(*) FROM sessions WHERE state = 'running'",
            [],
            |row| row.get(0),
        )?;
        Ok(usize::try_from(quanti).unwrap_or(0))
    }

    pub fn sessions(&self) -> StorageResult<Vec<Session>> {
        let mut statement = self.connection.prepare(
            "SELECT id, label, started_by, duration_mode, planned_seconds, state,
                    created_at, started_at, ended_at
             FROM sessions
             ORDER BY created_at DESC, id DESC",
        )?;

        let rows = statement.query_map([], SessionRow::read)?;

        let mut sessions = Vec::new();
        for row in rows {
            sessions.push(row?.into_domain()?);
        }
        Ok(sessions)
    }

    /// Fonti selezionate per una sessione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn session_source_ids(&self, id: SessionId) -> StorageResult<Vec<SourceId>> {
        let mut statement = self.connection.prepare(
            "SELECT source_id FROM session_sources WHERE session_id = ?1 ORDER BY source_id",
        )?;

        let rows = statement.query_map([id.get()], |row| row.get::<_, i64>(0))?;

        let mut ids = Vec::new();
        for row in rows {
            ids.push(SourceId::new(row?));
        }
        Ok(ids)
    }

    /// Fa transitare la sessione a un nuovo stato.
    ///
    /// La transizione è verificata contro il ciclo di vita del dominio prima di
    /// essere scritta: l'arresto è ordinato e da uno stato terminale non si
    /// riparte.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se la sessione non esiste e
    /// [`StorageError::InvalidSessionTransition`] se la transizione non è
    /// ammessa.
    pub fn update_session_state(
        &mut self,
        id: SessionId,
        next: SessionState,
        at: Timestamp,
    ) -> StorageResult<()> {
        let transaction = self.connection.transaction()?;

        let current: String = transaction
            .query_row(
                "SELECT state FROM sessions WHERE id = ?1",
                [id.get()],
                |row| row.get(0),
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound {
                    entity: "sessione",
                    id: id.get(),
                },
                other => StorageError::Sqlite(other),
            })?;

        let current = SessionState::from_str(&current)?;
        if !current.can_transition_to(next) {
            return Err(StorageError::InvalidSessionTransition {
                from: current.as_str(),
                to: next.as_str(),
            });
        }

        // Il primo avvio fissa `started_at`; le riprese successive non lo
        // riscrivono, perché l'inizio della sessione resta quello.
        let started_at = if next == SessionState::Running {
            Some(millis(at))
        } else {
            None
        };
        // Un monitoraggio mai avviato e arrestato è annullato: non ha un
        // inizio, e quindi nemmeno una fine. Fino a SCHEDULE-01 il dominio lo
        // ammetteva e l'archivio lo rifiutava (una fine senza avvio), e
        // «Arresta» su un pianificato finiva in un errore tecnico (ADR-0171).
        let ended_at = if next.is_final() && current != SessionState::Planned {
            Some(millis(at))
        } else {
            None
        };

        transaction.execute(
            "UPDATE sessions
             SET state = ?2,
                 started_at = coalesce(started_at, ?3),
                 ended_at = coalesce(?4, ended_at)
             WHERE id = ?1",
            rusqlite::params![id.get(), next.as_str(), started_at, ended_at],
        )?;

        transaction.commit()?;
        Ok(())
    }

    /// Le sessioni che acquisiscono ancora e la cui durata pianificata è
    /// **trascorsa** all'istante indicato (E2E01-01).
    ///
    /// La scadenza si calcola nell'archivio da due colonne conservate, l'avvio
    /// e i secondi pianificati: nessun orologio di processo, nessun timer
    /// dell'interfaccia. È inclusa — `<=` — come in
    /// [`Session::is_due`](lisi_core::model::Session::is_due), e una prova lo
    /// sorveglia.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// valore non conforme al dominio.
    pub fn due_sessions(&self, now: Timestamp) -> StorageResult<Vec<Session>> {
        let mut statement = self.connection.prepare(
            "SELECT id, label, started_by, duration_mode, planned_seconds, state,
                    created_at, started_at, ended_at
             FROM sessions
             WHERE state IN ('running', 'paused')
               AND started_at IS NOT NULL
               AND planned_seconds IS NOT NULL
               AND started_at + planned_seconds * 1000 <= ?1
             ORDER BY started_at, id",
        )?;

        let rows = statement.query_map([millis(now)], SessionRow::read)?;

        let mut sessions = Vec::new();
        for row in rows {
            sessions.push(row?.into_domain()?);
        }
        Ok(sessions)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::{SessionDuration, SessionState};
    use lisi_core::{SessionId, SourceId};

    use crate::error::StorageError;
    use crate::test_support::{database, later, new_session, new_source, now};

    #[test]
    fn a_session_is_written_with_its_selected_sources() {
        let mut database = database();
        let (Ok(first), Ok(second)) = (
            database.insert_source(&new_source("canale_uno"), now()),
            database.insert_source(&new_source("canale_due"), now()),
        ) else {
            panic!("le fonti di prova devono potersi registrare");
        };

        let Ok(session_id) = database.insert_session(&new_session(vec![first, second]), now())
        else {
            panic!("la sessione deve potersi creare");
        };

        let Ok(session) = database.session(session_id) else {
            panic!("la sessione deve potersi rileggere");
        };
        assert_eq!(session.state, SessionState::Planned);
        assert_eq!(session.duration, SessionDuration::Preset { seconds: 3_600 });
        assert_eq!(session.created_at, now());
        assert_eq!(session.started_at, None);
        assert_eq!(session.ended_at, None);

        let Ok(mut selected) = database.session_source_ids(session_id) else {
            panic!("le fonti selezionate devono potersi leggere");
        };
        selected.sort_unstable();
        assert_eq!(selected, vec![first, second]);
    }

    #[test]
    fn a_session_on_a_missing_source_writes_nothing() {
        let mut database = database();
        let Ok(existing) = database.insert_source(&new_source("canale_uno"), now()) else {
            panic!("la fonte di prova deve potersi registrare");
        };

        let result =
            database.insert_session(&new_session(vec![existing, SourceId::new(999)]), now());
        assert!(matches!(result, Err(StorageError::NotFound { .. })));

        // La transazione è stata annullata: non deve restare alcuna sessione.
        let Ok(sessions) = database.sessions() else {
            panic!("l'elenco deve potersi leggere");
        };
        assert!(
            sessions.is_empty(),
            "la sessione non doveva essere scritta a meta'"
        );
    }

    #[test]
    fn a_repeated_source_in_the_selection_is_recorded_once() {
        let mut database = database();
        let Ok(source_id) = database.insert_source(&new_source("canale_uno"), now()) else {
            panic!("la fonte di prova deve potersi registrare");
        };

        let Ok(session_id) =
            database.insert_session(&new_session(vec![source_id, source_id]), now())
        else {
            panic!("la sessione deve potersi creare");
        };

        assert_eq!(
            database.session_source_ids(session_id).ok(),
            Some(vec![source_id])
        );
    }

    #[test]
    fn a_missing_session_is_reported_as_not_found() {
        let database = database();
        assert!(matches!(
            database.session(SessionId::new(404)),
            Err(StorageError::NotFound {
                entity: "sessione",
                id: 404
            })
        ));
    }

    #[test]
    fn the_ordered_lifecycle_is_recorded() {
        let mut database = database();
        let Ok(source_id) = database.insert_source(&new_source("canale_uno"), now()) else {
            panic!("la fonte di prova deve potersi registrare");
        };
        let Ok(session_id) = database.insert_session(&new_session(vec![source_id]), now()) else {
            panic!("la sessione deve potersi creare");
        };

        let Ok(()) = database.update_session_state(session_id, SessionState::Running, later(10))
        else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = database.update_session_state(session_id, SessionState::Paused, later(20))
        else {
            panic!("la pausa deve riuscire");
        };
        let Ok(()) = database.update_session_state(session_id, SessionState::Running, later(30))
        else {
            panic!("la ripresa deve riuscire");
        };
        let Ok(()) = database.update_session_state(session_id, SessionState::Stopped, later(40))
        else {
            panic!("l'arresto deve riuscire");
        };

        let Ok(session) = database.session(session_id) else {
            panic!("la sessione deve potersi rileggere");
        };
        assert_eq!(session.state, SessionState::Stopped);
        // Il primo avvio resta l'inizio della sessione, non la ripresa.
        assert_eq!(session.started_at, Some(later(10)));
        assert_eq!(session.ended_at, Some(later(40)));
    }

    #[test]
    fn a_session_cannot_be_completed_without_having_run() {
        let mut database = database();
        let Ok(source_id) = database.insert_source(&new_source("canale_uno"), now()) else {
            panic!("la fonte di prova deve potersi registrare");
        };
        let Ok(session_id) = database.insert_session(&new_session(vec![source_id]), now()) else {
            panic!("la sessione deve potersi creare");
        };

        assert!(matches!(
            database.update_session_state(session_id, SessionState::Completed, later(10)),
            Err(StorageError::InvalidSessionTransition {
                from: "planned",
                to: "completed"
            })
        ));
    }

    #[test]
    fn a_stopped_session_cannot_be_restarted() {
        let mut database = database();
        let Ok(source_id) = database.insert_source(&new_source("canale_uno"), now()) else {
            panic!("la fonte di prova deve potersi registrare");
        };
        let Ok(session_id) = database.insert_session(&new_session(vec![source_id]), now()) else {
            panic!("la sessione deve potersi creare");
        };

        let Ok(()) = database.update_session_state(session_id, SessionState::Running, later(10))
        else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = database.update_session_state(session_id, SessionState::Stopped, later(20))
        else {
            panic!("l'arresto deve riuscire");
        };

        assert!(matches!(
            database.update_session_state(session_id, SessionState::Running, later(30)),
            Err(StorageError::InvalidSessionTransition { .. })
        ));
    }

    /// **Un monitoraggio pianificato si arresta, cioè si annulla, senza un
    /// inizio e senza una fine** (SCHEDULE-01, ADR-0171; prova negativa: la
    /// fine scritta anche per il pianificato → rossa, perché l'archivio la
    /// rifiuta).
    #[test]
    fn un_pianificato_arrestato_non_ha_inizio_ne_fine() {
        let (mut database, _, session_id) = crate::test_support::database_with_session();
        let Ok(()) = database.update_session_state(session_id, SessionState::Stopped, later(20))
        else {
            panic!("l'annullamento di un pianificato deve riuscire");
        };
        let Ok(sessione) = database.session(session_id) else {
            panic!("la sessione deve rileggersi");
        };
        assert_eq!(sessione.state, SessionState::Stopped);
        assert_eq!(sessione.started_at, None);
        assert_eq!(sessione.ended_at, None);
    }

    /// **La scadenza si legge dall'archivio, inclusa, e solo per chi
    /// acquisisce** (E2E01-01). `new_session` dura un'ora: avviata a +10 s,
    /// scade a +3610 s.
    #[test]
    fn a_due_session_is_found_at_its_planned_end_and_not_before() {
        let mut database = database();
        let Ok(source_id) = database.insert_source(&new_source("canale_uno"), now()) else {
            panic!("la fonte di prova deve potersi registrare");
        };
        let Ok(session_id) = database.insert_session(&new_session(vec![source_id]), now()) else {
            panic!("la sessione deve potersi creare");
        };
        // Pianificata: non scade, perche' non e' mai partita.
        assert!(
            database
                .due_sessions(later(100_000))
                .is_ok_and(|due| due.is_empty())
        );

        let Ok(()) = database.update_session_state(session_id, SessionState::Running, later(10))
        else {
            panic!("l'avvio deve riuscire");
        };
        assert!(
            database
                .due_sessions(later(3_609))
                .is_ok_and(|due| due.is_empty())
        );
        assert!(
            database
                .due_sessions(later(3_610))
                .is_ok_and(|due| due.iter().map(|s| s.id).eq([session_id]))
        );

        // Con gli avvisi sospesi acquisisce ancora: scade lo stesso.
        let Ok(()) = database.update_session_state(session_id, SessionState::Paused, later(20))
        else {
            panic!("la sospensione degli avvisi deve riuscire");
        };
        assert!(
            database
                .due_sessions(later(3_610))
                .is_ok_and(|due| due.len() == 1)
        );

        // Conclusa: non scade una seconda volta.
        let Ok(()) =
            database.update_session_state(session_id, SessionState::Completed, later(3_610))
        else {
            panic!("la conclusione deve riuscire");
        };
        assert!(
            database
                .due_sessions(later(100_000))
                .is_ok_and(|due| due.is_empty())
        );
    }

    /// **Una sessione manuale non scade mai**, a qualunque istante.
    #[test]
    fn a_manual_session_is_never_due() {
        let mut database = database();
        let Ok(source_id) = database.insert_source(&new_source("canale_uno"), now()) else {
            panic!("la fonte di prova deve potersi registrare");
        };
        let mut manuale = new_session(vec![source_id]);
        manuale.duration = SessionDuration::Manual;
        let Ok(session_id) = database.insert_session(&manuale, now()) else {
            panic!("la sessione deve potersi creare");
        };
        let Ok(()) = database.update_session_state(session_id, SessionState::Running, later(10))
        else {
            panic!("l'avvio deve riuscire");
        };
        assert!(
            database
                .due_sessions(later(10_000_000))
                .is_ok_and(|due| due.is_empty())
        );
    }

    #[test]
    fn a_transition_on_a_missing_session_is_reported_as_not_found() {
        let mut database = database();
        assert!(matches!(
            database.update_session_state(SessionId::new(404), SessionState::Running, now()),
            Err(StorageError::NotFound { .. })
        ));
    }
}

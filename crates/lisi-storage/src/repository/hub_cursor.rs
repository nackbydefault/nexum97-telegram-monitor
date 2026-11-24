//! Il cursore della postazione sulla storia dell'Hub (HUB-CATCHUP-01, ADR-0087).
//!
//! # Il cursore non torna indietro da solo
//!
//! Avanzare è ordinario; **tornare indietro non lo è**, perché rimetterebbe in
//! coda eventi già applicati come se fossero nuovi. Qui si può soltanto
//! avanzare sulla stessa storia; cambiare storia, o ricominciare, è un atto
//! **esplicito** ([`Database::clear_hub_cursor`]) che chi lo compie registra.

use lisi_core::Timestamp;
use lisi_core::model::hub_catchup::HubCursor;
use lisi_core::model::hub_event::HubEventStreamId;
use rusqlite::{OptionalExtension, params};

use crate::database::Database;
use crate::error::{StorageError, StorageResult};
use crate::repository::millis;

/// Perché un avanzamento del cursore è stato rifiutato.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorRefusal {
    /// Il cursore conservato segue un'altra storia: va cancellato di proposito.
    OtherStream,
    /// Il numero proposto non è più avanti di quello conservato.
    NotForward,
}

impl Database {
    /// Il punto in cui questa postazione è arrivata, se ne ha uno.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se la riga conservata
    /// non è interpretabile.
    pub fn hub_cursor(&self) -> StorageResult<Option<HubCursor>> {
        self.connection
            .query_row(
                "SELECT stream_id, last_applied FROM hub_stream_cursor WHERE id = 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
            .map(|(stream, last)| {
                Ok(HubCursor {
                    stream: HubEventStreamId::parse(&stream)?,
                    last_applied: u64::try_from(last).map_err(|_| StorageError::CorruptedRow {
                        detail: "il cursore conservato non è rappresentabile",
                    })?,
                })
            })
            .transpose()
    }

    /// Porta il cursore **avanti**, sulla stessa storia.
    ///
    /// Il primo avanzamento scrive anche il nome della storia.
    ///
    /// # Errori
    ///
    /// Restituisce [`CursorRefusal::OtherStream`] se il cursore conservato
    /// segue un'altra storia e [`CursorRefusal::NotForward`] se il numero non è
    /// più avanti; un errore d'archivio se la scrittura non riesce.
    pub fn advance_hub_cursor(
        &self,
        cursor: HubCursor,
        now: Timestamp,
    ) -> StorageResult<Result<(), CursorRefusal>> {
        if let Some(conservato) = self.hub_cursor()? {
            if conservato.stream != cursor.stream {
                return Ok(Err(CursorRefusal::OtherStream));
            }
            if cursor.last_applied <= conservato.last_applied {
                return Ok(Err(CursorRefusal::NotForward));
            }
        }

        let numero =
            i64::try_from(cursor.last_applied).map_err(|_| StorageError::CorruptedRow {
                detail: "il numero da conservare non è rappresentabile",
            })?;
        self.connection.execute(
            "INSERT INTO hub_stream_cursor (id, stream_id, last_applied, updated_at)
             VALUES (1, ?1, ?2, ?3)
             ON CONFLICT (id) DO UPDATE
                SET stream_id = ?1, last_applied = ?2, updated_at = ?3",
            params![cursor.stream.to_hex(), numero, millis(now)],
        )?;
        Ok(Ok(()))
    }

    /// Dimentica il punto raggiunto: **un atto esplicito**.
    ///
    /// Serve quando l'Hub risponde con un'altra storia, e chi lo compie deve
    /// averlo deciso e registrato: cancellare in silenzio significherebbe
    /// ricominciare a leggere senza che nessuno lo sappia.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn clear_hub_cursor(&self) -> StorageResult<()> {
        self.connection
            .execute("DELETE FROM hub_stream_cursor WHERE id = 1", [])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::hub_catchup::HubCursor;
    use lisi_core::model::hub_event::{HUB_STREAM_ID_BYTES, HubEventStreamId};

    use super::CursorRefusal;
    use crate::database::Database;

    fn archivio() -> Database {
        let Ok(database) = Database::open_in_memory() else {
            panic!("archivio di prova");
        };
        database
    }

    fn flusso(seme: u8) -> HubEventStreamId {
        HubEventStreamId::from_random_bytes([seme; HUB_STREAM_ID_BYTES])
    }

    fn adesso() -> Timestamp {
        Timestamp::from_millis(1_758_300_000_000)
    }

    #[test]
    fn a_station_that_never_followed_anything_has_no_cursor() {
        assert_eq!(archivio().hub_cursor().ok(), Some(None));
    }

    #[test]
    fn the_cursor_moves_forward_and_remembers_the_story() {
        let archivio = archivio();
        let stream = flusso(1);
        for numero in [1_u64, 2, 7] {
            assert_eq!(
                archivio
                    .advance_hub_cursor(
                        HubCursor {
                            stream,
                            last_applied: numero
                        },
                        adesso()
                    )
                    .ok(),
                Some(Ok(()))
            );
        }
        assert_eq!(
            archivio.hub_cursor().ok(),
            Some(Some(HubCursor {
                stream,
                last_applied: 7
            }))
        );
    }

    #[test]
    fn the_cursor_never_goes_backwards_by_itself() {
        let archivio = archivio();
        let stream = flusso(1);
        let _ = archivio.advance_hub_cursor(
            HubCursor {
                stream,
                last_applied: 7,
            },
            adesso(),
        );
        for numero in [7_u64, 6, 0] {
            assert_eq!(
                archivio
                    .advance_hub_cursor(
                        HubCursor {
                            stream,
                            last_applied: numero
                        },
                        adesso()
                    )
                    .ok(),
                Some(Err(CursorRefusal::NotForward))
            );
        }
        assert_eq!(
            archivio.hub_cursor().ok().flatten().map(|c| c.last_applied),
            Some(7)
        );
    }

    #[test]
    fn another_story_is_refused_until_someone_forgets_the_old_one() {
        let archivio = archivio();
        let _ = archivio.advance_hub_cursor(
            HubCursor {
                stream: flusso(1),
                last_applied: 7,
            },
            adesso(),
        );
        assert_eq!(
            archivio
                .advance_hub_cursor(
                    HubCursor {
                        stream: flusso(2),
                        last_applied: 1
                    },
                    adesso()
                )
                .ok(),
            Some(Err(CursorRefusal::OtherStream))
        );

        // Dimenticare è un atto esplicito, e allora la storia nuova entra.
        assert!(archivio.clear_hub_cursor().is_ok());
        assert_eq!(archivio.hub_cursor().ok(), Some(None));
        assert_eq!(
            archivio
                .advance_hub_cursor(
                    HubCursor {
                        stream: flusso(2),
                        last_applied: 1
                    },
                    adesso()
                )
                .ok(),
            Some(Ok(()))
        );
    }
}

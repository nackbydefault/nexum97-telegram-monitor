//! La coda di revisione condivisa, dal lato dell'Hub (TEAM-REVIEW-01,
//! ADR-0094).
//!
//! # L'elenco porta metadati, il contenuto si chiede a parte
//!
//! [`Database::hub_review_queue`] restituisce **identificativi, fonte, livello,
//! istante, stato e versione**: nessun testo, nemmeno un estratto. Il testo lo
//! consegna [`Database::hub_review_content`], una riga per volta, e chi lo
//! chiede finisce nell'audit (il servizio, non questo modulo).
//!
//! # La versione è il numero delle revisioni
//!
//! Il registro delle revisioni è append-only: contarle dà una versione che
//! cresce di uno a ogni decisione, e su cui la concorrenza ottimistica di
//! ADR-0089 può appoggiarsi senza aggiungere colonne.

use core::str::FromStr;

use lisi_core::model::hub_review::{ReviewContent, ReviewItem, ReviewQueueCursor};
use lisi_core::model::review::ReviewState;
use lisi_core::text::{DisplayName, SourceIdentifier};
use lisi_core::{ContentId, Timestamp};
use rusqlite::{OptionalExtension, params};

use crate::database::Database;
use crate::error::{StorageError, StorageResult};
use crate::repository::instant;

impl Database {
    /// Gli elementi da rivedere, in avanti dal cursore.
    ///
    /// L'ordine è quello degli identificativi dei contenuti: cresce, e la
    /// stessa domanda dà la stessa risposta finché nulla cambia. Ordinare per
    /// livello sarebbe una **classifica**, che questo prodotto non produce
    /// (ADR-0078).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il cursore non è utilizzabile, se la lettura
    /// non riesce, o se una riga conservata non è interpretabile.
    pub fn hub_review_queue(&self, cursor: ReviewQueueCursor) -> StorageResult<Vec<ReviewItem>> {
        if !cursor.is_usable() {
            return Err(StorageError::InvalidRange {
                what: "il cursore della coda di revisione non è utilizzabile",
            });
        }

        let mut statement = self.connection.prepare(
            "SELECT contents.id, sources.identifier, alerts.level, alerts.raised_at,
                    (SELECT state FROM reviews
                      WHERE reviews.content_id = contents.id
                      ORDER BY reviews.decided_at DESC, reviews.id DESC LIMIT 1),
                    (SELECT COUNT(*) FROM reviews WHERE reviews.content_id = contents.id)
             FROM alerts
             JOIN contents ON contents.id = alerts.content_id
             JOIN sources ON sources.id = contents.source_id
             WHERE contents.id > ?1
             ORDER BY contents.id ASC
             LIMIT ?2",
        )?;

        let righe = statement.query_map(
            params![
                cursor.after_content_id,
                i64::try_from(cursor.limit).unwrap_or(i64::MAX)
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )?;

        let mut elementi = Vec::new();
        for riga in righe {
            let (content_id, source, level, raised_at, state, version) = riga?;
            elementi.push(ReviewItem {
                content_id: ContentId::new(content_id),
                source: SourceIdentifier::try_new(&source)?,
                level: livello(level)?,
                raised_at: instant(raised_at),
                state: state.as_deref().map(ReviewState::from_str).transpose()?,
                version: u64::try_from(version).unwrap_or(0),
            });
        }
        Ok(elementi)
    }

    /// Il contenuto da rivedere, con ciò che serve a capirlo.
    ///
    /// Restituisce `None` quando il contenuto non esiste o non ha un avviso:
    /// la revisione condivisa riguarda ciò che il motore ha segnalato, e
    /// consegnare un contenuto qualsiasi trasformerebbe la richiesta in una
    /// lettura libera dell'archivio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga conservata
    /// non è interpretabile.
    pub fn hub_review_content(
        &self,
        content_id: ContentId,
    ) -> StorageResult<Option<ReviewContent>> {
        let riga = self
            .connection
            .query_row(
                "SELECT contents.id, sources.identifier, sources.display_name,
                        contents.published_at, contents.body, alerts.level,
                        (SELECT COUNT(*) FROM reviews WHERE reviews.content_id = contents.id)
                 FROM contents
                 JOIN sources ON sources.id = contents.source_id
                 JOIN alerts ON alerts.content_id = contents.id
                 WHERE contents.id = ?1",
                params![content_id.get()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()?;

        let Some((id, source, source_name, published_at, body, level, version)) = riga else {
            return Ok(None);
        };

        Ok(Some(ReviewContent {
            content_id: ContentId::new(id),
            source: SourceIdentifier::try_new(&source)?,
            source_name: DisplayName::try_new(&source_name)?,
            published_at: instant(published_at),
            body,
            level: livello(level)?,
            version: u64::try_from(version).unwrap_or(0),
        }))
    }

    /// Quante revisioni porta un contenuto: la sua **versione**.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn hub_review_version(&self, content_id: ContentId) -> StorageResult<u64> {
        let quante: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM reviews WHERE content_id = ?1",
            params![content_id.get()],
            |row| row.get(0),
        )?;
        Ok(u64::try_from(quante).unwrap_or(0))
    }

    /// Chi ha registrato l'ultima revisione di un contenuto, e in quale stato.
    ///
    /// Serve al conflitto: chi perde deve sapere **contro che cosa**, e **chi**
    /// c'era prima (ADR-0089).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se la riga non è
    /// interpretabile.
    pub fn hub_latest_review(
        &self,
        content_id: ContentId,
    ) -> StorageResult<Option<(ReviewState, String, Timestamp)>> {
        let riga = self
            .connection
            .query_row(
                "SELECT state, reviewer, decided_at FROM reviews
                 WHERE content_id = ?1
                 ORDER BY decided_at DESC, id DESC LIMIT 1",
                params![content_id.get()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;

        let Some((state, reviewer, decided_at)) = riga else {
            return Ok(None);
        };
        Ok(Some((
            ReviewState::from_str(&state)?,
            reviewer,
            instant(decided_at),
        )))
    }
}

/// Il livello conservato, riportato nell'intervallo del dominio.
fn livello(valore: i64) -> StorageResult<u8> {
    u8::try_from(valore).map_err(|_| StorageError::CorruptedRow {
        detail: "il livello conservato non è rappresentabile",
    })
}

impl Database {
    /// Lo stato dell'ultima revisione di un contenuto, dentro una transazione
    /// in corso.
    ///
    /// Serve all'assegnazione, che deve sapere se il lavoro è già stato fatto
    /// **nella stessa transazione** che scrive (TEAM-ASSIGN-01, ADR-0098,
    /// decisione 4).
    ///
    /// # Errori
    ///
    /// Un errore di lettura, o se lo stato conservato non è interpretabile.
    pub fn hub_review_state_in(
        transaction: &rusqlite::Transaction<'_>,
        content_id: ContentId,
    ) -> StorageResult<Option<ReviewState>> {
        let stato: Option<String> = transaction
            .query_row(
                "SELECT state FROM reviews WHERE content_id = ?1
                  ORDER BY decided_at DESC, id DESC LIMIT 1",
                params![content_id.get()],
                |row| row.get(0),
            )
            .optional()
            .map_err(StorageError::Sqlite)?;

        let Some(stato) = stato else {
            return Ok(None);
        };
        Ok(Some(ReviewState::from_str(&stato)?))
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::hub_review::ReviewQueueCursor;
    use lisi_core::model::review::ReviewState;
    use lisi_core::model::{AlertLevel, NewAlert, NewReview};
    use lisi_core::text::{Actor, AlertReason};
    use lisi_core::{ContentId, Timestamp};

    use crate::test_support::{database_with_session, new_content};

    fn adesso() -> Timestamp {
        Timestamp::from_millis(1_759_000_000_000)
    }

    fn attore() -> Actor {
        match Actor::try_new("postazione.prova") {
            Ok(attore) => attore,
            Err(errore) => panic!("attore: {errore}"),
        }
    }

    /// Un contenuto con il suo avviso, e l'identificativo che ne esce.
    fn contenuto_segnalato(
        database: &mut crate::database::Database,
        session_id: lisi_core::SessionId,
        source_id: lisi_core::SourceId,
        remoto: &str,
        testo: &str,
    ) -> ContentId {
        let contenuto = new_content(session_id, source_id, remoto, testo);
        let Ok(inserimento) = database.insert_content(&contenuto) else {
            panic!("il contenuto deve potersi inserire");
        };
        let content_id = inserimento.content_id();
        let (Ok(analisi), Ok(reason)) = (
            lisi_core::model::AnalysisLevel::try_new(3),
            AlertReason::try_new("termine sorvegliato"),
        ) else {
            panic!("livello e motivo");
        };
        let Ok(level) = AlertLevel::try_new(analisi) else {
            panic!("il livello deve comportare un allarme");
        };
        if database
            .insert_alert(&NewAlert {
                content_id,
                level,
                reason,
                raised_at: adesso(),
            })
            .is_err()
        {
            panic!("l'avviso deve potersi inserire");
        }
        content_id
    }

    #[test]
    fn the_queue_carries_metadata_and_never_the_text() {
        let (mut database, source_id, session_id) = database_with_session();
        let content_id =
            contenuto_segnalato(&mut database, session_id, source_id, "1", "domani alle sei");

        let Ok(coda) = database.hub_review_queue(ReviewQueueCursor::start()) else {
            panic!("la coda deve potersi leggere");
        };
        assert_eq!(coda.len(), 1);
        assert_eq!(coda[0].content_id, content_id);
        assert_eq!(coda[0].level, 3);
        assert!(coda[0].is_untouched());
        assert_eq!(coda[0].version, 0);
    }

    #[test]
    fn the_queue_moves_forward_with_the_cursor() {
        let (mut database, source_id, session_id) = database_with_session();
        let primo = contenuto_segnalato(&mut database, session_id, source_id, "primo", "primo");
        let secondo =
            contenuto_segnalato(&mut database, session_id, source_id, "secondo", "secondo");

        let Ok(coda) = database.hub_review_queue(ReviewQueueCursor {
            after_content_id: primo.get(),
            limit: 10,
        }) else {
            panic!("la coda deve potersi leggere");
        };
        assert_eq!(coda.len(), 1);
        assert_eq!(coda[0].content_id, secondo);
    }

    #[test]
    fn a_decision_raises_the_version_and_shows_the_state() {
        let (mut database, source_id, session_id) = database_with_session();
        let content_id =
            contenuto_segnalato(&mut database, session_id, source_id, "terzo", "terzo");
        if database
            .insert_review(&NewReview {
                content_id,
                state: ReviewState::Relevant,
                reviewer: attore(),
                note: None,
                decided_at: adesso(),
            })
            .is_err()
        {
            panic!("la revisione deve potersi registrare");
        }

        assert_eq!(database.hub_review_version(content_id).ok(), Some(1));
        let Ok(coda) = database.hub_review_queue(ReviewQueueCursor::start()) else {
            panic!("la coda deve potersi leggere");
        };
        assert_eq!(coda[0].state, Some(ReviewState::Relevant));
        assert_eq!(coda[0].version, 1);

        let Ok(Some((stato, chi, _))) = database.hub_latest_review(content_id) else {
            panic!("l'ultima revisione deve esserci");
        };
        assert_eq!(stato, ReviewState::Relevant);
        assert_eq!(chi, "postazione.prova");
    }

    #[test]
    fn the_content_is_delivered_only_when_it_was_flagged() {
        let (mut database, source_id, session_id) = database_with_session();
        let content_id =
            contenuto_segnalato(&mut database, session_id, source_id, "quarto", "quarto");
        let Ok(Some(contenuto)) = database.hub_review_content(content_id) else {
            panic!("il contenuto segnalato deve potersi consegnare");
        };
        assert_eq!(contenuto.body, "quarto");
        assert_eq!(contenuto.level, 3);

        let inesistente = ContentId::new(9_999);
        assert_eq!(database.hub_review_content(inesistente).ok(), Some(None));
    }

    #[test]
    fn a_cursor_without_a_ceiling_is_refused() {
        let (database, _source_id, _session_id) = database_with_session();
        assert!(
            database
                .hub_review_queue(ReviewQueueCursor {
                    after_content_id: 0,
                    limit: 0,
                })
                .is_err()
        );
    }
}

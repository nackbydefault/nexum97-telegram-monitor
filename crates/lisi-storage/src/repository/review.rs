//! Revisioni umane.

use core::str::FromStr;

use lisi_core::model::{NewReview, Review, ReviewState};
use lisi_core::text::{Actor, Note};
use lisi_core::{ContentId, ReviewId};
use rusqlite::{OptionalExtension, Row};

use crate::database::Database;
use crate::error::{ConstraintKind, StorageError, StorageResult, constraint_kind};
use crate::repository::{instant, millis};

/// Riga grezza della tabella `reviews`.
struct ReviewRow {
    id: i64,
    content_id: i64,
    state: String,
    reviewer: String,
    note: Option<String>,
    decided_at: i64,
}

impl ReviewRow {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            content_id: row.get(1)?,
            state: row.get(2)?,
            reviewer: row.get(3)?,
            note: row.get(4)?,
            decided_at: row.get(5)?,
        })
    }

    fn into_domain(self) -> StorageResult<Review> {
        let note = match self.note {
            Some(ref raw) => Some(Note::try_new(raw)?),
            None => None,
        };

        Ok(Review {
            id: ReviewId::new(self.id),
            content_id: ContentId::new(self.content_id),
            state: ReviewState::from_str(&self.state)?,
            reviewer: Actor::try_new(&self.reviewer)?,
            note,
            decided_at: instant(self.decided_at),
        })
    }
}

impl Database {
    /// Registra una revisione.
    ///
    /// Le revisioni sono uno storico e non uno stato: ogni decisione resta
    /// conservata, così che il percorso di valutazione di un contenuto sia
    /// leggibile a posteriori.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se il contenuto non esiste.
    pub fn insert_review(&self, review: &NewReview) -> StorageResult<ReviewId> {
        let id: i64 = self
            .connection
            .query_row(
                "INSERT INTO reviews (content_id, state, reviewer, note, decided_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 RETURNING id",
                rusqlite::params![
                    review.content_id.get(),
                    review.state.as_str(),
                    review.reviewer.as_str(),
                    review.note.as_ref().map(Note::as_str),
                    millis(review.decided_at),
                ],
                |row| row.get(0),
            )
            .map_err(|error| {
                if constraint_kind(&error) == Some(ConstraintKind::ForeignKey) {
                    StorageError::NotFound {
                        entity: "contenuto",
                        id: review.content_id.get(),
                    }
                } else {
                    StorageError::Sqlite(error)
                }
            })?;

        Ok(ReviewId::new(id))
    }

    /// Registra una revisione **dentro una transazione già aperta**.
    ///
    /// Serve al comando della revisione condivisa (TEAM-REVIEW-01, ADR-0094):
    /// la riga, l'evento della sequenza e la memoria del comando devono essere
    /// atomici o non esserlo affatto (ADR-0089).
    ///
    /// # Errori
    ///
    /// Gli stessi di [`Database::insert_review`].
    pub fn insert_review_in(
        transaction: &rusqlite::Transaction<'_>,
        review: &NewReview,
    ) -> StorageResult<ReviewId> {
        let id: i64 = transaction
            .query_row(
                "INSERT INTO reviews (content_id, state, reviewer, note, decided_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 RETURNING id",
                rusqlite::params![
                    review.content_id.get(),
                    review.state.as_str(),
                    review.reviewer.as_str(),
                    review.note.as_ref().map(Note::as_str),
                    millis(review.decided_at),
                ],
                |row| row.get(0),
            )
            .map_err(|error| {
                if constraint_kind(&error) == Some(ConstraintKind::ForeignKey) {
                    StorageError::NotFound {
                        entity: "contenuto",
                        id: review.content_id.get(),
                    }
                } else {
                    StorageError::Sqlite(error)
                }
            })?;

        Ok(ReviewId::new(id))
    }

    /// Storico delle revisioni di un contenuto, dalla più antica.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// valore non conforme al dominio.
    pub fn content_reviews(&self, content_id: ContentId) -> StorageResult<Vec<Review>> {
        let mut statement = self.connection.prepare(
            "SELECT id, content_id, state, reviewer, note, decided_at
             FROM reviews
             WHERE content_id = ?1
             ORDER BY decided_at, id",
        )?;

        let rows = statement.query_map([content_id.get()], ReviewRow::read)?;

        let mut reviews = Vec::new();
        for row in rows {
            reviews.push(row?.into_domain()?);
        }
        Ok(reviews)
    }

    /// Ultima revisione di un contenuto, se ne esiste una.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se la riga contiene un
    /// valore non conforme al dominio.
    pub fn latest_review(&self, content_id: ContentId) -> StorageResult<Option<Review>> {
        let row = self
            .connection
            .query_row(
                "SELECT id, content_id, state, reviewer, note, decided_at
                 FROM reviews
                 WHERE content_id = ?1
                 ORDER BY decided_at DESC, id DESC
                 LIMIT 1",
                [content_id.get()],
                ReviewRow::read,
            )
            .optional()?;

        row.map(ReviewRow::into_domain).transpose()
    }

    /// L'ultima revisione di un contenuto decisa **entro** l'istante indicato.
    ///
    /// Serve alla relazione, che fotografa lo stato della revisione e deve
    /// dirne il motivo (INSTALLED-APP-E2E-01, E2E01-12). Le revisioni si
    /// aggiungono e non si riscrivono: letta all'istante della fotografia, la
    /// risposta è la stessa oggi e domani, anche dopo una decisione nuova.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se la riga contiene un
    /// valore non conforme al dominio.
    pub fn review_as_of(
        &self,
        content_id: ContentId,
        at: lisi_core::Timestamp,
    ) -> StorageResult<Option<Review>> {
        let row = self
            .connection
            .query_row(
                "SELECT id, content_id, state, reviewer, note, decided_at
                 FROM reviews
                 WHERE content_id = ?1 AND decided_at <= ?2
                 ORDER BY decided_at DESC, id DESC
                 LIMIT 1",
                rusqlite::params![content_id.get(), at.as_millis()],
                ReviewRow::read,
            )
            .optional()?;

        row.map(ReviewRow::into_domain).transpose()
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::{NewReview, ReviewState};
    use lisi_core::text::Note;
    use lisi_core::{ContentId, Timestamp};

    use crate::error::StorageError;
    use crate::test_support::{actor, database_with_session, later, new_content};

    fn new_review(
        content_id: ContentId,
        state: ReviewState,
        decided_at: Timestamp,
        note: Option<&str>,
    ) -> NewReview {
        let note = note.map(|raw| {
            let Ok(note) = Note::try_new(raw) else {
                panic!("la nota di prova deve essere valida");
            };
            note
        });

        NewReview {
            content_id,
            state,
            reviewer: actor("operatore.prova"),
            note,
            decided_at,
        }
    }

    /// **La revisione a un istante non vede quelle decise dopo** (E2E01-12).
    #[test]
    fn la_revisione_a_un_istante_non_vede_quelle_decise_dopo() {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(insertion) =
            database.insert_content(&new_content(session_id, source_id, "1", "messaggio"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = insertion.content_id();
        for (stato, quando, nota) in [
            (ReviewState::Reported, later(60), "fonte da tenere d'occhio"),
            (ReviewState::Relevant, later(120), "confermato"),
        ] {
            let Ok(_) = database.insert_review(&new_review(content_id, stato, quando, Some(nota)))
            else {
                panic!("la revisione deve potersi registrare");
            };
        }

        let Ok(Some(allora)) = database.review_as_of(content_id, later(90)) else {
            panic!("una revisione c'era");
        };
        assert_eq!(allora.state, ReviewState::Reported);
        assert_eq!(
            allora.note.as_ref().map(Note::as_str),
            Some("fonte da tenere d'occhio")
        );
        let Ok(prima) = database.review_as_of(content_id, later(30)) else {
            panic!("la lettura deve riuscire");
        };
        assert!(prima.is_none());
    }

    #[test]
    fn a_review_is_written_and_read_back_unchanged() {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(insertion) =
            database.insert_content(&new_content(session_id, source_id, "1", "messaggio"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = insertion.content_id();

        let Ok(id) = database.insert_review(&new_review(
            content_id,
            ReviewState::Relevant,
            later(60),
            Some("Confermato dall'operatore"),
        )) else {
            panic!("la revisione deve potersi registrare");
        };

        let Ok(Some(review)) = database.latest_review(content_id) else {
            panic!("la revisione deve potersi rileggere");
        };
        assert_eq!(review.id, id);
        assert_eq!(review.state, ReviewState::Relevant);
        assert_eq!(review.reviewer.as_str(), "operatore.prova");
        assert_eq!(
            review.note.as_ref().map(Note::as_str),
            Some("Confermato dall'operatore")
        );
        assert_eq!(review.decided_at, later(60));
    }

    #[test]
    fn a_review_without_a_note_is_accepted() {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(insertion) =
            database.insert_content(&new_content(session_id, source_id, "1", "messaggio"))
        else {
            panic!("il contenuto deve potersi registrare");
        };

        let Ok(_) = database.insert_review(&new_review(
            insertion.content_id(),
            ReviewState::New,
            later(10),
            None,
        )) else {
            panic!("la revisione senza nota deve potersi registrare");
        };

        let Ok(Some(review)) = database.latest_review(insertion.content_id()) else {
            panic!("la revisione deve potersi rileggere");
        };
        assert_eq!(review.note, None);
    }

    #[test]
    fn every_decision_is_kept_and_the_latest_one_wins() {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(insertion) =
            database.insert_content(&new_content(session_id, source_id, "1", "messaggio"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = insertion.content_id();

        for (state, seconds) in [
            (ReviewState::New, 10),
            (ReviewState::InReview, 20),
            (ReviewState::Relevant, 30),
            (ReviewState::Reported, 40),
        ] {
            let Ok(_) =
                database.insert_review(&new_review(content_id, state, later(seconds), None))
            else {
                panic!("la revisione deve potersi registrare");
            };
        }

        let Ok(reviews) = database.content_reviews(content_id) else {
            panic!("lo storico deve potersi leggere");
        };
        assert_eq!(reviews.len(), 4);
        assert_eq!(reviews[0].state, ReviewState::New);
        assert_eq!(reviews[3].state, ReviewState::Reported);

        let Ok(Some(latest)) = database.latest_review(content_id) else {
            panic!("l'ultima revisione deve potersi leggere");
        };
        assert_eq!(latest.state, ReviewState::Reported);
    }

    #[test]
    fn a_review_on_a_missing_content_is_refused() {
        let (database, _source_id, _session_id) = database_with_session();
        assert!(matches!(
            database.insert_review(&new_review(
                ContentId::new(404),
                ReviewState::New,
                later(10),
                None
            )),
            Err(StorageError::NotFound {
                entity: "contenuto",
                id: 404
            })
        ));
    }

    #[test]
    fn a_content_without_reviews_has_none() {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(insertion) =
            database.insert_content(&new_content(session_id, source_id, "1", "messaggio"))
        else {
            panic!("il contenuto deve potersi registrare");
        };

        assert_eq!(
            database.latest_review(insertion.content_id()).ok(),
            Some(None)
        );
    }

    #[test]
    fn every_review_state_is_accepted_by_the_schema() {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(insertion) =
            database.insert_content(&new_content(session_id, source_id, "1", "messaggio"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = insertion.content_id();

        for (index, state) in ReviewState::all().iter().enumerate() {
            let seconds = i64::try_from(index).unwrap_or(0);
            let Ok(_) =
                database.insert_review(&new_review(content_id, *state, later(seconds), None))
            else {
                panic!("lo stato {state} deve essere ammesso dallo schema");
            };
        }

        assert_eq!(
            database.content_reviews(content_id).map(|r| r.len()).ok(),
            Some(ReviewState::all().len())
        );
    }
}

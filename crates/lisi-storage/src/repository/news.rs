//! L'ultima edizione delle novità vista (NEWS-01, ADR-0169, migrazione 0068).
//!
//! Una riga sola, o nessuna. **Nessuna riga** vuol dire che non è mai stata
//! registrata un'edizione. Il numero **non scende**: un archivio aperto da un
//! programma più vecchio non rivede le novità che aveva già visto.
//!
//! Non è audit: nessun attore, nessun testo libero.

use rusqlite::OptionalExtension;

use crate::database::Database;
use crate::error::StorageResult;

impl Database {
    /// L'ultima edizione delle novità registrata, se ce n'è una.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn news_seen_edition(&self) -> StorageResult<Option<u32>> {
        let riga: Option<i64> = self
            .connection
            .query_row(
                "SELECT seen_edition FROM news_state WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(riga.and_then(|edizione| u32::try_from(edizione).ok()))
    }

    /// Registra un'edizione come vista. Se ne era registrata una più alta,
    /// resta quella.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce o se l'edizione è zero.
    pub fn record_news_seen_edition(&self, edition: u32, now_ms: i64) -> StorageResult<()> {
        self.connection.execute(
            "INSERT INTO news_state (id, seen_edition, updated_at)
             VALUES (1, ?1, ?2)
             ON CONFLICT (id) DO UPDATE SET
                 seen_edition = max(news_state.seen_edition, excluded.seen_edition),
                 updated_at = excluded.updated_at",
            rusqlite::params![i64::from(edition), now_ms],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::database;

    /// **Un archivio nuovo non ha un'edizione; quella registrata si rilegge e
    /// non scende; lo zero si rifiuta** (NEWS-01, criterio 3; prova negativa:
    /// l'edizione che scende → rossa).
    #[test]
    fn l_edizione_vista_si_registra_e_non_scende() {
        let database = database();
        assert_eq!(database.news_seen_edition().ok(), Some(None));
        assert!(database.record_news_seen_edition(0, 1).is_err());
        assert_eq!(database.news_seen_edition().ok(), Some(None));

        let Ok(()) = database.record_news_seen_edition(2, 10) else {
            panic!("l'edizione deve registrarsi");
        };
        assert_eq!(database.news_seen_edition().ok(), Some(Some(2)));

        let Ok(()) = database.record_news_seen_edition(1, 20) else {
            panic!("un'edizione più vecchia non è un errore");
        };
        assert_eq!(database.news_seen_edition().ok(), Some(Some(2)));

        let Ok(()) = database.record_news_seen_edition(3, 30) else {
            panic!("un'edizione più nuova deve registrarsi");
        };
        assert_eq!(database.news_seen_edition().ok(), Some(Some(3)));
    }
}

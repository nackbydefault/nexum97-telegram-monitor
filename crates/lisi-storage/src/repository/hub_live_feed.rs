//! La proiezione locale del live condiviso (TEAM-LIVE-01, ADR-0093).
//!
//! # Non è la storia dell'Hub
//!
//! È ciò che si vede sullo schermo: le ultime righe, potate a ogni scrittura.
//! La storia autorevole sta sull'Hub (ADR-0086) e il punto raggiunto da questa
//! postazione sta nel cursore (ADR-0087), quindi potare non perde nulla.
//!
//! # Riapplicare non raddoppia
//!
//! Il numero è quello dell'Hub, ed è la chiave primaria: il recupero che
//! riapplica l'ultimo evento dopo un arresto a metà (ADR-0087) trova la riga
//! già presente e la lascia com'è.

use lisi_core::model::hub_event::{HubEvent, HubEventKind};
use lisi_core::model::hub_live::rows_to_prune;
use lisi_core::text::{HubEventDetail, HubEventSubject};
use rusqlite::params;

use crate::database::Database;
use crate::error::{StorageError, StorageResult};
use crate::repository::{instant, millis};

impl Database {
    /// Registra un evento nella proiezione e pota le righe in eccesso.
    ///
    /// Restituisce `true` se la riga è stata scritta ora, `false` se c'era già:
    /// riapplicare lo stesso evento non è un errore ed è ciò che rende
    /// l'operazione ripetibile.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura o la potatura non riescono.
    /// # Perché qui non c'è una transazione
    ///
    /// Scrittura e potatura sono due istruzioni, e fra l'una e l'altra un
    /// secondo scrittore può inserirne una terza. L'esito peggiore è **una
    /// riga in più o in meno sullo schermo**, che si corregge alla scrittura
    /// successiva: la proiezione è un limite di visualizzazione, non un
    /// invariante. Ciò che non si può perdere — il punto raggiunto — sta nel
    /// cursore, che ha la sua transazione (ADR-0087).
    pub fn record_hub_live_event(&self, event: &HubEvent, cap: usize) -> StorageResult<bool> {
        let scritte = self.connection.execute(
            "INSERT OR IGNORE INTO hub_live_feed (sequence, kind, subject, detail, recorded_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                i64::try_from(event.sequence).map_err(|_| StorageError::CorruptedRow {
                    detail: "numero dell'evento del live fuori dall'intervallo rappresentabile",
                })?,
                event.kind.as_str(),
                event.subject.as_str(),
                event.detail.as_ref().map(|detail| detail.as_str()),
                millis(event.recorded_at),
            ],
        )?;

        // LA POTATURA E' IL FUNZIONAMENTO NORMALE, non una manomissione: la
        // proiezione mostra le ultime righe e non conserva una storia.
        let eccesso = rows_to_prune(self.hub_live_feed_len()?, cap);
        if eccesso > 0 {
            self.connection.execute(
                "DELETE FROM hub_live_feed WHERE sequence IN (\
                   SELECT sequence FROM hub_live_feed ORDER BY sequence ASC LIMIT ?1)",
                params![i64::try_from(eccesso).unwrap_or(i64::MAX)],
            )?;
        }

        Ok(scritte == 1)
    }

    /// Le ultime righe del live, dalla più recente alla più vecchia.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga conservata
    /// non è interpretabile.
    pub fn hub_live_feed(&self, limit: usize) -> StorageResult<Vec<HubEvent>> {
        let mut statement = self.connection.prepare(
            "SELECT sequence, kind, subject, detail, recorded_at FROM hub_live_feed \
             ORDER BY sequence DESC LIMIT ?1",
        )?;
        let righe =
            statement.query_map(params![i64::try_from(limit).unwrap_or(i64::MAX)], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?;

        let mut eventi = Vec::new();
        for riga in righe {
            let (sequence, kind, subject, detail, recorded_at) = riga?;
            let sequence = u64::try_from(sequence).map_err(|_| StorageError::CorruptedRow {
                detail: "numero dell'evento del live conservato negativo",
            })?;
            let kind = HubEventKind::parse(&kind)?;
            let subject = HubEventSubject::try_new(&subject)?;
            let detail = detail.as_deref().map(HubEventDetail::try_new).transpose()?;
            eventi.push(HubEvent {
                sequence,
                kind,
                subject,
                detail,
                recorded_at: instant(recorded_at),
            });
        }
        Ok(eventi)
    }

    /// Quante righe conserva la proiezione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn hub_live_feed_len(&self) -> StorageResult<usize> {
        let righe: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM hub_live_feed", [], |row| row.get(0))?;
        Ok(usize::try_from(righe).unwrap_or(0))
    }

    /// Svuota la proiezione.
    ///
    /// Accompagna «dimentica il punto di lettura» (ADR-0087): dopo quell'atto
    /// le righe mostrate apparterrebbero a una storia che la postazione non
    /// segue più.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la cancellazione non riesce.
    pub fn clear_hub_live_feed(&self) -> StorageResult<()> {
        self.connection.execute("DELETE FROM hub_live_feed", [])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::hub_event::{HubEvent, HubEventKind};
    use lisi_core::text::HubEventSubject;

    use crate::database::Database;

    fn adesso() -> Timestamp {
        Timestamp::from_millis(1_759_000_000_000)
    }

    fn evento(sequence: u64) -> HubEvent {
        let Ok(subject) = HubEventSubject::try_new("@fonte") else {
            panic!("soggetto");
        };
        HubEvent {
            sequence,
            kind: HubEventKind::ContentAcquired,
            subject,
            detail: None,
            recorded_at: adesso(),
        }
    }

    fn archivio() -> Database {
        match Database::open_in_memory() {
            Ok(database) => database,
            Err(errore) => panic!("archivio di prova: {errore}"),
        }
    }

    #[test]
    fn the_feed_returns_the_most_recent_first() {
        let database = archivio();
        for numero in 1..=3 {
            let Ok(true) = database.record_hub_live_event(&evento(numero), 500) else {
                panic!("la riga deve potersi scrivere");
            };
        }
        let Ok(righe) = database.hub_live_feed(10) else {
            panic!("la lettura deve riuscire");
        };
        let numeri: Vec<u64> = righe.iter().map(|evento| evento.sequence).collect();
        assert_eq!(numeri, vec![3, 2, 1]);
    }

    #[test]
    fn applying_the_same_event_twice_does_not_double_the_row() {
        let database = archivio();
        let Ok(true) = database.record_hub_live_event(&evento(7), 500) else {
            panic!("la prima scrittura deve riuscire");
        };
        let Ok(false) = database.record_hub_live_event(&evento(7), 500) else {
            panic!("la seconda scrittura deve dire che la riga c'era già");
        };
        assert_eq!(database.hub_live_feed_len().ok(), Some(1));
    }

    #[test]
    fn the_projection_is_pruned_to_the_cap() {
        let database = archivio();
        for numero in 1..=10 {
            let Ok(_) = database.record_hub_live_event(&evento(numero), 4) else {
                panic!("la riga deve potersi scrivere");
            };
        }
        assert_eq!(database.hub_live_feed_len().ok(), Some(4));
        let Ok(righe) = database.hub_live_feed(10) else {
            panic!("la lettura deve riuscire");
        };
        let numeri: Vec<u64> = righe.iter().map(|evento| evento.sequence).collect();
        assert_eq!(
            numeri,
            vec![10, 9, 8, 7],
            "la potatura toglie le righe più vecchie, non le più recenti"
        );
    }

    #[test]
    fn the_projection_can_be_emptied() {
        let database = archivio();
        let Ok(_) = database.record_hub_live_event(&evento(1), 500) else {
            panic!("la riga deve potersi scrivere");
        };
        let Ok(()) = database.clear_hub_live_feed() else {
            panic!("lo svuotamento deve riuscire");
        };
        assert_eq!(database.hub_live_feed_len().ok(), Some(0));
    }
}

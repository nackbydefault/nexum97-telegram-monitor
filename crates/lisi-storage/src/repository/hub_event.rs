//! Il registro degli eventi dell'Hub (HUB-EVENT-01, ADR-0086).
//!
//! # Il numero si assegna dentro la transazione
//!
//! `sequence` è «il più alto finora, più uno», letto e scritto nella **stessa
//! transazione immediata**. SQLite serializza chi scrive, quindi due scritture
//! non possono scegliere lo stesso numero; e una transazione annullata non ne
//! consuma nessuno, che è la differenza con un `AUTOINCREMENT`.
//!
//! # Le letture sono limitate
//!
//! Un recupero chiede «che cosa è successo dopo il numero N», e riceve **al più
//! [`MAX_EVENTS_PER_READ`]** eventi: un client che torna dopo giorni non deve
//! poter chiedere all'Hub di costruire in memoria tutta la storia.

use lisi_core::Timestamp;
use lisi_core::model::hub_event::{
    HUB_STREAM_ID_BYTES, HubEvent, HubEventKind, HubEventStreamId, MAX_EVENTS_PER_READ, NewHubEvent,
};
use lisi_core::text::{HubEventDetail, HubEventSubject};
use rusqlite::{OptionalExtension, params};

use crate::database::Database;
use crate::error::{StorageError, StorageResult};
use crate::repository::{instant, millis};

impl Database {
    /// Scrive un evento e restituisce il numero che l'Hub gli ha dato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn append_hub_event(&mut self, event: &NewHubEvent, now: Timestamp) -> StorageResult<u64> {
        // **IMMEDIATE, non la transazione predefinita.**
        //
        // Qui si legge il numero più alto e poi si scrive: con la transazione
        // predefinita `DEFERRED`, due scritture concorrenti leggerebbero
        // entrambe e poi vorrebbero scrivere entrambe, e SQLite risponderebbe
        // **subito** `SQLITE_BUSY` alla seconda, senza aspettare il timeout:
        // un evento perso con un errore tecnico, a caso.
        //
        // `IMMEDIATE` prende il lucchetto di scrittura all'inizio: la seconda
        // aspetta il proprio turno e poi legge un numero più alto.
        //
        // E' lo stesso difetto che la prova di concorrenza dell'arruolamento
        // aveva gia' trovato una volta, e che ha trovato di nuovo qui: la
        // nota del modulo diceva «transazione immediata», il codice no.
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let sequence = append_hub_event_in(&transaction, event, now)?;
        transaction.commit()?;
        Ok(sequence)
    }

    /// L'ultimo numero emesso; zero se non è mai successo nulla.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn latest_hub_sequence(&self) -> StorageResult<u64> {
        let massimo: i64 = self.connection.query_row(
            "SELECT COALESCE(MAX(sequence), 0) FROM hub_events",
            [],
            |row| row.get(0),
        )?;
        u64::try_from(massimo).map_err(|_| StorageError::CorruptedRow {
            detail: "il numero di sequenza conservato non è rappresentabile",
        })
    }

    /// Gli eventi **dopo** il numero indicato, in ordine di numero.
    ///
    /// Ne restituisce al più `limit`, e comunque non più di
    /// [`MAX_EVENTS_PER_READ`]: il limite del chiamante non può alzare quello
    /// del prodotto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga conservata
    /// non è interpretabile.
    pub fn hub_events_after(&self, after: u64, limit: usize) -> StorageResult<Vec<HubEvent>> {
        let limite = limit.min(MAX_EVENTS_PER_READ);
        let dopo = i64::try_from(after).unwrap_or(i64::MAX);

        let mut statement = self.connection.prepare(
            "SELECT sequence, kind, subject, detail, recorded_at
               FROM hub_events
              WHERE sequence > ?1
              -- L'ORDINE VIENE DAL NUMERO, MAI DALL'ORA.
              ORDER BY sequence ASC
              LIMIT ?2",
        )?;
        let righe =
            statement.query_map(params![dopo, i64::try_from(limite).unwrap_or(0)], |row| {
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
            eventi.push(leggi_evento(riga?)?);
        }
        Ok(eventi)
    }

    /// Il nome del flusso di questo Hub, creandolo alla prima richiesta con i
    /// byte casuali forniti.
    ///
    /// I byte vengono dal generatore del sistema, che l'archivio non possiede.
    /// Chiamate successive restituiscono **sempre** il flusso già scritto: i
    /// byte nuovi si scartano, perché rinominare il flusso significherebbe
    /// dire a ogni client che la storia è cambiata.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura o la lettura non riescono, o se il
    /// valore conservato non è interpretabile.
    pub fn hub_event_stream_id(
        &self,
        random_bytes: [u8; HUB_STREAM_ID_BYTES],
        now: Timestamp,
    ) -> StorageResult<HubEventStreamId> {
        if let Some(conservato) = self.stream_id_conservato()? {
            return Ok(conservato);
        }

        let nuovo = HubEventStreamId::from_random_bytes(random_bytes);
        // `OR IGNORE`: se un'altra scrittura è arrivata prima, la sua vince, e
        // la rilettura qui sotto restituisce quella.
        self.connection.execute(
            "INSERT OR IGNORE INTO hub_event_stream (id, stream_id, created_at)
             VALUES (1, ?1, ?2)",
            params![nuovo.to_hex(), millis(now)],
        )?;

        self.stream_id_conservato()?
            .ok_or(StorageError::CorruptedRow {
                detail: "il flusso degli eventi non si è potuto scrivere",
            })
    }

    /// Il flusso già conservato, se c'è.
    fn stream_id_conservato(&self) -> StorageResult<Option<HubEventStreamId>> {
        self.connection
            .query_row(
                "SELECT stream_id FROM hub_event_stream WHERE id = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|testo| Ok(HubEventStreamId::parse(&testo)?))
            .transpose()
    }
}

/// Scrive un evento **dentro una transazione già aperta**, e ne restituisce il
/// numero.
///
/// Esiste perché un comando deve poter scrivere il proprio effetto, il proprio
/// evento e la propria memoria **nella stessa transazione** (ADR-0089): tre
/// transazioni separate lascerebbero tre istanti in cui una sola delle tre
/// esiste, e ciascuno di quegli istanti è un modo di raddoppiare o di perdere.
///
/// La transazione la apre il chiamante, e deve essere `IMMEDIATE` per la
/// ragione scritta in `Database::append_hub_event`.
///
/// # Errori
///
/// Restituisce un errore se la scrittura non riesce.
pub fn append_hub_event_in(
    transaction: &rusqlite::Transaction<'_>,
    event: &NewHubEvent,
    now: Timestamp,
) -> StorageResult<u64> {
    // Il numero più alto finora. Zero se non è mai successo nulla.
    let precedente: i64 = transaction.query_row(
        "SELECT COALESCE(MAX(sequence), 0) FROM hub_events",
        [],
        |row| row.get(0),
    )?;
    let sequence = precedente.saturating_add(1);

    transaction.execute(
        "INSERT INTO hub_events (sequence, kind, subject, detail, recorded_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            sequence,
            event.kind.as_str(),
            event.subject.as_str(),
            event.detail.as_ref().map(HubEventDetail::as_str),
            millis(now)
        ],
    )?;

    u64::try_from(sequence).map_err(|_| StorageError::CorruptedRow {
        detail: "il numero di sequenza non è rappresentabile",
    })
}

/// Interpreta una riga del registro.
fn leggi_evento(riga: (i64, String, String, Option<String>, i64)) -> StorageResult<HubEvent> {
    let (sequence, kind, subject, detail, recorded_at) = riga;
    Ok(HubEvent {
        sequence: u64::try_from(sequence).map_err(|_| StorageError::CorruptedRow {
            detail: "il numero di sequenza conservato non è rappresentabile",
        })?,
        kind: HubEventKind::parse(&kind)?,
        subject: HubEventSubject::try_new(&subject)?,
        detail: detail.as_deref().map(HubEventDetail::try_new).transpose()?,
        recorded_at: instant(recorded_at),
    })
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::hub_event::{HUB_STREAM_ID_BYTES, HubEventKind, NewHubEvent};
    use lisi_core::text::HubEventSubject;

    use crate::database::Database;

    fn archivio() -> Database {
        let Ok(database) = Database::open_in_memory() else {
            panic!("archivio di prova");
        };
        database
    }

    fn evento(soggetto: &str) -> NewHubEvent {
        let Ok(subject) = HubEventSubject::try_new(soggetto) else {
            panic!("soggetto di prova");
        };
        NewHubEvent {
            kind: HubEventKind::DeviceEnrolled,
            subject,
            detail: None,
        }
    }

    fn adesso() -> Timestamp {
        Timestamp::from_millis(1_758_100_000_000)
    }

    #[test]
    fn the_sequence_starts_at_one_and_has_no_gaps() {
        let mut archivio = archivio();
        assert_eq!(archivio.latest_hub_sequence().ok(), Some(0));
        for atteso in 1..=5_u64 {
            assert_eq!(
                archivio
                    .append_hub_event(&evento("dispositivo"), adesso())
                    .ok(),
                Some(atteso)
            );
        }
        assert_eq!(archivio.latest_hub_sequence().ok(), Some(5));

        let Ok(eventi) = archivio.hub_events_after(0, 100) else {
            panic!("lettura");
        };
        let numeri: Vec<u64> = eventi.iter().map(|evento| evento.sequence).collect();
        assert_eq!(numeri, vec![1, 2, 3, 4, 5], "nessun salto");
    }

    /// **Due scritture insieme non si danno lo stesso numero, e non ne saltano
    /// nessuno.**
    ///
    /// # Il difetto che questa prova ha trovato
    ///
    /// La prima versione usava la transazione predefinita (`DEFERRED`): legge il
    /// numero più alto, poi scrive. Due fili leggevano entrambi e poi volevano
    /// scrivere entrambi, e SQLite rispondeva subito `SQLITE_BUSY` al secondo —
    /// un evento perso con un errore tecnico, a caso. Lo ha reso rosso la prova
    /// di concorrenza dell'arruolamento, che passa di qui da quando l'ammissione
    /// scrive un evento. Ora la transazione è `IMMEDIATE`.
    #[test]
    fn two_writers_never_share_a_number() {
        const GIRI: u32 = 12;

        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        let percorso = cartella.path().join("hub.sqlite3");
        {
            let Ok(_) = Database::open(&percorso) else {
                panic!("archivio su file");
            };
        }

        for _ in 0..GIRI {
            std::thread::scope(|ambito| {
                for soggetto in ["primo", "secondo"] {
                    let percorso = percorso.clone();
                    ambito.spawn(move || {
                        let Ok(mut archivio) = Database::open(&percorso) else {
                            panic!("archivio su file");
                        };
                        let esito = archivio.append_hub_event(&evento(soggetto), adesso());
                        assert!(
                            esito.is_ok(),
                            "una scrittura concorrente non deve fallire con un errore tecnico: {esito:?}"
                        );
                    });
                }
            });
        }

        let Ok(archivio) = Database::open(&percorso) else {
            panic!("archivio su file");
        };
        let Ok(eventi) = archivio.hub_events_after(0, 500) else {
            panic!("lettura");
        };
        let numeri: Vec<u64> = eventi.iter().map(|evento| evento.sequence).collect();
        let attesi: Vec<u64> = (1..=u64::from(GIRI) * 2).collect();
        assert_eq!(numeri, attesi, "numeri distinti, in ordine, senza salti");
    }

    #[test]
    fn the_order_is_the_number_even_when_the_clock_goes_backwards() {
        let mut archivio = archivio();
        let tardi = Timestamp::from_millis(adesso().as_millis() + 60_000);
        let presto = Timestamp::from_millis(adesso().as_millis() - 60_000);
        let Ok(primo) = archivio.append_hub_event(&evento("primo"), tardi) else {
            panic!("scrittura");
        };
        let Ok(secondo) = archivio.append_hub_event(&evento("secondo"), presto) else {
            panic!("scrittura");
        };
        assert!(secondo > primo, "l'orologio non decide il numero");

        let Ok(eventi) = archivio.hub_events_after(0, 100) else {
            panic!("lettura");
        };
        let soggetti: Vec<&str> = eventi
            .iter()
            .map(|evento| evento.subject.as_str())
            .collect();
        assert_eq!(
            soggetti,
            vec!["primo", "secondo"],
            "l'ordine è il numero, non l'ora"
        );
    }

    #[test]
    fn reads_are_bounded_and_start_after_the_number_given() {
        let mut archivio = archivio();
        for _ in 0..10 {
            let _ = archivio.append_hub_event(&evento("dispositivo"), adesso());
        }
        let Ok(eventi) = archivio.hub_events_after(7, 2) else {
            panic!("lettura");
        };
        assert_eq!(
            eventi.iter().map(|e| e.sequence).collect::<Vec<u64>>(),
            vec![8, 9]
        );
        let Ok(tutti) = archivio.hub_events_after(0, usize::MAX) else {
            panic!("lettura");
        };
        assert_eq!(tutti.len(), 10);
        let Ok(nessuno) = archivio.hub_events_after(10, 5) else {
            panic!("lettura");
        };
        assert!(nessuno.is_empty());
    }

    #[test]
    fn history_cannot_be_rewritten() {
        let mut archivio = archivio();
        let _ = archivio.append_hub_event(&evento("dispositivo"), adesso());

        let modifica = archivio.connection.execute(
            "UPDATE hub_events SET subject = 'altro' WHERE sequence = 1",
            [],
        );
        assert!(modifica.is_err(), "un evento non si modifica");
        let cancellazione = archivio
            .connection
            .execute("DELETE FROM hub_events WHERE sequence = 1", []);
        assert!(cancellazione.is_err(), "un evento non si cancella");

        let Ok(eventi) = archivio.hub_events_after(0, 10) else {
            panic!("lettura");
        };
        assert_eq!(eventi.len(), 1);
        assert_eq!(eventi[0].subject.as_str(), "dispositivo");
    }

    #[test]
    fn the_stream_is_born_once_and_does_not_change() {
        let archivio = archivio();
        let Ok(primo) = archivio.hub_event_stream_id([3; HUB_STREAM_ID_BYTES], adesso()) else {
            panic!("flusso");
        };
        let Ok(secondo) = archivio.hub_event_stream_id([9; HUB_STREAM_ID_BYTES], adesso()) else {
            panic!("flusso");
        };
        assert_eq!(primo, secondo, "il flusso non si rinomina");

        let rinomina = archivio.connection.execute(
            "UPDATE hub_event_stream SET stream_id = ?1 WHERE id = 1",
            ["0".repeat(32)],
        );
        assert!(rinomina.is_err());
    }
}

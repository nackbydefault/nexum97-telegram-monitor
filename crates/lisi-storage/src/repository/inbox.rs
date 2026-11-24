//! Inbox di acquisizione, versioni e cancellazioni.
//!
//! È il livello di persistenza del runtime di acquisizione (ADR-0017). Tutte le
//! scritture qui usano `&self`: nessuna apre una transazione, perché ogni
//! operazione è una singola istruzione. L'unica eccezione del progetto —
//! `insert_content`, che apre una transazione e prende `&mut self` — resta dove
//! è.

use core::str::FromStr;
use std::collections::BTreeMap;

use lisi_core::digest::Sha256Digest;
use lisi_core::model::acquisition::{
    ContentDeletion, ContentVersion, InboxEntry, InboxEventKind, InboxOutcome, InboxState,
    NewContentDeletion, NewContentVersion, NewInboxEntry,
};
use lisi_core::model::content_history::{ContentHistory, ContentHistorySummary};
use lisi_core::text::RemoteMessageId;
use lisi_core::{ContentDeletionId, ContentId, ContentVersionId, InboxId, SessionId, SourceId};
use rusqlite::{OptionalExtension, Row};

use crate::database::Database;
use crate::error::{StorageError, StorageResult};
use crate::repository::{instant, millis};

/// Un evento ricevuto, ridotto a ciò che dice **quando** il programma
/// riceveva (PR-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceptionFact {
    /// Il genere dell'evento.
    pub kind: InboxEventKind,
    /// Quando è arrivato alla postazione.
    pub received_at: lisi_core::Timestamp,
    /// La fonte, quando l'evento è di una fonte.
    pub source_id: Option<SourceId>,
    /// Se l'evento ha portato in archivio un contenuto **recuperato** dalla
    /// cronologia (PR-07): prova che in quell'istante si era collegati, ma non
    /// che il messaggio sia arrivato dal vivo.
    pub recovered: bool,
}

/// Colonne dell'inbox lette in una riga, nell'ordine della query.
const INBOX_COLUMNS: &str = "id, session_id, source_id, event_kind, remote_event_id, \
     remote_timestamp, received_at, state, attempts, last_error_kind, next_attempt_at, \
     completed_at, payload_json, correlated_content_id";

fn read_inbox(row: &Row<'_>) -> StorageResult<InboxEntry> {
    let source_id: Option<i64> = row.get(2)?;
    let remote_event_id: Option<String> = row.get(4)?;
    let remote_timestamp: Option<i64> = row.get(5)?;
    let next_attempt_at: Option<i64> = row.get(10)?;
    let completed_at: Option<i64> = row.get(11)?;
    let correlated_content_id: Option<i64> = row.get(13)?;

    let event_kind = InboxEventKind::from_str(&row.get::<_, String>(3)?)?;
    let state = InboxState::from_str(&row.get::<_, String>(7)?)?;
    let attempts = u32::try_from(row.get::<_, i64>(8)?).unwrap_or(u32::MAX);

    let remote_event_id = match remote_event_id {
        Some(raw) => Some(RemoteMessageId::try_new(&raw)?),
        None => None,
    };

    Ok(InboxEntry {
        id: InboxId::new(row.get(0)?),
        session_id: SessionId::new(row.get(1)?),
        source_id: source_id.map(SourceId::new),
        event_kind,
        remote_event_id,
        remote_timestamp: remote_timestamp.map(instant),
        received_at: instant(row.get(6)?),
        state,
        attempts,
        last_error_kind: row.get(9)?,
        next_attempt_at: next_attempt_at.map(instant),
        completed_at: completed_at.map(instant),
        payload_json: row.get(12)?,
        correlated_content_id: correlated_content_id.map(ContentId::new),
    })
}

impl Database {
    // -------------------------------------------------------------- inbox

    /// Accoda un evento nell'inbox, in modo idempotente.
    ///
    /// La chiave di idempotenza è unica: accodare lo stesso evento una seconda
    /// volta non produce una nuova riga e non è un errore. Il chiamante
    /// distingue i due casi da [`InboxOutcome`].
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la sessione o la fonte indicate non esistono, o
    /// se la scrittura non riesce.
    pub fn enqueue_inbox(&self, entry: &NewInboxEntry) -> StorageResult<InboxOutcome> {
        let payload_sha256 = entry
            .payload_json
            .as_deref()
            .map(|payload| Sha256Digest::of_text(payload).as_str().to_owned());

        let inserted: Option<i64> = self
            .connection
            .query_row(
                "INSERT INTO inbox (
                     session_id, source_id, event_kind, remote_event_id, idempotency_key,
                     remote_timestamp, received_at, payload_json, payload_sha256, state,
                     format_version
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'received', ?10)
                 ON CONFLICT (idempotency_key) DO NOTHING
                 RETURNING id",
                rusqlite::params![
                    entry.session_id.get(),
                    entry.source_id.map(SourceId::get),
                    entry.event_kind.as_str(),
                    entry.remote_event_id.as_ref().map(RemoteMessageId::as_str),
                    entry.idempotency_key.as_str(),
                    entry.remote_timestamp.map(millis),
                    millis(entry.received_at),
                    entry.payload_json.as_deref(),
                    payload_sha256,
                    i64::from(entry.format_version),
                ],
                |row| row.get(0),
            )
            .optional()?;

        match inserted {
            Some(id) => Ok(InboxOutcome::Enqueued(InboxId::new(id))),
            None => {
                let existing: i64 = self.connection.query_row(
                    "SELECT id FROM inbox WHERE idempotency_key = ?1",
                    [entry.idempotency_key.as_str()],
                    |row| row.get(0),
                )?;
                Ok(InboxOutcome::AlreadyQueued(InboxId::new(existing)))
            }
        }
    }

    /// Legge una voce dell'inbox.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se la voce non esiste.
    pub fn inbox_entry(&self, id: InboxId) -> StorageResult<InboxEntry> {
        self.connection
            .query_row(
                &format!("SELECT {INBOX_COLUMNS} FROM inbox WHERE id = ?1"),
                [id.get()],
                |row| Ok(read_inbox(row)),
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound {
                    entity: "voce dell'inbox",
                    id: id.get(),
                },
                other => StorageError::Sqlite(other),
            })?
    }

    /// Voci in attesa di prima elaborazione, dalla più antica.
    ///
    /// Comprende gli stati `received`, `validated` e `retry`. **Non** comprende
    /// `processing`, che è di competenza del recupero dopo un crash.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn inbox_pending(&self, session_id: SessionId) -> StorageResult<Vec<InboxEntry>> {
        self.read_inbox_where(
            "session_id = ?1 AND state IN ('received', 'validated', 'retry')",
            session_id,
        )
    }

    /// Voci rimaste in elaborazione, dalla più antica.
    ///
    /// Sono quelle che un crash ha interrotto: vanno riprese in modo
    /// idempotente. Su una sessione sana questa lista è vuota.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn inbox_in_progress(&self, session_id: SessionId) -> StorageResult<Vec<InboxEntry>> {
        self.read_inbox_where("session_id = ?1 AND state = 'processing'", session_id)
    }

    fn read_inbox_where(
        &self,
        predicate: &str,
        session_id: SessionId,
    ) -> StorageResult<Vec<InboxEntry>> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT {INBOX_COLUMNS} FROM inbox WHERE {predicate} ORDER BY id ASC"
        ))?;
        let rows = statement.query_map([session_id.get()], |row| Ok(read_inbox(row)))?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row??);
        }
        Ok(entries)
    }

    /// Numero di voci non ancora concluse per una sessione.
    ///
    /// Serve al backpressure: raggiunto il tetto, l'acquisizione rallenta.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn inbox_open_count(&self, session_id: SessionId) -> StorageResult<usize> {
        let count: i64 = self.connection.query_row(
            "SELECT count(*) FROM inbox
             WHERE session_id = ?1 AND state NOT IN ('completed', 'failed', 'discarded')",
            [session_id.get()],
            |row| row.get(0),
        )?;
        Ok(usize::try_from(count).unwrap_or(usize::MAX))
    }

    /// Numero di voci fallite in modo permanente per una sessione.
    ///
    /// È un segnale di salute: un monitoraggio con voci fallite è «operativo
    /// con anomalie», non semplicemente operativo.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn inbox_failed_count(&self, session_id: SessionId) -> StorageResult<usize> {
        let count: i64 = self.connection.query_row(
            "SELECT count(*) FROM inbox WHERE session_id = ?1 AND state = 'failed'",
            [session_id.get()],
            |row| row.get(0),
        )?;
        Ok(usize::try_from(count).unwrap_or(usize::MAX))
    }

    /// Segna una voce come in elaborazione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'aggiornamento non riesce.
    pub fn mark_inbox_processing(&self, id: InboxId) -> StorageResult<()> {
        self.connection.execute(
            "UPDATE inbox SET state = 'processing' WHERE id = ?1",
            [id.get()],
        )?;
        Ok(())
    }

    /// Segna una voce come completata, collegandola al contenuto prodotto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'aggiornamento non riesce.
    pub fn mark_inbox_completed(
        &self,
        id: InboxId,
        content_id: Option<ContentId>,
        now: lisi_core::Timestamp,
    ) -> StorageResult<()> {
        self.connection.execute(
            "UPDATE inbox
             SET state = 'completed', completed_at = ?2, correlated_content_id = ?3,
                 next_attempt_at = NULL
             WHERE id = ?1",
            rusqlite::params![id.get(), millis(now), content_id.map(ContentId::get)],
        )?;
        Ok(())
    }

    /// Segna una voce da ritentare, incrementando i tentativi.
    ///
    /// `error_kind` è una classe d'errore del prodotto, mai testo remoto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'aggiornamento non riesce.
    pub fn mark_inbox_retry(
        &self,
        id: InboxId,
        error_kind: &str,
        next_attempt_at: lisi_core::Timestamp,
    ) -> StorageResult<()> {
        self.connection.execute(
            "UPDATE inbox
             SET state = 'retry', attempts = attempts + 1, last_error_kind = ?2,
                 next_attempt_at = ?3
             WHERE id = ?1",
            rusqlite::params![id.get(), error_kind, millis(next_attempt_at)],
        )?;
        Ok(())
    }

    /// Segna una voce come fallita in modo permanente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'aggiornamento non riesce.
    pub fn mark_inbox_failed(&self, id: InboxId, error_kind: &str) -> StorageResult<()> {
        self.connection.execute(
            "UPDATE inbox
             SET state = 'failed', attempts = attempts + 1, last_error_kind = ?2,
                 next_attempt_at = NULL
             WHERE id = ?1",
            rusqlite::params![id.get(), error_kind],
        )?;
        Ok(())
    }

    /// Mette una voce in quarantena, con il motivo (costante del prodotto).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'aggiornamento non riesce.
    pub fn mark_inbox_discarded(&self, id: InboxId, reason: &str) -> StorageResult<()> {
        self.connection.execute(
            "UPDATE inbox SET state = 'discarded', discard_reason = ?2 WHERE id = ?1",
            rusqlite::params![id.get(), reason],
        )?;
        Ok(())
    }

    // ------------------------------------------------------ versioni

    /// Aggiunge una versione a un contenuto, calcolandone numero e precedente.
    ///
    /// Il numero di versione e il collegamento alla versione precedente sono
    /// calcolati qui, così che nessun chiamante possa fornirne uno fuori
    /// sequenza. La versione è immutabile una volta scritta (trigger).
    ///
    /// # Idempotenza
    ///
    /// La versione è **legata alla voce d'inbox che l'ha prodotta**: applicare
    /// due volte la stessa voce — perché un crash ha lasciato la voce in
    /// elaborazione e la ripresa la riesegue — non produce una seconda
    /// versione. Il vincolo unico su `origin_inbox_id` lo rende impossibile per
    /// costruzione, come già fa `insert_content` con l'identità del messaggio.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se il contenuto non esiste, o un
    /// errore se la scrittura non riesce.
    pub fn append_content_version(
        &self,
        origin_inbox_id: InboxId,
        version: &NewContentVersion,
    ) -> StorageResult<ContentVersion> {
        let digest = version.body_digest();

        let inserted: Option<i64> = self
            .connection
            .query_row(
                "INSERT INTO content_versions (
                     content_id, version_number, body, body_sha256, remote_edit_timestamp,
                     observed_at, previous_version_id, origin_inbox_id
                 )
                 SELECT ?1,
                        COALESCE(MAX(version_number), 0) + 1,
                        ?2, ?3, ?4, ?5,
                        (SELECT id FROM content_versions
                         WHERE content_id = ?1
                         ORDER BY version_number DESC LIMIT 1),
                        ?6
                 FROM content_versions WHERE content_id = ?1
                 ON CONFLICT (origin_inbox_id) DO NOTHING
                 RETURNING id",
                rusqlite::params![
                    version.content_id.get(),
                    version.body.as_str(),
                    digest.as_str(),
                    version.remote_edit_timestamp.map(millis),
                    millis(version.observed_at),
                    origin_inbox_id.get(),
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| {
                if crate::error::constraint_kind(&error)
                    == Some(crate::error::ConstraintKind::ForeignKey)
                {
                    StorageError::NotFound {
                        entity: "contenuto",
                        id: version.content_id.get(),
                    }
                } else {
                    StorageError::Sqlite(error)
                }
            })?;

        let id = match inserted {
            Some(id) => id,
            None => {
                // Già applicata per questa voce d'inbox: ne restituisco la
                // versione esistente, senza aggiungerne una seconda.
                self.connection.query_row(
                    "SELECT id FROM content_versions WHERE origin_inbox_id = ?1",
                    [origin_inbox_id.get()],
                    |row| row.get(0),
                )?
            }
        };

        self.content_version(ContentVersionId::new(id))
    }

    /// Semina il corpo originale come versione 1 di un contenuto.
    ///
    /// Il modello delle versioni è: la versione 1 è il **corpo originale** con
    /// cui il contenuto è stato acquisito, e le modifiche osservate sono le
    /// versioni successive. Il corpo originale vive nel contenuto; qui lo si
    /// materializza nella tabella delle versioni alla prima modifica, così che
    /// la storia delle versioni sia completa e autosufficiente.
    ///
    /// È idempotente: la versione 1 esiste una sola volta per contenuto
    /// (vincolo `UNIQUE(content_id, version_number)`), quindi seminare due volte
    /// non produce un doppione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn seed_original_version(
        &self,
        content_id: ContentId,
        body: &str,
        observed_at: lisi_core::Timestamp,
    ) -> StorageResult<()> {
        let digest = Sha256Digest::of_text(body);
        self.connection.execute(
            "INSERT INTO content_versions (
                 content_id, version_number, body, body_sha256, observed_at, origin_inbox_id
             ) VALUES (?1, 1, ?2, ?3, ?4, NULL)
             ON CONFLICT (content_id, version_number) DO NOTHING",
            rusqlite::params![content_id.get(), body, digest.as_str(), millis(observed_at)],
        )?;
        Ok(())
    }

    /// Legge una versione.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se la versione non esiste.
    pub fn content_version(&self, id: ContentVersionId) -> StorageResult<ContentVersion> {
        self.connection
            .query_row(
                "SELECT id, content_id, version_number, body, body_sha256,
                        remote_edit_timestamp, observed_at, previous_version_id
                 FROM content_versions WHERE id = ?1",
                [id.get()],
                |row| Ok(read_version(row)),
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound {
                    entity: "versione del contenuto",
                    id: id.get(),
                },
                other => StorageError::Sqlite(other),
            })?
    }

    /// Versioni di un contenuto, dalla prima all'ultima.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn content_versions(&self, content_id: ContentId) -> StorageResult<Vec<ContentVersion>> {
        let mut statement = self.connection.prepare(
            "SELECT id, content_id, version_number, body, body_sha256,
                    remote_edit_timestamp, observed_at, previous_version_id
             FROM content_versions WHERE content_id = ?1 ORDER BY version_number ASC",
        )?;
        let rows = statement.query_map([content_id.get()], |row| Ok(read_version(row)))?;

        let mut versions = Vec::new();
        for row in rows {
            versions.push(row??);
        }
        Ok(versions)
    }

    // ---------------------------------------------------- cancellazioni

    /// Registra una cancellazione osservata.
    ///
    /// # Idempotenza
    ///
    /// Come per le versioni, la cancellazione è **legata alla voce d'inbox che
    /// l'ha prodotta**: applicare due volte la stessa voce dopo un crash non
    /// registra due cancellazioni dello stesso messaggio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la sessione non esiste o se la scrittura non
    /// riesce.
    pub fn insert_content_deletion(
        &self,
        origin_inbox_id: InboxId,
        deletion: &NewContentDeletion,
    ) -> StorageResult<ContentDeletionId> {
        let inserted: Option<i64> = self
            .connection
            .query_row(
                "INSERT INTO content_deletions (
                     content_id, session_id, source_id, remote_event_id, observed_at,
                     origin_inbox_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (origin_inbox_id) DO NOTHING
                 RETURNING id",
                rusqlite::params![
                    deletion.content_id.map(ContentId::get),
                    deletion.session_id.get(),
                    deletion.source_id.map(SourceId::get),
                    deletion
                        .remote_event_id
                        .as_ref()
                        .map(RemoteMessageId::as_str),
                    millis(deletion.observed_at),
                    origin_inbox_id.get(),
                ],
                |row| row.get(0),
            )
            .optional()?;

        let id = match inserted {
            Some(id) => id,
            None => self.connection.query_row(
                "SELECT id FROM content_deletions WHERE origin_inbox_id = ?1",
                [origin_inbox_id.get()],
                |row| row.get(0),
            )?,
        };
        Ok(ContentDeletionId::new(id))
    }

    /// Cancellazione osservata di un contenuto, se ce n'è una.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn content_deletion(
        &self,
        content_id: ContentId,
    ) -> StorageResult<Option<ContentDeletion>> {
        self.connection
            .query_row(
                "SELECT id, content_id, session_id, source_id, remote_event_id, observed_at
                 FROM content_deletions WHERE content_id = ?1
                 ORDER BY id DESC LIMIT 1",
                [content_id.get()],
                |row| Ok(read_deletion(row)),
            )
            .optional()?
            .transpose()
    }

    /// Cancellazioni osservate di una sessione, dalla più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn session_deletions(&self, session_id: SessionId) -> StorageResult<Vec<ContentDeletion>> {
        let mut statement = self.connection.prepare(
            "SELECT id, content_id, session_id, source_id, remote_event_id, observed_at
             FROM content_deletions WHERE session_id = ?1 ORDER BY id DESC",
        )?;
        let rows = statement.query_map([session_id.get()], |row| Ok(read_deletion(row)))?;

        let mut deletions = Vec::new();
        for row in rows {
            deletions.push(row??);
        }
        Ok(deletions)
    }

    // ---------------------------------------- correlazione e checkpoint

    /// Identificatore di un contenuto per (sessione, fonte, id remoto).
    ///
    /// Serve a collegare una modifica o una cancellazione al contenuto che
    /// riguardano. `None` se quel messaggio non è mai stato acquisito — che per
    /// una modifica arrivata fuori ordine, o una cancellazione di un messaggio
    /// mai visto, è un caso normale.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn find_content_id(
        &self,
        session_id: SessionId,
        source_id: SourceId,
        remote_message_id: &str,
    ) -> StorageResult<Option<ContentId>> {
        let id: Option<i64> = self
            .connection
            .query_row(
                "SELECT id FROM contents
                 WHERE session_id = ?1 AND source_id = ?2 AND remote_message_id = ?3",
                rusqlite::params![session_id.get(), source_id.get(), remote_message_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(id.map(ContentId::new))
    }

    /// I fatti di **ricezione** di un monitoraggio, in ordine di arrivo
    /// (PR-05, ADR-0121).
    ///
    /// # Tre colonne, e nient'altro
    ///
    /// Il genere dell'evento, l'istante in cui è **arrivato** e la fonte.
    /// Nessun corpo, nessun identificativo remoto, **nessun istante di
    /// pubblicazione**: la copertura è un fatto su di noi — quando ricevevamo —
    /// e non su chi pubblicava.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se un genere non è
    /// interpretabile.
    pub fn session_reception_facts(
        &self,
        session_id: SessionId,
    ) -> StorageResult<Vec<ReceptionFact>> {
        let mut statement = self.connection.prepare(
            "SELECT inbox.event_kind, inbox.received_at, inbox.source_id,
                    COALESCE(contents.acquisition_origin = 'recuperato', 0)
             FROM inbox
             LEFT JOIN contents ON contents.id = inbox.correlated_content_id
             WHERE inbox.session_id = ?1
             ORDER BY inbox.received_at, inbox.id",
        )?;
        let righe = statement.query_map([session_id.get()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, bool>(3)?,
            ))
        })?;

        let mut fatti = Vec::new();
        for riga in righe {
            let (genere, arrivo, fonte, recuperato) = riga?;
            fatti.push(ReceptionFact {
                kind: InboxEventKind::from_str(&genere)?,
                received_at: instant(arrivo),
                source_id: fonte.map(SourceId::new),
                recovered: recuperato,
            });
        }
        Ok(fatti)
    }

    /// Fissa il checkpoint di ripresa di una sessione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'aggiornamento non riesce.
    pub fn set_session_checkpoint(
        &self,
        session_id: SessionId,
        last_completed_inbox_id: InboxId,
        checkpoint_at: lisi_core::Timestamp,
    ) -> StorageResult<()> {
        self.connection.execute(
            "UPDATE sessions
             SET last_completed_inbox_id = ?2, checkpoint_at = ?3
             WHERE id = ?1",
            rusqlite::params![
                session_id.get(),
                last_completed_inbox_id.get(),
                millis(checkpoint_at),
            ],
        )?;
        Ok(())
    }

    /// Checkpoint di ripresa di una sessione, se ne esiste uno.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn session_checkpoint(
        &self,
        session_id: SessionId,
    ) -> StorageResult<Option<(InboxId, lisi_core::Timestamp)>> {
        let row: Option<(Option<i64>, Option<i64>)> = self
            .connection
            .query_row(
                "SELECT last_completed_inbox_id, checkpoint_at FROM sessions WHERE id = ?1",
                [session_id.get()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        Ok(match row {
            Some((Some(id), Some(at))) => Some((InboxId::new(id), instant(at))),
            _ => None,
        })
    }

    // ------------------------------------------- storia, in forma breve

    /// Che cosa è successo dopo l'acquisizione, per ogni contenuto di una
    /// sessione che abbia qualcosa da dire.
    ///
    /// # Perché una lettura sola e non due per contenuto
    ///
    /// Lo Storico mostra centinaia di righe, e ognuna deve poter dire
    /// «modificato» o «eliminato». Chiedere versioni e cancellazione per ogni
    /// riga significherebbe due interrogazioni per riga: qui sono **due in
    /// tutto**, e i corpi non si leggono affatto.
    ///
    /// I contenuti senza nulla da dire **non compaiono** nel risultato: sono la
    /// maggioranza, e restituirne una riga vuota ciascuno costerebbe memoria per
    /// dire «niente».
    ///
    /// # Errori
    ///
    /// Restituisce un errore se una delle due letture non riesce.
    pub fn session_content_history(
        &self,
        session_id: SessionId,
    ) -> StorageResult<BTreeMap<i64, ContentHistorySummary>> {
        let mut per_contenuto: BTreeMap<i64, ContentHistorySummary> = BTreeMap::new();

        // Le modifiche sono le versioni MENO UNA: la prima e' il corpo
        // originale, seminato alla prima modifica. Si conta in SQL invece di
        // caricare le righe, perche' qui i corpi non servono.
        {
            let mut statement = self.connection.prepare(
                "SELECT v.content_id, COUNT(*), MAX(v.observed_at)
                 FROM content_versions v
                 JOIN contents c ON c.id = v.content_id
                 WHERE c.session_id = ?1
                 GROUP BY v.content_id",
            )?;

            let righe = statement.query_map([session_id.get()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?;

            for riga in righe {
                let (content_id, versioni, ultima) = riga?;
                let revisions = u32::try_from(versioni.saturating_sub(1)).unwrap_or(u32::MAX);

                let voce = per_contenuto.entry(content_id).or_default();
                voce.revisions = revisions;
                // L'istante ha senso solo se c'e' stata una modifica: con una
                // sola versione conservata, `MAX(observed_at)` e' l'istante in
                // cui e' stato seminato l'originale, non quello di una modifica.
                voce.last_revision_at = if revisions > 0 {
                    Some(instant(ultima))
                } else {
                    None
                };
            }
        }

        let mut statement = self.connection.prepare(
            "SELECT content_id, MAX(observed_at)
             FROM content_deletions
             WHERE session_id = ?1 AND content_id IS NOT NULL
             GROUP BY content_id",
        )?;

        let righe = statement.query_map([session_id.get()], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })?;

        for riga in righe {
            let (content_id, quando) = riga?;
            per_contenuto.entry(content_id).or_default().deleted_at = Some(instant(quando));
        }

        // Un contenuto con una sola versione e nessuna cancellazione non ha
        // nulla da mostrare: e' entrato per la prima lettura e va tolto, perche'
        // chi legge questa mappa si aspetta che una chiave significhi «qualcosa
        // e' successo».
        per_contenuto.retain(|_, voce| voce.has_anything_to_show());

        Ok(per_contenuto)
    }

    /// Tutto ciò che si sa di un contenuto dopo l'acquisizione.
    ///
    /// Legge i corpi: si chiama quando l'operatore **apre** un contenuto, non
    /// per comporre un elenco.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se una delle letture non riesce.
    pub fn content_history(&self, content_id: ContentId) -> StorageResult<ContentHistory> {
        Ok(ContentHistory {
            versions: self.content_versions(content_id)?,
            deletion: self.content_deletion(content_id)?,
        })
    }
}

fn read_version(row: &Row<'_>) -> StorageResult<ContentVersion> {
    let remote_edit: Option<i64> = row.get(5)?;
    let previous: Option<i64> = row.get(7)?;
    let version_number = u32::try_from(row.get::<_, i64>(2)?).unwrap_or(u32::MAX);
    let body = lisi_core::text::ContentBody::try_new(&row.get::<_, String>(3)?)?;
    let body_sha256 = Sha256Digest::from_hex(&row.get::<_, String>(4)?)?;

    Ok(ContentVersion {
        id: ContentVersionId::new(row.get(0)?),
        content_id: ContentId::new(row.get(1)?),
        version_number,
        body,
        body_sha256,
        remote_edit_timestamp: remote_edit.map(instant),
        observed_at: instant(row.get(6)?),
        previous_version_id: previous.map(ContentVersionId::new),
    })
}

fn read_deletion(row: &Row<'_>) -> StorageResult<ContentDeletion> {
    let content_id: Option<i64> = row.get(1)?;
    let source_id: Option<i64> = row.get(3)?;
    let remote_event_id: Option<String> = row.get(4)?;

    let remote_event_id = match remote_event_id {
        Some(raw) => Some(RemoteMessageId::try_new(&raw)?),
        None => None,
    };

    Ok(ContentDeletion {
        id: ContentDeletionId::new(row.get(0)?),
        content_id: content_id.map(ContentId::new),
        session_id: SessionId::new(row.get(2)?),
        source_id: source_id.map(SourceId::new),
        remote_event_id,
        observed_at: instant(row.get(5)?),
    })
}

#[cfg(test)]
mod tests {
    use lisi_core::model::acquisition::{
        IdempotencyKey, InboxEventKind, NewContentDeletion, NewContentVersion, NewInboxEntry,
    };
    use lisi_core::text::RemoteMessageId;
    use lisi_core::{InboxId, SessionId, SourceId};

    use crate::database::Database;
    use crate::test_support::{body, later, new_content, new_session, new_source, now};

    /// Database con una fonte e una sessione, e i loro identificatori.
    fn seeded() -> (Database, SessionId, SourceId) {
        let mut database = crate::test_support::database();
        let Ok(source_id) = database.insert_source(&new_source("canale_uno"), now()) else {
            panic!("la fonte deve potersi registrare");
        };
        let Ok(session_id) = database.insert_session(&new_session(vec![source_id]), now()) else {
            panic!("la sessione deve potersi creare");
        };
        (database, session_id, source_id)
    }

    fn new_message(session_id: SessionId, source_id: SourceId, remote: &str) -> NewInboxEntry {
        let Ok(remote_event_id) = RemoteMessageId::try_new(remote) else {
            panic!("l'identificativo remoto di prova deve essere valido");
        };
        NewInboxEntry {
            session_id,
            source_id: Some(source_id),
            event_kind: InboxEventKind::NewMessage,
            remote_event_id: Some(remote_event_id),
            idempotency_key: IdempotencyKey::derive(
                session_id,
                Some(source_id),
                InboxEventKind::NewMessage,
                Some(remote),
                None,
            ),
            remote_timestamp: Some(now()),
            received_at: later(1),
            payload_json: Some(String::from("{}")),
            format_version: 1,
        }
    }

    #[test]
    fn enqueuing_the_same_event_twice_does_not_duplicate() {
        let (database, session_id, source_id) = seeded();
        let event = new_message(session_id, source_id, "m1");

        let (Ok(first), Ok(second)) = (
            database.enqueue_inbox(&event),
            database.enqueue_inbox(&event),
        ) else {
            panic!("l'accodamento deve riuscire");
        };

        assert!(first.is_new());
        assert!(!second.is_new(), "la seconda volta e' gia' presente");
        assert_eq!(first.id(), second.id(), "e' la stessa voce, non una nuova");
    }

    #[test]
    fn versions_are_numbered_in_sequence_and_link_to_the_previous() {
        let (mut database, session_id, source_id) = seeded();
        let Ok(insertion) =
            database.insert_content(&new_content(session_id, source_id, "m1", "originale"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = insertion.content_id();

        let Ok(first) = database.append_content_version(
            InboxId::new(101),
            &NewContentVersion {
                content_id,
                body: body("prima modifica"),
                remote_edit_timestamp: Some(later(10)),
                observed_at: later(11),
            },
        ) else {
            panic!("la prima versione deve potersi aggiungere");
        };
        let Ok(second) = database.append_content_version(
            InboxId::new(102),
            &NewContentVersion {
                content_id,
                body: body("seconda modifica"),
                remote_edit_timestamp: Some(later(20)),
                observed_at: later(21),
            },
        ) else {
            panic!("la seconda versione deve potersi aggiungere");
        };

        assert_eq!(first.version_number, 1);
        assert_eq!(second.version_number, 2);
        assert_eq!(second.previous_version_id, Some(first.id));

        let Ok(all) = database.content_versions(content_id) else {
            panic!("le versioni devono potersi leggere");
        };
        assert_eq!(all.len(), 2);
        assert!(all[0].is_original());
    }

    #[test]
    fn re_appending_the_same_edit_origin_is_a_no_op() {
        // Il difetto che questo test impedisce di ripetere: un crash fra
        // l'aggiunta della versione e la conclusione della voce d'inbox
        // lasciava la voce in elaborazione, e la ripresa aggiungeva una seconda
        // versione identica. Legare la versione alla voce d'origine lo impedisce.
        let (mut database, session_id, source_id) = seeded();
        let Ok(insertion) =
            database.insert_content(&new_content(session_id, source_id, "m1", "originale"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = insertion.content_id();
        let version = NewContentVersion {
            content_id,
            body: body("modifica"),
            remote_edit_timestamp: Some(later(10)),
            observed_at: later(11),
        };

        let (Ok(first), Ok(second)) = (
            database.append_content_version(InboxId::new(500), &version),
            database.append_content_version(InboxId::new(500), &version),
        ) else {
            panic!("le due applicazioni devono riuscire");
        };
        assert_eq!(first.id, second.id, "e' la stessa versione, non una nuova");
        assert_eq!(
            database
                .content_versions(content_id)
                .map(|all| all.len())
                .ok(),
            Some(1),
            "la ri-applicazione non aggiunge una seconda versione"
        );
    }

    #[test]
    fn seeding_the_original_is_idempotent() {
        let (mut database, session_id, source_id) = seeded();
        let Ok(insertion) =
            database.insert_content(&new_content(session_id, source_id, "m1", "originale"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = insertion.content_id();

        let (Ok(()), Ok(())) = (
            database.seed_original_version(content_id, "originale", later(1)),
            database.seed_original_version(content_id, "originale", later(1)),
        ) else {
            panic!("la semina deve riuscire due volte senza errore");
        };

        let Ok(all) = database.content_versions(content_id) else {
            panic!("le versioni devono potersi leggere");
        };
        assert_eq!(all.len(), 1, "un solo originale");
        assert_eq!(all[0].version_number, 1);
        assert!(all[0].is_original());
        assert_eq!(all[0].body.as_str(), "originale");
    }

    #[test]
    fn a_deletion_can_reference_a_message_never_acquired() {
        let (database, session_id, source_id) = seeded();
        let Ok(remote) = RemoteMessageId::try_new("mai_visto") else {
            panic!("l'identificativo deve essere valido");
        };
        let deletion = NewContentDeletion {
            content_id: None,
            session_id,
            source_id: Some(source_id),
            remote_event_id: Some(remote),
            observed_at: later(5),
        };

        // Anche la cancellazione e' legata alla voce d'origine: due
        // applicazioni della stessa voce non registrano due cancellazioni.
        let (Ok(first), Ok(second)) = (
            database.insert_content_deletion(InboxId::new(600), &deletion),
            database.insert_content_deletion(InboxId::new(600), &deletion),
        ) else {
            panic!("la cancellazione deve potersi registrare");
        };
        assert_eq!(first, second, "stessa voce d'origine, stessa cancellazione");

        let Ok(deletions) = database.session_deletions(session_id) else {
            panic!("le cancellazioni devono potersi leggere");
        };
        assert_eq!(deletions.len(), 1);
        assert!(deletions[0].is_of_an_unseen_message());
    }

    #[test]
    fn a_content_is_found_by_its_remote_identity() {
        let (mut database, session_id, source_id) = seeded();
        let Ok(insertion) =
            database.insert_content(&new_content(session_id, source_id, "m7", "testo"))
        else {
            panic!("il contenuto deve potersi registrare");
        };

        let Ok(found) = database.find_content_id(session_id, source_id, "m7") else {
            panic!("la ricerca deve riuscire");
        };
        assert_eq!(found, Some(insertion.content_id()));

        let Ok(missing) = database.find_content_id(session_id, source_id, "assente") else {
            panic!("la ricerca deve riuscire");
        };
        assert_eq!(missing, None);
    }

    #[test]
    fn the_checkpoint_round_trips() {
        let (database, session_id, source_id) = seeded();
        let Ok(outcome) = database.enqueue_inbox(&new_message(session_id, source_id, "m1")) else {
            panic!("l'accodamento deve riuscire");
        };

        let Ok(()) = database.set_session_checkpoint(session_id, outcome.id(), later(30)) else {
            panic!("il checkpoint deve potersi fissare");
        };
        let Ok(Some((inbox_id, at))) = database.session_checkpoint(session_id) else {
            panic!("il checkpoint deve potersi leggere");
        };
        assert_eq!(inbox_id, outcome.id());
        assert_eq!(at, later(30));
    }

    #[test]
    fn pending_excludes_what_is_in_progress_or_done() {
        let (database, session_id, source_id) = seeded();
        for remote in ["m1", "m2", "m3"] {
            let Ok(_) = database.enqueue_inbox(&new_message(session_id, source_id, remote)) else {
                panic!("l'accodamento deve riuscire");
            };
        }

        // Una in elaborazione (crash), una completata: restano in coda le altre.
        let Ok(open) = database.inbox_pending(session_id) else {
            panic!("la coda deve potersi leggere");
        };
        assert_eq!(open.len(), 3);

        let processing = open[0].id;
        let done = open[1].id;
        let (Ok(()), Ok(())) = (
            database.mark_inbox_processing(processing),
            database.mark_inbox_completed(done, None, later(2)),
        ) else {
            panic!("gli aggiornamenti devono riuscire");
        };

        let Ok(pending) = database.inbox_pending(session_id) else {
            panic!("la coda deve potersi leggere");
        };
        assert_eq!(pending.len(), 1, "resta solo la terza");

        let Ok(in_progress) = database.inbox_in_progress(session_id) else {
            panic!("le voci in elaborazione devono potersi leggere");
        };
        assert_eq!(in_progress.len(), 1, "la ripresa vede quella interrotta");
        assert_eq!(in_progress[0].id, processing);

        let Ok(open_count) = database.inbox_open_count(session_id) else {
            panic!("il conteggio deve riuscire");
        };
        assert_eq!(
            open_count, 2,
            "in elaborazione e in coda, non la completata"
        );
    }

    // -------------------------------------------- la storia, in forma breve

    /// **Un contenuto mai toccato non compare nel riepilogo.**
    ///
    /// Sono la maggioranza: restituirne una riga vuota ciascuno costerebbe
    /// memoria per dire «niente», e chi legge la mappa si aspetta che una
    /// chiave significhi «qualcosa e' successo».
    #[test]
    fn the_history_summary_omits_untouched_contents() {
        let (mut database, session_id, source_id) = seeded();
        let Ok(_) = database.insert_content(&new_content(session_id, source_id, "m1", "intatto"))
        else {
            panic!("il contenuto deve potersi registrare");
        };

        let Ok(storia) = database.session_content_history(session_id) else {
            panic!("il riepilogo deve potersi leggere");
        };
        assert!(storia.is_empty());
    }

    /// **Il solo originale seminato non conta come modifica.**
    ///
    /// Puo' capitare: l'originale viene seminato e la modifica fallisce dopo.
    /// La storia ha una versione, e zero revisioni.
    #[test]
    fn a_seeded_original_alone_is_not_a_revision() {
        let (mut database, session_id, source_id) = seeded();
        let Ok(insertion) =
            database.insert_content(&new_content(session_id, source_id, "m1", "originale"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let Ok(_) = database.seed_original_version(insertion.content_id(), "originale", later(1))
        else {
            panic!("l'originale deve potersi seminare");
        };

        let Ok(storia) = database.session_content_history(session_id) else {
            panic!("il riepilogo deve potersi leggere");
        };
        assert!(
            storia.is_empty(),
            "una sola versione conservata non e' una modifica"
        );
    }

    #[test]
    fn the_history_summary_counts_revisions_and_keeps_the_last_instant() {
        let (mut database, session_id, source_id) = seeded();
        let Ok(insertion) =
            database.insert_content(&new_content(session_id, source_id, "m1", "originale"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = insertion.content_id();

        let Ok(_) = database.seed_original_version(content_id, "originale", later(1)) else {
            panic!("l'originale deve potersi seminare");
        };
        for (inbox, testo, quando) in [(201, "prima modifica", 11), (202, "seconda", 21)] {
            let Ok(_) = database.append_content_version(
                InboxId::new(inbox),
                &NewContentVersion {
                    content_id,
                    body: body(testo),
                    remote_edit_timestamp: None,
                    observed_at: later(quando),
                },
            ) else {
                panic!("la modifica deve potersi aggiungere");
            };
        }

        let Ok(storia) = database.session_content_history(session_id) else {
            panic!("il riepilogo deve potersi leggere");
        };
        let Some(voce) = storia.get(&content_id.get()) else {
            panic!("il contenuto modificato deve comparire");
        };

        assert_eq!(voce.revisions, 2, "tre versioni sono due modifiche");
        assert_eq!(voce.last_revision_at, Some(later(21)));
        assert!(!voce.was_deleted());
    }

    #[test]
    fn the_history_summary_reports_an_observed_deletion() {
        let (mut database, session_id, source_id) = seeded();
        let Ok(insertion) =
            database.insert_content(&new_content(session_id, source_id, "m1", "corpo"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = insertion.content_id();

        let Ok(_) = database.insert_content_deletion(
            InboxId::new(301),
            &NewContentDeletion {
                content_id: Some(content_id),
                session_id,
                source_id: Some(source_id),
                remote_event_id: None,
                observed_at: later(50),
            },
        ) else {
            panic!("la cancellazione deve potersi registrare");
        };

        let Ok(storia) = database.session_content_history(session_id) else {
            panic!("il riepilogo deve potersi leggere");
        };
        let Some(voce) = storia.get(&content_id.get()) else {
            panic!("il contenuto cancellato deve comparire");
        };

        assert!(voce.was_deleted());
        assert_eq!(voce.deleted_at, Some(later(50)));
        assert!(!voce.was_revised());
        assert_eq!(voce.short_label().as_deref(), Some("eliminato su Telegram"));
    }

    /// **Una cancellazione di un messaggio mai acquisito non finisce nella
    /// mappa.**
    ///
    /// Non ha un contenuto a cui appartenere, e forzarla su una chiave
    /// inventata la attribuirebbe a un messaggio sbagliato. Resta leggibile con
    /// `session_deletions`, che e' dove va cercata.
    #[test]
    fn a_deletion_of_an_unseen_message_has_no_content_row() {
        let (mut database, session_id, source_id) = seeded();
        let Ok(insertion) =
            database.insert_content(&new_content(session_id, source_id, "m1", "corpo"))
        else {
            panic!("il contenuto deve potersi registrare");
        };

        let Ok(_) = database.insert_content_deletion(
            InboxId::new(302),
            &NewContentDeletion {
                content_id: None,
                session_id,
                source_id: Some(source_id),
                remote_event_id: None,
                observed_at: later(50),
            },
        ) else {
            panic!("la cancellazione deve potersi registrare");
        };

        let Ok(storia) = database.session_content_history(session_id) else {
            panic!("il riepilogo deve potersi leggere");
        };
        assert!(
            storia.is_empty(),
            "una cancellazione senza contenuto non si attribuisce a nessuno"
        );

        let Ok(cancellazioni) = database.session_deletions(session_id) else {
            panic!("le cancellazioni della sessione devono potersi leggere");
        };
        assert_eq!(cancellazioni.len(), 1);
        assert!(cancellazioni[0].is_of_an_unseen_message());
        // E il contenuto acquisito non deve risultarne toccato.
        assert!(
            database
                .content_deletion(insertion.content_id())
                .is_ok_and(|voce| voce.is_none())
        );
    }

    #[test]
    fn modifica_e_cancellazione_convivono_nella_stessa_voce() {
        let (mut database, session_id, source_id) = seeded();
        let Ok(insertion) =
            database.insert_content(&new_content(session_id, source_id, "m1", "originale"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = insertion.content_id();

        let Ok(_) = database.seed_original_version(content_id, "originale", later(1)) else {
            panic!("l'originale deve potersi seminare");
        };
        let Ok(_) = database.append_content_version(
            InboxId::new(401),
            &NewContentVersion {
                content_id,
                body: body("modificato"),
                remote_edit_timestamp: None,
                observed_at: later(11),
            },
        ) else {
            panic!("la modifica deve potersi aggiungere");
        };
        let Ok(_) = database.insert_content_deletion(
            InboxId::new(402),
            &NewContentDeletion {
                content_id: Some(content_id),
                session_id,
                source_id: Some(source_id),
                remote_event_id: None,
                observed_at: later(60),
            },
        ) else {
            panic!("la cancellazione deve potersi registrare");
        };

        let Ok(storia) = database.session_content_history(session_id) else {
            panic!("il riepilogo deve potersi leggere");
        };
        let Some(voce) = storia.get(&content_id.get()) else {
            panic!("il contenuto deve comparire");
        };

        assert_eq!(
            voce.short_label().as_deref(),
            Some("modificato, poi eliminato su Telegram")
        );
    }

    /// **La storia completa compone versioni e cancellazione.**
    #[test]
    fn the_full_history_carries_bodies_and_the_deletion() {
        let (mut database, session_id, source_id) = seeded();
        let Ok(insertion) =
            database.insert_content(&new_content(session_id, source_id, "m1", "originale"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = insertion.content_id();

        let Ok(_) = database.seed_original_version(content_id, "originale", later(1)) else {
            panic!("l'originale deve potersi seminare");
        };
        let Ok(_) = database.append_content_version(
            InboxId::new(501),
            &NewContentVersion {
                content_id,
                body: body("originale e altro"),
                remote_edit_timestamp: None,
                observed_at: later(11),
            },
        ) else {
            panic!("la modifica deve potersi aggiungere");
        };

        let Ok(storia) = database.content_history(content_id) else {
            panic!("la storia deve potersi leggere");
        };

        assert_eq!(storia.versions.len(), 2);
        assert!(storia.versions[0].is_original());
        assert_eq!(storia.revisions(), 1);
        assert!(storia.deletion.is_none());

        let passaggi = storia.steps();
        assert_eq!(passaggi.len(), 1);
        assert_eq!(
            passaggi[0].change,
            lisi_core::model::content_history::VersionChange::Appended
        );
    }

    /// **La storia di due contenuti distinti non si mescola.**
    ///
    /// La correlazione passa da (sessione, fonte, identificativo remoto): due
    /// messaggi diversi della stessa fonte devono restare separati anche quando
    /// entrambi sono stati modificati.
    #[test]
    fn the_history_of_two_contents_does_not_mix() {
        let (mut database, session_id, source_id) = seeded();

        let Ok(primo) = database.insert_content(&new_content(session_id, source_id, "m1", "uno"))
        else {
            panic!("il primo contenuto deve potersi registrare");
        };
        let Ok(secondo) = database.insert_content(&new_content(session_id, source_id, "m2", "due"))
        else {
            panic!("il secondo contenuto deve potersi registrare");
        };

        for (inbox, contenuto, testo) in [
            (601, primo.content_id(), "uno modificato"),
            (602, secondo.content_id(), "due modificato"),
            (603, secondo.content_id(), "due modificato ancora"),
        ] {
            let Ok(_) = database.seed_original_version(contenuto, "seme", later(1)) else {
                panic!("l'originale deve potersi seminare");
            };
            let Ok(_) = database.append_content_version(
                InboxId::new(inbox),
                &NewContentVersion {
                    content_id: contenuto,
                    body: body(testo),
                    remote_edit_timestamp: None,
                    observed_at: later(11),
                },
            ) else {
                panic!("la modifica deve potersi aggiungere");
            };
        }

        let Ok(storia) = database.session_content_history(session_id) else {
            panic!("il riepilogo deve potersi leggere");
        };

        assert_eq!(
            storia.get(&primo.content_id().get()).map(|v| v.revisions),
            Some(1)
        );
        assert_eq!(
            storia.get(&secondo.content_id().get()).map(|v| v.revisions),
            Some(2)
        );
    }

    /// **Il conteggio in SQL e quello nel dominio devono coincidere.**
    ///
    /// # Perche' questa prova esiste
    ///
    /// L'ha chiesta un controllo negativo. Rompendo `ContentHistory::revisions`
    /// — facendola contare le versioni invece delle versioni meno una — la
    /// prova del dominio e' diventata rossa e quella della persistenza e'
    /// rimasta **verde**: la lettura in blocco calcola le revisioni in SQL,
    /// `COUNT(*) - 1`, e non passa dal dominio.
    ///
    /// Sono due implementazioni della stessa regola, e servono entrambe: quella
    /// in SQL perche' l'elenco non carichi i corpi, quella nel dominio perche'
    /// la storia completa si compone da cio' che e' stato letto. Due
    /// implementazioni sono due cose che divergono, e l'unico modo di
    /// accorgersene e' confrontarle sugli stessi dati.
    #[test]
    fn the_sql_count_and_the_domain_count_agree() {
        let (mut database, session_id, source_id) = seeded();

        // Tre casi diversi nella stessa sessione: mai toccato, solo seminato,
        // e modificato due volte. Se le due implementazioni divergessero su uno
        // solo di questi, la prova lo direbbe.
        let Ok(intatto) = database.insert_content(&new_content(session_id, source_id, "m1", "a"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let Ok(seminato) = database.insert_content(&new_content(session_id, source_id, "m2", "b"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let Ok(modificato) =
            database.insert_content(&new_content(session_id, source_id, "m3", "c"))
        else {
            panic!("il contenuto deve potersi registrare");
        };

        let Ok(_) = database.seed_original_version(seminato.content_id(), "b", later(1)) else {
            panic!("l'originale deve potersi seminare");
        };

        let Ok(_) = database.seed_original_version(modificato.content_id(), "c", later(1)) else {
            panic!("l'originale deve potersi seminare");
        };
        for (inbox, testo) in [(701, "c piu'"), (702, "c ancora piu'")] {
            let Ok(_) = database.append_content_version(
                InboxId::new(inbox),
                &NewContentVersion {
                    content_id: modificato.content_id(),
                    body: body(testo),
                    remote_edit_timestamp: None,
                    observed_at: later(11),
                },
            ) else {
                panic!("la modifica deve potersi aggiungere");
            };
        }

        let Ok(in_blocco) = database.session_content_history(session_id) else {
            panic!("il riepilogo deve potersi leggere");
        };

        for contenuto in [
            intatto.content_id(),
            seminato.content_id(),
            modificato.content_id(),
        ] {
            let Ok(completa) = database.content_history(contenuto) else {
                panic!("la storia completa deve potersi leggere");
            };

            // Il riepilogo in blocco omette chi non ha nulla da dire; il
            // dominio, su quegli stessi dati, deve dire zero.
            let da_sql = in_blocco
                .get(&contenuto.get())
                .map_or(0, |voce| voce.revisions);

            assert_eq!(
                da_sql,
                completa.revisions(),
                "il conteggio in SQL e quello nel dominio divergono sul \
                 contenuto {}: sono due implementazioni della stessa regola",
                contenuto.get()
            );
        }
    }
}

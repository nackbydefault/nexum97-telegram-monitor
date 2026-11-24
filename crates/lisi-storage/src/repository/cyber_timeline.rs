//! I fatti da cui si compone la cronologia di un grappolo (CYT-01).
//!
//! # Che cosa fa questo modulo, e che cosa non fa
//!
//! Legge righe. La cronologia la **compone il dominio**, con una funzione pura
//! che si prova senza aprire un archivio: è la scelta di PERS-02, PERS-03 e
//! PERS-04, e vale qui per la stessa ragione.
//!
//! # Perché la finestra di osservazione si legge dalla sessione
//!
//! Perché è un fatto del **monitoraggio**, non dei contenuti: un monitoraggio
//! che ha guardato senza raccogliere nulla ha comunque guardato, e dedurre la
//! finestra dai contenuti perderebbe esattamente il caso in cui un vuoto va
//! spiegato.
//!
//! # Perché il tetto sui membri è lo stesso della correlazione
//!
//! Perché la cronologia racconta **quel** grappolo, e un grappolo caricato con
//! cinquanta membri raccontato su cinquecento righe descriverebbe qualcos'altro.

use lisi_core::model::cyber_timeline::{ContextAvailability, EventFact, ReviewFact};
use lisi_core::model::indicator::IndicatorKind;
use lisi_core::model::observation_window::ObservationWindow;
use lisi_core::text::RemoteMessageId;
use lisi_core::{ContentId, ContextSnapshotId, SessionId, SourceId, Timestamp};
use rusqlite::OptionalExtension;

use crate::Database;
use crate::error::{StorageError, StorageResult};

impl Database {
    /// La finestra di osservazione di un monitoraggio, **se ha guardato**.
    ///
    /// # Perché `None` e non una finestra che parte dalla creazione
    ///
    /// Perché un monitoraggio creato e mai avviato **non ha osservato niente**,
    /// e una finestra che partisse dall'istante di creazione dichiarerebbe una
    /// copertura che nessuno ha avuto. Chi riceve `None` deve dirlo, non
    /// riempirlo.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn observation_window(
        &self,
        session_id: SessionId,
    ) -> StorageResult<Option<ObservationWindow>> {
        let riga: Option<(Option<i64>, Option<i64>)> = self
            .connection
            .query_row(
                "SELECT started_at, ended_at FROM sessions WHERE id = ?1",
                [session_id.get()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let Some((inizio, fine)) = riga else {
            return Ok(None);
        };

        // SENZA AVVIO NON C'E' FINESTRA.
        //
        // La conclusione senza avvio la vieta gia' un vincolo dell'archivio; qui
        // conta l'altro caso, che l'archivio ammette: pianificata e mai avviata.
        Ok(inizio.map(|inizio| ObservationWindow {
            session: session_id,
            from: Timestamp::from_millis(inizio),
            to: fine.map(Timestamp::from_millis),
        }))
    }

    /// L'identificativo dell'ultima fotografia del contesto di un contenuto.
    ///
    /// # Perché non si caricano le fotografie intere
    ///
    /// Perché la cronologia deve sapere **se** esiste una fotografia, non che
    /// cosa contenga: caricare le righe del contorno di cinquanta membri per
    /// scrivere cinquanta volte «esiste» costerebbe l'archivio per un `sì`.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn latest_context_snapshot_id(
        &self,
        content_id: ContentId,
    ) -> StorageResult<Option<ContextSnapshotId>> {
        let id: Option<i64> = self
            .connection
            .query_row(
                "SELECT id FROM context_snapshots
                 WHERE content_id = ?1
                 ORDER BY taken_at DESC, id DESC
                 LIMIT 1",
                [content_id.get()],
                |row| row.get(0),
            )
            .optional()?;

        Ok(id.map(ContextSnapshotId::new))
    }

    /// I fatti dei contenuti che, in un monitoraggio, nominano un indicatore.
    ///
    /// Escono nell'ordine dell'istante dichiarato dalla fonte, con
    /// l'identificativo del contenuto a decidere i pareggi: il dominio riordina
    /// comunque, e un ordine stabile già qui rende confrontabili due letture
    /// dell'archivio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// valore che il dominio rifiuta.
    pub fn event_facts(
        &self,
        session_id: SessionId,
        kind: IndicatorKind,
        value: &str,
        limit: usize,
    ) -> StorageResult<Vec<EventFact>> {
        let tetto = i64::try_from(limit).unwrap_or(i64::MAX);

        let mut membri = self.connection.prepare(
            "SELECT c.id, c.source_id, c.remote_message_id, c.published_at
             FROM content_indicators i
             JOIN contents c ON c.id = i.content_id
             WHERE c.session_id = ?1 AND i.kind = ?2 AND i.value = ?3
             ORDER BY c.published_at, c.id
             LIMIT ?4",
        )?;
        let righe: Vec<(i64, i64, String, i64)> = membri
            .query_map(
                rusqlite::params![session_id.get(), kind.as_str(), value, tetto],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(membri);

        let mut fatti = Vec::with_capacity(righe.len());
        for (content_id, source_id, remoto, pubblicato) in righe {
            let content = ContentId::new(content_id);

            // Un identificativo remoto che il dominio rifiuta e' una riga
            // corrotta, non un contenuto senza messaggio: sostituirlo con un
            // segnaposto farebbe comparire in una cronologia un rimando che non
            // porta da nessuna parte.
            let remote_message_id =
                RemoteMessageId::try_new(&remoto).map_err(|_| StorageError::CorruptedRow {
                    detail: "identificativo remoto non valido in contents",
                })?;

            let indicators = self
                .content_indicators(content)?
                .into_iter()
                .map(|indicatore| (indicatore.kind, indicatore.value))
                .collect();

            let context = match self.latest_context_snapshot_id(content)? {
                Some(id) => ContextAvailability::Snapshot(id),
                None => ContextAvailability::NeverTaken,
            };

            let reviews = self
                .content_reviews(content)?
                .into_iter()
                .map(|revisione| ReviewFact {
                    state: revisione.state,
                    reviewer: revisione.reviewer,
                    at: revisione.decided_at,
                })
                .collect::<Vec<ReviewFact>>();

            fatti.push(EventFact {
                content,
                source: SourceId::new(source_id),
                remote_message_id,
                published_at: Timestamp::from_millis(pubblicato),
                indicators,
                context,
                reviews,
            });
        }

        Ok(fatti)
    }
}

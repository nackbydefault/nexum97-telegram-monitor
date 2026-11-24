//! Runtime di acquisizione: dal connettore all'inbox, e dall'inbox allo storico.
//!
//! Progettazione in `docs/adr/ADR-0017-ACQUISITION-RUNTIME.md`, minacce in
//! `docs/threat-model/THREAT_MODEL_ACQUISITION.md`.
//!
//! # L'ordine, che è la sostanza
//!
//! Ogni evento viene **scritto nell'inbox prima** di essere elaborato. È il
//! punto in cui si compra la resistenza al crash: se l'applicazione cade dopo
//! la scrittura e prima dell'elaborazione, l'evento è ancora lì al riavvio, e
//! [`AcquisitionService::recover`] lo riprende.
//!
//! # Che cosa questo modulo non fa
//!
//! Non si collega a Telegram: consuma [`ConnectorEvent`] da un
//! [`TelegramConnector`], che in questa milestone è il connettore simulato.
//! Non interpreta gli eventi: una cancellazione è «osservata», non attribuita a
//! nessuno. Non decide la legittimità del monitoraggio.

use std::collections::{BTreeMap, HashMap};

use lisi_core::model::AcquisitionOrigin;
use lisi_core::model::AnalysisLevel;
use lisi_core::model::acquisition::{
    IdempotencyKey, InboxEntry, InboxEventKind, InboxOutcome, NewContentDeletion,
    NewContentVersion, NewInboxEntry,
};
use lisi_core::model::dictionary::ResolvedDictionaryConfiguration;
use lisi_core::model::monitoring_account::attributes_to;
use lisi_core::model::telegram_account::AccountUuid;
use lisi_core::text::{Actor, ContentBody, ContentUrl, RemoteMessageId, TermCategory};
use lisi_core::{ContentId, SessionId, SourceId, Timestamp};
use lisi_storage::Database;
use lisi_telegram::{
    AttachmentDescriptor, ConnectionState, ConnectorEvent, IncomingMessage, TelegramConnector,
    TelegramError,
};
use serde::{Deserialize, Serialize};

use crate::analysis::{AnalysisService, NewContentDraft};
use crate::error::{ServiceError, ServiceResult};

/// Versione del formato del payload conservato nell'inbox.
const PAYLOAD_FORMAT: u32 = 1;

/// Tentativi massimi prima di dichiarare una modifica orfana.
///
/// Una modifica arrivata prima del suo originale attende che l'originale
/// arrivi. Se dopo questi tentativi non è arrivato, la modifica non si perde:
/// diventa una voce fallita con la sua ragione.
const MAX_ATTEMPTS: u32 = 5;

/// Secondi di attesa prima di ritentare una modifica orfana.
const RETRY_DELAY_SECONDS: i64 = 30;

/// Ragioni di quarantena e di fallimento: costanti del prodotto, mai testo remoto.
mod reason {
    pub const BODY_INVALID: &str = "corpo_non_valido";
    pub const TIMESTAMP_INVALID: &str = "timestamp_non_valido";
    pub const SOURCE_NOT_MONITORED: &str = "fonte_non_monitorata";
    pub const EDIT_WITHOUT_ORIGINAL: &str = "modifica_senza_originale";
    pub const PAYLOAD_MISSING: &str = "payload_incompleto";
}

/// Payload normalizzato di un evento con contenuto, conservato nell'inbox.
///
/// Deve bastare a rieseguire l'applicazione dopo un riavvio, quando l'evento in
/// memoria non c'è più.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MessagePayload {
    #[serde(default)]
    author: Option<String>,
    /// Identificativo dell'autore presso la piattaforma.
    ///
    /// `serde(default)` non è una formalità: le voci di inbox scritte prima che
    /// questo campo esistesse **devono continuare a leggersi**. Una ripresa
    /// dopo un arresto anomalo trova in coda eventi del formato precedente, e
    /// rifiutarli perderebbe contenuti già acquisiti e mai applicati.
    #[serde(default)]
    author_identifier: Option<String>,
    /// Username dell'autore, quando ne ha uno.
    ///
    /// `serde(default)` come per gli altri campi aggiunti dopo: le voci di
    /// coda scritte prima che questo esistesse devono continuare a leggersi.
    #[serde(default)]
    author_username: Option<String>,
    text: String,
    #[serde(default)]
    url: Option<String>,
    /// L'istante dichiarato dalla fonte: pubblicazione per un messaggio nuovo,
    /// modifica per una modifica.
    ///
    /// **Può mancare soltanto per una modifica ritrovata da un recupero**
    /// (PR-07): la cronologia mostra il testo di oggi, non quando è cambiato, e
    /// scriverci l'istante del recupero sarebbe attribuire alla fonte un'ora che
    /// non ha dichiarato. Le voci scritte prima avevano sempre un numero, che si
    /// legge come `Some`: la forma sul disco non cambia.
    timestamp_millis: Option<i64>,
    /// Se il messaggio è stato osservato dal vivo o recuperato dalla cronologia.
    ///
    /// Sopravvive alla coda per la stessa ragione per cui la coda esiste: una
    /// ripresa dopo un arresto anomalo deve applicare l'evento **come era**, e
    /// dedurre l'origine al momento dell'applicazione la legherebbe a quando si
    /// è ripreso invece che a come il messaggio era arrivato.
    ///
    /// Si conserva nella **forma stabile testuale** del dominio e non come
    /// enumerazione: `lisi-core` non conosce serde, e non deve — il dominio non
    /// va piegato al formato di una coda. La conversione avviene qui, in un
    /// punto solo.
    ///
    /// Il valore predefinito vale per le voci scritte prima che questo campo
    /// esistesse, e non è una comodità: erano tutte osservazioni dal vivo,
    /// perché era l'unico modo di entrare in coda.
    #[serde(default = "observed_origin")]
    origin: String,
    /// L'allegato, descritto e non scaricato (ATTACH-01, ADR-0177).
    ///
    /// `serde(default)` come per gli altri campi aggiunti dopo: le voci di
    /// coda scritte prima che questo esistesse si leggono senza allegato, ed è
    /// ciò che allora si sapeva.
    #[serde(default)]
    attachment: Option<Box<AttachmentPayload>>,
}

/// La descrizione di un allegato nella coda: il genere nella sua chiave
/// stabile e ciò che il mittente dichiara, già ripulito dal connettore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AttachmentPayload {
    kind: String,
    #[serde(default)]
    declared_name: Option<String>,
    #[serde(default)]
    declared_size: Option<u64>,
    #[serde(default)]
    declared_mime: Option<String>,
}

impl From<&AttachmentDescriptor> for AttachmentPayload {
    fn from(descrizione: &AttachmentDescriptor) -> Self {
        Self {
            kind: descrizione.kind.as_str().to_owned(),
            declared_name: descrizione.declared_name.clone(),
            declared_size: descrizione.declared_size,
            declared_mime: descrizione.declared_mime.clone(),
        }
    }
}

/// Forma testuale dell'origine predefinita per le voci di coda più vecchie.
fn observed_origin() -> String {
    AcquisitionOrigin::Observed.as_str().to_owned()
}

/// Dati di una sessione necessari all'acquisizione.
///
/// Si costruisce una volta con [`AcquisitionService::load_context`] e si riusa
/// per tutti gli eventi di quella sessione: la mappa delle fonti e la
/// configurazione risolta non cambiano durante una tornata di acquisizione.
#[derive(Debug, Clone)]
pub struct SessionContext {
    /// Sessione in corso.
    pub session_id: SessionId,
    /// Attore registrato nell'audit per le operazioni di questa sessione.
    pub actor: Actor,
    /// Da identificativo di chat a fonte configurata.
    sources: HashMap<i64, SourceId>,
    /// Fotografia dei termini con cui analizzare i contenuti.
    configuration: ResolvedDictionaryConfiguration,
    /// L'account d'ufficio con cui la sessione lavora (ADR-0173, migrazione
    /// 0072); `None` per le sessioni nate senza.
    account: Option<AccountUuid>,
}

impl SessionContext {
    /// L'account con cui la sessione lavora, se registrato.
    #[must_use]
    pub const fn account(&self) -> Option<&AccountUuid> {
        self.account.as_ref()
    }

    /// Se un aggiornamento arrivato all'account `origin`, mentre gli account
    /// aperti sono `open`, appartiene a questa sessione (ADR-0173, decisione
    /// 3).
    ///
    /// Va chiesto **prima** di [`AcquisitionService::ingest`]: la stessa chat
    /// può essere seguita da due account, e il numero della chat da solo non
    /// dice a quale monitoraggio l'aggiornamento appartenga.
    #[must_use]
    pub fn accepts_from(&self, origin: &AccountUuid, open: usize) -> bool {
        attributes_to(self.account.as_ref(), origin, open)
    }

    /// Chat monitorate da questa sessione, con la fonte corrispondente.
    ///
    /// La mappa resta privata: chi la legge non deve poterla modificare, perché
    /// l'insieme delle fonti di una sessione è fissato alla creazione e un
    /// contenuto non può essere collegato a una fonte non selezionata.
    pub fn monitored_chats(&self) -> impl Iterator<Item = (i64, SourceId)> + '_ {
        self.sources.iter().map(|(chat, source)| (*chat, *source))
    }

    /// Fotografia dei termini con cui questa sessione analizza.
    ///
    /// È **quella conservata con la sessione**, non i dizionari di adesso: chi
    /// cerca nel passato deve usare gli stessi termini con cui il monitoraggio
    /// sta giudicando il presente, altrimenti la stessa domanda riceve due
    /// risposte diverse a seconda di chi la pone.
    #[must_use]
    pub const fn configuration(&self) -> &ResolvedDictionaryConfiguration {
        &self.configuration
    }
}

/// Esito dell'ingestione di uno o più eventi.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngestReport {
    /// Eventi accodati per la prima volta.
    pub enqueued: usize,
    /// Eventi già presenti: stessa chiave di idempotenza.
    pub duplicates: usize,
    /// Eventi messi in quarantena alla validazione.
    pub discarded: usize,
    /// Eventi applicati e conclusi ora.
    pub applied: usize,
    /// Eventi rinviati (modifiche in attesa dell'originale).
    pub deferred: usize,
    /// Contenuti prodotti o toccati.
    pub content_ids: Vec<ContentId>,
    /// Quanti contenuti **nuovi** per ciascuna fonte, in questa tornata.
    ///
    /// Serve al live condiviso (TEAM-LIVE-01, ADR-0093), che pubblica un
    /// evento per fonte con il numero: un evento per messaggio riempirebbe in
    /// pochi secondi la coda verso i client (ADR-0088). Conta i contenuti
    /// **nuovi**: un duplicato non è un fatto nuovo da mostrare.
    pub per_source: BTreeMap<i64, usize>,
    /// Gli avvisi scattati in questa tornata.
    pub alerts: Vec<RaisedAlert>,
}

/// Un avviso scattato, come lo racconta il live condiviso.
///
/// Porta il **livello** e la **categoria** del termine che lo ha fatto
/// scattare, che vengono dai dizionari dell'ufficio (ADR-0038): non porta il
/// testo del messaggio, che resta sull'Hub (ADR-0093, decisione 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaisedAlert {
    /// La fonte da cui proviene il contenuto.
    pub source_id: i64,
    /// Il livello attribuito.
    pub level: AnalysisLevel,
    /// La categoria del termine riscontrato, se ce n'è uno.
    pub category: Option<TermCategory>,
}

impl LiveTally {
    /// Svuota l'accumulatore e restituisce ciò che conteneva.
    fn take(&mut self) -> (BTreeMap<i64, usize>, Vec<RaisedAlert>) {
        (
            core::mem::take(&mut self.per_source),
            core::mem::take(&mut self.alerts),
        )
    }
}

impl IngestReport {
    fn absorb(&mut self, other: IngestReport) {
        self.enqueued += other.enqueued;
        self.duplicates += other.duplicates;
        self.discarded += other.discarded;
        self.applied += other.applied;
        self.deferred += other.deferred;
        self.content_ids.extend(other.content_ids);
        for (fonte, quanti) in other.per_source {
            *self.per_source.entry(fonte).or_insert(0) += quanti;
        }
        self.alerts.extend(other.alerts);
    }
}

/// Esito del recupero dopo un'interruzione.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Voci trovate in elaborazione al riavvio.
    pub resumed: usize,
    /// Voci concluse durante il recupero.
    pub completed: usize,
    /// Voci ancora rinviate.
    pub deferred: usize,
}

/// Servizio di acquisizione.
///
/// Possiede un [`AnalysisService`], e con esso l'archivio: analizzare un
/// contenuto e gestirne l'inbox sono la stessa sequenza, e tenerli sullo stesso
/// archivio evita di prestarlo avanti e indietro a ogni evento.
#[derive(Debug)]
pub struct AcquisitionService {
    analysis: AnalysisService,
    /// Che cosa è accaduto nella tornata in corso, per il live condiviso.
    ///
    /// Vive qui e non viaggia come parametro perché il punto che *sa* — dove
    /// un contenuto viene applicato — è in fondo a una catena di cinque
    /// funzioni, e farvi passare il rapporto significherebbe cambiarle tutte
    /// per un dato che riguarda solo la fine. Si svuota a ogni tornata.
    tally: LiveTally,
}

/// Che cosa una tornata ha prodotto, per il live condiviso (ADR-0093).
#[derive(Debug, Default)]
struct LiveTally {
    per_source: BTreeMap<i64, usize>,
    alerts: Vec<RaisedAlert>,
}

impl AcquisitionService {
    /// Crea il servizio attorno al database indicato.
    #[must_use]
    pub fn new(database: Database) -> Self {
        Self {
            analysis: AnalysisService::new(database),
            tally: LiveTally::default(),
        }
    }

    /// Database sottostante, per i test e la diagnostica.
    #[must_use]
    pub const fn database(&self) -> &Database {
        self.analysis.database()
    }

    /// Database sottostante in prestito mutabile, per le operazioni che aprono
    /// una transazione.
    #[must_use]
    pub const fn database_mut(&mut self) -> &mut Database {
        self.analysis.database_mut()
    }

    /// Restituisce il database, consumando il servizio.
    #[must_use]
    pub fn into_database(self) -> Database {
        self.analysis.into_database()
    }

    /// Costruisce il contesto di una sessione leggendolo dall'archivio.
    ///
    /// La configurazione risolta può mancare — una sessione senza dizionari —,
    /// e in tal caso ogni contenuto risulta di livello 0: è comunque acquisito
    /// e registrato, che è ciò che il requisito chiede.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la sessione non esiste o se le sue fonti non
    /// sono leggibili.
    pub fn load_context(
        &self,
        session_id: SessionId,
        actor: Actor,
    ) -> ServiceResult<SessionContext> {
        let mut sources = HashMap::new();
        for source_id in self.database().session_source_ids(session_id)? {
            let source = self.database().source(source_id)?;
            if let Ok(chat_id) = source.identifier.as_str().parse::<i64>() {
                sources.insert(chat_id, source.id);
            }
        }

        let configuration = self
            .database()
            .session_resolved_configuration(session_id)?
            .unwrap_or_else(|| ResolvedDictionaryConfiguration::from_terms(Vec::new()));
        let account = self
            .database()
            .session_account(session_id)?
            .map(|legame| legame.account_uuid);

        Ok(SessionContext {
            session_id,
            actor,
            sources,
            configuration,
            account,
        })
    }

    /// Riceve gli eventi dal connettore fino al silenzio, e li ingesta.
    ///
    /// `budget` limita il numero di eventi per tornata, così che una fonte molto
    /// attiva non tenga il ciclo occupato all'infinito.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura nell'inbox o l'analisi non riescono.
    pub fn drain(
        &mut self,
        connector: &mut dyn TelegramConnector,
        context: &SessionContext,
        now: Timestamp,
        budget: usize,
    ) -> ServiceResult<IngestReport> {
        let mut report = IngestReport::default();

        for _ in 0..budget {
            match connector.poll_event(std::time::Duration::from_millis(0)) {
                Ok(Some(event)) => report.absorb(self.ingest(&event, context, now)?),
                // Nessun evento (fonte in silenzio) o un'attesa scaduta o un
                // connettore chiuso interrompono la tornata: non sono un errore
                // da propagare, sono la fine del flusso disponibile ora.
                Ok(None) | Err(_) => break,
            }
        }

        Ok(report)
    }

    /// Ingesta un singolo evento del connettore.
    ///
    /// Un evento può produrre più voci d'inbox — una cancellazione multipla è
    /// più cancellazioni — quindi il risultato è un riepilogo, non un esito
    /// singolo.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura nell'inbox o l'analisi non riescono.
    pub fn ingest(
        &mut self,
        event: &ConnectorEvent,
        context: &SessionContext,
        now: Timestamp,
    ) -> ServiceResult<IngestReport> {
        let mut report = IngestReport::default();

        for fact in classify(event) {
            self.ingest_fact(&fact, context, now, &mut report)?;
        }

        let (per_source, alerts) = self.tally.take();
        report.per_source = per_source;
        report.alerts = alerts;

        Ok(report)
    }

    /// Accoda messaggi **recuperati dalla cronologia** già pubblicata.
    ///
    /// Passa dalla stessa inbox durevole degli eventi osservati, e non è un
    /// dettaglio di comodità: è ciò che rende il recupero **idempotente e
    /// ripristinabile**. Un recupero di migliaia di messaggi interrotto a metà
    /// da un arresto anomalo riprende da dove era, e i messaggi già applicati
    /// non si duplicano — la chiave di idempotenza è quella dello schema, la
    /// stessa che protegge l'acquisizione dal vivo.
    ///
    /// Un messaggio che **era già stato osservato** non diventa recuperato: il
    /// vincolo di unicità lo riconosce come già presente e l'inserimento non
    /// avviene. L'archivio conserva la prima verità, che è quella più forte —
    /// «l'ho visto arrivare» — invece di sostituirla con la più debole.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura in coda non riesce.
    pub fn ingest_recovered(
        &mut self,
        messages: &[IncomingMessage],
        context: &SessionContext,
        now: Timestamp,
    ) -> ServiceResult<IngestReport> {
        let mut report = IngestReport::default();

        for message in messages {
            let fact = Fact {
                kind: InboxEventKind::NewMessage,
                chat_id: Some(message.chat_id.get()),
                message_id: Some(message.message_id.get()),
                remote_ts_millis: Some(message.published_at_millis),
                author: message.author.clone(),
                author_identifier: message.author_identifier.clone(),
                author_username: message.author_username.clone(),
                text: Some(message.text.clone()),
                url: message.url.clone(),
                // È l'unica differenza rispetto all'acquisizione dal vivo, ed è
                // quella che l'archivio deve dichiarare.
                origin: AcquisitionOrigin::Recovered,
                attachment: message
                    .attachment
                    .as_deref()
                    .map(|descrizione| Box::new(AttachmentPayload::from(descrizione))),
            };
            self.ingest_fact(&fact, context, now, &mut report)?;
        }

        Ok(report)
    }

    /// Registra come **versioni aggiuntive** i messaggi che il recupero ha
    /// ritrovato con un testo diverso da quello in archivio (PR-07, ADR-0123).
    ///
    /// # Perché una modifica, e non una sostituzione
    ///
    /// Perché il contenuto in archivio è ciò che è stato visto allora, e il
    /// recupero vede il messaggio come è adesso. Passano dalla stessa strada di
    /// una modifica osservata: una versione in più, e la prima resta. L'istante
    /// della modifica presso la fonte non è noto — la cronologia non lo dice —
    /// e resta vuoto invece di essere inventato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se una scrittura non riesce.
    pub fn ingest_recovered_edits(
        &mut self,
        messages: &[IncomingMessage],
        context: &SessionContext,
        now: Timestamp,
    ) -> ServiceResult<IngestReport> {
        let mut report = IngestReport::default();

        for message in messages {
            let fact = Fact {
                kind: InboxEventKind::EditedMessage,
                chat_id: Some(message.chat_id.get()),
                message_id: Some(message.message_id.get()),
                remote_ts_millis: None,
                author: None,
                author_identifier: None,
                author_username: None,
                text: Some(message.text.clone()),
                url: None,
                origin: AcquisitionOrigin::Recovered,
                attachment: None,
            };
            self.ingest_fact(&fact, context, now, &mut report)?;
        }

        Ok(report)
    }

    fn ingest_fact(
        &mut self,
        fact: &Fact,
        context: &SessionContext,
        now: Timestamp,
        report: &mut IngestReport,
    ) -> ServiceResult<()> {
        let source_id = fact
            .chat_id
            .and_then(|chat| context.sources.get(&chat).copied());
        let remote_event_id = match fact.message_id {
            Some(message) => Some(RemoteMessageId::try_new(&message.to_string())?),
            None => None,
        };

        // La validazione avviene qui, prima di decidere se l'evento è
        // elaborabile. Un evento con contenuto ma non valido viene comunque
        // accodato e poi messo in quarantena: la quarantena è durevole, non un
        // silenzio.
        let validation = validate(fact, source_id);

        let discriminator = fact.discriminator(now);
        let key = IdempotencyKey::derive(
            context.session_id,
            source_id,
            fact.kind,
            remote_event_id.as_ref().map(RemoteMessageId::as_str),
            discriminator.as_deref(),
        );

        let payload_json = match &validation {
            Validation::Valid(payload) => Some(serialize_payload(payload)?),
            Validation::Rejected(_) | Validation::None => None,
        };

        let outcome = self.database().enqueue_inbox(&NewInboxEntry {
            session_id: context.session_id,
            source_id,
            event_kind: fact.kind,
            remote_event_id,
            idempotency_key: key,
            remote_timestamp: fact.remote_ts_millis.map(Timestamp::from_millis),
            received_at: now,
            payload_json,
            format_version: PAYLOAD_FORMAT,
        })?;

        let InboxOutcome::Enqueued(id) = outcome else {
            // Già presente: la chiave di idempotenza ha fatto il suo lavoro.
            report.duplicates += 1;
            return Ok(());
        };
        report.enqueued += 1;

        // La quarantena è l'unico esito che non passa da `perform`: un evento
        // rifiutato alla validazione non si applica. Tutto il resto — contenuti,
        // cancellazioni, eventi operativi — è elaborato da `perform`, che li
        // distingue per tipo. Le cancellazioni e gli eventi operativi non hanno
        // un payload, e va bene: `perform` non lo richiede per loro.
        if let Validation::Rejected(cause) = validation {
            self.database().mark_inbox_discarded(id, cause)?;
            report.discarded += 1;
            return Ok(());
        }

        let payload = match validation {
            Validation::Valid(payload) => Some(payload),
            Validation::Rejected(_) | Validation::None => None,
        };
        let outcome = self.perform(
            id,
            fact.kind,
            source_id,
            fact.message_id,
            payload.as_ref(),
            context,
            now,
            0,
        )?;
        report.record(outcome);

        Ok(())
    }

    /// Applica le voci ancora in attesa, comprese le modifiche rinviate.
    ///
    /// Chiamarla dopo una tornata di acquisizione risolve le modifiche il cui
    /// originale è arrivato nel frattempo.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se una lettura o un'applicazione non riescono.
    pub fn process_pending(
        &mut self,
        context: &SessionContext,
        now: Timestamp,
    ) -> ServiceResult<IngestReport> {
        let pending = self.database().inbox_pending(context.session_id)?;
        let mut report = IngestReport::default();
        for entry in pending {
            let outcome = self.reapply(&entry, context, now)?;
            report.record(outcome);
        }

        let (per_source, alerts) = self.tally.take();
        report.per_source = per_source;
        report.alerts = alerts;
        Ok(report)
    }

    /// Riprende le voci rimaste in elaborazione dopo un'interruzione.
    ///
    /// Le riesegue in modo idempotente: una voce già applicata prima del crash
    /// non produce un doppione, perché l'inserimento del contenuto riconosce il
    /// messaggio già acquisito. Il recupero è registrato nell'audit.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se una lettura o un'applicazione non riescono.
    pub fn recover(
        &mut self,
        context: &SessionContext,
        now: Timestamp,
    ) -> ServiceResult<RecoveryReport> {
        let in_progress = self.database().inbox_in_progress(context.session_id)?;
        let mut report = RecoveryReport {
            resumed: in_progress.len(),
            ..RecoveryReport::default()
        };

        for entry in in_progress {
            match self.reapply(&entry, context, now)? {
                Outcome::Completed(_) | Outcome::CompletedEmpty => report.completed += 1,
                Outcome::Deferred => report.deferred += 1,
                Outcome::Duplicate => report.completed += 1,
            }
        }

        if report.resumed > 0 {
            self.record_recovery_audit(context, &report, now)?;
        }
        Ok(report)
    }

    /// Riapplica una voce dell'inbox a partire dai suoi dati conservati.
    fn reapply(
        &mut self,
        entry: &InboxEntry,
        context: &SessionContext,
        now: Timestamp,
    ) -> ServiceResult<Outcome> {
        let payload = match entry.payload_json.as_deref() {
            Some(raw) => Some(deserialize_payload(raw)?),
            None => None,
        };
        let message_id = entry
            .remote_event_id
            .as_ref()
            .and_then(|id| id.as_str().parse::<i64>().ok());

        self.perform(
            entry.id,
            entry.event_kind,
            entry.source_id,
            message_id,
            payload.as_ref(),
            context,
            now,
            entry.attempts,
        )
    }

    /// Cuore dell'elaborazione, condiviso dall'ingestione e dal recupero.
    #[allow(clippy::too_many_arguments)]
    fn perform(
        &mut self,
        id: lisi_core::InboxId,
        kind: InboxEventKind,
        source_id: Option<SourceId>,
        message_id: Option<i64>,
        payload: Option<&MessagePayload>,
        context: &SessionContext,
        now: Timestamp,
        attempts: u32,
    ) -> ServiceResult<Outcome> {
        self.database().mark_inbox_processing(id)?;

        match kind {
            InboxEventKind::NewMessage => {
                let (Some(payload), Some(source_id), Some(message_id)) =
                    (payload, source_id, message_id)
                else {
                    self.database()
                        .mark_inbox_failed(id, reason::PAYLOAD_MISSING)?;
                    return Ok(Outcome::CompletedEmpty);
                };
                self.apply_new_message(id, source_id, message_id, payload, context, now)
            }
            InboxEventKind::EditedMessage => {
                let (Some(payload), Some(source_id), Some(message_id)) =
                    (payload, source_id, message_id)
                else {
                    self.database()
                        .mark_inbox_failed(id, reason::PAYLOAD_MISSING)?;
                    return Ok(Outcome::CompletedEmpty);
                };
                self.apply_edit(id, source_id, message_id, payload, context, now, attempts)
            }
            InboxEventKind::DeletedMessage => {
                self.apply_deletion(id, source_id, message_id, context, now)
            }
            // Eventi operativi: registrati, senza contenuto da applicare.
            _ => {
                self.database().mark_inbox_completed(id, None, now)?;
                self.database()
                    .set_session_checkpoint(context.session_id, id, now)?;
                Ok(Outcome::CompletedEmpty)
            }
        }
    }

    fn apply_new_message(
        &mut self,
        id: lisi_core::InboxId,
        source_id: SourceId,
        message_id: i64,
        payload: &MessagePayload,
        context: &SessionContext,
        now: Timestamp,
    ) -> ServiceResult<Outcome> {
        // Un messaggio nuovo senza istante di pubblicazione non esiste: la
        // validazione non lo lascia passare, e una voce di coda che lo portasse
        // comunque non diventa un contenuto con una data inventata.
        let Some(published_at) = payload.timestamp_millis.map(Timestamp::from_millis) else {
            self.database()
                .mark_inbox_failed(id, reason::TIMESTAMP_INVALID)?;
            return Ok(Outcome::CompletedEmpty);
        };
        let draft = NewContentDraft {
            session_id: context.session_id,
            source_id,
            remote_message_id: RemoteMessageId::try_new(&message_id.to_string())?,
            author: payload
                .author
                .as_deref()
                .and_then(|name| Actor::try_new(name).ok()),
            author_identifier: payload.author_identifier.clone(),
            author_username: payload.author_username.clone(),
            body: ContentBody::try_new(&payload.text)?,
            url: payload
                .url
                .as_deref()
                .and_then(|url| ContentUrl::try_new(url).ok()),
            published_at,
            acquired_at: now,
            // L'origine viene dal payload e non da qui: è una proprietà del
            // messaggio, non del momento in cui lo si applica. Dedurla qui la
            // legherebbe a quando si è ripresa la coda invece che a come il
            // messaggio era arrivato.
            //
            // Un valore non riconoscibile ricade su «osservato», che è ciò che
            // ogni voce scritta prima di questo campo effettivamente era: è il
            // valore **vero** per quel caso, non un ripiego prudente.
            origin: payload
                .origin
                .parse()
                .unwrap_or(AcquisitionOrigin::Observed),
        };

        let record = self.analysis.analyse_and_record(
            &draft,
            &context.configuration,
            &context.actor,
            now,
        )?;
        let content_id = record.content_id;

        // L'ALLEGATO SI DESCRIVE, NON SI SCARICA (ATTACH-01, ADR-0177). La
        // scrittura non cambia una descrizione già registrata: una ripresa della
        // coda dopo un arresto fra il contenuto e questa riga la completa, e
        // non la raddoppia.
        if let (Some(content_id), Some(allegato)) = (content_id, payload.attachment.as_ref()) {
            self.database().record_content_attachment(
                content_id,
                &lisi_storage::repository::attachment::ContentAttachment {
                    kind: allegato.kind.clone(),
                    declared_name: allegato.declared_name.clone(),
                    declared_size: allegato.declared_size,
                    declared_mime: allegato.declared_mime.clone(),
                },
            )?;
        }

        // IL LIVE CONDIVISO CONTA I FATTI NUOVI (ADR-0093). Un contenuto già
        // acquisito non è un fatto nuovo da mostrare, e contarlo farebbe
        // leggere a chi guarda un'attività che non c'è stata.
        if content_id.is_some() && !record.already_known {
            *self.tally.per_source.entry(source_id.get()).or_insert(0) += 1;
            if record.raised_alert() {
                let categoria = record
                    .analysed
                    .occurrences
                    .first()
                    .and_then(|occorrenza| context.configuration.terms.get(occorrenza.term_index))
                    .map(|termine| termine.category.clone());
                self.tally.alerts.push(RaisedAlert {
                    source_id: source_id.get(),
                    level: record.analysed.outcome.level,
                    category: categoria,
                });
            }
        }

        self.database().mark_inbox_completed(id, content_id, now)?;
        self.database()
            .set_session_checkpoint(context.session_id, id, now)?;

        Ok(match content_id {
            Some(content_id) if record.already_known => Outcome::Duplicate.with(content_id),
            Some(content_id) => Outcome::Completed(content_id),
            None => Outcome::CompletedEmpty,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_edit(
        &mut self,
        id: lisi_core::InboxId,
        source_id: SourceId,
        message_id: i64,
        payload: &MessagePayload,
        context: &SessionContext,
        now: Timestamp,
        attempts: u32,
    ) -> ServiceResult<Outcome> {
        let remote = message_id.to_string();
        let content_id = self
            .database()
            .find_content_id(context.session_id, source_id, &remote)?;

        let Some(content_id) = content_id else {
            // La modifica è arrivata prima dell'originale. Non si inventa
            // l'originale: si attende. Dopo troppi tentativi la modifica non si
            // perde, diventa una voce fallita con la sua ragione.
            if attempts + 1 >= MAX_ATTEMPTS {
                self.database()
                    .mark_inbox_failed(id, reason::EDIT_WITHOUT_ORIGINAL)?;
                return Ok(Outcome::CompletedEmpty);
            }
            self.database().mark_inbox_retry(
                id,
                reason::EDIT_WITHOUT_ORIGINAL,
                now.plus_seconds(RETRY_DELAY_SECONDS),
            )?;
            return Ok(Outcome::Deferred);
        };

        // La versione 1 è il corpo originale: si semina alla prima modifica,
        // così che la storia delle versioni sia completa. È idempotente.
        let original = self.database().content(content_id)?;
        self.database().seed_original_version(
            content_id,
            original.body.as_str(),
            original.acquired_at,
        )?;

        // La versione è legata a QUESTA voce d'inbox: una ripresa dopo un crash
        // che riesegue la stessa voce non aggiunge una seconda versione.
        self.database().append_content_version(
            id,
            &NewContentVersion {
                content_id,
                body: ContentBody::try_new(&payload.text)?,
                remote_edit_timestamp: payload.timestamp_millis.map(Timestamp::from_millis),
                observed_at: now,
            },
        )?;

        self.database()
            .mark_inbox_completed(id, Some(content_id), now)?;
        self.database()
            .set_session_checkpoint(context.session_id, id, now)?;
        Ok(Outcome::Completed(content_id))
    }

    fn apply_deletion(
        &mut self,
        id: lisi_core::InboxId,
        source_id: Option<SourceId>,
        message_id: Option<i64>,
        context: &SessionContext,
        now: Timestamp,
    ) -> ServiceResult<Outcome> {
        // La cancellazione di un messaggio mai acquisito è un'informazione, non
        // un errore: la fonte ha cancellato qualcosa che non abbiamo visto.
        let content_id = match (source_id, message_id) {
            (Some(source_id), Some(message_id)) => self.database().find_content_id(
                context.session_id,
                source_id,
                &message_id.to_string(),
            )?,
            _ => None,
        };

        let remote_event_id = match message_id {
            Some(message) => Some(RemoteMessageId::try_new(&message.to_string())?),
            None => None,
        };

        // Anche la cancellazione è legata alla voce d'inbox: una ripresa dopo un
        // crash non registra due volte lo stesso fatto.
        self.database().insert_content_deletion(
            id,
            &NewContentDeletion {
                content_id,
                session_id: context.session_id,
                source_id,
                remote_event_id,
                observed_at: now,
            },
        )?;

        self.database().mark_inbox_completed(id, content_id, now)?;
        self.database()
            .set_session_checkpoint(context.session_id, id, now)?;

        Ok(content_id.map_or(Outcome::CompletedEmpty, Outcome::Completed))
    }

    /// Dichiara nel registro che la coda degli eventi in arrivo ne ha scartati.
    ///
    /// # Perché esiste (FINAL-REVIEW-01, FR-012)
    ///
    /// La coda ha un tetto, e a coda piena si scarta il più vecchio contando la
    /// perdita. Il conteggio esisteva e **non arrivava a nessuno**: un
    /// archivio incompleto restava indistinguibile da uno completo. Ora chi
    /// ingerisce, quando il conteggio cresce, lo scrive qui.
    ///
    /// # Errori
    ///
    /// Se la scrittura dell'audit non riesce.
    pub fn declare_dropped_events(
        &self,
        nuovi: u64,
        totale: u64,
        now: Timestamp,
    ) -> ServiceResult<()> {
        use lisi_core::model::NewAuditEntry;
        use lisi_core::text::{AuditAction, AuditDetail, AuditEntity};

        let detail = format!(
            "La coda degli eventi in arrivo da Telegram era piena: {nuovi} eventi sono stati \
             scartati ({totale} da quando l'account è aperto). Ciò che non è entrato in coda non \
             è in archivio."
        );
        self.database().append_audit(&NewAuditEntry {
            actor: Actor::try_new("acquisizione")?,
            action: AuditAction::try_new("eventi_scartati")?,
            entity: AuditEntity::try_new("acquisizione")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&detail)?),
            recorded_at: now,
        })?;
        Ok(())
    }

    fn record_recovery_audit(
        &self,
        context: &SessionContext,
        report: &RecoveryReport,
        now: Timestamp,
    ) -> ServiceResult<()> {
        use lisi_core::model::NewAuditEntry;
        use lisi_core::text::{AuditAction, AuditDetail, AuditEntity};

        let detail = format!(
            "riprese {}, concluse {}, rinviate {}",
            report.resumed, report.completed, report.deferred
        );

        self.database().append_audit(&NewAuditEntry {
            actor: context.actor.clone(),
            action: AuditAction::try_new("acquisizione_ripresa")?,
            entity: AuditEntity::try_new("session")?,
            entity_id: Some(context.session_id.get()),
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&detail)?),
            recorded_at: now,
        })?;
        Ok(())
    }
}

/// Esito dell'applicazione di una singola voce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Conclusa, con un contenuto prodotto o toccato.
    Completed(ContentId),
    /// Conclusa, senza un contenuto (cancellazione di un messaggio mai visto,
    /// evento operativo, o contenuto non registrato).
    CompletedEmpty,
    /// Rinviata: una modifica in attesa del suo originale.
    Deferred,
    /// Contenuto già acquisito: nessuna nuova riga.
    Duplicate,
}

impl Outcome {
    /// Sostituisce il contenuto di un esito duplicato, per riportarlo.
    const fn with(self, content_id: ContentId) -> Self {
        match self {
            Self::Duplicate => Self::Duplicate,
            _ => Self::Completed(content_id),
        }
    }
}

impl IngestReport {
    fn record(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Completed(content_id) => {
                self.applied += 1;
                self.content_ids.push(content_id);
            }
            Outcome::Duplicate => self.applied += 1,
            Outcome::CompletedEmpty => self.applied += 1,
            Outcome::Deferred => self.deferred += 1,
        }
    }
}

/// Esito di validazione di un evento con contenuto.
enum Validation {
    /// Valido, con il payload da conservare.
    Valid(MessagePayload),
    /// Rifiutato, con la ragione (costante del prodotto).
    Rejected(&'static str),
    /// Non è un evento con contenuto (operativo): niente da validare.
    None,
}

/// Fatto grezzo estratto da un evento del connettore.
///
/// Un `ConnectorEvent` può produrre più fatti: una cancellazione multipla è più
/// cancellazioni, ciascuna un evento a sé nell'inbox.
struct Fact {
    kind: InboxEventKind,
    chat_id: Option<i64>,
    message_id: Option<i64>,
    remote_ts_millis: Option<i64>,
    author: Option<String>,
    /// Identificativo dell'autore presso la piattaforma, quando esiste.
    author_identifier: Option<String>,
    /// Username dell'autore, quando ne ha uno.
    author_username: Option<String>,
    text: Option<String>,
    url: Option<String>,
    /// Se il messaggio è stato osservato dal vivo o recuperato dalla cronologia.
    origin: AcquisitionOrigin,
    /// L'allegato, descritto e non scaricato (ATTACH-01, ADR-0177).
    attachment: Option<Box<AttachmentPayload>>,
}

impl Fact {
    /// Discriminante che distingue eventi altrimenti identici.
    ///
    /// Per una modifica è l'istante **e l'impronta del nuovo corpo**: due
    /// modifiche distinte dello stesso messaggio sono due eventi anche se
    /// condividono l'istante (granularità al secondo), e la riconsegna della
    /// stessa modifica collide correttamente. Per un evento operativo è
    /// l'istante di ricezione: due cadute di connessione in momenti diversi
    /// sono due fatti. Per un nuovo messaggio o una cancellazione è assente: la
    /// riconsegna dello stesso evento **deve** collidere.
    fn discriminator(&self, now: Timestamp) -> Option<String> {
        match self.kind {
            InboxEventKind::EditedMessage => {
                let ts = self.remote_ts_millis.unwrap_or(0);
                let body = self.text.as_deref().unwrap_or_default();
                let digest = lisi_core::Sha256Digest::of_text(body);
                Some(format!("{ts}:{}", digest.as_str()))
            }
            InboxEventKind::NewMessage | InboxEventKind::DeletedMessage => None,
            _ => Some(now.as_millis().to_string()),
        }
    }
}

/// Traduce un evento del connettore in uno o più fatti.
fn classify(event: &ConnectorEvent) -> Vec<Fact> {
    match event {
        ConnectorEvent::MessageReceived(message) => vec![Fact {
            kind: InboxEventKind::NewMessage,
            chat_id: Some(message.chat_id.get()),
            message_id: Some(message.message_id.get()),
            remote_ts_millis: Some(message.published_at_millis),
            author: message.author.clone(),
            author_identifier: message.author_identifier.clone(),
            author_username: message.author_username.clone(),
            text: Some(message.text.clone()),
            url: message.url.clone(),
            origin: AcquisitionOrigin::Observed,
            attachment: message
                .attachment
                .as_deref()
                .map(|descrizione| Box::new(AttachmentPayload::from(descrizione))),
        }],
        ConnectorEvent::MessageEdited(edit) => vec![Fact {
            kind: InboxEventKind::EditedMessage,
            chat_id: Some(edit.chat_id.get()),
            message_id: Some(edit.message_id.get()),
            remote_ts_millis: Some(edit.edited_at_millis),
            author: None,
            // Non e' un messaggio di una persona: nessun identificativo da attribuire.
            author_identifier: None,
            author_username: None,
            text: Some(edit.text.clone()),
            url: None,
            origin: AcquisitionOrigin::Observed,
            attachment: None,
        }],
        ConnectorEvent::MessagesDeleted(deletion) => deletion
            .message_ids
            .iter()
            .map(|message_id| Fact {
                kind: InboxEventKind::DeletedMessage,
                chat_id: Some(deletion.chat_id.get()),
                message_id: Some(message_id.get()),
                remote_ts_millis: Some(deletion.deleted_at_millis),
                author: None,
                // Non e' un messaggio di una persona: nessun identificativo da attribuire.
                author_identifier: None,
                author_username: None,
                text: None,
                url: None,
                origin: AcquisitionOrigin::Observed,
                attachment: None,
            })
            .collect(),
        ConnectorEvent::Connection(state) => match state {
            ConnectionState::Online => vec![operational(InboxEventKind::ConnectionEstablished)],
            ConnectionState::Interrupted => vec![operational(InboxEventKind::ConnectionLost)],
            // Il tentativo di collegamento è transitorio: non lascia una traccia.
            ConnectionState::Connecting | ConnectionState::Offline => Vec::new(),
        },
        ConnectorEvent::Failure(error) => vec![operational(error_kind(error))],
        // L'autorizzazione è gestita dal servizio d'accesso, non qui.
        ConnectorEvent::Authorization(_) => Vec::new(),
    }
}

/// Fatto operativo senza contenuto.
fn operational(kind: InboxEventKind) -> Fact {
    Fact {
        kind,
        chat_id: None,
        message_id: None,
        remote_ts_millis: None,
        author: None,
        // Non e' un messaggio di una persona: nessun identificativo da attribuire.
        author_identifier: None,
        author_username: None,
        text: None,
        url: None,
        origin: AcquisitionOrigin::Observed,
        attachment: None,
    }
}

/// Classifica un errore del connettore come transitorio o permanente.
const fn error_kind(error: &TelegramError) -> InboxEventKind {
    match error {
        // Un connettore chiuso o una sessione revocata richiedono un intervento.
        TelegramError::Closed | TelegramError::SessionRevoked => InboxEventKind::PermanentError,
        // Il resto è transitorio: si ritenta con backoff.
        _ => InboxEventKind::TemporaryError,
    }
}

/// Valida un fatto con contenuto, producendo il payload o la ragione del rifiuto.
fn validate(fact: &Fact, source_id: Option<SourceId>) -> Validation {
    if !fact.kind.is_about_a_message() {
        return Validation::None;
    }
    // La cancellazione non porta un corpo: non ha un payload da validare, ma non
    // è nemmeno «operativa». Si tratta come valida senza payload.
    if fact.kind == InboxEventKind::DeletedMessage {
        return Validation::None;
    }

    if source_id.is_none() {
        // Un messaggio da una chat che questa sessione non monitora.
        return Validation::Rejected(reason::SOURCE_NOT_MONITORED);
    }

    // L'istante manca, legittimamente, soltanto a una modifica ritrovata da un
    // recupero: la cronologia non dice quando il testo è cambiato. Ovunque
    // altrove, un istante mancante è un evento non valido.
    let ammesso_senza_istante =
        fact.kind == InboxEventKind::EditedMessage && fact.origin == AcquisitionOrigin::Recovered;
    let timestamp = match fact.remote_ts_millis {
        Some(timestamp) if timestamp < 0 => {
            // Un messaggio non può essere stato pubblicato prima dell'epoca Unix.
            return Validation::Rejected(reason::TIMESTAMP_INVALID);
        }
        Some(timestamp) => Some(timestamp),
        None if ammesso_senza_istante => None,
        None => return Validation::Rejected(reason::TIMESTAMP_INVALID),
    };

    let text = fact.text.clone().unwrap_or_default();
    if ContentBody::try_new(&text).is_err() {
        // Corpo oltre misura o con caratteri non ammessi: quarantena.
        return Validation::Rejected(reason::BODY_INVALID);
    }

    Validation::Valid(MessagePayload {
        // Autore e URL non validi si lasciano cadere: il contenuto è la parte
        // che conta, e vale la pena conservarlo senza un dato accessorio ostile.
        author: fact
            .author
            .as_deref()
            .filter(|name| Actor::try_new(name).is_ok())
            .map(str::to_owned),
        // L'identificativo lo produce il prodotto, non la fonte: e' composto di
        // sole cifre e non ha nulla da filtrare. Il filtro resta comunque, a
        // difesa di un chiamante futuro che lo riempisse altrimenti.
        author_identifier: fact
            .author_identifier
            .as_deref()
            .filter(|value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
            .map(str::to_owned),
        author_username: fact.author_username.clone(),
        text,
        url: fact
            .url
            .as_deref()
            .filter(|url| ContentUrl::try_new(url).is_ok())
            .map(str::to_owned),
        timestamp_millis: timestamp,
        // L'origine non si valida: non viene dalla fonte, la dichiara il
        // percorso che ha chiesto il messaggio. È l'unico campo del payload di
        // cui il mondo remoto non ha voce.
        origin: fact.origin.as_str().to_owned(),
        attachment: fact.attachment.clone(),
    })
}

fn serialize_payload(payload: &MessagePayload) -> ServiceResult<String> {
    serde_json::to_string(payload).map_err(|error| ServiceError::SessionUnavailable {
        reason: format!("il contenuto tecnico del messaggio non si può salvare: {error}"),
    })
}

fn deserialize_payload(raw: &str) -> ServiceResult<MessagePayload> {
    serde_json::from_str(raw).map_err(|error| ServiceError::SessionUnavailable {
        reason: format!("il contenuto tecnico del messaggio non si può leggere: {error}"),
    })
}

#[cfg(test)]
mod tests {
    use lisi_core::model::acquisition::{InboxEventKind, InboxState, NewInboxEntry};
    use lisi_core::model::dictionary::{
        ConfigurationResolver, MatchMode, ResolvedDictionaryConfiguration, TermProvenance,
    };
    use lisi_core::model::{AcquisitionOrigin, NewSession, NewSource, SessionDuration, SourceKind};
    use lisi_core::text::{
        Actor, DisplayName, LanguageTag, SourceIdentifier, TermCategory, TermText,
    };
    use lisi_core::{SessionId, Timestamp};
    use lisi_telegram::{
        ChatId, ConnectorEvent, DeletedMessages, EditedMessage, IncomingMessage, MessageId,
        MockTelegramConnector,
    };

    use super::{
        AcquisitionService, IdempotencyKey, MessagePayload, SessionContext, serialize_payload,
    };
    use crate::sources::open_in_memory_database;

    const CHAT: i64 = -1_001;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn later(seconds: i64) -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000 + seconds * 1_000)
    }

    fn operator() -> Actor {
        let Ok(actor) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        actor
    }

    /// Configurazione con un termine positivo e uno mitigante.
    fn configuration() -> ResolvedDictionaryConfiguration {
        let mut resolver = ConfigurationResolver::new();
        for (text, level) in [("molotov", 3_i8), ("recensione", -2_i8)] {
            let (Ok(text), Ok(category), Ok(language)) = (
                TermText::try_new(text),
                TermCategory::try_new("prova"),
                LanguageTag::try_new("it"),
            ) else {
                panic!("i valori del termine devono essere validi");
            };
            let Ok(()) = resolver.add(
                text,
                category,
                language,
                MatchMode::NormalizedWord,
                level,
                TermProvenance::ad_hoc(),
            ) else {
                panic!("il termine deve essere accettato");
            };
        }
        resolver.finish()
    }

    /// Servizio con una sessione su una fonte, e il suo contesto.
    fn fixture() -> (AcquisitionService, SessionContext) {
        let Ok(mut database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };

        let (Ok(identifier), Ok(title), Ok(label)) = (
            SourceIdentifier::try_new(&CHAT.to_string()),
            DisplayName::try_new("Canale di prova"),
            DisplayName::try_new("Sessione di prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(source_id) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier,
                display_name: title,
                authorized_by: operator(),
                active: true,
            },
            now(),
        ) else {
            panic!("la fonte deve potersi registrare");
        };
        let Ok(session_id) = database.insert_session(
            &NewSession {
                label,
                started_by: operator(),
                duration: SessionDuration::Preset { seconds: 3_600 },
                source_ids: vec![source_id],
            },
            now(),
        ) else {
            panic!("la sessione deve potersi creare");
        };
        let Ok(()) = database.save_resolved_configuration(session_id, &configuration()) else {
            panic!("la configurazione deve potersi salvare");
        };

        let service = AcquisitionService::new(database);
        let Ok(context) = service.load_context(session_id, operator()) else {
            panic!("il contesto deve potersi costruire");
        };
        (service, context)
    }

    fn message(id: i64, text: &str, ts: Timestamp) -> ConnectorEvent {
        let (Ok(chat), Ok(message)) = (ChatId::try_new(CHAT), MessageId::try_new(id)) else {
            panic!("gli identificativi di prova devono essere validi");
        };
        ConnectorEvent::MessageReceived(IncomingMessage {
            chat_id: chat,
            message_id: message,
            author: None,
            // Non e' un messaggio di una persona: nessun identificativo da attribuire.
            author_identifier: None,
            author_username: None,
            text: text.to_owned(),
            published_at_millis: ts.as_millis(),
            url: None,
            attachment: None,
        })
    }

    fn edit(id: i64, text: &str, ts: Timestamp) -> ConnectorEvent {
        let (Ok(chat), Ok(message)) = (ChatId::try_new(CHAT), MessageId::try_new(id)) else {
            panic!("gli identificativi di prova devono essere validi");
        };
        ConnectorEvent::MessageEdited(EditedMessage {
            chat_id: chat,
            message_id: message,
            text: text.to_owned(),
            edited_at_millis: ts.as_millis(),
        })
    }

    fn deletion(ids: &[i64], ts: Timestamp) -> ConnectorEvent {
        let Ok(chat) = ChatId::try_new(CHAT) else {
            panic!("l'identificativo di prova deve essere valido");
        };
        let mut message_ids = Vec::new();
        for id in ids {
            let Ok(message) = MessageId::try_new(*id) else {
                panic!("l'identificativo di prova deve essere valido");
            };
            message_ids.push(message);
        }
        ConnectorEvent::MessagesDeleted(DeletedMessages {
            chat_id: chat,
            message_ids,
            deleted_at_millis: ts.as_millis(),
        })
    }

    fn contents(
        service: &AcquisitionService,
        session: SessionId,
    ) -> Vec<lisi_core::model::Content> {
        let Ok(contents) = service.database().session_contents(session) else {
            panic!("i contenuti devono potersi leggere");
        };
        contents
    }

    // ------------------------------------------------------------ 1, 24

    /// **La stessa chat su due account simulati: ogni aggiornamento va
    /// soltanto al monitoraggio del suo account** (MULTI-ACCOUNT-02 parte 2,
    /// ADR-0173, criterio 3; prova negativa: `accepts_from` che accetta
    /// tutto → rossa).
    ///
    /// Il numero della chat da solo non basta: entrambi i monitoraggi la
    /// seguono, e l'aggiornamento arrivato a B registrato sotto A sarebbe un
    /// contenuto attribuito all'account sbagliato, senza errore.
    #[test]
    fn la_stessa_chat_su_due_account_va_al_monitoraggio_del_suo_account() {
        use lisi_core::model::AccountUuid;

        let (mut service, primo_contesto) = fixture();
        let (account_a, account_b) = (
            AccountUuid::from_bytes([0xa1; 16]),
            AccountUuid::from_bytes([0xb2; 16]),
        );
        let (Ok(nome_a), Ok(nome_b), Ok(etichetta)) = (
            DisplayName::try_new("Ufficio A"),
            DisplayName::try_new("Ufficio B"),
            DisplayName::try_new("Sessione su B"),
        ) else {
            panic!("i nomi di prova devono essere validi");
        };
        let sessione_a = primo_contesto.session_id;
        let fonte = primo_contesto
            .monitored_chats()
            .map(|(_, fonte)| fonte)
            .next();
        let Some(fonte) = fonte else {
            panic!("la sessione di prova segue una fonte");
        };
        let Ok(()) =
            service
                .database()
                .insert_session_account(sessione_a, &account_a, &nome_a, now())
        else {
            panic!("il legame con A si registra");
        };
        let Ok(sessione_b) = service.database_mut().insert_session(
            &NewSession {
                label: etichetta,
                started_by: operator(),
                duration: SessionDuration::Preset { seconds: 3_600 },
                source_ids: vec![fonte],
            },
            now(),
        ) else {
            panic!("la seconda sessione si crea sulla stessa fonte");
        };
        let Ok(()) =
            service
                .database()
                .insert_session_account(sessione_b, &account_b, &nome_b, now())
        else {
            panic!("il legame con B si registra");
        };
        let (Ok(contesto_a), Ok(contesto_b)) = (
            service.load_context(sessione_a, operator()),
            service.load_context(sessione_b, operator()),
        ) else {
            panic!("i contesti si caricano");
        };
        assert_eq!(contesto_a.account(), Some(&account_a));

        // Lo stesso messaggio della stessa chat, arrivato all'account B.
        let evento = message(7, "una molotov", now());
        for contesto in [&contesto_a, &contesto_b] {
            if contesto.accepts_from(&account_b, 2) {
                let Ok(_) = service.ingest(&evento, contesto, later(1)) else {
                    panic!("l'ingestione deve riuscire");
                };
            }
        }
        assert_eq!(contents(&service, sessione_b).len(), 1, "B lo riceve");
        assert!(
            contents(&service, sessione_a).is_empty(),
            "il monitoraggio di A non riceve ciò che è arrivato a B"
        );
    }

    /// **Lo stesso messaggio arrivato a due account che seguono la stessa chat:
    /// un contenuto per monitoraggio, e nessun doppione se un account lo
    /// consegna di nuovo** (MULTI-ACCOUNT-02 parte 2, DEC-441). Prova
    /// negativa: la chiave d'idempotenza senza il monitoraggio → il secondo
    /// monitoraggio perde il messaggio, rossa; senza chiave → doppione, rossa.
    #[test]
    fn lo_stesso_messaggio_su_due_account_non_si_perde_e_non_si_duplica() {
        use lisi_core::model::AccountUuid;

        let (mut service, primo_contesto) = fixture();
        let (account_a, account_b) = (
            AccountUuid::from_bytes([0xa1; 16]),
            AccountUuid::from_bytes([0xb2; 16]),
        );
        let (Ok(nome_a), Ok(nome_b), Ok(etichetta)) = (
            DisplayName::try_new("Ufficio A"),
            DisplayName::try_new("Ufficio B"),
            DisplayName::try_new("Sessione su B"),
        ) else {
            panic!("i nomi di prova devono essere validi");
        };
        let sessione_a = primo_contesto.session_id;
        let Some(fonte) = primo_contesto
            .monitored_chats()
            .map(|(_, fonte)| fonte)
            .next()
        else {
            panic!("la sessione di prova segue una fonte");
        };
        let Ok(()) =
            service
                .database()
                .insert_session_account(sessione_a, &account_a, &nome_a, now())
        else {
            panic!("il legame con A si registra");
        };
        let Ok(sessione_b) = service.database_mut().insert_session(
            &NewSession {
                label: etichetta,
                started_by: operator(),
                duration: SessionDuration::Preset { seconds: 3_600 },
                source_ids: vec![fonte],
            },
            now(),
        ) else {
            panic!("la seconda sessione si crea sulla stessa fonte");
        };
        let Ok(()) =
            service
                .database()
                .insert_session_account(sessione_b, &account_b, &nome_b, now())
        else {
            panic!("il legame con B si registra");
        };
        let (Ok(contesto_a), Ok(contesto_b)) = (
            service.load_context(sessione_a, operator()),
            service.load_context(sessione_b, operator()),
        ) else {
            panic!("i contesti si caricano");
        };

        // Il messaggio arriva a A, poi a B, poi di nuovo a A (TDLib può
        // consegnare due volte lo stesso aggiornamento).
        let evento = message(7, "una molotov", now());
        for (origine, quando) in [(&account_a, 1), (&account_b, 2), (&account_a, 3)] {
            for contesto in [&contesto_a, &contesto_b] {
                if contesto.accepts_from(origine, 2) {
                    let Ok(_) = service.ingest(&evento, contesto, later(quando)) else {
                        panic!("l'ingestione deve riuscire");
                    };
                }
            }
        }
        assert_eq!(
            contents(&service, sessione_a).len(),
            1,
            "A lo ha una volta, anche se gli è arrivato due volte"
        );
        assert_eq!(
            contents(&service, sessione_b).len(),
            1,
            "B lo ha anche se A lo aveva già: ogni monitoraggio ha il suo"
        );
    }

    #[test]
    fn a_new_message_is_acquired_and_analysed() {
        let (mut service, context) = fixture();
        let Ok(report) = service.ingest(&message(1, "una molotov", now()), &context, later(1))
        else {
            panic!("l'ingestione deve riuscire");
        };

        assert_eq!(report.enqueued, 1);
        assert_eq!(report.applied, 1);

        let recorded = contents(&service, context.session_id);
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            recorded[0].analysis_level.get(),
            3,
            "il livello viene dal motore"
        );
    }

    /// **L'allegato si descrive accanto al contenuto, e non si scarica**
    /// (ATTACH-01, ADR-0177): la descrizione passa dalla coda e arriva
    /// nell'archivio; una voce di coda scritta prima, senza il campo, si legge
    /// ancora, senza allegato.
    #[test]
    fn l_allegato_si_descrive_accanto_al_contenuto() {
        let (mut service, context) = fixture();
        let ConnectorEvent::MessageReceived(mut con_allegato) = message(1, "guarda qui", now())
        else {
            panic!("il messaggio di prova è un messaggio");
        };
        con_allegato.attachment = Some(Box::new(lisi_telegram::AttachmentDescriptor {
            kind: lisi_telegram::AttachmentKind::Document,
            declared_name: Some(String::from("rapporto.pdf")),
            declared_size: Some(73_728),
            declared_mime: Some(String::from("application/pdf")),
        }));
        let evento = ConnectorEvent::MessageReceived(con_allegato);
        let Ok(report) = service.ingest(&evento, &context, later(1)) else {
            panic!("l'ingestione deve riuscire");
        };
        assert_eq!(report.applied, 1);
        let recorded = contents(&service, context.session_id);
        let Ok(Some(allegato)) = service.database().content_attachment(recorded[0].id) else {
            panic!("la descrizione dell'allegato deve esserci");
        };
        assert_eq!(allegato.kind, "documento");
        assert_eq!(allegato.declared_name.as_deref(), Some("rapporto.pdf"));
        assert_eq!(allegato.declared_size, Some(73_728));

        // Lo stesso evento riconsegnato non cambia niente.
        let Ok(_) = service.ingest(&evento, &context, later(2)) else {
            panic!("la riconsegna non è un errore");
        };
        assert_eq!(contents(&service, context.session_id).len(), 1);

        let Ok(vecchia) = super::deserialize_payload(
            r#"{"text":"di prima","timestamp_millis":5,"origin":"osservato"}"#,
        ) else {
            panic!("una voce di coda scritta prima deve leggersi");
        };
        assert_eq!(vecchia.attachment, None);
    }

    /// Messaggio grezzo, come lo consegna il recupero della cronologia.
    fn recovered_message(id: i64, text: &str, ts: Timestamp) -> IncomingMessage {
        let (Ok(chat), Ok(message)) = (ChatId::try_new(CHAT), MessageId::try_new(id)) else {
            panic!("gli identificativi di prova devono essere validi");
        };
        IncomingMessage {
            chat_id: chat,
            message_id: message,
            author: None,
            author_identifier: None,
            author_username: None,
            text: text.to_owned(),
            published_at_millis: ts.as_millis(),
            url: None,
            attachment: None,
        }
    }

    #[test]
    fn what_is_recovered_is_recorded_as_recovered() {
        let (mut service, context) = fixture();
        let Ok(report) = service.ingest_recovered(
            &[recovered_message(1, "una molotov", now())],
            &context,
            later(1),
        ) else {
            panic!("il recupero deve riuscire");
        };

        assert_eq!(report.enqueued, 1);
        assert_eq!(report.applied, 1);

        let recorded = contents(&service, context.session_id);
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            recorded[0].origin,
            AcquisitionOrigin::Recovered,
            "l'archivio non deve affermare di aver osservato cio' che ha ritrovato"
        );
        // L'analisi non cambia: il motore giudica il testo, non il modo in cui
        // e' arrivato. Se cambiasse, i due percorsi non sarebbero confrontabili.
        assert_eq!(recorded[0].analysis_level.get(), 3);
    }

    #[test]
    fn a_message_already_observed_does_not_become_recovered() {
        // La prima verita' e' la piu' forte: «l'ho visto arrivare». Un recupero
        // che passasse sopra la sostituirebbe con la piu' debole, e l'archivio
        // affermerebbe **meno** di quanto sa.
        let (mut service, context) = fixture();
        let Ok(_) = service.ingest(&message(1, "una molotov", now()), &context, later(1)) else {
            panic!("l'ingestione dal vivo deve riuscire");
        };

        let Ok(_) = service.ingest_recovered(
            &[recovered_message(1, "una molotov", now())],
            &context,
            later(2),
        ) else {
            panic!("il recupero deve riuscire anche su cio' che c'e' gia'");
        };

        let recorded = contents(&service, context.session_id);
        assert_eq!(recorded.len(), 1, "nessun duplicato");
        assert_eq!(
            recorded[0].origin,
            AcquisitionOrigin::Observed,
            "l'osservazione dal vivo non viene degradata a recupero"
        );
    }

    #[test]
    fn a_content_of_level_zero_is_still_recorded() {
        let (mut service, context) = fixture();
        let Ok(_) = service.ingest(&message(1, "buongiorno a tutti", now()), &context, later(1))
        else {
            panic!("l'ingestione deve riuscire");
        };

        let recorded = contents(&service, context.session_id);
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            recorded[0].analysis_level.get(),
            0,
            "registrato, non scartato"
        );
    }

    // ------------------------------------------------------------ 2, 23

    #[test]
    fn the_same_event_delivered_twice_produces_one_content() {
        let (mut service, context) = fixture();
        let event = message(1, "una molotov", now());

        let Ok(first) = service.ingest(&event, &context, later(1)) else {
            panic!("la prima ingestione deve riuscire");
        };
        let Ok(second) = service.ingest(&event, &context, later(2)) else {
            panic!("la seconda ingestione deve riuscire");
        };

        assert_eq!(first.enqueued, 1);
        assert_eq!(second.enqueued, 0, "il secondo evento e' gia' in inbox");
        assert_eq!(second.duplicates, 1);
        assert_eq!(contents(&service, context.session_id).len(), 1);
    }

    // ------------------------------------------------------------ 3, 4

    #[test]
    fn an_edit_adds_a_version_without_touching_the_original() {
        let (mut service, context) = fixture();
        let Ok(_) = service.ingest(&message(1, "testo iniziale", now()), &context, later(1)) else {
            panic!("l'ingestione deve riuscire");
        };
        let content_id = contents(&service, context.session_id)[0].id;

        let Ok(report) = service.ingest(&edit(1, "testo corretto", later(10)), &context, later(11))
        else {
            panic!("la modifica deve riuscire");
        };
        assert_eq!(report.applied, 1);

        let Ok(versions) = service.database().content_versions(content_id) else {
            panic!("le versioni devono potersi leggere");
        };
        // La storia delle versioni e' completa: l'originale (v1) e la modifica
        // (v2). L'originale e' seminato alla prima modifica.
        assert_eq!(versions.len(), 2);
        assert!(versions[0].is_original());
        assert_eq!(versions[0].body.as_str(), "testo iniziale");
        assert_eq!(versions[1].version_number, 2);
        assert_eq!(versions[1].body.as_str(), "testo corretto");
        // Il corpo originale del contenuto non e' stato toccato.
        assert_eq!(
            contents(&service, context.session_id)[0].body.as_str(),
            "testo iniziale"
        );
    }

    #[test]
    fn multiple_edits_are_numbered_in_sequence() {
        let (mut service, context) = fixture();
        let Ok(_) = service.ingest(&message(1, "v0", now()), &context, later(1)) else {
            panic!("l'ingestione deve riuscire");
        };
        let content_id = contents(&service, context.session_id)[0].id;

        for (index, text) in [(1, "v1"), (2, "v2"), (3, "v3")] {
            let Ok(_) = service.ingest(
                &edit(1, text, later(10 * index)),
                &context,
                later(10 * index + 1),
            ) else {
                panic!("la modifica deve riuscire");
            };
        }

        let Ok(versions) = service.database().content_versions(content_id) else {
            panic!("le versioni devono potersi leggere");
        };
        // Originale (v1) piu' tre modifiche (v2, v3, v4).
        assert_eq!(versions.len(), 4);
        assert!(versions[0].is_original());
        assert_eq!(versions[3].version_number, 4);
        assert_eq!(versions[3].previous_version_id, Some(versions[2].id));
    }

    #[test]
    fn the_same_edit_delivered_twice_adds_one_version() {
        let (mut service, context) = fixture();
        let Ok(_) = service.ingest(&message(1, "v0", now()), &context, later(1)) else {
            panic!("l'ingestione deve riuscire");
        };
        let content_id = contents(&service, context.session_id)[0].id;
        let same = edit(1, "v1", later(10));

        let Ok(_) = service.ingest(&same, &context, later(11)) else {
            panic!("la modifica deve riuscire");
        };
        let Ok(second) = service.ingest(&same, &context, later(12)) else {
            panic!("la seconda consegna deve riuscire");
        };
        assert_eq!(second.duplicates, 1, "stessa modifica, stesso evento");

        let Ok(versions) = service.database().content_versions(content_id) else {
            panic!("le versioni devono potersi leggere");
        };
        // Originale piu' una sola modifica: la seconda consegna e' un duplicato.
        assert_eq!(versions.len(), 2);
    }

    // ------------------------------------------------------------ 5, 6

    #[test]
    fn a_deletion_is_recorded_as_a_neutral_fact() {
        let (mut service, context) = fixture();
        let Ok(_) = service.ingest(&message(1, "una molotov", now()), &context, later(1)) else {
            panic!("l'ingestione deve riuscire");
        };
        let content_id = contents(&service, context.session_id)[0].id;

        let Ok(_) = service.ingest(&deletion(&[1], later(20)), &context, later(21)) else {
            panic!("la cancellazione deve riuscire");
        };

        let Ok(Some(recorded)) = service.database().content_deletion(content_id) else {
            panic!("la cancellazione deve essere registrata");
        };
        assert!(!recorded.is_of_an_unseen_message());
        // Il contenuto originale resta.
        assert_eq!(contents(&service, context.session_id).len(), 1);
    }

    #[test]
    fn a_deletion_of_a_message_never_acquired_is_still_recorded() {
        let (mut service, context) = fixture();

        let Ok(_) = service.ingest(&deletion(&[99], later(5)), &context, later(6)) else {
            panic!("la cancellazione deve riuscire");
        };

        let Ok(deletions) = service.database().session_deletions(context.session_id) else {
            panic!("le cancellazioni devono potersi leggere");
        };
        assert_eq!(deletions.len(), 1);
        assert!(deletions[0].is_of_an_unseen_message());
    }

    #[test]
    fn a_multiple_deletion_becomes_one_fact_per_message() {
        let (mut service, context) = fixture();
        let Ok(report) = service.ingest(&deletion(&[1, 2, 3], later(5)), &context, later(6)) else {
            panic!("la cancellazione deve riuscire");
        };
        assert_eq!(report.enqueued, 3, "tre messaggi, tre eventi nell'inbox");
        assert_eq!(
            service
                .database()
                .session_deletions(context.session_id)
                .map(|all| all.len())
                .ok(),
            Some(3)
        );
    }

    // ------------------------------------------------------------ 7

    #[test]
    fn an_edit_before_the_original_is_deferred_and_resolved_later() {
        let (mut service, context) = fixture();

        // La modifica arriva prima del suo originale: viene rinviata, non persa.
        let Ok(deferred) = service.ingest(&edit(1, "corretto", later(10)), &context, later(11))
        else {
            panic!("la modifica deve accodarsi");
        };
        assert_eq!(deferred.deferred, 1);
        assert_eq!(deferred.applied, 0);

        // Arriva l'originale.
        let Ok(_) = service.ingest(&message(1, "originale", later(12)), &context, later(13)) else {
            panic!("l'originale deve riuscire");
        };

        // Una nuova tornata risolve la modifica rinviata.
        let Ok(resolved) = service.process_pending(&context, later(14)) else {
            panic!("l'elaborazione delle voci in attesa deve riuscire");
        };
        assert_eq!(resolved.applied, 1);

        let content_id = contents(&service, context.session_id)[0].id;
        let Ok(versions) = service.database().content_versions(content_id) else {
            panic!("le versioni devono potersi leggere");
        };
        // Originale piu' la modifica orfana, ora applicata.
        assert_eq!(versions.len(), 2, "la modifica orfana e' stata applicata");
        assert!(versions[0].is_original());
    }

    /// **Una voce «messaggio nuovo» senza istante non diventa un contenuto con
    /// una data inventata** (PR-07): la validazione non la lascia entrare, e se
    /// una voce in coda la portasse comunque, l'applicazione la chiude come
    /// fallita con la sua ragione.
    #[test]
    fn a_queued_new_message_without_an_instant_is_not_given_one() {
        let (mut service, context) = fixture();
        let payload = MessagePayload {
            author: None,
            author_identifier: None,
            author_username: None,
            text: String::from("senza istante"),
            url: None,
            timestamp_millis: None,
            origin: String::from("osservato"),
            attachment: None,
        };
        let Ok(payload_json) = serialize_payload(&payload) else {
            panic!("il payload deve serializzarsi");
        };
        let Some(source_id) = context.sources.get(&CHAT).copied() else {
            panic!("la fonte deve esserci");
        };
        let Ok(outcome) = service.database().enqueue_inbox(&NewInboxEntry {
            session_id: context.session_id,
            source_id: Some(source_id),
            event_kind: InboxEventKind::NewMessage,
            remote_event_id: lisi_core::text::RemoteMessageId::try_new("9").ok(),
            idempotency_key: IdempotencyKey::derive(
                context.session_id,
                Some(source_id),
                InboxEventKind::NewMessage,
                Some("9"),
                None,
            ),
            remote_timestamp: None,
            received_at: now(),
            payload_json: Some(payload_json),
            format_version: 1,
        }) else {
            panic!("l'accodamento deve riuscire");
        };
        let Ok(()) = service.database().mark_inbox_processing(outcome.id()) else {
            panic!("la marcatura deve riuscire");
        };
        let Ok(_) = service.recover(&context, later(1)) else {
            panic!("la ripresa deve riuscire");
        };
        assert!(
            contents(&service, context.session_id).is_empty(),
            "nessun contenuto con una data di pubblicazione inventata"
        );
    }

    // ------------------------------------------------------------ 13, 14, 23

    #[test]
    fn a_crash_during_processing_is_resumed_without_duplication() {
        let (mut service, context) = fixture();

        // Simula un evento scritto nell'inbox e rimasto in elaborazione al
        // momento di un crash: la riga e' in 'processing', non completata.
        let payload = MessagePayload {
            author: None,
            // Non e' un messaggio di una persona: nessun identificativo da attribuire.
            author_identifier: None,
            author_username: None,
            text: String::from("una molotov"),
            url: None,
            timestamp_millis: Some(now().as_millis()),
            origin: String::from("osservato"),
            attachment: None,
        };
        let Ok(payload_json) = serialize_payload(&payload) else {
            panic!("il payload deve serializzarsi");
        };
        let source_id = *context.sources.get(&CHAT).expect("la fonte deve esserci");
        let key = IdempotencyKey::derive(
            context.session_id,
            Some(source_id),
            InboxEventKind::NewMessage,
            Some("1"),
            None,
        );
        let Ok(remote) = lisi_core::text::RemoteMessageId::try_new("1") else {
            panic!("l'identificativo deve essere valido");
        };
        let Ok(outcome) = service.database().enqueue_inbox(&NewInboxEntry {
            session_id: context.session_id,
            source_id: Some(source_id),
            event_kind: InboxEventKind::NewMessage,
            remote_event_id: Some(remote),
            idempotency_key: key,
            remote_timestamp: Some(now()),
            received_at: now(),
            payload_json: Some(payload_json),
            format_version: 1,
        }) else {
            panic!("l'accodamento deve riuscire");
        };
        let Ok(()) = service.database().mark_inbox_processing(outcome.id()) else {
            panic!("la marcatura deve riuscire");
        };

        // Il recupero riprende la voce e la applica.
        let Ok(first) = service.recover(&context, later(1)) else {
            panic!("il recupero deve riuscire");
        };
        assert_eq!(first.resumed, 1);
        assert_eq!(first.completed, 1);
        assert_eq!(contents(&service, context.session_id).len(), 1);

        // Un secondo recupero non trova nulla in sospeso e non duplica.
        let Ok(second) = service.recover(&context, later(2)) else {
            panic!("il secondo recupero deve riuscire");
        };
        assert_eq!(second.resumed, 0);
        assert_eq!(contents(&service, context.session_id).len(), 1);

        // Il recupero e' registrato nell'audit.
        let Ok(audit) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert!(
            audit
                .iter()
                .any(|entry| entry.action.as_str() == "acquisizione_ripresa")
        );
    }

    // ------------------------------------------------------------ 15, 18, 16

    #[test]
    fn an_oversized_message_is_quarantined_not_recorded() {
        let (mut service, context) = fixture();
        let huge = "a".repeat(70_000); // oltre il limite del corpo

        let Ok(report) = service.ingest(&message(1, &huge, now()), &context, later(1)) else {
            panic!("l'ingestione deve riuscire senza cadere");
        };
        assert_eq!(report.discarded, 1);
        assert_eq!(report.applied, 0);
        assert_eq!(contents(&service, context.session_id).len(), 0);
    }

    #[test]
    fn a_message_with_a_timestamp_before_the_epoch_is_quarantined() {
        let (mut service, context) = fixture();
        let event = message(1, "testo", Timestamp::from_millis(-1));

        let Ok(report) = service.ingest(&event, &context, later(1)) else {
            panic!("l'ingestione deve riuscire senza cadere");
        };
        assert_eq!(report.discarded, 1);
        assert_eq!(contents(&service, context.session_id).len(), 0);
    }

    #[test]
    fn a_hostile_url_is_dropped_and_the_content_is_kept() {
        let (mut service, context) = fixture();
        let (Ok(chat), Ok(message_id)) = (ChatId::try_new(CHAT), MessageId::try_new(1)) else {
            panic!("gli identificativi devono essere validi");
        };
        let event = ConnectorEvent::MessageReceived(IncomingMessage {
            chat_id: chat,
            message_id,
            author: None,
            // Non e' un messaggio di una persona: nessun identificativo da attribuire.
            author_identifier: None,
            author_username: None,
            text: String::from("una molotov"),
            published_at_millis: now().as_millis(),
            url: Some(String::from("javascript:alert(1)")),
            attachment: None,
        });

        let Ok(report) = service.ingest(&event, &context, later(1)) else {
            panic!("l'ingestione deve riuscire");
        };
        assert_eq!(report.applied, 1, "il contenuto e' conservato");

        let recorded = contents(&service, context.session_id);
        assert_eq!(recorded.len(), 1);
        assert!(
            recorded[0].url.is_none(),
            "l'URL ostile non e' stato conservato"
        );
    }

    // ------------------------------------------------------------ fonte non nella sessione

    #[test]
    fn a_message_from_an_unmonitored_chat_is_quarantined() {
        let (mut service, context) = fixture();
        let (Ok(chat), Ok(message_id)) = (ChatId::try_new(-9_999), MessageId::try_new(1)) else {
            panic!("gli identificativi devono essere validi");
        };
        let event = ConnectorEvent::MessageReceived(IncomingMessage {
            chat_id: chat,
            message_id,
            author: None,
            // Non e' un messaggio di una persona: nessun identificativo da attribuire.
            author_identifier: None,
            author_username: None,
            text: String::from("una molotov"),
            published_at_millis: now().as_millis(),
            url: None,
            attachment: None,
        });

        let Ok(report) = service.ingest(&event, &context, later(1)) else {
            panic!("l'ingestione deve riuscire");
        };
        assert_eq!(report.discarded, 1);
        assert_eq!(contents(&service, context.session_id).len(), 0);
    }

    // ------------------------------------------------------------ 27 + operativi

    #[test]
    fn an_operational_event_is_recorded_without_a_content() {
        let (mut service, context) = fixture();
        let event = ConnectorEvent::Connection(lisi_telegram::ConnectionState::Interrupted);

        let Ok(report) = service.ingest(&event, &context, later(1)) else {
            panic!("l'ingestione deve riuscire");
        };
        assert_eq!(report.enqueued, 1);
        assert_eq!(report.applied, 1);
        assert_eq!(contents(&service, context.session_id).len(), 0);
    }

    // ------------------------------------------------------------ 10, 11 (per fonte)

    #[test]
    fn one_failing_source_does_not_stop_the_others() {
        let (mut service, context) = fixture();

        // Un errore su una fonte e' un evento operativo: non interrompe
        // l'acquisizione dai messaggi che seguono.
        let error = ConnectorEvent::Failure(lisi_telegram::TelegramError::Closed);
        let Ok(_) = service.ingest(&error, &context, later(1)) else {
            panic!("l'evento d'errore deve accodarsi");
        };
        let Ok(report) = service.ingest(&message(1, "una molotov", later(2)), &context, later(3))
        else {
            panic!("il messaggio successivo deve essere acquisito");
        };
        assert_eq!(report.applied, 1);
        assert_eq!(contents(&service, context.session_id).len(), 1);
    }

    // ------------------------------------------------------------ 15 integrazione mock

    #[test]
    fn the_runtime_drains_a_deterministic_sequence_from_the_mock() {
        let (mut service, context) = fixture();
        let mut connector = MockTelegramConnector::new();

        let (Ok(()), Ok(()), Ok(())) = (
            connector.enqueue_message(CHAT, 1, "una molotov", now().as_millis()),
            connector.enqueue_message(CHAT, 2, "buongiorno", later(1).as_millis()),
            connector.enqueue_edit(CHAT, 1, "una molotov corretta", later(2).as_millis()),
        ) else {
            panic!("la sequenza deve accodarsi nel mock");
        };

        let Ok(report) = service.drain(&mut connector, &context, later(3), 100) else {
            panic!("il drenaggio deve riuscire");
        };

        assert_eq!(report.enqueued, 3);
        assert_eq!(report.applied, 3);

        let recorded = contents(&service, context.session_id);
        assert_eq!(
            recorded.len(),
            2,
            "due messaggi, la modifica non e' un contenuto"
        );

        let molotov = recorded
            .iter()
            .find(|content| content.remote_message_id.as_str() == "1")
            .expect("il primo messaggio deve esserci");
        let Ok(versions) = service.database().content_versions(molotov.id) else {
            panic!("le versioni devono potersi leggere");
        };
        // Originale piu' la modifica.
        assert_eq!(versions.len(), 2, "originale e modifica");
    }

    // ------------------------------------------------------------ 30 checkpoint

    #[test]
    fn the_checkpoint_advances_with_each_completed_event() {
        let (mut service, context) = fixture();
        let Ok(_) = service.ingest(&message(1, "una molotov", now()), &context, later(1)) else {
            panic!("l'ingestione deve riuscire");
        };

        let Ok(Some((inbox_id, _))) = service.database().session_checkpoint(context.session_id)
        else {
            panic!("il checkpoint deve essere fissato");
        };
        let Ok(entry) = service.database().inbox_entry(inbox_id) else {
            panic!("la voce del checkpoint deve potersi leggere");
        };
        assert_eq!(entry.state, InboxState::Completed);
    }

    /// **Soltanto una modifica ritrovata da un recupero può mancare
    /// dell'istante** (PR-07): un messaggio nuovo, o una modifica osservata dal
    /// vivo, senza istante restano eventi non validi.
    #[test]
    fn only_a_recovered_edit_may_lack_its_instant() {
        let fatto = |kind, origin| super::Fact {
            kind,
            chat_id: Some(CHAT),
            message_id: Some(1),
            remote_ts_millis: None,
            author: None,
            author_identifier: None,
            author_username: None,
            text: Some(String::from("testo")),
            url: None,
            origin,
            attachment: None,
        };
        let fonte = Some(lisi_core::SourceId::new(1));
        let casi = [
            (
                InboxEventKind::EditedMessage,
                AcquisitionOrigin::Recovered,
                true,
            ),
            (
                InboxEventKind::EditedMessage,
                AcquisitionOrigin::Observed,
                false,
            ),
            (
                InboxEventKind::NewMessage,
                AcquisitionOrigin::Recovered,
                false,
            ),
            (
                InboxEventKind::NewMessage,
                AcquisitionOrigin::Observed,
                false,
            ),
        ];
        for (kind, origin, ammesso) in casi {
            let esito = super::validate(&fatto(kind, origin), fonte);
            match esito {
                super::Validation::Valid(payload) => {
                    assert!(ammesso, "{kind:?}/{origin:?} non doveva passare");
                    assert_eq!(payload.timestamp_millis, None, "nessuna ora inventata");
                }
                super::Validation::Rejected(ragione) => {
                    assert!(!ammesso, "{kind:?}/{origin:?} doveva passare");
                    assert_eq!(ragione, super::reason::TIMESTAMP_INVALID);
                }
                super::Validation::None => panic!("un fatto con contenuto si valida"),
            }
        }
    }

    // ------------------------------------------------------------ 25/26 nessun panico, nessun segreto

    #[test]
    fn a_quarantine_reason_is_a_product_constant_not_remote_text() {
        let (mut service, context) = fixture();
        let secret_looking = format!("token-{}", "x".repeat(70_000));
        let Ok(_) = service.ingest(&message(1, &secret_looking, now()), &context, later(1)) else {
            panic!("l'ingestione non deve cadere su input ostile");
        };

        // La voce in quarantena porta una ragione costante, non il testo remoto.
        let Ok(pending_or_done) = service.database().inbox_pending(context.session_id) else {
            panic!("la lettura deve riuscire");
        };
        // La quarantena non e' "pending": la cerco fra tutte via il conteggio
        // aperto, che deve essere zero, e verifico che nessun contenuto sia
        // stato scritto.
        assert!(pending_or_done.is_empty());
        assert_eq!(contents(&service, context.session_id).len(), 0);
    }

    #[test]
    fn the_payload_debug_does_not_leak_into_the_error_kind() {
        // Un contenuto quarantenato non porta il proprio testo nel campo
        // d'errore: quel campo e' una costante del prodotto.
        for constant in [
            super::reason::BODY_INVALID,
            super::reason::TIMESTAMP_INVALID,
            super::reason::SOURCE_NOT_MONITORED,
        ] {
            assert!(!constant.contains(' '), "una classe d'errore e' una parola");
            assert!(constant.is_ascii());
        }
    }

    // ---------------- regressioni della revisione di sicurezza ----------------

    #[test]
    fn a_resumed_edit_does_not_add_a_second_version() {
        // Il difetto ALTA della revisione: un crash fra l'aggiunta della
        // versione e la conclusione della voce lasciava la voce in
        // elaborazione, e la ripresa aggiungeva una seconda versione identica.
        let (mut service, context) = fixture();
        let Ok(_) = service.ingest(&message(1, "originale", now()), &context, later(1)) else {
            panic!("l'ingestione deve riuscire");
        };
        let Ok(_) = service.ingest(&edit(1, "modificato", later(10)), &context, later(11)) else {
            panic!("la modifica deve riuscire");
        };
        let content_id = contents(&service, context.session_id)[0].id;
        assert_eq!(
            service
                .database()
                .content_versions(content_id)
                .map(|v| v.len())
                .ok(),
            Some(2)
        );

        // L'ultima voce completata e' la modifica: la si riporta in
        // elaborazione, come dopo un crash, e si esegue il recupero.
        let Ok(Some((edit_inbox_id, _))) =
            service.database().session_checkpoint(context.session_id)
        else {
            panic!("il checkpoint deve esistere");
        };
        let Ok(entry) = service.database().inbox_entry(edit_inbox_id) else {
            panic!("la voce deve potersi leggere");
        };
        assert_eq!(entry.event_kind, InboxEventKind::EditedMessage);
        let Ok(()) = service.database().mark_inbox_processing(edit_inbox_id) else {
            panic!("la marcatura deve riuscire");
        };

        let Ok(report) = service.recover(&context, later(20)) else {
            panic!("il recupero deve riuscire");
        };
        assert_eq!(report.resumed, 1);
        assert_eq!(
            service
                .database()
                .content_versions(content_id)
                .map(|v| v.len())
                .ok(),
            Some(2),
            "la modifica ripresa non aggiunge una seconda versione"
        );
    }

    #[test]
    fn a_resumed_deletion_does_not_add_a_second_deletion() {
        // Il difetto MEDIA della revisione, stessa radice del precedente.
        let (mut service, context) = fixture();
        let Ok(_) = service.ingest(&message(1, "una molotov", now()), &context, later(1)) else {
            panic!("l'ingestione deve riuscire");
        };
        let Ok(_) = service.ingest(&deletion(&[1], later(10)), &context, later(11)) else {
            panic!("la cancellazione deve riuscire");
        };
        assert_eq!(
            service
                .database()
                .session_deletions(context.session_id)
                .map(|d| d.len())
                .ok(),
            Some(1)
        );

        let Ok(Some((deletion_inbox_id, _))) =
            service.database().session_checkpoint(context.session_id)
        else {
            panic!("il checkpoint deve esistere");
        };
        let Ok(()) = service.database().mark_inbox_processing(deletion_inbox_id) else {
            panic!("la marcatura deve riuscire");
        };

        let Ok(_) = service.recover(&context, later(20)) else {
            panic!("il recupero deve riuscire");
        };
        assert_eq!(
            service
                .database()
                .session_deletions(context.session_id)
                .map(|d| d.len())
                .ok(),
            Some(1),
            "la cancellazione ripresa non si duplica"
        );
    }

    #[test]
    fn a_resumed_new_message_regains_its_matches_and_alert() {
        // Il difetto MEDIA #3: un crash fra il contenuto e i suoi riscontri
        // lasciava, dopo la ripresa, un contenuto di livello alto senza alert e
        // senza riscontri, perche' il ramo «gia' acquisito» li saltava.
        use lisi_core::model::{AcquisitionOrigin, AnalysisLevel, NewContent};
        use lisi_core::text::RemoteMessageId;

        let (mut service, context) = fixture();
        let source_id = *context.sources.get(&CHAT).expect("la fonte deve esserci");

        // Stato dopo un crash: il contenuto c'e', i riscontri e l'alert no.
        let (Ok(remote), Ok(body)) = (
            RemoteMessageId::try_new("1"),
            lisi_core::text::ContentBody::try_new("una molotov"),
        ) else {
            panic!("i valori devono essere validi");
        };
        let (Ok(level),) = (AnalysisLevel::try_new(3),) else {
            panic!("il livello deve essere valido");
        };
        let Ok(insertion) = service.database_mut().insert_content(&NewContent {
            session_id: context.session_id,
            source_id,
            remote_message_id: remote,
            author: None,
            author_identifier: None,
            author_username: None,
            body,
            url: None,
            published_at: now(),
            acquired_at: now(),
            origin: AcquisitionOrigin::Observed,
            analysis_level: level,
        }) else {
            panic!("il contenuto deve potersi inserire");
        };
        let content_id = insertion.content_id();
        assert!(
            service
                .database()
                .content_matches(content_id)
                .map(|m| m.is_empty())
                .ok()
                == Some(true)
        );
        assert!(
            service
                .database()
                .content_alert(content_id)
                .map(|a| a.is_none())
                .ok()
                == Some(true)
        );

        // Una voce d'inbox per lo stesso messaggio, rimasta in elaborazione.
        let payload = MessagePayload {
            author: None,
            // Non e' un messaggio di una persona: nessun identificativo da attribuire.
            author_identifier: None,
            author_username: None,
            text: String::from("una molotov"),
            url: None,
            timestamp_millis: Some(now().as_millis()),
            origin: String::from("osservato"),
            attachment: None,
        };
        let Ok(payload_json) = serialize_payload(&payload) else {
            panic!("il payload deve serializzarsi");
        };
        let Ok(remote2) = RemoteMessageId::try_new("1") else {
            panic!("l'identificativo deve essere valido");
        };
        let key = IdempotencyKey::derive(
            context.session_id,
            Some(source_id),
            InboxEventKind::NewMessage,
            Some("1"),
            None,
        );
        let Ok(outcome) = service.database().enqueue_inbox(&NewInboxEntry {
            session_id: context.session_id,
            source_id: Some(source_id),
            event_kind: InboxEventKind::NewMessage,
            remote_event_id: Some(remote2),
            idempotency_key: key,
            remote_timestamp: Some(now()),
            received_at: now(),
            payload_json: Some(payload_json),
            format_version: 1,
        }) else {
            panic!("l'accodamento deve riuscire");
        };
        let Ok(()) = service.database().mark_inbox_processing(outcome.id()) else {
            panic!("la marcatura deve riuscire");
        };

        // Il recupero completa il contenuto: riscontri e alert tornano.
        let Ok(_) = service.recover(&context, later(1)) else {
            panic!("il recupero deve riuscire");
        };
        assert!(
            service
                .database()
                .content_matches(content_id)
                .map(|m| !m.is_empty())
                .ok()
                == Some(true),
            "il recupero ha ripristinato i riscontri"
        );
        assert!(
            service
                .database()
                .content_alert(content_id)
                .map(|a| a.is_some())
                .ok()
                == Some(true),
            "il recupero ha ripristinato l'alert"
        );
    }

    #[test]
    fn two_distinct_edits_with_the_same_timestamp_are_two_versions() {
        // Il difetto BASSA #5: con il solo istante come discriminante, due
        // modifiche diverse nello stesso istante collidevano e la seconda si
        // perdeva. L'impronta del corpo le distingue.
        let (mut service, context) = fixture();
        let Ok(_) = service.ingest(&message(1, "originale", now()), &context, later(1)) else {
            panic!("l'ingestione deve riuscire");
        };
        let content_id = contents(&service, context.session_id)[0].id;

        let same_instant = later(10);
        let Ok(first) = service.ingest(
            &edit(1, "prima correzione", same_instant),
            &context,
            later(11),
        ) else {
            panic!("la prima modifica deve riuscire");
        };
        let Ok(second) = service.ingest(
            &edit(1, "seconda correzione", same_instant),
            &context,
            later(12),
        ) else {
            panic!("la seconda modifica deve riuscire");
        };

        assert_eq!(first.applied, 1);
        assert_eq!(second.applied, 1, "la seconda modifica non e' un duplicato");
        // Originale piu' due modifiche distinte.
        assert_eq!(
            service
                .database()
                .content_versions(content_id)
                .map(|v| v.len())
                .ok(),
            Some(3)
        );
    }
}

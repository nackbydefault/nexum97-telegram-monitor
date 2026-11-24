//! L'Esercitazione: l'insieme di dati sintetico e il ricominciare (PR-13,
//! ADR-0129).
//!
//! # Tutto inventato, e lo dice
//!
//! L'insieme [`DATASET_VERSION`] è costruito apposta: fonti, autori, persone,
//! messaggi e ricerche **non esistono**. Ogni identificativo ha una forma che
//! dice di essere di esercitazione — chat in un intervallo riservato, nomi che
//! contengono «esercitazione», indirizzi su domini `.invalid` (RFC 2606),
//! indirizzi IP dei blocchi di documentazione (RFC 5737), numeri di telefono
//! nel formato di prova di Telegram — e una prova ispeziona l'insieme e fallisce
//! su ciò che non ha quella forma.
//!
//! # Esercita tutto
//!
//! Una cronologia di tre giorni su quattro fonti: contenuti **dal vivo**,
//! **recuperati** per un intervallo e di modo **non determinabile**; un
//! collegamento perso che lascia un periodo non coperto; un grappolo di segnali
//! informatici; tre persone, una delle quali collegata a un'identità trovata; i
//! **cinque** esiti della ricerca puntuale; un workspace pronto per il pacchetto
//! di evidenze; revisioni, una nota e un guasto, perché il passaggio di
//! consegne abbia di che parlare.
//!
//! # Soltanto in Esercitazione
//!
//! Caricare l'insieme e ricominciare vogliono il testimone dell'esercitazione
//! ([`ExerciseMode`]): in un processo operativo non si chiamano. L'insieme si
//! carica soltanto in un archivio **vuoto**, e il ricominciare tocca soltanto i
//! file dell'archivio di esercitazione, mai una cartella che coincida con quella
//! operativa o la contenga.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use lisi_core::model::dictionary::{ConfigurationResolver, MatchMode, TermProvenance};
use lisi_core::model::identity_resolution::{
    ResolutionInputKind, ResolutionOutcome, ResolvedIdentity,
};
use lisi_core::model::note::NewOperatorNote;
use lisi_core::model::person::NewPerson;
use lisi_core::model::reason::OperationalReason;
use lisi_core::model::reference::{ArchiveRef, ArchiveRefKind};
use lisi_core::model::run_mode::{RunMode, data_root_in, directories_overlap};
use lisi_core::model::source_health::HealthCheckOutcome;
use lisi_core::model::workspace::NewWorkspace;
use lisi_core::model::{
    FaultKind, NewAuditEntry, NewFault, NewSession, NewSource, ReviewState, SessionDuration,
    SessionState, SourceKind,
};
use lisi_core::text::{
    Actor, AuditAction, AuditDetail, AuditEntity, DisplayName, FaultMessage, LanguageTag, Note,
    SourceIdentifier, TermCategory, TermText,
};
use lisi_core::{ContentId, IdentityResolutionId, SessionId, SourceId, Timestamp};
use lisi_storage::Database;
use lisi_storage::repository::recovery_operation::NewRecoveryOperation;
use lisi_storage::repository::source_health::NewHealthCheck;
use lisi_telegram::{ChatId, ConnectionState, ConnectorEvent, IncomingMessage, MessageId};

use crate::acquisition::AcquisitionService;
use crate::error::{ServiceError, ServiceResult};
use crate::identity_link::IdentityLinkService;
use crate::identity_resolver::{ResolutionRequest, record_exercise};
use crate::note::NoteService;
use crate::person::PersonService;
use crate::review::ReviewService;
use crate::run_mode::ExerciseMode;
use crate::workspace::WorkspaceService;

/// La versione dell'insieme di dati. Cambia quando cambia l'insieme.
pub const DATASET_VERSION: &str = "esercitazione-v1";

/// Chi agisce nell'insieme: il formatore, non una persona vera.
pub const TRAINER: &str = "formatore.esercitazione";

/// Il file che chiede di ricominciare al prossimo avvio.
pub const RESTART_MARKER: &str = ".ricomincia-esercitazione";

/// L'archivio dell'esercitazione e i suoi due file di giornale.
const ARCHIVE_FILES: [&str; 3] = ["monitor.sqlite", "monitor.sqlite-wal", "monitor.sqlite-shm"];

/// L'inizio dell'intervallo riservato agli identificativi di chat sintetici.
pub const SYNTHETIC_CHAT_BASE: i64 = -1_009_990_000_000;

/// Una fonte sintetica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyntheticSource {
    /// L'identificativo di chat, nell'intervallo riservato.
    pub chat_id: i64,
    /// Il nome, che dice di essere di esercitazione.
    pub name: &'static str,
    /// Il genere.
    pub kind: SourceKind,
}

/// Le quattro fonti.
pub const SOURCES: [SyntheticSource; 4] = [
    SyntheticSource {
        chat_id: SYNTHETIC_CHAT_BASE - 1,
        name: "Canale di esercitazione Alfa",
        kind: SourceKind::Channel,
    },
    SyntheticSource {
        chat_id: SYNTHETIC_CHAT_BASE - 2,
        name: "Gruppo di esercitazione Beta",
        kind: SourceKind::Group,
    },
    SyntheticSource {
        chat_id: SYNTHETIC_CHAT_BASE - 3,
        name: "Canale di esercitazione Gamma",
        kind: SourceKind::Channel,
    },
    SyntheticSource {
        chat_id: SYNTHETIC_CHAT_BASE - 4,
        name: "Canale di esercitazione Delta",
        kind: SourceKind::Channel,
    },
];

/// Un autore sintetico.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyntheticAuthor {
    /// Il nome mostrato.
    pub name: &'static str,
    /// L'identificativo numerico, nell'intervallo riservato.
    pub identifier: &'static str,
    /// Il nome utente, che comincia con «esercitazione_».
    pub username: &'static str,
}

/// I tre autori.
pub const AUTHORS: [SyntheticAuthor; 3] = [
    SyntheticAuthor {
        name: "Utente di esercitazione Uno",
        identifier: "990001",
        username: "esercitazione_utente_uno",
    },
    SyntheticAuthor {
        name: "Utente di esercitazione Due",
        identifier: "990002",
        username: "esercitazione_utente_due",
    },
    SyntheticAuthor {
        name: "Utente di esercitazione Tre",
        identifier: "990003",
        username: "esercitazione_utente_tre",
    },
];

/// Come un messaggio entra nell'archivio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arrival {
    /// Dal vivo, mentre il monitoraggio ascoltava.
    Live,
    /// Recuperato dopo, con il recupero del periodo scoperto.
    Recovered,
    /// Ricevuto dal vivo ma pubblicato prima dell'avvio: il modo non è
    /// determinabile.
    BeforeStart,
}

/// Un messaggio sintetico. Gli istanti sono in minuti dall'avvio del
/// monitoraggio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyntheticMessage {
    /// Quale fonte, per posizione in [`SOURCES`].
    pub source: usize,
    /// L'identificativo del messaggio nella fonte.
    pub id: i64,
    /// Quale autore, per posizione in [`AUTHORS`], se c'è.
    pub author: Option<usize>,
    /// Quando è stato pubblicato.
    pub published: i64,
    /// Quando è arrivato, per i messaggi dal vivo e prima dell'avvio.
    pub received: i64,
    /// Come entra.
    pub arrival: Arrival,
    /// Il testo, inventato.
    pub text: &'static str,
}

/// I minuti di un'ora.
const H: i64 = 60;

/// Il collegamento si perde a quest'ora dall'avvio, e torna dopo quattordici ore.
pub const CONNECTION_LOST_AT: i64 = 30 * H;
/// Il collegamento torna.
pub const CONNECTION_BACK_AT: i64 = 44 * H;
/// Il recupero del periodo scoperto.
pub const RECOVERY_AT: i64 = 46 * H;
/// Da quanto dura la cronologia, fino al caricamento.
pub const TIMELINE_HOURS: i64 = 72;

/// I messaggi.
pub const MESSAGES: [SyntheticMessage; 16] = [
    SyntheticMessage {
        source: 0,
        id: 101,
        author: None,
        published: -3 * H,
        received: 20,
        arrival: Arrival::BeforeStart,
        text: "Esercitazione: annuncio pubblicato prima dell'avvio del monitoraggio, per un \
               corteo nel quartiere di prova.",
    },
    SyntheticMessage {
        source: 0,
        id: 102,
        author: None,
        published: 2 * H,
        received: 2 * H + 1,
        arrival: Arrival::Live,
        text: "Esercitazione: confermato il corteo di sabato nella piazza di prova.",
    },
    SyntheticMessage {
        source: 1,
        id: 201,
        author: Some(0),
        published: 4 * H,
        received: 4 * H + 1,
        arrival: Arrival::Live,
        text: "Esercitazione: chi viene al presidio porti acqua, il percorso è quello di prova.",
    },
    SyntheticMessage {
        source: 1,
        id: 202,
        author: Some(1),
        published: 9 * H,
        received: 9 * H + 1,
        arrival: Arrival::Live,
        text: "Esercitazione: messaggio senza termini del dizionario, sul meteo di domani.",
    },
    SyntheticMessage {
        source: 2,
        id: 301,
        author: None,
        published: 12 * H,
        received: 12 * H + 1,
        arrival: Arrival::Live,
        text: "Esercitazione: campagna di phishing in corso, il collegamento porta a \
               aggiornamento-sicuro.invalid e il server risponde da 192.0.2.45.",
    },
    SyntheticMessage {
        source: 0,
        id: 103,
        author: None,
        published: 15 * H,
        received: 15 * H + 1,
        arrival: Arrival::Live,
        text: "Esercitazione: altri segnalano lo stesso phishing verso aggiornamento-sicuro.invalid.",
    },
    SyntheticMessage {
        source: 1,
        id: 203,
        author: Some(2),
        published: 20 * H,
        received: 20 * H + 1,
        arrival: Arrival::Live,
        text: "Esercitazione: qualcuno parla di una molotov, ma nel testo di una canzone di prova.",
    },
    SyntheticMessage {
        source: 2,
        id: 302,
        author: None,
        published: 26 * H,
        received: 26 * H + 1,
        arrival: Arrival::Live,
        text: "Esercitazione: il ransomware di prova cifra i file e contatta 192.0.2.45.",
    },
    SyntheticMessage {
        source: 0,
        id: 104,
        author: None,
        published: 31 * H,
        received: 0,
        arrival: Arrival::Recovered,
        text: "Esercitazione: messaggio pubblicato mentre il collegamento era perso, sul corteo.",
    },
    SyntheticMessage {
        source: 2,
        id: 303,
        author: None,
        published: 35 * H,
        received: 0,
        arrival: Arrival::Recovered,
        text: "Esercitazione: aggiornamento sul phishing, sempre verso aggiornamento-sicuro.invalid.",
    },
    SyntheticMessage {
        source: 1,
        id: 204,
        author: Some(0),
        published: 38 * H,
        received: 0,
        arrival: Arrival::Recovered,
        text: "Esercitazione: il presidio di prova si sposta di un'ora.",
    },
    SyntheticMessage {
        source: 0,
        id: 105,
        author: None,
        published: 47 * H,
        received: 47 * H + 1,
        arrival: Arrival::Live,
        text: "Esercitazione: resoconto del corteo di prova, tutto tranquillo.",
    },
    SyntheticMessage {
        source: 2,
        id: 304,
        author: None,
        published: 46 * H,
        received: 46 * H + 1,
        arrival: Arrival::Live,
        text: "Esercitazione: esfiltrazione di dati di prova dal dominio archivio-prova.invalid.",
    },
    SyntheticMessage {
        source: 1,
        id: 205,
        author: Some(1),
        published: 52 * H,
        received: 52 * H + 1,
        arrival: Arrival::Live,
        text: "Esercitazione: ci vediamo al presidio, chi ha domande scriva a \
               esercitazione_utente_due.",
    },
    SyntheticMessage {
        source: 3,
        id: 401,
        author: None,
        published: 55 * H,
        received: 55 * H + 1,
        arrival: Arrival::Live,
        text: "Esercitazione: ultimo messaggio prima che la fonte diventi non accessibile.",
    },
    SyntheticMessage {
        source: 0,
        id: 106,
        author: None,
        published: 66 * H,
        received: 66 * H + 1,
        arrival: Arrival::Live,
        text: "Esercitazione: nuovo appuntamento per il corteo di prova, la prossima settimana.",
    },
];

/// I termini del dizionario dell'esercitazione, con il loro livello.
pub const TERMS: [(&str, i8); 7] = [
    ("corteo", 1),
    ("presidio", 1),
    ("molotov", 3),
    ("phishing", 2),
    ("ransomware", 3),
    ("esfiltrazione", 2),
    ("canzone", -1),
];

/// Le tre persone.
pub const PERSONS: [&str; 3] = [
    "Persona di esercitazione A",
    "Persona di esercitazione B",
    "Persona di esercitazione C",
];

/// Un esito sintetico della ricerca puntuale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyntheticResolution {
    /// Che cosa si è cercato.
    pub kind: ResolutionInputKind,
    /// Il valore, inventato.
    pub input: &'static str,
    /// L'esito, per codice (`ResolutionOutcome::as_str`).
    pub outcome: &'static str,
}

/// I cinque esiti, uno per genere.
pub const RESOLUTIONS: [SyntheticResolution; 5] = [
    SyntheticResolution {
        kind: ResolutionInputKind::Username,
        input: "esercitazione_utente_uno",
        outcome: "trovato",
    },
    SyntheticResolution {
        kind: ResolutionInputKind::PhoneNumber,
        input: "+9996620001",
        outcome: "dato_non_disponibile",
    },
    SyntheticResolution {
        kind: ResolutionInputKind::Link,
        input: "https://esercitazione.invalid/profilo",
        outcome: "richiesta_non_valida",
    },
    SyntheticResolution {
        kind: ResolutionInputKind::Username,
        input: "esercitazione_utente_due",
        outcome: "errore_temporaneo",
    },
    SyntheticResolution {
        kind: ResolutionInputKind::TelegramId,
        input: "990003",
        outcome: "errore_operativo",
    },
];

/// L'esito che una riga di [`RESOLUTIONS`] registra.
fn outcome_of(riga: &SyntheticResolution) -> ResolutionOutcome {
    match riga.outcome {
        "trovato" => ResolutionOutcome::Found(ResolvedIdentity {
            kind: String::from("account"),
            telegram_id: 990_001,
            name: String::from(AUTHORS[0].name),
            username: Some(String::from(AUTHORS[0].username)),
            first_name: String::new(),
            last_name: String::new(),
            usernames: vec![String::from(AUTHORS[0].username)],
            masked_phone: None,
            not_obtained: vec![String::from(
                "Il numero di telefono non è stato restituito (esercitazione).",
            )],
        }),
        "dato_non_disponibile" => ResolutionOutcome::NotAvailable {
            reason: String::from("Nessun account con questo numero (esercitazione)."),
        },
        "richiesta_non_valida" => ResolutionOutcome::InvalidRequest {
            reason: String::from("Il collegamento non è un indirizzo di Telegram (esercitazione)."),
        },
        "errore_temporaneo" => ResolutionOutcome::Temporary {
            reason: String::from("Telegram ha chiesto di attendere (esercitazione)."),
            wait_seconds: Some(30),
        },
        _ => ResolutionOutcome::Operational {
            reason: String::from("La sessione non era valida (esercitazione)."),
            technical: Some(String::from("sessione di esercitazione non autorizzata")),
        },
    }
}

/// Che cosa ha fatto la preparazione dell'archivio all'avvio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prepared {
    /// Nessuna richiesta di ricominciare: l'archivio resta com'è.
    Kept,
    /// L'archivio dell'esercitazione è stato tolto: si ricomincia da capo.
    Restarted,
}

/// La cartella dell'archivio di esercitazione sotto la base indicata, dopo aver
/// verificato che non tocchi quella operativa.
///
/// # Errori
///
/// Restituisce un errore se le due cartelle si toccano.
pub fn exercise_root(_esercitazione: &ExerciseMode, base: &Path) -> ServiceResult<PathBuf> {
    let esercitazione = data_root_in(base, RunMode::Exercise);
    let operativa = data_root_in(base, RunMode::Operational);
    if directories_overlap(&esercitazione, &operativa) {
        return Err(ServiceError::ExportNotWritten {
            reason: String::from(
                "la cartella dell'esercitazione tocca quella operativa: non si azzera nulla",
            ),
        });
    }
    Ok(esercitazione)
}

/// Chiede di ricominciare l'esercitazione al **prossimo avvio**: con l'archivio
/// aperto i file non si tolgono.
///
/// # Errori
///
/// Restituisce un errore se la cartella tocca quella operativa o se il file
/// della richiesta non si scrive.
pub fn request_restart(esercitazione: &ExerciseMode, base: &Path) -> ServiceResult<()> {
    let cartella = exercise_root(esercitazione, base)?;
    std::fs::create_dir_all(&cartella).map_err(|errore| ServiceError::ExportNotWritten {
        reason: format!(
            "la cartella dell'esercitazione non si crea: {}",
            errore.kind()
        ),
    })?;
    std::fs::write(
        cartella.join(RESTART_MARKER),
        "si ricomincia l'esercitazione al prossimo avvio\n",
    )
    .map_err(|errore| ServiceError::ExportNotWritten {
        reason: format!("la richiesta non si scrive: {}", errore.kind()),
    })
}

/// Prepara l'archivio dell'esercitazione **prima** che qualcuno lo apra: se è
/// stato chiesto di ricominciare, toglie i soli file dell'archivio di
/// esercitazione.
///
/// # Errori
///
/// Restituisce un errore se la cartella tocca quella operativa o se un file non
/// si toglie.
pub fn prepare(esercitazione: &ExerciseMode, base: &Path) -> ServiceResult<Prepared> {
    let cartella = exercise_root(esercitazione, base)?;
    let richiesta = cartella.join(RESTART_MARKER);
    if !richiesta.exists() {
        return Ok(Prepared::Kept);
    }
    for nome in ARCHIVE_FILES {
        let percorso = cartella.join(nome);
        if percorso.exists() {
            std::fs::remove_file(&percorso).map_err(|errore| ServiceError::ExportNotWritten {
                reason: format!(
                    "un file dell'esercitazione non si toglie: {}",
                    errore.kind()
                ),
            })?;
        }
    }
    std::fs::remove_file(&richiesta).map_err(|errore| ServiceError::ExportNotWritten {
        reason: format!("la richiesta non si toglie: {}", errore.kind()),
    })?;
    Ok(Prepared::Restarted)
}

/// L'istante di un minuto della cronologia.
fn at(inizio: Timestamp, minuti: i64) -> Timestamp {
    inizio.plus_seconds(minuti * 60)
}

/// Carica l'insieme di dati in un archivio **vuoto**, e lo restituisce.
///
/// La cronologia finisce a `now`: chi apre l'esercitazione vede attività
/// recente.
///
/// # Errori
///
/// Restituisce un errore se l'archivio ha già delle fonti, o se una scrittura
/// non riesce.
pub fn seed(
    esercitazione: &ExerciseMode,
    database: Database,
    now: Timestamp,
) -> ServiceResult<Database> {
    if !database.sources()?.is_empty() {
        return Err(ServiceError::ExportNotWritten {
            reason: String::from("l'archivio non è vuoto: l'esercitazione non si carica sopra"),
        });
    }
    let formatore = Actor::try_new(TRAINER)?;
    let inizio = now.plus_seconds(-TIMELINE_HOURS * 3_600);

    let (database, sessione, fonti) = sources_and_monitoring(database, &formatore, inizio)?;
    let (mut database, contenuti) = timeline(database, sessione, &fonti, &formatore, inizio)?;
    recovery(
        &mut database,
        sessione,
        &fonti,
        &contenuti,
        &formatore,
        inizio,
    )?;
    health_and_faults(&database, sessione, &fonti, inizio)?;
    resolutions(&mut database, esercitazione, &formatore, inizio)?;
    let database = people(database, &formatore, inizio)?;
    let database = work(database, &contenuti, &formatore, inizio)?;
    Ok(database)
}

/// Le fonti, il dizionario e il monitoraggio avviato.
fn sources_and_monitoring(
    mut database: Database,
    formatore: &Actor,
    inizio: Timestamp,
) -> ServiceResult<(Database, SessionId, Vec<SourceId>)> {
    let mut fonti = Vec::with_capacity(SOURCES.len());
    for fonte in SOURCES {
        fonti.push(database.insert_source(
            &NewSource {
                kind: fonte.kind,
                identifier: SourceIdentifier::try_new(&fonte.chat_id.to_string())?,
                display_name: DisplayName::try_new(fonte.name)?,
                authorized_by: formatore.clone(),
                active: true,
            },
            at(inizio, -60),
        )?);
    }
    let sessione = database.insert_session(
        &NewSession {
            label: DisplayName::try_new("Monitoraggio di esercitazione")?,
            started_by: formatore.clone(),
            duration: SessionDuration::Preset {
                seconds: 7 * 24 * 3_600,
            },
            source_ids: fonti.clone(),
        },
        at(inizio, -30),
    )?;
    let mut risolutore = ConfigurationResolver::new();
    for (termine, livello) in TERMS {
        risolutore.add(
            TermText::try_new(termine)?,
            TermCategory::try_new("esercitazione")?,
            LanguageTag::try_new("it")?,
            MatchMode::NormalizedWord,
            livello,
            TermProvenance::ad_hoc(),
        )?;
    }
    database.save_resolved_configuration(sessione, &risolutore.finish())?;
    database.update_session_state(sessione, SessionState::Running, inizio)?;
    Ok((database, sessione, fonti))
}

/// Il messaggio di Telegram che un messaggio sintetico rappresenta.
fn incoming(messaggio: &SyntheticMessage, inizio: Timestamp) -> ServiceResult<IncomingMessage> {
    let autore = messaggio.author.and_then(|indice| AUTHORS.get(indice));
    Ok(IncomingMessage {
        chat_id: ChatId::try_new(SOURCES[messaggio.source].chat_id)?,
        message_id: MessageId::try_new(messaggio.id)?,
        author: autore.map(|autore| String::from(autore.name)),
        author_identifier: autore.map(|autore| String::from(autore.identifier)),
        author_username: autore.map(|autore| String::from(autore.username)),
        text: String::from(messaggio.text),
        published_at_millis: at(inizio, messaggio.published).as_millis(),
        url: None,
        attachment: None,
    })
}

/// La cronologia dal vivo: i collegamenti e i messaggi, nell'ordine in cui
/// arrivano. Restituisce gli identificativi dei contenuti per messaggio.
fn timeline(
    database: Database,
    sessione: SessionId,
    fonti: &[SourceId],
    formatore: &Actor,
    inizio: Timestamp,
) -> ServiceResult<(Database, BTreeMap<i64, ContentId>)> {
    let mut acquisizione = AcquisitionService::new(database);
    let contesto = acquisizione.load_context(sessione, formatore.clone())?;

    let mut eventi: Vec<(i64, ConnectorEvent)> = vec![
        (1, ConnectorEvent::Connection(ConnectionState::Online)),
        (
            CONNECTION_LOST_AT,
            ConnectorEvent::Connection(ConnectionState::Interrupted),
        ),
        (
            CONNECTION_BACK_AT,
            ConnectorEvent::Connection(ConnectionState::Online),
        ),
    ];
    for messaggio in MESSAGES
        .iter()
        .filter(|messaggio| messaggio.arrival != Arrival::Recovered)
    {
        eventi.push((
            messaggio.received,
            ConnectorEvent::MessageReceived(incoming(messaggio, inizio)?),
        ));
    }
    eventi.sort_by_key(|(minuto, _)| *minuto);
    for (minuto, evento) in &eventi {
        acquisizione.ingest(evento, &contesto, at(inizio, *minuto))?;
    }

    let recuperati: Vec<IncomingMessage> = MESSAGES
        .iter()
        .filter(|messaggio| messaggio.arrival == Arrival::Recovered)
        .map(|messaggio| incoming(messaggio, inizio))
        .collect::<ServiceResult<_>>()?;
    acquisizione.ingest_recovered(&recuperati, &contesto, at(inizio, RECOVERY_AT))?;
    let database = acquisizione.into_database();

    let mut contenuti = BTreeMap::new();
    for contenuto in database.session_contents(sessione)? {
        let Some(posizione) = fonti.iter().position(|fonte| *fonte == contenuto.source_id) else {
            continue;
        };
        if let Some(messaggio) = MESSAGES.iter().find(|messaggio| {
            messaggio.source == posizione
                && contenuto.remote_message_id.as_str() == messaggio.id.to_string()
        }) {
            contenuti.insert(messaggio.id, contenuto.id);
        }
    }
    Ok((database, contenuti))
}

/// Il recupero del periodo scoperto, registrato come lo registrerebbe un
/// recupero vero: per fonte, con l'intervallo e chi l'ha chiesto.
fn recovery(
    database: &mut Database,
    sessione: SessionId,
    fonti: &[SourceId],
    contenuti: &BTreeMap<i64, ContentId>,
    formatore: &Actor,
    inizio: Timestamp,
) -> ServiceResult<()> {
    let intervallo = (
        at(inizio, CONNECTION_LOST_AT),
        at(inizio, CONNECTION_BACK_AT),
    );
    for (posizione, fonte) in fonti.iter().enumerate() {
        let archiviati: Vec<ContentId> = MESSAGES
            .iter()
            .filter(|messaggio| {
                messaggio.arrival == Arrival::Recovered && messaggio.source == posizione
            })
            .filter_map(|messaggio| contenuti.get(&messaggio.id).copied())
            .collect();
        if archiviati.is_empty() {
            continue;
        }
        let quanti = u32::try_from(archiviati.len()).unwrap_or(u32::MAX);
        database.insert_recovery_operation(
            &NewRecoveryOperation {
                session_id: sessione,
                source_id: *fonte,
                interval: Some(intervallo),
                requested_by: String::from(formatore.as_str()),
                performed_at: at(inizio, RECOVERY_AT),
                found: quanti,
                archived: archiviati,
            },
            &NewAuditEntry {
                actor: formatore.clone(),
                action: AuditAction::try_new("recupero_per_intervallo_archiviato")?,
                entity: AuditEntity::try_new("fonte")?,
                entity_id: Some(fonte.get()),
                actor_mode: None,
                detail: Some(AuditDetail::try_new(&format!(
                    "esercitazione: {quanti} messaggi recuperati del periodo scoperto"
                ))?),
                recorded_at: at(inizio, RECOVERY_AT),
            },
        )?;
    }
    Ok(())
}

/// La salute delle fonti e un guasto: Delta diventa non accessibile.
fn health_and_faults(
    database: &Database,
    sessione: SessionId,
    fonti: &[SourceId],
    inizio: Timestamp,
) -> ServiceResult<()> {
    for fonte in fonti {
        database.insert_health_check(
            &NewHealthCheck {
                source_id: *fonte,
                account_id: None,
                outcome: HealthCheckOutcome::Reachable,
                detail: None,
            },
            at(inizio, 5),
        )?;
    }
    if let Some(delta) = fonti.get(3) {
        database.insert_health_check(
            &NewHealthCheck {
                source_id: *delta,
                account_id: None,
                outcome: HealthCheckOutcome::NotAccessible,
                detail: None,
            },
            at(inizio, 60 * H),
        )?;
        database.insert_fault(&NewFault {
            session_id: Some(sessione),
            source_id: Some(*delta),
            kind: FaultKind::Network,
            message: FaultMessage::try_new("esercitazione: la fonte non risponde più")?,
            occurred_at: at(inizio, 60 * H),
        })?;
    }
    Ok(())
}

/// I cinque esiti della ricerca puntuale, registrati senza chiedere nulla.
fn resolutions(
    database: &mut Database,
    esercitazione: &ExerciseMode,
    formatore: &Actor,
    inizio: Timestamp,
) -> ServiceResult<()> {
    for (indice, riga) in RESOLUTIONS.iter().enumerate() {
        let richiesta = ResolutionRequest::for_exercise(
            esercitazione,
            riga.kind,
            riga.input,
            formatore.clone(),
            OperationalReason::try_new("esercitazione: ricerca di prova sul caso alfa")?,
        );
        let minuto = 44 * H + i64::try_from(indice).unwrap_or(0) * 10;
        record_exercise(database, &richiesta, at(inizio, minuto), &outcome_of(riga))?;
    }
    Ok(())
}

/// Le persone, e il legame della prima con l'identità trovata.
fn people(database: Database, formatore: &Actor, inizio: Timestamp) -> ServiceResult<Database> {
    let persone = PersonService::new(database);
    let mut aperte = Vec::with_capacity(PERSONS.len());
    for (indice, nome) in PERSONS.iter().enumerate() {
        aperte.push(persone.open(
            &NewPerson::open(
                DisplayName::try_new(nome)?,
                OperationalReason::try_new("esercitazione: fascicolo di prova del caso alfa")?,
            ),
            formatore,
            at(inizio, 48 * H + i64::try_from(indice).unwrap_or(0)),
        )?);
    }
    let database = persone.into_database();
    let trovata = crate::identity_resolver::recent(&database, 50)?
        .into_iter()
        .find(|ricerca| ricerca.resolution.outcome == "trovato");
    let legami = IdentityLinkService::new(database);
    if let (Some(trovata), Some(prima)) = (trovata, aperte.first()) {
        legami.link_from_resolution(
            *prima,
            IdentityResolutionId::new(trovata.id),
            &OperationalReason::try_new("esercitazione: l'identità trovata è quella del caso")?,
            formatore,
            at(inizio, 49 * H),
        )?;
    }
    Ok(legami.into_database())
}

/// Il lavoro: un workspace pronto per il pacchetto, revisioni e una nota.
fn work(
    database: Database,
    contenuti: &BTreeMap<i64, ContentId>,
    formatore: &Actor,
    inizio: Timestamp,
) -> ServiceResult<Database> {
    let workspace = WorkspaceService::new(database);
    let caso = workspace.open(
        &NewWorkspace {
            name: DisplayName::try_new("Caso di esercitazione alfa")?,
            description: Some(Note::try_new(
                "Esercitazione: i messaggi di prova da esaminare insieme.",
            )?),
            created_by: formatore.clone(),
        },
        at(inizio, 50 * H),
    )?;
    for id in [301, 103, 303, 302, 102] {
        if let Some(contenuto) = contenuti.get(&id) {
            workspace.add(
                caso,
                ArchiveRef::to(ArchiveRefKind::Content, contenuto.get())?,
                formatore,
                at(inizio, 50 * H + 5),
            )?;
        }
    }
    let revisioni = ReviewService::new(workspace.into_database());
    for (id, stato, minuto) in [
        (301, ReviewState::Relevant, 56 * H),
        (302, ReviewState::Relevant, 57 * H),
        (203, ReviewState::NotRelevant, 58 * H),
    ] {
        if let Some(contenuto) = contenuti.get(&id) {
            revisioni.record(
                *contenuto,
                stato,
                formatore,
                Some("Esercitazione: decisione di prova del formatore."),
                at(inizio, minuto),
            )?;
        }
    }
    let note = NoteService::new(revisioni.into_database());
    if let Some(contenuto) = contenuti.get(&301) {
        note.write(
            &NewOperatorNote::about(
                ArchiveRef::to(ArchiveRefKind::Content, contenuto.get())?,
                &Note::try_new("Esercitazione: da confrontare con gli altri due messaggi.")?,
            )?,
            formatore,
            at(inizio, 59 * H),
        )?;
    }
    Ok(note.into_database())
}

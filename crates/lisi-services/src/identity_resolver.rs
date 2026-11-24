//! La ricerca puntuale su Telegram (PR-09, ADR-0125).
//!
//! # Che cosa fa
//!
//! Da **un** ingresso — un nome utente, un numero, un identificativo, un
//! collegamento — chiede a Telegram, con la richiesta ufficiale di quel genere,
//! che cosa rende visibile all'account d'ufficio, e registra l'esito fra i
//! cinque (`ResolutionOutcome`).
//!
//! # La tabella è quella della matrice
//!
//! [`RESOLVER_TABLE`] è la tabella «risposte ed esiti» di
//! `docs/validation/PR-09_IDENTITY_RESOLVER_MATRIX.md`, versione
//! [`RESOLVER_TABLE_VERSION`], **copiata e non reinventata**: una prova legge
//! il documento e la confronta riga per riga.
//!
//! # Che cosa non fa
//!
//! - Non ripete una richiesta: una, e una sola, per ricerca.
//! - Non promette `numero → identità` né `nome utente → numero`.
//! - Non unisce nulla a Person Intelligence (PR-10), non cerca fuori da
//!   Telegram, non stima, non assegna punteggi.
//! - Non esegue senza ragione né senza autorità: la richiesta non si costruisce.
//!
//! # Senza autorità, non compila
//!
//! Una postazione che segue un Hub non ottiene l'`AcquisitionAuthority`, e senza
//! di essa la richiesta non si scrive nemmeno. La prova qui sotto **deve non
//! compilare** (controllo negativo 7): togliere l'autorità dalla firma la farebbe
//! compilare, e la prova diventerebbe rossa.
//!
//! ```compile_fail
//! use lisi_core::model::identity_resolution::ResolutionInputKind;
//! use lisi_core::model::reason::OperationalReason;
//! use lisi_core::text::Actor;
//! use lisi_services::identity_resolver::ResolutionRequest;
//!
//! fn da_un_client(operatore: Actor, ragione: OperationalReason) -> ResolutionRequest {
//!     ResolutionRequest::new(ResolutionInputKind::Username, "nome_utente", operatore, ragione)
//! }
//! ```

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::model::identity_resolution::{
    ResolutionInputKind, ResolutionOutcome, ResolvedIdentity,
};
use lisi_core::model::reason::OperationalReason;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_storage::Database;
use lisi_storage::repository::identity_resolution::{
    FoundProfile, NewIdentityResolution, StoredIdentityResolution,
};
use lisi_telegram::lookup::{LookupKind, LookupQuery, LookupReply};
use lisi_telegram::{TelegramConnector, TelegramError};

use crate::acquisition_authority::AcquisitionAuthority;
use crate::error::ServiceResult;
use crate::run_mode::ExerciseMode;

/// La versione della tabella «risposte ed esiti».
pub const RESOLVER_TABLE_VERSION: u32 = 1;

/// Ricerche eseguite al più in un'ora, sulla postazione.
pub const MAX_PER_HOUR: u32 = 20;

/// Secondi, almeno, fra una ricerca eseguita e la successiva.
pub const MIN_SECONDS_BETWEEN: i64 = 15;

/// L'azione d'audit di una ricerca.
pub const RESOLVER_AUDIT_ACTION: &str = "ricerca_puntuale";

/// La lunghezza massima di un ingresso, in caratteri.
const MAX_INPUT_CHARS: usize = 256;

const ORA: i64 = 60 * 60 * 1_000;

/// La frase del tetto, sulla schermata e nei rifiuti.
pub const LIMITS_SENTENCE: &str = "Al più 20 ricerche per ora, e 15 secondi fra una ricerca e \
     l'altra. Una ricerca puntuale fatta a raffica non è una ricerca puntuale.";

/// Da dove viene un riscontro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Una risposta di TDLib: codice e messaggio.
    Tdlib,
    /// Un errore del collegamento: la richiesta non è arrivata a una risposta.
    Connector,
}

impl Source {
    /// Il nome nella tabella della matrice: non si mostra all'operatore.
    #[must_use]
    pub const fn matrix_name(self) -> &'static str {
        match self {
            Self::Tdlib => "risposta TDLib",
            Self::Connector => "collegamento",
        }
    }
}

/// Un esito che non è un profilo: la classe di una riga della tabella.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// `dato_non_disponibile`.
    NotAvailable,
    /// `richiesta_non_valida`.
    InvalidRequest,
    /// `errore_temporaneo`.
    Temporary,
    /// `errore_operativo`.
    Operational,
}

impl Class {
    /// Il nome stabile.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAvailable => "dato_non_disponibile",
            Self::InvalidRequest => "richiesta_non_valida",
            Self::Temporary => "errore_temporaneo",
            Self::Operational => "errore_operativo",
        }
    }
}

/// Una riga della tabella.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableRow {
    /// Da dove viene il riscontro.
    pub source: Source,
    /// Il codice, o `None` per qualunque.
    pub code: Option<i64>,
    /// Una parte del messaggio, o `*` per qualunque. Per il collegamento, il
    /// nome del guasto.
    pub message: &'static str,
    /// L'esito.
    pub class: Class,
}

const fn riga(source: Source, code: Option<i64>, message: &'static str, class: Class) -> TableRow {
    TableRow {
        source,
        code,
        message,
        class,
    }
}

/// La tabella «risposte ed esiti», versione 1. **Si legge dall'alto: vale la
/// prima riga che corrisponde.**
pub const RESOLVER_TABLE: [TableRow; 21] = [
    riga(
        Source::Tdlib,
        Some(400),
        "USERNAME_NOT_OCCUPIED",
        Class::NotAvailable,
    ),
    riga(
        Source::Tdlib,
        Some(400),
        "USERNAME_INVALID",
        Class::InvalidRequest,
    ),
    riga(
        Source::Tdlib,
        Some(400),
        "PHONE_NUMBER_INVALID",
        Class::InvalidRequest,
    ),
    riga(Source::Tdlib, Some(404), "*", Class::NotAvailable),
    riga(
        Source::Tdlib,
        Some(400),
        "User not found",
        Class::NotAvailable,
    ),
    riga(
        Source::Tdlib,
        Some(400),
        "Chat not found",
        Class::NotAvailable,
    ),
    riga(
        Source::Tdlib,
        Some(400),
        "Invalid user identifier",
        Class::InvalidRequest,
    ),
    riga(Source::Tdlib, Some(429), "*", Class::Temporary),
    riga(Source::Tdlib, Some(420), "FLOOD_WAIT", Class::Temporary),
    riga(Source::Tdlib, Some(401), "*", Class::Operational),
    riga(Source::Tdlib, Some(403), "*", Class::Operational),
    riga(Source::Tdlib, Some(500), "*", Class::Temporary),
    riga(Source::Tdlib, None, "*", Class::Operational),
    riga(Source::Connector, None, "attesa scaduta", Class::Temporary),
    riga(
        Source::Connector,
        None,
        "rete non disponibile",
        Class::Temporary,
    ),
    riga(Source::Connector, None, "coda piena", Class::Temporary),
    riga(
        Source::Connector,
        None,
        "sessione revocata",
        Class::Operational,
    ),
    riga(
        Source::Connector,
        None,
        "account non pronto",
        Class::Operational,
    ),
    riga(
        Source::Connector,
        None,
        "connettore arrestato",
        Class::Operational,
    ),
    riga(
        Source::Connector,
        None,
        "ricerca non supportata",
        Class::Operational,
    ),
    riga(Source::Connector, None, "altro", Class::Operational),
];

/// La classe di una risposta di TDLib: la prima riga che corrisponde.
#[must_use]
pub fn classify_refusal(code: i64, message: &str) -> Class {
    RESOLVER_TABLE
        .iter()
        .filter(|riga| riga.source == Source::Tdlib)
        .find(|riga| {
            riga.code.is_none_or(|atteso| atteso == code)
                && (riga.message == "*" || message.contains(riga.message))
        })
        .map_or(Class::Operational, |riga| riga.class)
}

/// Il nome del guasto del collegamento, come la matrice lo scrive.
#[must_use]
pub const fn connector_fault(errore: &TelegramError) -> &'static str {
    match errore {
        TelegramError::Timeout { .. } => "attesa scaduta",
        TelegramError::NetworkUnavailable => "rete non disponibile",
        TelegramError::QueueFull { .. } => "coda piena",
        TelegramError::SessionRevoked => "sessione revocata",
        TelegramError::UnexpectedAuthorizationState { .. }
        | TelegramError::InvalidAuthorizationTransition { .. } => "account non pronto",
        TelegramError::Closed => "connettore arrestato",
        _ => "altro",
    }
}

/// La classe di un guasto del collegamento.
#[must_use]
pub fn classify_fault(guasto: &str) -> Class {
    RESOLVER_TABLE
        .iter()
        .filter(|riga| riga.source == Source::Connector)
        .find(|riga| riga.message == guasto)
        .map_or(Class::Operational, |riga| riga.class)
}

/// L'attesa che Telegram indica: `retry after N` o `FLOOD_WAIT_N`.
#[must_use]
pub fn indicated_wait(message: &str) -> Option<u32> {
    let coda = if let Some((_, dopo)) = message.rsplit_once("retry after ") {
        dopo
    } else if let Some((_, dopo)) = message.rsplit_once("FLOOD_WAIT_") {
        dopo
    } else {
        return None;
    };
    let cifre: String = coda.chars().take_while(char::is_ascii_digit).collect();
    cifre.parse().ok()
}

/// Un ingresso letto dal prodotto, **senza rete**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadInput {
    /// Ammissibile: la richiesta da fare.
    Query(LookupQuery),
    /// Non ammissibile: perché.
    Invalid(&'static str),
}

/// Legge un nome utente: 4–32 caratteri, lettere latine, cifre e trattino
/// basso, che comincia con una lettera; la `@` iniziale si toglie.
fn read_username(testo: &str) -> Option<String> {
    let nome = testo.trim().trim_start_matches('@');
    let lunghezza = nome.chars().count();
    let ammesso = (4..=32).contains(&lunghezza)
        && nome.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && nome.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    ammesso.then(|| nome.to_owned())
}

/// Le prime parti dei collegamenti di Telegram che **non** portano a un nome
/// pubblico.
const NOT_A_PUBLIC_NAME: &[&str] = &[
    "joinchat",
    "c",
    "addstickers",
    "addemoji",
    "share",
    "proxy",
    "socks",
    "login",
    "invoice",
    "setlanguage",
    "bg",
    "addtheme",
    "iv",
    "confirmphone",
    "boost",
    "giftcode",
    "m",
];

/// Legge un ingresso del genere indicato.
#[must_use]
pub fn read_input(genere: ResolutionInputKind, testo: &str) -> ReadInput {
    let testo = testo.trim();
    if testo.is_empty() {
        return ReadInput::Invalid("L'ingresso è vuoto.");
    }
    if testo.chars().count() > MAX_INPUT_CHARS {
        return ReadInput::Invalid("L'ingresso è troppo lungo per essere un dato puntuale.");
    }
    match genere {
        ResolutionInputKind::Username => read_username(testo).map_or(
            ReadInput::Invalid(
                "Un nome utente ha da 4 a 32 caratteri: lettere, cifre e trattino basso, e comincia \
                 con una lettera.",
            ),
            |nome| ReadInput::Query(LookupQuery::Username(nome)),
        ),
        ResolutionInputKind::PhoneNumber => {
            let senza_segni: String = testo
                .chars()
                .filter(|c| !matches!(c, ' ' | '-' | '(' | ')' | '.'))
                .collect();
            let cifre = senza_segni.strip_prefix('+').unwrap_or(&senza_segni);
            if (7..=15).contains(&cifre.len()) && cifre.chars().all(|c| c.is_ascii_digit()) {
                ReadInput::Query(LookupQuery::PhoneNumber(cifre.to_owned()))
            } else {
                ReadInput::Invalid(
                    "Un numero di telefono ha da 7 a 15 cifre, con il prefisso internazionale.",
                )
            }
        }
        ResolutionInputKind::TelegramId => match testo.parse::<i64>() {
            Ok(id) if id > 0 => ReadInput::Query(LookupQuery::UserId(id)),
            Ok(id) if id < 0 => ReadInput::Query(LookupQuery::ChatId(id)),
            _ => ReadInput::Invalid("Un identificativo Telegram è un numero intero diverso da zero."),
        },
        ResolutionInputKind::Link => read_link(testo),
    }
}

/// I domini dei collegamenti di Telegram che si leggono.
const LINK_DOMAINS: [&str; 4] = ["t.me/", "telegram.me/", "www.t.me/", "www.telegram.me/"];

/// Legge un collegamento nella sola forma pubblica `t.me/<nome>`.
fn read_link(testo: &str) -> ReadInput {
    let senza_schema = testo
        .strip_prefix("https://")
        .or_else(|| testo.strip_prefix("http://"))
        .unwrap_or(testo);
    let Some(percorso) = LINK_DOMAINS
        .iter()
        .find_map(|dominio| senza_schema.strip_prefix(dominio))
    else {
        return ReadInput::Invalid("Si leggono soltanto i collegamenti pubblici di Telegram.");
    };
    let percorso = percorso.split(['?', '#']).next().unwrap_or_default();
    let mut parti = percorso.split('/').filter(|parte| !parte.is_empty());
    let mut prima = parti.next().unwrap_or_default();
    if prima.starts_with('+') {
        return ReadInput::Invalid(
            "Un collegamento d'invito non si risolve: porta a un'adesione, e il prodotto non \
             aderisce a nulla.",
        );
    }
    if prima == "s" {
        prima = parti.next().unwrap_or_default();
    }
    if NOT_A_PUBLIC_NAME.contains(&prima.to_ascii_lowercase().as_str()) {
        return ReadInput::Invalid(
            "Questo collegamento non porta a un nome pubblico: il prodotto non lo risolve.",
        );
    }
    read_username(prima).map_or(
        ReadInput::Invalid("Il collegamento non contiene un nome utente valido."),
        |nome| ReadInput::Query(LookupQuery::Username(nome)),
    )
}

/// Una richiesta di ricerca puntuale. **Vuole l'autorità di acquisizione e
/// una ragione operativa**: senza, non esiste.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionRequest {
    kind: ResolutionInputKind,
    input: String,
    operator: Actor,
    reason: OperationalReason,
}

impl ResolutionRequest {
    /// Costruisce la richiesta.
    #[must_use]
    pub fn new(
        _autorita: &AcquisitionAuthority,
        kind: ResolutionInputKind,
        input: &str,
        operator: Actor,
        reason: OperationalReason,
    ) -> Self {
        Self {
            kind,
            input: input.trim().chars().take(MAX_INPUT_CHARS + 1).collect(),
            operator,
            reason,
        }
    }
}

impl ResolutionRequest {
    /// La richiesta di un esito **sintetico** dell'Esercitazione (PR-13,
    /// ADR-0129). Vuole il testimone dell'esercitazione invece dell'autorità:
    /// non parte verso Telegram, si registra soltanto con [`record_exercise`].
    pub(crate) fn for_exercise(
        _esercitazione: &ExerciseMode,
        kind: ResolutionInputKind,
        input: &str,
        operator: Actor,
        reason: OperationalReason,
    ) -> Self {
        Self {
            kind,
            input: input.trim().chars().take(MAX_INPUT_CHARS + 1).collect(),
            operator,
            reason,
        }
    }
}

/// Registra un esito **sintetico** nell'archivio dell'Esercitazione, con la
/// sua riga d'audit, come lo registrerebbe una ricerca vera. Nessuna richiesta
/// esce: la richiesta stessa esiste soltanto con il testimone
/// dell'esercitazione.
///
/// # Errori
///
/// Restituisce un errore se l'archivio non si scrive.
pub(crate) fn record_exercise(
    database: &mut Database,
    richiesta: &ResolutionRequest,
    now: Timestamp,
    esito: &ResolutionOutcome,
) -> ServiceResult<()> {
    record(database, richiesta, now, true, esito)
}

/// Com'è andata una ricerca.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attempt {
    /// La ricerca è registrata, con il suo esito.
    Recorded(ResolutionOutcome),
    /// Il prodotto ha rifiutato di chiedere: il perché. Nessuna richiesta, e
    /// quindi nessun esito.
    Refused(String),
}

/// La ricerca puntuale: rifiuti prima di chiedere, poi **una** richiesta, poi
/// il registro.
///
/// # Errori
///
/// Restituisce un errore se l'archivio non si legge o non si scrive.
pub fn resolve(
    connector: &mut dyn TelegramConnector,
    database: &mut Database,
    richiesta: &ResolutionRequest,
    now: Timestamp,
) -> ServiceResult<Attempt> {
    let query = match read_input(richiesta.kind, &richiesta.input) {
        ReadInput::Query(query) => query,
        ReadInput::Invalid(motivo) => {
            let esito = ResolutionOutcome::InvalidRequest {
                reason: String::from(motivo),
            };
            record(database, richiesta, now, false, &esito)?;
            return Ok(Attempt::Recorded(esito));
        }
    };

    if let Some(rifiuto) = refusal_before_asking(database, now)? {
        return Ok(Attempt::Refused(rifiuto));
    }

    let Some(ricerca) = connector.official_lookup() else {
        let esito = operational("ricerca non supportata", None);
        record(database, richiesta, now, false, &esito)?;
        return Ok(Attempt::Recorded(esito));
    };
    // UNA richiesta, e una sola. Nessuna ripetizione, qualunque sia l'esito.
    let esito = match ricerca.lookup(&query) {
        Ok(LookupReply::Found(profilo)) => ResolutionOutcome::Found(ResolvedIdentity {
            kind: String::from(profilo.kind.label()),
            telegram_id: profilo.telegram_id,
            not_obtained: not_obtained(
                &query,
                profilo.kind,
                &profilo.name,
                profilo.username.as_deref(),
                profilo.phone_number.is_some(),
            ),
            name: profilo.name,
            username: profilo.username,
            first_name: profilo.first_name,
            last_name: profilo.last_name,
            usernames: profilo.usernames,
            // IL TELEFONO SI MASCHERA QUI, APPENA ARRIVA (ADR-0153, decisione 2):
            // il numero pieno non prosegue oltre questa riga.
            masked_phone: profilo
                .phone_number
                .as_deref()
                .map(lisi_core::model::MaskedPhoneNumber::from_digits),
        }),
        Ok(LookupReply::Refused { code, message }) => {
            from_refusal(&query, classify_refusal(code, &message), code, &message)
        }
        Err(errore) => {
            let guasto = connector_fault(&errore);
            match classify_fault(guasto) {
                Class::Temporary => ResolutionOutcome::Temporary {
                    reason: format!(
                        "La richiesta non è arrivata a una risposta: {guasto}. Non vuol dire che il \
                         dato manchi."
                    ),
                    wait_seconds: None,
                },
                _ => operational(guasto, Some(errore.kind())),
            }
        }
    };
    record(database, richiesta, now, true, &esito)?;
    Ok(Attempt::Recorded(esito))
}

/// Un errore operativo, con che cosa fare.
fn operational(guasto: &str, tecnico: Option<&str>) -> ResolutionOutcome {
    let che_cosa_fare = match guasto {
        "sessione revocata" => "Serve un nuovo accesso all'account.",
        "account non pronto" => "L'account non è collegato: serve completare l'accesso.",
        "ricerca non supportata" => {
            "Il collegamento in uso non offre la ricerca puntuale: serve l'account d'ufficio \
             collegato su questa postazione."
        }
        _ => "Serve la diagnostica, o l'amministratore.",
    };
    ResolutionOutcome::Operational {
        reason: format!(
            "La richiesta non può arrivare a una risposta finché qualcuno non interviene: \
             {guasto}. {che_cosa_fare}"
        ),
        technical: tecnico.map(str::to_owned),
    }
}

/// L'esito di una risposta di TDLib che non è un profilo.
fn from_refusal(query: &LookupQuery, classe: Class, code: i64, message: &str) -> ResolutionOutcome {
    let tecnico = format!("codice {code}: {message}");
    match classe {
        Class::NotAvailable => ResolutionOutcome::NotAvailable {
            reason: String::from(match query {
                LookupQuery::Username(_) => {
                    "Telegram non restituisce a questo account un account o un canale pubblico con \
                     questo nome utente."
                }
                LookupQuery::PhoneNumber(_) => {
                    "Telegram non restituisce a questo account un profilo per questo numero: non \
                     esiste, oppure la persona non lo rende visibile."
                }
                // `getMe` non passa da qui: lo usa la pagina Account
                // (`office_account`), non la Ricerca puntuale.
                LookupQuery::UserId(_) | LookupQuery::ChatId(_) | LookupQuery::Me => {
                    "Telegram non restituisce a questo account un profilo per questo \
                     identificativo: l'account non lo ha mai incontrato."
                }
            }),
        },
        Class::InvalidRequest => ResolutionOutcome::InvalidRequest {
            reason: String::from("Telegram ha respinto l'ingresso come non valido."),
        },
        Class::Temporary => {
            let attesa = indicated_wait(message);
            ResolutionOutcome::Temporary {
                reason: attesa.map_or_else(
                    || {
                        String::from(
                            "Telegram non ha risposto per una causa transitoria. Non vuol dire \
                             che il dato manchi.",
                        )
                    },
                    |secondi| {
                        format!(
                            "Telegram ha chiesto di aspettare {secondi} secondi prima di altre \
                             richieste. Non vuol dire che il dato manchi."
                        )
                    },
                ),
                wait_seconds: attesa,
            }
        }
        Class::Operational => {
            let guasto = if code == 401 {
                "sessione revocata"
            } else if code == 403 {
                "Telegram ha rifiutato la richiesta a questo account, e la causa va verificata"
            } else {
                "Telegram ha dato una risposta che il prodotto non riconosce, e non è una prova \
                 che il dato manchi"
            };
            operational(guasto, Some(&tecnico))
        }
    }
}

/// Che cosa, fra ciò che ci si poteva aspettare, non è arrivato.
fn not_obtained(
    query: &LookupQuery,
    genere: LookupKind,
    nome: &str,
    nome_utente: Option<&str>,
    telefono_restituito: bool,
) -> Vec<String> {
    let mut mancanti = Vec::new();
    if nome_utente.is_none() {
        mancanti.push(String::from(
            "Nome utente: Telegram non ne restituisce uno per questo profilo.",
        ));
    }
    if nome.is_empty() {
        mancanti.push(String::from("Nome: Telegram non ne restituisce uno."));
    }
    // Il resolver non promette «nome utente → numero»: lo dice. Quando
    // Telegram lo ha restituito (ADR-0153) non manca, e non si dice.
    if !telefono_restituito
        && !matches!(query, LookupQuery::PhoneNumber(_))
        && matches!(
            genere,
            LookupKind::Account | LookupKind::Person | LookupKind::Bot
        )
    {
        mancanti.push(String::from(
            "Numero di telefono: questa ricerca non lo restituisce, e Telegram non lo dà a chi non \
             è un contatto.",
        ));
    }
    // GLI ALTRI NOMI UTENTE (ADR-0153): una persona trovata per nome utente
    // porta solo quello cercato, perché la risposta è una chat. Chiederli tutti
    // è una seconda ricerca, per identificativo, che decide l'operatore.
    if matches!(query, LookupQuery::Username(_)) && matches!(genere, LookupKind::Account) {
        mancanti.push(String::from(
            "Altri nomi utente: la ricerca per nome utente porta solo quello cercato; la ricerca \
             per identificativo li porta tutti.",
        ));
    }
    mancanti
}

/// Il rifiuto prima di chiedere, se c'è: tetto, frequenza, attesa indicata.
fn refusal_before_asking(database: &Database, now: Timestamp) -> ServiceResult<Option<String>> {
    let dal = Timestamp::from_millis(now.as_millis() - ORA);
    if database.executed_identity_resolutions_since(dal)? >= MAX_PER_HOUR {
        return Ok(Some(format!(
            "Il tetto delle ricerche è raggiunto: nessuna richiesta è partita. {LIMITS_SENTENCE}"
        )));
    }
    if let Some((ultima, attesa)) = database.latest_executed_identity_resolution()? {
        let trascorsi = (now.as_millis() - ultima.as_millis()) / 1_000;
        if let Some(secondi) = attesa
            && trascorsi < i64::from(secondi)
        {
            return Ok(Some(format!(
                "Telegram ha chiesto di aspettare: mancano {}. Nessuna richiesta è partita.",
                lisi_core::text::counted(
                    usize::try_from(i64::from(secondi) - trascorsi).unwrap_or_default(),
                    "secondo",
                    "secondi"
                )
            )));
        }
        if trascorsi < MIN_SECONDS_BETWEEN {
            return Ok(Some(format!(
                "Fra una ricerca e l'altra passano almeno {MIN_SECONDS_BETWEEN} secondi: mancano \
                 {}. Nessuna richiesta è partita.",
                lisi_core::text::counted(
                    usize::try_from(MIN_SECONDS_BETWEEN - trascorsi).unwrap_or_default(),
                    "secondo",
                    "secondi"
                )
            )));
        }
    }
    Ok(None)
}

/// Registra la ricerca e la sua riga d'audit, insieme.
fn record(
    database: &mut Database,
    richiesta: &ResolutionRequest,
    now: Timestamp,
    eseguita: bool,
    esito: &ResolutionOutcome,
) -> ServiceResult<()> {
    let (attesa, tecnico, trovato) = match esito {
        ResolutionOutcome::Temporary { wait_seconds, .. } => (*wait_seconds, None, None),
        ResolutionOutcome::Operational { technical, .. } => (None, technical.clone(), None),
        ResolutionOutcome::Found(profilo) => (
            None,
            None,
            Some(FoundProfile {
                kind: profilo.kind.clone(),
                telegram_id: profilo.telegram_id,
                name: profilo.name.clone(),
                username: profilo.username.clone(),
                details: Some(
                    lisi_storage::repository::identity_resolution::FoundDetails {
                        first_name: profilo.first_name.clone(),
                        last_name: profilo.last_name.clone(),
                        usernames: profilo.usernames.clone(),
                        phone_masked: profilo
                            .masked_phone
                            .as_ref()
                            .map(|telefono| telefono.as_str().to_owned()),
                    },
                ),
            }),
        ),
        ResolutionOutcome::NotAvailable { .. } | ResolutionOutcome::InvalidRequest { .. } => {
            (None, None, None)
        }
    };
    let audit = NewAuditEntry {
        actor: richiesta.operator.clone(),
        action: AuditAction::try_new(RESOLVER_AUDIT_ACTION)?,
        entity: AuditEntity::try_new("ricerca")?,
        entity_id: None,
        actor_mode: None,
        detail: Some(AuditDetail::try_new(&format!(
            "{}, motivo: «{}»: {}",
            richiesta.kind.label(),
            richiesta.reason.as_str(),
            esito.label()
        ))?),
        recorded_at: now,
    };
    database.insert_identity_resolution(
        &NewIdentityResolution {
            requested_by: String::from(richiesta.operator.as_str()),
            reason: String::from(richiesta.reason.as_str()),
            input_kind: String::from(richiesta.kind.as_str()),
            input_value: richiesta.input.clone(),
            requested_at: now,
            executed: eseguita,
            outcome: String::from(esito.as_str()),
            outcome_reason: stored_reason(esito),
            wait_seconds: attesa,
            technical_detail: tecnico,
            found: trovato,
            table_version: RESOLVER_TABLE_VERSION,
        },
        &audit,
    )?;
    Ok(())
}

/// Il motivo che si registra.
///
/// Per un «trovato» è **che cosa non è arrivato**: ciò che Telegram ha
/// restituito sta nei campi del profilo, che sono osservati, e non si mescola a
/// una frase che il prodotto ha composto (PR-03).
fn stored_reason(esito: &ResolutionOutcome) -> String {
    match esito {
        ResolutionOutcome::Found(trovato) if trovato.not_obtained.is_empty() => {
            String::from("Nessuna assenza da segnalare.")
        }
        ResolutionOutcome::Found(trovato) => trovato.not_obtained.join(" "),
        altro => altro.sentence(),
    }
}

/// Ciò che Telegram ha restituito, come si mostra in una riga del registro.
#[must_use]
pub fn found_in_words(profilo: &FoundProfile) -> String {
    let mut frase = format!("{}, identificativo {}", profilo.kind, profilo.telegram_id);
    if !profilo.name.is_empty() {
        frase.push_str(&format!(", nome «{}»", profilo.name));
    }
    match profilo.details.as_ref() {
        Some(dettagli) if dettagli.usernames.len() > 1 => frase.push_str(&format!(
            ", nomi utente attivi {}",
            dettagli
                .usernames
                .iter()
                .map(|nome| format!("@{nome}"))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        _ => {
            if let Some(nome_utente) = &profilo.username {
                frase.push_str(&format!(", nome utente @{nome_utente}"));
            }
        }
    }
    if let Some(telefono) = profilo
        .details
        .as_ref()
        .and_then(|d| d.phone_masked.as_ref())
    {
        frase.push_str(&format!(", telefono {telefono} (ultime cifre)"));
    }
    frase
}

/// Le ricerche più recenti, per la schermata.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn recent(database: &Database, limite: u32) -> ServiceResult<Vec<StoredIdentityResolution>> {
    Ok(database.recent_identity_resolutions(limite)?)
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::identity_resolution::{ResolutionInputKind, ResolutionOutcome};
    use lisi_core::model::reason::OperationalReason;
    use lisi_core::text::Actor;
    use lisi_storage::Database;
    use lisi_telegram::lookup::{LookupKind, LookupProfile, LookupQuery, LookupReply};
    use lisi_telegram::{MockTelegramConnector, TelegramError};

    use super::{
        Attempt, MAX_PER_HOUR, MIN_SECONDS_BETWEEN, ReadInput, ResolutionRequest, read_input,
        resolve,
    };
    use crate::acquisition_authority::StationAuthorityService;

    // La matrice di validazione sta soltanto nell'archivio (ADR-0210).

    fn t(secondi: i64) -> Timestamp {
        Timestamp::from_millis(1_790_294_400_000 + secondi * 1_000)
    }

    fn pronto() -> MockTelegramConnector {
        use lisi_telegram::TelegramConnector;
        use lisi_telegram::connector::ClientParameters;
        use lisi_telegram::secret::{ApiHash, ApiId, LoginCode, PhoneNumber};

        let mut connettore = MockTelegramConnector::new();
        let (Ok(api_id), Ok(api_hash)) = (ApiId::try_new(1), ApiHash::try_new(&"a".repeat(32)))
        else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(()) = connettore.start(&ClientParameters {
            api_id,
            api_hash,
            database_directory: std::path::PathBuf::from("."),
            use_test_datacenter: true,
            application_version: String::from("prova"),
            system_language_code: String::from("it"),
        }) else {
            panic!("l'avvio simulato deve riuscire");
        };
        let (Ok(telefono), Ok(codice)) = (
            PhoneNumber::try_new("+390000000000"),
            LoginCode::try_new("12345"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let (Ok(()), Ok(())) = (
            connettore.submit_phone_number(&telefono),
            connettore.submit_code(&codice),
        ) else {
            panic!("l'accesso simulato deve riuscire");
        };
        connettore
    }

    fn archivio() -> Database {
        let Ok(archivio) = crate::sources::open_in_memory_database() else {
            panic!("l'archivio in memoria deve potersi aprire");
        };
        archivio
    }

    fn richiesta(genere: ResolutionInputKind, ingresso: &str) -> ResolutionRequest {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let Ok(esito) = StationAuthorityService::in_directory(cartella.path())
            .acquisition_authority(&crate::run_mode::operational_for_tests())
        else {
            panic!("la domanda di autorità deve avere una risposta");
        };
        let Some(autorita) = esito.into_granted() else {
            panic!("una postazione senza Hub è autorità di sé stessa");
        };
        let (Ok(operatore), Ok(ragione)) = (
            Actor::try_new("operatore.prova"),
            OperationalReason::try_new("fascicolo 12/2026, verifica di un contatto"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        ResolutionRequest::new(&autorita, genere, ingresso, operatore, ragione)
    }

    fn esito(
        connettore: &mut MockTelegramConnector,
        archivio: &mut Database,
        genere: ResolutionInputKind,
        ingresso: &str,
        quando: Timestamp,
    ) -> ResolutionOutcome {
        match resolve(connettore, archivio, &richiesta(genere, ingresso), quando) {
            Ok(Attempt::Recorded(esito)) => esito,
            altro => panic!("doveva esserci un esito: {altro:?}"),
        }
    }

    /// Un rifiuto simulato di Telegram per il nome `canale_prova`.
    fn risponde(
        connettore: &mut MockTelegramConnector,
        risposta: Result<LookupReply, TelegramError>,
    ) {
        connettore.set_lookup_reply(
            LookupQuery::Username(String::from("canale_prova")),
            risposta,
        );
    }

    fn rifiuto(code: i64, message: &str) -> Result<LookupReply, TelegramError> {
        Ok(LookupReply::Refused {
            code,
            message: String::from(message),
        })
    }

    /// **Un dato che Telegram non fornisce è «Dato non disponibile», mai un
    /// valore** (controllo negativo 1), e il registro non conserva un profilo.
    #[test]
    fn un_dato_non_fornito_non_diventa_un_valore() {
        let (mut connettore, mut archivio) = (pronto(), archivio());
        let esito = esito(
            &mut connettore,
            &mut archivio,
            ResolutionInputKind::PhoneNumber,
            "+39 000 000 0000",
            t(0),
        );
        let ResolutionOutcome::NotAvailable { reason } = &esito else {
            panic!("un 404 è un dato non disponibile: {esito:?}");
        };
        assert!(reason.contains("non lo rende visibile"), "{reason}");
        let Ok(righe) = archivio.recent_identity_resolutions(5) else {
            panic!("il registro deve leggersi");
        };
        assert_eq!(righe[0].resolution.found, None);
        assert_eq!(righe[0].resolution.outcome, "dato_non_disponibile");
    }

    /// **Un profilo trovato dice anche che cosa non è arrivato**, e il
    /// resolver non promette il numero a partire dal nome.
    #[test]
    fn trovato_dice_che_cosa_manca() {
        let (mut connettore, mut archivio) = (pronto(), archivio());
        risponde(
            &mut connettore,
            Ok(LookupReply::Found(LookupProfile {
                kind: LookupKind::Account,
                telegram_id: 42,
                name: String::from("Profilo di prova"),
                username: Some(String::from("canale_prova")),
                first_name: String::new(),
                last_name: String::new(),
                usernames: vec![String::from("canale_prova")],
                phone_number: None,
            })),
        );
        let esito = esito(
            &mut connettore,
            &mut archivio,
            ResolutionInputKind::Link,
            "https://t.me/canale_prova/123",
            t(0),
        );
        let ResolutionOutcome::Found(trovato) = &esito else {
            panic!("doveva essere trovato: {esito:?}");
        };
        assert_eq!(trovato.telegram_id, 42);
        assert!(
            trovato
                .not_obtained
                .iter()
                .any(|mancante| mancante.starts_with("Numero di telefono")),
            "nome utente → numero non si promette"
        );
        assert!(
            esito
                .what_to_do()
                .contains("non è un giudizio su una persona")
        );
    }

    /// **Un'attesa imposta da Telegram è un errore temporaneo, con l'attesa**
    /// (controllo negativo 8).
    #[test]
    fn un_attesa_di_telegram_e_temporanea() {
        for (codice, messaggio) in [
            (429, "Too Many Requests: retry after 30"),
            (420, "FLOOD_WAIT_30"),
        ] {
            let (mut connettore, mut archivio) = (pronto(), archivio());
            risponde(&mut connettore, rifiuto(codice, messaggio));
            let esito = esito(
                &mut connettore,
                &mut archivio,
                ResolutionInputKind::Username,
                "@canale_prova",
                t(0),
            );
            assert_eq!(
                esito,
                ResolutionOutcome::Temporary {
                    reason: String::from(
                        "Telegram ha chiesto di aspettare 30 secondi prima di altre richieste. \
                         Non vuol dire che il dato manchi."
                    ),
                    wait_seconds: Some(30),
                },
                "{codice} {messaggio}"
            );
        }
    }

    /// **Tempo scaduto e rete assente sono errori temporanei, mai un dato non
    /// disponibile** (controllo negativo 9).
    #[test]
    fn tempo_scaduto_e_rete_sono_temporanei() {
        for guasto in [
            TelegramError::Timeout { millis: 5_000 },
            TelegramError::NetworkUnavailable,
        ] {
            let (mut connettore, mut archivio) = (pronto(), archivio());
            risponde(&mut connettore, Err(guasto));
            let esito = esito(
                &mut connettore,
                &mut archivio,
                ResolutionInputKind::Username,
                "canale_prova",
                t(0),
            );
            assert!(
                matches!(esito, ResolutionOutcome::Temporary { .. }),
                "{esito:?}"
            );
        }
    }

    /// **Una sessione non valida è un errore operativo**, né temporaneo né
    /// dato non disponibile (controllo negativo 10).
    #[test]
    fn una_sessione_non_valida_e_operativa() {
        for risposta in [
            rifiuto(401, "Unauthorized"),
            Err(TelegramError::SessionRevoked),
        ] {
            let (mut connettore, mut archivio) = (pronto(), archivio());
            risponde(&mut connettore, risposta);
            let esito = esito(
                &mut connettore,
                &mut archivio,
                ResolutionInputKind::Username,
                "canale_prova",
                t(0),
            );
            let ResolutionOutcome::Operational { reason, .. } = &esito else {
                panic!("una sessione non valida è operativa: {esito:?}");
            };
            assert!(reason.contains("nuovo accesso"), "{reason}");
        }
    }

    /// **Una risposta non riconosciuta è un errore operativo, con il codice
    /// nel dettaglio** (controllo negativo 11).
    #[test]
    fn una_risposta_non_riconosciuta_e_operativa() {
        for (codice, messaggio) in [(418, "QUALCOSA_DI_NUOVO"), (0, "risposta inattesa: ok")] {
            let (mut connettore, mut archivio) = (pronto(), archivio());
            risponde(&mut connettore, rifiuto(codice, messaggio));
            let esito = esito(
                &mut connettore,
                &mut archivio,
                ResolutionInputKind::Username,
                "canale_prova",
                t(0),
            );
            let ResolutionOutcome::Operational { technical, .. } = &esito else {
                panic!("una risposta non riconosciuta è operativa: {esito:?}");
            };
            assert_eq!(
                technical.as_deref(),
                Some(format!("codice {codice}: {messaggio}").as_str())
            );
        }
    }

    /// **Nessuna ripetizione, e l'attesa indicata si rispetta** (controllo
    /// negativo 12): una richiesta per ricerca, e nessuna prima che l'attesa
    /// sia trascorsa.
    #[test]
    fn nessuna_ripetizione_e_l_attesa_si_rispetta() {
        let (mut connettore, mut archivio) = (pronto(), archivio());
        risponde(
            &mut connettore,
            rifiuto(429, "Too Many Requests: retry after 60"),
        );
        let _ = esito(
            &mut connettore,
            &mut archivio,
            ResolutionInputKind::Username,
            "canale_prova",
            t(0),
        );
        assert_eq!(connettore.lookup_calls(), 1, "una richiesta, e una sola");

        let Ok(Attempt::Refused(frase)) = resolve(
            &mut connettore,
            &mut archivio,
            &richiesta(ResolutionInputKind::Username, "canale_prova"),
            t(59),
        ) else {
            panic!("prima dell'attesa non si chiede");
        };
        assert!(
            frase.contains("Telegram ha chiesto di aspettare"),
            "{frase}"
        );
        assert_eq!(connettore.lookup_calls(), 1);

        let _ = esito(
            &mut connettore,
            &mut archivio,
            ResolutionInputKind::Username,
            "canale_prova",
            t(60),
        );
        assert_eq!(
            connettore.lookup_calls(),
            2,
            "dopo l'attesa, a mano, si può"
        );
    }

    /// **Il tetto e la frequenza si applicano** (controllo negativo 4).
    #[test]
    fn il_tetto_e_la_frequenza_si_applicano() {
        let (mut connettore, mut archivio) = (pronto(), archivio());
        let passo = MIN_SECONDS_BETWEEN;
        for indice in 0..i64::from(MAX_PER_HOUR) {
            let _ = esito(
                &mut connettore,
                &mut archivio,
                ResolutionInputKind::Username,
                "canale_prova",
                t(indice * passo),
            );
        }
        assert_eq!(connettore.lookup_calls(), MAX_PER_HOUR);
        let Ok(Attempt::Refused(frase)) = resolve(
            &mut connettore,
            &mut archivio,
            &richiesta(ResolutionInputKind::Username, "canale_prova"),
            t(i64::from(MAX_PER_HOUR) * passo),
        ) else {
            panic!("oltre il tetto non si chiede");
        };
        assert!(frase.contains("tetto"), "{frase}");
        assert_eq!(connettore.lookup_calls(), MAX_PER_HOUR);

        // Troppo presto dopo l'ultima: rifiuto, e nessuna richiesta.
        let (mut altro, mut suo) = (pronto(), self::archivio());
        let _ = esito(
            &mut altro,
            &mut suo,
            ResolutionInputKind::Username,
            "canale_prova",
            t(0),
        );
        let Ok(Attempt::Refused(frase)) = resolve(
            &mut altro,
            &mut suo,
            &richiesta(ResolutionInputKind::Username, "canale_prova"),
            t(5),
        ) else {
            panic!("troppo presto non si chiede");
        };
        assert!(frase.contains("almeno 15 secondi"), "{frase}");
        assert_eq!(altro.lookup_calls(), 1);
    }

    /// **Un ingresso non ammissibile non parte**: si registra come richiesta
    /// non valida, senza chiedere nulla a Telegram.
    #[test]
    fn un_ingresso_non_ammissibile_non_parte() {
        let (mut connettore, mut archivio) = (pronto(), archivio());
        for (genere, ingresso) in [
            (ResolutionInputKind::Username, "ab"),
            (ResolutionInputKind::Link, "https://t.me/+AbCdEf123"),
            (ResolutionInputKind::Link, "https://t.me/joinchat/AbCd"),
            (ResolutionInputKind::Link, "https://t.me/c/123/45"),
            (ResolutionInputKind::PhoneNumber, "12"),
            (ResolutionInputKind::TelegramId, "zero"),
        ] {
            let esito = esito(&mut connettore, &mut archivio, genere, ingresso, t(0));
            assert!(
                matches!(esito, ResolutionOutcome::InvalidRequest { .. }),
                "{ingresso}: {esito:?}"
            );
        }
        assert_eq!(connettore.lookup_calls(), 0, "nessuna richiesta è partita");
        let Ok(quante) = archivio.executed_identity_resolutions_since(t(-1)) else {
            panic!("il conteggio deve riuscire");
        };
        assert_eq!(quante, 0, "non contano nel tetto");
    }

    /// **Ogni ingresso ammesso ha un percorso, e uno solo.**
    #[test]
    fn ogni_ingresso_ha_il_suo_percorso() {
        let casi = [
            (
                ResolutionInputKind::Username,
                "@Canale_Prova",
                LookupQuery::Username(String::from("Canale_Prova")),
            ),
            (
                ResolutionInputKind::PhoneNumber,
                "+39 (000) 000-0000",
                LookupQuery::PhoneNumber(String::from("390000000000")),
            ),
            (
                ResolutionInputKind::TelegramId,
                "42",
                LookupQuery::UserId(42),
            ),
            (
                ResolutionInputKind::TelegramId,
                "-1001234",
                LookupQuery::ChatId(-1_001_234),
            ),
            (
                ResolutionInputKind::Link,
                "t.me/s/canale_prova",
                LookupQuery::Username(String::from("canale_prova")),
            ),
            (
                ResolutionInputKind::Link,
                "https://telegram.me/canale_prova?start=1",
                LookupQuery::Username(String::from("canale_prova")),
            ),
        ];
        for (genere, ingresso, atteso) in casi {
            assert_eq!(
                read_input(genere, ingresso),
                ReadInput::Query(atteso),
                "{ingresso}"
            );
        }
    }

    /// **La ragione è nel registro e nell'audit** (controllo negativo 3).
    #[test]
    fn la_ragione_resta() {
        let (mut connettore, mut archivio) = (pronto(), archivio());
        let _ = esito(
            &mut connettore,
            &mut archivio,
            ResolutionInputKind::Username,
            "canale_prova",
            t(0),
        );
        let Ok(righe) = archivio.recent_identity_resolutions(1) else {
            panic!("il registro deve leggersi");
        };
        assert_eq!(
            righe[0].resolution.reason,
            "fascicolo 12/2026, verifica di un contatto"
        );
        let Ok(voci) = archivio.audit_entries() else {
            panic!("l'audit deve leggersi");
        };
        let Some(voce) = voci
            .iter()
            .find(|voce| voce.action.as_str() == super::RESOLVER_AUDIT_ACTION)
        else {
            panic!("la ricerca deve essere nell'audit");
        };
        let dettaglio = voce
            .detail
            .as_ref()
            .map_or("", |dettaglio| dettaglio.as_str());
        assert!(dettaglio.contains("fascicolo 12/2026"), "{dettaglio}");
    }

    /// **Prova di proprietà (PR-15): un ingresso qualunque non fa cadere la
    /// lettura, e ciò che passa ha la forma del suo genere.**
    ///
    /// Duemila ingressi generati da un alfabeto che comprende segni, spazi,
    /// virgolette, barre, cifre, lettere accentate e il carattere che inverte la
    /// scrittura, di lunghezza fino a trecento: nessuno fa cadere la lettura;
    /// un nome utente ammesso ha la forma di un nome utente, un numero ammesso
    /// ha da 7 a 15 cifre, nessuna richiesta ammessa porta una virgoletta o una
    /// barra rovesciata — la richiesta a Telegram si compone con quei valori —, e
    /// un ingresso oltre il tetto non passa mai.
    #[test]
    fn un_ingresso_qualunque_si_legge_o_si_rifiuta_senza_cadere() {
        use super::{MAX_INPUT_CHARS, ReadInput, read_input};

        const ALFABETO: &[char] = &[
            'a', 'Z', 'k', '0', '7', '9', '_', '@', '+', '-', ' ', '.', '/', ':', '"', '\\', '\n',
            '(', ')', 'é', '€', '\u{202e}', 't', 'm', 'e', 'h', 's', 'p', '?', '=', '&', '#',
        ];
        let mut stato: u64 = 20_261_001;
        let mut prossimo = |limite: u64| -> u64 {
            stato = stato
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (stato >> 33) % limite.max(1)
        };
        let generi = [
            ResolutionInputKind::Username,
            ResolutionInputKind::PhoneNumber,
            ResolutionInputKind::TelegramId,
            ResolutionInputKind::Link,
        ];
        for numero in 0..2_000 {
            let lunghezza = prossimo(300);
            let mut ingresso: String = (0..lunghezza)
                .map(|_| {
                    ALFABETO[usize::try_from(prossimo(ALFABETO.len() as u64)).unwrap_or_default()]
                })
                .collect();
            // Un quarto degli ingressi parte da una forma quasi valida.
            match prossimo(8) {
                0 => ingresso.insert_str(0, "@nome_"),
                1 => ingresso.insert_str(0, "+39"),
                2 => ingresso.insert_str(0, "https://t.me/"),
                _ => {}
            }
            for genere in generi {
                match read_input(genere, &ingresso) {
                    ReadInput::Invalid(frase) => assert!(!frase.is_empty()),
                    ReadInput::Query(richiesta) => {
                        assert!(
                            ingresso.trim().chars().count() <= MAX_INPUT_CHARS,
                            "caso {numero}: un ingresso oltre il tetto è passato"
                        );
                        match &richiesta {
                            LookupQuery::Username(nome) => {
                                let lunghezza = nome.chars().count();
                                assert!((4..=32).contains(&lunghezza), "caso {numero}: {nome}");
                                assert!(
                                    nome.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                                    "caso {numero}: {nome}"
                                );
                            }
                            LookupQuery::PhoneNumber(cifre) => {
                                assert!((7..=15).contains(&cifre.len()), "caso {numero}: {cifre}");
                                assert!(cifre.chars().all(|c| c.is_ascii_digit()));
                            }
                            LookupQuery::UserId(id) => assert!(*id > 0),
                            LookupQuery::ChatId(id) => assert!(*id < 0),
                            LookupQuery::Me => {
                                panic!("caso {numero}: nessun ingresso della Ricerca diventa getMe")
                            }
                        }
                        let composta = format!("{richiesta:?}");
                        assert!(
                            !composta.contains("\\\"") && !composta.contains("\\\\"),
                            "caso {numero}: una richiesta ammessa porta una virgoletta o una barra"
                        );
                    }
                }
            }
        }
    }
}

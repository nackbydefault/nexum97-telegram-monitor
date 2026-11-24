//! La ricerca cyber estesa nei messaggi: **B** nelle chat dell'account, **C**
//! dentro una chat indicata (NEXUM97-CYBER-SEARCH-01, ADR-0154, DG-06) e **D**
//! nei post dei canali pubblici (CYBER-SEARCH-02, ADR-0161).
//!
//! # I risultati non sono acquisizioni
//!
//! Un messaggio trovato si **mostra**: con la chat, l'istante, chi l'ha scritto
//! come Telegram lo dichiara e un estratto. Non entra nei contenuti, nello
//! Storico, negli avvisi, nei documenti. Si registra **la ricerca** — chi,
//! quando, ramo, parole, perimetro, quanti risultati, esito — con audit, senza
//! il testo dei messaggi.
//!
//! # La D soltanto dentro la quota gratuita
//!
//! Prima di ogni pagina della D si legge la quota dichiarata da Telegram: se
//! la query non è gratuita, o le gratuite di oggi sono finite, non si cerca e
//! lo si dice con l'attesa dichiarata. Se Telegram dichiara superati i limiti,
//! la ricerca si ferma. Il prodotto non spende Stelle: la richiesta porta zero.
//!
//! # Limiti dichiarati
//!
//! Parole da 2 a 64 caratteri; al più [`PAGE`] risultati per pagina e
//! [`MAX_RESULTS`] per ricerca; al più [`MAX_PER_HOUR`] pagine all'ora, per
//! tutti i rami insieme. Ogni limite è un numero scelto, non misurato dal vivo.
//!
//! # Che cosa non c'è
//!
//! La E (ricerca ricorrente) non è attiva: è CYBER-WATCH-02.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_storage::Database;
use lisi_storage::repository::cyber_search::NewCyberSearch;
use lisi_telegram::search::{PublicPostLimits, SearchPage, SearchQuery};
use lisi_telegram::{ChatId, TelegramConnector, TelegramError};

use crate::error::ServiceResult;

/// Quanti risultati per pagina.
pub const PAGE: u32 = 50;
/// Quanti risultati al più per ricerca.
pub const MAX_RESULTS: usize = 200;
/// Quante pagine al più all'ora, per postazione.
pub const MAX_PER_HOUR: u32 = 30;
/// L'azione d'audit di una ricerca.
pub const CYBER_SEARCH_AUDIT_ACTION: &str = "ricerca_cyber";

const ORA: i64 = 3_600_000;
/// Quanti caratteri dell'estratto.
const EXCERPT_CHARS: usize = 220;

/// Dove si cerca.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Branch {
    /// **B**: nelle chat dell'account.
    AccountChats,
    /// **C**: dentro una chat indicata.
    InChat(ChatId),
    /// **D**: nei post dei canali pubblici, soltanto dentro la quota gratuita.
    PublicPosts,
}

impl Branch {
    /// La C su una chat scritta per numero. Un numero che non si legge non si
    /// indovina: `None`.
    #[must_use]
    pub fn in_chat(scritto: &str) -> Option<Self> {
        scritto
            .trim()
            .parse::<i64>()
            .ok()
            .and_then(|numero| ChatId::try_new(numero).ok())
            .map(Self::InChat)
    }

    /// La lettera del ramo, come si registra.
    #[must_use]
    pub const fn letter(self) -> &'static str {
        match self {
            Self::AccountChats => "B",
            Self::InChat(_) => "C",
            Self::PublicPosts => "D",
        }
    }

    /// La chat della C, come si registra; nessuna per la B e la D.
    #[must_use]
    pub const fn chat_id(self) -> Option<i64> {
        match self {
            Self::InChat(chat) => Some(chat.get()),
            Self::AccountChats | Self::PublicPosts => None,
        }
    }

    /// Il ramo registrato, dalla lettera e dalla chat. Una coppia che non si
    /// legge non si indovina: `None`.
    #[must_use]
    pub fn from_stored(lettera: &str, chat_id: Option<i64>) -> Option<Self> {
        match (lettera, chat_id) {
            ("B", None) => Some(Self::AccountChats),
            ("D", None) => Some(Self::PublicPosts),
            ("C", Some(numero)) => ChatId::try_new(numero).ok().map(Self::InChat),
            _ => None,
        }
    }
}

/// Un messaggio trovato, come si mostra. **Non è una prova**: è ciò che
/// Telegram ha restituito alla ricerca, adesso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// In quale chat, a parole: il nome della fonte se è fra le fonti, il
    /// numero altrimenti.
    pub chat: String,
    /// L'identificativo della chat.
    pub chat_id: i64,
    /// Il numero del messaggio.
    pub message_id: i64,
    /// Quando è stato pubblicato, come Telegram lo dichiara.
    pub published_at: Timestamp,
    /// Chi l'ha scritto, come Telegram lo dichiara adesso, in una frase.
    pub who: String,
    /// L'inizio del testo, con il taglio dichiarato.
    pub excerpt: String,
}

/// Una ricerca in corso: le pagine già lette e dove continuare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CyberSearch {
    /// Dove.
    pub branch: Branch,
    /// Le parole.
    pub query: String,
    /// I risultati letti finora, nell'ordine di Telegram.
    pub hits: Vec<Hit>,
    /// Quante pagine.
    pub pages: u32,
    /// Quando è stata chiesta la prima.
    pub asked_at: Timestamp,
    next_offset: Option<String>,
    next_from_message_id: Option<i64>,
    /// Che cosa è successo all'ultima pagina, in una frase.
    pub last_outcome: String,
    /// Se la chiede una ricerca ricorrente E: per la D vale la riserva
    /// (ADR-0162, decisione 3).
    recurring: bool,
    /// Il numero dell'ultima pagina nel registro delle ricerche.
    last_search_id: Option<i64>,
    /// L'esito dell'ultima pagina, come si registra.
    last_code: &'static str,
}

impl CyberSearch {
    /// Il numero dell'ultima pagina nel registro delle ricerche, se una pagina
    /// è stata registrata.
    #[must_use]
    pub const fn last_search_id(&self) -> Option<i64> {
        self.last_search_id
    }

    /// L'esito dell'ultima pagina, come si registra: `trovati`,
    /// `nessun_risultato`, `rifiutata` o `non_riuscita`.
    #[must_use]
    pub const fn last_code(&self) -> &'static str {
        self.last_code
    }

    /// Il perimetro, detto a chi legge.
    #[must_use]
    pub fn scope_sentence(&self) -> String {
        scope_of(self.branch)
    }

    /// Se si può chiedere un'altra pagina.
    #[must_use]
    pub fn can_continue(&self) -> bool {
        self.hits.len() < MAX_RESULTS
            && (self.next_offset.as_deref().is_some_and(|o| !o.is_empty())
                || self.next_from_message_id.is_some_and(|id| id > 0))
    }
}

/// Il perimetro di un ramo non chiesto, dalla sua lettera: la C senza la sua
/// chat (CYBER-SEARCH-03).
pub(crate) fn scope_sentence_of(lettera: &str) -> String {
    match lettera {
        "B" => scope_of(Branch::AccountChats),
        "D" => scope_of(Branch::PublicPosts),
        _ => String::from("Dentro una chat indicata per numero."),
    }
}

/// Il perimetro di un ramo, in una frase.
fn scope_of(branch: Branch) -> String {
    match branch {
        Branch::AccountChats => String::from(
            "Nelle chat dell'elenco principale e dell'archivio di questo account, tranne le \
             segrete. Non nelle chat di cui l'account non fa parte, e non in tutto Telegram.",
        ),
        Branch::InChat(chat) => format!(
            "Dentro la chat {}. Se l'account non ne fa parte, la lettura senza iscrizione non \u{e8} \
             verificata: se Telegram la rifiuta, lo si dice.",
            chat.get()
        ),
        Branch::PublicPosts => String::from(
            "Nei post dei canali pubblici di Telegram, anche di canali che questo account non \
             segue, e soltanto dentro la quota gratuita di oggi. Non nei gruppi, non nelle chat \
             private, e non in tutto Telegram.",
        ),
    }
}

/// L'esito di una richiesta di ricerca.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attempt {
    /// La pagina è stata chiesta e registrata.
    Done(CyberSearch),
    /// Il prodotto non ha chiesto nulla: il perché.
    Refused(String),
}

/// Controlla le parole prima di chiedere.
///
/// # Errori
///
/// Restituisce la frase del rifiuto se le parole sono fuori misura o portano
/// caratteri di controllo.
pub fn read_query(testo: &str) -> Result<String, String> {
    let parole = testo.trim();
    let quanti = parole.chars().count();
    if !(2..=64).contains(&quanti) {
        return Err(format!(
            "Scrivere da 2 a 64 caratteri; ne sono stati scritti {quanti}. La ricerca non \u{e8} \
             partita."
        ));
    }
    if parole.chars().any(char::is_control) {
        return Err(String::from(
            "Le parole contengono caratteri non ammessi: la ricerca non \u{e8} partita.",
        ));
    }
    Ok(parole.to_owned())
}

/// Chiede la prima pagina di una ricerca, e la registra.
///
/// # Errori
///
/// Restituisce un errore soltanto se l'archivio non si legge o non si scrive.
pub fn start(
    connector: Option<&mut dyn TelegramConnector>,
    database: &mut Database,
    operator: &Actor,
    branch: Branch,
    testo: &str,
    now: Timestamp,
) -> ServiceResult<Attempt> {
    first_page(connector, database, operator, branch, testo, now, false)
}

/// Chiede la pagina di una ricerca ricorrente E, e la registra: come
/// [`start`], e per la D con la riserva di metà della quota gratuita a chi
/// cerca a mano (ADR-0162, decisione 3).
///
/// # Errori
///
/// Restituisce un errore soltanto se l'archivio non si legge o non si scrive.
pub fn start_recurring(
    connector: Option<&mut dyn TelegramConnector>,
    database: &mut Database,
    operator: &Actor,
    branch: Branch,
    testo: &str,
    now: Timestamp,
) -> ServiceResult<Attempt> {
    first_page(connector, database, operator, branch, testo, now, true)
}

/// La prima pagina, a mano o per una ricorrente.
fn first_page(
    connector: Option<&mut dyn TelegramConnector>,
    database: &mut Database,
    operator: &Actor,
    branch: Branch,
    testo: &str,
    now: Timestamp,
    recurring: bool,
) -> ServiceResult<Attempt> {
    let query = match read_query(testo) {
        Ok(query) => query,
        Err(frase) => return Ok(Attempt::Refused(frase)),
    };
    let ricerca = CyberSearch {
        branch,
        query,
        hits: Vec::new(),
        pages: 0,
        asked_at: now,
        next_offset: Some(String::new()),
        next_from_message_id: Some(0),
        last_outcome: String::new(),
        recurring,
        last_search_id: None,
        last_code: "",
    };
    page(connector, database, operator, ricerca, now)
}

/// Chiede la pagina successiva di una ricerca già avviata.
///
/// # Errori
///
/// Restituisce un errore soltanto se l'archivio non si legge o non si scrive.
pub fn next(
    connector: Option<&mut dyn TelegramConnector>,
    database: &mut Database,
    operator: &Actor,
    ricerca: CyberSearch,
    now: Timestamp,
) -> ServiceResult<Attempt> {
    if !ricerca.can_continue() {
        return Ok(Attempt::Refused(format!(
            "Non ci sono altre pagine da chiedere, oppure \u{e8} raggiunto il tetto di \
             {MAX_RESULTS} risultati per ricerca."
        )));
    }
    page(connector, database, operator, ricerca, now)
}

/// Una pagina: i rifiuti prima di chiedere, poi **una** richiesta, poi il
/// registro.
fn page(
    connector: Option<&mut dyn TelegramConnector>,
    database: &mut Database,
    operator: &Actor,
    mut ricerca: CyberSearch,
    now: Timestamp,
) -> ServiceResult<Attempt> {
    // IL TETTO ORARIO, PRIMA DI CHIEDERE (ADR-0154, decisione 5).
    let dal = Timestamp::from_millis(now.as_millis() - ORA);
    if database.cyber_searches_since(dal)? >= MAX_PER_HOUR {
        return Ok(Attempt::Refused(format!(
            "\u{c8} raggiunto il tetto di {MAX_PER_HOUR} ricerche all'ora su questa postazione: \
             la ricerca non \u{e8} partita. Si potr\u{e0} riprovare pi\u{f9} tardi."
        )));
    }
    let Some(connector) = connector else {
        return Ok(Attempt::Refused(String::from(
            "Non c'\u{e8} un account collegato: la ricerca nei messaggi si fa con l'account \
             d'ufficio, e non \u{e8} partita.",
        )));
    };

    let restano = MAX_RESULTS.saturating_sub(ricerca.hits.len());
    let limite = u32::try_from(restano).unwrap_or(PAGE).min(PAGE);
    let richiesta = match ricerca.branch {
        Branch::AccountChats => SearchQuery::AccountChats {
            query: ricerca.query.clone(),
            offset: ricerca.next_offset.clone().unwrap_or_default(),
            limit: limite,
        },
        Branch::InChat(chat_id) => SearchQuery::InChat {
            chat_id,
            query: ricerca.query.clone(),
            from_message_id: ricerca.next_from_message_id.unwrap_or(0),
            limit: limite,
        },
        Branch::PublicPosts => SearchQuery::PublicPosts {
            query: ricerca.query.clone(),
            offset: ricerca.next_offset.clone().unwrap_or_default(),
            limit: limite,
        },
    };

    // LA QUOTA GRATUITA, PRIMA DI OGNI PAGINA DELLA D (ADR-0161, decisione 2).
    let esito = if ricerca.branch == Branch::PublicPosts {
        match connector.public_post_limits(&ricerca.query) {
            // LA RISERVA DELLA RICORRENTE (ADR-0162, decisione 3).
            Ok(quota)
                if quota.allows_free_search() && ricerca.recurring && !keeps_reserve(&quota) =>
            {
                Err(("rifiutata", reserve_sentence(&quota)))
            }
            Ok(quota) if quota.allows_free_search() => connector
                .search_messages(&richiesta)
                .map_err(|e| refusal_sentence(&e)),
            Ok(quota) => Err(("rifiutata", quota_sentence(quota.next_free_in_seconds))),
            Err(errore) => {
                let (esito, frase) = refusal_sentence(&errore);
                Err((
                    esito,
                    format!(
                        "La quota gratuita della ricerca nei post pubblici non si \u{e8} potuta \
                         leggere, e senza quota la ricerca non parte. {frase}"
                    ),
                ))
            }
        }
    } else {
        connector
            .search_messages(&richiesta)
            .map_err(|e| refusal_sentence(&e))
    };
    ricerca.pages += 1;
    let (outcome, risultati, frase) = match esito {
        Ok(pagina) => {
            let nuovi = hits_of(database, &pagina, restano);
            let quanti = nuovi.len();
            ricerca.next_offset = pagina.next_offset.clone();
            ricerca.next_from_message_id = pagina.next_from_message_id;
            ricerca.hits.extend(nuovi);
            // LIMITI SUPERATI: LA D SI FERMA (ADR-0161, decisione 3).
            let fermata = ricerca.branch == Branch::PublicPosts && pagina.limits_exceeded;
            if fermata {
                ricerca.next_offset = None;
            }
            if fermata && quanti == 0 {
                ricerca.next_from_message_id = None;
                (
                    "rifiutata",
                    0,
                    String::from(
                        "Telegram dichiara superati i limiti della ricerca nei post pubblici: \
                         la ricerca si ferma qui, e il prodotto non spende Stelle.",
                    ),
                )
            } else if fermata {
                (
                    "trovati",
                    quanti,
                    format!(
                        "Telegram ha restituito {quanti} messaggi in questa pagina, e dichiara \
                         superati i limiti della ricerca nei post pubblici: la ricerca si ferma \
                         qui. I messaggi non sono acquisiti e non entrano nello Storico."
                    ),
                )
            } else if quanti == 0 {
                ricerca.next_offset = None;
                ricerca.next_from_message_id = None;
                (
                    "nessun_risultato",
                    0,
                    String::from(
                        "Telegram non ha restituito messaggi per queste parole in questo \
                         perimetro. Non significa che non ce ne siano altrove.",
                    ),
                )
            } else {
                (
                    "trovati",
                    quanti,
                    format!(
                        "Telegram ha restituito {quanti} messaggi in questa pagina. Sono ci\u{f2} \
                         che si legge adesso: non sono acquisiti e non entrano nello Storico."
                    ),
                )
            }
        }
        Err((esito, frase)) => {
            ricerca.next_offset = None;
            ricerca.next_from_message_id = None;
            (esito, 0, frase)
        }
    };
    ricerca.last_outcome = frase.clone();
    ricerca.last_code = outcome;

    // LA RICERCA SI REGISTRA, I MESSAGGI NO (ADR-0154, decisione 4).
    let registro = NewCyberSearch {
        searched_by: operator.as_str().to_owned(),
        searched_at: now,
        branch: ricerca.branch.letter(),
        query: ricerca.query.clone(),
        scope: ricerca.scope_sentence(),
        chat_id: ricerca.branch.chat_id(),
        page: ricerca.pages,
        outcome,
        results: u32::try_from(risultati).unwrap_or(u32::MAX),
        outcome_reason: frase,
    };
    let audit = NewAuditEntry {
        actor: operator.clone(),
        action: AuditAction::try_new(CYBER_SEARCH_AUDIT_ACTION)?,
        entity: AuditEntity::try_new("ricerca")?,
        entity_id: None,
        actor_mode: None,
        detail: Some(AuditDetail::try_new(&format!(
            "ramo {}, pagina {}, {} risultati",
            ricerca.branch.letter(),
            ricerca.pages,
            risultati
        ))?),
        recorded_at: now,
    };
    ricerca.last_search_id = Some(database.insert_cyber_search(&registro, &audit)?);
    Ok(Attempt::Done(ricerca))
}

/// Se una ricorrente può usare una ricerca gratuita della D: dopo la sua
/// ricerca deve restare almeno la metà, arrotondata per eccesso, di quelle del
/// giorno (ADR-0162, decisione 3).
fn keeps_reserve(quota: &PublicPostLimits) -> bool {
    i64::from(quota.remaining_free) > (i64::from(quota.daily_free) + 1) / 2
}

/// Che cosa dire quando la ricorrente lascia la quota a chi cerca a mano.
fn reserve_sentence(quota: &PublicPostLimits) -> String {
    format!(
        "La ricerca ricorrente lascia a chi cerca a mano la met\u{e0} delle ricerche gratuite di \
         oggi: ne restano {} su {}, e non \u{e8} partita. Il prodotto non spende Stelle.",
        quota.remaining_free, quota.daily_free
    )
}

/// Che cosa dire di un errore della ricerca: rifiutata o non riuscita.
fn refusal_sentence(errore: &TelegramError) -> (&'static str, String) {
    match errore {
        TelegramError::Timeout { .. } => (
            "non_riuscita",
            String::from(
                "Telegram non ha risposto entro il tempo massimo: la ricerca non \u{e8} riuscita, \
                 e non significa che non ci siano messaggi. Si pu\u{f2} riprovare.",
            ),
        ),
        TelegramError::NetworkUnavailable => (
            "non_riuscita",
            String::from("La rete non \u{e8} disponibile: la ricerca non \u{e8} riuscita."),
        ),
        TelegramError::Tdlib { reason } => (
            "rifiutata",
            format!("Telegram ha rifiutato la ricerca: {reason}."),
        ),
        altro => (
            "non_riuscita",
            format!(
                "La ricerca non \u{e8} riuscita per un problema tecnico ({}).",
                altro.kind()
            ),
        ),
    }
}

/// Che cosa dire quando la quota gratuita della D non basta: non si cerca, il
/// prodotto non spende Stelle, e l'attesa è quella dichiarata da Telegram.
fn quota_sentence(secondi: i32) -> String {
    let quando = if secondi <= 0 {
        String::from("Telegram non dichiara quando torner\u{e0} disponibile una ricerca gratuita.")
    } else {
        let minuti = (i64::from(secondi) + 59) / 60;
        let (ore, resto) = (minuti / 60, minuti % 60);
        let durata = match (ore, resto) {
            (0, 1) => String::from("circa un minuto"),
            (0, m) => format!("circa {m} minuti"),
            (1, 0) => String::from("circa un'ora"),
            (h, 0) => format!("circa {h} ore"),
            (1, m) => format!("circa un'ora e {m} minuti"),
            (h, m) => format!("circa {h} ore e {m} minuti"),
        };
        format!("Telegram dichiara la prossima ricerca gratuita fra {durata}.")
    };
    format!(
        "La quota gratuita della ricerca nei post pubblici non basta per questa ricerca: la \
         ricerca non \u{e8} partita, e il prodotto non spende Stelle. {quando}"
    )
}

/// I risultati di una pagina, pronti da mostrare: la chat a parole, chi ha
/// scritto, l'estratto. Al più `restano`.
fn hits_of(database: &Database, pagina: &SearchPage, restano: usize) -> Vec<Hit> {
    let fonti = database.sources().unwrap_or_default();
    pagina
        .hits
        .iter()
        .take(restano)
        .map(|messaggio| {
            let chat_id = messaggio.chat_id.get();
            let chat = fonti
                .iter()
                .find(|fonte| fonte.identifier.as_str() == chat_id.to_string())
                .map_or_else(
                    || format!("chat {chat_id}, non fra le fonti"),
                    |fonte| format!("{} (fonte)", fonte.display_name.as_str()),
                );
            Hit {
                chat,
                chat_id,
                message_id: messaggio.message_id.get(),
                published_at: Timestamp::from_millis(messaggio.published_at_millis),
                who: crate::context::chi_ha_scritto(messaggio),
                excerpt: excerpt(&messaggio.text),
            }
        })
        .collect()
}

/// L'inizio del testo, con il taglio dichiarato da un'ellissi.
pub(crate) fn excerpt(testo: &str) -> String {
    let pulito: String = testo
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if pulito.chars().count() > EXCERPT_CHARS {
        let mut tagliato: String = pulito.chars().take(EXCERPT_CHARS).collect();
        tagliato.push('\u{2026}');
        tagliato
    } else {
        pulito
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::text::Actor;
    use lisi_storage::Database;
    use lisi_telegram::search::{PublicPostLimits, SearchPage, SearchQuery};
    use lisi_telegram::{
        ChatId, IncomingMessage, MessageId, MockTelegramConnector, TelegramConnector, TelegramError,
    };

    use super::{Attempt, Branch, MAX_PER_HOUR, MAX_RESULTS, next, read_query, start};

    const ORA: i64 = 1_760_000_000_000;
    const THIS_MODULE: &str = include_str!("cyber_search.rs");

    fn operatore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("attore valido");
        };
        attore
    }

    fn archivio() -> Database {
        let Ok(archivio) = crate::sources::open_in_memory_database() else {
            panic!("archivio in memoria");
        };
        archivio
    }

    /// Un connettore simulato con l'accesso completato.
    fn pronto() -> MockTelegramConnector {
        use lisi_telegram::connector::ClientParameters;
        use lisi_telegram::secret::{ApiHash, ApiId, LoginCode, PhoneNumber};

        let mut connettore = MockTelegramConnector::new();
        let (Ok(api_id), Ok(api_hash)) = (ApiId::try_new(1), ApiHash::try_new(&"a".repeat(32)))
        else {
            panic!("valori di prova validi");
        };
        let Ok(()) = connettore.start(&ClientParameters {
            api_id,
            api_hash,
            database_directory: std::path::PathBuf::from("."),
            use_test_datacenter: true,
            application_version: String::from("prova"),
            system_language_code: String::from("it"),
        }) else {
            panic!("avvio simulato");
        };
        let (Ok(telefono), Ok(codice)) = (
            PhoneNumber::try_new("+390000000000"),
            LoginCode::try_new("12345"),
        ) else {
            panic!("valori di prova validi");
        };
        let (Ok(()), Ok(())) = (
            connettore.submit_phone_number(&telefono),
            connettore.submit_code(&codice),
        ) else {
            panic!("accesso simulato");
        };
        connettore
    }

    fn messaggio(chat: i64, id: i64, testo: &str) -> IncomingMessage {
        let (Ok(chat_id), Ok(message_id)) = (ChatId::try_new(chat), MessageId::try_new(id)) else {
            panic!("identificativi validi");
        };
        IncomingMessage {
            chat_id,
            message_id,
            author: Some(String::from("Persona")),
            author_identifier: Some(String::from("42")),
            author_username: None,
            text: testo.to_owned(),
            published_at_millis: ORA,
            url: None,
            attachment: None,
        }
    }

    fn pagina(n: usize, prossima: &str) -> SearchPage {
        SearchPage {
            hits: (0..n)
                .map(|i| messaggio(-1001, i64::try_from(i + 1).unwrap_or(1), "ransomware"))
                .collect(),
            total_count: None,
            next_offset: Some(String::from(prossima)),
            next_from_message_id: None,
            limits: None,
            limits_exceeded: false,
        }
    }

    /// Una quota della D: `restano` query gratuite, e se questa lo è.
    fn quota(restano: i32, gratuita: bool, fra_secondi: i32) -> PublicPostLimits {
        PublicPostLimits {
            daily_free: 10,
            remaining_free: restano,
            next_free_in_seconds: fra_secondi,
            star_count: 10,
            current_query_free: gratuita,
        }
    }

    /// Avvia una ricerca D con le parole di prova.
    fn avvia_d(
        connettore: &mut MockTelegramConnector,
        db: &mut Database,
    ) -> super::ServiceResult<Attempt> {
        start(
            Some(connettore as &mut dyn TelegramConnector),
            db,
            &operatore(),
            Branch::PublicPosts,
            "#ransomware",
            Timestamp::from_millis(ORA),
        )
    }

    /// **Senza quota gratuita la D non cerca, lo dice con l'attesa dichiarata,
    /// e la ricerca si registra rifiutata** (CYBER-SEARCH-02, criterio 2; prova
    /// negativa: controllo della quota tolto → rossa).
    #[test]
    fn senza_quota_gratuita_la_d_non_cerca() {
        for (quota, attesa) in [
            (quota(0, true, 5_400), "circa un'ora e 30 minuti"),
            (quota(4, false, 60), "circa un minuto"),
            (quota(0, false, 0), "non dichiara quando"),
        ] {
            let mut db = archivio();
            let mut connettore = pronto();
            connettore.queue_limits_reply(Ok(quota));
            connettore.queue_search_reply(Ok(pagina(3, "cursore")));
            let ricerca = fatta(avvia_d(&mut connettore, &mut db));
            assert!(connettore.searched().is_empty(), "nulla cercato: {quota:?}");
            assert_eq!(connettore.limits_asked(), ["#ransomware"]);
            assert!(ricerca.hits.is_empty());
            assert!(!ricerca.can_continue());
            assert!(
                ricerca.last_outcome.contains("non spende Stelle")
                    && ricerca.last_outcome.contains(attesa),
                "{}",
                ricerca.last_outcome
            );
            let Ok(registro) = db.recent_cyber_searches(10) else {
                panic!("il registro deve leggersi");
            };
            assert_eq!(registro.len(), 1, "il rifiuto si registra");
            assert_eq!(registro[0].branch, "D");
            assert_eq!(registro[0].results, 0);
        }
    }

    /// **Dentro la quota la D cerca nei post pubblici, rilegge la quota prima
    /// di ogni pagina, e continua dal cursore** (criteri 1, 2, 5).
    #[test]
    fn dentro_la_quota_la_d_cerca_e_continua() {
        let mut db = archivio();
        let mut connettore = pronto();
        connettore.queue_limits_reply(Ok(quota(3, true, 0)));
        connettore.queue_search_reply(Ok(pagina(2, "cursore-d")));
        let ricerca = fatta(avvia_d(&mut connettore, &mut db));
        assert_eq!(ricerca.hits.len(), 2);
        assert!(ricerca.can_continue());
        assert!(ricerca.scope_sentence().contains("canali pubblici"));
        assert!(ricerca.scope_sentence().contains("quota gratuita"));
        assert_eq!(
            connettore.searched(),
            [SearchQuery::PublicPosts {
                query: String::from("#ransomware"),
                offset: String::new(),
                limit: 50
            }]
        );

        connettore.queue_limits_reply(Ok(quota(0, true, 600)));
        let ricerca = fatta(next(
            Some(&mut connettore as &mut dyn TelegramConnector),
            &mut db,
            &operatore(),
            ricerca,
            Timestamp::from_millis(ORA + 1),
        ));
        assert_eq!(connettore.limits_asked().len(), 2, "una quota per pagina");
        assert_eq!(
            connettore.searched().len(),
            1,
            "la seconda pagina non si chiede a quota finita"
        );
        assert_eq!(ricerca.hits.len(), 2, "i risultati letti restano");
        assert!(ricerca.last_outcome.contains("circa 10 minuti"));
        let Ok(registro) = db.recent_cyber_searches(10) else {
            panic!("il registro deve leggersi");
        };
        assert_eq!(registro.len(), 2);
        assert!(registro.iter().all(|riga| riga.branch == "D"));
    }

    /// **Limiti superati: la D si ferma e lo dice** (criterio 3; prova
    /// negativa: fermata tolta → rossa).
    #[test]
    fn i_limiti_superati_fermano_la_d() {
        for trovati in [1, 0] {
            let mut db = archivio();
            let mut connettore = pronto();
            connettore.queue_limits_reply(Ok(quota(3, true, 0)));
            connettore.queue_search_reply(Ok(SearchPage {
                limits_exceeded: true,
                ..pagina(trovati, "ancora")
            }));
            let ricerca = fatta(avvia_d(&mut connettore, &mut db));
            assert!(
                !ricerca.can_continue(),
                "con i limiti superati non si continua"
            );
            assert!(
                ricerca.last_outcome.contains("superati i limiti"),
                "{}",
                ricerca.last_outcome
            );
            assert_eq!(ricerca.hits.len(), trovati);
        }
    }

    /// **Una quota che non si legge ferma la D prima di cercare** (criterio 2).
    #[test]
    fn una_quota_che_non_si_legge_ferma_la_d() {
        let mut db = archivio();
        let mut connettore = pronto();
        connettore.queue_search_reply(Ok(pagina(3, "cursore")));
        let ricerca = fatta(avvia_d(&mut connettore, &mut db));
        assert!(connettore.searched().is_empty());
        assert!(
            ricerca
                .last_outcome
                .contains("non si \u{e8} potuta leggere"),
            "{}",
            ricerca.last_outcome
        );
    }

    fn fatta(esito: super::ServiceResult<Attempt>) -> super::CyberSearch {
        match esito {
            Ok(Attempt::Done(ricerca)) => ricerca,
            altro => panic!("la ricerca doveva essere fatta: {altro:?}"),
        }
    }

    /// **Le parole si controllano prima di chiedere** (criterio 4).
    #[test]
    fn le_parole_si_controllano_prima_di_chiedere() {
        assert!(read_query("x").is_err());
        assert!(read_query(&"a".repeat(65)).is_err());
        assert!(read_query("ran\u{7}som").is_err());
        assert_eq!(read_query("  ransomware  "), Ok(String::from("ransomware")));

        let mut db = archivio();
        let mut connettore = pronto();
        let Ok(Attempt::Refused(_)) = start(
            Some(&mut connettore as &mut dyn TelegramConnector),
            &mut db,
            &operatore(),
            Branch::AccountChats,
            "x",
            Timestamp::from_millis(ORA),
        ) else {
            panic!("una parola di un carattere non parte");
        };
        assert!(connettore.searched().is_empty(), "nulla chiesto a Telegram");
    }

    /// **Una ricerca B si fa, si registra, e continua dalla pagina giusta**
    /// (criteri 2, 5).
    #[test]
    fn una_ricerca_si_fa_si_registra_e_continua() {
        let mut db = archivio();
        let mut connettore = pronto();
        connettore.queue_search_reply(Ok(pagina(3, "cursore-2")));
        connettore.queue_search_reply(Ok(pagina(0, "")));
        let ricerca = fatta(start(
            Some(&mut connettore as &mut dyn TelegramConnector),
            &mut db,
            &operatore(),
            Branch::AccountChats,
            "ransomware",
            Timestamp::from_millis(ORA),
        ));
        assert_eq!(ricerca.hits.len(), 3);
        assert!(ricerca.hits[0].chat.contains("non fra le fonti"));
        assert!(ricerca.hits[0].who.contains("Persona"));
        assert!(ricerca.can_continue());
        assert!(ricerca.scope_sentence().contains("tranne le segrete"));

        let ricerca = fatta(next(
            Some(&mut connettore as &mut dyn TelegramConnector),
            &mut db,
            &operatore(),
            ricerca,
            Timestamp::from_millis(ORA + 1),
        ));
        assert_eq!(ricerca.hits.len(), 3, "una pagina vuota non aggiunge nulla");
        assert!(
            !ricerca.can_continue(),
            "dopo una pagina vuota non si continua"
        );
        assert_eq!(
            connettore.searched().get(1),
            Some(&SearchQuery::AccountChats {
                query: String::from("ransomware"),
                offset: String::from("cursore-2"),
                limit: 50
            }),
            "la seconda pagina parte dal cursore della prima"
        );
        let Ok(registro) = db.recent_cyber_searches(10) else {
            panic!("il registro deve leggersi");
        };
        assert_eq!(registro.len(), 2, "una riga per pagina");
    }

    /// **Un rifiuto si dice con il testo di Telegram** (criterio 3).
    #[test]
    fn un_rifiuto_si_dice_con_il_testo_di_telegram() {
        let mut db = archivio();
        let mut connettore = pronto();
        connettore.queue_search_reply(Err(TelegramError::Tdlib {
            reason: String::from("errore del componente per Telegram 400: CHANNEL_PRIVATE"),
        }));
        let Ok(chat) = ChatId::try_new(-1009) else {
            panic!("identificativo valido");
        };
        let ricerca = fatta(start(
            Some(&mut connettore as &mut dyn TelegramConnector),
            &mut db,
            &operatore(),
            Branch::InChat(chat),
            "ransomware",
            Timestamp::from_millis(ORA),
        ));
        assert!(ricerca.hits.is_empty());
        assert!(
            ricerca.last_outcome.contains("CHANNEL_PRIVATE"),
            "{}",
            ricerca.last_outcome
        );
        assert!(ricerca.scope_sentence().contains("non \u{e8} verificata"));
    }

    /// **Il tetto orario ferma la ricerca prima di chiedere** (criterio 4;
    /// prova negativa: tetto tolto → rossa).
    #[test]
    fn il_tetto_orario_ferma_la_ricerca() {
        let mut db = archivio();
        let mut connettore = pronto();
        for _ in 0..MAX_PER_HOUR {
            let _ = fatta(start(
                Some(&mut connettore as &mut dyn TelegramConnector),
                &mut db,
                &operatore(),
                Branch::AccountChats,
                "ransomware",
                Timestamp::from_millis(ORA),
            ));
        }
        let chieste = connettore.searched().len();
        let Ok(Attempt::Refused(frase)) = start(
            Some(&mut connettore as &mut dyn TelegramConnector),
            &mut db,
            &operatore(),
            Branch::AccountChats,
            "ransomware",
            Timestamp::from_millis(ORA + 1),
        ) else {
            panic!("oltre il tetto la ricerca non parte");
        };
        assert!(frase.contains("tetto di 30 ricerche"));
        assert_eq!(
            connettore.searched().len(),
            chieste,
            "nulla chiesto oltre il tetto"
        );

        // Il tetto vale per tutti i rami (ADR-0161, decisione 4): la D non
        // chiede nemmeno la quota.
        connettore.queue_limits_reply(Ok(quota(3, true, 0)));
        let Ok(Attempt::Refused(_)) = avvia_d(&mut connettore, &mut db) else {
            panic!("oltre il tetto la D non parte");
        };
        assert!(
            connettore.limits_asked().is_empty(),
            "nessuna quota chiesta"
        );
    }

    /// **Al più 200 risultati per ricerca** (criterio 4).
    #[test]
    fn al_piu_duecento_risultati_per_ricerca() {
        let mut db = archivio();
        let mut connettore = pronto();
        for _ in 0..6 {
            connettore.queue_search_reply(Ok(pagina(50, "ancora")));
        }
        let mut ricerca = fatta(start(
            Some(&mut connettore as &mut dyn TelegramConnector),
            &mut db,
            &operatore(),
            Branch::AccountChats,
            "ransomware",
            Timestamp::from_millis(ORA),
        ));
        while ricerca.can_continue() {
            ricerca = fatta(next(
                Some(&mut connettore as &mut dyn TelegramConnector),
                &mut db,
                &operatore(),
                ricerca,
                Timestamp::from_millis(ORA + 1),
            ));
        }
        assert_eq!(ricerca.hits.len(), MAX_RESULTS);
        assert_eq!(
            connettore.searched().len(),
            4,
            "quattro pagine da cinquanta"
        );
    }

    /// **Il servizio non scrive contenuti, avvisi, Storico** (criterio 6).
    #[test]
    fn il_servizio_non_scrive_contenuti() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]") else {
            panic!("il modulo deve avere le sue prove");
        };
        for scrittura in [
            "insert_content",
            "analyse_and_record",
            "insert_alert",
            "record_content",
            "AcquisitionService",
            "star_count",
        ] {
            assert!(
                !produzione.contains(scrittura),
                "la ricerca chiama «{scrittura}»: i risultati non sono acquisizioni"
            );
        }
        assert_eq!(
            produzione.matches("insert_cyber_search(").count(),
            1,
            "si registra la ricerca, una volta per pagina"
        );
    }
}

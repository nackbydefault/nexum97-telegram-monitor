//! PD-2, parte seconda: che cosa le funzioni rispondono **davvero**.
//!
//! La parte prima ha stabilito che il binario **riconosce** undici funzioni.
//! Riconoscere non e' rispondere, e rispondere non e' rispondere come ci si
//! aspetta: qui si prendono le cinque misure che mancano, e senza le quali
//! ogni pezzo dell'espansione poggerebbe su ipotesi.
//!
//! # Che cosa questo modulo NON contiene
//!
//! **Nessun segreto, e nessun modo di stamparne uno.** Le credenziali le chiede
//! il binario interattivo, restano nel suo perimetro e non attraversano mai
//! queste funzioni. Qui entrano una libreria gia' caricata e un client gia'
//! autorizzato; escono forme, conteggi, limiti e codici di errore.
//!
//! **Nessun contenuto di messaggio.** Le misure riguardano quanti risultati
//! arrivano e come sono fatti, mai che cosa dicono. Un PoC che stampasse il
//! testo dei messaggi trovati sarebbe un PoC che porta fuori dati monitorati.
//!
//! # Le cinque misure
//!
//! 1. la **forma reale** della limitazione, da cui dipende il backoff;
//! 2. i **valori reali** delle quote gratuite di ricerca pubblica;
//! 3. se `searchMessages` **richieda il database dei messaggi** — lo schema non
//!    lo dichiara, e se lo richiedesse cambierebbe l'occupazione su disco del
//!    prodotto;
//! 4. **quanta ampiezza** abbia `searchPublicChats`, che non dichiara limiti;
//! 5. se `searchPublicPosts` restituisca **davvero solo canali**.

use std::collections::BTreeSet;

use crate::error::TelegramResult;
use crate::tdlib::ffi::TdJsonLibrary;
use crate::tdlib::{json_string_value, json_type};

/// Quante volte si interroga la libreria prima di rinunciare a una risposta.
const MAX_POLLS: usize = 600;

/// Attesa di ogni interrogazione, in secondi.
const POLL_TIMEOUT: f64 = 0.05;

/// Quanti risultati si chiedono a una ricerca di misura.
///
/// Non il massimo consentito: la misura serve a vedere **come** risponde, non a
/// raccogliere. Chiedere cento risultati per poi contarli sarebbe consumare
/// quota per niente.
const MEASURE_LIMIT: i32 = 20;

/// I limiti della ricerca pubblica, come Telegram li dichiara.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PublicSearchLimits {
    /// Quante interrogazioni gratuite al giorno.
    pub daily_free: i64,
    /// Quante ne restano oggi.
    pub remaining_free: i64,
    /// Fra quanti secondi la prossima gratuita.
    pub next_free_in: i64,
    /// Quante Stars costerebbe una interrogazione **non** gratuita.
    pub star_cost: i64,
    /// Se **questa** interrogazione non e' a pagamento.
    pub current_is_free: bool,
}

impl PublicSearchLimits {
    /// Se una ricerca puo' partire senza spendere nulla.
    ///
    /// Le due condizioni sono **entrambe** necessarie: una quota residua che non
    /// riguardi questa query non serve, e una query gratuita senza quota non si
    /// puo' fare.
    #[must_use]
    pub const fn free_search_possible(&self) -> bool {
        self.current_is_free && self.remaining_free > 0
    }
}

/// Che cosa una singola misura ha stabilito.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Measure {
    /// La funzione ha risposto, e la misura e' questa.
    Measured(String),
    /// La funzione ha rifiutato, con questo codice e questo messaggio.
    Refused { code: i64, message: String },
    /// La misura **non e' stata tentata**, e questo e' il motivo.
    ///
    /// Distinta dal rifiuto: «non provato» e «provato e negato» sono due cose
    /// diverse, e confonderle farebbe scrivere nel rapporto una conclusione che
    /// nessuno ha verificato.
    NotAttempted(String),
}

impl Measure {
    /// Frase per il rapporto.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Measured(text) => text.clone(),
            Self::Refused { code, message } => format!("RIFIUTATA (errore {code}: {message})"),
            Self::NotAttempted(reason) => format!("NON TENTATA ({reason})"),
        }
    }

    /// Se la misura e' stata presa davvero.
    #[must_use]
    pub const fn was_taken(&self) -> bool {
        matches!(self, Self::Measured(_))
    }
}

/// Esito delle cinque misure.
#[derive(Debug, Clone)]
pub struct LiveProbeReport {
    /// Misura 2: le quote della ricerca pubblica.
    pub limits: Option<PublicSearchLimits>,
    /// Misura 5 e ampiezza: la ricerca nei post pubblici.
    pub public_posts: Measure,
    /// Misura 3: `searchMessages` con il database dei messaggi spento.
    pub account_search: Measure,
    /// Misura 4: quanti risultati da `searchPublicChats`.
    pub public_chats: Measure,
    /// Misura 1: la forma della limitazione, se si e' presentata.
    pub rate_limit: Measure,
}

/// Prende le misure che non richiedono di provocare una limitazione.
///
/// # Errori
///
/// Restituisce un errore se il confine FFI rifiuta una richiesta.
pub fn measure(library: &TdJsonLibrary, client_id: i32) -> TelegramResult<LiveProbeReport> {
    // **Prima di tutto i limiti.** Non e' un ordine casuale: dice se le altre
    // misure si possono fare senza spendere, e risponde senza eseguire alcuna
    // ricerca.
    let limits = read_limits(library, client_id, "sicurezza informatica")?;

    let public_posts = match &limits {
        Some(limits) if limits.free_search_possible() => {
            measure_public_posts(library, client_id, "sicurezza informatica")?
        }
        Some(_) => Measure::NotAttempted(String::from(
            "la ricerca non risulta gratuita nei limiti correnti: non si spende",
        )),
        None => Measure::NotAttempted(String::from(
            "i limiti non sono leggibili: senza sapere se è gratuita, non si cerca",
        )),
    };

    let account_search = measure_account_search(library, client_id)?;
    let public_chats = measure_public_chats(library, client_id, "sicurezza")?;

    Ok(LiveProbeReport {
        limits,
        public_posts,
        account_search,
        public_chats,
        // La forma della limitazione si misura solo se qualcuno chiede di
        // provocarla: vedere `provoke_rate_limit`.
        rate_limit: Measure::NotAttempted(String::from(
            "non provocata: richiede una scelta esplicita dell'operatore",
        )),
    })
}

/// Interroga i limiti della ricerca pubblica.
fn read_limits(
    library: &TdJsonLibrary,
    client_id: i32,
    query: &str,
) -> TelegramResult<Option<PublicSearchLimits>> {
    let request = format!(
        r#"{{"@extra":"limiti","@type":"getPublicPostSearchLimits","query":"{}"}}"#,
        escape(query)
    );
    library.send(client_id, &request)?;
    let Some(response) = await_tagged(library, "limiti")? else {
        return Ok(None);
    };
    if json_type(&response).as_deref() == Some("error") {
        return Ok(None);
    }

    Ok(Some(PublicSearchLimits {
        daily_free: number(&response, "daily_free_query_count").unwrap_or(0),
        remaining_free: number(&response, "remaining_free_query_count").unwrap_or(0),
        next_free_in: number(&response, "next_free_query_in").unwrap_or(0),
        star_cost: number(&response, "star_count").unwrap_or(0),
        current_is_free: response.contains(r#""is_current_query_free":true"#),
    }))
}

/// Misura 5: la ricerca nei post pubblici.
///
/// **`star_count` vale zero**, come vale zero in ogni punto del prodotto.
fn measure_public_posts(
    library: &TdJsonLibrary,
    client_id: i32,
    query: &str,
) -> TelegramResult<Measure> {
    let request = format!(
        concat!(
            r#"{{"@extra":"post","@type":"searchPublicPosts","query":"{}","#,
            r#""offset":"","limit":{},"star_count":0}}"#
        ),
        escape(query),
        MEASURE_LIMIT
    );
    library.send(client_id, &request)?;

    let Some(response) = await_tagged(library, "post")? else {
        return Ok(Measure::NotAttempted(String::from(
            "nessuna risposta entro l'attesa",
        )));
    };
    if let Some(refused) = as_refusal(&response) {
        return Ok(refused);
    }

    let quanti = count_occurrences(&response, r#""@type":"message""#);
    let chat_ids = distinct_chat_ids(&response);
    let next_offset = json_string_value(&response, "next_offset").unwrap_or_default();
    let limiti_superati = response.contains(r#""are_limits_exceeded":true"#);

    Ok(Measure::Measured(format!(
        "chiesti {MEASURE_LIMIT}, ricevuti {quanti} messaggi da {} chat distinte; \
         paginazione {}; limiti superati: {}",
        chat_ids.len(),
        if next_offset.is_empty() {
            String::from("esaurita (offset successivo vuoto)")
        } else {
            String::from("disponibile (offset successivo presente)")
        },
        if limiti_superati { "SI" } else { "no" }
    )))
}

/// Misura 3: `searchMessages` con il database dei messaggi spento.
///
/// Lo schema **non dichiara** che serva. Se lo richiedesse, il prodotto
/// dovrebbe accendere il database dei messaggi, e l'occupazione su disco di
/// ogni postazione cambierebbe.
fn measure_account_search(library: &TdJsonLibrary, client_id: i32) -> TelegramResult<Measure> {
    let request = concat!(
        r#"{"@extra":"conto","@type":"searchMessages","chat_list":null,"#,
        r#""query":"a","offset":"","limit":10,"filter":null,"#,
        r#""chat_type_filter":null,"min_date":0,"max_date":0}"#
    );
    library.send(client_id, request)?;

    let Some(response) = await_tagged(library, "conto")? else {
        return Ok(Measure::NotAttempted(String::from(
            "nessuna risposta entro l'attesa",
        )));
    };
    if let Some(refused) = as_refusal(&response) {
        return Ok(refused);
    }

    let quanti = count_occurrences(&response, r#""@type":"message""#);
    Ok(Measure::Measured(format!(
        "ha risposto con il database dei messaggi SPENTO: {quanti} messaggi. \
         Il prodotto non deve accenderlo per cercare nelle chat dell'account"
    )))
}

/// Misura 4: quanti risultati restituisce `searchPublicChats`.
///
/// Non dichiara ne' limite ne' paginazione: e' la superficie di cui non
/// sappiamo dire l'ampiezza, e questo numero e' l'unico modo di stimarla.
fn measure_public_chats(
    library: &TdJsonLibrary,
    client_id: i32,
    query: &str,
) -> TelegramResult<Measure> {
    let request = format!(
        r#"{{"@extra":"chat","@type":"searchPublicChats","query":"{}","type_filter":null}}"#,
        escape(query)
    );
    library.send(client_id, &request)?;

    let Some(response) = await_tagged(library, "chat")? else {
        return Ok(Measure::NotAttempted(String::from(
            "nessuna risposta entro l'attesa",
        )));
    };
    if let Some(refused) = as_refusal(&response) {
        return Ok(refused);
    }

    let dichiarati = number(&response, "total_count").unwrap_or(-1);
    let identificativi = count_occurrences(&response, ",");
    Ok(Measure::Measured(format!(
        "totale dichiarato {dichiarati}; l'elenco restituito contiene circa \
         {identificativi} identificativi. Nessun limite e nessuna paginazione \
         sono offerti: questa è tutta l'ampiezza disponibile"
    )))
}

/// Misura 1: provoca deliberatamente una limitazione e ne registra la forma.
///
/// # Perche' e' separata e non entra in [`measure`]
///
/// Perche' **costa**. Provocare una limitazione su un account d'ufficio
/// significa renderlo temporaneamente meno utilizzabile, e non e' una decisione
/// che uno strumento di misura possa prendere per conto proprio. Si chiama solo
/// se qualcuno la chiede sapendo che cosa comporta.
///
/// # Errori
///
/// Restituisce un errore se il confine FFI rifiuta una richiesta.
pub fn provoke_rate_limit(
    library: &TdJsonLibrary,
    client_id: i32,
    attempts: usize,
) -> TelegramResult<Measure> {
    for tentativo in 0..attempts {
        // Query **distinte**: ripetere la stessa sarebbe gratuito e non
        // consumerebbe quota, quindi non provocherebbe nulla.
        let request = format!(
            concat!(
                r#"{{"@extra":"limite-{}","@type":"searchPublicPosts","#,
                r#""query":"misura limite {}","offset":"","limit":1,"star_count":0}}"#
            ),
            tentativo, tentativo
        );
        library.send(client_id, &request)?;

        let etichetta = format!("limite-{tentativo}");
        let Some(response) = await_tagged(library, &etichetta)? else {
            continue;
        };

        if json_type(&response).as_deref() == Some("error") {
            let code = number(&response, "code").unwrap_or(0);
            let message = json_string_value(&response, "message").unwrap_or_default();
            return Ok(Measure::Measured(format!(
                "limitazione dopo {} interrogazioni: errore {code} — «{message}»",
                tentativo + 1
            )));
        }
        if response.contains(r#""are_limits_exceeded":true"#) {
            return Ok(Measure::Measured(format!(
                "quota esaurita dopo {} interrogazioni, dichiarata dal risultato \
                 con `are_limits_exceeded` e non da un errore",
                tentativo + 1
            )));
        }
    }

    Ok(Measure::NotAttempted(format!(
        "{attempts} interrogazioni non hanno provocato alcuna limitazione"
    )))
}

/// Attende la risposta con l'etichetta indicata, scartando gli aggiornamenti.
fn await_tagged(library: &TdJsonLibrary, tag: &str) -> TelegramResult<Option<String>> {
    for _ in 0..MAX_POLLS {
        let Some(message) = library.receive(POLL_TIMEOUT)? else {
            continue;
        };
        if json_string_value(&message, "@extra").as_deref() == Some(tag) {
            return Ok(Some(message));
        }
    }
    Ok(None)
}

/// Se la risposta e' un errore, la traduce in una misura rifiutata.
fn as_refusal(response: &str) -> Option<Measure> {
    if json_type(response).as_deref() != Some("error") {
        return None;
    }
    Some(Measure::Refused {
        code: number(response, "code").unwrap_or(0),
        message: json_string_value(response, "message").unwrap_or_default(),
    })
}

/// Quante volte una sequenza compare nel testo.
fn count_occurrences(haystack: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    haystack.matches(needle).count()
}

/// Gli identificativi di chat distinti citati nella risposta.
///
/// Serve a dire da **quante** fonti diverse vengono i risultati, che e' la
/// misura utile: cento messaggi da una chat sola e cento da cento chat sono due
/// risposte molto diverse.
fn distinct_chat_ids(response: &str) -> BTreeSet<i64> {
    let mut ids = BTreeSet::new();
    let needle = r#""chat_id":"#;
    let mut rest = response;
    while let Some(at) = rest.find(needle) {
        rest = &rest[at + needle.len()..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit() && c != '-')
            .unwrap_or(rest.len());
        if let Ok(id) = rest[..end].parse::<i64>() {
            ids.insert(id);
        }
    }
    ids
}

/// Estrae un intero da un oggetto JSON piatto.
fn number(json: &str, key: &str) -> Option<i64> {
    let needle = format!("\"{key}\":");
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit() && c != '-')
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// Rende un testo sicuro dentro una stringa JSON.
///
/// Le query di misura sono scritte da noi, ma passano comunque di qui: una
/// funzione che costruisce JSON per concatenazione e non protegge le virgolette
/// e' una funzione che aspetta il giorno in cui qualcuno le passa un testo che
/// non ha scritto lui.
fn escape(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .flat_map(|c| match c {
            '"' => vec!['\\', '"'],
            '\\' => vec!['\\', '\\'],
            other => vec![other],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_free_search_needs_both_conditions() {
        // Una quota residua che non riguarda questa query non serve, e una
        // query gratuita senza quota non si puo' fare.
        let entrambe = PublicSearchLimits {
            current_is_free: true,
            remaining_free: 3,
            ..PublicSearchLimits::default()
        };
        assert!(entrambe.free_search_possible());

        let senza_quota = PublicSearchLimits {
            current_is_free: true,
            remaining_free: 0,
            ..PublicSearchLimits::default()
        };
        assert!(!senza_quota.free_search_possible());

        let a_pagamento = PublicSearchLimits {
            current_is_free: false,
            remaining_free: 10,
            ..PublicSearchLimits::default()
        };
        assert!(!a_pagamento.free_search_possible());
    }

    #[test]
    fn a_measure_not_attempted_is_not_a_measure_taken() {
        // **La distinzione che impedisce di scrivere una conclusione che
        // nessuno ha verificato.** «Non provato» e «provato e negato» sono due
        // cose diverse, e nel rapporto non devono somigliarsi.
        assert!(!Measure::NotAttempted(String::from("x")).was_taken());
        assert!(
            !Measure::Refused {
                code: 429,
                message: String::from("Too Many Requests")
            }
            .was_taken()
        );
        assert!(Measure::Measured(String::from("x")).was_taken());
    }

    #[test]
    fn a_refusal_carries_its_code_and_message() {
        let rifiuto = as_refusal(r#"{"@type":"error","code":429,"message":"Too Many Requests"}"#)
            .expect("un errore deve produrre un rifiuto");
        assert_eq!(
            rifiuto,
            Measure::Refused {
                code: 429,
                message: String::from("Too Many Requests")
            }
        );
        assert!(as_refusal(r#"{"@type":"chats","total_count":3}"#).is_none());
    }

    #[test]
    fn distinct_chats_are_counted_once_each() {
        // Cento messaggi da una chat sola e cento da cento chat sono due
        // risposte molto diverse, e il rapporto deve poterle distinguere.
        let risposta = r#"{"messages":[{"chat_id":10},{"chat_id":10},{"chat_id":-42}]}"#;
        let ids = distinct_chat_ids(risposta);
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&10));
        assert!(ids.contains(&-42));
    }

    #[test]
    fn a_query_cannot_break_out_of_its_json_string() {
        // L'invariante vera non e' «la sequenza pericolosa sparisce»: e' che
        // **ogni virgoletta sia preceduta da una barra**. La prima stesura di
        // questa prova cercava la sequenza e falliva su un testo protetto
        // correttamente — cercava il sintomo invece della proprieta'.
        let cattiva = escape(r#"prova" ,"star_count":5000,"x":"#);

        let mut precedente = '\0';
        for carattere in cattiva.chars() {
            if carattere == '"' {
                assert_eq!(
                    precedente, '\\',
                    "una virgoletta non protetta esce dalla stringa: {cattiva}"
                );
            }
            // Una barra gia' protetta non protegge la virgoletta che segue.
            precedente = if precedente == '\\' && carattere == '\\' {
                '\0'
            } else {
                carattere
            };
        }
        assert!(cattiva.starts_with("prova\\\""));
    }

    #[test]
    fn control_characters_never_reach_the_request() {
        assert_eq!(escape("prima\nseconda\u{0}terza"), "primasecondaterza");
    }

    #[test]
    fn the_numbers_are_read_from_the_response() {
        let risposta = r#"{"daily_free_query_count":5,"remaining_free_query_count":0,"next_free_query_in":3600,"star_count":10,"is_current_query_free":true}"#;
        assert_eq!(number(risposta, "daily_free_query_count"), Some(5));
        assert_eq!(number(risposta, "remaining_free_query_count"), Some(0));
        assert_eq!(number(risposta, "next_free_query_in"), Some(3600));
        assert_eq!(number(risposta, "assente"), None);
    }
}

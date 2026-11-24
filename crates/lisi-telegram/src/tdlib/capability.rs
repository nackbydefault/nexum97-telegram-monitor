//! PD-2, parte prima: quali funzioni il **binario** riconosce.
//!
//! # Che cosa risponde, e che cosa non risponde
//!
//! La matrice di PD-1 ha letto lo **schema** del commit bloccato e ha stabilito
//! che undici funzioni esistono. Questa sonda verifica la stessa cosa sul
//! **binario realmente distribuito**, che e' un'affermazione piu' forte: lo
//! schema descrive cio' che il sorgente dichiara, la DLL e' cio' che gira.
//!
//! **Non** risponde alla domanda «la funzione funziona»: quella richiede un
//! account, ed e' la parte seconda di PD-2.
//!
//! # Perche' si puo' eseguire senza credenziali e senza rete
//!
//! TDLib valida il **tipo** della richiesta prima di guardare lo stato di
//! autorizzazione. Una funzione che non conosce produce un errore di richiesta
//! non valida; una che conosce, chiamata da un client non autorizzato, produce
//! un errore di autorizzazione.
//!
//! I due errori sono distinguibili, e la distinzione **e' la misura**. La rete
//! resta spenta come nel collaudo esistente, e le credenziali sono fittizie:
//! nessuna richiesta lascia la macchina.
//!
//! # Perche' non si usa `td_execute`
//!
//! `td_execute` serve un piccolo insieme di funzioni sincrone e rifiuta tutto
//! il resto **allo stesso modo**, che la funzione esista o no: userebbe un
//! canale che non sa distinguere cio' che questa sonda deve distinguere.

use std::collections::BTreeMap;
use std::path::Path;

use crate::error::TelegramResult;
use crate::tdlib::ffi::TdJsonLibrary;
use crate::tdlib::{json_string_value, json_type};

/// Le funzioni che l'espansione Public Discovery richiede.
///
/// L'ordine e' quello della matrice di PD-1, cosi' che i due documenti si
/// leggano affiancati. Ogni voce porta la richiesta minima ben formata: i
/// valori sono segnaposto, e non devono essere validi — deve essere valido il
/// **tipo**, che e' cio' che si sta misurando.
const PROBES: &[(&str, &str)] = &[
    (
        "searchMessages",
        r#"{"@type":"searchMessages","chat_list":null,"query":"prova","offset":"","limit":1,"filter":null,"chat_type_filter":null,"min_date":0,"max_date":0}"#,
    ),
    (
        "searchChatMessages",
        r#"{"@type":"searchChatMessages","chat_id":1,"topic_id":null,"query":"prova","sender_id":null,"from_message_id":0,"offset":0,"limit":1,"filter":null}"#,
    ),
    (
        "searchPublicChat",
        r#"{"@type":"searchPublicChat","username":"prova"}"#,
    ),
    (
        "searchPublicChats",
        r#"{"@type":"searchPublicChats","query":"prova","type_filter":null}"#,
    ),
    (
        // **La funzione che merita piu' attenzione di tutte.** `star_count` e'
        // l'unico parametro economico del prodotto, e qui vale zero come
        // varra' sempre.
        "searchPublicPosts",
        r#"{"@type":"searchPublicPosts","query":"prova","offset":"","limit":1,"star_count":0}"#,
    ),
    (
        "getPublicPostSearchLimits",
        r#"{"@type":"getPublicPostSearchLimits","query":"prova"}"#,
    ),
    (
        "getChatSimilarChats",
        r#"{"@type":"getChatSimilarChats","chat_id":1}"#,
    ),
    (
        "getChatSimilarChatCount",
        r#"{"@type":"getChatSimilarChatCount","chat_id":1,"return_local":true}"#,
    ),
    (
        "getChats",
        r#"{"@type":"getChats","chat_list":null,"limit":1}"#,
    ),
    (
        "loadChats",
        r#"{"@type":"loadChats","chat_list":null,"limit":1}"#,
    ),
    (
        // Presente nello schema ma non richiesta dalla v1: si misura per
        // completezza, cosi' che la matrice non abbia buchi.
        "searchPublicMessagesByTag",
        r##"{"@type":"searchPublicMessagesByTag","tag":"#prova","offset":"","limit":1}"##,
    ),
    (
        // **Il controllo negativo.** Un nome che non puo' esistere: se questo
        // risultasse riconosciuto, la sonda non starebbe misurando nulla e
        // ogni riga sopra sarebbe priva di significato.
        "questaFunzioneNonEsisteDavvero",
        r#"{"@type":"questaFunzioneNonEsisteDavvero","query":"prova"}"#,
    ),
];

/// Nome del controllo negativo, che deve risultare sconosciuto.
pub const NEGATIVE_CONTROL: &str = "questaFunzioneNonEsisteDavvero";

/// Quante volte si interroga la libreria prima di rinunciare a una risposta.
const MAX_POLLS_PER_PROBE: usize = 200;

/// Attesa di ogni singola interrogazione, in secondi.
const POLL_TIMEOUT: f64 = 0.05;

/// Che cosa il binario ha risposto su una funzione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// Il binario **conosce** la funzione: l'errore riguarda l'autorizzazione o
    /// i parametri, non il tipo della richiesta.
    Recognised {
        /// Codice restituito.
        code: i64,
        /// Messaggio restituito, utile a distinguere i motivi.
        message: String,
    },
    /// Il binario **non conosce** la funzione.
    Unknown {
        /// Messaggio con cui l'ha rifiutata.
        message: String,
    },
    /// La funzione ha risposto senza errore. Non atteso da un client non
    /// autorizzato, ma non impossibile per le funzioni puramente locali.
    Answered {
        /// Tipo dell'oggetto restituito.
        kind: String,
    },
    /// Nessuna risposta entro l'attesa. **Non e' un esito**: e' l'assenza di un
    /// esito, e va distinta da «sconosciuta».
    NoAnswer,
}

impl Capability {
    /// Se il binario riconosce la funzione, comunque abbia risposto.
    #[must_use]
    pub const fn is_recognised(&self) -> bool {
        matches!(self, Self::Recognised { .. } | Self::Answered { .. })
    }

    /// Frase per il rapporto.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Recognised { code, message } => {
                format!("riconosciuta (errore {code}: {message})")
            }
            Self::Unknown { message } => format!("SCONOSCIUTA ({message})"),
            Self::Answered { kind } => format!("riconosciuta e ha risposto ({kind})"),
            Self::NoAnswer => String::from("nessuna risposta entro l'attesa"),
        }
    }
}

/// Esito della sonda.
#[derive(Debug, Clone)]
pub struct CapabilityReport {
    /// Versione dichiarata dalla libreria caricata.
    pub tdlib_version: Option<String>,
    /// Una voce per funzione, in ordine di nome.
    pub capabilities: BTreeMap<String, Capability>,
}

impl CapabilityReport {
    /// Se il controllo negativo si e' comportato come deve.
    ///
    /// Senza questo, un esito in cui **tutto** risulta riconosciuto sarebbe
    /// indistinguibile da una sonda che non misura nulla.
    #[must_use]
    pub fn negative_control_holds(&self) -> bool {
        matches!(
            self.capabilities.get(NEGATIVE_CONTROL),
            Some(Capability::Unknown { .. })
        )
    }

    /// Le funzioni richieste dall'espansione che il binario non riconosce.
    #[must_use]
    pub fn missing(&self) -> Vec<&str> {
        self.capabilities
            .iter()
            .filter(|(name, capability)| {
                name.as_str() != NEGATIVE_CONTROL && !capability.is_recognised()
            })
            .map(|(name, _)| name.as_str())
            .collect()
    }
}

/// Interroga il binario su ogni funzione dell'espansione.
///
/// # Errori
///
/// Restituisce un errore se la libreria non si carica o se il confine FFI
/// rifiuta una richiesta.
pub fn run_capability_probe(library_path: &Path) -> TelegramResult<CapabilityReport> {
    let library = TdJsonLibrary::load(library_path)?;

    // Nessun registro della libreria sullo standard error: la sonda stampa il
    // proprio rapporto e nient'altro.
    let _ = library.execute(r#"{"@type":"setLogVerbosityLevel","new_verbosity_level":0}"#)?;

    let tdlib_version = library
        .execute(r#"{"@type":"getOption","name":"version"}"#)?
        .as_deref()
        .and_then(|response| json_string_value(response, "value"));

    let client_id = library.create_client_id()?;

    // **La rete resta spenta.** E' la stessa scelta del collaudo esistente, e
    // qui vale doppio: la sonda deve poter girare su qualunque macchina senza
    // che nulla parta verso Telegram.
    library.send(
        client_id,
        r#"{"@type":"setNetworkType","type":{"@type":"networkTypeNone"}}"#,
    )?;

    let mut capabilities = BTreeMap::new();
    for (index, (name, request)) in PROBES.iter().enumerate() {
        let tagged = tag_request(request, index);
        library.send(client_id, &tagged)?;
        capabilities.insert((*name).to_owned(), collect_answer(&library, index)?);
    }

    Ok(CapabilityReport {
        tdlib_version,
        capabilities,
    })
}

/// Aggiunge alla richiesta l'etichetta che TDLib restituisce nella risposta.
///
/// Serve a **non confondere le risposte fra loro**: le risposte arrivano da una
/// coda unica e non necessariamente nell'ordine in cui le richieste sono
/// partite. Senza etichetta, una risposta lenta verrebbe attribuita alla
/// funzione sbagliata, e il rapporto direbbe una cosa per un'altra.
fn tag_request(request: &str, index: usize) -> String {
    let Some(rest) = request.strip_prefix('{') else {
        return request.to_owned();
    };
    format!("{{\"@extra\":\"sonda-{index}\",{rest}")
}

/// Raccoglie la risposta con l'etichetta attesa, scartando gli aggiornamenti.
fn collect_answer(library: &TdJsonLibrary, index: usize) -> TelegramResult<Capability> {
    let expected = format!("sonda-{index}");

    for _ in 0..MAX_POLLS_PER_PROBE {
        let Some(message) = library.receive(POLL_TIMEOUT)? else {
            continue;
        };
        // Gli aggiornamenti spontanei della libreria non portano l'etichetta:
        // si scartano senza guardarli.
        if json_string_value(&message, "@extra").as_deref() != Some(expected.as_str()) {
            continue;
        }
        return Ok(classify(&message));
    }
    Ok(Capability::NoAnswer)
}

/// Distingue «non conosco questa funzione» da «non sei autorizzato».
///
/// # Perche' si guarda il messaggio e non solo il codice
///
/// Perche' TDLib usa il codice **400** sia per una richiesta malformata sia per
/// un tipo sconosciuto: il codice da solo non separa i due casi. Il messaggio
/// lo fa, ed e' l'unica via che la libreria offre.
fn classify(message: &str) -> Capability {
    if json_type(message).as_deref() != Some("error") {
        return Capability::Answered {
            kind: json_type(message).unwrap_or_else(|| String::from("sconosciuto")),
        };
    }

    let text = json_string_value(message, "message").unwrap_or_default();
    let code = json_number_value(message, "code").unwrap_or(0);

    // **La formula vera, misurata e non supposta.** Alla prima esecuzione
    // questo elenco conteneva cinque frasi plausibili e nessuna era quella
    // giusta: TDLib 1.8.66 rifiuta un tipo che non conosce con
    //
    //     Failed to parse JSON object as TDLib request: Unknown class "..."
    //
    // Il controllo negativo ha colto l'errore al primo colpo — la funzione
    // inventata risultava «riconosciuta» — ed e' esattamente la ragione per cui
    // esiste: senza, il rapporto avrebbe dichiarato disponibili undici funzioni
    // con la stessa autorevolezza con cui dichiarava disponibile una che non
    // esiste.
    //
    // `Unknown class` e' la formula precisa e nomina la classe rifiutata: un
    // parametro sbagliato su una funzione vera produce un messaggio diverso, e
    // non verrebbe scambiato per assenza. Le altre frasi restano come rete di
    // sicurezza per versioni che dovessero usarne un'altra.
    let unknown = text.contains("Unknown class")
        || text.contains("Unknown request")
        || text.contains("Unknown function")
        || text.contains("Wrong request type")
        || text.contains("Unsupported request");

    if unknown {
        Capability::Unknown { message: text }
    } else {
        Capability::Recognised {
            code,
            message: text,
        }
    }
}

/// Estrae un valore numerico da un oggetto JSON piatto.
///
/// Il modulo ne ha gia' uno per le stringhe; questo serve al codice di errore.
fn json_number_value(json: &str, key: &str) -> Option<i64> {
    let needle = format!("\"{key}\":");
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    let end = rest
        .find(|character: char| !character.is_ascii_digit() && character != '-')
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_probe_is_well_formed_json_with_a_type() {
        // Una richiesta malformata verrebbe rifiutata come «non analizzabile»,
        // e la sonda registrerebbe «sconosciuta» per una funzione che invece
        // esiste: il rapporto direbbe il falso.
        for (name, request) in PROBES {
            assert!(request.starts_with('{'), "«{name}» non e' un oggetto JSON");
            assert!(request.ends_with('}'), "«{name}» non e' chiuso");
            assert!(
                request.contains(&format!("\"@type\":\"{name}\"")),
                "«{name}» non dichiara il proprio tipo"
            );
        }
    }

    #[test]
    fn no_probe_ever_offers_to_pay() {
        // **Il test negativo del mandato, alla sua prima occasione.** Nessuna
        // richiesta della sonda puo' proporre un pagamento, e l'unica che ha un
        // parametro economico deve portare zero.
        for (name, request) in PROBES {
            assert!(
                !request.contains("\"star_count\":") || request.contains("\"star_count\":0"),
                "la sonda «{name}» propone una spesa"
            );
        }
        let pubblica = PROBES
            .iter()
            .find(|(name, _)| *name == "searchPublicPosts")
            .expect("la sonda sulla ricerca pubblica deve esistere");
        assert!(
            pubblica.1.contains("\"star_count\":0"),
            "la ricerca pubblica non dichiara zero Stars"
        );
    }

    #[test]
    fn the_probe_set_covers_the_capability_matrix() {
        let nomi: Vec<&str> = PROBES.iter().map(|(name, _)| *name).collect();
        for richiesta in [
            "searchMessages",
            "searchChatMessages",
            "searchPublicChat",
            "searchPublicChats",
            "searchPublicPosts",
            "getPublicPostSearchLimits",
            "getChatSimilarChats",
            "getChatSimilarChatCount",
            "getChats",
            "loadChats",
        ] {
            assert!(nomi.contains(&richiesta), "manca la sonda su «{richiesta}»");
        }
        assert!(
            nomi.contains(&NEGATIVE_CONTROL),
            "manca il controllo negativo: senza, la sonda non dimostrerebbe di misurare"
        );
    }

    #[test]
    fn the_tag_survives_and_does_not_break_the_request() {
        let etichettata = tag_request(r#"{"@type":"getChats","limit":1}"#, 3);
        assert!(etichettata.starts_with('{'));
        assert!(etichettata.contains(r#""@extra":"sonda-3""#));
        assert!(etichettata.contains(r#""@type":"getChats""#));
        assert!(etichettata.ends_with('}'));
    }

    #[test]
    fn an_unknown_type_is_told_apart_from_a_refused_authorization() {
        let sconosciuta = classify(
            r#"{"@type":"error","code":400,"message":"Unknown request type","@extra":"sonda-0"}"#,
        );
        assert!(matches!(sconosciuta, Capability::Unknown { .. }));
        assert!(!sconosciuta.is_recognised());

        let non_autorizzata =
            classify(r#"{"@type":"error","code":401,"message":"Unauthorized","@extra":"sonda-1"}"#);
        assert!(non_autorizzata.is_recognised());
        assert!(matches!(
            non_autorizzata,
            Capability::Recognised { code: 401, .. }
        ));
    }

    #[test]
    fn the_real_refusal_of_tdlib_1_8_66_is_recognised_as_such() {
        // **Misurata, non supposta.** E' la risposta letterale della libreria
        // distribuita, copiata dall'esecuzione del 2026-08-18. Il primo elenco
        // di formule non la conteneva, e la sonda dichiarava riconosciuta una
        // funzione inventata.
        let reale = classify(
            r#"{"@type":"error","code":400,"message":"Failed to parse JSON object as TDLib request: Unknown class \"questaFunzioneNonEsisteDavvero\"","@extra":"sonda-11"}"#,
        );
        assert!(
            matches!(reale, Capability::Unknown { .. }),
            "la formula reale di rifiuto non e' riconosciuta come tale: {}",
            reale.describe()
        );
    }

    #[test]
    fn a_function_that_exists_but_is_not_initialised_counts_as_recognised() {
        // L'altra meta' della misura, anch'essa letterale: e' cosi' che la
        // libreria risponde per una funzione che conosce, su un client non
        // ancora inizializzato.
        let vera = classify(
            r#"{"@type":"error","code":400,"message":"Initialization parameters are needed: call setTdlibParameters first","@extra":"sonda-0"}"#,
        );
        assert!(
            vera.is_recognised(),
            "una funzione esistente e' stata scambiata per assente: {}",
            vera.describe()
        );
    }

    #[test]
    fn a_successful_answer_counts_as_recognised() {
        let risposta = classify(r#"{"@type":"chats","total_count":0,"@extra":"sonda-2"}"#);
        assert!(risposta.is_recognised());
    }

    #[test]
    fn a_missing_answer_is_not_an_absent_function() {
        // Sono due cose diverse, e confonderle farebbe dichiarare mancante una
        // funzione che c'e'.
        assert!(!Capability::NoAnswer.is_recognised());
        assert!(!matches!(Capability::NoAnswer, Capability::Unknown { .. }));
    }

    #[test]
    fn the_negative_control_decides_whether_the_report_means_anything() {
        let mut capabilities = BTreeMap::new();
        capabilities.insert(
            String::from(NEGATIVE_CONTROL),
            Capability::Unknown {
                message: String::from("Unknown request type"),
            },
        );
        let buono = CapabilityReport {
            tdlib_version: None,
            capabilities,
        };
        assert!(buono.negative_control_holds());

        let mut capabilities = BTreeMap::new();
        capabilities.insert(
            String::from(NEGATIVE_CONTROL),
            Capability::Recognised {
                code: 401,
                message: String::from("Unauthorized"),
            },
        );
        let sospetto = CapabilityReport {
            tdlib_version: None,
            capabilities,
        };
        assert!(
            !sospetto.negative_control_holds(),
            "un controllo negativo riconosciuto significa che la sonda non misura"
        );
    }

    #[test]
    fn the_error_code_is_read_from_the_response() {
        assert_eq!(
            json_number_value(r#"{"@type":"error","code":401,"message":"x"}"#, "code"),
            Some(401)
        );
        assert_eq!(
            json_number_value(r#"{"@type":"error","code":-5,"message":"x"}"#, "code"),
            Some(-5)
        );
        assert_eq!(json_number_value(r#"{"@type":"ok"}"#, "code"), None);
    }
}

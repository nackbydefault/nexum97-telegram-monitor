//! Proof of concept che carica realmente TDLib.
//!
//! Compilato soltanto con la feature `tdlib-runtime`. Lo scopo è dimostrare che
//! il confine FFI regge contro la libreria vera, non simulare un accesso: non
//! esiste alcuna credenziale, e la rete è **disattivata a livello di libreria**
//! prima di qualunque altra operazione.
//!
//! Le risposte sono ispezionate con semplici ricerche testuali e non con un
//! parser JSON: in questa milestone servono poche verifiche puntuali, e
//! introdurre una dipendenza di deserializzazione per esse sarebbe superficie
//! non giustificata. La tipizzazione dell'API arriva con la milestone che
//! introduce l'accesso all'account.

pub mod capability;
pub mod ffi;
pub mod live;
pub mod live_probe;
pub mod router;

pub use self::capability::{Capability, CapabilityReport, run_capability_probe};
pub use self::live::LiveTdlibConnector;

use std::path::{Path, PathBuf};

use crate::error::{TelegramError, TelegramResult};
use crate::tdlib::ffi::TdJsonLibrary;

/// Valori dichiaratamente fittizi usati dal proof of concept.
///
/// Non sono credenziali: con la rete disattivata non vengono mai trasmessi, e
/// servono solo perché `setTdlibParameters` esige i campi valorizzati.
const FICTITIOUS_API_ID: i32 = 1;
const FICTITIOUS_API_HASH: &str = "00000000000000000000000000000000";
/// Chiave di prova in base64, sedici byte da 0x00 a 0x0F.
const FICTITIOUS_DATABASE_KEY: &str = "AAECAwQFBgcICQoLDA0ODw==";

/// Testo non ASCII usato per verificare il giro completo attraverso la FFI.
///
/// Contiene lettere accentate, un carattere cirillico e un'emoji fuori dal
/// piano base: se il confine perdesse o alterasse byte, il confronto fallirebbe.
const NON_ASCII_PROBE: &str = "caffè è ok — Ж — \u{1F600}";

/// Numero massimo di attese durante una fase, per non restare bloccati.
const MAX_POLLS: usize = 400;

/// Esito della verifica del confine FFI contro la libreria reale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmokeTestReport {
    /// Percorso della libreria realmente caricata.
    pub library_path: PathBuf,
    /// Identificativo opaco del client creato.
    pub client_id: i32,
    /// Versione riportata dalla libreria.
    pub tdlib_version: Option<String>,
    /// Una richiesta con un byte NUL interno è stata rifiutata prima della FFI.
    pub interior_nul_rejected: bool,
    /// Un testo non ASCII ha attraversato il confine e ne è tornato integro.
    pub non_ascii_round_trip: bool,
    /// Testo realmente restituito dalla prova non ASCII.
    ///
    /// Conservato perché un fallimento sia diagnosticabile senza rieseguire:
    /// mostra se il testo sia stato alterato o se la richiesta sia stata
    /// rifiutata del tutto.
    pub non_ascii_returned: Option<String>,
    /// `td_receive` ha restituito un puntatore nullo allo scadere dell'attesa.
    pub null_on_timeout: bool,
    /// Il database locale è stato aperto: è il percorso che usa PBKDF2.
    pub local_database_opened: bool,
    /// Stati di autorizzazione osservati, in ordine.
    pub authorization_states: Vec<String>,
    /// Aggiornamenti ricevuti complessivamente.
    pub updates_received: usize,
    /// La chiusura ordinata è stata confermata dalla libreria.
    pub closed_orderly: bool,
}

impl SmokeTestReport {
    /// Se ogni verifica prevista è riuscita.
    #[must_use]
    pub fn is_fully_successful(&self) -> bool {
        self.tdlib_version.is_some()
            && self.interior_nul_rejected
            && self.non_ascii_round_trip
            && self.null_on_timeout
            && self.local_database_opened
            && self.closed_orderly
    }
}

/// Estrae il valore testuale di una chiave da una risposta JSON, decodificando
/// le sequenze di escape.
///
/// La decodifica degli escape **non è un dettaglio**: TDLib codifica ogni
/// carattere non ASCII nella forma `\uXXXX`, e le emoji come coppia surrogata.
/// Una versione precedente di questa funzione si limitava a scartare la barra
/// rovesciata, e restituiva `caffu00e8` al posto di `caffè`. Il difetto è emerso
/// soltanto eseguendo la verifica contro la libreria reale.
///
/// Restituisce `None` se il valore non è terminato o contiene una sequenza di
/// escape non valida: un dato malformato non viene indovinato.
#[must_use]
pub fn json_string_value(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = json.find(&needle)? + needle.len();
    unescape_json_string(json.get(start..)?)
}

/// Decodifica il corpo di una stringa JSON fino alla virgoletta di chiusura.
fn unescape_json_string(rest: &str) -> Option<String> {
    let mut characters = rest.chars();
    let mut value = String::new();

    while let Some(character) = characters.next() {
        match character {
            '"' => return Some(value),
            '\\' => {
                let escape = characters.next()?;
                match escape {
                    '"' => value.push('"'),
                    '\\' => value.push('\\'),
                    '/' => value.push('/'),
                    'b' => value.push('\u{8}'),
                    'f' => value.push('\u{c}'),
                    'n' => value.push('\n'),
                    'r' => value.push('\r'),
                    't' => value.push('\t'),
                    'u' => value.push(read_escaped_code_point(&mut characters)?),
                    _ => return None,
                }
            }
            other => value.push(other),
        }
    }

    None
}

/// Legge un carattere codificato come `\uXXXX`, ricomponendo le coppie
/// surrogate necessarie ai caratteri fuori dal piano base.
fn read_escaped_code_point(characters: &mut core::str::Chars<'_>) -> Option<char> {
    let first = read_four_hexadecimal_digits(characters)?;

    // Un surrogato alto non è un carattere: deve essere seguito dal suo
    // surrogato basso, e insieme rappresentano un carattere fuori dal piano
    // base, come le emoji.
    if (0xD800..0xDC00).contains(&first) {
        if characters.next()? != '\\' || characters.next()? != 'u' {
            return None;
        }
        let second = read_four_hexadecimal_digits(characters)?;
        if !(0xDC00..0xE000).contains(&second) {
            return None;
        }

        let combined =
            0x1_0000_u32 + ((u32::from(first) - 0xD800) << 10) + (u32::from(second) - 0xDC00);
        return char::from_u32(combined);
    }

    char::from_u32(u32::from(first))
}

/// Legge esattamente quattro cifre esadecimali.
fn read_four_hexadecimal_digits(characters: &mut core::str::Chars<'_>) -> Option<u16> {
    let mut value = 0_u16;
    for _ in 0..4 {
        let digit = characters.next()?.to_digit(16)?;
        let digit = u16::try_from(digit).ok()?;
        value = value.checked_mul(16)?.checked_add(digit)?;
    }
    Some(value)
}

/// Tipo dichiarato da una risposta TDLib.
#[must_use]
pub fn json_type(json: &str) -> Option<String> {
    json_string_value(json, "@type")
}

/// L'oggetto annidato associato a una chiave, **delimitato davvero**.
///
/// # Perché non basta «tutto ciò che viene dopo»
///
/// Perché il resto del progetto legge il JSON di TDLib cercando la chiave e
/// prendendo ciò che segue. Su un valore semplice funziona; su un oggetto
/// annidato **no**, e sbaglia in silenzio: cercare `date` dopo `"forward_info":`
/// trova il `date` del messaggio che sta dopo, se l'inoltro non ne ha uno, e
/// restituisce un istante che non appartiene a nulla di ciò che si sta
/// leggendo.
///
/// Questa funzione conta le parentesi e restituisce **soltanto** l'oggetto. Se
/// non lo trova, o se non si chiude, restituisce `None`: è la lezione di SIM-01
/// e LINK-01, dove un estrattore che ripiegava sul resto del file rendeva cieca
/// una guardia proprio mentre sembrava funzionare.
///
/// Le virgolette e le sequenze di escape sono rispettate: una parentesi dentro
/// una stringa non è una parentesi.
#[must_use]
pub fn json_object_value<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\":");
    let start = json.find(&needle)? + needle.len();
    let rest = json.get(start..)?;
    let offset = rest.len() - rest.trim_start().len();
    let rest = rest.get(offset..)?;
    if !rest.starts_with('{') {
        return None;
    }

    let bytes = rest.as_bytes();
    // Le parentesi aperte, **con il loro tipo**: una quadra non chiude una
    // graffa. Contare soltanto la profondita' farebbe finire l'oggetto su
    // `{"origin":{]}}`, cioe' su un dato malformato, restituendo un frammento
    // che sembra un oggetto e non lo e'.
    let mut aperte: Vec<u8> = Vec::new();
    let mut in_string = false;
    let mut escaped = false;

    for (index, byte) in bytes.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }

        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => aperte.push(*byte),
            b'}' | b']' => {
                // Contenuto remoto ostile: una chiusura che non corrisponde
                // all'ultima apertura, o che non ne ha alcuna, e' un dato
                // malformato. Non si indovina che cosa intendesse.
                let atteso = if *byte == b'}' { b'{' } else { b'[' };
                if aperte.pop() != Some(atteso) {
                    return None;
                }
                if aperte.is_empty() {
                    return rest.get(..=index);
                }
            }
            _ => {}
        }
    }

    // L'oggetto non si chiude: il dato e' troncato, e indovinare dove finisse
    // sarebbe inventare.
    None
}

/// Verifica il confine FFI contro la libreria realmente prodotta.
///
/// La sequenza non richiede alcuna credenziale e **non contatta la rete**: il
/// primo comando inviato al client disattiva la rete a livello di libreria.
/// Il database locale viene però aperto davvero, perché è quello il percorso
/// che esercita la derivazione di chiave di OpenSSL.
///
/// # Errori
///
/// Restituisce [`TelegramError::Tdlib`] se la libreria non è caricabile, non
/// espone i simboli attesi o non risponde.
pub fn run_smoke_test(library_path: &Path) -> TelegramResult<SmokeTestReport> {
    let library = TdJsonLibrary::load(library_path)?;

    // Prima di ogni altra cosa: nessun log della libreria sullo standard error.
    let _ = library.execute(r#"{"@type":"setLogVerbosityLevel","new_verbosity_level":0}"#)?;

    let version_response = library.execute(r#"{"@type":"getOption","name":"version"}"#)?;
    let tdlib_version = version_response
        .as_deref()
        .and_then(|response| json_string_value(response, "value"));

    // Invariante 5: una richiesta con un byte NUL interno non e' una stringa C
    // valida e deve essere rifiutata **prima** di attraversare il confine.
    let interior_nul_rejected = library.execute("{\"@type\":\"get\0Option\"}").is_err();

    // Invariante 6: il testo non ASCII deve attraversare il confine integro, in
    // entrambe le direzioni. `parseTextEntities` e' sincrona, non tocca la rete
    // e restituisce il testo ricevuto: e' quindi un giro completo attraverso la
    // FFI, andata e ritorno.
    let non_ascii_probe = library.execute(&format!(
        r#"{{"@type":"parseTextEntities","text":"{NON_ASCII_PROBE}","parse_mode":{{"@type":"textParseModeMarkdown","version":2}}}}"#
    ))?;
    let returned_text = non_ascii_probe
        .as_deref()
        .and_then(|response| json_string_value(response, "text"));
    let non_ascii_round_trip = returned_text.as_deref() == Some(NON_ASCII_PROBE);

    let client_id = library.create_client_id()?;

    // Disattivazione della rete a livello di libreria: da qui in avanti TDLib
    // non tenta alcuna connessione. E' cio' che permette di aprire il database
    // locale senza contattare Telegram.
    library.send(
        client_id,
        r#"{"@type":"setNetworkType","type":{"@type":"networkTypeNone"}}"#,
    )?;

    let database_directory = std::env::temp_dir().join("lisi-tdlib-smoke-test");
    let escaped_directory = database_directory
        .display()
        .to_string()
        .replace('\\', "\\\\");

    // L'apertura del database locale con una chiave esercita la derivazione di
    // chiave di OpenSSL: e' il percorso su cui e' segnalata la regressione
    // della issue tdlib/td#3171.
    let parameters = format!(
        concat!(
            r#"{{"@type":"setTdlibParameters","use_test_dc":true,"#,
            r#""database_directory":"{}","files_directory":"{}","#,
            r#""database_encryption_key":"{}","#,
            r#""use_file_database":false,"use_chat_info_database":false,"#,
            r#""use_message_database":false,"use_secret_chats":false,"#,
            r#""api_id":{},"api_hash":"{}","#,
            r#""system_language_code":"it","device_model":"LISI proof of concept","#,
            r#""application_version":"0.1.0"}}"#
        ),
        escaped_directory,
        escaped_directory,
        FICTITIOUS_DATABASE_KEY,
        FICTITIOUS_API_ID,
        FICTITIOUS_API_HASH
    );
    library.send(client_id, &parameters)?;

    let mut authorization_states = Vec::new();
    let mut updates_received = 0_usize;
    let mut local_database_opened = false;

    for _ in 0..MAX_POLLS {
        let Some(update) = library.receive(0.05)? else {
            if local_database_opened {
                break;
            }
            continue;
        };
        updates_received += 1;

        if json_type(&update).as_deref() == Some("updateAuthorizationState")
            && let Some(state) = json_string_value(&update, "@type").and_then(|_| {
                // Il tipo dello stato e' il secondo "@type" della risposta.
                update
                    .rfind("\"@type\":\"authorizationState")
                    .and_then(|position| update.get(position..))
                    .and_then(|tail| json_string_value(tail, "@type"))
            })
        {
            if !authorization_states.contains(&state) {
                authorization_states.push(state.clone());
            }
            // Raggiungere la richiesta del numero significa che i parametri
            // sono stati accettati e il database locale e' stato aperto.
            if state == "authorizationStateWaitPhoneNumber" {
                local_database_opened = true;
            }
        }
    }

    // Invariante 3: a coda vuota `td_receive` restituisce un puntatore nullo,
    // che deve tradursi in assenza e non in un errore ne' in un panico.
    let mut null_on_timeout = false;
    for _ in 0..40 {
        if library.receive(0.01)?.is_none() {
            null_on_timeout = true;
            break;
        }
    }

    // Chiusura ordinata: la documentazione avverte che ogni client va chiuso
    // prima della terminazione, altrimenti la consistenza dei dati e' a rischio.
    library.send(client_id, r#"{"@type":"close"}"#)?;

    let mut closed_orderly = false;
    for _ in 0..MAX_POLLS {
        let Some(update) = library.receive(0.05)? else {
            continue;
        };
        updates_received += 1;
        if update.contains("authorizationStateClosed") {
            closed_orderly = true;
            if !authorization_states
                .iter()
                .any(|state| state == "authorizationStateClosed")
            {
                authorization_states.push(String::from("authorizationStateClosed"));
            }
            break;
        }
    }

    // La cartella di prova non contiene dati operativi: rimuoverla evita di
    // lasciare in giro un database, anche se vuoto.
    let _ = std::fs::remove_dir_all(&database_directory);

    Ok(SmokeTestReport {
        library_path: library_path.to_path_buf(),
        client_id,
        tdlib_version,
        interior_nul_rejected,
        non_ascii_round_trip,
        non_ascii_returned: returned_text,
        null_on_timeout,
        local_database_opened,
        authorization_states,
        updates_received,
        closed_orderly,
    })
}

/// Percorso predefinito della libreria accanto all'eseguibile.
///
/// # Errori
///
/// Restituisce [`TelegramError::Tdlib`] se il percorso dell'eseguibile non è
/// determinabile e nessuna variabile d'ambiente lo sostituisce.
pub fn default_library_path() -> TelegramResult<PathBuf> {
    resolve_library_path(std::env::var_os(LIBRARY_PATH_OVERRIDE_VAR))
}

/// Variabile d'ambiente che, se impostata, sostituisce il percorso
/// predefinito accanto all'eseguibile.
///
/// Serve a chi esegue un binario di sviluppo senza copiare la libreria (e le
/// sue dipendenze) accanto a ogni artefatto compilato: punta direttamente alla
/// cartella degli artefatti verificati (`artifacts/tdlib`), dove risiedono
/// già tutte e quattro insieme.
pub const LIBRARY_PATH_OVERRIDE_VAR: &str = "LISI_TDJSON_PATH";

/// Logica di [`default_library_path`], isolata dalla lettura dell'ambiente
/// reale così da poter essere provata senza mutare variabili di processo
/// condivise fra i test.
fn resolve_library_path(override_value: Option<std::ffi::OsString>) -> TelegramResult<PathBuf> {
    if let Some(overridden) = override_value {
        return Ok(PathBuf::from(overridden));
    }

    let executable = std::env::current_exe().map_err(|error| TelegramError::Tdlib {
        reason: format!("percorso dell'eseguibile non determinabile: {error}"),
    })?;
    let directory = executable.parent().ok_or_else(|| TelegramError::Tdlib {
        reason: String::from("l'eseguibile non ha una cartella contenitrice"),
    })?;

    Ok(directory.join(TdJsonLibrary::DEFAULT_WINDOWS_NAME))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        default_library_path, json_object_value, json_string_value, json_type,
        resolve_library_path, run_smoke_test,
    };

    #[test]
    fn the_default_path_sits_next_to_the_executable() {
        let Ok(path) = default_library_path() else {
            panic!("il percorso predefinito deve essere determinabile");
        };
        assert!(path.ends_with("tdjson.dll"));
        assert!(path.parent().is_some());
    }

    #[test]
    fn an_override_value_replaces_the_path_next_to_the_executable() {
        let Ok(path) = resolve_library_path(Some(std::ffi::OsString::from(
            "artifacts\\tdlib\\tdjson.dll",
        ))) else {
            panic!("il percorso indicato dalla variabile d'ambiente deve essere accettato");
        };
        assert_eq!(
            path,
            std::path::PathBuf::from("artifacts\\tdlib\\tdjson.dll")
        );
    }

    #[test]
    fn without_an_override_the_path_still_sits_next_to_the_executable() {
        let Ok(path) = resolve_library_path(None) else {
            panic!("senza una variabile d'ambiente il percorso predefinito deve restare valido");
        };
        assert!(path.ends_with("tdjson.dll"));
    }

    #[test]
    fn the_smoke_test_fails_cleanly_when_the_library_is_absent() {
        let result = run_smoke_test(Path::new("C:\\assente\\tdjson.dll"));
        assert!(result.is_err());
    }

    #[test]
    fn a_string_value_is_extracted_from_a_response() {
        let response = r#"{"@type":"optionValueString","value":"1.8.66"}"#;
        assert_eq!(json_type(response).as_deref(), Some("optionValueString"));
        assert_eq!(
            json_string_value(response, "value").as_deref(),
            Some("1.8.66")
        );
    }

    #[test]
    fn an_absent_key_yields_nothing() {
        let response = r#"{"@type":"error","code":400}"#;
        assert_eq!(json_string_value(response, "value"), None);
    }

    #[test]
    fn an_escaped_quotation_mark_does_not_end_the_value() {
        let response = r#"{"message":"virgoletta \" interna","other":"x"}"#;
        assert_eq!(
            json_string_value(response, "message").as_deref(),
            Some("virgoletta \" interna")
        );
    }

    #[test]
    fn a_non_ascii_value_is_preserved() {
        let response = r#"{"value":"caffè è ok"}"#;
        assert_eq!(
            json_string_value(response, "value").as_deref(),
            Some("caffè è ok")
        );
    }

    #[test]
    fn a_unicode_escape_is_decoded() {
        // E' la forma in cui TDLib restituisce ogni carattere non ASCII.
        let response = r#"{"value":"caffè è ok — Ж"}"#;
        assert_eq!(
            json_string_value(response, "value").as_deref(),
            Some("caffè è ok — Ж")
        );
    }

    #[test]
    fn a_surrogate_pair_is_recomposed_into_a_single_character() {
        // Le emoji stanno fuori dal piano base e arrivano come coppia.
        let response = r#"{"value":"😀"}"#;
        assert_eq!(
            json_string_value(response, "value").as_deref(),
            Some("\u{1F600}")
        );
    }

    #[test]
    fn the_usual_escape_sequences_are_decoded() {
        let response = r#"{"value":"a\tb\nc\\d\"e\/f"}"#;
        assert_eq!(
            json_string_value(response, "value").as_deref(),
            Some("a\tb\nc\\d\"e/f")
        );
    }

    #[test]
    fn a_lone_high_surrogate_is_refused_instead_of_being_guessed() {
        assert_eq!(json_string_value(r#"{"value":"\ud83d"}"#, "value"), None);
        assert_eq!(json_string_value(r#"{"value":"\ud83dA"}"#, "value"), None);
    }

    #[test]
    fn an_unknown_escape_is_refused() {
        assert_eq!(json_string_value(r#"{"value":"a\qb"}"#, "value"), None);
    }

    #[test]
    fn a_truncated_unicode_escape_is_refused_instead_of_panicking() {
        assert_eq!(json_string_value(r#"{"value":"\u00"}"#, "value"), None);
        assert_eq!(json_string_value(r#"{"value":"\u"}"#, "value"), None);
    }

    #[test]
    fn an_unterminated_value_is_refused_instead_of_panicking() {
        assert_eq!(json_string_value(r#"{"value":"senza fine"#, "value"), None);
    }

    /// **Un oggetto annidato si ferma dove finisce.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che leggere `date` dentro `forward_info` trovi il `date` del messaggio
    /// che lo contiene, quando l'inoltro non ne ha uno. Restituirebbe un
    /// istante vero, appartenente a un'altra cosa: il tipo peggiore di errore,
    /// perché nulla lo dichiara.
    #[test]
    fn un_oggetto_annidato_si_ferma_dove_finisce() {
        let json =
            r#"{"forward_info":{"origin":{"@type":"messageOriginChannel"}},"date":1700000000}"#;
        let Some(oggetto) = json_object_value(json, "forward_info") else {
            panic!("l'oggetto deve essere trovato");
        };
        assert_eq!(oggetto, r#"{"origin":{"@type":"messageOriginChannel"}}"#);
        assert!(
            !oggetto.contains("date"),
            "l'istante del messaggio non appartiene all'inoltro"
        );
    }

    /// **Una parentesi dentro una stringa non è una parentesi.**
    #[test]
    fn una_parentesi_dentro_una_stringa_non_chiude_nulla() {
        let json = r#"{"origin":{"sender_name":"}} finto","altro":1},"date":7}"#;
        let Some(oggetto) = json_object_value(json, "origin") else {
            panic!("l'oggetto deve essere trovato");
        };
        assert_eq!(oggetto, r#"{"sender_name":"}} finto","altro":1}"#);
    }

    /// **Una virgoletta preceduta da una barra rovesciata non chiude la
    /// stringa.**
    #[test]
    fn una_virgoletta_protetta_non_chiude_la_stringa() {
        let json = r#"{"origin":{"sender_name":"virgoletta \" e poi }","x":1},"date":7}"#;
        let Some(oggetto) = json_object_value(json, "origin") else {
            panic!("l'oggetto deve essere trovato");
        };
        assert!(oggetto.ends_with(r#""x":1}"#), "{oggetto}");
    }

    /// **Un oggetto che non si chiude non viene indovinato.**
    ///
    /// È la regola di SIM-01 e LINK-01: un estrattore che ripiega sul resto del
    /// testo rende cieca la guardia che lo usa, e lo fa in silenzio.
    #[test]
    fn un_oggetto_troncato_non_si_indovina() {
        assert_eq!(
            json_object_value(r#"{"origin":{"sender_name":"senza fine"#, "origin"),
            None
        );
    }

    /// **Una chiave che non c'è non restituisce il resto del documento.**
    #[test]
    fn una_chiave_assente_non_restituisce_il_resto() {
        assert_eq!(json_object_value(r#"{"date":7}"#, "forward_info"), None);
    }

    /// **Un valore che non è un oggetto non viene restituito come tale.**
    #[test]
    fn un_valore_semplice_non_e_un_oggetto() {
        assert_eq!(json_object_value(r#"{"date":7}"#, "date"), None);
        assert_eq!(json_object_value(r#"{"nome":"x"}"#, "nome"), None);
    }

    /// **Una parentesi di chiusura in più non fa sottrarre sotto zero.**
    ///
    /// Contenuto remoto ostile: un dato malformato deve produrre `None`, non un
    /// arresto.
    #[test]
    fn una_chiusura_in_piu_non_fa_arrestare_nulla() {
        assert_eq!(json_object_value(r#"{"origin":{]}}"#, "origin"), None);
    }
}

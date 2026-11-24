//! Chi ha registrato un nome o un indirizzo, chiesto dal PC al registro che
//! lo tiene (WHOIS-01, ADR-0205).
//!
//! # Chi decide
//!
//! Si chiede soltanto se l'amministratore lo ha abilitato: è la dodicesima
//! azione riservata, e di fabbrica è spenta ([`choose`]).
//!
//! # Che cosa fa
//!
//! Per **un** indicatore e per un gesto:
//!
//! - un **dominio** (o l'host di un indirizzo web): si legge l'elenco RDAP di
//!   IANA; se il suffisso ha un servizio RDAP in `https`, si chiede lì il nome
//!   registrato. Altrimenti si chiede a `whois.iana.org`, sulla porta 43,
//!   **soltanto il suffisso**, e al server WHOIS che IANA indica si chiede il
//!   nome;
//! - un **indirizzo**: si legge l'elenco RDAP di IANA degli indirizzi, e si
//!   chiede al registro regionale indicato.
//!
//! Registra chi, quando, che cosa si è chiesto, a chi, com'è andata e il
//! riassunto della risposta, con la riga d'audit nella stessa transazione.
//!
//! # Le destinazioni (ADR-0205, decisione 2)
//!
//! Gli unici indirizzi scritti a mano sono quelli di IANA, qui sotto. Il
//! registro RDAP viene da un elenco IANA, quello WHOIS dalla risposta di
//! `whois.iana.org`. Un contenuto monitorato decide **quale nome** si chiede,
//! mai **a chi**.
//!
//! # Che cosa non fa
//!
//! - Non parte se il WHOIS non è abilitato, né in Esercitazione.
//! - Non segue i rimandi fra registri e non si collega a ciò che trova.
//! - Non ripete: una richiesta per gesto, e mai due troppo vicine sullo
//!   stesso indicatore.

use std::net::IpAddr;

use lisi_core::model::NewAuditEntry;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{OperatingMode, RestrictedAction, Timestamp};
use lisi_platform::https::{self, BodyLimit, FetchRefusal, Fetched};
use lisi_platform::whois::{self, WhoisOutcome};
use lisi_storage::Database;
use lisi_storage::repository::registration_lookup::NewRegistrationLookup;
pub use lisi_storage::repository::registration_lookup::StoredRegistrationLookup;

use crate::error::{ServiceError, ServiceResult};
use crate::indicator_resolution::{self, Query as ResolutionQuery};

/// L'elenco IANA dei servizi RDAP per i domini.
pub const IANA_RDAP_DOMAINS: &str = "https://data.iana.org/rdap/dns.json";
/// L'elenco IANA dei servizi RDAP per gli indirizzi IPv4.
pub const IANA_RDAP_IPV4: &str = "https://data.iana.org/rdap/ipv4.json";
/// L'elenco IANA dei servizi RDAP per gli indirizzi IPv6.
pub const IANA_RDAP_IPV6: &str = "https://data.iana.org/rdap/ipv6.json";
/// Il server WHOIS di IANA, che dice quale server WHOIS tiene un suffisso.
pub const IANA_WHOIS: &str = "whois.iana.org";

/// L'azione d'audit della scelta.
pub const CHOICE_AUDIT_ACTION: &str = "whois_scelto";
/// L'azione d'audit di una richiesta.
pub const REQUEST_AUDIT_ACTION: &str = "registrazione_chiesta";
/// Secondi, almeno, fra due richieste sullo stesso indicatore.
pub const MIN_SECONDS_BETWEEN: i64 = 10;
/// Quante richieste la schermata mostra, per indicatore.
pub const SHOWN: u32 = 5;
/// Quante righe di una risposta si tengono, al più.
pub const MAX_SUMMARY_LINES: usize = 60;
/// Quanti caratteri di una riga si tengono, al più.
pub const MAX_LINE_CHARS: usize = 200;

/// Le forme di secondo livello più comuni sotto un suffisso nazionale
/// (ADR-0205, decisione 7): `esempio.co.uk` si registra come tale, e il
/// registro non conosce `posta.esempio.co.uk`.
const SECONDO_LIVELLO: [&str; 12] = [
    "ac", "co", "com", "edu", "gob", "go", "gov", "ne", "net", "or", "org", "mil",
];

/// La rete. In produzione è quella del PC ([`Network::of_this_pc`]); le prove
/// ne passano una finta, e nessuna richiesta parte.
#[derive(Debug, Clone, Copy)]
pub struct Network {
    /// Una lettura in `https`.
    pub read: fn(&str, BodyLimit) -> Fetched,
    /// Una domanda WHOIS sulla porta 43.
    pub ask: fn(&str, &str) -> WhoisOutcome,
}

impl Network {
    /// La rete del PC: WinHTTP e la porta 43.
    #[must_use]
    pub const fn of_this_pc() -> Self {
        Self {
            read: https::fetch_within,
            ask: whois::ask,
        }
    }
}

/// Che cosa si chiede.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    /// Il nome registrato.
    Domain(String),
    /// L'indirizzo.
    Address(IpAddr),
}

impl Query {
    /// Il nome o l'indirizzo chiesto, per il registro.
    #[must_use]
    pub fn queried_name(&self) -> String {
        match self {
            Self::Domain(nome) => nome.clone(),
            Self::Address(indirizzo) => indirizzo.to_string(),
        }
    }
}

/// Com'è andata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupAttempt {
    /// La richiesta è partita ed è registrata.
    Recorded {
        /// La riga della richiesta.
        id: i64,
        /// La frase che dice l'esito.
        sentence: String,
    },
    /// Il prodotto ha rifiutato di chiedere: il perché. Nessuna richiesta.
    Refused(String),
}

/// Se un genere d'indicatore si può chiedere.
#[must_use]
pub fn applicable(kind: &str) -> bool {
    indicator_resolution::resolvable(kind)
}

/// Che cosa si chiederebbe per un indicatore, se si può chiedere.
#[must_use]
pub fn query_for(kind: &str, value: &str) -> Option<Query> {
    match indicator_resolution::query_for(kind, value)? {
        ResolutionQuery::Name(nome) => Some(Query::Domain(registered_domain(&nome))),
        ResolutionQuery::Address(indirizzo) => Some(Query::Address(indirizzo)),
    }
}

/// Il nome registrato: le ultime due parti, o tre sotto una forma di secondo
/// livello comune di un suffisso nazionale (ADR-0205, decisione 7).
#[must_use]
pub fn registered_domain(name: &str) -> String {
    let parti: Vec<&str> = name.split('.').collect();
    let quante = if parti.len() >= 3
        && parti[parti.len() - 1].len() == 2
        && SECONDO_LIVELLO.contains(&parti[parti.len() - 2])
    {
        3
    } else {
        2
    };
    parti[parti.len().saturating_sub(quante)..].join(".")
}

/// Il servizio RDAP di un suffisso, dall'elenco IANA dei domini: il primo
/// indirizzo in `https`, con la barra in fondo.
#[must_use]
pub fn rdap_base_for_suffix(elenco: &[u8], suffix: &str) -> Option<String> {
    let documento: serde_json::Value = serde_json::from_slice(elenco).ok()?;
    documento
        .get("services")?
        .as_array()?
        .iter()
        .find(|servizio| {
            servizio
                .get(0)
                .and_then(serde_json::Value::as_array)
                .is_some_and(|suffissi| {
                    suffissi
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .any(|voce| voce.eq_ignore_ascii_case(suffix))
                })
        })
        .and_then(|servizio| primo_https(servizio.get(1)?))
}

/// Il servizio RDAP di un indirizzo, dall'elenco IANA: quello del blocco più
/// stretto che lo contiene.
#[must_use]
pub fn rdap_base_for_address(elenco: &[u8], indirizzo: IpAddr) -> Option<String> {
    let documento: serde_json::Value = serde_json::from_slice(elenco).ok()?;
    let mut migliore: Option<(u8, String)> = None;
    for servizio in documento.get("services")?.as_array()? {
        let Some(blocchi) = servizio.get(0).and_then(serde_json::Value::as_array) else {
            continue;
        };
        let Some(base) = servizio.get(1).and_then(primo_https) else {
            continue;
        };
        for blocco in blocchi.iter().filter_map(serde_json::Value::as_str) {
            if let Some(lunghezza) = contiene(blocco, indirizzo)
                && migliore
                    .as_ref()
                    .is_none_or(|(finora, _)| lunghezza > *finora)
            {
                migliore = Some((lunghezza, base.clone()));
            }
        }
    }
    migliore.map(|(_, base)| base)
}

fn primo_https(indirizzi: &serde_json::Value) -> Option<String> {
    indirizzi
        .as_array()?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .find(|indirizzo| indirizzo.starts_with("https://") && !indirizzo.contains('@'))
        .map(|indirizzo| {
            if indirizzo.ends_with('/') {
                indirizzo.to_owned()
            } else {
                format!("{indirizzo}/")
            }
        })
}

/// Se il blocco `a.b.c.d/n` contiene l'indirizzo: la lunghezza del prefisso.
fn contiene(blocco: &str, indirizzo: IpAddr) -> Option<u8> {
    let (rete, lunghezza) = blocco.split_once('/')?;
    let lunghezza: u8 = lunghezza.parse().ok()?;
    let rete: IpAddr = rete.parse().ok()?;
    let (rete, indirizzo, bit) = match (rete, indirizzo) {
        (IpAddr::V4(rete), IpAddr::V4(indirizzo)) => (
            u128::from(u32::from(rete)),
            u128::from(u32::from(indirizzo)),
            32_u8,
        ),
        (IpAddr::V6(rete), IpAddr::V6(indirizzo)) => {
            (u128::from(rete), u128::from(indirizzo), 128_u8)
        }
        _ => return None,
    };
    if lunghezza > bit {
        return None;
    }
    let spostamento = u32::from(bit - lunghezza);
    let uguali = if lunghezza == 0 {
        true
    } else {
        rete.checked_shr(spostamento) == indirizzo.checked_shr(spostamento)
    };
    uguali.then_some(lunghezza)
}

/// Il server WHOIS di un suffisso, dalla risposta di `whois.iana.org`: la
/// riga `whois:`, se c'è e se è un nome di server.
#[must_use]
pub fn whois_server_from_iana(answer: &str) -> Option<String> {
    answer.lines().find_map(|riga| {
        let (chiave, valore) = riga.split_once(':')?;
        if !chiave.trim().eq_ignore_ascii_case("whois") {
            return None;
        }
        let server = valore.trim().to_ascii_lowercase();
        whois::is_server_name(&server).then_some(server)
    })
}

/// Una riga di testo arrivato da fuori, resa innocua da mostrare: senza
/// caratteri di controllo né di direzione, accorciata.
#[must_use]
pub fn clean_line(riga: &str) -> String {
    let pulita: String = riga
        .chars()
        .filter(|carattere| {
            !carattere.is_control()
                && !matches!(
                    carattere,
                    '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
                )
        })
        .collect();
    let pulita = pulita.trim();
    if pulita.chars().count() > MAX_LINE_CHARS {
        let mut corta: String = pulita.chars().take(MAX_LINE_CHARS).collect();
        corta.push('…');
        corta
    } else {
        pulita.to_owned()
    }
}

/// Il riassunto di una risposta WHOIS: le righe con un contenuto, senza i
/// commenti, al più [`MAX_SUMMARY_LINES`].
#[must_use]
pub fn summarize_whois(answer: &str) -> String {
    answer
        .lines()
        .map(clean_line)
        .filter(|riga| !riga.is_empty() && !riga.starts_with('%') && !riga.starts_with('#'))
        .filter(|riga| !riga.starts_with(">>>"))
        .take(MAX_SUMMARY_LINES)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Se una risposta WHOIS dice che il nome non è registrato.
#[must_use]
pub fn whois_says_not_found(answer: &str) -> bool {
    let minuscolo = answer.to_ascii_lowercase();
    // Le frasi dei registri si scrivono senza spazi: non sono testo da
    // mostrare, e si confrontano con la risposta in cui gli spazi diventano
    // trattini bassi.
    let compatta = minuscolo.replace(' ', "_");
    [
        "no_match",
        "not_found",
        "no_entries_found",
        "no_data_found",
        "no_object_found",
        "object_does_not_exist",
    ]
    .iter()
    .any(|frase| compatta.contains(frase))
        || minuscolo.lines().any(|riga| {
            riga.trim_start().starts_with("status:")
                && (riga.contains("available") || riga.trim_end().ends_with("free"))
        })
}

/// Il riassunto di una risposta RDAP: le voci che servono a chi indaga, una
/// per riga. `None` se non è un documento RDAP.
#[must_use]
pub fn summarize_rdap(risposta: &[u8]) -> Option<String> {
    let documento: serde_json::Value = serde_json::from_slice(risposta).ok()?;
    let oggetto = documento.as_object()?;
    oggetto.get("objectClassName")?;
    let mut righe: Vec<String> = Vec::new();
    let mut voce = |etichetta: &str, valore: &str| {
        let valore = clean_line(valore);
        if !valore.is_empty() && righe.len() < MAX_SUMMARY_LINES {
            righe.push(format!("{etichetta}: {valore}"));
        }
    };
    let testo = |chiave: &str| oggetto.get(chiave).and_then(serde_json::Value::as_str);

    if let Some(nome) = testo("ldhName").or_else(|| testo("unicodeName")) {
        voce("Nome", nome);
    }
    if let Some(nome) = testo("name") {
        voce("Nome della rete", nome);
    }
    if let Some(identificativo) = testo("handle") {
        voce("Identificativo", identificativo);
    }
    if let (Some(inizio), Some(fine)) = (testo("startAddress"), testo("endAddress")) {
        voce("Indirizzi", &format!("{inizio} - {fine}"));
    }
    if let Some(paese) = testo("country") {
        voce("Paese", paese);
    }
    for evento in oggetto
        .get("events")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        let azione = evento
            .get("eventAction")
            .and_then(serde_json::Value::as_str);
        let data = evento.get("eventDate").and_then(serde_json::Value::as_str);
        if let (Some(azione), Some(data)) = (azione, data) {
            let etichetta = match azione.replace(' ', "_").as_str() {
                "registration" => "Registrato il",
                "expiration" => "Scade il",
                "last_changed" => "Cambiato il",
                _ => continue,
            };
            voce(etichetta, data);
        }
    }
    let stati: Vec<&str> = oggetto
        .get("status")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect();
    if !stati.is_empty() {
        voce("Stato", &stati.join(", "));
    }
    for (ruolo, etichetta) in [
        ("registrar", "Chi l'ha registrato per conto altrui"),
        ("registrant", "Intestatario"),
        ("abuse", "Contatto per gli abusi"),
    ] {
        for entita in entita_con_ruolo(&documento, ruolo) {
            let descrizione = [nome_vcard(entita), posta_vcard(entita)]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(", ");
            voce(etichetta, &descrizione);
        }
    }
    let server_dei_nomi: Vec<&str> = oggetto
        .get("nameservers")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|server| server.get("ldhName").and_then(serde_json::Value::as_str))
        .collect();
    if !server_dei_nomi.is_empty() {
        voce("Nomi di rete che lo servono", &server_dei_nomi.join(", "));
    }
    Some(righe.join("\n"))
}

/// Le entità con un ruolo, anche dentro altre entità (il contatto per gli
/// abusi sta spesso dentro il registrar).
fn entita_con_ruolo<'a>(nodo: &'a serde_json::Value, ruolo: &str) -> Vec<&'a serde_json::Value> {
    let mut trovate = Vec::new();
    for entita in nodo
        .get("entities")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        let ha_il_ruolo = entita
            .get("roles")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|ruoli| ruoli.iter().any(|voce| voce.as_str() == Some(ruolo)));
        if ha_il_ruolo {
            trovate.push(entita);
        }
        trovate.extend(entita_con_ruolo(entita, ruolo));
    }
    trovate
}

/// Un campo della scheda vCard di un'entità (`jCard`, RFC 7095).
fn campo_vcard<'a>(entita: &'a serde_json::Value, campo: &str) -> Option<&'a str> {
    entita
        .get("vcardArray")?
        .get(1)?
        .as_array()?
        .iter()
        .find(|proprieta| proprieta.get(0).and_then(serde_json::Value::as_str) == Some(campo))?
        .get(3)?
        .as_str()
}

fn nome_vcard(entita: &serde_json::Value) -> Option<String> {
    campo_vcard(entita, "fn")
        .filter(|nome| !nome.trim().is_empty())
        .map(str::to_owned)
}

fn posta_vcard(entita: &serde_json::Value) -> Option<String> {
    campo_vcard(entita, "email")
        .filter(|posta| !posta.trim().is_empty())
        .map(str::to_owned)
}

/// Se il WHOIS è abilitato.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn enabled(database: &Database) -> ServiceResult<bool> {
    Ok(database.registration_lookup_enabled()?)
}

/// Abilita o spegne il WHOIS. Soltanto l'amministratore.
///
/// # Errori
///
/// [`ServiceError::ActionReservedToAdministrator`] in modalità operatore; un
/// errore se la scrittura non riesce.
pub fn choose(
    database: &mut Database,
    enable: bool,
    mode: OperatingMode,
    actor: &Actor,
    now: Timestamp,
) -> ServiceResult<String> {
    if !mode.allows(RestrictedAction::ChooseRegistrationLookup) {
        return Err(ServiceError::ActionReservedToAdministrator {
            action: RestrictedAction::ChooseRegistrationLookup,
        });
    }
    let audit = NewAuditEntry {
        actor: actor.clone(),
        action: AuditAction::try_new(CHOICE_AUDIT_ACTION)?,
        entity: AuditEntity::try_new("postazione")?,
        entity_id: None,
        actor_mode: Some(mode),
        detail: Some(AuditDetail::try_new(if enable {
            "abilitato"
        } else {
            "spento"
        })?),
        recorded_at: now,
    };
    database.save_registration_lookup_enabled(enable, actor, &audit)?;
    Ok(String::from(if enable {
        "Il WHOIS si può chiedere dal PC. Ogni richiesta arriva al registro, e resta nel registro \
         delle operazioni."
    } else {
        "Il WHOIS non si chiede più dal PC."
    }))
}

/// Che cosa è successo sulla rete, prima di scriverlo.
struct Esito {
    service: &'static str,
    server: String,
    outcome: &'static str,
    detail: String,
    summary: String,
}

impl Esito {
    fn non_riuscito(service: &'static str, server: String, detail: String) -> Self {
        Self {
            service,
            server,
            outcome: "non_riuscito",
            detail,
            summary: String::new(),
        }
    }
}

/// Il motivo di una lettura non riuscita, accorciato per il registro.
fn motivo(rifiuto: &FetchRefusal) -> String {
    clean_line(&rifiuto.to_string())
}

/// RDAP, all'indirizzo che l'elenco IANA ha dato.
fn chiedi_rdap(rete: Network, indirizzo: String) -> Esito {
    match (rete.read)(&indirizzo, BodyLimit::Registration) {
        Fetched::Body(risposta) => match summarize_rdap(&risposta) {
            Some(summary) => Esito {
                service: "rdap",
                server: indirizzo,
                outcome: "trovato",
                detail: String::new(),
                summary,
            },
            None => Esito::non_riuscito(
                "rdap",
                indirizzo,
                String::from("la risposta non è un documento del registro che si possa leggere"),
            ),
        },
        Fetched::Refused(FetchRefusal::Status { status: 404 }) => Esito {
            service: "rdap",
            server: indirizzo,
            outcome: "inesistente",
            detail: String::new(),
            summary: String::new(),
        },
        Fetched::Refused(rifiuto) => Esito::non_riuscito("rdap", indirizzo, motivo(&rifiuto)),
    }
}

/// Un dominio: RDAP se l'elenco IANA lo offre, altrimenti la porta 43.
fn chiedi_dominio(rete: Network, nome: &str) -> Esito {
    let suffisso = nome.rsplit('.').next().unwrap_or(nome);
    let elenco = match (rete.read)(IANA_RDAP_DOMAINS, BodyLimit::Catalogue) {
        Fetched::Body(elenco) => elenco,
        Fetched::Refused(rifiuto) => {
            return Esito::non_riuscito("rdap", IANA_RDAP_DOMAINS.to_owned(), motivo(&rifiuto));
        }
    };
    if let Some(base) = rdap_base_for_suffix(&elenco, suffisso) {
        return chiedi_rdap(rete, format!("{base}domain/{nome}"));
    }

    // Il suffisso non ha RDAP: a IANA si chiede SOLTANTO il suffisso.
    let server = match (rete.ask)(IANA_WHOIS, suffisso) {
        WhoisOutcome::Answer(risposta) => match whois_server_from_iana(&risposta) {
            Some(server) => server,
            None => {
                return Esito {
                    service: "nessuno",
                    server: IANA_WHOIS.to_owned(),
                    outcome: "nessun_servizio",
                    detail: String::new(),
                    summary: String::new(),
                };
            }
        },
        WhoisOutcome::Refused(rifiuto) => {
            return Esito::non_riuscito(
                "whois",
                IANA_WHOIS.to_owned(),
                clean_line(&rifiuto.to_string()),
            );
        }
    };
    match (rete.ask)(&server, nome) {
        WhoisOutcome::Answer(risposta) => Esito {
            service: "whois",
            outcome: if whois_says_not_found(&risposta) {
                "inesistente"
            } else {
                "trovato"
            },
            server,
            detail: String::new(),
            summary: summarize_whois(&risposta),
        },
        WhoisOutcome::Refused(rifiuto) => {
            Esito::non_riuscito("whois", server, clean_line(&rifiuto.to_string()))
        }
    }
}

/// Un indirizzo: RDAP, al registro regionale dell'elenco IANA.
fn chiedi_indirizzo(rete: Network, indirizzo: IpAddr) -> Esito {
    let elenco_iana = if indirizzo.is_ipv4() {
        IANA_RDAP_IPV4
    } else {
        IANA_RDAP_IPV6
    };
    let elenco = match (rete.read)(elenco_iana, BodyLimit::Catalogue) {
        Fetched::Body(elenco) => elenco,
        Fetched::Refused(rifiuto) => {
            return Esito::non_riuscito("rdap", elenco_iana.to_owned(), motivo(&rifiuto));
        }
    };
    match rdap_base_for_address(&elenco, indirizzo) {
        Some(base) => chiedi_rdap(rete, format!("{base}ip/{indirizzo}")),
        None => Esito {
            service: "nessuno",
            server: elenco_iana.to_owned(),
            outcome: "nessun_servizio",
            detail: String::new(),
            summary: String::new(),
        },
    }
}

/// La richiesta: i rifiuti prima di chiedere, poi la richiesta, poi il
/// registro.
///
/// # Errori
///
/// Restituisce un errore se l'archivio non si legge o non si scrive.
pub fn lookup(
    database: &mut Database,
    network: Network,
    kind: &str,
    value: &str,
    actor: &Actor,
    exercise: bool,
    now: Timestamp,
) -> ServiceResult<LookupAttempt> {
    if !database.registration_lookup_enabled()? {
        return Ok(LookupAttempt::Refused(String::from(
            "Il WHOIS non è abilitato: lo abilita l'amministratore, nelle Impostazioni.",
        )));
    }
    if exercise {
        return Ok(LookupAttempt::Refused(String::from(
            "In Esercitazione nessuna richiesta parte dal PC.",
        )));
    }
    let Some(richiesta) = query_for(kind, value) else {
        return Ok(LookupAttempt::Refused(String::from(
            "Per questo indicatore non si chiede il WHOIS: si chiede soltanto per domini e indirizzi scritti in modo corretto, anche dentro un indirizzo web.",
        )));
    };
    if let Some(ultima) = database
        .registration_lookups(kind, value, 1)?
        .first()
        .map(|ultima| ultima.requested_at)
        && now.millis_since(ultima) < MIN_SECONDS_BETWEEN * 1_000
    {
        return Ok(LookupAttempt::Refused(format!(
            "Per questo indicatore il WHOIS è stato chiesto da meno di {MIN_SECONDS_BETWEEN} \
             secondi: la risposta è qui sotto."
        )));
    }

    // Una richiesta per gesto: nessuna ripetizione, qualunque sia l'esito.
    let esito = match &richiesta {
        Query::Domain(nome) => chiedi_dominio(network, nome),
        Query::Address(indirizzo) => chiedi_indirizzo(network, *indirizzo),
    };
    let registro = NewRegistrationLookup {
        indicator_kind: match kind {
            "ipv4" => "ipv4",
            "ipv6" => "ipv6",
            "dominio" => "dominio",
            _ => "url",
        },
        indicator_value: value.to_owned(),
        queried_name: richiesta.queried_name(),
        service: esito.service,
        server: esito.server.chars().take(2048).collect(),
        requested_by: actor.as_str().to_owned(),
        requested_at: now,
        outcome: esito.outcome,
        detail: esito.detail.chars().take(1024).collect(),
        summary: esito.summary.chars().take(16_384).collect(),
    };
    let sentence = outcome_sentence(registro.outcome, &registro.detail, &registro.summary);
    let audit = NewAuditEntry {
        actor: actor.clone(),
        action: AuditAction::try_new(REQUEST_AUDIT_ACTION)?,
        entity: AuditEntity::try_new("indicatore")?,
        entity_id: None,
        actor_mode: None,
        detail: Some(AuditDetail::try_new(&format!(
            "{} {}: chiesto «{}» con {} a {}, {}",
            registro.indicator_kind,
            clean_line(value),
            registro.queried_name,
            registro.service,
            clean_line(&registro.server),
            registro.outcome
        ))?),
        recorded_at: now,
    };
    let id = database.insert_registration_lookup(&registro, &audit)?;
    Ok(LookupAttempt::Recorded { id, sentence })
}

/// L'esito in una frase, con il riassunto sotto.
#[must_use]
pub fn outcome_sentence(outcome: &str, detail: &str, summary: &str) -> String {
    match outcome {
        "trovato" if summary.is_empty() => {
            String::from("Il registro ha risposto, ma senza dati da mostrare.")
        }
        "trovato" => format!("Il registro ha risposto:\n{summary}"),
        "inesistente" => {
            String::from("Il registro dice che il nome o l'indirizzo non è registrato.")
        }
        "nessun_servizio" => String::from(
            "Per questo nome o indirizzo nessun registro offre il WHOIS: non è partita altra richiesta.",
        ),
        _ if detail.is_empty() => String::from("Il registro non ha risposto."),
        _ => format!("Il registro non ha risposto: {detail}."),
    }
}

/// Le richieste per un indicatore, dalla più nuova.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn recent(
    database: &Database,
    kind: &str,
    value: &str,
) -> ServiceResult<Vec<StoredRegistrationLookup>> {
    Ok(database.registration_lookups(kind, value, SHOWN)?)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::net::IpAddr;

    use lisi_core::text::Actor;
    use lisi_core::{OperatingMode, Timestamp};
    use lisi_platform::https::{BodyLimit, FetchRefusal, Fetched};
    use lisi_platform::whois::WhoisOutcome;
    use lisi_storage::Database;

    use super::{
        IANA_RDAP_DOMAINS, IANA_RDAP_IPV4, IANA_WHOIS, LookupAttempt, Network, Query, choose,
        clean_line, lookup, query_for, rdap_base_for_address, rdap_base_for_suffix, recent,
        registered_domain, summarize_rdap, summarize_whois, whois_says_not_found,
        whois_server_from_iana,
    };
    use crate::error::ServiceError;

    const ELENCO_DOMINI: &str = r#"{"services":[[["com","net"],["https://rdap.esempio-com.invalid/"]],[["kg"],["http://rdap.cctld.kg/"]],[["org"],["https://rdap.esempio-org.invalid"]]]}"#;
    const ELENCO_IPV4: &str = r#"{"services":[[["192.0.0.0/8"],["https://rdap.ampio.invalid/"]],[["192.0.2.0/24"],["https://rdap.stretto.invalid/"]],[["198.51.100.0/24"],["http://rdap.chiaro.invalid/"]]]}"#;
    const RISPOSTA_RDAP: &str = r#"{"objectClassName":"domain","ldhName":"ESEMPIO.COM","status":["client transfer prohibited"],"events":[{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"},{"eventAction":"expiration","eventDate":"2030-08-13T04:00:00Z"}],"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Registrar d'esempio"]]],"entities":[{"roles":["abuse"],"vcardArray":["vcard",[["fn",{},"text",""],["email",{},"text","abuso@esempio.invalid"]]]}]}],"nameservers":[{"ldhName":"A.NS.ESEMPIO.INVALID"}]}"#;
    const IANA_IT: &str = "% IANA WHOIS server\n\ndomain:       IT\n\nwhois:        whois.nic.it\n\nstatus:       ACTIVE\n";

    thread_local! {
        /// Le richieste partite, in ordine: indirizzo o server e domanda.
        static PARTITE: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    fn partite() -> Vec<String> {
        PARTITE.with(|partite| partite.borrow().clone())
    }

    fn leggi(indirizzo: &str, _: BodyLimit) -> Fetched {
        PARTITE.with(|partite| partite.borrow_mut().push(indirizzo.to_owned()));
        match indirizzo {
            IANA_RDAP_DOMAINS => Fetched::Body(ELENCO_DOMINI.as_bytes().to_vec()),
            IANA_RDAP_IPV4 => Fetched::Body(ELENCO_IPV4.as_bytes().to_vec()),
            "https://rdap.esempio-com.invalid/domain/esempio.com" => {
                Fetched::Body(RISPOSTA_RDAP.as_bytes().to_vec())
            }
            _ => Fetched::Refused(FetchRefusal::Status { status: 404 }),
        }
    }

    fn chiedi(server: &str, domanda: &str) -> WhoisOutcome {
        PARTITE.with(|partite| partite.borrow_mut().push(format!("{server} {domanda}")));
        match (server, domanda) {
            (IANA_WHOIS, "it") => WhoisOutcome::Answer(String::from(IANA_IT)),
            ("whois.nic.it", "esempio.it") => WhoisOutcome::Answer(String::from(
                "*********\n* Please note that the following result\n*********\n\nDomain:             esempio.it\nStatus:             ok\nCreated:            2000-01-01 00:00:00\n\nRegistrar\n  Organization:     Registrar d'esempio\n",
            )),
            _ => WhoisOutcome::Answer(String::from("domain: X\n")),
        }
    }

    fn non_deve_leggere(_: &str, _: BodyLimit) -> Fetched {
        panic!("nessuna lettura doveva partire")
    }

    fn non_deve_chiedere(_: &str, _: &str) -> WhoisOutcome {
        panic!("nessuna domanda doveva partire")
    }

    const FINTA: Network = Network {
        read: leggi,
        ask: chiedi,
    };
    const MUTA: Network = Network {
        read: non_deve_leggere,
        ask: non_deve_chiedere,
    };

    fn adesso(secondi: i64) -> Timestamp {
        Timestamp::from_millis(1_800_000_000_000 + secondi * 1_000)
    }

    fn chi() -> Actor {
        let Ok(chi) = Actor::try_new("operatore.prova") else {
            panic!("valori di prova validi");
        };
        chi
    }

    fn archivio(abilitato: bool) -> Database {
        let Ok(mut database) = Database::open_in_memory() else {
            panic!("l'archivio di prova si apre");
        };
        if abilitato {
            let Ok(_) = choose(
                &mut database,
                true,
                OperatingMode::Administrator,
                &chi(),
                adesso(0),
            ) else {
                panic!("l'amministratore abilita");
            };
        }
        database
    }

    #[test]
    fn si_chiede_il_nome_registrato() {
        assert_eq!(registered_domain("posta.esempio.it"), "esempio.it");
        assert_eq!(registered_domain("esempio.it"), "esempio.it");
        assert_eq!(registered_domain("a.b.esempio.co.uk"), "esempio.co.uk");
        assert_eq!(registered_domain("www.esempio.com"), "esempio.com");
        // `com` sotto un suffisso generico non è un secondo livello.
        assert_eq!(registered_domain("x.com.example"), "com.example");
        assert_eq!(
            query_for("url", "https://posta.esempio.it/accesso"),
            Some(Query::Domain(String::from("esempio.it")))
        );
        let Ok(indirizzo) = "192.0.2.7".parse::<IpAddr>() else {
            panic!("indirizzo di prova");
        };
        assert_eq!(
            query_for("ipv4", "192.0.2.7"),
            Some(Query::Address(indirizzo))
        );
        assert_eq!(query_for("sha256", "abc"), None);
    }

    #[test]
    fn gli_elenchi_iana_danno_soltanto_indirizzi_https() {
        let elenco = ELENCO_DOMINI.as_bytes();
        assert_eq!(
            rdap_base_for_suffix(elenco, "COM").as_deref(),
            Some("https://rdap.esempio-com.invalid/")
        );
        assert_eq!(
            rdap_base_for_suffix(elenco, "org").as_deref(),
            Some("https://rdap.esempio-org.invalid/"),
            "la barra in fondo si aggiunge"
        );
        assert_eq!(
            rdap_base_for_suffix(elenco, "kg"),
            None,
            "in chiaro non si usa"
        );
        assert_eq!(rdap_base_for_suffix(elenco, "it"), None);
        assert_eq!(rdap_base_for_suffix(b"non json", "com"), None);

        let indirizzi = ELENCO_IPV4.as_bytes();
        let indirizzo = |testo: &str| -> IpAddr {
            let Ok(indirizzo) = testo.parse() else {
                panic!("indirizzo di prova");
            };
            indirizzo
        };
        assert_eq!(
            rdap_base_for_address(indirizzi, indirizzo("192.0.2.7")).as_deref(),
            Some("https://rdap.stretto.invalid/"),
            "vince il blocco più stretto"
        );
        assert_eq!(
            rdap_base_for_address(indirizzi, indirizzo("192.1.1.1")).as_deref(),
            Some("https://rdap.ampio.invalid/")
        );
        assert_eq!(
            rdap_base_for_address(indirizzi, indirizzo("198.51.100.1")),
            None
        );
        assert_eq!(
            rdap_base_for_address(indirizzi, indirizzo("2001:db8::1")),
            None
        );
    }

    #[test]
    fn il_server_whois_viene_dalla_riga_di_iana() {
        assert_eq!(
            whois_server_from_iana(IANA_IT).as_deref(),
            Some("whois.nic.it")
        );
        assert_eq!(whois_server_from_iana("domain: XX\nstatus: ACTIVE\n"), None);
        assert_eq!(
            whois_server_from_iana("whois: whois.esempio.invalid:4343\n"),
            None,
            "un'altra porta non è un nome di server"
        );
    }

    #[test]
    fn le_risposte_si_riassumono_e_si_ripuliscono() {
        let Some(riassunto) = summarize_rdap(RISPOSTA_RDAP.as_bytes()) else {
            panic!("la risposta RDAP si legge");
        };
        for atteso in [
            "Nome: ESEMPIO.COM",
            "Registrato il: 1995-08-14T04:00:00Z",
            "Scade il: 2030-08-13T04:00:00Z",
            "Chi l'ha registrato per conto altrui: Registrar d'esempio",
            "Contatto per gli abusi: abuso@esempio.invalid",
            "Nomi di rete che lo servono: A.NS.ESEMPIO.INVALID",
        ] {
            assert!(
                riassunto.contains(atteso),
                "manca «{atteso}» in:\n{riassunto}"
            );
        }
        assert_eq!(summarize_rdap(br#"{"errorCode":404}"#), None);

        assert_eq!(clean_line("a\u{202e}b\u{7}c"), "abc");
        assert_eq!(clean_line(&"x".repeat(500)).chars().count(), 201);
        let whois =
            summarize_whois("% commento\n\nDomain: esempio.it\r\n# altro\n>>> Last update <<<\n");
        assert_eq!(whois, "Domain: esempio.it");

        assert!(whois_says_not_found("No match for \"ESEMPIO.COM\"."));
        assert!(whois_says_not_found(
            "Domain: esempio.it\nStatus:             AVAILABLE\n"
        ));
        assert!(!whois_says_not_found("Domain: esempio.it\nStatus: ok\n"));
    }

    #[test]
    fn spento_di_fabbrica_e_riservato_all_amministratore() {
        let mut database = archivio(false);
        assert!(matches!(
            lookup(
                &mut database,
                MUTA,
                "dominio",
                "esempio.com",
                &chi(),
                false,
                adesso(1)
            ),
            Ok(LookupAttempt::Refused(_))
        ));
        assert!(matches!(
            choose(
                &mut database,
                true,
                OperatingMode::Operator,
                &chi(),
                adesso(1)
            ),
            Err(ServiceError::ActionReservedToAdministrator { .. })
        ));
    }

    #[test]
    fn in_esercitazione_non_parte_nulla() {
        let mut database = archivio(true);
        assert!(matches!(
            lookup(
                &mut database,
                MUTA,
                "dominio",
                "esempio.com",
                &chi(),
                true,
                adesso(1)
            ),
            Ok(LookupAttempt::Refused(_))
        ));
        assert_eq!(
            recent(&database, "dominio", "esempio.com")
                .map(|r| r.len())
                .ok(),
            Some(0)
        );
    }

    /// Un suffisso con RDAP: l'elenco IANA, poi il registro, e nient'altro.
    #[test]
    fn un_dominio_con_rdap_si_chiede_al_registro_dell_elenco() {
        PARTITE.with(|partite| partite.borrow_mut().clear());
        let mut database = archivio(true);
        let Ok(LookupAttempt::Recorded { sentence, .. }) = lookup(
            &mut database,
            FINTA,
            "url",
            "https://www.esempio.com/x",
            &chi(),
            false,
            adesso(1),
        ) else {
            panic!("la richiesta parte e si registra");
        };
        assert!(sentence.contains("Registrar d'esempio"), "{sentence}");
        assert_eq!(
            partite(),
            vec![
                String::from(IANA_RDAP_DOMAINS),
                String::from("https://rdap.esempio-com.invalid/domain/esempio.com"),
            ]
        );
        let Ok(registro) = recent(&database, "url", "https://www.esempio.com/x") else {
            panic!("la lettura riesce");
        };
        assert_eq!(registro[0].queried_name, "esempio.com");
        assert_eq!(registro[0].service, "rdap");
        assert_eq!(registro[0].outcome, "trovato");
        // E non si ripete subito.
        assert!(matches!(
            lookup(
                &mut database,
                MUTA,
                "url",
                "https://www.esempio.com/x",
                &chi(),
                false,
                adesso(3)
            ),
            Ok(LookupAttempt::Refused(_))
        ));
    }

    /// Un suffisso senza RDAP: a IANA si chiede SOLTANTO il suffisso, poi il
    /// nome al server che IANA indica.
    #[test]
    fn un_dominio_senza_rdap_passa_dal_whois_indicato_da_iana() {
        PARTITE.with(|partite| partite.borrow_mut().clear());
        let mut database = archivio(true);
        let Ok(LookupAttempt::Recorded { sentence, .. }) = lookup(
            &mut database,
            FINTA,
            "dominio",
            "posta.esempio.it",
            &chi(),
            false,
            adesso(1),
        ) else {
            panic!("la richiesta parte e si registra");
        };
        assert!(sentence.contains("Status:             ok"), "{sentence}");
        assert_eq!(
            partite(),
            vec![
                String::from(IANA_RDAP_DOMAINS),
                format!("{IANA_WHOIS} it"),
                String::from("whois.nic.it esempio.it"),
            ]
        );
        let Ok(registro) = recent(&database, "dominio", "posta.esempio.it") else {
            panic!("la lettura riesce");
        };
        assert_eq!(registro[0].service, "whois");
        assert_eq!(registro[0].server, "whois.nic.it");
    }

    #[test]
    fn un_indirizzo_si_chiede_al_registro_regionale() {
        PARTITE.with(|partite| partite.borrow_mut().clear());
        let mut database = archivio(true);
        let Ok(LookupAttempt::Recorded { sentence, .. }) = lookup(
            &mut database,
            FINTA,
            "ipv4",
            "192.0.2.7",
            &chi(),
            false,
            adesso(1),
        ) else {
            panic!("la richiesta parte e si registra");
        };
        assert!(sentence.contains("non è registrato"), "{sentence}");
        assert_eq!(
            partite(),
            vec![
                String::from(IANA_RDAP_IPV4),
                String::from("https://rdap.stretto.invalid/ip/192.0.2.7"),
            ]
        );
    }
}

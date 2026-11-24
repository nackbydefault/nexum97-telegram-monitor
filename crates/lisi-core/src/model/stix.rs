//! STIX 2.1: che cosa questo prodotto può dire in un formato che altri
//! consumano, e che cosa tace.
//!
//! # La regola che governa questo modulo
//!
//! **Un fatto più debole non diventa un'affermazione più forte per riuscire a
//! essere esportato.**
//!
//! STIX non è un formato di trasporto neutro: ogni suo oggetto **asserisce**
//! qualcosa, e chi lo riceve lo indicizza e ci agisce sopra. Di un indicatore
//! estratto questo prodotto sa una cosa sola — che una stringa **è comparsa nel
//! testo** di un contenuto acquisito — e nessun oggetto STIX che dica di più
//! può essere costruito da qui.
//!
//! # Che cosa non è costruibile
//!
//! `indicator`, `observed-data`, `sighting`, `relationship`, `identity`,
//! `threat-actor`, `malware`: non esistono in [`StixType`], e non c'è funzione
//! che li produca. Il primo dichiarerebbe che un pattern **rileva attività
//! sospetta**; il secondo che un valore è stato **visto su una rete o un
//! sistema**; il terzo la **convinzione** di averlo visto; il quarto un legame
//! **nominato** fra due oggetti — che è il problema dei percorsi dell'Evidence
//! Graph in forma di interscambio; gli ultimi un'attribuzione.
//!
//! Restano gli **osservabili**, che sono vocabolario e non affermazioni — dicono
//! «questo è un nome di dominio», non che qualcuno lo abbia visitato — la
//! `vulnerability`, che nomina una vulnerabilità **che esiste** senza dire nulla
//! su nessuno, e un `note`, che è il solo oggetto STIX progettato per portare
//! testo informativo senza asserire.
//!
//! La matrice completa, con la ragione di ogni riga, sta in
//! `docs/adr/ADR-0057-STIX-DOVE-LA-SEMANTICA-REGGE.md`.
//!
//! # Perché il modulo non riceve i contenuti
//!
//! Le funzioni di questo modulo ricevono [`CyberIndicator`] — un genere e un
//! valore normalizzato — e nient'altro. Non ricevono il corpo del messaggio,
//! l'autore, l'username, il numero di telefono, la nota dell'operatore né la
//! valutazione di un soggetto: **una funzione che non riceve una cosa non può
//! esportarla**, ed è una garanzia più forte di un elenco di campi da escludere.

use std::collections::BTreeMap;

use uuid::Uuid;

use crate::model::indicator::{
    CyberIndicator, IndicatorKind, as_cve, as_hash, as_url, is_domain, is_ipv4, is_ipv6,
};
use crate::time::Timestamp;

/// Versione della specifica che questo modulo produce.
pub const STIX_SPEC_VERSION: &str = "2.1";

/// Spazio dei nomi degli osservabili, fissato da STIX 2.1 §2.9.
///
/// **Non è nostro e non si cambia.** È la ragione per cui un altro produttore
/// STIX, davanti allo stesso dominio, calcola il medesimo identificativo: è la
/// proprietà per cui l'algoritmo deterministico esiste.
const SCO_NAMESPACE: Uuid = Uuid::from_u128(0x00ab_edb4_aa42_466c_9c01_fed2_3315_a9b7);

/// Spazio dei nomi di NEXUM/97 per gli oggetti che lo standard lascia casuali.
///
/// STIX 2.1 §2.9 raccomanda un UUID versione 4 per gli oggetti di dominio e per
/// il pacchetto, e permette esplicitamente un'alternativa a chi usi «uno spazio
/// dei nomi che garantisca l'unicità». Si usa l'alternativa perché un
/// identificativo casuale renderebbe l'esportazione irriproducibile, e il
/// manifest SHA-256 che accompagna ogni documento di questo prodotto non
/// direbbe più nulla (ADR-0057).
const NEXUM_NAMESPACE: Uuid = Uuid::from_u128(0x5c06_37fe_5d96_478e_afbb_ada9_ed57_c72f);

/// Servizi di messaggistica Telegram, che non escono in un pacchetto STIX.
///
/// `t.me/qualcuno` è un **identificativo personale**, e dice insieme quale
/// account interessa a questo ufficio. Resta visibile dentro NEXUM, dove è al
/// suo posto.
const TELEGRAM_HOSTS: &[&str] = &["t.me", "telegram.me", "telegram.dog", "telesco.pe"];

/// I tipi di oggetto che questo prodotto sa emettere.
///
/// # Perché è un'enumerazione chiusa
///
/// Perché l'esportazione si definisce per ciò che **rifiuta** di emettere.
/// Aggiungere qui un tipo è una decisione di prodotto — dice a un'altra
/// organizzazione qualcosa che prima non le si diceva — e va presa in un ADR,
/// non scrivendo una variante.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StixType {
    /// Un nome di dominio.
    DomainName,
    /// Un indirizzo IPv4.
    Ipv4Addr,
    /// Un indirizzo IPv6.
    Ipv6Addr,
    /// Un indirizzo web.
    Url,
    /// Un file, riconosciuto dalla sola impronta.
    File,
    /// Una vulnerabilità dichiarata.
    Vulnerability,
    /// Testo informativo che non asserisce.
    Note,
    /// Il contenitore.
    Bundle,
}

impl StixType {
    /// Il nome del tipo, come lo scrive lo standard.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DomainName => "domain-name",
            Self::Ipv4Addr => "ipv4-addr",
            Self::Ipv6Addr => "ipv6-addr",
            Self::Url => "url",
            Self::File => "file",
            Self::Vulnerability => "vulnerability",
            Self::Note => "note",
            Self::Bundle => "bundle",
        }
    }

    /// Se il tipo è un osservabile, e quindi porta un identificativo
    /// deterministico calcolato nello spazio dei nomi dello standard.
    #[must_use]
    const fn is_observable(self) -> bool {
        matches!(
            self,
            Self::DomainName | Self::Ipv4Addr | Self::Ipv6Addr | Self::Url | Self::File
        )
    }
}

/// Un identificativo STIX, nella forma `tipo--UUID`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StixId {
    object_type: StixType,
    uuid: Uuid,
}

impl StixId {
    /// Il tipo dell'oggetto identificato.
    #[must_use]
    pub const fn object_type(&self) -> StixType {
        self.object_type
    }

    /// La forma testuale, quella che finisce nel documento.
    #[must_use]
    pub fn as_string(&self) -> String {
        format!("{}--{}", self.object_type.as_str(), self.uuid)
    }
}

/// Un valore JSON **ristretto**: stringhe, elenchi e oggetti di stringhe.
///
/// # Perché ristretto, e perché è una garanzia
///
/// Perché la canonicalizzazione RFC 8785 è difficile **sui numeri**, e qui i
/// numeri non possono arrivare: non c'è variante che li rappresenti. Il
/// canonicalizzatore di questo modulo è quindi corretto per tutto ciò che può
/// ricevere, e non esiste un ingresso che lo porti fuori dai casi coperti.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StixValue {
    /// Una stringa.
    Text(String),
    /// Un elenco, il cui ordine è significativo e si conserva.
    List(Vec<StixValue>),
    /// Un oggetto, le cui chiavi si ordinano.
    Object(BTreeMap<String, StixValue>),
}

impl StixValue {
    /// Comodità di costruzione.
    fn text(value: &str) -> Self {
        Self::Text(String::from(value))
    }

    /// Forma canonica secondo RFC 8785, che è il nome dell'UUID versione 5.
    ///
    /// Chiavi ordinate, nessuno spazio, stringhe con le sole sequenze di fuga
    /// previste da ECMAScript: `"`, `\`, i caratteri di controllo nella loro
    /// forma breve dove esiste e in `\u00xx` altrimenti. I caratteri non ASCII
    /// restano tali, perché il risultato è UTF-8.
    ///
    /// L'ordinamento delle chiavi è quello di [`BTreeMap`], cioè per byte
    /// UTF-8. RFC 8785 chiede l'ordine per unità di codice UTF-16: i due
    /// coincidono su tutto ciò che questo modulo produce, dove **ogni chiave è
    /// una costante ASCII** scritta qui sotto.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut out = String::new();
        self.write_canonical(&mut out);
        out
    }

    fn write_canonical(&self, out: &mut String) {
        match self {
            Self::Text(value) => write_json_string(value, out),
            Self::List(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write_canonical(out);
                }
                out.push(']');
            }
            Self::Object(fields) => {
                out.push('{');
                for (index, (key, value)) in fields.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write_json_string(key, out);
                    out.push(':');
                    value.write_canonical(out);
                }
                out.push('}');
            }
        }
    }
}

/// Scrive una stringa JSON secondo RFC 8785.
fn write_json_string(value: &str, out: &mut String) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{9}' => out.push_str("\\t"),
            '\u{a}' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\u{d}' => out.push_str("\\r"),
            control if control < '\u{20}' => {
                // Le altre posizioni di controllo non hanno forma breve.
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

/// L'UUID versione 5 di un nome già in forma canonica.
///
/// Sta qui, isolato e con il nome già canonicalizzato in ingresso, perché sia
/// possibile esercitarlo con il **vettore ufficiale** della implementazione di
/// riferimento OASIS senza costruire un oggetto che questo prodotto non emette.
#[must_use]
pub fn observable_uuid_from_canonical(canonical_name: &str) -> Uuid {
    Uuid::new_v5(&SCO_NAMESPACE, canonical_name.as_bytes())
}

/// Un oggetto STIX pronto a essere scritto.
///
/// # Perché i campi sono privati
///
/// Perché un oggetto STIX di questo prodotto non si compone dall'esterno: si
/// **deriva** da un indicatore, e la derivazione è il punto in cui la matrice
/// semantica viene applicata. Un costruttore libero permetterebbe di aggirarla
/// senza toccare né questo modulo né le sue prove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StixObject {
    id: StixId,
    fields: BTreeMap<String, StixValue>,
}

impl StixObject {
    /// L'identificativo.
    #[must_use]
    pub const fn id(&self) -> &StixId {
        &self.id
    }

    /// Il tipo.
    #[must_use]
    pub const fn object_type(&self) -> StixType {
        self.id.object_type
    }

    /// L'oggetto come valore JSON ristretto, `type` e `id` compresi.
    #[must_use]
    pub fn to_value(&self) -> StixValue {
        let mut fields = self.fields.clone();
        fields.insert(
            String::from("type"),
            StixValue::text(self.id.object_type.as_str()),
        );
        fields.insert(String::from("id"), StixValue::Text(self.id.as_string()));
        fields.insert(
            String::from("spec_version"),
            StixValue::text(STIX_SPEC_VERSION),
        );
        StixValue::Object(fields)
    }

    /// Costruisce un osservabile, calcolandone l'identificativo deterministico.
    fn observable(object_type: StixType, id_properties: BTreeMap<String, StixValue>) -> Self {
        debug_assert!(
            object_type.is_observable(),
            "l'identificativo deterministico dello standard vale per gli osservabili"
        );
        let canonical = StixValue::Object(id_properties.clone()).to_canonical_json();
        let uuid = observable_uuid_from_canonical(&canonical);
        Self {
            id: StixId { object_type, uuid },
            fields: id_properties,
        }
    }
}

/// Perché un valore non è diventato un oggetto STIX.
///
/// # Perché l'omissione è un esito e non un silenzio
///
/// Perché un pacchetto formalmente valido e falso è peggio di un pacchetto
/// incompleto: chi lo riceve non ha modo di accorgersene. Un elemento che non
/// si può rappresentare correttamente esce dall'esportazione **con il proprio
/// motivo scritto**, e chi legge sa che cosa non gli è stato detto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StixOmission {
    /// Il valore conservato non ha più la forma che il suo genere promette.
    MalformedValue,
    /// Il valore nomina un servizio di messaggistica Telegram.
    TelegramIdentifier,
}

impl StixOmission {
    /// Etichetta stabile, per l'audit e per il manifest.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedValue => "forma_non_valida",
            Self::TelegramIdentifier => "identificativo_telegram",
        }
    }

    /// Il motivo, come si scrive a una persona.
    #[must_use]
    pub const fn as_sentence(self) -> &'static str {
        match self {
            Self::MalformedValue => {
                "il valore conservato non ha la forma che il suo genere richiede, e \
                 un oggetto STIX con un valore sbagliato è un oggetto falso"
            }
            Self::TelegramIdentifier => {
                "nomina un servizio di messaggistica Telegram, che è un identificativo \
                 personale e dice quale account interessa a questo ufficio"
            }
        }
    }
}

/// Deriva l'oggetto STIX di un indicatore, oppure il motivo per cui non esiste.
///
/// # La matrice, in una funzione
///
/// Ogni ramo emette **soltanto** ciò che il dato regge: un osservabile per i
/// valori tecnici, che dice che cosa quel valore è e nient'altro, e una
/// `vulnerability` per una CVE, che nomina una vulnerabilità esistente senza
/// dire che sia stata sfruttata, né da chi, né dove.
///
/// La forma si **riconvalida** con le stesse funzioni che l'hanno riconosciuta
/// in fase di estrazione: l'archivio si rilegge, e una riga scritta da un'altra
/// versione o modificata a mano non deve poter uscire come oggetto standard.
///
/// # Errori
///
/// Restituisce il motivo dell'omissione quando il valore non è rappresentabile.
pub fn object_for(indicator: &CyberIndicator) -> Result<StixObject, StixOmission> {
    let value = indicator.value.as_str();

    match indicator.kind {
        IndicatorKind::Cve => {
            let normalised = as_cve(value).ok_or(StixOmission::MalformedValue)?;
            if normalised != value {
                // Una CVE conservata in una forma diversa da quella normalizzata
                // e' una riga che il prodotto non ha scritto.
                return Err(StixOmission::MalformedValue);
            }
            Ok(vulnerability(&normalised))
        }
        IndicatorKind::Ipv4 => {
            if !is_ipv4(value) {
                return Err(StixOmission::MalformedValue);
            }
            Ok(simple_observable(StixType::Ipv4Addr, value))
        }
        IndicatorKind::Ipv6 => {
            if !is_ipv6(value) {
                return Err(StixOmission::MalformedValue);
            }
            Ok(simple_observable(StixType::Ipv6Addr, value))
        }
        IndicatorKind::Domain => {
            if !is_domain(value) {
                return Err(StixOmission::MalformedValue);
            }
            if is_telegram_host(value) {
                return Err(StixOmission::TelegramIdentifier);
            }
            Ok(simple_observable(StixType::DomainName, value))
        }
        IndicatorKind::Url => {
            let host = as_url(value).ok_or(StixOmission::MalformedValue)?;
            if is_telegram_host(&host) {
                return Err(StixOmission::TelegramIdentifier);
            }
            Ok(simple_observable(StixType::Url, value))
        }
        IndicatorKind::Md5 | IndicatorKind::Sha1 | IndicatorKind::Sha256 => {
            if as_hash(value) != Some(indicator.kind) {
                return Err(StixOmission::MalformedValue);
            }
            Ok(file_with_hash(indicator.kind, value))
        }
    }
}

/// Se un host appartiene a un servizio di messaggistica Telegram.
///
/// Confronta l'host **intero** e i suoi sottodomini, non una sottostringa:
/// `nont.me.esempio.test` non è `t.me`, e un confronto per contenuto lo
/// scarterebbe.
fn is_telegram_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    TELEGRAM_HOSTS
        .iter()
        .any(|telegram| host == *telegram || host.ends_with(&format!(".{telegram}")))
}

/// Un osservabile la cui sola proprietà identificante è `value`.
fn simple_observable(object_type: StixType, value: &str) -> StixObject {
    let mut properties = BTreeMap::new();
    properties.insert(String::from("value"), StixValue::text(value));
    StixObject::observable(object_type, properties)
}

/// Un `file` riconosciuto dalla sola impronta.
///
/// # Perché un file per ogni impronta
///
/// Perché se un messaggio nomina l'MD5 e il SHA-256, NEXUM **non sa** che sono
/// lo stesso file: unirli sarebbe un'affermazione che nessuno ha fatto. Ne
/// segue anche che la precedenza fra impronte prevista dallo standard non si
/// applica mai, perché ogni `file` ne porta esattamente una.
fn file_with_hash(kind: IndicatorKind, value: &str) -> StixObject {
    let algorithm = match kind {
        IndicatorKind::Md5 => "MD5",
        IndicatorKind::Sha1 => "SHA-1",
        _ => "SHA-256",
    };
    let mut hashes = BTreeMap::new();
    hashes.insert(String::from(algorithm), StixValue::text(value));

    let mut properties = BTreeMap::new();
    properties.insert(String::from("hashes"), StixValue::Object(hashes));
    StixObject::observable(StixType::File, properties)
}

/// Una `vulnerability` che nomina una CVE, e nient'altro.
///
/// Il riferimento esterno porta `source_name` uguale a `cve` e `external_id`
/// uguale all'identificativo esatto, che è la forma con cui lo standard nomina
/// una vulnerabilità del catalogo.
///
/// **Non dice che sia stata sfruttata.** Una CVE nominata in un messaggio
/// Telegram è una CVE nominata in un messaggio Telegram.
fn vulnerability(cve: &str) -> StixObject {
    let mut reference = BTreeMap::new();
    reference.insert(String::from("source_name"), StixValue::text("cve"));
    reference.insert(String::from("external_id"), StixValue::text(cve));

    let mut fields = BTreeMap::new();
    fields.insert(String::from("name"), StixValue::text(cve));
    fields.insert(
        String::from("external_references"),
        StixValue::List(vec![StixValue::Object(reference)]),
    );

    let mut identifying = BTreeMap::new();
    identifying.insert(String::from("name"), StixValue::text(cve));
    identifying.insert(
        String::from("type"),
        StixValue::text(StixType::Vulnerability.as_str()),
    );
    let uuid = Uuid::new_v5(
        &NEXUM_NAMESPACE,
        StixValue::Object(identifying)
            .to_canonical_json()
            .as_bytes(),
    );

    StixObject {
        id: StixId {
            object_type: StixType::Vulnerability,
            uuid,
        },
        fields,
    }
}

/// L'avvertenza che accompagna ogni pacchetto.
///
/// # Perché è dentro il pacchetto e non accanto
///
/// Perché un file viaggia da solo. Un pacchetto che elenca dieci domini senza
/// dire che cosa siano si legge come un elenco di indicatori di compromissione,
/// che è precisamente ciò che non è. L'avvertenza deve poter essere letta da
/// chi apre il file e non ha visto null'altro.
#[must_use]
pub fn caveat_text(product: &str, version: &str) -> String {
    format!(
        "Prodotto da {product} {version}. I valori di questo pacchetto sono stati \
         NOMINATI NEL TESTO di contenuti acquisiti da fonti autorizzate, e nient'altro \
         è affermato di essi. Non sono stati osservati su una rete o su un sistema, non \
         sono dichiarati dannosi, non sono indicatori di compromissione, e la loro \
         presenza in questo pacchetto non asserisce alcun legame fra di essi né alcuna \
         attribuzione a persona od organizzazione. Le valutazioni interne del prodotto e \
         quelle dei suoi operatori non sono esportate. Ideazione e progettazione: Giuseppe LISI."
    )
}

/// Un pacchetto pronto a essere scritto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StixBundle {
    id: StixId,
    objects: Vec<StixObject>,
}

impl StixBundle {
    /// Compone il pacchetto: gli oggetti, e la nota che li accompagna.
    ///
    /// L'ordine degli oggetti è quello ricevuto, e la nota va in fondo perché
    /// riferisce tutti gli altri. L'identificativo del pacchetto si calcola sul
    /// suo contenuto, così che due esportazioni della stessa selezione lo
    /// producano uguale.
    #[must_use]
    pub fn new(objects: Vec<StixObject>, caveat: &str, now: Timestamp) -> Self {
        let mut objects = objects;
        if !objects.is_empty() {
            objects.push(note(&objects, caveat, now));
        }

        let identifiers: Vec<StixValue> = objects
            .iter()
            .map(|object| StixValue::Text(object.id.as_string()))
            .collect();
        let mut identifying = BTreeMap::new();
        identifying.insert(String::from("objects"), StixValue::List(identifiers));
        identifying.insert(
            String::from("type"),
            StixValue::text(StixType::Bundle.as_str()),
        );
        let uuid = Uuid::new_v5(
            &NEXUM_NAMESPACE,
            StixValue::Object(identifying)
                .to_canonical_json()
                .as_bytes(),
        );

        Self {
            id: StixId {
                object_type: StixType::Bundle,
                uuid,
            },
            objects,
        }
    }

    /// L'identificativo del pacchetto.
    #[must_use]
    pub const fn id(&self) -> &StixId {
        &self.id
    }

    /// Gli oggetti contenuti.
    #[must_use]
    pub fn objects(&self) -> &[StixObject] {
        &self.objects
    }

    /// Se il pacchetto non contiene nulla.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// Il pacchetto come valore JSON ristretto.
    ///
    /// Il contenitore **non porta `spec_version`**: STIX 2.1 lo ha tolto dal
    /// pacchetto e lo mette su ciascun oggetto, e aggiungerlo qui lo renderebbe
    /// una proprietà personalizzata dentro un formato standard.
    #[must_use]
    pub fn to_value(&self) -> StixValue {
        let mut fields = BTreeMap::new();
        fields.insert(
            String::from("type"),
            StixValue::text(StixType::Bundle.as_str()),
        );
        fields.insert(String::from("id"), StixValue::Text(self.id.as_string()));
        fields.insert(
            String::from("objects"),
            StixValue::List(self.objects.iter().map(StixObject::to_value).collect()),
        );
        StixValue::Object(fields)
    }
}

/// La nota che riferisce tutti gli oggetti del pacchetto.
fn note(objects: &[StixObject], caveat: &str, now: Timestamp) -> StixObject {
    let refs: Vec<StixValue> = objects
        .iter()
        .map(|object| StixValue::Text(object.id.as_string()))
        .collect();

    let mut fields = BTreeMap::new();
    fields.insert(String::from("content"), StixValue::text(caveat));
    fields.insert(String::from("object_refs"), StixValue::List(refs.clone()));
    fields.insert(String::from("created"), StixValue::Text(now.to_stix_utc()));
    fields.insert(String::from("modified"), StixValue::Text(now.to_stix_utc()));

    let mut identifying = BTreeMap::new();
    identifying.insert(String::from("content"), StixValue::text(caveat));
    identifying.insert(String::from("object_refs"), StixValue::List(refs));
    identifying.insert(
        String::from("type"),
        StixValue::text(StixType::Note.as_str()),
    );
    let uuid = Uuid::new_v5(
        &NEXUM_NAMESPACE,
        StixValue::Object(identifying)
            .to_canonical_json()
            .as_bytes(),
    );

    StixObject {
        id: StixId {
            object_type: StixType::Note,
            uuid,
        },
        fields,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn indicatore(kind: IndicatorKind, value: &str) -> CyberIndicator {
        CyberIndicator {
            kind,
            value: String::from(value),
        }
    }

    fn id_of(kind: IndicatorKind, value: &str) -> String {
        match object_for(&indicatore(kind, value)) {
            Ok(object) => object.id().as_string(),
            Err(omission) => panic!("doveva essere esportabile, omesso: {}", omission.as_str()),
        }
    }

    /// **Il vettore ufficiale della implementazione di riferimento OASIS.**
    ///
    /// È l'unica prova di questo modulo che non dipende dal nostro giudizio:
    /// la chiave di registro di `cti-python-stix2/test_deterministic_ids.py`,
    /// con il suo identificativo atteso. Se il canonicalizzatore RFC 8785 o
    /// l'UUID versione 5 sbagliassero, diventerebbe rossa.
    #[test]
    fn l_algoritmo_riproduce_il_vettore_ufficiale_oasis() {
        let canonico = "{\"values\":[{\"data\":\"qwerty\",\"name\":\"Foo\"},\
                        {\"data\":\"42\",\"name\":\"Bar\"}]}";
        assert_eq!(
            observable_uuid_from_canonical(canonico).to_string(),
            "36594eba-bcc7-5014-9835-0e154264e588"
        );
    }

    /// Il canonicalizzatore compone davvero quella forma, e non solo la ripete.
    #[test]
    fn il_canonicalizzatore_compone_il_vettore_ufficiale() {
        let voce = |data: &str, name: &str| {
            let mut campo = BTreeMap::new();
            campo.insert(String::from("name"), StixValue::text(name));
            campo.insert(String::from("data"), StixValue::text(data));
            StixValue::Object(campo)
        };
        let mut oggetto = BTreeMap::new();
        oggetto.insert(
            String::from("values"),
            StixValue::List(vec![voce("qwerty", "Foo"), voce("42", "Bar")]),
        );

        let canonico = StixValue::Object(oggetto).to_canonical_json();
        assert_eq!(
            canonico,
            "{\"values\":[{\"data\":\"qwerty\",\"name\":\"Foo\"},\
             {\"data\":\"42\",\"name\":\"Bar\"}]}"
        );
        assert_eq!(
            observable_uuid_from_canonical(&canonico).to_string(),
            "36594eba-bcc7-5014-9835-0e154264e588"
        );
    }

    /// Gli identificativi degli osservabili sono quelli che calcolerebbe
    /// chiunque altro applichi lo standard.
    ///
    /// I valori attesi sono stati calcolati **fuori da questo codice**, con una
    /// implementazione indipendente di SHA-1 e della costruzione UUID versione
    /// 5: se il modulo cambiasse algoritmo per errore, li mancherebbe.
    #[test]
    fn gli_identificativi_degli_osservabili_sono_interoperabili() {
        assert_eq!(
            id_of(IndicatorKind::Domain, "esempio.test"),
            "domain-name--d9f56f5f-7dee-5557-9004-3525f17ce55a"
        );
        assert_eq!(
            id_of(IndicatorKind::Ipv4, "198.51.100.3"),
            "ipv4-addr--28bb3599-77cd-5a82-a950-b5bc3caf07c4"
        );
        assert_eq!(
            id_of(IndicatorKind::Ipv6, "2001:db8::1"),
            "ipv6-addr--6469e3a9-b053-5e34-a025-9396ae051d26"
        );
        assert_eq!(
            id_of(IndicatorKind::Url, "https://esempio.test/a"),
            "url--a81aa6db-813b-5526-a9b8-b96b65c27d02"
        );
        assert_eq!(
            id_of(
                IndicatorKind::Sha256,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ),
            "file--22f8ff52-8f62-5f03-a53a-6f50f54fd74c"
        );
        assert_eq!(
            id_of(IndicatorKind::Md5, "d41d8cd98f00b204e9800998ecf8427e"),
            "file--02fff920-f614-527c-81d1-6353633a6d21"
        );
    }

    /// **Una menzione non è un indicatore.**
    ///
    /// Il dominio nominato in un messaggio esce come `domain-name`, che dice
    /// che cosa quel valore è. Non esce come `indicator`, che direbbe che
    /// rileva attività sospetta.
    #[test]
    fn un_dominio_nominato_non_diventa_un_indicator() {
        let Ok(object) = object_for(&indicatore(IndicatorKind::Domain, "esempio.test")) else {
            panic!("un dominio ben formato deve essere esportabile");
        };
        assert_eq!(object.object_type(), StixType::DomainName);
        // Il nome scritto, non solo la variante: e' quello che legge chi
        // riceve il pacchetto, ed e' li' che una sovra-affermazione arriva.
        assert_eq!(object.object_type().as_str(), "domain-name");
        assert!(object.id().as_string().starts_with("domain-name--"));
    }

    /// **Un indirizzo nominato non diventa attività malevola.**
    #[test]
    fn un_indirizzo_nominato_non_diventa_attivita_malevola() {
        let Ok(object) = object_for(&indicatore(IndicatorKind::Ipv4, "198.51.100.3")) else {
            panic!("un indirizzo ben formato deve essere esportabile");
        };
        assert_eq!(object.object_type(), StixType::Ipv4Addr);
        let json = object.to_value().to_canonical_json();
        for parola in [
            "malicious",
            "indicator",
            "observed-data",
            "labels",
            "pattern",
        ] {
            assert!(
                !json.contains(parola),
                "l'osservabile non deve portare «{parola}»: {json}"
            );
        }
    }

    /// **Un'impronta non diventa una compromissione.**
    #[test]
    fn un_impronta_non_diventa_una_compromissione() {
        let Ok(object) = object_for(&indicatore(
            IndicatorKind::Sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )) else {
            panic!("un'impronta ben formata deve essere esportabile");
        };
        assert_eq!(object.object_type(), StixType::File);
        let json = object.to_value().to_canonical_json();
        assert!(json.contains("\"SHA-256\""));
        for parola in ["malware", "indicator", "compromise", "observed-data"] {
            assert!(
                !json.contains(parola),
                "il file non deve portare «{parola}»"
            );
        }
    }

    /// **Una CVE produce una vulnerability, e non dichiara sfruttamento.**
    #[test]
    fn una_cve_produce_una_vulnerability_senza_sfruttamento() {
        let Ok(object) = object_for(&indicatore(IndicatorKind::Cve, "CVE-2026-1234")) else {
            panic!("una CVE ben formata deve essere esportabile");
        };
        assert_eq!(object.object_type(), StixType::Vulnerability);

        let json = object.to_value().to_canonical_json();
        assert!(json.contains("\"source_name\":\"cve\""));
        assert!(json.contains("\"external_id\":\"CVE-2026-1234\""));
        for parola in [
            "exploit",
            "exploited",
            "indicator",
            "sighting",
            "threat-actor",
            "campaign",
        ] {
            assert!(
                !json.contains(parola),
                "la vulnerability non deve portare «{parola}»: {json}"
            );
        }
    }

    /// L'identificativo della vulnerability è stabile fra due esportazioni.
    #[test]
    fn la_vulnerability_ha_un_identificativo_stabile() {
        assert_eq!(
            id_of(IndicatorKind::Cve, "CVE-2026-1234"),
            "vulnerability--f1e731ca-c3e8-56ad-8b69-4efa64ff90e0"
        );
    }

    /// **Un valore che non regge la propria forma si omette.**
    #[test]
    fn un_valore_deformato_si_omette_con_il_motivo() {
        for (kind, value) in [
            (IndicatorKind::Ipv4, "999.1.1.1"),
            (IndicatorKind::Ipv4, "non-un-indirizzo"),
            (IndicatorKind::Ipv6, "nemmeno-questo"),
            (IndicatorKind::Domain, "esempio"),
            (IndicatorKind::Url, "ftp://esempio.test/a"),
            (IndicatorKind::Cve, "CVE-26-1"),
            (IndicatorKind::Sha256, "abc"),
            (IndicatorKind::Md5, "d41d8cd98f00b204e9800998ecf8427"),
        ] {
            assert_eq!(
                object_for(&indicatore(kind, value)),
                Err(StixOmission::MalformedValue),
                "«{value}» non doveva essere rappresentabile"
            );
        }
    }

    /// Un'impronta conservata sotto il genere sbagliato non si riscrive: si omette.
    #[test]
    fn un_impronta_di_lunghezza_diversa_dal_genere_si_omette() {
        assert_eq!(
            object_for(&indicatore(
                IndicatorKind::Md5,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )),
            Err(StixOmission::MalformedValue)
        );
    }

    /// **Un identificativo Telegram non esce.**
    #[test]
    fn un_riferimento_telegram_si_omette_con_il_motivo() {
        for (kind, value) in [
            (IndicatorKind::Domain, "t.me"),
            (IndicatorKind::Domain, "telegram.me"),
            (IndicatorKind::Url, "https://t.me/mario_rossi"),
            (IndicatorKind::Url, "https://web.telegram.org/x"),
        ] {
            let esito = object_for(&indicatore(kind, value));
            if value.contains("web.telegram.org") {
                // Non e' un servizio di messaggistica diretta: resta esportabile.
                assert!(esito.is_ok());
                continue;
            }
            assert_eq!(
                esito,
                Err(StixOmission::TelegramIdentifier),
                "«{value}» non doveva uscire"
            );
        }
    }

    /// Un host che *somiglia* a Telegram senza esserlo non si omette per errore.
    #[test]
    fn un_host_che_somiglia_a_telegram_non_si_omette() {
        let Ok(object) = object_for(&indicatore(IndicatorKind::Domain, "nont.me.esempio.test"))
        else {
            panic!("non è un host Telegram e deve poter uscire");
        };
        assert_eq!(object.object_type(), StixType::DomainName);
    }

    /// **Nel pacchetto non compare mai un tipo vietato.**
    ///
    /// La guardia del tipo impedisce di costruirli; questa impedisce che
    /// qualcuno domani aggiunga una variante senza accorgersi di che cosa
    /// significhi.
    #[test]
    fn il_pacchetto_non_contiene_alcun_tipo_vietato() {
        let indicatori = [
            indicatore(IndicatorKind::Domain, "esempio.test"),
            indicatore(IndicatorKind::Ipv4, "198.51.100.3"),
            indicatore(IndicatorKind::Cve, "CVE-2026-1234"),
            indicatore(
                IndicatorKind::Sha256,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
        ];
        let oggetti: Vec<StixObject> = indicatori
            .iter()
            .filter_map(|i| object_for(i).ok())
            .collect();
        let bundle = StixBundle::new(
            oggetti,
            "avvertenza",
            Timestamp::from_millis(1_757_000_000_000),
        );

        let json = bundle.to_value().to_canonical_json();
        for vietato in [
            "indicator",
            "observed-data",
            "sighting",
            "relationship",
            "identity",
            "threat-actor",
            "malware",
            "attack-pattern",
            "campaign",
            "intrusion-set",
            "grouping",
            "opinion",
            "infrastructure",
            "created_by_ref",
            "confidence",
        ] {
            assert!(
                !json.contains(&format!("\"{vietato}\"")),
                "il pacchetto non deve nominare «{vietato}»"
            );
        }
    }

    /// Ogni oggetto del pacchetto porta un tipo dell'insieme ammesso.
    #[test]
    fn ogni_oggetto_porta_un_tipo_ammesso() {
        let oggetti = vec![
            simple_observable(StixType::DomainName, "esempio.test"),
            vulnerability("CVE-2026-1234"),
        ];
        let bundle = StixBundle::new(oggetti, "avvertenza", Timestamp::from_millis(0));

        let ammessi = [
            StixType::DomainName,
            StixType::Ipv4Addr,
            StixType::Ipv6Addr,
            StixType::Url,
            StixType::File,
            StixType::Vulnerability,
            StixType::Note,
        ];
        for object in bundle.objects() {
            assert!(
                ammessi.contains(&object.object_type()),
                "tipo non ammesso: {}",
                object.object_type().as_str()
            );
        }
        assert_eq!(bundle.id().object_type(), StixType::Bundle);
    }

    /// La nota riferisce tutti gli oggetti, e nessuno riferisce la nota.
    #[test]
    fn la_nota_riferisce_ogni_oggetto_del_pacchetto() {
        let oggetti = vec![
            simple_observable(StixType::DomainName, "esempio.test"),
            simple_observable(StixType::Ipv4Addr, "198.51.100.3"),
        ];
        let attesi: Vec<String> = oggetti.iter().map(|o| o.id().as_string()).collect();
        let bundle = StixBundle::new(oggetti, "avvertenza", Timestamp::from_millis(0));

        let Some(nota) = bundle
            .objects()
            .iter()
            .find(|object| object.object_type() == StixType::Note)
        else {
            panic!("il pacchetto deve portare la propria avvertenza");
        };
        let json = nota.to_value().to_canonical_json();
        for atteso in attesi {
            assert!(json.contains(&atteso), "la nota deve riferire {atteso}");
        }
    }

    /// Un pacchetto senza oggetti non porta nemmeno la nota: una nota che non
    /// riferisce nulla non è costruibile secondo lo standard.
    #[test]
    fn un_pacchetto_vuoto_non_porta_una_nota_senza_riferimenti() {
        let bundle = StixBundle::new(Vec::new(), "avvertenza", Timestamp::from_millis(0));
        assert!(bundle.is_empty());
        let json = bundle.to_value().to_canonical_json();
        assert!(!json.contains("note--"));
    }

    /// **Due composizioni della stessa selezione danno lo stesso pacchetto.**
    #[test]
    fn due_composizioni_uguali_danno_lo_stesso_pacchetto() {
        let comporre = || {
            let oggetti = vec![
                simple_observable(StixType::DomainName, "esempio.test"),
                vulnerability("CVE-2026-1234"),
            ];
            StixBundle::new(
                oggetti,
                "avvertenza",
                Timestamp::from_millis(1_757_000_000_000),
            )
            .to_value()
            .to_canonical_json()
        };
        assert_eq!(comporre(), comporre());
    }

    /// L'identificativo del pacchetto non dipende dall'istante: due
    /// esportazioni della stessa selezione restano riconoscibili come la stessa.
    #[test]
    fn gli_identificativi_degli_osservabili_non_dipendono_dall_istante() {
        let primo = simple_observable(StixType::DomainName, "esempio.test");
        let secondo = simple_observable(StixType::DomainName, "esempio.test");
        assert_eq!(primo.id().as_string(), secondo.id().as_string());
    }

    /// Le sequenze di fuga sono quelle di RFC 8785, non quelle comode.
    #[test]
    fn le_stringhe_si_scrivono_secondo_rfc_8785() {
        let mut oggetto = BTreeMap::new();
        oggetto.insert(
            String::from("value"),
            StixValue::Text(String::from("a\"b\\c\nd\u{1}e\u{7f}f€")),
        );
        assert_eq!(
            StixValue::Object(oggetto).to_canonical_json(),
            "{\"value\":\"a\\\"b\\\\c\\nd\\u0001e\u{7f}f€\"}"
        );
    }

    /// Le chiavi escono ordinate, comunque siano state inserite.
    #[test]
    fn le_chiavi_escono_ordinate() {
        let mut oggetto = BTreeMap::new();
        oggetto.insert(String::from("zeta"), StixValue::text("2"));
        oggetto.insert(String::from("alfa"), StixValue::text("1"));
        assert_eq!(
            StixValue::Object(oggetto).to_canonical_json(),
            "{\"alfa\":\"1\",\"zeta\":\"2\"}"
        );
    }

    /// L'avvertenza dice le tre cose che non sono affermate.
    #[test]
    fn l_avvertenza_dichiara_cio_che_non_afferma() {
        let testo = caveat_text("NEXUM/97", "0.1.0");
        for frase in [
            "NOMINATI NEL TESTO",
            "Non sono stati osservati",
            "non asserisce alcun legame",
            "Ideazione e progettazione: Giuseppe LISI",
        ] {
            assert!(testo.contains(frase), "l'avvertenza deve dire «{frase}»");
        }
    }
}

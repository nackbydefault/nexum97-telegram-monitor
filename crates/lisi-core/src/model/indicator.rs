//! Gli indicatori tecnici estratti da un contenuto.
//!
//! CVE, indirizzi, domini, URL e impronte: si **estraggono** e si conservano
//! come dati.
//!
//! # La regola che governa questo modulo
//!
//! **Un indicatore si estrae, non si contatta.**
//!
//! Nessuna risoluzione DNS, nessuna connessione, nessun prelievo, nessun
//! download. Questo modulo non ha accesso alla rete e non deve averlo mai:
//! contattare un indicatore significherebbe due cose ugualmente inaccettabili —
//! eseguire codice altrui su una postazione d'ufficio, e dire a chi ha
//! pubblicato quel contenuto che qualcuno lo sta guardando (ADR-0035 Decisione
//! 8).
//!
//! # Perche' nessuna espressione regolare
//!
//! Il testo da cui si estrae arriva da Telegram, cioe' e' **ostile per
//! definizione**, e un messaggio costruito apposta puo' far esplodere il tempo
//! di analisi di un'espressione regolare con ripetizioni annidate — fermando il
//! monitoraggio senza che nessuno capisca perche'.
//!
//! Qui non ci sono espressioni regolari. C'e' una **passata sola**, che divide
//! il testo in parole e classifica ciascuna guardandola una volta. Non esiste
//! ritorno all'indietro, quindi la catastrofe combinatoria non e' mitigata:
//! **non e' possibile**. Ed e' anche il motivo per cui il workspace non
//! acquisisce un motore di espressioni regolari solo per questo.
//!
//! # I limiti, e perche' ci sono
//!
//! Un contenuto puo' essere lungo quanto la fonte vuole. Si analizza fino a
//! [`MAX_TEXT_CHARS`] e si estraggono fino a [`MAX_INDICATORS`] indicatori: oltre
//! quella misura non si sta piu' analizzando un messaggio, si sta subendo un
//! ingresso costruito.

use std::collections::BTreeSet;

/// Quanti caratteri di un contenuto si analizzano.
///
/// Un messaggio piu' lungo di cosi' non e' un messaggio: e' un carico. Il
/// troncamento **si dichiara** nel risultato invece di essere silenzioso.
pub const MAX_TEXT_CHARS: usize = 64 * 1024;

/// Quanti indicatori si estraggono da un singolo contenuto.
///
/// Un contenuto che ne contiene di piu' e' quasi certamente un elenco
/// automatico, e conservarli tutti riempirebbe l'archivio con dati che nessuno
/// leggera'.
pub const MAX_INDICATORS: usize = 512;

/// Lunghezza massima di una parola che si prende in considerazione.
///
/// Il piu' lungo indicatore ammesso e' un URL, e oltre questa misura non e' un
/// URL: e' una stringa costruita per occupare memoria.
const MAX_TOKEN_CHARS: usize = 2_048;

/// Estensioni che somigliano a domini di primo livello e non lo sono.
///
/// `relazione.pdf` ha la stessa forma di `esempio.it`, e senza questo elenco
/// ogni nome di file diventerebbe un dominio. **Riduce, non elimina**: non e'
/// un elenco dei domini esistenti, e non lo sara' — quello invecchierebbe e
/// andrebbe aggiornato dalla rete, che la v1 non fa.
const FILE_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "odt", "csv", "zip", "rar",
    "7z", "tar", "gz", "exe", "dll", "msi", "bat", "cmd", "ps1", "sh", "apk", "dmg", "iso", "jpg",
    "jpeg", "png", "gif", "bmp", "svg", "webp", "mp3", "mp4", "avi", "mkv", "mov", "wav", "json",
    "xml", "html", "htm", "css", "js", "py", "rs", "log", "bak", "tmp", "eml", "msg",
];

/// Il genere di un indicatore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IndicatorKind {
    /// Identificativo di vulnerabilita' `CVE-anno-numero`.
    Cve,
    /// Indirizzo IPv4.
    Ipv4,
    /// Indirizzo IPv6.
    Ipv6,
    /// Nome di dominio.
    Domain,
    /// Indirizzo web completo.
    Url,
    /// Impronta MD5, 32 cifre esadecimali.
    Md5,
    /// Impronta SHA-1, 40 cifre esadecimali.
    Sha1,
    /// Impronta SHA-256, 64 cifre esadecimali.
    Sha256,
}

impl IndicatorKind {
    /// Tutti i generi, nell'ordine in cui si mostrano.
    ///
    /// # Il limite di questo elenco
    ///
    /// Rust garantisce che `as_str` copra ogni variante — il `match` e'
    /// esaustivo — ma **non** che una variante nuova venga aggiunta qui. Una
    /// prova percorre l'elenco e verifica che ogni etichetta si riconosca; se
    /// un giorno un genere venisse aggiunto e dimenticato qui, l'archivio
    /// smetterebbe di saperlo rileggere. E' scritto perche' chi aggiunge una
    /// variante lo legga.
    pub const ALL: &'static [Self] = &[
        Self::Cve,
        Self::Ipv4,
        Self::Ipv6,
        Self::Domain,
        Self::Url,
        Self::Md5,
        Self::Sha1,
        Self::Sha256,
    ];

    /// Riconosce un genere dalla propria etichetta stabile.
    ///
    /// Restituisce `None` per un'etichetta sconosciuta: un archivio scritto da
    /// una versione che non conosciamo, o modificato a mano, non va indovinato.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| kind.as_str() == raw)
    }

    /// Etichetta stabile, per archivio, audit e documenti.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cve => "cve",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Domain => "dominio",
            Self::Url => "url",
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    /// Frase per l'operatore.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Cve => "vulnerabilità dichiarata",
            Self::Ipv4 => "indirizzo IPv4",
            Self::Ipv6 => "indirizzo IPv6",
            Self::Domain => "nome di dominio",
            Self::Url => "indirizzo web",
            Self::Md5 => "impronta MD5",
            Self::Sha1 => "impronta SHA-1",
            Self::Sha256 => "impronta SHA-256",
        }
    }
}

/// Un indicatore estratto.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CyberIndicator {
    /// Genere.
    pub kind: IndicatorKind,
    /// Valore **normalizzato**: e' la forma su cui si correla.
    pub value: String,
}

/// Esito di un'estrazione.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Extraction {
    /// Gli indicatori trovati, deduplicati e in ordine stabile.
    pub indicators: Vec<CyberIndicator>,
    /// Se il testo e' stato troncato prima dell'analisi.
    pub text_truncated: bool,
    /// Se gli indicatori sono stati troncati perche' troppi.
    pub indicators_truncated: bool,
}

impl Extraction {
    /// Se qualcosa e' stato lasciato fuori.
    ///
    /// Serve alla schermata e ai documenti: un elenco parziale che non dichiara
    /// di esserlo e' peggio di un elenco vuoto.
    #[must_use]
    pub const fn is_partial(&self) -> bool {
        self.text_truncated || self.indicators_truncated
    }

    /// Quanti indicatori di un certo genere.
    #[must_use]
    pub fn count(&self, kind: IndicatorKind) -> usize {
        self.indicators
            .iter()
            .filter(|indicator| indicator.kind == kind)
            .count()
    }
}

/// Estrae gli indicatori tecnici da un contenuto.
///
/// L'ordine del risultato e' **stabile**: gli indicatori escono ordinati per
/// genere e valore, non nell'ordine in cui compaiono nel testo. Due analisi
/// dello stesso contenuto producono lo stesso elenco, che e' cio' che serve per
/// correlare e per confrontare.
#[must_use]
pub fn extract(text: &str) -> Extraction {
    let mut trovati: BTreeSet<CyberIndicator> = BTreeSet::new();
    let mut text_truncated = false;

    // Il taglio si fa in **caratteri** e non in byte: tagliare in byte
    // spezzerebbe una lettera accentata a meta', ed e' lo stesso motivo per cui
    // lo Storico taglia le anteprime in caratteri.
    let analizzato: String = if text.chars().count() > MAX_TEXT_CHARS {
        text_truncated = true;
        text.chars().take(MAX_TEXT_CHARS).collect()
    } else {
        text.to_owned()
    };

    for parola in tokens(&analizzato) {
        if parola.chars().count() > MAX_TOKEN_CHARS {
            continue;
        }
        classify(parola, &mut trovati);
        if trovati.len() >= MAX_INDICATORS {
            break;
        }
    }

    let indicators_truncated = trovati.len() >= MAX_INDICATORS;
    Extraction {
        indicators: trovati.into_iter().take(MAX_INDICATORS).collect(),
        text_truncated,
        indicators_truncated,
    }
}

/// Divide il testo in parole, su spazi e punteggiatura di contorno.
///
/// La punteggiatura **finale** si toglie qui e non nella classificazione: un
/// indirizzo a fine frase finisce con un punto, e senza questo taglio ogni
/// dominio a fine periodo verrebbe scartato.
fn tokens(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | '|'
            )
    })
    .map(|parola| parola.trim_matches(|c: char| matches!(c, '.' | ':' | '!' | '?')))
    .filter(|parola| !parola.is_empty())
}

/// Classifica una parola, aggiungendo cio' che riconosce.
fn classify(token: &str, out: &mut BTreeSet<CyberIndicator>) {
    if let Some(cve) = as_cve(token) {
        out.insert(CyberIndicator {
            kind: IndicatorKind::Cve,
            value: cve,
        });
        return;
    }

    if let Some(kind) = as_hash(token) {
        out.insert(CyberIndicator {
            kind,
            value: token.to_ascii_lowercase(),
        });
        return;
    }

    if is_ipv4(token) {
        out.insert(CyberIndicator {
            kind: IndicatorKind::Ipv4,
            value: token.to_owned(),
        });
        return;
    }

    if is_ipv6(token) {
        out.insert(CyberIndicator {
            kind: IndicatorKind::Ipv6,
            value: token.to_ascii_lowercase(),
        });
        return;
    }

    if let Some(host) = as_url(token) {
        out.insert(CyberIndicator {
            kind: IndicatorKind::Url,
            value: token.to_owned(),
        });
        // **Anche il dominio, e non e' una duplicazione.** Due contenuti che
        // citano lo stesso sito con percorsi diversi si correlano sul dominio e
        // non sull'URL: senza questa riga il legame andrebbe perso.
        if is_domain(&host) {
            out.insert(CyberIndicator {
                kind: IndicatorKind::Domain,
                value: host.to_ascii_lowercase(),
            });
        }
        return;
    }

    if is_domain(token) {
        out.insert(CyberIndicator {
            kind: IndicatorKind::Domain,
            value: token.to_ascii_lowercase(),
        });
    }
}

/// `CVE-anno-numero`, normalizzato in maiuscolo.
pub(crate) fn as_cve(token: &str) -> Option<String> {
    let resto = token
        .strip_prefix("CVE-")
        .or_else(|| token.strip_prefix("cve-"))
        .or_else(|| token.strip_prefix("Cve-"))?;

    let (anno, numero) = resto.split_once('-')?;
    if anno.len() != 4 || !anno.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    // Il formato ammette quattro cifre o piu': i numeri hanno superato le
    // 9999 nel 2014, e un estrattore che si fermasse a quattro perderebbe
    // tutto cio' che conta oggi.
    if numero.len() < 4 || !numero.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(format!("CVE-{anno}-{numero}"))
}

/// Un'impronta, riconosciuta dalla **lunghezza esatta**.
///
/// Le tre lunghezze non si sovrappongono, quindi una stringa di 64 cifre
/// esadecimali e' un SHA-256 e non due MD5 attaccati: e' la ragione per cui si
/// guarda la parola intera invece di cercare dentro.
pub(crate) fn as_hash(token: &str) -> Option<IndicatorKind> {
    if !token.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    match token.len() {
        32 => Some(IndicatorKind::Md5),
        40 => Some(IndicatorKind::Sha1),
        64 => Some(IndicatorKind::Sha256),
        _ => None,
    }
}

/// Quattro ottetti da 0 a 255.
pub(crate) fn is_ipv4(token: &str) -> bool {
    let mut parti = 0;
    for parte in token.split('.') {
        parti += 1;
        if parti > 4 {
            return false;
        }
        // Niente zeri iniziali: `01.2.3.4` non e' una forma canonica, e
        // accettarla farebbe correlare due scritture dello stesso indirizzo
        // come se fossero due indirizzi.
        if parte.is_empty() || parte.len() > 3 || (parte.len() > 1 && parte.starts_with('0')) {
            return false;
        }
        if !parte.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        if parte.parse::<u16>().is_ok_and(|valore| valore > 255) {
            return false;
        }
    }
    parti == 4
}

/// Forma conservativa di IPv6.
///
/// Non convalida ogni caso del formato: chiede almeno due `:`, solo cifre
/// esadecimali fra i separatori, gruppi non piu' lunghi di quattro, e al massimo
/// una abbreviazione `::`. Riconosce meno di quanto il formato ammetta, e
/// **preferisce perdere un indirizzo che inventarne uno**.
pub(crate) fn is_ipv6(token: &str) -> bool {
    if token.matches(':').count() < 2 || token.len() > 45 {
        return false;
    }
    if token.matches("::").count() > 1 {
        return false;
    }
    for gruppo in token.split(':') {
        if gruppo.is_empty() {
            // Le posizioni vuote appartengono all'abbreviazione, gia' contata.
            continue;
        }
        if gruppo.len() > 4 || !gruppo.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
    }
    true
}

/// Un indirizzo web, di cui restituisce l'host.
///
/// Solo `http` e `https`: gli altri schemi non sono indirizzi web e non devono
/// entrare in un archivio che poi qualcuno potrebbe aprire (ADR-0018).
pub(crate) fn as_url(token: &str) -> Option<String> {
    let resto = token
        .strip_prefix("https://")
        .or_else(|| token.strip_prefix("http://"))?;
    let host = resto
        .split(['/', '?', '#'])
        .next()
        .filter(|host| !host.is_empty())?;
    // Le credenziali dentro l'indirizzo si scartano: non servono a correlare, e
    // conservarle significherebbe conservare una password trovata per caso.
    let host = host.rsplit('@').next().unwrap_or(host);
    // La porta non fa parte del dominio.
    let host = host.split(':').next().unwrap_or(host);
    Some(host.to_owned())
}

/// Un nome di dominio plausibile.
pub(crate) fn is_domain(token: &str) -> bool {
    if token.len() > 253 || token.contains('/') || token.contains('@') {
        return false;
    }
    let etichette: Vec<&str> = token.split('.').collect();
    if etichette.len() < 2 {
        return false;
    }

    let Some(tld) = etichette.last() else {
        return false;
    };
    if tld.len() < 2 || tld.len() > 24 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    // Un nome di file ha la stessa forma di un dominio.
    if FILE_EXTENSIONS.contains(&tld.to_ascii_lowercase().as_str()) {
        return false;
    }

    etichette.iter().all(|etichetta| {
        !etichetta.is_empty()
            && etichetta.len() <= 63
            && !etichetta.starts_with('-')
            && !etichetta.ends_with('-')
            && etichetta
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valori(text: &str, kind: IndicatorKind) -> Vec<String> {
        extract(text)
            .indicators
            .into_iter()
            .filter(|indicator| indicator.kind == kind)
            .map(|indicator| indicator.value)
            .collect()
    }

    #[test]
    fn a_cve_is_recognised_and_normalised() {
        assert_eq!(
            valori(
                "riguarda CVE-2026-1234 e cve-2026-98765.",
                IndicatorKind::Cve
            ),
            vec!["CVE-2026-1234", "CVE-2026-98765"]
        );
    }

    #[test]
    fn a_cve_with_more_than_four_digits_is_not_lost() {
        // I numeri hanno superato le 9999 nel 2014: un estrattore fermo a
        // quattro cifre perderebbe tutto cio' che conta oggi.
        assert_eq!(
            valori("CVE-2021-44228 e' Log4Shell", IndicatorKind::Cve),
            vec!["CVE-2021-44228"]
        );
    }

    #[test]
    fn something_that_only_looks_like_a_cve_is_refused() {
        assert!(valori("CVE-26-1234", IndicatorKind::Cve).is_empty());
        assert!(valori("CVE-2026-12", IndicatorKind::Cve).is_empty());
        assert!(valori("CVE-2026", IndicatorKind::Cve).is_empty());
        assert!(valori("XCVE-2026-1234", IndicatorKind::Cve).is_empty());
    }

    #[test]
    fn the_three_hash_lengths_are_told_apart() {
        let md5 = "d41d8cd98f00b204e9800998ecf8427e";
        let sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        assert_eq!(valori(md5, IndicatorKind::Md5), vec![md5]);
        assert_eq!(valori(sha1, IndicatorKind::Sha1), vec![sha1]);
        assert_eq!(valori(sha256, IndicatorKind::Sha256), vec![sha256]);
    }

    #[test]
    fn a_sha256_is_not_two_md5_stuck_together() {
        // Guardare la parola intera invece di cercare dentro e' cio' che lo
        // impedisce: una stringa da 64 cifre non produce due impronte da 32.
        let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let estrazione = extract(sha256);
        assert_eq!(estrazione.count(IndicatorKind::Sha256), 1);
        assert_eq!(estrazione.count(IndicatorKind::Md5), 0);
    }

    #[test]
    fn a_hash_is_normalised_to_lowercase() {
        // Due scritture della stessa impronta devono correlare come una sola.
        let maiuscolo = "D41D8CD98F00B204E9800998ECF8427E";
        assert_eq!(
            valori(maiuscolo, IndicatorKind::Md5),
            vec!["d41d8cd98f00b204e9800998ecf8427e"]
        );
    }

    #[test]
    fn addresses_are_recognised_and_impostors_refused() {
        assert_eq!(
            valori("da 192.168.1.1 verso", IndicatorKind::Ipv4),
            vec!["192.168.1.1"]
        );
        assert!(valori("999.1.1.1", IndicatorKind::Ipv4).is_empty());
        assert!(valori("1.2.3", IndicatorKind::Ipv4).is_empty());
        assert!(valori("1.2.3.4.5", IndicatorKind::Ipv4).is_empty());
    }

    #[test]
    fn a_non_canonical_address_is_refused() {
        // `01.2.3.4` e `1.2.3.4` sono lo stesso indirizzo scritto in due modi:
        // accettarli entrambi li farebbe correlare come due indirizzi diversi.
        assert!(valori("01.2.3.4", IndicatorKind::Ipv4).is_empty());
    }

    #[test]
    fn a_version_number_is_not_an_address() {
        assert!(valori("versione 1.8.66", IndicatorKind::Ipv4).is_empty());
    }

    #[test]
    fn an_ipv6_is_recognised_conservatively() {
        assert!(!valori("2001:db8::1", IndicatorKind::Ipv6).is_empty());
        assert!(valori("non:e:un:indirizzo:zz", IndicatorKind::Ipv6).is_empty());
        // Due abbreviazioni non sono ammesse dal formato.
        assert!(valori("2001::db8::1", IndicatorKind::Ipv6).is_empty());
    }

    #[test]
    fn a_url_yields_both_itself_and_its_domain() {
        // Due contenuti che citano lo stesso sito con percorsi diversi si
        // correlano sul dominio, non sull'URL.
        let estrazione = extract("vedere https://esempio.invalid/percorso/lungo per i dettagli");
        assert_eq!(
            estrazione
                .indicators
                .iter()
                .filter(|i| i.kind == IndicatorKind::Url)
                .count(),
            1
        );
        assert_eq!(
            valori("https://esempio.invalid/x", IndicatorKind::Domain),
            vec!["esempio.invalid"]
        );
    }

    #[test]
    fn credentials_inside_a_url_do_not_become_a_domain() {
        // Una password trovata per caso non si conserva.
        assert_eq!(
            valori(
                "http://utente:segreto@esempio.invalid/x",
                IndicatorKind::Domain
            ),
            vec!["esempio.invalid"]
        );
    }

    #[test]
    fn a_port_is_not_part_of_the_domain() {
        assert_eq!(
            valori("https://esempio.invalid:8443/x", IndicatorKind::Domain),
            vec!["esempio.invalid"]
        );
    }

    #[test]
    fn only_web_schemes_become_urls() {
        // Gli altri schemi non sono indirizzi web e non devono entrare in un
        // archivio che poi qualcuno potrebbe aprire (ADR-0018).
        assert!(valori("file:///C:/segreto.txt", IndicatorKind::Url).is_empty());
        assert!(valori("ftp://esempio.invalid/x", IndicatorKind::Url).is_empty());
        assert!(valori("javascript:alert(1)", IndicatorKind::Url).is_empty());
    }

    #[test]
    fn a_file_name_is_not_a_domain() {
        // `relazione.pdf` ha la stessa forma di `esempio.it`.
        for nome in ["relazione.pdf", "archivio.zip", "programma.exe", "note.txt"] {
            assert!(
                valori(nome, IndicatorKind::Domain).is_empty(),
                "«{nome}» e' stato scambiato per un dominio"
            );
        }
    }

    #[test]
    fn a_domain_at_the_end_of_a_sentence_is_not_lost() {
        // Senza il taglio della punteggiatura finale, ogni dominio a fine
        // periodo verrebbe scartato.
        assert_eq!(
            valori("il sito e' esempio.invalid.", IndicatorKind::Domain),
            vec!["esempio.invalid"]
        );
        assert_eq!(
            valori("guarda (esempio.invalid)", IndicatorKind::Domain),
            vec!["esempio.invalid"]
        );
    }

    #[test]
    fn the_same_indicator_twice_is_one_indicator() {
        let estrazione = extract("CVE-2026-1111 e ancora CVE-2026-1111 e poi cve-2026-1111");
        assert_eq!(estrazione.count(IndicatorKind::Cve), 1);
    }

    #[test]
    fn the_order_is_stable_across_two_extractions() {
        // Due analisi dello stesso contenuto devono dare lo stesso elenco: e'
        // cio' che permette di correlare e di confrontare.
        let testo = "CVE-2026-2 poi 10.0.0.1 poi CVE-2026-1 poi esempio.invalid";
        assert_eq!(extract(testo), extract(testo));
        let primi: Vec<String> = extract(testo)
            .indicators
            .into_iter()
            .map(|i| i.value)
            .collect();
        let secondi: Vec<String> = extract(testo)
            .indicators
            .into_iter()
            .map(|i| i.value)
            .collect();
        assert_eq!(primi, secondi);
    }

    #[test]
    fn an_oversized_text_is_truncated_and_says_so() {
        // Un elenco parziale che non dichiara di esserlo e' peggio di un elenco
        // vuoto.
        let enorme = "parola ".repeat(MAX_TEXT_CHARS);
        let estrazione = extract(&enorme);
        assert!(estrazione.text_truncated);
        assert!(estrazione.is_partial());
    }

    #[test]
    fn too_many_indicators_are_capped_and_declared() {
        let elenco: String = (0..MAX_INDICATORS + 100)
            .map(|n| format!("CVE-2026-{:05} ", n))
            .collect();
        let estrazione = extract(&elenco);
        assert!(estrazione.indicators.len() <= MAX_INDICATORS);
        assert!(estrazione.indicators_truncated);
        assert!(estrazione.is_partial());
    }

    #[test]
    fn a_pathological_input_does_not_take_forever() {
        // **La prova che sostituisce la protezione dalla catastrofe
        // combinatoria.** Non c'e' alcuna espressione regolare, quindi non c'e'
        // ritorno all'indietro: un ingresso costruito per esplodere non ha nulla
        // da far esplodere. Qui si verifica che l'analisi finisca comunque in
        // un tempo ragionevole.
        let patologico = format!("{}!", "a.".repeat(20_000));
        let inizio = std::time::Instant::now();
        let _ = extract(&patologico);
        assert!(
            inizio.elapsed() < std::time::Duration::from_secs(2),
            "l'analisi di un ingresso patologico ha impiegato troppo"
        );

        let annidato = format!("{}{}", "(".repeat(50_000), ")".repeat(50_000));
        let inizio = std::time::Instant::now();
        let _ = extract(&annidato);
        assert!(inizio.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn ordinary_text_yields_nothing() {
        // Il rovescio che si dimentica: un estrattore che trovasse indicatori
        // ovunque sarebbe inutile quanto uno che non ne trova mai.
        let estrazione = extract(
            "Buongiorno, la riunione e' spostata a giovedi' alle 15.30 in sala 2. \
             Cordiali saluti.",
        );
        assert!(
            estrazione.indicators.is_empty(),
            "trovati indicatori dove non ce ne sono: {:?}",
            estrazione.indicators
        );
    }

    #[test]
    fn nothing_in_this_module_reaches_the_network() {
        // Guardia strutturale. Un indicatore si estrae, non si contatta:
        // contattarlo significherebbe eseguire codice altrui su una postazione
        // d'ufficio, e dire a chi ha pubblicato il contenuto che qualcuno lo
        // sta guardando.
        let sorgente = include_str!("indicator.rs");
        let Some((produzione, _)) = sorgente.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo di prova deve essere riconoscibile per poterlo escludere");
        };
        for vietato in [
            "TcpStream",
            "UdpSocket",
            "to_socket_addrs",
            "lookup_host",
            "reqwest",
            "std::net",
        ] {
            assert!(
                !produzione.contains(vietato),
                "il modulo contiene «{vietato}»: un indicatore si estrae, non si contatta"
            );
        }
    }
}

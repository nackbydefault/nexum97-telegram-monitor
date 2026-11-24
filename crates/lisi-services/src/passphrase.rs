//! Parole di sblocco: validazione e impronta salata.
//!
//! Esiste **una sola** implementazione, e questo modulo è la ragione per cui.
//! Due parti del prodotto conservano una parola che qualcuno dovrà ridigitare —
//! la modalità operativa della postazione (`station`) e il blocco per account
//! (`lock`) — e una seconda copia di questo codice sarebbe una seconda occasione
//! di sbagliarlo: un salt più corto qui, un separatore diverso là, e la
//! differenza non la vedrebbe alcun test perché ciascuna metà resterebbe
//! coerente con sé stessa.
//!
//! # Che cosa questo modulo non promette
//!
//! **Non è una funzione per password.** Una SHA-256 salata resiste a chi legge
//! il file, non a chi ha tempo e una scheda grafica: contro un attacco a
//! dizionario servirebbe una derivazione lenta (Argon2, scrypt), che è una
//! dipendenza in più e una decisione da ADR. Quel che protegge, lo protegge:
//! chi apre il file non trova la parola, e due postazioni con la stessa parola
//! non mostrano la stessa impronta. Quel che non protegge, è scritto qui invece
//! che scoperto dopo.

use lisi_core::Sha256Digest;
use lisi_security::{SecurityError, random_bytes};

use crate::error::{ServiceError, ServiceResult};

/// Byte di salt generati per ogni parola.
const SALT_BYTES: usize = 16;

/// Lunghezza minima, in caratteri.
///
/// Corta abbastanza da ricordarsi, lunga abbastanza da non indovinarsi al primo
/// tentativo.
const MIN_CHARS: usize = 4;

/// Lunghezza massima, per evitare un valore fuori misura in un file finito.
const MAX_CHARS: usize = 128;

/// Salt e impronta di una parola, pronti per essere conservati.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedPassphrase {
    /// Salt in esadecimale.
    pub salt_hex: String,
    /// Impronta della parola con quel salt.
    pub hash: String,
}

/// Valida la parola e ne produce salt e impronta.
///
/// # Errori
///
/// Restituisce [`ServiceError::WeakUnlockWord`] se la parola è troppo corta,
/// troppo lunga o contiene caratteri di controllo, e un errore se il generatore
/// casuale non è disponibile.
pub fn seal(raw: &str) -> ServiceResult<SealedPassphrase> {
    let word = validate(raw)?;

    let mut salt = [0_u8; SALT_BYTES];
    random_bytes(&mut salt).map_err(map_security_error)?;
    let salt_hex = to_hex(&salt);
    let hash = fingerprint(&salt_hex, word);

    Ok(SealedPassphrase { salt_hex, hash })
}

/// Se il tentativo corrisponde all'impronta conservata.
///
/// Il tentativo viene solo ripulito dagli spazi ai bordi e **non validato**: chi
/// digita una parola troppo corta deve ricevere «parola errata», non «parola
/// debole». Il secondo messaggio direbbe a chi prova che quella non è nemmeno
/// nella forma giusta, che è un'informazione in più data gratis.
#[must_use]
pub fn matches(sealed_salt_hex: &str, sealed_hash: &str, attempt: &str) -> bool {
    fingerprint(sealed_salt_hex, attempt.trim()) == sealed_hash
}

/// Verifica che la parola sia utilizzabile.
///
/// # Errori
///
/// Restituisce [`ServiceError::WeakUnlockWord`] se non lo è.
pub fn validate(raw: &str) -> ServiceResult<&str> {
    let trimmed = raw.trim();
    let length = trimmed.chars().count();

    if !(MIN_CHARS..=MAX_CHARS).contains(&length) {
        return Err(ServiceError::WeakUnlockWord);
    }
    if trimmed.chars().any(char::is_control) {
        return Err(ServiceError::WeakUnlockWord);
    }
    Ok(trimmed)
}

/// Impronta salata della parola.
///
/// Il salt precede la parola con un separatore che la parola non può contenere
/// (i caratteri di controllo sono rifiutati alla validazione): due parole
/// diverse non possono così produrre lo stesso testo da cui si calcola
/// l'impronta.
fn fingerprint(salt_hex: &str, word: &str) -> String {
    Sha256Digest::of_text(&format!("{salt_hex}\u{1f}{word}"))
        .as_str()
        .to_owned()
}

/// Converte byte in esadecimale minuscolo.
fn to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(nibble(byte >> 4));
        hex.push(nibble(byte & 0x0f));
    }
    hex
}

const fn nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + value - 10) as char,
    }
}

/// Traduce un errore di sicurezza in un errore di servizio.
fn map_security_error(error: SecurityError) -> ServiceError {
    ServiceError::SessionUnavailable {
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{matches, seal, validate};

    #[test]
    fn a_sealed_word_matches_itself_and_nothing_else() {
        let Ok(sealed) = seal("parola-di-prova") else {
            panic!("la parola di prova deve potersi sigillare");
        };

        assert!(matches(&sealed.salt_hex, &sealed.hash, "parola-di-prova"));
        assert!(!matches(&sealed.salt_hex, &sealed.hash, "parola-diversa"));
    }

    #[test]
    fn the_word_is_never_recoverable_from_what_gets_stored() {
        let Ok(sealed) = seal("segreto-da-non-trovare") else {
            panic!("la parola di prova deve potersi sigillare");
        };

        assert!(!sealed.hash.contains("segreto"));
        assert!(!sealed.salt_hex.contains("segreto"));
    }

    #[test]
    fn the_same_word_sealed_twice_stores_two_different_hashes() {
        // E' cio' che fa il salt, ed e' verificabile: senza, due postazioni con
        // la stessa parola mostrerebbero la stessa impronta, e chi ne vedesse
        // due uguali saprebbe che le parole coincidono senza conoscerle.
        let (Ok(first), Ok(second)) = (seal("stessa-parola"), seal("stessa-parola")) else {
            panic!("entrambe devono potersi sigillare");
        };

        assert_ne!(first.salt_hex, second.salt_hex);
        assert_ne!(first.hash, second.hash);
        // Ma entrambe riconoscono la parola.
        assert!(matches(&first.salt_hex, &first.hash, "stessa-parola"));
        assert!(matches(&second.salt_hex, &second.hash, "stessa-parola"));
    }

    #[test]
    fn surrounding_spaces_do_not_change_the_word() {
        let Ok(sealed) = seal("  con-spazi  ") else {
            panic!("la parola deve potersi sigillare");
        };
        assert!(matches(&sealed.salt_hex, &sealed.hash, "con-spazi"));
        assert!(matches(&sealed.salt_hex, &sealed.hash, "   con-spazi "));
    }

    #[test]
    fn a_word_too_short_or_with_control_characters_is_refused() {
        assert!(validate("abc").is_err(), "tre caratteri sono pochi");
        assert!(validate("   ").is_err(), "soli spazi non sono una parola");
        assert!(validate("con\u{0}nullo").is_err());
        assert!(validate("con\ninvio").is_err());
        assert!(validate(&"x".repeat(129)).is_err(), "fuori misura");

        assert!(validate("quattro").is_ok());
    }

    #[test]
    fn a_wrong_attempt_that_is_also_malformed_is_simply_wrong() {
        // Chi prova una parola troppo corta riceve «errata», non «debole»: il
        // secondo messaggio direbbe che quella non e' nemmeno nella forma
        // giusta, cioe' regalerebbe un'informazione a chi sta tentando.
        let Ok(sealed) = seal("parola-vera") else {
            panic!("la parola deve potersi sigillare");
        };
        assert!(!matches(&sealed.salt_hex, &sealed.hash, "ab"));
        assert!(!matches(&sealed.salt_hex, &sealed.hash, ""));
    }
}

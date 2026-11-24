//! Le espressioni regolari di un dizionario (DICT-REGEX-01, ADR-0187).
//!
//! # Soltanto in tempo lineare
//!
//! Il motore è la crate `regex`, che non ha ritorni all'indietro: niente
//! riferimenti all'indietro né sguardi avanti o indietro, e un tempo che cresce
//! con il testo, qualunque testo. Si compila con un tetto di memoria; ciò che
//! lo supera si rifiuta quando si scrive, non quando si cerca (decisioni 2 e
//! 3).
//!
//! # Il testo è normalizzato, l'espressione no
//!
//! Il riscontro lavora sul testo normalizzato (NFC e minuscole). L'espressione
//! si applica senza distinguere le maiuscole e non si normalizza: abbassarla
//! cambierebbe `\D` in `\d` (decisione 4).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use regex::{Regex, RegexBuilder};

/// Quanti caratteri può avere un'espressione.
pub const MAX_EXPRESSION_CHARS: usize = 200;

/// Il tetto di memoria del programma compilato e della sua cache, in byte.
const SIZE_LIMIT: usize = 1 << 20;

/// Compila un'espressione, o dice perché non si può.
///
/// # Errori
///
/// Una frase per chi compila il dizionario: vuota, troppo lunga, su più
/// righe, che non si compila o oltre il tetto, che riscontra il testo vuoto.
pub fn compile(pattern: &str) -> Result<Regex, &'static str> {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return Err("un'espressione vuota non cerca niente");
    }
    if pattern.chars().count() > MAX_EXPRESSION_CHARS {
        return Err("un'espressione ha al più 200 caratteri");
    }
    if pattern.chars().any(char::is_control) {
        return Err("un'espressione si scrive su una riga");
    }
    let espressione = RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(SIZE_LIMIT)
        .dfa_size_limit(SIZE_LIMIT)
        .build()
        .map_err(|errore| match errore {
            regex::Error::CompiledTooBig(_) => "l'espressione è troppo grande per essere cercata",
            _ => "l'espressione non è scritta in una forma che il programma legge",
        })?;
    if espressione.is_match("") {
        return Err("l'espressione riscontra anche il testo vuoto, cioè ogni contenuto");
    }
    Ok(espressione)
}

/// Le espressioni già compilate: un dizionario si applica a ogni contenuto, e
/// ricompilare a ogni contenuto costerebbe quanto il numero dei contenuti.
fn cache() -> &'static Mutex<HashMap<String, Arc<Regex>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Arc<Regex>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Dove l'espressione riscontra nel testo, in caratteri: le coppie di inizio e
/// fine. Un'espressione che non si compila non riscontra niente: è già stata
/// rifiutata quando si è scritta.
#[must_use]
pub fn occurrences(normalised: &str, pattern: &str) -> Vec<(usize, usize)> {
    let espressione = {
        let Ok(mut compilate) = cache().lock() else {
            return Vec::new();
        };
        if let Some(pronta) = compilate.get(pattern) {
            Arc::clone(pronta)
        } else {
            let Ok(nuova) = compile(pattern) else {
                return Vec::new();
            };
            let nuova = Arc::new(nuova);
            compilate.insert(pattern.to_owned(), Arc::clone(&nuova));
            nuova
        }
    };
    let mut trovate = Vec::new();
    let mut carattere = 0;
    let mut byte_letti = 0;
    for riscontro in espressione.find_iter(normalised) {
        // Le posizioni dei byte diventano posizioni di caratteri, in avanti e
        // una volta sola.
        carattere += normalised[byte_letti..riscontro.start()].chars().count();
        let inizio = carattere;
        carattere += riscontro.as_str().chars().count();
        byte_letti = riscontro.end();
        trovate.push((inizio, carattere));
    }
    trovate
}

#[cfg(test)]
mod tests {
    use super::{MAX_EXPRESSION_CHARS, compile, occurrences};

    /// **Ciò che non si può cercare si rifiuta quando si scrive** (ADR-0187,
    /// decisione 3).
    #[test]
    fn cio_che_non_si_puo_cercare_si_rifiuta() {
        assert!(compile(r"vend[eo] armi?").is_ok());
        for sbagliata in [
            String::new(),
            String::from("   "),
            "a".repeat(MAX_EXPRESSION_CHARS + 1),
            String::from("una\nriga"),
            String::from("(non chiusa"),
            String::from(r"(\w+)\1"),
            String::from(r"a(?=b)"),
            String::from("a*"),
            String::from(r"\w{1000}{1000}"),
        ] {
            assert!(compile(&sbagliata).is_err(), "«{sbagliata}» va rifiutata");
        }
    }

    /// **Un testo costruito per un motore a ritorno all'indietro non lo
    /// rallenta** (ADR-0187, decisione 7).
    #[test]
    fn un_testo_ostile_non_rallenta() {
        let mut ostile = "a".repeat(200_000);
        ostile.push('!');
        let inizio = std::time::Instant::now();
        assert!(occurrences(&ostile, "(a+)+$").is_empty());
        assert!(
            inizio.elapsed() < std::time::Duration::from_secs(2),
            "il motore deve restare lineare"
        );
    }

    /// **Le posizioni sono in caratteri, e il caso non conta** (decisione 4).
    #[test]
    fn le_posizioni_sono_in_caratteri() {
        assert_eq!(occurrences("perché vende armi", r"VENDE\s+ARMI"), [(7, 17)]);
        assert_eq!(
            occurrences("città 1488 e 88", r"\b\d{2,4}\b"),
            [(6, 10), (13, 15)]
        );
        assert!(occurrences("niente", "(non chiusa").is_empty());
    }
}

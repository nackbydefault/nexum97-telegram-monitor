//! Riscontro dei termini risolti dentro il testo di un contenuto.
//!
//! Il confronto è **lessicale** e avviene sul testo normalizzato con la stessa
//! funzione usata dalla risoluzione: se le due normalizzazioni divergessero, un
//! termine potrebbe entrare nella configurazione e non riscontrare mai, oppure
//! riscontrare parole che il compilatore del dizionario non intendeva.
//!
//! # Che cosa si intende per «parola intera»
//!
//! Un termine in modalità parola non deve riscontrare dentro un'altra parola:
//! «arma» non riscontra in «armadio». Il confine è determinato dalle proprietà
//! Unicode del carattere adiacente, non da un elenco di separatori: un elenco
//! scritto a mano dimentica sempre qualcosa, e ciò che dimentica diventa un
//! riscontro mancato in una lingua che nessuno aveva in mente.
//!
//! # Il codice numerico
//!
//! Un codice di sole cifre riscontra soltanto come **numero isolato**: non
//! dentro un decimale, una data, un'ora, un importo o una percentuale
//! (DICT-CODES-01, ADR-0170). Che conti soltanto insieme a un altro termine lo
//! decide il punteggio, non questo modulo.
//!
//! # Le espressioni regolari, soltanto in tempo lineare
//!
//! Per la ragione fissata in ADR-0012: su testo costruito apposta un motore a
//! ritorno all'indietro richiede tempo esponenziale. Un termine in modo
//! espressione si cerca con [`crate::analysis::expression`], che non ha
//! ritorni all'indietro (DICT-REGEX-01, ADR-0187); i confini li decide
//! l'espressione stessa.

use crate::model::dictionary::{MatchMode, ResolvedTerm, normalise_for_matching};

/// Occorrenza di un termine nel testo di un contenuto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TermOccurrence {
    /// Posizione del termine risolto nella configurazione.
    ///
    /// È un indice e non una copia del termine: la configurazione risolta vive
    /// già altrove, e duplicarne i dati significherebbe poterli far divergere.
    pub term_index: usize,
    /// Primo carattere dell'occorrenza, in caratteri Unicode.
    pub start: usize,
    /// Carattere successivo all'ultimo, in caratteri Unicode.
    pub end: usize,
}

impl TermOccurrence {
    /// Numero di caratteri dell'occorrenza.
    #[must_use]
    pub const fn length(&self) -> usize {
        self.end - self.start
    }
}

/// Cerca ogni termine della configurazione dentro il testo.
///
/// Restituisce le occorrenze in **ordine canonico**: prima per posizione, poi
/// per indice del termine. L'ordine non dipende da come i termini sono arrivati,
/// perché la motivazione mostrata all'operatore non deve cambiare fra due
/// esecuzioni identiche.
///
/// Un termine che compare più volte produce **più occorrenze**: sapere che una
/// parola ricorre è un'informazione, e collassarla in una sola la perderebbe.
#[must_use]
pub fn find_occurrences(body: &str, terms: &[ResolvedTerm]) -> Vec<TermOccurrence> {
    // La normalizzazione del corpo avviene una volta sola: rifarla per ogni
    // termine costerebbe quanto il numero dei termini, che arriva a decine di
    // migliaia.
    let testo = normalise_for_matching(body);
    let normalised: Vec<char> = testo.chars().collect();

    let mut found = Vec::new();
    for (term_index, term) in terms.iter().enumerate() {
        if term.match_mode == MatchMode::Expression {
            for (start, end) in crate::analysis::expression::occurrences(&testo, &term.normalised) {
                found.push(TermOccurrence {
                    term_index,
                    start,
                    end,
                });
            }
            continue;
        }
        let needle: Vec<char> = term.normalised.chars().collect();
        if needle.is_empty() {
            continue;
        }

        for start in positions_of(&normalised, &needle, term.match_mode) {
            found.push(TermOccurrence {
                term_index,
                start,
                end: start + needle.len(),
            });
        }
    }

    found.sort_by_key(|occurrence| (occurrence.start, occurrence.term_index));
    found
}

/// Posizioni in cui l'ago compare nel pagliaio, secondo la modalità.
fn positions_of(haystack: &[char], needle: &[char], mode: MatchMode) -> Vec<usize> {
    let mut positions = Vec::new();
    if needle.len() > haystack.len() {
        return positions;
    }

    for start in 0..=(haystack.len() - needle.len()) {
        if &haystack[start..start + needle.len()] != needle {
            continue;
        }

        let end = start + needle.len();
        let acceptable = match mode {
            // La frase può iniziare e finire dentro la punteggiatura, ma non
            // dentro una parola: «dare fuoco» non deve riscontrare in
            // «dare fuochino».
            MatchMode::Phrase | MatchMode::ExactWord | MatchMode::NormalizedWord => {
                is_boundary(haystack, start, end)
            }
            MatchMode::NumericCode => {
                is_boundary(haystack, start, end) && is_isolated_number(haystack, start, end)
            }
            // Le espressioni non passano di qui: le cerca il loro modulo.
            MatchMode::Expression => false,
        };

        if acceptable {
            positions.push(start);
        }
    }

    positions
}

/// Se l'intervallo indicato è delimitato da confini di parola.
fn is_boundary(haystack: &[char], start: usize, end: usize) -> bool {
    let before_is_word = start
        .checked_sub(1)
        .and_then(|index| haystack.get(index))
        .is_some_and(|character| is_word_character(*character));

    let after_is_word = haystack
        .get(end)
        .is_some_and(|character| is_word_character(*character));

    !before_is_word && !after_is_word
}

/// Se il carattere fa parte di una parola.
///
/// Alfanumerico secondo Unicode, più il trattino basso: comprende quindi le
/// lettere accentate e gli alfabeti non latini, che un elenco di separatori
/// scritto a mano avrebbe trattato come confini.
fn is_word_character(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

/// Se l'intervallo è un numero isolato, e non parte di una forma numerica
/// (DICT-CODES-01, ADR-0170).
///
/// Il confine di parola è già stato verificato. Qui si guarda **la forma** dei
/// caratteri vicini, non un elenco di parole: un decimale, una data, un'ora o
/// un intervallo (un separatore con una cifra dall'altra parte), un importo
/// (un simbolo di valuta accanto, anche dopo uno spazio), una percentuale o un
/// grado (dopo, anche dopo uno spazio), un anno o una quantità eliso (un
/// apostrofo prima). «14 ottobre» e «88 euro» non si riconoscono: un codice da
/// solo non alza il livello (`scoring`), ed è quello che li rende innocui.
fn is_isolated_number(haystack: &[char], start: usize, end: usize) -> bool {
    let before = |distance: usize| {
        start
            .checked_sub(distance)
            .and_then(|index| haystack.get(index))
            .copied()
    };
    let after = |distance: usize| haystack.get(end + distance - 1).copied();

    // Un separatore numerico con una cifra dall'altra parte: «1.88», «10/88»,
    // «14:30», «2024-88».
    let joins_a_number = |separator: Option<char>, beyond: Option<char>| {
        separator.is_some_and(is_numeric_separator) && beyond.is_some_and(|c| c.is_ascii_digit())
    };
    if joins_a_number(before(1), before(2)) || joins_a_number(after(1), after(2)) {
        return false;
    }

    // Un apostrofo prima: «nell'88», «'88».
    if before(1).is_some_and(|c| c == '\'' || c == '\u{2019}') {
        return false;
    }

    // Un simbolo accanto, oppure dopo uno spazio solo.
    let near = |first: Option<char>, second: Option<char>, wanted: fn(char) -> bool| {
        first.is_some_and(wanted) || (first == Some(' ') && second.is_some_and(wanted))
    };
    if near(before(1), before(2), is_currency_symbol)
        || near(after(1), after(2), is_currency_symbol)
        || near(after(1), after(2), is_quantity_sign)
    {
        return false;
    }

    true
}

/// Un separatore che dentro un numero lega due gruppi di cifre.
fn is_numeric_separator(character: char) -> bool {
    matches!(character, '.' | ',' | ':' | '/' | '-')
}

/// Un segno che dopo un numero ne fa una percentuale o un grado.
fn is_quantity_sign(character: char) -> bool {
    matches!(character, '%' | '\u{2030}' | '\u{b0}')
}

/// Un simbolo di valuta: il blocco Unicode dei simboli di valuta e quelli che
/// stanno fuori da quel blocco.
fn is_currency_symbol(character: char) -> bool {
    matches!(character, '\u{20a0}'..='\u{20cf}')
        || matches!(
            character,
            '$' | '\u{a2}'
                | '\u{a3}'
                | '\u{a4}'
                | '\u{a5}'
                | '\u{58f}'
                | '\u{60b}'
                | '\u{9f3}'
                | '\u{e3f}'
                | '\u{fdfc}'
                | '\u{ff04}'
                | '\u{ffe0}'
                | '\u{ffe1}'
                | '\u{ffe5}'
                | '\u{ffe6}'
        )
}

#[cfg(test)]
mod tests {
    use super::{find_occurrences, is_word_character};
    use crate::model::dictionary::{MatchMode, ResolvedTerm, TermProvenance};
    use crate::text::{LanguageTag, TermCategory, TermText};

    /// Termine risolto di prova.
    fn term(text: &str, mode: MatchMode) -> ResolvedTerm {
        let (Ok(original), Ok(category), Ok(language)) = (
            TermText::try_new(text),
            TermCategory::try_new("prova"),
            LanguageTag::try_new("it"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };

        ResolvedTerm {
            normalised: crate::model::dictionary::normalise_for_matching(text),
            original,
            category,
            language,
            match_mode: mode,
            suggested_level: 2,
            provenances: vec![TermProvenance::ad_hoc()],
        }
    }

    /// Testi riscontrati, nell'ordine in cui il motore li restituisce.
    fn matched(body: &str, terms: &[ResolvedTerm]) -> Vec<String> {
        let characters: Vec<char> = super::normalise_for_matching(body).chars().collect();
        find_occurrences(body, terms)
            .iter()
            .map(|occurrence| {
                characters[occurrence.start..occurrence.end]
                    .iter()
                    .collect::<String>()
            })
            .collect()
    }

    #[test]
    fn a_word_is_found_where_it_appears() {
        let terms = vec![term("incendio", MatchMode::NormalizedWord)];
        let found = find_occurrences("hanno appiccato un incendio ieri", &terms);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].term_index, 0);
        assert_eq!(found[0].length(), 8);
    }

    #[test]
    fn a_word_does_not_match_inside_another_word() {
        // "arma" dentro "armadio" non e' un riscontro: e' il difetto che rende
        // inutilizzabile un motore lessicale ingenuo.
        let terms = vec![term("arma", MatchMode::NormalizedWord)];
        assert!(find_occurrences("ha aperto l'armadio", &terms).is_empty());
        assert_eq!(find_occurrences("ha preso un'arma", &terms).len(), 1);
    }

    #[test]
    fn the_case_and_the_unicode_form_do_not_matter() {
        let terms = vec![term("citt\u{e0}", MatchMode::NormalizedWord)];

        // Maiuscolo e forma decomposta devono riscontrare lo stesso.
        assert_eq!(find_occurrences("in CITT\u{c0} oggi", &terms).len(), 1);
        assert_eq!(find_occurrences("in citta\u{300} oggi", &terms).len(), 1);
    }

    /// **Un'espressione riscontra con le sue posizioni, e la configurazione
    /// non la abbassa** (DICT-REGEX-01, ADR-0187, decisioni 4 e 5).
    #[test]
    fn un_espressione_riscontra_con_le_sue_posizioni() {
        let mut espressione = term(r"vend[eo]\s+arm[ie]", MatchMode::Expression);
        espressione.normalised = String::from(r"vend[eo]\s+arm[ie]");
        let trovate = find_occurrences("Chi VENDE ARMI e chi vendo armi?", &[espressione]);
        assert_eq!(trovate.len(), 2);
        assert_eq!((trovate[0].start, trovate[0].end), (4, 14));
    }

    /// **Un codice numerico riscontra soltanto come numero isolato**
    /// (DICT-CODES-01, ADR-0170, criterio 2; prova negativa: il codice trattato
    /// come una parola qualunque → rossa).
    #[test]
    fn un_codice_numerico_riscontra_soltanto_come_numero_isolato() {
        let terms = vec![term("88", MatchMode::NumericCode)];

        for isolato in [
            "88",
            "scritto 88 sul muro",
            "(88)",
            "#88",
            "fine. 88.",
            "88, 14 e altro",
            "88!",
        ] {
            assert_eq!(
                find_occurrences(isolato, &terms).len(),
                1,
                "«{isolato}» deve riscontrare"
            );
        }

        for forma in [
            "1488",
            "88enne",
            "costa 1,88",
            "vale 88,5",
            "il 3.88",
            "alle 14:88",
            "il 10/88",
            "dal 2024-88",
            "88-14",
            "88.5",
            "€88",
            "€ 88",
            "88€",
            "88 €",
            "$88",
            "88%",
            "88 %",
            "88‰",
            "88°",
            "nell'88",
            "nell’88",
            "'88",
        ] {
            assert!(
                find_occurrences(forma, &terms).is_empty(),
                "«{forma}» è una forma numerica, non un codice isolato"
            );
        }
    }

    /// **Una parola di sole cifre resta com'era**: la regola del codice vale
    /// soltanto per il modo «codice numerico» (ADR-0170, decisione 6).
    #[test]
    fn una_parola_di_sole_cifre_resta_com_era() {
        let terms = vec![term("88", MatchMode::NormalizedWord)];
        assert_eq!(find_occurrences("costa 1,88", &terms).len(), 1);
        assert_eq!(find_occurrences("88%", &terms).len(), 1);
    }

    #[test]
    fn a_phrase_matches_only_as_a_whole_and_not_inside_a_longer_word() {
        let terms = vec![term("dare fuoco", MatchMode::Phrase)];

        assert_eq!(
            find_occurrences("vogliono dare fuoco al deposito", &terms).len(),
            1
        );
        assert!(find_occurrences("vogliono dare fuochino", &terms).is_empty());
    }

    #[test]
    fn a_repeated_word_produces_one_occurrence_per_appearance() {
        // Sapere che una parola ricorre e' un'informazione: collassarla in un
        // solo riscontro la perderebbe.
        let terms = vec![term("molotov", MatchMode::NormalizedWord)];
        let found = find_occurrences("molotov, poi ancora molotov e molotov", &terms);

        assert_eq!(found.len(), 3);
        assert!(found[0].start < found[1].start);
        assert!(found[1].start < found[2].start);
    }

    #[test]
    fn the_occurrences_are_returned_in_canonical_order() {
        // L'ordine non dipende da come i termini sono arrivati: la motivazione
        // mostrata all'operatore non deve cambiare fra due esecuzioni identiche.
        let terms = vec![
            term("zeta", MatchMode::NormalizedWord),
            term("alfa", MatchMode::NormalizedWord),
        ];
        assert_eq!(matched("alfa poi zeta", &terms), ["alfa", "zeta"]);

        let inverted = vec![
            term("alfa", MatchMode::NormalizedWord),
            term("zeta", MatchMode::NormalizedWord),
        ];
        assert_eq!(matched("alfa poi zeta", &inverted), ["alfa", "zeta"]);
    }

    #[test]
    fn punctuation_and_line_breaks_are_word_boundaries() {
        let terms = vec![term("incendio", MatchMode::NormalizedWord)];

        for body in ["incendio.", "(incendio)", "incendio\nieri", "\"incendio\""] {
            assert_eq!(
                find_occurrences(body, &terms).len(),
                1,
                "nessun riscontro in {body:?}"
            );
        }
    }

    #[test]
    fn a_term_longer_than_the_text_is_not_found_and_does_not_panic() {
        let terms = vec![term("una frase molto lunga", MatchMode::Phrase)];
        assert!(find_occurrences("breve", &terms).is_empty());
        assert!(find_occurrences("", &terms).is_empty());
    }

    #[test]
    fn an_empty_body_or_an_empty_configuration_finds_nothing() {
        let terms = vec![term("incendio", MatchMode::NormalizedWord)];
        assert!(find_occurrences("", &terms).is_empty());
        assert!(find_occurrences("incendio", &[]).is_empty());
    }

    #[test]
    fn a_word_character_is_alphanumeric_across_alphabets() {
        // Un elenco di separatori scritto a mano avrebbe trattato queste
        // lettere come confini, spezzando le parole nelle lingue che le usano.
        for character in ['a', 'Z', '9', '_', 'à', 'ç', 'ß', 'я', 'م', '中'] {
            assert!(
                is_word_character(character),
                "{character} doveva essere parola"
            );
        }
        for character in [' ', '.', ',', '\n', '"', '(', '\'', '-', '!'] {
            assert!(
                !is_word_character(character),
                "{character} doveva essere confine"
            );
        }
    }

    #[test]
    fn the_position_is_expressed_in_characters_and_not_in_bytes() {
        // Con caratteri multibyte prima del riscontro, un offset in byte
        // indicherebbe all'operatore un punto sbagliato del messaggio.
        let terms = vec![term("fuoco", MatchMode::NormalizedWord)];
        let found = find_occurrences("città città fuoco", &terms);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].start, 12, "dodici caratteri, non byte");
    }
}

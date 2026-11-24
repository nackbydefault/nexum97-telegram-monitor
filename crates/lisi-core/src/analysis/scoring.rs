//! Attribuzione del livello e motivazione dell'esito.
//!
//! La formula è quella di `docs/adr/ADR-0016-ANALYSIS-ENGINE.md`, e sta in una
//! frase:
//!
//! ```text
//! livello = limita(base + corroborazione + mitigazione, 0, 4)
//! ```
//!
//! dove la **base** è il livello suggerito più alto fra i termini positivi
//! trovati, la **corroborazione** vale `+1` quando i termini positivi distinti
//! sono almeno tre e provengono da almeno due categorie, e la **mitigazione** è
//! il livello suggerito più basso fra i termini negativi.
//!
//! Un **codice numerico** è positivo soltanto se nello stesso contenuto c'è
//! almeno un altro termine positivo che non sia un codice: da solo compare
//! nella motivazione e non alza il livello (DICT-CODES-01, ADR-0170).
//!
//! # Perché una formula così semplice
//!
//! Perché deve potersi spiegare a chi legge il rapporto. Un punteggio continuo
//! sarebbe più fine e nessuno saprebbe dire perché un contenuto vale 2,7. I
//! livelli sono cinque perché devono essere cinque cose dicibili.
//!
//! # Che cosa questo modulo non fa
//!
//! Non decide. Attribuisce un livello e lo motiva; la valutazione resta
//! all'operatore, e la revisione umana è parte del percorso.

use crate::model::analysis::AnalysisLevel;
use crate::model::dictionary::{MatchMode, ResolvedTerm};

/// Numero di termini positivi distinti oltre il quale scatta la corroborazione.
pub const CORROBORATION_TERMS: usize = 3;

/// Numero di categorie distinte richieste dalla corroborazione.
///
/// Senza questo vincolo la corroborazione sarebbe un modo mascherato di
/// sommare: dieci sinonimi della stessa condotta restano un solo fatto.
pub const CORROBORATION_CATEGORIES: usize = 2;

/// Termine che ha contribuito all'esito, con la sua provenienza.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContributingTerm {
    /// Testo del termine come compare nel dizionario.
    pub text: String,
    /// Categoria dichiarata dal dizionario.
    pub category: String,
    /// Livello suggerito, con il segno.
    pub suggested_level: i8,
    /// Quante volte compare nel contenuto.
    pub occurrences: usize,
    /// Dizionari da cui proviene, in forma leggibile.
    pub sources: Vec<String>,
    /// Se è un codice numerico, che conta soltanto insieme a un altro termine.
    pub numeric_code: bool,
}

impl ContributingTerm {
    /// Se il termine abbassa il peso invece di aumentarlo.
    #[must_use]
    pub const fn is_mitigating(&self) -> bool {
        self.suggested_level < 0
    }
}

/// Perché un contenuto ha ricevuto il livello che ha ricevuto.
///
/// È **parte dell'esito**, non un registro di diagnostica: comparirà nella
/// notifica, nella schermata di revisione e nel rapporto, ed è ciò che permette
/// a un operatore di dire «questo è un falso positivo, ecco perché».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisRationale {
    /// Termini che hanno contribuito, in ordine canonico.
    pub terms: Vec<ContributingTerm>,
    /// Livello suggerito più alto fra i positivi.
    pub base: i8,
    /// Termine che ha determinato la base, se esiste.
    pub base_term: Option<String>,
    /// Contributo della corroborazione, `0` o `1`.
    pub corroboration: i8,
    /// Categorie distinte che hanno corroborato.
    pub corroborating_categories: Vec<String>,
    /// Contributo della mitigazione, sempre minore o uguale a zero.
    pub mitigation: i8,
    /// Termine che ha mitigato, se esiste.
    pub mitigating_term: Option<String>,
    /// Codici numerici trovati da soli, che non hanno contato: senza un altro
    /// termine positivo non alzano il livello (ADR-0170).
    pub held_codes: Vec<String>,
}

impl AnalysisRationale {
    /// Se nessun termine è stato trovato.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }

    /// Frase leggibile che spiega l'esito.
    ///
    /// Dice **che cosa** è stato trovato e **come** ha pesato. Non dichiara che
    /// il contenuto sia rilevante: quella è una valutazione, e spetta a chi
    /// legge.
    #[must_use]
    pub fn to_sentence(&self) -> String {
        if self.terms.is_empty() {
            return String::from("Nessun termine della configurazione compare nel contenuto.");
        }

        let mut sentence = match &self.base_term {
            Some(term) => format!(
                "Il termine più significativo trovato è \"{term}\", con livello suggerito {}.",
                self.base
            ),
            None if !self.held_codes.is_empty() => String::from("Nessun termine alza il livello."),
            None => String::from(
                "Sono stati trovati soltanto termini di contesto riduttivo, \
                 che non alzano il livello.",
            ),
        };

        if self.corroboration > 0 {
            sentence.push_str(&format!(
                " Il livello è stato alzato di uno perché i termini distinti trovati sono {} \
                 e appartengono a più categorie: {}.",
                self.terms.iter().filter(|t| !t.is_mitigating()).count(),
                self.corroborating_categories.join(", ")
            ));
        }

        if let Some(mitigating) = &self.mitigating_term {
            sentence.push_str(&format!(
                " Il livello è stato abbassato di {} per la presenza di \"{mitigating}\", \
                 che indica un contesto in cui il riscontro può essere fuorviante.",
                self.mitigation.abs()
            ));
        }

        let codici: Vec<String> = self
            .held_codes
            .iter()
            .map(|code| format!("\"{code}\""))
            .collect();
        match codici.as_slice() {
            [] => {}
            [uno] => sentence.push_str(&format!(
                " Il codice numerico {uno} compare, ma da solo non alza il livello: conta \
                 soltanto insieme a un altro termine."
            )),
            _ => sentence.push_str(&format!(
                " I codici numerici {} compaiono, ma da soli non alzano il livello: contano \
                 soltanto insieme a un altro termine.",
                codici.join(", ")
            )),
        }

        sentence
    }
}

/// Esito dell'analisi di un contenuto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisOutcome {
    /// Livello attribuito, da 0 a 4.
    pub level: AnalysisLevel,
    /// Perché quel livello.
    pub rationale: AnalysisRationale,
}

impl AnalysisOutcome {
    /// Se l'esito comporta un alert.
    #[must_use]
    pub const fn raises_alert(&self) -> bool {
        self.level.raises_alert()
    }
}

/// Calcola l'esito a partire dai termini trovati e da quante volte compaiono.
///
/// `counts[i]` è il numero di occorrenze del termine `terms[i]`. Un termine con
/// zero occorrenze non ha contribuito e non compare nella motivazione: elencare
/// ciò che **non** è stato trovato renderebbe la spiegazione illeggibile.
///
/// La funzione è **pura**: stesso ingresso, stesso esito. È la proprietà su cui
/// si regge la ripetibilità di una sessione.
#[must_use]
pub fn score(terms: &[ResolvedTerm], counts: &[usize]) -> AnalysisOutcome {
    let mut contributing: Vec<ContributingTerm> = terms
        .iter()
        .enumerate()
        .filter_map(|(index, term)| {
            let occurrences = counts.get(index).copied().unwrap_or(0);
            if occurrences == 0 {
                return None;
            }
            Some(ContributingTerm {
                text: term.original.as_str().to_string(),
                category: term.category.as_str().to_string(),
                suggested_level: term.suggested_level,
                occurrences,
                sources: term
                    .provenances
                    .iter()
                    .map(|provenance| provenance.label.clone())
                    .collect(),
                numeric_code: term.match_mode == MatchMode::NumericCode,
            })
        })
        .collect();

    // Ordine canonico: prima i più significativi, poi per testo. La motivazione
    // non deve cambiare fra due esecuzioni identiche.
    contributing.sort_by(|left, right| {
        right
            .suggested_level
            .cmp(&left.suggested_level)
            .then_with(|| left.text.cmp(&right.text))
    });

    // Un codice numerico conta soltanto insieme a un altro termine positivo
    // che non sia un codice (ADR-0170, decisione 3): una cifra da sola
    // coincide con date, prezzi e identificativi (DEC-224).
    let accompanied = contributing
        .iter()
        .any(|term| term.suggested_level > 0 && !term.numeric_code);
    let held_codes: Vec<String> = if accompanied {
        Vec::new()
    } else {
        contributing
            .iter()
            .filter(|term| term.numeric_code)
            .map(|term| term.text.clone())
            .collect()
    };

    let positives: Vec<&ContributingTerm> = contributing
        .iter()
        .filter(|term| term.suggested_level > 0 && (accompanied || !term.numeric_code))
        .collect();

    let base = positives.first().map_or(0, |term| term.suggested_level);
    let base_term = positives.first().map(|term| term.text.clone());

    // Categorie distinte fra i positivi, in ordine canonico.
    let mut categories: Vec<String> = Vec::new();
    for term in &positives {
        if !categories.contains(&term.category) {
            categories.push(term.category.clone());
        }
    }
    categories.sort();

    let corroborates =
        positives.len() >= CORROBORATION_TERMS && categories.len() >= CORROBORATION_CATEGORIES;
    let corroboration = i8::from(corroborates);

    let mitigator = contributing
        .iter()
        .filter(|term| term.is_mitigating())
        .min_by_key(|term| term.suggested_level);
    let mitigation = mitigator.map_or(0, |term| term.suggested_level);
    let mitigating_term = mitigator.map(|term| term.text.clone());

    let raw = i32::from(base) + i32::from(corroboration) + i32::from(mitigation);
    let clamped = raw.clamp(0, i32::from(AnalysisLevel::MAX));

    // `clamped` sta per costruzione fra 0 e 4, quindi la conversione riesce; il
    // ramo di errore resta il livello nullo invece di un panico.
    let level = u8::try_from(clamped)
        .ok()
        .and_then(|value| AnalysisLevel::try_new(value).ok())
        .unwrap_or(AnalysisLevel::NOT_RELEVANT);

    AnalysisOutcome {
        level,
        rationale: AnalysisRationale {
            terms: contributing,
            base,
            base_term,
            corroboration,
            corroborating_categories: if corroborates { categories } else { vec![] },
            mitigation,
            mitigating_term,
            held_codes,
        },
    }
}

#[cfg(test)]
mod tests {

    use super::{AnalysisLevel, score};
    use crate::model::dictionary::{MatchMode, ResolvedTerm, TermProvenance};
    use crate::text::{LanguageTag, TermCategory, TermText};

    /// Termine risolto con testo, categoria e livello indicati.
    fn term(text: &str, category: &str, level: i8) -> ResolvedTerm {
        let (Ok(original), Ok(category), Ok(language)) = (
            TermText::try_new(text),
            TermCategory::try_new(category),
            LanguageTag::try_new("it"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };

        ResolvedTerm {
            normalised: crate::model::dictionary::normalise_for_matching(text),
            original,
            category,
            language,
            match_mode: MatchMode::NormalizedWord,
            suggested_level: level,
            provenances: vec![TermProvenance::ad_hoc()],
        }
    }

    /// Codice numerico risolto, con il suo livello 1.
    fn code(text: &str) -> ResolvedTerm {
        ResolvedTerm {
            match_mode: MatchMode::NumericCode,
            ..term(text, "codice", 1)
        }
    }

    /// **Un codice numerico da solo non alza il livello, e la motivazione lo
    /// dice** (DICT-CODES-01, ADR-0170, criterio 3; prova negativa: il codice
    /// contato come ogni termine → rossa).
    #[test]
    fn un_codice_da_solo_non_alza_il_livello() {
        let outcome = score(&[code("88")], &[3]);
        assert_eq!(outcome.level, AnalysisLevel::NOT_RELEVANT);
        assert!(!outcome.raises_alert());
        assert_eq!(outcome.rationale.terms.len(), 1, "il riscontro si mostra");
        assert_eq!(outcome.rationale.held_codes, ["88"]);
        assert_eq!(outcome.rationale.base_term, None);
        let frase = outcome.rationale.to_sentence();
        assert!(
            frase.starts_with("Nessun termine alza il livello."),
            "{frase}"
        );
        assert!(
            frase.contains("\"88\" compare, ma da solo non alza il livello"),
            "{frase}"
        );

        // Due codici non si fanno compagnia.
        let due = score(&[code("88"), code("14")], &[1, 1]);
        assert_eq!(due.level, AnalysisLevel::NOT_RELEVANT);
        assert_eq!(due.rationale.held_codes.len(), 2);
        assert!(due.rationale.to_sentence().contains("I codici numerici"));
    }

    /// **Insieme a un altro termine positivo il codice conta, e con il livello
    /// 1 concorre soltanto alla corroborazione** (criterio 3).
    #[test]
    fn insieme_a_un_altro_termine_il_codice_conta() {
        let senza = score(
            &[
                term("appiccare", "azione", 2),
                term("molotov", "oggetto", 2),
            ],
            &[1, 1],
        );
        assert_eq!(senza.level.get(), 2, "due termini non corroborano");

        let con = score(
            &[
                term("appiccare", "azione", 2),
                term("molotov", "oggetto", 2),
                code("88"),
            ],
            &[1, 1, 1],
        );
        assert_eq!(con.rationale.base, 2, "il codice non fa la base");
        assert_eq!(con.rationale.corroboration, 1);
        assert_eq!(con.level.get(), 3);
        assert!(con.rationale.held_codes.is_empty());
        assert!(!con.rationale.to_sentence().contains("da solo"));

        // Un termine di contesto riduttivo non è un compagno.
        let riduttivo = score(&[code("88"), term("nel film", "finzione", -2)], &[1, 1]);
        assert_eq!(riduttivo.level, AnalysisLevel::NOT_RELEVANT);
        assert_eq!(riduttivo.rationale.held_codes, ["88"]);
    }

    #[test]
    fn nothing_found_means_level_zero_and_a_sentence_that_says_so() {
        let terms = vec![term("incendio", "azione", 3)];
        let outcome = score(&terms, &[0]);

        assert_eq!(outcome.level, AnalysisLevel::NOT_RELEVANT);
        assert!(!outcome.raises_alert());
        assert!(outcome.rationale.is_empty());
        assert!(outcome.rationale.to_sentence().contains("Nessun termine"));
    }

    #[test]
    fn the_level_is_the_highest_suggested_and_not_the_sum() {
        // Sommare farebbe salire a 4 qualunque contenuto abbastanza lungo:
        // dieci parole da 1 peserebbero come una da 4.
        let terms = vec![
            term("uno", "azione", 1),
            term("due", "azione", 1),
            term("tre", "azione", 1),
        ];
        // Tre termini di una sola categoria: nessuna corroborazione.
        let outcome = score(&terms, &[1, 1, 1]);

        assert_eq!(outcome.level.get(), 1);
        assert_eq!(outcome.rationale.base, 1);
        assert_eq!(outcome.rationale.corroboration, 0);
    }

    #[test]
    fn three_distinct_terms_from_two_categories_raise_the_level_by_one() {
        let terms = vec![
            term("appiccare", "azione", 2),
            term("molotov", "oggetto", 2),
            term("innesco", "oggetto", 1),
        ];
        let outcome = score(&terms, &[1, 1, 1]);

        assert_eq!(outcome.rationale.base, 2);
        assert_eq!(outcome.rationale.corroboration, 1);
        assert_eq!(outcome.level.get(), 3);
        assert!(outcome.rationale.to_sentence().contains("alzato di uno"));
    }

    #[test]
    fn many_synonyms_of_one_category_do_not_corroborate() {
        // Dieci sinonimi della stessa condotta restano un solo fatto.
        let terms: Vec<_> = (0..10)
            .map(|index| term(&format!("sinonimo{index}"), "azione", 2))
            .collect();
        let counts = vec![1_usize; 10];
        let outcome = score(&terms, &counts);

        assert_eq!(outcome.rationale.corroboration, 0);
        assert_eq!(outcome.level.get(), 2);
    }

    #[test]
    fn a_mitigating_term_lowers_the_level() {
        let terms = vec![
            term("incendio", "azione", 3),
            term("nel film", "finzione", -3),
        ];
        let outcome = score(&terms, &[1, 1]);

        assert_eq!(outcome.rationale.base, 3);
        assert_eq!(outcome.rationale.mitigation, -3);
        assert_eq!(
            outcome.level.get(),
            0,
            "un livello 3 su una recensione e' un errore"
        );
        assert!(outcome.rationale.to_sentence().contains("abbassato di 3"));
    }

    #[test]
    fn mitigation_cannot_push_the_level_below_zero() {
        let terms = vec![
            term("incendio", "azione", 1),
            term("nel videogioco", "finzione", -4),
        ];
        assert_eq!(score(&terms, &[1, 1]).level, AnalysisLevel::NOT_RELEVANT);
    }

    #[test]
    fn only_mitigating_terms_leave_the_level_at_zero() {
        // Non c'e' nulla da abbassare.
        let terms = vec![term("nel film", "finzione", -3)];
        let outcome = score(&terms, &[1]);

        assert_eq!(outcome.level, AnalysisLevel::NOT_RELEVANT);
        assert_eq!(outcome.rationale.base, 0);
        assert!(outcome.rationale.base_term.is_none());
        assert!(
            outcome
                .rationale
                .to_sentence()
                .contains("contesto riduttivo")
        );
    }

    #[test]
    fn the_level_never_exceeds_four() {
        let terms = vec![
            term("uno", "a", 4),
            term("due", "b", 4),
            term("tre", "c", 4),
        ];
        // base 4 + corroborazione 1 = 5, limitato a 4.
        assert_eq!(score(&terms, &[1, 1, 1]).level.get(), AnalysisLevel::MAX);
    }

    #[test]
    fn the_strongest_mitigator_is_the_one_that_applies() {
        let terms = vec![
            term("incendio", "azione", 4),
            term("per scherzo", "ironia", -1),
            term("nel film", "finzione", -3),
        ];
        let outcome = score(&terms, &[1, 1, 1]);

        assert_eq!(outcome.rationale.mitigation, -3);
        assert_eq!(
            outcome.rationale.mitigating_term.as_deref(),
            Some("nel film")
        );
    }

    #[test]
    fn only_the_terms_actually_found_appear_in_the_rationale() {
        // Elencare cio' che non e' stato trovato renderebbe la spiegazione
        // illeggibile.
        let terms = vec![term("trovato", "azione", 2), term("assente", "azione", 4)];
        let outcome = score(&terms, &[1, 0]);

        assert_eq!(outcome.rationale.terms.len(), 1);
        assert_eq!(outcome.rationale.terms[0].text, "trovato");
        assert_eq!(outcome.level.get(), 2, "il termine assente non pesa");
    }

    #[test]
    fn the_number_of_occurrences_is_kept_but_does_not_change_the_level() {
        // Ricorrere e' un'informazione da mostrare, non un moltiplicatore: una
        // parola ripetuta venti volte resta un solo termine.
        let terms = vec![term("molotov", "oggetto", 3)];
        let once = score(&terms, &[1]);
        let many = score(&terms, &[20]);

        assert_eq!(once.level, many.level);
        assert_eq!(many.rationale.terms[0].occurrences, 20);
    }

    #[test]
    fn the_outcome_is_deterministic_and_its_order_is_canonical() {
        // Senza questa proprieta' l'impronta della configurazione non
        // servirebbe a nulla.
        let terms = vec![
            term("zeta", "b", 2),
            term("alfa", "a", 3),
            term("mike", "a", 2),
        ];
        let first = score(&terms, &[1, 1, 1]);
        let second = score(&terms, &[1, 1, 1]);

        assert_eq!(first, second);
        let order: Vec<&str> = first
            .rationale
            .terms
            .iter()
            .map(|entry| entry.text.as_str())
            .collect();
        assert_eq!(
            order,
            ["alfa", "mike", "zeta"],
            "livello decrescente, poi testo"
        );
    }

    #[test]
    fn the_sentence_names_the_term_that_set_the_base() {
        let terms = vec![term("appiccare", "azione", 3)];
        let sentence = score(&terms, &[1]).rationale.to_sentence();

        assert!(sentence.contains("appiccare"));
        assert!(sentence.contains('3'));
    }

    #[test]
    fn the_rationale_keeps_the_provenance_of_every_term() {
        // E' la risposta alla domanda "perche' questo contenuto e' stato
        // segnalato": nominare il termine senza il dizionario dice meta' cosa.
        let terms = vec![term("incendio", "azione", 2)];
        let outcome = score(&terms, &[1]);

        assert_eq!(outcome.rationale.terms[0].sources.len(), 1);
        assert!(!outcome.rationale.terms[0].sources[0].is_empty());
    }
}

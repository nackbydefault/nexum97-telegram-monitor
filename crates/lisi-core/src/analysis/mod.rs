//! Motore di analisi trasparente, livelli 0–4.
//!
//! Le scelte sono in `docs/adr/ADR-0016-ANALYSIS-ENGINE.md`.
//!
//! # Che cosa il motore fa
//!
//! Riceve il testo di un contenuto e la **configurazione risolta** di una
//! sessione, trova quali termini vi compaiono e dove, e ne ricava un livello da
//! 0 a 4 **insieme alla ragione** per cui l'ha attribuito.
//!
//! # Che cosa non fa
//!
//! - **non decide.** La valutazione resta all'operatore, e la revisione umana è
//!   parte del percorso, non un ripensamento;
//! - **non comprende.** Il riscontro è lessicale: ironia, negazione a distanza,
//!   riferimento a un messaggio precedente e sottinteso non sono visti;
//! - **non stima una probabilità.** Il livello 4 non dice «è molto probabile
//!   che accada»: dice che sono comparse parole che l'ufficio ha deciso di
//!   monitorare, in una combinazione che l'ufficio ha deciso di considerare
//!   grave.
//!
//! # Purezza
//!
//! [`analyse`] è una funzione: stesso testo e stessa configurazione, stesso
//! esito. La persistenza sta altrove, e i test non hanno bisogno di un
//! database. È anche la proprietà su cui si regge la ripetibilità di una
//! sessione: dire «fu condotta con questi termini» conta solo se quei termini
//! producono sempre lo stesso esito.

pub mod engine;
pub mod expression;
pub mod matching;
pub mod scoring;

pub use crate::analysis::engine::{ENGINE_VERSION, engine_label, unknown_engine_label};
pub use crate::analysis::matching::{TermOccurrence, find_occurrences};
pub use crate::analysis::scoring::{
    AnalysisOutcome, AnalysisRationale, CORROBORATION_CATEGORIES, CORROBORATION_TERMS,
    ContributingTerm, score,
};
use crate::model::dictionary::ResolvedDictionaryConfiguration;

/// Esito completo dell'analisi di un contenuto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysedContent {
    /// Livello e motivazione.
    pub outcome: AnalysisOutcome,
    /// Dove ciascun termine è stato trovato, in ordine canonico.
    ///
    /// Serve a mostrare all'operatore **quale porzione** del messaggio ha
    /// prodotto il riscontro: un livello senza il punto del testo costringe a
    /// rileggere tutto per capire.
    pub occurrences: Vec<TermOccurrence>,
}

/// Analizza un contenuto rispetto alla configurazione risolta di una sessione.
///
/// La configurazione è quella **conservata con la sessione**, non i dizionari
/// correnti: se un dizionario cambia mentre la sessione è in corso, l'analisi
/// continua con i termini di prima.
#[must_use]
pub fn analyse(body: &str, configuration: &ResolvedDictionaryConfiguration) -> AnalysedContent {
    let occurrences = find_occurrences(body, &configuration.terms);

    let mut counts = vec![0_usize; configuration.terms.len()];
    for occurrence in &occurrences {
        if let Some(count) = counts.get_mut(occurrence.term_index) {
            *count += 1;
        }
    }

    AnalysedContent {
        outcome: score(&configuration.terms, &counts),
        occurrences,
    }
}

#[cfg(test)]
mod tests {
    use super::analyse;
    use crate::model::analysis::AnalysisLevel;
    use crate::model::dictionary::{
        ConfigurationResolver, MatchMode, ResolvedDictionaryConfiguration, TermProvenance,
    };
    use crate::text::{LanguageTag, TermCategory, TermText};

    /// Configurazione risolta con i termini indicati.
    fn configuration(entries: &[(&str, &str, i8)]) -> ResolvedDictionaryConfiguration {
        let (Ok(language), Ok(_)) = (LanguageTag::try_new("it"), TermText::try_new("x")) else {
            panic!("i valori di prova devono essere validi");
        };

        let mut resolver = ConfigurationResolver::new();
        for (text, category, level) in entries {
            let (Ok(text), Ok(category)) =
                (TermText::try_new(text), TermCategory::try_new(category))
            else {
                panic!("il termine di prova '{text}' deve essere valido");
            };
            let Ok(()) = resolver.add(
                text,
                category,
                language.clone(),
                MatchMode::NormalizedWord,
                *level,
                TermProvenance::ad_hoc(),
            ) else {
                panic!("il termine doveva essere accettato");
            };
        }
        resolver.finish()
    }

    #[test]
    fn a_content_without_any_term_is_analysed_and_found_not_relevant() {
        // Livello 0 non e' assenza di analisi: e' un contenuto analizzato e
        // risultato non rilevante, che resta nello storico.
        let config = configuration(&[("incendio", "azione", 3)]);
        let analysed = analyse("ci vediamo domani alle otto", &config);

        assert_eq!(analysed.outcome.level, AnalysisLevel::NOT_RELEVANT);
        assert!(analysed.occurrences.is_empty());
        assert!(!analysed.outcome.raises_alert());
    }

    #[test]
    fn a_single_term_gives_its_own_level_and_says_where_it_is() {
        let config = configuration(&[("molotov", "oggetto", 4)]);
        let analysed = analyse("hanno preparato una molotov", &config);

        assert_eq!(analysed.outcome.level.get(), 4);
        assert!(analysed.outcome.raises_alert());
        assert_eq!(analysed.occurrences.len(), 1);
        assert_eq!(analysed.occurrences[0].start, 20);
    }

    #[test]
    fn the_mitigating_context_lowers_a_real_content() {
        // La frase e' plausibile e il riscontro sarebbe fuorviante: e' il caso
        // per cui il dizionario di contesto riduttivo esiste.
        let config = configuration(&[("incendio", "azione", 3), ("nel film", "finzione", -3)]);

        let allarmante = analyse("hanno appiccato un incendio al deposito", &config);
        let recensione = analyse("nel film c'e' un incendio spettacolare", &config);

        assert_eq!(allarmante.outcome.level.get(), 3);
        assert_eq!(recensione.outcome.level.get(), 0);
        assert!(
            recensione
                .outcome
                .rationale
                .to_sentence()
                .contains("nel film")
        );
    }

    #[test]
    fn the_same_content_analysed_twice_gives_the_same_outcome() {
        let config = configuration(&[
            ("appiccare", "azione", 2),
            ("molotov", "oggetto", 3),
            ("innesco", "oggetto", 1),
        ]);
        let body = "vogliono appiccare con una molotov e un innesco";

        assert_eq!(analyse(body, &config), analyse(body, &config));
    }

    #[test]
    fn a_repeated_term_is_counted_but_does_not_raise_the_level() {
        let config = configuration(&[("molotov", "oggetto", 2)]);
        let analysed = analyse("molotov, molotov, ancora molotov", &config);

        assert_eq!(analysed.occurrences.len(), 3);
        assert_eq!(analysed.outcome.rationale.terms[0].occurrences, 3);
        assert_eq!(analysed.outcome.level.get(), 2);
    }

    #[test]
    fn an_empty_configuration_analyses_without_finding_anything() {
        let empty = ResolvedDictionaryConfiguration::from_terms(vec![]);
        let analysed = analyse("qualunque testo", &empty);

        assert_eq!(analysed.outcome.level, AnalysisLevel::NOT_RELEVANT);
        assert!(analysed.outcome.rationale.is_empty());
    }

    #[test]
    fn an_empty_body_is_analysed_without_panicking() {
        let config = configuration(&[("incendio", "azione", 3)]);
        assert_eq!(
            analyse("", &config).outcome.level,
            AnalysisLevel::NOT_RELEVANT
        );
    }

    #[test]
    fn the_sentence_is_readable_and_names_what_was_found() {
        let config = configuration(&[
            ("appiccare", "azione", 2),
            ("molotov", "oggetto", 3),
            ("innesco", "oggetto", 1),
        ]);
        let sentence = analyse("appiccare con molotov e innesco", &config)
            .outcome
            .rationale
            .to_sentence();

        assert!(sentence.contains("molotov"), "manca il termine della base");
        assert!(
            sentence.contains("alzato di uno"),
            "manca la corroborazione"
        );
        assert!(!sentence.contains("None"), "residuo di formattazione");
    }
}

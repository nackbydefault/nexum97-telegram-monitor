//! Perché l'operatore sta vedendo questo.
//!
//! # I tre fatti da cui questo modulo nasce
//!
//! Nessuno dei tre è stato introdotto da PROV-01: erano già veri, e la
//! spiegazione non era raggiungibile.
//!
//! **1. Ogni riscontro è persistito, una riga per occorrenza.** `matches`
//! conserva il termine, la categoria, il testo trovato, la posizione e il
//! livello — anche per i contenuti di livello 0. Quante volte un termine
//! compare non è un dato da ricostruire: è il numero di righe.
//!
//! **2. La configurazione della sessione è una fotografia immutabile.**
//! `session_resolved_terms` conserva i termini **come erano quando la sessione
//! è stata avviata**, con le loro provenienze, e la sua impronta viene
//! verificata a ogni lettura. Un dizionario modificato dopo non la tocca.
//!
//! **3. Il livello è una funzione pura di quei due.** `analysis::score` non
//! guarda l'orologio, non guarda i dizionari correnti, non guarda nulla che
//! non gli venga passato.
//!
//! # La conseguenza, che è tutta la milestone
//!
//! La spiegazione di un livello **non va conservata**: va **ricalcolata dalla
//! fotografia della sessione**, che è la configurazione realmente in vigore al
//! momento dell'analisi. Non è una ricostruzione speculativa — è la stessa
//! aritmetica sugli stessi fatti.
//!
//! # E la regola che rende onesta la ricostruzione
//!
//! Un ricalcolo che *sembra* giusto non basta. Questo modulo **confronta il
//! livello ricalcolato con il livello persistito** e mostra la spiegazione
//! **soltanto quando i due coincidono** ([`ScoringExplanation::Verified`]).
//!
//! Quando non coincidono la spiegazione **non** viene mostrata come tale: si
//! dichiara la discordanza ([`ScoringExplanation::Disagreeing`]). Una
//! spiegazione plausibile e sbagliata, accanto a un livello vero, è peggio di
//! nessuna spiegazione — è la stessa ragione per cui CTX-01 ha rifiutato il
//! confronto parola per parola (ADR-0051 Decisione 2).
//!
//! # Che cosa questo modulo non fa
//!
//! Non riesegue il riscontro sul testo. I riscontri sono **fatti registrati**,
//! e rileggerli col motore di oggi risponderebbe alla domanda sbagliata: non
//! «che cosa fu trovato», ma «che cosa troverei adesso». Qui si ricalcola
//! soltanto l'**aritmetica** del livello, sui riscontri che furono scritti.

use std::collections::BTreeMap;

use crate::analysis::scoring::{AnalysisRationale, ContributingTerm, score};
use crate::model::analysis::{AnalysisLevel, ContentMatch, MatchRange};
use crate::model::dictionary::{ResolvedDictionaryConfiguration, ResolvedTerm};

/// Un termine che ha contribuito, con la sua provenienza documentale.
///
/// Mette insieme due cose che l'archivio tiene separate: i **riscontri**, che
/// dicono dove e quante volte, e la **fotografia della sessione**, che dice da
/// quale dizionario e in quale versione il termine veniva.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TermContribution {
    /// Testo del termine come è stato trovato nel contenuto.
    pub text: String,
    /// Forma normalizzata, che è la chiave con cui i due archivi si legano.
    pub normalised: String,
    /// Categoria dichiarata dal dizionario.
    pub category: String,
    /// Quante volte compare nel contenuto: è il numero di riscontri registrati.
    pub occurrences: usize,
    /// Posizione della prima occorrenza nel testo.
    pub first_position: MatchRange,
    /// Livello suggerito **con il segno**, quando la fotografia lo dice.
    ///
    /// # Perché non basta il livello del riscontro
    ///
    /// La tabella dei riscontri conserva il livello **schiacciato a zero** per
    /// i termini mitiganti: un livello di analisi parte da 0 e non ammette il
    /// segno. Da lì un termine che *abbassa* il livello e un termine positivo
    /// che non lo alza sono indistinguibili.
    ///
    /// Il segno esiste solo nella fotografia della sessione, ed è il motivo
    /// per cui la mitigazione si può spiegare soltanto leggendola.
    pub suggested_level: Option<i8>,
    /// Dizionari di provenienza, come l'operatore li conosce.
    ///
    /// Vuoto quando la fotografia non è disponibile: allora si sa **che** il
    /// termine fu trovato, non **da dove** veniva.
    pub dictionaries: Vec<String>,
}

impl TermContribution {
    /// Se il termine abbassa il livello invece di alzarlo.
    ///
    /// `false` anche quando il segno non è noto: dichiarare mitigante ciò che
    /// non si sa sarebbe un'attribuzione inventata.
    #[must_use]
    pub fn is_mitigating(&self) -> bool {
        self.suggested_level.is_some_and(|level| level < 0)
    }

    /// Se la fotografia della sessione conosce questo termine.
    #[must_use]
    pub fn has_documentary_origin(&self) -> bool {
        self.suggested_level.is_some()
    }

    /// Frase che dice all'operatore che cosa è stato trovato e da dove viene.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let quante = match self.occurrences {
            1 => String::from("una volta"),
            altre => format!("{altre} volte"),
        };

        // IL DIZIONARIO SI NOMINA COME TALE, E IL TERMINE CHE ATTENUA LO DICE
        // (FULL-OPERATIONAL-VALIDATION-01, OBS-AN-1). Il nome nudo dopo il
        // trattino non si leggeva come un dizionario, e la spiegazione di un
        // termine riduttivo non diceva che abbassava il livello.
        let origine = match self.dictionaries.as_slice() {
            [] => String::from("provenienza non registrata"),
            [uno] => format!("dal dizionario \u{ab}{uno}\u{bb}"),
            molti => format!(
                "dai dizionari {}",
                molti
                    .iter()
                    .map(|nome| format!("\u{ab}{nome}\u{bb}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
        let effetto = if self.is_mitigating() {
            "; abbassa il livello"
        } else {
            ""
        };

        format!(
            "\u{ab}{}\u{bb}, categoria {}, trovato {quante} \u{2014} {origine}{effetto}",
            self.text, self.category
        )
    }
}

/// Perché la spiegazione di un livello non è disponibile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplanationGap {
    /// La sessione non conserva la fotografia dei termini.
    ///
    /// È il caso dei dati anteriori alla fotografia, e delle sessioni le cui
    /// selezioni sono state rimosse dalla conservazione.
    NoSessionSnapshot,
    /// La fotografia esiste ma non ha superato la verifica della propria
    /// impronta: è stata alterata, e non se ne può rispondere.
    SnapshotNotTrustworthy,
    /// Il contenuto non ha alcun riscontro registrato.
    ///
    /// Non è una lacuna dell'archivio: è l'esito. Nessun termine della
    /// configurazione compariva nel contenuto.
    NoMatches,
}

impl ExplanationGap {
    /// Frase che dice all'operatore che cosa manca, e che non lo nasconde.
    #[must_use]
    pub const fn as_sentence(self) -> &'static str {
        match self {
            Self::NoSessionSnapshot => {
                "Informazione non disponibile per questo contenuto: la sessione che lo ha \
                 acquisito non conserva l'elenco dei termini con cui fu analizzato. Il livello \
                 registrato resta valido; ciò che manca è il modo di rispiegarlo."
            }
            Self::SnapshotNotTrustworthy => {
                "L'elenco dei termini conservato con questa sessione non corrisponde più alla \
                 propria impronta. Non viene usato per spiegare alcunché: una copia alterata \
                 non può giustificare un risultato."
            }
            Self::NoMatches => {
                "Nessun termine della configurazione compare in questo contenuto. È il motivo \
                 per cui il livello è 0: analizzato, e nessun avviso."
            }
        }
    }
}

/// Come è stato calcolato il livello, e con quanta certezza lo si può dire.
///
/// L'ordine delle varianti è l'ordine della fiducia: la prima è verificata, le
/// altre dichiarano che cosa manca.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScoringExplanation {
    /// Ricalcolo riuscito **e coincidente** con il livello persistito.
    ///
    /// È l'unico caso in cui una spiegazione viene presentata come la ragione
    /// del livello.
    Verified {
        /// Base, corroborazione, mitigazione e termini, ricalcolati.
        rationale: AnalysisRationale,
        /// Livello, identico a quello registrato.
        level: AnalysisLevel,
    },
    /// Ricalcolo riuscito ma **discorde** dal livello persistito.
    ///
    /// Il livello che vale resta quello registrato. La discordanza si dichiara
    /// e non si nasconde, perché significa che qualcosa non torna: la formula
    /// è cambiata dopo, oppure i riscontri e il livello non appartengono allo
    /// stesso calcolo.
    Disagreeing {
        /// Livello registrato, che resta quello valido.
        stored: AnalysisLevel,
        /// Livello che i riscontri conservati producono oggi.
        recomputed: AnalysisLevel,
    },
    /// Non ricalcolabile: manca qualcosa, e si dice che cosa.
    Unavailable(ExplanationGap),
}

impl ScoringExplanation {
    /// Se la spiegazione può essere mostrata come la ragione del livello.
    #[must_use]
    pub const fn is_trustworthy(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// Frase per l'operatore, in ogni caso: anche «non lo so» è una risposta.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self {
            Self::Verified { rationale, level } => {
                format!(
                    "{} Il calcolo è stato rifatto sui riscontri conservati e sui termini con \
                     cui la sessione fu condotta, e riproduce il livello registrato ({}).",
                    rationale.to_sentence(),
                    level.get()
                )
            }
            Self::Disagreeing { stored, recomputed } => format!(
                "Il livello registrato è {}, ma i riscontri conservati oggi ne produrrebbero \
                 {}. La spiegazione non viene mostrata: il livello che vale è quello \
                 registrato, e una motivazione che non lo riproduce non è la sua motivazione.",
                stored.get(),
                recomputed.get()
            ),
            Self::Unavailable(gap) => gap.as_sentence().to_owned(),
        }
    }
}

/// Termini che hanno contribuito e spiegazione del livello, insieme.
///
/// Sono un risultato solo perché si producono con la stessa lettura: separarli
/// costringerebbe a leggere due volte le stesse righe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoringProvenance {
    /// Termini trovati, in ordine canonico.
    pub contributions: Vec<TermContribution>,
    /// Come è stato calcolato il livello.
    pub explanation: ScoringExplanation,
}

impl ScoringProvenance {
    /// Quante volte, in tutto, un termine della configurazione è comparso.
    #[must_use]
    pub fn total_occurrences(&self) -> usize {
        self.contributions
            .iter()
            .map(|contribution| contribution.occurrences)
            .sum()
    }

    /// Se almeno un termine ha perso la propria provenienza documentale.
    ///
    /// Serve all'interfaccia per dire «alcune provenienze non sono note»
    /// invece di lasciar credere che l'elenco sia completo.
    #[must_use]
    pub fn has_incomplete_origins(&self) -> bool {
        self.contributions
            .iter()
            .any(|contribution| !contribution.has_documentary_origin())
    }
}

/// Ricostruisce perché un contenuto ha il livello che ha.
///
/// `matches` sono i riscontri **registrati** per il contenuto — una riga per
/// occorrenza. `configuration` è la fotografia della sessione che lo acquisì,
/// assente quando la sessione non la conserva. `stored_level` è il livello che
/// sta nell'archivio, e che questa funzione non cambia mai.
///
/// # Perché non riesegue il riscontro sul testo
///
/// Perché la domanda è «che cosa fu trovato», non «che cosa troverei adesso».
/// I riscontri sono fatti registrati; il motore di riscontro di oggi potrebbe
/// rispondere diversamente, e risponderebbe a un'altra domanda.
#[must_use]
pub fn explain_scoring(
    matches: &[ContentMatch],
    configuration: Option<&ResolvedDictionaryConfiguration>,
    stored_level: AnalysisLevel,
) -> ScoringProvenance {
    let contributions = collect_contributions(matches, configuration);

    let explanation = if matches.is_empty() {
        ScoringExplanation::Unavailable(ExplanationGap::NoMatches)
    } else if let Some(configuration) = configuration {
        recompute(&contributions, configuration, stored_level)
    } else {
        ScoringExplanation::Unavailable(ExplanationGap::NoSessionSnapshot)
    };

    ScoringProvenance {
        contributions,
        explanation,
    }
}

/// Raggruppa i riscontri per termine e vi accosta la provenienza documentale.
fn collect_contributions(
    matches: &[ContentMatch],
    configuration: Option<&ResolvedDictionaryConfiguration>,
) -> Vec<TermContribution> {
    // Chiave: la forma normalizzata, che e' cio' con cui il riscontro e' stato
    // scritto e cio' con cui la fotografia indicizza i termini.
    let mut per_termine: BTreeMap<&str, TermContribution> = BTreeMap::new();

    for entry in matches {
        let normalised = entry.rule_id.as_str();
        if let Some(existing) = per_termine.get_mut(normalised) {
            existing.occurrences += 1;
            // La prima occorrenza e' la piu' in alto nel testo, non la prima
            // letta: l'ordine delle righe non e' garantito.
            if entry.range.start() < existing.first_position.start() {
                existing.first_position = entry.range;
            }
            continue;
        }

        let resolved = configuration.and_then(|configuration| find_term(configuration, normalised));

        per_termine.insert(
            normalised,
            TermContribution {
                text: entry.matched_text.as_str().to_owned(),
                normalised: normalised.to_owned(),
                category: entry.rule_category.as_str().to_owned(),
                occurrences: 1,
                first_position: entry.range,
                suggested_level: resolved.map(|term| term.suggested_level),
                dictionaries: resolved.map_or_else(Vec::new, |term| {
                    term.provenances
                        .iter()
                        .map(|provenance| provenance.label.clone())
                        .collect()
                }),
            },
        );
    }

    let mut contributions: Vec<TermContribution> = per_termine.into_values().collect();

    // Lo stesso ordine canonico della motivazione del motore: prima i piu'
    // significativi, poi per testo. Due letture identiche devono presentare le
    // stesse righe nello stesso ordine.
    contributions.sort_by(|left, right| {
        right
            .suggested_level
            .unwrap_or(0)
            .cmp(&left.suggested_level.unwrap_or(0))
            .then_with(|| left.text.cmp(&right.text))
    });
    contributions
}

/// Termine della fotografia con quella forma normalizzata.
fn find_term<'a>(
    configuration: &'a ResolvedDictionaryConfiguration,
    normalised: &str,
) -> Option<&'a ResolvedTerm> {
    configuration
        .terms
        .iter()
        .find(|term| term.normalised == normalised)
}

/// Rifà l'aritmetica del livello e la confronta con quello registrato.
fn recompute(
    contributions: &[TermContribution],
    configuration: &ResolvedDictionaryConfiguration,
    stored_level: AnalysisLevel,
) -> ScoringExplanation {
    let mut terms: Vec<ResolvedTerm> = Vec::with_capacity(contributions.len());
    let mut counts: Vec<usize> = Vec::with_capacity(contributions.len());

    for contribution in contributions {
        // Un riscontro il cui termine non e' nella fotografia non puo' entrare
        // nel calcolo: non se ne conosce il livello suggerito, e attribuirgliene
        // uno sarebbe inventare la causa di un risultato.
        let Some(term) = find_term(configuration, &contribution.normalised) else {
            return ScoringExplanation::Unavailable(ExplanationGap::NoSessionSnapshot);
        };
        terms.push(term.clone());
        counts.push(contribution.occurrences);
    }

    let outcome = score(&terms, &counts);
    if outcome.level == stored_level {
        ScoringExplanation::Verified {
            rationale: outcome.rationale,
            level: outcome.level,
        }
    } else {
        ScoringExplanation::Disagreeing {
            stored: stored_level,
            recomputed: outcome.level,
        }
    }
}

/// Termini della motivazione ricalcolata, per chi vuole leggerli in ordine.
///
/// Esiste perché l'interfaccia mostra i termini della [`AnalysisRationale`]
/// quando la spiegazione è verificata, e le [`TermContribution`] quando non lo
/// è: due elenchi che devono restare distinguibili.
#[must_use]
pub fn rationale_terms(explanation: &ScoringExplanation) -> &[ContributingTerm] {
    match explanation {
        ScoringExplanation::Verified { rationale, .. } => &rationale.terms,
        ScoringExplanation::Disagreeing { .. } | ScoringExplanation::Unavailable(_) => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ExplanationGap, ScoringExplanation, TermContribution, explain_scoring, rationale_terms,
    };
    use crate::id::{ContentId, MatchId};
    use crate::model::analysis::{AnalysisLevel, ContentMatch, MatchRange};
    use crate::model::dictionary::{
        MatchMode, ResolvedDictionaryConfiguration, ResolvedTerm, TermProvenance,
    };
    use crate::text::{LanguageTag, MatchedText, RuleCategory, RuleId, TermCategory, TermText};
    use crate::time::Timestamp;

    fn timestamp() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn level(value: u8) -> AnalysisLevel {
        AnalysisLevel::try_new(value).expect("livello valido")
    }

    fn term(normalised: &str, categoria: &str, suggested: i8, provenienza: &str) -> ResolvedTerm {
        ResolvedTerm {
            normalised: String::from(normalised),
            original: TermText::try_new(normalised).expect("testo valido"),
            category: TermCategory::try_new(categoria).expect("categoria valida"),
            language: LanguageTag::try_new("it").expect("lingua valida"),
            match_mode: MatchMode::NormalizedWord,
            suggested_level: suggested,
            provenances: vec![TermProvenance {
                dictionary_id: None,
                version_id: None,
                label: String::from(provenienza),
            }],
        }
    }

    fn configuration(terms: &[ResolvedTerm]) -> ResolvedDictionaryConfiguration {
        ResolvedDictionaryConfiguration::from_terms(terms.to_vec())
    }

    fn riscontro(raw: i64, normalised: &str, categoria: &str, start: usize) -> ContentMatch {
        ContentMatch {
            id: MatchId::new(raw),
            content_id: ContentId::new(1),
            rule_id: RuleId::try_new(normalised).expect("regola valida"),
            rule_category: RuleCategory::try_new(categoria).expect("categoria valida"),
            matched_text: MatchedText::try_new(normalised).expect("testo valido"),
            range: MatchRange::try_new(start, start + normalised.len()).expect("intervallo valido"),
            level: AnalysisLevel::NOT_RELEVANT,
            created_at: timestamp(),
        }
    }

    #[test]
    fn a_recomputation_that_reproduces_the_stored_level_is_shown() {
        let terms = [term("incendio", "violenza", 3, "Dizionario di prova v1")];
        let configuration = configuration(&terms);
        let matches = [riscontro(1, "incendio", "violenza", 0)];

        let provenance = explain_scoring(&matches, Some(&configuration), level(3));

        assert!(provenance.explanation.is_trustworthy());
        let ScoringExplanation::Verified { level: shown, .. } = &provenance.explanation else {
            panic!("la spiegazione doveva essere verificata");
        };
        assert_eq!(*shown, level(3));
        assert_eq!(rationale_terms(&provenance.explanation).len(), 1);
    }

    #[test]
    fn a_recomputation_that_disagrees_is_declared_and_not_shown() {
        // E' la regola centrale del modulo: una motivazione che non riproduce
        // il livello registrato NON e' la motivazione di quel livello.
        let terms = [term("incendio", "violenza", 3, "Dizionario di prova v1")];
        let configuration = configuration(&terms);
        let matches = [riscontro(1, "incendio", "violenza", 0)];

        // Il livello registrato dice 1, i riscontri conservati direbbero 3.
        let provenance = explain_scoring(&matches, Some(&configuration), level(1));

        assert!(!provenance.explanation.is_trustworthy());
        let ScoringExplanation::Disagreeing { stored, recomputed } = &provenance.explanation else {
            panic!("la discordanza doveva essere dichiarata");
        };
        assert_eq!(*stored, level(1));
        assert_eq!(*recomputed, level(3));
        // Nessun termine viene presentato come causa.
        assert!(rationale_terms(&provenance.explanation).is_empty());
        // E la frase dice quale dei due livelli vale.
        let frase = provenance.explanation.as_sentence();
        assert!(frase.contains("il livello che vale è quello registrato"));
    }

    #[test]
    fn without_the_session_snapshot_the_gap_is_declared() {
        let matches = [riscontro(1, "incendio", "violenza", 0)];

        let provenance = explain_scoring(&matches, None, level(3));

        assert_eq!(
            provenance.explanation,
            ScoringExplanation::Unavailable(ExplanationGap::NoSessionSnapshot)
        );
        // I riscontri restano leggibili: si sa CHE cosa fu trovato, non da dove
        // veniva.
        assert_eq!(provenance.contributions.len(), 1);
        assert!(provenance.has_incomplete_origins());
        assert!(provenance.contributions[0].dictionaries.is_empty());
        assert!(
            provenance
                .explanation
                .as_sentence()
                .contains("Informazione non disponibile")
        );
    }

    #[test]
    fn a_content_without_matches_says_why_it_is_level_zero() {
        let configuration = configuration(&[term("incendio", "violenza", 3, "Prova v1")]);

        let provenance = explain_scoring(&[], Some(&configuration), AnalysisLevel::NOT_RELEVANT);

        assert_eq!(
            provenance.explanation,
            ScoringExplanation::Unavailable(ExplanationGap::NoMatches)
        );
        assert!(provenance.contributions.is_empty());
        assert!(
            provenance
                .explanation
                .as_sentence()
                .contains("analizzato, e nessun avviso")
        );
    }

    #[test]
    fn the_occurrences_are_counted_from_the_recorded_rows() {
        let terms = [term("incendio", "violenza", 2, "Prova v1")];
        let configuration = configuration(&terms);
        let matches = [
            riscontro(1, "incendio", "violenza", 40),
            riscontro(2, "incendio", "violenza", 10),
            riscontro(3, "incendio", "violenza", 80),
        ];

        let provenance = explain_scoring(&matches, Some(&configuration), level(2));

        assert_eq!(provenance.contributions.len(), 1);
        assert_eq!(provenance.contributions[0].occurrences, 3);
        assert_eq!(provenance.total_occurrences(), 3);
        // La posizione mostrata e' la piu' in alto nel testo, non la prima riga
        // letta: l'ordine delle righe non e' garantito.
        assert_eq!(provenance.contributions[0].first_position.start(), 10);
    }

    #[test]
    fn a_mitigating_term_keeps_its_sign_from_the_snapshot() {
        // Il segno NON e' nella tabella dei riscontri: il livello di un
        // riscontro parte da zero. Senza la fotografia, un termine mitigante e
        // un termine positivo che non alza sono indistinguibili.
        let terms = [
            term("incendio", "violenza", 3, "Prova v1"),
            term("film", "contesto", -2, "Prova v1"),
        ];
        let configuration = configuration(&terms);
        let matches = [
            riscontro(1, "incendio", "violenza", 0),
            riscontro(2, "film", "contesto", 20),
        ];

        let provenance = explain_scoring(&matches, Some(&configuration), level(1));

        let mitigante: Vec<&TermContribution> = provenance
            .contributions
            .iter()
            .filter(|contribution| contribution.is_mitigating())
            .collect();
        assert_eq!(mitigante.len(), 1);
        assert_eq!(mitigante[0].text, "film");
        assert!(provenance.explanation.is_trustworthy());
    }

    #[test]
    fn without_the_snapshot_no_term_is_declared_mitigating() {
        // Dichiarare mitigante cio' che non si sa sarebbe un'attribuzione
        // inventata: senza fotografia il segno non esiste.
        let matches = [riscontro(1, "film", "contesto", 0)];

        let provenance = explain_scoring(&matches, None, AnalysisLevel::NOT_RELEVANT);

        assert!(!provenance.contributions[0].is_mitigating());
        assert!(!provenance.contributions[0].has_documentary_origin());
    }

    #[test]
    fn a_match_unknown_to_the_snapshot_refuses_the_recomputation() {
        // Un riscontro il cui termine non e' nella fotografia significa che i
        // due archivi non raccontano la stessa sessione. Meglio dichiararlo che
        // calcolare un livello su una parte dei fatti.
        let configuration = configuration(&[term("incendio", "violenza", 3, "Prova v1")]);
        let matches = [
            riscontro(1, "incendio", "violenza", 0),
            riscontro(2, "sconosciuto", "altro", 20),
        ];

        let provenance = explain_scoring(&matches, Some(&configuration), level(3));

        assert_eq!(
            provenance.explanation,
            ScoringExplanation::Unavailable(ExplanationGap::NoSessionSnapshot)
        );
        // Ma il riscontro sconosciuto resta visibile, con la sua lacuna.
        assert_eq!(provenance.contributions.len(), 2);
        assert!(provenance.has_incomplete_origins());
    }

    #[test]
    fn the_provenance_of_a_term_names_the_dictionary_and_the_version() {
        let terms = [term("incendio", "violenza", 3, "Cyber core v4")];
        let configuration = configuration(&terms);
        let matches = [riscontro(1, "incendio", "violenza", 0)];

        let provenance = explain_scoring(&matches, Some(&configuration), level(3));

        assert_eq!(provenance.contributions[0].dictionaries, ["Cyber core v4"]);
        assert!(!provenance.has_incomplete_origins());
        assert!(
            provenance.contributions[0]
                .as_sentence()
                .contains("Cyber core v4")
        );
    }

    /// **Il dizionario si nomina come tale, e il termine che attenua lo dice**
    /// (OBS-AN-1).
    #[test]
    fn la_frase_del_termine_nomina_il_dizionario_e_l_attenuazione() {
        let mut contributo = TermContribution {
            text: String::from("esercitazione"),
            normalised: String::from("esercitazione"),
            category: String::from("contesto"),
            occurrences: 1,
            first_position: MatchRange::try_new(0, 13)
                .unwrap_or_else(|_| panic!("intervallo valido")),
            suggested_level: Some(-2),
            dictionaries: vec![String::from("Contesto v2")],
        };
        let frase = contributo.as_sentence();
        assert!(
            frase.contains("dal dizionario \u{ab}Contesto v2\u{bb}"),
            "{frase}"
        );
        assert!(frase.ends_with("; abbassa il livello"), "{frase}");

        contributo.suggested_level = Some(2);
        contributo.dictionaries.push(String::from("Base v1"));
        let frase = contributo.as_sentence();
        assert!(
            frase.contains("dai dizionari \u{ab}Contesto v2\u{bb}, \u{ab}Base v1\u{bb}"),
            "{frase}"
        );
        assert!(!frase.contains("abbassa"), "{frase}");
    }

    #[test]
    fn a_term_without_a_known_origin_says_so_instead_of_staying_silent() {
        let matches = [riscontro(1, "incendio", "violenza", 0)];

        let provenance = explain_scoring(&matches, None, level(3));

        assert!(
            provenance.contributions[0]
                .as_sentence()
                .contains("provenienza non registrata")
        );
    }

    #[test]
    fn the_sentence_of_a_verified_explanation_says_it_reproduces_the_stored_level() {
        let terms = [term("incendio", "violenza", 3, "Prova v1")];
        let configuration = configuration(&terms);
        let matches = [riscontro(1, "incendio", "violenza", 0)];

        let frase = explain_scoring(&matches, Some(&configuration), level(3))
            .explanation
            .as_sentence();

        assert!(frase.contains("riproduce il livello registrato"));
    }

    #[test]
    fn the_order_of_the_contributions_does_not_depend_on_the_order_of_the_rows() {
        let terms = [
            term("incendio", "violenza", 3, "Prova v1"),
            term("corteo", "ordine", 1, "Prova v1"),
        ];
        let configuration = configuration(&terms);

        let uno = [
            riscontro(1, "incendio", "violenza", 0),
            riscontro(2, "corteo", "ordine", 20),
        ];
        let altro = [
            riscontro(2, "corteo", "ordine", 20),
            riscontro(1, "incendio", "violenza", 0),
        ];

        let prima = explain_scoring(&uno, Some(&configuration), level(3));
        let dopo = explain_scoring(&altro, Some(&configuration), level(3));

        assert_eq!(prima.contributions, dopo.contributions);
        // Il piu' significativo per primo.
        assert_eq!(prima.contributions[0].text, "incendio");
    }
}

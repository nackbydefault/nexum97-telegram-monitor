//! Risoluzione di una configurazione in termini concreti, e sua impronta.
//!
//! La procedura è quella di `docs/adr/ADR-0013-RESOLUTION-AND-SNAPSHOT.md`.
//! Tre punti meritano di essere ripetuti qui, perché toccano direttamente
//! questo codice:
//!
//! - **la normalizzazione precede la deduplicazione.** Due termini identici a
//!   vedersi possono essere sequenze di byte diverse: `à` esiste come carattere
//!   precomposto e come `a` seguita da un accento combinante. Deduplicare prima
//!   di normalizzare li lascerebbe entrambi, e l'operatore vedrebbe due volte
//!   la stessa parola senza capire perché;
//! - **tutte le provenienze sono conservate.** Alla domanda «perché questo
//!   contenuto è stato segnalato» la risposta «per il termine incendio» è meno
//!   utile di «per il termine incendio, presente nei dizionari Globale, Italia
//!   e Tematico incendi». La provenienza è ciò che rende il motore trasparente;
//! - **la serializzazione è canonica.** Se dipendesse dall'ordine di
//!   inserimento, la stessa configurazione produrrebbe impronte diverse e
//!   l'impronta non servirebbe a nulla.

use alloc::collections::BTreeMap;
use core::fmt;

use unicode_normalization::UnicodeNormalization;

use crate::digest::Sha256Digest;
use crate::error::{DomainError, DomainResult};
use crate::id::{DictionaryId, DictionaryVersionId};
use crate::model::dictionary::{MAX_RESOLVED_TERMS, MatchMode};
use crate::text::{DictionaryName, LanguageTag, TermCategory, TermText};

extern crate alloc;

/// Da dove proviene un termine.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TermProvenance {
    /// Dizionario di provenienza, assente per i termini aggiunti alla sessione.
    pub dictionary_id: Option<DictionaryId>,
    /// Versione di provenienza, assente per i termini aggiunti alla sessione.
    pub version_id: Option<DictionaryVersionId>,
    /// Nome mostrabile della provenienza.
    pub label: String,
}

impl TermProvenance {
    /// Provenienza da un dizionario.
    #[must_use]
    pub fn from_dictionary(
        dictionary_id: DictionaryId,
        version_id: DictionaryVersionId,
        name: &DictionaryName,
        version_number: u32,
    ) -> Self {
        Self {
            dictionary_id: Some(dictionary_id),
            version_id: Some(version_id),
            label: format!("{} v{version_number}", name.as_str()),
        }
    }

    /// Provenienza da una parola aggiunta per la singola sessione.
    #[must_use]
    pub fn ad_hoc() -> Self {
        Self {
            dictionary_id: None,
            version_id: None,
            label: String::from("aggiunta alla sessione"),
        }
    }

    /// Chiave canonica, usata nella serializzazione.
    fn canonical_key(&self) -> String {
        match (self.dictionary_id, self.version_id) {
            (Some(dictionary), Some(version)) => {
                format!("d{}v{}", dictionary.get(), version.get())
            }
            _ => String::from("adhoc"),
        }
    }
}

/// Termine risolto, pronto per il motore di analisi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTerm {
    /// Testo normalizzato, usato per il confronto.
    pub normalised: String,
    /// Testo originale, mostrato all'operatore.
    pub original: TermText,
    /// Categoria.
    pub category: TermCategory,
    /// Lingua.
    pub language: LanguageTag,
    /// Modalità di riscontro.
    pub match_mode: MatchMode,
    /// Livello suggerito più alto fra le provenienze.
    pub suggested_level: i8,
    /// Tutte le provenienze, ordinate.
    pub provenances: Vec<TermProvenance>,
}

impl ResolvedTerm {
    /// Se il termine proviene da più di una fonte.
    #[must_use]
    pub fn is_shared(&self) -> bool {
        self.provenances.len() > 1
    }
}

/// Impronta di una configurazione risolta.
///
/// **Non è una firma.** Riconosce che due configurazioni sono la stessa; non
/// prova chi l'abbia composta né che il database non sia stato alterato da chi
/// vi abbia accesso diretto. Chiamarla «prova di integrità» sarebbe fuorviante.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DictionaryConfigurationDigest(Sha256Digest);

impl DictionaryConfigurationDigest {
    /// Forma esadecimale completa.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Forma abbreviata, per l'interfaccia.
    ///
    /// Dodici caratteri bastano a distinguere due configurazioni a colpo
    /// d'occhio; il confronto rigoroso usa la forma completa.
    #[must_use]
    pub fn short(&self) -> String {
        self.0.as_str().chars().take(12).collect()
    }
}

impl fmt::Display for DictionaryConfigurationDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0.as_str())
    }
}

/// Configurazione risolta e immutabile di una sessione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDictionaryConfiguration {
    /// Termini, in ordine canonico.
    pub terms: Vec<ResolvedTerm>,
    /// Numero di termini distinti.
    pub unique_count: usize,
    /// Quanti termini provengono da più di una fonte.
    pub shared_count: usize,
    /// Impronta della configurazione.
    pub digest: DictionaryConfigurationDigest,
}

impl ResolvedDictionaryConfiguration {
    /// Se la configurazione non contiene alcun termine.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }

    /// Ricostruisce una configurazione a partire da termini già risolti.
    ///
    /// Serve alla rilettura di uno snapshot conservato. L'impronta viene
    /// **ricalcolata** dai termini, non riletta accanto a essi: solo così
    /// confrontarla con quella scritta al momento della risoluzione dice
    /// qualcosa. Se la si rileggesse e basta, il confronto sarebbe fra un
    /// valore e sé stesso.
    ///
    /// L'ordine dei termini in ingresso non conta: viene riportato a quello
    /// canonico prima di ogni calcolo.
    #[must_use]
    pub fn from_terms(mut terms: Vec<ResolvedTerm>) -> Self {
        // Lo stesso ordine che `BTreeMap` impone in `ConfigurationResolver`:
        // testo normalizzato, poi modalità di riscontro.
        terms.sort_by(|left, right| {
            left.normalised
                .cmp(&right.normalised)
                .then_with(|| left.match_mode.as_str().cmp(right.match_mode.as_str()))
        });

        for term in &mut terms {
            term.provenances.sort_by_key(TermProvenance::canonical_key);
        }

        let unique_count = terms.len();
        let shared_count = terms.iter().filter(|term| term.is_shared()).count();
        let digest = DictionaryConfigurationDigest(Sha256Digest::of_text(&canonical_form(&terms)));

        Self {
            terms,
            unique_count,
            shared_count,
            digest,
        }
    }
}

/// Normalizza un testo per il confronto.
///
/// Applica la forma Unicode NFC e abbassa il caso con le regole predefinite di
/// Unicode. **Non** usa trasformazioni dipendenti dalla lingua di sistema: il
/// prodotto lavora su testo multilingue, e la stessa parola non deve
/// comportarsi in modo diverso a seconda di un'impostazione della macchina.
#[must_use]
pub fn normalise_for_matching(text: &str) -> String {
    text.nfc().collect::<String>().to_lowercase()
}

/// Costruisce una configurazione risolta.
///
/// I termini vanno aggiunti con [`ConfigurationResolver::add`]; la
/// deduplicazione, l'ordinamento canonico e il calcolo dell'impronta avvengono
/// in [`ConfigurationResolver::finish`].
#[derive(Debug, Default)]
pub struct ConfigurationResolver {
    /// Chiave canonica -> termine risolto.
    collected: BTreeMap<(String, &'static str), ResolvedTerm>,
}

impl ConfigurationResolver {
    /// Crea un risolutore vuoto.
    #[must_use]
    pub fn new() -> Self {
        Self {
            collected: BTreeMap::new(),
        }
    }

    /// Aggiunge un termine, fondendolo con quello già presente se coincide.
    ///
    /// Due termini coincidono quando hanno lo **stesso testo normalizzato** e
    /// la **stessa modalità di riscontro**: la stessa parola cercata come
    /// parola esatta e come frase sono due cose diverse.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::TooLong`] se i termini distinti superano
    /// [`MAX_RESOLVED_TERMS`].
    pub fn add(
        &mut self,
        original: TermText,
        category: TermCategory,
        language: LanguageTag,
        match_mode: MatchMode,
        suggested_level: i8,
        provenance: TermProvenance,
    ) -> DomainResult<()> {
        // Un'espressione non si normalizza: abbassarla cambierebbe `\D` in
        // `\d` (ADR-0187, decisione 4).
        let normalised = if match_mode == MatchMode::Expression {
            original.as_str().trim().to_owned()
        } else {
            normalise_for_matching(original.as_str())
        };
        let key = (normalised.clone(), match_mode.as_str());

        if let Some(existing) = self.collected.get_mut(&key) {
            // Il livello più alto prevale: se un dizionario giudica un termine
            // più significativo di un altro, il giudizio più alto è quello che
            // l'operatore deve vedere.
            existing.suggested_level = existing.suggested_level.max(suggested_level);
            if !existing.provenances.contains(&provenance) {
                existing.provenances.push(provenance);
            }
            return Ok(());
        }

        if self.collected.len() >= MAX_RESOLVED_TERMS {
            return Err(DomainError::TooLong {
                field: "termini_risolti",
                max: MAX_RESOLVED_TERMS,
                actual: self.collected.len() + 1,
            });
        }

        self.collected.insert(
            key,
            ResolvedTerm {
                normalised,
                original,
                category,
                language,
                match_mode,
                suggested_level,
                provenances: vec![provenance],
            },
        );
        Ok(())
    }

    /// Numero di termini distinti raccolti finora.
    #[must_use]
    pub fn len(&self) -> usize {
        self.collected.len()
    }

    /// Se non è stato raccolto alcun termine.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.collected.is_empty()
    }

    /// Conclude la risoluzione, ordinando e calcolando l'impronta.
    ///
    /// L'ordinamento e il calcolo passano da
    /// [`ResolvedDictionaryConfiguration::from_terms`], lo stesso che usa la
    /// rilettura di uno snapshot: se i due percorsi calcolassero l'impronta
    /// ciascuno per conto proprio, potrebbero divergere senza che nulla lo
    /// segnali.
    #[must_use]
    pub fn finish(self) -> ResolvedDictionaryConfiguration {
        // `BTreeMap` garantisce già l'ordine per chiave: l'ordine di
        // inserimento non influisce sul risultato, ed è ciò che rende
        // l'impronta stabile.
        ResolvedDictionaryConfiguration::from_terms(self.collected.into_values().collect())
    }
}

/// Forma canonica di un insieme di termini risolti.
///
/// Separatori espliciti, nessuno spazio superfluo, un termine per riga, tutto
/// in un ordine che non dipende da come i termini sono arrivati.
///
/// # Che cosa vi entra, e perché tutto
///
/// Vi entra **ogni campo che sopravvive alla persistenza**, compresi il testo
/// originale e le etichette di provenienza. Non è pignoleria: sono esattamente
/// i campi che l'operatore legge. Il testo originale è quello mostrato accanto
/// al riscontro, e l'etichetta di provenienza è la risposta alla domanda
/// «perché questo contenuto è stato segnalato». Lasciarli fuori significherebbe
/// che chi li altera nella copia conservata passa indenne il confronto, mentre
/// il prodotto dichiara di accorgersi che la copia è stata alterata.
fn canonical_form(terms: &[ResolvedTerm]) -> String {
    let mut text = String::new();

    for term in terms {
        text.push_str(term.match_mode.as_str());
        text.push('\u{1f}');
        text.push_str(&term.normalised);
        text.push('\u{1f}');
        text.push_str(term.original.as_str());
        text.push('\u{1f}');
        text.push_str(term.category.as_str());
        text.push('\u{1f}');
        text.push_str(term.language.as_str());
        text.push('\u{1f}');
        text.push_str(&term.suggested_level.to_string());
        text.push('\u{1f}');

        for (index, provenance) in term.provenances.iter().enumerate() {
            if index > 0 {
                text.push(',');
            }
            text.push_str(&provenance.canonical_key());
            text.push('=');
            text.push_str(&provenance.label);
        }
        text.push('\u{1e}');
    }

    text
}

#[cfg(test)]
mod tests {
    use super::{ConfigurationResolver, TermProvenance, normalise_for_matching};
    use crate::error::DomainError;
    use crate::id::{DictionaryId, DictionaryVersionId};
    use crate::model::dictionary::{MAX_RESOLVED_TERMS, MatchMode};
    use crate::text::{DictionaryName, LanguageTag, TermCategory, TermText};

    fn term(text: &str) -> TermText {
        let Ok(value) = TermText::try_new(text) else {
            panic!("il termine di prova '{text}' deve essere valido");
        };
        value
    }

    fn category() -> TermCategory {
        let Ok(value) = TermCategory::try_new("incendio") else {
            panic!("la categoria di prova deve essere valida");
        };
        value
    }

    fn language() -> LanguageTag {
        let Ok(value) = LanguageTag::try_new("it") else {
            panic!("la lingua di prova deve essere valida");
        };
        value
    }

    fn provenance(number: i64) -> TermProvenance {
        let Ok(name) = DictionaryName::try_new(&format!("Dizionario {number}")) else {
            panic!("il nome di prova deve essere valido");
        };
        TermProvenance::from_dictionary(
            DictionaryId::new(number),
            DictionaryVersionId::new(number * 10),
            &name,
            1,
        )
    }

    /// Aggiunge un termine con valori di prova.
    fn add(resolver: &mut ConfigurationResolver, text: &str, level: i8, source: i64) {
        let Ok(()) = resolver.add(
            term(text),
            category(),
            language(),
            MatchMode::NormalizedWord,
            level,
            provenance(source),
        ) else {
            panic!("il termine '{text}' doveva essere accettato");
        };
    }

    // ------------------------------------------------------- normalizzazione

    #[test]
    fn the_normalisation_lowers_the_case() {
        assert_eq!(normalise_for_matching("INCENDIO"), "incendio");
        assert_eq!(normalise_for_matching("Incendio"), "incendio");
    }

    #[test]
    fn precomposed_and_decomposed_forms_become_identical() {
        // "città" con la a accentata precomposta e con l'accento combinante.
        let precomposed = "citt\u{e0}";
        let decomposed = "citta\u{300}";
        assert_ne!(precomposed, decomposed, "partono diversi");
        assert_eq!(
            normalise_for_matching(precomposed),
            normalise_for_matching(decomposed),
            "dopo la normalizzazione devono coincidere"
        );
    }

    #[test]
    fn the_case_folding_does_not_depend_on_the_system_language() {
        // La I maiuscola deve diventare sempre la i minuscola latina, anche su
        // una macchina configurata in turco: la libreria standard di Rust usa
        // le regole predefinite di Unicode e non quelle locali.
        assert_eq!(normalise_for_matching("ISTANBUL"), "istanbul");
        assert!(!normalise_for_matching("I").contains('\u{131}'));
    }

    // ---------------------------------------------------------- deduplicazione

    #[test]
    fn identical_terms_from_different_dictionaries_become_one_with_two_sources() {
        let mut resolver = ConfigurationResolver::new();
        add(&mut resolver, "incendio", 2, 1);
        add(&mut resolver, "incendio", 2, 2);

        let resolved = resolver.finish();
        assert_eq!(resolved.unique_count, 1);
        assert_eq!(resolved.shared_count, 1);
        assert_eq!(resolved.terms[0].provenances.len(), 2);
        assert!(resolved.terms[0].is_shared());
    }

    #[test]
    fn the_deduplication_happens_after_the_normalisation() {
        let mut resolver = ConfigurationResolver::new();
        add(&mut resolver, "Incendio", 1, 1);
        add(&mut resolver, "INCENDIO", 1, 2);
        add(&mut resolver, "incendio", 1, 3);

        let resolved = resolver.finish();
        assert_eq!(resolved.unique_count, 1, "sono la stessa parola");
        assert_eq!(resolved.terms[0].provenances.len(), 3);
    }

    #[test]
    fn the_same_word_with_two_match_modes_stays_two_terms() {
        let mut resolver = ConfigurationResolver::new();
        let Ok(()) = resolver.add(
            term("appiccare il fuoco"),
            category(),
            language(),
            MatchMode::Phrase,
            3,
            provenance(1),
        ) else {
            panic!("il termine doveva essere accettato");
        };
        let Ok(()) = resolver.add(
            term("appiccare il fuoco"),
            category(),
            language(),
            MatchMode::NormalizedWord,
            3,
            provenance(1),
        ) else {
            panic!("il termine doveva essere accettato");
        };

        assert_eq!(resolver.finish().unique_count, 2);
    }

    #[test]
    fn the_highest_suggested_level_prevails() {
        let mut resolver = ConfigurationResolver::new();
        add(&mut resolver, "incendio", 1, 1);
        add(&mut resolver, "incendio", 3, 2);
        add(&mut resolver, "incendio", 2, 3);

        assert_eq!(resolver.finish().terms[0].suggested_level, 3);
    }

    #[test]
    fn the_same_source_twice_is_recorded_once() {
        let mut resolver = ConfigurationResolver::new();
        add(&mut resolver, "incendio", 1, 1);
        add(&mut resolver, "incendio", 1, 1);

        let resolved = resolver.finish();
        assert_eq!(resolved.terms[0].provenances.len(), 1);
        assert!(!resolved.terms[0].is_shared());
    }

    // ----------------------------------------------------------- impronta

    #[test]
    fn the_same_configuration_built_in_different_orders_yields_the_same_digest() {
        // E' la proprieta' che rende l'impronta utile: senza di essa non
        // servirebbe a nulla.
        let mut first = ConfigurationResolver::new();
        add(&mut first, "incendio", 2, 1);
        add(&mut first, "appiccare", 3, 1);
        add(&mut first, "molotov", 4, 2);

        let mut second = ConfigurationResolver::new();
        add(&mut second, "molotov", 4, 2);
        add(&mut second, "incendio", 2, 1);
        add(&mut second, "appiccare", 3, 1);

        assert_eq!(first.finish().digest, second.finish().digest);
    }

    #[test]
    fn the_provenance_order_does_not_change_the_digest() {
        let mut first = ConfigurationResolver::new();
        add(&mut first, "incendio", 2, 1);
        add(&mut first, "incendio", 2, 2);

        let mut second = ConfigurationResolver::new();
        add(&mut second, "incendio", 2, 2);
        add(&mut second, "incendio", 2, 1);

        assert_eq!(first.finish().digest, second.finish().digest);
    }

    #[test]
    fn a_different_configuration_yields_a_different_digest() {
        let mut first = ConfigurationResolver::new();
        add(&mut first, "incendio", 2, 1);

        let mut second = ConfigurationResolver::new();
        add(&mut second, "incendio", 3, 1);

        assert_ne!(
            first.finish().digest,
            second.finish().digest,
            "un livello diverso e' una configurazione diversa"
        );
    }

    #[test]
    fn adding_a_source_changes_the_digest() {
        let mut first = ConfigurationResolver::new();
        add(&mut first, "incendio", 2, 1);

        let mut second = ConfigurationResolver::new();
        add(&mut second, "incendio", 2, 1);
        add(&mut second, "incendio", 2, 2);

        assert_ne!(first.finish().digest, second.finish().digest);
    }

    #[test]
    fn an_empty_configuration_has_a_stable_digest() {
        let first = ConfigurationResolver::new().finish();
        let second = ConfigurationResolver::new().finish();

        assert!(first.is_empty());
        assert_eq!(first.digest, second.digest);
        assert_eq!(first.unique_count, 0);
    }

    #[test]
    fn the_short_digest_is_a_prefix_of_the_full_one() {
        let mut resolver = ConfigurationResolver::new();
        add(&mut resolver, "incendio", 2, 1);
        let digest = resolver.finish().digest;

        assert_eq!(digest.short().len(), 12);
        assert!(digest.as_str().starts_with(&digest.short()));
        assert_eq!(digest.as_str().len(), 64);
    }

    // ------------------------------------------------------------ provenienze

    #[test]
    fn an_ad_hoc_term_declares_its_own_provenance() {
        let mut resolver = ConfigurationResolver::new();
        let Ok(()) = resolver.add(
            term("parola della sessione"),
            category(),
            language(),
            MatchMode::NormalizedWord,
            0,
            TermProvenance::ad_hoc(),
        ) else {
            panic!("il termine doveva essere accettato");
        };

        let resolved = resolver.finish();
        assert_eq!(resolved.terms[0].provenances[0].dictionary_id, None);
        assert!(
            resolved.terms[0].provenances[0]
                .label
                .contains("aggiunta alla sessione")
        );
    }

    #[test]
    fn the_original_text_is_preserved_alongside_the_normalised_one() {
        let mut resolver = ConfigurationResolver::new();
        add(&mut resolver, "INCENDIO Doloso", 2, 1);

        let resolved = resolver.finish();
        assert_eq!(resolved.terms[0].original.as_str(), "INCENDIO Doloso");
        assert_eq!(resolved.terms[0].normalised, "incendio doloso");
    }

    // ----------------------------------------------------------------- limiti

    #[test]
    fn the_resolver_counts_what_it_has_collected() {
        let mut resolver = ConfigurationResolver::new();
        assert!(resolver.is_empty());

        add(&mut resolver, "uno", 1, 1);
        add(&mut resolver, "due", 1, 1);
        assert_eq!(resolver.len(), 2);
        assert!(!resolver.is_empty());
    }

    // ------------------------------------------------------- ricostruzione

    #[test]
    fn a_configuration_rebuilt_from_its_own_terms_has_the_same_digest() {
        // E' la proprieta' su cui si regge la rilettura di uno snapshot: se
        // non valesse, l'impronta conservata non sarebbe confrontabile con
        // nulla.
        let mut resolver = ConfigurationResolver::new();
        add(&mut resolver, "incendio", 2, 1);
        add(&mut resolver, "molotov", 4, 2);
        add(&mut resolver, "incendio", 3, 2);

        let original = resolver.finish();
        let rebuilt = super::ResolvedDictionaryConfiguration::from_terms(original.terms.clone());

        assert_eq!(rebuilt.digest, original.digest);
        assert_eq!(rebuilt.terms, original.terms);
        assert_eq!(rebuilt.unique_count, original.unique_count);
        assert_eq!(rebuilt.shared_count, original.shared_count);
    }

    #[test]
    fn the_order_of_the_terms_given_back_does_not_change_the_rebuilt_digest() {
        let mut resolver = ConfigurationResolver::new();
        add(&mut resolver, "alfa", 1, 1);
        add(&mut resolver, "zeta", 2, 1);
        add(&mut resolver, "mike", 3, 2);

        let original = resolver.finish();
        let mut shuffled = original.terms.clone();
        shuffled.reverse();
        for entry in &mut shuffled {
            entry.provenances.reverse();
        }

        assert_eq!(
            super::ResolvedDictionaryConfiguration::from_terms(shuffled).digest,
            original.digest
        );
    }

    #[test]
    fn altering_the_original_text_changes_the_digest() {
        // E' il testo mostrato accanto al riscontro: se non entrasse
        // nell'impronta, chi lo altera passerebbe indenne il confronto.
        let mut resolver = ConfigurationResolver::new();
        add(&mut resolver, "INCENDIO", 2, 1);
        let original = resolver.finish();

        let mut altered = original.terms.clone();
        altered[0].original = term("Incendio");
        assert_eq!(
            altered[0].normalised, original.terms[0].normalised,
            "il testo normalizzato non cambia: cambia solo cio' che si legge"
        );

        assert_ne!(
            super::ResolvedDictionaryConfiguration::from_terms(altered).digest,
            original.digest
        );
    }

    #[test]
    fn altering_a_provenance_label_changes_the_digest() {
        // L'etichetta e' la risposta alla domanda "perche' questo contenuto e'
        // stato segnalato": alterarla cambia la spiegazione data all'operatore.
        let mut resolver = ConfigurationResolver::new();
        add(&mut resolver, "incendio", 2, 1);
        let original = resolver.finish();

        let mut altered = original.terms.clone();
        altered[0].provenances[0].label = String::from("Un dizionario che non esiste v9");

        assert_ne!(
            super::ResolvedDictionaryConfiguration::from_terms(altered).digest,
            original.digest
        );
    }

    #[test]
    fn a_term_altered_after_the_fact_changes_the_rebuilt_digest() {
        // E' cio' che permette di accorgersi che la copia conservata non e'
        // piu' quella su cui l'impronta fu calcolata.
        let mut resolver = ConfigurationResolver::new();
        add(&mut resolver, "incendio", 2, 1);

        let original = resolver.finish();
        let mut altered = original.terms.clone();
        altered[0].suggested_level = 4;

        assert_ne!(
            super::ResolvedDictionaryConfiguration::from_terms(altered).digest,
            original.digest
        );
    }

    #[test]
    fn the_resolver_accepts_the_limit_and_refuses_one_term_beyond_it() {
        // Il limite era dichiarato e mai provato: un limite non provato e' un
        // limite che si scopre rotto il giorno in cui serve.
        let mut resolver = ConfigurationResolver::new();
        for index in 0..MAX_RESOLVED_TERMS {
            let Ok(()) = resolver.add(
                term(&format!("termine{index}")),
                category(),
                language(),
                MatchMode::NormalizedWord,
                1,
                provenance(1),
            ) else {
                panic!("il termine numero {index} doveva essere accettato");
            };
        }
        assert_eq!(resolver.len(), MAX_RESOLVED_TERMS);

        assert!(matches!(
            resolver.add(
                term("uno di troppo"),
                category(),
                language(),
                MatchMode::NormalizedWord,
                1,
                provenance(1),
            ),
            Err(DomainError::TooLong {
                field: "termini_risolti",
                ..
            })
        ));

        // Un termine gia' presente si fonde e non conta come nuovo, anche a
        // limite raggiunto: altrimenti una provenienza in piu' su un termine
        // esistente verrebbe respinta senza ragione.
        assert!(
            resolver
                .add(
                    term("termine0"),
                    category(),
                    language(),
                    MatchMode::NormalizedWord,
                    2,
                    provenance(2),
                )
                .is_ok()
        );
    }

    #[test]
    fn terms_are_returned_in_canonical_order() {
        let mut resolver = ConfigurationResolver::new();
        add(&mut resolver, "zeta", 1, 1);
        add(&mut resolver, "alfa", 1, 1);
        add(&mut resolver, "mike", 1, 1);

        let resolved = resolver.finish();
        let order: Vec<&str> = resolved
            .terms
            .iter()
            .map(|entry| entry.normalised.as_str())
            .collect();
        assert_eq!(order, ["alfa", "mike", "zeta"]);
    }
}

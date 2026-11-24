//! Entità della libreria dei dizionari.
//!
//! Come nel resto del dominio, ogni entità esiste in due forme: `New*` per ciò
//! che si vuole registrare, e la forma completa per ciò che è stato
//! registrato, con identificatore e istanti assegnati dalla persistenza.

use crate::error::{DomainError, DomainResult};
use crate::id::{DictionaryId, DictionaryProfileId, DictionaryTermId, DictionaryVersionId};
use crate::model::dictionary::{
    DictionaryOrigin, DictionaryScope, DictionaryStatus, DictionaryVisibility, MatchMode,
};
use crate::text::{
    Actor, DictionaryDescription, DictionaryName, LanguageTag, ProfileName, TermCategory, TermNote,
    TermText,
};
use crate::time::Timestamp;

/// Livello suggerito da chi ha compilato il dizionario.
///
/// **Non è l'esito dell'analisi.** È l'indicazione di chi ha scritto il
/// termine su quanto lo ritenga significativo; l'esito lo determinerà il
/// motore con le proprie regole, e la valutazione finale resta all'operatore.
///
/// Il valore negativo è ammesso e serve alle **negazioni e al contesto
/// riduttivo**: «non è vero che», «ha smentito», «nel film» abbassano il peso
/// di un riscontro che altrimenti sarebbe fuorviante.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SuggestedLevel(i8);

impl SuggestedLevel {
    /// Valore minimo, per il contesto che riduce il peso.
    pub const MIN: i8 = -4;
    /// Valore massimo.
    pub const MAX: i8 = 4;
    /// Nessuna indicazione.
    pub const NEUTRAL: Self = Self(0);

    /// Il livello più debole che produce comunque un avviso.
    ///
    /// [`Self::NEUTRAL`] non ne produce: un contenuto che resta a livello 0 è
    /// «non rilevante» e non genera né avviso né notifica. Serve quindi un
    /// valore predefinito per chi aggiunge una parola da sorvegliare senza
    /// esprimersi sulla gravità: la parola è stata chiesta, quindi la sua
    /// comparsa va segnalata, ma al minimo grado, perché una gravità
    /// superiore sarebbe un giudizio che l'operatore non ha dato.
    #[must_use]
    pub const fn weakest_that_alerts() -> Self {
        Self(1)
    }

    /// Costruisce il livello verificandone l'intervallo.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::InvalidAnalysisLevel`] fuori
    /// dall'intervallo ammesso.
    pub const fn try_new(value: i8) -> DomainResult<Self> {
        if value < Self::MIN || value > Self::MAX {
            // Il livello suggerito condivide l'errore con quello di analisi:
            // sono due grandezze diverse ma il difetto è lo stesso, un valore
            // fuori intervallo. Il valore assoluto entra nel messaggio.
            return Err(DomainError::InvalidAnalysisLevel(value.unsigned_abs()));
        }
        Ok(Self(value))
    }

    /// Valore numerico.
    #[must_use]
    pub const fn get(self) -> i8 {
        self.0
    }

    /// Se il termine riduce il peso di un riscontro invece di aumentarlo.
    #[must_use]
    pub const fn is_mitigating(self) -> bool {
        self.0 < 0
    }
}

/// Dizionario che si intende registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDictionary {
    /// Nome mostrato all'operatore.
    pub name: DictionaryName,
    /// Descrizione di che cosa copre.
    pub description: DictionaryDescription,
    /// Ambito.
    pub scope: DictionaryScope,
    /// Chi lo ha prodotto.
    pub origin: DictionaryOrigin,
    /// Chi lo vede.
    pub visibility: DictionaryVisibility,
    /// Soggetto che lo crea.
    pub created_by: Actor,
    /// Dizionario da cui deriva, quando è una duplicazione.
    pub derived_from: Option<DictionaryId>,
}

/// Dizionario registrato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dictionary {
    /// Identificatore assegnato dalla persistenza.
    pub id: DictionaryId,
    /// Nome mostrato all'operatore.
    pub name: DictionaryName,
    /// Descrizione.
    pub description: DictionaryDescription,
    /// Ambito.
    pub scope: DictionaryScope,
    /// Chi lo ha prodotto.
    pub origin: DictionaryOrigin,
    /// Chi lo vede.
    pub visibility: DictionaryVisibility,
    /// Stato corrente.
    pub status: DictionaryStatus,
    /// Soggetto che lo ha creato.
    pub created_by: Actor,
    /// Dizionario da cui deriva.
    pub derived_from: Option<DictionaryId>,
    /// Istante di creazione.
    pub created_at: Timestamp,
    /// Istante dell'ultima modifica.
    pub updated_at: Timestamp,
}

impl Dictionary {
    /// Se l'operatore può modificarne il contenuto.
    #[must_use]
    pub const fn is_editable(&self) -> bool {
        self.visibility.is_editable()
    }

    /// Se può essere selezionato per una nuova sessione.
    #[must_use]
    pub const fn is_selectable(&self) -> bool {
        self.status.is_selectable()
    }
}

/// Versione di dizionario che si intende registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDictionaryVersion {
    /// Dizionario a cui appartiene.
    pub dictionary_id: DictionaryId,
    /// Numero progressivo, da 1.
    pub number: u32,
    /// Nota di rilascio.
    pub note: DictionaryDescription,
    /// Soggetto che la crea.
    pub created_by: Actor,
}

/// Versione registrata.
///
/// Una versione **pubblicata** non si modifica più. È ciò che rende ripetibile
/// una sessione conclusa: la sessione riferisce la versione, non il dizionario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DictionaryVersion {
    /// Identificatore assegnato dalla persistenza.
    pub id: DictionaryVersionId,
    /// Dizionario a cui appartiene.
    pub dictionary_id: DictionaryId,
    /// Numero progressivo.
    pub number: u32,
    /// Nota di rilascio.
    pub note: DictionaryDescription,
    /// Soggetto che l'ha creata.
    pub created_by: Actor,
    /// Istante di creazione.
    pub created_at: Timestamp,
    /// Istante di pubblicazione, assente finché è in bozza.
    pub published_at: Option<Timestamp>,
}

impl DictionaryVersion {
    /// Se la versione è pubblicata, e quindi immutabile.
    #[must_use]
    pub const fn is_published(&self) -> bool {
        self.published_at.is_some()
    }

    /// Se il contenuto della versione può ancora essere modificato.
    #[must_use]
    pub const fn is_mutable(&self) -> bool {
        self.published_at.is_none()
    }
}

/// Termine che si intende registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDictionaryTerm {
    /// Versione a cui appartiene.
    pub version_id: DictionaryVersionId,
    /// Testo del termine.
    pub text: TermText,
    /// Categoria.
    pub category: TermCategory,
    /// Lingua.
    pub language: LanguageTag,
    /// Modalità di riscontro.
    pub match_mode: MatchMode,
    /// Livello suggerito.
    pub suggested_level: SuggestedLevel,
    /// Nota che spiega perché il termine è presente.
    pub note: TermNote,
}

/// Termine non ancora legato ad alcuna versione.
///
/// Serve a chi scrive un dizionario **intero** in un colpo solo — un import, un
/// dizionario fornito con il prodotto — perché in quel momento la versione a
/// cui il termine apparterrà non esiste ancora. Un [`NewDictionaryTerm`] con un
/// identificatore inventato o ignorato sarebbe un valore che mente sul proprio
/// contenuto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnboundTerm {
    /// Testo del termine.
    pub text: TermText,
    /// Categoria.
    pub category: TermCategory,
    /// Lingua.
    pub language: LanguageTag,
    /// Modalità di riscontro.
    pub match_mode: MatchMode,
    /// Livello suggerito.
    pub suggested_level: SuggestedLevel,
    /// Nota che spiega perché il termine è presente.
    pub note: TermNote,
}

impl UnboundTerm {
    /// Lo lega alla versione indicata, una volta che questa esiste.
    #[must_use]
    pub fn bind(self, version_id: DictionaryVersionId) -> NewDictionaryTerm {
        NewDictionaryTerm {
            version_id,
            text: self.text,
            category: self.category,
            language: self.language,
            match_mode: self.match_mode,
            suggested_level: self.suggested_level,
            note: self.note,
        }
    }
}

/// Termine registrato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DictionaryTerm {
    /// Identificatore assegnato dalla persistenza.
    pub id: DictionaryTermId,
    /// Versione a cui appartiene.
    pub version_id: DictionaryVersionId,
    /// Testo del termine.
    pub text: TermText,
    /// Categoria.
    pub category: TermCategory,
    /// Lingua.
    pub language: LanguageTag,
    /// Modalità di riscontro.
    pub match_mode: MatchMode,
    /// Livello suggerito.
    pub suggested_level: SuggestedLevel,
    /// Nota.
    pub note: TermNote,
}

/// Parola aggiunta per una singola sessione.
///
/// Porta con sé la propria modalità di riscontro: la stessa parola cercata come
/// parola esatta e come frase sono due cose diverse, e l'operatore che la
/// aggiunge deve poter dire quale delle due intende.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCustomTerm {
    /// Testo della parola.
    pub text: TermText,
    /// Modalità di riscontro.
    pub match_mode: MatchMode,
    /// Quanto è grave la comparsa di questa parola, da 1 a 4.
    ///
    /// Fino al 2026-07-31 una parola aggiunta entrava nella risoluzione con
    /// livello 0, cioè «nessun avviso»: il solo livello che non produce un
    /// avviso, e quindi non produce mai una notifica. Il wizard offriva però
    /// «un dizionario **oppure** una parola», e chi seguiva la seconda strada
    /// otteneva un monitoraggio incapace di segnalare, senza che nulla lo
    /// dicesse. Chi aggiunge una parola dice ora anche quanto sia grave, come
    /// per un termine di dizionario.
    pub suggested_level: SuggestedLevel,
}

impl SessionCustomTerm {
    /// Parola confrontata dopo normalizzazione, il caso più comune.
    ///
    /// Il livello predefinito è il più debole fra quelli che producono un
    /// avviso: chi non si esprime ottiene comunque una sorveglianza che
    /// funziona, senza vedersi attribuire una gravità che non ha dichiarato.
    #[must_use]
    pub fn normalised(text: TermText) -> Self {
        Self {
            text,
            match_mode: MatchMode::NormalizedWord,
            suggested_level: SuggestedLevel::weakest_that_alerts(),
        }
    }
}

/// Selezione di dizionari per una sessione.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DictionarySelection {
    /// Dizionari scelti.
    pub dictionary_ids: Vec<DictionaryId>,
    /// Termini aggiunti per questa sola sessione.
    pub ad_hoc_terms: Vec<SessionCustomTerm>,
}

impl DictionarySelection {
    /// Selezione vuota.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            dictionary_ids: Vec::new(),
            ad_hoc_terms: Vec::new(),
        }
    }

    /// Se non è stato scelto nulla.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.dictionary_ids.is_empty() && self.ad_hoc_terms.is_empty()
    }

    /// Numero di dizionari scelti.
    #[must_use]
    pub fn dictionary_count(&self) -> usize {
        self.dictionary_ids.len()
    }
}

/// Profilo di selezione che si intende registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDictionaryProfile {
    /// Nome del profilo.
    pub name: ProfileName,
    /// Descrizione.
    pub description: DictionaryDescription,
    /// Dizionari inclusi.
    pub dictionary_ids: Vec<DictionaryId>,
    /// Soggetto che lo crea.
    pub created_by: Actor,
    /// Se è visibile a tutti gli operatori della postazione.
    pub shared: bool,
}

/// Profilo di selezione riutilizzabile.
///
/// Riferisce **dizionari**, non versioni: alla risoluzione si sceglie la
/// versione pubblicata più recente. Un profilo che congelasse le versioni
/// diventerebbe obsoleto in silenzio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DictionaryProfile {
    /// Identificatore assegnato dalla persistenza.
    pub id: DictionaryProfileId,
    /// Nome del profilo.
    pub name: ProfileName,
    /// Descrizione.
    pub description: DictionaryDescription,
    /// Dizionari inclusi.
    pub dictionary_ids: Vec<DictionaryId>,
    /// Soggetto che lo ha creato.
    pub created_by: Actor,
    /// Se è visibile a tutti gli operatori della postazione.
    pub shared: bool,
    /// Istante di creazione.
    pub created_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::{DictionarySelection, SuggestedLevel};
    use crate::error::DomainError;
    use crate::id::DictionaryId;

    #[test]
    fn every_level_in_the_admitted_range_is_accepted() {
        for value in SuggestedLevel::MIN..=SuggestedLevel::MAX {
            let Ok(level) = SuggestedLevel::try_new(value) else {
                panic!("il livello {value} doveva essere accettato");
            };
            assert_eq!(level.get(), value);
        }
    }

    #[test]
    fn a_level_outside_the_range_is_refused() {
        assert!(matches!(
            SuggestedLevel::try_new(5),
            Err(DomainError::InvalidAnalysisLevel(_))
        ));
        assert!(matches!(
            SuggestedLevel::try_new(-5),
            Err(DomainError::InvalidAnalysisLevel(_))
        ));
        assert!(SuggestedLevel::try_new(i8::MIN).is_err());
        assert!(SuggestedLevel::try_new(i8::MAX).is_err());
    }

    #[test]
    fn a_negative_level_mitigates_instead_of_aggravating() {
        // Serve alle negazioni e al contesto riduttivo: "non e' vero che",
        // "ha smentito", "nel film".
        let Ok(mitigating) = SuggestedLevel::try_new(-2) else {
            panic!("il livello mitigante doveva essere accettato");
        };
        assert!(mitigating.is_mitigating());
        assert!(!SuggestedLevel::NEUTRAL.is_mitigating());

        let Ok(aggravating) = SuggestedLevel::try_new(3) else {
            panic!("il livello doveva essere accettato");
        };
        assert!(!aggravating.is_mitigating());
    }

    #[test]
    fn levels_are_ordered_by_weight() {
        let (Ok(low), Ok(high)) = (SuggestedLevel::try_new(-4), SuggestedLevel::try_new(4)) else {
            panic!("i livelli estremi devono essere accettati");
        };
        assert!(low < SuggestedLevel::NEUTRAL);
        assert!(SuggestedLevel::NEUTRAL < high);
    }

    #[test]
    fn an_empty_selection_is_recognised_as_such() {
        let mut selection = DictionarySelection::new();
        assert!(selection.is_empty());
        assert_eq!(selection.dictionary_count(), 0);

        selection.dictionary_ids.push(DictionaryId::new(1));
        assert!(!selection.is_empty());
        assert_eq!(selection.dictionary_count(), 1);
    }

    #[test]
    fn a_selection_of_only_ad_hoc_terms_is_not_empty() {
        // Una sessione con sole parole aggiuntive e' legittima.
        let Ok(term) = crate::text::TermText::try_new("parola") else {
            panic!("il termine di prova deve essere valido");
        };
        let selection = DictionarySelection {
            dictionary_ids: Vec::new(),
            ad_hoc_terms: vec![super::SessionCustomTerm::normalised(term)],
        };
        assert!(!selection.is_empty());
        assert_eq!(selection.dictionary_count(), 0);
    }

    #[test]
    fn an_added_word_is_normalised_unless_stated_otherwise() {
        let Ok(term) = crate::text::TermText::try_new("Parola") else {
            panic!("il termine di prova deve essere valido");
        };
        let added = super::SessionCustomTerm::normalised(term);
        assert_eq!(
            added.match_mode,
            crate::model::dictionary::MatchMode::NormalizedWord
        );
    }
}

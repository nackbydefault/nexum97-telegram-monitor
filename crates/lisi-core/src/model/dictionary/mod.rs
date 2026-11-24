//! Libreria multi-dizionario.
//!
//! Un dizionario è un contenitore con identità stabile; il suo **contenuto**
//! vive in versioni. Una versione pubblicata non si modifica più: una sessione
//! conclusa mesi fa è stata condotta con certi termini, e se quel dizionario
//! fosse modificabile nessuno potrebbe più dire con che cosa fu condotta.
//!
//! Le scelte sono motivate in `docs/adr/ADR-0012-DICTIONARY-LIBRARY.md`.
//!
//! # Che cosa questo modulo non fa
//!
//! Non analizza nulla. Non attribuisce livelli definitivi, non decide che cosa
//! sia rilevante e non produce alert. Prepara i termini con cui il motore della
//! Milestone 5 lavorerà. Il **livello suggerito** di un termine è un
//! suggerimento del compilatore del dizionario, non l'esito di un'analisi.

pub mod entities;
pub mod resolution;

pub use crate::model::dictionary::entities::{
    Dictionary, DictionaryProfile, DictionarySelection, DictionaryTerm, DictionaryVersion,
    NewDictionary, NewDictionaryProfile, NewDictionaryTerm, NewDictionaryVersion,
    SessionCustomTerm, SuggestedLevel, UnboundTerm,
};
pub use crate::model::dictionary::resolution::{
    ConfigurationResolver, DictionaryConfigurationDigest, ResolvedDictionaryConfiguration,
    ResolvedTerm, TermProvenance, normalise_for_matching,
};

use crate::error::{DomainError, DomainResult};

// ------------------------------------------------------------------- limiti

/// Numero massimo di termini in un singolo dizionario.
pub const MAX_TERMS_PER_DICTIONARY: usize = 10_000;

/// Numero massimo di dizionari selezionabili per una sessione.
pub const MAX_DICTIONARIES_PER_SESSION: usize = 32;

/// Numero massimo di termini risolti per una sessione.
pub const MAX_RESOLVED_TERMS: usize = 50_000;

/// Numero massimo di profili personali.
pub const MAX_PERSONAL_PROFILES: usize = 100;

/// Dimensione massima di un file di import, in byte.
pub const MAX_IMPORT_BYTES: usize = 10 * 1024 * 1024;

// --------------------------------------------------------------- tassonomia

string_enum!(
    /// Che cosa il dizionario copre.
    DictionaryScope {
        /// Valido ovunque.
        Global => "global",
        /// Riferito a un Paese.
        Country => "country",
        /// Riferito a una regione.
        Region => "region",
        /// Riferito a una provincia.
        Province => "province",
        /// Riferito a un comune.
        Municipality => "municipality",
        /// Riferito a un tema, indipendentemente dal territorio.
        Thematic => "thematic",
        /// Composto dall'operatore per un proprio scopo.
        Custom => "custom",
    }
);

string_enum!(
    /// Chi ha prodotto il dizionario.
    DictionaryOrigin {
        /// Fornito con il prodotto.
        System => "system",
        /// Creato da un amministratore.
        Administrator => "administrator",
        /// Creato da un operatore.
        Operator => "operator",
        /// Importato da un file.
        Imported => "imported",
    }
);

string_enum!(
    /// Chi vede il dizionario.
    DictionaryVisibility {
        /// Di sistema: visibile a tutti, non modificabile.
        BuiltIn => "built_in",
        /// Condiviso fra gli operatori della postazione.
        Shared => "shared",
        /// Personale di chi lo ha creato.
        Personal => "personal",
    }
);

string_enum!(
    /// Se e come il dizionario è utilizzabile.
    DictionaryStatus {
        /// In lavorazione, non ancora utilizzabile.
        Draft => "draft",
        /// Utilizzabile.
        Active => "active",
        /// Non più proposto per nuove sessioni.
        Inactive => "inactive",
        /// Sostituito da una versione più recente.
        Superseded => "superseded",
        /// Conservato per lo storico, fuori dall'uso corrente.
        Archived => "archived",
    }
);

string_enum!(
    /// Come un termine viene confrontato con il testo.
    ///
    /// **Le espressioni regolari** ci sono dal 2026-11-06, soltanto con un
    /// motore in tempo lineare e con un tetto (DICT-REGEX-01, ADR-0187): su
    /// testi costruiti apposta un motore a ritorno all'indietro richiede tempo
    /// esponenziale, e qui il testo arriva da fonti ostili.
    MatchMode {
        /// Parola intera, confronto esatto.
        ExactWord => "exact_word",
        /// Sequenza di parole.
        Phrase => "phrase",
        /// Parola intera dopo normalizzazione e abbassamento del caso.
        NormalizedWord => "normalized_word",
        /// Codice di sole cifre: riscontra soltanto come numero isolato, e
        /// conta soltanto insieme a un altro termine (DICT-CODES-01,
        /// ADR-0170).
        NumericCode => "numeric_code",
        /// Espressione regolare, in tempo lineare (DICT-REGEX-01, ADR-0187).
        Expression => "expression",
    }
);

impl DictionaryScope {
    /// Descrizione mostrata all'operatore.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Global => "Globale",
            Self::Country => "Paese",
            Self::Region => "Regione",
            Self::Province => "Provincia",
            Self::Municipality => "Comune",
            Self::Thematic => "Tematico",
            Self::Custom => "Personalizzato",
        }
    }
}

impl DictionaryOrigin {
    /// Descrizione mostrata all'operatore.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::System => "Sistema",
            Self::Administrator => "Amministratore",
            Self::Operator => "Operatore",
            Self::Imported => "Importato",
        }
    }
}

impl DictionaryVisibility {
    /// Descrizione mostrata all'operatore.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::BuiltIn => "Di sistema",
            Self::Shared => "Condiviso",
            Self::Personal => "Personale",
        }
    }

    /// Se il dizionario può essere modificato dall'operatore.
    ///
    /// I dizionari di sistema si **duplicano**, non si modificano: altrimenti
    /// due installazioni con lo stesso numero di versione conterrebbero cose
    /// diverse, e il numero di versione smetterebbe di significare qualcosa.
    #[must_use]
    pub const fn is_editable(self) -> bool {
        !matches!(self, Self::BuiltIn)
    }

    /// Se il dizionario può essere cancellato dall'operatore.
    #[must_use]
    pub const fn is_deletable(self) -> bool {
        !matches!(self, Self::BuiltIn)
    }
}

impl DictionaryStatus {
    /// Descrizione mostrata all'operatore.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Draft => "Bozza",
            Self::Active => "Attivo",
            Self::Inactive => "Disattivato",
            Self::Superseded => "Sostituito",
            Self::Archived => "Archiviato",
        }
    }

    /// Se il dizionario è selezionabile per una nuova sessione.
    #[must_use]
    pub const fn is_selectable(self) -> bool {
        matches!(self, Self::Active)
    }
}

impl MatchMode {
    /// Descrizione mostrata all'operatore.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ExactWord => "Parola esatta",
            Self::Phrase => "Frase",
            Self::NormalizedWord => "Parola come viene cercata",
            Self::NumericCode => "Codice numerico",
            Self::Expression => "Espressione",
        }
    }

    /// Se la modalità richiede la normalizzazione del testo cercato.
    #[must_use]
    pub const fn requires_normalisation(self) -> bool {
        matches!(self, Self::NormalizedWord)
    }
}

/// Le cifre di un codice numerico, al minimo: una cifra sola non è un codice.
pub const NUMERIC_CODE_MIN_DIGITS: usize = 2;

/// Le cifre di un codice numerico, al massimo.
pub const NUMERIC_CODE_MAX_DIGITS: usize = 12;

/// Il livello suggerito di un codice numerico, e nessun altro: un codice vale
/// come corroborazione, non come base (ADR-0170, decisione 1).
pub const NUMERIC_CODE_LEVEL: i8 = 1;

/// Se un testo è fatto di sole cifre ASCII, spazi esterni a parte.
#[must_use]
pub fn is_digits_only(text: &str) -> bool {
    let text = text.trim();
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// Verifica un termine **nuovo** contro la regola del codice numerico
/// (DICT-CODES-01, ADR-0170, decisione 5).
///
/// Un codice numerico ha da [`NUMERIC_CODE_MIN_DIGITS`] a
/// [`NUMERIC_CODE_MAX_DIGITS`] cifre e il livello [`NUMERIC_CODE_LEVEL`]; un
/// termine di sole cifre è un codice, o non entra. Vale per ciò che si scrive
/// adesso: i termini delle versioni già pubblicate non passano di qui, e non
/// cambiano (decisione 6).
///
/// # Errori
///
/// Restituisce [`DomainError::InvalidNumericCode`] con la ragione, scritta per
/// chi compila il dizionario.
pub fn check_new_term(text: &str, mode: MatchMode, suggested_level: i8) -> DomainResult<()> {
    let digits = is_digits_only(text);
    match mode {
        MatchMode::NumericCode => {
            if !digits {
                return Err(DomainError::InvalidNumericCode {
                    reason: "un codice numerico è fatto di sole cifre",
                });
            }
            let quante = text.trim().len();
            if !(NUMERIC_CODE_MIN_DIGITS..=NUMERIC_CODE_MAX_DIGITS).contains(&quante) {
                return Err(DomainError::InvalidNumericCode {
                    reason: "un codice numerico ha da 2 a 12 cifre",
                });
            }
            if suggested_level != NUMERIC_CODE_LEVEL {
                return Err(DomainError::InvalidNumericCode {
                    reason: "un codice numerico ha il livello 1: conta soltanto insieme ad altri \
                             termini",
                });
            }
            Ok(())
        }
        MatchMode::ExactWord | MatchMode::Phrase | MatchMode::NormalizedWord if digits => {
            Err(DomainError::InvalidNumericCode {
                reason: "un termine di sole cifre si scrive come codice numerico",
            })
        }
        MatchMode::ExactWord | MatchMode::Phrase | MatchMode::NormalizedWord => Ok(()),
        MatchMode::Expression => crate::analysis::expression::compile(text)
            .map(|_| ())
            .map_err(|reason| DomainError::InvalidExpression {
                reason: expression_refusal(text, reason),
            }),
    }
}

/// Il motivo del rifiuto di un'espressione, detto a chi scrive il dizionario
/// (COLLAUDO-FIX-01, CU01-003, DEC-510).
///
/// Riferimenti all'indietro, da `\1` a `\9` e `\k<…>`, e sguardi avanti o
/// indietro, cioè una parentesi aperta seguita da `?=`, `?!`, `?<=` o `?<!`,
/// sono la forma che il motore rifiuta per costruzione: lo si dice con il
/// perché. Il commento non scrive quelle parentesi aperte senza chiuderle: la
/// guardia dell'italiano semplice conta le parentesi anche nei commenti, e
/// avrebbe saltato le righe seguenti. Si guarda soltanto dopo il rifiuto, e
/// serve soltanto a scegliere la frase; una barra rovesciata scritta come
/// carattere (`\\1`) non conta, perché le coppie di barre si saltano.
///
/// **Sta qui e non nel motore**: il motore non cambia, e la sua impronta
/// (ADR-0187, `analysis::engine`) resta quella della versione che cerca.
fn expression_refusal(pattern: &str, engine_reason: &'static str) -> &'static str {
    // Soltanto al posto della frase generale del motore: un'espressione troppo
    // lunga o troppo grande ha già il suo motivo, e resta quello.
    if engine_reason == "l'espressione non è scritta in una forma che il programma legge"
        && rimanda_o_guarda(pattern)
    {
        return "i riferimenti all'indietro e il guardare avanti o indietro non sono ammessi: il \
                programma cerca in un tempo che cresce soltanto con il testo";
    }
    engine_reason
}

/// Se un'espressione contiene un riferimento all'indietro o uno sguardo avanti
/// o indietro.
fn rimanda_o_guarda(pattern: &str) -> bool {
    if ["(?=", "(?!", "(?<=", "(?<!"]
        .iter()
        .any(|sguardo| pattern.contains(sguardo))
    {
        return true;
    }
    let mut caratteri = pattern.chars();
    while let Some(carattere) = caratteri.next() {
        if carattere == '\\' && matches!(caratteri.next(), Some('1'..='9' | 'k')) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::{
        DictionaryOrigin, DictionaryScope, DictionaryStatus, DictionaryVisibility, MatchMode,
        check_new_term,
    };
    use crate::error::DomainError;

    #[test]
    fn every_taxonomy_value_survives_a_round_trip_through_its_stored_form() {
        for scope in DictionaryScope::all() {
            assert_eq!(DictionaryScope::from_str(scope.as_str()), Ok(*scope));
        }
        for origin in DictionaryOrigin::all() {
            assert_eq!(DictionaryOrigin::from_str(origin.as_str()), Ok(*origin));
        }
        for visibility in DictionaryVisibility::all() {
            assert_eq!(
                DictionaryVisibility::from_str(visibility.as_str()),
                Ok(*visibility)
            );
        }
        for status in DictionaryStatus::all() {
            assert_eq!(DictionaryStatus::from_str(status.as_str()), Ok(*status));
        }
        for mode in MatchMode::all() {
            assert_eq!(MatchMode::from_str(mode.as_str()), Ok(*mode));
        }
    }

    #[test]
    fn every_value_has_a_distinct_label_for_the_operator() {
        let scopes: Vec<&str> = DictionaryScope::all().iter().map(|s| s.label()).collect();
        for (index, label) in scopes.iter().enumerate() {
            assert!(!label.is_empty());
            assert!(!scopes.iter().skip(index + 1).any(|other| other == label));
        }
        for status in DictionaryStatus::all() {
            assert!(!status.label().is_empty());
        }
        for mode in MatchMode::all() {
            assert!(!mode.label().is_empty());
        }
    }

    /// **L'espressione esiste soltanto con il suo motore in tempo lineare**
    /// (DICT-REGEX-01, ADR-0187). Fino al 2026-11-06 questa prova diceva che
    /// il modo non esisteva (ADR-0012, decisione 4); ADR-0187 l'ha riesaminata
    /// alla condizione che essa aveva scritto. Ora dice che i modi sono cinque,
    /// che l'espressione ha un nome solo, e che un modo nuovo resta una
    /// decisione da prendere qui.
    #[test]
    fn the_expression_mode_exists_only_with_its_linear_engine() {
        assert_eq!(MatchMode::all().len(), 5);
        assert_eq!(
            MatchMode::from_str("expression").ok(),
            Some(MatchMode::Expression)
        );
        assert!(MatchMode::from_str("regex").is_err());
        assert!(MatchMode::from_str("regular_expression").is_err());
        assert!(check_new_term(r"(\w+)\1", MatchMode::Expression, 2).is_err());
        assert!(check_new_term(r"vend[eo]\s+armi", MatchMode::Expression, 2).is_ok());
    }

    /// **Un codice numerico ha da due a dodici cifre e il livello 1; un
    /// termine di sole cifre è un codice o non entra** (DICT-CODES-01,
    /// ADR-0170, criterio 1; prova negativa: una parola di sole cifre accolta
    /// → rossa).
    #[test]
    fn un_termine_di_sole_cifre_e_un_codice_o_non_entra() {
        assert!(check_new_term("88", MatchMode::NumericCode, 1).is_ok());
        assert!(check_new_term(" 1488 ", MatchMode::NumericCode, 1).is_ok());
        assert!(check_new_term("123456789012", MatchMode::NumericCode, 1).is_ok());

        for (testo, livello) in [
            ("8", 1),
            ("1234567890123", 1),
            ("88a", 1),
            ("8 8", 1),
            ("٨٨", 1),
            ("88", 2),
            ("88", 0),
            ("88", -1),
        ] {
            assert!(
                matches!(
                    check_new_term(testo, MatchMode::NumericCode, livello),
                    Err(DomainError::InvalidNumericCode { .. })
                ),
                "«{testo}» con livello {livello} non è un codice numerico"
            );
        }

        for modo in [
            MatchMode::ExactWord,
            MatchMode::Phrase,
            MatchMode::NormalizedWord,
        ] {
            assert!(check_new_term("88", modo, 2).is_err(), "«88» come {modo:?}");
            assert!(check_new_term("molotov", modo, 2).is_ok());
            assert!(check_new_term("ore 88", modo, 2).is_ok());
        }
    }

    #[test]
    fn a_built_in_dictionary_is_neither_editable_nor_deletable() {
        assert!(!DictionaryVisibility::BuiltIn.is_editable());
        assert!(!DictionaryVisibility::BuiltIn.is_deletable());
        assert!(DictionaryVisibility::Personal.is_editable());
        assert!(DictionaryVisibility::Shared.is_editable());
    }

    #[test]
    fn only_an_active_dictionary_is_selectable() {
        assert!(DictionaryStatus::Active.is_selectable());
        for other in [
            DictionaryStatus::Draft,
            DictionaryStatus::Inactive,
            DictionaryStatus::Superseded,
            DictionaryStatus::Archived,
        ] {
            assert!(
                !other.is_selectable(),
                "{other} non deve essere selezionabile"
            );
        }
    }

    #[test]
    fn only_the_normalised_mode_requires_normalisation() {
        assert!(MatchMode::NormalizedWord.requires_normalisation());
        assert!(!MatchMode::ExactWord.requires_normalisation());
        assert!(!MatchMode::Phrase.requires_normalisation());
    }

    #[test]
    fn an_unknown_taxonomy_value_is_refused() {
        assert!(matches!(
            DictionaryScope::from_str("galattico"),
            Err(DomainError::UnknownVariant { .. })
        ));
        assert!(matches!(
            DictionaryVisibility::from_str("segreto"),
            Err(DomainError::UnknownVariant { .. })
        ));
    }

    /// **Un riferimento all'indietro o uno sguardo avanti o indietro si
    /// rifiuta dicendo perché** (COLLAUDO-FIX-01, CU01-003, DEC-510).
    ///
    /// Nel collaudo `(x)\1` si rifiutava con «non è scritta in una forma che il
    /// programma legge»: chi ha scritto il dizionario non sapeva che cosa
    /// correggere. La frase si sceglie qui e non nel motore, che non cambia.
    #[test]
    fn un_riferimento_all_indietro_si_rifiuta_dicendo_perche() {
        for sbagliata in [
            r"(x)\1", r"(\w+)\1", r"a(?=b)", r"a(?!b)", r"(?<=a)b", r"(?<!a)b",
        ] {
            let Err(DomainError::InvalidExpression { reason }) =
                check_new_term(sbagliata, MatchMode::Expression, 2)
            else {
                panic!("«{sbagliata}» non si cerca in tempo lineare, e va rifiutata");
            };
            assert!(
                reason.contains("cresce soltanto con il testo"),
                "«{sbagliata}»: {reason}"
            );
        }
        // Una barra rovesciata scritta come carattere, seguita da una cifra, si
        // cerca: non è un riferimento.
        assert!(check_new_term(r"\\1", MatchMode::Expression, 2).is_ok());
        // Un'espressione soltanto sbagliata dice ancora la frase del motore.
        assert_eq!(
            check_new_term("(non chiusa", MatchMode::Expression, 2),
            Err(DomainError::InvalidExpression {
                reason: "l'espressione non è scritta in una forma che il programma legge"
            })
        );
        // Un'espressione troppo lunga tiene il suo motivo, anche con uno sguardo.
        let lunga = format!("(?=a){}", "b".repeat(250));
        assert_eq!(
            check_new_term(&lunga, MatchMode::Expression, 2),
            Err(DomainError::InvalidExpression {
                reason: "un'espressione ha al più 200 caratteri"
            })
        );
    }
}

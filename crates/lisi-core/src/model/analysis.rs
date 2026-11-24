//! Livelli di analisi e riscontri del dizionario.
//!
//! Il livello è l'esito dell'analisi di un contenuto e vale da 0 a 4. Il livello
//! 0 non è assenza di analisi: è un contenuto analizzato e risultato non
//! rilevante, che resta registrato nello storico senza generare alcun alert.

use core::fmt;

use crate::error::{DomainError, DomainResult};
use crate::id::{ContentId, MatchId};
use crate::text::{MatchedText, RuleCategory, RuleId};
use crate::time::Timestamp;

/// Livello di analisi attribuito a un contenuto, nell'intervallo 0..=4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AnalysisLevel(u8);

impl AnalysisLevel {
    /// Livello massimo ammesso.
    pub const MAX: u8 = 4;

    /// Contenuto analizzato e non rilevante: registrato, senza alert.
    pub const NOT_RELEVANT: Self = Self(0);

    /// Costruisce il livello verificandone l'intervallo.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::InvalidAnalysisLevel`] oltre [`Self::MAX`].
    pub const fn try_new(value: u8) -> DomainResult<Self> {
        if value > Self::MAX {
            return Err(DomainError::InvalidAnalysisLevel(value));
        }
        Ok(Self(value))
    }

    /// Valore numerico del livello.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// Se il livello comporta un alert.
    ///
    /// Solo i livelli da 1 a 4 lo comportano; il livello 0 no.
    #[must_use]
    pub const fn raises_alert(self) -> bool {
        self.0 > 0
    }

    /// Parola che dice il senso del livello all'operatore.
    ///
    /// Il numero da solo non dice nulla a chi apre una schermata la prima volta,
    /// e il livello 0 in particolare non è «nessuna analisi» ma «analizzato, e
    /// nessun avviso»: la differenza è tutta qui. Vive nel dominio perché più
    /// schermate lo mostrano (storico, avvisi, centro notifiche) e devono dire
    /// la stessa cosa.
    ///
    /// # Perché nessuna parola è quella di una decisione
    ///
    /// Il livello lo attribuisce il motore; «Rilevante» e «Non rilevante» le
    /// dice una persona (`ReviewState::label`). Il livello 0 si chiamava «non
    /// rilevante» e il 3 «rilevante»: sulla stessa riga, accanto alla
    /// decisione, l'analisi si leggeva come una valutazione (BUG-UX-3).
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self.0 {
            0 => "nessun avviso",
            1 => "debole",
            2 => "da tenere d'occhio",
            3 => "forte",
            _ => "prioritario",
        }
    }

    /// Etichetta leggibile: «Livello N — senso».
    #[must_use]
    pub fn label(self) -> String {
        format!("Livello {} \u{2014} {}", self.0, self.meaning())
    }
}

impl fmt::Display for AnalysisLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// Estremi, in caratteri, della porzione di testo che ha attivato una regola.
///
/// Gli offset servono a mostrare all'operatore *dove* nel messaggio si trova il
/// riscontro: un intervallo vuoto o invertito non indicherebbe nulla, quindi è
/// rifiutato alla costruzione.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MatchRange {
    start: usize,
    end: usize,
}

impl MatchRange {
    /// Costruisce l'intervallo verificandone la coerenza.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::InvalidMatchRange`] se `end` non è successivo
    /// a `start`.
    pub const fn try_new(start: usize, end: usize) -> DomainResult<Self> {
        if end <= start {
            return Err(DomainError::InvalidMatchRange { start, end });
        }
        Ok(Self { start, end })
    }

    /// Offset iniziale, in caratteri.
    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    /// Offset finale, escluso, in caratteri.
    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }

    /// Ampiezza dell'intervallo, sempre maggiore di zero.
    #[must_use]
    pub const fn length(self) -> usize {
        self.end - self.start
    }
}

impl fmt::Display for MatchRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}..{}", self.start, self.end)
    }
}

/// Riscontro che si intende registrare per un contenuto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewMatch {
    /// Contenuto in cui è avvenuto il riscontro.
    pub content_id: ContentId,
    /// Regola del dizionario che ha prodotto il riscontro.
    pub rule_id: RuleId,
    /// Categoria della regola.
    pub rule_category: RuleCategory,
    /// Porzione di testo riscontrata.
    pub matched_text: MatchedText,
    /// Posizione della porzione nel corpo del contenuto.
    pub range: MatchRange,
    /// Livello attribuito dalla regola.
    pub level: AnalysisLevel,
}

/// Riscontro registrato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentMatch {
    /// Identificatore assegnato dalla persistenza.
    pub id: MatchId,
    /// Contenuto in cui è avvenuto il riscontro.
    pub content_id: ContentId,
    /// Regola del dizionario che ha prodotto il riscontro.
    pub rule_id: RuleId,
    /// Categoria della regola.
    pub rule_category: RuleCategory,
    /// Porzione di testo riscontrata.
    pub matched_text: MatchedText,
    /// Posizione della porzione nel corpo del contenuto.
    pub range: MatchRange,
    /// Livello attribuito dalla regola.
    pub level: AnalysisLevel,
    /// Istante di registrazione.
    pub created_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::{AnalysisLevel, MatchRange};
    use crate::error::DomainError;

    #[test]
    fn every_level_from_zero_to_four_is_accepted() {
        for value in 0..=AnalysisLevel::MAX {
            let Ok(level) = AnalysisLevel::try_new(value) else {
                panic!("il livello {value} doveva essere accettato");
            };
            assert_eq!(level.get(), value);
        }
    }

    #[test]
    fn a_level_above_four_is_rejected() {
        assert_eq!(
            AnalysisLevel::try_new(5),
            Err(DomainError::InvalidAnalysisLevel(5))
        );
        assert_eq!(
            AnalysisLevel::try_new(u8::MAX),
            Err(DomainError::InvalidAnalysisLevel(u8::MAX))
        );
    }

    #[test]
    fn level_zero_does_not_raise_an_alert() {
        assert!(!AnalysisLevel::NOT_RELEVANT.raises_alert());
    }

    #[test]
    fn every_level_above_zero_raises_an_alert() {
        for value in 1..=AnalysisLevel::MAX {
            let Ok(level) = AnalysisLevel::try_new(value) else {
                panic!("il livello {value} doveva essere accettato");
            };
            assert!(level.raises_alert());
        }
    }

    #[test]
    fn every_level_has_a_distinct_readable_meaning() {
        // È la fonte unica per storico, avvisi e centro notifiche: se il testo
        // cambia, cambia in un punto solo. Il livello 0 non è «nessuna analisi».
        let mut seen: Vec<&str> = Vec::new();
        for value in 0..=AnalysisLevel::MAX {
            let Ok(level) = AnalysisLevel::try_new(value) else {
                panic!("il livello {value} doveva essere accettato");
            };
            let meaning = level.meaning();
            assert!(!meaning.is_empty());
            assert!(!seen.contains(&meaning), "significati distinti: {meaning}");
            seen.push(meaning);
            assert!(level.label().starts_with(&format!("Livello {value} ")));
            assert!(level.label().contains(meaning));
        }
        assert_eq!(AnalysisLevel::NOT_RELEVANT.meaning(), "nessun avviso");
    }

    /// **Il livello non usa le parole della decisione umana** (BUG-UX-3): il
    /// livello 0 «non rilevante» stava sulla stessa riga della decisione «Non
    /// rilevante», e confondeva l'analisi con la valutazione.
    #[test]
    fn nessun_livello_si_chiama_come_una_decisione() {
        for value in 0..=AnalysisLevel::MAX {
            let Ok(level) = AnalysisLevel::try_new(value) else {
                panic!("il livello {value} doveva essere accettato");
            };
            let senso = level.meaning().to_lowercase();
            for decisione in crate::model::review::ReviewState::all() {
                let parola = decisione.label().to_lowercase();
                assert!(
                    !senso.contains(&parola),
                    "il livello {value} («{senso}») usa la parola della decisione «{parola}»"
                );
            }
        }
    }

    #[test]
    fn levels_are_ordered_by_severity() {
        let (Ok(low), Ok(high)) = (AnalysisLevel::try_new(1), AnalysisLevel::try_new(4)) else {
            panic!("i livelli 1 e 4 devono essere accettati");
        };
        assert!(AnalysisLevel::NOT_RELEVANT < low);
        assert!(low < high);
    }

    #[test]
    fn a_match_range_must_be_non_empty() {
        assert_eq!(
            MatchRange::try_new(5, 5),
            Err(DomainError::InvalidMatchRange { start: 5, end: 5 })
        );
    }

    #[test]
    fn an_inverted_match_range_is_rejected() {
        assert_eq!(
            MatchRange::try_new(9, 3),
            Err(DomainError::InvalidMatchRange { start: 9, end: 3 })
        );
    }

    #[test]
    fn a_valid_match_range_keeps_its_bounds_and_length() {
        let Ok(range) = MatchRange::try_new(4, 11) else {
            panic!("l'intervallo doveva essere accettato");
        };
        assert_eq!(range.start(), 4);
        assert_eq!(range.end(), 11);
        assert_eq!(range.length(), 7);
    }
}

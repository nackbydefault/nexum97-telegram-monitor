//! Alert generati dall'analisi.
//!
//! Un alert esiste solo per i livelli da 1 a 4. Un contenuto di livello 0 resta
//! registrato nello storico e semplicemente non ha un alert: la struttura rende
//! impossibile che «nessun alert» significhi «nessuna registrazione».

use crate::error::{DomainError, DomainResult};
use crate::id::{AlertId, ContentId};
use crate::model::analysis::AnalysisLevel;
use crate::text::AlertReason;
use crate::time::Timestamp;

/// Livello di un alert: un livello di analisi che comporta un allarme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AlertLevel(AnalysisLevel);

impl AlertLevel {
    /// Costruisce il livello dell'alert verificando che comporti un allarme.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::AlertLevelWithoutAlarm`] per il livello 0.
    pub const fn try_new(level: AnalysisLevel) -> DomainResult<Self> {
        if !level.raises_alert() {
            return Err(DomainError::AlertLevelWithoutAlarm);
        }
        Ok(Self(level))
    }

    /// Livello di analisi corrispondente.
    #[must_use]
    pub const fn level(self) -> AnalysisLevel {
        self.0
    }

    /// Valore numerico, da 1 a 4.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0.get()
    }
}

/// Alert che si intende registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAlert {
    /// Contenuto che ha generato l'alert.
    pub content_id: ContentId,
    /// Livello dell'allarme, da 1 a 4.
    pub level: AlertLevel,
    /// Motivazione leggibile, mostrata all'operatore e riportata nei report.
    pub reason: AlertReason,
    /// Istante di generazione.
    pub raised_at: Timestamp,
}

/// Alert registrato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    /// Identificatore assegnato dalla persistenza.
    pub id: AlertId,
    /// Contenuto che ha generato l'alert.
    pub content_id: ContentId,
    /// Livello dell'allarme, da 1 a 4.
    pub level: AlertLevel,
    /// Motivazione leggibile.
    pub reason: AlertReason,
    /// Istante di generazione.
    pub raised_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::AlertLevel;
    use crate::error::DomainError;
    use crate::model::analysis::AnalysisLevel;

    #[test]
    fn every_alarming_level_is_accepted() {
        for value in 1..=AnalysisLevel::MAX {
            let Ok(level) = AnalysisLevel::try_new(value) else {
                panic!("il livello {value} doveva essere accettato");
            };
            let Ok(alert_level) = AlertLevel::try_new(level) else {
                panic!("il livello {value} doveva poter generare un alert");
            };
            assert_eq!(alert_level.get(), value);
            assert_eq!(alert_level.level(), level);
        }
    }

    #[test]
    fn level_zero_cannot_become_an_alert() {
        assert_eq!(
            AlertLevel::try_new(AnalysisLevel::NOT_RELEVANT),
            Err(DomainError::AlertLevelWithoutAlarm)
        );
    }

    #[test]
    fn alert_levels_are_ordered_by_severity() {
        let (Ok(low), Ok(high)) = (AnalysisLevel::try_new(1), AnalysisLevel::try_new(4)) else {
            panic!("i livelli 1 e 4 devono essere accettati");
        };
        let (Ok(low), Ok(high)) = (AlertLevel::try_new(low), AlertLevel::try_new(high)) else {
            panic!("i livelli 1 e 4 devono poter generare un alert");
        };
        assert!(low < high);
    }
}

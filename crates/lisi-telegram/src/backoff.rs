//! Attesa crescente fra i tentativi di riconnessione.
//!
//! Riprovare subito e senza limite una connessione caduta significa martellare
//! il servizio remoto: è esattamente il comportamento che i limiti di traffico
//! sono fatti per fermare, e che i requisiti di sicurezza vietano di aggirare.
//! L'attesa cresce quindi in modo geometrico fino a un massimo, e il numero di
//! tentativi è limitato.
//!
//! La progressione è **deterministica**, senza componente casuale: un solo
//! client per postazione non produce lo sciame di richieste simultanee che la
//! casualità serve a disperdere, e una progressione prevedibile è verificabile
//! da un test e spiegabile a un operatore.

use core::time::Duration;

use crate::error::{TelegramError, TelegramResult};

/// Politica di attesa fra i tentativi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffPolicy {
    initial: Duration,
    maximum: Duration,
    factor: u32,
    max_attempts: u32,
}

impl BackoffPolicy {
    /// Attesa iniziale predefinita.
    pub const DEFAULT_INITIAL: Duration = Duration::from_millis(500);
    /// Attesa massima predefinita.
    pub const DEFAULT_MAXIMUM: Duration = Duration::from_secs(60);
    /// Fattore di crescita predefinito.
    pub const DEFAULT_FACTOR: u32 = 2;
    /// Numero massimo di tentativi predefinito.
    pub const DEFAULT_MAX_ATTEMPTS: u32 = 8;

    /// Costruisce la politica.
    ///
    /// I valori incoerenti sono corretti invece di essere rifiutati: un fattore
    /// minore di due non farebbe crescere l'attesa e un massimo inferiore
    /// all'iniziale non avrebbe senso.
    #[must_use]
    pub const fn new(initial: Duration, maximum: Duration, factor: u32, max_attempts: u32) -> Self {
        let factor = if factor < 2 { 2 } else { factor };
        let maximum = if maximum.as_millis() < initial.as_millis() {
            initial
        } else {
            maximum
        };

        Self {
            initial,
            maximum,
            factor,
            max_attempts,
        }
    }

    /// Attesa prima del tentativo numero `attempt`, contato da 1.
    ///
    /// # Errori
    ///
    /// Restituisce [`TelegramError::BackoffExhausted`] quando i tentativi
    /// ammessi sono esauriti. È il segnale che va smesso di riprovare e
    /// informato l'operatore, non che si debba riprovare più piano.
    pub fn delay_for_attempt(self, attempt: u32) -> TelegramResult<Duration> {
        if attempt == 0 || attempt > self.max_attempts {
            return Err(TelegramError::BackoffExhausted {
                attempts: self.max_attempts,
            });
        }

        let mut delay = self.initial.as_millis();
        let maximum = self.maximum.as_millis();

        for _ in 1..attempt {
            delay = delay.saturating_mul(u128::from(self.factor));
            if delay >= maximum {
                return Ok(self.maximum);
            }
        }

        let millis = u64::try_from(delay).unwrap_or(u64::MAX);
        Ok(Duration::from_millis(millis).min(self.maximum))
    }

    /// Numero massimo di tentativi ammessi.
    #[must_use]
    pub const fn max_attempts(self) -> u32 {
        self.max_attempts
    }

    /// Attesa massima raggiungibile.
    #[must_use]
    pub const fn maximum(self) -> Duration {
        self.maximum
    }
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self::new(
            Self::DEFAULT_INITIAL,
            Self::DEFAULT_MAXIMUM,
            Self::DEFAULT_FACTOR,
            Self::DEFAULT_MAX_ATTEMPTS,
        )
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::BackoffPolicy;
    use crate::error::TelegramError;

    fn policy() -> BackoffPolicy {
        BackoffPolicy::new(
            Duration::from_millis(100),
            Duration::from_millis(2_000),
            2,
            6,
        )
    }

    #[test]
    fn the_delay_grows_geometrically() {
        let policy = policy();
        for (attempt, expected) in [(1, 100), (2, 200), (3, 400), (4, 800), (5, 1_600)] {
            assert_eq!(
                policy.delay_for_attempt(attempt).ok(),
                Some(Duration::from_millis(expected)),
                "tentativo {attempt}"
            );
        }
    }

    #[test]
    fn the_delay_never_exceeds_the_declared_maximum() {
        let policy = policy();
        for attempt in 1..=policy.max_attempts() {
            let Ok(delay) = policy.delay_for_attempt(attempt) else {
                panic!("il tentativo {attempt} doveva essere ammesso");
            };
            assert!(delay <= policy.maximum(), "tentativo {attempt}");
        }
        assert_eq!(policy.delay_for_attempt(6).ok(), Some(policy.maximum()));
    }

    #[test]
    fn exhausting_the_attempts_is_reported_and_does_not_wrap_around() {
        let policy = policy();
        assert!(matches!(
            policy.delay_for_attempt(7),
            Err(TelegramError::BackoffExhausted { attempts: 6 })
        ));
        assert!(matches!(
            policy.delay_for_attempt(u32::MAX),
            Err(TelegramError::BackoffExhausted { .. })
        ));
    }

    #[test]
    fn attempt_zero_is_not_a_valid_attempt() {
        assert!(matches!(
            policy().delay_for_attempt(0),
            Err(TelegramError::BackoffExhausted { .. })
        ));
    }

    #[test]
    fn an_incoherent_factor_is_corrected_instead_of_disabling_the_growth() {
        let policy = BackoffPolicy::new(
            Duration::from_millis(100),
            Duration::from_millis(10_000),
            0,
            5,
        );
        let (Ok(first), Ok(second)) = (policy.delay_for_attempt(1), policy.delay_for_attempt(2))
        else {
            panic!("i tentativi dovevano essere ammessi");
        };
        assert!(second > first, "l'attesa deve comunque crescere");
    }

    #[test]
    fn a_maximum_below_the_initial_delay_is_raised_to_it() {
        let policy = BackoffPolicy::new(
            Duration::from_millis(5_000),
            Duration::from_millis(10),
            2,
            3,
        );
        assert_eq!(policy.maximum(), Duration::from_millis(5_000));
        assert_eq!(
            policy.delay_for_attempt(1).ok(),
            Some(Duration::from_millis(5_000))
        );
    }

    #[test]
    fn an_extreme_progression_saturates_instead_of_overflowing() {
        let policy = BackoffPolicy::new(
            Duration::from_millis(1_000),
            Duration::from_secs(3_600),
            1_000_000,
            30,
        );
        for attempt in 1..=30 {
            let Ok(delay) = policy.delay_for_attempt(attempt) else {
                panic!("il tentativo {attempt} doveva essere ammesso");
            };
            assert!(delay <= policy.maximum());
        }
    }

    #[test]
    fn the_default_policy_is_bounded() {
        let policy = BackoffPolicy::default();
        assert_eq!(policy.max_attempts(), BackoffPolicy::DEFAULT_MAX_ATTEMPTS);
        assert_eq!(policy.maximum(), BackoffPolicy::DEFAULT_MAXIMUM);
        assert!(policy.delay_for_attempt(policy.max_attempts()).is_ok());
        assert!(policy.delay_for_attempt(policy.max_attempts() + 1).is_err());
    }
}

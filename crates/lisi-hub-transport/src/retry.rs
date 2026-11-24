//! Quando riprovare, e quando no.
//!
//! Si riprova **solo** quando l'Hub non risponde, con attesa che raddoppia e un
//! tetto sia sull'attesa sia sul numero di tentativi. Quando l'Hub risponde ma
//! non è quello atteso **non si riprova da soli** (ADR-0083, decisione 6): un
//! ritentare automatico trasformerebbe un possibile impostore in un rumore di
//! fondo che nessuno guarda.
//!
//! Il modulo non dorme e non apre connessioni: dice quanto aspettare. Chi
//! aspetta è il chiamante, che può essere interrotto.

use std::time::Duration;

use crate::error::{ConnectOutcome, TransportError};

/// La politica dei nuovi tentativi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// L'attesa prima del secondo tentativo.
    pub initial_delay: Duration,
    /// L'attesa massima fra due tentativi.
    pub max_delay: Duration,
    /// Quanti tentativi in tutto, il primo compreso.
    pub max_attempts: u32,
}

impl Default for RetryPolicy {
    /// Valori scelti da noi, non misurati: un secondo, poi il doppio, fino a un
    /// minuto, per otto tentativi — poco più di due minuti prima di dire
    /// all'operatore che l'Hub non risponde.
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            max_attempts: 8,
        }
    }
}

impl RetryPolicy {
    /// Quanto aspettare prima del tentativo numero `next_attempt` (il primo è
    /// 1), dopo che il precedente è fallito con `error`.
    ///
    /// `None` significa **non riprovare**: perché l'errore non lo consente, o
    /// perché i tentativi sono finiti.
    #[must_use]
    pub fn delay_before(&self, next_attempt: u32, error: &TransportError) -> Option<Duration> {
        if error.outcome() != ConnectOutcome::HubUnreachable {
            return None;
        }
        if next_attempt < 2 || next_attempt > self.max_attempts {
            return None;
        }
        // Il raddoppio si ferma prima di traboccare: dopo trentadue raddoppi
        // qualunque attesa ragionevole ha già raggiunto il tetto.
        let raddoppi = (next_attempt - 2).min(32);
        let attesa = self
            .initial_delay
            .checked_mul(1_u32 << raddoppi.min(31))
            .unwrap_or(self.max_delay);
        Some(attesa.min(self.max_delay))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::RetryPolicy;
    use crate::error::TransportError;

    #[test]
    fn silence_is_retried_with_a_growing_and_capped_delay() {
        let politica = RetryPolicy::default();
        let errore = TransportError::Unreachable;
        let attese: Vec<Option<Duration>> = (1..=10)
            .map(|tentativo| politica.delay_before(tentativo, &errore))
            .collect();
        assert_eq!(attese[0], None, "il primo tentativo non aspetta");
        assert_eq!(attese[1], Some(Duration::from_secs(1)));
        assert_eq!(attese[2], Some(Duration::from_secs(2)));
        assert_eq!(attese[7], Some(Duration::from_secs(60)), "il tetto tiene");
        assert_eq!(attese[8], None, "i tentativi finiscono");
    }

    #[test]
    fn an_unexpected_hub_is_never_retried_automatically() {
        let politica = RetryPolicy::default();
        for errore in [
            TransportError::NotTheExpectedHub,
            TransportError::ProtocolMismatch,
        ] {
            for tentativo in 1..=10 {
                assert_eq!(politica.delay_before(tentativo, &errore), None);
            }
        }
    }

    #[test]
    fn huge_policies_do_not_overflow() {
        let politica = RetryPolicy {
            initial_delay: Duration::from_secs(u64::MAX / 2),
            max_delay: Duration::from_secs(30),
            max_attempts: u32::MAX,
        };
        assert_eq!(
            politica.delay_before(u32::MAX, &TransportError::Unreachable),
            Some(Duration::from_secs(30))
        );
    }
}

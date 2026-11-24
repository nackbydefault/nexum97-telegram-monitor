//! La pausa vera dell'acquisizione (PAUSE-01, ADR-0172, DEC-437).
//!
//! # Che cosa è
//!
//! Un fatto con il suo motivo: da quando, chi, perché, e — se è stata ripresa —
//! quando e chi. Durante la pausa il monitoraggio **non acquisisce**, e il
//! periodo è «non coperto» per decisione dell'operatore.
//!
//! # Che cosa non è
//!
//! Non è la sospensione degli avvisi (ADR-0017, decisione 6), che non ferma
//! niente; e non è uno stato della sessione: lo stato non cambia, e la storia
//! delle sessioni già registrate resta com'era.

use crate::id::SessionId;
use crate::model::reason::OperationalReason;
use crate::model::session::SessionState;
use crate::text::Actor;
use crate::time::Timestamp;

/// Una pausa dell'acquisizione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquisitionPause {
    /// Il monitoraggio.
    pub session_id: SessionId,
    /// Da quando.
    pub paused_at: Timestamp,
    /// Chi l'ha decisa.
    pub paused_by: Actor,
    /// Perché.
    pub reason: OperationalReason,
    /// Quando è stata ripresa, se lo è stata.
    pub resumed_at: Option<Timestamp>,
    /// Chi l'ha ripresa, o il programma alla fine del monitoraggio.
    pub resumed_by: Option<Actor>,
}

impl AcquisitionPause {
    /// Se è ancora aperta.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.resumed_at.is_none()
    }

    /// Il tratto non coperto: dalla pausa alla ripresa, oppure a `until` se è
    /// ancora aperta. Mai rovesciato.
    #[must_use]
    pub fn span(&self, until: Timestamp) -> (Timestamp, Timestamp) {
        let fine = self.resumed_at.unwrap_or(until);
        (self.paused_at, fine.max(self.paused_at))
    }
}

/// Perché una pausa non si mette o non si riprende.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseRefusal {
    /// Il monitoraggio non acquisisce: è pianificato o concluso.
    NotAcquiring,
    /// Aspetta una decisione dopo un'interruzione (ADR-0146).
    AwaitingDecision,
    /// È già in pausa.
    AlreadyPaused,
    /// Non è in pausa.
    NotPaused,
}

impl PauseRefusal {
    /// La ragione, come la legge l'operatore.
    #[must_use]
    pub const fn sentence(self) -> &'static str {
        match self {
            Self::NotAcquiring => {
                "Si mette in pausa soltanto un monitoraggio in corso, anche con gli avvisi sospesi."
            }
            Self::AwaitingDecision => {
                "Il monitoraggio aspetta una decisione dopo un'interruzione: prima va presa quella."
            }
            Self::AlreadyPaused => "L'acquisizione è già in pausa.",
            Self::NotPaused => "L'acquisizione non è in pausa.",
        }
    }
}

/// Se un monitoraggio si può mettere in pausa (ADR-0172, decisione 7).
///
/// # Errori
///
/// Restituisce il rifiuto con la sua ragione.
pub const fn may_pause(
    state: SessionState,
    awaiting_decision: bool,
    open_pause: bool,
) -> Result<(), PauseRefusal> {
    if !matches!(state, SessionState::Running | SessionState::Paused) {
        return Err(PauseRefusal::NotAcquiring);
    }
    if awaiting_decision {
        return Err(PauseRefusal::AwaitingDecision);
    }
    if open_pause {
        return Err(PauseRefusal::AlreadyPaused);
    }
    Ok(())
}

/// Se un monitoraggio si può riprendere: soltanto se è in pausa.
///
/// # Errori
///
/// Restituisce [`PauseRefusal::NotPaused`] se non lo è.
pub const fn may_resume(open_pause: bool) -> Result<(), PauseRefusal> {
    if open_pause {
        Ok(())
    } else {
        Err(PauseRefusal::NotPaused)
    }
}

#[cfg(test)]
mod tests {
    use super::{PauseRefusal, may_pause, may_resume};
    use crate::model::session::SessionState;

    /// **Si mette in pausa soltanto ciò che acquisisce, una volta, e non chi
    /// aspetta una decisione** (PAUSE-01, ADR-0172, criterio 1; prova
    /// negativa: un pianificato messo in pausa → rossa).
    #[test]
    fn si_mette_in_pausa_soltanto_cio_che_acquisisce() {
        assert_eq!(may_pause(SessionState::Running, false, false), Ok(()));
        assert_eq!(may_pause(SessionState::Paused, false, false), Ok(()));
        for stato in [
            SessionState::Planned,
            SessionState::Completed,
            SessionState::Stopped,
        ] {
            assert_eq!(
                may_pause(stato, false, false),
                Err(PauseRefusal::NotAcquiring),
                "{stato:?}"
            );
        }
        assert_eq!(
            may_pause(SessionState::Running, true, false),
            Err(PauseRefusal::AwaitingDecision)
        );
        assert_eq!(
            may_pause(SessionState::Running, false, true),
            Err(PauseRefusal::AlreadyPaused)
        );
        assert_eq!(may_resume(true), Ok(()));
        assert_eq!(may_resume(false), Err(PauseRefusal::NotPaused));
    }
}

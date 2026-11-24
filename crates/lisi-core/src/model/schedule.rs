//! L'avvio programmato di un monitoraggio (SCHEDULE-01, ADR-0171, DEC-436).
//!
//! # Che cosa decide questo modulo
//!
//! - **Quanto avanti** si può programmare: da un minuto a sette giorni.
//! - **Che cosa fare all'istante detto**: partire, aspettare, o dichiarare un
//!   avvio mancato con la sua ragione. La funzione è pura: l'istante e lo
//!   stato dell'account li porta chi chiama.
//!
//! # Che cosa non fa
//!
//! Non avvia niente da sé e non recupera in silenzio: un avvio mancato resta
//! mancato, e il monitoraggio si avvia a mano o si annulla.

use crate::id::SessionId;
use crate::text::Actor;
use crate::time::Timestamp;

/// Il minimo anticipo: un inizio fra meno di un minuto è un «adesso».
pub const SCHEDULE_MIN_LEAD_MS: i64 = 60_000;

/// Il massimo anticipo: sette giorni, come la durata personalizzata
/// (ADR-0150).
pub const SCHEDULE_MAX_LEAD_MS: i64 = 7 * 24 * 3_600_000;

/// La tolleranza: oltre un minuto dopo l'istante detto l'avvio è mancato.
pub const START_GRACE_MS: i64 = 60_000;

string_enum!(
    /// Perché un avvio programmato non è avvenuto.
    MissedStartReason {
        /// Il programma se n'è accorto oltre la tolleranza: era chiuso, o la
        /// postazione dormiva.
        ProgramClosed => "programma_chiuso",
        /// All'istante detto l'account non era collegato.
        AccountNotConnected => "account_non_collegato",
    }
);

impl MissedStartReason {
    /// La ragione, come la legge l'operatore.
    #[must_use]
    pub const fn sentence(self) -> &'static str {
        match self {
            Self::ProgramClosed => {
                "all'ora programmata il programma era chiuso, o la postazione era in pausa"
            }
            Self::AccountNotConnected => "all'ora programmata l'account non era collegato",
        }
    }
}

/// Un avvio mancato, registrato una volta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissedStart {
    /// Quando il programma lo ha dichiarato.
    pub at: Timestamp,
    /// Perché.
    pub reason: MissedStartReason,
}

/// L'inizio programmato di un monitoraggio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledStart {
    /// Il monitoraggio, nello stato pianificato finché non parte.
    pub session_id: SessionId,
    /// L'istante in cui deve partire.
    pub start_at: Timestamp,
    /// Chi lo ha programmato.
    pub scheduled_by: Actor,
    /// Quando.
    pub scheduled_at: Timestamp,
    /// L'avvio mancato, se c'è stato.
    pub missed: Option<MissedStart>,
}

/// Perché un inizio non si può programmare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeadRefusal {
    /// Fra meno di un minuto, o nel passato.
    TooSoon,
    /// Oltre sette giorni.
    TooFar,
}

impl LeadRefusal {
    /// La ragione, come la legge l'operatore.
    #[must_use]
    pub const fn sentence(self) -> &'static str {
        match self {
            Self::TooSoon => {
                "L'inizio deve essere almeno un minuto nel futuro. Per partire subito, scegliere «Adesso»."
            }
            Self::TooFar => "L'inizio può essere al più sette giorni nel futuro.",
        }
    }
}

/// Se un inizio si può programmare adesso (ADR-0171, decisione 2).
///
/// # Errori
///
/// Restituisce [`LeadRefusal`] se l'inizio è troppo vicino o troppo lontano.
pub const fn check_lead(start_at: Timestamp, now: Timestamp) -> Result<(), LeadRefusal> {
    let anticipo = start_at.as_millis().saturating_sub(now.as_millis());
    if anticipo < SCHEDULE_MIN_LEAD_MS {
        return Err(LeadRefusal::TooSoon);
    }
    if anticipo > SCHEDULE_MAX_LEAD_MS {
        return Err(LeadRefusal::TooFar);
    }
    Ok(())
}

/// Che cosa fare, adesso, di un inizio programmato non ancora deciso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartDecision {
    /// Non è ancora l'ora.
    NotYet,
    /// Partire adesso.
    Start,
    /// L'avvio è mancato, per questa ragione.
    Missed(MissedStartReason),
}

/// Decide che cosa fare di un inizio programmato (ADR-0171, decisioni 4 e 5).
///
/// Prima dell'istante, niente. Oltre la tolleranza, mancato perché il
/// programma era chiuso: lo si dice anche se ora l'account è collegato,
/// perché partire adesso sarebbe recuperare in silenzio. Entro la tolleranza,
/// si parte se l'account è collegato; altrimenti è mancato per l'account.
#[must_use]
pub const fn decide(start_at: Timestamp, now: Timestamp, account_ready: bool) -> StartDecision {
    let ritardo = now.as_millis().saturating_sub(start_at.as_millis());
    if ritardo < 0 {
        return StartDecision::NotYet;
    }
    if ritardo > START_GRACE_MS {
        return StartDecision::Missed(MissedStartReason::ProgramClosed);
    }
    if !account_ready {
        return StartDecision::Missed(MissedStartReason::AccountNotConnected);
    }
    StartDecision::Start
}

#[cfg(test)]
mod tests {
    use super::{
        LeadRefusal, MissedStartReason, START_GRACE_MS, StartDecision, check_lead, decide,
    };
    use crate::time::Timestamp;

    const ORA: i64 = 1_800_000_000_000;

    fn a(ms: i64) -> Timestamp {
        Timestamp::from_millis(ORA + ms)
    }

    /// **Si programma da un minuto a sette giorni** (SCHEDULE-01, ADR-0171,
    /// criterio 2).
    #[test]
    fn si_programma_da_un_minuto_a_sette_giorni() {
        assert_eq!(check_lead(a(60_000), a(0)), Ok(()));
        assert_eq!(check_lead(a(7 * 86_400_000), a(0)), Ok(()));
        assert_eq!(check_lead(a(59_999), a(0)), Err(LeadRefusal::TooSoon));
        assert_eq!(check_lead(a(-1), a(0)), Err(LeadRefusal::TooSoon));
        assert_eq!(
            check_lead(a(7 * 86_400_000 + 1), a(0)),
            Err(LeadRefusal::TooFar)
        );
    }

    /// **Parte all'istante detto con l'account collegato; altrimenti dice
    /// perché, e oltre il minuto non recupera** (criterio 3; prova negativa:
    /// un avvio in ritardo trattato come in orario → rossa).
    #[test]
    fn parte_all_istante_o_dice_perche_no() {
        let inizio = a(0);
        assert_eq!(decide(inizio, a(-1), true), StartDecision::NotYet);
        assert_eq!(decide(inizio, a(0), true), StartDecision::Start);
        assert_eq!(
            decide(inizio, a(START_GRACE_MS), true),
            StartDecision::Start
        );
        assert_eq!(
            decide(inizio, a(START_GRACE_MS + 1), true),
            StartDecision::Missed(MissedStartReason::ProgramClosed),
            "oltre il minuto, partire sarebbe recuperare in silenzio"
        );
        assert_eq!(
            decide(inizio, a(0), false),
            StartDecision::Missed(MissedStartReason::AccountNotConnected)
        );
        assert_eq!(
            decide(inizio, a(3_600_000), false),
            StartDecision::Missed(MissedStartReason::ProgramClosed)
        );
    }

    /// Ogni ragione ha la sua frase, e si rilegge dalla forma conservata.
    #[test]
    fn ogni_ragione_si_dice_e_si_rilegge() {
        for ragione in MissedStartReason::all() {
            assert!(ragione.sentence().starts_with("all'ora programmata"));
            assert_eq!(ragione.as_str().parse::<MissedStartReason>(), Ok(*ragione));
        }
    }
}

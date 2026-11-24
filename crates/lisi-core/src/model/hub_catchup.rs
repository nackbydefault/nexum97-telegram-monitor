//! Il recupero dopo una riconnessione (HUB-CATCHUP-01, ADR-0087).
//!
//! ADR-0042 decisione 7: *un client che torna dice l'ultimo numero che ha visto
//! e riceve ciò che manca, poi torna in diretta.* Questo modulo è la parte del
//! client che rende vera quella frase, e sta in `lisi-core` perché è una
//! macchina a stati pura: nessuna rete, nessun archivio, nessun orologio.
//!
//! # Le tre regole
//!
//! 1. **Il client non si fida della diretta.** Ogni evento ricevuto deve avere
//!    il numero **subito dopo** l'ultimo applicato. Se ne arriva uno più avanti,
//!    è un **buco**, e un buco si chiede — non si assume che «tanto arriverà».
//!    È ciò che rende impossibile il buco silenzioso anche se il passaggio da
//!    recupero a diretta avesse una corsa.
//! 2. **Si applica prima, si segna dopo.** Il cursore avanza **solo** dopo che
//!    l'evento è stato applicato. Segnarlo prima significherebbe, dopo un
//!    arresto improvviso, ripartire **oltre** un evento mai applicato: perso per
//!    sempre, e in silenzio.
//! 3. **Un duplicato non avanza niente.** Il prezzo della regola 2 è che un
//!    evento può arrivare due volte; applicarlo due volte non deve fare danno, e
//!    il cursore non torna indietro né salta.
//!
//! # Che cosa questo modulo non decide
//!
//! Non decide che cosa significhi «applicare» un evento — lo sa chi lo riceve —
//! né come si trasportano le pagine (protocollo), né che cosa succede se il
//! client non sta al passo (HUB-BP-01).

use crate::model::hub_event::HubEventStreamId;

/// Quanti eventi chiedere per pagina.
///
/// Scelto da noi, non misurato: sta comodamente sotto il tetto di lettura
/// dell'Hub (ADR-0086) e dentro un frame del protocollo (ADR-0084).
pub const CATCH_UP_PAGE: usize = 200;

/// Che cosa è successo a un evento consegnato al client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptOutcome {
    /// È il prossimo: si applica, e il cursore avanzerà dopo.
    Next,
    /// Già visto: si scarta, e **niente avanza**.
    Duplicate,
    /// Manca qualcosa in mezzo: non si applica, e il buco si chiede.
    Gap {
        /// Il numero che ci si aspettava.
        expected: u64,
        /// Il numero arrivato.
        received: u64,
    },
}

/// Che cosa il client deve fare adesso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextStep {
    /// Chiedere una pagina di ciò che manca.
    RequestPage {
        /// L'ultimo numero applicato.
        after: u64,
        /// Quanti eventi al più.
        limit: usize,
    },
    /// È allineato: può stare in diretta.
    Live,
}

/// Perché il recupero si è fermato, e non riprenderà da solo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatchUpStop {
    /// L'Hub segue un'altra storia: reinstallato, ripristinato, o un altro Hub.
    StreamChanged,
    /// L'Hub non ha mai emesso il numero che il client dichiara: il suo
    /// archivio è tornato indietro.
    HubWentBackwards,
}

impl CatchUpStop {
    /// La frase per l'operatore: dice il fatto e **non** propone di procedere.
    #[must_use]
    pub const fn operator_message(self) -> &'static str {
        match self {
            Self::StreamChanged => {
                "L'Hub risponde con una storia diversa da quella che questa postazione \
                 seguiva. Può essere stato reinstallato o ripristinato da una copia. Gli eventi \
                 già ricevuti non si collegano più ai nuovi. L'allineamento automatico si ferma \
                 qui."
            }
            Self::HubWentBackwards => {
                "L'Hub non conosce il punto in cui questa postazione era arrivata: il suo \
                 archivio risulta tornato indietro. L'allineamento automatico si ferma qui."
            }
        }
    }
}

/// Il punto in cui una postazione è arrivata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HubCursor {
    /// La storia che sta seguendo.
    pub stream: HubEventStreamId,
    /// L'ultimo numero **applicato**. Zero se non ha mai applicato nulla.
    pub last_applied: u64,
}

/// La macchina a stati del recupero, dal lato del client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatchUpTracker {
    cursor: HubCursor,
}

impl CatchUpTracker {
    /// Comincia dal punto conservato.
    #[must_use]
    pub const fn resuming_from(cursor: HubCursor) -> Self {
        Self { cursor }
    }

    /// Il punto attuale, da conservare **dopo** ogni applicazione riuscita.
    #[must_use]
    pub const fn cursor(&self) -> HubCursor {
        self.cursor
    }

    /// Che cosa fare di un evento appena arrivato, **prima** di applicarlo.
    #[must_use]
    pub const fn inspect(&self, sequence: u64) -> AcceptOutcome {
        let atteso = self.cursor.last_applied + 1;
        if sequence == atteso {
            AcceptOutcome::Next
        } else if sequence <= self.cursor.last_applied {
            AcceptOutcome::Duplicate
        } else {
            AcceptOutcome::Gap {
                expected: atteso,
                received: sequence,
            }
        }
    }

    /// Segna un evento come **applicato**.
    ///
    /// Va chiamata **dopo** che l'applicazione è riuscita e persistita: è la
    /// regola 2 del modulo. Restituisce `false` — e non cambia nulla — se
    /// quell'evento non era il prossimo.
    pub const fn applied(&mut self, sequence: u64) -> bool {
        if sequence != self.cursor.last_applied + 1 {
            return false;
        }
        self.cursor.last_applied = sequence;
        true
    }

    /// Che cosa fare adesso, sapendo l'ultimo numero che l'Hub dichiara.
    #[must_use]
    pub const fn next_step(&self, hub_latest: u64) -> NextStep {
        if self.cursor.last_applied >= hub_latest {
            NextStep::Live
        } else {
            NextStep::RequestPage {
                after: self.cursor.last_applied,
                limit: CATCH_UP_PAGE,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AcceptOutcome, CATCH_UP_PAGE, CatchUpStop, CatchUpTracker, HubCursor, NextStep};
    use crate::model::hub_event::{HUB_STREAM_ID_BYTES, HubEventStreamId};

    fn tracker(da: u64) -> CatchUpTracker {
        CatchUpTracker::resuming_from(HubCursor {
            stream: HubEventStreamId::from_random_bytes([5; HUB_STREAM_ID_BYTES]),
            last_applied: da,
        })
    }

    #[test]
    fn the_next_event_is_applied_and_the_cursor_follows_it() {
        let mut tracker = tracker(39);
        assert_eq!(tracker.inspect(40), AcceptOutcome::Next);
        assert!(tracker.applied(40));
        assert_eq!(tracker.cursor().last_applied, 40);
    }

    #[test]
    fn a_hole_is_seen_and_never_assumed_to_fill_itself() {
        let mut tracker = tracker(39);
        assert_eq!(
            tracker.inspect(41),
            AcceptOutcome::Gap {
                expected: 40,
                received: 41
            }
        );
        // E non si può segnarlo applicato saltando ciò che manca.
        assert!(!tracker.applied(41));
        assert_eq!(tracker.cursor().last_applied, 39);
        // Il passo successivo è chiedere ciò che manca.
        assert_eq!(
            tracker.next_step(41),
            NextStep::RequestPage {
                after: 39,
                limit: CATCH_UP_PAGE
            }
        );
    }

    #[test]
    fn a_duplicate_advances_nothing_and_is_not_an_error() {
        let mut tracker = tracker(40);
        assert_eq!(tracker.inspect(40), AcceptOutcome::Duplicate);
        assert_eq!(tracker.inspect(1), AcceptOutcome::Duplicate);
        assert!(!tracker.applied(40));
        assert_eq!(tracker.cursor().last_applied, 40);
    }

    #[test]
    fn a_client_that_never_saw_anything_starts_from_the_first() {
        let mut tracker = tracker(0);
        assert_eq!(tracker.inspect(1), AcceptOutcome::Next);
        assert_eq!(
            tracker.next_step(3),
            NextStep::RequestPage {
                after: 0,
                limit: CATCH_UP_PAGE
            }
        );
        assert!(tracker.applied(1));
        assert!(tracker.applied(2));
        assert!(tracker.applied(3));
        assert_eq!(tracker.next_step(3), NextStep::Live);
    }

    #[test]
    fn being_aligned_is_being_live_and_staying_live_is_checked_event_by_event() {
        let mut tracker = tracker(10);
        assert_eq!(tracker.next_step(10), NextStep::Live);
        // In diretta arriva l'undicesimo: bene.
        assert_eq!(tracker.inspect(11), AcceptOutcome::Next);
        assert!(tracker.applied(11));
        // Poi arriva il tredicesimo: la diretta non basta a fidarsi.
        assert_eq!(
            tracker.inspect(13),
            AcceptOutcome::Gap {
                expected: 12,
                received: 13
            }
        );
    }

    #[test]
    fn stopping_says_the_fact_without_proposing_to_go_on() {
        for stop in [CatchUpStop::StreamChanged, CatchUpStop::HubWentBackwards] {
            let frase = stop.operator_message();
            assert!(frase.contains("si ferma qui"));
            let minuscolo = frase.to_lowercase();
            assert!(!minuscolo.contains("comunque"));
            assert!(!minuscolo.contains("ignora"));
        }
    }
}

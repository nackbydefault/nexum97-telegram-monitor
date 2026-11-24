//! Macchina a stati dell'autorizzazione.
//!
//! Gli stati ricalcano quelli che TDLib comunica durante l'accesso, ma il tipo è
//! nostro: il resto dell'applicazione non deve conoscere le strutture della
//! libreria. Le transizioni non ammesse sono **rifiutate** con un errore
//! tipizzato e non ignorate, perché una transizione inattesa durante un accesso
//! è un fatto da registrare, non un evento da assorbire in silenzio.

use core::fmt;

use crate::error::{TelegramError, TelegramResult};

/// Stato dell'autorizzazione dell'account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorizationState {
    /// Il client non è ancora stato avviato.
    Uninitialized,
    /// La libreria attende i parametri di configurazione.
    WaitingForTdlibParameters,
    /// La libreria attende il numero di telefono.
    WaitingForPhoneNumber,
    /// La libreria attende il codice ricevuto.
    WaitingForCode,
    /// La libreria attende la password della verifica in due passaggi.
    WaitingForPassword,
    /// L'account è autorizzato e operativo.
    Ready,
    /// È in corso l'arresto ordinato.
    Closing,
    /// Il client è chiuso.
    Closed,
    /// L'autorizzazione è fallita in modo non recuperabile.
    Failed,
}

impl AuthorizationState {
    /// Tutte le varianti, per test e per l'interfaccia.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Uninitialized,
            Self::WaitingForTdlibParameters,
            Self::WaitingForPhoneNumber,
            Self::WaitingForCode,
            Self::WaitingForPassword,
            Self::Ready,
            Self::Closing,
            Self::Closed,
            Self::Failed,
        ]
    }

    /// Etichetta stabile, usata nei messaggi di errore e nell'audit.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Uninitialized => "uninitialized",
            Self::WaitingForTdlibParameters => "waiting_for_tdlib_parameters",
            Self::WaitingForPhoneNumber => "waiting_for_phone_number",
            Self::WaitingForCode => "waiting_for_code",
            Self::WaitingForPassword => "waiting_for_password",
            Self::Ready => "ready",
            Self::Closing => "closing",
            Self::Closed => "closed",
            Self::Failed => "failed",
        }
    }

    /// Se lo stato è terminale.
    #[must_use]
    pub const fn is_final(self) -> bool {
        matches!(self, Self::Closed | Self::Failed)
    }

    /// Se lo stato attende un dato dall'operatore.
    #[must_use]
    pub const fn awaits_operator_input(self) -> bool {
        matches!(
            self,
            Self::WaitingForPhoneNumber | Self::WaitingForCode | Self::WaitingForPassword
        )
    }

    /// Se la transizione verso `next` è ammessa.
    ///
    /// L'arresto ordinato è raggiungibile da ogni stato non terminale: un
    /// operatore deve poter interrompere l'accesso in qualunque momento. Il
    /// fallimento pure, perché la libreria può segnalarlo in ogni fase.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        if self.is_final() {
            return false;
        }
        if matches!(next, Self::Closing | Self::Failed) {
            return !matches!(self, Self::Closing) || matches!(next, Self::Failed);
        }

        matches!(
            (self, next),
            (Self::Uninitialized, Self::WaitingForTdlibParameters)
                | (Self::WaitingForTdlibParameters, Self::WaitingForPhoneNumber)
                // Ripresa di una sessione gia' autorizzata: quando il binlog
                // TDLib contiene una sessione valida, la libreria risponde a
                // `setTdlibParameters` saltando dritta a `ready`, senza
                // richiedere numero ne' codice. E' il percorso normale di
                // **ogni** avvio successivo al primo accesso riuscito, non
                // un'eccezione. Finche' questa transizione mancava,
                // l'aggiornamento veniva scartato come "inatteso" e la
                // macchina restava ferma su `waiting_for_tdlib_parameters`,
                // stato che ammette il solo `Cancel`: l'interfaccia appariva
                // bloccata, senza campo del numero e senza via d'uscita
                // (osservato il 2026-07-30, riga di registro
                // `transizione di autorizzazione inattesa: ignorata
                // from="waiting_for_tdlib_parameters" to="ready"`).
                | (Self::WaitingForTdlibParameters, Self::Ready)
                | (Self::WaitingForPhoneNumber, Self::WaitingForCode)
                // Telegram puo' richiedere la password dopo il codice, oppure
                // concludere l'accesso senza chiederla se la verifica in due
                // passaggi non e' attiva.
                | (Self::WaitingForCode, Self::WaitingForPassword | Self::Ready)
                // Un numero sbagliato riporta alla richiesta del numero.
                | (Self::WaitingForCode, Self::WaitingForPhoneNumber)
                | (Self::WaitingForPassword, Self::Ready)
                | (Self::Closing, Self::Closed)
        )
    }
}

impl fmt::Display for AuthorizationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Macchina a stati che sorveglia le transizioni.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationMachine {
    state: AuthorizationState,
    history: Vec<AuthorizationState>,
}

impl AuthorizationMachine {
    /// Numero massimo di transizioni conservate nella cronologia.
    ///
    /// La cronologia serve alla diagnostica di un accesso, non a essere un
    /// registro: senza un limite crescerebbe indefinitamente in una sessione
    /// lunga con molte riconnessioni.
    pub const HISTORY_LIMIT: usize = 64;

    /// Crea la macchina nello stato iniziale.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: AuthorizationState::Uninitialized,
            history: vec![AuthorizationState::Uninitialized],
        }
    }

    /// Stato corrente.
    #[must_use]
    pub const fn state(&self) -> AuthorizationState {
        self.state
    }

    /// Cronologia degli stati attraversati, dal più antico.
    #[must_use]
    pub fn history(&self) -> &[AuthorizationState] {
        &self.history
    }

    /// Applica una transizione.
    ///
    /// # Errori
    ///
    /// Restituisce [`TelegramError::InvalidAuthorizationTransition`] se la
    /// transizione non è ammessa. Lo stato corrente resta invariato.
    pub fn transition_to(&mut self, next: AuthorizationState) -> TelegramResult<()> {
        if !self.state.can_transition_to(next) {
            return Err(TelegramError::InvalidAuthorizationTransition {
                from: self.state.as_str(),
                to: next.as_str(),
            });
        }

        self.state = next;
        if self.history.len() == Self::HISTORY_LIMIT {
            self.history.remove(0);
        }
        self.history.push(next);
        Ok(())
    }

    /// Verifica che lo stato corrente sia quello atteso.
    ///
    /// # Errori
    ///
    /// Restituisce [`TelegramError::UnexpectedAuthorizationState`] altrimenti.
    pub const fn expect_state(&self, expected: AuthorizationState) -> TelegramResult<()> {
        if self.state as u8 != expected as u8 {
            return Err(TelegramError::UnexpectedAuthorizationState {
                state: self.state.as_str(),
                expected: expected.as_str(),
            });
        }
        Ok(())
    }
}

impl Default for AuthorizationMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthorizationMachine, AuthorizationState};
    use crate::error::TelegramError;

    #[test]
    fn all_nine_required_states_are_present() {
        assert_eq!(AuthorizationState::all().len(), 9);
    }

    #[test]
    fn every_state_has_a_distinct_stable_label() {
        for (index, state) in AuthorizationState::all().iter().enumerate() {
            assert!(!state.as_str().is_empty());
            for other in AuthorizationState::all().iter().skip(index + 1) {
                assert_ne!(state.as_str(), other.as_str());
            }
        }
    }

    #[test]
    fn the_nominal_login_without_two_factor_reaches_ready() {
        let mut machine = AuthorizationMachine::new();
        for state in [
            AuthorizationState::WaitingForTdlibParameters,
            AuthorizationState::WaitingForPhoneNumber,
            AuthorizationState::WaitingForCode,
            AuthorizationState::Ready,
        ] {
            let Ok(()) = machine.transition_to(state) else {
                panic!("la transizione verso {state} doveva essere ammessa");
            };
        }
        assert_eq!(machine.state(), AuthorizationState::Ready);
    }

    #[test]
    fn the_login_with_two_factor_passes_through_the_password() {
        let mut machine = AuthorizationMachine::new();
        for state in [
            AuthorizationState::WaitingForTdlibParameters,
            AuthorizationState::WaitingForPhoneNumber,
            AuthorizationState::WaitingForCode,
            AuthorizationState::WaitingForPassword,
            AuthorizationState::Ready,
        ] {
            let Ok(()) = machine.transition_to(state) else {
                panic!("la transizione verso {state} doveva essere ammessa");
            };
        }
        assert_eq!(machine.state(), AuthorizationState::Ready);
    }

    #[test]
    fn a_wrong_number_returns_to_the_phone_number_request() {
        let mut machine = AuthorizationMachine::new();
        for state in [
            AuthorizationState::WaitingForTdlibParameters,
            AuthorizationState::WaitingForPhoneNumber,
            AuthorizationState::WaitingForCode,
            AuthorizationState::WaitingForPhoneNumber,
        ] {
            let Ok(()) = machine.transition_to(state) else {
                panic!("la transizione verso {state} doveva essere ammessa");
            };
        }
        assert_eq!(machine.state(), AuthorizationState::WaitingForPhoneNumber);
    }

    #[test]
    fn a_skipped_step_is_refused_and_leaves_the_state_untouched() {
        let mut machine = AuthorizationMachine::new();

        let refused = machine.transition_to(AuthorizationState::Ready);
        assert!(matches!(
            refused,
            Err(TelegramError::InvalidAuthorizationTransition {
                from: "uninitialized",
                to: "ready"
            })
        ));
        assert_eq!(machine.state(), AuthorizationState::Uninitialized);
    }

    #[test]
    fn the_code_cannot_be_requested_before_the_phone_number() {
        let mut machine = AuthorizationMachine::new();
        let Ok(()) = machine.transition_to(AuthorizationState::WaitingForTdlibParameters) else {
            panic!("la prima transizione doveva essere ammessa");
        };

        assert!(matches!(
            machine.transition_to(AuthorizationState::WaitingForCode),
            Err(TelegramError::InvalidAuthorizationTransition { .. })
        ));
    }

    /// Regressione diretta del pilot del 2026-07-30: riavviando l'applicazione
    /// dopo un accesso riuscito, TDLib legge il proprio binlog e risponde a
    /// `setTdlibParameters` saltando dritta a `ready`, senza richiedere numero
    /// ne' codice. Finche' la tabella non ammetteva quel salto, l'aggiornamento
    /// veniva scartato come "inatteso" e la macchina restava ferma su
    /// `waiting_for_tdlib_parameters` - stato che ammette il solo `Cancel` -
    /// con l'interfaccia bloccata e nessun campo del numero. La tabella
    /// modellava soltanto il **primo** accesso, non la ripresa, che e' il
    /// percorso normale di ogni avvio successivo.
    #[test]
    fn a_restored_session_may_jump_from_the_parameters_straight_to_ready() {
        assert!(
            AuthorizationState::WaitingForTdlibParameters
                .can_transition_to(AuthorizationState::Ready),
            "una sessione gia' autorizzata nel binlog deve poter riprendere \
             senza ripassare da numero e codice"
        );

        let mut machine = AuthorizationMachine::new();
        let Ok(()) = machine.transition_to(AuthorizationState::WaitingForTdlibParameters) else {
            panic!("la prima transizione doveva essere ammessa");
        };
        let Ok(()) = machine.transition_to(AuthorizationState::Ready) else {
            panic!("la ripresa della sessione doveva essere ammessa");
        };
        assert_eq!(machine.state(), AuthorizationState::Ready);
    }

    /// La transizione aggiunta per la ripresa non deve allargare la macchina
    /// oltre il necessario: restano vietati i salti che nessun percorso reale
    /// di TDLib produce, e in particolare quello che scavalcherebbe del tutto
    /// la configurazione.
    #[test]
    fn the_resume_shortcut_does_not_open_any_other_jump_to_ready() {
        assert!(
            !AuthorizationState::Uninitialized.can_transition_to(AuthorizationState::Ready),
            "senza aver nemmeno configurato la libreria non si puo' essere pronti"
        );
        assert!(
            !AuthorizationState::WaitingForPhoneNumber.can_transition_to(AuthorizationState::Ready),
            "dal numero si passa sempre dal codice"
        );
    }

    #[test]
    fn the_orderly_shutdown_is_reachable_from_every_non_final_state() {
        for state in AuthorizationState::all() {
            if state.is_final() {
                continue;
            }
            if *state == AuthorizationState::Closing {
                continue;
            }
            assert!(
                state.can_transition_to(AuthorizationState::Closing),
                "da {state} deve essere possibile avviare l'arresto"
            );
        }
    }

    #[test]
    fn a_failure_is_reachable_from_every_non_final_state() {
        for state in AuthorizationState::all() {
            if state.is_final() {
                continue;
            }
            assert!(
                state.can_transition_to(AuthorizationState::Failed),
                "da {state} la libreria deve poter segnalare un fallimento"
            );
        }
    }

    #[test]
    fn no_transition_leaves_a_final_state() {
        for terminal in [AuthorizationState::Closed, AuthorizationState::Failed] {
            assert!(terminal.is_final());
            for next in AuthorizationState::all() {
                assert!(
                    !terminal.can_transition_to(*next),
                    "da {terminal} non deve essere possibile passare a {next}"
                );
            }
        }
    }

    #[test]
    fn a_closed_client_refuses_to_restart() {
        let mut machine = AuthorizationMachine::new();
        for state in [AuthorizationState::Closing, AuthorizationState::Closed] {
            let Ok(()) = machine.transition_to(state) else {
                panic!("la transizione verso {state} doveva essere ammessa");
            };
        }

        assert!(matches!(
            machine.transition_to(AuthorizationState::WaitingForTdlibParameters),
            Err(TelegramError::InvalidAuthorizationTransition { from: "closed", .. })
        ));
    }

    #[test]
    fn only_the_waiting_states_ask_the_operator_for_something() {
        for state in AuthorizationState::all() {
            let expected = matches!(
                state,
                AuthorizationState::WaitingForPhoneNumber
                    | AuthorizationState::WaitingForCode
                    | AuthorizationState::WaitingForPassword
            );
            assert_eq!(state.awaits_operator_input(), expected, "stato {state}");
        }
    }

    #[test]
    fn the_expected_state_check_names_both_states_without_any_secret() {
        let machine = AuthorizationMachine::new();
        let Err(error) = machine.expect_state(AuthorizationState::Ready) else {
            panic!("lo stato atteso doveva risultare diverso");
        };
        let rendered = error.to_string();

        assert!(rendered.contains("uninitialized"));
        assert!(rendered.contains("ready"));
    }

    #[test]
    fn the_history_records_the_path_and_does_not_grow_without_bound() {
        let mut machine = AuthorizationMachine::new();
        for _ in 0..(AuthorizationMachine::HISTORY_LIMIT * 2) {
            // Alternanza ammessa fra richiesta del codice e del numero.
            let _ = machine.transition_to(AuthorizationState::WaitingForTdlibParameters);
            let _ = machine.transition_to(AuthorizationState::WaitingForPhoneNumber);
            let _ = machine.transition_to(AuthorizationState::WaitingForCode);
            let _ = machine.transition_to(AuthorizationState::WaitingForPhoneNumber);
        }

        assert!(machine.history().len() <= AuthorizationMachine::HISTORY_LIMIT);
        assert!(!machine.history().is_empty());
    }
}

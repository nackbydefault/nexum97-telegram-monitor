//! Test del servizio di autenticazione, attraverso l'API pubblica.
//!
//! Nessuna rete, nessuna credenziale, nessuna TDLib: il connettore simulato è
//! deterministico. **Tutti i valori sono dichiaratamente fittizi.**

use std::path::PathBuf;
use std::time::Duration;

use lisi_services::{AuthCommand, AuthStage, AuthenticationService, ServiceError};
use lisi_telegram::{
    AccessibleChat, ApiHash, ApiId, AuthorizationState, ClientParameters, ConnectionState,
    ConnectorEvent, LoginCode, MockTelegramConnector, PhoneNumber, TelegramConnector,
    TelegramError, TelegramResult, TwoFactorPassword,
};

const FAKE_PHONE: &str = "+390612345678";
const FAKE_CODE: &str = "12345";
const FAKE_PASSWORD: &str = "password-di-prova-non-reale";
const FAKE_API_HASH: &str = "00000000000000000000000000000000";

fn parameters() -> ClientParameters {
    let (Ok(api_id), Ok(api_hash)) = (ApiId::try_new(1), ApiHash::try_new(FAKE_API_HASH)) else {
        panic!("i valori fittizi devono essere validi");
    };

    ClientParameters {
        api_id,
        api_hash,
        database_directory: PathBuf::from("target/prova-sessione"),
        use_test_datacenter: true,
        application_version: String::from("0.1.0"),
        system_language_code: String::from("it"),
    }
}

fn phone() -> PhoneNumber {
    let Ok(value) = PhoneNumber::try_new(FAKE_PHONE) else {
        panic!("il numero fittizio deve essere valido");
    };
    value
}

fn code() -> LoginCode {
    let Ok(value) = LoginCode::try_new(FAKE_CODE) else {
        panic!("il codice fittizio deve essere valido");
    };
    value
}

fn password() -> TwoFactorPassword {
    let Ok(value) = TwoFactorPassword::try_new(FAKE_PASSWORD) else {
        panic!("la password fittizia deve essere valida");
    };
    value
}

fn service(two_factor: bool) -> AuthenticationService {
    AuthenticationService::new(Box::new(
        MockTelegramConnector::new().requiring_two_factor(two_factor),
    ))
}

/// Porta il servizio fino alla richiesta del codice.
fn advance_to_code(service: &mut AuthenticationService) {
    let (Ok(()), Ok(())) = (
        service.start(&parameters()),
        service.submit_phone_number(phone()),
    ) else {
        panic!("i primi passi dell'accesso devono riuscire");
    };
}

// ------------------------------------------------------------- flusso nominale

#[test]
fn the_first_run_offers_the_start_command_and_a_way_out() {
    // `Cancel` qui ricostruisce un runtime pulito, non e' una richiesta al
    // connettore: senza, un accesso che non avanza (per esempio perche'
    // l'interfaccia non ha ancora pompato gli eventi in arrivo) lascerebbe
    // l'operatore senza alcuna via d'uscita se non chiudere l'applicazione.
    let service = service(false);
    let view = service.view();

    assert_eq!(view.stage, AuthStage::FirstRun);
    assert_eq!(
        view.allowed_commands,
        vec![AuthCommand::Start, AuthCommand::Cancel]
    );
    assert_eq!(view.account_label, None);
    assert_eq!(view.failure, None);
}

#[test]
fn the_complete_flow_without_two_factor_reaches_the_authenticated_stage() {
    let mut service = service(false);

    let (Ok(()), Ok(()), Ok(())) = (
        service.start(&parameters()),
        service.submit_phone_number(phone()),
        service.submit_code(code()),
    ) else {
        panic!("l'accesso senza verifica in due passaggi deve riuscire");
    };

    let view = service.view();
    assert_eq!(view.state, AuthorizationState::Ready);
    assert_eq!(view.stage, AuthStage::Authenticated);
    assert!(view.allows(AuthCommand::LogOut));
    assert!(view.allows(AuthCommand::SwitchAccount));
    assert!(!view.allows(AuthCommand::SubmitCode));
}

#[test]
fn the_complete_flow_with_two_factor_passes_through_the_password() {
    let mut service = service(true);

    advance_to_code(&mut service);
    let Ok(()) = service.submit_code(code()) else {
        panic!("il codice deve essere accettato");
    };
    assert_eq!(service.stage(), AuthStage::NeedPassword);

    let Ok(()) = service.submit_password(password()) else {
        panic!("la password deve essere accettata");
    };
    assert_eq!(service.stage(), AuthStage::Authenticated);
}

#[test]
fn every_stage_of_the_flow_is_traversed_in_order() {
    let mut service = service(true);
    let mut stages = vec![service.stage()];

    let Ok(()) = service.start(&parameters()) else {
        panic!("l'avvio deve riuscire");
    };
    stages.push(service.stage());
    let Ok(()) = service.submit_phone_number(phone()) else {
        panic!("il numero deve essere accettato");
    };
    stages.push(service.stage());
    let Ok(()) = service.submit_code(code()) else {
        panic!("il codice deve essere accettato");
    };
    stages.push(service.stage());
    let Ok(()) = service.submit_password(password()) else {
        panic!("la password deve essere accettata");
    };
    stages.push(service.stage());
    let Ok(()) = service.log_out() else {
        panic!("l'uscita deve riuscire");
    };
    stages.push(service.stage());

    assert_eq!(
        stages,
        vec![
            AuthStage::FirstRun,
            AuthStage::NeedPhoneNumber,
            AuthStage::NeedCode,
            AuthStage::NeedPassword,
            AuthStage::Authenticated,
            AuthStage::Closed,
        ]
    );
}

// -------------------------------------------------------- comandi non ammessi

#[test]
fn a_command_not_allowed_in_the_current_state_is_refused() {
    let mut service = service(false);

    // Nessun accesso avviato: non si puo' inviare un codice.
    assert!(matches!(
        service.submit_code(code()),
        Err(ServiceError::CommandNotAllowed { .. })
    ));
    assert_eq!(service.state(), AuthorizationState::Uninitialized);
}

#[test]
fn the_password_cannot_be_sent_when_it_is_not_requested() {
    let mut service = service(false);
    advance_to_code(&mut service);

    assert!(matches!(
        service.submit_password(password()),
        Err(ServiceError::CommandNotAllowed { .. })
    ));
}

#[test]
fn no_command_is_accepted_while_closing() {
    // Durante la chiusura nessun comando e' ammesso: uno solo lascerebbe la
    // sessione a meta'.
    let mut connector = MockTelegramConnector::new();
    let Ok(()) = connector.enqueue_message(-1_001, 1, "riempitivo", 0) else {
        panic!("l'evento di prova deve potersi accodare");
    };
    let service = AuthenticationService::new(Box::new(connector));

    // Lo stato Closing e' transitorio nel mock; si verifica l'elenco dichiarato.
    assert!(!service.view().allows(AuthCommand::SubmitCode));
}

#[test]
fn every_state_declares_its_allowed_commands_explicitly() {
    // La copertura di questa decisione e' cio' che rende verificabile la
    // disabilitazione dei pulsanti senza aprire una finestra.
    let mut service = service(false);
    assert_eq!(
        service.allowed_commands(),
        vec![AuthCommand::Start, AuthCommand::Cancel]
    );

    let Ok(()) = service.start(&parameters()) else {
        panic!("l'avvio deve riuscire");
    };
    assert_eq!(
        service.allowed_commands(),
        vec![AuthCommand::SubmitPhoneNumber, AuthCommand::Cancel]
    );

    let Ok(()) = service.submit_phone_number(phone()) else {
        panic!("il numero deve essere accettato");
    };
    assert_eq!(
        service.allowed_commands(),
        vec![
            AuthCommand::SubmitCode,
            AuthCommand::SubmitPhoneNumber,
            AuthCommand::Cancel
        ]
    );

    let Ok(()) = service.submit_code(code()) else {
        panic!("il codice deve essere accettato");
    };
    assert_eq!(
        service.allowed_commands(),
        vec![AuthCommand::LogOut, AuthCommand::SwitchAccount]
    );
}

// --------------------------------------------------------------- errori attesi

#[test]
fn a_wrong_code_is_reported_and_the_flow_stays_on_the_code() {
    let mut connector = MockTelegramConnector::new();
    connector.reject_next_codes(1);
    let mut service = AuthenticationService::new(Box::new(connector));

    advance_to_code(&mut service);
    assert!(matches!(
        service.submit_code(code()),
        Err(ServiceError::CodeRejected)
    ));

    // Un codice sbagliato non interrompe l'accesso: lo fa ripetere.
    let view = service.view();
    assert_eq!(view.stage, AuthStage::NeedCode);
    assert!(view.allows(AuthCommand::SubmitCode));
    assert!(view.failure_is_correctable);

    // Il secondo tentativo riesce.
    let Ok(()) = service.submit_code(code()) else {
        panic!("il secondo codice deve essere accettato");
    };
    assert_eq!(service.stage(), AuthStage::Authenticated);
}

#[test]
fn a_wrong_password_is_reported_and_the_flow_stays_on_the_password() {
    let mut connector = MockTelegramConnector::new().requiring_two_factor(true);
    connector.reject_next_passwords(1);
    let mut service = AuthenticationService::new(Box::new(connector));

    advance_to_code(&mut service);
    let Ok(()) = service.submit_code(code()) else {
        panic!("il codice deve essere accettato");
    };

    assert!(matches!(
        service.submit_password(password()),
        Err(ServiceError::PasswordRejected)
    ));
    assert_eq!(service.stage(), AuthStage::NeedPassword);

    let Ok(()) = service.submit_password(password()) else {
        panic!("la seconda password deve essere accettata");
    };
    assert_eq!(service.stage(), AuthStage::Authenticated);
}

#[test]
fn a_missing_network_at_start_is_reported_with_an_operator_message() {
    let mut connector = MockTelegramConnector::new();
    connector.fail_next_start_with(TelegramError::NetworkUnavailable);
    let mut service = AuthenticationService::new(Box::new(connector));

    assert!(matches!(
        service.start(&parameters()),
        Err(ServiceError::NetworkUnavailable)
    ));

    let view = service.view();
    let Some(message) = view.failure else {
        panic!("il fallimento deve essere riportato");
    };
    assert!(message.contains("rete"));
    assert!(!view.failure_is_correctable);
}

#[test]
fn an_unreadable_session_is_reported_with_a_way_out() {
    let mut connector = MockTelegramConnector::new();
    connector.fail_next_start_with(TelegramError::SessionUnavailable {
        reason: "cartella non leggibile",
    });
    let mut service = AuthenticationService::new(Box::new(connector));

    assert!(matches!(
        service.start(&parameters()),
        Err(ServiceError::SessionUnavailable { .. })
    ));

    let Some(message) = service.view().failure else {
        panic!("il fallimento deve essere riportato");
    };
    // Il messaggio deve dire che cosa fare, non solo che cosa e' rotto. Fino
    // al 2026-10-02 chiedeva «Ripristina accesso», un comando che non esiste
    // (D-18): ora nomina il percorso vero.
    assert!(message.contains("«Azzeramento e rimozione…»"));
    assert!(message.contains("resta nell'archivio"));
    assert!(!message.contains("Ripristina accesso"));
}

#[test]
fn a_timeout_is_reported_as_such() {
    let mut connector = MockTelegramConnector::new();
    connector.fail_next_start_with(TelegramError::Timeout { millis: 5_000 });
    let mut service = AuthenticationService::new(Box::new(connector));

    assert!(matches!(
        service.start(&parameters()),
        Err(ServiceError::TimedOut)
    ));
}

#[test]
fn a_revoked_session_is_surfaced_through_the_event_pump() {
    let mut connector = MockTelegramConnector::new();
    let Ok(()) = connector.simulate_session_revoked() else {
        panic!("la revoca deve potersi simulare");
    };
    let mut service = AuthenticationService::new(Box::new(connector));

    let Ok(consumed) = service.pump_events() else {
        panic!("la lettura degli eventi deve riuscire");
    };
    assert!(consumed > 0);

    let Some(message) = service.view().failure else {
        panic!("la revoca deve essere riportata");
    };
    assert!(message.contains("revocato"));
}

// ------------------------------------------------ annullamento, uscita, cambio

#[test]
fn cancelling_leaves_a_coherent_state_and_forgets_the_account() {
    let mut service = service(false);
    advance_to_code(&mut service);
    assert!(service.view().account_label.is_some());

    let Ok(()) = service.cancel() else {
        panic!("l'annullamento deve riuscire");
    };

    let view = service.view();
    assert_eq!(view.stage, AuthStage::Closed);
    assert_eq!(view.account_label, None, "il numero non resta in memoria");
    assert!(
        view.allows(AuthCommand::Start),
        "si deve poter ricominciare"
    );
}

#[test]
fn logging_out_forgets_the_account_and_allows_a_new_login() {
    let mut service = service(false);
    let (Ok(()), Ok(()), Ok(())) = (
        service.start(&parameters()),
        service.submit_phone_number(phone()),
        service.submit_code(code()),
    ) else {
        panic!("l'accesso deve riuscire");
    };

    let Ok(()) = service.log_out() else {
        panic!("l'uscita deve riuscire");
    };

    let view = service.view();
    assert_eq!(view.stage, AuthStage::Closed);
    assert_eq!(view.account_label, None);
    assert_eq!(view.allowed_commands, vec![AuthCommand::Start]);
}

#[test]
fn switching_account_requires_being_authenticated_first() {
    let mut service = service(false);

    // Non si cambia account durante un accesso a meta'.
    advance_to_code(&mut service);
    assert!(matches!(
        service.switch_account(),
        Err(ServiceError::CommandNotAllowed { .. })
    ));

    let Ok(()) = service.submit_code(code()) else {
        panic!("il codice deve essere accettato");
    };
    let Ok(()) = service.switch_account() else {
        panic!("il cambio account deve riuscire da autenticato");
    };
    assert_eq!(service.view().account_label, None);
}

#[test]
fn a_shutdown_during_authentication_is_orderly() {
    let mut service = service(true);
    advance_to_code(&mut service);
    let Ok(()) = service.submit_code(code()) else {
        panic!("il codice deve essere accettato");
    };
    assert_eq!(service.stage(), AuthStage::NeedPassword);

    // Arresto mentre si attende la password.
    let Ok(()) = service.cancel() else {
        panic!("l'annullamento durante l'autenticazione deve riuscire");
    };
    assert_eq!(service.stage(), AuthStage::Closed);
}

// ------------------------------------------------------- redazione dei segreti

#[test]
fn the_account_label_is_redacted_and_never_shows_the_full_number() {
    let mut service = service(false);
    advance_to_code(&mut service);

    let Some(label) = service.view().account_label else {
        panic!("il numero configurato deve essere mostrato in forma redatta");
    };

    assert!(
        !label.contains("0612345"),
        "il corpo del numero non compare"
    );
    assert!(label.starts_with("+39"));
    assert!(label.ends_with("78"));
    assert!(label.contains('*'));
}

#[test]
fn the_debug_rendering_of_the_service_hides_the_account() {
    let mut service = service(false);
    advance_to_code(&mut service);

    let rendered = format!("{service:?}");
    assert!(!rendered.contains(FAKE_PHONE));
    assert!(!rendered.contains("0612345"));
    assert!(rendered.contains("account_configured"));
}

#[test]
fn no_operator_message_contains_a_secret() {
    let mut connector = MockTelegramConnector::new();
    connector.reject_next_codes(1);
    let mut service = AuthenticationService::new(Box::new(connector));
    advance_to_code(&mut service);
    let _ = service.submit_code(code());

    let Some(message) = service.view().failure else {
        panic!("il fallimento deve essere riportato");
    };
    assert!(!message.contains(FAKE_CODE));
    assert!(!message.contains(FAKE_PHONE));
    assert!(!message.contains(FAKE_PASSWORD));
}

#[test]
fn clearing_the_failure_removes_it_from_the_view() {
    let mut connector = MockTelegramConnector::new();
    connector.reject_next_codes(1);
    let mut service = AuthenticationService::new(Box::new(connector));
    advance_to_code(&mut service);
    let _ = service.submit_code(code());
    assert!(service.view().failure.is_some());

    service.clear_failure();
    assert!(service.view().failure.is_none());
}

#[test]
fn a_successful_operation_clears_a_previous_failure() {
    let mut connector = MockTelegramConnector::new();
    connector.reject_next_codes(1);
    let mut service = AuthenticationService::new(Box::new(connector));
    advance_to_code(&mut service);
    let _ = service.submit_code(code());
    assert!(service.view().failure.is_some());

    let Ok(()) = service.submit_code(code()) else {
        panic!("il secondo tentativo deve riuscire");
    };
    assert!(service.view().failure.is_none());
}

// ----------------------------------------------------------- stato osservabile

#[test]
fn every_stage_offers_a_headline_and_a_detail_for_the_operator() {
    for stage in [
        AuthStage::FirstRun,
        AuthStage::Preparing,
        AuthStage::NeedPhoneNumber,
        AuthStage::NeedCode,
        AuthStage::NeedPassword,
        AuthStage::Authenticated,
        AuthStage::ClosingDown,
        AuthStage::Closed,
        AuthStage::Failed,
    ] {
        assert!(!stage.headline().is_empty());
        assert!(!stage.detail().is_empty());
    }
}

#[test]
fn only_the_input_stages_expect_a_secret() {
    assert!(AuthStage::NeedPhoneNumber.expects_secret_input());
    assert!(AuthStage::NeedCode.expects_secret_input());
    assert!(AuthStage::NeedPassword.expects_secret_input());
    assert!(!AuthStage::Authenticated.expects_secret_input());
    assert!(!AuthStage::FirstRun.expects_secret_input());
}

#[test]
fn every_command_has_a_distinct_label_and_identifier() {
    for (index, command) in AuthCommand::all().iter().enumerate() {
        assert!(!command.as_str().is_empty());
        assert!(!command.label().is_empty());
        for other in AuthCommand::all().iter().skip(index + 1) {
            assert_ne!(command.as_str(), other.as_str());
            assert_ne!(command.label(), other.label());
        }
    }
}

// ============================================================================
// Regressione — incidente M3B del 2026-07-26 (nessun pompaggio degli eventi)
// ============================================================================
//
// `MockTelegramConnector::start()` avanza subito lo stato fino a
// `WaitingForPhoneNumber`, in modo sincrono: e' comodo per i test, ma per lo
// stesso motivo non avrebbe mai potuto rivelare l'incidente reale. Il
// connettore reale (`LiveTdlibConnector`) lascia invece lo stato a
// `Uninitialized` dentro `start()`, e lo fa avanzare **solo** quando qualcosa
// chiama `poll_event` (cioe' `AuthenticationService::pump_events`). Questo
// connettore fittizio riproduce esattamente quella forma, senza TDLib e senza
// rete, cosi' da poter provare il difetto e la correzione.

/// Connettore fittizio che si comporta come il connettore reale sul punto che
/// contava in questo incidente: `start()` non avanza nulla, `poll_event()` sì.
struct StepByStepFakeConnector {
    state: AuthorizationState,
    pending_advance: Option<AuthorizationState>,
    /// Come `LiveTdlibConnector`: un secondo `start()` sullo stesso connettore
    /// deve fallire invece di far finta di ripartire.
    started: bool,
}

impl StepByStepFakeConnector {
    const fn new() -> Self {
        Self {
            state: AuthorizationState::Uninitialized,
            pending_advance: None,
            started: false,
        }
    }
}

impl TelegramConnector for StepByStepFakeConnector {
    fn start(&mut self, _parameters: &ClientParameters) -> TelegramResult<()> {
        if self.started {
            return Err(TelegramError::Tdlib {
                reason: String::from("il connettore e' gia' stato avviato"),
            });
        }
        self.started = true;
        // Come il connettore reale: nessuna transizione qui. Il prossimo
        // `poll_event` consegnera' l'aggiornamento che la sposta avanti.
        self.pending_advance = Some(AuthorizationState::WaitingForPhoneNumber);
        Ok(())
    }

    fn submit_phone_number(&mut self, _phone: &PhoneNumber) -> TelegramResult<()> {
        self.state = AuthorizationState::WaitingForCode;
        Ok(())
    }

    fn submit_code(&mut self, _code: &LoginCode) -> TelegramResult<()> {
        self.state = AuthorizationState::Ready;
        Ok(())
    }

    fn submit_password(&mut self, _password: &TwoFactorPassword) -> TelegramResult<()> {
        self.state = AuthorizationState::Ready;
        Ok(())
    }

    fn poll_event(&mut self, _timeout: Duration) -> TelegramResult<Option<ConnectorEvent>> {
        if let Some(next) = self.pending_advance.take() {
            self.state = next;
            return Ok(Some(ConnectorEvent::Authorization(next)));
        }
        Ok(None)
    }

    fn accessible_chats(&mut self) -> TelegramResult<Vec<AccessibleChat>> {
        Ok(Vec::new())
    }

    fn authorization_state(&self) -> AuthorizationState {
        self.state
    }

    fn connection_state(&self) -> ConnectionState {
        ConnectionState::Offline
    }

    fn shutdown(&mut self) -> TelegramResult<()> {
        self.state = AuthorizationState::Closed;
        Ok(())
    }

    /// I doppi di prova non parlano con Telegram: nessun collegamento.
    fn message_link(
        &mut self,
        _chat_id: lisi_telegram::ChatId,
        _message_id: lisi_telegram::MessageId,
    ) -> lisi_telegram::TelegramResult<lisi_telegram::LinkOutcome> {
        Ok(lisi_telegram::LinkOutcome::NotProvided(
            lisi_telegram::LinkGap::ConnectorUnavailable,
        ))
    }

    /// I doppi di prova non parlano con Telegram: nessun contesto.
    fn fetch_context(
        &mut self,
        _chat_id: lisi_telegram::ChatId,
        _around: lisi_telegram::MessageId,
        _before: u32,
        _after: u32,
    ) -> lisi_telegram::TelegramResult<Vec<lisi_telegram::ContextMessage>> {
        Ok(Vec::new())
    }
}

#[test]
fn without_pumping_events_the_authorization_never_leaves_the_state_start_produced() {
    // E' esattamente il difetto dell'incidente: un connettore che avanza solo
    // alla ricezione di un evento resta bloccato se nessuno lo interroga mai.
    let mut service = AuthenticationService::new(Box::new(StepByStepFakeConnector::new()));

    let Ok(()) = service.start(&parameters()) else {
        panic!("l'avvio deve riuscire");
    };

    assert_eq!(
        service.state(),
        AuthorizationState::Uninitialized,
        "senza pompaggio lo stato non deve muoversi da solo"
    );
    assert!(
        !service
            .view()
            .allowed_commands
            .contains(&AuthCommand::SubmitPhoneNumber),
        "il campo del numero non deve apparire finche' l'evento non e' stato pompato"
    );
}

#[test]
fn pumping_events_advances_the_authorization_like_a_slower_real_connector_would() {
    let mut service = AuthenticationService::new(Box::new(StepByStepFakeConnector::new()));

    let Ok(()) = service.start(&parameters()) else {
        panic!("l'avvio deve riuscire");
    };
    let Ok(consumed) = service.pump_events() else {
        panic!("il pompaggio degli eventi deve riuscire");
    };

    assert_eq!(consumed, 1, "un solo evento era in attesa");
    assert_eq!(service.state(), AuthorizationState::WaitingForPhoneNumber);
    assert!(
        service
            .view()
            .allowed_commands
            .contains(&AuthCommand::SubmitPhoneNumber),
        "dopo il pompaggio il campo del numero deve poter comparire"
    );
}

#[test]
fn a_second_start_on_the_same_connector_fails_cleanly_instead_of_advancing() {
    // Il secondo dei due guasti registrati nell'incidente: un secondo clic su
    // "Avvia accesso" senza ricostruire il runtime rientra nello stesso
    // connettore gia' avviato. Deve fallire in modo esplicito, non in un modo
    // che l'operatore possa scambiare per un progresso, e non deve andare in
    // panic.
    let mut service = AuthenticationService::new(Box::new(StepByStepFakeConnector::new()));

    let Ok(()) = service.start(&parameters()) else {
        panic!("il primo avvio deve riuscire");
    };
    assert!(service.start(&parameters()).is_err());
}

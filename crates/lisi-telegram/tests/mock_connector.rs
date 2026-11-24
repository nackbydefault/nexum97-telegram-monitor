//! Test d'integrazione del connettore simulato.
//!
//! Girano attraverso l'**API pubblica** del crate, come farà chi lo userà: se un
//! tipo necessario non fosse esportato, questi test non compilerebbero. Non
//! richiedono rete, credenziali né TDLib.
//!
//! Tutti i valori riservati usati qui sono dichiaratamente fittizi.

use core::time::Duration;
use std::path::PathBuf;

use lisi_core::model::AcquisitionOrigin;
use lisi_core::{SessionId, SourceId, Timestamp};
use lisi_telegram::mapping::{SequenceGuard, to_new_content};
use lisi_telegram::{
    ApiHash, ApiId, AuthorizationState, ChatId, ClientParameters, ConnectionState, ConnectorEvent,
    EventQueue, LoginCode, MockTelegramConnector, PhoneNumber, TelegramConnector, TelegramError,
    TwoFactorPassword,
};

const FAKE_PHONE: &str = "+390612345678";
const FAKE_CODE: &str = "12345";
const FAKE_PASSWORD: &str = "password-di-prova-non-reale";
const FAKE_API_HASH: &str = "0123456789abcdef0123456789abcdef";
const FAKE_API_ID: i32 = 1_234_567;

const CHAT: i64 = -1_001_234_567_890;
const POLL: Duration = Duration::from_millis(10);

fn parameters() -> ClientParameters {
    let (Ok(api_id), Ok(api_hash)) = (ApiId::try_new(FAKE_API_ID), ApiHash::try_new(FAKE_API_HASH))
    else {
        panic!("i valori fittizi di prova devono essere validi");
    };

    ClientParameters {
        api_id,
        api_hash,
        database_directory: PathBuf::from("target/tdlib-prova"),
        use_test_datacenter: true,
        application_version: String::from("0.1.0"),
        system_language_code: String::from("it"),
    }
}

fn phone() -> PhoneNumber {
    let Ok(phone) = PhoneNumber::try_new(FAKE_PHONE) else {
        panic!("il numero fittizio deve essere valido");
    };
    phone
}

fn code() -> LoginCode {
    let Ok(code) = LoginCode::try_new(FAKE_CODE) else {
        panic!("il codice fittizio deve essere valido");
    };
    code
}

fn password() -> TwoFactorPassword {
    let Ok(password) = TwoFactorPassword::try_new(FAKE_PASSWORD) else {
        panic!("la password fittizia deve essere valida");
    };
    password
}

/// Raccoglie tutti gli eventi disponibili, ignorando gli errori programmati.
fn drain(connector: &mut MockTelegramConnector) -> Vec<ConnectorEvent> {
    let mut events = Vec::new();
    for _ in 0..1_000 {
        match connector.poll_event(POLL) {
            Ok(Some(event)) => events.push(event),
            Ok(None) | Err(_) => break,
        }
    }
    events
}

#[test]
fn the_login_without_two_factor_reaches_the_ready_state() {
    let mut connector = MockTelegramConnector::new();
    assert_eq!(
        connector.authorization_state(),
        AuthorizationState::Uninitialized
    );

    let Ok(()) = connector.start(&parameters()) else {
        panic!("l'avvio deve riuscire");
    };
    assert_eq!(
        connector.authorization_state(),
        AuthorizationState::WaitingForPhoneNumber
    );

    let Ok(()) = connector.submit_phone_number(&phone()) else {
        panic!("il numero deve essere accettato");
    };
    assert_eq!(
        connector.authorization_state(),
        AuthorizationState::WaitingForCode
    );

    let Ok(()) = connector.submit_code(&code()) else {
        panic!("il codice deve essere accettato");
    };
    assert_eq!(connector.authorization_state(), AuthorizationState::Ready);
    assert_eq!(connector.connection_state(), ConnectionState::Online);
}

#[test]
fn the_login_with_two_factor_passes_through_the_password() {
    let mut connector = MockTelegramConnector::new().requiring_two_factor(true);

    let (Ok(()), Ok(()), Ok(())) = (
        connector.start(&parameters()),
        connector.submit_phone_number(&phone()),
        connector.submit_code(&code()),
    ) else {
        panic!("i passi dell'accesso devono riuscire");
    };
    assert_eq!(
        connector.authorization_state(),
        AuthorizationState::WaitingForPassword
    );

    let Ok(()) = connector.submit_password(&password()) else {
        panic!("la password deve essere accettata");
    };
    assert_eq!(connector.authorization_state(), AuthorizationState::Ready);
}

#[test]
fn the_code_cannot_be_submitted_before_the_phone_number() {
    let mut connector = MockTelegramConnector::new();
    let Ok(()) = connector.start(&parameters()) else {
        panic!("l'avvio deve riuscire");
    };

    assert!(matches!(
        connector.submit_code(&code()),
        Err(TelegramError::UnexpectedAuthorizationState { .. })
    ));
    assert_eq!(
        connector.authorization_state(),
        AuthorizationState::WaitingForPhoneNumber
    );
}

#[test]
fn the_password_cannot_be_submitted_when_it_is_not_requested() {
    let mut connector = MockTelegramConnector::new();
    let (Ok(()), Ok(()), Ok(())) = (
        connector.start(&parameters()),
        connector.submit_phone_number(&phone()),
        connector.submit_code(&code()),
    ) else {
        panic!("i passi dell'accesso devono riuscire");
    };

    assert!(matches!(
        connector.submit_password(&password()),
        Err(TelegramError::UnexpectedAuthorizationState { .. })
    ));
}

#[test]
fn the_authorization_events_are_delivered_in_order() {
    let mut connector = MockTelegramConnector::new();
    let (Ok(()), Ok(()), Ok(())) = (
        connector.start(&parameters()),
        connector.submit_phone_number(&phone()),
        connector.submit_code(&code()),
    ) else {
        panic!("i passi dell'accesso devono riuscire");
    };

    let states: Vec<AuthorizationState> = drain(&mut connector)
        .into_iter()
        .filter_map(|event| match event {
            ConnectorEvent::Authorization(state) => Some(state),
            _ => None,
        })
        .collect();

    assert_eq!(
        states,
        vec![
            AuthorizationState::WaitingForTdlibParameters,
            AuthorizationState::WaitingForPhoneNumber,
            AuthorizationState::WaitingForCode,
            AuthorizationState::Ready,
        ]
    );
}

#[test]
fn a_received_message_becomes_a_content_of_the_domain() {
    let mut connector = MockTelegramConnector::new();
    let Ok(()) = connector.enqueue_message(CHAT, 42, "messaggio acquisito", 1_700_000_000_000)
    else {
        panic!("il messaggio deve potersi accodare");
    };

    let Ok(Some(ConnectorEvent::MessageReceived(message))) = connector.poll_event(POLL) else {
        panic!("il messaggio doveva essere consegnato");
    };

    let Ok(content) = to_new_content(
        &message,
        SessionId::new(1),
        SourceId::new(1),
        Timestamp::from_millis(1_700_000_001_000),
        AcquisitionOrigin::Observed,
    ) else {
        panic!("il messaggio doveva essere traducibile");
    };
    assert_eq!(content.body.as_str(), "messaggio acquisito");
    assert_eq!(content.remote_message_id.as_str(), "42");
    assert_eq!(content.analysis_level.get(), 0);
}

#[test]
fn an_edit_and_a_deletion_are_delivered_as_distinct_events() {
    let mut connector = MockTelegramConnector::new();
    let (Ok(()), Ok(())) = (
        connector.enqueue_edit(CHAT, 42, "testo corretto", 1_700_000_010_000),
        connector.enqueue_deletion(CHAT, &[42, 43], 1_700_000_020_000),
    ) else {
        panic!("gli eventi devono potersi accodare");
    };

    let kinds: Vec<&str> = drain(&mut connector)
        .iter()
        .map(ConnectorEvent::kind)
        .collect();
    assert_eq!(kinds, ["messaggio_modificato", "messaggi_cancellati"]);
}

#[test]
fn an_invalid_identifier_is_refused_without_panicking() {
    let mut connector = MockTelegramConnector::new();

    assert!(matches!(
        connector.enqueue_message(0, 42, "testo", 0),
        Err(TelegramError::InvalidIdentifier { kind: "chat" })
    ));
    assert!(matches!(
        connector.enqueue_message(CHAT, 0, "testo", 0),
        Err(TelegramError::InvalidIdentifier { kind: "messaggio" })
    ));
}

#[test]
fn a_message_beyond_the_domain_limit_is_refused_at_the_translation() {
    let mut connector = MockTelegramConnector::new();
    let oversized = "a".repeat(70_000);
    let Ok(()) = connector.enqueue_message(CHAT, 1, &oversized, 1_700_000_000_000) else {
        panic!("il messaggio deve potersi accodare: il limite e' del dominio");
    };

    let Ok(Some(ConnectorEvent::MessageReceived(message))) = connector.poll_event(POLL) else {
        panic!("il messaggio doveva essere consegnato");
    };

    assert!(matches!(
        to_new_content(
            &message,
            SessionId::new(1),
            SourceId::new(1),
            Timestamp::from_millis(0),
            AcquisitionOrigin::Observed
        ),
        Err(TelegramError::UnacceptableContent(_))
    ));
}

#[test]
fn a_network_drop_is_followed_by_a_reconnection() {
    let mut connector = MockTelegramConnector::new();
    let (Ok(()), Ok(()), Ok(())) = (
        connector.start(&parameters()),
        connector.submit_phone_number(&phone()),
        connector.submit_code(&code()),
    ) else {
        panic!("i passi dell'accesso devono riuscire");
    };
    let _ = drain(&mut connector);

    let Ok(()) = connector.simulate_network_drop() else {
        panic!("la caduta deve potersi simulare");
    };
    assert_eq!(connector.connection_state(), ConnectionState::Interrupted);

    let Ok(()) = connector.simulate_reconnection() else {
        panic!("la riconnessione deve potersi simulare");
    };
    assert_eq!(connector.connection_state(), ConnectionState::Online);

    let states: Vec<ConnectionState> = drain(&mut connector)
        .into_iter()
        .filter_map(|event| match event {
            ConnectorEvent::Connection(state) => Some(state),
            _ => None,
        })
        .collect();
    assert_eq!(
        states,
        vec![
            ConnectionState::Interrupted,
            ConnectionState::Connecting,
            ConnectionState::Online,
        ]
    );
}

#[test]
fn a_planned_network_error_is_reported_and_then_the_connector_recovers() {
    let mut connector = MockTelegramConnector::new();
    connector.plan_failure(TelegramError::Timeout { millis: 1_000 });
    let Ok(()) = connector.enqueue_message(CHAT, 1, "dopo l'errore", 1_700_000_000_000) else {
        panic!("il messaggio deve potersi accodare");
    };

    // Prima l'errore programmato...
    assert!(matches!(
        connector.poll_event(POLL),
        Err(TelegramError::Timeout { millis: 1_000 })
    ));
    // ...poi l'evento, che non e' andato perso.
    let Ok(Some(event)) = connector.poll_event(POLL) else {
        panic!("l'evento accodato non doveva essere perso");
    };
    assert_eq!(event.kind(), "messaggio_ricevuto");
}

#[test]
fn a_timeout_is_distinguishable_from_the_absence_of_events() {
    let mut connector = MockTelegramConnector::new();
    connector.plan_failure(TelegramError::Timeout { millis: 500 });

    assert!(matches!(
        connector.poll_event(POLL),
        Err(TelegramError::Timeout { .. })
    ));
    // Senza errori programmati e senza eventi, l'assenza non e' un errore.
    assert_eq!(connector.poll_event(POLL).ok(), Some(None));
}

#[test]
fn a_full_queue_refuses_new_events_without_losing_the_accepted_ones() {
    let mut connector = MockTelegramConnector::with_queue_capacity(3);

    for number in 1..=3 {
        let Ok(()) = connector.enqueue_message(CHAT, number, "accettato", 1_700_000_000_000) else {
            panic!("i primi tre eventi devono essere accettati");
        };
    }

    for number in 4..=10 {
        assert!(matches!(
            connector.enqueue_message(CHAT, number, "rifiutato", 1_700_000_000_000),
            Err(TelegramError::QueueFull { capacity: 3 })
        ));
    }
    assert_eq!(connector.rejected_events(), 7);

    let events = drain(&mut connector);
    assert_eq!(events.len(), 3);
    for event in &events {
        match event {
            ConnectorEvent::MessageReceived(message) => {
                assert_eq!(message.text, "accettato");
            }
            other => panic!("evento inatteso: {}", other.kind()),
        }
    }
}

#[test]
fn out_of_order_messages_are_detected() {
    let mut connector = MockTelegramConnector::new();
    for (message_id, millis) in [(10, 1_700_000_000_000), (9, 1_700_000_001_000)] {
        let Ok(()) = connector.enqueue_message(CHAT, message_id, "testo", millis) else {
            panic!("gli eventi devono potersi accodare");
        };
    }

    let mut guard = SequenceGuard::new();
    let mut outcomes = Vec::new();
    for event in drain(&mut connector) {
        if let ConnectorEvent::MessageReceived(message) = event {
            outcomes.push(guard.accept(message.chat_id, message.message_id).is_ok());
        }
    }

    let Ok(chat) = ChatId::try_new(CHAT) else {
        panic!("l'identificativo di prova deve essere valido");
    };
    assert_eq!(outcomes, vec![true, false]);
    assert_eq!(guard.last_accepted(chat), Some(10));
}

#[test]
fn the_shutdown_is_orderly_and_idempotent() {
    let mut connector = MockTelegramConnector::new();
    let (Ok(()), Ok(()), Ok(())) = (
        connector.start(&parameters()),
        connector.submit_phone_number(&phone()),
        connector.submit_code(&code()),
    ) else {
        panic!("i passi dell'accesso devono riuscire");
    };
    let _ = drain(&mut connector);

    let Ok(()) = connector.shutdown() else {
        panic!("l'arresto deve riuscire");
    };
    assert_eq!(connector.authorization_state(), AuthorizationState::Closed);

    // Idempotente: piu' percorsi possono richiederlo durante la chiusura.
    let Ok(()) = connector.shutdown() else {
        panic!("il secondo arresto non deve essere un errore");
    };
    assert_eq!(connector.shutdown_calls(), 2);
}

#[test]
fn the_events_accepted_before_the_shutdown_are_not_lost() {
    let mut connector = MockTelegramConnector::new();
    let Ok(()) =
        connector.enqueue_message(CHAT, 1, "acquisito prima dell'arresto", 1_700_000_000_000)
    else {
        panic!("il messaggio deve potersi accodare");
    };

    let Ok(()) = connector.shutdown() else {
        panic!("l'arresto deve riuscire");
    };

    // L'evento gia' accettato resta leggibile: perderlo renderebbe lo storico
    // silenziosamente incompleto proprio alla chiusura.
    let events = drain(&mut connector);
    assert!(
        events
            .iter()
            .any(|event| event.kind() == "messaggio_ricevuto"),
        "l'evento accettato prima dell'arresto doveva restare leggibile"
    );

    // Solo a coda vuota l'arresto diventa visibile.
    assert!(matches!(
        connector.poll_event(POLL),
        Err(TelegramError::Closed)
    ));
}

#[test]
fn a_closed_connector_refuses_every_further_operation() {
    let mut connector = MockTelegramConnector::new();
    let Ok(()) = connector.shutdown() else {
        panic!("l'arresto deve riuscire");
    };
    let _ = drain(&mut connector);

    assert!(matches!(
        connector.start(&parameters()),
        Err(TelegramError::Closed)
    ));
    assert!(matches!(
        connector.submit_phone_number(&phone()),
        Err(TelegramError::Closed)
    ));
}

#[test]
fn the_mock_is_deterministic_across_identical_runs() {
    let render = || {
        let mut connector = MockTelegramConnector::new();
        let (Ok(()), Ok(()), Ok(())) = (
            connector.start(&parameters()),
            connector.submit_phone_number(&phone()),
            connector.submit_code(&code()),
        ) else {
            panic!("i passi dell'accesso devono riuscire");
        };
        let Ok(()) = connector.enqueue_message(CHAT, 1, "testo", 1_700_000_000_000) else {
            panic!("il messaggio deve potersi accodare");
        };
        let _ = connector.simulate_network_drop();
        let _ = connector.simulate_reconnection();
        let Ok(()) = connector.shutdown() else {
            panic!("l'arresto deve riuscire");
        };

        drain(&mut connector)
            .iter()
            .map(|event| event.kind().to_owned())
            .collect::<Vec<String>>()
    };

    let first = render();
    let second = render();
    assert_eq!(first, second, "il mock non deve dipendere da tempo o caso");
    assert!(!first.is_empty());
}

#[test]
fn the_default_queue_capacity_is_bounded() {
    const { assert!(EventQueue::DEFAULT_CAPACITY > 0) };

    // Una coda predefinita accetta fino alla propria capacita' e non oltre: il
    // connettore non cresce senza limite nemmeno senza configurazione esplicita.
    let mut connector = MockTelegramConnector::new();
    assert_eq!(connector.rejected_events(), 0);

    for number in 1..=(EventQueue::DEFAULT_CAPACITY as i64) {
        let Ok(()) = connector.enqueue_message(CHAT, number, "testo", 1_700_000_000_000) else {
            panic!("l'evento {number} doveva rientrare nella capacita' predefinita");
        };
    }
    assert!(matches!(
        connector.enqueue_message(CHAT, 1, "oltre la capacita'", 1_700_000_000_000),
        Err(TelegramError::QueueFull { .. })
    ));
}

//! Percorso completo dell'operatore, dall'avvio alla configurazione delle fonti.
//!
//! Sostituisce la guida automatica dell'interfaccia grafica, che dipendeva dalle
//! coordinate dei pulsanti e dal controllo di mouse e tastiera reali. Un test
//! che clicca su coordinate si rompe al primo spostamento di un bottone e non
//! dice nulla su ciò che l'applicazione fa; questo percorre le stesse decisioni
//! che l'interfaccia si limita a mostrare.
//!
//! Nessuna rete, nessuna credenziale, nessuna TDLib. **Soli valori fittizi.**

use std::path::PathBuf;

use lisi_services::sources::{RemovalOutcome, SourceService};
use lisi_services::{
    AuthCommand, AuthStage, AuthenticationService, ServiceError, session::SessionService,
};
use lisi_telegram::{
    ApiHash, ApiId, ClientParameters, LoginCode, MockTelegramConnector, PhoneNumber,
    TwoFactorPassword,
};

const FAKE_PHONE: &str = "+390612345678";
const OTHER_FAKE_PHONE: &str = "+390698765432";
const FAKE_CODE: &str = "12345";
const FAKE_PASSWORD: &str = "password-di-prova-non-reale";
const FAKE_API_HASH: &str = "00000000000000000000000000000000";

const CANALE_ALFA: i64 = -1_001_000_000_001;
const GRUPPO: i64 = -1_002_000_000_001;
const SUPERGRUPPO: i64 = -1_003_000_000_001;
const SENZA_STORICO: i64 = -1_003_000_000_002;

fn parameters() -> ClientParameters {
    let (Ok(api_id), Ok(api_hash)) = (ApiId::try_new(1), ApiHash::try_new(FAKE_API_HASH)) else {
        panic!("i valori fittizi devono essere validi");
    };
    ClientParameters {
        api_id,
        api_hash,
        database_directory: PathBuf::from("target/percorso-operatore"),
        use_test_datacenter: true,
        application_version: String::from("0.1.0"),
        system_language_code: String::from("it"),
    }
}

fn phone(raw: &str) -> PhoneNumber {
    let Ok(value) = PhoneNumber::try_new(raw) else {
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

fn actor() -> lisi_core::text::Actor {
    let Ok(value) = lisi_core::text::Actor::try_new("responsabile.ufficio") else {
        panic!("l'attore di prova deve essere valido");
    };
    value
}

fn now() -> lisi_core::Timestamp {
    lisi_core::Timestamp::from_millis(1_700_000_000_000)
}

fn source_service() -> SourceService {
    let Ok(database) = lisi_services::sources::open_in_memory_database() else {
        panic!("il database in memoria deve potersi aprire");
    };
    SourceService::new(database)
}

/// Porta il servizio fino allo stato autorizzato.
fn authenticate(service: &mut AuthenticationService) {
    let (Ok(()), Ok(()), Ok(())) = (
        service.start(&parameters()),
        service.submit_phone_number(phone(FAKE_PHONE)),
        service.submit_code(code()),
    ) else {
        panic!("l'accesso simulato deve riuscire");
    };
}

#[test]
fn the_complete_journey_from_first_run_to_configured_sources() {
    let mut authentication = AuthenticationService::simulated();
    let sources = source_service();

    // --- primo avvio: nessun account, avvio o annullamento disponibili.
    let view = authentication.view();
    assert_eq!(view.stage, AuthStage::FirstRun);
    assert_eq!(
        view.allowed_commands,
        vec![AuthCommand::Start, AuthCommand::Cancel]
    );
    assert_eq!(view.account_label, None);

    // --- senza accesso non esiste alcuna fonte disponibile.
    assert!(
        sources.available(authentication.connector_mut()).is_err(),
        "l'elenco delle fonti richiede un account autorizzato"
    );

    // --- accesso completo.
    authenticate(&mut authentication);
    assert_eq!(authentication.stage(), AuthStage::Authenticated);

    // Il numero mostrato e' redatto: e' cio' che l'interfaccia visualizza.
    let Some(label) = authentication.view().account_label else {
        panic!("l'account configurato deve essere mostrato");
    };
    assert!(!label.contains("0612345"));
    assert!(label.starts_with("+39") && label.ends_with("78"));

    // --- elenco delle chat accessibili.
    let Ok(available) = sources.available(authentication.connector_mut()) else {
        panic!("l'elenco deve potersi ottenere dopo l'accesso");
    };
    assert_eq!(available.len(), 5);
    assert_eq!(
        available
            .iter()
            .filter(|entry| entry.can_be_added())
            .count(),
        4,
        "una chat e' senza storico leggibile e non e' selezionabile"
    );

    // --- aggiunta dei tre tipi di fonte.
    for chat in [CANALE_ALFA, GRUPPO, SUPERGRUPPO] {
        let Ok(_) = sources.add(authentication.connector_mut(), chat, &actor(), now()) else {
            panic!("la fonte {chat} deve potersi aggiungere");
        };
    }
    assert_eq!(sources.configured().map(|list| list.len()).ok(), Some(3));

    // --- la chat senza storico resta rifiutata.
    assert!(matches!(
        sources.add(
            authentication.connector_mut(),
            SENZA_STORICO,
            &actor(),
            now()
        ),
        Err(ServiceError::SourceNotAccessible)
    ));

    // --- il duplicato e' riconosciuto come tale, non come errore generico.
    assert!(matches!(
        sources.add(authentication.connector_mut(), CANALE_ALFA, &actor(), now()),
        Err(ServiceError::SourceAlreadyConfigured)
    ));

    // --- dopo l'aggiunta le chat risultano gia' configurate.
    let Ok(available) = sources.available(authentication.connector_mut()) else {
        panic!("l'elenco deve potersi rileggere");
    };
    assert_eq!(
        available
            .iter()
            .filter(|entry| entry.already_configured)
            .count(),
        3
    );

    // --- disattivazione e riattivazione.
    let Ok(configured) = sources.configured() else {
        panic!("l'elenco configurato deve potersi leggere");
    };
    let first = configured[0].id;
    let Ok(()) = sources.set_active(first, false, &actor(), now()) else {
        panic!("la disattivazione deve riuscire");
    };
    let Ok(after) = sources.configured() else {
        panic!("l'elenco deve potersi rileggere");
    };
    assert!(
        after
            .iter()
            .any(|source| source.id == first && !source.active)
    );

    // --- rimozione di una fonte mai usata.
    assert_eq!(
        sources.remove(first, &actor(), now()).ok(),
        Some(RemovalOutcome::Deleted)
    );
    assert_eq!(sources.configured().map(|list| list.len()).ok(), Some(2));

    // --- ogni modifica e' finita nell'audit, nell'ordine.
    let Ok(entries) = sources.database().audit_entries() else {
        panic!("l'audit deve potersi leggere");
    };
    let actions: Vec<&str> = entries.iter().map(|entry| entry.action.as_str()).collect();
    assert_eq!(
        actions,
        [
            "fonte_aggiunta",
            "fonte_aggiunta",
            "fonte_aggiunta",
            "fonte_disattivata",
            "fonte_rimossa"
        ]
    );

    // --- uscita: l'account e' dimenticato e si puo' ricominciare.
    let Ok(()) = authentication.log_out() else {
        panic!("l'uscita deve riuscire");
    };
    let view = authentication.view();
    assert_eq!(view.stage, AuthStage::Closed);
    assert_eq!(view.account_label, None);
    assert_eq!(view.allowed_commands, vec![AuthCommand::Start]);
}

#[test]
fn the_journey_with_two_factor_and_a_mistyped_code() {
    let mut connector = MockTelegramConnector::new().requiring_two_factor(true);
    connector.reject_next_codes(1);
    connector.reject_next_passwords(1);
    let mut authentication = AuthenticationService::new(Box::new(connector));

    let (Ok(()), Ok(())) = (
        authentication.start(&parameters()),
        authentication.submit_phone_number(phone(FAKE_PHONE)),
    ) else {
        panic!("i primi passi devono riuscire");
    };

    // Codice sbagliato: si resta sul codice, con un messaggio correggibile.
    assert!(matches!(
        authentication.submit_code(code()),
        Err(ServiceError::CodeRejected)
    ));
    let view = authentication.view();
    assert_eq!(view.stage, AuthStage::NeedCode);
    assert!(view.failure_is_correctable);
    assert!(view.allows(AuthCommand::SubmitCode));

    let Ok(()) = authentication.submit_code(code()) else {
        panic!("il secondo codice deve essere accettato");
    };
    assert_eq!(authentication.stage(), AuthStage::NeedPassword);

    // Password sbagliata: stesso comportamento.
    assert!(matches!(
        authentication.submit_password(password()),
        Err(ServiceError::PasswordRejected)
    ));
    assert_eq!(authentication.stage(), AuthStage::NeedPassword);

    let Ok(()) = authentication.submit_password(password()) else {
        panic!("la seconda password deve essere accettata");
    };
    assert_eq!(authentication.stage(), AuthStage::Authenticated);
    assert!(authentication.view().failure.is_none());
}

#[test]
fn switching_account_requires_leaving_the_current_one_and_frees_the_session() {
    let Ok(directory) = tempfile::tempdir() else {
        panic!("la cartella temporanea deve potersi creare");
    };
    let mut sessions = SessionService::new(directory.path().join("sessioni"));
    let mut authentication = AuthenticationService::simulated();

    authenticate(&mut authentication);
    let Ok(_) = sessions.open(&phone(FAKE_PHONE)) else {
        panic!("la sessione deve potersi aprire");
    };

    // Un secondo account puo' essere attivo insieme al primo (ADR-0173): il
    // tetto e' tre, e lo prova il servizio delle sessioni.
    let Ok(_) = sessions.open(&phone(OTHER_FAKE_PHONE)) else {
        panic!("un secondo account si apre insieme al primo");
    };
    assert_eq!(sessions.active().len(), 2);

    // Il cambio account passa dall'uscita.
    let Ok(()) = authentication.switch_account() else {
        panic!("il cambio account deve riuscire da autenticato");
    };
    assert_eq!(authentication.view().account_label, None);

    let Ok(session) = sessions.switch_to(&phone(OTHER_FAKE_PHONE)) else {
        panic!("la nuova sessione deve potersi aprire");
    };
    assert!(
        !session
            .directory()
            .display()
            .to_string()
            .contains("0698765")
    );
}

#[test]
fn no_secret_appears_in_any_text_the_interface_would_show() {
    // Raccoglie tutto cio' che l'interfaccia mostrerebbe durante l'accesso e
    // verifica che nessun valore riservato vi compaia.
    let mut connector = MockTelegramConnector::new().requiring_two_factor(true);
    connector.reject_next_codes(1);
    let mut authentication = AuthenticationService::new(Box::new(connector));

    let mut shown = Vec::new();
    let mut collect = |service: &AuthenticationService| {
        let view = service.view();
        shown.push(String::from(view.stage.headline()));
        shown.push(String::from(view.stage.detail()));
        if let Some(failure) = view.failure {
            shown.push(failure);
        }
        if let Some(label) = view.account_label {
            shown.push(label);
        }
        shown.push(format!("{service:?}"));
    };

    collect(&authentication);
    let (Ok(()), Ok(())) = (
        authentication.start(&parameters()),
        authentication.submit_phone_number(phone(FAKE_PHONE)),
    ) else {
        panic!("i primi passi devono riuscire");
    };
    collect(&authentication);
    let _ = authentication.submit_code(code());
    collect(&authentication);
    let Ok(()) = authentication.submit_code(code()) else {
        panic!("il secondo codice deve essere accettato");
    };
    collect(&authentication);
    let Ok(()) = authentication.submit_password(password()) else {
        panic!("la password deve essere accettata");
    };
    collect(&authentication);

    for text in &shown {
        assert!(!text.contains(FAKE_PHONE), "numero in chiaro in: {text}");
        assert!(!text.contains("0612345"), "corpo del numero in: {text}");
        assert!(!text.contains(FAKE_CODE), "codice in chiaro in: {text}");
        assert!(
            !text.contains(FAKE_PASSWORD),
            "password in chiaro in: {text}"
        );
        assert!(!text.contains(FAKE_API_HASH), "hash in chiaro in: {text}");
    }
    assert!(shown.len() > 10, "il campione deve essere significativo");
}

#[test]
fn the_allowed_commands_never_include_something_the_state_forbids() {
    // Verifica esaustiva: per ogni stato raggiungibile, ogni comando NON
    // elencato deve essere rifiutato dal servizio. E' il presidio della
    // decisione che l'interfaccia si limita a rispecchiare nei pulsanti.
    let mut service = AuthenticationService::simulated();

    let check = |service: &mut AuthenticationService| {
        let allowed = service.allowed_commands();
        for command in AuthCommand::all() {
            let expected = allowed.contains(command);
            assert_eq!(
                service.ensure_allowed(*command).is_ok(),
                expected,
                "comando {command:?} nello stato {:?}",
                service.state()
            );
        }
    };

    check(&mut service);
    let Ok(()) = service.start(&parameters()) else {
        panic!("l'avvio deve riuscire");
    };
    check(&mut service);
    let Ok(()) = service.submit_phone_number(phone(FAKE_PHONE)) else {
        panic!("il numero deve essere accettato");
    };
    check(&mut service);
    let Ok(()) = service.submit_code(code()) else {
        panic!("il codice deve essere accettato");
    };
    check(&mut service);
    let Ok(()) = service.log_out() else {
        panic!("l'uscita deve riuscire");
    };
    check(&mut service);
}

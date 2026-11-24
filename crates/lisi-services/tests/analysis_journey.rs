//! Il percorso completo, dalla fonte alla decisione umana.
//!
//! I test per modulo provano che ogni pezzo funzioni da solo. Questo prova che
//! funzionino **insieme**, che è una domanda diversa: ciascun servizio possiede
//! il proprio archivio, e se la catena non se lo passasse ogni pezzo scriverebbe
//! da un'altra parte. Una sessione creata dal wizard sarebbe invisibile
//! all'analisi, e l'insieme sembrerebbe funzionante mentre non lo è.
//!
//! Il percorso è quello reale, meno l'acquisizione: quella arriva da Telegram,
//! e finché non c'è i contenuti entrano da qui come entrerebbero da lì.

use lisi_core::model::AcquisitionOrigin;
use lisi_core::model::dictionary::{
    DictionaryScope, DictionarySelection, DictionaryVisibility, MatchMode, NewDictionaryTerm,
    SessionCustomTerm, SuggestedLevel,
};
use lisi_core::model::{NewSession, NewSource, ReviewState, SessionDuration, SourceKind};
use lisi_core::text::{
    Actor, ContentBody, DictionaryDescription, DictionaryName, DisplayName, LanguageTag,
    RemoteMessageId, SourceIdentifier, TermCategory, TermNote, TermText,
};
use lisi_core::{SessionId, SourceId, Timestamp};
use lisi_services::analysis::{AnalysisService, NewContentDraft};
use lisi_services::dictionaries::{DictionaryProposal, DictionaryService};
use lisi_services::review::ReviewService;
use lisi_services::sources::open_in_memory_database;
use lisi_storage::Database;

fn now() -> Timestamp {
    Timestamp::from_millis(1_700_000_000_000)
}

fn later(seconds: i64) -> Timestamp {
    Timestamp::from_millis(1_700_000_000_000 + seconds * 1_000)
}

fn operator() -> Actor {
    let Ok(value) = Actor::try_new("operatore.ufficio") else {
        panic!("l'attore di prova deve essere valido");
    };
    value
}

/// Fonte e sessione, come le lascerebbe la configurazione delle fonti.
fn source_and_session(database: &mut Database) -> (SourceId, SessionId) {
    let (Ok(identifier), Ok(title), Ok(label)) = (
        SourceIdentifier::try_new("canale_autorizzato"),
        DisplayName::try_new("Canale autorizzato"),
        DisplayName::try_new("Monitoraggio di prova"),
    ) else {
        panic!("i valori di prova devono essere validi");
    };

    let Ok(source_id) = database.insert_source(
        &NewSource {
            kind: SourceKind::Channel,
            identifier,
            display_name: title,
            authorized_by: operator(),
            active: true,
        },
        now(),
    ) else {
        panic!("la fonte deve potersi registrare");
    };

    let Ok(session_id) = database.insert_session(
        &NewSession {
            label,
            started_by: operator(),
            duration: SessionDuration::Preset { seconds: 3_600 },
            source_ids: vec![source_id],
        },
        now(),
    ) else {
        panic!("la sessione deve potersi creare");
    };

    (source_id, session_id)
}

/// Termine di prova pronto per l'inserimento.
fn term(version: lisi_core::DictionaryVersionId, text: &str, level: i8) -> NewDictionaryTerm {
    let (Ok(text), Ok(category), Ok(language), Ok(note), Ok(level)) = (
        TermText::try_new(text),
        TermCategory::try_new("azione"),
        LanguageTag::try_new("it"),
        TermNote::try_new("termine di prova"),
        SuggestedLevel::try_new(level),
    ) else {
        panic!("i valori del termine devono essere validi");
    };

    NewDictionaryTerm {
        version_id: version,
        text,
        category,
        language,
        match_mode: MatchMode::NormalizedWord,
        suggested_level: level,
        note,
    }
}

#[test]
fn from_the_source_to_the_human_decision() {
    // ---------------------------------------------------- fonte e sessione
    let Ok(mut database) = open_in_memory_database() else {
        panic!("il database in memoria deve potersi aprire");
    };
    let (source_id, session_id) = source_and_session(&mut database);

    // ------------------------------------------------------- i dizionari
    let mut dictionaries = DictionaryService::new(database);
    let (Ok(name), Ok(description)) = (
        DictionaryName::try_new("Incendi di prova"),
        DictionaryDescription::try_new("dizionario del percorso completo"),
    ) else {
        panic!("i valori del dizionario devono essere validi");
    };

    let Ok((dictionary_id, version_id)) = dictionaries.create(
        &DictionaryProposal {
            name,
            description,
            scope: DictionaryScope::Thematic,
            visibility: DictionaryVisibility::Personal,
        },
        &operator(),
        now(),
    ) else {
        panic!("il dizionario deve potersi creare");
    };

    let Ok(_) = dictionaries.add_terms(
        version_id,
        &[
            term(version_id, "molotov", 4),
            term(version_id, "appiccare", 2),
        ],
        &operator(),
        now(),
    ) else {
        panic!("i termini devono potersi aggiungere");
    };
    let Ok(()) = dictionaries.publish(version_id, &operator(), now()) else {
        panic!("la pubblicazione deve riuscire");
    };

    // ------------------------------------- la configurazione della sessione
    let Ok(extra) = TermText::try_new("deposito") else {
        panic!("il termine aggiuntivo deve essere valido");
    };
    let selection = DictionarySelection {
        dictionary_ids: vec![dictionary_id],
        ad_hoc_terms: vec![SessionCustomTerm::normalised(extra)],
    };

    let Ok(configuration) =
        dictionaries.apply_to_session(session_id, &selection, &operator(), now())
    else {
        panic!("la configurazione deve potersi fissare sulla stessa sessione");
    };
    assert_eq!(
        configuration.unique_count, 3,
        "due termini del dizionario piu' la parola aggiunta"
    );

    // --------------------------------------------------------- l'analisi
    let mut analysis = AnalysisService::new(dictionaries.into_database());

    let (Ok(remote_alert), Ok(body_alert)) = (
        RemoteMessageId::try_new("msg-1"),
        ContentBody::try_new("vogliono appiccare con una molotov al deposito"),
    ) else {
        panic!("i valori del contenuto devono essere validi");
    };
    let (Ok(remote_quiet), Ok(body_quiet)) = (
        RemoteMessageId::try_new("msg-2"),
        ContentBody::try_new("ci vediamo domani per il caffe'"),
    ) else {
        panic!("i valori del contenuto devono essere validi");
    };

    let draft = |remote: RemoteMessageId, body: ContentBody| NewContentDraft {
        session_id,
        source_id,
        remote_message_id: remote,
        author: None,
        author_identifier: None,
        author_username: None,
        body,
        url: None,
        published_at: now(),
        acquired_at: later(10),
        origin: AcquisitionOrigin::Observed,
    };

    let Ok(segnalato) = analysis.analyse_and_record(
        &draft(remote_alert, body_alert),
        &configuration,
        &operator(),
        later(10),
    ) else {
        panic!("l'analisi del contenuto rilevante deve riuscire");
    };
    let Ok(tranquillo) = analysis.analyse_and_record(
        &draft(remote_quiet, body_quiet),
        &configuration,
        &operator(),
        later(20),
    ) else {
        panic!("l'analisi del contenuto irrilevante deve riuscire");
    };

    // Tre termini distinti ma una sola categoria per i due del dizionario, piu'
    // la parola aggiunta che ha categoria propria: base 4, corroborazione 1,
    // limitato a 4.
    assert_eq!(segnalato.analysed.outcome.level.get(), 4);
    assert!(segnalato.raised_alert());
    assert_eq!(tranquillo.analysed.outcome.level.get(), 0);
    assert!(!tranquillo.raised_alert());

    // -------------------------------------------------- la revisione umana
    let review = ReviewService::new(analysis.into_database());

    let Ok(pending) = review.pending(session_id) else {
        panic!("la coda deve potersi leggere");
    };
    assert_eq!(pending.len(), 1, "solo il contenuto segnalato attende");
    assert!(pending[0].is_untouched());
    assert!(
        pending[0].alert.reason.as_str().contains("molotov"),
        "la motivazione deve nominare il termine: {}",
        pending[0].alert.reason.as_str()
    );

    let Some(content_id) = segnalato.content_id else {
        panic!("il contenuto segnalato doveva essere registrato");
    };
    let Ok(()) = review.record(
        content_id,
        ReviewState::Relevant,
        &operator(),
        None,
        later(300),
    ) else {
        panic!("la conferma deve riuscire");
    };

    assert_eq!(
        review.current_state(content_id).ok(),
        Some(ReviewState::Relevant)
    );
    assert_eq!(
        review.pending(session_id).map(|all| all.len()).ok(),
        Some(0)
    );

    // ------------------------------------------------ cio' che resta scritto
    let Ok(contents) = review.database().session_contents(session_id) else {
        panic!("lo storico deve potersi leggere");
    };
    assert_eq!(
        contents.len(),
        2,
        "anche il contenuto non rilevante resta nello storico"
    );

    let Ok(entries) = review.database().audit_entries() else {
        panic!("l'audit deve potersi leggere");
    };
    let actions: Vec<&str> = entries.iter().map(|entry| entry.action.as_str()).collect();
    for expected in [
        "dizionario_creato",
        "versione_pubblicata",
        "configurazione_fissata",
        "alert_generato",
        "revisione_registrata",
    ] {
        assert!(
            actions.contains(&expected),
            "l'audit non riporta '{expected}': {actions:?}"
        );
    }
}

#[test]
fn a_dictionary_changed_afterwards_does_not_change_a_session_already_configured() {
    // E' la ragione per cui la fotografia esiste, provata lungo la catena vera
    // e non su un servizio isolato.
    let Ok(mut database) = open_in_memory_database() else {
        panic!("il database in memoria deve potersi aprire");
    };
    let (source_id, session_id) = source_and_session(&mut database);

    let mut dictionaries = DictionaryService::new(database);
    let (Ok(name), Ok(description)) = (
        DictionaryName::try_new("Dizionario che cambiera'"),
        DictionaryDescription::try_new("prima stesura"),
    ) else {
        panic!("i valori devono essere validi");
    };
    let Ok((dictionary_id, version_id)) = dictionaries.create(
        &DictionaryProposal {
            name,
            description,
            scope: DictionaryScope::Thematic,
            visibility: DictionaryVisibility::Personal,
        },
        &operator(),
        now(),
    ) else {
        panic!("il dizionario deve potersi creare");
    };
    let Ok(_) = dictionaries.add_terms(
        version_id,
        &[term(version_id, "molotov", 3)],
        &operator(),
        now(),
    ) else {
        panic!("il termine deve potersi aggiungere");
    };
    let Ok(()) = dictionaries.publish(version_id, &operator(), now()) else {
        panic!("la pubblicazione deve riuscire");
    };

    let selection = DictionarySelection {
        dictionary_ids: vec![dictionary_id],
        ad_hoc_terms: Vec::new(),
    };
    let Ok(configuration) =
        dictionaries.apply_to_session(session_id, &selection, &operator(), now())
    else {
        panic!("la configurazione deve potersi fissare");
    };

    // Il dizionario prosegue: una versione nuova con un termine in piu'.
    let (Ok(note),) = (DictionaryDescription::try_new("seconda stesura"),) else {
        panic!("la nota deve essere valida");
    };
    let Ok(draft_version) =
        dictionaries.start_new_version(dictionary_id, &note, &operator(), later(60))
    else {
        panic!("la nuova versione deve potersi aprire");
    };
    let Ok(_) = dictionaries.add_terms(
        draft_version,
        &[term(draft_version, "deposito", 4)],
        &operator(),
        later(60),
    ) else {
        panic!("il termine deve potersi aggiungere");
    };
    let Ok(()) = dictionaries.publish(draft_version, &operator(), later(60)) else {
        panic!("la pubblicazione deve riuscire");
    };

    // La sessione continua con i termini di prima: "deposito" non riscontra.
    let mut analysis = AnalysisService::new(dictionaries.into_database());
    let (Ok(remote), Ok(body)) = (
        RemoteMessageId::try_new("msg-1"),
        ContentBody::try_new("hanno portato tutto al deposito"),
    ) else {
        panic!("i valori del contenuto devono essere validi");
    };

    let Ok(record) = analysis.analyse_and_record(
        &NewContentDraft {
            session_id,
            source_id,
            remote_message_id: remote,
            author: None,
            author_identifier: None,
            author_username: None,
            body,
            url: None,
            published_at: later(120),
            acquired_at: later(120),
            origin: AcquisitionOrigin::Observed,
        },
        &configuration,
        &operator(),
        later(120),
    ) else {
        panic!("l'analisi deve riuscire");
    };

    assert_eq!(
        record.analysed.outcome.level.get(),
        0,
        "il termine aggiunto dopo non deve riscontrare"
    );
}

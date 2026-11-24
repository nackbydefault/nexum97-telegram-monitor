//! Sostegno ai test del crate.
//!
//! Compilato soltanto sotto `cfg(test)`: non fa parte del prodotto e non entra
//! nel binario distribuito. Raccoglie le costruzioni di prova ricorrenti perché
//! ogni test possa dire in poche righe che cosa sta verificando.

use lisi_core::model::dictionary::{
    DictionaryOrigin, DictionaryScope, DictionaryStatus, DictionaryVisibility, MatchMode,
    NewDictionary, NewDictionaryTerm, NewDictionaryVersion, SuggestedLevel,
};
use lisi_core::model::{
    AcquisitionOrigin, AnalysisLevel, NewContent, NewSession, NewSource, SessionDuration,
    SourceKind,
};
use lisi_core::text::{
    Actor, ContentBody, DictionaryDescription, DictionaryName, DisplayName, LanguageTag,
    ProfileName, RemoteMessageId, SourceIdentifier, TermCategory, TermNote, TermText,
};
use lisi_core::{DictionaryId, DictionaryVersionId, SessionId, SourceId, Timestamp};

use crate::database::Database;

/// Istante di riferimento dei test: 2023-11-14T22:13:20Z.
pub(crate) const REFERENCE_MILLIS: i64 = 1_700_000_000_000;

/// Database in memoria già migrato.
pub(crate) fn database() -> Database {
    let Ok(database) = Database::open_in_memory() else {
        panic!("il database in memoria deve potersi aprire");
    };
    database
}

/// Istante di riferimento.
pub(crate) const fn now() -> Timestamp {
    Timestamp::from_millis(REFERENCE_MILLIS)
}

/// Istante spostato in avanti di `seconds` secondi rispetto al riferimento.
pub(crate) const fn later(seconds: i64) -> Timestamp {
    Timestamp::from_millis(REFERENCE_MILLIS + seconds * 1_000)
}

/// Testo obbligatorio di prova, con messaggio esplicito se non è valido.
pub(crate) fn actor(raw: &str) -> Actor {
    let Ok(value) = Actor::try_new(raw) else {
        panic!("l'attore di prova '{raw}' deve essere valido");
    };
    value
}

/// Nome visualizzato di prova.
pub(crate) fn display_name(raw: &str) -> DisplayName {
    let Ok(value) = DisplayName::try_new(raw) else {
        panic!("il nome di prova '{raw}' deve essere valido");
    };
    value
}

/// Corpo di prova.
pub(crate) fn body(raw: &str) -> ContentBody {
    let Ok(value) = ContentBody::try_new(raw) else {
        panic!("il corpo di prova deve essere valido");
    };
    value
}

/// Livello di analisi di prova.
pub(crate) fn level(value: u8) -> AnalysisLevel {
    let Ok(level) = AnalysisLevel::try_new(value) else {
        panic!("il livello di prova {value} deve essere valido");
    };
    level
}

/// Fonte di prova con l'identificativo indicato.
pub(crate) fn new_source(identifier: &str) -> NewSource {
    let Ok(identifier) = SourceIdentifier::try_new(identifier) else {
        panic!("l'identificativo di prova deve essere valido");
    };

    NewSource {
        kind: SourceKind::Channel,
        identifier,
        display_name: display_name("Canale di prova"),
        authorized_by: actor("responsabile.ufficio"),
        active: true,
    }
}

/// Sessione di prova sulle fonti indicate.
pub(crate) fn new_session(source_ids: Vec<SourceId>) -> NewSession {
    NewSession {
        label: display_name("Sessione di prova"),
        started_by: actor("operatore.prova"),
        duration: SessionDuration::Preset { seconds: 3_600 },
        source_ids,
    }
}

/// Contenuto di prova.
pub(crate) fn new_content(
    session_id: SessionId,
    source_id: SourceId,
    remote_message_id: &str,
    text: &str,
) -> NewContent {
    let Ok(remote_message_id) = RemoteMessageId::try_new(remote_message_id) else {
        panic!("l'identificativo remoto di prova deve essere valido");
    };

    NewContent {
        session_id,
        source_id,
        remote_message_id,
        author: None,
        author_identifier: None,
        author_username: None,
        body: body(text),
        url: None,
        published_at: now(),
        acquired_at: later(1),
        origin: AcquisitionOrigin::Observed,
        analysis_level: AnalysisLevel::NOT_RELEVANT,
    }
}

// ------------------------------------------------------------------ dizionari

/// Nome di dizionario di prova.
pub(crate) fn dictionary_name(raw: &str) -> DictionaryName {
    let Ok(value) = DictionaryName::try_new(raw) else {
        panic!("il nome di dizionario di prova '{raw}' deve essere valido");
    };
    value
}

/// Descrizione di prova.
pub(crate) fn description(raw: &str) -> DictionaryDescription {
    let Ok(value) = DictionaryDescription::try_new(raw) else {
        panic!("la descrizione di prova deve essere valida");
    };
    value
}

/// Nome di profilo di prova.
pub(crate) fn profile_name(raw: &str) -> ProfileName {
    let Ok(value) = ProfileName::try_new(raw) else {
        panic!("il nome di profilo di prova '{raw}' deve essere valido");
    };
    value
}

/// Testo di termine di prova.
pub(crate) fn term_text(raw: &str) -> TermText {
    let Ok(value) = TermText::try_new(raw) else {
        panic!("il termine di prova '{raw}' deve essere valido");
    };
    value
}

/// Dizionario di prova con la visibilità indicata.
pub(crate) fn new_dictionary(name: &str, visibility: DictionaryVisibility) -> NewDictionary {
    NewDictionary {
        name: dictionary_name(name),
        description: description("dizionario di prova"),
        scope: DictionaryScope::Thematic,
        origin: DictionaryOrigin::Operator,
        visibility,
        created_by: actor("operatore.prova"),
        derived_from: None,
    }
}

/// Versione di prova, numerata come indicato.
pub(crate) fn new_version(dictionary_id: DictionaryId, number: u32) -> NewDictionaryVersion {
    NewDictionaryVersion {
        dictionary_id,
        number,
        note: description("versione di prova"),
        created_by: actor("operatore.prova"),
    }
}

/// Termine di prova con testo e livello suggerito.
pub(crate) fn new_term(
    version_id: DictionaryVersionId,
    text: &str,
    suggested: i8,
) -> NewDictionaryTerm {
    let (Ok(category), Ok(language), Ok(note), Ok(suggested_level)) = (
        TermCategory::try_new("prova"),
        LanguageTag::try_new("it"),
        TermNote::try_new(""),
        SuggestedLevel::try_new(suggested),
    ) else {
        panic!("i valori del termine di prova devono essere validi");
    };

    NewDictionaryTerm {
        version_id,
        text: term_text(text),
        category,
        language,
        match_mode: MatchMode::NormalizedWord,
        suggested_level,
        note,
    }
}

/// Dizionario attivo con una versione pubblicata contenente i termini indicati.
///
/// È la forma in cui un dizionario diventa realmente utilizzabile: senza una
/// versione pubblicata non contribuisce nulla a una sessione.
pub(crate) fn published_dictionary(
    database: &mut Database,
    name: &str,
    terms: &[&str],
) -> (DictionaryId, DictionaryVersionId) {
    let Ok(dictionary_id) =
        database.insert_dictionary(&new_dictionary(name, DictionaryVisibility::Personal), now())
    else {
        panic!("il dizionario di prova deve potersi registrare");
    };
    let Ok(version_id) = database.insert_dictionary_version(&new_version(dictionary_id, 1), now())
    else {
        panic!("la versione di prova deve potersi registrare");
    };

    let collected: Vec<_> = terms
        .iter()
        .map(|text| new_term(version_id, text, 1))
        .collect();
    let Ok(_) = database.insert_dictionary_terms(version_id, &collected) else {
        panic!("i termini di prova devono potersi inserire");
    };

    let (Ok(()), Ok(())) = (
        database.publish_dictionary_version(version_id, now()),
        database.set_dictionary_status(dictionary_id, DictionaryStatus::Active, now()),
    ) else {
        panic!("la pubblicazione di prova deve riuscire");
    };

    (dictionary_id, version_id)
}

/// Fonte registrata e sessione che la seleziona, pronte per i test dei
/// contenuti.
pub(crate) fn database_with_session() -> (Database, SourceId, SessionId) {
    let mut database = database();

    let Ok(source_id) = database.insert_source(&new_source("canale_uno"), now()) else {
        panic!("la fonte di prova deve potersi registrare");
    };
    let Ok(session_id) = database.insert_session(&new_session(vec![source_id]), now()) else {
        panic!("la sessione di prova deve potersi creare");
    };

    (database, source_id, session_id)
}

//! **Un monitoraggio avviato dal wizard dichiara i dizionari con cui lavora**
//! (FINAL-REVIEW-01, FR-049).
//!
//! Fino al 2026-10-04 l'avvio salvava soltanto i termini risolti: la tabella
//! delle versioni scelte restava vuota, e ogni relazione scriveva «Versioni di
//! dizionario in vigore: nessuna.». La prova percorre la strada vera: il
//! wizard sceglie un dizionario, il riepilogo fotografa la versione, il
//! monitoraggio si avvia, e l'archivio dice quale versione è in vigore.

use lisi_core::Timestamp;
use lisi_core::model::NewSource;
use lisi_core::model::SourceKind;
use lisi_core::model::dictionary::{
    DictionaryScope, DictionarySelection, DictionaryVisibility, MatchMode, NewDictionaryTerm,
    SessionCustomTerm, SuggestedLevel,
};
use lisi_core::text::{
    Actor, DictionaryDescription, DictionaryName, DisplayName, LanguageTag, SourceIdentifier,
    TermCategory, TermNote, TermText,
};
use lisi_services::dictionaries::{DictionaryProposal, DictionaryService};
use lisi_services::monitoring::{DictionaryChoice, MonitoringService};
use lisi_services::sources::open_in_memory_database;
use lisi_services::wizard::WizardDuration;

fn now() -> Timestamp {
    Timestamp::from_millis(1_700_000_000_000)
}

fn operator() -> Actor {
    let Ok(value) = Actor::try_new("operatore.ufficio") else {
        panic!("l'attore di prova deve essere valido");
    };
    value
}

#[test]
fn un_monitoraggio_dichiara_le_versioni_di_dizionario_in_vigore() {
    let Ok(database) = open_in_memory_database() else {
        panic!("il database in memoria deve potersi aprire");
    };
    let (Ok(identifier), Ok(title)) = (
        SourceIdentifier::try_new("canale_autorizzato"),
        DisplayName::try_new("Canale autorizzato"),
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

    // Un dizionario pubblicato, con un termine.
    let mut dizionari = DictionaryService::new(database);
    let (Ok(name), Ok(description)) = (
        DictionaryName::try_new("Dizionario in vigore"),
        DictionaryDescription::try_new("per la prova della relazione"),
    ) else {
        panic!("i valori del dizionario devono essere validi");
    };
    let Ok((dictionary_id, version_id)) = dizionari.create(
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
    let (Ok(text), Ok(category), Ok(language), Ok(note), Ok(level)) = (
        TermText::try_new("molotov"),
        TermCategory::try_new("azione"),
        LanguageTag::try_new("it"),
        TermNote::try_new("termine di prova"),
        SuggestedLevel::try_new(3),
    ) else {
        panic!("i valori del termine devono essere validi");
    };
    let Ok(_) = dizionari.add_terms(
        version_id,
        &[NewDictionaryTerm {
            version_id,
            text,
            category,
            language,
            match_mode: MatchMode::NormalizedWord,
            suggested_level: level,
            note,
        }],
        &operator(),
        now(),
    ) else {
        panic!("il termine deve potersi aggiungere");
    };
    let Ok(()) = dizionari.publish(version_id, &operator(), now()) else {
        panic!("la pubblicazione deve riuscire");
    };

    // Ciò che il riepilogo del wizard calcola.
    let Ok(extra) = TermText::try_new("deposito") else {
        panic!("la parola aggiunta deve essere valida");
    };
    let selection = DictionarySelection {
        dictionary_ids: vec![dictionary_id],
        ad_hoc_terms: vec![SessionCustomTerm::normalised(extra)],
    };
    let Ok(configuration) = dizionari.resolve(&selection) else {
        panic!("la configurazione deve risolversi");
    };
    let Ok(scelti) = dizionari.selected_versions(&selection.dictionary_ids) else {
        panic!("le versioni devono potersi fotografare");
    };
    let choice = DictionaryChoice {
        versions: scelti
            .iter()
            .map(|scelto| (scelto.id, scelto.version_id))
            .collect(),
        custom_terms: selection.ad_hoc_terms.clone(),
    };

    // L'avvio, come lo fa la schermata.
    let mut monitoraggio = MonitoringService::new(dizionari.into_database());
    let Ok(label) = DisplayName::try_new("Monitoraggio con dizionario") else {
        panic!("nome di prova");
    };
    let Ok(session_id) = monitoraggio.begin(
        label,
        &operator(),
        WizardDuration::Manual,
        &[source_id],
        Some(&configuration),
        &choice,
        now(),
    ) else {
        panic!("il monitoraggio deve avviarsi");
    };

    let Ok(in_vigore) = monitoraggio
        .database()
        .session_dictionary_version_ids(session_id)
    else {
        panic!("le versioni in vigore devono potersi leggere");
    };
    assert_eq!(
        in_vigore,
        vec![version_id],
        "la relazione deve poter dire quale versione era in vigore"
    );
}

/// **Due grafie della stessa parola non impediscono l'avvio** (FINAL-REVIEW-01,
/// revisione finale del diff).
///
/// Il wizard tiene «Bomba» e «bomba» come due voci; il risolutore le unisce,
/// l'archivio rifiuta la seconda. Prima di questa prova l'avvio falliva e
/// restava una sessione pianificata senza configurazione.
#[test]
fn due_grafie_della_stessa_parola_si_scrivono_una_volta_con_il_livello_piu_alto() {
    let Ok(database) = open_in_memory_database() else {
        panic!("il database in memoria deve potersi aprire");
    };
    let (Ok(identifier), Ok(title)) = (
        SourceIdentifier::try_new("canale_autorizzato"),
        DisplayName::try_new("Canale autorizzato"),
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

    let (Ok(maiuscola), Ok(minuscola), Ok(tre), Ok(quattro)) = (
        TermText::try_new("Bomba"),
        TermText::try_new("bomba"),
        SuggestedLevel::try_new(3),
        SuggestedLevel::try_new(4),
    ) else {
        panic!("le parole di prova devono essere valide");
    };
    let parole = vec![
        SessionCustomTerm {
            text: maiuscola,
            match_mode: MatchMode::NormalizedWord,
            suggested_level: tre,
        },
        SessionCustomTerm {
            text: minuscola,
            match_mode: MatchMode::NormalizedWord,
            suggested_level: quattro,
        },
    ];
    let dizionari = DictionaryService::new(database);
    let selection = DictionarySelection {
        dictionary_ids: Vec::new(),
        ad_hoc_terms: parole.clone(),
    };
    let Ok(configuration) = dizionari.resolve(&selection) else {
        panic!("la configurazione deve risolversi");
    };
    let choice = DictionaryChoice {
        versions: Vec::new(),
        custom_terms: parole,
    };

    let mut monitoraggio = MonitoringService::new(dizionari.into_database());
    let Ok(label) = DisplayName::try_new("Monitoraggio con due grafie") else {
        panic!("nome di prova");
    };
    let avvio = monitoraggio.begin(
        label,
        &operator(),
        WizardDuration::Manual,
        &[source_id],
        Some(&configuration),
        &choice,
        now(),
    );
    let Ok(session_id) = avvio else {
        panic!("il monitoraggio deve avviarsi: {avvio:?}");
    };

    let Ok(scritte) = monitoraggio.database().session_custom_terms(session_id) else {
        panic!("le parole aggiunte devono potersi leggere");
    };
    assert_eq!(scritte.len(), 1, "una parola sola, come nel risolutore");
    assert_eq!(scritte[0].text.as_str(), "Bomba", "resta la prima grafia");
    assert_eq!(
        scritte[0].suggested_level, quattro,
        "con il livello più alto"
    );
}

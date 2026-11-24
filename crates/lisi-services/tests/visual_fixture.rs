//! Archivio di prova per la verifica a vista delle schermate.
//!
//! Le schermate Storico e Alert mostrano contenuti acquisiti. Su una postazione
//! che non ha mai condotto un monitoraggio l'archivio è vuoto, e una schermata
//! vuota non dice se le righe siano leggibili, se il testo lungo venga tagliato
//! bene, se i livelli si distinguano. Questa prova costruisce un archivio con
//! contenuti **dichiaratamente inventati** perché quella verifica sia possibile.
//!
//! # Tre limiti, perché non diventi altro
//!
//! È `#[ignore]`: non viene eseguita dal quality gate né dalla CI, e va chiesta
//! per nome. Scrive **solo** nel percorso indicato dalla variabile
//! `LISI_FIXTURE_DB`, e senza quella variabile non fa nulla: non può toccare
//! l'archivio di esercizio nemmeno per errore. I testi non imitano materiale
//! reale: sono frasi neutre costruite per far scattare termini di prova.
//!
//! Si esegue così, da PowerShell:
//!
//! ```text
//! $env:LISI_FIXTURE_DB = "...\verifica\monitor.sqlite"
//! cargo test -p lisi-services --test visual_fixture -- --ignored
//! ```

use lisi_core::Timestamp;
use lisi_core::model::AcquisitionOrigin;
use lisi_core::model::dictionary::{
    ConfigurationResolver, MatchMode, ResolvedDictionaryConfiguration, TermProvenance,
};
use lisi_core::model::{NewSession, NewSource, SessionDuration, SourceKind};
use lisi_core::text::{
    Actor, ContentBody, ContentUrl, DisplayName, LanguageTag, RemoteMessageId, SourceIdentifier,
    TermCategory, TermText,
};
use lisi_services::analysis::{AnalysisService, NewContentDraft};
use lisi_storage::Database;

/// Termini di prova: parole comuni, nessun riferimento a persone o categorie.
const TERMS: [(&str, i8); 4] = [("alfa", 4), ("beta", 3), ("gamma", 1), ("recensione", -2)];

/// Contenuti di prova, con il testo lungo in fondo per vedere il taglio.
const BODIES: [&str; 6] = [
    "Messaggio di prova con la parola alfa e anche beta.",
    "Messaggio di prova con la parola beta.",
    "Messaggio di prova con la parola gamma.",
    "Messaggio di prova senza alcun termine del dizionario.",
    "Messaggio di prova con beta dentro una recensione, che la attenua.",
    "Messaggio di prova volutamente lungo, ripetuto per verificare che il testo venga tagliato \
     con l'ellissi invece di essere troncato in silenzio: alfa. Ripetizione uno. Ripetizione due. \
     Ripetizione tre. Ripetizione quattro. Ripetizione cinque. Ripetizione sei. Ripetizione sette. \
     Ripetizione otto. Ripetizione nove. Ripetizione dieci.",
];

fn configuration() -> ResolvedDictionaryConfiguration {
    let mut resolver = ConfigurationResolver::new();
    for (text, level) in TERMS {
        let (Ok(text), Ok(category), Ok(language)) = (
            TermText::try_new(text),
            TermCategory::try_new("prova"),
            LanguageTag::try_new("it"),
        ) else {
            panic!("i valori del termine devono essere validi");
        };
        let Ok(()) = resolver.add(
            text,
            category,
            language,
            MatchMode::NormalizedWord,
            level,
            TermProvenance::ad_hoc(),
        ) else {
            panic!("il termine doveva essere accettato");
        };
    }
    resolver.finish()
}

#[test]
#[ignore = "fixture per la verifica a vista: richiede LISI_FIXTURE_DB"]
fn build_a_visible_archive() {
    let Ok(path) = std::env::var("LISI_FIXTURE_DB") else {
        panic!("senza LISI_FIXTURE_DB la prova non scrive nulla, ed e' voluto");
    };

    let path = std::path::PathBuf::from(path);
    let _ = std::fs::remove_file(&path);
    let Ok(mut database) = Database::open(&path) else {
        panic!("l'archivio di prova deve potersi aprire");
    };

    let now = Timestamp::from_millis(1_752_000_000_000);
    let Ok(operator) = Actor::try_new("operatore.prova") else {
        panic!("l'attore di prova deve essere valido");
    };

    let (Ok(identifier), Ok(title), Ok(label)) = (
        SourceIdentifier::try_new("canale_di_prova"),
        DisplayName::try_new("Canale di prova"),
        DisplayName::try_new("Monitoraggio di prova"),
    ) else {
        panic!("i valori di prova devono essere validi");
    };
    let Ok(source_id) = database.insert_source(
        &NewSource {
            kind: SourceKind::Channel,
            identifier,
            display_name: title,
            authorized_by: operator.clone(),
            active: true,
        },
        now,
    ) else {
        panic!("la fonte deve potersi registrare");
    };
    let Ok(session_id) = database.insert_session(
        &NewSession {
            label,
            started_by: operator.clone(),
            duration: SessionDuration::Preset { seconds: 3_600 },
            source_ids: vec![source_id],
        },
        now,
    ) else {
        panic!("la sessione deve potersi creare");
    };

    let configuration = configuration();
    let mut analysis = AnalysisService::new(database);
    for (index, body) in BODIES.iter().enumerate() {
        let Ok(index) = i64::try_from(index) else {
            panic!("l'indice deve stare in un intero");
        };
        let (Ok(remote), Ok(body), Ok(url)) = (
            RemoteMessageId::try_new(&format!("prova-{index}")),
            ContentBody::try_new(body),
            ContentUrl::try_new(&format!("https://esempio.invalid/prova/{index}")),
        ) else {
            panic!("i valori del contenuto devono essere validi");
        };
        let acquired = now.plus_seconds(index * 60);

        let Ok(_) = analysis.analyse_and_record(
            &NewContentDraft {
                session_id,
                source_id,
                remote_message_id: remote,
                author: None,
                author_identifier: None,
                author_username: None,
                body,
                url: Some(url),
                published_at: acquired,
                acquired_at: acquired,
                origin: AcquisitionOrigin::Observed,
            },
            &configuration,
            &operator,
            acquired,
        ) else {
            panic!("l'analisi deve riuscire");
        };
    }

    // La connessione si chiude qui: il WAL viene riversato nel file, che e'
    // quello che l'applicazione riaprira'.
    drop(analysis);
    assert!(path.exists(), "l'archivio di prova deve esistere");
}

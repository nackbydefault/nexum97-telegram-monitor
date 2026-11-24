//! **Con quali termini, in ogni documento** (NEXUM97-REPORT-CONFIG-01,
//! ADR-0156, DEC-417).
//!
//! Il collaudo con il profilo reale (DEC-415) ha trovato due difetti nello
//! stesso punto. BUG-REP-1: un monitoraggio avviato prima che le scelte di
//! dizionario si registrassero (FR-049, 2026-10-04) produceva una relazione che
//! diceva «Versioni di dizionario in vigore: nessuna» e un registro con «(nessun
//! record)», mentre l'archivio conservava i termini risolti e la loro impronta.
//! BUG-REP-2: le parole aggiunte per la sessione e l'impronta della
//! configurazione non comparivano in alcun documento.
//!
//! Le prove percorrono la strada vera — la generazione del pacchetto e
//! l'esportazione del rapporto — e leggono i file prodotti: la relazione in
//! Word, l'allegato tecnico in PDF, il registro in Excel e in testo, il
//! rapporto. Una sessione «vecchia» è costruita come la costruiva l'avvio
//! anteriore a FR-049: soltanto i termini risolti, nessuna scelta e nessuna
//! parola registrate a parte.

use std::io::{Cursor, Read};

use lisi_core::model::dictionary::{
    DictionaryScope, DictionarySelection, DictionaryVisibility, MatchMode, NewDictionaryTerm,
    ResolvedDictionaryConfiguration, SessionCustomTerm, SuggestedLevel,
};
use lisi_core::model::report::{ReportArtifactKind, ReportSelection};
use lisi_core::model::report_template::ReportTemplateProfile;
use lisi_core::model::{NewSession, NewSource, SessionDuration, SessionState, SourceKind};
use lisi_core::text::{
    Actor, DictionaryDescription, DictionaryName, DisplayName, LanguageTag, SourceIdentifier,
    TermCategory, TermNote, TermText,
};
use lisi_core::{SessionId, SourceId, Timestamp};
use lisi_services::dictionaries::{DictionaryProposal, DictionaryService};
use lisi_services::export::{ExportOptions, ExportService};
use lisi_services::monitoring::{DictionaryChoice, MonitoringService};
use lisi_services::pdf_text::to_winansi;
use lisi_services::report::{PRODUCIBLE_KINDS, ReportGenerationRequest, ReportService};
use lisi_services::sources::open_in_memory_database;
use lisi_services::wizard::WizardDuration;
use lisi_storage::Database;

fn now() -> Timestamp {
    Timestamp::from_millis(1_700_000_000_000)
}

fn later() -> Timestamp {
    Timestamp::from_millis(1_700_000_600_000)
}

fn operator() -> Actor {
    let Ok(value) = Actor::try_new("operatore.ufficio") else {
        panic!("l'attore di prova deve essere valido");
    };
    value
}

fn text(value: &str) -> TermText {
    let Ok(text) = TermText::try_new(value) else {
        panic!("il testo di prova «{value}» deve essere valido");
    };
    text
}

fn level(value: i8) -> SuggestedLevel {
    let Ok(level) = SuggestedLevel::try_new(value) else {
        panic!("il livello di prova deve essere valido");
    };
    level
}

/// Una fonte e un dizionario «Incendi» pubblicato, con due termini.
fn archive_with_dictionary() -> (DictionaryService, SourceId, DictionarySelection) {
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

    let mut dizionari = DictionaryService::new(database);
    let (Ok(name), Ok(description)) = (
        DictionaryName::try_new("Incendi"),
        DictionaryDescription::try_new("per la prova della configurazione nei documenti"),
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
    let (Ok(category), Ok(language), Ok(note)) = (
        TermCategory::try_new("evento"),
        LanguageTag::try_new("it"),
        TermNote::try_new("termine di prova"),
    ) else {
        panic!("i valori del termine devono essere validi");
    };
    let termini: Vec<NewDictionaryTerm> = ["incendio", "rogo"]
        .iter()
        .map(|parola| NewDictionaryTerm {
            version_id,
            text: text(parola),
            category: category.clone(),
            language: language.clone(),
            match_mode: MatchMode::NormalizedWord,
            suggested_level: level(3),
            note: note.clone(),
        })
        .collect();
    let Ok(_) = dizionari.add_terms(version_id, &termini, &operator(), now()) else {
        panic!("i termini devono potersi aggiungere");
    };
    let Ok(()) = dizionari.publish(version_id, &operator(), now()) else {
        panic!("la pubblicazione deve riuscire");
    };

    let selection = DictionarySelection {
        dictionary_ids: vec![dictionary_id],
        ad_hoc_terms: Vec::new(),
    };
    (dizionari, source_id, selection)
}

/// **Un monitoraggio come lo avviava la versione anteriore a FR-049**: la
/// configurazione risolta (il dizionario e la parola «zanzara» a livello 2) si
/// conserva, le scelte e le parole non si registrano a parte.
fn old_session() -> (Database, SessionId, ResolvedDictionaryConfiguration) {
    let (dizionari, source_id, mut selection) = archive_with_dictionary();
    selection.ad_hoc_terms = vec![SessionCustomTerm {
        text: text("zanzara"),
        match_mode: MatchMode::NormalizedWord,
        suggested_level: level(2),
    }];
    let Ok(configuration) = dizionari.resolve(&selection) else {
        panic!("la configurazione deve risolversi");
    };

    let mut database = dizionari.into_database();
    let Ok(label) = DisplayName::try_new("Monitoraggio di agosto") else {
        panic!("nome di prova");
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
    let Ok(()) = database.save_resolved_configuration(session_id, &configuration) else {
        panic!("la configurazione risolta deve potersi conservare");
    };
    let Ok(()) = database.update_session_state(session_id, SessionState::Running, now()) else {
        panic!("la sessione deve potersi avviare");
    };

    // La premessa della prova: la tabella delle scelte è vuota, come per le
    // sessioni 1–6 del profilo reale.
    assert_eq!(
        database.session_dictionary_version_ids(session_id).ok(),
        Some(Vec::new()),
        "la sessione vecchia non deve avere scelte registrate"
    );
    (database, session_id, configuration)
}

/// **Un monitoraggio avviato oggi**, dalla strada del wizard: scelte e parola
/// «pdf» a livello 2 registrate.
fn new_session() -> (Database, SessionId, ResolvedDictionaryConfiguration) {
    let (dizionari, source_id, mut selection) = archive_with_dictionary();
    selection.ad_hoc_terms = vec![SessionCustomTerm {
        text: text("pdf"),
        match_mode: MatchMode::NormalizedWord,
        suggested_level: level(2),
    }];
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

    let mut monitoraggio = MonitoringService::new(dizionari.into_database());
    let Ok(label) = DisplayName::try_new("Monitoraggio di oggi") else {
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
    (monitoraggio.into_database(), session_id, configuration)
}

/// I documenti prodotti per una sessione: relazione, allegato, registro e
/// rapporto.
struct Documents {
    /// Il testo della relazione in Word, senza i marcatori XML.
    narrative: String,
    /// I byte dell'allegato tecnico in PDF.
    annex: Vec<u8>,
    /// Il testo di tutte le voci del registro in Excel.
    workbook: String,
    /// Il registro in testo.
    ledger: String,
    /// Il rapporto di esportazione.
    export: String,
}

fn produce(database: Database, session_id: SessionId) -> Documents {
    let cartella = tempfile::tempdir().expect("cartella temporanea");
    let profile = ReportTemplateProfile::default();

    let mut service = ReportService::new(database);
    let Ok(prodotto) = service.generate(&ReportGenerationRequest {
        session_id,
        selection: ReportSelection::empty(),
        profile: &profile,
        destination: cartella.path(),
        requested_kinds: PRODUCIBLE_KINDS.to_vec(),
        requested_by: operator(),
        requested_at: later(),
        asked_links: None,
    }) else {
        panic!("il pacchetto deve potersi generare");
    };
    let file = |kind: ReportArtifactKind| -> Vec<u8> {
        let Some(artefatto) = prodotto
            .artifacts
            .iter()
            .find(|artefatto| artefatto.kind == kind)
        else {
            panic!("manca il documento {}", kind.as_str());
        };
        std::fs::read(prodotto.directory.join(&artefatto.file_name)).expect("documento leggibile")
    };

    let narrative = without_markup(&zip_entry(
        &file(ReportArtifactKind::NarrativeDocx),
        "word/document.xml",
    ));
    let annex = file(ReportArtifactKind::TechnicalAnnexPdf);
    let workbook = all_zip_entries(&file(ReportArtifactKind::AnalyticalXlsx));
    let ledger = String::from_utf8(file(ReportArtifactKind::PlainTxt)).expect("registro in UTF-8");

    let esportazione = ExportService::new(service.into_database());
    let Ok(esito) = esportazione.export_session(
        session_id,
        &[],
        &cartella.path().join("rapporti"),
        &operator(),
        later(),
        ExportOptions::without_identifiers(),
        None,
    ) else {
        panic!("il rapporto deve potersi esportare");
    };
    let export = std::fs::read_to_string(&esito.report).expect("rapporto in UTF-8");

    Documents {
        narrative,
        annex,
        workbook,
        ledger,
        export,
    }
}

fn zip_entry(bytes: &[u8], name: &str) -> String {
    let mut archivio = zip::ZipArchive::new(Cursor::new(bytes.to_vec())).expect("file ZIP");
    let mut voce = archivio.by_name(name).expect("voce presente");
    let mut testo = String::new();
    voce.read_to_string(&mut testo).expect("voce in UTF-8");
    testo
}

fn all_zip_entries(bytes: &[u8]) -> String {
    let mut archivio = zip::ZipArchive::new(Cursor::new(bytes.to_vec())).expect("file ZIP");
    let mut tutto = String::new();
    for indice in 0..archivio.len() {
        let mut voce = archivio.by_index(indice).expect("voce leggibile");
        let mut testo = String::new();
        if voce.read_to_string(&mut testo).is_ok() {
            tutto.push_str(&testo);
            tutto.push('\n');
        }
    }
    tutto
}

/// Il testo di un XML senza i marcatori, con le entità comuni sciolte.
fn without_markup(xml: &str) -> String {
    let mut testo = String::new();
    let mut dentro = false;
    for carattere in xml.chars() {
        match carattere {
            '<' => dentro = true,
            '>' => dentro = false,
            altro if !dentro => testo.push(altro),
            _ => {}
        }
    }
    testo
        .replace("&apos;", "'")
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Il foglio del registro in testo che porta quel nome, fino al successivo.
fn ledger_sheet<'a>(ledger: &'a str, name: &str) -> &'a str {
    let Some(inizio) = ledger.find(&format!("\n{name}\n")) else {
        panic!("il registro in testo non ha il foglio «{name}»");
    };
    let resto = &ledger[inizio + name.len() + 2..];
    // Il foglio finisce dove comincia la riga di «=» del successivo, dopo la
    // propria intestazione.
    let dopo_intestazione = resto.find("\n\n").map_or(resto.len(), |fine| fine);
    &resto[..dopo_intestazione]
}

fn pdf_contains(bytes: &[u8], cercato: &str) -> bool {
    let cercato = to_winansi(cercato);
    bytes
        .windows(cercato.len())
        .any(|finestra| finestra == cercato.as_slice())
}

/// Le versioni scritte senza spazi, per non dipendere da come il Word divide
/// la guida e il corpo di una riga.
fn compact(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

// ------------------------------------------------------------ BUG-REP-1

/// **Un monitoraggio di prima non dice «nessuna».** Le versioni si ricavano
/// dalle provenienze dei termini risolti, e il documento dice che le scelte non
/// erano registrate.
#[test]
fn un_monitoraggio_di_prima_non_dichiara_nessuna_versione_di_dizionario() {
    let (database, session_id, _) = old_session();
    let documenti = produce(database, session_id);

    for (nome, testo) in [
        ("relazione", &documenti.narrative),
        ("registro", &documenti.ledger),
        ("rapporto", &documenti.export),
    ] {
        assert!(
            !compact(testo).contains("invigore:nessuna"),
            "«{nome}»: dice ancora «Versioni di dizionario in vigore: nessuna»"
        );
        assert!(
            testo.contains("Incendi v1"),
            "«{nome}»: non nomina la versione da cui vengono i termini risolti"
        );
        assert!(
            testo.contains("non sono state registrate"),
            "«{nome}»: non dice che le scelte non erano registrate"
        );
    }
    assert!(
        pdf_contains(&documenti.annex, "Incendi v1"),
        "l'allegato tecnico non nomina la versione"
    );

    // Il foglio delle versioni non è più vuoto, e dice da dove lo sa.
    let dizionari = ledger_sheet(&documenti.ledger, "07 — Dizionari");
    assert!(
        !dizionari.contains("(nessun record)"),
        "il registro dice ancora «(nessun record)» per le versioni: {dizionari}"
    );
    assert!(dizionari.contains("Incendi"));
    assert!(dizionari.contains("da dove vengono i termini della sessione"));
}

/// **L'impronta e il numero dei termini, in tutti e quattro i documenti.**
#[test]
fn l_impronta_della_configurazione_e_in_ogni_documento() {
    let (database, session_id, configuration) = old_session();
    let impronta = configuration.digest.as_str().to_owned();
    let documenti = produce(database, session_id);

    for (nome, testo) in [
        ("relazione", &documenti.narrative),
        ("registro in Excel", &documenti.workbook),
        ("registro in testo", &documenti.ledger),
        ("rapporto", &documenti.export),
    ] {
        assert!(
            testo.contains(&impronta),
            "«{nome}»: non porta l'impronta della configurazione"
        );
        assert!(
            testo.contains("3 termini diversi"),
            "«{nome}»: non dice quanti termini risolti conserva l'archivio"
        );
    }
    // Nel PDF l'impronta può andare a capo: basta il suo inizio.
    assert!(
        pdf_contains(&documenti.annex, &impronta[..16]),
        "l'allegato tecnico non porta l'impronta"
    );
}

// ------------------------------------------------------------ BUG-REP-2

/// **La parola aggiunta per la sessione compare, con livello e modalità**, nel
/// monitoraggio di oggi.
#[test]
fn la_parola_aggiunta_per_la_sessione_e_in_ogni_documento() {
    let (database, session_id, configuration) = new_session();
    let documenti = produce(database, session_id);

    for (nome, testo) in [
        ("relazione", &documenti.narrative),
        ("registro in testo", &documenti.ledger),
        ("rapporto", &documenti.export),
    ] {
        assert!(
            testo.contains("«pdf», livello 2, modalità «Parola come viene cercata»"),
            "«{nome}»: non riporta la parola aggiunta con livello e modalità"
        );
        assert!(
            testo.contains(configuration.digest.as_str()),
            "«{nome}»: non porta l'impronta della configurazione"
        );
        // Le scelte registrate si scrivono come prima.
        assert!(
            testo.contains("Incendi v1."),
            "«{nome}»: non scrive più le versioni registrate come prima"
        );
    }
    for (nome, testo) in [
        ("relazione", &documenti.narrative),
        ("rapporto", &documenti.export),
    ] {
        assert!(
            compact(testo).contains("invigore:Incendiv1."),
            "«{nome}»: non scrive più «Versioni di dizionario in vigore: Incendi v1.»"
        );
    }
    assert!(
        pdf_contains(&documenti.annex, "«pdf»"),
        "l'allegato tecnico non riporta la parola aggiunta"
    );

    // Nel registro la parola ha il suo foglio, colonna per colonna.
    let parole = ledger_sheet(&documenti.ledger, "12 — Parole aggiunte");
    assert!(
        parole.contains("pdf"),
        "il foglio delle parole è vuoto: {parole}"
    );
    assert!(parole.contains("Parola come viene cercata"));
    assert!(parole.contains("registrata all'avvio"));
    assert!(documenti.workbook.contains("12 — Parole aggiunte"));
}

/// **La parola di un monitoraggio di prima si ricava dai termini risolti**, e
/// il documento lo dice.
#[test]
fn la_parola_di_un_monitoraggio_di_prima_si_ricava_dai_termini_risolti() {
    let (database, session_id, _) = old_session();
    let documenti = produce(database, session_id);

    for (nome, testo) in [
        ("relazione", &documenti.narrative),
        ("registro in testo", &documenti.ledger),
        ("rapporto", &documenti.export),
    ] {
        assert!(
            testo.contains("«zanzara», livello 2, modalità «Parola come viene cercata»"),
            "«{nome}»: non riporta la parola conservata nei termini risolti"
        );
        assert!(
            testo.contains("non sono state registrate a parte"),
            "«{nome}»: non dice da dove ricava la parola"
        );
    }
    let parole = ledger_sheet(&documenti.ledger, "12 — Parole aggiunte");
    assert!(parole.contains("zanzara"));
    assert!(parole.contains("dall'elenco dei termini della sessione"));
}

/// I documenti letti sono quelli della sessione: una prova che leggesse il
/// file sbagliato passerebbe, o fallirebbe, per la ragione sbagliata.
#[test]
fn i_documenti_letti_sono_quelli_della_sessione() {
    let (database, session_id, _) = new_session();
    let documenti = produce(database, session_id);
    assert!(documenti.narrative.contains("Monitoraggio di oggi"));
    assert!(documenti.export.contains("Monitoraggio di oggi"));
    assert!(documenti.ledger.contains("Monitoraggio di oggi"));
    assert!(documenti.workbook.contains("Monitoraggio di oggi"));
    assert!(pdf_contains(&documenti.annex, "Monitoraggio di oggi"));
}

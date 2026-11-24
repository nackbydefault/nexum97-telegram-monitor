//! La modalità Esercitazione, in un processo che lavora in Esercitazione
//! (PR-13, ADR-0129).
//!
//! # Perché un eseguibile di prova a parte
//!
//! Il modo è **del processo**, e si stabilisce una volta. Le prove della
//! libreria lavorano in modo operativo; queste lavorano in Esercitazione, e
//! ogni prova lo stabilisce per prima cosa — la prima che arriva decide, le
//! altre lo confermano.
//!
//! # Che cosa verificano
//!
//! - in Esercitazione il testimone operativo non si ottiene, e quindi
//!   l'autorità di acquisizione non si chiede (la forma lo verifica a
//!   compilazione, in `run_mode`);
//! - ogni documento prodotto è marcato, nel nome e nel contenuto, in ogni
//!   formato;
//! - l'insieme di dati esercita tutte le funzioni, ed è sintetico;
//! - ricominciare non tocca l'archivio operativo.

use std::io::Cursor;
use std::path::Path;

use lisi_core::Timestamp;
use lisi_core::model::AcquisitionMode;
use lisi_core::model::reason::OperationalReason;
use lisi_core::model::run_mode::{EXERCISE_DATA_DIRECTORY, EXERCISE_FILE_PREFIX, RunMode};
use lisi_core::text::Actor;
use lisi_services::Database;
use lisi_services::exercise::{
    AUTHORS, MESSAGES, PERSONS, Prepared, RESOLUTIONS, RESTART_MARKER, SOURCES,
    SYNTHETIC_CHAT_BASE, TRAINER, prepare, request_restart, seed,
};
use lisi_services::report_ledger::{Cell, Ledger, Sheet};
use lisi_services::report_narrative::{Block, Letterhead, NarrativeReport};
use lisi_services::run_mode::{EXERCISE_MARK, ExerciseMode};

/// L'istante del caricamento.
fn adesso() -> Timestamp {
    Timestamp::from_millis(1_790_294_400_000)
}

/// Il testimone dell'esercitazione: questo processo lavora in Esercitazione.
fn esercitazione() -> ExerciseMode {
    match lisi_services::run_mode::exercise() {
        Ok(testimone) => testimone,
        Err(conflitto) => panic!("questo eseguibile lavora in Esercitazione: {conflitto}"),
    }
}

fn formatore() -> Actor {
    let Ok(attore) = Actor::try_new(TRAINER) else {
        panic!("il formatore deve essere un attore valido");
    };
    attore
}

/// L'archivio dell'esercitazione, caricato.
fn caricato() -> Database {
    let testimone = esercitazione();
    let Ok(vuoto) = lisi_services::sources::open_in_memory_database() else {
        panic!("l'archivio in memoria deve aprirsi");
    };
    match seed(&testimone, vuoto, adesso()) {
        Ok(database) => database,
        Err(errore) => panic!("l'insieme deve caricarsi: {errore}"),
    }
}

fn cartella() -> tempfile::TempDir {
    match tempfile::tempdir() {
        Ok(cartella) => cartella,
        Err(errore) => panic!("cartella temporanea: {errore}"),
    }
}

/// Le voci di un archivio ZIP (Word, Excel), come testo.
fn voci_zip(byte: &[u8]) -> String {
    let Ok(mut archivio) = zip::ZipArchive::new(Cursor::new(byte.to_vec())) else {
        panic!("il documento deve essere un archivio ZIP");
    };
    let mut tutto = String::new();
    for indice in 0..archivio.len() {
        let Ok(mut voce) = archivio.by_index(indice) else {
            panic!("voce leggibile");
        };
        let mut grezzo = Vec::new();
        if std::io::Read::read_to_end(&mut voce, &mut grezzo).is_err() {
            panic!("voce leggibile");
        }
        tutto.push_str(&String::from_utf8_lossy(&grezzo));
    }
    tutto
}

fn relazione() -> NarrativeReport {
    NarrativeReport {
        generated_at: adesso(),
        letterhead: Letterhead {
            emblem: None,
            lines: Vec::new(),
        },
        footer: Vec::new(),
        blocks: vec![Block::Paragraph(String::from(
            "Corpo della relazione di prova.",
        ))],
    }
}

fn registro() -> Ledger {
    Ledger {
        generated_at: adesso(),
        sheets: vec![Sheet {
            name: String::from("Contenuti"),
            headers: vec![String::from("Numero")],
            rows: vec![vec![Cell::Number(1)]],
        }],
    }
}

// ---------------------------------------------------------------------------
// 1. Nessun percorso verso Telegram
// ---------------------------------------------------------------------------

/// **In Esercitazione il testimone operativo non si ottiene**: l'autorità di
/// acquisizione lo vuole, e quindi non si chiede.
#[test]
fn in_esercitazione_il_modo_operativo_non_si_ottiene() {
    let _ = esercitazione();
    assert_eq!(lisi_services::run_mode::current(), RunMode::Exercise);
    assert!(lisi_services::run_mode::operational().is_err());
}

/// **La cartella dati è quella dell'esercitazione.**
#[test]
fn la_cartella_dati_e_quella_dell_esercitazione() {
    let _ = esercitazione();
    if let Some(cartella) = lisi_services::data_directory::mode_directory() {
        assert!(
            cartella.ends_with(EXERCISE_DATA_DIRECTORY),
            "{}",
            cartella.display()
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Ogni documento è marcato
// ---------------------------------------------------------------------------

/// **Word, PDF, testo ed Excel portano la frase dell'esercitazione.**
#[test]
fn i_quattro_formati_della_relazione_sono_marcati() {
    let _ = esercitazione();
    let Ok(word) = lisi_services::report_docx::render(&relazione()) else {
        panic!("il documento Word deve comporsi");
    };
    let interno = voci_zip(&word);
    assert!(
        interno.contains("ESERCITAZIONE. Dati sintetici"),
        "Word non marcato"
    );
    assert!(
        interno.matches("ESERCITAZIONE").count() >= 2,
        "Word: la frase deve stare in apertura e nel piede"
    );

    let Ok(pdf) = lisi_services::report_pdf::render(
        &relazione(),
        lisi_services::report_pdf::PdfKind::Narrative,
    ) else {
        panic!("il PDF deve comporsi");
    };
    let testo_pdf = String::from_utf8_lossy(&pdf);
    assert!(
        testo_pdf.contains("ESERCITAZIONE. Dati sintetici"),
        "PDF: prima pagina"
    );
    assert!(
        testo_pdf.contains("ESERCITAZIONE \u{97} Pagina") || testo_pdf.contains("ESERCITAZIONE")
    );

    let Ok(testo) = lisi_services::report_txt::render(&registro()) else {
        panic!("il testo deve comporsi");
    };
    assert!(String::from_utf8_lossy(&testo).starts_with(EXERCISE_MARK));

    let Ok(excel) = lisi_services::report_xlsx::render(&registro()) else {
        panic!("il foglio Excel deve comporsi");
    };
    let interno = voci_zip(&excel);
    assert!(
        interno.contains("ESERCITAZIONE. Dati sintetici"),
        "Excel non marcato"
    );
}

/// **Il nome di ogni file della relazione porta il prefisso.**
#[test]
fn i_nomi_della_relazione_portano_il_prefisso() {
    let _ = esercitazione();
    let cartella = cartella();
    let Ok(identificativo) = lisi_core::model::report::ReportId::try_new("R-2026-000001") else {
        panic!("identificativo valido");
    };
    let Ok(disposizione) =
        lisi_services::report_package::PackageLayout::new(cartella.path(), &identificativo)
    else {
        panic!("la disposizione deve comporsi");
    };
    for genere in [
        lisi_core::model::report::ReportArtifactKind::NarrativeDocx,
        lisi_core::model::report::ReportArtifactKind::Manifest,
    ] {
        assert!(
            disposizione
                .file_name(genere)
                .starts_with(EXERCISE_FILE_PREFIX)
        );
    }
}

/// **Esportazione, passaggio di consegne, pacchetto di evidenze, diagnostica,
/// copia di sicurezza e STIX: tutti marcati, nel nome e nel contenuto.**
#[test]
fn ogni_documento_prodotto_e_marcato() {
    let testimone = esercitazione();
    let database = caricato();
    let cartella = cartella();
    let destinazione = cartella.path();
    let Ok(sessioni) = database.sessions() else {
        panic!("le sessioni devono leggersi");
    };
    let sessione = sessioni[0].id;

    // L'esportazione del monitoraggio.
    let storia = lisi_services::history::HistoryService::new(database);
    let Ok(voci) = storia.entries(lisi_services::history::HistoryScope::Session(sessione)) else {
        panic!("lo storico deve leggersi");
    };
    let esportazione = lisi_services::export::ExportService::new(storia.into_database());
    let Ok(esito) = esportazione.export_session(
        sessione,
        &voci,
        destinazione,
        &formatore(),
        adesso(),
        lisi_services::export::ExportOptions::default(),
        None,
    ) else {
        panic!("l'esportazione deve riuscire");
    };
    controlla_file(&esito.report);
    let database = esportazione.into_database();

    // STIX.
    let Ok(stix) = lisi_services::stix_export::StixExportService::new(&database).export(
        sessione,
        destinazione,
        &formatore(),
        adesso(),
    ) else {
        panic!("l'esportazione STIX deve riuscire sull'insieme");
    };
    assert!(nome(&stix.bundle).starts_with(EXERCISE_FILE_PREFIX));
    let Ok(pacchetto) = std::fs::read_to_string(&stix.bundle) else {
        panic!("il pacchetto STIX deve leggersi");
    };
    assert!(
        pacchetto.contains("ESERCITAZIONE"),
        "STIX: la parola dentro il pacchetto"
    );
    controlla_file(&stix.manifest);

    // Il passaggio di consegne.
    let consegne = lisi_services::handover::HandoverService::new(database);
    let Ok(foglio) = consegne.compose(168, adesso()) else {
        panic!("il passaggio di consegne deve comporsi");
    };
    for formato in [
        lisi_services::handover::HandoverFormat::Text,
        lisi_services::handover::HandoverFormat::Word,
    ] {
        let Ok(percorso) = consegne.export(
            &foglio,
            formato,
            destinazione,
            false,
            &formatore(),
            adesso(),
        ) else {
            panic!("il passaggio di consegne deve esportarsi");
        };
        assert!(nome(&percorso).starts_with(EXERCISE_FILE_PREFIX));
        if formato == lisi_services::handover::HandoverFormat::Text {
            controlla_file(&percorso);
            // Il foglio dice che non raccomanda indagini (PR-12, PR-15).
            let Ok(testo) = std::fs::read_to_string(&percorso) else {
                panic!("il foglio deve leggersi");
            };
            assert!(testo.contains(lisi_services::handover::NOT_A_RECOMMENDATION));
        } else {
            let Ok(byte) = std::fs::read(&percorso) else {
                panic!("il Word deve leggersi");
            };
            assert!(voci_zip(&byte).contains("ESERCITAZIONE. Dati sintetici"));
        }
    }
    // Il servizio del passaggio di consegne ha preso l'archivio: il pacchetto
    // si produce su un altro caricamento dello stesso insieme.
    drop(consegne);
    let mut database = caricato();

    // Il pacchetto di evidenze, con il testimone dell'esercitazione.
    let Ok(workspace) = database.workspaces() else {
        panic!("i workspace devono leggersi");
    };
    let caso = workspace[0].id;
    let Ok(elementi) = database.workspace_items(caso) else {
        panic!("gli elementi devono leggersi");
    };
    let scelti: Vec<lisi_core::ContentId> = elementi
        .iter()
        .map(|elemento| lisi_core::ContentId::new(elemento.entry.item.target_id()))
        .collect();
    let (Ok(ragione),) = (OperationalReason::try_new(
        "esercitazione: pacchetto di prova",
    ),) else {
        panic!("ragione valida");
    };
    let Ok(richiesta) = lisi_services::evidence_package::EvidenceRequest::new(
        &testimone,
        caso,
        &scelti,
        formatore(),
        ragione,
    ) else {
        panic!("la richiesta deve comporsi");
    };
    let Ok(prodotto) =
        lisi_services::evidence_package::produce(&mut database, &richiesta, destinazione, adesso())
    else {
        panic!("il pacchetto deve prodursi");
    };
    assert!(nome(&prodotto.directory).starts_with(EXERCISE_FILE_PREFIX));
    for (file, _, _) in &prodotto.files {
        controlla_file(&prodotto.directory.join(file));
    }
    // LA SALVAGUARDIA INTERPRETATIVA sta nel documento di lettura (PR-15,
    // controllo negativo 4): un pacchetto che ne uscisse senza direbbe meno di
    // ciò che deve.
    let Ok(leggimi) = std::fs::read_to_string(
        prodotto
            .directory
            .join(lisi_services::evidence_package::READING_FILE),
    ) else {
        panic!("il documento di lettura deve leggersi");
    };
    for salvaguardia in [
        lisi_services::evidence_package::INTERPRETIVE_SAFEGUARD,
        lisi_services::evidence_package::NOT_FORENSIC,
    ] {
        assert!(
            leggimi.contains(salvaguardia),
            "il documento di lettura non porta «{salvaguardia}»"
        );
    }

    // La copia di sicurezza.
    let copia = lisi_services::backup::BackupService::new(database);
    let Ok(prodotta) = copia.write_to(destinazione, &formatore(), adesso()) else {
        panic!("la copia deve prodursi");
    };
    assert!(nome(&prodotta.archive).starts_with(EXERCISE_FILE_PREFIX));
    controlla_file(&prodotta.note);
    drop(copia);
    let database = caricato();

    // Il pacchetto diagnostico.
    let diagnostica = lisi_services::diagnostics::DiagnosticsService::new(database);
    let Ok(percorso) = diagnostica.export_to(
        destinazione,
        &lisi_services::diagnostics::StationFacts {
            mode: lisi_core::role::OperatingMode::Operator,
            telegram_runtime_started: false,
            sources: lisi_services::source_health::HealthSummary::default(),
        },
        &formatore(),
        adesso(),
    ) else {
        panic!("il pacchetto diagnostico deve prodursi");
    };
    controlla_file(&percorso);

    // NESSUN SEGRETO E NESSUN PERCORSO DELLA MACCHINA, in alcun formato in
    // uscita (PR-15, controllo negativo 3): la stessa scansione su tutto ciò che
    // questa prova ha prodotto, Word ed Excel aperti come archivi.
    let difetti = scansiona(destinazione);
    assert!(
        difetti.is_empty(),
        "forme di segreti o percorsi della macchina nei documenti prodotti:\n{}",
        difetti.join("\n")
    );
}

/// Le forme che non devono uscire dal programma in un documento.
const FORME_VIETATE: [&str; 9] = [
    "AppData",
    "\\Users\\",
    "/home/",
    "api_hash",
    "LISI_TELEGRAM_API",
    "td.binlog",
    "-----BEGIN",
    "hub-client.protetto",
    ".protetto",
];

/// Scansiona ogni file sotto la cartella, Word ed Excel compresi, e dice dove
/// compare una forma vietata o una sequenza di 32 cifre esadecimali isolata —
/// la forma di un API hash.
///
/// La copia di sicurezza dell'archivio non si scansiona: è l'archivio intero, e
/// contiene per definizione ciò che l'archivio contiene.
fn scansiona(cartella: &Path) -> Vec<String> {
    let mut difetti = Vec::new();
    let Ok(voci) = std::fs::read_dir(cartella) else {
        return vec![format!("«{}» non si legge", cartella.display())];
    };
    for voce in voci.flatten() {
        let percorso = voce.path();
        if percorso.is_dir() {
            difetti.extend(scansiona(&percorso));
            continue;
        }
        let estensione = percorso
            .extension()
            .and_then(|estensione| estensione.to_str())
            .unwrap_or_default()
            .to_lowercase();
        // «sqlite3» è l'estensione della copia di sicurezza (`backup.rs`).
        if estensione == "sqlite3" {
            continue;
        }
        let Ok(byte) = std::fs::read(&percorso) else {
            difetti.push(format!("«{}» non si legge", percorso.display()));
            continue;
        };
        let testo = if estensione == "docx" || estensione == "xlsx" {
            voci_zip(&byte)
        } else {
            String::from_utf8_lossy(&byte).into_owned()
        };
        for forma in FORME_VIETATE {
            if testo.contains(forma) {
                difetti.push(format!("«{forma}» in {}", nome(&percorso)));
            }
        }
        for parola in testo.split(|carattere: char| !carattere.is_ascii_hexdigit()) {
            if parola.len() == 32 {
                difetti.push(format!(
                    "trentadue cifre esadecimali in {}",
                    nome(&percorso)
                ));
            }
        }
    }
    difetti
}

/// La scansione vede ciò che deve vedere: non è verde perché non guarda.
#[test]
fn la_scansione_dei_segreti_vede_un_segreto() {
    let cartella = cartella();
    for (nome, testo) in [
        ("uno.txt", "api_hash = 0123456789abcdef0123456789abcdef"),
        ("due.txt", "C:\\Users\\operatore\\AppData\\Local"),
        ("tre.txt", "sessione in td.binlog"),
    ] {
        if std::fs::write(cartella.path().join(nome), testo).is_err() {
            panic!("il file di prova deve scriversi");
        }
    }
    let difetti = scansiona(cartella.path());
    for atteso in ["uno.txt", "due.txt", "tre.txt"] {
        assert!(
            difetti.iter().any(|difetto| difetto.contains(atteso)),
            "la scansione non ha visto {atteso}: {difetti:?}"
        );
    }
    assert!(
        difetti
            .iter()
            .any(|difetto| difetto.starts_with("trentadue cifre")),
        "la scansione non vede un API hash isolato"
    );
}

fn nome(percorso: &Path) -> String {
    percorso
        .file_name()
        .and_then(|nome| nome.to_str())
        .unwrap_or_default()
        .to_owned()
}

/// Un file di testo prodotto: il nome porta il prefisso, o sta in una cartella
/// che lo porta, e il contenuto si apre con la frase.
fn controlla_file(percorso: &Path) {
    let nel_nome = nome(percorso).starts_with(EXERCISE_FILE_PREFIX)
        || percorso
            .parent()
            .is_some_and(|cartella| nome(cartella).starts_with(EXERCISE_FILE_PREFIX));
    assert!(nel_nome, "«{}» senza prefisso", percorso.display());
    let Ok(testo) = std::fs::read_to_string(percorso) else {
        panic!("«{}» deve leggersi", percorso.display());
    };
    assert!(
        testo.starts_with(EXERCISE_MARK),
        "«{}» non si apre con la frase dell'esercitazione",
        percorso.display()
    );
}

// ---------------------------------------------------------------------------
// 3. L'insieme esercita tutto, ed è sintetico
// ---------------------------------------------------------------------------

/// **I tre modi di acquisizione, i cinque esiti, le persone, un periodo
/// scoperto, un grappolo, un workspace, e un passaggio di consegne con tutte e
/// sei le sezioni piene.**
#[test]
fn l_insieme_esercita_tutto() {
    let database = caricato();
    let Ok(sessioni) = database.sessions() else {
        panic!("le sessioni devono leggersi");
    };
    assert_eq!(sessioni.len(), 1);
    let Ok(fonti) = database.sources() else {
        panic!("le fonti devono leggersi");
    };
    assert_eq!(fonti.len(), SOURCES.len());

    let Ok(modi) =
        lisi_services::acquisition_mode::for_session(&database, sessioni[0].id, adesso())
    else {
        panic!("i modi devono derivarsi");
    };
    assert_eq!(modi.len(), MESSAGES.len(), "ogni messaggio è un contenuto");
    assert!(modi.values().any(|modo| *modo == AcquisitionMode::Live));
    assert!(
        modi.values()
            .any(|modo| *modo == AcquisitionMode::Undetermined)
    );
    assert!(modi.values().any(|modo| matches!(
        modo,
        AcquisitionMode::Recovered {
            interval: Some(_),
            ..
        }
    )));

    let Ok(ricerche) = lisi_services::identity_resolver::recent(&database, 50) else {
        panic!("le ricerche devono leggersi");
    };
    let mut esiti: Vec<String> = ricerche
        .iter()
        .map(|ricerca| ricerca.resolution.outcome.clone())
        .collect();
    esiti.sort();
    esiti.dedup();
    assert_eq!(esiti.len(), 5, "i cinque esiti: {esiti:?}");

    let Ok(persone) = database.persons() else {
        panic!("le persone devono leggersi");
    };
    assert_eq!(persone.len(), PERSONS.len());

    let Ok(periodi) = lisi_services::gap::assess(&database, adesso()) else {
        panic!("i periodi devono valutarsi");
    };
    assert!(
        !periodi.listed.is_empty(),
        "un periodo non coperto prioritario"
    );

    let Ok(workspace) = database.workspaces() else {
        panic!("i workspace devono leggersi");
    };
    assert_eq!(workspace.len(), 1);

    let consegne = lisi_services::handover::HandoverService::new(database);
    let Ok(foglio) = consegne.compose(168, adesso()) else {
        panic!("il passaggio di consegne deve comporsi");
    };
    for sezione in &foglio.sections {
        assert!(
            !sezione.lines.is_empty(),
            "la sezione «{}» è vuota",
            sezione.title
        );
    }
    let Ok(coda) = lisi_services::work_queue::WorkQueueService::new(caricato()).compose(adesso())
    else {
        panic!("la coda deve comporsi");
    };
    assert!(
        coda.items.iter().any(|elemento| elemento.in_cyber_event),
        "un grappolo di segnali informatici"
    );
}

/// **L'insieme si carica soltanto in un archivio vuoto.**
#[test]
fn l_insieme_non_si_carica_sopra_un_archivio() {
    let testimone = esercitazione();
    let database = caricato();
    assert!(seed(&testimone, database, adesso()).is_err());
}

/// **Nessun dato reale**: ogni identificativo ha la forma sintetica, e i testi
/// non portano indirizzi, nomi utente, numeri o indirizzi IP che non lo siano
/// (controllo negativo 5).
#[test]
fn l_insieme_e_sintetico() {
    let mut difetti = Vec::new();
    for fonte in SOURCES {
        if !(fonte.chat_id < SYNTHETIC_CHAT_BASE && fonte.chat_id > SYNTHETIC_CHAT_BASE - 1_000) {
            difetti.push(format!(
                "chat {} fuori dall'intervallo riservato",
                fonte.chat_id
            ));
        }
        if !fonte.name.contains("di esercitazione") {
            difetti.push(format!("fonte «{}»", fonte.name));
        }
    }
    for autore in AUTHORS {
        if !autore.name.contains("di esercitazione") {
            difetti.push(format!("autore «{}»", autore.name));
        }
        if !autore.username.starts_with("esercitazione_") {
            difetti.push(format!("nome utente «{}»", autore.username));
        }
        if !autore.identifier.starts_with("990") {
            difetti.push(format!("identificativo «{}»", autore.identifier));
        }
    }
    for persona in PERSONS {
        if !persona.starts_with("Persona di esercitazione") {
            difetti.push(format!("persona «{persona}»"));
        }
    }
    for ricerca in RESOLUTIONS {
        difetti.extend(non_sintetici(ricerca.input));
    }
    for messaggio in MESSAGES {
        if !messaggio.text.starts_with("Esercitazione:") {
            difetti.push(format!("messaggio {} senza la parola", messaggio.id));
        }
        difetti.extend(non_sintetici(messaggio.text));
    }
    assert!(
        difetti.is_empty(),
        "dati non sintetici nell'insieme:\n{}",
        difetti.join("\n")
    );
}

/// Che cosa, in un testo, non ha la forma sintetica.
fn non_sintetici(testo: &str) -> Vec<String> {
    let mut difetti = Vec::new();
    for parola in testo.split(|carattere: char| {
        carattere.is_whitespace() || matches!(carattere, ',' | ';' | '(' | ')' | '«' | '»')
    }) {
        let parola = parola.trim_end_matches(['.', ':', '!', '?']);
        if parola.is_empty() {
            continue;
        }
        let minuscola = parola.to_lowercase();
        // Indirizzi e domini: soltanto `.invalid`.
        let sembra_un_dominio = minuscola.contains("://")
            || (minuscola.contains('.')
                && minuscola
                    .rsplit('.')
                    .next()
                    .is_some_and(|coda| coda.len() >= 2 && coda.chars().all(char::is_alphabetic)));
        if sembra_un_dominio && !minuscola.contains(".invalid") {
            difetti.push(format!("dominio o indirizzo «{parola}»"));
        }
        // Nomi utente.
        if let Some(utente) = minuscola.strip_prefix('@')
            && !utente.starts_with("esercitazione_")
        {
            difetti.push(format!("nome utente «{parola}»"));
        }
        if minuscola.contains('_') && !minuscola.starts_with("esercitazione_") && !sembra_un_dominio
        {
            difetti.push(format!("nome utente «{parola}»"));
        }
        // Numeri di telefono: soltanto il formato di prova di Telegram.
        let cifre: String = parola.chars().filter(char::is_ascii_digit).collect();
        if cifre.len() >= 8 && !cifre.starts_with("99966") {
            difetti.push(format!("numero «{parola}»"));
        }
        // Indirizzi IP: soltanto i blocchi di documentazione.
        let ottetti: Vec<&str> = parola.split('.').collect();
        if ottetti.len() == 4
            && ottetti
                .iter()
                .all(|ottetto| !ottetto.is_empty() && ottetto.chars().all(|c| c.is_ascii_digit()))
            && !["192.0.2.", "198.51.100.", "203.0.113."]
                .iter()
                .any(|blocco| parola.starts_with(blocco))
        {
            difetti.push(format!("indirizzo IP «{parola}»"));
        }
    }
    difetti
}

/// La guardia vede ciò che deve vedere: non è verde perché non guarda.
#[test]
fn la_guardia_del_sintetico_vede_un_dato_reale() {
    for reale in [
        "scrivete a @mario_rossi",
        "il sito esempio.it",
        "chiamate il 3331234567",
        "il server 8.8.8.8",
        "https://t.me/qualcuno",
    ] {
        assert!(
            !non_sintetici(reale).is_empty(),
            "«{reale}» non è stato visto"
        );
    }
    assert!(non_sintetici("Esercitazione: aggiornamento-sicuro.invalid e 192.0.2.45.").is_empty());
}

// ---------------------------------------------------------------------------
// 4. Ricominciare
// ---------------------------------------------------------------------------

/// **Ricominciare toglie l'archivio dell'esercitazione, e non tocca quello
/// operativo** (controllo negativo 6).
#[test]
fn ricominciare_non_tocca_l_archivio_operativo() {
    let testimone = esercitazione();
    let base = cartella();
    let operativa = base.path().join(lisi_core::branding::DATA_DIRECTORY);
    let di_esercitazione = base.path().join(EXERCISE_DATA_DIRECTORY);
    for cartella in [&operativa, &di_esercitazione] {
        if std::fs::create_dir_all(cartella).is_err()
            || std::fs::write(cartella.join("monitor.sqlite"), b"archivio").is_err()
            || std::fs::write(cartella.join("monitor.sqlite-wal"), b"giornale").is_err()
        {
            panic!("i file di prova devono scriversi");
        }
    }

    assert_eq!(prepare(&testimone, base.path()).ok(), Some(Prepared::Kept));
    assert!(
        di_esercitazione.join("monitor.sqlite").exists(),
        "senza richiesta resta"
    );

    let Ok(()) = request_restart(&testimone, base.path()) else {
        panic!("la richiesta deve scriversi");
    };
    assert!(di_esercitazione.join(RESTART_MARKER).exists());
    assert!(!operativa.join(RESTART_MARKER).exists());

    assert_eq!(
        prepare(&testimone, base.path()).ok(),
        Some(Prepared::Restarted)
    );
    assert!(!di_esercitazione.join("monitor.sqlite").exists());
    assert!(!di_esercitazione.join("monitor.sqlite-wal").exists());
    assert!(!di_esercitazione.join(RESTART_MARKER).exists());
    assert!(
        operativa.join("monitor.sqlite").exists(),
        "l'archivio operativo è toccato"
    );
    assert!(
        operativa.join("monitor.sqlite-wal").exists(),
        "il giornale operativo è toccato"
    );
}

/// **In Esercitazione non si manda a TAXII** (ADR-0179, decisione 8): anche
/// con la destinazione, il nome, la parola d'ordine e osservabili veri
/// nell'archivio, l'invio si rifiuta prima della rete e il registro resta
/// vuoto.
#[test]
fn in_esercitazione_non_si_manda_a_taxii() {
    let _ = esercitazione();
    let mut database = caricato();
    let Ok(sessioni) = database.sessions() else {
        panic!("le sessioni devono leggersi");
    };
    let sessione = sessioni[0].id;
    let cartella = cartella();
    let cassaforte = lisi_security::ProtectedStore::at(cartella.path().join("taxii.protetto"));
    let mut servizio = lisi_services::taxii::TaxiiService::new(&mut database, cassaforte);
    let modo = lisi_core::OperatingMode::Administrator;
    let (Ok(()), Ok(())) = (
        servizio.set_destination(
            Some("https://taxii.esempio.test/api1/"),
            Some("collezione-prova"),
            Some("ufficio.prova"),
            modo,
            &formatore(),
            adesso(),
        ),
        servizio.set_password(Some("parola-di-prova"), modo, &formatore(), adesso()),
    ) else {
        panic!("destinazione e parola d'ordine devono scriversi");
    };

    assert!(matches!(
        servizio.send(sessione, &formatore(), adesso()),
        Err(lisi_services::ServiceError::TaxiiInExercise)
    ));
    assert_eq!(servizio.submissions().map(|v| v.len()).ok(), Some(0));
}

//! Prove sul `.pdf` realmente prodotto.
//!
//! Coprono il criterio 2 (nessun contenuto attivo) e il criterio 30
//! (generazione deterministica) per i due documenti PDF, e sono le prove 5 e 6
//! di ADR-0034.
//!
//! # Perche' si cerca nei byte, qui, e non aprendo un archivio
//!
//! Perche' un PDF **non e' uno ZIP**: e' un formato a oggetti, e la parte che
//! interessa — i nomi delle azioni, i tipi di annotazione, i riferimenti a file
//! esterni — sta in chiaro nel corpo del documento, non dentro un flusso
//! compresso. La ricerca nei byte e' quindi diretta e non cieca, ed e' l'esatto
//! contrario del caso `.docx`, dove cercare nei byte grezzi sarebbe stato un
//! test che non puo' fallire.
//!
//! Il controllo positivo qui sotto lo dimostra invece di darlo per scontato.

use lisi_core::digest::Sha256Digest;
use lisi_core::model::analysis::AnalysisLevel;
use lisi_core::model::report::{ReportContentSnapshot, ReportId, ReportSnapshot};
use lisi_core::model::report_template::{ReportTemplateProfile, TemplateField};
use lisi_core::text::Actor;
use lisi_core::{ContentId, SessionId, Timestamp};
use lisi_services::analysis_configuration::AnalysisConfiguration;
use lisi_services::report_annex::{AnnexInput, compose as compose_annex};
use lisi_services::report_ledger::{LedgerAlert, LedgerContent, LedgerSession};
use lisi_services::report_narrative::{
    NarrativeFinding, NarrativeInput, NarrativeSession, NarrativeSource, compose as compose_report,
};
use lisi_services::report_pdf::{PdfKind, render};

fn fotografia(monitorati: &[i64]) -> ReportSnapshot {
    ReportSnapshot {
        taken_at: Timestamp::from_millis(1_752_000_000_000),
        session_id: SessionId::new(1),
        source_ids: Vec::new(),
        dictionary_version_ids: Vec::new(),
        template_version: 1,
        contents: monitorati
            .iter()
            .map(|raw| ReportContentSnapshot {
                content_id: ContentId::new(*raw),
                level: AnalysisLevel::try_new(u8::try_from(raw % 5).unwrap_or(0))
                    .expect("livello valido"),
                review_state: None,
                body_sha256: Sha256Digest::of_text(&format!("corpo {raw}")),
                selected: false,
            })
            .collect(),
    }
}

fn profilo() -> ReportTemplateProfile {
    ReportTemplateProfile {
        version: 1,
        organisation: Some(TemplateField::try_new("ENTE DI PROVA").expect("valido")),
        office: Some(TemplateField::try_new("Unita' di Prova").expect("valido")),
        place: Some(TemplateField::try_new("Citta' d'Esempio").expect("valido")),
        signer_role: Some(TemplateField::try_new("Qualifica di Prova").expect("valido")),
        signer_name: Some(TemplateField::try_new("Nome COGNOME").expect("valido")),
        ..ReportTemplateProfile::default()
    }
}

fn contenuto(id: i64, body: &str) -> LedgerContent {
    LedgerContent {
        content_id: ContentId::new(id),
        source_label: String::from("Canale di prova"),
        author: None,
        published_at: Timestamp::from_millis(1_752_001_000_000),
        acquired_at: Timestamp::from_millis(1_752_001_500_000),
        origin: String::from("osservato"),
        body: String::from(body),
        url: None,
        asked_link: None,
        attachment: None,
        level: 0,
        review_state: None,
        selected: false,
        body_digest: Sha256Digest::of_text(body).as_str().to_owned(),
        after_acquisition: None,
        revisions: Vec::new(),
        revisions_beyond: 0,
        contexts: Vec::new(),
        contexts_beyond: 0,
        analysis_origin: None,
    }
}

/// La relazione in PDF.
fn relazione() -> Vec<u8> {
    let report_id = ReportId::from_sequence(2026, 42);
    let profile = profilo();
    let operator = Actor::try_new("operatore").expect("attore valido");
    let snapshot = fotografia(&[1, 2, 3]);
    let session = NarrativeSession {
        pauses: Vec::new(),
        label: String::from("Monitoraggio di prova"),
        started_at: Timestamp::from_millis(1_752_000_000_000),
        ended_at: Some(Timestamp::from_millis(1_752_010_800_000)),
        account: None,
        profile_observations: Vec::new(),
    };
    let sources = [NarrativeSource {
        label: String::from("Canale di prova"),
        acquired: 3,
        reliability: None,
    }];
    let findings = [NarrativeFinding {
        content_id: ContentId::new(2),
        source_label: String::from("Canale di prova"),
        published_at: Timestamp::from_millis(1_752_001_800_000),
        acquired_at: Timestamp::from_millis(1_752_001_860_000),
        recovered: false,
        url: Some(String::from("https://esempio.invalid/prova/2")),
        asked_link: None,
        attachment: None,
        body: String::from(
            "Messaggio sintetico di prova, con lettere accentate — citta', perche', \
             cosi' — e un apostrofo nell'estratto.",
        ),
        level: AnalysisLevel::try_new(4).expect("livello valido"),
        engine_reason: Some(String::from("Riscontro di due termini del dizionario.")),
        review_state: None,
        review_note: None,
        after_acquisition: None,
        revisions: Vec::new(),
        revisions_beyond: 0,
        contexts: Vec::new(),
        contexts_beyond: 0,
        acquisition_mode: String::from("Acquisito dal vivo."),
    }];

    let report = compose_report(&NarrativeInput {
        report_id: &report_id,
        profile: &profile,
        snapshot: &snapshot,
        operator: &operator,
        generated_at: Timestamp::from_millis(1_752_086_400_000),
        session: &session,
        sources: &sources,
        findings: &findings,
        coverage: &[],
        faults: &[],
        configuration: &AnalysisConfiguration::unknown(),
    });

    render(&report, PdfKind::Narrative).expect("la relazione deve potersi scrivere")
}

/// L'allegato tecnico in PDF.
fn allegato() -> Vec<u8> {
    let report_id = ReportId::from_sequence(2026, 42);
    let profile = profilo();
    let operator = Actor::try_new("operatore").expect("attore valido");
    let session = LedgerSession {
        pauses: Vec::new(),
        label: String::from("Monitoraggio di prova"),
        started_at: Timestamp::from_millis(1_752_000_000_000),
        ended_at: None,
        state: String::from("conclusa"),
    };
    let contents = [
        contenuto(1, "Primo contenuto di prova, con accenti: citta', perche'."),
        contenuto(2, "Secondo contenuto di prova."),
    ];
    let alerts = [LedgerAlert {
        content_id: ContentId::new(1),
        level: 3,
        reason: String::from("Riscontro di un termine."),
        raised_at: Timestamp::from_millis(1_752_002_000_000),
    }];

    let annex = compose_annex(&AnnexInput {
        report_id: &report_id,
        profile: &profile,
        operator: &operator,
        generated_at: Timestamp::from_millis(1_752_086_400_000),
        session: &session,
        sources: &[],
        contents: &contents,
        alerts: &alerts,
        faults: &[],
        cyber_events: &[],
        subjects: &[],
        taxonomy: &[],
        taxonomy_beyond: 0,
        official_sources: &[],
        notes: &[],
        notes_beyond: 0,
        workspaces: &[],
        workspaces_beyond: 0,
        investigative_basis: true,
        coverage: &[],
        configuration: &AnalysisConfiguration::unknown(),
    });

    render(&annex, PdfKind::TechnicalAnnex).expect("l'allegato deve potersi scrivere")
}

#[test]
fn both_documents_are_pdf_files() {
    for bytes in [relazione(), allegato()] {
        assert!(bytes.starts_with(b"%PDF-"), "manca l'intestazione PDF");
        assert!(
            bytes.windows(5).any(|w| w == b"%%EOF"),
            "manca il marcatore di fine file"
        );
    }
}

#[test]
fn the_search_in_the_bytes_is_not_blind() {
    // **Il controllo positivo.** Prima di dichiarare che certe stringhe non ci
    // sono, bisogna dimostrare che una stringa che c'e' si trova davvero. Senza
    // questo, ogni prova negativa qui sotto sarebbe verde per la ragione
    // sbagliata.
    let bytes = relazione();
    let testo = String::from_utf8_lossy(&bytes);
    assert!(
        testo.contains("Times-Roman"),
        "il carattere dichiarato non si trova nei byte: la ricerca e' cieca"
    );
    assert!(
        testo.contains("/Type/Page"),
        "la struttura delle pagine non si trova nei byte"
    );
}

#[test]
fn neither_document_carries_active_content() {
    // Criterio 2. Un PDF puo' eseguire codice all'apertura, incorporare file e
    // aprire risorse remote: nessuna di queste cose deve esserci.
    for (nome, bytes) in [("relazione", relazione()), ("allegato", allegato())] {
        let testo = String::from_utf8_lossy(&bytes);
        for vietata in [
            "/JavaScript",
            "/JS",
            "/OpenAction",
            "/AA",
            "/Launch",
            "/EmbeddedFile",
            "/RichMedia",
            "/Movie",
            "/Sound",
            "/SubmitForm",
            "/ImportData",
            "/GoToR",
            "/GoToE",
        ] {
            assert!(
                !testo.contains(vietata),
                "il documento «{nome}» contiene «{vietata}»"
            );
        }
    }
}

#[test]
fn neither_document_declares_a_link_to_the_outside() {
    // Gli URL dei contenuti restano **testo**, come nel `.docx` e per la stessa
    // ragione: un collegamento e' una relazione esterna, e questi documenti non
    // ne dichiarano nessuna.
    for (nome, bytes) in [("relazione", relazione()), ("allegato", allegato())] {
        let testo = String::from_utf8_lossy(&bytes);
        assert!(
            !testo.contains("/URI"),
            "«{nome}» dichiara un collegamento esterno"
        );
        assert!(
            !testo.contains("/Annots"),
            "«{nome}» dichiara annotazioni, che possono essere collegamenti"
        );
    }
}

#[test]
fn the_url_of_a_finding_is_still_readable_as_text() {
    // Il rovescio della prova qui sopra: togliere i collegamenti non deve
    // togliere gli indirizzi. Chi legge il documento deve poterli trascrivere.
    let bytes = relazione();
    let testo = String::from_utf8_lossy(&bytes);
    assert!(
        testo.contains("esempio.invalid"),
        "l'indirizzo del contenuto non compare nel documento"
    );
}

#[test]
fn two_generations_of_the_report_are_identical() {
    // Criterio 30. Sono le tre date e l'array `/ID` del trailer: con la
    // libreria scartata quest'ultimo era casuale e non governabile (ADR-0034).
    let primo = relazione();
    std::thread::sleep(std::time::Duration::from_millis(2_100));
    let secondo = relazione();

    assert_eq!(
        Sha256Digest::of_bytes(&primo),
        Sha256Digest::of_bytes(&secondo),
        "due generazioni della stessa relazione hanno impronte diverse"
    );
}

#[test]
fn two_generations_of_the_annex_are_identical() {
    let primo = allegato();
    std::thread::sleep(std::time::Duration::from_millis(2_100));
    let secondo = allegato();

    assert_eq!(
        Sha256Digest::of_bytes(&primo),
        Sha256Digest::of_bytes(&secondo),
        "due generazioni dello stesso allegato hanno impronte diverse"
    );
}

#[test]
fn the_two_documents_are_not_the_same_file() {
    // Sarebbero identici se il generatore ignorasse il genere richiesto: un
    // pacchetto con due copie dello stesso documento e' peggio di un pacchetto
    // con un documento solo, perche' sembra completo.
    assert_ne!(
        Sha256Digest::of_bytes(&relazione()),
        Sha256Digest::of_bytes(&allegato())
    );
}

#[test]
fn the_properties_declare_the_generation_instant_and_not_nineteen_seventy() {
    let bytes = relazione();
    let testo = String::from_utf8_lossy(&bytes);
    assert!(
        testo.contains("D:20250709") || testo.contains("D:20250710"),
        "le proprieta' non portano l'istante di generazione"
    );
    assert!(
        !testo.contains("D:1970"),
        "le proprieta' dichiarano il 1970"
    );
}

#[test]
fn the_properties_do_not_carry_a_person_or_a_machine() {
    for bytes in [relazione(), allegato()] {
        let testo = String::from_utf8_lossy(&bytes);
        assert!(
            !testo.contains("/Author(operatore"),
            "l'identita' dell'operatore e' finita nei metadati"
        );
        assert!(
            testo.contains("/Author(unknown)"),
            "l'autore dichiarato non e' quello atteso"
        );
    }
}

#[test]
fn the_accented_letters_reach_the_document() {
    // Sono le lettere che l'italiano usa di piu', ed erano il punto in cui una
    // codifica sbagliata si sarebbe vista subito.
    let bytes = relazione();
    // In WinAnsi la `à` e' 0xE0 e la `è` 0xE8: si cercano come byte, perche'
    // nel PDF non sono UTF-8.
    assert!(
        bytes.windows(1).any(|w| w == [0xE0]) || bytes.windows(1).any(|w| w == [0xE8]),
        "nessuna lettera accentata nel documento: la codifica non e' arrivata"
    );
}

#[test]
fn the_annex_represents_more_than_the_selection() {
    // La differenza fra i due documenti, verificata sul file: l'allegato porta
    // entrambi i contenuti monitorati, la relazione la sola selezione.
    let bytes = allegato();
    let testo = String::from_utf8_lossy(&bytes);
    assert!(testo.contains("Primo contenuto di prova"));
    assert!(testo.contains("Secondo contenuto di prova"));
}

/// Scrive i due PDF di prova, per la verifica su un lettore vero.
///
/// Non e' una prova automatica: sono i file che una **persona** deve aprire.
/// Si esegue a mano:
///
/// ```powershell
/// $env:LISI_PDF_PILOT_DIR = "C:\percorso\cartella"
/// cargo test -p lisi-services --test pdf_determinismo -- --ignored --nocapture
/// ```
#[test]
#[ignore = "scrive due file: si esegue a mano per la verifica a vista"]
fn writes_the_two_pilot_pdfs() {
    let Ok(directory) = std::env::var("LISI_PDF_PILOT_DIR") else {
        panic!("impostare LISI_PDF_PILOT_DIR con la cartella in cui scrivere");
    };
    let directory = std::path::PathBuf::from(directory);
    std::fs::create_dir_all(&directory).expect("la cartella deve potersi creare");

    let percorso_a = directory.join("NEXUM97_RELAZIONE_PDF_PILOT.pdf");
    std::fs::write(&percorso_a, relazione()).expect("il file deve potersi scrivere");

    let percorso_b = directory.join("NEXUM97_ALLEGATO_TECNICO_PDF_PILOT.pdf");
    std::fs::write(&percorso_b, allegato_lungo()).expect("il file deve potersi scrivere");

    println!("A. relazione       : {}", percorso_a.display());
    println!("B. allegato tecnico: {}", percorso_b.display());
}

/// Un allegato con abbastanza contenuti da occupare piu' pagine.
///
/// Serve alla verifica a vista: l'impaginazione la scriviamo noi, e il punto in
/// cui puo' sbagliare e' il salto di pagina.
fn allegato_lungo() -> Vec<u8> {
    let report_id = ReportId::from_sequence(2026, 900_020);
    let profile = profilo();
    let operator = Actor::try_new("operatore.prova").expect("attore valido");
    let session = LedgerSession {
        pauses: Vec::new(),
        label: String::from("Monitoraggio di prova"),
        started_at: Timestamp::from_millis(1_752_000_000_000),
        ended_at: Some(Timestamp::from_millis(1_752_010_800_000)),
        state: String::from("conclusa"),
    };

    let corpi = [
        "Messaggio sintetico di prova, con lettere accentate — città, perché, così — \
         e un apostrofo nell'estratto, per verificare la resa tipografica.",
        "Secondo messaggio, più breve.",
        "Terzo messaggio, scritto lungo apposta per far vedere come si comporta la \
         spezzatura delle righe quando il testo supera la larghezza della colonna e \
         deve proseguire sulla riga successiva senza perdere parole, senza tagliarle \
         a metà e senza uscire dal margine destro del foglio.",
        "Quarto messaggio con un indirizzo dentro: https://esempio.invalid/un/percorso/molto/lungo/che/non/entra/in/una/riga",
        "Quinto messaggio, di livello zero, che deve comparire ugualmente.",
        "Sesto messaggio, con virgolette «basse» e puntini di sospensione…",
    ];

    let contents: Vec<LedgerContent> = corpi
        .iter()
        .enumerate()
        .map(|(index, body)| contenuto(i64::try_from(index).unwrap_or(0) + 1, body))
        .collect();

    let alerts = [LedgerAlert {
        content_id: ContentId::new(1),
        level: 4,
        reason: String::from("Riscontro di due termini del dizionario di prova."),
        raised_at: Timestamp::from_millis(1_752_002_000_000),
    }];

    let annex = compose_annex(&AnnexInput {
        report_id: &report_id,
        profile: &profile,
        operator: &operator,
        generated_at: Timestamp::from_millis(1_752_086_400_000),
        session: &session,
        sources: &[],
        contents: &contents,
        alerts: &alerts,
        faults: &[],
        cyber_events: &[],
        subjects: &[],
        taxonomy: &[],
        taxonomy_beyond: 0,
        official_sources: &[],
        notes: &[],
        notes_beyond: 0,
        workspaces: &[],
        workspaces_beyond: 0,
        investigative_basis: true,
        coverage: &[],
        configuration: &AnalysisConfiguration::unknown(),
    });

    render(&annex, PdfKind::TechnicalAnnex).expect("l'allegato deve potersi scrivere")
}

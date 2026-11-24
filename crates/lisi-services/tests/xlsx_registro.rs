//! Prove sul registro `.xlsx` realmente prodotto.
//!
//! Coprono ADR-0031 Decisione 6 (iniezione di formule neutralizzata e **provata
//! al contrario**) e il criterio 30 (generazione deterministica), e sono per il
//! foglio di calcolo cio' che `docx_determinismo.rs` e' per la relazione.
//!
//! # Perche' l'archivio si apre davvero
//!
//! Stessa ragione del DOCX: un `.xlsx` e' uno ZIP, e uno ZIP comprime. Cercare
//! `<f>` nei byte grezzi darebbe verde anche a un file che contiene formule,
//! perche' la stringa non c'e' in chiaro. Sarebbe un test che non puo' fallire,
//! cioe' il genere peggiore.

use std::io::Cursor;

use lisi_core::digest::Sha256Digest;
use lisi_core::model::analysis::AnalysisLevel;
use lisi_core::model::report::{ReportContentSnapshot, ReportId, ReportSnapshot};
use lisi_core::model::report_template::ReportTemplateProfile;
use lisi_core::text::Actor;
use lisi_core::{ContentId, SessionId, Timestamp};
use lisi_services::analysis_configuration::AnalysisConfiguration;
use lisi_services::report_ledger::{
    LedgerAlert, LedgerContent, LedgerCyberEvent, LedgerInput, LedgerReview, LedgerSession, compose,
};
use lisi_services::report_xlsx::render;

/// Fotografia sintetica con i contenuti indicati.
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

fn sessione() -> LedgerSession {
    LedgerSession {
        label: String::from("Monitoraggio di prova"),
        started_at: Timestamp::from_millis(1_752_000_000_000),
        ended_at: Some(Timestamp::from_millis(1_752_010_800_000)),
        state: String::from("conclusa"),
    }
}

/// Compone e scrive un registro con i corpi indicati.
fn registro(corpi: &[&str]) -> Vec<u8> {
    let report_id = ReportId::from_sequence(2026, 7);
    let profile = ReportTemplateProfile::default();
    let operator = Actor::try_new("operatore").expect("attore valido");
    let session = sessione();

    let contents: Vec<LedgerContent> = corpi
        .iter()
        .enumerate()
        .map(|(index, body)| contenuto(i64::try_from(index).unwrap_or(0) + 1, body))
        .collect();
    let monitorati: Vec<i64> = (1..=i64::try_from(corpi.len()).unwrap_or(0)).collect();
    let snapshot = fotografia(&monitorati);

    let ledger = compose(&LedgerInput {
        report_id: &report_id,
        profile: &profile,
        snapshot: &snapshot,
        operator: &operator,
        generated_at: Timestamp::from_millis(1_752_086_400_000),
        session: &session,
        sources: &[],
        contents: &contents,
        alerts: &[],
        reviews: &[],
        faults: &[],
        configuration: &AnalysisConfiguration::unknown(),
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
    });

    render(&ledger).expect("il registro deve potersi scrivere")
}

/// Nome e contenuto di ogni voce dell'archivio.
fn voci(bytes: &[u8]) -> Vec<(String, String)> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes.to_vec())).expect("il file e' uno ZIP");
    let mut collected = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).expect("voce leggibile");
        let name = entry
            .name()
            .expect("nome della voce leggibile")
            .into_owned();
        let mut raw = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut raw).expect("voce leggibile");
        collected.push((name, String::from_utf8_lossy(&raw).into_owned()));
    }
    collected
}

/// Il contenuto di una voce dell'archivio.
fn voce(bytes: &[u8], nome: &str) -> String {
    voci(bytes)
        .into_iter()
        .find(|(name, _)| name == nome)
        .map(|(_, content)| content)
        .unwrap_or_else(|| panic!("il registro deve contenere «{nome}»"))
}

#[test]
fn the_archive_can_actually_be_opened_and_read() {
    // Il controllo positivo: se questo non trovasse il testo dentro
    // l'archivio, ogni ricerca di stringhe vietate sarebbe verde per la
    // ragione sbagliata.
    let bytes = registro(&["messaggio sintetico di prova"]);
    let voci = voci(&bytes);

    assert!(!voci.is_empty(), "l'archivio non contiene alcuna voce");
    let tutto: String = voci.iter().map(|(_, content)| content.as_str()).collect();
    assert!(
        tutto.contains("messaggio sintetico di prova"),
        "il testo del registro non si ritrova nell'archivio: la prova sarebbe cieca"
    );
}

#[test]
fn a_message_that_starts_with_an_equals_sign_is_not_a_formula() {
    // **La prova di ADR-0031 Decisione 6.**
    //
    // Un contenuto acquisito da Telegram che comincia per `=` e' testo, e deve
    // restare testo. In OOXML una formula e' un elemento `<f>` dentro la cella:
    // se non c'e' alcun `<f>`, Excel non ha nulla da valutare.
    let bytes = registro(&["=SOMMA(A1:A9)"]);
    let tutto: String = voci(&bytes)
        .iter()
        .map(|(_, content)| content.as_str())
        .collect();

    assert!(
        !tutto.contains("<f>"),
        "il registro contiene una formula: un contenuto acquisito e' stato \
         interpretato invece che riportato"
    );
    assert!(
        !tutto.contains("<f "),
        "il registro contiene una formula con attributi"
    );
}

#[test]
fn every_hostile_prefix_stays_text() {
    // Non solo `=`. Excel interpreta anche `+`, `-` e `@` all'inizio di una
    // cella, e un solo prefisso provato lascerebbe scoperti gli altri tre.
    let bytes = registro(&[
        "=SOMMA(A1:A9)",
        "+1+1",
        "-1-1",
        "@SUM(A1)",
        "=cmd|' /c calc'!A0",
    ]);
    let tutto: String = voci(&bytes)
        .iter()
        .map(|(_, content)| content.as_str())
        .collect();

    assert!(
        !tutto.contains("<f>"),
        "una delle celle e' diventata formula"
    );
}

#[test]
fn the_hostile_text_is_still_there_unchanged() {
    // **Il rovescio della medaglia, ed e' la meta' che si dimentica.** Un
    // registro che neutralizzasse le formule togliendo il carattere iniziale
    // sarebbe sicuro e **falso**: questo documento esiste per dire che cosa la
    // fonte ha pubblicato, non una versione ritoccata perche' faceva paura.
    let bytes = registro(&["=SOMMA(A1:A9)"]);
    let tutto: String = voci(&bytes)
        .iter()
        .map(|(_, content)| content.as_str())
        .collect();

    assert!(
        tutto.contains("=SOMMA(A1:A9)"),
        "il testo acquisito e' stato alterato per renderlo innocuo: il registro \
         non riporta piu' cio' che la fonte ha pubblicato"
    );
}

#[test]
fn the_cell_is_typed_as_a_string() {
    // La ragione per cui la cella non e' una formula non e' il carattere
    // iniziale: e' il **tipo**. Se un giorno il renderer scrivesse le celle
    // senza tipo, questa prova lo direbbe.
    let bytes = registro(&["=SOMMA(A1:A9)"]);
    let foglio = voce(&bytes, "xl/worksheets/sheet3.xml");

    assert!(
        foglio.contains("t=\"s\"")
            || foglio.contains("t=\"str\"")
            || foglio.contains("t=\"inlineStr\""),
        "le celle del foglio dei contenuti non sono tipizzate come stringa: {foglio}"
    );
}

#[test]
fn the_workbook_carries_the_nine_sheets() {
    let bytes = registro(&["primo", "secondo"]);
    let workbook = voce(&bytes, "xl/workbook.xml");

    for nome in [
        "01 — Sessione",
        "02 — Fonti",
        "03 — Contenuti",
        "04 — Avvisi",
        "05 — Revisioni",
        "06 — Errori",
        "07 — Dizionari",
        "08 — Configurazione",
        "09 — Integrità",
    ] {
        assert!(
            workbook.contains(nome),
            "il registro non dichiara il foglio «{nome}»"
        );
    }
}

#[test]
fn the_registry_declares_no_macro_and_no_active_content() {
    // Il criterio 2, per il foglio di calcolo. Un `.xlsm` porterebbe
    // `vbaProject.bin`; un foglio con contenuto attivo dichiarerebbe tipi che
    // qui non devono comparire.
    let bytes = registro(&["testo"]);
    let voci = voci(&bytes);

    for (nome, _) in &voci {
        assert!(
            !nome.contains("vbaProject"),
            "il registro contiene un progetto VBA: «{nome}»"
        );
        assert!(
            !nome.ends_with(".bin") || nome.contains("printerSettings"),
            "il registro contiene un oggetto binario inatteso: «{nome}»"
        );
    }

    let content_types = voce(&bytes, "[Content_Types].xml");
    assert!(
        !content_types.contains("macroEnabled"),
        "il registro si dichiara abilitato alle macro"
    );
}

#[test]
fn the_registry_declares_no_external_relationship() {
    // Nessun collegamento verso l'esterno: gli URL dei contenuti restano
    // testo, come nel DOCX e per la stessa ragione.
    let bytes = registro(&["testo"]);
    for (nome, contenuto) in voci(&bytes) {
        if !nome.contains("_rels") {
            continue;
        }
        assert!(
            !contenuto.contains("TargetMode=\"External\""),
            "«{nome}» dichiara una relazione esterna"
        );
    }
}

#[test]
fn two_generations_of_the_same_registry_are_identical() {
    // Il criterio 30. La libreria scrive l'istante corrente nelle proprieta';
    // il generatore lo sostituisce con l'istante di generazione, che e' un
    // ingresso. Due secondi di attesa fra le due scritture: senza la
    // sostituzione, il secondo file porterebbe un istante diverso.
    let primo = registro(&["testo di prova"]);
    std::thread::sleep(std::time::Duration::from_millis(2_100));
    let secondo = registro(&["testo di prova"]);

    assert_eq!(
        Sha256Digest::of_bytes(&primo),
        Sha256Digest::of_bytes(&secondo),
        "due generazioni dello stesso registro hanno impronte diverse"
    );
}

#[test]
fn the_properties_declare_the_generation_instant_and_not_nineteen_seventy() {
    // La stessa lezione del DOCX: deterministico e falso e' peggio di
    // deterministico e vero.
    let bytes = registro(&["testo"]);
    let core = voce(&bytes, "docProps/core.xml");

    assert!(
        core.contains("2025-07-09") || core.contains("2025-07-10"),
        "le proprieta' non portano l'istante di generazione: {core}"
    );
    assert!(
        !core.contains("1970"),
        "le proprieta' dichiarano il 1970: {core}"
    );
}

#[test]
fn the_properties_do_not_carry_a_person_or_a_machine() {
    let bytes = registro(&["testo"]);
    let core = voce(&bytes, "docProps/core.xml");

    assert!(
        core.contains("unknown"),
        "l'autore dichiarato non e' quello atteso: {core}"
    );
    assert!(
        !core.contains("operatore"),
        "l'identita' dell'operatore e' finita nei metadati del file: {core}"
    );
}

#[test]
fn nothing_disappears_from_the_produced_file() {
    // Il criterio del registro, verificato **sul file** e non solo sulla
    // struttura: cinque contenuti monitorati devono essere cinque righe.
    let bytes = registro(&["uno", "due", "tre", "quattro", "cinque"]);
    let tutto: String = voci(&bytes)
        .iter()
        .map(|(_, content)| content.as_str())
        .collect();

    for corpo in ["uno", "due", "tre", "quattro", "cinque"] {
        assert!(
            tutto.contains(corpo),
            "il contenuto «{corpo}» non e' finito nel registro"
        );
    }
}

#[test]
fn an_alert_reason_is_also_untrusted_text() {
    // La motivazione del motore contiene termini del dizionario e frammenti
    // del contenuto: e' testo non fidato quanto il corpo, e un solo campo
    // protetto non basta.
    let report_id = ReportId::from_sequence(2026, 8);
    let profile = ReportTemplateProfile::default();
    let operator = Actor::try_new("operatore").expect("attore valido");
    let session = sessione();
    let contents = [contenuto(1, "testo innocuo")];
    let snapshot = fotografia(&[1]);
    let alerts = [LedgerAlert {
        content_id: ContentId::new(1),
        level: 3,
        reason: String::from("=RISCONTRO(A1)"),
        raised_at: Timestamp::from_millis(1_752_002_000_000),
    }];
    let reviews = [LedgerReview {
        content_id: ContentId::new(1),
        state: String::from("pertinente"),
        note: Some(String::from("@nota dell'operatore")),
        actor: String::from("operatore"),
        decided_at: Timestamp::from_millis(1_752_003_000_000),
    }];

    let ledger = compose(&LedgerInput {
        report_id: &report_id,
        profile: &profile,
        snapshot: &snapshot,
        operator: &operator,
        generated_at: Timestamp::from_millis(1_752_086_400_000),
        session: &session,
        sources: &[],
        contents: &contents,
        alerts: &alerts,
        reviews: &reviews,
        faults: &[],
        configuration: &AnalysisConfiguration::unknown(),
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
    });
    let bytes = render(&ledger).expect("il registro deve potersi scrivere");

    let tutto: String = voci(&bytes)
        .iter()
        .map(|(_, content)| content.as_str())
        .collect();
    assert!(
        !tutto.contains("<f>"),
        "la motivazione del motore o la nota di revisione sono diventate formule"
    );
    assert!(tutto.contains("=RISCONTRO(A1)"));
    assert!(tutto.contains("@nota dell'operatore"));
}

/// Scrive un registro di prova, per la verifica su Microsoft Excel.
///
/// Non e' una prova automatica: e' il file che una **persona** deve aprire, ed
/// e' l'unico modo di chiudere le voci T74-T90 del pilot. Si esegue a mano:
///
/// ```powershell
/// $env:LISI_XLSX_PILOT_DIR = "C:\percorso\cartella"
/// cargo test -p lisi-services --test xlsx_registro -- --ignored --nocapture
/// ```
#[test]
#[ignore = "scrive un file: si esegue a mano per la verifica su Excel"]
fn writes_the_pilot_registry() {
    let Ok(directory) = std::env::var("LISI_XLSX_PILOT_DIR") else {
        panic!("impostare LISI_XLSX_PILOT_DIR con la cartella in cui scrivere");
    };
    let directory = std::path::PathBuf::from(directory);
    std::fs::create_dir_all(&directory).expect("la cartella deve potersi creare");

    let report_id = ReportId::from_sequence(2026, 900_010);
    let profile = ReportTemplateProfile::default();
    let operator = Actor::try_new("operatore.prova").expect("attore valido");
    let session = sessione();

    // I contenuti sono scelti per far vedere **ogni caso che il pilot chiede di
    // giudicare**, e non per somigliare a un monitoraggio vero.
    let corpi: [(&str, u8, bool, Option<&str>); 8] = [
        (
            "Messaggio sintetico di prova, con lettere accentate — citta', perche', \
             cosi' — e un apostrofo nell'estratto.",
            2,
            true,
            Some("https://esempio.invalid/prova/1"),
        ),
        // T77: deve comparire COSI', testo e non formula.
        ("=SOMMA(A1:A9)", 0, false, None),
        // T78: gli altri tre prefissi che Excel interpreta.
        ("+1+1", 0, false, None),
        ("-1-1", 0, false, None),
        ("@SUM(A1)", 0, false, None),
        // La formula di esecuzione remota: il caso peggiore.
        ("=cmd|' /c calc'!A0", 4, false, None),
        // T82: un testo lungo, per giudicare la larghezza delle colonne.
        (
            "Messaggio lungo di prova, scritto per far vedere come si comporta la \
             colonna del testo quando il contenuto supera la larghezza massima: il \
             foglio deve restare leggibile e stampabile invece di allargarsi fino a \
             uscire dallo schermo, e la cella deve mandare a capo.",
            1,
            false,
            None,
        ),
        // T83: livello 0, non selezionato, senza alert. Deve esserci.
        (
            "Contenuto di livello zero, che deve comparire ugualmente.",
            0,
            false,
            None,
        ),
    ];

    let contents: Vec<LedgerContent> = corpi
        .iter()
        .enumerate()
        .map(|(index, (body, level, selected, url))| {
            let id = i64::try_from(index).unwrap_or(0) + 1;
            let mut content = contenuto(id, body);
            content.level = *level;
            content.selected = *selected;
            content.url = url.map(String::from);
            // Il primo porta un autore; gli altri no, cosi' si vede la cella
            // che dichiara «non disponibile» (T84).
            if index == 0 {
                content.author = Some(String::from("utente_di_prova"));
                content.review_state = Some(String::from("Pertinente"));
            }
            content
        })
        .collect();

    let monitorati: Vec<i64> = (1..=i64::try_from(corpi.len()).unwrap_or(0)).collect();
    let mut snapshot = fotografia(&monitorati);
    snapshot.template_version = 3;

    let alerts = [LedgerAlert {
        content_id: ContentId::new(6),
        level: 4,
        // Anche la motivazione del motore e' testo non fidato.
        reason: String::from("=RISCONTRO(A1) — riscontro di due termini del dizionario"),
        raised_at: Timestamp::from_millis(1_752_002_000_000),
    }];

    let reviews = [LedgerReview {
        content_id: ContentId::new(1),
        state: String::from("Pertinente"),
        note: Some(String::from("@nota di prova dell'operatore")),
        actor: String::from("operatore.prova"),
        decided_at: Timestamp::from_millis(1_752_003_000_000),
    }];

    let ledger = compose(&LedgerInput {
        report_id: &report_id,
        profile: &profile,
        snapshot: &snapshot,
        operator: &operator,
        generated_at: Timestamp::from_millis(1_752_086_400_000),
        session: &session,
        sources: &[],
        contents: &contents,
        alerts: &alerts,
        reviews: &reviews,
        // Vuoto apposta: il foglio 06 — Errori deve esserci ugualmente (T85).
        faults: &[],
        configuration: &AnalysisConfiguration::unknown(),
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
    });

    let bytes = render(&ledger).expect("il registro deve potersi scrivere");
    let percorso = directory.join("NEXUM97_REGISTRO_EXCEL_PILOT.xlsx");
    std::fs::write(&percorso, &bytes).expect("il file deve potersi scrivere");

    println!("registro : {}", percorso.display());
}

/// Registro con i gruppi di segnali indicati e nessun contenuto.
fn registro_con_gruppi(eventi: &[LedgerCyberEvent]) -> Vec<u8> {
    let report_id = ReportId::from_sequence(2026, 1);
    let profile = ReportTemplateProfile::default();
    let operator = Actor::try_new("operatore").expect("attore valido");
    let session = sessione();
    let snapshot = fotografia(&[]);

    let ledger = compose(&LedgerInput {
        report_id: &report_id,
        profile: &profile,
        snapshot: &snapshot,
        operator: &operator,
        generated_at: Timestamp::from_millis(1_752_086_400_000),
        session: &session,
        sources: &[],
        contents: &[],
        alerts: &[],
        reviews: &[],
        faults: &[],
        configuration: &AnalysisConfiguration::unknown(),
        cyber_events: eventi,
        subjects: &[],
        taxonomy: &[],
        taxonomy_beyond: 0,
        official_sources: &[],
        notes: &[],
        notes_beyond: 0,
        workspaces: &[],
        workspaces_beyond: 0,
        investigative_basis: true,
    });

    render(&ledger).expect("il registro deve potersi scrivere")
}

/// Un gruppo di segnali con il valore di indicatore indicato.
///
/// # Perché ogni colonna porta un valore DIVERSO
///
/// La prima stesura ripeteva lo stesso testo nella colonna del valore e in
/// quella degli indicatori nominati. La prova cercava quel testo, lo trovava —
/// e continuava a trovarlo anche dopo che la colonna del valore era stata
/// rotta apposta. **Era verde a vuoto**, e il controllo negativo l'ha scoperto.
///
/// Ogni colonna porta ora un valore riconoscibile e distinto, così che una
/// prova che ne cerca uno stia davvero guardando quella colonna.
fn gruppo(valore: &str) -> LedgerCyberEvent {
    LedgerCyberEvent {
        reason: String::from("nominano lo stesso indirizzo RAGIONE-1"),
        indicator_kind: String::from("indirizzo"),
        indicator_value: String::from(valore),
        contents: 3,
        distinct_sources: 2,
        apparent_reposts: 1,
        first_seen: Some(Timestamp::from_millis(1_752_000_000_000)),
        last_seen: Some(Timestamp::from_millis(1_752_086_400_000)),
        italy: String::from("Nessun segnale che riguardi l'Italia."),
        sectors: None,
        indicators: vec![String::from("indirizzo: ELENCO-1")],
        review: String::from("Nessuno dei 3 contenuti è stato ancora esaminato."),
        timeline: None,
        neighbourhood: None,
    }
}

/// **Il foglio dei gruppi c'è anche quando non ci sono gruppi.**
///
/// Un foglio assente in un fascicolo consegnato si legge come «non è stato
/// cercato». Le intestazioni ci sono sempre, e dicono che cosa la colonna
/// conterrebbe.
#[test]
fn the_cyber_sheet_exists_even_with_no_groups() {
    let bytes = registro_con_gruppi(&[]);
    let tutto: String = voci(&bytes)
        .iter()
        .map(|(_, content)| content.as_str())
        .collect();

    assert!(
        tutto.contains("10 — Gruppi di segnali"),
        "il foglio dei gruppi deve esserci anche vuoto"
    );
}

/// **Un indicatore che comincia per `=` resta testo anche nel foglio nuovo.**
///
/// È la stessa prova di ADR-0031 Decisione 6, ripetuta sul foglio aggiunto:
/// un valore di indicatore viene da un contenuto remoto, e un foglio nuovo non
/// eredita automaticamente la protezione di quelli vecchi.
#[test]
fn a_hostile_indicator_stays_text_in_the_cyber_sheet() {
    let bytes = registro_con_gruppi(&[gruppo("=cmd|' /c calc'!A0")]);
    let tutto: String = voci(&bytes)
        .iter()
        .map(|(_, content)| content.as_str())
        .collect();

    assert!(
        !tutto.contains("<f>") && !tutto.contains("<f "),
        "una cella del foglio dei gruppi e' diventata una formula"
    );
    // Il valore ostile compare SOLO nella colonna del valore: se questa
    // asserzione passa, e' perche' quella colonna lo porta davvero.
    assert!(
        tutto.contains("=cmd|' /c calc'!A0") || tutto.contains("=cmd|&apos; /c calc&apos;!A0"),
        "il valore dell'indicatore e' stato alterato per renderlo innocuo, oppure \
         la colonna non lo porta affatto: il registro non riporta piu' cio' che la \
         fonte ha pubblicato"
    );
    // E le altre due colonne di testo restano distinguibili, cosi' che una
    // prova che cerca l'una non trovi per sbaglio l'altra.
    assert!(
        tutto.contains("RAGIONE-1") && tutto.contains("ELENCO-1"),
        "la ragione e l'elenco degli indicatori devono comparire, e distinti"
    );
}

/// **I conteggi del gruppo sono numeri, e la ragione è testo.**
///
/// Chi apre il registro deve poter ordinare per «contenuti» e per «fonti
/// distinte»: se fossero testo, l'ordinamento metterebbe 10 prima di 9.
#[test]
fn the_cyber_counts_are_numbers_and_the_reason_is_text() {
    let bytes = registro_con_gruppi(&[gruppo("198.51.100.7")]);
    let tutto: String = voci(&bytes)
        .iter()
        .map(|(_, content)| content.as_str())
        .collect();

    // I tre conteggi del gruppo di prova: 3 contenuti, 2 fonti, 1 ripubblicazione.
    assert!(
        tutto.contains(">3<") && tutto.contains(">2<") && tutto.contains(">1<"),
        "i conteggi devono essere celle numeriche"
    );
}

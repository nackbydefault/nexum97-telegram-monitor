//! PD-2, parte prima: interroga il binario TDLib su quali funzioni riconosce.
//!
//! **Non richiede credenziali e non contatta la rete.** La rete viene spenta a
//! livello di libreria prima di qualunque richiesta, e le credenziali usate
//! sono fittizie: la sonda misura quali tipi di richiesta il binario conosce,
//! non che cosa un account puo' fare.
//!
//! La parte seconda — che cosa le funzioni rispondono davvero — richiede una
//! persona che inserisca le proprie credenziali, e non sta qui.
//!
//! Compilato soltanto con la feature `tdlib-runtime`.
//!
//! Uso:
//!
//! ```text
//! lisi-tdlib-capability [percorso\tdjson.dll]
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

use lisi_telegram::tdlib::capability::NEGATIVE_CONTROL;
use lisi_telegram::tdlib::{CapabilityReport, default_library_path, run_capability_probe};

/// Le funzioni senza le quali l'espansione non si puo' costruire.
const REQUIRED: &[&str] = &[
    "searchMessages",
    "searchChatMessages",
    "searchPublicChat",
    "searchPublicChats",
    "searchPublicPosts",
    "getPublicPostSearchLimits",
    "getChatSimilarChats",
    "getChatSimilarChatCount",
    "getChats",
    "loadChats",
];

fn riporta(report: &CapabilityReport) {
    println!(
        "TDLib caricata, versione riportata: {}",
        report.tdlib_version.as_deref().unwrap_or("non ottenuta")
    );
    println!();
    println!("Funzioni richieste dall'espansione Public Discovery:");
    for nome in REQUIRED {
        let esito = report
            .capabilities
            .get(*nome)
            .map_or_else(|| String::from("non interrogata"), |c| c.describe());
        let segno = report
            .capabilities
            .get(*nome)
            .is_some_and(lisi_telegram::tdlib::Capability::is_recognised);
        println!("  [{}] {nome:<28} {esito}", if segno { "SI" } else { "NO" });
    }

    println!();
    println!("Altre funzioni misurate:");
    for (nome, capacita) in &report.capabilities {
        if REQUIRED.contains(&nome.as_str()) || nome == NEGATIVE_CONTROL {
            continue;
        }
        println!("  {nome:<32} {}", capacita.describe());
    }

    println!();
    println!("Controllo negativo:");
    let controllo = report
        .capabilities
        .get(NEGATIVE_CONTROL)
        .map_or_else(|| String::from("non interrogato"), |c| c.describe());
    println!("  {NEGATIVE_CONTROL:<32} {controllo}");
    if report.negative_control_holds() {
        println!("  La sonda distingue davvero: un nome inventato risulta sconosciuto.");
    } else {
        println!(
            "  ATTENZIONE: il controllo negativo NON e' risultato sconosciuto.\n  \
             Il rapporto qui sopra non dimostra nulla: la sonda non sta distinguendo."
        );
    }
}

fn main() -> ExitCode {
    let percorso = match std::env::args_os().nth(1) {
        Some(argomento) => PathBuf::from(argomento),
        None => match default_library_path() {
            Ok(percorso) => percorso,
            Err(errore) => {
                eprintln!("Percorso della libreria non determinabile: {errore}");
                return ExitCode::FAILURE;
            }
        },
    };

    println!("Libreria: {}", percorso.display());
    println!();

    let report = match run_capability_probe(&percorso) {
        Ok(report) => report,
        Err(errore) => {
            eprintln!("Sonda non riuscita: {errore}");
            return ExitCode::FAILURE;
        }
    };

    riporta(&report);

    // L'esito e' un fallimento se manca una funzione richiesta **oppure** se il
    // controllo negativo non regge: un rapporto che non distingue e' peggio di
    // un rapporto mancante, perche' sembra una risposta.
    let mancanti = report.missing();
    println!();
    if !report.negative_control_holds() {
        println!("ESITO: NON ATTENDIBILE — il controllo negativo non ha retto.");
        return ExitCode::FAILURE;
    }
    if mancanti.is_empty() {
        println!("ESITO: tutte le funzioni richieste sono riconosciute dal binario.");
        ExitCode::SUCCESS
    } else {
        println!(
            "ESITO: il binario NON riconosce {} funzioni:",
            mancanti.len()
        );
        for nome in mancanti {
            println!("  - {nome}");
        }
        ExitCode::FAILURE
    }
}

//! Eseguibile tecnico del proof of concept TDLib.
//!
//! È separato dal binario dell'applicazione e non ne altera l'avvio. Verifica
//! che il confine FFI regga contro la libreria reale: non richiede credenziali
//! e non contatta la rete, perché il primo comando inviato al client disattiva
//! la rete a livello di libreria.
//!
//! Compilato soltanto con la feature `tdlib-runtime`.
//!
//! Uso:
//!
//! ```text
//! lisi-tdlib-poc [percorso\tdjson.dll]
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

use lisi_telegram::tdlib::{SmokeTestReport, default_library_path, run_smoke_test};

fn esito(riuscito: bool) -> &'static str {
    if riuscito { "OK      " } else { "FALLITO " }
}

fn riporta(report: &SmokeTestReport) {
    println!("Caricamento riuscito.");
    println!("  Identificativo del client : {}", report.client_id);
    println!(
        "  Versione riportata        : {}",
        report.tdlib_version.as_deref().unwrap_or("non ottenuta")
    );
    println!();
    println!("Verifiche del confine FFI:");
    println!(
        "  [{}] richiesta con byte NUL interno rifiutata prima della FFI",
        esito(report.interior_nul_rejected)
    );
    println!(
        "  [{}] testo non ASCII conservato attraverso il confine",
        esito(report.non_ascii_round_trip)
    );
    if !report.non_ascii_round_trip {
        println!(
            "           testo restituito: {}",
            report.non_ascii_returned.as_deref().unwrap_or("nessuno")
        );
    }
    println!(
        "  [{}] puntatore nullo allo scadere dell'attesa trattato come assenza",
        esito(report.null_on_timeout)
    );
    println!(
        "  [{}] database locale aperto (percorso che usa la derivazione di chiave)",
        esito(report.local_database_opened)
    );
    println!(
        "  [{}] chiusura ordinata confermata dalla libreria",
        esito(report.closed_orderly)
    );
    println!();
    println!("  Aggiornamenti ricevuti    : {}", report.updates_received);
    println!("  Stati di autorizzazione   :");
    for state in &report.authorization_states {
        println!("      {state}");
    }
}

fn main() -> ExitCode {
    println!("LISI Telegram Monitor - proof of concept TDLib");
    println!("{}", lisi_core::ATTRIBUTION);
    println!();

    let path = match std::env::args().nth(1) {
        Some(argument) => PathBuf::from(argument),
        None => match default_library_path() {
            Ok(path) => path,
            Err(error) => {
                eprintln!("Impossibile determinare il percorso predefinito: {error}");
                return ExitCode::FAILURE;
            }
        },
    };

    println!("Libreria attesa: {}", path.display());
    println!();

    match run_smoke_test(&path) {
        Ok(report) => {
            riporta(&report);
            println!();
            println!("Nessuna credenziale e' stata richiesta o usata.");
            println!(
                "La rete e' stata disattivata a livello di libreria: nessun server contattato."
            );

            if report.is_fully_successful() {
                println!();
                println!("Tutte le verifiche sono riuscite.");
                ExitCode::SUCCESS
            } else {
                eprintln!();
                eprintln!("Almeno una verifica non e' riuscita: vedere l'elenco sopra.");
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("Verifica non riuscita: {error}");
            eprintln!();
            eprintln!(
                "Costruire la libreria con scripts\\build-tdlib.ps1 oppure indicarne il percorso \
                 come primo argomento."
            );
            ExitCode::FAILURE
        }
    }
}

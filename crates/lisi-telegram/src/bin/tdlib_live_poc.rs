//! PD-2, parte seconda: prende le cinque misure con un account reale.
//!
//! # Che cosa fa, detto prima di farlo
//!
//! Si collega a Telegram con le credenziali che **una persona inserisce qui**,
//! esegue **quattro interrogazioni di misura** e chiude. Non acquisisce
//! contenuti, non li conserva, non li stampa.
//!
//! # Che cosa NON fa, mai
//!
//! - **non stampa** numero di telefono, codice, password, chiave dell'API ne'
//!   contenuti dei messaggi: solo forme, conteggi, limiti e codici di errore;
//! - **non legge** credenziali da variabili d'ambiente, da file o dalla riga di
//!   comando: le chiede, e restano nella memoria del processo;
//! - **non tocca** l'archivio del prodotto: usa una cartella propria, che
//!   cancella alla fine;
//! - **non spende**: `star_count` vale zero e i limiti si interrogano prima;
//! - **non entra** in alcun gruppo, non scrive, non reagisce.
//!
//! Compilato soltanto con la feature `tdlib-runtime`.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use lisi_telegram::tdlib::ffi::TdJsonLibrary;
use lisi_telegram::tdlib::live_probe::{LiveProbeReport, measure, provoke_rate_limit};
use lisi_telegram::tdlib::{default_library_path, json_string_value, json_type};

/// Quante volte si interroga la libreria durante l'accesso.
const MAX_POLLS: usize = 2_000;

/// Attesa di ogni interrogazione, in secondi.
const POLL_TIMEOUT: f64 = 0.05;

/// Quante interrogazioni distinte si tentano per provocare una limitazione.
const RATE_LIMIT_ATTEMPTS: usize = 30;

/// Chiede una riga all'operatore.
///
/// **Il testo digitato compare sullo schermo** — questo strumento non spegne
/// l'eco del terminale, perche' farlo richiederebbe una chiamata di sistema e
/// il progetto vieta `unsafe` fuori da un modulo dedicato. Chi digita una
/// password lo faccia senza spettatori: e' detto anche a schermo prima di
/// chiederla.
fn chiedi(domanda: &str) -> Option<String> {
    print!("{domanda}");
    let _ = std::io::stdout().flush();
    let mut riga = String::new();
    if std::io::stdin().read_line(&mut riga).ok()? == 0 {
        return None;
    }
    let riga = riga.trim().to_owned();
    if riga.is_empty() { None } else { Some(riga) }
}

/// Chiede una conferma esplicita.
fn conferma(domanda: &str) -> bool {
    matches!(
        chiedi(&format!("{domanda} [scrivere SI per confermare]: ")).as_deref(),
        Some("SI")
    )
}

/// Rende un testo sicuro dentro una stringa JSON.
fn escape(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .flat_map(|c| match c {
            '"' => vec!['\\', '"'],
            '\\' => vec!['\\', '\\'],
            other => vec![other],
        })
        .collect()
}

/// Porta il client fino all'autorizzazione, chiedendo cio' che TDLib chiede.
///
/// Restituisce `true` se l'account e' pronto.
fn autorizza(
    library: &TdJsonLibrary,
    client_id: i32,
    api_id: &str,
    api_hash: &str,
    directory: &str,
) -> bool {
    let mut parametri_inviati = false;

    for _ in 0..MAX_POLLS {
        let Ok(Some(messaggio)) = library.receive(POLL_TIMEOUT) else {
            continue;
        };
        if json_type(&messaggio).as_deref() != Some("updateAuthorizationState") {
            continue;
        }
        let stato = json_string_value(&messaggio, "@type")
            .filter(|tipo| tipo.starts_with("authorizationState"))
            .or_else(|| {
                // Lo stato e' annidato: si cerca il secondo `@type`.
                messaggio.rfind(r#""@type":"authorizationState"#).map(|at| {
                    let resto = &messaggio[at + 9..];
                    let inizio = resto.find('"').map_or(0, |i| i + 1);
                    let resto = &resto[inizio..];
                    let fine = resto.find('"').unwrap_or(resto.len());
                    resto[..fine].to_owned()
                })
            })
            .unwrap_or_default();

        match stato.as_str() {
            "authorizationStateWaitTdlibParameters" if !parametri_inviati => {
                parametri_inviati = true;
                let richiesta = format!(
                    concat!(
                        r#"{{"@type":"setTdlibParameters","use_test_dc":false,"#,
                        r#""database_directory":"{}","files_directory":"{}","#,
                        r#""use_file_database":false,"use_chat_info_database":false,"#,
                        // **Spento apposta**: e' la misura 3. Se
                        // `searchMessages` lo richiedesse, rifiuterebbe qui.
                        r#""use_message_database":false,"use_secret_chats":false,"#,
                        r#""api_id":{},"api_hash":"{}","#,
                        r#""system_language_code":"it","device_model":"NEXUM97 PoC",""#,
                        r#"application_version":"0.1.0"}}"#
                    ),
                    directory,
                    directory,
                    api_id,
                    escape(api_hash)
                );
                let _ = library.send(client_id, &richiesta);
            }
            "authorizationStateWaitPhoneNumber" => {
                println!();
                println!("Telegram chiede il numero di telefono dell'account autorizzato.");
                let Some(numero) = chiedi("Numero (con prefisso internazionale): ") else {
                    println!("Nessun numero inserito: si interrompe.");
                    return false;
                };
                let richiesta = format!(
                    r#"{{"@type":"setAuthenticationPhoneNumber","phone_number":"{}"}}"#,
                    escape(&numero)
                );
                let _ = library.send(client_id, &richiesta);
            }
            "authorizationStateWaitCode" => {
                println!();
                println!("Telegram ha inviato un codice all'account.");
                let Some(codice) = chiedi("Codice ricevuto: ") else {
                    println!("Nessun codice inserito: si interrompe.");
                    return false;
                };
                let richiesta = format!(
                    r#"{{"@type":"checkAuthenticationCode","code":"{}"}}"#,
                    escape(&codice)
                );
                let _ = library.send(client_id, &richiesta);
            }
            "authorizationStateWaitPassword" => {
                println!();
                println!("L'account ha la verifica in due passaggi.");
                println!("ATTENZIONE: la password comparira' sullo schermo mentre la digiti.");
                let Some(password) = chiedi("Password: ") else {
                    println!("Nessuna password inserita: si interrompe.");
                    return false;
                };
                let richiesta = format!(
                    r#"{{"@type":"checkAuthenticationPassword","password":"{}"}}"#,
                    escape(&password)
                );
                let _ = library.send(client_id, &richiesta);
            }
            "authorizationStateReady" => {
                println!();
                println!("Accesso riuscito.");
                return true;
            }
            "authorizationStateClosed" => {
                println!("La libreria ha chiuso il client.");
                return false;
            }
            _ => {}
        }
    }

    println!("Autorizzazione non completata entro l'attesa.");
    false
}

/// Stampa il rapporto delle misure.
fn riporta(report: &LiveProbeReport) {
    println!();
    println!("======== LE CINQUE MISURE ========");
    println!();

    println!("Misura 2 — quote della ricerca pubblica:");
    match &report.limits {
        Some(limiti) => {
            println!(
                "  interrogazioni gratuite al giorno : {}",
                limiti.daily_free
            );
            println!(
                "  gratuite rimaste oggi             : {}",
                limiti.remaining_free
            );
            println!(
                "  prossima gratuita fra (secondi)   : {}",
                limiti.next_free_in
            );
            println!("  costo di una NON gratuita (Stars) : {}", limiti.star_cost);
            println!(
                "  questa interrogazione e' gratuita : {}",
                if limiti.current_is_free { "SI" } else { "NO" }
            );
            println!(
                "  => una ricerca gratuita {} partire ora",
                if limiti.free_search_possible() {
                    "PUO'"
                } else {
                    "NON PUO'"
                }
            );
        }
        None => println!("  NON LEGGIBILI: la funzione non ha risposto o ha rifiutato."),
    }

    println!();
    println!("Misura 5 — ricerca nei post pubblici (star_count = 0):");
    println!("  {}", report.public_posts.describe());

    println!();
    println!("Misura 3 — searchMessages con il database dei messaggi SPENTO:");
    println!("  {}", report.account_search.describe());

    println!();
    println!("Misura 4 — ampiezza di searchPublicChats:");
    println!("  {}", report.public_chats.describe());

    println!();
    println!("Misura 1 — forma della limitazione:");
    println!("  {}", report.rate_limit.describe());
}

fn main() -> ExitCode {
    println!("NEXUM/97 — PD-2 parte seconda: misure dal vivo");
    println!();
    println!("Questo strumento si collega a Telegram con le credenziali che inserisci qui,");
    println!("esegue quattro interrogazioni di misura e chiude.");
    println!();
    println!("NON stampa numero, codice, password, chiave dell'API o contenuti dei messaggi.");
    println!("NON legge credenziali da variabili d'ambiente, da file o dalla riga di comando.");
    println!("NON tocca l'archivio del prodotto: usa una cartella propria.");
    println!("NON spende: star_count vale zero e i limiti si interrogano prima di cercare.");
    println!("NON entra in gruppi, non scrive, non reagisce.");
    println!();

    if !conferma("Procedere") {
        println!("Interrotto.");
        return ExitCode::SUCCESS;
    }

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

    println!();
    println!("Servono le credenziali dell'applicazione Telegram dell'ufficio.");
    println!("Si ottengono da my.telegram.org e NON vengono conservate da questo strumento.");
    let Some(api_id) = chiedi("api_id: ") else {
        println!("Nessun api_id: si interrompe.");
        return ExitCode::FAILURE;
    };
    if api_id.chars().any(|c| !c.is_ascii_digit()) {
        println!("L'api_id deve essere un numero.");
        return ExitCode::FAILURE;
    }
    println!("ATTENZIONE: la chiave comparira' sullo schermo mentre la digiti.");
    let Some(api_hash) = chiedi("api_hash: ") else {
        println!("Nessun api_hash: si interrompe.");
        return ExitCode::FAILURE;
    };

    let library = match TdJsonLibrary::load(&percorso) {
        Ok(library) => library,
        Err(errore) => {
            eprintln!("Libreria non caricata: {errore}");
            return ExitCode::FAILURE;
        }
    };
    let _ = library.execute(r#"{"@type":"setLogVerbosityLevel","new_verbosity_level":0}"#);

    let cartella = std::env::temp_dir().join("nexum97-pd2-poc");
    let cartella_json = cartella.display().to_string().replace('\\', "\\\\");

    let Ok(client_id) = library.create_client_id() else {
        eprintln!("Client non creato.");
        return ExitCode::FAILURE;
    };
    // La prima richiesta avvia il flusso degli aggiornamenti di autorizzazione.
    let _ = library.send(client_id, r#"{"@type":"getOption","name":"version"}"#);

    if !autorizza(&library, client_id, &api_id, &api_hash, &cartella_json) {
        let _ = library.send(client_id, r#"{"@type":"close"}"#);
        return ExitCode::FAILURE;
    }

    let mut report = match measure(&library, client_id) {
        Ok(report) => report,
        Err(errore) => {
            eprintln!("Misure non riuscite: {errore}");
            let _ = library.send(client_id, r#"{"@type":"logOut"}"#);
            return ExitCode::FAILURE;
        }
    };

    // **La misura che costa.** Provocare una limitazione rende l'account
    // temporaneamente meno utilizzabile, e non e' una decisione che uno
    // strumento possa prendere da solo.
    println!();
    println!("Resta la misura 1: la forma della limitazione.");
    println!("Per prenderla bisogna PROVOCARLA, con interrogazioni distinte ripetute.");
    println!("Costo: l'account potrebbe restare limitato per un po' sulla ricerca pubblica.");
    if conferma("Provocare la limitazione") {
        match provoke_rate_limit(&library, client_id, RATE_LIMIT_ATTEMPTS) {
            Ok(misura) => report.rate_limit = misura,
            Err(errore) => eprintln!("Misura della limitazione non riuscita: {errore}"),
        }
    } else {
        println!("Saltata. La misura 1 resta da prendere.");
    }

    riporta(&report);

    println!();
    println!("Chiusura: si esce dall'account e si cancella la cartella temporanea.");
    let _ = library.send(client_id, r#"{"@type":"logOut"}"#);
    for _ in 0..200 {
        if library.receive(POLL_TIMEOUT).is_err() {
            break;
        }
    }
    let _ = library.send(client_id, r#"{"@type":"close"}"#);
    let _ = std::fs::remove_dir_all(&cartella);

    println!();
    println!("Riportare queste misure nella parte seconda di docs/validation/PD-2_POC_TDLIB.md,");
    println!("portando ciascuna riga a PROVATO DAL VIVO oppure lasciandola non provata.");
    ExitCode::SUCCESS
}

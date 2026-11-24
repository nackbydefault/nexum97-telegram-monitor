//! La prova che mancava: **aggiornare un archivio vero**.
//!
//! # Perche' questa prova esiste
//!
//! Tutte le prove sulle migrazioni girano su un database **nuovo**: si apre un
//! archivio vuoto, si applicano sedici migrazioni in fila, si verifica la
//! versione. Passano, e non dimostrano cio' che serve.
//!
//! Un archivio vero non e' vuoto. Ha dentro contenuti, sessioni, fonti,
//! dizionari e vincoli gia' soddisfatti da righe che esistono. Una migrazione
//! che aggiunge una colonna con un vincolo, o che ricrea una tabella, si
//! comporta diversamente su una tabella piena — e la differenza si vede solo
//! provandola su una tabella piena.
//!
//! Il 2026-08-18, sulla prima installazione reale del prodotto, l'archivio
//! dell'operatore **non si e' aperto**: il programma ha ripiegato su
//! un'archiviazione in memoria e ha perso tutto alla chiusura. L'archivio era
//! alla versione 10, il codice alla 16.
//!
//! # Come si esegue
//!
//! Serve un archivio reale, che **non e' e non sara' mai** nel repository:
//!
//! ```powershell
//! $env:LISI_ARCHIVIO_DA_AGGIORNARE = "C:\percorso\copia-di-monitor.sqlite"
//! cargo test -p lisi-storage --test aggiornamento_archivio_reale -- --ignored --nocapture
//! ```
//!
//! **Si esegue su una COPIA.** La prova apre l'archivio in scrittura e vi
//! applica le migrazioni: puntarla all'archivio in uso significherebbe
//! modificarlo mentre si sta cercando di capire perche' non funziona.

use lisi_storage::Database;

/// Variabile con cui si indica l'archivio da aggiornare.
const PERCORSO: &str = "LISI_ARCHIVIO_DA_AGGIORNARE";

#[test]
#[ignore = "richiede un archivio reale: si esegue a mano, su una copia"]
fn a_real_archive_upgrades_to_the_current_schema() {
    let Ok(percorso) = std::env::var(PERCORSO) else {
        panic!("impostare {PERCORSO} con il percorso di una COPIA dell'archivio");
    };
    let percorso = std::path::PathBuf::from(percorso);
    assert!(
        percorso.exists(),
        "l'archivio indicato non esiste: {}",
        percorso.display()
    );

    println!("Archivio: {}", percorso.display());
    println!(
        "Versione attesa dal codice: {}",
        lisi_storage::LATEST_VERSION
    );
    println!();

    match Database::open(&percorso) {
        Ok(_) => {
            println!("APERTO E AGGIORNATO senza errori.");
        }
        Err(errore) => {
            // **Il messaggio e' il risultato della prova**, non un dettaglio:
            // e' l'unica cosa che dice quale migrazione si e' fermata e
            // perche'. Un fallimento che non lo riportasse costringerebbe a
            // rifare la diagnosi da capo.
            println!("NON APERTO.");
            println!("  motivo  : {errore}");
            panic!("l'archivio reale non si aggiorna: {errore}");
        }
    }
}

/// La stessa cosa, **otto volte di fila**, come fa l'applicazione.
///
/// # Perche' ripetere
///
/// L'applicazione non apre l'archivio una volta: lo apre una volta per
/// servizio, oltre venti in tutto. La prima apertura applica le migrazioni; le
/// altre trovano il lavoro gia' fatto.
///
/// Se il difetto vivesse nella ripetizione — un file lasciato in uno stato che
/// la seconda apertura non regge — una prova che apre una volta sola sarebbe
/// verde e non direbbe nulla.
#[test]
#[ignore = "richiede un archivio reale: si esegue a mano, su una copia"]
fn a_real_archive_survives_being_opened_as_many_times_as_the_application_does() {
    let Ok(percorso) = std::env::var(PERCORSO) else {
        panic!("impostare {PERCORSO} con il percorso di una COPIA dell'archivio");
    };
    let percorso = std::path::PathBuf::from(percorso);

    let mut aperture = Vec::new();
    for numero in 1..=8 {
        match Database::open(&percorso) {
            Ok(database) => {
                let versione = database.schema_version().map_or_else(
                    |errore| format!("non leggibile: {errore}"),
                    |v| v.to_string(),
                );
                println!("apertura {numero}: RIUSCITA, versione {versione}");
                // Le connessioni restano aperte, come nell'applicazione: e' la
                // condizione in cui il difetto potrebbe manifestarsi.
                aperture.push(database);
            }
            Err(errore) => {
                println!("apertura {numero}: FALLITA — {errore}");
                panic!("l'apertura {numero} e' fallita: {errore}");
            }
        }
    }
    println!("Tutte e otto le aperture sono riuscite.");
}

/// Che cosa c'e' davvero nel profilo documentale conservato.
///
/// Serve a separare due difetti che si somigliano: **il profilo non e' stato
/// salvato** e **il profilo e' stato salvato e l'interfaccia non lo mostra**.
/// Dedurlo dalla schermata e' impossibile — in entrambi i casi i campi
/// appaiono vuoti — e sbagliare la diagnosi significa correggere il punto
/// sbagliato.
#[test]
#[ignore = "richiede un archivio reale: si esegue a mano, su una copia"]
fn what_the_stored_profile_actually_contains() {
    let Ok(percorso) = std::env::var(PERCORSO) else {
        panic!("impostare {PERCORSO} con il percorso di una COPIA dell'archivio");
    };
    let database = Database::open(&std::path::PathBuf::from(percorso))
        .expect("l'archivio deve potersi aprire");

    match database.report_profile() {
        Ok(None) => println!("NESSUNA RIGA: la domanda non e' mai stata posta."),
        Ok(Some(profile)) => {
            println!("RIGA PRESENTE, versione {}", profile.version);
            println!("  campi compilati : {}", profile.filled_fields());
            println!(
                "  stemma          : {}",
                if profile.emblem.is_some() {
                    "presente"
                } else {
                    "assente"
                }
            );
            // I valori NON si stampano: sono dati dell'ufficio, e per capire
            // dove sia il difetto basta sapere QUANTI campi sono pieni.
            println!("  (i valori non si stampano: basta il conteggio)");
        }
        Err(errore) => println!("NON LEGGIBILE: {errore}"),
    }
}

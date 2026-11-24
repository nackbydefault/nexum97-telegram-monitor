//! Che cosa succede davvero seguendo la procedura di ripristino.
//!
//! # Perché questa prova esiste
//!
//! Il prodotto **non ripristina**, ed è una decisione presa apposta: il gesto
//! resta a una persona, che segue il foglio scritto accanto alla copia di
//! sicurezza (ADR-0101). Quel foglio diceva «mettere da parte l'archivio che
//! c'è», al singolare.
//!
//! **Ma l'archivio non è un file: sono tre.** In modalità WAL, accanto
//! all'archivio vivono il giornale delle ultime scritture (`-wal`) e la sua
//! cache condivisa (`-shm`). Il percorso di azzeramento lo sa già e li cancella
//! tutti e tre, «perché lasciarne uno dei tre ricostruirebbe parte del
//! contenuto appena cancellato».
//!
//! Questa prova esegue la procedura del foglio nei due modi e guarda che cosa
//! ne esce. Non deduce: misura. È la ragione per cui il foglio dice quello che
//! dice (ADR-0115).
//!
//! # Perché la si tiene anche adesso che il foglio è corretto
//!
//! Perché la correzione è **prosa**, e la prosa non smette di funzionare: smette
//! di essere vera. Se un domani SQLite cambiasse comportamento — o se qualcuno
//! togliesse la modalità WAL — questa prova diventerebbe rossa e direbbe che il
//! foglio parla di un pericolo che non c'è più.

use rusqlite::Connection;

/// Il nome con cui il prodotto apre l'archivio, ripetuto qui perché
/// `lisi-storage` non conosce `lisi-services`. Non è il nome che conta: conta
/// che i file accanto si chiamino come questo, più un suffisso.
const ARCHIVIO: &str = "monitor.sqlite";

/// Prepara una cartella con un archivio in WAL, il cui giornale **non** è stato
/// consolidato: è lo stato in cui una postazione resta dopo un arresto brusco,
/// che è poi il giorno in cui si ripristina.
fn postazione_dopo_un_guasto(radice: &std::path::Path, contenuto: &str) -> std::path::PathBuf {
    let viva = radice.join("viva");
    std::fs::create_dir_all(&viva).expect("la cartella viva deve potersi creare");
    let archivio = viva.join(ARCHIVIO);

    let connessione = Connection::open(&archivio).expect("l'archivio deve potersi aprire");
    let _modalita: String = connessione
        .query_row("PRAGMA journal_mode = WAL", [], |riga| riga.get(0))
        .expect("la modalita' WAL deve potersi adottare");
    connessione
        .execute_batch(&format!(
            "PRAGMA wal_autocheckpoint = 0;
             CREATE TABLE contenuto (valore TEXT NOT NULL);
             INSERT INTO contenuto (valore) VALUES ('{contenuto}');"
        ))
        .expect("la scrittura deve riuscire");

    // La fotografia si prende mentre la connessione e' ancora aperta: chiudere
    // in modo pulito consoliderebbe il giornale e lo farebbe sparire, che e'
    // esattamente il caso in cui il pericolo non c'e'.
    let guasto = radice.join("guasto");
    std::fs::create_dir_all(&guasto).expect("la cartella del guasto deve potersi creare");
    for suffisso in ["", "-wal", "-shm"] {
        let nome = format!("{ARCHIVIO}{suffisso}");
        let sorgente = viva.join(&nome);
        if sorgente.exists() {
            std::fs::copy(&sorgente, guasto.join(&nome)).expect("la copia deve riuscire");
        }
    }
    drop(connessione);

    guasto
}

/// Una copia di sicurezza: un archivio diverso, con un contenuto riconoscibile.
fn copia_di_sicurezza(radice: &std::path::Path, contenuto: &str) -> std::path::PathBuf {
    let copia = radice.join("nexum97-copia-0001700000000000.sqlite3");
    let connessione = Connection::open(&copia).expect("la copia deve potersi creare");
    connessione
        .execute_batch(&format!(
            "CREATE TABLE contenuto (valore TEXT NOT NULL);
             INSERT INTO contenuto (valore) VALUES ('{contenuto}');"
        ))
        .expect("la scrittura deve riuscire");
    drop(connessione);
    copia
}

/// Che cosa si legge riaprendo l'archivio, e che cosa ne dice la verifica.
fn cosa_si_legge(archivio: &std::path::Path) -> (String, String) {
    let connessione = Connection::open(archivio).expect("l'archivio deve potersi riaprire");
    let valore: String = connessione
        .query_row("SELECT valore FROM contenuto", [], |riga| riga.get(0))
        .expect("il contenuto deve potersi leggere");
    let verifica: String = connessione
        .query_row("PRAGMA quick_check", [], |riga| riga.get(0))
        .expect("la verifica deve potersi eseguire");
    (valore, verifica)
}

/// **Un giornale rimasto riporta indietro un archivio appena ripristinato, e
/// l'archivio si apre lo stesso.**
///
/// È il difetto che la vecchia procedura lasciava commettere: il ripristino non
/// fallisce, **non avviene**, e niente lo dice.
#[test]
fn un_giornale_rimasto_riporta_indietro_l_archivio_ripristinato() {
    let radice = tempfile::tempdir().expect("la cartella temporanea deve potersi creare");
    let guasto = postazione_dopo_un_guasto(radice.path(), "PRIMA");
    let copia = copia_di_sicurezza(radice.path(), "RIPRISTINATO");

    assert!(
        guasto.join(format!("{ARCHIVIO}-wal")).exists(),
        "senza un giornale rimasto questa prova non sta misurando nulla: \
         il caso che vuole descrivere e' proprio quello dell'arresto brusco"
    );

    // La procedura vecchia: si mette da parte SOLO l'archivio.
    let bersaglio = guasto.join(ARCHIVIO);
    std::fs::rename(&bersaglio, guasto.join("messo-da-parte.sqlite"))
        .expect("l'archivio deve potersi spostare");
    std::fs::copy(&copia, &bersaglio).expect("la copia deve potersi mettere al suo posto");

    let (valore, verifica) = cosa_si_legge(&bersaglio);

    assert_eq!(
        valore, "PRIMA",
        "il giornale rimasto non e' stato riversato sull'archivio ripristinato: \
         se SQLite ha cambiato comportamento, il foglio della copia di sicurezza \
         descrive un pericolo che non c'e' piu' e va riscritto (ADR-0115)"
    );
    assert_eq!(
        verifica, "ok",
        "la verifica dell'archivio non dichiara piu' integro un archivio tornato \
         indietro: se ora se ne accorge, il foglio puo' tornare a mandare \
         l'operatore li' (ADR-0115)"
    );
}

/// **Spostando tutti e tre i file, il ripristino avviene.**
///
/// È il controllo dell'altra prova: senza di esso, «si legge PRIMA» potrebbe
/// dipendere dal fatto che la copia non era leggibile, e non dal giornale.
#[test]
fn spostando_tutti_e_tre_i_file_il_ripristino_avviene() {
    let radice = tempfile::tempdir().expect("la cartella temporanea deve potersi creare");
    let guasto = postazione_dopo_un_guasto(radice.path(), "PRIMA");
    let copia = copia_di_sicurezza(radice.path(), "RIPRISTINATO");

    // La procedura corretta: si spostano TUTTI E TRE i file.
    let da_parte = radice.path().join("da-parte");
    std::fs::create_dir_all(&da_parte).expect("la cartella deve potersi creare");
    for suffisso in ["", "-wal", "-shm"] {
        let nome = format!("{ARCHIVIO}{suffisso}");
        let sorgente = guasto.join(&nome);
        if sorgente.exists() {
            std::fs::rename(&sorgente, da_parte.join(&nome)).expect("lo spostamento deve riuscire");
        }
    }

    let bersaglio = guasto.join(ARCHIVIO);
    std::fs::copy(&copia, &bersaglio).expect("la copia deve potersi mettere al suo posto");

    let (valore, verifica) = cosa_si_legge(&bersaglio);

    assert_eq!(
        valore, "RIPRISTINATO",
        "spostando tutti e tre i file il ripristino deve avvenire: se non avviene, \
         la procedura scritta sul foglio non funziona (ADR-0115)"
    );
    assert_eq!(
        verifica, "ok",
        "l'archivio ripristinato deve essere integro"
    );
}

//! **TDLib sta sull'Hub** (TEAM-AUTHORITY-01, ADR-0092).
//!
//! # Il difetto che queste prove impediscono
//!
//! L'acquisizione da Telegram la esegue **una sola autorità**, una volta per
//! tutto l'ufficio (freeze §7.10). Il giorno in cui una postazione che segue un
//! Hub aprisse una propria sessione TDLib, il prodotto produrrebbe N carichi su
//! Telegram per N postazioni e, per lo stesso account, N dispositivi — e non
//! fallirebbe niente.
//!
//! # Perché una capacità, e perché queste prove
//!
//! `AcquisitionAuthority` non ha un costruttore pubblico, e aprire il
//! connettore reale la richiede: un `if` si dimentica, un parametro no. Le
//! prove verificano **entrambe** le metà:
//!
//! 1. **il comportamento**: una postazione con un Hub configurato non ottiene
//!    l'autorità, e una senza sì;
//! 2. **la forma del codice**: TDLib si istanzia in un solo punto, quel punto
//!    chiede l'autorità, e l'autorità non si fabbrica altrove.
//!
//! La seconda esiste perché la prima non basta: un secondo percorso che
//! aprisse TDLib senza chiedere nulla passerebbe tutte le prove di
//! comportamento del primo.

use std::path::{Path, PathBuf};

use lisi_core::model::hub_client::{HubAddress, HubConnection, StationRole};
use lisi_core::model::hub_identity::{HUB_FINGERPRINT_BYTES, HubExpectation, HubFingerprint};
use lisi_security::ProtectedStore;
use lisi_services::acquisition_authority::StationAuthorityService;
use lisi_services::hub_client::{HUB_FILE, HubConnectionStore};

/// La radice del repository, dedotta dalla posizione di questo crate.
fn radice() -> PathBuf {
    let mio = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let Some(crates) = mio.parent() else {
        panic!("il crate deve stare dentro «crates»");
    };
    let Some(radice) = crates.parent() else {
        panic!("«crates» deve stare dentro la radice del repository");
    };
    radice.to_path_buf()
}

/// Tutti i sorgenti Rust del prodotto.
fn sorgenti(percorso: &Path) -> Vec<PathBuf> {
    let mut trovati = Vec::new();
    let Ok(voci) = std::fs::read_dir(percorso) else {
        return trovati;
    };
    for voce in voci.flatten() {
        let percorso = voce.path();
        if percorso.is_dir() {
            if percorso.file_name().is_some_and(|nome| nome == "target") {
                continue;
            }
            trovati.extend(sorgenti(&percorso));
        } else if percorso
            .extension()
            .is_some_and(|estensione| estensione == "rs")
        {
            trovati.push(percorso);
        }
    }
    trovati
}

/// La parte di un sorgente che finisce nel programma consegnato.
///
/// Si tengono **tutte** le parti fuori dai moduli di prova, non solo la prima:
/// è la stessa funzione della guardia del proof of concept, e per la stessa
/// ragione — in Rust un file può avere un modulo di prova a metà e altro codice
/// sotto.
fn produzione(testo: &str) -> String {
    let mut fuori = String::new();
    let mut resto = testo;
    while let Some((prima, dopo)) = resto.split_once("#[cfg(test)]") {
        fuori.push_str(prima);
        match dopo.split_once("\n}\n") {
            Some((_, coda)) => resto = coda,
            None => return fuori,
        }
    }
    fuori.push_str(resto);
    fuori
}

/// Il testimone operativo: queste prove lavorano in modo operativo (PR-13).
fn operativo() -> lisi_services::run_mode::OperationalMode {
    match lisi_services::run_mode::operational() {
        Ok(testimone) => testimone,
        Err(conflitto) => panic!("queste prove lavorano in modo operativo: {conflitto}"),
    }
}

fn cartella() -> tempfile::TempDir {
    match tempfile::tempdir() {
        Ok(cartella) => cartella,
        Err(errore) => panic!("cartella temporanea: {errore}"),
    }
}

/// Scrive una configurazione dell'Hub nella cartella indicata: da qui in poi la
/// postazione **segue un Hub**.
fn configura_un_hub(cartella: &Path) {
    let archivio = HubConnectionStore::at(ProtectedStore::at(cartella.join(HUB_FILE)));
    let Ok(indirizzo) = HubAddress::parse("192.0.2.10:8443") else {
        panic!("indirizzo");
    };
    let impronta = HubFingerprint::from_bytes([9; HUB_FINGERPRINT_BYTES]);
    if archivio
        .save(&HubConnection::new(
            indirizzo,
            HubExpectation::Pinned(impronta),
        ))
        .is_err()
    {
        panic!("la configurazione deve potersi scrivere");
    }
}

// ---------------------------------------------------------------------------
// 1. Il comportamento
// ---------------------------------------------------------------------------

/// **Un client non ottiene l'autorità di acquisire.**
///
/// È la prova negativa che il piano chiede: il giorno in cui un client
/// riuscisse a istanziare TDLib, dovrebbe prima ottenere questa autorità — e
/// non può.
#[test]
fn una_postazione_che_segue_un_hub_non_ottiene_l_autorita() {
    let cartella = cartella();
    configura_un_hub(cartella.path());

    let stazione = StationAuthorityService::in_directory(cartella.path());
    assert_eq!(stazione.role(), StationRole::HubClient);

    let Ok(esito) = stazione.acquisition_authority(&operativo()) else {
        panic!("l'esito deve esserci");
    };
    assert!(
        esito.granted().is_none(),
        "una postazione che segue un Hub non deve poter aprire una sessione Telegram: \
         l'acquisizione la esegue l'Hub, una volta sola"
    );
    let Some(frase) = esito.refusal_message() else {
        panic!("il rifiuto deve avere una frase");
    };
    assert!(
        frase.contains("l'Hub"),
        "il rifiuto deve dire dove il lavoro viene fatto: «{frase}»"
    );
}

/// **Una postazione senza Hub acquisisce da sé.**
///
/// Serve a che la prova precedente non sia verde perché l'autorità non si
/// ottiene mai.
#[test]
fn una_postazione_senza_hub_ottiene_l_autorita() {
    let cartella = cartella();
    let stazione = StationAuthorityService::in_directory(cartella.path());
    assert_eq!(stazione.role(), StationRole::OwnAuthority);

    let Ok(esito) = stazione.acquisition_authority(&operativo()) else {
        panic!("l'esito deve esserci");
    };
    assert!(
        esito.granted().is_some(),
        "una postazione Standalone, e l'Hub stesso, devono poter acquisire"
    );
}

// ---------------------------------------------------------------------------
// 2. La forma del codice
// ---------------------------------------------------------------------------

/// Il tipo che apre davvero una sessione TDLib.
const CONNETTORE_REALE: &str = "LiveTdlibConnector::new(";

/// Il solo file del prodotto che può costruirlo.
const FILE_DEL_RUNTIME: &str = "telegram_runtime.rs";

/// **TDLib si istanzia in un punto solo, e quel punto chiede l'autorità.**
#[test]
fn il_connettore_reale_si_costruisce_in_un_punto_solo_e_chiede_l_autorita() {
    let crates = radice().join("crates");
    let file = sorgenti(&crates);
    assert!(
        file.len() > 50,
        "trovati solo {} sorgenti: la prova non sta percorrendo il prodotto",
        file.len()
    );

    let mut costruttori = Vec::new();
    for percorso in &file {
        let Ok(testo) = std::fs::read_to_string(percorso) else {
            continue;
        };
        // Questo file nomina il costruttore per cercarlo, e la crate che lo
        // definisce lo nomina per definirlo: nessuno dei due lo costruisce.
        if percorso.ends_with("tdlib_solo_sull_hub.rs")
            || percorso
                .components()
                .any(|parte| parte.as_os_str() == "lisi-telegram")
        {
            continue;
        }
        if produzione(&testo).contains(CONNETTORE_REALE) {
            costruttori.push(percorso.display().to_string());
        }
    }

    assert_eq!(
        costruttori.len(),
        1,
        "il connettore reale deve costruirsi in UN SOLO punto del prodotto, e invece \
         lo costruiscono {costruttori:#?} (ADR-0092)"
    );
    assert!(
        costruttori[0].ends_with(FILE_DEL_RUNTIME),
        "il punto in cui TDLib si istanzia deve essere «{FILE_DEL_RUNTIME}», e invece è {}",
        costruttori[0]
    );

    let Ok(sorgente) = std::fs::read_to_string(&costruttori[0]) else {
        panic!("il modulo del runtime deve potersi leggere");
    };
    let codice = produzione(&sorgente);
    let Some(firma) = codice.split("pub fn open_live(").nth(1) else {
        panic!("la funzione che apre la modalità reale deve chiamarsi open_live");
    };
    let Some((parametri, _)) = firma.split_once(") -> ") else {
        panic!("la firma di open_live non si delimita");
    };
    assert!(
        parametri.contains("authority: &AcquisitionAuthority"),
        "open_live deve RICHIEDERE la prova che questa postazione acquisisce: un \
         controllo dentro la funzione si può dimenticare, un parametro no (ADR-0092). \
         Parametri visti: {parametri}"
    );

    let Some(firma) = codice.split("pub fn open(").nth(1) else {
        panic!("l'ingresso dell'interfaccia deve chiamarsi open");
    };
    let Some((parametri, _)) = firma.split_once(") -> ") else {
        panic!("la firma di open non si delimita");
    };
    assert!(
        parametri.contains("authority: &AcquisitionAuthority"),
        "anche l'ingresso che l'interfaccia usa deve richiedere la prova: è da lì che \
         la modalità reale si sceglie. Parametri visti: {parametri}"
    );
}

/// **L'autorità non si fabbrica altrove.**
///
/// Un tipo senza costruttore pubblico difende solo finché nessun altro modulo
/// del prodotto lo costruisce: dentro la stessa crate il campo privato è
/// raggiungibile, e un secondo punto di costruzione riaprirebbe la porta senza
/// che nulla diventasse rosso.
#[test]
fn l_autorita_nasce_in_un_modulo_solo() {
    let crates = radice().join("crates");
    let mut fabbriche = Vec::new();
    for percorso in sorgenti(&crates) {
        let Ok(testo) = std::fs::read_to_string(&percorso) else {
            continue;
        };
        if percorso.ends_with("acquisition_authority.rs")
            || percorso.ends_with("tdlib_solo_sull_hub.rs")
        {
            continue;
        }
        let codice = produzione(&testo);
        if codice.contains("AcquisitionAuthority {") || codice.contains("AcquisitionAuthority(") {
            fabbriche.push(percorso.display().to_string());
        }
    }
    assert!(
        fabbriche.is_empty(),
        "questi sorgenti costruiscono l'autorità di acquisire fuori dal modulo che la \
         concede: {fabbriche:#?}. La prova che una postazione può acquisire deve \
         nascere da un solo posto (ADR-0092)"
    );
}

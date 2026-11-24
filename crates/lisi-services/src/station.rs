//! Modalità operativa **conservata** della postazione.
//!
//! `lisi-core` definisce la modalità e ciò che ciascuna consente; i servizi la
//! applicano. Questo modulo aggiunge la parte che mancava perché la modalità
//! valesse fra un avvio e l'altro: **la conserva**.
//!
//! Le scelte sono in `docs/adr/ADR-0015-OPERATOR-ROLES.md`. Tre punti toccano
//! questo codice.
//!
//! **La modalità sta in un file protetto proprio**, distinto da quello delle
//! credenziali Telegram: leggere in quale modalità è la postazione non deve
//! richiedere che le credenziali siano presenti, né viceversa.
//!
//! **Una postazione senza il file è nuova, quindi amministratore.** Qualcuno
//! deve poter configurare prima che esista un operatore. Ma un file *presente e
//! illeggibile* non ricade sull'amministratore: sarebbe una promozione ottenuta
//! corrompendo un file.
//!
//! **La parola di sblocco è conservata come impronta, non in chiaro.** Il file è
//! protetto con DPAPI, ma un operatore sullo stesso profilo può decifrarlo:
//! conservare la parola in chiaro gli permetterebbe di leggerla e tornare
//! amministratore **in silenzio**, lasciando intatta la configurazione. Con
//! l'impronta non può leggerla; per tornare deve conoscerla, oppure cancellare
//! il file — che è visibile. È coerente con il limite dichiarato: contro
//! l'errore protegge, contro la determinazione no, ma lascia una traccia.

use std::collections::BTreeMap;
use std::path::PathBuf;

use lisi_core::OperatingMode;
use lisi_security::{ProtectedStore, SecurityError};

use crate::error::{ServiceError, ServiceResult};
use crate::passphrase;

/// Chiave della modalità nel file protetto.
const MODE_KEY: &str = "operating_mode";
/// Chiave del salt della parola di sblocco.
const SALT_KEY: &str = "unlock_salt";
/// Chiave dell'impronta della parola di sblocco.
const HASH_KEY: &str = "unlock_hash";

/// Nome del file protetto della postazione.
pub const STATION_FILE: &str = "station.protetto";

// La validazione della parola, il salt e l'impronta vivono in
// crate::passphrase, in un'unica copia: questo modulo e crate::lock
// conservano entrambi una parola da ridigitare, e due implementazioni sarebbero
// due occasioni di sbagliarla senza che alcun test se ne accorga.

/// Percorso predefinito del file della postazione.
///
/// Accanto a quello delle credenziali, sotto la stessa cartella dati protetta
/// dal profilo. Il nome della cartella viene da `lisi-core` e non segue il nome
/// pubblico del prodotto: è un identificatore persistente.
///
/// # Errori
///
/// Restituisce un errore se la cartella dati locale non è determinabile.
pub fn default_station_path() -> ServiceResult<PathBuf> {
    Ok(crate::data_directory::application_directory()?.join(STATION_FILE))
}

/// Legge la modalità conservata.
///
/// Una postazione senza il file è **nuova**: amministratore. Un file presente
/// ma illeggibile, o con una modalità non riconoscibile, è un **errore**, non
/// un ritorno silenzioso all'amministratore.
///
/// # Errori
///
/// Restituisce un errore se il file esiste ma non è decifrabile con il profilo
/// corrente, o se contiene una modalità non interpretabile.
pub fn load_mode(store: &ProtectedStore) -> ServiceResult<OperatingMode> {
    if !store.exists() {
        return Ok(OperatingMode::Administrator);
    }

    let entries = store.load().map_err(map_security_error)?;
    let Some(raw) = entries.get(MODE_KEY) else {
        // Il file esiste ma non dichiara una modalità: e' corrotto o e' di
        // un'altra versione. Non lo si interpreta come amministratore.
        return Err(ServiceError::SessionUnavailable {
            reason: String::from("la configurazione della postazione è incompleta"),
        });
    };

    OperatingMode::parse(raw).map_err(ServiceError::Domain)
}

/// Modalità conservata sulla postazione, dal percorso predefinito.
///
/// Esiste perché l'interfaccia possa conoscere la modalità **senza dipendere da
/// `lisi-security`**: il confine è posto da ADR-0010 ed è verificato da un test.
///
/// Se la configurazione esiste ma non è leggibile, restituisce la modalità più
/// **ristretta**. Ricadere sull'amministratore trasformerebbe un file corrotto,
/// o appartenente a un altro profilo, in un ampliamento dei privilegi.
#[must_use]
pub fn persisted_mode_or_restricted() -> OperatingMode {
    let Ok(path) = default_station_path() else {
        // Senza cartella dati non c'e' configurazione da leggere: e' una
        // postazione non predisposta, non una postazione degradata.
        return OperatingMode::Administrator;
    };

    load_mode(&ProtectedStore::at(path)).unwrap_or(OperatingMode::Operator)
}

/// Passa la postazione in modalità operatore, fissando la parola di sblocco.
///
/// La parola è **obbligatoria**: un passaggio senza parola renderebbe il
/// ritorno gratuito, e la modalità operatore una decorazione. Da questo momento
/// il ritorno all'amministratore richiede quella parola, oppure la
/// cancellazione del file.
///
/// # Errori
///
/// Restituisce [`ServiceError::WeakUnlockWord`] se la parola è troppo corta,
/// troppo lunga o contiene caratteri di controllo, e un errore se la scrittura
/// protetta non riesce.
pub fn enter_operator_mode(store: &ProtectedStore, unlock_word: &str) -> ServiceResult<()> {
    let sealed = passphrase::seal(unlock_word)?;

    let mut entries = BTreeMap::new();
    entries.insert(
        String::from(MODE_KEY),
        String::from(OperatingMode::Operator.as_str()),
    );
    entries.insert(String::from(SALT_KEY), sealed.salt_hex);
    entries.insert(String::from(HASH_KEY), sealed.hash);

    store.save(&entries).map_err(map_security_error)
}

/// Riporta la postazione in modalità amministratore, verificando la parola.
///
/// # Errori
///
/// Restituisce [`ServiceError::WrongUnlockWord`] se la parola non corrisponde,
/// [`ServiceError::SessionUnavailable`] se non era stata fissata alcuna parola
/// (il file va allora cancellato e la postazione riconfigurata), e un errore se
/// la scrittura non riesce.
pub fn return_to_administrator(store: &ProtectedStore, attempt: &str) -> ServiceResult<()> {
    // Già amministratore: nulla da sbloccare.
    if load_mode(store)? == OperatingMode::Administrator {
        return Ok(());
    }

    let entries = store.load().map_err(map_security_error)?;
    let (Some(salt_hex), Some(stored_hash)) = (entries.get(SALT_KEY), entries.get(HASH_KEY)) else {
        return Err(ServiceError::SessionUnavailable {
            reason: String::from(
                "nessuna parola di sblocco risulta fissata: la postazione va riconfigurata",
            ),
        });
    };

    if !passphrase::matches(salt_hex, stored_hash, attempt) {
        return Err(ServiceError::WrongUnlockWord);
    }

    // La parola era giusta: la modalità torna amministratore e le tracce della
    // parola si rimuovono, perche' non servono piu' e ogni segreto conservato
    // oltre il suo scopo e' un rischio in piu'.
    let mut cleared = BTreeMap::new();
    cleared.insert(
        String::from(MODE_KEY),
        String::from(OperatingMode::Administrator.as_str()),
    );
    store.save(&cleared).map_err(map_security_error)
}

/// Traduce un errore della protezione locale.
fn map_security_error(error: SecurityError) -> ServiceError {
    ServiceError::SessionUnavailable {
        reason: String::from(error.operator_message()),
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::OperatingMode;
    use lisi_security::ProtectedStore;

    use super::{enter_operator_mode, load_mode, return_to_administrator};
    use crate::error::ServiceError;

    /// Store su un percorso temporaneo, distrutto con il test.
    fn store() -> (ProtectedStore, tempfile::TempDir) {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let store = ProtectedStore::at(directory.path().join("station.protetto"));
        (store, directory)
    }

    #[test]
    fn a_station_without_a_file_is_a_fresh_administrator() {
        // Qualcuno deve poter configurare prima che esista un operatore.
        let (store, _guard) = store();
        assert!(!store.exists());
        assert_eq!(load_mode(&store).ok(), Some(OperatingMode::Administrator));
    }

    #[test]
    fn entering_operator_mode_persists_across_a_reload() {
        // E' la proprieta' che mancava: senza, ogni avvio riparte da
        // amministratore e la modalita' non protegge nulla.
        let (store, _guard) = store();
        let Ok(()) = enter_operator_mode(&store, "parola-di-prova") else {
            panic!("il passaggio a operatore deve riuscire");
        };

        // Un secondo `load_mode`, come dopo un riavvio, legge dal file.
        assert_eq!(load_mode(&store).ok(), Some(OperatingMode::Operator));
    }

    #[test]
    fn the_right_word_returns_to_administrator() {
        let (store, _guard) = store();
        let Ok(()) = enter_operator_mode(&store, "torno-indietro") else {
            panic!("il passaggio deve riuscire");
        };

        let Ok(()) = return_to_administrator(&store, "torno-indietro") else {
            panic!("la parola giusta deve riportare amministratore");
        };
        assert_eq!(load_mode(&store).ok(), Some(OperatingMode::Administrator));
    }

    #[test]
    fn the_wrong_word_does_not_return_to_administrator() {
        let (store, _guard) = store();
        let Ok(()) = enter_operator_mode(&store, "parola-giusta") else {
            panic!("il passaggio deve riuscire");
        };

        assert!(matches!(
            return_to_administrator(&store, "parola-sbagliata"),
            Err(ServiceError::WrongUnlockWord)
        ));
        assert_eq!(
            load_mode(&store).ok(),
            Some(OperatingMode::Operator),
            "un tentativo fallito non cambia la modalita'"
        );
    }

    #[test]
    fn the_unlock_word_is_never_stored_in_clear() {
        // Un operatore sullo stesso profilo puo' decifrare il file: la parola
        // non deve esservi leggibile, altrimenti tornerebbe amministratore in
        // silenzio lasciando intatta la configurazione.
        let (store, _guard) = store();
        let secret = "parola-riconoscibile";
        let Ok(()) = enter_operator_mode(&store, secret) else {
            panic!("il passaggio deve riuscire");
        };

        let Ok(entries) = store.load() else {
            panic!("il file appena scritto deve potersi rileggere");
        };
        for value in entries.values() {
            assert!(
                !value.contains(secret),
                "la parola non deve comparire in chiaro nel file protetto"
            );
        }
    }

    #[test]
    fn two_stations_with_the_same_word_store_different_hashes() {
        // Il salt rende inutile una tabella di impronte precalcolate: la stessa
        // parola su due postazioni non produce la stessa impronta.
        let (first, _g1) = store();
        let (second, _g2) = store();
        let Ok(()) = enter_operator_mode(&first, "identica") else {
            panic!("il primo passaggio deve riuscire");
        };
        let Ok(()) = enter_operator_mode(&second, "identica") else {
            panic!("il secondo passaggio deve riuscire");
        };

        let (Ok(a), Ok(b)) = (first.load(), second.load()) else {
            panic!("i file devono potersi rileggere");
        };
        assert_ne!(a.get("unlock_hash"), b.get("unlock_hash"));
    }

    #[test]
    fn a_word_too_short_is_refused() {
        let (store, _guard) = store();
        assert!(matches!(
            enter_operator_mode(&store, "ab"),
            Err(ServiceError::WeakUnlockWord)
        ));
        // Nulla e' stato scritto: la postazione resta amministratore.
        assert_eq!(load_mode(&store).ok(), Some(OperatingMode::Administrator));
    }

    #[test]
    fn a_word_with_control_characters_is_refused() {
        let (store, _guard) = store();
        assert!(matches!(
            enter_operator_mode(&store, "parola\u{7}campanello"),
            Err(ServiceError::WeakUnlockWord)
        ));
    }

    #[test]
    fn returning_when_already_administrator_is_a_no_operation() {
        let (store, _guard) = store();
        assert!(return_to_administrator(&store, "qualunque").is_ok());
        assert_eq!(load_mode(&store).ok(), Some(OperatingMode::Administrator));
    }
}

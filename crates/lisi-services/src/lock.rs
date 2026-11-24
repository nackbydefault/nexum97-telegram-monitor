//! Blocco della postazione **per account Telegram**.
//!
//! # Che cosa protegge, e che cosa no
//!
//! Su un computer condiviso più persone usano lo stesso profilo Windows e la
//! stessa copia del programma. Chi conduce un monitoraggio deve poter lasciare
//! la postazione senza che il collega che si siede dopo veda **i dati di quel
//! monitoraggio**.
//!
//! Il blocco nasconde i dati dell'account. **Non ferma il monitoraggio**, ed è
//! il punto: fermarlo trasformerebbe una pausa caffè in un buco nell'archivio.
//! Mentre è bloccato, la schermata dice *il fatto* — un monitoraggio è in
//! corso, quanti contenuti sono stati acquisiti — e non *il contenuto*.
//!
//! # Una parola per account, non una per postazione
//!
//! Ogni account Telegram ha la propria, ed è la richiesta dell'ufficio. Due
//! operatori che condividono il computer non condividono la parola, e togliere
//! la protezione a un account non la toglie agli altri: le voci sono indicizzate
//! per UUID dell'account, che è l'identità stabile del dominio.
//!
//! # Il limite dichiarato, come per la modalità operativa
//!
//! Non è un confine di sicurezza contro chi controlla la macchina. Il file è
//! protetto con DPAPI, ma **chiunque usi quel profilo Windows può cancellarlo**,
//! e cancellandolo toglie ogni protezione. È deliberato e documentato: serve
//! che esista una via d'uscita quando la parola si perde, e serve che quella via
//! **lasci traccia** invece di essere silenziosa. Dopo la cancellazione gli
//! account risultano non protetti, e la schermata lo dice: nessuno si ritrova
//! protetto per finta.
//!
//! Contro l'errore e contro lo sguardo di passaggio protegge. Contro la
//! determinazione no, e prometterlo sarebbe peggio che non proteggere.

use std::collections::BTreeMap;
use std::path::PathBuf;

use lisi_security::{ProtectedStore, SecurityError};

use crate::error::{ServiceError, ServiceResult};
use crate::passphrase;

/// Nome del file protetto del blocco.
///
/// Distinto da quello della postazione e da quello delle credenziali: leggere se
/// un account è protetto non deve richiedere che le credenziali siano presenti,
/// né viceversa.
pub const LOCK_FILE: &str = "blocco.protetto";

/// Prefisso della chiave del salt, seguito dall'UUID dell'account.
const SALT_PREFIX: &str = "salt.";
/// Prefisso della chiave dell'impronta, seguito dall'UUID dell'account.
const HASH_PREFIX: &str = "hash.";
/// Chiave dei minuti di inattività dopo i quali si blocca da sé.
const AUTO_LOCK_KEY: &str = "auto_lock_minuti";

/// Minuti di inattività predefiniti prima del blocco automatico.
///
/// Dieci, come chiesto dall'ufficio. Abbastanza da non bloccarsi mentre si legge
/// una schermata, abbastanza poco da coprire una pausa.
pub const DEFAULT_AUTO_LOCK_MINUTES: u32 = 10;

/// Minimo ammesso: sotto un minuto il blocco scatterebbe mentre si lavora.
pub const MIN_AUTO_LOCK_MINUTES: u32 = 1;

/// Massimo ammesso.
///
/// Oltre le otto ore la protezione diventa nominale — copre una giornata intera
/// senza mai scattare — e un'impostazione che non fa mai nulla è peggio di
/// nessuna impostazione, perché fa credere di essere protetti.
pub const MAX_AUTO_LOCK_MINUTES: u32 = 480;

/// Percorso predefinito del file del blocco.
///
/// Accanto agli altri file protetti, sotto la stessa cartella dati del profilo.
///
/// # Errori
///
/// Restituisce un errore se la cartella dati locale non è determinabile.
pub fn default_lock_path() -> ServiceResult<PathBuf> {
    Ok(crate::data_directory::application_directory()?.join(LOCK_FILE))
}

/// Il blocco, come lo vede l'interfaccia.
///
/// Esiste perché `ProtectedStore` è un tipo di `lisi-security`, e l'interfaccia
/// **non deve dipendere da quel crate** (ADR-0010, verificato da un test).
/// Passarle il file protetto significherebbe farle attraversare quel confine
/// per comodità; possederlo qui costa una struttura e lo lascia intatto.
#[derive(Debug)]
pub struct LockService {
    store: ProtectedStore,
}

impl LockService {
    /// Crea il servizio sul file protetto predefinito.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la cartella dati locale non è determinabile.
    pub fn open_default() -> ServiceResult<Self> {
        Ok(Self {
            store: ProtectedStore::at(default_lock_path()?),
        })
    }

    /// Crea il servizio sul file indicato.
    ///
    /// Prende un **percorso** e non un `ProtectedStore` di proposito: così anche
    /// i test dell'interfaccia possono costruirlo senza nominare un tipo di
    /// `lisi-security`, che è precisamente il confine che questa struttura
    /// esiste per proteggere.
    #[must_use]
    pub fn at(path: PathBuf) -> Self {
        Self {
            store: ProtectedStore::at(path),
        }
    }

    /// Fissa o sostituisce la parola di sblocco di un account.
    ///
    /// # Errori
    ///
    /// Come [`protect_account`].
    pub fn protect(&self, account_uuid: &str, passphrase_text: &str) -> ServiceResult<()> {
        protect_account(&self.store, account_uuid, passphrase_text)
    }

    /// Toglie la protezione di un account.
    ///
    /// # Errori
    ///
    /// Come [`remove_protection`].
    pub fn unprotect(&self, account_uuid: &str) -> ServiceResult<()> {
        remove_protection(&self.store, account_uuid)
    }

    /// Se l'account ha una parola di sblocco fissata.
    ///
    /// # Errori
    ///
    /// Come [`is_protected`].
    pub fn is_protected(&self, account_uuid: &str) -> ServiceResult<bool> {
        is_protected(&self.store, account_uuid)
    }

    /// Verifica un tentativo di sblocco.
    ///
    /// # Errori
    ///
    /// Come [`unlock`].
    pub fn unlock(&self, account_uuid: &str, attempt: &str) -> ServiceResult<()> {
        unlock(&self.store, account_uuid, attempt)
    }

    /// Minuti di inattività prima del blocco automatico.
    ///
    /// # Errori
    ///
    /// Come [`auto_lock_minutes`].
    pub fn auto_lock_minutes(&self) -> ServiceResult<u32> {
        auto_lock_minutes(&self.store)
    }

    /// Fissa i minuti di inattività, ricondotti entro i limiti.
    ///
    /// # Errori
    ///
    /// Come [`set_auto_lock_minutes`].
    pub fn set_auto_lock_minutes(&self, minutes: u32) -> ServiceResult<u32> {
        set_auto_lock_minutes(&self.store, minutes)
    }
}

/// Fissa o sostituisce la parola di sblocco di un account.
///
/// # Errori
///
/// Restituisce [`ServiceError::WeakUnlockWord`] se la parola non è utilizzabile,
/// e un errore se la scrittura protetta non riesce.
pub fn protect_account(
    store: &ProtectedStore,
    account_uuid: &str,
    passphrase_text: &str,
) -> ServiceResult<()> {
    let sealed = passphrase::seal(passphrase_text)?;

    // Si rilegge e si riscrive **tutto**: il file porta le voci di ogni account,
    // e salvare solo le proprie cancellerebbe quelle degli altri. E' l'errore
    // che questo commento esiste per non far ripetere.
    let mut entries = load(store)?;
    entries.insert(format!("{SALT_PREFIX}{account_uuid}"), sealed.salt_hex);
    entries.insert(format!("{HASH_PREFIX}{account_uuid}"), sealed.hash);

    store.save(&entries).map_err(map_security_error)
}

/// Toglie la protezione di un account, lasciando intatte quelle degli altri.
///
/// È l'azione dell'amministratore quando una parola si perde. Non richiede di
/// conoscerla: se la richiedesse, una parola dimenticata renderebbe l'account
/// inutilizzabile per sempre.
///
/// # Errori
///
/// Restituisce un errore se la lettura o la scrittura protetta non riescono.
pub fn remove_protection(store: &ProtectedStore, account_uuid: &str) -> ServiceResult<()> {
    let mut entries = load(store)?;
    entries.remove(&format!("{SALT_PREFIX}{account_uuid}"));
    entries.remove(&format!("{HASH_PREFIX}{account_uuid}"));
    store.save(&entries).map_err(map_security_error)
}

/// Se l'account ha una parola di sblocco fissata.
///
/// # Errori
///
/// Restituisce un errore se la lettura protetta non riesce.
pub fn is_protected(store: &ProtectedStore, account_uuid: &str) -> ServiceResult<bool> {
    let entries = load(store)?;
    Ok(sealed_of(&entries, account_uuid).is_some())
}

/// Verifica un tentativo di sblocco.
///
/// # Errori
///
/// Restituisce [`ServiceError::WrongUnlockWord`] se la parola non corrisponde
/// **o se l'account non è protetto**: chi prova non deve poter distinguere i due
/// casi, altrimenti avrebbe scoperto quali account hanno una parola e quali no.
pub fn unlock(store: &ProtectedStore, account_uuid: &str, attempt: &str) -> ServiceResult<()> {
    let entries = load(store)?;
    let Some((salt_hex, hash)) = sealed_of(&entries, account_uuid) else {
        return Err(ServiceError::WrongUnlockWord);
    };

    if passphrase::matches(salt_hex, hash, attempt) {
        Ok(())
    } else {
        Err(ServiceError::WrongUnlockWord)
    }
}

/// Minuti di inattività dopo i quali la postazione si blocca da sé.
///
/// Un valore assente o fuori scala non è un errore: si restituisce quello
/// predefinito. Un file corrotto non deve poter **allungare** l'attesa fino a
/// renderla inefficace, che è il modo in cui una protezione si spegne senza che
/// nessuno lo decida.
///
/// # Errori
///
/// Restituisce un errore se la lettura protetta non riesce.
pub fn auto_lock_minutes(store: &ProtectedStore) -> ServiceResult<u32> {
    let entries = load(store)?;
    let Some(raw) = entries.get(AUTO_LOCK_KEY) else {
        return Ok(DEFAULT_AUTO_LOCK_MINUTES);
    };
    let parsed = raw.parse::<u32>().unwrap_or(DEFAULT_AUTO_LOCK_MINUTES);
    Ok(clamp_minutes(parsed))
}

/// Fissa i minuti di inattività, ricondotti entro i limiti.
///
/// Restituisce il valore **effettivamente** conservato: se quello chiesto era
/// fuori scala, chi chiama deve mostrare quello che vale davvero.
///
/// # Errori
///
/// Restituisce un errore se la scrittura protetta non riesce.
pub fn set_auto_lock_minutes(store: &ProtectedStore, minutes: u32) -> ServiceResult<u32> {
    let value = clamp_minutes(minutes);
    let mut entries = load(store)?;
    entries.insert(String::from(AUTO_LOCK_KEY), value.to_string());
    store.save(&entries).map_err(map_security_error)?;
    Ok(value)
}

/// Riconduce i minuti entro i limiti ammessi.
const fn clamp_minutes(minutes: u32) -> u32 {
    if minutes < MIN_AUTO_LOCK_MINUTES {
        MIN_AUTO_LOCK_MINUTES
    } else if minutes > MAX_AUTO_LOCK_MINUTES {
        MAX_AUTO_LOCK_MINUTES
    } else {
        minutes
    }
}

/// Salt e impronta di un account, se ci sono entrambi.
///
/// Uno solo dei due non basta: un file con il salt e senza impronta non è un
/// account protetto a metà, è un file da cui non si può verificare nulla, e
/// trattarlo come protetto renderebbe l'account inaccessibile senza rimedio.
fn sealed_of<'a>(
    entries: &'a BTreeMap<String, String>,
    account_uuid: &str,
) -> Option<(&'a str, &'a str)> {
    let salt = entries.get(&format!("{SALT_PREFIX}{account_uuid}"))?;
    let hash = entries.get(&format!("{HASH_PREFIX}{account_uuid}"))?;
    Some((salt.as_str(), hash.as_str()))
}

/// Legge il file, trattando l'assenza come «nessuna protezione».
///
/// Una postazione che non ha mai fissato alcuna parola non ha il file, e non
/// averlo non è un guasto. Un file **presente e illeggibile** invece lo è, e
/// risale al chiamante: non si finge che non ci sia nulla, perché sarebbe una
/// protezione tolta da un errore di lettura.
fn load(store: &ProtectedStore) -> ServiceResult<BTreeMap<String, String>> {
    if !store.exists() {
        return Ok(BTreeMap::new());
    }
    store.load().map_err(map_security_error)
}

/// Traduce un errore della protezione locale.
fn map_security_error(error: SecurityError) -> ServiceError {
    ServiceError::SessionUnavailable {
        reason: String::from(error.operator_message()),
    }
}

#[cfg(test)]
mod tests {
    use lisi_security::ProtectedStore;

    use super::{
        DEFAULT_AUTO_LOCK_MINUTES, MAX_AUTO_LOCK_MINUTES, MIN_AUTO_LOCK_MINUTES, auto_lock_minutes,
        is_protected, protect_account, remove_protection, set_auto_lock_minutes, unlock,
    };

    const FIRST: &str = "11111111111111111111111111111111";
    const SECOND: &str = "22222222222222222222222222222222";

    fn store() -> (ProtectedStore, tempfile::TempDir) {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let path = directory.path().join("blocco.protetto");
        (ProtectedStore::at(path), directory)
    }

    #[test]
    fn an_account_without_a_word_is_not_protected() {
        let (store, _guard) = store();
        let Ok(protected) = is_protected(&store, FIRST) else {
            panic!("lo stato deve potersi leggere anche senza file");
        };
        assert!(!protected);
    }

    #[test]
    fn the_right_word_unlocks_and_the_wrong_one_does_not() {
        let (store, _guard) = store();
        let Ok(()) = protect_account(&store, FIRST, "parola-del-primo") else {
            panic!("la protezione deve potersi fissare");
        };

        assert!(unlock(&store, FIRST, "parola-del-primo").is_ok());
        assert!(unlock(&store, FIRST, "parola-sbagliata").is_err());
    }

    #[test]
    fn each_account_has_its_own_word() {
        // E' la richiesta dell'ufficio: due operatori sullo stesso computer non
        // condividono la parola.
        let (store, _guard) = store();
        let (Ok(()), Ok(())) = (
            protect_account(&store, FIRST, "parola-del-primo"),
            protect_account(&store, SECOND, "parola-del-secondo"),
        ) else {
            panic!("entrambe le protezioni devono potersi fissare");
        };

        assert!(unlock(&store, FIRST, "parola-del-primo").is_ok());
        assert!(unlock(&store, SECOND, "parola-del-secondo").is_ok());
        // La parola dell'uno non apre l'altro.
        assert!(unlock(&store, FIRST, "parola-del-secondo").is_err());
        assert!(unlock(&store, SECOND, "parola-del-primo").is_err());
    }

    #[test]
    fn protecting_one_account_does_not_disturb_another() {
        // Il file e' unico e porta le voci di tutti: salvare solo le proprie
        // cancellerebbe quelle degli altri. E' l'errore che questo test blocca.
        let (store, _guard) = store();
        let Ok(()) = protect_account(&store, FIRST, "parola-del-primo") else {
            panic!("la prima protezione deve potersi fissare");
        };
        let Ok(()) = protect_account(&store, SECOND, "parola-del-secondo") else {
            panic!("la seconda protezione deve potersi fissare");
        };

        assert!(
            unlock(&store, FIRST, "parola-del-primo").is_ok(),
            "il primo account deve restare sbloccabile dopo il secondo"
        );
    }

    #[test]
    fn removing_one_protection_leaves_the_others_standing() {
        let (store, _guard) = store();
        let (Ok(()), Ok(())) = (
            protect_account(&store, FIRST, "parola-del-primo"),
            protect_account(&store, SECOND, "parola-del-secondo"),
        ) else {
            panic!("entrambe le protezioni devono potersi fissare");
        };

        let Ok(()) = remove_protection(&store, FIRST) else {
            panic!("la rimozione deve riuscire");
        };

        let (Ok(first), Ok(second)) = (is_protected(&store, FIRST), is_protected(&store, SECOND))
        else {
            panic!("lo stato deve potersi leggere");
        };
        assert!(
            !first,
            "l'account a cui e' stata tolta non e' piu' protetto"
        );
        assert!(second, "l'altro lo e' ancora");
    }

    #[test]
    fn an_unprotected_account_answers_wrong_word_rather_than_admitting_it_has_none() {
        // Chi prova non deve poter distinguere «parola sbagliata» da «questo
        // account non ha parola»: la seconda risposta direbbe quali account
        // aprire senza fatica.
        let (store, _guard) = store();
        let Ok(()) = protect_account(&store, FIRST, "parola-del-primo") else {
            panic!("la protezione deve potersi fissare");
        };

        let wrong_on_protected = unlock(&store, FIRST, "sbagliata");
        let any_on_unprotected = unlock(&store, SECOND, "sbagliata");

        let (Err(first), Err(second)) = (wrong_on_protected, any_on_unprotected) else {
            panic!("entrambi i tentativi devono fallire");
        };
        assert_eq!(
            first.operator_message(),
            second.operator_message(),
            "i due casi non devono distinguersi dal messaggio"
        );
    }

    #[test]
    fn the_word_is_never_stored_in_clear() {
        let (store, guard) = store();
        let Ok(()) = protect_account(&store, FIRST, "parola-da-non-trovare") else {
            panic!("la protezione deve potersi fissare");
        };

        let Ok(raw) = std::fs::read(guard.path().join("blocco.protetto")) else {
            panic!("il file deve esistere");
        };
        let text = String::from_utf8_lossy(&raw);
        assert!(
            !text.contains("parola-da-non-trovare"),
            "la parola non deve comparire nel file"
        );
    }

    #[test]
    fn a_fresh_station_waits_the_agreed_ten_minutes() {
        let (store, _guard) = store();
        let Ok(minutes) = auto_lock_minutes(&store) else {
            panic!("i minuti devono potersi leggere");
        };
        assert_eq!(minutes, DEFAULT_AUTO_LOCK_MINUTES);
        assert_eq!(DEFAULT_AUTO_LOCK_MINUTES, 10);
    }

    #[test]
    fn the_waiting_time_is_configurable_and_kept_within_bounds() {
        let (store, _guard) = store();

        let Ok(saved) = set_auto_lock_minutes(&store, 25) else {
            panic!("il valore deve potersi fissare");
        };
        assert_eq!(saved, 25);
        let Ok(reloaded) = auto_lock_minutes(&store) else {
            panic!("il valore deve potersi rileggere");
        };
        assert_eq!(reloaded, 25);

        // Zero bloccherebbe la postazione mentre ci si lavora; un valore enorme
        // renderebbe la protezione nominale. Entrambi si riconducono.
        let (Ok(too_small), Ok(too_large)) = (
            set_auto_lock_minutes(&store, 0),
            set_auto_lock_minutes(&store, 100_000),
        ) else {
            panic!("i valori fuori scala non devono far fallire");
        };
        assert_eq!(too_small, MIN_AUTO_LOCK_MINUTES);
        assert_eq!(too_large, MAX_AUTO_LOCK_MINUTES);
    }

    #[test]
    fn setting_the_waiting_time_does_not_erase_the_protections() {
        let (store, _guard) = store();
        let Ok(()) = protect_account(&store, FIRST, "parola-del-primo") else {
            panic!("la protezione deve potersi fissare");
        };
        let Ok(_) = set_auto_lock_minutes(&store, 30) else {
            panic!("il valore deve potersi fissare");
        };

        assert!(
            unlock(&store, FIRST, "parola-del-primo").is_ok(),
            "scrivere i minuti non deve toccare le parole"
        );
    }

    #[test]
    fn deleting_the_file_removes_every_protection_and_says_so() {
        // E' la via d'uscita documentata quando una parola si perde, ed e'
        // deliberatamente **visibile**: dopo, gli account risultano non
        // protetti, e nessuno resta protetto per finta.
        let (store, guard) = store();
        let Ok(()) = protect_account(&store, FIRST, "parola-del-primo") else {
            panic!("la protezione deve potersi fissare");
        };

        let Ok(()) = std::fs::remove_file(guard.path().join("blocco.protetto")) else {
            panic!("il file deve potersi cancellare");
        };

        let Ok(protected) = is_protected(&store, FIRST) else {
            panic!("lo stato deve potersi leggere anche senza file");
        };
        assert!(!protected, "senza file nessun account risulta protetto");
    }

    #[test]
    fn a_word_too_weak_is_refused_when_setting_it() {
        let (store, _guard) = store();
        assert!(protect_account(&store, FIRST, "ab").is_err());
        assert!(protect_account(&store, FIRST, "   ").is_err());
    }
}

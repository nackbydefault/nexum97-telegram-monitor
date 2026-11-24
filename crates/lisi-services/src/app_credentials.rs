//! Le credenziali dell'applicazione arrivano con la distribuzione
//! (APP-CREDENTIALS-01, ADR-0204).
//!
//! API ID e API hash sono di NEXUM/97, non di chi lo usa: li fornisce il
//! committente una volta, viaggiano nel pacchetto privato o li porta
//! l'amministratore, e nessuna schermata li mostra o li chiede.
//!
//! Il **file di distribuzione** sta accanto al programma soltanto fino al primo
//! avvio: [`import_distribution_file`] lo valida, ne protegge il contenuto con
//! DPAPI nella cartella dei dati e lo cancella dopo averlo sovrascritto. Da lì
//! in avanti le credenziali si leggono con [`load_account_credentials`], che le
//! cerca nell'ordine di ADR-0204 decisione 3.
//!
//! Nessuna funzione di questo modulo restituisce i valori a chi non li passa a
//! TDLib, e nessun errore li contiene.

use std::io::Write;
use std::path::{Path, PathBuf};

use lisi_core::ApiCredentialProfileId;
use lisi_security::ProtectedStore;

use crate::config::{
    TelegramCredentials, credentials_from_text, environment_credentials, load_profile_credentials,
    profile_store_path, save_profile_credentials,
};
use crate::error::{ServiceError, ServiceResult};

/// Nome del file di distribuzione, accanto all'eseguibile.
///
/// Lo scrivono il pacchetto privato e `Provisioning.ps1`; il programma lo
/// consuma al primo avvio.
pub const DISTRIBUTION_FILE: &str = "nexum97-distribuzione.cfg";

/// Nome del file protetto con le credenziali dell'applicazione, nella
/// cartella dei dati.
pub const APPLICATION_STORE_FILE: &str = "applicazione-telegram.protetto";

/// Chiave dell'identificativo nel file di distribuzione.
const ID_KEY: &str = "api_id";
/// Chiave dell'hash nel file di distribuzione.
const HASH_KEY: &str = "api_hash";

/// Che cosa è successo al file di distribuzione.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportOutcome {
    /// Nessun file: niente da fare.
    Absent,
    /// Importato e cancellato.
    Imported,
    /// Importato, ma il file non si è potuto cancellare.
    ImportedNotRemoved,
    /// Il file c'è ma non contiene credenziali valide: non si importa e si
    /// lascia dov'è, perché l'amministratore lo possa sostituire.
    Invalid,
}

/// Percorso del file protetto dell'applicazione nella cartella `base_dir`.
#[must_use]
pub fn application_store_path(base_dir: &Path) -> PathBuf {
    base_dir.join(APPLICATION_STORE_FILE)
}

/// Percorso del file di distribuzione accanto all'eseguibile `program`.
#[must_use]
pub fn distribution_file_beside(program: &Path) -> Option<PathBuf> {
    program
        .parent()
        .map(|folder| folder.join(DISTRIBUTION_FILE))
}

/// Legge le credenziali dal **testo** di un file di distribuzione.
///
/// Righe `chiave=valore`; le righe vuote e quelle che cominciano con `#` non
/// contano. Il valore grezzo non compare in alcun errore.
///
/// # Errori
///
/// Restituisce un errore se manca una delle due chiavi, se una è ripetuta o se
/// i valori non sono credenziali valide.
pub fn parse_distribution(text: &str) -> ServiceResult<TelegramCredentials> {
    let mut id: Option<&str> = None;
    let mut hash: Option<&str> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(not_valid());
        };
        let slot = match key.trim() {
            ID_KEY => &mut id,
            HASH_KEY => &mut hash,
            _ => return Err(not_valid()),
        };
        if slot.replace(value.trim()).is_some() {
            return Err(not_valid());
        }
    }
    let (Some(id), Some(hash)) = (id, hash) else {
        return Err(not_valid());
    };
    credentials_from_text(id, hash).map_err(|_| not_valid())
}

/// Importa il file di distribuzione `file` nella cartella `base_dir`.
///
/// Se il file c'è e contiene credenziali valide, le protegge con DPAPI in
/// [`application_store_path`], poi sovrascrive il file con zeri e lo cancella.
///
/// # Errori
///
/// Restituisce un errore se il file c'è ma non si legge, o se la protezione o
/// la scrittura non riescono. Un file con credenziali non valide non è un
/// errore: è [`ImportOutcome::Invalid`].
pub fn import_distribution_file(file: &Path, base_dir: &Path) -> ServiceResult<ImportOutcome> {
    if !file.is_file() {
        return Ok(ImportOutcome::Absent);
    }
    let mut bytes = std::fs::read(file).map_err(|_| ServiceError::SessionUnavailable {
        reason: String::from("il file della configurazione non si legge"),
    })?;
    let parsed = std::str::from_utf8(&bytes)
        .map_err(|_| not_valid())
        .and_then(parse_distribution);
    let length = bytes.len();
    bytes.fill(0);
    let Ok(credentials) = parsed else {
        return Ok(ImportOutcome::Invalid);
    };
    let store = ProtectedStore::at(application_store_path(base_dir));
    save_profile_credentials(&store, &credentials)?;
    Ok(if wipe(file, length).is_ok() {
        ImportOutcome::Imported
    } else {
        ImportOutcome::ImportedNotRemoved
    })
}

/// Sovrascrive il file con zeri e lo cancella.
fn wipe(file: &Path, length: usize) -> std::io::Result<()> {
    {
        let mut handle = std::fs::OpenOptions::new().write(true).open(file)?;
        handle.write_all(&vec![0_u8; length])?;
        handle.sync_all()?;
    }
    std::fs::remove_file(file)
}

/// Se questa installazione ha le credenziali dell'applicazione: nella
/// sessione (sviluppo) o protette nella cartella `base_dir`.
#[must_use]
pub fn is_configured(base_dir: &Path) -> bool {
    if matches!(environment_credentials(), Ok(Some(_))) {
        return true;
    }
    let store = ProtectedStore::at(application_store_path(base_dir));
    store.exists() && load_profile_credentials(&store).is_ok()
}

/// Le credenziali con cui l'account del profilo `profile_id` si presenta a
/// Telegram (ADR-0204 decisione 3).
///
/// Nell'ordine: le variabili d'ambiente della sessione, la configurazione
/// dell'applicazione, il file del profilo scritto prima di questa decisione.
///
/// # Errori
///
/// Restituisce [`ServiceError::ApplicationNotConfigured`] se nessuna delle tre
/// c'è, e un errore se una c'è ma non si legge.
pub fn load_account_credentials(
    base_dir: &Path,
    profile_id: ApiCredentialProfileId,
) -> ServiceResult<TelegramCredentials> {
    if let Some(credentials) = environment_credentials()? {
        return Ok(credentials);
    }
    for path in [
        application_store_path(base_dir),
        profile_store_path(base_dir, profile_id),
    ] {
        let store = ProtectedStore::at(path);
        if store.exists() {
            let (credentials, _origin) = load_profile_credentials(&store)?;
            return Ok(credentials);
        }
    }
    Err(ServiceError::ApplicationNotConfigured)
}

/// L'errore di un file di distribuzione che non contiene credenziali valide.
fn not_valid() -> ServiceError {
    ServiceError::ApplicationNotConfigured
}

#[cfg(test)]
mod tests {
    use lisi_core::ApiCredentialProfileId;

    use super::{
        DISTRIBUTION_FILE, ImportOutcome, application_store_path, distribution_file_beside,
        import_distribution_file, load_account_credentials, parse_distribution,
    };
    use crate::error::ServiceError;

    /// Valori sintetici: nessuna credenziale vera entra nelle prove.
    const ID: &str = "1234567";
    const HASH: &str = "0123456789abcdef0123456789abcdef";

    fn testo() -> String {
        format!("# prova\napi_id={ID}\n\napi_hash = {HASH}\n")
    }

    #[test]
    fn un_file_ben_fatto_da_le_credenziali() {
        let Ok(credentials) = parse_distribution(&testo()) else {
            panic!("il file sintetico deve leggersi");
        };
        assert_eq!(credentials.api_id.expose_secret(), 1_234_567);
        assert_eq!(credentials.api_hash.expose_secret(), HASH);
    }

    #[test]
    fn un_file_incompleto_doppio_o_strano_non_vale_e_non_ripete_i_valori() {
        for testo in [
            format!("api_id={ID}\n"),
            format!("api_hash={HASH}\n"),
            format!("api_id={ID}\napi_id={ID}\napi_hash={HASH}\n"),
            format!("api_id={ID}\napi_hash={HASH}\naltro=1\n"),
            format!("api_id={ID}\n{HASH}\n"),
            format!("api_id=non-un-numero\napi_hash={HASH}\n"),
            format!("api_id={ID}\napi_hash=corto\n"),
        ] {
            let Err(error) = parse_distribution(&testo) else {
                panic!("doveva essere rifiutato: {}", testo.lines().count());
            };
            assert!(matches!(error, ServiceError::ApplicationNotConfigured));
            let messaggio = format!("{error} {error:?} {}", error.operator_message());
            assert!(
                !messaggio.contains(HASH) && !messaggio.contains(ID),
                "{messaggio}"
            );
        }
    }

    #[test]
    fn il_file_si_cerca_accanto_al_programma() {
        let Some(percorso) = distribution_file_beside(std::path::Path::new(r"C:\p\nexum.exe"))
        else {
            panic!("la cartella del programma c'e'");
        };
        assert!(percorso.ends_with(DISTRIBUTION_FILE));
        assert!(percorso.starts_with(r"C:\p"));
    }

    #[test]
    fn senza_file_non_si_importa_nulla() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        let file = cartella.path().join(DISTRIBUTION_FILE);
        assert_eq!(
            import_distribution_file(&file, cartella.path()).ok(),
            Some(ImportOutcome::Absent)
        );
        assert!(!application_store_path(cartella.path()).exists());
    }

    #[test]
    fn un_file_non_valido_resta_e_non_si_importa() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        let file = cartella.path().join(DISTRIBUTION_FILE);
        assert!(std::fs::write(&file, "api_id=1\n").is_ok());
        assert_eq!(
            import_distribution_file(&file, cartella.path()).ok(),
            Some(ImportOutcome::Invalid)
        );
        assert!(file.exists(), "l'amministratore lo deve poter sostituire");
        assert!(!application_store_path(cartella.path()).exists());
    }

    #[test]
    fn senza_configurazione_l_errore_dice_di_rivolgersi_all_amministratore() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        // Se l'ambiente della prova definisse le variabili dello sviluppo,
        // varrebbero quelle: è lo stesso limite di `config`.
        if matches!(crate::config::environment_credentials(), Ok(Some(_))) {
            return;
        }
        let Err(error) = load_account_credentials(cartella.path(), ApiCredentialProfileId::new(7))
        else {
            panic!("senza configurazione non ci sono credenziali");
        };
        assert!(matches!(error, ServiceError::ApplicationNotConfigured));
        let messaggio = error.operator_message();
        assert!(messaggio.contains("amministratore"), "{messaggio}");
        for parola in ["API", "hash", "my.telegram", "protetto", ".cfg"] {
            assert!(!messaggio.contains(parola), "{messaggio}");
        }
        assert!(!super::is_configured(cartella.path()));
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use lisi_core::ApiCredentialProfileId;

    use super::{
        DISTRIBUTION_FILE, ImportOutcome, application_store_path, import_distribution_file,
        is_configured, load_account_credentials,
    };
    use crate::config::{credentials_from_text, profile_store_path, save_profile_credentials};

    const HASH: &str = "0123456789abcdef0123456789abcdef";
    const ALTRO: &str = "fedcba9876543210fedcba9876543210";

    #[test]
    fn il_file_si_importa_si_protegge_e_si_cancella() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        let file = cartella.path().join(DISTRIBUTION_FILE);
        assert!(std::fs::write(&file, format!("api_id=1234567\napi_hash={HASH}\n")).is_ok());

        assert_eq!(
            import_distribution_file(&file, cartella.path()).ok(),
            Some(ImportOutcome::Imported)
        );
        assert!(!file.exists(), "il file di distribuzione si consuma");
        let Ok(protetto) = std::fs::read(application_store_path(cartella.path())) else {
            panic!("il file protetto c'e'");
        };
        assert!(
            !protetto.windows(HASH.len()).any(|w| w == HASH.as_bytes()),
            "il file protetto non contiene l'hash in chiaro"
        );
        assert!(is_configured(cartella.path()));
        if matches!(crate::config::environment_credentials(), Ok(Some(_))) {
            return;
        }
        let Ok(credentials) =
            load_account_credentials(cartella.path(), ApiCredentialProfileId::new(1))
        else {
            panic!("le credenziali importate si leggono");
        };
        assert_eq!(credentials.api_hash.expose_secret(), HASH);
    }

    #[test]
    fn l_applicazione_vince_sul_vecchio_profilo_che_resta_di_riserva() {
        if matches!(crate::config::environment_credentials(), Ok(Some(_))) {
            return;
        }
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        let profilo = ApiCredentialProfileId::new(3);
        let Ok(vecchie) = credentials_from_text("7654321", ALTRO) else {
            panic!("valori sintetici");
        };
        let store = lisi_security::ProtectedStore::at(profile_store_path(cartella.path(), profilo));
        assert!(save_profile_credentials(&store, &vecchie).is_ok());

        // Prima della configurazione dell'applicazione vale il vecchio profilo.
        let Ok(lette) = load_account_credentials(cartella.path(), profilo) else {
            panic!("il vecchio profilo resta di riserva");
        };
        assert_eq!(lette.api_hash.expose_secret(), ALTRO);
        assert!(!is_configured(cartella.path()));

        let file = cartella.path().join(DISTRIBUTION_FILE);
        assert!(std::fs::write(&file, format!("api_id=1234567\napi_hash={HASH}\n")).is_ok());
        assert!(import_distribution_file(&file, cartella.path()).is_ok());
        let Ok(lette) = load_account_credentials(cartella.path(), profilo) else {
            panic!("la configurazione dell'applicazione si legge");
        };
        assert_eq!(lette.api_hash.expose_secret(), HASH, "tutti con le stesse");
    }
}

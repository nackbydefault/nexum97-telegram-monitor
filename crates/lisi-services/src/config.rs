//! Caricamento dei parametri dell'applicazione Telegram.
//!
//! API ID e API hash **non compaiono nel codice, nei manifest, nei test, nei
//! log né nel repository**. Sono caricati, nell'ordine:
//!
//! 1. dalle variabili d'ambiente, se presenti;
//! 2. altrimenti dall'archivio protetto con DPAPI.
//!
//! L'ordine è deliberato: le variabili d'ambiente servono alla prova operativa
//! e non lasciano traccia su disco; l'archivio protetto serve all'uso ordinario.
//!
//! Vedere `docs/adr/ADR-0009-SECRETS-AND-SESSION.md`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use lisi_core::ApiCredentialProfileId;
use lisi_security::{ProtectedStore, SecurityError};
use lisi_telegram::{ApiHash, ApiId, TelegramError};

use crate::error::{ServiceError, ServiceResult};

/// Variabile d'ambiente con l'identificativo dell'applicazione.
///
/// Rimanda a `lisi-core`, dove gli identificatori persistenti stanno insieme
/// e sono protetti da un test: il nome pubblico del prodotto è cambiato, questi
/// no, e la distinzione va tenuta in un punto solo.
pub const API_ID_VARIABLE: &str = lisi_core::branding::API_ID_VARIABLE;
/// Variabile d'ambiente con l'hash dell'applicazione.
pub const API_HASH_VARIABLE: &str = lisi_core::branding::API_HASH_VARIABLE;

/// Chiave dell'identificativo nell'archivio protetto.
pub const API_ID_KEY: &str = "api_id";
/// Chiave dell'hash nell'archivio protetto.
pub const API_HASH_KEY: &str = "api_hash";

/// Nome del file protetto del profilo predefinito (compatibilità).
pub const CONFIGURATION_FILE: &str = "telegram.protetto";

/// Prefisso del nome di file protetto di un **profilo** di credenziali.
///
/// Il nome include l'**id numerico** del profilo, che non è un segreto: né
/// l'API hash né altri dati riservati compaiono nel nome del file (ADR-0019).
pub const PROFILE_FILE_PREFIX: &str = "telegram-profilo-";

/// Suffisso del nome di file protetto di un profilo di credenziali.
pub const PROFILE_FILE_SUFFIX: &str = ".protetto";

/// Parametri dell'applicazione presso Telegram.
///
/// `Debug` è derivabile perché entrambi i campi redigono da sé il proprio
/// valore: la struttura non può stamparli nemmeno per errore.
#[derive(Debug)]
pub struct TelegramCredentials {
    /// Identificativo dell'applicazione.
    pub api_id: ApiId,
    /// Hash dell'applicazione.
    pub api_hash: ApiHash,
}

/// Da dove provengono i parametri caricati.
///
/// Serve alla diagnostica e alla guida: un operatore che non capisce perché
/// l'applicazione usi credenziali diverse da quelle configurate deve poter
/// scoprire che una variabile d'ambiente le sta scavalcando.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialsOrigin {
    /// Variabili d'ambiente del processo.
    Environment,
    /// Archivio protetto con DPAPI.
    ProtectedStore,
}

impl CredentialsOrigin {
    /// Descrizione mostrabile all'operatore.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Environment => {
                "variabili d'ambiente della sessione corrente, non conservate su disco"
            }
            Self::ProtectedStore => "configurazione locale protetta dal profilo Windows",
        }
    }
}

/// Percorso predefinito dell'archivio protetto.
///
/// Sotto `%LOCALAPPDATA%`, che è già ristretto all'utente: è il posto dove i
/// dati di un'applicazione appartengono a un solo profilo.
///
/// Il nome della cartella viene da `lisi-core` e **non** segue il nome pubblico
/// del prodotto: è un identificatore persistente, e rinominarlo renderebbe
/// irraggiungibile la configurazione protetta con DPAPI già scritta sui profili
/// esistenti. L'operatore vedrebbe un'applicazione che si comporta come al
/// primo avvio, senza alcun messaggio che lo spieghi.
///
/// # Errori
///
/// Restituisce un errore se la cartella dati locale non è determinabile.
pub fn default_store_path() -> ServiceResult<PathBuf> {
    Ok(crate::data_directory::application_directory()?.join(CONFIGURATION_FILE))
}

/// Percorso del file protetto di un **profilo** di credenziali.
///
/// Il chiamante fornisce la cartella base (per esempio la cartella dati
/// dell'applicazione) e l'id del profilo; il nome del file deriva dall'id
/// numerico, **mai** dai segreti del profilo. Due profili distinti hanno file
/// distinti e indipendenti.
#[must_use]
pub fn profile_store_path(base_dir: &Path, profile_id: ApiCredentialProfileId) -> PathBuf {
    let id = profile_id.get();
    base_dir.join(format!("{PROFILE_FILE_PREFIX}{id}{PROFILE_FILE_SUFFIX}"))
}

/// Carica i parametri dal profilo predefinito, preferendo le variabili
/// d'ambiente.
///
/// Conservata per compatibilità: delega a [`load_profile_credentials`], che
/// ora è l'implementazione. Il chiamante che gestisce più profili costruisce lo
/// `store` con [`profile_store_path`] e usa direttamente quella funzione.
///
/// # Errori
///
/// Restituisce [`ServiceError::SessionUnavailable`] se nessuna delle due
/// origini è disponibile, e un errore di dominio se i valori trovati non sono
/// validi.
pub fn load_credentials(
    store: &ProtectedStore,
) -> ServiceResult<(TelegramCredentials, CredentialsOrigin)> {
    load_profile_credentials(store)
}

/// Salva i parametri del profilo predefinito nell'archivio protetto.
///
/// Conservata per compatibilità: delega a [`save_profile_credentials`].
///
/// # Errori
///
/// Restituisce un errore se la protezione o la scrittura non riescono.
pub fn save_credentials(
    store: &ProtectedStore,
    credentials: &TelegramCredentials,
) -> ServiceResult<()> {
    save_profile_credentials(store, credentials)
}

/// Carica le credenziali di **un profilo** dal suo archivio protetto.
///
/// L'archivio è quello dell'id del profilo, costruito dal chiamante con
/// [`profile_store_path`]. Le variabili d'ambiente, se presenti, hanno la
/// precedenza come per il profilo predefinito: sono l'unica scappatoia per la
/// prova operativa e valgono, quando impostate, per qualunque profilo. Non si
/// accettano segreti dalla riga di comando.
///
/// # Errori
///
/// Restituisce [`ServiceError::SessionUnavailable`] se né le variabili
/// d'ambiente né l'archivio del profilo sono disponibili, e un errore di
/// dominio se i valori trovati non sono validi.
pub fn load_profile_credentials(
    store: &ProtectedStore,
) -> ServiceResult<(TelegramCredentials, CredentialsOrigin)> {
    if let Some(credentials) = from_environment()? {
        return Ok((credentials, CredentialsOrigin::Environment));
    }

    let entries = store.load().map_err(map_security_error)?;
    let credentials = from_entries(&entries)?;
    Ok((credentials, CredentialsOrigin::ProtectedStore))
}

/// Salva le credenziali di **un profilo** nel suo archivio protetto.
///
/// L'archivio è quello dell'id del profilo, costruito dal chiamante con
/// [`profile_store_path`]. Ogni profilo ha un file distinto, così che salvarne
/// uno non tocchi gli altri.
///
/// # Errori
///
/// Restituisce un errore se la protezione o la scrittura non riescono.
pub fn save_profile_credentials(
    store: &ProtectedStore,
    credentials: &TelegramCredentials,
) -> ServiceResult<()> {
    let mut entries = BTreeMap::new();
    entries.insert(
        String::from(API_ID_KEY),
        credentials.api_id.expose_secret().to_string(),
    );
    entries.insert(
        String::from(API_HASH_KEY),
        String::from(credentials.api_hash.expose_secret()),
    );

    store.save(&entries).map_err(map_security_error)
}

/// Costruisce e valida le credenziali a partire dal **testo** digitato.
///
/// È l'ingresso usato dall'interfaccia per non costruire da sé i tipi riservati:
/// il testo entra qui, viene validato e diventa un [`TelegramCredentials`] che
/// non torna al livello grafico. Il valore grezzo **non** compare in alcun
/// messaggio d'errore.
///
/// # Errori
///
/// Restituisce un errore se l'identificativo non è un numero valido o se l'hash
/// non rispetta il formato atteso.
pub fn credentials_from_text(api_id: &str, api_hash: &str) -> ServiceResult<TelegramCredentials> {
    build(api_id, api_hash)
}

/// Le credenziali delle variabili d'ambiente, se entrambe presenti: la via
/// dello sviluppo e della prova dal vivo (ADR-0204 decisione 1).
///
/// # Errori
///
/// Restituisce un errore se le variabili ci sono ma sono vuote o non valide.
pub(crate) fn environment_credentials() -> ServiceResult<Option<TelegramCredentials>> {
    from_environment()
}

/// Legge i parametri dalle variabili d'ambiente, se entrambe presenti.
fn from_environment() -> ServiceResult<Option<TelegramCredentials>> {
    let (Ok(raw_id), Ok(raw_hash)) = (
        std::env::var(API_ID_VARIABLE),
        std::env::var(API_HASH_VARIABLE),
    ) else {
        return Ok(None);
    };

    // Una variabile presente ma vuota e' quasi certamente un errore di
    // configurazione: va segnalata invece di essere trattata come assente.
    if raw_id.trim().is_empty() || raw_hash.trim().is_empty() {
        return Err(ServiceError::SessionUnavailable {
            reason: format!(
                "le variabili {API_ID_VARIABLE} e {API_HASH_VARIABLE} sono presenti ma vuote"
            ),
        });
    }

    Ok(Some(build(&raw_id, &raw_hash)?))
}

/// Costruisce i parametri dalle voci dell'archivio.
fn from_entries(entries: &BTreeMap<String, String>) -> ServiceResult<TelegramCredentials> {
    let (Some(raw_id), Some(raw_hash)) = (entries.get(API_ID_KEY), entries.get(API_HASH_KEY))
    else {
        return Err(ServiceError::SessionUnavailable {
            reason: String::from("la configurazione protetta è incompleta"),
        });
    };

    build(raw_id, raw_hash)
}

/// Costruisce i tipi riservati validandoli.
///
/// Il valore grezzo **non compare** in alcun messaggio d'errore.
fn build(raw_id: &str, raw_hash: &str) -> ServiceResult<TelegramCredentials> {
    let parsed_id: i32 = raw_id.trim().parse().map_err(|_| {
        ServiceError::Connector(TelegramError::InvalidSecret {
            field: "api_id",
            reason: "deve essere un numero intero",
        })
    })?;

    Ok(TelegramCredentials {
        api_id: ApiId::try_new(parsed_id)?,
        api_hash: ApiHash::try_new(raw_hash.trim())?,
    })
}

/// Traduce un errore della protezione locale.
fn map_security_error(error: SecurityError) -> ServiceError {
    ServiceError::SessionUnavailable {
        reason: String::from(error.operator_message()),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{API_HASH_KEY, API_ID_KEY, CredentialsOrigin, build, from_entries};
    use crate::error::ServiceError;

    const FAKE_HASH: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn valid_values_produce_credentials() {
        let Ok(credentials) = build("1234567", FAKE_HASH) else {
            panic!("i valori fittizi devono essere accettati");
        };
        assert_eq!(credentials.api_id.expose_secret(), 1_234_567);
        assert_eq!(credentials.api_hash.expose_secret(), FAKE_HASH);
    }

    #[test]
    fn surrounding_spaces_are_tolerated() {
        assert!(build("  1234567  ", &format!("  {FAKE_HASH}  ")).is_ok());
    }

    #[test]
    fn a_non_numeric_identifier_is_refused_without_echoing_it() {
        let Err(error) = build("non-un-numero-9999", FAKE_HASH) else {
            panic!("il valore doveva essere rifiutato");
        };
        assert!(!error.to_string().contains("9999"));
    }

    /// Digitando un API ID non numerico nella schermata Account l'operatore
    /// vedeva «i dati di accesso non sono leggibili, usare Ripristina
    /// accesso»: un messaggio che parla di sessioni e di un pulsante che in
    /// quella schermata non esiste, invece di dire che l'API ID va corretto.
    #[test]
    fn a_non_numeric_identifier_gets_a_message_about_the_field_not_about_the_session() {
        let Err(error) = build("non-un-numero-9999", FAKE_HASH) else {
            panic!("il valore doveva essere rifiutato");
        };
        let message = error.operator_message();

        assert!(
            message.contains("API ID"),
            "il messaggio '{message}' non nomina il campo interessato"
        );
        assert!(!message.contains("Ripristina accesso"));
    }

    #[test]
    fn a_malformed_hash_is_refused() {
        assert!(build("1", "troppo-corto").is_err());
    }

    #[test]
    fn a_non_positive_identifier_is_refused() {
        assert!(build("0", FAKE_HASH).is_err());
        assert!(build("-1", FAKE_HASH).is_err());
    }

    #[test]
    fn incomplete_entries_are_reported() {
        let mut entries = BTreeMap::new();
        entries.insert(String::from(API_ID_KEY), String::from("1"));

        assert!(matches!(
            from_entries(&entries),
            Err(ServiceError::SessionUnavailable { .. })
        ));
    }

    #[test]
    fn complete_entries_are_accepted() {
        let mut entries = BTreeMap::new();
        entries.insert(String::from(API_ID_KEY), String::from("1"));
        entries.insert(String::from(API_HASH_KEY), String::from(FAKE_HASH));

        assert!(from_entries(&entries).is_ok());
    }

    #[test]
    fn the_debug_rendering_hides_both_values() {
        let Ok(credentials) = build("1234567", FAKE_HASH) else {
            panic!("i valori fittizi devono essere accettati");
        };
        let rendered = format!("{credentials:?}");

        assert!(!rendered.contains("1234567"));
        assert!(!rendered.contains(FAKE_HASH));
        assert!(rendered.contains("redatto"));
    }

    #[test]
    fn each_origin_is_described_for_the_operator() {
        assert!(
            CredentialsOrigin::Environment
                .describe()
                .contains("ambiente")
        );
        assert!(
            CredentialsOrigin::ProtectedStore
                .describe()
                .contains("protetta")
        );
    }

    #[test]
    fn profile_paths_carry_the_id_and_never_a_secret() {
        use lisi_core::ApiCredentialProfileId;

        use super::{PROFILE_FILE_SUFFIX, profile_store_path};

        let base = std::path::Path::new("cartella-base");
        let first = profile_store_path(base, ApiCredentialProfileId::new(1));
        let second = profile_store_path(base, ApiCredentialProfileId::new(42));

        assert_ne!(first, second, "profili distinti hanno file distinti");

        let name_first = first
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let name_second = second
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();

        assert!(name_first.contains('1'), "il nome porta l'id del profilo");
        assert!(name_second.contains("42"), "il nome porta l'id del profilo");
        assert!(name_first.ends_with(PROFILE_FILE_SUFFIX));
        assert!(
            !name_first.contains(FAKE_HASH),
            "nessun segreto nel nome del file"
        );
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use lisi_core::ApiCredentialProfileId;
    use lisi_security::ProtectedStore;

    use super::{build, from_entries, profile_store_path, save_profile_credentials};

    const FAKE_HASH_A: &str = "0123456789abcdef0123456789abcdef";
    const FAKE_HASH_B: &str = "fedcba9876543210fedcba9876543210";

    #[test]
    fn profiles_are_saved_and_reloaded_independently() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let base = directory.path();

        let store_a = ProtectedStore::at(profile_store_path(base, ApiCredentialProfileId::new(1)));
        let store_b = ProtectedStore::at(profile_store_path(base, ApiCredentialProfileId::new(2)));

        let (Ok(creds_a), Ok(creds_b)) = (build("111", FAKE_HASH_A), build("222", FAKE_HASH_B))
        else {
            panic!("le credenziali fittizie devono essere accettate");
        };

        let (Ok(()), Ok(())) = (
            save_profile_credentials(&store_a, &creds_a),
            save_profile_credentials(&store_b, &creds_b),
        ) else {
            panic!("entrambi i salvataggi devono riuscire");
        };

        // Riletti dallo strato protetto, senza passare per l'ambiente: il test
        // resta deterministico anche se le variabili di prova fossero impostate.
        let (Ok(entries_a), Ok(entries_b)) = (store_a.load(), store_b.load()) else {
            panic!("entrambi i profili devono rileggersi");
        };
        let (Ok(got_a), Ok(got_b)) = (from_entries(&entries_a), from_entries(&entries_b)) else {
            panic!("entrambe le credenziali devono ricostruirsi");
        };

        assert_eq!(got_a.api_id.expose_secret(), 111);
        assert_eq!(got_b.api_id.expose_secret(), 222);
        assert_eq!(got_a.api_hash.expose_secret(), FAKE_HASH_A);
        assert_eq!(got_b.api_hash.expose_secret(), FAKE_HASH_B);
    }

    #[test]
    fn an_absent_profile_is_reported_without_panic() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let store = ProtectedStore::at(profile_store_path(
            directory.path(),
            ApiCredentialProfileId::new(999),
        ));

        assert!(!store.exists());
        assert!(store.load().is_err());
    }

    #[test]
    fn a_profile_hash_is_not_written_in_clear() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let path = profile_store_path(directory.path(), ApiCredentialProfileId::new(7));
        let store = ProtectedStore::at(path.clone());

        let Ok(creds) = build("111", FAKE_HASH_A) else {
            panic!("le credenziali fittizie devono essere accettate");
        };
        let Ok(()) = save_profile_credentials(&store, &creds) else {
            panic!("il salvataggio deve riuscire");
        };

        let Ok(raw) = std::fs::read(&path) else {
            panic!("il file deve essere leggibile");
        };
        let hash_bytes = FAKE_HASH_A.as_bytes();
        let contains = raw.windows(hash_bytes.len()).any(|w| w == hash_bytes);
        assert!(!contains, "l'hash non deve comparire in chiaro sul disco");
    }
}

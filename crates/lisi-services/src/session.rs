//! Gestione della sessione locale.
//!
//! Ogni account ha la propria cartella di sessione, il cui nome deriva
//! dall'**impronta** del numero e non dal numero in chiaro: il nome di una
//! cartella è visibile a chiunque elenchi il disco, e un numero d'ufficio in
//! chiaro nel percorso sarebbe un segreto scritto in chiaro.
//!
//! **Al più tre account possono essere attivi insieme** (ADR-0173, DEC-439).
//! Fino a MULTI-ACCOUNT-02 era uno solo, perché due account insieme avrebbero
//! prodotto uno storico in cui non si sapeva più quale account avesse
//! acquisito che cosa. Ora ogni aggiornamento arriva al connettore del suo
//! account (l'instradatore della parte 1) e ogni monitoraggio è legato a un
//! account (migrazione 0072): la ragione del divieto è chiusa per
//! costruzione, e resta il tetto.
//!
//! Vedere `docs/adr/ADR-0009-SECRETS-AND-SESSION.md` e ADR-0173.

use std::fs::File;
use std::path::{Path, PathBuf};

use lisi_core::Sha256Digest;
use lisi_core::model::monitoring_account::MAX_ACTIVE_ACCOUNTS;
use lisi_telegram::PhoneNumber;

use crate::error::{ServiceError, ServiceResult};

/// Nome del file che marca una cartella come sessione di questo prodotto.
const MARKER_FILE: &str = "sessione.lisi";
/// Nome del file usato per l'esclusività.
const LOCK_FILE: &str = "sessione.lock";
/// Versione del formato della sessione.
const SESSION_FORMAT: u32 = 1;

/// Impronta dell'account, usata come nome di cartella.
///
/// Non è reversibile: dall'impronta non si risale al numero.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountFingerprint(String);

impl AccountFingerprint {
    /// Calcola l'impronta del numero indicato.
    #[must_use]
    pub fn of(phone: &PhoneNumber) -> Self {
        let digest = Sha256Digest::of_text(phone.expose_secret());
        // Sedici caratteri bastano a evitare collisioni pratiche e tengono i
        // percorsi leggibili.
        Self(digest.as_str().chars().take(16).collect())
    }

    /// Forma testuale, adatta a un nome di cartella e all'audit.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stato di una sessione su disco.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    /// Nessuna sessione presente per quell'account.
    Absent,
    /// Sessione presente e utilizzabile.
    Present,
    /// La cartella esiste ma non è una sessione valida di questo prodotto.
    Corrupted,
}

/// Che cosa dice una sessione Telegram danneggiata all'operatore (D-18).
pub const CORRUPTED_SESSION_MESSAGE: &str = "I dati dell'accesso a Telegram salvati su questo \
     computer non sono leggibili, e l'accesso non si può riprendere. Ciò che è già stato \
     acquisito resta nell'archivio. In Account aprire «Azzeramento e rimozione…», premere \
     «Rimuovi l'account selezionato…» e confermare con «Sì, rimuovi l'account». Poi \
     aggiungere di nuovo l'account e rifare l'accesso con numero e codice.";

impl SessionStatus {
    /// Messaggio destinato all'operatore.
    #[must_use]
    pub const fn operator_message(self) -> &'static str {
        match self {
            Self::Absent => "Nessun accesso salvato per questo account.",
            Self::Present => "È presente un accesso salvato: verrà ripreso.",
            // D-18: il percorso vero, con le etichette dello schermo. Nello
            // stato rotto l'accesso non e' riuscito, e «Rimuovi questo
            // account…» non compare: compare il pannello in cima ad Account.
            Self::Corrupted => CORRUPTED_SESSION_MESSAGE,
        }
    }
}

/// Sessione attiva, con il proprio lock esclusivo.
///
/// Il lock è tenuto aperto per tutta la durata: rilasciarlo è ciò che rende la
/// sessione disponibile a un'altra istanza.
#[derive(Debug)]
pub struct ActiveSession {
    fingerprint: AccountFingerprint,
    directory: PathBuf,
    /// Il file resta aperto: è l'handle a garantire l'esclusività.
    _lock: File,
}

impl ActiveSession {
    /// Impronta dell'account attivo.
    #[must_use]
    pub const fn fingerprint(&self) -> &AccountFingerprint {
        &self.fingerprint
    }

    /// Cartella della sessione.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }
}

/// Servizio che apre, riprende e chiude le sessioni.
#[derive(Debug)]
pub struct SessionService {
    root: PathBuf,
    /// Le sessioni attive, al più [`MAX_ACTIVE_ACCOUNTS`], nell'ordine in cui
    /// sono state aperte.
    active: Vec<ActiveSession>,
}

impl SessionService {
    /// Crea il servizio con la radice indicata.
    #[must_use]
    pub const fn new(root: PathBuf) -> Self {
        Self {
            root,
            active: Vec::new(),
        }
    }

    /// Radice sotto cui vivono le sessioni.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Le sessioni attive, nell'ordine in cui sono state aperte.
    #[must_use]
    pub fn active(&self) -> &[ActiveSession] {
        &self.active
    }

    /// Se la sessione dell'account indicato è attiva.
    #[must_use]
    pub fn is_active(&self, fingerprint: &AccountFingerprint) -> bool {
        self.active
            .iter()
            .any(|active| &active.fingerprint == fingerprint)
    }

    /// Cartella che ospiterebbe la sessione dell'account indicato.
    #[must_use]
    pub fn directory_for(&self, fingerprint: &AccountFingerprint) -> PathBuf {
        self.root.join(fingerprint.as_str())
    }

    /// Stato della sessione dell'account indicato.
    #[must_use]
    pub fn status(&self, fingerprint: &AccountFingerprint) -> SessionStatus {
        let directory = self.directory_for(fingerprint);
        if !directory.is_dir() {
            return SessionStatus::Absent;
        }

        let marker = directory.join(MARKER_FILE);
        let Ok(contents) = std::fs::read_to_string(&marker) else {
            // La cartella esiste ma non e' nostra, oppure il marcatore e'
            // illeggibile: non va usata come se fosse valida.
            return SessionStatus::Corrupted;
        };

        if parse_marker(&contents).is_none() {
            return SessionStatus::Corrupted;
        }

        SessionStatus::Present
    }

    /// Apre la sessione dell'account indicato, acquisendone l'esclusività.
    ///
    /// Se una sessione precedente esiste ed è valida, viene **ripresa**: la
    /// cartella non viene toccata.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::ActiveAccountLimit`] se sono già attivi
    /// [`MAX_ACTIVE_ACCOUNTS`] altri account, [`ServiceError::AccountInUse`]
    /// se la sessione è tenuta da un'altra istanza, e
    /// [`ServiceError::SessionUnavailable`] se la cartella non è utilizzabile.
    pub fn open(&mut self, phone: &PhoneNumber) -> ServiceResult<&ActiveSession> {
        let fingerprint = AccountFingerprint::of(phone);

        if let Some(posizione) = self
            .active
            .iter()
            .position(|active| active.fingerprint == fingerprint)
        {
            // Riapertura dello stesso account: la sessione e' gia' attiva.
            return self.active_at(posizione);
        }
        // IL TETTO (ADR-0173, decisione 2): un account in piu' si rifiuta, e
        // nessuno degli attivi si chiude da se' per fargli posto.
        if self.active.len() >= MAX_ACTIVE_ACCOUNTS {
            return Err(ServiceError::ActiveAccountLimit {
                limit: MAX_ACTIVE_ACCOUNTS,
            });
        }

        let directory = self.directory_for(&fingerprint);
        std::fs::create_dir_all(&directory).map_err(|error| ServiceError::SessionUnavailable {
            reason: format!("cartella della sessione non creabile: {error}"),
        })?;

        let lock = acquire_lock(&directory.join(LOCK_FILE))?;
        write_marker(&directory, &fingerprint)?;

        self.active.push(ActiveSession {
            fingerprint,
            directory,
            _lock: lock,
        });
        self.active_at(self.active.len() - 1)
    }

    /// La sessione attiva in quella posizione.
    fn active_at(&self, posizione: usize) -> ServiceResult<&ActiveSession> {
        self.active
            .get(posizione)
            .ok_or_else(|| ServiceError::SessionUnavailable {
                reason: String::from("sessione non registrata dopo l'apertura"),
            })
    }

    /// Chiude la sessione dell'account indicato, rilasciandone il lock.
    ///
    /// È idempotente: chiudere ciò che non è aperto non è un errore, perché il
    /// risultato voluto è lo stesso. Le altre sessioni restano attive.
    pub fn close(&mut self, fingerprint: &AccountFingerprint) {
        self.active
            .retain(|active| &active.fingerprint != fingerprint);
    }

    /// Chiude tutte le sessioni attive.
    pub fn close_all(&mut self) {
        self.active.clear();
    }

    /// Lascia attivo soltanto l'account indicato, chiudendo gli altri.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la nuova sessione non è apribile.
    pub fn switch_to(&mut self, phone: &PhoneNumber) -> ServiceResult<&ActiveSession> {
        self.close_all();
        self.open(phone)
    }

    /// Cancella in modo controllato i dati di sessione dell'account indicato.
    ///
    /// La sessione va **chiusa prima**: cancellare i file mentre il lock è
    /// tenuto lascerebbe una cartella a metà.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::AccountInUse`] se quella sessione è ancora
    /// attiva, e [`ServiceError::SessionUnavailable`] se la cancellazione non
    /// riesce.
    pub fn revoke(&mut self, fingerprint: &AccountFingerprint) -> ServiceResult<()> {
        if self.is_active(fingerprint) {
            return Err(ServiceError::AccountInUse);
        }

        let directory = self.directory_for(fingerprint);
        if !directory.exists() {
            // Il risultato voluto e' gia' quello.
            return Ok(());
        }

        std::fs::remove_dir_all(&directory).map_err(|error| ServiceError::SessionUnavailable {
            reason: format!("cancellazione della sessione non riuscita: {error}"),
        })
    }

    /// Ripristina una sessione danneggiata, rimuovendola.
    ///
    /// Esiste come funzione dell'interfaccia perché chiedere a un operatore non
    /// tecnico di cancellare una cartella è un modo per fargliene cancellare
    /// una sbagliata.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la rimozione non riesce.
    pub fn repair(&mut self, fingerprint: &AccountFingerprint) -> ServiceResult<()> {
        self.close(fingerprint);
        self.revoke(fingerprint)
    }

    /// Impronte delle sessioni presenti su disco.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la radice non è leggibile.
    pub fn known_accounts(&self) -> ServiceResult<Vec<AccountFingerprint>> {
        if !self.root.is_dir() {
            return Ok(Vec::new());
        }

        let listing =
            std::fs::read_dir(&self.root).map_err(|error| ServiceError::SessionUnavailable {
                reason: format!("cartella delle sessioni non leggibile: {error}"),
            })?;

        let mut accounts = Vec::new();
        for entry in listing.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            if let Some(name) = entry.file_name().to_str() {
                accounts.push(AccountFingerprint(name.to_owned()));
            }
        }
        accounts.sort();
        Ok(accounts)
    }
}

/// Acquisisce il lock esclusivo sulla sessione.
///
/// Su Windows si apre il file con modalità di condivisione **nulla**: qualunque
/// altro tentativo di aprirlo fallisce finché l'handle resta vivo. È una
/// proprietà del sistema operativo, non una convenzione, e ha una conseguenza
/// utile: se il processo termina in modo anomalo, il sistema chiude l'handle e
/// la sessione torna disponibile. Il recupero dopo un arresto anomalo non
/// richiede quindi alcuna pulizia manuale né file da cancellare a mano.
fn acquire_lock(path: &Path) -> ServiceResult<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            // Nessuna condivisione: e' questo che realizza l'esclusivita'.
            .share_mode(0)
            .open(path)
            .map_err(|_| ServiceError::AccountInUse)
    }
    #[cfg(not(windows))]
    {
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|_| ServiceError::AccountInUse)
    }
}

/// Scrive il marcatore che identifica la cartella come sessione del prodotto.
///
/// Contiene l'**impronta**, non il numero: nemmeno dentro la cartella un
/// segreto viene scritto in chiaro.
fn write_marker(directory: &Path, fingerprint: &AccountFingerprint) -> ServiceResult<()> {
    let contents = format!(
        "formato={SESSION_FORMAT}\nimpronta={}\n",
        fingerprint.as_str()
    );

    std::fs::write(directory.join(MARKER_FILE), contents).map_err(|error| {
        ServiceError::SessionUnavailable {
            reason: format!("marcatore della sessione non scrivibile: {error}"),
        }
    })
}

/// Interpreta il marcatore, restituendo la versione di formato dichiarata.
fn parse_marker(contents: &str) -> Option<u32> {
    let mut format = None;
    let mut has_fingerprint = false;

    for line in contents.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        match key.trim() {
            "formato" => format = value.trim().parse().ok(),
            "impronta" if !value.trim().is_empty() => has_fingerprint = true,
            _ => {}
        }
    }

    // Un formato piu' recente di quello conosciuto non va interpretato con le
    // regole vecchie, come per lo schema del database.
    match format {
        Some(version) if version <= SESSION_FORMAT && has_fingerprint => Some(version),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use lisi_telegram::PhoneNumber;

    use super::{
        AccountFingerprint, LOCK_FILE, MARKER_FILE, SessionService, SessionStatus, parse_marker,
    };
    use crate::error::ServiceError;

    const FAKE_PHONE: &str = "+390612345678";
    const OTHER_FAKE_PHONE: &str = "+390698765432";
    const THIRD_FAKE_PHONE: &str = "+390611112222";
    const FOURTH_FAKE_PHONE: &str = "+390633334444";

    fn phone(raw: &str) -> PhoneNumber {
        let Ok(value) = PhoneNumber::try_new(raw) else {
            panic!("il numero fittizio deve essere valido");
        };
        value
    }

    fn service() -> (tempfile::TempDir, SessionService) {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let service = SessionService::new(directory.path().join("sessioni"));
        (directory, service)
    }

    #[test]
    fn the_fingerprint_does_not_contain_the_number() {
        let fingerprint = AccountFingerprint::of(&phone(FAKE_PHONE));

        // Si verifica l'assenza del corpo distintivo del numero, non di brevi
        // sequenze come "39": in sedici caratteri esadecimali quelle compaiono
        // per caso, e una verifica cosi' proverebbe una coincidenza.
        assert!(!fingerprint.as_str().contains("0612345"));
        assert!(!fingerprint.as_str().contains("612345678"));
        assert_eq!(fingerprint.as_str().len(), 16);
        assert!(
            fingerprint
                .as_str()
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        );
    }

    #[test]
    fn the_fingerprint_is_stable_for_the_same_number() {
        assert_eq!(
            AccountFingerprint::of(&phone(FAKE_PHONE)),
            AccountFingerprint::of(&phone(FAKE_PHONE))
        );
    }

    #[test]
    fn different_numbers_produce_different_fingerprints() {
        assert_ne!(
            AccountFingerprint::of(&phone(FAKE_PHONE)),
            AccountFingerprint::of(&phone(OTHER_FAKE_PHONE))
        );
    }

    #[test]
    fn an_absent_session_is_reported_as_such() {
        let (_guard, service) = service();
        let fingerprint = AccountFingerprint::of(&phone(FAKE_PHONE));

        assert_eq!(service.status(&fingerprint), SessionStatus::Absent);
    }

    #[test]
    fn an_opened_session_becomes_present_and_is_isolated_by_account() {
        let (_guard, mut service) = service();

        let Ok(session) = service.open(&phone(FAKE_PHONE)) else {
            panic!("l'apertura deve riuscire");
        };
        let directory = session.directory().to_path_buf();
        let fingerprint = session.fingerprint().clone();

        assert!(directory.is_dir());
        assert!(directory.join(MARKER_FILE).is_file());
        assert!(directory.join(LOCK_FILE).is_file());
        assert_eq!(service.status(&fingerprint), SessionStatus::Present);

        // L'altro account non ha ancora nulla.
        let other = AccountFingerprint::of(&phone(OTHER_FAKE_PHONE));
        assert_eq!(service.status(&other), SessionStatus::Absent);
        assert_ne!(service.directory_for(&other), directory);
    }

    #[test]
    fn the_session_path_does_not_contain_the_number() {
        let (_guard, mut service) = service();
        let Ok(session) = service.open(&phone(FAKE_PHONE)) else {
            panic!("l'apertura deve riuscire");
        };

        let path = session.directory().display().to_string();
        assert!(!path.contains("0612345"));
        assert!(!path.contains("+39"));
    }

    /// **Tre account attivi insieme, il quarto si rifiuta e nessuno degli
    /// attivi si chiude per fargli posto** (MULTI-ACCOUNT-02 parte 2,
    /// ADR-0173, criterio 1; prova negativa: il tetto tolto → rossa).
    #[test]
    fn three_accounts_may_be_active_and_the_fourth_is_refused() {
        let (_guard, mut service) = service();
        for numero in [FAKE_PHONE, OTHER_FAKE_PHONE, THIRD_FAKE_PHONE] {
            let Ok(_) = service.open(&phone(numero)) else {
                panic!("fino a tre account si aprono insieme");
            };
        }
        assert_eq!(service.active().len(), 3);

        assert!(matches!(
            service.open(&phone(FOURTH_FAKE_PHONE)),
            Err(ServiceError::ActiveAccountLimit { limit: 3 })
        ));
        assert_eq!(service.active().len(), 3, "nessuno ha ceduto il posto");
        assert!(!service.is_active(&AccountFingerprint::of(&phone(FOURTH_FAKE_PHONE))));

        // Uno chiuso dall'operatore libera il posto, e gli altri restano.
        service.close(&AccountFingerprint::of(&phone(OTHER_FAKE_PHONE)));
        assert!(service.is_active(&AccountFingerprint::of(&phone(FAKE_PHONE))));
        assert!(service.open(&phone(FOURTH_FAKE_PHONE)).is_ok());
    }

    #[test]
    fn reopening_the_same_account_is_not_an_error() {
        let (_guard, mut service) = service();
        let Ok(_) = service.open(&phone(FAKE_PHONE)) else {
            panic!("la prima apertura deve riuscire");
        };
        assert!(service.open(&phone(FAKE_PHONE)).is_ok());
    }

    #[test]
    fn switching_account_closes_the_previous_one() {
        let (_guard, mut service) = service();
        let Ok(_) = service.open(&phone(FAKE_PHONE)) else {
            panic!("la prima apertura deve riuscire");
        };

        let Ok(session) = service.switch_to(&phone(OTHER_FAKE_PHONE)) else {
            panic!("il cambio account deve riuscire");
        };
        assert_eq!(
            session.fingerprint(),
            &AccountFingerprint::of(&phone(OTHER_FAKE_PHONE))
        );
    }

    #[test]
    fn an_existing_session_is_resumed_without_being_recreated() {
        let (_guard, mut service) = service();
        let Ok(session) = service.open(&phone(FAKE_PHONE)) else {
            panic!("l'apertura deve riuscire");
        };
        let directory = session.directory().to_path_buf();

        // Un file lasciato da TDLib: la ripresa non deve cancellarlo.
        let Ok(()) = std::fs::write(directory.join("dati-simulati.bin"), b"contenuto") else {
            panic!("il file di prova deve potersi scrivere");
        };

        service.close_all();
        let Ok(_) = service.open(&phone(FAKE_PHONE)) else {
            panic!("la ripresa deve riuscire");
        };

        assert!(directory.join("dati-simulati.bin").is_file());
    }

    #[test]
    fn closing_releases_the_session() {
        let (_guard, mut service) = service();
        let Ok(_) = service.open(&phone(FAKE_PHONE)) else {
            panic!("la prima apertura deve riuscire");
        };
        // Un'altra istanza sulla stessa radice: finché la sessione è aperta
        // non la ottiene, chiusa sì.
        let mut altra = SessionService::new(service.root().to_path_buf());
        assert!(matches!(
            altra.open(&phone(FAKE_PHONE)),
            Err(ServiceError::AccountInUse)
        ));
        service.close(&AccountFingerprint::of(&phone(FAKE_PHONE)));

        assert!(altra.open(&phone(FAKE_PHONE)).is_ok());
    }

    #[test]
    fn closing_twice_is_not_an_error() {
        let (_guard, mut service) = service();
        service.close_all();
        service.close_all();
        assert!(service.active().is_empty());
    }

    #[test]
    fn a_corrupted_marker_is_detected() {
        let (_guard, mut service) = service();
        let Ok(session) = service.open(&phone(FAKE_PHONE)) else {
            panic!("l'apertura deve riuscire");
        };
        let directory = session.directory().to_path_buf();
        let fingerprint = session.fingerprint().clone();
        service.close_all();

        let Ok(()) = std::fs::write(directory.join(MARKER_FILE), b"contenuto senza senso") else {
            panic!("il marcatore deve potersi sovrascrivere");
        };

        assert_eq!(service.status(&fingerprint), SessionStatus::Corrupted);
    }

    #[test]
    fn a_missing_marker_makes_the_session_corrupted() {
        let (_guard, mut service) = service();
        let Ok(session) = service.open(&phone(FAKE_PHONE)) else {
            panic!("l'apertura deve riuscire");
        };
        let directory = session.directory().to_path_buf();
        let fingerprint = session.fingerprint().clone();
        service.close_all();

        let Ok(()) = std::fs::remove_file(directory.join(MARKER_FILE)) else {
            panic!("il marcatore deve potersi rimuovere");
        };

        assert_eq!(service.status(&fingerprint), SessionStatus::Corrupted);
    }

    #[test]
    fn a_newer_session_format_is_refused_instead_of_being_interpreted() {
        // Stessa prudenza dello schema del database: un formato piu' recente
        // non va letto con le regole vecchie.
        assert_eq!(parse_marker("formato=1\nimpronta=abc\n"), Some(1));
        assert_eq!(parse_marker("formato=999\nimpronta=abc\n"), None);
        assert_eq!(parse_marker("formato=1\n"), None);
        assert_eq!(parse_marker("impronta=abc\n"), None);
    }

    #[test]
    fn repairing_removes_the_damaged_session() {
        let (_guard, mut service) = service();
        let Ok(session) = service.open(&phone(FAKE_PHONE)) else {
            panic!("l'apertura deve riuscire");
        };
        let fingerprint = session.fingerprint().clone();
        let directory = session.directory().to_path_buf();

        let Ok(()) = service.repair(&fingerprint) else {
            panic!("il ripristino deve riuscire");
        };

        assert!(!directory.exists());
        assert_eq!(service.status(&fingerprint), SessionStatus::Absent);
    }

    #[test]
    fn revoking_an_active_session_is_refused() {
        let (_guard, mut service) = service();
        let Ok(session) = service.open(&phone(FAKE_PHONE)) else {
            panic!("l'apertura deve riuscire");
        };
        let fingerprint = session.fingerprint().clone();

        assert!(matches!(
            service.revoke(&fingerprint),
            Err(ServiceError::AccountInUse)
        ));
    }

    #[test]
    fn revoking_an_absent_session_is_not_an_error() {
        let (_guard, mut service) = service();
        let fingerprint = AccountFingerprint::of(&phone(FAKE_PHONE));
        assert!(service.revoke(&fingerprint).is_ok());
    }

    #[test]
    fn known_accounts_are_listed_by_fingerprint_only() {
        let (_guard, mut service) = service();
        let Ok(_) = service.open(&phone(FAKE_PHONE)) else {
            panic!("l'apertura deve riuscire");
        };
        service.close_all();
        let Ok(_) = service.open(&phone(OTHER_FAKE_PHONE)) else {
            panic!("l'apertura deve riuscire");
        };

        let Ok(accounts) = service.known_accounts() else {
            panic!("l'elenco deve potersi leggere");
        };
        assert_eq!(accounts.len(), 2);
        for account in &accounts {
            assert!(!account.as_str().contains("0612345"));
            assert!(!account.as_str().contains("0698765"));
        }
    }

    #[test]
    fn an_absent_root_yields_no_accounts() {
        let (_guard, service) = service();
        assert_eq!(
            service.known_accounts().map(|list| list.len()).ok(),
            Some(0)
        );
    }

    #[test]
    fn every_status_offers_an_operator_message() {
        for status in [
            SessionStatus::Absent,
            SessionStatus::Present,
            SessionStatus::Corrupted,
        ] {
            assert!(!status.operator_message().is_empty());
        }
        // Il messaggio della sessione danneggiata deve dire che cosa fare e
        // rassicurare sui contenuti gia' acquisiti: e' la prima paura di chi
        // legge "i dati non sono leggibili". Fino al 2026-10-02 la prova
        // chiedeva «Ripristina accesso», un comando che non esiste (D-18): ora
        // chiede il percorso vero, e la prova dell'interfaccia verifica che le
        // etichette esistano.
        let damaged = SessionStatus::Corrupted.operator_message();
        assert!(damaged.contains("«Rimuovi l'account selezionato…»"));
        assert!(damaged.contains("resta nell'archivio"));
        assert!(!damaged.contains("Ripristina accesso"));
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use lisi_telegram::PhoneNumber;

    use super::{AccountFingerprint, LOCK_FILE, SessionService};
    use crate::error::ServiceError;

    const FAKE_PHONE: &str = "+390612345678";

    fn phone() -> PhoneNumber {
        let Ok(value) = PhoneNumber::try_new(FAKE_PHONE) else {
            panic!("il numero fittizio deve essere valido");
        };
        value
    }

    #[test]
    fn a_second_instance_cannot_open_the_same_session() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let root = directory.path().join("sessioni");

        let mut first = SessionService::new(root.clone());
        let Ok(_) = first.open(&phone()) else {
            panic!("la prima istanza deve poter aprire");
        };

        // Seconda istanza del servizio: rappresenta un secondo processo.
        let mut second = SessionService::new(root);
        assert!(
            matches!(second.open(&phone()), Err(ServiceError::AccountInUse)),
            "il lock deve essere una proprieta' del sistema, non una convenzione"
        );
    }

    #[test]
    fn the_session_becomes_available_again_after_the_holder_is_dropped() {
        // Simula il recupero dopo un arresto anomalo: il sistema chiude
        // l'handle quando il detentore sparisce, senza pulizia manuale.
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let root = directory.path().join("sessioni");

        {
            let mut first = SessionService::new(root.clone());
            let Ok(_) = first.open(&phone()) else {
                panic!("la prima apertura deve riuscire");
            };
        }

        let mut second = SessionService::new(root.clone());
        assert!(
            second.open(&phone()).is_ok(),
            "dopo il rilascio la sessione deve tornare disponibile"
        );

        // Il file di lock rimane sul disco: e' l'handle a contare, non il file.
        let fingerprint = AccountFingerprint::of(&phone());
        assert!(root.join(fingerprint.as_str()).join(LOCK_FILE).is_file());
    }
}

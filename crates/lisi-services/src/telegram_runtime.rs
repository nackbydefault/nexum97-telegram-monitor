//! Orchestrazione applicativa di un account Telegram.
//!
//! È il punto in cui i pezzi già costruiti si compongono in un ciclo verificabile:
//! un [`crate::accounts::AccountService`] registra profili e account; qui un
//! account registrato diventa una sessione di accesso guidata. La sequenza è
//! quella prevista da ADR-0019:
//!
//! `profilo API → account → directory e chiave isolate → connettore → login →
//! persistenza dello stato`.
//!
//! # Che cosa vive qui e che cosa no
//!
//! Un [`AccountRuntime`] è lo stato **volatile** di un account collegato (il
//! connettore vivo, la macchina di autorizzazione dentro
//! [`crate::auth::AuthenticationService`]): non è persistito, vive in memoria e
//! ne esiste uno per account. La persistenza dei **metadati** dell'account resta
//! all'`AccountService`, che possiede il database; il runtime gli chiede di
//! aggiornare la riga dopo ogni passo, così che lo stato conservato non diverga
//! mai da quello reale.
//!
//! # Isolamento per account (ADR-0019 §2)
//!
//! Le cartelle e il file della chiave di un account derivano **solo dal suo
//! UUID**, mai dal numero di telefono: un elenco di cartelle non rivela a chi
//! appartengono. Due account non condividono né directory né chiave.
//!
//! # Segreti
//!
//! API hash, codice e password 2FA non compaiono qui: transitano dentro
//! `AuthenticationService` e non sono mai persistiti. Il numero di telefono non
//! è conservato in chiaro: se ne ricava, per la sola persistenza, la forma
//! **mascherata** ([`MaskedPhoneNumber`]), che mostra al più le ultime due cifre.
//! La resa `Debug` del runtime è redatta di conseguenza.
//!
//! # Mock predefinito, live esplicito (ADR-0019 §4)
//!
//! Il connettore predefinito è il **mock** deterministico. La modalità reale è
//! disponibile soltanto con la feature di compilazione `tdlib-runtime`; chiederla
//! senza quella feature non apre alcuna sessione e restituisce un errore chiaro.

use std::path::{Path, PathBuf};

use lisi_core::model::{
    AccountUuid, MaskedPhoneNumber, PersistedAuthStatus, PersistedConnectionStatus, TelegramAccount,
};
use lisi_core::{TelegramAccountId, Timestamp};
use lisi_security::{AccountKey, SecurityError, ensure_account_key};
use lisi_telegram::{
    AuthorizationState, ClientParameters, LoginCode, MockTelegramConnector, PhoneNumber,
    TelegramConnector, TelegramError, TwoFactorPassword,
};

use crate::accounts::AccountService;
use crate::acquisition_authority::AcquisitionAuthority;
use crate::auth::{AuthenticationService, AuthenticationView};
use crate::error::{ServiceError, ServiceResult};
use crate::live_diagnostics::{LiveDiagnostic, LiveStartupPhase};

// La modalità reale (cablaggio di M3B.1b) è compilata solo con la feature che
// carica TDLib. Questi tipi non esistono senza di essa e le importazioni sono
// perciò condizionate, così che la build senza la feature resti identica.
#[cfg(feature = "tdlib-runtime")]
use lisi_core::ApiCredentialProfileId;
#[cfg(feature = "tdlib-runtime")]
use lisi_telegram::LiveTdlibConnector;
#[cfg(feature = "tdlib-runtime")]
use lisi_telegram::tdlib::router::shared_router;

#[cfg(feature = "tdlib-runtime")]
use crate::config::TelegramCredentials;

/// Se **questo binario** porta con se' la capacita' di parlare con Telegram
/// dal vivo.
///
/// # Perche' una costante e non una prova a tentativi
///
/// La modalita' reale esiste soltanto quando il binario e' stato compilato
/// con la feature `tdlib-runtime`, che porta con se' il caricamento di TDLib.
/// Senza quella feature `open_live` fallisce con una ragione chiara — ed e'
/// gia' cosi' — ma **l'operatore lo scopriva solo provando**: l'interfaccia
/// offriva la scelta «Telegram reale» come se fosse disponibile.
///
/// Un prodotto che offre una funzione che non ha promette una cosa falsa, e
/// il fatto che poi lo dica non ripara la promessa: chi ha scelto quella
/// modalita' ha gia' preso una decisione basandosi su di essa.
///
/// **E' costata due installer difettosi.** Il 2026-08-18 e il 2026-08-19 sono
/// stati costruiti due pacchetti senza TDLib — dimenticando la feature — e
/// nulla, ne' nel prodotto ne' nell'installer, lo ha dichiarato. Il difetto
/// era invisibile fino al momento dell'accesso.
///
/// # Perche' si ricava dalla feature e non si scrive a mano
///
/// `cfg!` la legge dal compilatore. Scriverla a mano significherebbe una
/// seconda definizione della stessa cosa, che prima o poi direbbe il
/// contrario di quella vera — ed e' esattamente il difetto che questa
/// costante esiste per impedire.
pub const TELEGRAM_RUNTIME_AVAILABLE: bool = cfg!(feature = "tdlib-runtime");

/// **La dichiarazione corrisponde alla compilazione, in tutti e due i versi.**
///
/// Due asserzioni che il compilatore valuta, e non una prova: una divergenza
/// non fa diventare rossa una prova, fa **fallire la costruzione**. E' piu'
/// forte, e su una cosa cosi' la forza in piu' serve.
///
/// Servono a un caso solo e preciso: che il nome della feature venga cambiato
/// in un punto e non nell'altro. Un refuso del genere renderebbe la costante
/// sempre falsa, il prodotto sempre muto sulla propria capacita', e nessuna
/// prova ordinaria se ne accorgerebbe — perche' una costante falsa e' una
/// costante perfettamente valida.
#[cfg(feature = "tdlib-runtime")]
const _: () = assert!(
    TELEGRAM_RUNTIME_AVAILABLE,
    "compilato CON il componente e dichiara di non averlo"
);

#[cfg(not(feature = "tdlib-runtime"))]
const _: () = assert!(
    !TELEGRAM_RUNTIME_AVAILABLE,
    "compilato SENZA il componente e dichiara di averlo: è la promessa falsa \
     che questa costante esiste per impedire"
);

/// Che cosa dire all'operatore quando la capacita' non c'e'.
///
/// Dice **il fatto** e non la causa tecnica: «manca una feature di
/// compilazione» non e' una frase che un operatore possa usare. La causa sta
/// nel dettaglio tecnico, dietro «Dettagli tecnici».
///
/// E' il messaggio di sicurezza SIC-15 (PR-01, ADR-0117): il testo sta nel
/// registro versionato, e questa costante ne e' la versione corrente. Una
/// copia scritta qui divergerebbe dal registro alla prima riformulazione.
pub const TELEGRAM_RUNTIME_MISSING_REASON: &str =
    lisi_core::security_messages::RUNTIME_MISSING.current.text;

/// Il dettaglio tecnico di [`TELEGRAM_RUNTIME_MISSING_REASON`].
pub const TELEGRAM_RUNTIME_MISSING_DETAIL: &str = lisi_core::security_messages::RUNTIME_MISSING
    .current
    .technical_detail;

/// Sottocartella che raccoglie i dati dei singoli account.
pub(crate) const ACCOUNTS_DIR: &str = "accounts";
/// Sottocartella del database TDLib di un account.
const TDLIB_SUBDIR: &str = "tdlib";
/// Sottocartella dei file scaricati di un account.
const FILES_SUBDIR: &str = "files";
/// Nome del file protetto che custodisce la chiave di cifratura dell'account.
const KEY_FILE: &str = "tdlib.key.protetto";

/// Tempo massimo di attesa del primo stato di autorizzazione in modalità Live
/// (fase 10) prima di diagnosticarlo come non riuscito.
///
/// Abbastanza lungo per tollerare una rete lenta, abbastanza corto da non
/// lasciar credere che l'interfaccia sia bloccata.
const FIRST_AUTHORIZATION_STATE_TIMEOUT_MILLIS: i64 = 20_000;

/// Tempo massimo di attesa di `authorizationStateWaitCode` dopo un invio
/// riuscito del numero (fase 14) prima di diagnosticarlo come non riuscito.
///
/// Costante **distinta** da [`FIRST_AUTHORIZATION_STATE_TIMEOUT_MILLIS`],
/// anche se ne condivide oggi il valore: quella copre l'attesa del *primo*
/// stato dopo `start()`, questa copre l'attesa che segue l'invio del numero
/// (`WaitingForPhoneNumber` → `WaitingForCode`). Tenerle separate permette di
/// farle divergere in futuro senza che una trascini l'altra, ed evita che chi
/// legge il codice sospetti un'unica soglia condivisa fra due fasi diverse
/// dell'accesso.
const PHONE_NUMBER_CODE_WAIT_TIMEOUT_MILLIS: i64 = FIRST_AUTHORIZATION_STATE_TIMEOUT_MILLIS;

/// Versione dell'applicazione dichiarata alla piattaforma nella modalità reale.
///
/// Coerente con NEXUM/97 e non ingannevole (ADR-0019 §4): è la versione del
/// pacchetto, non un valore inventato.
#[cfg(feature = "tdlib-runtime")]
const APPLICATION_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Codice di lingua dichiarato alla piattaforma nella modalità reale.
#[cfg(feature = "tdlib-runtime")]
const SYSTEM_LANGUAGE_CODE: &str = "it";

/// Cartella base dei dati dell'applicazione.
///
/// Sotto `%LOCALAPPDATA%`, già ristretta all'utente, e con il nome persistente
/// del prodotto: è la radice sotto cui vivono i file protetti dei profili e le
/// sottocartelle per-account. Il nome della cartella viene da `lisi-core` e
/// **non** segue il nome pubblico del prodotto, per non rendere irraggiungibile
/// la configurazione già scritta sui profili esistenti.
///
/// # Errori
///
/// Restituisce un errore se la cartella dati locale non è determinabile (fuori
/// da Windows la variabile può mancare).
pub fn account_data_root() -> ServiceResult<PathBuf> {
    crate::data_directory::application_directory()
}

/// Percorsi isolati di un account, tutti derivati dal suo UUID.
///
/// Nessuno di questi percorsi contiene il numero di telefono, il nome o
/// l'username: l'unico componente variabile è l'UUID (trentadue cifre
/// esadecimali casuali). Due account distinti hanno percorsi distinti e non
/// condividono nulla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountPaths {
    /// Radice dell'account: `<base>/accounts/<uuid>`.
    pub root: PathBuf,
    /// Cartella del database TDLib dell'account.
    pub tdlib_dir: PathBuf,
    /// Cartella dei file dell'account.
    pub files_dir: PathBuf,
    /// File protetto della chiave di cifratura del database dell'account.
    pub key_path: PathBuf,
}

impl AccountPaths {
    /// Compone i percorsi isolati a partire dalla cartella base e dall'UUID.
    ///
    /// Il numero di telefono **non** entra qui: l'identità che nomina le cartelle
    /// è l'UUID, mai il numero (ADR-0019 §2).
    #[must_use]
    pub fn new(base_dir: &Path, uuid: &AccountUuid) -> Self {
        let root = base_dir.join(ACCOUNTS_DIR).join(uuid.as_str());
        let tdlib_dir = root.join(TDLIB_SUBDIR);
        let files_dir = root.join(FILES_SUBDIR);
        let key_path = root.join(KEY_FILE);
        Self {
            root,
            tdlib_dir,
            files_dir,
            key_path,
        }
    }

    /// Se l'account ha una **sessione Telegram reale salvata** su questa
    /// postazione (E2E01-02, ADR-0146).
    ///
    /// È il registro di TDLib nella cartella isolata dell'account: lo scrive
    /// soltanto il connettore reale. L'autorizzazione conservata nell'archivio
    /// non basta, perché la scrive anche l'accesso dimostrativo. Non dice che la
    /// sessione sia ancora valida — lo sa solo Telegram, all'accesso — e non
    /// legge il file: ne guarda l'esistenza.
    #[must_use]
    pub fn has_saved_session(&self) -> bool {
        self.tdlib_dir.join(TDLIB_BINLOG).is_file()
    }
}

/// Il registro della sessione che TDLib scrive nella cartella del database.
const TDLIB_BINLOG: &str = "td.binlog";

/// Modalità con cui si costruisce il connettore di un account.
///
/// Il mock è la scelta predefinita e l'unica usata dai test automatici. La
/// modalità reale è una decisione esplicita, e senza la feature `tdlib-runtime`
/// non è nemmeno disponibile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeMode {
    /// Connettore simulato deterministico: nessuna rete, nessuna credenziale.
    Mock,
    /// Connettore reale verso Telegram, disponibile solo con `tdlib-runtime`.
    Live,
}

/// Prepara la directory e la chiave isolate di un account.
///
/// Crea le cartelle `tdlib` e `files` sotto la radice dell'account e assicura la
/// chiave di cifratura del database: se il file protetto è assente ne genera una
/// casuale, altrimenti ricarica quella esistente. La chiave è **distinta per
/// account** e non compare in log, errori o nomi di file (ADR-0019 §2).
///
/// # Errori
///
/// Restituisce un errore se le cartelle non sono creabili o se la protezione
/// della chiave non riesce. Fuori da Windows la protezione DPAPI non è
/// disponibile e l'operazione fallisce senza fingere di aver protetto nulla.
pub fn prepare_account_storage(base_dir: &Path, uuid: &AccountUuid) -> ServiceResult<AccountKey> {
    let paths = AccountPaths::new(base_dir, uuid);
    create_directory(&paths.tdlib_dir)?;
    create_directory(&paths.files_dir)?;
    ensure_account_key(paths.key_path).map_err(map_security_error)
}

/// Crea una cartella e i suoi genitori, senza riportare il percorso nell'errore.
fn create_directory(path: &Path) -> ServiceResult<()> {
    std::fs::create_dir_all(path).map_err(|_| ServiceError::SessionUnavailable {
        reason: String::from("impossibile preparare le cartelle isolate dell'account"),
    })
}

/// Stato volatile di un account collegato: il connettore vivo e il login in
/// corso.
///
/// Non è persistito: dopo ogni passo chiede all'`AccountService` di aggiornare la
/// riga dell'account, ma lo stato fine dell'accesso vive qui. La resa `Debug` è
/// affidata al servizio di autenticazione, che redige i valori riservati; il
/// numero mascherato conservato mostra al più le ultime due cifre.
#[derive(Debug)]
pub struct AccountRuntime {
    /// Account a cui questo runtime è legato.
    account_id: TelegramAccountId,
    /// Servizio che conduce l'accesso guidando il connettore.
    auth: AuthenticationService,
    /// Parametri con cui avviare il client.
    ///
    /// `None` per il mock, che li ignora e usa i propri segnaposto: il
    /// comportamento del mock resta identico. `Some` per la modalità reale, dove
    /// portano API id/hash (redatti), la directory del database dell'account e la
    /// versione dichiarata. La chiave del database **non** vive qui: è custodita,
    /// redatta, dentro il connettore reale.
    parameters: Option<ClientParameters>,
    /// Numero mascherato, noto dopo l'invio del numero e persistito così.
    masked_phone: Option<MaskedPhoneNumber>,
    /// UUID dell'account, per comporre le diagnostiche di avvio Live senza una
    /// lettura aggiuntiva del database a ogni pompaggio.
    account_uuid: AccountUuid,
    /// Istante di avvio dell'attesa del primo stato di autorizzazione (fase
    /// 10, solo modalità Live). `None` fuori dalla modalità Live, prima
    /// dell'avvio, o dopo che l'attesa si è risolta (con successo o con
    /// diagnosi).
    live_started_at: Option<Timestamp>,
    /// Se il timeout dell'attesa del primo stato di autorizzazione è già
    /// stato diagnosticato per il tentativo corrente: evita diagnosi ripetute
    /// a ogni pompaggio successivo.
    live_timeout_diagnosed: bool,
    /// Istante di avvio dell'attesa di `authorizationStateWaitCode` dopo un
    /// invio riuscito del numero (fase 14, solo modalità Live). `None` fuori
    /// dalla modalità Live, prima dell'invio del numero, o dopo che l'attesa
    /// si è risolta (con successo o con diagnosi).
    ///
    /// Guardiano **distinto** da [`Self::live_started_at`] (fase 10): quello
    /// copre l'attesa del primo stato dopo `start()`, questo copre l'attesa
    /// che segue l'invio del numero.
    code_wait_started_at: Option<Timestamp>,
    /// Se il timeout dell'attesa del codice (fase 14) è già stato
    /// diagnosticato per il tentativo corrente: evita diagnosi ripetute a
    /// ogni pompaggio successivo.
    code_wait_diagnosed: bool,
    /// Se [`Self::start`] è già riuscito per questo runtime.
    ///
    /// Finché è `false` il connettore non è stato avviato e non ha nulla da
    /// consegnare: [`Self::pump`] non deve nemmeno interrogarlo. Senza questa
    /// guardia il pompaggio periodico dell'interfaccia (ogni 200 ms, attivo
    /// dal momento in cui esiste una sessione, **prima** che l'operatore
    /// prema «Avvia accesso») chiama `poll_event` su un connettore mai
    /// avviato, ne raccoglie l'errore «il connettore non e' stato avviato» e
    /// lo classifica come guasto di avvio Live — una diagnosi **falsa**, che
    /// nel pilot del 2026-07-30 ha prodotto `LIVE-E015` («client Telegram non
    /// creato») per il solo fatto che l'accesso non era ancora stato avviato.
    started: bool,
}

impl AccountRuntime {
    /// Crea il runtime di un account nella modalità indicata.
    ///
    /// È il costruttore **leggero**: conosce solo l'account. In modalità
    /// [`RuntimeMode::Mock`] costruisce il connettore simulato. In modalità
    /// [`RuntimeMode::Live`] non costruisce nulla, perché la modalità reale ha
    /// bisogno del profilo, delle directory e della chiave dell'account: va aperta
    /// con [`Self::open_live`]. Senza la feature `tdlib-runtime` la modalità reale
    /// non è nemmeno disponibile.
    ///
    /// # Errori
    ///
    /// Restituisce un errore quando si chiede la modalità reale (vedere
    /// [`RuntimeMode::Live`]).
    pub fn new(account: &TelegramAccount, mode: RuntimeMode) -> ServiceResult<Self> {
        let connector = build_connector(mode)?;
        Ok(Self::from_parts(
            account.id,
            account.uuid.clone(),
            AuthenticationService::new(connector),
            None,
        ))
    }

    /// Apre il runtime di un account nella modalità scelta dall'operatore.
    ///
    /// È l'unico ingresso che l'interfaccia usa: le passa la modalità e il
    /// livello servizi decide come costruire il connettore, senza che la GUI
    /// conosca TDLib o i segreti.
    ///
    /// - [`RuntimeMode::Mock`]: costruisce il connettore simulato (predefinito).
    /// - [`RuntimeMode::Live`]: con la feature `tdlib-runtime` apre il connettore
    ///   reale ([`Self::open_live`]) con la libreria attesa accanto all'eseguibile;
    ///   senza la feature restituisce un errore chiaro e **non** apre nulla.
    ///
    /// # Errori
    ///
    /// Propaga gli errori tipizzati della modalità richiesta (profilo assente,
    /// libreria non disponibile, feature mancante, …). Nessun messaggio trasporta
    /// un valore riservato.
    pub fn open(
        accounts: &AccountService,
        account: &TelegramAccount,
        mode: RuntimeMode,
        base_dir: &Path,
        authority: &AcquisitionAuthority,
    ) -> ServiceResult<Self> {
        match mode {
            RuntimeMode::Mock => Self::new(account, RuntimeMode::Mock),
            RuntimeMode::Live => open_live_default(accounts, account, base_dir, authority),
        }
    }

    /// Connettore vivo dell'account, riservato agli **altri servizi**.
    ///
    /// È `pub(crate)`: il connettore non attraversa mai l'interfaccia (ADR-0010).
    /// Serve al servizio delle fonti, che deve chiedere all'account quali chat gli
    /// siano accessibili, riusando lo stesso connettore dell'accesso.
    /// Connettore dell'account, per le letture che non passano dagli eventi.
    ///
    /// Era interno finche' l'unico consumatore era l'accesso. Il recupero della
    /// cronologia **interroga** la piattaforma invece di attendere che gli
    /// arrivi qualcosa, e ha bisogno dello stesso connettore: aprirne un secondo
    /// significherebbe una seconda sessione TDLib per lo stesso account.
    ///
    /// Restituisce un oggetto tratto e non un tipo concreto: chi legge la
    /// cronologia non deve sapere se dietro c'e' TDLib o il connettore simulato.
    pub fn connector_mut(&mut self) -> &mut dyn TelegramConnector {
        self.auth.connector_mut()
    }

    /// Chiude il client in modo ordinato, senza uscire dall'account: la
    /// sessione salvata resta, e chi viene dopo la riapre (SERVICE-01,
    /// ADR-0203).
    ///
    /// Serve al passaggio di mano: il servizio e la finestra sono due processi,
    /// e la libreria non apre gli stessi file in due processi insieme.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la chiusura non riesce.
    pub fn close(&mut self) -> ServiceResult<()> {
        self.auth.connector_mut().shutdown()?;
        Ok(())
    }

    /// Crea il runtime attorno a un servizio di autenticazione già costruito.
    ///
    /// È il punto d'iniezione comune al mock e alla modalità reale: `parameters`
    /// è `None` per il mock (che li ignora) e `Some` per il connettore reale, che
    /// li riceverà all'avvio. In prova riceve un servizio costruito su un mock
    /// configurato (per esempio con verifica in due passaggi o codice rifiutato).
    fn from_parts(
        account_id: TelegramAccountId,
        account_uuid: AccountUuid,
        auth: AuthenticationService,
        parameters: Option<ClientParameters>,
    ) -> Self {
        Self {
            account_id,
            auth,
            parameters,
            masked_phone: None,
            account_uuid,
            live_started_at: None,
            live_timeout_diagnosed: false,
            code_wait_started_at: None,
            code_wait_diagnosed: false,
            started: false,
        }
    }

    /// Account a cui il runtime è legato.
    #[must_use]
    pub const fn account_id(&self) -> TelegramAccountId {
        self.account_id
    }

    /// Identità stabile dell'account: è ciò con cui un monitoraggio è legato
    /// al suo account (ADR-0173, migrazione 0072).
    #[must_use]
    pub const fn account_uuid(&self) -> &AccountUuid {
        &self.account_uuid
    }

    /// Stato osservabile dell'accesso, per l'interfaccia e i test.
    #[must_use]
    pub fn view(&self) -> AuthenticationView {
        self.auth.view()
    }

    /// Stato corrente dell'autorizzazione.
    #[must_use]
    pub fn authorization_state(&self) -> AuthorizationState {
        self.auth.state()
    }

    /// Se l'account è collegato e pronto: la condizione di un avvio
    /// programmato (SCHEDULE-01, ADR-0171). L'interfaccia la chiede così,
    /// senza conoscere gli stati del connettore (ADR-0010).
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.auth.state() == AuthorizationState::Ready
    }

    /// Stato di autorizzazione **conservato** corrispondente allo stato corrente.
    #[must_use]
    pub fn persisted_auth_status(&self) -> PersistedAuthStatus {
        persisted_auth(self.auth.state())
    }

    /// Apre il runtime di un account in **modalità reale**, costruendo il
    /// connettore TDLib.
    ///
    /// Compone i pezzi già presenti, senza duplicarne la logica: verifica che il
    /// profilo API esista, carica la libreria, prepara le directory e la chiave
    /// isolate dell'account, decifra le credenziali del profilo e ne costruisce i
    /// [`ClientParameters`], quindi istanzia [`LiveTdlibConnector`] e lo consegna
    /// all'orchestrazione attraverso il confine [`TelegramConnector`].
    ///
    /// **Non apre alcuna sessione né contatta Telegram:** l'avvio effettivo
    /// avviene solo quando il chiamante invoca [`Self::start`]. Disponibile
    /// esclusivamente con la feature `tdlib-runtime`.
    ///
    /// # Ordine e segreti
    ///
    /// La libreria è caricata **prima** di decifrare qualunque credenziale: se
    /// manca, si fallisce senza aver toccato alcun segreto. Le credenziali e la
    /// chiave sono ottenute il più tardi possibile e non sono duplicate in
    /// strutture intermedie: confluiscono direttamente nel costruttore che le
    /// richiede. La chiave in chiaro esce di scope appena il connettore ne ha
    /// preso la forma base64 redatta.
    ///
    /// # Errori
    ///
    /// Restituisce un errore tipizzato se il profilo API non esiste, se la
    /// libreria TDLib non è caricabile, se le directory non sono preparabili, se
    /// le credenziali non sono leggibili o valide, o se la chiave dell'account non
    /// è disponibile. Nessun messaggio trasporta un valore riservato.
    #[cfg(feature = "tdlib-runtime")]
    pub fn open_live(
        accounts: &AccountService,
        account: &TelegramAccount,
        base_dir: &Path,
        config: &LiveRuntimeConfig,
        authority: &AcquisitionAuthority,
    ) -> ServiceResult<Self> {
        // La prova che questa postazione acquisisce da sé (TEAM-AUTHORITY-01,
        // ADR-0092). Non si controlla: si RICHIEDE, e una postazione che segue
        // un Hub non può ottenerla. Il parametro esiste per questo, e il
        // riferimento non serve ad altro.
        let _autorita: &AcquisitionAuthority = authority;
        // Non riceve un `now` dal chiamante (a differenza di `start`/`pump`,
        // che già lo hanno): sintetizzarlo qui evita di far propagare il
        // parametro fino al sito di chiamata in `lisi-app`.
        let timestamp = lisi_core::time::anchored_now();
        let account_uuid = Some(account.uuid.as_str().to_string());

        // Il profilo API selezionato deve esistere: un account valido lo ha per
        // vincolo di schema, ma il controllo rende esplicito e diagnosticabile il
        // caso in cui il profilo sia stato rimosso.
        if let Err(error) = accounts.api_profile(account.profile_id) {
            let category = error.kind();
            return Err(live_error(
                LiveStartupPhase::ApiProfileLoad,
                category,
                "profilo delle credenziali di Telegram non trovato o non leggibile",
                timestamp,
                account_uuid,
            ));
        }

        // La libreria si carica per prima: se manca, si fallisce con un errore
        // chiaro prima di decifrare qualunque segreto. Il percorso è esplicito,
        // mai per nome (ADR-0008). È UNA PER PROCESSO, dietro l'instradatore
        // (MULTI-ACCOUNT-02, ADR-0173): ogni connettore riceve soltanto gli
        // oggetti del proprio client, anche con un account solo.
        let library = match shared_router(&config.library_path) {
            Ok(router) => router.handle(),
            Err(error) => {
                let category = error.kind();
                let (phase, cause) = classify_load_failure(&error);
                return Err(live_error(phase, category, cause, timestamp, account_uuid));
            }
        };

        // Directory isolate dell'account, derivate dall'UUID e mai dal numero.
        let paths = AccountPaths::new(base_dir, &account.uuid);
        if let Err(error) = create_directory(&paths.tdlib_dir) {
            let category = error.kind();
            return Err(live_error(
                LiveStartupPhase::AccountDirectoryPrepare,
                category,
                "impossibile creare le cartelle isolate dell'account",
                timestamp,
                account_uuid,
            ));
        }
        if let Err(error) = create_directory(&paths.files_dir) {
            let category = error.kind();
            return Err(live_error(
                LiveStartupPhase::AccountDirectoryPrepare,
                category,
                "impossibile creare le cartelle isolate dell'account",
                timestamp,
                account_uuid,
            ));
        }

        // Credenziali dell'applicazione, decifrate ora e subito trasferite nei
        // parametri: non restano in una struttura a parte. Se mancano, la
        // persona legge di rivolgersi all'amministratore (ADR-0204).
        let credentials = match load_profile_api_credentials(base_dir, account.profile_id) {
            Ok(credentials) => credentials,
            Err(ServiceError::ApplicationNotConfigured) => {
                return Err(ServiceError::ApplicationNotConfigured);
            }
            Err(error) => {
                let category = error.kind();
                return Err(live_error(
                    LiveStartupPhase::DpapiOpen,
                    category,
                    "credenziali del profilo non decifrabili",
                    timestamp,
                    account_uuid,
                ));
            }
        };
        let parameters = build_client_parameters(credentials, &paths.tdlib_dir, config);

        // Chiave di cifratura del database, distinta per account.
        let key = match ensure_account_key(paths.key_path) {
            Ok(key) => key,
            Err(error) => {
                let category = error.kind();
                return Err(live_error(
                    LiveStartupPhase::DpapiOpen,
                    category,
                    "chiave dell'account non decifrabile",
                    timestamp,
                    account_uuid,
                ));
            }
        };
        let connector: Box<dyn TelegramConnector> =
            Box::new(LiveTdlibConnector::new(library, key.as_base64()));
        // La chiave in chiaro non serve più: il connettore ne conserva solo la
        // forma base64, redatta. La si lascia cadere subito per ridurne la vita.
        drop(key);

        Ok(Self::from_parts(
            account.id,
            account.uuid.clone(),
            AuthenticationService::new(connector),
            Some(parameters),
        ))
    }

    /// Avvia il client e comincia l'accesso, poi persiste lo stato dell'account.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'avvio non è ammesso o fallisce, o se la
    /// persistenza non riesce.
    pub fn start(&mut self, accounts: &AccountService, now: Timestamp) -> ServiceResult<()> {
        let is_live = self.parameters.is_some();

        // Con i parametri reali (modalità Live) si avvia con essi; senza (mock)
        // si usano i segnaposto di `start_configured`, che il mock ignora: il
        // comportamento del mock resta invariato.
        let outcome = match self.parameters.as_ref() {
            Some(parameters) => self.auth.start(parameters),
            None => self.auth.start_configured(),
        };

        match outcome {
            Ok(()) => {
                self.started = true;
                if is_live {
                    self.live_started_at = Some(now);
                    self.live_timeout_diagnosed = false;
                }
            }
            Err(error) => {
                // Solo un guasto del connettore ha una fase di avvio da
                // attribuire: un comando non ammesso, una sessione revocata,
                // una rete assente o un annullamento sono già messaggi
                // corretti e parlanti (`ServiceError::from_kind_of` li
                // conserva fedelmente) e non vanno riscritti in una diagnosi
                // di avvio.
                if !is_live || !matches!(error, ServiceError::Connector(_)) {
                    return Err(error);
                }
                // Il valore restituito da `self.auth.start` può essere una
                // ricostruzione generica priva del testo originale (vedere
                // `ServiceError::from_kind_of`, necessaria perché
                // `ServiceError` non è clonabile): la classificazione legge
                // invece l'errore reale che `AuthenticationService` conserva
                // per la propria vista (`self.auth.failure()`), che porta il
                // testo con cui riconoscere la fase esatta.
                let category = error.kind();
                let (phase, cause) = match self.auth.failure() {
                    Some(ServiceError::Connector(telegram_error)) => {
                        classify_start_failure(telegram_error)
                    }
                    _ => (
                        LiveStartupPhase::ConnectorStart,
                        "avvio del connettore non riuscito",
                    ),
                };
                let diagnosed = live_error(
                    phase,
                    category,
                    cause,
                    now,
                    Some(self.account_uuid.as_str().to_string()),
                );
                // La diagnosi classificata va anche **registrata**, non solo
                // restituita: l'interfaccia scarta il `Result` di questa
                // chiamata e legge il guasto dalla vista (`view().failure`),
                // dove finora restava soltanto l'errore grezzo del
                // connettore, privo della fase. Con il pompaggio che ora si
                // ferma prima dell'avvio, nessun ciclo successivo
                // riclassificherebbe più quell'errore grezzo: senza questa
                // riga un avvio fallito mostrerebbe un messaggio tecnico
                // senza codice `LIVE-E`.
                if let ServiceError::LiveStartup(diagnostic) = &diagnosed {
                    self.auth
                        .record_failure(ServiceError::LiveStartup(diagnostic.clone()));
                }
                return Err(diagnosed);
            }
        }

        self.persist_live_aware(accounts, now)
    }

    /// Ritira gli eventi che [`Self::pump`] ha letto dal connettore e che non
    /// riguardano l'accesso, per consegnarli all'acquisizione.
    ///
    /// Il pompaggio è l'**unico** punto che legge dal connettore: senza questa
    /// consegna esplicita, l'unico modo per acquisire i contenuti sarebbe un
    /// secondo consumatore della stessa coda, cioè una corsa che perde
    /// contenuti in silenzio (vedere `AuthenticationService::pump_events`).
    ///
    /// Ne ritira **al più `max`**: ciò che resta rimane in coda, in ordine,
    /// per la tornata successiva (FINAL-REVIEW-01, FR-001).
    pub fn take_pending_events(&mut self, max: usize) -> Vec<lisi_telegram::ConnectorEvent> {
        self.auth.take_pending_events(max)
    }

    /// Vero se ci sono eventi in attesa di acquisizione.
    #[must_use]
    pub fn has_pending_events(&self) -> bool {
        self.auth.has_pending_events()
    }

    /// Quanti eventi sono stati scartati perché nessuno li ritirava.
    ///
    /// Monotono crescente: serve a poter **dichiarare** una perdita invece di
    /// lasciare un archivio incompleto che nessuno sa essere incompleto.
    #[must_use]
    pub const fn dropped_event_count(&self) -> u64 {
        self.auth.dropped_event_count()
    }

    /// Consuma gli eventi in attesa dal connettore, aggiornando lo stato e
    /// persistendolo se è cambiato.
    ///
    /// Va richiamata **periodicamente** dall'interfaccia finché l'accesso è in
    /// corso: è l'unico modo in cui la modalità reale apprende gli
    /// aggiornamenti di TDLib (parametri richiesti, numero richiesto, codice
    /// richiesto, esito) invece di restare bloccata nello stato in cui
    /// [`Self::start`] l'ha lasciata. Il mock ignora l'attesa e risponde subito
    /// dalla propria coda: chiamarla anche in modalità dimostrativa è innocuo.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la persistenza dello stato cambiato non
    /// riesce. Un guasto nella lettura degli eventi resta invece nello stato
    /// osservabile (`view().failure`), come fa già [`Self::start`].
    pub fn pump(&mut self, accounts: &AccountService, now: Timestamp) -> ServiceResult<()> {
        // Finché l'accesso non è stato avviato non c'è nulla da pompare: il
        // connettore non ha un client, non ha una coda e il suo rifiuto non è
        // un guasto ma la risposta corretta a una domanda prematura.
        // Interrogarlo comunque - come faceva il pompaggio periodico
        // dell'interfaccia, attivo ogni 200 ms già prima che l'operatore
        // prema «Avvia accesso» - produceva un errore grezzo a ogni ciclo, poi
        // classificato come guasto di avvio Live: la diagnosi `LIVE-E015`
        // osservata nel pilot del 2026-07-30 era **falsa**, e descriveva
        // soltanto il fatto che l'accesso non era ancora iniziato.
        if !self.started {
            return Ok(());
        }

        let before = self.auth.state();
        let consumed = self.auth.pump_events()?;
        let is_live = self.parameters.is_some();
        let after = self.auth.state();

        if after != AuthorizationState::Uninitialized {
            // Fase 11: è arrivato un vero progresso, non un fallimento. Annulla
            // il watchdog della fase 10, qualunque fosse il suo stato.
            self.live_started_at = None;
        } else if is_live && let Some(started) = self.live_started_at {
            let already_classified =
                matches!(self.auth.failure(), Some(ServiceError::LiveStartup(_)));
            if !self.live_timeout_diagnosed
                && !already_classified
                && now.millis_since(started) >= FIRST_AUTHORIZATION_STATE_TIMEOUT_MILLIS
            {
                let diagnosed = live_error(
                    LiveStartupPhase::FirstAuthorizationStateWait,
                    "attesa_scaduta_o_nessun_evento",
                    "nessun aggiornamento ricevuto entro il tempo previsto",
                    now,
                    Some(self.account_uuid.as_str().to_string()),
                );
                self.auth.record_failure(diagnosed);
                self.live_timeout_diagnosed = true;
            }
        }

        // Fase 14: attesa di `authorizationStateWaitCode` dopo un invio
        // riuscito del numero (guardiano **distinto** da quello della fase
        // 10 sopra: quello copre l'attesa del primo stato dopo `start()`,
        // questo copre l'attesa che segue l'invio del numero). Allineato
        // deliberatamente alla fase 10: diagnostica **indipendentemente** da
        // `consumed`, non solo quando il pompaggio non ha consegnato nulla.
        // Un `consumed == 0` qui sarebbe stato troppo fragile: se TDLib
        // consegna ripetutamente un aggiornamento non rilevante (per esempio
        // `updateConnectionState`) a ogni tick senza mai portare il codice,
        // il guardiano non sarebbe mai scattato, per quanto a lungo
        // l'operatore restasse bloccato — la stessa lacuna "nessuna
        // diagnosi" che questa fase esiste per colmare (rilievo 3 della
        // revisione indipendente). Per lo stesso motivo la causa tecnica
        // registrata non promette "nessun aggiornamento ricevuto" (che
        // potrebbe essere falso se qualcosa di non rilevante è comunque
        // arrivato): promette solo che il codice non è arrivato.
        if after != AuthorizationState::WaitingForPhoneNumber {
            // Lo stato non è (più) in attesa del codice: o l'accesso è
            // avanzato davvero, o è fallito altrove. In entrambi i casi
            // questo guardiano non ha più motivo di restare armato.
            self.code_wait_started_at = None;
        } else if is_live && let Some(started) = self.code_wait_started_at {
            let already_classified =
                matches!(self.auth.failure(), Some(ServiceError::LiveStartup(_)));
            if !self.code_wait_diagnosed
                && !already_classified
                && now.millis_since(started) >= PHONE_NUMBER_CODE_WAIT_TIMEOUT_MILLIS
            {
                let diagnosed = live_error(
                    LiveStartupPhase::CodeWaitAfterPhoneNumber,
                    "attesa_scaduta_o_nessun_evento",
                    "nessuna richiesta del codice entro il tempo previsto",
                    now,
                    Some(self.account_uuid.as_str().to_string()),
                );
                self.auth.record_failure(diagnosed);
                self.code_wait_diagnosed = true;
            }
        }

        // Riclassifica un guasto grezzo del connettore già registrato da
        // `pump_events` (per esempio l'invio di `setTdlibParameters` non
        // riuscito dentro `handle_authorization`) in una diagnosi di avvio
        // classificata, ma **solo** quando questo pompaggio non ha davvero
        // consegnato alcun aggiornamento (`consumed == 0`): un aggiornamento
        // consegnato - anche un evento di fallimento - contraddice il
        // messaggio "nessun aggiornamento ricevuto dal connettore" e non va
        // mai rietichettato così (incidente del 2026-07-29: il pilot ripetuto
        // ha mostrato lo stesso codice `LIVE-E009` ripetuto a ogni pompaggio
        // anche quando il connettore stava davvero consegnando qualcosa,
        // perché ogni guasto grezzo veniva riscritto senza distinguere i due
        // casi). La fase è scelta guardando lo stato **dopo** il pompaggio
        // (`after`), non quello di prima (`before`): una transizione può
        // essere davvero avvenuta durante questa stessa chiamata anche se
        // l'evento che la annunciava non è stato consegnato (per esempio se
        // l'invio della risposta fallisce subito dopo una transizione interna
        // già avvenuta, come in `LiveTdlibConnector::handle_authorization`) —
        // usare lo stato di prima classificherebbe la fase sbagliata
        // ("sospetto strutturale #2" dell'incidente). Un guasto già parlante
        // (un codice rifiutato, una password rifiutata, una sessione
        // revocata, un annullamento o un'assenza di rete) non passa mai di
        // qui, perché non è un `ServiceError::Connector` grezzo.
        if is_live
            && consumed == 0
            && matches!(
                after,
                AuthorizationState::Uninitialized | AuthorizationState::WaitingForTdlibParameters
            )
        {
            let reclassification = self.auth.failure().and_then(|raw| match raw {
                ServiceError::Connector(telegram_error) => {
                    let category = raw.kind();
                    let (phase, cause) = classify_polling_failure(telegram_error, after);
                    Some((phase, category, cause))
                }
                _ => None,
            });

            if let Some((phase, category, cause)) = reclassification {
                let wrapped = live_error(
                    phase,
                    category,
                    cause,
                    now,
                    Some(self.account_uuid.as_str().to_string()),
                );
                self.auth.record_failure(wrapped);
            }
        }

        if after != before {
            self.persist_live_aware(accounts, now)?;
        }
        Ok(())
    }

    /// Comunica il numero dell'account d'ufficio e ne persiste la forma
    /// mascherata.
    ///
    /// Il numero pieno non è conservato: se ne ricava soltanto la maschera, che
    /// mostra al più le ultime due cifre. L'esposizione del valore in chiaro
    /// avviene qui, una sola volta, per calcolare quella maschera, e non lascia
    /// il metodo.
    ///
    /// In modalità Live, un invio riuscito arma l'attesa di
    /// `authorizationStateWaitCode` (fase 14, [`Self::pump`]); un guasto
    /// grezzo del connettore nell'invio stesso viene invece riclassificato
    /// subito in una diagnosi di avvio Live, sullo stesso modello già usato
    /// da [`Self::start`].
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il comando non è ammesso, se il numero non è
    /// accettato o se la persistenza non riesce.
    pub fn submit_phone_number(
        &mut self,
        phone: PhoneNumber,
        accounts: &AccountService,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let is_live = self.parameters.is_some();
        // Nessun dato riservato in questa traccia: solo la conferma che il
        // percorso numero → codice e' stato imboccato, utile a orientarsi nel
        // registro quando un accesso resta bloccato dopo l'invio del numero.
        tracing::debug!(
            passo = "invio_numero_avviato",
            account = self.account_uuid.as_str(),
            "invio del numero verso il connettore avviato"
        );
        let masked = MaskedPhoneNumber::from_digits(phone.expose_secret());

        if let Err(error) = self.auth.submit_phone_number(phone) {
            // Stesso principio di `Self::start`: solo un guasto grezzo del
            // connettore ha una fase da attribuire. Un comando non ammesso
            // (per esempio inviato mentre l'accesso non è in attesa del
            // numero) è già un messaggio corretto e parlante e non va
            // riscritto in una diagnosi di avvio.
            if !is_live || !matches!(error, ServiceError::Connector(_)) {
                return Err(error);
            }
            // Il valore restituito da `self.auth.submit_phone_number` può
            // essere una ricostruzione generica priva del testo originale
            // (vedere `ServiceError::from_kind_of`, necessaria perché
            // `ServiceError` non è clonabile): per riconoscere un rifiuto già
            // parlante si legge invece l'errore reale che
            // `AuthenticationService` conserva per la propria vista
            // (`self.auth.failure()`), esattamente come fa già `Self::start`.
            // Il caso che conta qui è `UnexpectedAuthorizationState`: la GUI
            // ammette deliberatamente di inviare di nuovo il numero mentre
            // l'accesso attende già il codice (per poter tornare indietro,
            // vedere `crate::auth::AuthenticationService::allowed_commands`),
            // e in quel caso **nessun invio è stato tentato** dal connettore
            // reale (`expect_state` rifiuta prima di comporre la richiesta):
            // riscriverlo come "invio del numero al connettore non riuscito"
            // sarebbe una diagnosi fuorviante, con un'azione suggerita
            // ("riprovare inviando di nuovo il numero") che non potrebbe mai
            // funzionare.
            if matches!(
                self.auth.failure(),
                Some(ServiceError::Connector(
                    TelegramError::UnexpectedAuthorizationState { .. }
                ))
            ) {
                return Err(error);
            }
            let category = error.kind();
            return Err(live_error(
                LiveStartupPhase::CodeWaitAfterPhoneNumber,
                category,
                "invio del numero al connettore non riuscito",
                now,
                Some(self.account_uuid.as_str().to_string()),
            ));
        }

        self.masked_phone = Some(masked);
        if is_live {
            self.code_wait_started_at = Some(now);
            self.code_wait_diagnosed = false;
            tracing::debug!(
                passo = "attesa_codice_avviata",
                account = self.account_uuid.as_str(),
                "attesa di authorizationStateWaitCode avviata"
            );
        }
        self.persist_live_aware(accounts, now)
    }

    /// Comunica il codice ricevuto e persiste lo stato aggiornato.
    ///
    /// Un codice rifiutato **non** avanza l'accesso: l'errore risale al chiamante
    /// e nulla viene persistito come se fosse riuscito.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::CodeRejected`] se il codice non è corretto, o
    /// un errore se il comando non è ammesso o la persistenza non riesce.
    pub fn submit_code(
        &mut self,
        code: LoginCode,
        accounts: &AccountService,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.auth.submit_code(code)?;
        self.persist_live_aware(accounts, now)
    }

    /// Comunica la password della verifica in due passaggi e persiste lo stato.
    ///
    /// Come per il codice, una password rifiutata non dichiara alcun falso
    /// successo: l'errore risale e lo stato resta in attesa della password.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::PasswordRejected`] se la password non è
    /// corretta, o un errore se il comando non è ammesso o la persistenza non
    /// riesce.
    pub fn submit_password(
        &mut self,
        password: TwoFactorPassword,
        accounts: &AccountService,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.auth.submit_password(password)?;
        self.persist_live_aware(accounts, now)
    }

    /// Aggiorna la riga dell'account con lo stato corrente dell'accesso.
    ///
    /// Traduce lo stato fine dell'autorizzazione nelle sintesi conservate
    /// (autorizzazione e connessione) e fissa l'ora dell'ultima connessione solo
    /// quando l'account diventa autorizzato. Il numero mascherato, se noto, viene
    /// scritto; un numero ancora ignoto non cancella quello già conservato.
    fn persist(&self, accounts: &AccountService, now: Timestamp) -> ServiceResult<()> {
        let state = self.auth.state();
        let auth_status = persisted_auth(state);
        let connection_status = persisted_connection(state);
        let connected_at = if auth_status == PersistedAuthStatus::Authorized {
            Some(now)
        } else {
            None
        };
        accounts.record_account_state(
            self.account_id,
            auth_status,
            connection_status,
            self.masked_phone.as_ref(),
            connected_at,
            now,
        )
    }

    /// Persiste lo stato conservato, riclassificando l'errore nella fase 12
    /// **soltanto** in modalità Live.
    ///
    /// Il mock mantiene esattamente lo stesso `ServiceError` che restituisce
    /// oggi: solo con parametri reali (modalità Live) un fallimento della
    /// persistenza diventa una diagnosi [`ServiceError::LiveStartup`].
    fn persist_live_aware(&self, accounts: &AccountService, now: Timestamp) -> ServiceResult<()> {
        match self.persist(accounts, now) {
            Ok(()) => Ok(()),
            Err(error) if self.parameters.is_some() => {
                let category = error.kind();
                Err(live_error(
                    LiveStartupPhase::ServiceUpdate,
                    category,
                    "aggiornamento dello stato conservato non riuscito",
                    now,
                    Some(self.account_uuid.as_str().to_string()),
                ))
            }
            Err(error) => Err(error),
        }
    }
}

/// Costruisce, registra nel registro applicativo e restituisce una diagnosi
/// classificata dell'avvio Live.
///
/// Ogni sito di chiamata passa da qui: così nessuno può dimenticare di
/// registrarla, ed è l'unico punto in cui [`LiveDiagnostic::log`] viene
/// invocato per l'avvio Live.
fn live_error(
    phase: LiveStartupPhase,
    category: &'static str,
    // `&'static str`, non `impl Into<String>`: solo una costante scritta a
    // mano nel sorgente può attraversare questo confine, mai un valore
    // costruito a runtime (per esempio interpolando l'errore sottostante).
    // Il vincolo è verificato dal compilatore, non da una convenzione.
    technical_cause: &'static str,
    timestamp: Timestamp,
    account_uuid: Option<String>,
) -> ServiceError {
    let diagnostic = LiveDiagnostic::new(phase, category, technical_cause, timestamp, account_uuid);
    diagnostic.log();
    ServiceError::LiveStartup(diagnostic)
}

/// Classifica un fallimento del caricamento della libreria TDLib nella fase e
/// nella causa tecnica corrispondenti.
///
/// Funzione pura, collaudabile costruendo direttamente un valore
/// [`TelegramError::Tdlib`]: non serve costruire né caricare una libreria
/// reale, tantomeno una rotta danneggiata di proposito.
// Senza la feature `tdlib-runtime` l'unico chiamante di produzione
// (`AccountRuntime::open_live`) non è compilato, e questa funzione risulta
// morta in una build non di test — ma **non** nei test, che la esercitano in
// ogni configurazione perché è pura e non richiede alcuna libreria. `allow`, e
// non `expect`, proprio per questo: l'aspettativa sarebbe insoddisfatta nella
// build di test. Il warning non era mai emerso perché il quality gate completo
// non veniva eseguito da quando questa funzione è stata introdotta.
#[cfg_attr(not(feature = "tdlib-runtime"), allow(dead_code))]
fn classify_load_failure(error: &TelegramError) -> (LiveStartupPhase, &'static str) {
    if let TelegramError::Tdlib { reason } = error
        && reason.contains("non espone il simbolo")
    {
        return (
            LiveStartupPhase::TdlibSymbolResolve,
            "la libreria caricata non è il componente per Telegram previsto",
        );
    }
    (
        LiveStartupPhase::TdjsonLoad,
        "la libreria non è stata trovata o non è stata caricata",
    )
}

/// Classifica un fallimento dell'avvio del connettore nella fase e nella
/// causa tecnica corrispondenti.
///
/// Funzione pura, collaudabile con valori di [`TelegramError::Tdlib`]
/// costruiti direttamente.
fn classify_start_failure(error: &TelegramError) -> (LiveStartupPhase, &'static str) {
    if let TelegramError::Tdlib { reason } = error {
        if reason.contains("già stato avviato") {
            return (
                LiveStartupPhase::ConnectorStart,
                "il connettore era già stato avviato in precedenza",
            );
        }
        if reason.contains("td_create_client_id") {
            return (
                LiveStartupPhase::ClientCreate,
                "creazione del client Telegram non riuscita",
            );
        }
        // Anche `start()` invia (il risveglio `getOption`): i due soli modi in
        // cui `TdJsonLibrary::send` può fallire vanno distinti qui come in
        // [`classify_polling_failure`], altrimenti un guasto dell'invio
        // resterebbe indistinguibile da qualunque altro guasto d'avvio.
        if reason.contains("byte NUL") {
            return (
                LiveStartupPhase::WakeupNotConfirmed,
                "la richiesta di risveglio contiene un byte NUL e non è una stringa C valida",
            );
        }
        if reason.contains("'td_send' non disponibile") {
            return (
                LiveStartupPhase::WakeupNotConfirmed,
                "simbolo 'td_send' non disponibile nella libreria caricata",
            );
        }
    }
    (
        LiveStartupPhase::ConnectorStart,
        "avvio del connettore non riuscito",
    )
}

/// Classifica un guasto grezzo del connettore rilevato durante il pompaggio
/// (fuori da `start()`, che ha già la propria classificazione in
/// [`classify_start_failure`]) nella fase e nella causa tecnica
/// corrispondenti.
///
/// Distingue esplicitamente, tramite il testo stabile prodotto da
/// `LiveTdlibConnector::poll_event` (vedere
/// `crates/lisi-telegram/src/tdlib/live.rs::LiveTdlibConnector::ensure_woken`),
/// i due guasti strutturali oggi indistinguibili dal generico "nessun
/// aggiornamento ricevuto" — il buco diagnostico più grave rilevato dal pilot
/// Live ripetuto del 2026-07-30 — da quel residuo generico, che resta per un
/// guasto del backend diverso da entrambi (per esempio un errore di ricezione
/// dopo un avvio riuscito).
///
/// Funzione pura, collaudabile con valori di [`TelegramError::Tdlib`]
/// costruiti direttamente: non serve un connettore reale né un pilot.
fn classify_polling_failure(
    error: &TelegramError,
    after: AuthorizationState,
) -> (LiveStartupPhase, &'static str) {
    if let TelegramError::Tdlib { reason } = error {
        if reason.contains("non risulta creato") {
            return (
                LiveStartupPhase::ClientNotCreated,
                "il client Telegram non è mai stato creato",
            );
        }
        if reason.contains("risveglio iniziale non è stato confermato") {
            return (
                LiveStartupPhase::WakeupNotConfirmed,
                "il client è stato creato ma il risveglio non risulta confermato",
            );
        }
        // `TdJsonLibrary::send` (`crates/lisi-telegram/src/tdlib/ffi.rs`) può
        // fallire per **due soli** motivi, entrambi con un testo stabile. La
        // classificazione generica sottostante li appiattiva entrambi in
        // "invio della configurazione al connettore non riuscito", che dice
        // che l'invio è fallito ma non quale dei due sia: il pilot del
        // 2026-07-30 ha mostrato `LIVE-E008` due volte, su due account
        // diversi, senza che il registro permettesse di distinguerli. Il
        // motivo reale esisteva già e veniva scartato dalla riscrittura: è la
        // stessa lacuna, per la terza volta, in cui la fase copre la causa.
        // Le due cause qui sotto restano costanti scritte a mano, senza alcun
        // valore costruito a runtime: nessun payload, nessun percorso,
        // nessun segreto attraversa questo confine.
        if reason.contains("byte NUL") {
            return (
                LiveStartupPhase::TdlibParametersSet,
                "la richiesta di configurazione contiene un byte NUL e non è una stringa C valida",
            );
        }
        if reason.contains("'td_send' non disponibile") {
            return (
                LiveStartupPhase::TdlibParametersSet,
                "simbolo 'td_send' non disponibile nella libreria caricata",
            );
        }
    }
    match after {
        AuthorizationState::WaitingForTdlibParameters => (
            LiveStartupPhase::TdlibParametersSet,
            "invio della configurazione al connettore non riuscito",
        ),
        // Le uniche varianti ammesse dal chiamante: resta solo `Uninitialized`.
        _ => (
            LiveStartupPhase::PollingStart,
            "nessun aggiornamento ricevuto dal connettore",
        ),
    }
}

/// Costruisce il connettore per la modalità indicata.
fn build_connector(mode: RuntimeMode) -> ServiceResult<Box<dyn TelegramConnector>> {
    match mode {
        RuntimeMode::Mock => Ok(Box::new(MockTelegramConnector::new())),
        RuntimeMode::Live => Err(live_mode_unavailable()),
    }
}

/// Errore restituito quando si chiede la modalità reale al costruttore leggero.
///
/// Senza la feature `tdlib-runtime` la build non può in alcun modo collegarsi a
/// Telegram. Con la feature la modalità reale esiste, ma va aperta con
/// [`AccountRuntime::open_live`], che riceve profilo, directory e chiave
/// dell'account: il costruttore leggero non li conosce. In nessuno dei due casi
/// si apre una sessione reale. Il messaggio distingue i due casi senza
/// trasportare alcun dato riservato.
fn live_mode_unavailable() -> ServiceError {
    #[cfg(not(feature = "tdlib-runtime"))]
    let reason = String::from(
        "la modalità Telegram reale non è disponibile in questa build: \
         manca la feature di compilazione «tdlib-runtime»",
    );
    #[cfg(feature = "tdlib-runtime")]
    let reason = String::from(
        "la modalità Telegram reale si apre con AccountRuntime::open_live, \
         che riceve profilo, directory e chiave dell'account",
    );
    ServiceError::SessionUnavailable { reason }
}

/// Apre il runtime reale con la configurazione predefinita, o segnala che non è
/// disponibile.
///
/// Con la feature `tdlib-runtime` compone la libreria attesa accanto
/// all'eseguibile e delega a [`AccountRuntime::open_live`]; senza la feature non
/// tocca nulla e restituisce l'errore chiaro di [`live_mode_unavailable`].
#[cfg(not(feature = "tdlib-runtime"))]
fn open_live_default(
    _accounts: &AccountService,
    _account: &TelegramAccount,
    _base_dir: &Path,
    _authority: &AcquisitionAuthority,
) -> ServiceResult<AccountRuntime> {
    Err(live_mode_unavailable())
}

/// Datacenter Telegram usato dalla modalità reale.
///
/// `false` = **produzione**, l'infrastruttura reale di Telegram. È la
/// configurazione che serve al prodotto: solo lì il codice di accesso viene
/// davvero recapitato all'operatore.
///
/// Fino al 2026-07-30 questo valore era `true` (datacenter di prova), scelto
/// come cautela per un primo pilot controllato. Il quarto pilot ha mostrato il
/// costo di quella cautela una volta dimenticata: sul datacenter di prova
/// l'accesso avanza fino all'attesa del codice e **poi si ferma per sempre**,
/// perché nessun codice viene mai inviato. L'operatore aveva inserito
/// credenziali API e numero reali senza che la scelta gli fosse stata
/// comunicata, e il blocco è stato scambiato per un difetto. Passato a
/// produzione su decisione esplicita dell'operatore (DEC-110).
///
/// È una costante nominata, e non un letterale sepolto in una struttura,
/// proprio perché la scelta sia greppabile, documentata e fissata da un test
/// invece di restare un dettaglio che nessuno rilegge.
#[cfg(feature = "tdlib-runtime")]
const USE_TEST_DATACENTER: bool = false;

#[cfg(feature = "tdlib-runtime")]
fn open_live_default(
    accounts: &AccountService,
    account: &TelegramAccount,
    base_dir: &Path,
    authority: &AcquisitionAuthority,
) -> ServiceResult<AccountRuntime> {
    let library_path = lisi_telegram::tdlib::default_library_path()?;
    let config = LiveRuntimeConfig {
        library_path,
        use_test_datacenter: USE_TEST_DATACENTER,
    };
    AccountRuntime::open_live(accounts, account, base_dir, &config, authority)
}

/// Configurazione **non segreta** per aprire un account in modalità reale.
///
/// Non contiene alcun segreto: solo il percorso **esplicito** della libreria
/// `tdjson` (mai caricata per nome, ADR-0008) e la scelta dell'infrastruttura.
/// API id/hash, numero, codici, password e chiavi non passano di qui.
#[cfg(feature = "tdlib-runtime")]
#[derive(Debug, Clone)]
pub struct LiveRuntimeConfig {
    /// Percorso esplicito della libreria `tdjson` da caricare.
    pub library_path: PathBuf,
    /// Se usare l'infrastruttura di prova invece di quella di produzione.
    pub use_test_datacenter: bool,
}

/// Costruisce i [`ClientParameters`] della modalità reale.
///
/// Le credenziali sono **consumate**: API id e hash si spostano nei parametri
/// senza essere copiati altrove. La directory del database è quella isolata
/// dell'account (derivata dall'UUID). La directory dei file è ricavata dal
/// connettore come sottocartella dedicata, finché `ClientParameters` non
/// espone un campo proprio.
#[cfg(feature = "tdlib-runtime")]
fn build_client_parameters(
    credentials: TelegramCredentials,
    tdlib_dir: &Path,
    config: &LiveRuntimeConfig,
) -> ClientParameters {
    ClientParameters {
        api_id: credentials.api_id,
        api_hash: credentials.api_hash,
        database_directory: tdlib_dir.to_path_buf(),
        use_test_datacenter: config.use_test_datacenter,
        application_version: String::from(APPLICATION_VERSION),
        system_language_code: String::from(SYSTEM_LANGUAGE_CODE),
    }
}

/// Carica le credenziali con cui l'account si presenta a Telegram.
///
/// Le cerca nell'ordine di ADR-0204 decisione 3, con
/// [`crate::app_credentials::load_account_credentials`]: le variabili
/// d'ambiente dello sviluppo, la configurazione dell'applicazione, il vecchio
/// file del profilo.
///
/// # Errori
///
/// Restituisce un errore se l'archivio del profilo non è leggibile o se i valori
/// non sono credenziali valide. Il valore grezzo non compare mai nell'errore.
#[cfg(feature = "tdlib-runtime")]
fn load_profile_api_credentials(
    base_dir: &Path,
    profile_id: ApiCredentialProfileId,
) -> ServiceResult<TelegramCredentials> {
    crate::app_credentials::load_account_credentials(base_dir, profile_id)
}

/// Traduce lo stato fine dell'autorizzazione nella sintesi conservata.
const fn persisted_auth(state: AuthorizationState) -> PersistedAuthStatus {
    match state {
        AuthorizationState::Uninitialized => PersistedAuthStatus::Fresh,
        AuthorizationState::WaitingForTdlibParameters
        | AuthorizationState::WaitingForPhoneNumber
        | AuthorizationState::WaitingForCode
        | AuthorizationState::WaitingForPassword => PersistedAuthStatus::Authorizing,
        AuthorizationState::Ready => PersistedAuthStatus::Authorized,
        AuthorizationState::Closing | AuthorizationState::Closed => PersistedAuthStatus::LoggedOut,
        AuthorizationState::Failed => PersistedAuthStatus::Failed,
    }
}

/// Traduce lo stato fine dell'autorizzazione nella sintesi di connessione
/// conservata (ultimo stato noto, di grana grossa).
const fn persisted_connection(state: AuthorizationState) -> PersistedConnectionStatus {
    match state {
        AuthorizationState::Ready => PersistedConnectionStatus::Connected,
        AuthorizationState::WaitingForTdlibParameters
        | AuthorizationState::WaitingForPhoneNumber
        | AuthorizationState::WaitingForCode
        | AuthorizationState::WaitingForPassword => PersistedConnectionStatus::Connecting,
        AuthorizationState::Closing | AuthorizationState::Closed | AuthorizationState::Failed => {
            PersistedConnectionStatus::Offline
        }
        AuthorizationState::Uninitialized => PersistedConnectionStatus::Unknown,
    }
}

/// Traduce un errore della protezione locale, senza trasportarne alcun dettaglio
/// riservato.
fn map_security_error(error: SecurityError) -> ServiceError {
    ServiceError::SessionUnavailable {
        reason: String::from(error.operator_message()),
    }
}

#[cfg(test)]
mod prove_di_capacita {
    /// Il sorgente di questo modulo, letto a tempo di compilazione.
    const QUESTO_MODULO: &str = include_str!("telegram_runtime.rs");

    /// **La capacita' dichiarata si ricava dal compilatore, non si scrive.**
    ///
    /// Se un giorno qualcuno sostituisse `cfg!` con `true` — per far
    /// funzionare una prova, per fretta, per errore — il prodotto tornerebbe a
    /// promettere una funzione che non ha, e nulla fallirebbe. E' il difetto
    /// che questa costante esiste per impedire, quindi va impedito anche alla
    /// costante stessa.
    ///
    /// Due installer sono gia' stati costruiti senza TDLib senza che nulla lo
    /// dichiarasse.
    #[test]
    fn la_capacita_si_ricava_dalla_feature_e_non_e_scritta_a_mano() {
        let (codice, _) = QUESTO_MODULO
            .split_once("#[cfg(test)]")
            .unwrap_or((QUESTO_MODULO, ""));

        let riga = codice
            .lines()
            .find(|riga| riga.contains("pub const TELEGRAM_RUNTIME_AVAILABLE"))
            .unwrap_or("");

        assert!(
            riga.contains("cfg!(feature = \"tdlib-runtime\")"),
            "la capacita' dichiarata non viene piu' dal compilatore: «{riga}». \
             Scriverla a mano crea una seconda definizione della stessa cosa, \
             che prima o poi dira' il contrario di quella vera"
        );
    }

    /// La ragione da mostrare esiste e non nomina la causa tecnica.
    ///
    /// «Manca una feature di compilazione» e' vero e inutile a chi usa il
    /// prodotto: non gli dice ne' che cosa puo' ancora fare, ne' a chi
    /// rivolgersi.
    #[test]
    fn la_ragione_dice_il_fatto_e_non_la_causa_tecnica() {
        let ragione = super::TELEGRAM_RUNTIME_MISSING_REASON;

        assert!(!ragione.is_empty());
        assert!(
            ragione.contains("dimostrativa"),
            "la ragione deve dire che cosa il prodotto puo' ANCORA fare"
        );
        assert!(
            ragione.contains("Segnalarlo"),
            "la ragione deve dire a chi rivolgersi"
        );
        for tecnicismo in ["feature", "cargo", "tdlib-runtime", "compilazione con"] {
            assert!(
                !ragione.contains(tecnicismo),
                "la ragione mostrata all'operatore nomina «{tecnicismo}», che non \
                 gli serve: la causa tecnica sta nel registro e nei documenti"
            );
        }
    }

    /// **Ogni connettore reale riceve dall'instradatore condiviso, mai dalla
    /// libreria** (MULTI-ACCOUNT-02, ADR-0173, criterio 1; prova negativa: il
    /// connettore costruito sulla libreria caricata → rossa).
    ///
    /// Con la libreria caricata a ogni apertura, ogni connettore chiamerebbe
    /// `td_receive` per conto suo, e con due account il primo potrebbe
    /// ricevere gli oggetti del secondo. La prova dell'instradamento sta in
    /// `lisi-telegram::tdlib::router`; qui si sorveglia che sia la sola strada.
    #[test]
    fn ogni_connettore_reale_riceve_dall_instradatore() {
        let (codice, _) = QUESTO_MODULO
            .split_once("#[cfg(test)]")
            .unwrap_or((QUESTO_MODULO, ""));
        let senza_commenti: String = codice
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            senza_commenti.contains("shared_router(&config.library_path)")
                && senza_commenti.contains("Ok(router) => router.handle(),"),
            "il connettore reale deve nascere da una maniglia dell'instradatore"
        );
        assert!(
            !senza_commenti.contains("TdJsonLibrary::load("),
            "una libreria caricata fuori dall'instradatore riceverebbe per conto suo"
        );
        assert_eq!(
            senza_commenti.matches("LiveTdlibConnector::new(").count(),
            1,
            "un solo punto costruisce il connettore reale"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::time::Duration;

    use lisi_core::model::{
        AccountUuid, NewApiCredentialProfile, NewTelegramAccount, PersistedAuthStatus,
        TelegramAccount,
    };
    use lisi_core::text::DisplayName;
    use lisi_core::{ApiCredentialProfileId, Timestamp};
    use lisi_security::ProtectedStore;
    use lisi_storage::Database;
    use lisi_telegram::{
        AccessibleChat, ApiHash, ApiId, AuthorizationState, ClientParameters, ConnectionState,
        ConnectorEvent, LoginCode, MockTelegramConnector, PhoneNumber, TelegramConnector,
        TelegramError, TelegramResult, TwoFactorPassword,
    };

    use super::{
        AccountPaths, AccountRuntime, LiveStartupPhase, RuntimeMode, classify_load_failure,
        classify_polling_failure, classify_start_failure,
    };
    use crate::accounts::AccountService;
    use crate::acquisition_authority::{AcquisitionAuthority, StationAuthorityService};
    use crate::auth::{AuthCommand, AuthStage, AuthenticationService};
    use crate::error::ServiceError;
    use crate::hub_client::HubConnectionStore;

    // Valori dichiaratamente fittizi: nessun dato reale compare nei test.
    const FAKE_PHONE: &str = "+390612345678";
    const FAKE_CODE: &str = "12345";
    const FAKE_PASSWORD: &str = "password-di-prova-non-reale";

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn label(text: &str) -> DisplayName {
        let Ok(name) = DisplayName::try_new(text) else {
            panic!("l'etichetta di prova deve essere valida");
        };
        name
    }

    fn service() -> AccountService {
        let Ok(database) = Database::open_in_memory() else {
            panic!("il database in memoria deve potersi aprire");
        };
        AccountService::new(database)
    }

    fn seed_profile(service: &AccountService) -> ApiCredentialProfileId {
        let Ok(id) = service.database().insert_api_profile(
            &NewApiCredentialProfile {
                label: label("Profilo ufficio"),
            },
            now(),
        ) else {
            panic!("il profilo di prova deve potersi inserire");
        };
        id
    }

    /// Inserisce un account con UUID fisso, senza passare dal generatore di
    /// sistema: rende i test indipendenti dalla piattaforma.
    fn seed_account(service: &AccountService, byte: u8) -> lisi_core::model::TelegramAccount {
        let profile_id = seed_profile(service);
        let Ok(id) = service.database().insert_telegram_account(
            &NewTelegramAccount {
                uuid: AccountUuid::from_bytes([byte; 16]),
                label: label("Account di prova"),
                profile_id,
            },
            now(),
        ) else {
            panic!("l'account di prova deve potersi inserire");
        };
        let Ok(account) = service.database().telegram_account(id) else {
            panic!("l'account appena inserito deve potersi rileggere");
        };
        account
    }

    fn phone() -> PhoneNumber {
        let Ok(value) = PhoneNumber::try_new(FAKE_PHONE) else {
            panic!("il numero di prova deve essere valido");
        };
        value
    }

    fn code() -> LoginCode {
        let Ok(value) = LoginCode::try_new(FAKE_CODE) else {
            panic!("il codice di prova deve essere valido");
        };
        value
    }

    fn password() -> TwoFactorPassword {
        let Ok(value) = TwoFactorPassword::try_new(FAKE_PASSWORD) else {
            panic!("la password di prova deve essere valida");
        };
        value
    }

    /// Runtime attorno a un connettore mock arbitrario (per configurarne 2FA o
    /// rifiuti prima dell'accesso). Il mock ignora i parametri: `None`.
    fn runtime_with(account: &TelegramAccount, mock: MockTelegramConnector) -> AccountRuntime {
        AccountRuntime::from_parts(
            account.id,
            account.uuid.clone(),
            AuthenticationService::new(Box::new(mock)),
            None,
        )
    }

    /// Runtime "Live-shaped" attorno al connettore di prova [`FakeLiveLikeConnector`]:
    /// passare `Some(parameters)` è ciò che fa trattare il runtime come Live
    /// dalle nuove diagnosi, indipendentemente dal tipo concreto del
    /// connettore (nessuna libreria TDLib è coinvolta).
    fn live_shaped_runtime_with(
        account: &TelegramAccount,
        connector: FakeLiveLikeConnector,
    ) -> AccountRuntime {
        AccountRuntime::from_parts(
            account.id,
            account.uuid.clone(),
            AuthenticationService::new(Box::new(connector)),
            Some(fake_client_parameters()),
        )
    }

    /// Parametri fittizi, sufficienti a far riconoscere il runtime come
    /// "Live-shaped": nessun valore qui è reale né attraversa mai la rete.
    fn fake_client_parameters() -> ClientParameters {
        let (Ok(api_id), Ok(api_hash)) = (
            ApiId::try_new(1),
            ApiHash::try_new("00000000000000000000000000000000"),
        ) else {
            panic!("i parametri fittizi di prova devono essere validi");
        };
        ClientParameters {
            api_id,
            api_hash,
            database_directory: std::path::PathBuf::from("sessione-di-prova"),
            use_test_datacenter: true,
            application_version: String::from("0.0.0-test"),
            system_language_code: String::from("it"),
        }
    }

    /// Connettore di prova che si comporta "come se" fosse Live, per
    /// verificare la classificazione degli errori di avvio senza caricare
    /// TDLib. A differenza di [`MockTelegramConnector`], che avanza da solo
    /// con un proprio automa deterministico, qui ogni evento restituito da
    /// `poll_event` è controllato a mano dal test.
    struct FakeLiveLikeConnector {
        state: AuthorizationState,
        started: bool,
        start_error: Option<TelegramError>,
        /// Se impostato, la **prossima** chiamata a `submit_phone_number`
        /// fallisce con questo errore (una sola volta): riproduce un guasto
        /// grezzo nell'invio del numero, come un fallimento FFI immediato
        /// dentro `LiveTdlibConnector::submit_phone_number`.
        submit_phone_number_error: Option<TelegramError>,
        poll_responses: VecDeque<TelegramResult<Option<ConnectorEvent>>>,
        /// Se impostato, la **prossima** chiamata a `poll_event` porta lo
        /// stato a questo valore prima di restituire la risposta programmata:
        /// riproduce una transizione riuscita "internamente" il cui evento di
        /// conferma non raggiunge però il chiamante (per esempio quando
        /// l'invio della risposta a `authorizationStateWaitTdlibParameters`
        /// fallisce subito dopo la transizione, come in
        /// `LiveTdlibConnector::handle_authorization`).
        silent_transition_before_next_poll: Option<AuthorizationState>,
        /// Se impostato, una volta esaurita `poll_responses` le chiamate
        /// successive continuano a restituire un aggiornamento **non
        /// rilevante** (`ConnectorEvent::Connection`) invece di `Ok(None)`:
        /// riproduce un flusso di aggiornamenti che non fanno mai avanzare lo
        /// stato (rilievo 3 della revisione indipendente sul 2026-07-30).
        deliver_connection_noise_when_exhausted: bool,
    }

    impl FakeLiveLikeConnector {
        fn new() -> Self {
            Self {
                state: AuthorizationState::Uninitialized,
                started: false,
                start_error: None,
                submit_phone_number_error: None,
                poll_responses: VecDeque::new(),
                silent_transition_before_next_poll: None,
                deliver_connection_noise_when_exhausted: false,
            }
        }

        /// Fa fallire la **prossima** chiamata a `start()` con l'errore
        /// indicato (una sola volta: dopo, si comporta come se fosse
        /// riuscita).
        fn failing_start(mut self, error: TelegramError) -> Self {
            self.start_error = Some(error);
            self
        }

        /// Fa fallire la **prossima** chiamata a `submit_phone_number` con
        /// l'errore indicato (una sola volta).
        fn failing_submit_phone_number(mut self, error: TelegramError) -> Self {
            self.submit_phone_number_error = Some(error);
            self
        }

        /// Programma le risposte restituite da `poll_event`, nell'ordine
        /// indicato; esaurita la coda, risponde `Ok(None)` indefinitamente.
        fn with_poll_responses(
            mut self,
            responses: Vec<TelegramResult<Option<ConnectorEvent>>>,
        ) -> Self {
            self.poll_responses = responses.into_iter().collect();
            self
        }

        /// Vedere il campo [`Self::silent_transition_before_next_poll`].
        fn with_silent_transition_before_next_poll(mut self, state: AuthorizationState) -> Self {
            self.silent_transition_before_next_poll = Some(state);
            self
        }

        /// Vedere il campo [`Self::deliver_connection_noise_when_exhausted`].
        fn delivering_connection_noise_once_exhausted(mut self) -> Self {
            self.deliver_connection_noise_when_exhausted = true;
            self
        }
    }

    impl TelegramConnector for FakeLiveLikeConnector {
        fn start(&mut self, _parameters: &ClientParameters) -> TelegramResult<()> {
            // Rispecchia `LiveTdlibConnector::start`: una seconda chiamata a
            // connettore già avviato fallisce con lo stesso testo, e la
            // macchina di autorizzazione resta `Uninitialized` fino al primo
            // aggiornamento consegnato da `poll_event` (mai qui).
            if self.started {
                return Err(TelegramError::Tdlib {
                    reason: String::from("il connettore e' gia' stato avviato"),
                });
            }
            if let Some(error) = self.start_error.take() {
                return Err(error);
            }
            self.started = true;
            Ok(())
        }

        fn submit_phone_number(&mut self, _phone: &PhoneNumber) -> TelegramResult<()> {
            if let Some(error) = self.submit_phone_number_error.take() {
                return Err(error);
            }
            // Rispecchia `LiveTdlibConnector::submit_phone_number`: fuori
            // dallo stato atteso il connettore rifiuta con
            // `UnexpectedAuthorizationState`, senza tentare alcun invio. Sul
            // fittizio originario (che accettava sempre) il rilievo 2 della
            // revisione indipendente non sarebbe stato riproducibile: un
            // secondo invio del numero mentre l'accesso attende già il
            // codice (ammesso deliberatamente dalla GUI, vedere
            // `crate::auth::AuthenticationService::allowed_commands`) andava
            // sempre a buon fine qui, mascherando la misclassificazione.
            if self.state != AuthorizationState::WaitingForPhoneNumber {
                return Err(TelegramError::UnexpectedAuthorizationState {
                    state: self.state.as_str(),
                    expected: AuthorizationState::WaitingForPhoneNumber.as_str(),
                });
            }
            Ok(())
        }

        fn submit_code(&mut self, _code: &LoginCode) -> TelegramResult<()> {
            Ok(())
        }

        fn submit_password(&mut self, _password: &TwoFactorPassword) -> TelegramResult<()> {
            Ok(())
        }

        fn poll_event(&mut self, _timeout: Duration) -> TelegramResult<Option<ConnectorEvent>> {
            // Rispecchia `LiveTdlibConnector::poll_event`, che rifiuta con
            // questo testo esatto finché non esiste un client. Il doppio non
            // lo faceva, e per questo il pompaggio prematuro dell'interfaccia
            // (prima che l'operatore avvii l'accesso) non era osservabile in
            // prova: nel pilot del 2026-07-30 produceva `LIVE-E015`, una
            // diagnosi falsa. È la stessa asimmetria doppio/reale già
            // registrata due volte in `PROJECT_STATUS.md`: un doppio più
            // indulgente del connettore vero misura solo se stesso.
            if !self.started {
                return Err(TelegramError::Tdlib {
                    reason: String::from("il connettore non e' stato avviato"),
                });
            }
            if let Some(state) = self.silent_transition_before_next_poll.take() {
                self.state = state;
            }
            match self.poll_responses.pop_front() {
                Some(Ok(Some(ConnectorEvent::Authorization(new_state)))) => {
                    self.state = new_state;
                    Ok(Some(ConnectorEvent::Authorization(new_state)))
                }
                Some(other) => other,
                None if self.deliver_connection_noise_when_exhausted => {
                    Ok(Some(ConnectorEvent::Connection(ConnectionState::Online)))
                }
                None => Ok(None),
            }
        }

        fn accessible_chats(&mut self) -> TelegramResult<Vec<AccessibleChat>> {
            Ok(Vec::new())
        }

        fn authorization_state(&self) -> AuthorizationState {
            self.state
        }

        fn connection_state(&self) -> ConnectionState {
            ConnectionState::Offline
        }

        fn shutdown(&mut self) -> TelegramResult<()> {
            self.state = AuthorizationState::Closed;
            Ok(())
        }

        /// I doppi di prova non parlano con Telegram: nessun collegamento.
        fn message_link(
            &mut self,
            _chat_id: lisi_telegram::ChatId,
            _message_id: lisi_telegram::MessageId,
        ) -> lisi_telegram::TelegramResult<lisi_telegram::LinkOutcome> {
            Ok(lisi_telegram::LinkOutcome::NotProvided(
                lisi_telegram::LinkGap::ConnectorUnavailable,
            ))
        }

        /// I doppi di prova non parlano con Telegram: nessun contesto.
        fn fetch_context(
            &mut self,
            _chat_id: lisi_telegram::ChatId,
            _around: lisi_telegram::MessageId,
            _before: u32,
            _after: u32,
        ) -> lisi_telegram::TelegramResult<Vec<lisi_telegram::ContextMessage>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn the_nominal_mock_login_reaches_authorized_and_is_persisted() {
        let service = service();
        let account = seed_account(&service, 0x11);

        let Ok(mut runtime) = AccountRuntime::new(&account, RuntimeMode::Mock) else {
            panic!("il runtime mock deve potersi creare");
        };

        let Ok(()) = runtime.start(&service, now()) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = runtime.submit_phone_number(phone(), &service, now()) else {
            panic!("l'invio del numero deve riuscire");
        };
        let Ok(()) = runtime.submit_code(code(), &service, now()) else {
            panic!("l'invio del codice deve riuscire");
        };

        assert_eq!(runtime.authorization_state(), AuthorizationState::Ready);
        assert_eq!(
            runtime.persisted_auth_status(),
            PersistedAuthStatus::Authorized
        );

        let Ok(stored) = service.database().telegram_account(account.id) else {
            panic!("l'account deve potersi rileggere");
        };
        assert_eq!(stored.auth_status, PersistedAuthStatus::Authorized);
        assert!(
            stored.masked_phone.is_some(),
            "dopo l'accesso il numero mascherato e' conservato"
        );
        assert!(
            stored.last_connected_at.is_some(),
            "l'ora dell'ultima connessione e' fissata all'autorizzazione"
        );
    }

    /// **Un account che cade non ferma gli altri, e non ne prende gli eventi**
    /// (MULTI-ACCOUNT-02 parte 2, DEC-441). A perde la rete mentre B riceve
    /// un messaggio: il guasto resta nello stato di A, B resta pronto e il
    /// messaggio è soltanto fra gli eventi di B.
    #[test]
    fn un_account_che_cade_non_ferma_gli_altri() {
        let service = service();
        let (account_a, account_b) = (seed_account(&service, 0xa1), seed_account(&service, 0xb2));
        let mut caduta = MockTelegramConnector::new();
        caduta.plan_failure(TelegramError::NetworkUnavailable);
        let mut runtime_a = runtime_with(&account_a, caduta);
        let mut con_messaggio = MockTelegramConnector::new();
        let Ok(()) = con_messaggio.enqueue_message(-1_001, 7, "una molotov", 1_800_000_000_000)
        else {
            panic!("il messaggio si accoda");
        };
        let mut runtime_b = runtime_with(&account_b, con_messaggio);
        for runtime in [&mut runtime_a, &mut runtime_b] {
            let Ok(()) = runtime.start(&service, now()) else {
                panic!("l'avvio deve riuscire");
            };
            let Ok(()) = runtime.submit_phone_number(phone(), &service, now()) else {
                panic!("l'invio del numero deve riuscire");
            };
            let Ok(()) = runtime.submit_code(code(), &service, now()) else {
                panic!("l'invio del codice deve riuscire");
            };
        }
        let esito_a = runtime_a.pump(&service, now());
        let Ok(()) = runtime_b.pump(&service, now()) else {
            panic!("il pompaggio di B non dipende da A");
        };
        assert!(
            esito_a.is_err() || runtime_a.view().failure.is_some(),
            "il guasto di A si vede, in A"
        );
        assert!(runtime_b.is_ready(), "B resta pronto");
        assert!(
            runtime_b.view().failure.is_none(),
            "il guasto di A non è di B"
        );
        let di_b = runtime_b.take_pending_events(usize::MAX);
        assert!(
            di_b.iter()
                .any(|evento| matches!(evento, lisi_telegram::ConnectorEvent::MessageReceived(_))),
            "il messaggio è fra gli eventi di B: {di_b:?}"
        );
        assert!(
            !runtime_a
                .take_pending_events(usize::MAX)
                .iter()
                .any(|evento| matches!(evento, lisi_telegram::ConnectorEvent::MessageReceived(_))),
            "A non riceve il messaggio di B"
        );
    }

    /// Regressione — incidente M3B del 2026-07-26: `main.rs` deve poter
    /// richiamare `pump` periodicamente su qualunque runtime, mock o reale,
    /// senza che questo fallisca o richieda un evento gia' pronto. Il mock
    /// avanza gia' da solo dentro `start`/`submit_*`; il pompaggio qui non
    /// deve fare nulla di dannoso.
    #[test]
    fn pumping_a_mock_runtime_after_start_is_harmless() {
        let service = service();
        let account = seed_account(&service, 0x77);
        let Ok(mut runtime) = AccountRuntime::new(&account, RuntimeMode::Mock) else {
            panic!("il runtime mock deve potersi creare");
        };

        let Ok(()) = runtime.start(&service, now()) else {
            panic!("l'avvio deve riuscire");
        };

        assert!(runtime.pump(&service, now()).is_ok());
    }

    #[test]
    fn the_login_with_two_factor_reaches_authorized() {
        let service = service();
        let account = seed_account(&service, 0x22);
        let mock = MockTelegramConnector::new().requiring_two_factor(true);
        let mut runtime = runtime_with(&account, mock);

        let (Ok(()), Ok(()), Ok(())) = (
            runtime.start(&service, now()),
            runtime.submit_phone_number(phone(), &service, now()),
            runtime.submit_code(code(), &service, now()),
        ) else {
            panic!("i passi fino alla richiesta della password devono riuscire");
        };
        assert_eq!(
            runtime.authorization_state(),
            AuthorizationState::WaitingForPassword
        );

        let Ok(()) = runtime.submit_password(password(), &service, now()) else {
            panic!("l'invio della password deve riuscire");
        };
        assert_eq!(
            runtime.persisted_auth_status(),
            PersistedAuthStatus::Authorized
        );
        assert_eq!(
            service
                .database()
                .telegram_account(account.id)
                .map(|a| a.auth_status)
                .ok(),
            Some(PersistedAuthStatus::Authorized)
        );
    }

    #[test]
    fn a_rejected_code_does_not_claim_success() {
        let service = service();
        let account = seed_account(&service, 0x33);
        let mut mock = MockTelegramConnector::new();
        mock.reject_next_codes(1);
        let mut runtime = runtime_with(&account, mock);

        let (Ok(()), Ok(())) = (
            runtime.start(&service, now()),
            runtime.submit_phone_number(phone(), &service, now()),
        ) else {
            panic!("l'avvio e l'invio del numero devono riuscire");
        };

        assert!(
            matches!(
                runtime.submit_code(code(), &service, now()),
                Err(ServiceError::CodeRejected)
            ),
            "un codice sbagliato deve risalire come rifiuto"
        );
        // L'accesso resta in attesa del codice: nessun falso successo.
        assert_eq!(
            runtime.authorization_state(),
            AuthorizationState::WaitingForCode
        );
        assert_ne!(
            service
                .database()
                .telegram_account(account.id)
                .map(|a| a.auth_status)
                .ok(),
            Some(PersistedAuthStatus::Authorized)
        );

        // Il codice corretto, subito dopo, conclude l'accesso.
        let Ok(()) = runtime.submit_code(code(), &service, now()) else {
            panic!("il codice corretto deve riuscire");
        };
        assert_eq!(runtime.authorization_state(), AuthorizationState::Ready);
    }

    #[test]
    fn a_rejected_two_factor_password_does_not_claim_success() {
        let service = service();
        let account = seed_account(&service, 0x44);
        let mut mock = MockTelegramConnector::new().requiring_two_factor(true);
        mock.reject_next_passwords(1);
        let mut runtime = runtime_with(&account, mock);

        let (Ok(()), Ok(()), Ok(())) = (
            runtime.start(&service, now()),
            runtime.submit_phone_number(phone(), &service, now()),
            runtime.submit_code(code(), &service, now()),
        ) else {
            panic!("i passi fino alla richiesta della password devono riuscire");
        };

        assert!(
            matches!(
                runtime.submit_password(password(), &service, now()),
                Err(ServiceError::PasswordRejected)
            ),
            "una password sbagliata deve risalire come rifiuto"
        );
        assert_eq!(
            runtime.authorization_state(),
            AuthorizationState::WaitingForPassword
        );

        let Ok(()) = runtime.submit_password(password(), &service, now()) else {
            panic!("la password corretta deve riuscire");
        };
        assert_eq!(runtime.authorization_state(), AuthorizationState::Ready);
    }

    #[test]
    fn requesting_live_mode_through_the_lightweight_constructor_errors_clearly() {
        let service = service();
        let account = seed_account(&service, 0x55);

        // Il costruttore leggero non conosce profilo, directory e chiave: la
        // modalita' reale non si apre di qui, in nessuna configurazione.
        let outcome = AccountRuntime::new(&account, RuntimeMode::Live);
        assert!(outcome.is_err(), "la modalita' reale non deve aprire nulla");

        let Err(ServiceError::SessionUnavailable { reason }) = outcome else {
            panic!("l'errore deve essere una sessione non disponibile");
        };
        // Il messaggio spiega perche', senza trasportare alcun segreto: senza la
        // feature dichiara che manca, con la feature indirizza a `open_live`.
        #[cfg(not(feature = "tdlib-runtime"))]
        assert!(reason.contains("tdlib-runtime"));
        #[cfg(feature = "tdlib-runtime")]
        assert!(reason.contains("open_live"));
    }

    /// L'autorità di acquisire, ottenuta come la ottiene il prodotto: da una
    /// postazione che **non ha un Hub configurato** (TEAM-AUTHORITY-01, ADR-0092).
    ///
    /// Non è una scorciatoia per le prove: `AcquisitionAuthority` non ha un
    /// costruttore pubblico, e questa funzione passa dal percorso vero.
    pub(super) fn autorita(cartella: &tempfile::TempDir) -> AcquisitionAuthority {
        let servizio = StationAuthorityService::new(HubConnectionStore::at(ProtectedStore::at(
            cartella.path().join("hub-client.protetto"),
        )));
        let Ok(esito) = servizio.acquisition_authority(&crate::run_mode::operational_for_tests())
        else {
            panic!("l'esito dell'autorità deve esserci");
        };
        let Some(autorita) = esito.into_granted() else {
            panic!("una postazione senza Hub configurato deve poter acquisire");
        };
        autorita
    }

    /// Una cartella temporanea che vive quanto la prova.
    pub(super) fn cartella_di_prova() -> tempfile::TempDir {
        match tempfile::tempdir() {
            Ok(cartella) => cartella,
            Err(errore) => panic!("cartella temporanea: {errore}"),
        }
    }

    #[test]
    fn open_builds_a_mock_runtime_by_default() {
        let service = service();
        let account = seed_account(&service, 0x5a);
        let base = std::path::Path::new("base");
        let cartella = cartella_di_prova();
        let autorita = autorita(&cartella);

        let Ok(mut runtime) =
            AccountRuntime::open(&service, &account, RuntimeMode::Mock, base, &autorita)
        else {
            panic!("la modalita' mock deve costruire un runtime");
        };
        // È davvero un mock: percorre l'accesso senza rete fino ad autorizzato.
        let (Ok(()), Ok(()), Ok(())) = (
            runtime.start(&service, now()),
            runtime.submit_phone_number(phone(), &service, now()),
            runtime.submit_code(code(), &service, now()),
        ) else {
            panic!("il ciclo mock deve riuscire");
        };
        assert_eq!(runtime.authorization_state(), AuthorizationState::Ready);
    }

    #[cfg(not(feature = "tdlib-runtime"))]
    #[test]
    fn open_in_live_mode_without_the_feature_is_a_clear_error() {
        let service = service();
        let account = seed_account(&service, 0x5b);
        let base = std::path::Path::new("base");

        let cartella = cartella_di_prova();
        let autorita = autorita(&cartella);

        let Err(ServiceError::SessionUnavailable { reason }) =
            AccountRuntime::open(&service, &account, RuntimeMode::Live, base, &autorita)
        else {
            panic!("la modalita' reale senza feature deve dare un errore chiaro");
        };
        assert!(reason.contains("tdlib-runtime"));
    }

    #[test]
    fn two_accounts_get_isolated_directories_and_key_paths() {
        let base = std::path::Path::new("cartella-base");
        let first = AccountPaths::new(base, &AccountUuid::from_bytes([0x01; 16]));
        let second = AccountPaths::new(base, &AccountUuid::from_bytes([0x02; 16]));

        assert_ne!(first.root, second.root);
        assert_ne!(first.tdlib_dir, second.tdlib_dir);
        assert_ne!(first.files_dir, second.files_dir);
        assert_ne!(first.key_path, second.key_path);

        // Le sottocartelle di uno stanno sotto la sua radice, non condivise.
        assert!(first.tdlib_dir.starts_with(&first.root));
        assert!(first.files_dir.starts_with(&first.root));
        assert!(!second.root.starts_with(&first.root));
    }

    #[test]
    fn account_paths_never_contain_the_phone_number() {
        let uuid = AccountUuid::from_bytes([0xab; 16]);
        let paths = AccountPaths::new(std::path::Path::new("base"), &uuid);

        for path in [
            &paths.root,
            &paths.tdlib_dir,
            &paths.files_dir,
            &paths.key_path,
        ] {
            let text = path.to_string_lossy();
            assert!(text.contains(uuid.as_str()), "il percorso porta l'UUID");
            // Nessuna delle cifre del numero fittizio compare nel percorso.
            for fragment in ["0612345678", "612345678", "12345678", "345678"] {
                assert!(
                    !text.contains(fragment),
                    "il percorso '{text}' non deve contenere il numero"
                );
            }
        }
    }

    #[test]
    fn the_masked_phone_persisted_reveals_at_most_the_last_two_digits() {
        let service = service();
        let account = seed_account(&service, 0x66);
        let Ok(mut runtime) = AccountRuntime::new(&account, RuntimeMode::Mock) else {
            panic!("il runtime mock deve potersi creare");
        };

        let (Ok(()), Ok(())) = (
            runtime.start(&service, now()),
            runtime.submit_phone_number(phone(), &service, now()),
        ) else {
            panic!("l'avvio e l'invio del numero devono riuscire");
        };

        let Ok(stored) = service.database().telegram_account(account.id) else {
            panic!("l'account deve potersi rileggere");
        };
        let Some(masked) = stored.masked_phone else {
            panic!("il numero mascherato deve essere conservato");
        };
        let visible = masked.as_str().chars().filter(char::is_ascii_digit).count();
        assert!(
            visible <= 2,
            "al piu' le ultime due cifre restano in chiaro"
        );
        assert!(!masked.as_str().contains("612345"), "il corpo non compare");
    }

    #[test]
    fn the_debug_rendering_of_the_runtime_hides_the_phone_number() {
        let service = service();
        let account = seed_account(&service, 0x77);
        let Ok(mut runtime) = AccountRuntime::new(&account, RuntimeMode::Mock) else {
            panic!("il runtime mock deve potersi creare");
        };

        let (Ok(()), Ok(())) = (
            runtime.start(&service, now()),
            runtime.submit_phone_number(phone(), &service, now()),
        ) else {
            panic!("l'avvio e l'invio del numero devono riuscire");
        };

        let rendered = format!("{runtime:?}");
        assert!(
            !rendered.contains("612345678"),
            "la resa Debug non deve contenere il numero in chiaro"
        );
    }

    #[test]
    fn the_persisted_state_survives_reopening_the_database() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let path = directory.path().join("stato.db");

        let account_id = {
            let Ok(database) = Database::open(&path) else {
                panic!("il database su file deve potersi aprire");
            };
            let service = AccountService::new(database);
            let account = seed_account(&service, 0x88);

            let Ok(mut runtime) = AccountRuntime::new(&account, RuntimeMode::Mock) else {
                panic!("il runtime mock deve potersi creare");
            };
            let (Ok(()), Ok(()), Ok(())) = (
                runtime.start(&service, now()),
                runtime.submit_phone_number(phone(), &service, now()),
                runtime.submit_code(code(), &service, now()),
            ) else {
                panic!("il ciclo di accesso deve riuscire");
            };
            account.id
            // Il servizio (e quindi il database) viene chiuso qui.
        };

        // Riaperto il database, lo stato dell'account resta autorizzato.
        let Ok(reopened) = Database::open(&path) else {
            panic!("il database deve potersi riaprire");
        };
        let Ok(account) = reopened.telegram_account(account_id) else {
            panic!("l'account deve potersi rileggere dopo la riapertura");
        };
        assert_eq!(account.auth_status, PersistedAuthStatus::Authorized);
        assert!(account.masked_phone.is_some());
    }

    #[test]
    fn preparing_storage_fails_clearly_when_a_directory_cannot_be_created() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        // Un file al posto della cartella «accounts» impedisce di creare le
        // sottocartelle dell'account: la preparazione deve fallire con chiarezza,
        // prima ancora di toccare la chiave.
        let blocker = directory.path().join("accounts");
        if std::fs::write(&blocker, b"non una cartella").is_err() {
            panic!("il file di blocco deve potersi scrivere");
        }

        let uuid = AccountUuid::from_bytes([0x99; 16]);
        assert!(
            matches!(
                super::prepare_account_storage(directory.path(), &uuid),
                Err(ServiceError::SessionUnavailable { .. })
            ),
            "una cartella non creabile deve dare un errore chiaro"
        );
    }

    // --- Classificatori puri (nessuna feature richiesta) ---------------

    #[test]
    fn classify_load_failure_recognises_a_missing_symbol_as_the_symbol_resolve_phase() {
        let error = TelegramError::Tdlib {
            reason: String::from(
                "la libreria non espone il simbolo 'td_create_client_id': \
                 non sembra una tdjson compatibile",
            ),
        };
        let (phase, _cause) = classify_load_failure(&error);
        assert_eq!(phase, LiveStartupPhase::TdlibSymbolResolve);
    }

    #[test]
    fn classify_load_failure_treats_any_other_reason_as_the_library_missing_phase() {
        let error = TelegramError::Tdlib {
            reason: String::from("la libreria non esiste al percorso indicato: x"),
        };
        let (phase, _cause) = classify_load_failure(&error);
        assert_eq!(phase, LiveStartupPhase::TdjsonLoad);
    }

    #[test]
    fn classify_start_failure_recognises_an_already_started_connector() {
        // Testo reale prodotto da `LiveTdlibConnector::start` (vedere
        // `crates/lisi-telegram/src/tdlib/live.rs`): un test con un testo
        // diverso da quello davvero emesso non avrebbe potuto accorgersi che
        // il riconoscimento non scattava mai in pratica.
        let error = TelegramError::Tdlib {
            reason: String::from("il connettore è già stato avviato"),
        };
        let (phase, cause) = classify_start_failure(&error);
        assert_eq!(phase, LiveStartupPhase::ConnectorStart);
        assert_eq!(
            cause, "il connettore era già stato avviato in precedenza",
            "la causa deve distinguere il riavvio dal fallimento generico, \
             non solo la fase"
        );
    }

    #[test]
    fn classify_start_failure_recognises_a_client_creation_failure() {
        let error = TelegramError::Tdlib {
            reason: String::from("simbolo 'td_create_client_id' non disponibile: prova"),
        };
        let (phase, _cause) = classify_start_failure(&error);
        assert_eq!(phase, LiveStartupPhase::ClientCreate);
    }

    #[test]
    fn classify_start_failure_falls_back_to_connector_start_for_anything_else() {
        let error = TelegramError::Tdlib {
            reason: String::from("guasto imprevisto di prova"),
        };
        let (phase, _cause) = classify_start_failure(&error);
        assert_eq!(phase, LiveStartupPhase::ConnectorStart);
    }

    // --- Classificatore del pompaggio (nessuna feature richiesta) -------

    /// Testo reale prodotto da `LiveTdlibConnector::ensure_woken` (vedere
    /// `crates/lisi-telegram/src/tdlib/live.rs`) quando il client non è mai
    /// stato creato: un test con un testo diverso da quello davvero emesso
    /// non si sarebbe accorto che il riconoscimento non scattava mai in
    /// pratica.
    #[test]
    fn classify_polling_failure_recognises_a_client_never_created() {
        let error = TelegramError::Tdlib {
            reason: String::from(
                "il client non risulta creato: il connettore non e' mai stato avviato",
            ),
        };
        let (phase, _cause) = classify_polling_failure(&error, AuthorizationState::Uninitialized);
        assert_eq!(phase, LiveStartupPhase::ClientNotCreated);
    }

    /// I due soli modi in cui `TdJsonLibrary::send` può fallire devono
    /// arrivare all'operatore **distinti**, non appiattiti nel generico
    /// "invio della configurazione al connettore non riuscito": nel pilot del
    /// 2026-07-30 `LIVE-E008` è comparso due volte senza che il registro
    /// permettesse di sapere quale dei due fosse. I testi confrontati qui
    /// sono quelli **reali** prodotti da
    /// `crates/lisi-telegram/src/tdlib/ffi.rs::TdJsonLibrary::send`: se
    /// cambiassero là senza cambiare qui, questi test lo rivelerebbero.
    #[test]
    fn the_two_send_failures_are_never_flattened_into_the_same_cause() {
        let nul = TelegramError::Tdlib {
            reason: String::from("la richiesta contiene un byte NUL e non e' una stringa C valida"),
        };
        let missing_symbol = TelegramError::Tdlib {
            reason: String::from(
                "simbolo 'td_send' non disponibile: impossibile risolvere il simbolo",
            ),
        };
        let generic = TelegramError::Tdlib {
            reason: String::from("un guasto qualunque, non riconducibile all'invio"),
        };

        let state = AuthorizationState::WaitingForTdlibParameters;
        let (nul_phase, nul_cause) = classify_polling_failure(&nul, state);
        let (symbol_phase, symbol_cause) = classify_polling_failure(&missing_symbol, state);
        let (generic_phase, generic_cause) = classify_polling_failure(&generic, state);

        // Stessa fase - il guasto avviene davvero nell'invio della
        // configurazione - ma tre cause distinte, altrimenti la diagnosi non
        // aggiunge nulla a quella che avevamo.
        assert_eq!(nul_phase, LiveStartupPhase::TdlibParametersSet);
        assert_eq!(symbol_phase, LiveStartupPhase::TdlibParametersSet);
        assert_eq!(generic_phase, LiveStartupPhase::TdlibParametersSet);
        assert_ne!(nul_cause, symbol_cause);
        assert_ne!(nul_cause, generic_cause);
        assert_ne!(symbol_cause, generic_cause);
        assert!(symbol_cause.contains("td_send"));
        assert!(nul_cause.contains("NUL"));

        // Lo stesso vale per un guasto dell'invio dentro `start()` (il
        // risveglio), che prima finiva nel generico "avvio del connettore non
        // riuscito".
        let (start_symbol_phase, start_symbol_cause) = classify_start_failure(&missing_symbol);
        let (start_generic_phase, start_generic_cause) = classify_start_failure(&generic);
        assert_eq!(start_symbol_phase, LiveStartupPhase::WakeupNotConfirmed);
        assert_eq!(start_generic_phase, LiveStartupPhase::ConnectorStart);
        assert_ne!(start_symbol_cause, start_generic_cause);
    }

    /// Nessuna delle cause introdotte deve trasportare un valore costruito a
    /// runtime: il vincolo è già imposto dal tipo (`&'static str`), ma il
    /// testo dell'errore reale contiene un dettaglio della libreria che non
    /// deve comparire nella causa mostrata all'operatore.
    #[test]
    fn the_send_failure_causes_never_carry_the_underlying_library_detail() {
        let missing_symbol = TelegramError::Tdlib {
            reason: String::from(
                "simbolo 'td_send' non disponibile: C:\\percorso\\riservato\\tdjson.dll",
            ),
        };
        let (_phase, cause) = classify_polling_failure(
            &missing_symbol,
            AuthorizationState::WaitingForTdlibParameters,
        );
        assert!(
            !cause.contains("percorso"),
            "la causa non deve riportare il dettaglio della libreria: {cause}"
        );
    }

    #[test]
    fn classify_polling_failure_recognises_an_unconfirmed_wake_up() {
        let error = TelegramError::Tdlib {
            reason: String::from(
                "il client è stato creato ma il risveglio iniziale non è stato confermato",
            ),
        };
        let (phase, _cause) = classify_polling_failure(&error, AuthorizationState::Uninitialized);
        assert_eq!(phase, LiveStartupPhase::WakeupNotConfirmed);
    }

    #[test]
    fn classify_polling_failure_falls_back_by_the_state_reached_for_anything_else() {
        let error = TelegramError::Tdlib {
            reason: String::from("guasto grezzo di prova"),
        };
        assert_eq!(
            classify_polling_failure(&error, AuthorizationState::Uninitialized).0,
            LiveStartupPhase::PollingStart
        );
        assert_eq!(
            classify_polling_failure(&error, AuthorizationState::WaitingForTdlibParameters).0,
            LiveStartupPhase::TdlibParametersSet
        );
    }

    // --- Integrazione con il connettore "Live-shaped" di prova ----------

    #[test]
    fn a_start_failure_in_live_mode_is_reported_with_the_classified_phase() {
        let service = service();
        let account = seed_account(&service, 0xA1);
        let fake = FakeLiveLikeConnector::new().failing_start(TelegramError::Tdlib {
            reason: String::from("simbolo 'td_create_client_id' non disponibile: prova"),
        });
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let Err(error) = runtime.start(&service, now()) else {
            panic!("l'avvio deve fallire");
        };
        let ServiceError::LiveStartup(diagnostic) = error else {
            panic!("l'errore deve essere una diagnosi classificata dell'avvio Live");
        };
        assert_eq!(diagnostic.phase(), LiveStartupPhase::ClientCreate);
    }

    #[test]
    fn a_second_start_in_live_mode_is_reported_as_an_already_started_connector() {
        let service = service();
        let account = seed_account(&service, 0xA2);
        let fake = FakeLiveLikeConnector::new();
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let Ok(()) = runtime.start(&service, now()) else {
            panic!("il primo avvio deve riuscire");
        };
        // Lo stato resta `Uninitialized` finché `pump` non consegna il primo
        // aggiornamento (rispecchia `LiveTdlibConnector::start`): un secondo
        // avvio resta quindi ammesso e raggiunge di nuovo il connettore.
        let Err(error) = runtime.start(&service, now()) else {
            panic!("il secondo avvio deve fallire");
        };
        let ServiceError::LiveStartup(diagnostic) = error else {
            panic!("l'errore deve essere una diagnosi classificata dell'avvio Live");
        };
        assert_eq!(diagnostic.phase(), LiveStartupPhase::ConnectorStart);
    }

    #[test]
    fn pumping_a_live_shaped_runtime_that_was_never_started_does_not_panic() {
        let service = service();
        let account = seed_account(&service, 0xA3);
        let fake = FakeLiveLikeConnector::new();
        let mut runtime = live_shaped_runtime_with(&account, fake);

        // Nessun `start()` è stato chiamato: il pompaggio non deve fare nulla
        // di dannoso e non deve fallire.
        assert!(runtime.pump(&service, now()).is_ok());
        assert!(runtime.auth.failure().is_none());
    }

    /// Regressione diretta del pilot del 2026-07-30: l'interfaccia pompa ogni
    /// 200 ms **già prima** che l'operatore prema «Avvia accesso». Su un
    /// account in modalità reale, ogni pompaggio interrogava un connettore
    /// mai avviato, ne raccoglieva il rifiuto e lo classificava come guasto
    /// di avvio — `LIVE-E015`, «client Telegram non creato»: una diagnosi
    /// **falsa**, che descriveva soltanto un accesso non ancora iniziato.
    /// Il collegamento con l'acquisizione: fino al 2026-07-30 il pompaggio
    /// **buttava via** tutto cio' che non riguardava l'accesso, e
    /// `AcquisitionService` - pur costruito e collaudato - non era chiamato da
    /// nessuna parte. Un contenuto in arrivo non poteva quindi raggiungere
    /// l'archivio in alcun modo.
    ///
    /// Farlo leggere direttamente all'acquisizione avrebbe creato **due**
    /// consumatori della stessa coda, ciascuno cieco a cio' che interessa
    /// all'altro (`AcquisitionService::drain` scarta gli eventi di
    /// autorizzazione): una corsa che perde contenuti in silenzio. Il
    /// pompaggio resta percio' l'unico lettore, e consegna cio' che non usa.
    #[test]
    fn the_events_that_do_not_concern_the_login_survive_the_pump_for_acquisition() {
        let service = service();
        let account = seed_account(&service, 0xC1);
        let fake = FakeLiveLikeConnector::new().with_poll_responses(vec![
            Ok(Some(ConnectorEvent::Connection(ConnectionState::Online))),
            Ok(Some(ConnectorEvent::Authorization(
                AuthorizationState::WaitingForPhoneNumber,
            ))),
            Ok(Some(ConnectorEvent::Connection(
                ConnectionState::Interrupted,
            ))),
            Ok(None),
        ]);
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let t0 = Timestamp::from_millis(3_000_000);
        let Ok(()) = runtime.start(&service, t0) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = runtime.pump(&service, t0.plus_seconds(1)) else {
            panic!("il pompaggio non deve fallire");
        };

        let pending = runtime.take_pending_events(usize::MAX);
        assert_eq!(
            pending.len(),
            2,
            "i due eventi di connessione devono essere consegnati all'acquisizione: {pending:?}"
        );
        assert!(
            pending
                .iter()
                .all(|event| !matches!(event, ConnectorEvent::Authorization(_))),
            "l'autorizzazione la gestisce il servizio d'accesso, non l'acquisizione"
        );
        // Ma l'evento di autorizzazione ha comunque fatto avanzare lo stato:
        // consegnare il resto non toglie nulla al percorso d'accesso.
        assert_eq!(
            runtime.view().state,
            AuthorizationState::WaitingForPhoneNumber
        );
        assert!(
            runtime.take_pending_events(usize::MAX).is_empty(),
            "un secondo ritiro non deve restituire gli stessi eventi"
        );
        assert_eq!(
            runtime.dropped_event_count(),
            0,
            "nessuna perdita con la coda ampiamente sotto il tetto"
        );
    }

    /// Molti pompaggi prima dell'avvio non devono produrre alcuna diagnosi.
    #[test]
    fn pumping_before_the_login_is_started_never_produces_a_startup_diagnosis() {
        let service = service();
        let account = seed_account(&service, 0xB7);
        let fake = FakeLiveLikeConnector::new();
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let t0 = Timestamp::from_millis(2_000_000);
        for tick in 0..50 {
            let Ok(()) = runtime.pump(&service, t0.plus_seconds(tick)) else {
                panic!("il pompaggio prima dell'avvio non deve fallire");
            };
            assert!(
                runtime.auth.failure().is_none(),
                "un accesso non ancora avviato non e' un guasto: {:?}",
                runtime.auth.failure()
            );
        }

        // Dopo un avvio riuscito il pompaggio torna a interrogare davvero il
        // connettore: la guardia sospende il pompaggio, non lo disattiva.
        let Ok(()) = runtime.start(&service, t0) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = runtime.pump(&service, t0.plus_seconds(1)) else {
            panic!("il pompaggio dopo l'avvio non deve fallire");
        };
    }

    /// Un avvio Live fallito deve lasciare la **diagnosi classificata** nella
    /// vista che l'interfaccia mostra, non il solo errore grezzo del
    /// connettore: l'interfaccia scarta il `Result` di `start` e legge
    /// `view().failure`. Prima, la fase arrivava lì solo di rimbalzo, quando
    /// un pompaggio successivo riclassificava l'errore grezzo — cosa che ora
    /// non accade più, perché il pompaggio si ferma finché l'avvio non
    /// riesce.
    #[test]
    fn a_failed_live_start_leaves_the_classified_diagnosis_in_the_view() {
        let service = service();
        let account = seed_account(&service, 0xB8);
        let fake = FakeLiveLikeConnector::new().failing_start(TelegramError::Tdlib {
            reason: String::from("il connettore non e' stato avviato"),
        });
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let Err(_) = runtime.start(&service, now()) else {
            panic!("l'avvio deve fallire");
        };
        let Some(ServiceError::LiveStartup(diagnostic)) = runtime.auth.failure() else {
            panic!(
                "la vista deve portare la diagnosi classificata: {:?}",
                runtime.auth.failure()
            );
        };
        assert!(
            diagnostic.code().starts_with("LIVE-E0"),
            "la diagnosi deve avere un codice stabile"
        );
    }

    #[test]
    fn no_authorization_state_within_the_timeout_produces_the_watchdog_diagnosis_once() {
        let service = service();
        let account = seed_account(&service, 0xA4);
        let fake = FakeLiveLikeConnector::new();
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let t0 = Timestamp::from_millis(1_000_000);
        let Ok(()) = runtime.start(&service, t0) else {
            panic!("l'avvio deve riuscire");
        };

        // Prima della scadenza: nessuna diagnosi.
        let Ok(()) = runtime.pump(&service, t0.plus_seconds(5)) else {
            panic!("il pompaggio non deve fallire");
        };
        assert!(runtime.auth.failure().is_none());
        assert!(!runtime.live_timeout_diagnosed);

        // Dopo la scadenza: la diagnosi compare, una sola volta.
        let after_timeout = t0.plus_seconds(21);
        let Ok(()) = runtime.pump(&service, after_timeout) else {
            panic!("il pompaggio non deve fallire");
        };
        assert!(runtime.live_timeout_diagnosed);
        let Some(ServiceError::LiveStartup(diagnostic)) = runtime.auth.failure() else {
            panic!("deve esserci una diagnosi classificata");
        };
        assert_eq!(
            diagnostic.phase(),
            LiveStartupPhase::FirstAuthorizationStateWait
        );

        // Pompaggi successivi non la duplicano: il guardiano resta acceso e
        // non tenta una nuova diagnosi.
        let Ok(()) = runtime.pump(&service, after_timeout.plus_seconds(5)) else {
            panic!("il pompaggio non deve fallire");
        };
        assert!(runtime.live_timeout_diagnosed);
    }

    #[test]
    fn receiving_the_first_authorization_state_cancels_the_watchdog() {
        let service = service();
        let account = seed_account(&service, 0xA5);
        let fake = FakeLiveLikeConnector::new().with_poll_responses(vec![Ok(Some(
            ConnectorEvent::Authorization(AuthorizationState::WaitingForTdlibParameters),
        ))]);
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let t0 = Timestamp::from_millis(2_000_000);
        let Ok(()) = runtime.start(&service, t0) else {
            panic!("l'avvio deve riuscire");
        };

        // Il primo pompaggio consegna l'evento di autorizzazione: il
        // guardiano viene annullato, non diagnosticato.
        let Ok(()) = runtime.pump(&service, t0.plus_seconds(1)) else {
            panic!("il pompaggio non deve fallire");
        };
        assert!(runtime.live_started_at.is_none());
        assert!(runtime.auth.failure().is_none());

        // Anche ben oltre la scadenza, nessuna diagnosi compare: il
        // progresso ricevuto era reale.
        let Ok(()) = runtime.pump(&service, t0.plus_seconds(30)) else {
            panic!("il pompaggio non deve fallire");
        };
        assert!(runtime.auth.failure().is_none());
    }

    #[test]
    fn a_raw_polling_failure_in_live_mode_is_reclassified_as_the_polling_start_phase() {
        let service = service();
        let account = seed_account(&service, 0xA6);
        let fake =
            FakeLiveLikeConnector::new().with_poll_responses(vec![Err(TelegramError::Tdlib {
                reason: String::from("prova di guasto grezzo"),
            })]);
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let Ok(()) = runtime.start(&service, now()) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = runtime.pump(&service, now()) else {
            panic!("il pompaggio non deve fallire");
        };

        let Some(ServiceError::LiveStartup(diagnostic)) = runtime.auth.failure() else {
            panic!("il guasto grezzo deve essere riclassificato");
        };
        assert_eq!(diagnostic.phase(), LiveStartupPhase::PollingStart);
    }

    /// Regressione — la riclassificazione deve toccare **solo** un guasto
    /// grezzo del connettore, mai un rifiuto già parlante come un codice
    /// sbagliato: prima della correzione, qualunque guasto non ancora
    /// classificato (compreso `CodeRejected`) veniva riscritto come
    /// `LIVE-E009` entro un pompaggio, cancellando il messaggio corretto che
    /// l'operatore avrebbe dovuto leggere.
    #[test]
    fn a_rejected_code_in_live_mode_is_not_rewritten_as_a_startup_diagnosis() {
        let service = service();
        let account = seed_account(&service, 0xA7);
        let fake = FakeLiveLikeConnector::new().with_poll_responses(vec![
            Ok(Some(ConnectorEvent::Authorization(
                AuthorizationState::WaitingForCode,
            ))),
            Ok(Some(ConnectorEvent::Failure(TelegramError::CodeRejected))),
        ]);
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let Ok(()) = runtime.start(&service, now()) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = runtime.pump(&service, now()) else {
            panic!("il pompaggio non deve fallire");
        };

        assert!(
            matches!(runtime.auth.failure(), Some(ServiceError::CodeRejected)),
            "un codice rifiutato non deve diventare una diagnosi di avvio Live: {:?}",
            runtime.auth.failure()
        );
    }

    /// Regressione — un comando non ammesso (per esempio un secondo `start()`
    /// ad account già autorizzato) non deve mai diventare una diagnosi di
    /// avvio Live: prima della correzione, `start()` classificava **ogni**
    /// errore in modalità Live, non solo quelli del connettore.
    #[test]
    fn a_command_not_allowed_error_in_live_mode_is_not_rewritten_as_a_startup_diagnosis() {
        let service = service();
        let account = seed_account(&service, 0xA8);
        let fake = FakeLiveLikeConnector::new().with_poll_responses(vec![Ok(Some(
            ConnectorEvent::Authorization(AuthorizationState::Ready),
        ))]);
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let Ok(()) = runtime.start(&service, now()) else {
            panic!("il primo avvio deve riuscire");
        };
        let Ok(()) = runtime.pump(&service, now()) else {
            panic!("il pompaggio non deve fallire");
        };
        assert_eq!(runtime.authorization_state(), AuthorizationState::Ready);

        let Err(error) = runtime.start(&service, now()) else {
            panic!("un secondo avvio ad account già autorizzato deve essere rifiutato");
        };
        assert!(
            matches!(error, ServiceError::CommandNotAllowed { .. }),
            "un comando non ammesso non deve diventare una diagnosi di avvio Live: {error:?}"
        );
    }

    /// Regressione — il guardiano dell'attesa (fase 10) non deve sovrascrivere
    /// una diagnosi già classificata da un guasto grezzo precedente: prima
    /// della correzione, un guasto del polling classificato come
    /// `PollingStart` veniva rimpiazzato da `FirstAuthorizationStateWait` non
    /// appena scadeva il tempo massimo, perdendo l'informazione più precisa.
    #[test]
    fn the_timeout_watchdog_does_not_overwrite_an_already_classified_diagnosis() {
        let service = service();
        let account = seed_account(&service, 0xA9);
        let fake =
            FakeLiveLikeConnector::new().with_poll_responses(vec![Err(TelegramError::Tdlib {
                reason: String::from("prova di guasto grezzo"),
            })]);
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let t0 = Timestamp::from_millis(3_000_000);
        let Ok(()) = runtime.start(&service, t0) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = runtime.pump(&service, t0.plus_seconds(1)) else {
            panic!("il pompaggio non deve fallire");
        };
        let Some(ServiceError::LiveStartup(diagnostic)) = runtime.auth.failure() else {
            panic!("il guasto grezzo deve essere riclassificato");
        };
        assert_eq!(diagnostic.phase(), LiveStartupPhase::PollingStart);

        // Ben oltre la scadenza del guardiano: la diagnosi già classificata
        // non deve essere sovrascritta da quella generica dell'attesa.
        let Ok(()) = runtime.pump(&service, t0.plus_seconds(30)) else {
            panic!("il pompaggio non deve fallire");
        };
        let Some(ServiceError::LiveStartup(diagnostic)) = runtime.auth.failure() else {
            panic!("la diagnosi classificata deve restare");
        };
        assert_eq!(
            diagnostic.phase(),
            LiveStartupPhase::PollingStart,
            "il guardiano dell'attesa non deve sovrascrivere una diagnosi già classificata"
        );
    }

    /// "Corrispondenza fra codice diagnostico e fase" a livello di
    /// `telegram_runtime`: percorre tre siti di chiamata reali (creazione del
    /// client, attesa del primo stato di autorizzazione, riclassificazione di
    /// un guasto grezzo del polling) e verifica che il `kind()` restituito da
    /// `ServiceError` combaci sempre con il codice della fase riportata.
    #[test]
    fn the_diagnostic_code_matches_the_reported_phase_across_the_real_call_paths() {
        let service = service();

        let account_client_create = seed_account(&service, 0xB1);
        let fake_client_create = FakeLiveLikeConnector::new().failing_start(TelegramError::Tdlib {
            reason: String::from("simbolo 'td_create_client_id' non disponibile: prova"),
        });
        let mut runtime_client_create =
            live_shaped_runtime_with(&account_client_create, fake_client_create);
        let Err(error_client_create) = runtime_client_create.start(&service, now()) else {
            panic!("l'avvio deve fallire");
        };
        assert_eq!(
            error_client_create.kind(),
            LiveStartupPhase::ClientCreate.diagnostic_code()
        );

        let account_timeout = seed_account(&service, 0xB2);
        let fake_timeout = FakeLiveLikeConnector::new();
        let mut runtime_timeout = live_shaped_runtime_with(&account_timeout, fake_timeout);
        let t0 = now();
        let Ok(()) = runtime_timeout.start(&service, t0) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = runtime_timeout.pump(&service, t0.plus_seconds(25)) else {
            panic!("il pompaggio non deve fallire");
        };
        let Some(ServiceError::LiveStartup(diagnostic_timeout)) = runtime_timeout.auth.failure()
        else {
            panic!("deve esserci una diagnosi classificata");
        };
        assert_eq!(
            diagnostic_timeout.code(),
            LiveStartupPhase::FirstAuthorizationStateWait.diagnostic_code()
        );

        let account_polling = seed_account(&service, 0xB3);
        let fake_polling =
            FakeLiveLikeConnector::new().with_poll_responses(vec![Err(TelegramError::Tdlib {
                reason: String::from("prova di guasto grezzo"),
            })]);
        let mut runtime_polling = live_shaped_runtime_with(&account_polling, fake_polling);
        let Ok(()) = runtime_polling.start(&service, now()) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = runtime_polling.pump(&service, now()) else {
            panic!("il pompaggio non deve fallire");
        };
        let Some(ServiceError::LiveStartup(diagnostic_polling)) = runtime_polling.auth.failure()
        else {
            panic!("deve esserci una diagnosi classificata");
        };
        assert_eq!(
            diagnostic_polling.code(),
            LiveStartupPhase::PollingStart.diagnostic_code()
        );
    }

    /// Regressione — incidente del 2026-07-29 (pilot ripetuto con la
    /// diagnostica in campo): un evento di fallimento **davvero consegnato**
    /// dal connettore (un update è arrivato) non deve mai essere rietichettato
    /// come "nessun aggiornamento ricevuto dal connettore": prima della
    /// correzione, qualunque guasto grezzo del connettore veniva riscritto
    /// come `PollingStart` non appena l'accesso restava a `Uninitialized`,
    /// anche quando un aggiornamento era stato consegnato (un evento di
    /// fallimento è pur sempre un evento ricevuto), producendo un messaggio
    /// falso.
    #[test]
    fn a_failure_event_that_was_actually_delivered_is_not_relabeled_as_no_update_received() {
        let service = service();
        let account = seed_account(&service, 0xAA);
        let fake = FakeLiveLikeConnector::new().with_poll_responses(vec![Ok(Some(
            ConnectorEvent::Failure(TelegramError::Tdlib {
                reason: String::from("errore TDLib 400: evento di fallimento di prova"),
            }),
        ))]);
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let Ok(()) = runtime.start(&service, now()) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = runtime.pump(&service, now()) else {
            panic!("il pompaggio non deve fallire");
        };

        assert!(
            matches!(runtime.auth.failure(), Some(ServiceError::Connector(_))),
            "un fallimento davvero consegnato non deve diventare una diagnosi di \
             'nessun aggiornamento ricevuto': {:?}",
            runtime.auth.failure()
        );
    }

    /// Regressione — la stessa correzione, ma su più pompaggi separati: un
    /// evento di fallimento fresco consegnato a **ogni** tentativo (come
    /// osservato nel registro del pilot: lo stesso codice `LIVE-E009` ripetuto
    /// a ogni tentativo per circa cinque secondi) non deve produrre una nuova
    /// diagnosi di avvio a ogni pompaggio: resta il guasto grezzo del
    /// connettore, non travestito da una fase che nega il fatto stesso che
    /// qualcosa sia stato ricevuto.
    #[test]
    fn repeated_failure_events_across_separate_pumps_are_never_relabeled_as_no_update_received() {
        let service = service();
        let account = seed_account(&service, 0xAB);
        let fake = FakeLiveLikeConnector::new().with_poll_responses(vec![
            Ok(Some(ConnectorEvent::Failure(TelegramError::Tdlib {
                reason: String::from("prova 1"),
            }))),
            Ok(None),
            Ok(Some(ConnectorEvent::Failure(TelegramError::Tdlib {
                reason: String::from("prova 2"),
            }))),
            Ok(None),
            Ok(Some(ConnectorEvent::Failure(TelegramError::Tdlib {
                reason: String::from("prova 3"),
            }))),
        ]);
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let Ok(()) = runtime.start(&service, now()) else {
            panic!("l'avvio deve riuscire");
        };

        for tentativo in 1..=3 {
            let Ok(()) = runtime.pump(&service, now()) else {
                panic!("il pompaggio {tentativo} non deve fallire");
            };
            assert!(
                matches!(runtime.auth.failure(), Some(ServiceError::Connector(_))),
                "il pompaggio {tentativo} non deve produrre una diagnosi di avvio: {:?}",
                runtime.auth.failure()
            );
        }
    }

    /// Regressione — "sospetto strutturale #2" dell'incidente del
    /// 2026-07-29: una transizione può essere davvero avvenuta "dentro" un
    /// pompaggio anche se l'evento che la annunciava non è arrivato al
    /// chiamante (per esempio perché l'invio della risposta a
    /// `authorizationStateWaitTdlibParameters` fallisce subito dopo la
    /// transizione, come corretto in
    /// `LiveTdlibConnector::handle_authorization`). La riclassificazione deve
    /// guardare lo stato **dopo** il pompaggio, non quello di prima:
    /// altrimenti etichetterebbe "nessun aggiornamento ricevuto" (fase 9,
    /// `PollingStart`) un guasto avvenuto invece in fase 8
    /// (`TdlibParametersSet`), nascondendo il punto reale del fallimento.
    #[test]
    fn a_failure_right_after_an_undelivered_internal_transition_is_classified_by_the_state_it_actually_reached()
     {
        let service = service();
        let account = seed_account(&service, 0xAC);
        let fake = FakeLiveLikeConnector::new()
            .with_silent_transition_before_next_poll(AuthorizationState::WaitingForTdlibParameters)
            .with_poll_responses(vec![Err(TelegramError::Tdlib {
                reason: String::from("invio dei parametri non riuscito (prova)"),
            })]);
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let Ok(()) = runtime.start(&service, now()) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = runtime.pump(&service, now()) else {
            panic!("il pompaggio non deve fallire");
        };

        assert_eq!(
            runtime.authorization_state(),
            AuthorizationState::WaitingForTdlibParameters,
            "la transizione interna deve restare visibile anche se l'evento non e' arrivato"
        );
        let Some(ServiceError::LiveStartup(diagnostic)) = runtime.auth.failure() else {
            panic!("il guasto grezzo deve essere riclassificato");
        };
        assert_eq!(
            diagnostic.phase(),
            LiveStartupPhase::TdlibParametersSet,
            "la fase deve riflettere lo stato realmente raggiunto, non quello prima del pompaggio"
        );
    }

    /// Regressione diretta del sintomo del pilot Live ripetuto (2026-07-30):
    /// `LIVE-E009` ripetuto ogni ~200ms per alcuni secondi. Un guasto grezzo
    /// del connettore restituito **identico a ogni pompaggio** (qui: il
    /// client non risulta mai creato, come accade quando `poll_event` viene
    /// interrogato senza che l'avvio sia mai riuscito) non deve produrre una
    /// nuova diagnosi — e quindi un nuovo registro — a ogni ciclo: al più una
    /// sola diagnosi, che resta la stessa (istante di prima classificazione
    /// compreso) finché la condizione non cambia davvero. Usare istanti
    /// diversi per ogni pompaggio è essenziale: prima della correzione,
    /// ognuno avrebbe costruito una nuova diagnosi con il proprio istante,
    /// diversa dalle precedenti anche a parità di fase.
    #[test]
    fn a_persistently_repeating_raw_polling_failure_is_diagnosed_at_most_once() {
        let service = service();
        let account = seed_account(&service, 0xC1);
        let responses = (0..5)
            .map(|_| {
                Err(TelegramError::Tdlib {
                    reason: String::from("guasto grezzo persistente di prova"),
                })
            })
            .collect();
        let fake = FakeLiveLikeConnector::new().with_poll_responses(responses);
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let t0 = Timestamp::from_millis(10_000_000);
        let Ok(()) = runtime.start(&service, t0) else {
            panic!("l'avvio deve riuscire");
        };

        let instants = [
            t0.plus_seconds(1),
            t0.plus_seconds(2),
            t0.plus_seconds(3),
            t0.plus_seconds(4),
            t0.plus_seconds(5),
        ];
        let mut first_diagnostic: Option<crate::live_diagnostics::LiveDiagnostic> = None;
        for (index, instant) in instants.into_iter().enumerate() {
            let tentativo = index + 1;
            let Ok(()) = runtime.pump(&service, instant) else {
                panic!("il pompaggio {tentativo} non deve fallire");
            };
            let Some(ServiceError::LiveStartup(diagnostic)) = runtime.auth.failure() else {
                panic!(
                    "il pompaggio {tentativo} deve mostrare una diagnosi classificata, \
                     non quella grezza: {:?}",
                    runtime.auth.failure()
                );
            };
            match &first_diagnostic {
                None => first_diagnostic = Some(diagnostic.clone()),
                Some(first) => assert_eq!(
                    diagnostic, first,
                    "il pompaggio {tentativo} non deve produrre una nuova diagnosi \
                     (istante compreso): il guasto grezzo e' lo stesso di prima"
                ),
            }
        }
    }

    // --- Percorso numero → codice (fase 14, LIVE-E014) ------------------

    /// Un guasto grezzo del connettore nell'invio del numero (per esempio un
    /// fallimento FFI immediato dentro
    /// `LiveTdlibConnector::submit_phone_number`) deve risalire come diagnosi
    /// classificata dell'avvio Live, sullo stesso modello già usato da
    /// `Self::start`.
    #[test]
    fn a_phone_number_submission_failure_in_live_mode_is_reported_with_the_classified_phase() {
        let service = service();
        let account = seed_account(&service, 0xAD);
        let fake = FakeLiveLikeConnector::new()
            .with_poll_responses(vec![Ok(Some(ConnectorEvent::Authorization(
                AuthorizationState::WaitingForPhoneNumber,
            )))])
            .failing_submit_phone_number(TelegramError::Tdlib {
                reason: String::from("prova di guasto grezzo nell'invio del numero"),
            });
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let Ok(()) = runtime.start(&service, now()) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = runtime.pump(&service, now()) else {
            panic!("il pompaggio non deve fallire");
        };
        assert_eq!(
            runtime.authorization_state(),
            AuthorizationState::WaitingForPhoneNumber
        );

        let Err(error) = runtime.submit_phone_number(phone(), &service, now()) else {
            panic!("l'invio del numero deve fallire");
        };
        let ServiceError::LiveStartup(diagnostic) = error else {
            panic!("l'errore deve essere una diagnosi classificata dell'avvio Live");
        };
        assert_eq!(
            diagnostic.phase(),
            LiveStartupPhase::CodeWaitAfterPhoneNumber
        );
        // Il numero resta non consegnato: nessuna maschera è stata salvata.
        let Ok(stored) = service.database().telegram_account(account.id) else {
            panic!("l'account deve potersi rileggere");
        };
        assert!(
            stored.masked_phone.is_none(),
            "un invio fallito non deve lasciare una maschera del numero"
        );
    }

    /// Un rifiuto già parlante (comando non ammesso, per esempio inviare il
    /// numero mentre l'accesso non lo sta attendendo) non deve mai diventare
    /// una diagnosi di avvio Live: stessa regressione già coperta per
    /// `Self::start` in `a_command_not_allowed_error_in_live_mode_is_not_rewritten_as_a_startup_diagnosis`.
    #[test]
    fn a_command_not_allowed_phone_number_submission_is_not_rewritten_as_a_startup_diagnosis() {
        let service = service();
        let account = seed_account(&service, 0xB4);
        let fake = FakeLiveLikeConnector::new();
        let mut runtime = live_shaped_runtime_with(&account, fake);

        // Mai avviato: lo stato resta `Uninitialized`, non
        // `WaitingForPhoneNumber`. Il numero non deve essere ammesso.
        let Err(error) = runtime.submit_phone_number(phone(), &service, now()) else {
            panic!("l'invio del numero deve essere rifiutato fuori dallo stato atteso");
        };
        assert!(
            matches!(error, ServiceError::CommandNotAllowed { .. }),
            "un comando non ammesso non deve diventare una diagnosi di avvio Live: {error:?}"
        );
    }

    /// Regressione — rilievo 2 della revisione indipendente: la GUI ammette
    /// deliberatamente di inviare di nuovo il numero mentre l'accesso attende
    /// già il codice, per poter tornare indietro (vedere
    /// `crate::auth::AuthenticationService::allowed_commands`,
    /// `AuthorizationState::WaitingForCode`). In quel caso il connettore
    /// reale rifiuta con `UnexpectedAuthorizationState`, **senza aver
    /// tentato alcun invio**: non deve diventare una diagnosi `LIVE-E014`
    /// ("invio del numero al connettore non riuscito", con l'azione
    /// "riprovare inviando di nuovo il numero", che non potrebbe mai
    /// funzionare in questo caso).
    #[test]
    fn resubmitting_the_phone_number_while_waiting_for_the_code_is_not_rewritten_as_a_startup_diagnosis()
     {
        let service = service();
        let account = seed_account(&service, 0xBB);
        let fake = FakeLiveLikeConnector::new().with_poll_responses(vec![
            Ok(Some(ConnectorEvent::Authorization(
                AuthorizationState::WaitingForPhoneNumber,
            ))),
            Ok(None),
            Ok(Some(ConnectorEvent::Authorization(
                AuthorizationState::WaitingForCode,
            ))),
        ]);
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let Ok(()) = runtime.start(&service, now()) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = runtime.pump(&service, now()) else {
            panic!("il pompaggio non deve fallire");
        };
        let Ok(()) = runtime.submit_phone_number(phone(), &service, now()) else {
            panic!("il primo invio del numero deve riuscire");
        };
        let Ok(()) = runtime.pump(&service, now()) else {
            panic!("il pompaggio non deve fallire");
        };
        assert_eq!(
            runtime.authorization_state(),
            AuthorizationState::WaitingForCode,
            "l'accesso deve attendere ora il codice"
        );

        // L'accesso attende già il codice: un secondo invio del numero deve
        // fallire, ma senza diventare una diagnosi di avvio Live.
        let Err(error) = runtime.submit_phone_number(phone(), &service, now()) else {
            panic!("il secondo invio del numero deve fallire fuori dallo stato atteso");
        };
        assert!(
            !matches!(error, ServiceError::LiveStartup(_)),
            "un rifiuto già parlante non deve diventare una diagnosi di avvio Live: {error:?}"
        );
    }

    /// Un invio riuscito del numero arma l'attesa del codice, e passare allo
    /// stato `WaitingForCode` la disarma senza produrre alcuna diagnosi: la
    /// vista del servizio riflette anche la fase, con il campo del codice
    /// (`SubmitCode`) ammesso solo dopo la transizione.
    #[test]
    fn receiving_the_code_request_cancels_the_phone_number_watchdog_and_advances_the_stage() {
        let service = service();
        let account = seed_account(&service, 0xB5);
        let fake = FakeLiveLikeConnector::new().with_poll_responses(vec![
            Ok(Some(ConnectorEvent::Authorization(
                AuthorizationState::WaitingForPhoneNumber,
            ))),
            // Sentinel: separa i due aggiornamenti in due pompaggi distinti,
            // come farebbe un vero tick del timer che non trova altro pronto.
            Ok(None),
            Ok(Some(ConnectorEvent::Authorization(
                AuthorizationState::WaitingForCode,
            ))),
        ]);
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let t0 = Timestamp::from_millis(5_000_000);
        let Ok(()) = runtime.start(&service, t0) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = runtime.pump(&service, t0.plus_seconds(1)) else {
            panic!("il pompaggio non deve fallire");
        };
        assert_eq!(
            runtime.authorization_state(),
            AuthorizationState::WaitingForPhoneNumber
        );
        assert_eq!(runtime.view().stage, AuthStage::NeedPhoneNumber);

        let Ok(()) = runtime.submit_phone_number(phone(), &service, t0.plus_seconds(1)) else {
            panic!("l'invio del numero deve riuscire");
        };
        assert!(
            runtime.code_wait_started_at.is_some(),
            "l'invio riuscito deve armare l'attesa del codice"
        );

        let Ok(()) = runtime.pump(&service, t0.plus_seconds(2)) else {
            panic!("il pompaggio non deve fallire");
        };
        assert_eq!(
            runtime.authorization_state(),
            AuthorizationState::WaitingForCode
        );
        assert!(
            runtime.code_wait_started_at.is_none(),
            "la ricezione della richiesta del codice deve disarmare il guardiano"
        );
        assert!(runtime.auth.failure().is_none());
        assert_eq!(runtime.view().stage, AuthStage::NeedCode);
        assert!(
            runtime
                .view()
                .allowed_commands
                .contains(&AuthCommand::SubmitCode),
            "il campo del codice deve poter comparire dopo la transizione"
        );

        // Anche ben oltre la scadenza del guardiano, nessuna diagnosi compare:
        // il progresso ricevuto era reale.
        let Ok(()) = runtime.pump(&service, t0.plus_seconds(30)) else {
            panic!("il pompaggio non deve fallire");
        };
        assert!(runtime.auth.failure().is_none());
    }

    /// Nessuna richiesta del codice entro il tempo previsto dopo un invio
    /// riuscito del numero: la diagnosi `LIVE-E014` compare, una sola volta,
    /// e solo dopo la scadenza — non prima.
    #[test]
    fn no_code_request_within_the_timeout_after_the_phone_number_produces_the_watchdog_diagnosis_once()
     {
        let service = service();
        let account = seed_account(&service, 0xB6);
        let fake = FakeLiveLikeConnector::new().with_poll_responses(vec![Ok(Some(
            ConnectorEvent::Authorization(AuthorizationState::WaitingForPhoneNumber),
        ))]);
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let t0 = Timestamp::from_millis(6_000_000);
        let Ok(()) = runtime.start(&service, t0) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = runtime.pump(&service, t0.plus_seconds(1)) else {
            panic!("il pompaggio non deve fallire");
        };
        let Ok(()) = runtime.submit_phone_number(phone(), &service, t0.plus_seconds(1)) else {
            panic!("l'invio del numero deve riuscire");
        };

        // Prima della scadenza: nessuna diagnosi.
        let Ok(()) = runtime.pump(&service, t0.plus_seconds(5)) else {
            panic!("il pompaggio non deve fallire");
        };
        assert!(runtime.auth.failure().is_none());
        assert!(!runtime.code_wait_diagnosed);

        // Dopo la scadenza: la diagnosi compare, una sola volta.
        let after_timeout = t0.plus_seconds(1).plus_seconds(21);
        let Ok(()) = runtime.pump(&service, after_timeout) else {
            panic!("il pompaggio non deve fallire");
        };
        assert!(runtime.code_wait_diagnosed);
        let Some(ServiceError::LiveStartup(diagnostic)) = runtime.auth.failure() else {
            panic!("deve esserci una diagnosi classificata");
        };
        assert_eq!(
            diagnostic.phase(),
            LiveStartupPhase::CodeWaitAfterPhoneNumber
        );
        assert_eq!(diagnostic.code(), "LIVE-E014");

        // Pompaggi successivi non la duplicano.
        let Ok(()) = runtime.pump(&service, after_timeout.plus_seconds(5)) else {
            panic!("il pompaggio non deve fallire");
        };
        assert!(runtime.code_wait_diagnosed);
    }

    /// Regressione — rilievo 3 della revisione indipendente: il guardiano
    /// della fase 14 deve scattare anche quando ogni pompaggio consegna
    /// davvero qualcosa (`consumed > 0`), purché irrilevante (per esempio un
    /// aggiornamento di connessione) e purché il codice non arrivi mai:
    /// altrimenti un flusso di aggiornamenti non pertinenti manterrebbe
    /// l'operatore bloccato senza alcuna diagnosi, per quanto a lungo
    /// attendesse.
    #[test]
    fn no_code_request_within_the_timeout_is_diagnosed_even_when_irrelevant_updates_keep_arriving()
    {
        let service = service();
        let account = seed_account(&service, 0xBC);
        let fake = FakeLiveLikeConnector::new()
            .with_poll_responses(vec![Ok(Some(ConnectorEvent::Authorization(
                AuthorizationState::WaitingForPhoneNumber,
            )))])
            .delivering_connection_noise_once_exhausted();
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let t0 = Timestamp::from_millis(9_000_000);
        let Ok(()) = runtime.start(&service, t0) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = runtime.pump(&service, t0.plus_seconds(1)) else {
            panic!("il pompaggio non deve fallire");
        };
        let Ok(()) = runtime.submit_phone_number(phone(), &service, t0.plus_seconds(1)) else {
            panic!("l'invio del numero deve riuscire");
        };

        // Ogni pompaggio successivo consegna davvero un aggiornamento (mai
        // `consumed == 0`), ma nessuno di essi è il codice: prima della
        // scadenza non deve comparire alcuna diagnosi.
        for elapsed_seconds in [3, 6, 9, 12, 15, 18] {
            let Ok(()) = runtime.pump(&service, t0.plus_seconds(1 + elapsed_seconds)) else {
                panic!("il pompaggio non deve fallire");
            };
            assert!(
                runtime.auth.failure().is_none(),
                "prima della scadenza non deve comparire alcuna diagnosi, \
                 anche se ogni pompaggio consegna un aggiornamento irrilevante"
            );
        }

        let after_timeout = t0.plus_seconds(1).plus_seconds(21);
        let Ok(()) = runtime.pump(&service, after_timeout) else {
            panic!("il pompaggio non deve fallire");
        };
        let Some(ServiceError::LiveStartup(diagnostic)) = runtime.auth.failure() else {
            panic!(
                "la diagnosi deve comparire anche quando ogni pompaggio consegna \
                 qualcosa, purché irrilevante"
            );
        };
        assert_eq!(
            diagnostic.phase(),
            LiveStartupPhase::CodeWaitAfterPhoneNumber
        );
    }

    /// Regressione — il guardiano non deve mai armarsi prima che il numero
    /// sia stato inviato con successo: pompaggi ripetuti mentre l'accesso
    /// resta in attesa del numero non devono produrre la diagnosi `LIVE-E014`,
    /// che riguarda l'attesa **successiva** all'invio.
    #[test]
    fn the_phone_number_watchdog_never_arms_before_the_number_is_submitted() {
        let service = service();
        let account = seed_account(&service, 0xB7);
        let fake = FakeLiveLikeConnector::new().with_poll_responses(vec![Ok(Some(
            ConnectorEvent::Authorization(AuthorizationState::WaitingForPhoneNumber),
        ))]);
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let t0 = Timestamp::from_millis(7_000_000);
        let Ok(()) = runtime.start(&service, t0) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = runtime.pump(&service, t0.plus_seconds(1)) else {
            panic!("il pompaggio non deve fallire");
        };
        assert!(runtime.code_wait_started_at.is_none());

        // Ben oltre la soglia della fase 14, ma il numero non è mai stato
        // inviato: nessuna diagnosi di quella fase deve comparire.
        let Ok(()) = runtime.pump(&service, t0.plus_seconds(60)) else {
            panic!("il pompaggio non deve fallire");
        };
        assert!(runtime.auth.failure().is_none());
        assert!(!runtime.code_wait_diagnosed);
    }

    /// Il pompaggio prosegue senza errori dopo l'invio del numero, anche
    /// quando nessun evento è pronto: non deve mai bloccarsi né fallire.
    #[test]
    fn pumping_repeatedly_after_a_successful_phone_number_submission_is_harmless() {
        let service = service();
        let account = seed_account(&service, 0xB8);
        let fake = FakeLiveLikeConnector::new().with_poll_responses(vec![Ok(Some(
            ConnectorEvent::Authorization(AuthorizationState::WaitingForPhoneNumber),
        ))]);
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let Ok(()) = runtime.start(&service, now()) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = runtime.pump(&service, now()) else {
            panic!("il pompaggio non deve fallire");
        };
        let Ok(()) = runtime.submit_phone_number(phone(), &service, now()) else {
            panic!("l'invio del numero deve riuscire");
        };

        for _ in 0..5 {
            assert!(runtime.pump(&service, now()).is_ok());
        }
    }

    /// Nessun numero compare nella resa `Debug` del runtime, nemmeno dopo che
    /// la diagnosi `LIVE-E014` è stata registrata.
    #[test]
    fn the_debug_rendering_after_the_phone_number_watchdog_diagnosis_hides_the_phone_number() {
        let service = service();
        let account = seed_account(&service, 0xB9);
        let fake = FakeLiveLikeConnector::new().with_poll_responses(vec![Ok(Some(
            ConnectorEvent::Authorization(AuthorizationState::WaitingForPhoneNumber),
        ))]);
        let mut runtime = live_shaped_runtime_with(&account, fake);

        let t0 = Timestamp::from_millis(8_000_000);
        let Ok(()) = runtime.start(&service, t0) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = runtime.pump(&service, t0.plus_seconds(1)) else {
            panic!("il pompaggio non deve fallire");
        };
        let Ok(()) = runtime.submit_phone_number(phone(), &service, t0.plus_seconds(1)) else {
            panic!("l'invio del numero deve riuscire");
        };
        let Ok(()) = runtime.pump(&service, t0.plus_seconds(25)) else {
            panic!("il pompaggio non deve fallire");
        };
        let Some(ServiceError::LiveStartup(diagnostic)) = runtime.auth.failure() else {
            panic!("deve esserci una diagnosi classificata");
        };
        assert_eq!(
            diagnostic.phase(),
            LiveStartupPhase::CodeWaitAfterPhoneNumber
        );

        let rendered = format!("{runtime:?}");
        assert!(
            !rendered.contains("612345678"),
            "la resa Debug non deve contenere il numero in chiaro"
        );
    }
}

/// Cablaggio della modalità reale (M3B.1b). Nessuno di questi test carica
/// realmente `tdjson.dll`: verificano la composizione, la selezione del
/// connettore e la costruzione dei parametri con valori fittizi e un percorso di
/// libreria inesistente, così che il caricamento fallisca in modo controllato.
#[cfg(all(test, feature = "tdlib-runtime"))]
mod live_tests {
    use lisi_core::model::{
        AccountUuid, NewApiCredentialProfile, NewTelegramAccount, PersistedAuthStatus,
        PersistedConnectionStatus, TelegramAccount,
    };
    use lisi_core::text::DisplayName;
    use lisi_core::{ApiCredentialProfileId, TelegramAccountId, Timestamp};
    use lisi_storage::Database;
    use lisi_telegram::{ApiHash, ApiId};

    use super::tests::{autorita, cartella_di_prova};
    use super::{
        AccountPaths, AccountRuntime, LiveRuntimeConfig, LiveStartupPhase, TelegramCredentials,
        build_client_parameters, load_profile_api_credentials,
    };
    use crate::accounts::AccountService;
    use crate::error::ServiceError;

    // Valori dichiaratamente fittizi: nessuna credenziale reale compare mai.
    const FAKE_API_ID: i32 = 1_234_567;
    const FAKE_API_HASH: &str = "0123456789abcdef0123456789abcdef";
    const FAKE_PHONE_DIGITS: &str = "0612345678";

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn label(text: &str) -> DisplayName {
        let Ok(name) = DisplayName::try_new(text) else {
            panic!("l'etichetta di prova deve essere valida");
        };
        name
    }

    fn service() -> AccountService {
        let Ok(database) = Database::open_in_memory() else {
            panic!("il database in memoria deve potersi aprire");
        };
        AccountService::new(database)
    }

    fn seed_account(service: &AccountService, byte: u8) -> TelegramAccount {
        let Ok(profile_id) = service.database().insert_api_profile(
            &NewApiCredentialProfile {
                label: label("Profilo ufficio"),
            },
            now(),
        ) else {
            panic!("il profilo di prova deve potersi inserire");
        };
        let Ok(id) = service.database().insert_telegram_account(
            &NewTelegramAccount {
                uuid: AccountUuid::from_bytes([byte; 16]),
                label: label("Account di prova"),
                profile_id,
            },
            now(),
        ) else {
            panic!("l'account di prova deve potersi inserire");
        };
        let Ok(account) = service.database().telegram_account(id) else {
            panic!("l'account appena inserito deve potersi rileggere");
        };
        account
    }

    fn fake_credentials() -> TelegramCredentials {
        let (Ok(api_id), Ok(api_hash)) =
            (ApiId::try_new(FAKE_API_ID), ApiHash::try_new(FAKE_API_HASH))
        else {
            panic!("le credenziali fittizie devono essere valide");
        };
        TelegramCredentials { api_id, api_hash }
    }

    fn config_with_missing_library() -> LiveRuntimeConfig {
        LiveRuntimeConfig {
            library_path: std::path::PathBuf::from("percorso/inesistente/tdjson.dll"),
            use_test_datacenter: true,
        }
    }

    /// La modalità reale deve puntare al datacenter di **produzione**: è
    /// l'unico su cui il codice di accesso venga davvero recapitato.
    ///
    /// Il valore è stato `true` (datacenter di prova) fino al 2026-07-30, e
    /// quella scelta - presa come cautela per un primo pilot e poi mai
    /// rivista - è costata all'operatore un pilot in cui l'accesso si fermava
    /// all'attesa di un codice che non poteva arrivare. Questo test esiste
    /// perché un ritorno silenzioso a `true` non passi inosservato: se la
    /// scelta va cambiata di nuovo, va cambiata **anche qui**, cioè
    /// deliberatamente.
    #[test]
    #[expect(
        clippy::assertions_on_constants,
        reason = "l'asserzione su una costante e' deliberata: fissa una scelta \
                  di configurazione che e' gia' regredita in silenzio una volta \
                  (datacenter di prova lasciato attivo, pilot del 2026-07-30). \
                  Il valore del test non e' scoprire qualcosa a runtime, ma \
                  fare in modo che cambiare quella costante richieda di \
                  cambiare anche questo test, cioe' una scelta esplicita e \
                  visibile nel diff"
    )]
    fn the_production_default_targets_the_real_telegram_datacenter() {
        assert!(
            !super::USE_TEST_DATACENTER,
            "la modalita' reale deve usare il datacenter di produzione: sul \
             datacenter di prova il codice di accesso non viene mai recapitato"
        );
    }

    #[test]
    fn the_client_parameters_carry_the_credentials_and_the_account_directory() {
        let uuid = AccountUuid::from_bytes([0x11; 16]);
        let paths = AccountPaths::new(std::path::Path::new("base"), &uuid);
        let config = config_with_missing_library();

        let parameters = build_client_parameters(fake_credentials(), &paths.tdlib_dir, &config);

        assert_eq!(parameters.api_id.expose_secret(), FAKE_API_ID);
        assert_eq!(parameters.api_hash.expose_secret(), FAKE_API_HASH);
        assert_eq!(parameters.database_directory, paths.tdlib_dir);
        // Questo verifica la **propagazione** del valore configurato (qui
        // `true`, scelto dalla configurazione di prova), non il datacenter
        // usato in produzione: quello è fissato da
        // `the_production_default_targets_the_real_telegram_datacenter`.
        assert!(parameters.use_test_datacenter);
        // La directory del database porta l'UUID dell'account, mai il numero.
        let directory = parameters.database_directory.to_string_lossy();
        assert!(directory.contains(uuid.as_str()));
        assert!(!directory.contains(FAKE_PHONE_DIGITS));
    }

    #[test]
    fn the_client_parameters_debug_never_reveals_the_secrets() {
        let paths = AccountPaths::new(
            std::path::Path::new("base"),
            &AccountUuid::from_bytes([0x22; 16]),
        );
        let parameters = build_client_parameters(
            fake_credentials(),
            &paths.tdlib_dir,
            &config_with_missing_library(),
        );

        let rendered = format!("{parameters:?}");
        assert!(
            !rendered.contains(FAKE_API_HASH),
            "l'API hash non compare nel Debug"
        );
        assert!(
            !rendered.contains(&FAKE_API_ID.to_string()),
            "l'API id non compare nel Debug"
        );
        assert!(
            rendered.contains("redatto"),
            "i valori riservati sono redatti"
        );
    }

    #[test]
    fn two_accounts_get_distinct_database_directories() {
        let base = std::path::Path::new("base");
        let config = config_with_missing_library();

        let first_paths = AccountPaths::new(base, &AccountUuid::from_bytes([0x01; 16]));
        let second_paths = AccountPaths::new(base, &AccountUuid::from_bytes([0x02; 16]));

        let first = build_client_parameters(fake_credentials(), &first_paths.tdlib_dir, &config);
        let second = build_client_parameters(fake_credentials(), &second_paths.tdlib_dir, &config);

        assert_ne!(
            first.database_directory, second.database_directory,
            "account distinti non condividono la directory del database"
        );
    }

    #[test]
    fn opening_live_without_the_library_fails_after_confirming_the_profile() {
        let service = service();
        let account = seed_account(&service, 0x33);
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };

        // Il profilo esiste, ma la libreria non c'è: si fallisce con la
        // diagnosi classificata della fase 4 (caricamento della libreria),
        // senza aprire alcuna sessione.
        let cartella_autorita = cartella_di_prova();
        let autorita = autorita(&cartella_autorita);
        let outcome = AccountRuntime::open_live(
            &service,
            &account,
            directory.path(),
            &config_with_missing_library(),
            &autorita,
        );
        let Err(ServiceError::LiveStartup(diagnostic)) = outcome else {
            panic!("una libreria assente deve dare una diagnosi classificata dell'avvio Live");
        };
        assert_eq!(diagnostic.phase(), LiveStartupPhase::TdjsonLoad);
    }

    #[test]
    fn opening_live_for_a_missing_profile_is_reported_clearly() {
        let service = service();
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };

        // Account costruito con un profilo che non esiste nel database: la verifica
        // del profilo fallisce prima di toccare la libreria o qualunque segreto.
        let account = TelegramAccount {
            id: TelegramAccountId::new(1),
            uuid: AccountUuid::from_bytes([0x44; 16]),
            label: label("Account orfano"),
            masked_phone: None,
            profile_id: ApiCredentialProfileId::new(9_999),
            auth_status: PersistedAuthStatus::Fresh,
            connection_status: PersistedConnectionStatus::Unknown,
            last_connected_at: None,
            created_at: now(),
            updated_at: now(),
        };

        let cartella_autorita = cartella_di_prova();
        let autorita = autorita(&cartella_autorita);
        let outcome = AccountRuntime::open_live(
            &service,
            &account,
            directory.path(),
            &config_with_missing_library(),
            &autorita,
        );
        let Err(ServiceError::LiveStartup(diagnostic)) = outcome else {
            panic!("un profilo inesistente deve essere segnalato con una diagnosi classificata");
        };
        assert_eq!(diagnostic.phase(), LiveStartupPhase::ApiProfileLoad);
    }

    /// "Profilo DPAPI non leggibile" (fase 2, `DpapiOpen`).
    ///
    /// Non è collaudato attraverso l'intero `open_live`, perché richiederebbe
    /// caricare per davvero `tdjson.dll`: questo modulo evita **deliberatamente**
    /// di farlo (vedere la nota in testa al modulo), e la scelta resta corretta
    /// anche per questa diagnosi. Collauda invece direttamente il sito di
    /// chiamata responsabile della fase `DpapiOpen`: senza la configurazione
    /// dell'applicazione, il vecchio profilo e le variabili d'ambiente, l'errore
    /// rimanda all'amministratore (ADR-0204).
    ///
    /// **Nota:** se l'ambiente di collaudo definisse le variabili d'ambiente
    /// delle credenziali (riservate alla sola prova operativa), questo test
    /// leggerebbe quelle invece di fallire: è lo stesso limite già accettato
    /// dal resto della suite per quelle variabili.
    #[test]
    fn a_profile_without_saved_or_environment_credentials_is_reported_clearly() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let profile_id = ApiCredentialProfileId::new(4_242);

        assert!(
            matches!(
                load_profile_api_credentials(directory.path(), profile_id),
                Err(ServiceError::ApplicationNotConfigured)
            ),
            "senza la configurazione dell'applicazione si rimanda all'amministratore"
        );
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use lisi_core::model::AccountUuid;

    use super::{AccountPaths, prepare_account_storage};

    #[test]
    fn preparing_storage_creates_the_isolated_directories_and_a_key() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let uuid = AccountUuid::from_bytes([0x01; 16]);

        let Ok(_key) = prepare_account_storage(directory.path(), &uuid) else {
            panic!("la preparazione dello spazio dell'account deve riuscire");
        };

        let paths = AccountPaths::new(directory.path(), &uuid);
        assert!(paths.tdlib_dir.is_dir(), "la cartella tdlib deve esistere");
        assert!(paths.files_dir.is_dir(), "la cartella file deve esistere");
        assert!(
            paths.key_path.exists(),
            "il file della chiave deve esistere"
        );
    }

    #[test]
    fn two_accounts_do_not_share_the_encryption_key() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let first_uuid = AccountUuid::from_bytes([0x11; 16]);
        let second_uuid = AccountUuid::from_bytes([0x22; 16]);

        let (Ok(first), Ok(second)) = (
            prepare_account_storage(directory.path(), &first_uuid),
            prepare_account_storage(directory.path(), &second_uuid),
        ) else {
            panic!("entrambe le preparazioni devono riuscire");
        };
        assert_ne!(
            first.expose_secret(),
            second.expose_secret(),
            "account distinti non devono condividere la chiave"
        );
    }
}

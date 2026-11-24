//! Servizio di autenticazione.
//!
//! Conduce l'accesso guidando la macchina a stati del connettore e stabilisce
//! **quali comandi siano ammessi** nello stato corrente. Quella decisione vive
//! qui e non nell'interfaccia: un pulsante disabilitato impedisce di inviare un
//! codice mentre la libreria attende un numero, ed è quindi una decisione di
//! sicurezza. Se vivesse in un binding grafico sarebbe verificabile soltanto
//! aprendo la finestra e guardandola.
//!
//! Il servizio non conosce Slint e non stampa nulla: produce uno stato
//! osservabile che l'interfaccia si limita a mostrare.

use core::time::Duration;
use std::collections::VecDeque;

use lisi_telegram::{
    AuthorizationState, ClientParameters, LoginCode, PhoneNumber, TelegramConnector, TelegramError,
    TwoFactorPassword,
};

use crate::error::{ServiceError, ServiceResult, from_connector};

/// Comando che l'operatore può impartire durante l'accesso.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthCommand {
    /// Avvia il client e comincia l'accesso.
    Start,
    /// Invia il numero di telefono.
    SubmitPhoneNumber,
    /// Invia il codice ricevuto.
    SubmitCode,
    /// Invia la password della verifica in due passaggi.
    SubmitPassword,
    /// Annulla l'accesso in corso.
    Cancel,
    /// Esce dall'account.
    LogOut,
    /// Avvia il cambio di account.
    SwitchAccount,
}

impl AuthCommand {
    /// Tutti i comandi, per i test e per l'interfaccia.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Start,
            Self::SubmitPhoneNumber,
            Self::SubmitCode,
            Self::SubmitPassword,
            Self::Cancel,
            Self::LogOut,
            Self::SwitchAccount,
        ]
    }

    /// Etichetta stabile, usata nell'audit e nei messaggi di errore.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::SubmitPhoneNumber => "submit_phone_number",
            Self::SubmitCode => "submit_code",
            Self::SubmitPassword => "submit_password",
            Self::Cancel => "cancel",
            Self::LogOut => "log_out",
            Self::SwitchAccount => "switch_account",
        }
    }

    /// Etichetta mostrata sul comando nell'interfaccia.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Start => "Avvia accesso",
            Self::SubmitPhoneNumber => "Invia numero",
            Self::SubmitCode => "Invia codice",
            Self::SubmitPassword => "Invia password",
            Self::Cancel => "Annulla",
            Self::LogOut => "Esci dall'account",
            Self::SwitchAccount => "Cambia account",
        }
    }
}

/// Ciò che l'interfaccia deve chiedere all'operatore in questo momento.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStage {
    /// Nessun account configurato: primo avvio.
    FirstRun,
    /// Preparazione del client in corso.
    Preparing,
    /// Serve il numero di telefono.
    NeedPhoneNumber,
    /// Serve il codice ricevuto.
    NeedCode,
    /// Serve la password della verifica in due passaggi.
    NeedPassword,
    /// Account autorizzato e operativo.
    Authenticated,
    /// Uscita in corso.
    ClosingDown,
    /// Sessione chiusa.
    Closed,
    /// Accesso fallito in modo non recuperabile.
    Failed,
}

impl AuthStage {
    /// Se in questa fase è atteso un dato riservato dall'operatore.
    #[must_use]
    pub const fn expects_secret_input(self) -> bool {
        matches!(
            self,
            Self::NeedPhoneNumber | Self::NeedCode | Self::NeedPassword
        )
    }

    /// Titolo mostrato all'operatore.
    #[must_use]
    pub const fn headline(self) -> &'static str {
        match self {
            Self::FirstRun => "Nessun account configurato",
            Self::Preparing => "Preparazione in corso",
            Self::NeedPhoneNumber => "Inserire il numero dell'account d'ufficio",
            Self::NeedCode => "Inserire il codice ricevuto da Telegram",
            Self::NeedPassword => "Inserire la password della verifica in due passaggi",
            Self::Authenticated => "Account attivo",
            Self::ClosingDown => "Uscita in corso",
            Self::Closed => "Sessione chiusa",
            Self::Failed => "Accesso non riuscito",
        }
    }

    /// Spiegazione mostrata sotto al titolo.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::FirstRun => {
                "Per monitorare le fonti occorre accedere con l'account d'ufficio autorizzato."
            }
            Self::Preparing => "Attendere il completamento della preparazione.",
            Self::NeedPhoneNumber => {
                "Indicare il numero in formato internazionale, per esempio +39 seguito dal numero."
            }
            Self::NeedCode => {
                "Telegram ha inviato un codice all'account. Il codice ha validità limitata."
            }
            Self::NeedPassword => {
                "L'account è protetto dalla verifica in due passaggi. La password non viene mostrata."
            }
            Self::Authenticated => "È possibile configurare le fonti e avviare il monitoraggio.",
            Self::ClosingDown => "Chiusura ordinata della sessione in corso.",
            Self::Closed => "Per riprendere occorre accedere di nuovo.",
            Self::Failed => "Consultare il messaggio riportato e riprovare.",
        }
    }
}

/// Spiegazione della preparazione che dura (OBS-TG-1).
///
/// Il collaudo ha visto «Preparazione in corso» per 25-30 secondi, senza un
/// segno che qualcosa avanzasse. La causa era nella lettura degli
/// aggiornamenti ed è corretta; se l'attesa torna, almeno si vede da quanto
/// dura e come la si interrompe.
#[must_use]
pub fn preparing_detail(waited: std::time::Duration) -> String {
    let secondi = usize::try_from(waited.as_secs()).unwrap_or(usize::MAX);
    if secondi < 3 {
        return String::from(AuthStage::Preparing.detail());
    }
    format!(
        "Il programma apre la sessione e si collega a Telegram: in attesa da {}. «{}» interrompe l'attesa.",
        lisi_core::text::counted(secondi, "secondo", "secondi"),
        AuthCommand::Cancel.label()
    )
}

/// Stato osservabile dell'accesso, destinato all'interfaccia.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationView {
    /// Stato della macchina del connettore.
    pub state: AuthorizationState,
    /// Fase, cioè che cosa serve ora.
    pub stage: AuthStage,
    /// Comandi ammessi in questo momento.
    pub allowed_commands: Vec<AuthCommand>,
    /// Se è in corso un'operazione che richiede attesa.
    pub busy: bool,
    /// Messaggio d'errore per l'operatore, se l'ultima operazione è fallita.
    pub failure: Option<String>,
    /// Se l'errore è correggibile reinserendo il dato.
    pub failure_is_correctable: bool,
    /// Numero dell'account in forma **redatta**, quando configurato.
    pub account_label: Option<String>,
}

impl AuthenticationView {
    /// Se il comando indicato è ammesso.
    #[must_use]
    pub fn allows(&self, command: AuthCommand) -> bool {
        self.allowed_commands.contains(&command)
    }
}

/// Parametri di avvio con valori **dichiaratamente fittizi**.
///
/// Vivono nei servizi e non nell'interfaccia perché contengono API ID e API
/// hash: sono valori riservati, e un valore riservato non deve attraversare il
/// livello grafico nemmeno quando è finto, perché la struttura del codice
/// rimarrebbe quella sbagliata il giorno in cui diventa vero.
fn placeholder_parameters() -> ServiceResult<ClientParameters> {
    let api_id = lisi_telegram::ApiId::try_new(1)?;
    let api_hash = lisi_telegram::ApiHash::try_new("00000000000000000000000000000000")?;

    Ok(ClientParameters {
        api_id,
        api_hash,
        database_directory: std::path::PathBuf::from("sessione-simulata"),
        use_test_datacenter: true,
        application_version: String::from(env!("CARGO_PKG_VERSION")),
        system_language_code: String::from("it"),
    })
}

/// Servizio che conduce l'accesso.
pub struct AuthenticationService {
    connector: Box<dyn TelegramConnector>,
    /// Numero configurato, conservato solo in memoria e mai scritto altrove.
    phone: Option<PhoneNumber>,
    failure: Option<ServiceError>,
    /// Resa testuale dell'ultimo guasto **grezzo** registrato da
    /// [`Self::pump_events`], usata solo per riconoscere che lo stesso guasto
    /// si sta ripresentando identico (vedere il ramo `Err` di quella
    /// funzione). Non è mai mostrata all'operatore: la vista continua a
    /// leggere `failure`. Non contiene più di quanto `failure` già mostri,
    /// perché è esattamente la resa di quel medesimo errore.
    last_raw_failure: Option<String>,
    /// Eventi non di autorizzazione già letti dal connettore e in attesa di
    /// essere consegnati all'acquisizione (vedere [`Self::take_pending_events`]).
    pending_events: VecDeque<lisi_telegram::ConnectorEvent>,
    /// Eventi scartati perché [`Self::pending_events`] era saturo.
    ///
    /// Esiste perché una perdita non resti **silenziosa**: se nessuno ritira
    /// gli eventi (nessuna sessione di monitoraggio attiva, o un consumatore
    /// fermo) la coda non può crescere senza limite, ma il fatto che si sia
    /// buttato qualcosa dev'essere dichiarabile invece che invisibile.
    dropped_events: u64,
    busy: bool,
    poll_timeout: Duration,
}

/// Tetto della coda degli eventi in attesa di acquisizione.
///
/// Dimensionato con larghezza rispetto al ritmo reale: il pompaggio gira ogni
/// 200 ms e legge fino a 256 eventi per giro, quindi la coda regge diversi
/// secondi di silenzio del consumatore anche su una fonte molto attiva. Non è
/// un limite di banda ma una rete di sicurezza contro la crescita illimitata
/// quando **nessuno** consuma.
const PENDING_EVENTS_CAPACITY: usize = 4_096;

impl core::fmt::Debug for AuthenticationService {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Il numero non compare: `PhoneNumber` redige da sé, ma la resa
        // esplicita rende l'intenzione leggibile.
        formatter
            .debug_struct("AuthenticationService")
            .field("state", &self.connector.authorization_state())
            .field("account_configured", &self.phone.is_some())
            .field("busy", &self.busy)
            .finish_non_exhaustive()
    }
}

impl AuthenticationService {
    /// Crea il servizio con il connettore **simulato**.
    ///
    /// È il costruttore che usa l'interfaccia grafica in questa fase: permette
    /// di percorrere l'intero accesso senza rete, senza credenziali e senza
    /// TDLib installata. Esiste qui, e non nell'interfaccia, perché la GUI non
    /// deve conoscere il connettore: è il confine posto da ADR-0010.
    #[must_use]
    pub fn simulated() -> Self {
        Self::new(Box::new(lisi_telegram::MockTelegramConnector::new()))
    }

    /// Crea il servizio con il connettore simulato che richiede la verifica in
    /// due passaggi.
    #[must_use]
    pub fn simulated_with_two_factor() -> Self {
        Self::new(Box::new(
            lisi_telegram::MockTelegramConnector::new().requiring_two_factor(true),
        ))
    }

    /// Avvia l'accesso costruendo da sé i parametri del client.
    ///
    /// I parametri contengono API ID e API hash, che sono valori riservati: non
    /// devono attraversare l'interfaccia grafica. In questa fase sono
    /// **dichiaratamente fittizi** e non vengono trasmessi ad alcun servizio;
    /// il caricamento di quelli reali da configurazione protetta è lavoro della
    /// fase operativa.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il comando non è ammesso o se l'avvio fallisce.
    pub fn start_configured(&mut self) -> ServiceResult<()> {
        let parameters = placeholder_parameters()?;
        self.start(&parameters)
    }

    /// Crea il servizio attorno al connettore indicato.
    ///
    /// Il connettore è iniettato: in prova è quello simulato, in esercizio
    /// quello reale. È ciò che permette di percorrere l'intero accesso senza
    /// rete, senza credenziali e senza TDLib installata.
    #[must_use]
    pub fn new(connector: Box<dyn TelegramConnector>) -> Self {
        Self {
            connector,
            phone: None,
            failure: None,
            last_raw_failure: None,
            pending_events: VecDeque::new(),
            dropped_events: 0,
            busy: false,
            poll_timeout: Duration::from_millis(50),
        }
    }

    /// Stato corrente dell'autorizzazione.
    #[must_use]
    pub fn state(&self) -> AuthorizationState {
        self.connector.authorization_state()
    }

    /// Fase corrente.
    #[must_use]
    pub fn stage(&self) -> AuthStage {
        match self.state() {
            AuthorizationState::Uninitialized => AuthStage::FirstRun,
            AuthorizationState::WaitingForTdlibParameters => AuthStage::Preparing,
            AuthorizationState::WaitingForPhoneNumber => AuthStage::NeedPhoneNumber,
            AuthorizationState::WaitingForCode => AuthStage::NeedCode,
            AuthorizationState::WaitingForPassword => AuthStage::NeedPassword,
            AuthorizationState::Ready => AuthStage::Authenticated,
            AuthorizationState::Closing => AuthStage::ClosingDown,
            AuthorizationState::Closed => AuthStage::Closed,
            AuthorizationState::Failed => AuthStage::Failed,
        }
    }

    /// Comandi ammessi nello stato corrente.
    ///
    /// È l'elenco che l'interfaccia usa per abilitare o disabilitare i propri
    /// comandi. Non va duplicato altrove.
    #[must_use]
    pub fn allowed_commands(&self) -> Vec<AuthCommand> {
        let mut allowed = Vec::new();

        match self.state() {
            // `Cancel` qui ricostruisce un runtime pulito (non e' una vera
            // richiesta al connettore): senza, un accesso che non avanza -
            // per esempio perche' l'interfaccia non ha ancora pompato gli
            // eventi in arrivo - lascerebbe l'operatore senza alcuna via
            // d'uscita se non chiudere l'intera applicazione.
            AuthorizationState::Uninitialized => {
                allowed.push(AuthCommand::Start);
                allowed.push(AuthCommand::Cancel);
            }
            AuthorizationState::WaitingForTdlibParameters => allowed.push(AuthCommand::Cancel),
            AuthorizationState::WaitingForPhoneNumber => {
                allowed.push(AuthCommand::SubmitPhoneNumber);
                allowed.push(AuthCommand::Cancel);
            }
            AuthorizationState::WaitingForCode => {
                allowed.push(AuthCommand::SubmitCode);
                // Il numero puo' essere sbagliato: si deve poter tornare indietro.
                allowed.push(AuthCommand::SubmitPhoneNumber);
                allowed.push(AuthCommand::Cancel);
            }
            AuthorizationState::WaitingForPassword => {
                allowed.push(AuthCommand::SubmitPassword);
                allowed.push(AuthCommand::Cancel);
            }
            AuthorizationState::Ready => {
                allowed.push(AuthCommand::LogOut);
                allowed.push(AuthCommand::SwitchAccount);
            }
            // Durante la chiusura non si accetta nulla: un comando qui
            // lascerebbe la sessione a meta'.
            AuthorizationState::Closing => {}
            AuthorizationState::Closed | AuthorizationState::Failed => {
                allowed.push(AuthCommand::Start);
            }
        }

        allowed
    }

    /// Stato osservabile completo.
    #[must_use]
    pub fn view(&self) -> AuthenticationView {
        AuthenticationView {
            state: self.state(),
            stage: self.stage(),
            allowed_commands: self.allowed_commands(),
            busy: self.busy,
            failure: self.failure.as_ref().map(ServiceError::operator_message),
            failure_is_correctable: self
                .failure
                .as_ref()
                .is_some_and(ServiceError::is_correctable_by_operator),
            account_label: self.phone.as_ref().map(PhoneNumber::redacted),
        }
    }

    /// Verifica che il comando sia ammesso, senza eseguirlo.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::CommandNotAllowed`] se non lo è.
    pub fn ensure_allowed(&self, command: AuthCommand) -> ServiceResult<()> {
        if self.allowed_commands().contains(&command) {
            return Ok(());
        }
        Err(ServiceError::CommandNotAllowed {
            command: command.as_str(),
            state: self.state().as_str(),
        })
    }

    /// Avvia il client e comincia l'accesso.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il comando non è ammesso o se l'avvio fallisce.
    pub fn start(&mut self, parameters: &ClientParameters) -> ServiceResult<()> {
        self.ensure_allowed(AuthCommand::Start)?;
        self.run(|connector| connector.start(parameters))
    }

    /// Comunica il numero dell'account d'ufficio.
    ///
    /// Il numero è conservato **solo in memoria**, per poterlo mostrare in
    /// forma redatta; non viene scritto in alcun archivio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il comando non è ammesso o se il numero non è
    /// accettato.
    pub fn submit_phone_number(&mut self, phone: PhoneNumber) -> ServiceResult<()> {
        self.ensure_allowed(AuthCommand::SubmitPhoneNumber)?;
        // Nessun dato riservato in questa traccia: solo un passo stabile,
        // utile a distinguere "il comando non era ammesso" da "il comando è
        // arrivato al connettore ma non ha ancora avuto esito" quando si
        // legge il registro dopo un accesso rimasto bloccato.
        tracing::debug!(
            passo = "numero_consegnato_al_connettore",
            "numero pronto per l'invio al connettore"
        );
        self.run(|connector| connector.submit_phone_number(&phone))?;
        self.phone = Some(phone);
        Ok(())
    }

    /// Comunica il codice ricevuto.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::CodeRejected`] se il codice non è corretto.
    /// Lo stato resta in attesa del codice: un codice sbagliato non interrompe
    /// l'accesso, lo fa ripetere.
    pub fn submit_code(&mut self, code: LoginCode) -> ServiceResult<()> {
        self.ensure_allowed(AuthCommand::SubmitCode)?;
        self.run(|connector| connector.submit_code(&code))
    }

    /// Comunica la password della verifica in due passaggi.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::PasswordRejected`] se la password non è
    /// corretta.
    pub fn submit_password(&mut self, password: TwoFactorPassword) -> ServiceResult<()> {
        self.ensure_allowed(AuthCommand::SubmitPassword)?;
        self.run(|connector| connector.submit_password(&password))
    }

    /// Annulla l'accesso in corso, chiudendo in modo ordinato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il comando non è ammesso o se la chiusura
    /// fallisce.
    pub fn cancel(&mut self) -> ServiceResult<()> {
        self.ensure_allowed(AuthCommand::Cancel)?;
        self.run(|connector| connector.shutdown())?;
        self.phone = None;
        self.failure = Some(ServiceError::Cancelled);
        Ok(())
    }

    /// Esce dall'account in modo ordinato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il comando non è ammesso o se l'uscita
    /// fallisce.
    pub fn log_out(&mut self) -> ServiceResult<()> {
        self.ensure_allowed(AuthCommand::LogOut)?;
        self.run(|connector| connector.shutdown())?;
        self.phone = None;
        Ok(())
    }

    /// Avvia il cambio di account.
    ///
    /// È un'operazione protetta: esce dall'account corrente **prima** di
    /// consentire una nuova configurazione, così che due account non risultino
    /// mai attivi insieme.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il comando non è ammesso o se l'uscita
    /// fallisce.
    pub fn switch_account(&mut self) -> ServiceResult<()> {
        self.ensure_allowed(AuthCommand::SwitchAccount)?;
        self.run(|connector| connector.shutdown())?;
        self.phone = None;
        Ok(())
    }

    /// Consuma gli eventi in attesa, aggiornando lo stato osservabile.
    ///
    /// Va richiamata periodicamente dall'interfaccia. Un evento di fallimento
    /// aggiorna il messaggio mostrato all'operatore; un evento di **progresso
    /// reale** dell'autorizzazione (`ConnectorEvent::Authorization` verso uno
    /// stato **non** terminale e diverso da `Closing`) ripulisce invece un
    /// fallimento registrato in precedenza, sullo stesso principio per cui
    /// [`Self::run`] ripulisce `self.failure` a ogni comando riuscito: senza,
    /// un guasto osservato una volta resterebbe riportato come diagnosi
    /// corrente anche dopo che l'accesso è davvero avanzato oltre quella fase
    /// (Ipotesi A del report dell'incidente del 2026-07-29, confermata da
    /// `tests::pump_events_clears_a_previous_failure_when_real_progress_arrives`).
    ///
    /// Uno stato **terminale** (`Failed`, `Closed`) o `Closing` non è invece
    /// un progresso da festeggiare: di norma *segue*, nello stesso pompaggio,
    /// il guasto che lo ha causato (per esempio una sessione revocata arriva
    /// come `Failure(SessionRevoked)` seguita subito da
    /// `Authorization(Closing)`/`Authorization(Closed)`): pulire il
    /// fallimento anche lì cancellerebbe il motivo della chiusura prima che
    /// l'operatore possa leggerlo (regressione rilevata dalla revisione
    /// indipendente su `crates/lisi-services/tests/authentication.rs::a_revoked_session_is_surfaced_through_the_event_pump`).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura degli eventi fallisce per una
    /// ragione diversa dall'attesa scaduta o dalla chiusura.
    pub fn pump_events(&mut self) -> ServiceResult<usize> {
        let mut consumed = 0_usize;

        for _ in 0..256 {
            match self.connector.poll_event(self.poll_timeout) {
                Ok(Some(event)) => {
                    consumed += 1;
                    match event {
                        lisi_telegram::ConnectorEvent::Failure(failure) => {
                            self.failure = Some(from_connector(failure));
                        }
                        lisi_telegram::ConnectorEvent::Authorization(state) => {
                            if !state.is_final() && state != AuthorizationState::Closing {
                                self.failure = None;
                                self.last_raw_failure = None;
                            }
                        }
                        // Tutto il resto - contenuti, modifiche, cancellazioni,
                        // cambi di stato della connessione - non riguarda
                        // l'accesso, ma **non va buttato via**: e' il materiale
                        // che l'acquisizione deve ingerire.
                        //
                        // Questa funzione e' l'**unico** punto del prodotto che
                        // chiama `poll_event`. Farlo consumare anche
                        // all'acquisizione creerebbe due consumatori della
                        // stessa coda, ciascuno cieco a cio' che interessa
                        // all'altro (`AcquisitionService::drain` scarta a sua
                        // volta gli eventi di autorizzazione): chi arriva primo
                        // vince e gli eventi dell'altro spariscono, in modo
                        // intermittente e senza alcun errore. Per un prodotto
                        // di monitoraggio sarebbe la perdita silenziosa di
                        // contenuti, il guasto peggiore possibile. Con un solo
                        // consumatore e una consegna esplicita
                        // ([`Self::take_pending_events`]) la corsa non esiste
                        // **per costruzione**, non per disciplina.
                        other => self.buffer_for_acquisition(other),
                    }
                }
                Ok(None) => break,
                Err(TelegramError::Closed) => break,
                Err(other) => {
                    // Se il guasto grezzo e' gia' stato riclassificato in una
                    // diagnosi di avvio Live (`ServiceError::LiveStartup`, per
                    // esempio da `crate::telegram_runtime::AccountRuntime::pump`),
                    // non lo si sovrascrive con una ricostruzione generica:
                    // altrimenti quella classificazione verrebbe cancellata a
                    // ogni pompaggio successivo in cui il connettore continua a
                    // restituire lo stesso guasto grezzo (per esempio un client
                    // mai creato, che risponde identico a ogni `poll_event`),
                    // producendo una nuova diagnosi — e un nuovo registro — a
                    // ogni ciclo invece che una sola volta (incidente del
                    // 2026-07-30: il pilot ha mostrato `LIVE-E009` ripetuto ogni
                    // ~200ms). Lo stato dell'accesso non puo' avanzare mentre
                    // questo stesso guasto persiste (un aggiornamento reale
                    // richiede che `poll_event` restituisca `Ok`, non `Err`),
                    // quindi la diagnosi gia' registrata resta valida finche'
                    // qualcosa non cambia davvero.
                    //
                    // La soppressione e' pero' limitata al guasto **identico**
                    // a quello che ha originato la diagnosi corrente, non a
                    // qualunque guasto successivo (rilievo della revisione
                    // indipendente del 2026-07-30): sopprimere in base al solo
                    // fatto che `failure` sia gia' un `LiveStartup`
                    // nasconderebbe in silenzio un guasto grezzo **diverso**
                    // sopraggiunto dopo, reintroducendo la diagnosi stantia
                    // che l'incidente del 2026-07-29 aveva gia' dovuto
                    // correggere una volta. Il confronto usa la resa testuale
                    // dell'errore ricostruito, cioe' esattamente cio' che
                    // l'operatore vedrebbe: due guasti che si mostrano
                    // identici sono, per la diagnosi, lo stesso guasto.
                    let rebuilt = from_connector(other);
                    let rendered = rebuilt.to_string();
                    let same_failure_already_classified =
                        matches!(self.failure, Some(ServiceError::LiveStartup(_)))
                            && self.last_raw_failure.as_deref() == Some(rendered.as_str());
                    if !same_failure_already_classified {
                        self.last_raw_failure = Some(rendered);
                        self.failure = Some(rebuilt);
                    }
                    break;
                }
            }
        }

        Ok(consumed)
    }

    /// Connettore sottostante, per i servizi che ne hanno bisogno.
    ///
    /// L'accesso è concesso agli **altri servizi**, non all'interfaccia: il
    /// servizio delle fonti deve poter chiedere all'account quali chat gli
    /// siano accessibili, e il connettore è uno solo per istanza. L'alternativa
    /// — due connettori, o una copia dell'elenco — introdurrebbe uno stato
    /// duplicato che può divergere.
    pub fn connector_mut(&mut self) -> &mut dyn TelegramConnector {
        self.connector.as_mut()
    }

    /// Ultimo errore registrato, se presente.
    #[must_use]
    pub const fn failure(&self) -> Option<&ServiceError> {
        self.failure.as_ref()
    }

    /// Dimentica l'ultimo errore, per esempio quando l'operatore ricomincia.
    pub fn clear_failure(&mut self) {
        self.failure = None;
        self.last_raw_failure = None;
    }

    /// Accoda un evento destinato all'acquisizione, senza superare il tetto.
    ///
    /// A coda satura si scarta il **più vecchio**: davanti a una scelta fra
    /// perdere il contenuto appena arrivato e perdere quello più vecchio, si
    /// preferisce conservare il più recente, che è quello che un operatore sta
    /// verosimilmente aspettando. La perdita viene contata, non taciuta.
    fn buffer_for_acquisition(&mut self, event: lisi_telegram::ConnectorEvent) {
        if self.pending_events.len() >= PENDING_EVENTS_CAPACITY {
            self.pending_events.pop_front();
            self.dropped_events = self.dropped_events.saturating_add(1);
        }
        self.pending_events.push_back(event);
    }

    /// Ritira **al più `max`** eventi in attesa di acquisizione, i più vecchi.
    ///
    /// È il solo modo per ottenerli: [`Self::pump_events`] è l'unico punto che
    /// legge dal connettore, e questa funzione è l'unica uscita verso chi
    /// ingerisce. Chiamarla quando non c'è nulla restituisce un vettore vuoto,
    /// che non è una condizione d'errore ma il caso normale di una fonte
    /// silenziosa.
    ///
    /// # Perché c'è un massimo (FINAL-REVIEW-01, FR-001)
    ///
    /// Chi ingerisce ha un budget per tornata. Fino al 2026-10-03 questa
    /// funzione svuotava la coda e chi chiamava ne trattava una parte: il resto
    /// spariva senza conteggio. Ciò che non viene ritirato resta in coda, nel
    /// suo ordine, e il tetto della coda continua a valere.
    pub fn take_pending_events(&mut self, max: usize) -> Vec<lisi_telegram::ConnectorEvent> {
        let quanti = max.min(self.pending_events.len());
        self.pending_events.drain(..quanti).collect()
    }

    /// Vero se ci sono eventi in attesa di acquisizione.
    #[must_use]
    pub fn has_pending_events(&self) -> bool {
        !self.pending_events.is_empty()
    }

    /// Quanti eventi sono stati scartati per saturazione della coda.
    ///
    /// Monotono crescente per la vita del servizio: serve a poter **dichiarare**
    /// una perdita, non a nasconderla dietro un archivio incompleto.
    #[must_use]
    pub const fn dropped_event_count(&self) -> u64 {
        self.dropped_events
    }

    /// Sostituisce l'ultimo errore registrato con uno già classificato.
    ///
    /// È l'unico modo in cui `telegram_runtime` può far confluire una
    /// diagnostica dell'avvio Live ([`ServiceError::LiveStartup`]) nella vista
    /// che l'interfaccia già mostra (`view().failure`), senza duplicare quel
    /// canale.
    pub(crate) fn record_failure(&mut self, error: ServiceError) {
        self.failure = Some(error);
    }

    /// Esegue un'operazione sul connettore registrandone l'esito.
    fn run<F>(&mut self, operation: F) -> ServiceResult<()>
    where
        F: FnOnce(&mut dyn TelegramConnector) -> Result<(), TelegramError>,
    {
        self.busy = true;
        let outcome = operation(self.connector.as_mut());
        self.busy = false;

        match outcome {
            Ok(()) => {
                self.failure = None;
                Ok(())
            }
            Err(error) => {
                let translated = from_connector(error);
                // Il messaggio tecnico finisce nel registro applicativo; quello
                // per l'operatore passa dalla vista. Nessuno dei due contiene
                // un valore riservato.
                tracing::warn!(
                    kind = translated.kind(),
                    "operazione di accesso non riuscita"
                );
                let returned = ServiceError::from_kind_of(&translated);
                self.failure = Some(translated);
                Err(returned)
            }
        }
    }
}

impl ServiceError {
    /// Duplica un errore mantenendone la classe.
    ///
    /// Serve perché il servizio conserva l'errore per la vista **e** lo
    /// restituisce al chiamante, mentre `ServiceError` non è clonabile: le
    /// varianti che incapsulano errori di terze parti non lo consentono.
    fn from_kind_of(other: &Self) -> Self {
        match other {
            Self::CommandNotAllowed { command, state } => {
                Self::CommandNotAllowed { command, state }
            }
            Self::CodeRejected => Self::CodeRejected,
            Self::PasswordRejected => Self::PasswordRejected,
            Self::SessionRevoked => Self::SessionRevoked,
            Self::SessionUnavailable { reason } => Self::SessionUnavailable {
                reason: reason.clone(),
            },
            Self::ApplicationNotConfigured => Self::ApplicationNotConfigured,
            Self::DeviceIdentity { reason } => Self::DeviceIdentity {
                reason: reason.clone(),
            },
            Self::HubForbidden { reason } => Self::HubForbidden {
                reason: reason.clone(),
            },
            Self::HubClient { reason } => Self::HubClient {
                reason: reason.clone(),
            },
            Self::HubServer { reason } => Self::HubServer {
                reason: reason.clone(),
            },
            Self::AccountInUse => Self::AccountInUse,
            Self::ActiveAccountLimit { limit } => Self::ActiveAccountLimit { limit: *limit },
            Self::NetworkUnavailable => Self::NetworkUnavailable,
            Self::TimedOut => Self::TimedOut,
            Self::Cancelled => Self::Cancelled,
            Self::SourceNotAccessible => Self::SourceNotAccessible,
            Self::SourceAlreadyConfigured => Self::SourceAlreadyConfigured,
            Self::ReviewNeedsReason { state } => Self::ReviewNeedsReason { state },
            Self::WorkspaceNameTaken { name } => Self::WorkspaceNameTaken { name: name.clone() },
            Self::WorkspaceClosed { name } => Self::WorkspaceClosed { name: name.clone() },
            Self::AlreadyInWorkspace { name } => Self::AlreadyInWorkspace { name: name.clone() },
            Self::AlreadyBookmarked => Self::AlreadyBookmarked,
            Self::CollectionNameTaken { name } => Self::CollectionNameTaken { name: name.clone() },
            Self::CollectionNotEmpty { count } => Self::CollectionNotEmpty { count: *count },
            Self::TemplateNameTaken { name } => Self::TemplateNameTaken { name: name.clone() },
            Self::PersonAlreadyClosed => Self::PersonAlreadyClosed,
            Self::NoteAlreadyWithdrawn => Self::NoteAlreadyWithdrawn,
            Self::SavedSearchNameTaken { name } => {
                Self::SavedSearchNameTaken { name: name.clone() }
            }
            Self::SnapshotNeedsReason => Self::SnapshotNeedsReason,
            Self::SnapshotWithoutAnswer => Self::SnapshotWithoutAnswer,
            Self::ReviewStateUnchanged { state } => Self::ReviewStateUnchanged { state },
            Self::MonitoringActionNotAllowed { action, state } => {
                Self::MonitoringActionNotAllowed { action, state }
            }
            Self::ScheduleRefused { reason } => Self::ScheduleRefused { reason },
            Self::PauseRefused { reason } => Self::PauseRefused { reason },
            Self::ExportNotWritten { reason } => Self::ExportNotWritten {
                reason: reason.clone(),
            },
            Self::ProtectionNotGuaranteed { what, reason } => Self::ProtectionNotGuaranteed {
                what,
                reason: reason.clone(),
            },
            Self::SealedCopyRefused { reason } => Self::SealedCopyRefused {
                reason: reason.clone(),
            },
            Self::FascicoloRefused { reason } => Self::FascicoloRefused {
                reason: reason.clone(),
            },
            Self::SubjectEntryRefused { reason } => Self::SubjectEntryRefused {
                reason: reason.clone(),
            },
            Self::DocumentGeneration { reason } => Self::DocumentGeneration {
                reason: reason.clone(),
            },
            Self::ReportSelectionOutsideSession => Self::ReportSelectionOutsideSession,
            Self::WeakUnlockWord => Self::WeakUnlockWord,
            Self::WrongUnlockWord => Self::WrongUnlockWord,
            Self::MissingParticipantBasis => Self::MissingParticipantBasis,
            Self::ActionReservedToAdministrator { action } => {
                Self::ActionReservedToAdministrator { action: *action }
            }
            Self::ReasonRequired => Self::ReasonRequired,
            Self::DictionaryNameAlreadyUsed => Self::DictionaryNameAlreadyUsed,
            Self::TermAlreadyInVersion => Self::TermAlreadyInVersion,
            Self::AttackAssociationAlreadyStanding => Self::AttackAssociationAlreadyStanding,
            Self::BuiltInDictionaryIsReadOnly => Self::BuiltInDictionaryIsReadOnly,
            Self::DictionaryHasNoPublishedVersion => Self::DictionaryHasNoPublishedVersion,
            Self::EmptyDictionaryVersion => Self::EmptyDictionaryVersion,
            Self::PublishedVersionIsImmutable => Self::PublishedVersionIsImmutable,
            Self::DictionaryNotSelectable { name } => {
                Self::DictionaryNotSelectable { name: name.clone() }
            }
            Self::EmptyDictionarySelection => Self::EmptyDictionarySelection,
            Self::LinkNotOpened { reason } => Self::LinkNotOpened { reason },
            Self::NoObservationWindow { session } => {
                Self::NoObservationWindow { session: *session }
            }
            Self::ImportTooLarge { max } => Self::ImportTooLarge { max: *max },
            Self::ImportRefused { reason } => Self::ImportRefused { reason },
            Self::ImportExpressionRefused { position, reason } => Self::ImportExpressionRefused {
                position: *position,
                reason,
            },
            Self::CveImportRefused { reason } => Self::CveImportRefused { reason },
            Self::KevImportRefused { reason } => Self::KevImportRefused { reason },
            Self::UnreadableUpdateChannel { found } => Self::UnreadableUpdateChannel {
                found: found.clone(),
            },
            Self::UpdateNotFetched { reason } => Self::UpdateNotFetched {
                reason: reason.clone(),
            },
            Self::UpdateOriginMissing => Self::UpdateOriginMissing,
            Self::UpdateOriginRefused { reason } => Self::UpdateOriginRefused {
                reason: reason.clone(),
            },
            Self::DictionarySourceMissing => Self::DictionarySourceMissing,
            Self::NoDictionarySignerAllowed => Self::NoDictionarySignerAllowed,
            Self::DictionarySourceRefused { reason } => Self::DictionarySourceRefused {
                reason: reason.clone(),
            },
            Self::DictionarySignersRefused { reason } => Self::DictionarySignersRefused {
                reason: reason.clone(),
            },
            Self::TaxiiDestinationMissing => Self::TaxiiDestinationMissing,
            Self::TaxiiCredentialsMissing => Self::TaxiiCredentialsMissing,
            Self::TaxiiDestinationRefused { reason } => Self::TaxiiDestinationRefused {
                reason: reason.clone(),
            },
            Self::TaxiiPasswordRefused { reason } => Self::TaxiiPasswordRefused {
                reason: reason.clone(),
            },
            Self::TaxiiInExercise => Self::TaxiiInExercise,
            Self::SigningCertificateMissing => Self::SigningCertificateMissing,
            Self::SigningCertificateRefused { reason } => Self::SigningCertificateRefused {
                reason: reason.clone(),
            },
            Self::SigningInExercise => Self::SigningInExercise,
            Self::BackupScheduleRefused { reason } => Self::BackupScheduleRefused {
                reason: reason.clone(),
            },
            Self::OverviewRefused { reason } => Self::OverviewRefused {
                reason: reason.clone(),
            },
            Self::ConsultationLogRefused { reason } => Self::ConsultationLogRefused {
                reason: reason.clone(),
            },
            Self::SnapshotDownloadRefused { reason } => Self::SnapshotDownloadRefused {
                reason: reason.clone(),
            },
            Self::UpdateSignerRefused { reason } => Self::UpdateSignerRefused {
                reason: reason.clone(),
            },
            Self::UpdateArtifactElsewhere { expected } => Self::UpdateArtifactElsewhere {
                expected: expected.clone(),
            },
            Self::UpdateNotOffered => Self::UpdateNotOffered,
            Self::CandidateNotFound => Self::CandidateNotFound,
            Self::CandidateWithoutAddress => Self::CandidateWithoutAddress,
            Self::CandidateDecisionWithoutReason => Self::CandidateDecisionWithoutReason,
            Self::LinkBasisRefused { reason } => Self::LinkBasisRefused { reason },
            Self::UpdateNotVerified => Self::UpdateNotVerified,
            Self::UpdateMonitoringRunning { running } => {
                Self::UpdateMonitoringRunning { running: *running }
            }
            Self::AttackImportRefused { reason } => Self::AttackImportRefused { reason },
            Self::StixNothingToExport => Self::StixNothingToExport,
            Self::LiveStartup(diagnostic) => Self::LiveStartup(diagnostic.clone()),
            Self::Connector(_) | Self::Storage(_) | Self::Domain(_) | Self::Security(_) => {
                Self::Connector(TelegramError::Tdlib {
                    reason: String::from("errore tecnico registrato nel registro applicativo"),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;
    use std::collections::VecDeque;

    use lisi_telegram::{
        AccessibleChat, AuthorizationState, ClientParameters, ConnectionState, ConnectorEvent,
        LoginCode, PhoneNumber, TelegramConnector, TelegramError, TelegramResult,
        TwoFactorPassword,
    };

    use super::AuthenticationService;
    use crate::error::ServiceError;
    use crate::live_diagnostics::{LiveDiagnostic, LiveStartupPhase};

    #[test]
    fn la_preparazione_che_dura_dice_da_quanto_e_come_si_interrompe() {
        assert_eq!(
            super::preparing_detail(Duration::from_secs(1)),
            super::AuthStage::Preparing.detail()
        );
        let lunga = super::preparing_detail(Duration::from_secs(27));
        assert!(lunga.contains("in attesa da 27 secondi"), "{lunga}");
        assert!(lunga.contains("«Annulla»"), "{lunga}");
    }

    /// Connettore di prova che restituisce, in ordine, le risposte
    /// programmate da `poll_event`. Serve **solo** a dimostrare (o
    /// confutare) l'Ipotesi A del report dell'incidente del 2026-07-29:
    /// se `pump_events` dimentica di ripulire un fallimento registrato in
    /// precedenza quando arriva, in un pompaggio successivo, un evento di
    /// progresso reale.
    struct ScriptedConnector {
        state: AuthorizationState,
        poll_responses: VecDeque<TelegramResult<Option<ConnectorEvent>>>,
    }

    impl ScriptedConnector {
        fn new(responses: Vec<TelegramResult<Option<ConnectorEvent>>>) -> Self {
            Self {
                state: AuthorizationState::Uninitialized,
                poll_responses: responses.into_iter().collect(),
            }
        }
    }

    impl TelegramConnector for ScriptedConnector {
        fn start(&mut self, _parameters: &ClientParameters) -> TelegramResult<()> {
            Ok(())
        }

        fn submit_phone_number(&mut self, _phone: &PhoneNumber) -> TelegramResult<()> {
            Ok(())
        }

        fn submit_code(&mut self, _code: &LoginCode) -> TelegramResult<()> {
            Ok(())
        }

        fn submit_password(&mut self, _password: &TwoFactorPassword) -> TelegramResult<()> {
            Ok(())
        }

        fn poll_event(&mut self, _timeout: Duration) -> TelegramResult<Option<ConnectorEvent>> {
            match self.poll_responses.pop_front() {
                Some(Ok(Some(ConnectorEvent::Authorization(new_state)))) => {
                    self.state = new_state;
                    Ok(Some(ConnectorEvent::Authorization(new_state)))
                }
                Some(other) => other,
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

    /// Ipotesi A del report dell'incidente del 2026-07-29 (pilot Live
    /// ripetuto): un fallimento registrato da `pump_events` (per esempio un
    /// `ConnectorEvent::Failure` consegnato mentre l'accesso resta bloccato)
    /// deve smettere di essere riportato come diagnosi corrente non appena
    /// un evento di **progresso reale** (`ConnectorEvent::Authorization`)
    /// arriva in un pompaggio successivo: altrimenti l'operatore e chi legge
    /// `view().failure` continuerebbero a vedere l'ultima diagnosi anche
    /// dopo che l'accesso è davvero avanzato oltre quella fase.
    #[test]
    fn pump_events_clears_a_previous_failure_when_real_progress_arrives() {
        // `pump_events` drena l'intera coda disponibile in una sola
        // chiamata (fino a 256 eventi, o finché la coda non si svuota): il
        // sentinel `Ok(None)` fra i due eventi riproduce il confine reale
        // fra due pompaggi separati (per esempio due tick del timer di
        // `main.rs`), così che il fallimento e il progresso arrivino in
        // **chiamate distinte** a `pump_events`, come nell'incidente reale.
        let connector = ScriptedConnector::new(vec![
            Ok(Some(ConnectorEvent::Failure(TelegramError::Tdlib {
                reason: String::from("guasto grezzo di prova"),
            }))),
            Ok(None),
            Ok(Some(ConnectorEvent::Authorization(
                AuthorizationState::WaitingForTdlibParameters,
            ))),
        ]);
        let mut service = AuthenticationService::new(Box::new(connector));

        let Ok(consumed_first) = service.pump_events() else {
            panic!("il primo pompaggio non deve fallire");
        };
        assert_eq!(consumed_first, 1, "il primo pompaggio consegna il guasto");
        assert!(
            matches!(service.failure(), Some(ServiceError::Connector(_))),
            "il guasto grezzo deve essere registrato: {:?}",
            service.failure()
        );

        let Ok(consumed_second) = service.pump_events() else {
            panic!("il secondo pompaggio non deve fallire");
        };
        assert_eq!(
            consumed_second, 1,
            "il secondo pompaggio consegna il progresso"
        );
        assert!(
            service.failure().is_none(),
            "un progresso reale successivo deve ripulire il fallimento precedente: {:?}",
            service.failure()
        );
    }

    /// Regressione — rilevata dalla revisione indipendente sul rilievo 1: una
    /// sessione revocata arriva tipicamente come `Failure(SessionRevoked)`
    /// **seguita, nello stesso pompaggio**, da `Authorization(Failed)` (lo
    /// stato terminale che la revoca provoca). Uno stato terminale non è un
    /// progresso da festeggiare: pulire il fallimento anche lì
    /// cancellerebbe il motivo della chiusura prima che l'operatore possa
    /// leggerlo. Corrisponde al test di integrazione
    /// `crates/lisi-services/tests/authentication.rs::a_revoked_session_is_surfaced_through_the_event_pump`,
    /// che con la correzione incondizionata falliva.
    #[test]
    fn pump_events_does_not_clear_a_failure_followed_by_a_terminal_authorization_state() {
        let connector = ScriptedConnector::new(vec![
            Ok(Some(ConnectorEvent::Failure(TelegramError::SessionRevoked))),
            Ok(Some(ConnectorEvent::Authorization(
                AuthorizationState::Failed,
            ))),
        ]);
        let mut service = AuthenticationService::new(Box::new(connector));

        let Ok(consumed) = service.pump_events() else {
            panic!("il pompaggio non deve fallire");
        };
        assert_eq!(consumed, 2, "entrambi gli eventi devono essere consegnati");
        assert!(
            matches!(service.failure(), Some(ServiceError::SessionRevoked)),
            "lo stato terminale che segue la revoca non deve cancellarne il motivo: {:?}",
            service.failure()
        );
    }

    /// La stessa regola vale per `Closing`, che tipicamente precede
    /// `Closed` durante una chiusura provocata da un guasto: non è un
    /// progresso, quindi non deve ripulire un fallimento appena registrato.
    #[test]
    fn pump_events_does_not_clear_a_failure_followed_by_the_closing_state() {
        let connector = ScriptedConnector::new(vec![
            Ok(Some(ConnectorEvent::Failure(TelegramError::SessionRevoked))),
            Ok(Some(ConnectorEvent::Authorization(
                AuthorizationState::Closing,
            ))),
        ]);
        let mut service = AuthenticationService::new(Box::new(connector));

        let Ok(_) = service.pump_events() else {
            panic!("il pompaggio non deve fallire");
        };
        assert!(
            matches!(service.failure(), Some(ServiceError::SessionRevoked)),
            "'Closing' non e' un progresso e non deve ripulire il fallimento: {:?}",
            service.failure()
        );
    }

    /// Un evento che non è né un fallimento né un progresso di
    /// autorizzazione (qui: nessun evento pronto, o un cambio di
    /// connessione) non deve toccare un fallimento già registrato: solo un
    /// progresso reale (non terminale) lo ripulisce.
    #[test]
    fn pump_events_leaves_an_unrelated_absence_of_events_untouched() {
        let connector = ScriptedConnector::new(vec![
            Ok(Some(ConnectorEvent::Failure(TelegramError::Tdlib {
                reason: String::from("guasto grezzo di prova"),
            }))),
            Ok(Some(ConnectorEvent::Connection(ConnectionState::Online))),
        ]);
        let mut service = AuthenticationService::new(Box::new(connector));

        let Ok(_) = service.pump_events() else {
            panic!("il primo pompaggio non deve fallire");
        };
        assert!(service.failure().is_some());

        // Nessun altro evento è in coda: la coda vuota non deve ripulire un
        // fallimento reale.
        let Ok(consumed) = service.pump_events() else {
            panic!("il secondo pompaggio non deve fallire");
        };
        assert_eq!(consumed, 0);
        assert!(
            service.failure().is_some(),
            "l'assenza di eventi non deve ripulire un fallimento reale"
        );
    }

    /// Regressione diretta — incidente del 2026-07-30 (pilot Live ripetuto):
    /// un guasto grezzo **gia' riclassificato** in una diagnosi di avvio Live
    /// (`ServiceError::LiveStartup`, come fa `AccountRuntime::pump`) non deve
    /// essere sovrascritto da una ricostruzione generica quando lo stesso
    /// guasto grezzo si ripresenta a un pompaggio successivo: altrimenti la
    /// guardia "gia' classificato" che quel chiamante applica verrebbe
    /// vanificata, perche' opera su un valore che questa funzione ha appena
    /// cancellato.
    #[test]
    fn pump_events_does_not_overwrite_an_already_classified_live_startup_diagnosis_with_a_fresh_raw_error()
     {
        let connector = ScriptedConnector::new(vec![
            Err(TelegramError::Tdlib {
                reason: String::from("guasto grezzo persistente di prova"),
            }),
            Err(TelegramError::Tdlib {
                reason: String::from("guasto grezzo persistente di prova"),
            }),
        ]);
        let mut service = AuthenticationService::new(Box::new(connector));

        // Primo pompaggio: nessuna classificazione preesistente, il guasto
        // grezzo viene registrato normalmente (comportamento invariato).
        let Ok(consumed_first) = service.pump_events() else {
            panic!("il primo pompaggio non deve fallire");
        };
        assert_eq!(
            consumed_first, 0,
            "un guasto grezzo non e' un evento consegnato"
        );
        assert!(
            matches!(service.failure(), Some(ServiceError::Connector(_))),
            "il primo guasto grezzo deve essere registrato cosi' com'e': {:?}",
            service.failure()
        );

        // Un chiamante (per esempio `AccountRuntime::pump`) lo riclassifica in
        // una diagnosi di avvio Live, come farebbe davvero.
        let diagnostic = LiveDiagnostic::new(
            LiveStartupPhase::PollingStart,
            "errore_connettore",
            "nessun aggiornamento ricevuto dal connettore",
            lisi_core::Timestamp::from_millis(1_700_000_000_000),
            Some(String::from("account-di-prova")),
        );
        service.record_failure(ServiceError::LiveStartup(diagnostic));

        // Secondo pompaggio: lo stesso guasto grezzo si ripresenta. La
        // diagnosi gia' classificata non deve essere sovrascritta dalla sua
        // ricostruzione generica.
        let Ok(consumed_second) = service.pump_events() else {
            panic!("il secondo pompaggio non deve fallire");
        };
        assert_eq!(consumed_second, 0);
        assert!(
            matches!(service.failure(), Some(ServiceError::LiveStartup(_))),
            "la diagnosi gia' classificata non deve essere sovrascritta da un \
             guasto grezzo che si ripresenta identico: {:?}",
            service.failure()
        );
    }

    /// Contro-prova del test precedente, richiesta dalla revisione
    /// indipendente del 2026-07-30: la soppressione deve valere **solo** per
    /// il guasto identico. Un guasto grezzo **diverso** che sopraggiunge dopo
    /// una diagnosi gia' classificata deve restare visibile, altrimenti si
    /// reintroduce la diagnosi stantia che maschera un blocco successivo —
    /// esattamente il difetto corretto dopo l'incidente del 2026-07-29.
    #[test]
    fn pump_events_still_reports_a_genuinely_different_raw_error_after_a_classified_diagnosis() {
        let connector = ScriptedConnector::new(vec![
            Err(TelegramError::Tdlib {
                reason: String::from("primo guasto grezzo di prova"),
            }),
            Err(TelegramError::Tdlib {
                reason: String::from("secondo guasto grezzo, diverso dal primo"),
            }),
        ]);
        let mut service = AuthenticationService::new(Box::new(connector));

        let Ok(_) = service.pump_events() else {
            panic!("il primo pompaggio non deve fallire");
        };
        let diagnostic = LiveDiagnostic::new(
            LiveStartupPhase::PollingStart,
            "errore_connettore",
            "nessun aggiornamento ricevuto dal connettore",
            lisi_core::Timestamp::from_millis(1_700_000_000_000),
            Some(String::from("account-di-prova")),
        );
        service.record_failure(ServiceError::LiveStartup(diagnostic));

        let Ok(_) = service.pump_events() else {
            panic!("il secondo pompaggio non deve fallire");
        };
        let Some(failure) = service.failure() else {
            panic!("un guasto grezzo diverso non deve sparire in silenzio");
        };
        assert!(
            matches!(failure, ServiceError::Connector(_)),
            "un guasto grezzo diverso da quello gia' classificato deve \
             sostituire la diagnosi, non restare nascosto: {failure:?}"
        );
        assert!(
            failure.to_string().contains("secondo guasto grezzo"),
            "deve essere riportato il guasto nuovo, non quello precedente: {failure}"
        );
    }

    /// Il cuore del collegamento con l'acquisizione: `pump_events` e' l'unico
    /// punto del prodotto che legge dal connettore, quindi cio' che non
    /// riguarda l'accesso non puo' essere buttato via - altrimenti l'unico
    /// modo per acquisirlo sarebbe un secondo consumatore della stessa coda,
    /// cioe' una corsa che perde contenuti in silenzio.
    #[test]
    fn the_events_that_do_not_concern_the_login_are_kept_for_acquisition() {
        let connector = ScriptedConnector::new(vec![
            Ok(Some(ConnectorEvent::Connection(ConnectionState::Online))),
            Ok(Some(ConnectorEvent::Authorization(
                AuthorizationState::WaitingForPhoneNumber,
            ))),
            Ok(Some(ConnectorEvent::Connection(
                ConnectionState::Interrupted,
            ))),
            Ok(None),
        ]);
        let mut service = AuthenticationService::new(Box::new(connector));

        let Ok(consumed) = service.pump_events() else {
            panic!("il pompaggio non deve fallire");
        };
        assert_eq!(consumed, 3, "tutti e tre gli eventi sono stati letti");

        let pending = service.take_pending_events(usize::MAX);
        assert_eq!(
            pending.len(),
            2,
            "i due eventi di connessione devono essere conservati: {pending:?}"
        );
        assert!(
            pending
                .iter()
                .all(|event| !matches!(event, ConnectorEvent::Authorization(_))),
            "un evento di autorizzazione non deve mai finire nella coda \
             dell'acquisizione: lo gestisce questo servizio"
        );

        // Ritirarli svuota la coda: nessuna doppia ingestione.
        assert!(
            service.take_pending_events(usize::MAX).is_empty(),
            "un secondo ritiro non deve restituire gli stessi eventi"
        );
    }

    /// A coda satura si scarta il piu' vecchio e **si conta**: una perdita di
    /// contenuti deve poter essere dichiarata, non nascosta dietro un archivio
    /// incompleto che nessuno sa essere incompleto.
    #[test]
    fn a_saturated_queue_drops_the_oldest_events_and_counts_them() {
        let overflow = 3_usize;
        let total = super::PENDING_EVENTS_CAPACITY + overflow;
        let mut responses: Vec<TelegramResult<Option<ConnectorEvent>>> = Vec::with_capacity(total);
        for _ in 0..total {
            responses.push(Ok(Some(ConnectorEvent::Connection(
                ConnectionState::Online,
            ))));
        }
        responses.push(Ok(None));

        let mut service = AuthenticationService::new(Box::new(ScriptedConnector::new(responses)));
        assert_eq!(
            service.dropped_event_count(),
            0,
            "nessuna perdita prima di aver pompato"
        );

        // `pump_events` legge al massimo 256 eventi per giro: servono piu'
        // giri per superare il tetto.
        for _ in 0..total.div_ceil(256) + 1 {
            let Ok(_) = service.pump_events() else {
                panic!("il pompaggio non deve fallire");
            };
        }

        assert_eq!(
            service.take_pending_events(usize::MAX).len(),
            super::PENDING_EVENTS_CAPACITY,
            "la coda non deve superare il proprio tetto"
        );
        assert_eq!(
            service.dropped_event_count(),
            overflow as u64,
            "ogni evento scartato deve essere contato"
        );
    }

    /// **Un ritiro limitato lascia il resto in coda, nel suo ordine**
    /// (FINAL-REVIEW-01, FR-001).
    ///
    /// Chi ingerisce ne tratta sessantaquattro per tornata. Fino al
    /// 2026-10-03 il ritiro svuotava la coda e il resto spariva senza essere
    /// contato: duecento eventi arrivati insieme ne lasciavano in archivio
    /// sessantaquattro. Qui duecento eventi si ritirano in quattro tornate e
    /// arrivano tutti, nello stesso ordine, senza nessuna perdita contata.
    #[test]
    fn a_bounded_take_leaves_the_rest_in_the_queue_in_order() {
        let total = 200_usize;
        let stato = |indice: usize| {
            if indice.is_multiple_of(3) {
                ConnectionState::Interrupted
            } else {
                ConnectionState::Online
            }
        };
        let mut responses: Vec<TelegramResult<Option<ConnectorEvent>>> = (0..total)
            .map(|indice| Ok(Some(ConnectorEvent::Connection(stato(indice)))))
            .collect();
        responses.push(Ok(None));
        let mut service = AuthenticationService::new(Box::new(ScriptedConnector::new(responses)));
        let Ok(letti) = service.pump_events() else {
            panic!("il pompaggio non deve fallire");
        };
        assert_eq!(letti, total);

        let mut ritirati = Vec::new();
        for _ in 0..4 {
            let tornata = service.take_pending_events(64);
            assert!(tornata.len() <= 64, "una tornata non supera il massimo");
            ritirati.extend(tornata);
        }

        assert!(
            !service.has_pending_events(),
            "dopo quattro tornate la coda è vuota"
        );
        assert_eq!(
            ritirati.len(),
            total,
            "nessun evento perso fra una tornata e l'altra"
        );
        for (indice, evento) in ritirati.iter().enumerate() {
            assert!(
                matches!(evento, ConnectorEvent::Connection(stato_letto) if *stato_letto == stato(indice)),
                "l'evento {indice} è fuori ordine: {evento:?}"
            );
        }
        assert_eq!(service.dropped_event_count(), 0);
    }
}

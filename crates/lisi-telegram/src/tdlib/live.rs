//! Connettore reale verso Telegram attraverso TDLib.
//!
//! A differenza del proof of concept in `super`, questo modulo **non disattiva la
//! rete**: implementa `crate::connector::TelegramConnector` collegandosi
//! davvero, guidato dallo stato di autorizzazione comunicato da TDLib. Resta
//! comunque isolato dietro la feature `tdlib-runtime` e non contiene alcun
//! `unsafe`: l'unico confine non sicuro è quello di `ffi.rs`.
//!
//! # Postura passiva (ADR-0019 §5)
//!
//! Il connettore osserva soltanto: autorizzazione, elenco delle chat già
//! accessibili, ricezione e normalizzazione degli aggiornamenti. Non invia
//! messaggi, non reagisce, non entra o esce da gruppi, non forza letture né
//! scarica media. Le uniche richieste emesse sono di risveglio del client
//! appena creato (`getOption` di sola lettura, vedere `start()`), di
//! autorizzazione, configurazione, lettura dell'elenco chat e chiusura
//! ordinata.
//!
//! # Segreti (ADR-0019 §3)
//!
//! API hash, numero, codice, password e chiave del database non compaiono mai in
//! log, errori o resa `Debug`. I valori riservati esistono in chiaro solo per il
//! tempo della singola richiesta TDLib in cui vengono trasmessi. La chiave del
//! database arriva dal costruttore come base64 già pronta, così che questo crate
//! non dipenda da `lisi-security`.
//!
//! # Confine e fragilità dichiarata
//!
//! Gli aggiornamenti sono ispezionati con gli stessi helper testuali del proof
//! of concept (`super::json_string_value`, `super::json_type`) più alcuni
//! estrattori numerici locali, non con un deserializzatore tipizzato. È una
//! scelta di superficie minima per il pilot: la sostituzione con una
//! deserializzazione tipizzata è un naturale seguito ed è annotata come limite.

use core::fmt;
use core::time::Duration;
use std::collections::{BTreeMap, VecDeque};

use lisi_core::Timestamp;

use tracing::{debug, warn};

use crate::attachment::{
    AttachmentDescriptor, AttachmentKind, clean_declared_mime, clean_declared_name, declared_size,
};
use crate::auth::{AuthorizationMachine, AuthorizationState};
use crate::chat::{AccessibleChat, ChatKind};
use crate::connector::{ClientParameters, TelegramConnector};
use crate::correlation::{Correlator, Delivery, Incoming, RequestId, Resolution};
use crate::error::{TelegramError, TelegramResult};
use crate::event::{
    ConnectionState, ConnectorEvent, DeletedMessages, EditedMessage, IncomingMessage,
};
use crate::identifier::{ChatId, MessageId};
use crate::link::{LinkGap, LinkOutcome, MessageLink};
use crate::lookup::{LookupKind, LookupProfile, LookupQuery, LookupReply, OfficialLookup};
use crate::relation::{
    ContextMessage, ForwardOrigin, Forwarded, MessageRelations, ReplyTo, Thread,
};
use crate::secret::{LoginCode, PhoneNumber, REDACTED, TwoFactorPassword};
use crate::tdlib::ffi::TdJsonLibrary;

use super::{json_object_value, json_string_value, json_type};

/// Numero massimo di letture vuote durante l'arresto ordinato, per non bloccarsi
/// se la libreria non conferma la chiusura (vedere [`Attesa`]).
const SHUTDOWN_MAX_POLLS: usize = 200;

/// Numero massimo di letture vuote durante la raccolta dell'elenco chat (vedere
/// [`Attesa`]).
const CHATS_MAX_POLLS: usize = 4_000;

/// Aggiornamenti grezzi che una sola chiamata a `poll_event` può assorbire
/// senza consegnare nulla, prima di restituire la parola a chi la chiama
/// (vedere `poll_event`, OBS-TG-1).
const POLL_MAX_ABSORBED: usize = 256;

/// Tetto ai messaggi chiesti in una sola pagina di cronologia.
///
/// E' il massimo che getChatHistory accetta. Chiederne di piu' non e' un
/// errore per TDLib, che tronca in silenzio: il tetto sta qui perche' il numero
/// chiesto e quello ottenibile coincidano, invece di far credere a chi chiama
/// di aver chiesto mille messaggi.
const HISTORY_MAX_LIMIT: u32 = 100;

/// Entro quanto ci si aspetta una pagina di cronologia.
///
/// Fino al 2026-10-03 l'attesa finiva dopo un secondo di silenzio (venti
/// letture vuote), e su una rete lenta una pagina chiesta con
/// `only_local: false` arrivava dopo: diventava la risposta della richiesta
/// successiva (FINAL-REVIEW-01, FR-007). Ora la richiesta è correlata e si
/// aspetta fino a questo termine, che è anche quello dichiarato nell'errore.
/// **Dieci secondi**, come l'elenco delle chat.
const HISTORY_TIMEOUT_MS: i64 = 10_000;

/// Contenitore di un valore riservato di questo modulo.
///
/// Come i tipi di `crate::secret`, redige la propria resa `Debug` e non
/// implementa `Display`: un segreto non può finire in un log nemmeno per errore.
struct Redacted(String);

impl Redacted {
    fn new(value: String) -> Self {
        Self(value)
    }

    /// Espone il valore in chiaro: da usare solo per comporre una richiesta.
    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Redacted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

/// Parametri già pronti per `setTdlibParameters`, calcolati una sola volta
/// all'avvio e riusati quando la libreria li richiede.
///
/// I valori riservati sono redatti nella resa `Debug`: la struttura non può
/// stamparli. I campi non riservati (percorsi, lingua, versione) restano
/// leggibili per la diagnostica.
struct PreparedParameters {
    api_id: i32,
    api_hash: Redacted,
    database_directory: String,
    files_directory: String,
    database_key_base64: Redacted,
    use_test_dc: bool,
    system_language_code: String,
    application_version: String,
}

impl fmt::Debug for PreparedParameters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedParameters")
            .field("api_id", &REDACTED)
            .field("api_hash", &self.api_hash)
            .field("database_directory", &self.database_directory)
            .field("files_directory", &self.files_directory)
            .field("database_encryption_key", &self.database_key_base64)
            .field("use_test_dc", &self.use_test_dc)
            .field("system_language_code", &self.system_language_code)
            .field("application_version", &self.application_version)
            .finish()
    }
}

/// Confine minimo verso le quattro funzioni FFI usate da questo modulo.
///
/// Esiste per un solo motivo: iniettare nei test un doppio fittizio che si
/// comporta come TDLib senza caricare alcuna libreria nativa, così che il
/// percorso completo (avvio, prima ricezione, riconoscimento
/// dell'aggiornamento, normalizzazione, transizione, evento restituito da
/// [`TelegramConnector::poll_event`]) sia dimostrabile con un test, non solo
/// ipotizzato (incidente del 2026-07-29). **Nessuna** implementazione diversa
/// da [`TdJsonLibrary`] esiste fuori da `#[cfg(test)]`: l'unico `unsafe`
/// resta confinato a `ffi.rs` (ADR-0003), che questo trait non tocca e la cui
/// superficie si limita a inoltrare.
pub trait TdJsonBackend: fmt::Debug {
    /// Vedere [`TdJsonLibrary::create_client_id`].
    fn create_client_id(&self) -> TelegramResult<i32>;
    /// Vedere [`TdJsonLibrary::send`].
    fn send(&self, client_id: i32, request: &str) -> TelegramResult<()>;
    /// Vedere [`TdJsonLibrary::receive`].
    fn receive(&self, timeout_seconds: f64) -> TelegramResult<Option<String>>;
    /// Vedere [`TdJsonLibrary::execute`].
    fn execute(&self, request: &str) -> TelegramResult<Option<String>>;
}

impl TdJsonBackend for TdJsonLibrary {
    fn create_client_id(&self) -> TelegramResult<i32> {
        Self::create_client_id(self)
    }

    fn send(&self, client_id: i32, request: &str) -> TelegramResult<()> {
        Self::send(self, client_id, request)
    }

    fn receive(&self, timeout_seconds: f64) -> TelegramResult<Option<String>> {
        Self::receive(self, timeout_seconds)
    }

    fn execute(&self, request: &str) -> TelegramResult<Option<String>> {
        Self::execute(self, request)
    }
}

/// Connettore reale verso Telegram.
///
/// Vive per un solo account: directory, chiave del database e client TDLib sono
/// suoi. Il modello multi-account (ADR-0019 §1) prevede un'istanza per account,
/// non una condivisa.
///
/// Generico sul confine FFI ([`TdJsonBackend`]) solo per poter essere
/// costruito, nei test, attorno a un doppio fittizio: in produzione `L` è
/// sempre [`TdJsonLibrary`], come esprime il parametro predefinito.
#[derive(Debug)]
pub struct LiveTdlibConnector<L = TdJsonLibrary> {
    library: L,
    database_key_base64: Redacted,
    machine: AuthorizationMachine,
    connection: ConnectionState,
    client_id: Option<i32>,
    prepared: Option<PreparedParameters>,
    /// Eventi già normalizzati ma non ancora consegnati: riempita quando altre
    /// operazioni (per esempio l'elenco chat) drenano la coda della libreria, in
    /// modo che nessun contenuto vada perso.
    pending: VecDeque<ConnectorEvent>,
    /// Chat accessibili annunciate da TDLib, accumulate da **qualunque**
    /// percorso di lettura.
    ///
    /// Esiste perché `updateNewChat` arriva una volta sola per client: senza
    /// un registro, l'elenco delle fonti disponibili dipenderebbe da quale
    /// lettore ha visto l'annuncio per primo — il pompaggio periodico o
    /// [`TelegramConnector::accessible_chats`] — e sarebbe monco in modo
    /// intermittente e senza errore.
    known_chats: BTreeMap<i64, AccessibleChat>,
    /// Utenti annunciati da `updateUser`, per nominare gli autori dei messaggi
    /// senza chiedere nulla in più alla piattaforma.
    known_users: BTreeMap<i64, KnownUser>,
    /// Username dei supergruppi annunciati da `updateSupergroup`.
    ///
    /// Sta in un registro **separato** da quello delle chat perché i due
    /// aggiornamenti arrivano indipendentemente e in ordine non garantito: la
    /// chat può essere annunciata prima del supergruppo o dopo. Fonderli al
    /// momento dell'arrivo avrebbe fatto dipendere il risultato da quale dei due
    /// arriva primo — e sarebbe stato lo stesso difetto già costato l'elenco
    /// delle fonti monco del 2026-07-30. La fusione avviene **in lettura**.
    supergroup_usernames: BTreeMap<i64, String>,
    /// Da chat al supergruppo che la realizza, per collegare i due registri.
    chat_supergroups: BTreeMap<i64, i64>,
    ignored_updates: u64,
    started: bool,
    /// Se la richiesta di risveglio del client (vedere [`Self::start`]) è
    /// stata inviata **con successo**.
    ///
    /// Distingue lo stato osservabile "avviato e risvegliato" da quello
    /// "client creato ma mai risvegliato": `client_id` resta `Some` anche se
    /// il risveglio fallisce (il client esiste già per davvero dentro TDLib,
    /// e ricrearne un secondo lo lascerebbe orfano — vedere il commento su
    /// [`Self::start`]), ma senza questo campo un chiamante non potrebbe
    /// distinguere le due situazioni e proverebbe comunque a ricevere in
    /// silenzio da un client mai risvegliato (incidente del 2026-07-30).
    wakeup_confirmed: bool,
    /// A quale richiesta appartiene ogni risposta (TDL-REQ-01).
    ///
    /// Prima di questo campo le risposte si riconoscevano **per tipo**, e con
    /// due richieste dello stesso tipo restava solo il conteggio: un errore
    /// che arrivava in mezzo veniva assorbito come benigno «perche' e' quasi
    /// sempre di `loadChats`». Adesso si sa di chi sia.
    correlator: Correlator,
    /// Fino a quando Telegram ha chiesto di non fare richieste, in millisecondi
    /// dall'epoca (FINAL-REVIEW-01, FR-008).
    ///
    /// Un limite di frequenza (429, `FLOOD_WAIT`) arrivato **anche in ritardo**,
    /// a una richiesta che nessuno aspettava più, resta qui: le richieste
    /// puntuali successive non partono prima che l'attesa indicata sia passata.
    flood_wait_until_ms: Option<i64>,
}

impl<L: TdJsonBackend> LiveTdlibConnector<L> {
    /// Crea un connettore reale attorno a una libreria TDLib già caricata.
    ///
    /// La chiave di cifratura del database dell'account arriva **già codificata
    /// in base64 standard**: è la forma esposta da `lisi_security::AccountKey`
    /// tramite `as_base64()`. Riceverla come stringa, e non come tipo di
    /// `lisi-security`, evita che `lisi-telegram` dipenda da quel crate e tiene
    /// il confine sottile. La chiave è custodita redatta e non compare mai in
    /// log, errori o resa `Debug`.
    #[must_use]
    pub fn new(library: L, database_key_base64: String) -> Self {
        Self {
            library,
            database_key_base64: Redacted::new(database_key_base64),
            machine: AuthorizationMachine::new(),
            connection: ConnectionState::Offline,
            client_id: None,
            prepared: None,
            pending: VecDeque::new(),
            known_chats: BTreeMap::new(),
            known_users: BTreeMap::new(),
            supergroup_usernames: BTreeMap::new(),
            chat_supergroups: BTreeMap::new(),
            ignored_updates: 0,
            started: false,
            wakeup_confirmed: false,
            correlator: Correlator::default(),
            flood_wait_until_ms: None,
        }
    }

    /// Numero di aggiornamenti ignorati perché non pertinenti o non supportati.
    ///
    /// Serve alla diagnostica e alle metriche: un aggiornamento ignorato non è
    /// un errore, ma la sua frequenza racconta quanto la normalizzazione copra
    /// il flusso reale.
    #[must_use]
    pub const fn ignored_update_count(&self) -> u64 {
        self.ignored_updates
    }

    /// Reagisce a un `updateAuthorizationState`.
    ///
    /// Per gli otto stati canonici applica **prima** la transizione sorvegliata
    /// dalla macchina, e solo dopo, se lo stato appena raggiunto è l'attesa dei
    /// parametri, li invia. L'ordine non è un dettaglio: l'aggiornamento
    /// TDLib appena letto da `poll_event` è già stato consumato dalla coda
    /// della libreria e non viene mai re-inviato. Se l'invio dei parametri
    /// fallisse mentre la transizione avviene *prima* (l'ordine corretto), lo
    /// stato interno riflette comunque ciò che TDLib ha davvero comunicato,
    /// anziché restare stantio sul valore precedente: un ordine invertito
    /// (invio prima, transizione poi) lascerebbe la macchina bloccata in
    /// silenzio su quello stato precedente per sempre in caso di guasto
    /// dell'invio, senza che nulla lo segnali con la fase corretta
    /// (incidente del 2026-07-29, "sospetto strutturale #1"). Per uno stato
    /// non mappato registra soltanto il tipo e lo conta, senza panico né
    /// transizione illecita.
    fn handle_authorization(&mut self, json: &str) -> TelegramResult<Option<ConnectorEvent>> {
        let Some(inner) = nested_type(json, "authorization_state") else {
            self.ignored_updates += 1;
            return Ok(None);
        };

        let Some(state) = map_authorization_state(&inner) else {
            // ADR-0019 §7: stati ulteriori (email, registrazione, conferma da
            // altro dispositivo, passkey, o non ancora mappati) non causano
            // panico né blocco. Si registra solo il tipo, mai un contenuto.
            warn!(
                stato = inner.as_str(),
                "stato di autorizzazione non supportato: ignorato e conteggiato"
            );
            self.ignored_updates += 1;
            return Ok(None);
        };

        // Uno stato ripetuto (per esempio `ready` dopo una riconnessione, o
        // `closing` inviato due volte) non è una transizione: si assorbe senza
        // errore e senza rieventare.
        if state == self.machine.state() {
            return Ok(None);
        }

        let from = self.machine.state();
        if let Err(_error) = self.machine.transition_to(state) {
            warn!(
                from = from.as_str(),
                to = state.as_str(),
                "transizione di autorizzazione inattesa: ignorata"
            );
            self.ignored_updates += 1;
            return Ok(None);
        }

        if state == AuthorizationState::WaitingForTdlibParameters {
            let request = self.prepared.as_ref().map(build_tdlib_parameters);
            if let (Some(request), Some(client_id)) = (request, self.client_id) {
                self.library.send(client_id, &request)?;
            }
        } else if state == AuthorizationState::WaitingForCode {
            // Nessun dato riservato: solo la conferma, per la diagnostica,
            // che la richiesta del codice e' davvero arrivata da Telegram e
            // non e' andata persa fra l'invio del numero e questo punto.
            debug!(
                passo = "codice_richiesto_da_telegram",
                "authorizationStateWaitCode ricevuto da Telegram"
            );
        }

        Ok(Some(ConnectorEvent::Authorization(state)))
    }

    /// Aggiunge al messaggio il nome e lo username dell'autore, se noti.
    ///
    /// Non chiede nulla alla piattaforma: consulta soltanto ciò che gli
    /// aggiornamenti hanno già portato. Un autore mai annunciato resta senza
    /// nome, ed è la risposta giusta — un archivio che inventasse un nome
    /// sarebbe peggio di uno che ammette di non averlo.
    fn name_the_author(&self, message: &mut IncomingMessage) {
        let Some(raw_id) = message
            .author_identifier
            .as_deref()
            .and_then(|value| value.parse::<i64>().ok())
        else {
            // Nessun autore individuale: un messaggio di canale non ha un nome
            // di persona da cercare.
            return;
        };

        if let Some(known) = self.known_users.get(&raw_id) {
            message.author.clone_from(&known.display_name);
            message.author_username.clone_from(&known.username);
        }
    }

    /// Interpreta un aggiornamento non di autorizzazione e ne aggiorna lo stato
    /// interno di connessione, restituendo l'eventuale evento normalizzato.
    fn absorb_update(&mut self, json: &str) -> Option<ConnectorEvent> {
        // `updateNewChat` non e' un contenuto e non produce un evento, ma non
        // va **buttato via**: e' l'unico modo in cui TDLib annuncia una chat
        // accessibile, e la annuncia **una volta sola** per client. Finiva nel
        // ramo "ignorato" di `normalize_update`, quindi il pompaggio periodico
        // (ogni 200 ms) se lo mangiava prima che `accessible_chats` potesse
        // vederlo: due consumatori della stessa coda, e chi arriva primo fa
        // sparire la chat per sempre. L'operatore vedeva un elenco delle fonti
        // disponibili completo la prima volta e monco dopo, senza alcun errore
        // (osservato il 2026-07-30 con le chat archiviate, che sparivano al
        // secondo accesso alla schermata). Registrandole qui, da **qualunque**
        // percorso di lettura, l'elenco non dipende piu' da chi legge per
        // primo.
        if json_type(json).as_deref() == Some("updateNewChat") {
            if let Some(chat) = parse_accessible_chat(json) {
                // Il legame chat → supergruppo si registra qui perché è l'unico
                // punto in cui l'aggiornamento lo porta.
                if let Some(supergroup_id) = parse_chat_supergroup_id(json) {
                    self.chat_supergroups
                        .insert(chat.chat_id.get(), supergroup_id);
                }
                self.known_chats.insert(chat.chat_id.get(), chat);
            }
            return None;
        }

        // `updateSupergroup` porta lo username pubblico di canali e supergruppi.
        // Arriva indipendentemente da `updateNewChat`, e in ordine non
        // garantito: si registra e basta, e la fusione avviene in lettura.
        if json_type(json).as_deref() == Some("updateSupergroup") {
            if let Some((supergroup_id, username)) = parse_supergroup_username(json) {
                self.supergroup_usernames.insert(supergroup_id, username);
            }
            return None;
        }

        // `updateUser` non e' un contenuto, e vale per gli utenti cio' che
        // `updateNewChat` vale per le chat: e' il modo in cui TDLib annuncia
        // **chi** sono gli identificativi che i messaggi portano. Registrarlo
        // qui evita di dover chiedere `getUser` per ogni autore, che sarebbe
        // una richiesta in piu' per ogni messaggio e un'esposizione ai limiti
        // di frequenza per un dato che arriva comunque da solo.
        if json_type(json).as_deref() == Some("updateUser") {
            if let Some(known) = parse_known_user(json) {
                self.known_users.insert(known.user_id, known);
            }
            return None;
        }

        let event = normalize_update(json, now_millis());

        // Il nome e lo username si aggiungono **dopo** la normalizzazione, e
        // non dentro: la traduzione di un messaggio deve restare una funzione
        // pura del messaggio, mentre questi due dipendono da cio' che il
        // connettore ha imparato finora. Un messaggio il cui autore non e'
        // ancora noto resta senza: e' la verita', e inventarla sarebbe peggio.
        let event = match event {
            Normalized::Event(ConnectorEvent::MessageReceived(mut message)) => {
                self.name_the_author(&mut message);
                Normalized::Event(ConnectorEvent::MessageReceived(message))
            }
            other => other,
        };

        match event {
            Normalized::Event(event) => {
                if let ConnectorEvent::Connection(state) = &event {
                    self.connection = *state;
                }
                Some(event)
            }
            Normalized::Ignored => {
                self.ignored_updates += 1;
                None
            }
        }
    }

    /// Verifica che il connettore sia osservabile come **avviato e
    /// risvegliato**, restituendo il `client_id` se lo è.
    ///
    /// Distingue due guasti che prima di questa correzione condividevano lo
    /// stesso messaggio generico "il connettore non e' stato avviato",
    /// indistinguibile l'uno dall'altro e dal caso "nessun aggiornamento
    /// ricevuto" (buco diagnostico rilevato dal pilot Live ripetuto del
    /// 2026-07-30):
    ///
    /// 1. il client non è mai stato creato (`client_id` è `None`): `start()`
    ///    non è mai stato chiamato, oppure è fallito prima di creare il
    ///    client;
    /// 2. il client è stato creato ma il risveglio non è confermato
    ///    (`wakeup_confirmed` è `false`): `start()` è fallito **dopo** aver
    ///    creato il client per davvero dentro TDLib (irreversibile), sul
    ///    proprio invio di risveglio.
    ///
    /// Nessuno dei due casi tenta di leggere dalla libreria: un client mai
    /// risvegliato non emetterebbe comunque nulla di spontaneo (vedere il
    /// commento in [`TelegramConnector::start`]), quindi proseguire fino a
    /// `receive` produrrebbe solo un silenzio indistinguibile da una fonte
    /// quieta, mascherando il guasto reale.
    fn ensure_woken(&self) -> TelegramResult<i32> {
        let Some(client_id) = self.client_id else {
            return Err(TelegramError::Tdlib {
                reason: String::from(
                    "il collegamento a Telegram non risulta creato: il connettore non è mai stato \
                     avviato",
                ),
            });
        };
        if !self.wakeup_confirmed {
            return Err(TelegramError::Tdlib {
                reason: String::from(
                    "il collegamento a Telegram è stato creato ma il risveglio iniziale non è \
                     stato confermato",
                ),
            });
        }
        Ok(client_id)
    }
    /// A chi appartiene un messaggio uscito dalla coda.
    ///
    /// # Perché la classificazione sta qui e la correlazione no
    ///
    /// Perché questa funzione conosce il **formato** — `@type`, `@extra`, la
    /// forma di un errore — e il correlatore no: `crate::correlation` è
    /// provabile per intero su una macchina che TDLib non ce l'ha, ed è la
    /// ragione per cui esiste separato.
    ///
    /// Un `@extra` che il correlatore non ha mai coniato **non è la risposta a
    /// niente**: potrebbe essere l'eco di un campo scritto da qualcun altro, e
    /// trattarlo come nostro consegnerebbe un messaggio estraneo a una
    /// richiesta che aspetta.
    fn classify(&self, json: &str) -> Incoming {
        let Some(id) = json_extra(json).and_then(|raw| self.correlator.recognise(raw)) else {
            return Incoming::Unsolicited {
                payload: json.to_owned(),
            };
        };

        if json_type(json).as_deref() == Some("error") {
            return Incoming::Failure {
                id,
                code: i32::try_from(json_number_value(json, "code").unwrap_or(0)).unwrap_or(0),
                // Il messaggio di TDLib e' una costante del protocollo, non un
                // contenuto remoto: non porta testo di messaggi ne' identita'.
                message: json_string_value(json, "message").unwrap_or_default(),
            };
        }

        Incoming::Answer {
            id,
            payload: json.to_owned(),
        }
    }

    /// Se la risposta è un limite di frequenza, ricorda fino a quando vale
    /// (FINAL-REVIEW-01, FR-008).
    ///
    /// Vale anche per una risposta **tardiva**, a una richiesta che nessuno
    /// aspettava più: il limite è di Telegram, non della richiesta, e
    /// rispettarlo è la regola (CLAUDE.md: nessuna evasione dei limiti).
    fn note_rate_limit(&mut self, incoming: &Incoming) {
        let Incoming::Failure { code, message, .. } = incoming else {
            return;
        };
        if *code != 429 && !message.contains("FLOOD_WAIT") {
            return;
        }
        let secondi = indicated_wait_seconds(message).unwrap_or(DEFAULT_FLOOD_WAIT_SECONDS);
        let fino = adesso()
            .as_millis()
            .saturating_add(secondi.saturating_mul(1_000));
        self.flood_wait_until_ms = Some(
            self.flood_wait_until_ms
                .map_or(fino, |prima| prima.max(fino)),
        );
        tracing::warn!(
            secondi,
            "Telegram ha chiesto di attendere prima di altre richieste"
        );
    }

    /// I secondi che restano dell'attesa chiesta da Telegram, se ne restano.
    fn flood_wait_remaining(&self) -> Option<i64> {
        let resta = self.flood_wait_until_ms? - adesso().as_millis();
        (resta > 0).then_some((resta + 999) / 1_000)
    }

    /// Una risposta etichettata arrivata quando nessuno la aspettava più: si
    /// consegna al correlatore, che la riconosce come tardiva, e **non diventa
    /// un guasto dell'account** (FINAL-REVIEW-01, FR-008).
    ///
    /// Fino al 2026-10-03 un errore tardivo — per esempio il 429 di una
    /// ricerca che aveva già smesso di aspettare — passava da
    /// `normalize_error` e compariva come «libreria non utilizzabile».
    fn absorb_late_reply(&mut self, incoming: Incoming) {
        let esito = self.deliver(incoming);
        tracing::debug!(esito = %esito.as_sentence(), "risposta arrivata dopo il termine");
    }

    /// Consegna una risposta al correlatore, annotando prima un eventuale
    /// limite di frequenza: è l'unico punto da cui le risposte etichettate
    /// passano, così nessun 429 sfugge.
    fn deliver(&mut self, incoming: Incoming) -> Delivery {
        self.note_rate_limit(&incoming);
        self.correlator.deliver(incoming, adesso())
    }
}

/// Quanto si attende quando Telegram dice 429 senza indicare per quanto.
///
/// Un minuto: più lungo dell'intervallo minimo fra due ricerche puntuali, e
/// abbastanza breve da non fermare il lavoro per un'indicazione mancante.
const DEFAULT_FLOOD_WAIT_SECONDS: i64 = 60;

/// Il rifiuto che si dà da sé quando Telegram ha chiesto di attendere: nella
/// forma del protocollo, perché chi lo legge (il Resolver, la frase della
/// cronologia) la riconosce come quella di Telegram (FINAL-REVIEW-01, FR-008).
fn attesa_di_frequenza(secondi: i64) -> String {
    format!("Too Many Requests: retry after {secondi}")
}

/// I secondi indicati da un errore di frequenza: «retry after N» o
/// «FLOOD_WAIT_N». `None` se il testo non ne porta.
fn indicated_wait_seconds(message: &str) -> Option<i64> {
    let dopo = message
        .find("retry after ")
        .map(|inizio| inizio + "retry after ".len())
        .or_else(|| {
            message
                .find("FLOOD_WAIT_")
                .map(|inizio| inizio + "FLOOD_WAIT_".len())
        })?;
    let cifre: String = message
        .get(dopo..)?
        .chars()
        .take_while(char::is_ascii_digit)
        .take(9)
        .collect();
    cifre.parse::<i64>().ok()
}

impl<L: TdJsonBackend> TelegramConnector for LiveTdlibConnector<L> {
    fn start(&mut self, parameters: &ClientParameters) -> TelegramResult<()> {
        if self.machine.state().is_final() {
            return Err(TelegramError::Closed);
        }
        if self.started {
            return Err(TelegramError::Tdlib {
                reason: String::from("il connettore è già stato avviato"),
            });
        }

        // Nessun log della libreria sullo standard error, prima di ogni altra
        // cosa.
        let _ = self
            .library
            .execute(r#"{"@type":"setLogVerbosityLevel","new_verbosity_level":0}"#)?;

        let client_id = self.library.create_client_id()?;

        // Ogni account ha directory proprie (ADR-0019 §2). `ClientParameters`
        // porta oggi solo la directory del database: quella dei file è derivata
        // come sottocartella dedicata finché il campo non viene aggiunto a monte.
        let database_directory = parameters.database_directory.to_string_lossy().into_owned();
        let files_directory = parameters
            .database_directory
            .join("files")
            .to_string_lossy()
            .into_owned();

        self.prepared = Some(PreparedParameters {
            api_id: parameters.api_id.expose_secret(),
            api_hash: Redacted::new(parameters.api_hash.expose_secret().to_owned()),
            database_directory,
            files_directory,
            database_key_base64: Redacted::new(self.database_key_base64.expose().to_owned()),
            use_test_dc: parameters.use_test_datacenter,
            system_language_code: parameters.system_language_code.clone(),
            application_version: parameters.application_version.clone(),
        });
        self.client_id = Some(client_id);
        self.started = true;

        // Causa plausibile e più accreditata di LIVE-E010 (incidente del
        // 2026-07-29, sessione successiva), non riconfermata con un pilot
        // reale in questa sessione: un client TDLib appena creato non emette
        // nulla di spontaneo finché non riceve almeno una richiesta. È il
        // comportamento documentato dagli esempi ufficiali di TDLib
        // (`td_example.cpp`, `tdjson_example.py`), che inviano sempre una
        // `getOption("version")` innocua subito dopo la creazione del client,
        // prima di iniziare a ricevere. Il proof of concept
        // (`super::run_smoke_test`, verificato contro la libreria reale) è un
        // indizio più debole a supporto, non una controprova equivalente:
        // invia `setNetworkType` e poi `setTdlibParameters` **senza mai
        // attendere** lo stato intermedio, quindi dimostra che gli
        // aggiornamenti arrivano dopo una richiesta, non che non arrivi nulla
        // senza. Senza questo invio, `poll_event`/`receive` restava comunque
        // in attesa per sempre di un `authorizationStateWaitTdlibParameters`
        // mai arrivato, coerente con il pilot (timeout di 20 secondi, nessun
        // aggiornamento). La richiesta è di sola lettura, locale alla
        // libreria, non tocca la rete e non trasporta alcun segreto.
        //
        // Rischio residuo dichiarato: se TDLib rispondesse a questa richiesta
        // con un `error` prima ancora dello stato di autorizzazione (non
        // osservato, non atteso per un'opzione locale), `absorb_update` lo
        // tradurrebbe in un `ConnectorEvent::Failure` spurio mentre l'accesso
        // prosegue comunque — un banner d'errore fuorviante, non un blocco.
        self.library
            .send(client_id, r#"{"@type":"getOption","name":"version"}"#)?;
        // Il risveglio è stato consegnato con successo: da qui in avanti il
        // connettore è osservabile come "avviato e risvegliato", non più come
        // "creato ma non risvegliato" (vedere `Self::ensure_woken`, usato da
        // `poll_event`). Se la `send` sopra fosse fallita, il `?` avrebbe già
        // fatto uscire questa funzione con `Err` prima di questo punto, e
        // `wakeup_confirmed` sarebbe rimasto `false`.
        self.wakeup_confirmed = true;

        // La macchina resta `Uninitialized`: sarà `poll_event`, alla ricezione di
        // `authorizationStateWaitTdlibParameters`, a inviare i parametri e ad
        // avviare le transizioni. Così esiste un unico punto che consuma la coda
        // della libreria.
        Ok(())
    }

    fn submit_phone_number(&mut self, phone: &PhoneNumber) -> TelegramResult<()> {
        self.machine
            .expect_state(AuthorizationState::WaitingForPhoneNumber)?;
        let client_id = self.ensure_woken()?;
        // Il numero compare solo in questa richiesta, mai in log né in errori.
        let request = format!(
            r#"{{"@type":"setAuthenticationPhoneNumber","phone_number":"{}"}}"#,
            json_escape(phone.expose_secret())
        );
        self.library.send(client_id, &request)?;
        // Nessun dato riservato: solo la conferma che l'invio verso TDLib e'
        // riuscito. La transizione a `WaitingForCode` non avviene qui: arriva
        // solo con un successivo `poll_event` (vedere `handle_authorization`).
        debug!(
            passo = "numero_inviato_a_tdlib",
            "richiesta di invio del numero consegnata a TDLib"
        );
        Ok(())
    }

    fn submit_code(&mut self, code: &LoginCode) -> TelegramResult<()> {
        self.machine
            .expect_state(AuthorizationState::WaitingForCode)?;
        let client_id = self.ensure_woken()?;
        let request = format!(
            r#"{{"@type":"checkAuthenticationCode","code":"{}"}}"#,
            json_escape(code.expose_secret())
        );
        self.library.send(client_id, &request)
    }

    fn submit_password(&mut self, password: &TwoFactorPassword) -> TelegramResult<()> {
        self.machine
            .expect_state(AuthorizationState::WaitingForPassword)?;
        let client_id = self.ensure_woken()?;
        // La password può contenere qualunque carattere: va sempre resa sicura
        // per JSON prima di attraversare il confine.
        let request = format!(
            r#"{{"@type":"checkAuthenticationPassword","password":"{}"}}"#,
            json_escape(password.expose_secret())
        );
        self.library.send(client_id, &request)
    }

    fn poll_event(&mut self, timeout: Duration) -> TelegramResult<Option<ConnectorEvent>> {
        if self.machine.state().is_final() {
            return Err(TelegramError::Closed);
        }
        // Distingue "mai creato" da "creato ma non risvegliato": vedere
        // `Self::ensure_woken`. Nessuno dei due casi tenta `receive`.
        self.ensure_woken()?;

        // `Ok(None)` vuol dire «la coda è vuota», e chi pompa smette di
        // leggere fino al giro successivo, 200 ms dopo. Un aggiornamento
        // assorbito senza evento (un'opzione, un utente, una chat annunciata)
        // non è una coda vuota: restituire `None` anche per lui faceva
        // consumare UN solo aggiornamento muto per giro. All'avvio TDLib ne
        // manda un centinaio prima di `authorizationStateReady`, e
        // l'operatore guardava «Preparazione in corso» per 25-30 secondi
        // (OBS-TG-1). Si continua a leggere, senza più attendere, finché
        // arriva un evento o la coda è vuota davvero.
        let mut attesa = timeout.as_secs_f64();
        for _ in 0..POLL_MAX_ABSORBED {
            // Prima gli eventi eventualmente accumulati da un'altra operazione.
            if let Some(event) = self.pending.pop_front() {
                return Ok(Some(event));
            }

            let Some(json) = self.library.receive(attesa)? else {
                // Coda vuota entro l'attesa: condizione normale di una fonte
                // silenziosa, non un errore.
                return Ok(None);
            };
            attesa = 0.0;

            if json_type(&json).as_deref() == Some("updateAuthorizationState") {
                return self.handle_authorization(&json);
            }

            match self.classify(&json) {
                Incoming::Unsolicited { payload } => {
                    if let Some(event) = self.absorb_update(&payload) {
                        return Ok(Some(event));
                    }
                }
                tardiva => self.absorb_late_reply(tardiva),
            }
        }
        Ok(self.pending.pop_front())
    }

    fn accessible_chats(&mut self) -> TelegramResult<Vec<AccessibleChat>> {
        // L'elenco ha senso solo ad account autorizzato.
        self.machine.expect_state(AuthorizationState::Ready)?;
        let client_id = self.ensure_woken()?;

        // Postura passiva: `loadChats` e `getChats` sono di sola lettura e non
        // entrano in alcuna chat. `loadChats` può restituire un errore benigno
        // quando l'elenco è già caricato: viene assorbito, non propagato —
        // adesso però si sa che è **suo**, e non lo si suppone.
        //
        // Si interrogano **entrambe** le liste di TDLib. `chatListMain` da sola
        // non vede le chat archiviate, che in Telegram vivono in una lista
        // distinta: un canale archiviato dall'operatore sarebbe rimasto
        // invisibile fra le fonti disponibili, senza alcun errore e senza
        // Telegram (osservato nel pilot del 2026-07-30). L'archiviazione è una
        // scelta di ordinamento personale di chi possiede l'account, non un
        // giudizio sulla rilevanza della fonte: non deve decidere che cosa sia
        // monitorabile. Le due liste possono contenere la stessa chat: la
        // raccolta è una mappa per identificatore, quindi il duplicato si
        // fonde da sé.
        // Le richieste rimaste in attesa da una chiamata precedente si chiudono
        // PRIMA di coniarne altre: `loadChats` puo' non rispondere affatto
        // quando l'elenco e' gia' caricato, e senza questa spazzata il
        // correlatore se le porterebbe appresso fino al limite.
        let now = adesso();
        for scaduta in self.correlator.sweep(now) {
            tracing::debug!(esito = %scaduta.as_sentence(), "richiesta chiusa senza risposta");
        }

        let mut elenchi_attesi: Vec<RequestId> = Vec::new();

        for list in ["chatListMain", "chatListArchive"] {
            // Anche `loadChats` viene correlato: e' il solo modo di sapere che
            // un errore e' il SUO e non quello di `getChats`.
            if let Ok(carico) = self.correlator.register("loadChats", now, CHATS_TIMEOUT_MS) {
                let _ = self.library.send(
                    client_id,
                    &format!(
                        r#"{{"@type":"loadChats","@extra":"{carico}","chat_list":{{"@type":"{list}"}},"limit":1000}}"#
                    ),
                );
            }

            let elenco = self
                .correlator
                .register("getChats", now, CHATS_TIMEOUT_MS)
                .map_err(|errore| TelegramError::Tdlib {
                    reason: errore.to_string(),
                })?;
            self.library.send(
                client_id,
                &format!(
                    r#"{{"@type":"getChats","@extra":"{elenco}","chat_list":{{"@type":"{list}"}},"limit":1000}}"#
                ),
            )?;
            elenchi_attesi.push(elenco);
        }

        // FINO AL TERMINE DICHIARATO, NON FINO A UN SECONDO DI SILENZIO
        // (FINAL-REVIEW-01, FR-008). Un secondo senza messaggi non vuol dire
        // che le liste non arriveranno: su una rete lenta arrivavano dopo, e
        // l'elenco restituito era monco senza dirlo.
        let termine = now.as_millis().saturating_add(CHATS_TIMEOUT_MS);
        let concluse = |connettore: &Self| {
            elenchi_attesi
                .iter()
                .all(|id| !connettore.correlator.is_waiting_for(*id))
        };

        let mut attesa = Attesa::fino_a(termine, CHATS_MAX_POLLS);
        while attesa.continua() {
            let Some(json) = self.library.receive(0.05)? else {
                // Ci si ferma quando **entrambe** le liste hanno risposto e la
                // coda si è svuotata: fermarsi alla prima risposta, come
                // faceva la versione a lista singola, troncherebbe l'archivio.
                if concluse(self) {
                    break;
                }
                attesa.silenzio();
                continue;
            };
            attesa.messaggio();

            // Prima di tutto: di CHI e' questa risposta. Solo cio' che non
            // appartiene ad alcuna richiesta passa dall'interpretazione degli
            // aggiornamenti.
            match self.classify(&json) {
                Incoming::Unsolicited { payload } => match json_type(&payload).as_deref() {
                    Some("updateAuthorizationState") => {
                        if let Some(event) = self.handle_authorization(&payload)? {
                            self.pending.push_back(event);
                        }
                    }
                    _ => {
                        // Tutto il resto passa da `absorb_update`, che è
                        // l'unico punto in cui gli aggiornamenti si
                        // interpretano.
                        //
                        // `updateNewChat` aveva qui un ramo proprio che
                        // duplicava quella logica, e la duplicazione ha fatto
                        // **esattamente** ciò che le duplicazioni fanno: quando
                        // è stato aggiunto il legame chat → supergruppo, la
                        // copia di là lo registrava e questa no, e lo username
                        // della fonte compariva o spariva a seconda di quale
                        // percorso avesse letto l'aggiornamento. L'ha trovato
                        // un test scritto sull'ordine di arrivo.
                        //
                        // Ogni contenuto o cambio di connessione incrociato
                        // mentre si raccoglie l'elenco viene comunque
                        // preservato per `poll_event`.
                        if let Some(event) = self.absorb_update(&payload) {
                            self.pending.push_back(event);
                        }
                    }
                },
                incoming => match self.deliver(incoming) {
                    // Una lista ha risposto.
                    Delivery::Resolved(Resolution::Answered { .. }) => {}
                    // UN ERRORE ORA HA UN PROPRIETARIO.
                    //
                    // Su `loadChats` resta benigno: e' l'esito normale quando
                    // l'elenco e' gia' caricato. Su `getChats` no — e prima di
                    // questa milestone finiva nello stesso ramo, lasciando un
                    // elenco delle fonti piu' corto senza che nulla lo
                    // dichiarasse.
                    Delivery::Resolved(Resolution::Failed {
                        request,
                        code,
                        message,
                        ..
                    }) => {
                        if request.kind == "getChats" {
                            return Err(TelegramError::Tdlib {
                                reason: format!(
                                    "l'elenco delle chat non è stato consegnato: {code} {message}"
                                ),
                            });
                        }
                        self.ignored_updates += 1;
                    }
                    // Una richiesta scaduta non produce un errore: e' l'assenza
                    // di una risposta, non una risposta negativa.
                    Delivery::Resolved(Resolution::TimedOut { request, .. }) => {
                        tracing::warn!(richiesta = %request.kind, "nessuna risposta entro il termine");
                    }
                    // Una risposta a una richiesta gia' scaduta: non serve piu'
                    // a nessuno, ma il fatto che sia arrivata dice che il
                    // termine era troppo stretto.
                    Delivery::AnswerToNobody { id } => {
                        tracing::warn!(richiesta = %id, "risposta arrivata dopo la scadenza");
                        self.ignored_updates += 1;
                    }
                    Delivery::Unsolicited(_) => self.ignored_updates += 1,
                },
            }
        }

        // UN ELENCO CHE NON È ARRIVATO NON È UN ELENCO CORTO (FINAL-REVIEW-01,
        // FR-008). Se una delle liste non ha risposto entro il termine, il
        // registro può essere parziale: restituirlo come se fosse intero
        // faceva concludere alla verifica delle fonti che l'accesso a quelle
        // mancanti era perso, con una riga d'audit che lo affermava.
        let tutte_arrivate = concluse(self);

        // Le richieste ancora in attesa hanno superato il termine: si chiudono
        // qui, cosi' il correlatore non le porta appresso alla prossima
        // chiamata. Non aver ricevuto risposta non e' aver ricevuto un no: e'
        // un elenco che non si conosce per intero, e lo si dice.
        for scaduta in self.correlator.sweep(adesso()) {
            tracing::warn!(esito = %scaduta.as_sentence(), "richiesta chiusa senza risposta");
        }
        if !tutte_arrivate {
            return Err(TelegramError::Timeout {
                millis: u64::try_from(CHATS_TIMEOUT_MS).unwrap_or(u64::MAX),
            });
        }

        // Si restituisce il **registro**, non le sole chat raccolte in questa
        // tornata: `updateNewChat` arriva una volta sola per client, quindi
        // una seconda apertura della schermata Fonti non lo rivedrebbe e
        // l'elenco risulterebbe monco senza alcun errore.
        // Lo username si aggiunge **adesso** e non all'arrivo: `updateNewChat` e
        // `updateSupergroup` arrivano in ordine non garantito, e fondere al
        // momento dell'arrivo avrebbe fatto dipendere il risultato da quale dei
        // due arriva primo.
        Ok(self
            .known_chats
            .values()
            .map(|chat| {
                let mut chat = chat.clone();
                chat.username = self
                    .chat_supergroups
                    .get(&chat.chat_id.get())
                    .and_then(|supergroup_id| self.supergroup_usernames.get(supergroup_id))
                    .cloned();
                chat
            })
            .collect())
    }

    fn fetch_history(
        &mut self,
        chat_id: ChatId,
        from_message_id: i64,
        limit: u32,
    ) -> TelegramResult<Vec<IncomingMessage>> {
        // La cronologia ha senso solo ad account autorizzato, come l'elenco
        // delle chat.
        self.machine.expect_state(AuthorizationState::Ready)?;
        let client_id = self.ensure_woken()?;

        // UNA RICHIESTA CHE PORTA IL SUO NOME (FINAL-REVIEW-01, FR-007).
        //
        // Fino al 2026-10-03 questa era l'unica lettura non correlata: si
        // accettava il primo `messages` o il primo `error` in arrivo. Una
        // risposta tardiva a un'altra richiesta — un contesto scaduto, una
        // pagina precedente lenta — diventava la pagina corrente, e un intervallo
        // poteva risultare letto quando non lo era.
        if let Some(secondi) = self.flood_wait_remaining() {
            // Telegram ha chiesto di aspettare: non si chiede altro prima.
            return Err(classify_tdlib_error(&attesa_di_frequenza(secondi), 429));
        }
        let now = adesso();
        for scaduta in self.correlator.sweep(now) {
            tracing::debug!(esito = %scaduta.as_sentence(), "richiesta chiusa senza risposta");
        }
        let richiesta = self
            .correlator
            .register("getChatHistory", now, HISTORY_TIMEOUT_MS)
            .map_err(|errore| TelegramError::Tdlib {
                reason: errore.to_string(),
            })?;

        // Postura passiva: `getChatHistory` **legge** ciò che l'account già
        // vede, come farebbe scorrendo all'indietro la conversazione. Non entra
        // in alcuna chat e non cerca nulla sulla piattaforma.
        //
        // `only_local: false` perché la copia locale di TDLib contiene solo ciò
        // che questo client ha già scaricato: con `true` un recupero appena
        // dopo l'accesso restituirebbe quasi nulla e sembrerebbe che la
        // cronologia non ci fosse.
        self.library.send(
            client_id,
            &format!(
                r#"{{"@type":"getChatHistory","@extra":"{richiesta}","chat_id":{},"from_message_id":{},"offset":0,"limit":{},"only_local":false}}"#,
                chat_id.get(),
                from_message_id,
                limit.min(HISTORY_MAX_LIMIT),
            ),
        )?;

        let termine = now.as_millis().saturating_add(HISTORY_TIMEOUT_MS);
        let mut attesa = Attesa::fino_a(termine, CHATS_MAX_POLLS);
        while attesa.continua() {
            let Some(json) = self.library.receive(0.05)? else {
                attesa.silenzio();
                continue;
            };
            attesa.messaggio();

            match self.classify(&json) {
                Incoming::Unsolicited { payload } => {
                    if json_type(&payload).as_deref() == Some("updateAuthorizationState") {
                        if let Some(event) = self.handle_authorization(&payload)? {
                            self.pending.push_back(event);
                        }
                    } else if let Some(event) = self.absorb_update(&payload) {
                        // Ogni contenuto arrivato dal vivo mentre si recupera
                        // va **conservato**, non scartato: sarebbe un buco
                        // proprio nel momento in cui si sta colmando un buco.
                        self.pending.push_back(event);
                    }
                }
                incoming => match self.deliver(incoming) {
                    Delivery::Resolved(Resolution::Answered {
                        request, payload, ..
                    }) if request.id == richiesta => {
                        // Si tengono solo i messaggi della chat chiesta: una
                        // pagina è di una conversazione, e un messaggio di
                        // un'altra non vi appartiene in nessun caso.
                        let mut pagina = parse_history_page(&payload, now_millis());
                        pagina.retain(|message| message.chat_id == chat_id);
                        return Ok(pagina);
                    }
                    Delivery::Resolved(Resolution::Failed {
                        request,
                        code,
                        message,
                        ..
                    }) if request.id == richiesta => {
                        // L'errore di TDLib si traduce con la stessa funzione
                        // che traduce ogni altro errore: una seconda
                        // traduzione qui classificherebbe diversamente lo
                        // stesso guasto a seconda dell'operazione.
                        return Err(classify_tdlib_error(&message, i64::from(code)));
                    }
                    altro => {
                        tracing::debug!(esito = %altro.as_sentence(), "messaggio non pertinente");
                    }
                },
            }
        }

        for scaduta in self.correlator.sweep(adesso()) {
            tracing::debug!(esito = %scaduta.as_sentence(), "richiesta chiusa senza risposta");
        }
        // La risposta non è arrivata entro l'attesa. Restituire un elenco vuoto
        // direbbe «non c'era nulla», che è un'affermazione diversa e falsa.
        Err(TelegramError::Timeout {
            millis: u64::try_from(HISTORY_TIMEOUT_MS).unwrap_or(u64::MAX),
        })
    }

    fn fetch_context(
        &mut self,
        chat_id: ChatId,
        around: MessageId,
        before: u32,
        after: u32,
    ) -> TelegramResult<Vec<ContextMessage>> {
        self.machine.expect_state(AuthorizationState::Ready)?;
        let client_id = self.ensure_woken()?;
        if let Some(secondi) = self.flood_wait_remaining() {
            return Err(classify_tdlib_error(&attesa_di_frequenza(secondi), 429));
        }

        let now = adesso();
        for scaduta in self.correlator.sweep(now) {
            tracing::debug!(esito = %scaduta.as_sentence(), "richiesta chiusa senza risposta");
        }

        let richiesta = self
            .correlator
            .register("getChatHistory", now, CONTEXT_TIMEOUT_MS)
            .map_err(|errore| TelegramError::Tdlib {
                reason: errore.to_string(),
            })?;

        // UNA richiesta sola, centrata sul messaggio.
        //
        // `offset` negativo chiede a TDLib anche i messaggi PIU' RECENTI di
        // quello indicato: con `offset = -after` e `limit = before + after + 1`
        // la finestra si apre da entrambe le parti attorno all'ancora. Due
        // richieste separate — una indietro e una avanti — darebbero due
        // risposte da ricucire, e la ricucitura e' il punto in cui due elenchi
        // diventano uno che non corrisponde a nessuno dei due.
        //
        // Postura passiva: `getChatHistory` legge, e nient'altro.
        //
        // LA FINESTRA NON SUPERA CENTO (FINAL-REVIEW-01, FR-011): è il massimo
        // che `getChatHistory` consegna, e oltre tronca in silenzio dal lato
        // dei messaggi più vecchi. Con cinquanta per parte si chiedevano
        // centouno messaggi e se ne ricevevano cento: si accorcia il lato
        // vecchio, dichiaratamente, invece di farlo accorciare a Telegram.
        let after = after.min(HISTORY_MAX_LIMIT - 1);
        let before = before.min(HISTORY_MAX_LIMIT - 1 - after);
        let finestra = before.saturating_add(after).saturating_add(1);
        self.library.send(
            client_id,
            &format!(
                r#"{{"@type":"getChatHistory","@extra":"{richiesta}","chat_id":{},"from_message_id":{},"offset":{},"limit":{finestra},"only_local":false}}"#,
                chat_id.get(),
                around.get(),
                -i64::from(after)
            ),
        )?;

        // FINO AL TERMINE DICHIARATO (FINAL-REVIEW-01, FR-008): un secondo di
        // silenzio non è la fine dell'attesa, e la risposta che arriva dopo non
        // deve diventare un guasto altrove.
        let termine = now.as_millis().saturating_add(CONTEXT_TIMEOUT_MS);
        let mut attesa = Attesa::fino_a(termine, CONTEXT_MAX_POLLS);
        while attesa.continua() {
            let Some(json) = self.library.receive(0.05)? else {
                attesa.silenzio();
                continue;
            };
            attesa.messaggio();

            match self.classify(&json) {
                Incoming::Unsolicited { payload } => {
                    if let Some(event) = self.absorb_update(&payload) {
                        self.pending.push_back(event);
                    }
                }
                incoming => match self.deliver(incoming) {
                    Delivery::Resolved(Resolution::Answered {
                        request, payload, ..
                    }) if request.id == richiesta => {
                        return Ok(parse_context_page(&payload, adesso().as_millis()));
                    }
                    // UN RIFIUTO SI DICE COME TALE (ADR-0151, decisione 5).
                    //
                    // Fino a CONVERSATION-VIEW-01 tornava come elenco vuoto, e
                    // la pagina della conversazione avrebbe scritto «Telegram
                    // non ha restituito messaggi» per una fonte che non e'
                    // piu' accessibile. Un elenco vuoto resta la risposta di
                    // una richiesta riuscita senza messaggi; un rifiuto e'
                    // un errore classificato, con il testo di TDLib.
                    Delivery::Resolved(Resolution::Failed {
                        request,
                        code,
                        message,
                        ..
                    }) if request.id == richiesta => {
                        tracing::warn!(codice = code, "contesto non consegnato");
                        return Err(classify_tdlib_error(&message, i64::from(code)));
                    }
                    altro => {
                        tracing::debug!(esito = %altro.as_sentence(), "messaggio non pertinente");
                    }
                },
            }
        }

        for scaduta in self.correlator.sweep(adesso()) {
            tracing::debug!(esito = %scaduta.as_sentence(), "richiesta chiusa senza risposta");
        }
        // IL TEMPO MASSIMO E' SCADUTO: non e' «non c'era nulla», ed e' la
        // frase che la conversazione deve poter dire (ADR-0151, decisione 4).
        Err(TelegramError::Timeout {
            millis: u64::try_from(CONTEXT_TIMEOUT_MS).unwrap_or(u64::MAX),
        })
    }

    fn message_link(
        &mut self,
        chat_id: ChatId,
        message_id: MessageId,
    ) -> TelegramResult<LinkOutcome> {
        // Chiedere un collegamento ha senso solo ad account autorizzato.
        self.machine.expect_state(AuthorizationState::Ready)?;
        let client_id = self.ensure_woken()?;
        if let Some(secondi) = self.flood_wait_remaining() {
            return Err(classify_tdlib_error(&attesa_di_frequenza(secondi), 429));
        }

        let now = adesso();
        for scaduta in self.correlator.sweep(now) {
            tracing::debug!(esito = %scaduta.as_sentence(), "richiesta chiusa senza risposta");
        }

        let richiesta = self
            .correlator
            .register("getMessageLink", now, LINK_TIMEOUT_MS)
            .map_err(|errore| TelegramError::Tdlib {
                reason: errore.to_string(),
            })?;

        // Postura passiva: `getMessageLink` e' di sola lettura e non entra in
        // alcuna chat.
        self.library.send(
            client_id,
            &format!(
                r#"{{"@type":"getMessageLink","@extra":"{richiesta}","chat_id":{},"message_id":{},"for_album":false,"in_message_thread":false}}"#,
                chat_id.get(),
                message_id.get()
            ),
        )?;

        // FINO AL TERMINE DICHIARATO (FINAL-REVIEW-01, FR-008): un secondo di
        // silenzio non è la fine dell'attesa, e la risposta che arriva dopo non
        // deve diventare un guasto altrove.
        let termine = now.as_millis().saturating_add(LINK_TIMEOUT_MS);
        let mut attesa = Attesa::fino_a(termine, LINK_MAX_POLLS);
        while attesa.continua() {
            let Some(json) = self.library.receive(0.05)? else {
                attesa.silenzio();
                continue;
            };
            attesa.messaggio();

            match self.classify(&json) {
                Incoming::Unsolicited { payload } => {
                    // Tutto cio' che non e' la nostra risposta resta un
                    // aggiornamento, e non va perso: `poll_event` lo consegnera'.
                    if let Some(event) = self.absorb_update(&payload) {
                        self.pending.push_back(event);
                    }
                }
                incoming => match self.deliver(incoming) {
                    Delivery::Resolved(Resolution::Answered {
                        request, payload, ..
                    }) if request.id == richiesta => {
                        // TDLib risponde con `messageLink`, che porta
                        // l'indirizzo e se sia pubblico. Un indirizzo che non
                        // supera la verifica di forma non si usa: e' la stessa
                        // ragione per cui non si compone.
                        return Ok(json_string_value(&payload, "link")
                            .and_then(|url| {
                                MessageLink::from_telegram(
                                    &url,
                                    json_bool_value(&payload, "is_public").unwrap_or(false),
                                )
                            })
                            .map_or(
                                LinkOutcome::NotProvided(LinkGap::NotOfferedByTelegram),
                                LinkOutcome::Provided,
                            ));
                    }
                    Delivery::Resolved(Resolution::Failed {
                        request,
                        code,
                        message,
                        ..
                    }) if request.id == richiesta => {
                        return Ok(LinkOutcome::NotProvided(LinkGap::Refused { code, message }));
                    }
                    // Risposte di altre richieste, scadenze, risposte tardive:
                    // non riguardano questa domanda e non la concludono.
                    altro => {
                        tracing::debug!(esito = %altro.as_sentence(), "messaggio non pertinente");
                    }
                },
            }
        }

        // Nessuna risposta. **Non e' «il collegamento non esiste»**: e' «non e'
        // arrivato niente», e la frase lo dice.
        let attesa = adesso().as_millis() - now.as_millis();
        for scaduta in self.correlator.sweep(adesso()) {
            tracing::debug!(esito = %scaduta.as_sentence(), "richiesta chiusa senza risposta");
        }
        Ok(LinkOutcome::NotProvided(LinkGap::NoAnswer {
            waited_ms: attesa,
        }))
    }

    fn authorization_state(&self) -> AuthorizationState {
        self.machine.state()
    }

    fn connection_state(&self) -> ConnectionState {
        self.connection
    }

    fn shutdown(&mut self) -> TelegramResult<()> {
        // Idempotente: su un connettore già in stato terminale non c'è nulla da
        // fare.
        if self.machine.state().is_final() {
            return Ok(());
        }

        let Some(client_id) = self.client_id else {
            // Mai avviato: si porta la macchina a uno stato chiuso senza toccare
            // la libreria.
            let _ = self.machine.transition_to(AuthorizationState::Closing);
            let _ = self.machine.transition_to(AuthorizationState::Closed);
            self.connection = ConnectionState::Offline;
            return Ok(());
        };

        self.library.send(client_id, r#"{"@type":"close"}"#)?;
        let _ = self.machine.transition_to(AuthorizationState::Closing);

        let mut confirmed = false;
        let mut attesa = Attesa::fino_a(
            adesso().as_millis().saturating_add(SHUTDOWN_TIMEOUT_MS),
            SHUTDOWN_MAX_POLLS,
        );
        while attesa.continua() {
            let Some(json) = self.library.receive(0.05)? else {
                attesa.silenzio();
                continue;
            };
            attesa.messaggio();
            if json_type(&json).as_deref() == Some("updateAuthorizationState")
                && nested_type(&json, "authorization_state").as_deref()
                    == Some("authorizationStateClosed")
            {
                confirmed = true;
                break;
            }
        }

        let _ = self.machine.transition_to(AuthorizationState::Closed);
        self.connection = ConnectionState::Offline;
        if !confirmed {
            warn!("chiusura non confermata dalla libreria entro il budget: forzata a chiusa");
        }
        Ok(())
    }

    fn official_lookup(&mut self) -> Option<&mut dyn OfficialLookup> {
        Some(self)
    }

    fn profile_media(&mut self) -> Option<&mut dyn crate::profile::ProfileMediaReader> {
        Some(self)
    }

    fn attachment_reader(&mut self) -> Option<&mut dyn crate::attachment::AttachmentReader> {
        Some(self)
    }

    fn members_reader(&mut self) -> Option<&mut dyn crate::members::MembersReader> {
        Some(self)
    }

    /// Una pagina di ricerca nei messaggi (ADR-0154, ADR-0161): **una**
    /// richiesta, che legge. Un rifiuto è l'errore classificato con il testo di
    /// TDLib, il tempo scaduto è `Timeout`; una risposta senza risultati è una
    /// pagina vuota.
    fn search_messages(
        &mut self,
        query: &crate::search::SearchQuery,
    ) -> TelegramResult<crate::search::SearchPage> {
        let payload =
            self.read_only_request(query.function_name(), |tag| query.tdlib_request_tagged(tag))?;
        Ok(parse_search_page(&payload, adesso().as_millis()))
    }

    /// La quota della ricerca D (ADR-0161): **una** richiesta, che legge e non
    /// costa. Una risposta che non si legge come quota è un errore: senza
    /// quota la ricerca D non parte.
    fn public_post_limits(
        &mut self,
        query: &str,
    ) -> TelegramResult<crate::search::PublicPostLimits> {
        let payload = self.read_only_request("getPublicPostSearchLimits", |tag| {
            crate::search::limits_request_tagged(query, tag)
        })?;
        if json_type(&payload).as_deref() != Some("publicPostSearchLimits") {
            return Err(TelegramError::Tdlib {
                reason: String::from("la risposta sulla quota non è quella attesa"),
            });
        }
        parse_public_post_limits(&payload).ok_or_else(|| TelegramError::Tdlib {
            reason: String::from("la quota dichiarata da Telegram non si legge"),
        })
    }
}

impl<L: TdJsonBackend> LiveTdlibConnector<L> {
    /// Una richiesta di **sola lettura**, e la sua risposta: la ricerca nei
    /// messaggi e la quota della ricerca D passano da qui.
    ///
    /// Postura passiva: si manda la richiesta costruita da `build` con il
    /// proprio segno `@extra`, si aspetta al più [`SEARCH_TIMEOUT_MS`], e gli
    /// aggiornamenti che arrivano nel frattempo si conservano per dopo.
    fn read_only_request(
        &mut self,
        function_name: &'static str,
        build: impl FnOnce(&str) -> String,
    ) -> TelegramResult<String> {
        self.machine.expect_state(AuthorizationState::Ready)?;
        let client_id = self.ensure_woken()?;
        if let Some(secondi) = self.flood_wait_remaining() {
            return Err(classify_tdlib_error(&attesa_di_frequenza(secondi), 429));
        }

        let now = adesso();
        for scaduta in self.correlator.sweep(now) {
            tracing::debug!(esito = %scaduta.as_sentence(), "richiesta chiusa senza risposta");
        }
        let richiesta = self
            .correlator
            .register(function_name, now, SEARCH_TIMEOUT_MS)
            .map_err(|errore| TelegramError::Tdlib {
                reason: errore.to_string(),
            })?;

        self.library
            .send(client_id, &build(&richiesta.to_string()))?;

        let termine = now.as_millis().saturating_add(SEARCH_TIMEOUT_MS);
        let mut attesa = Attesa::fino_a(termine, CONTEXT_MAX_POLLS);
        while attesa.continua() {
            let Some(json) = self.library.receive(0.05)? else {
                attesa.silenzio();
                continue;
            };
            attesa.messaggio();

            match self.classify(&json) {
                Incoming::Unsolicited { payload } => {
                    if let Some(event) = self.absorb_update(&payload) {
                        self.pending.push_back(event);
                    }
                }
                incoming => match self.deliver(incoming) {
                    Delivery::Resolved(Resolution::Answered {
                        request, payload, ..
                    }) if request.id == richiesta => {
                        return Ok(payload);
                    }
                    Delivery::Resolved(Resolution::Failed {
                        request,
                        code,
                        message,
                        ..
                    }) if request.id == richiesta => {
                        tracing::warn!(codice = code, "richiesta di lettura non consegnata");
                        return Err(classify_tdlib_error(&message, i64::from(code)));
                    }
                    altro => {
                        tracing::debug!(esito = %altro.as_sentence(), "messaggio non pertinente");
                    }
                },
            }
        }

        for scaduta in self.correlator.sweep(adesso()) {
            tracing::debug!(esito = %scaduta.as_sentence(), "richiesta chiusa senza risposta");
        }
        Err(TelegramError::Timeout {
            millis: u64::try_from(SEARCH_TIMEOUT_MS).unwrap_or(u64::MAX),
        })
    }
}

impl<L: TdJsonBackend> crate::lookup::sealed::Sealed for LiveTdlibConnector<L> {}

/// La risposta di TDLib a una richiesta che legge: il corpo, o il rifiuto
/// com'è.
enum Risposta {
    Corpo(String),
    Rifiuto { code: i64, message: String },
}

impl<L: TdJsonBackend> LiveTdlibConnector<L> {
    /// **Una** richiesta che legge, fino alla sua risposta o al termine.
    ///
    /// `componi` riceve il segno `@extra` e restituisce la richiesta JSON. Non
    /// riprova: un tempo scaduto è `Timeout`, non «il dato non c'è».
    fn chiedi_una_volta(
        &mut self,
        nome: &'static str,
        termine_ms: i64,
        componi: impl FnOnce(&str) -> String,
    ) -> TelegramResult<Risposta> {
        self.chiedi_una_volta_tacendo(nome, termine_ms, LINK_MAX_POLLS, componi)
    }

    /// Come [`Self::chiedi_una_volta`], con quante letture vuote si tollerano:
    /// uno scaricamento sincrono tace finché non ha finito (ATTACH-01).
    fn chiedi_una_volta_tacendo(
        &mut self,
        nome: &'static str,
        termine_ms: i64,
        silenzi: usize,
        componi: impl FnOnce(&str) -> String,
    ) -> TelegramResult<Risposta> {
        let client_id = self.ensure_woken()?;
        let now = adesso();
        for scaduta in self.correlator.sweep(now) {
            tracing::debug!(esito = %scaduta.as_sentence(), "richiesta chiusa senza risposta");
        }
        let richiesta = self
            .correlator
            .register(nome, now, termine_ms)
            .map_err(|errore| TelegramError::Tdlib {
                reason: errore.to_string(),
            })?;
        self.library
            .send(client_id, &componi(&json_escape(&richiesta.to_string())))?;

        let termine = now.as_millis().saturating_add(termine_ms);
        let mut attesa = Attesa::fino_a(termine, silenzi);
        while attesa.continua() {
            let Some(json) = self.library.receive(0.05)? else {
                attesa.silenzio();
                continue;
            };
            attesa.messaggio();
            match self.classify(&json) {
                Incoming::Unsolicited { payload } => {
                    if let Some(event) = self.absorb_update(&payload) {
                        self.pending.push_back(event);
                    }
                }
                incoming => match self.deliver(incoming) {
                    Delivery::Resolved(Resolution::Answered {
                        request, payload, ..
                    }) if request.id == richiesta => {
                        return Ok(Risposta::Corpo(payload));
                    }
                    Delivery::Resolved(Resolution::Failed {
                        request,
                        code,
                        message,
                        ..
                    }) if request.id == richiesta => {
                        return Ok(Risposta::Rifiuto {
                            code: i64::from(code),
                            message,
                        });
                    }
                    altro => {
                        tracing::debug!(esito = %altro.as_sentence(), "messaggio non pertinente");
                    }
                },
            }
        }
        for scaduta in self.correlator.sweep(adesso()) {
            tracing::debug!(esito = %scaduta.as_sentence(), "richiesta chiusa senza risposta");
        }
        Err(TelegramError::Timeout {
            millis: u64::try_from(termine_ms).unwrap_or(u64::MAX),
        })
    }
}

impl<L: TdJsonBackend> crate::profile::ProfileMediaReader for LiveTdlibConnector<L> {
    /// Foto, biografia e stato di un account (PERSON-MEDIA-01, ADR-0174): al
    /// più tre letture, in sequenza, nessuna ripetuta. `getUser` per lo stato e
    /// la foto, `getUserFullInfo` per la biografia, `downloadFile` sincrono per
    /// l'immagine piccola. Un rifiuto della prima o della seconda torna com'è;
    /// una foto che non si legge si dice, e il resto resta.
    fn read_profile_media(
        &mut self,
        user_id: i64,
    ) -> TelegramResult<crate::profile::ProfileMediaReply> {
        use crate::profile::{ProfileMedia, ProfileMediaReply};

        self.machine.expect_state(AuthorizationState::Ready)?;
        if let Some(secondi) = self.flood_wait_remaining() {
            return Ok(ProfileMediaReply::Refused {
                code: 429,
                message: attesa_di_frequenza(secondi),
            });
        }
        let utente = match self.chiedi_una_volta("getUser", LINK_TIMEOUT_MS, |extra| {
            format!(r#"{{"@type":"getUser","@extra":"{extra}","user_id":{user_id}}}"#)
        })? {
            Risposta::Corpo(corpo) => corpo,
            Risposta::Rifiuto { code, message } => {
                return Ok(ProfileMediaReply::Refused { code, message });
            }
        };
        let completo = match self.chiedi_una_volta("getUserFullInfo", LINK_TIMEOUT_MS, |extra| {
            format!(r#"{{"@type":"getUserFullInfo","@extra":"{extra}","user_id":{user_id}}}"#)
        })? {
            Risposta::Corpo(corpo) => corpo,
            Risposta::Rifiuto { code, message } => {
                return Ok(ProfileMediaReply::Refused { code, message });
            }
        };

        let (photo, photo_not_read) = match profile_small_photo_id(&utente) {
            None => (None, None),
            Some(file_id) => {
                let esito = self.chiedi_una_volta("downloadFile", PHOTO_TIMEOUT_MS, |extra| {
                    format!(
                        r#"{{"@type":"downloadFile","@extra":"{extra}","file_id":{file_id},"priority":1,"offset":0,"limit":0,"synchronous":true}}"#
                    )
                });
                match esito {
                    Ok(Risposta::Corpo(file)) => read_downloaded_photo(&file),
                    Ok(Risposta::Rifiuto { message, .. }) => (
                        None,
                        Some(format!("Telegram non ha dato la foto: {message}")),
                    ),
                    Err(errore) => (None, Some(format!("La foto non è arrivata: {errore}"))),
                }
            }
        };

        Ok(ProfileMediaReply::Found(ProfileMedia {
            user_id,
            bio: parse_bio(&completo),
            status: parse_profile_status(&utente),
            photo,
            photo_not_read,
        }))
    }
}

impl<L: TdJsonBackend> crate::members::MembersReader for LiveTdlibConnector<L> {
    /// Gli iscritti di un gruppo (MEMBERS-01, ADR-0201): `getChat` per sapere
    /// che gruppo è, poi `getSupergroupMembers` a pagine o
    /// `getBasicGroupFullInfo`, poi `getUser` per ogni iscritto, che TDLib
    /// risponde dalla propria memoria. Tutto in lettura, nessuna richiesta
    /// ripetuta; il telefono si maschera qui.
    fn read_members(
        &mut self,
        chat_id: i64,
        max: usize,
    ) -> TelegramResult<crate::members::MembersReply> {
        use crate::members::{MAX_MEMBERS, MEMBERS_PER_PAGE, MemberList, MembersReply};

        self.machine.expect_state(AuthorizationState::Ready)?;
        if let Some(secondi) = self.flood_wait_remaining() {
            return Ok(MembersReply::Refused {
                code: 429,
                message: attesa_di_frequenza(secondi),
            });
        }
        let tetto = max.clamp(1, MAX_MEMBERS);
        let chat = match self.chiedi_una_volta("getChat", LINK_TIMEOUT_MS, |extra| {
            format!(r#"{{"@type":"getChat","@extra":"{extra}","chat_id":{chat_id}}}"#)
        })? {
            Risposta::Corpo(corpo) => corpo,
            Risposta::Rifiuto { code, message } => {
                return Ok(MembersReply::Refused { code, message });
            }
        };

        let mut righe = Vec::new();
        let mut dichiarati = None;
        let fermato;
        match member_source(&chat) {
            None => {
                return Ok(MembersReply::NotAGroup(String::from(
                    "Questa fonte non è un gruppo: Telegram non dà un elenco dei suoi iscritti.",
                )));
            }
            Some(MemberSource::Basic(gruppo)) => {
                let completo =
                    match self.chiedi_una_volta("getBasicGroupFullInfo", LINK_TIMEOUT_MS, |extra| {
                        format!(
                            r#"{{"@type":"getBasicGroupFullInfo","@extra":"{extra}","basic_group_id":{gruppo}}}"#
                        )
                    })? {
                        Risposta::Corpo(corpo) => corpo,
                        Risposta::Rifiuto { code, message } => {
                            return Ok(MembersReply::Refused { code, message });
                        }
                    };
                let pagina = parse_member_page(&completo);
                dichiarati = i64::try_from(pagina.len()).ok();
                fermato = pagina.len() > tetto;
                righe.extend(pagina.into_iter().take(tetto));
            }
            Some(MemberSource::Super(gruppo)) => {
                while righe.len() < tetto {
                    let offset = righe.len();
                    let limite = MEMBERS_PER_PAGE.min(tetto - offset);
                    let pagina =
                        match self.chiedi_una_volta("getSupergroupMembers", LINK_TIMEOUT_MS, |extra| {
                            format!(
                                r#"{{"@type":"getSupergroupMembers","@extra":"{extra}","supergroup_id":{gruppo},"filter":{{"@type":"supergroupMembersFilterRecent"}},"offset":{offset},"limit":{limite}}}"#
                            )
                        })? {
                            Risposta::Corpo(corpo) => corpo,
                            Risposta::Rifiuto { code, message } => {
                                if righe.is_empty() {
                                    return Ok(MembersReply::Refused { code, message });
                                }
                                // Le pagine già arrivate restano: l'elenco è
                                // parziale, e il totale dichiarato lo dice.
                                break;
                            }
                        };
                    if dichiarati.is_none() {
                        dichiarati = top_level_number(&pagina, "total_count");
                    }
                    let iscritti = parse_member_page(&pagina);
                    if iscritti.is_empty() {
                        break;
                    }
                    righe.extend(iscritti);
                    let arrivati = i64::try_from(righe.len()).unwrap_or(i64::MAX);
                    if dichiarati.is_some_and(|totale| arrivati >= totale) {
                        break;
                    }
                }
                if righe.len() > tetto {
                    righe.truncate(tetto);
                }
                let arrivati = i64::try_from(righe.len()).unwrap_or(i64::MAX);
                fermato =
                    righe.len() == tetto && dichiarati.is_some_and(|totale| totale > arrivati);
            }
        }

        let mut members = Vec::with_capacity(righe.len());
        for riga in righe {
            let utente = self
                .chiedi_una_volta("getUser", LINK_TIMEOUT_MS, |extra| {
                    format!(
                        r#"{{"@type":"getUser","@extra":"{extra}","user_id":{}}}"#,
                        riga.user_id
                    )
                })
                .ok()
                .and_then(|risposta| match risposta {
                    Risposta::Corpo(corpo) => Some(corpo),
                    Risposta::Rifiuto { .. } => None,
                });
            // Un utente che TDLib non conosce resta nell'elenco con il solo
            // identificativo: è la verità, e inventarne il nome sarebbe peggio.
            members.push(member_from(riga, utente.as_deref()));
        }

        Ok(MembersReply::Found(MemberList {
            declared_total: dichiarati,
            members,
            stopped_at_cap: fermato,
        }))
    }
}

impl<L: TdJsonBackend> crate::attachment::AttachmentReader for LiveTdlibConnector<L> {
    /// I byte dell'allegato di un messaggio (ATTACH-01, ADR-0177,
    /// decisione 4): `getMessage`, poi `downloadFile` sincrono, poi
    /// `deleteFile` sulla copia di TDLib. Nessuna richiesta si ripete. La
    /// dimensione si controlla prima di scaricare e si ricontrolla sul file;
    /// la copia si fa cancellare anche quando lo scaricamento non riesce.
    fn fetch_attachment(
        &mut self,
        chat_id: i64,
        message_id: i64,
        max_bytes: u64,
    ) -> TelegramResult<crate::attachment::AttachmentReply> {
        use crate::attachment::AttachmentReply;

        self.machine.expect_state(AuthorizationState::Ready)?;
        if let Some(secondi) = self.flood_wait_remaining() {
            return Ok(AttachmentReply::Refused {
                code: 429,
                message: attesa_di_frequenza(secondi),
            });
        }
        let messaggio = match self.chiedi_una_volta("getMessage", LINK_TIMEOUT_MS, |extra| {
            format!(
                r#"{{"@type":"getMessage","@extra":"{extra}","chat_id":{chat_id},"message_id":{message_id}}}"#
            )
        })? {
            Risposta::Corpo(corpo) => corpo,
            Risposta::Rifiuto { code, message } => {
                return Ok(AttachmentReply::Refused { code, message });
            }
        };
        let Some(file) = top_level_value(&messaggio, "content")
            .and_then(attachment_parts)
            .and_then(|(_, _, file)| file)
        else {
            return Ok(AttachmentReply::NotRead(String::from(
                "Il messaggio non ha più un allegato che si possa leggere.",
            )));
        };
        let Some(file_id) = top_level_number(file, "id").filter(|id| *id > 0) else {
            return Ok(AttachmentReply::NotRead(String::from(
                "Telegram non dice quale file è l'allegato.",
            )));
        };
        // PRIMA DI SCARICARE (decisione 5): senza una dimensione nota non si
        // scarica, e oltre il tetto nemmeno.
        let Some(dimensione) = file_declared_size(file) else {
            return Ok(AttachmentReply::NotRead(String::from(
                "Telegram non dice quanto è grande l'allegato: senza saperlo non si scarica.",
            )));
        };
        if dimensione > max_bytes {
            return Ok(AttachmentReply::TooLarge { size: dimensione });
        }

        let scaricato = self.chiedi_una_volta_tacendo(
            "downloadFile",
            ATTACHMENT_TIMEOUT_MS,
            ATTACHMENT_MAX_POLLS,
            |extra| {
                format!(
                    r#"{{"@type":"downloadFile","@extra":"{extra}","file_id":{file_id},"priority":1,"offset":0,"limit":0,"synchronous":true}}"#
                )
            },
        );
        let esito = match scaricato {
            Ok(Risposta::Corpo(corpo)) => Ok(read_downloaded_attachment(&corpo, max_bytes)
                .map_or_else(AttachmentReply::NotRead, |bytes| AttachmentReply::Fetched {
                    bytes,
                    leftover: None,
                })),
            Ok(Risposta::Rifiuto { code, message }) => {
                Ok(AttachmentReply::Refused { code, message })
            }
            Err(errore) => Err(errore),
        };
        // LA COPIA DI TDLIB SI FA CANCELLARE SEMPRE (decisione 6): i byte
        // stanno nell'archivio, non in una cartella.
        let rimasto = match self.chiedi_una_volta("deleteFile", LINK_TIMEOUT_MS, |extra| {
            format!(r#"{{"@type":"deleteFile","@extra":"{extra}","file_id":{file_id}}}"#)
        }) {
            Ok(Risposta::Corpo(_)) => None,
            Ok(Risposta::Rifiuto { message, .. }) => Some(format!(
                "La copia di Telegram non si è cancellata: {message}"
            )),
            Err(errore) => Some(format!(
                "La copia di Telegram non si è cancellata: {errore}"
            )),
        };
        if let Some(perche) = &rimasto {
            warn!(esito = %perche, "copia dell'allegato rimasta");
        }
        match esito {
            Ok(AttachmentReply::Fetched { bytes, .. }) => Ok(AttachmentReply::Fetched {
                bytes,
                leftover: rimasto,
            }),
            Ok(AttachmentReply::NotRead(perche)) => Ok(AttachmentReply::NotRead(match rimasto {
                Some(rimasta) => format!("{perche} {rimasta}"),
                None => perche,
            })),
            altro => altro,
        }
    }
}

impl<L: TdJsonBackend> OfficialLookup for LiveTdlibConnector<L> {
    /// Una ricerca puntuale (PR-09, ADR-0125): **una** richiesta, e una sola.
    ///
    /// Non riprova, non attende oltre il termine, non cambia account: un'attesa
    /// chiesta da Telegram torna indietro com'è, e la rispetta chi la legge.
    fn lookup(&mut self, query: &LookupQuery) -> TelegramResult<LookupReply> {
        self.machine.expect_state(AuthorizationState::Ready)?;
        let client_id = self.ensure_woken()?;

        // TELEGRAM HA CHIESTO DI ASPETTARE (FINAL-REVIEW-01, FR-008): la ricerca
        // non parte, e il rifiuto porta l'attesa che resta, come lo porterebbe
        // la risposta di Telegram.
        if let Some(secondi) = self.flood_wait_remaining() {
            return Ok(LookupReply::Refused {
                code: 429,
                message: attesa_di_frequenza(secondi),
            });
        }

        let now = adesso();
        for scaduta in self.correlator.sweep(now) {
            tracing::debug!(esito = %scaduta.as_sentence(), "richiesta chiusa senza risposta");
        }
        let richiesta = self
            .correlator
            .register(query.function_name(), now, LINK_TIMEOUT_MS)
            .map_err(|errore| TelegramError::Tdlib {
                reason: errore.to_string(),
            })?;

        // Postura passiva: le quattro funzioni leggono ciò che Telegram rende
        // visibile all'account, e nessuna entra in una chat.
        self.library.send(
            client_id,
            &query.tdlib_request_tagged(&richiesta.to_string()),
        )?;

        // FINO AL TERMINE DICHIARATO (FINAL-REVIEW-01, FR-008): un secondo di
        // silenzio non è la fine dell'attesa, e la risposta che arriva dopo non
        // deve diventare un guasto altrove.
        let termine = now.as_millis().saturating_add(LINK_TIMEOUT_MS);
        let mut attesa = Attesa::fino_a(termine, LINK_MAX_POLLS);
        while attesa.continua() {
            let Some(json) = self.library.receive(0.05)? else {
                attesa.silenzio();
                continue;
            };
            attesa.messaggio();

            match self.classify(&json) {
                Incoming::Unsolicited { payload } => {
                    if let Some(event) = self.absorb_update(&payload) {
                        self.pending.push_back(event);
                    }
                }
                incoming => match self.deliver(incoming) {
                    Delivery::Resolved(Resolution::Answered {
                        request, payload, ..
                    }) if request.id == richiesta => {
                        return Ok(parse_lookup(&payload, query));
                    }
                    Delivery::Resolved(Resolution::Failed {
                        request,
                        code,
                        message,
                        ..
                    }) if request.id == richiesta => {
                        return Ok(LookupReply::Refused {
                            code: i64::from(code),
                            message,
                        });
                    }
                    altro => {
                        tracing::debug!(esito = %altro.as_sentence(), "messaggio non pertinente");
                    }
                },
            }
        }

        // Nessuna risposta: **non** è «il dato non c'è». È un tempo scaduto, e
        // chi lo legge deve poterlo distinguere.
        for scaduta in self.correlator.sweep(adesso()) {
            tracing::debug!(esito = %scaduta.as_sentence(), "richiesta chiusa senza risposta");
        }
        Err(TelegramError::Timeout {
            millis: u64::try_from(LINK_TIMEOUT_MS).unwrap_or(u64::MAX),
        })
    }
}

/// Ciò che Telegram ha restituito a una ricerca puntuale, **e nient'altro**.
///
/// Una risposta di un tipo inatteso, o senza identificativo, non diventa un
/// profilo: torna come rifiuto con codice zero, che la tabella dei servizi
/// classifica come errore operativo — mai come assenza di dato.
fn parse_lookup(payload: &str, query: &LookupQuery) -> LookupReply {
    let tipo = json_type(payload);
    let profilo = match tipo.as_deref() {
        Some("chat") => parse_lookup_chat(payload, query),
        Some("user") => parse_lookup_user(payload),
        _ => None,
    };
    profilo.map_or_else(
        || LookupReply::Refused {
            code: 0,
            message: format!(
                "risposta inattesa: {}",
                tipo.as_deref().unwrap_or("senza tipo")
            ),
        },
        LookupReply::Found,
    )
}

/// Una chat restituita da `searchPublicChat` o `getChat`.
fn parse_lookup_chat(payload: &str, query: &LookupQuery) -> Option<LookupProfile> {
    let id = json_number_value(payload, "id")?;
    let (kind, telegram_id) = if payload.contains(r#""@type":"chatTypePrivate""#) {
        (
            LookupKind::Account,
            json_number_value(payload, "user_id").unwrap_or(id),
        )
    } else if payload.contains(r#""@type":"chatTypeSupergroup""#) {
        let genere = if json_bool_value(payload, "is_channel").unwrap_or(false) {
            LookupKind::Channel
        } else {
            LookupKind::Supergroup
        };
        (genere, id)
    } else if payload.contains(r#""@type":"chatTypeBasicGroup""#) {
        (LookupKind::Group, id)
    } else {
        (LookupKind::Other, id)
    };
    // La chat non porta il nome utente: quello cercato è il solo che Telegram
    // ha confermato, trovandola. Gli altri richiederebbero una seconda
    // richiesta, e una ricerca è una richiesta sola (ADR-0125).
    let usernames = match query {
        LookupQuery::Username(nome) => vec![nome.clone()],
        _ => Vec::new(),
    };
    Some(LookupProfile {
        kind,
        telegram_id,
        name: json_string_value(payload, "title").unwrap_or_default(),
        username: usernames.first().cloned(),
        first_name: String::new(),
        last_name: String::new(),
        usernames,
        phone_number: None,
    })
}

/// Una persona restituita da `searchUserByPhoneNumber` o `getUser`.
fn parse_lookup_user(payload: &str) -> Option<LookupProfile> {
    let id = json_number_value(payload, "id")?;
    let kind = if payload.contains(r#""@type":"userTypeBot""#) {
        LookupKind::Bot
    } else if payload.contains(r#""@type":"userTypeDeleted""#) {
        LookupKind::DeletedAccount
    } else if payload.contains(r#""@type":"userTypeRegular""#) {
        LookupKind::Person
    } else {
        LookupKind::Other
    };
    let first_name = json_string_value(payload, "first_name").unwrap_or_default();
    let last_name = json_string_value(payload, "last_name").unwrap_or_default();
    let nome = format!("{first_name} {last_name}");
    let usernames = active_usernames(payload);
    Some(LookupProfile {
        kind,
        telegram_id: id,
        name: nome.trim().to_owned(),
        username: usernames.first().cloned(),
        first_name,
        last_name,
        usernames,
        phone_number: visible_phone(payload),
    })
}

/// Entro quanto ci si aspetta l'immagine piccola del profilo: si scarica, e
/// può volerci più di una risposta puntuale. **Dieci secondi.**
const PHOTO_TIMEOUT_MS: i64 = 10_000;

/// L'identificativo del file dell'immagine **piccola** del profilo, se
/// l'account ne ha una visibile (`user.profile_photo.small.id`).
fn profile_small_photo_id(user: &str) -> Option<i64> {
    let foto = top_level_value(user, "profile_photo")?;
    if !foto.starts_with('{') {
        return None;
    }
    let piccola = top_level_value(foto, "small")?;
    top_level_number(piccola, "id").filter(|id| *id > 0)
}

/// Entro quanto ci si aspetta lo scaricamento sincrono di un allegato
/// (ATTACH-01): 25 MiB su una linea d'ufficio lenta. **Tre minuti.**
const ATTACHMENT_TIMEOUT_MS: i64 = 180_000;

/// Quante letture vuote si tollerano mentre l'allegato scende: uno
/// scaricamento sincrono tace finché non ha finito. Coprono il termine, a
/// 50 ms ciascuna.
const ATTACHMENT_MAX_POLLS: usize = 3_600;

/// I byte dell'allegato scaricato, o perché non si leggono. Si legge soltanto
/// un file completo e non oltre `max_bytes`: la dimensione si ricontrolla sul
/// disco, prima di leggerlo (ADR-0177, decisione 5). Il file è quello di
/// TDLib, con il nome che TDLib gli ha dato.
fn read_downloaded_attachment(file: &str, max_bytes: u64) -> Result<Vec<u8>, String> {
    let locale = top_level_value(file, "local")
        .ok_or_else(|| String::from("Telegram non ha detto dove ha messo l'allegato."))?;
    if json_bool_value(locale, "is_downloading_completed") != Some(true) {
        return Err(String::from(
            "Lo scaricamento dell'allegato non si è completato.",
        ));
    }
    let percorso = json_string_value(locale, "path")
        .filter(|p| !p.is_empty())
        .ok_or_else(|| String::from("Telegram non ha detto dove ha messo l'allegato."))?;
    let dati = std::fs::metadata(&percorso)
        .map_err(|_| String::from("Il file dell'allegato non si legge."))?;
    if dati.len() > max_bytes {
        return Err(format!(
            "Il file dell'allegato è di {} byte, oltre il tetto: non si conserva.",
            dati.len()
        ));
    }
    match std::fs::read(&percorso) {
        Ok(byte) if !byte.is_empty() => Ok(byte),
        _ => Err(String::from("Il file dell'allegato non si legge.")),
    }
}

/// I byte della foto scaricata, o perché non si leggono. Si legge soltanto un
/// file completo e sotto il tetto: un file più grande non è l'immagine
/// piccola che si è chiesta.
fn read_downloaded_photo(file: &str) -> (Option<Vec<u8>>, Option<String>) {
    let Some(locale) = top_level_value(file, "local") else {
        return (
            None,
            Some(String::from("Telegram non ha detto dove ha messo la foto.")),
        );
    };
    if json_bool_value(locale, "is_downloading_completed") != Some(true) {
        return (
            None,
            Some(String::from(
                "Lo scaricamento della foto non si è completato.",
            )),
        );
    }
    let Some(percorso) = json_string_value(locale, "path").filter(|p| !p.is_empty()) else {
        return (
            None,
            Some(String::from("Telegram non ha detto dove ha messo la foto.")),
        );
    };
    let Ok(dati) = std::fs::metadata(&percorso) else {
        return (None, Some(String::from("Il file della foto non si legge.")));
    };
    if dati.len() > u64::try_from(crate::profile::MAX_PHOTO_BYTES).unwrap_or(u64::MAX) {
        return (
            None,
            Some(String::from(
                "La foto è più grande del tetto, e non si conserva.",
            )),
        );
    }
    match std::fs::read(&percorso) {
        Ok(byte) if !byte.is_empty() => (Some(byte), None),
        _ => (None, Some(String::from("Il file della foto non si legge."))),
    }
}

/// La biografia di `userFullInfo.bio.text`, ripulita.
fn parse_bio(full: &str) -> Option<String> {
    let bio = top_level_value(full, "bio")?;
    if !bio.starts_with('{') {
        return None;
    }
    crate::profile::clean_bio(&json_string_value(bio, "text")?)
}

/// Lo stato di `user.status`. Un tipo sconosciuto è «non mostrato», mai
/// «non attivo».
fn parse_profile_status(user: &str) -> crate::profile::ProfileStatus {
    use crate::profile::ProfileStatus;

    let Some(stato) = top_level_value(user, "status").filter(|s| s.starts_with('{')) else {
        return ProfileStatus::NotShown;
    };
    match json_type(stato).as_deref() {
        Some("userStatusOnline") => ProfileStatus::Online,
        Some("userStatusOffline") => top_level_number(stato, "was_online")
            .filter(|secondi| *secondi > 0)
            .map_or(ProfileStatus::NotShown, |secondi| ProfileStatus::Offline {
                was_online_millis: secondi.saturating_mul(1_000),
            }),
        Some("userStatusRecently") => ProfileStatus::Recently,
        Some("userStatusLastWeek") => ProfileStatus::LastWeek,
        Some("userStatusLastMonth") => ProfileStatus::LastMonth,
        _ => ProfileStatus::NotShown,
    }
}

/// Quanti username attivi si leggono al più: Telegram ne consente pochi, e una
/// risposta che ne portasse centinaia non è una risposta da credere.
const MAX_USERNAMES: usize = 20;

/// **Tutti** gli username attivi, nell'ordine di Telegram (ADR-0153, DG-07).
///
/// Si leggono dentro `usernames`, e soltanto da `active_usernames`: quelli
/// disattivati e quello modificabile sono altro. Un valore che non ha la forma
/// di uno username — lettere, cifre, trattino basso, al più 64 caratteri — si
/// scarta invece di arrivare alla schermata.
fn active_usernames(payload: &str) -> Vec<String> {
    let Some(blocco) = slice_after(payload, "usernames") else {
        return Vec::new();
    };
    let Some(resto) = slice_after(blocco, "active_usernames") else {
        return Vec::new();
    };
    let Some(mut resto) = resto.trim_start().strip_prefix('[') else {
        return Vec::new();
    };
    let mut nomi = Vec::new();
    loop {
        resto = resto.trim_start();
        if let Some(dopo) = resto.strip_prefix(',') {
            resto = dopo;
            continue;
        }
        let Some(dopo) = resto.strip_prefix('"') else {
            // Una parentesi chiusa, o qualunque altra cosa: l'elenco finisce
            // qui, e ciò che non si legge non si indovina.
            break;
        };
        let Some(fine) = dopo.find('"') else {
            break;
        };
        let Some(nome) = dopo.get(..fine) else {
            break;
        };
        if !nome.is_empty()
            && nome.len() <= 64
            && nome
                .chars()
                .all(|carattere| carattere.is_ascii_alphanumeric() || carattere == '_')
        {
            nomi.push(nome.to_owned());
        }
        if nomi.len() >= MAX_USERNAMES {
            break;
        }
        resto = dopo.get(fine + 1..).unwrap_or_default();
    }
    nomi
}

/// Il telefono, **solo** se Telegram lo restituisce: sole cifre, da 5 a 20.
///
/// Telegram dà `phone_number` vuoto quando non lo mostra a questo account, ed
/// è il caso ordinario: vuoto resta assente. Nulla si ricava da altro.
fn visible_phone(payload: &str) -> Option<String> {
    let numero = top_level_value(payload, "phone_number")?
        .trim()
        .trim_matches('"')
        .to_owned();
    (numero.len() >= 5 && numero.len() <= 20 && numero.chars().all(|c| c.is_ascii_digit()))
        .then_some(numero)
}

/// Che gruppo è una chat, per chiederne gli iscritti (MEMBERS-01).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemberSource {
    /// Un gruppo semplice: `getBasicGroupFullInfo`.
    Basic(i64),
    /// Un supergruppo o un canale: `getSupergroupMembers`.
    Super(i64),
}

/// Il tipo di gruppo dalla risposta di `getChat`; `None` per una chat che
/// non è un gruppo.
fn member_source(chat: &str) -> Option<MemberSource> {
    let tipo = top_level_value(chat, "type")?;
    match json_type(tipo)?.as_str() {
        "chatTypeBasicGroup" => json_number_value(tipo, "basic_group_id")
            .filter(|id| *id > 0)
            .map(MemberSource::Basic),
        "chatTypeSupergroup" => json_number_value(tipo, "supergroup_id")
            .filter(|id| *id > 0)
            .map(MemberSource::Super),
        _ => None,
    }
}

/// Una riga di `chatMembers` o di `basicGroupFullInfo`, prima del nome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MemberRow {
    user_id: i64,
    status: crate::members::MemberStatus,
    joined_at_millis: Option<i64>,
}

/// Le righe degli iscritti di una pagina. Un iscritto che è una chat e non una
/// persona si salta; uno stato che non si conosce conta come iscritto.
fn parse_member_page(pagina: &str) -> Vec<MemberRow> {
    use crate::members::MemberStatus;

    split_object_array(pagina, "members")
        .into_iter()
        .filter_map(|elemento| {
            let mittente = top_level_value(elemento, "member_id")?;
            if json_type(mittente).as_deref() != Some("messageSenderUser") {
                return None;
            }
            let user_id = json_number_value(mittente, "user_id").filter(|id| *id > 0)?;
            let status = top_level_value(elemento, "status")
                .and_then(json_type)
                .and_then(|tipo| MemberStatus::from_tdlib(&tipo))
                .unwrap_or(MemberStatus::Member);
            let joined_at_millis = top_level_number(elemento, "joined_chat_date")
                .filter(|secondi| *secondi > 0)
                .map(|secondi| secondi.saturating_mul(1_000));
            Some(MemberRow {
                user_id,
                status,
                joined_at_millis,
            })
        })
        .collect()
}

/// L'iscritto, con nome, username e telefono mascherato dalla risposta di
/// `getUser`, quando c'è.
fn member_from(riga: MemberRow, utente: Option<&str>) -> crate::members::Member {
    let (display_name, username, masked_phone) = utente.map_or((None, None, None), |utente| {
        let first = json_string_value(utente, "first_name").unwrap_or_default();
        let last = json_string_value(utente, "last_name").unwrap_or_default();
        let nome = match (first.trim(), last.trim()) {
            ("", "") => None,
            ("", cognome) => Some(cognome.to_owned()),
            (nome, "") => Some(nome.to_owned()),
            (nome, cognome) => Some(format!("{nome} {cognome}")),
        };
        let username = active_usernames(utente).into_iter().next();
        let telefono = visible_phone(utente).and_then(|cifre| crate::members::mask_phone(&cifre));
        (nome, username, telefono)
    });
    crate::members::Member {
        user_id: riga.user_id,
        display_name,
        username,
        masked_phone,
        status: riga.status,
        joined_at_millis: riga.joined_at_millis,
    }
}

/// Esito della normalizzazione di un aggiornamento.
#[derive(Debug, PartialEq, Eq)]
enum Normalized {
    /// Un evento normalizzato da consegnare.
    Event(ConnectorEvent),
    /// L'aggiornamento non è pertinente o non è supportato: va conteggiato, non
    /// trasformato in errore.
    Ignored,
}

/// Mappa il tipo `@type` di uno stato TDLib sullo stato del dominio.
///
/// Copre gli **otto stati canonici** che il flusso di accesso attraversa. Lo
/// stato di disconnessione (`authorizationStateLoggingOut`) e quello di chiusura
/// (`authorizationStateClosing`) confluiscono entrambi in `Closing`: sono due
/// forme dello stesso avvicinarsi alla chiusura. Ogni altro stato restituisce
/// `None`, così che il chiamante lo tratti come non supportato senza panico.
fn map_authorization_state(td_type: &str) -> Option<AuthorizationState> {
    match td_type {
        "authorizationStateWaitTdlibParameters" => {
            Some(AuthorizationState::WaitingForTdlibParameters)
        }
        "authorizationStateWaitPhoneNumber" => Some(AuthorizationState::WaitingForPhoneNumber),
        "authorizationStateWaitCode" => Some(AuthorizationState::WaitingForCode),
        "authorizationStateWaitPassword" => Some(AuthorizationState::WaitingForPassword),
        "authorizationStateReady" => Some(AuthorizationState::Ready),
        "authorizationStateLoggingOut" | "authorizationStateClosing" => {
            Some(AuthorizationState::Closing)
        }
        "authorizationStateClosed" => Some(AuthorizationState::Closed),
        _ => None,
    }
}

/// Mappa il tipo `@type` di uno stato di connessione TDLib sul dominio.
fn map_connection_state(td_type: &str) -> Option<ConnectionState> {
    match td_type {
        "connectionStateReady" | "connectionStateUpdating" => Some(ConnectionState::Online),
        "connectionStateConnecting" | "connectionStateConnectingToProxy" => {
            Some(ConnectionState::Connecting)
        }
        "connectionStateWaitingForNetwork" => Some(ConnectionState::Interrupted),
        _ => None,
    }
}

/// Compone la richiesta `setTdlibParameters` con i campi reali della 1.8.66.
///
/// `device_model` è `NEXUM/97`, non ingannevole (ADR-0019 §4). La rete **non**
/// viene disattivata: è il connettore reale, non lo smoke test.
fn build_tdlib_parameters(prepared: &PreparedParameters) -> String {
    format!(
        concat!(
            r#"{{"@type":"setTdlibParameters","#,
            r#""use_test_dc":{use_test_dc},"#,
            r#""database_directory":"{database_directory}","#,
            r#""files_directory":"{files_directory}","#,
            r#""database_encryption_key":"{database_key}","#,
            r#""use_file_database":true,"#,
            r#""use_message_database":true,"#,
            r#""use_chat_info_database":true,"#,
            r#""use_secret_chats":false,"#,
            r#""api_id":{api_id},"#,
            r#""api_hash":"{api_hash}","#,
            r#""system_language_code":"{system_language_code}","#,
            r#""device_model":"NEXUM/97","#,
            r#""system_version":"Windows 10/11 x64","#,
            r#""application_version":"{application_version}""#,
            r#"}}"#
        ),
        use_test_dc = prepared.use_test_dc,
        database_directory = json_escape(&prepared.database_directory),
        files_directory = json_escape(&prepared.files_directory),
        database_key = json_escape(prepared.database_key_base64.expose()),
        api_id = prepared.api_id,
        api_hash = json_escape(prepared.api_hash.expose()),
        system_language_code = json_escape(&prepared.system_language_code),
        application_version = json_escape(&prepared.application_version),
    )
}

/// Normalizza un aggiornamento TDLib (diverso da `updateAuthorizationState`) in
/// un evento del dominio, oppure lo segnala come da ignorare.
///
/// `received_at_millis` è l'istante di ricezione, usato come ripiego quando
/// l'aggiornamento non porta un istante remoto proprio.
fn normalize_update(json: &str, received_at_millis: i64) -> Normalized {
    match json_type(json).as_deref() {
        Some("updateNewMessage") => normalize_new_message(json, received_at_millis),
        Some("updateMessageContent") => normalize_message_content(json, received_at_millis),
        Some("updateMessageEdited") => normalize_message_edited(json, received_at_millis),
        Some("updateDeleteMessages") => normalize_delete_messages(json, received_at_millis),
        Some("updateConnectionState") => normalize_connection_state(json),
        Some("error") => normalize_error(json),
        _ => Normalized::Ignored,
    }
}

fn normalize_new_message(json: &str, received_at_millis: i64) -> Normalized {
    let Some(message) = slice_after(json, "message") else {
        return Normalized::Ignored;
    };
    parse_message(message, received_at_millis).map_or(Normalized::Ignored, |message| {
        Normalized::Event(ConnectorEvent::MessageReceived(message))
    })
}

/// Traduce **un oggetto messaggio** nella forma normalizzata del connettore.
///
/// Separata da [`normalize_new_message`] perché la stessa forma arriva da due
/// strade: l'aggiornamento `updateNewMessage`, che ne porta uno solo, e la
/// risposta `messages` del recupero della cronologia, che ne porta molti. Una
/// seconda traduzione avrebbe fatto divergere le due — un messaggio recuperato
/// che porta un collegamento diverso da quello dello stesso messaggio
/// osservato dal vivo sarebbe un archivio che si contraddice.
///
/// `received_at_millis` è il ripiego per un messaggio senza data dichiarata.
/// Nella cronologia la data c'è sempre, ma il ripiego resta comune: dedurne uno
/// diverso qui significherebbe che lo stesso messaggio ha due istanti a seconda
/// di come è entrato.
fn parse_message(message: &str, received_at_millis: i64) -> Option<IncomingMessage> {
    // I CAMPI SI LEGGONO AL PRIMO LIVELLO DELL'OGGETTO (FINAL-REVIEW-01,
    // FR-002). Fino al 2026-10-03 si prendeva la prima occorrenza della chiave
    // nel testo, e nell'ordine dello schema TL `sender_id` precede `chat_id`:
    // per un messaggio pubblicato «come chat» (`messageSenderChat`, che porta
    // un suo `chat_id`) la chat letta era quella del MITTENTE — nei gruppi di
    // discussione, il canale collegato. Allo stesso modo `reply_to` precede
    // `content`, e può portarne uno suo.
    let (Some(chat_raw), Some(id_raw)) = (
        top_level_number(message, "chat_id"),
        top_level_number(message, "id"),
    ) else {
        return None;
    };
    let (Ok(chat_id), Ok(message_id)) = (ChatId::try_new(chat_raw), MessageId::try_new(id_raw))
    else {
        return None;
    };

    // Non tutti i messaggi hanno testo (i media senza didascalia non ne hanno):
    // l'assenza è un valore vuoto, non un errore. Il testo si cerca DENTRO il
    // contenuto e non oltre: un adesivo, che testo non ne ha, faceva proseguire
    // la ricerca fino alle etichette dei pulsanti di `reply_markup`.
    let text = top_level_value(message, "content")
        .and_then(|content| json_string_value(content, "text"))
        .unwrap_or_default();
    let published_at_millis = top_level_number(message, "date")
        .map(|date| date.saturating_mul(1_000))
        .unwrap_or(received_at_millis);

    // Il mittente: l'aggiornamento porta il tipo e, se è una persona, il suo
    // identificativo. Il **nome** non c'è — risolverlo richiede una richiesta a
    // TDLib con risposta da correlare, macchinario che oggi manca.
    let sender = top_level_value(message, "sender_id");
    let sender_type = sender.and_then(json_type);
    let sender_user_id = sender.and_then(|slice| json_number_value(slice, "user_id"));
    let author_identifier =
        crate::author::author_identifier(sender_type.as_deref(), sender_user_id);

    Some(IncomingMessage {
        chat_id,
        message_id,
        // Il nome leggibile dell'autore non è esposto nell'aggiornamento.
        author: None,
        author_identifier,
        // Il nome e lo username non stanno nell'aggiornamento del messaggio: li
        // aggiunge il connettore, che sa che cosa ha imparato dagli `updateUser`
        // già ricevuti. Questa funzione resta pura.
        author_username: None,
        text,
        published_at_millis,
        // NESSUN COLLEGAMENTO ALL'ACQUISIZIONE (LINK-01).
        //
        // Fino a LINK-01 qui si **componeva** un indirizzo dai due
        // identificativi — `t.me/c/<chat>/<messaggio>` — che funziona per i
        // membri di quella conversazione. Il problema non era che non
        // funzionasse: era che finiva **nell'archivio**, nella colonna che dice
        // dove sta il messaggio, accanto al testo acquisito e all'istante
        // dichiarato dalla fonte.
        //
        // Un indirizzo composto da noi è una **deduzione**, e in un archivio
        // che ha valore probatorio non sta nella stessa colonna dei fatti
        // osservati. Il congelamento lo scrive: **non si fabbrica** un
        // collegamento che Telegram non fornisce.
        //
        // Quello ufficiale si chiede con `message_link`, al momento in cui
        // serve, e non si conserva.
        url: None,
        // DESCRITTO, NON SCARICATO (ATTACH-01, ADR-0177): il genere e ciò che
        // il mittente dichiara. Nessuna richiesta parte da qui.
        attachment: top_level_value(message, "content")
            .and_then(parse_attachment)
            .map(Box::new),
    })
}

/// L'allegato di un contenuto, **descritto e non scaricato** (ATTACH-01,
/// ADR-0177): il genere dal tipo del contenuto, e ciò che il mittente
/// dichiara, ripulito. Un genere che non si riconosce non ha descrizione: non
/// si inventa che cosa fosse.
fn parse_attachment(content: &str) -> Option<AttachmentDescriptor> {
    let (kind, media, file) = attachment_parts(content)?;
    let Some(media) = media else {
        return Some(AttachmentDescriptor::of_kind(kind));
    };
    Some(AttachmentDescriptor {
        kind,
        declared_name: top_level_string(media, "file_name")
            .as_deref()
            .and_then(clean_declared_name),
        declared_size: file.and_then(file_declared_size),
        declared_mime: top_level_string(media, "mime_type")
            .as_deref()
            .and_then(clean_declared_mime),
    })
}

/// Il genere, l'oggetto del media e l'oggetto `file` dell'allegato di un
/// contenuto: una sola lettura della forma, per la descrizione e per lo
/// scaricamento. Un genere che non si riconosce non ha parti.
fn attachment_parts(content: &str) -> Option<(AttachmentKind, Option<&str>, Option<&str>)> {
    let (kind, oggetto, chiave_del_file) = match top_level_string(content, "@type")?.as_str() {
        "messageDocument" => (AttachmentKind::Document, "document", "document"),
        "messagePhoto" => (AttachmentKind::Photo, "photo", ""),
        "messageVideo" => (AttachmentKind::Video, "video", "video"),
        "messageAudio" => (AttachmentKind::Audio, "audio", "audio"),
        "messageVoiceNote" => (AttachmentKind::VoiceNote, "voice_note", "voice"),
        "messageVideoNote" => (AttachmentKind::VideoNote, "video_note", "video"),
        "messageAnimation" => (AttachmentKind::Animation, "animation", "animation"),
        "messageSticker" => (AttachmentKind::Sticker, "sticker", "sticker"),
        _ => return None,
    };
    let Some(media) = top_level_value(content, oggetto) else {
        return Some((kind, None, None));
    };
    // Una foto ha più dimensioni: si dichiara, e si conserverebbe, la più
    // grande.
    let file = if kind == AttachmentKind::Photo {
        split_object_array(media, "sizes")
            .into_iter()
            .filter_map(|misura| top_level_value(misura, "photo"))
            .max_by_key(|file| file_declared_size(file).unwrap_or(0))
    } else {
        top_level_value(media, chiave_del_file)
    };
    Some((kind, Some(media), file))
}

/// La dimensione di un oggetto `file` di TDLib: quella nota, o quella attesa.
fn file_declared_size(file: &str) -> Option<u64> {
    top_level_number(file, "size")
        .and_then(declared_size)
        .or_else(|| top_level_number(file, "expected_size").and_then(declared_size))
}

/// Una stringa al primo livello dell'oggetto, decodificata: vedere
/// [`top_level_value`].
fn top_level_string(json: &str, key: &str) -> Option<String> {
    super::unescape_json_string(top_level_value(json, key)?.strip_prefix('"')?)
}

/// Le relazioni che Telegram dichiara per un messaggio, lette **adesso**.
///
/// # Perché non entrano in `IncomingMessage`
///
/// Perché quel tipo attraversa l'acquisizione e diventa un contenuto
/// archiviato. Queste relazioni sono lo stato corrente della conversazione:
/// metterle nella stessa struttura le porterebbe nella colonna dei fatti,
/// accanto a un testo acquisito prima. Vivono in
/// [`lisi_telegram::MessageRelations`](crate::MessageRelations), che
/// l'acquisizione non vede.
///
/// # Perché si leggono due forme
///
/// Perché TDLib ha cambiato la forma di queste due informazioni fra versioni:
/// la risposta era `reply_to_message_id` piatto ed è diventata un oggetto
/// `reply_to`; l'origine di un inoltro si chiamava `messageForwardOrigin*` e si
/// chiama `messageOrigin*`. La versione della libreria non è verificabile senza
/// eseguirla (ADR-0008 lo dichiara: il repository non pubblica release
/// recenti), e leggere entrambe le forme **non è indovinare**: sono due forme
/// che Telegram ha realmente prodotto.
///
/// Una terza forma, non riconosciuta, dà `None`. Non si inventa che cosa
/// significasse.
fn parse_relations(message: &str, chat_id: ChatId) -> MessageRelations {
    MessageRelations {
        reply_to: parse_reply_to(message, chat_id),
        forwarded: parse_forwarded(message),
        thread: json_number_value(message, "message_thread_id").and_then(Thread::new),
        // `edit_date` vale zero quando il messaggio non e' stato modificato:
        // uno zero letto come istante direbbe «modificato il 1° gennaio 1970».
        edited_at: json_number_value(message, "edit_date")
            .filter(|secondi| *secondi > 0)
            .map(|secondi| Timestamp::from_millis(secondi.saturating_mul(1_000))),
    }
}

/// A quale messaggio questo risponde, se risponde.
fn parse_reply_to(message: &str, chat_id: ChatId) -> Option<ReplyTo> {
    // Forma recente: un oggetto, che dice anche A CHE COSA si risponde.
    if let Some(oggetto) = json_object_value(message, "reply_to") {
        // TDLib sa rappresentare anche la risposta a una storia, che **non e'
        // un messaggio** e non sta in questo contorno. Una forma diversa da
        // quella attesa non si interpreta.
        if json_type(oggetto).as_deref() != Some("messageReplyToMessage") {
            return None;
        }
        let raw = json_number_value(oggetto, "message_id")?;
        let message_id = MessageId::try_new(raw).ok()?;
        let altrove = json_number_value(oggetto, "chat_id")
            .filter(|raw| *raw != 0 && *raw != chat_id.get())
            .and_then(|raw| ChatId::try_new(raw).ok());
        return Some(match altrove {
            Some(altra) => ReplyTo::in_another_conversation(altra, message_id),
            None => ReplyTo::in_the_same_conversation(message_id),
        });
    }

    // Forma precedente: due campi piatti, e lo zero significa «nessuna
    // risposta».
    let raw = json_number_value(message, "reply_to_message_id").filter(|raw| *raw != 0)?;
    let message_id = MessageId::try_new(raw).ok()?;
    let altrove = json_number_value(message, "reply_in_chat_id")
        .filter(|raw| *raw != 0 && *raw != chat_id.get())
        .and_then(|raw| ChatId::try_new(raw).ok());
    Some(match altrove {
        Some(altra) => ReplyTo::in_another_conversation(altra, message_id),
        None => ReplyTo::in_the_same_conversation(message_id),
    })
}

/// Che questo messaggio sia un inoltro, e da dove.
fn parse_forwarded(message: &str) -> Option<Forwarded> {
    // L'oggetto va **delimitato**: cercare `date` dopo la sola chiave
    // troverebbe l'istante del messaggio che lo contiene, quando l'inoltro non
    // ne ha uno, e lo attribuirebbe all'originale.
    let info = json_object_value(message, "forward_info")?;
    let published_at = json_number_value(info, "date")
        .filter(|secondi| *secondi > 0)
        .map(|secondi| Timestamp::from_millis(secondi.saturating_mul(1_000)));
    let origin = json_object_value(info, "origin").and_then(parse_forward_origin);
    Some(Forwarded::new(origin, published_at))
}

/// Da dove viene un inoltro, quando Telegram lo dichiara in una forma nota.
///
/// # Perché un mittente nascosto è una variante e non un'assenza
///
/// Perché Telegram **dice** che c'è un mittente e **dice** di non mostrarlo.
/// Trattarlo come «origine sconosciuta» perderebbe la differenza fra «non
/// l'hanno detto» e «hanno detto di non dirlo», e quella differenza riguarda
/// una scelta di una persona.
fn parse_forward_origin(origin: &str) -> Option<ForwardOrigin> {
    match json_type(origin).as_deref() {
        Some("messageOriginUser" | "messageForwardOriginUser") => {
            json_number_value(origin, "sender_user_id")
                .filter(|identificativo| *identificativo > 0)
                .map(|identificativo| ForwardOrigin::Person {
                    identifier: identificativo.to_string(),
                })
        }
        Some("messageOriginChannel" | "messageForwardOriginChannel") => {
            let chat = ChatId::try_new(json_number_value(origin, "chat_id")?).ok()?;
            let messaggio = json_number_value(origin, "message_id")
                .and_then(|raw| MessageId::try_new(raw).ok());
            Some(ForwardOrigin::Channel {
                chat_id: chat,
                message_id: messaggio,
            })
        }
        Some("messageOriginChat" | "messageForwardOriginChat") => {
            let chat = ChatId::try_new(json_number_value(origin, "sender_chat_id")?).ok()?;
            Some(ForwardOrigin::Chat { chat_id: chat })
        }
        Some("messageOriginHiddenUser" | "messageForwardOriginHiddenUser") => {
            json_string_value(origin, "sender_name")
                .filter(|nome| !nome.trim().is_empty())
                .map(|shown_name| ForwardOrigin::Hidden { shown_name })
        }
        // Una forma che non sappiamo leggere non si indovina: l'inoltro resta,
        // e la sua origine resta `None`, che dice «Telegram non l'ha dichiarata
        // in una forma leggibile».
        _ => None,
    }
}

/// Traduce una risposta `messages` nei messaggi del **contorno**, con le loro
/// relazioni.
///
/// È il gemello di [`parse_history_page`], e le due funzioni restano separate
/// di proposito: quella alimenta l'**acquisizione**, e ciò che ne esce può
/// diventare un contenuto archiviato; questa alimenta la **vista del
/// contesto**, e ciò che ne esce non si conserva.
///
/// Unirle darebbe una funzione sola con due significati, e il primo che se ne
/// dimenticasse porterebbe una relazione letta oggi dentro un contenuto
/// acquisito ieri.
fn parse_context_page(json: &str, received_at_millis: i64) -> Vec<ContextMessage> {
    split_object_array(json, "messages")
        .into_iter()
        .filter_map(|message| {
            let letto = parse_message(message, received_at_millis)?;
            let relations = parse_relations(message, letto.chat_id);
            Some(ContextMessage {
                message: letto,
                relations,
            })
        })
        .collect()
}

/// Entro quanto ci si aspetta la risposta a una ricerca nei messaggi
/// (ADR-0154): più del contesto, perché `searchMessages` attraversa tutte le
/// chat dell'account.
const SEARCH_TIMEOUT_MS: i64 = 10_000;

/// Una pagina di risultati, da `foundMessages` (B), `foundChatMessages` (C) o
/// `foundPublicPosts` (D, ADR-0161).
///
/// I messaggi si leggono come quelli della cronologia; il cursore della pagina
/// successiva si conserva com'è. Per la D si leggono anche la quota dopo la
/// pagina e se i limiti sono superati. Una risposta di un altro tipo non
/// diventa una pagina inventata: è una pagina vuota.
fn parse_search_page(json: &str, received_at_millis: i64) -> crate::search::SearchPage {
    match json_type(json).as_deref() {
        Some("foundMessages" | "foundChatMessages") => crate::search::SearchPage {
            hits: parse_history_page(json, received_at_millis),
            total_count: top_level_value(json, "total_count")
                .and_then(|valore| valore.trim().parse::<i64>().ok()),
            next_offset: json_string_value(json, "next_offset").filter(|o| !o.is_empty()),
            next_from_message_id: top_level_value(json, "next_from_message_id")
                .and_then(|valore| valore.trim().parse::<i64>().ok())
                .filter(|id| *id > 0),
            limits: None,
            limits_exceeded: false,
        },
        Some("foundPublicPosts") => crate::search::SearchPage {
            hits: parse_history_page(json, received_at_millis),
            total_count: None,
            next_offset: json_string_value(json, "next_offset").filter(|o| !o.is_empty()),
            next_from_message_id: None,
            limits: top_level_value(json, "search_limits").and_then(parse_public_post_limits),
            // Un campo che manca o non si legge vale «superati»: la ricerca si
            // ferma invece di chiedere un'altra pagina.
            limits_exceeded: top_level_value(json, "are_limits_exceeded")
                .is_none_or(|valore| valore.trim() != "false"),
        },
        _ => crate::search::SearchPage::default(),
    }
}

/// La quota della ricerca D da un oggetto `publicPostSearchLimits`
/// (ADR-0161). Un campo che manca o non si legge dà `None`: senza quota la
/// ricerca non parte.
fn parse_public_post_limits(oggetto: &str) -> Option<crate::search::PublicPostLimits> {
    let intero = |chiave: &str| i32::try_from(top_level_number(oggetto, chiave)?).ok();
    Some(crate::search::PublicPostLimits {
        daily_free: intero("daily_free_query_count")?,
        remaining_free: intero("remaining_free_query_count")?,
        next_free_in_seconds: intero("next_free_query_in")?,
        star_count: top_level_number(oggetto, "star_count").unwrap_or(0),
        current_query_free: match top_level_value(oggetto, "is_current_query_free")?.trim() {
            "true" => true,
            "false" => false,
            _ => return None,
        },
    })
}

/// Traduce una risposta `messages` nell'elenco dei messaggi che porta.
///
/// È il recupero della cronologia visto dal connettore: TDLib risponde a
/// `getChatHistory` con un oggetto che contiene un array di messaggi, e questa
/// funzione lo riduce alla forma che il resto del prodotto conosce.
///
/// **I messaggi che non si riescono a leggere vengono saltati, non fanno
/// fallire la pagina.** Una risposta con novantanove messaggi buoni e uno
/// illeggibile deve consegnare novantanove messaggi: perderli tutti per uno
/// solo trasformerebbe un difetto minore in un buco nell'archivio.
///
/// **L'ordine è quello della risposta**, che per `getChatHistory` va dal più
/// recente al più vecchio. Non viene invertito qui: chi lo consuma sa che cosa
/// farne, e riordinare in silenzio nasconderebbe a chi legge quale sia
/// l'ordine vero.
fn parse_history_page(json: &str, received_at_millis: i64) -> Vec<IncomingMessage> {
    split_object_array(json, "messages")
        .into_iter()
        .filter_map(|message| parse_message(message, received_at_millis))
        .collect()
}

fn normalize_message_content(json: &str, received_at_millis: i64) -> Normalized {
    let (Some(chat_raw), Some(id_raw)) = (
        json_number_value(json, "chat_id"),
        json_number_value(json, "message_id"),
    ) else {
        return Normalized::Ignored;
    };
    let (Ok(chat_id), Ok(message_id)) = (ChatId::try_new(chat_raw), MessageId::try_new(id_raw))
    else {
        return Normalized::Ignored;
    };

    let text = slice_after(json, "new_content")
        .and_then(|content| json_string_value(content, "text"))
        .unwrap_or_default();

    Normalized::Event(ConnectorEvent::MessageEdited(EditedMessage {
        chat_id,
        message_id,
        text,
        // Questo aggiornamento non porta l'istante della modifica: si usa quello
        // di ricezione.
        edited_at_millis: received_at_millis,
    }))
}

fn normalize_message_edited(json: &str, received_at_millis: i64) -> Normalized {
    let (Some(chat_raw), Some(id_raw)) = (
        json_number_value(json, "chat_id"),
        json_number_value(json, "message_id"),
    ) else {
        return Normalized::Ignored;
    };
    let (Ok(chat_id), Ok(message_id)) = (ChatId::try_new(chat_raw), MessageId::try_new(id_raw))
    else {
        return Normalized::Ignored;
    };

    let edited_at_millis = json_number_value(json, "edit_date")
        .map(|date| date.saturating_mul(1_000))
        .unwrap_or(received_at_millis);

    Normalized::Event(ConnectorEvent::MessageEdited(EditedMessage {
        chat_id,
        message_id,
        // Questo aggiornamento porta l'istante ma non il nuovo testo: il testo
        // arriva con `updateMessageContent`.
        text: String::new(),
        edited_at_millis,
    }))
}

fn normalize_delete_messages(json: &str, received_at_millis: i64) -> Normalized {
    // Una rimozione non permanente è uno sfratto dalla cache di TDLib, non una
    // cancellazione reale: segnalarla falserebbe lo storico.
    if json_bool_value(json, "is_permanent") == Some(false) {
        return Normalized::Ignored;
    }

    let Some(chat_raw) = json_number_value(json, "chat_id") else {
        return Normalized::Ignored;
    };
    let Ok(chat_id) = ChatId::try_new(chat_raw) else {
        return Normalized::Ignored;
    };

    let message_ids = parse_message_ids(json);
    if message_ids.is_empty() {
        return Normalized::Ignored;
    }

    Normalized::Event(ConnectorEvent::MessagesDeleted(DeletedMessages {
        chat_id,
        message_ids,
        deleted_at_millis: received_at_millis,
    }))
}

fn normalize_connection_state(json: &str) -> Normalized {
    let Some(inner) = nested_type(json, "state") else {
        return Normalized::Ignored;
    };
    match map_connection_state(&inner) {
        Some(state) => Normalized::Event(ConnectorEvent::Connection(state)),
        None => Normalized::Ignored,
    }
}

fn normalize_error(json: &str) -> Normalized {
    let message = json_string_value(json, "message").unwrap_or_default();
    let code = json_number_value(json, "code").unwrap_or(0);
    Normalized::Event(ConnectorEvent::Failure(classify_tdlib_error(
        &message, code,
    )))
}

/// Traduce un errore TDLib nel corrispondente errore tipizzato del dominio.
///
/// I messaggi TDLib qui riconosciuti sono costanti del protocollo, non
/// contenuto dell'operatore: non trasportano segreti. Per i casi non
/// riconosciuti si conserva codice e messaggio a scopo diagnostico.
fn classify_tdlib_error(message: &str, code: i64) -> TelegramError {
    if message.contains("PHONE_CODE_INVALID")
        || message.contains("PHONE_CODE_EMPTY")
        || message.contains("PHONE_CODE_EXPIRED")
    {
        TelegramError::CodeRejected
    } else if message.contains("PASSWORD_HASH_INVALID") {
        TelegramError::PasswordRejected
    } else if message.contains("SESSION_REVOKED")
        || message.contains("AUTH_KEY_UNREGISTERED")
        || message.contains("SESSION_EXPIRED")
        || message.contains("USER_DEACTIVATED")
    {
        TelegramError::SessionRevoked
    } else {
        TelegramError::Tdlib {
            reason: format!("errore del componente per Telegram {code}: {message}"),
        }
    }
}

/// Costruisce una chat accessibile a partire da un `updateNewChat`.
///
/// Le conversazioni individuali e segrete non sono fonti monitorabili e vengono
/// scartate (restituendo `None`). Per canali, gruppi e supergruppi la lettura
/// dello storico è assunta possibile perché la chat è nell'elenco dell'account;
/// una verifica puntuale richiederebbe l'informazione estesa della chat ed è un
/// limite dichiarato.
fn parse_accessible_chat(json: &str) -> Option<AccessibleChat> {
    let chat = slice_after(json, "chat")?;
    let chat_id = ChatId::try_new(json_number_value(chat, "id")?).ok()?;
    let title = json_string_value(chat, "title").unwrap_or_default();
    let kind = classify_chat_kind(slice_after(chat, "type")?)?;

    Some(AccessibleChat {
        chat_id,
        title,
        kind,
        // Lo username non sta in questo aggiornamento: lo porta
        // `updateSupergroup`, e viene unito in lettura. Lasciarlo assente qui è
        // la verità di ciò che questa funzione ha visto.
        username: None,
        can_read_history: true,
    })
}

/// Identificativo del supergruppo che realizza una chat, quando ce n'è uno.
///
/// Vive nel tipo della chat, ed è l'unico ponte fra i due aggiornamenti che
/// portano il titolo e lo username della stessa fonte.
fn parse_chat_supergroup_id(json: &str) -> Option<i64> {
    let chat = slice_after(json, "chat")?;
    let chat_type = slice_after(chat, "type")?;
    if json_type(chat_type)?.as_str() != "chatTypeSupergroup" {
        return None;
    }
    json_number_value(chat_type, "supergroup_id").filter(|value| *value > 0)
}

/// Identificativo e username di un supergruppo annunciato.
///
/// Restituisce `None` quando il supergruppo non ha username: è il caso normale
/// dei gruppi privati, e registrare una stringa vuota li farebbe poi comparire
/// con una chiocciola e nulla dopo.
fn parse_supergroup_username(json: &str) -> Option<(i64, String)> {
    let supergroup = slice_after(json, "supergroup")?;
    let supergroup_id = json_number_value(supergroup, "id").filter(|value| *value > 0)?;

    let username = slice_after(supergroup, "usernames")
        .and_then(|slice| first_string_of_array(slice, "active_usernames"))
        .filter(|value| !value.is_empty())?;

    Some((supergroup_id, username))
}

/// Ciò che il connettore ha imparato su un utente dagli aggiornamenti.
///
/// **Nessuno dei due campi è un'identità.** Il nome cambia a piacere di chi lo
/// porta; lo username può essere rilasciato e **preso da qualcun altro**, il che
/// lo rende ancora meno affidabile di un nome per rispondere a «chi ha scritto
/// questo» a distanza di tempo. L'identità è l'identificativo numerico, e resta
/// in un campo suo.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KnownUser {
    user_id: i64,
    /// Nome leggibile, composto da nome e cognome quando ci sono.
    display_name: Option<String>,
    /// Username attivo, senza la chiocciola.
    username: Option<String>,
}

/// Estrae da `updateUser` ciò che serve a nominare un autore.
fn parse_known_user(json: &str) -> Option<KnownUser> {
    let user = slice_after(json, "user")?;
    let user_id = json_number_value(user, "id")?;
    if user_id <= 0 {
        return None;
    }

    let first = json_string_value(user, "first_name").unwrap_or_default();
    let last = json_string_value(user, "last_name").unwrap_or_default();
    let display_name = match (first.trim(), last.trim()) {
        ("", "") => None,
        ("", surname) => Some(surname.to_owned()),
        (name, "") => Some(name.to_owned()),
        (name, surname) => Some(format!("{name} {surname}")),
    };

    // Gli username attivi stanno in un array dentro `usernames`. Si prende il
    // **primo**, che TDLib documenta come quello principale. Prendere l'ultimo
    // o concatenarli darebbe un valore che non corrisponde a ciò che si vede
    // in Telegram.
    let username = slice_after(user, "usernames")
        .and_then(|slice| first_string_of_array(slice, "active_usernames"))
        .filter(|value| !value.is_empty());

    Some(KnownUser {
        user_id,
        display_name,
        username,
    })
}

/// Primo elemento testuale dell'array associato alla chiave indicata.
///
/// La scansione rispetta le stringhe e i loro escape per la stessa ragione di
/// [`split_object_array`]: il contenuto non deve poter decidere dove finisce un
/// elemento. Uno username non può contenere virgolette, ma il giorno in cui
/// questa funzione servisse a un altro campo la differenza conterebbe, e un
/// lettore non dovrebbe chiedersi se sia sicura.
fn first_string_of_array(json: &str, key: &str) -> Option<String> {
    let rest = slice_after(json, key)?.trim_start();
    let rest = rest.strip_prefix('[')?.trim_start();
    let rest = rest.strip_prefix('"')?;

    let mut value = String::new();
    let mut escaped = false;
    for character in rest.chars() {
        if escaped {
            value.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            return Some(value);
        } else {
            value.push(character);
        }
    }
    None
}

/// Classifica il tipo di chat, scartando quelle che non sono fonti.
fn classify_chat_kind(type_slice: &str) -> Option<ChatKind> {
    match json_type(type_slice)?.as_str() {
        "chatTypeSupergroup" => {
            if json_bool_value(type_slice, "is_channel") == Some(true) {
                Some(ChatKind::Channel)
            } else {
                Some(ChatKind::Supergroup)
            }
        }
        "chatTypeBasicGroup" => Some(ChatKind::Group),
        _ => None,
    }
}

/// Estrae il tipo `@type` annidato nel valore della chiave indicata.
fn nested_type(json: &str, key: &str) -> Option<String> {
    json_type(slice_after(json, key)?)
}

/// Spezza in oggetti l'array associato alla chiave indicata.
///
/// # Perché non basta contare le graffe
///
/// Il resto di questo modulo legge il JSON cercando sottostringhe, e per i campi
/// scalari funziona. Qui no: un array di messaggi contiene **testo scritto da
/// altri**, e quel testo può contenere `{`, `}`, `[`, `]` e virgolette. Un
/// conteggio ingenuo di graffe spezzerebbe l'array nel punto sbagliato appena
/// qualcuno scrive `}` in un messaggio — cioè appena qualcuno ci prova.
///
/// La scansione perciò distingue **dentro** e **fuori** da una stringa, e dentro
/// una stringa rispetta l'escape `\`. È il minimo per non farsi dettare i
/// confini dal contenuto acquisito, che questo prodotto tratta come ostile per
/// ipotesi.
///
/// Restituisce le porzioni corrispondenti a ciascun elemento dell'array, nel
/// loro ordine. Un array assente o malformato dà un elenco vuoto: non si tira a
/// indovinare su un input che non ha la forma attesa.
fn split_object_array<'a>(json: &'a str, key: &str) -> Vec<&'a str> {
    let Some(rest) = slice_after(json, key) else {
        return Vec::new();
    };
    let rest = rest.trim_start();
    if !rest.starts_with('[') {
        return Vec::new();
    }

    let bytes = rest.as_bytes();
    let mut objects = Vec::new();
    // Profondità **relativa all'array**: entra a 1 sulla `[` iniziale, e un
    // elemento è ciò che sta fra profondità 1 e 1.
    let mut depth = 0_usize;
    let mut start = 0_usize;
    let mut in_string = false;
    let mut escaped = false;

    for (index, byte) in bytes.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }

        match byte {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                if depth == 2 && *byte == b'{' {
                    start = index;
                }
            }
            b']' | b'}' => {
                if depth == 2
                    && *byte == b'}'
                    && let Some(object) = rest.get(start..=index)
                {
                    objects.push(object);
                }
                depth = depth.saturating_sub(1);
                // Chiusura dell'array: oltre non si guarda, perché ciò che
                // segue appartiene a un altro campo.
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
    }

    // L'array non si è chiuso: la risposta è troncata, e mezza risposta non è
    // mezza verità — è una risposta di cui non si conosce la fine.
    if depth != 0 {
        return Vec::new();
    }

    objects
}

/// Restituisce la porzione di `json` che inizia subito dopo `"<key>":`.
///
/// La virgoletta iniziale e i due punti finali del bisogno impediscono che una
/// chiave più lunga (per esempio `new_content` quando si cerca `content`) o una
/// annidata combacino per errore.
fn slice_after<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\":");
    let start = json.find(&needle)? + needle.len();
    json.get(start..)
}

/// Il valore della chiave `key` **al primo livello** del primo oggetto di
/// `json`, delimitato: un oggetto o un array dalla parentesi aperta a quella
/// che la chiude, una stringa con le sue virgolette, un numero o una parola
/// fino al separatore.
///
/// # Perché esiste (FINAL-REVIEW-01, FR-002)
///
/// [`slice_after`] trova la prima occorrenza della chiave **ovunque**, anche
/// dentro un oggetto annidato che la precede. Per i campi di un messaggio non
/// basta: `sender_id` (che per un mittente-chat porta un suo `chat_id`) e
/// `reply_to` (che può portare un suo `content`) precedono i campi omonimi del
/// messaggio. Qui la profondità è contata, le stringhe sono saltate con le loro
/// sequenze di escape, e una chiave conta solo a profondità uno.
///
/// Un ingresso troncato o malformato dà `None`: non si indovina.
fn top_level_value<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let bytes = json.as_bytes();
    let mut index = json.find('{')?;
    let mut depth = 0_usize;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                let fine = string_end(bytes, index)?;
                if depth == 1 {
                    let mut dopo = fine + 1;
                    while dopo < bytes.len() && bytes[dopo].is_ascii_whitespace() {
                        dopo += 1;
                    }
                    if bytes.get(dopo) == Some(&b':') {
                        if json.get(index + 1..fine) == Some(key) {
                            let mut valore = dopo + 1;
                            while valore < bytes.len() && bytes[valore].is_ascii_whitespace() {
                                valore += 1;
                            }
                            return value_at(json, valore);
                        }
                        index = dopo + 1;
                        continue;
                    }
                }
                index = fine + 1;
                continue;
            }
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    // Fine dell'oggetto: la chiave non c'è al primo livello.
                    return None;
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

/// Un numero intero al primo livello dell'oggetto: vedere [`top_level_value`].
pub(crate) fn top_level_number(json: &str, key: &str) -> Option<i64> {
    let valore = top_level_value(json, key)?;
    let cifre = valore.strip_prefix('-').unwrap_or(valore);
    if cifre.is_empty() || !cifre.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    valore.parse::<i64>().ok()
}

/// L'indice della virgoletta che chiude la stringa che si apre in `start`.
fn string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'"' => return Some(index),
            _ => index += 1,
        }
    }
    None
}

/// Il valore che comincia in `start`, delimitato.
fn value_at(json: &str, start: usize) -> Option<&str> {
    let bytes = json.as_bytes();
    match bytes.get(start)? {
        b'"' => json.get(start..=string_end(bytes, start)?),
        b'{' | b'[' => {
            let mut depth = 0_usize;
            let mut index = start;
            while index < bytes.len() {
                match bytes[index] {
                    b'"' => {
                        index = string_end(bytes, index)? + 1;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth = depth.checked_sub(1)?;
                        if depth == 0 {
                            return json.get(start..=index);
                        }
                    }
                    _ => {}
                }
                index += 1;
            }
            None
        }
        _ => {
            let fine = bytes[start..]
                .iter()
                .position(|byte| matches!(byte, b',' | b'}' | b']') || byte.is_ascii_whitespace())
                .map_or(bytes.len(), |offset| start + offset);
            json.get(start..fine)
        }
    }
}

/// Entro quanto ci si aspetta la risposta a una richiesta sull'elenco chat.
///
/// # Perché questo valore
///
/// Perché il ciclo di raccolta dura al massimo `CHATS_MAX_POLLS` letture vuote
/// da 50 ms, e un termine più lungo del ciclo non scadrebbe mai: le richieste
/// resterebbero in attesa alla chiamata successiva, e il correlatore se le
/// porterebbe appresso. **Dieci secondi** è più del ciclo di inattività e meno
/// del ciclo intero.
const CHATS_TIMEOUT_MS: i64 = 10_000;

/// Entro quanto ci si aspetta la risposta a `getMessageLink`.
///
/// Piu' corto di quello dell'elenco: e' una richiesta puntuale, e chi la fa
/// sta aspettando davanti a uno schermo. **Cinque secondi.**
const LINK_TIMEOUT_MS: i64 = 5_000;

/// Quante letture **vuote** per una richiesta puntuale.
///
/// A 50 ms ciascuna, coprono il termine dichiarato con margine. Le letture che
/// trovano un messaggio non contano (vedere [`Attesa`]).
const LINK_MAX_POLLS: usize = 200;

/// Entro quanto ci si aspetta la risposta a `getChatHistory` per un contesto.
///
/// Come il collegamento: chi la fa sta aspettando davanti a uno schermo.
const CONTEXT_TIMEOUT_MS: i64 = 5_000;

/// Quante letture **vuote** per una finestra di contesto (vedere [`Attesa`]).
const CONTEXT_MAX_POLLS: usize = 200;

/// Entro quanto si aspetta la conferma della chiusura: quanto duravano i
/// duecento tentativi da 50 ms quando la coda taceva.
const SHUTDOWN_TIMEOUT_MS: i64 = 10_000;

/// Tetto ai messaggi letti in una sola attesa, se l'orologio non avanza.
///
/// Non è il limite che conta: conta il termine. Esiste soltanto perché un
/// orologio fermo, con una coda che non si svuota mai, non trattenga la
/// schermata per sempre. Mezzo milione è molto più di quanto Telegram consegni
/// in dieci secondi a un account d'ufficio.
const MAX_MESSAGES_PER_WAIT: usize = 500_000;

/// Fino a quando si aspetta una risposta: il **termine**, e un tetto ai
/// **silenzi**.
///
/// # Perché i messaggi non consumano i tentativi (NEXUM97-FULL-OPERATIONAL-VALIDATION-01)
///
/// Fino al 2026-10-19 ogni lettura consumava un tentativo, anche quella che
/// trovava subito un aggiornamento. Dopo l'accesso, e finché nessun
/// monitoraggio li legge, gli aggiornamenti di Telegram restano in coda:
/// duecento tentativi finivano su quella coda in meno di un secondo, e la
/// risposta — che sta in fondo — non veniva mai letta. Dal vivo, «Chiedi a
/// Telegram chi è questo account» rispondeva «attesa scaduta» a ogni prova,
/// con un termine di cinque secondi mai trascorso.
///
/// Il tetto ai tentativi resta, ma conta soltanto le letture **vuote**: è lui
/// che chiude l'attesa quando la coda tace, e senza di lui una libreria che
/// non risponde terrebbe la schermata ferma fino al termine.
#[derive(Debug, Clone, Copy)]
struct Attesa {
    termine_ms: i64,
    silenzi_restanti: usize,
    messaggi_restanti: usize,
}

impl Attesa {
    /// Un'attesa che finisce al termine, o dopo `silenzi` letture vuote.
    const fn fino_a(termine_ms: i64, silenzi: usize) -> Self {
        Self {
            termine_ms,
            silenzi_restanti: silenzi,
            messaggi_restanti: MAX_MESSAGES_PER_WAIT,
        }
    }

    /// Vero finché il termine non è passato e restano letture.
    fn continua(&self) -> bool {
        self.silenzi_restanti > 0
            && self.messaggi_restanti > 0
            && adesso().as_millis() < self.termine_ms
    }

    /// Una lettura è tornata vuota.
    const fn silenzio(&mut self) {
        self.silenzi_restanti = self.silenzi_restanti.saturating_sub(1);
    }

    /// Una lettura ha trovato un messaggio.
    const fn messaggio(&mut self) {
        self.messaggi_restanti = self.messaggi_restanti.saturating_sub(1);
    }
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
///
/// Serve al correlatore per i termini. Un orologio illeggibile non deve far
/// fallire una richiesta: produrrebbe un guasto là dove non ce n'è uno. E
/// non deve nemmeno produrre un istante falso, che è ciò che accadeva
/// scrivendo l'epoca (FINAL-FPR-ALL-16, FPR-10).
fn adesso() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// Estrae il valore del campo `@extra`, che TDLib rimanda indietro immutato.
///
/// Il campo è scritto da questo prodotto come una stringa di cifre. Un valore
/// di altra forma non è uno dei nostri: si restituisce `None`, e il messaggio
/// verrà trattato come un aggiornamento spontaneo.
fn json_extra(json: &str) -> Option<u64> {
    let needle = "\"@extra\":\"";
    let start = json.find(needle)? + needle.len();
    let rest = json.get(start..)?;
    let end = rest.find('"')?;
    rest.get(..end)?.parse::<u64>().ok()
}

/// Estrae un valore numerico intero associato a una chiave.
fn json_number_value(json: &str, key: &str) -> Option<i64> {
    let needle = format!("\"{key}\":");
    let start = json.find(&needle)? + needle.len();
    let rest = json.get(start..)?.trim_start();
    let bytes = rest.as_bytes();

    let mut end = 0_usize;
    if bytes.first() == Some(&b'-') {
        end = 1;
    }
    let first_digit = end;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == first_digit {
        return None;
    }
    rest.get(..end)?.parse::<i64>().ok()
}

/// Estrae un valore booleano associato a una chiave.
fn json_bool_value(json: &str, key: &str) -> Option<bool> {
    let needle = format!("\"{key}\":");
    let start = json.find(&needle)? + needle.len();
    let rest = json.get(start..)?.trim_start();
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

/// Estrae la lista di identificativi di messaggio dall'array `message_ids`.
fn parse_message_ids(json: &str) -> Vec<MessageId> {
    let Some(after) = slice_after(json, "message_ids") else {
        return Vec::new();
    };
    let after = after.trim_start();
    let Some(inner) = after.strip_prefix('[') else {
        return Vec::new();
    };
    let end = inner.find(']').unwrap_or(inner.len());
    let Some(list) = inner.get(..end) else {
        return Vec::new();
    };

    list.split(',')
        .filter_map(|token| token.trim().parse::<i64>().ok())
        .filter_map(|value| MessageId::try_new(value).ok())
        .collect()
}

/// Rende un testo sicuro come corpo di una stringa JSON, senza le virgolette
/// delimitatrici.
fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 2);
    for character in input.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            control if (control as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out
}

/// Istante corrente in millisecondi dall'epoca Unix, senza mai andare in panico.
fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;
    use core::time::Duration;
    use std::collections::VecDeque;

    use super::parse_attachment;
    use super::{
        LiveTdlibConnector, Normalized, PreparedParameters, Redacted, TdJsonBackend,
        build_tdlib_parameters, classify_chat_kind, classify_tdlib_error, json_bool_value,
        json_escape, json_number_value, map_authorization_state, map_connection_state, nested_type,
        normalize_update, parse_accessible_chat, parse_message_ids,
    };
    use crate::attachment::{AttachmentDescriptor, AttachmentKind};
    use crate::auth::AuthorizationState;
    use crate::chat::ChatKind;
    use crate::connector::{ClientParameters, TelegramConnector};
    use crate::error::{TelegramError, TelegramResult};
    use crate::event::{ConnectionState, ConnectorEvent};
    use crate::identifier::{ChatId, MessageId};
    use crate::relation::ForwardOrigin;
    use crate::secret::{ApiHash, ApiId, PhoneNumber, REDACTED};
    use lisi_core::Timestamp;

    const FAKE_HASH: &str = "0123456789abcdef0123456789abcdef";
    const FAKE_DATABASE_KEY: &str = "AAECAwQFBgcICQoLDA0ODw==";
    // Numero dichiaratamente fittizio: non e' mai stato un numero reale, come
    // gli altri valori di prova di questo modulo e del resto della suite
    // (per esempio `crates/lisi-services/src/telegram_runtime.rs`, che usa la
    // stessa costante).
    const FAKE_PHONE: &str = "+390612345678";

    fn sample_prepared() -> PreparedParameters {
        PreparedParameters {
            api_id: 1_234_567,
            api_hash: Redacted::new(String::from(FAKE_HASH)),
            database_directory: String::from("C:\\dati\\account\\tdlib"),
            files_directory: String::from("C:\\dati\\account\\tdlib\\files"),
            database_key_base64: Redacted::new(String::from("AAECAwQFBgcICQoLDA0ODw==")),
            use_test_dc: false,
            system_language_code: String::from("it"),
            application_version: String::from("0.1.0"),
        }
    }

    // --- Doppio fittizio del confine FFI (nessuna libreria nativa caricata) -

    /// Doppio fittizio delle quattro funzioni TDLib usato **solo** nei test di
    /// questo modulo: dimostra il percorso completo dentro
    /// `LiveTdlibConnector`, fino all'evento restituito da `poll_event`, senza
    /// caricare `tdjson.dll`. Nessun `unsafe`: l'unico modulo autorizzato resta
    /// `ffi.rs`, che questo doppio non tocca in alcun modo.
    #[derive(Debug, Default)]
    struct FakeTdJson {
        receive_queue: RefCell<VecDeque<TelegramResult<Option<String>>>>,
        sent_requests: RefCell<Vec<String>>,
        /// I `client_id` con cui `send` è stata chiamata finora, nello stesso
        /// ordine di [`Self::sent_requests`]: usato per verificare che ogni
        /// invio, dal risveglio in poi, usi sempre lo stesso identificativo.
        sent_client_ids: RefCell<Vec<i32>>,
        /// Se impostato, la **prossima** chiamata a `send` fallisce con
        /// questo errore (una sola volta): riproduce un guasto FFI nell'invio
        /// della risposta a un aggiornamento appena ricevuto.
        next_send_error: RefCell<Option<TelegramError>>,
    }

    impl FakeTdJson {
        fn new() -> Self {
            Self::default()
        }

        /// Accoda la risposta restituita dalla prossima chiamata a `receive`.
        fn then_receive(self, response: TelegramResult<Option<String>>) -> Self {
            self.receive_queue.borrow_mut().push_back(response);
            self
        }

        /// Arma il guasto sulla **prossima** chiamata a `send`, una sola volta.
        ///
        /// Prende `&self`, non `self`: va potuto richiamare **dopo** che
        /// `start()` ha già consumato con successo il proprio invio di
        /// risveglio, per colpire con precisione un invio successivo (per
        /// esempio quello di `setTdlibParameters` dentro
        /// `handle_authorization`), non quello di `start()`.
        fn failing_next_send(&self, error: TelegramError) {
            *self.next_send_error.borrow_mut() = Some(error);
        }

        /// Accoda una risposta **dopo** che il connettore è già stato
        /// costruito attorno a questo doppio fittizio (a differenza di
        /// [`Self::then_receive`], che prende `self` e va usato solo prima).
        /// Serve ai test del percorso numero → codice, che devono far
        /// avanzare il connettore fino a `WaitingForPhoneNumber` prima di
        /// programmare l'aggiornamento successivo.
        fn queue_receive(&self, response: TelegramResult<Option<String>>) {
            self.receive_queue.borrow_mut().push_back(response);
        }

        /// Le richieste inviate finora, nell'ordine: usato per verificare che
        /// `setTdlibParameters` sia stato davvero composto e inoltrato.
        fn sent_requests(&self) -> Vec<String> {
            self.sent_requests.borrow().clone()
        }

        /// I `client_id` con cui ogni invio è stato effettuato, nello stesso
        /// ordine di [`Self::sent_requests`].
        fn sent_client_ids(&self) -> Vec<i32> {
            self.sent_client_ids.borrow().clone()
        }
    }

    impl TdJsonBackend for FakeTdJson {
        fn create_client_id(&self) -> TelegramResult<i32> {
            Ok(1)
        }

        fn send(&self, client_id: i32, request: &str) -> TelegramResult<()> {
            if let Some(error) = self.next_send_error.borrow_mut().take() {
                return Err(error);
            }
            self.sent_requests.borrow_mut().push(request.to_string());
            self.sent_client_ids.borrow_mut().push(client_id);
            Ok(())
        }

        fn receive(&self, _timeout_seconds: f64) -> TelegramResult<Option<String>> {
            self.receive_queue
                .borrow_mut()
                .pop_front()
                .unwrap_or(Ok(None))
        }

        fn execute(&self, _request: &str) -> TelegramResult<Option<String>> {
            Ok(None)
        }
    }

    fn fake_client_parameters() -> ClientParameters {
        let (Ok(api_id), Ok(api_hash)) = (ApiId::try_new(1), ApiHash::try_new(FAKE_HASH)) else {
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

    const WAIT_TDLIB_PARAMETERS_UPDATE: &str = concat!(
        r#"{"@type":"updateAuthorizationState","authorization_state":"#,
        r#"{"@type":"authorizationStateWaitTdlibParameters"}}"#
    );

    const WAIT_PHONE_NUMBER_UPDATE: &str = concat!(
        r#"{"@type":"updateAuthorizationState","authorization_state":"#,
        r#"{"@type":"authorizationStateWaitPhoneNumber"}}"#
    );

    const WAIT_CODE_UPDATE: &str = concat!(
        r#"{"@type":"updateAuthorizationState","authorization_state":"#,
        r#"{"@type":"authorizationStateWaitCode","code_info":{}}}"#
    );

    /// Porta un connettore fittizio appena avviato fino a
    /// `WaitingForPhoneNumber`, consumando i due aggiornamenti intermedi.
    /// Riusata da tutti i test del percorso numero → codice, per non
    /// ripetere la stessa sequenza in ognuno.
    fn connector_waiting_for_phone_number() -> LiveTdlibConnector<FakeTdJson> {
        let backend = FakeTdJson::new()
            .then_receive(Ok(Some(String::from(WAIT_TDLIB_PARAMETERS_UPDATE))))
            .then_receive(Ok(Some(String::from(WAIT_PHONE_NUMBER_UPDATE))));
        let mut connector = LiveTdlibConnector::new(backend, String::from(FAKE_DATABASE_KEY));
        let Ok(()) = connector.start(&fake_client_parameters()) else {
            panic!("l'avvio deve riuscire");
        };
        for _ in 0..2 {
            let Ok(Some(_)) = connector.poll_event(Duration::from_millis(10)) else {
                panic!("i due aggiornamenti intermedi devono arrivare fino a poll_event");
            };
        }
        assert_eq!(
            connector.authorization_state(),
            AuthorizationState::WaitingForPhoneNumber
        );
        connector
    }

    /// OBS-TG-1: all'avvio TDLib manda un centinaio di aggiornamenti che non
    /// diventano eventi prima di `authorizationStateReady`. Se ognuno di essi
    /// chiudeva la lettura, il pronto arrivava cento giri di pompaggio dopo:
    /// 25-30 secondi di «Preparazione in corso».
    #[test]
    fn gli_aggiornamenti_muti_non_ritardano_il_pronto() {
        const READY_UPDATE: &str = concat!(
            r#"{"@type":"updateAuthorizationState","authorization_state":"#,
            r#"{"@type":"authorizationStateReady"}}"#
        );
        const OPTION_UPDATE: &str = r#"{"@type":"updateOption","name":"version","value":{"@type":"optionValueString","value":"1.8"}}"#;
        let mut backend =
            FakeTdJson::new().then_receive(Ok(Some(String::from(WAIT_TDLIB_PARAMETERS_UPDATE))));
        for _ in 0..150 {
            backend = backend.then_receive(Ok(Some(String::from(OPTION_UPDATE))));
        }
        let backend = backend.then_receive(Ok(Some(String::from(READY_UPDATE))));
        let mut connector = LiveTdlibConnector::new(backend, String::from(FAKE_DATABASE_KEY));
        let Ok(()) = connector.start(&fake_client_parameters()) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(Some(_)) = connector.poll_event(Duration::from_millis(10)) else {
            panic!("la richiesta dei parametri deve arrivare");
        };
        let Ok(Some(ConnectorEvent::Authorization(stato))) =
            connector.poll_event(Duration::from_millis(10))
        else {
            panic!("una sola lettura deve attraversare gli aggiornamenti muti fino al pronto");
        };
        assert_eq!(stato, AuthorizationState::Ready);
        // E la coda vuota resta una coda vuota.
        assert!(matches!(
            connector.poll_event(Duration::from_millis(10)),
            Ok(None)
        ));
    }

    /// Le chat archiviate vivono in `chatListArchive`, una lista distinta da
    /// `chatListMain`: interrogare solo la principale le rende invisibili fra
    /// le fonti disponibili, **senza alcun errore** e senza modo di
    /// accorgersene se non confrontando l'elenco a mano con Telegram
    /// (osservato nel pilot del 2026-07-30). L'archiviazione è una scelta di
    /// ordinamento personale di chi possiede l'account, non un giudizio sulla
    /// rilevanza della fonte.
    #[test]
    fn the_available_chats_include_the_archived_ones_and_not_only_the_main_list() {
        const READY_UPDATE: &str = concat!(
            r#"{"@type":"updateAuthorizationState","authorization_state":"#,
            r#"{"@type":"authorizationStateReady"}}"#
        );
        const MAIN_CHAT: &str = concat!(
            r#"{"@type":"updateNewChat","chat":{"@type":"chat","id":-1001111111111,"#,
            r#""title":"Canale nella lista principale","#,
            r#""type":{"@type":"chatTypeSupergroup","supergroup_id":11,"is_channel":true}}}"#
        );
        const ARCHIVED_CHAT: &str = concat!(
            r#"{"@type":"updateNewChat","chat":{"@type":"chat","id":-1002222222222,"#,
            r#""title":"Canale archiviato","#,
            r#""type":{"@type":"chatTypeSupergroup","supergroup_id":22,"is_channel":true}}}"#
        );
        // Le risposte portano l'`@extra` della richiesta a cui appartengono,
        // come fa TDLib: senza, passerebbero per aggiornamenti spontanei e la
        // prova attraverserebbe un percorso diverso da quello vero.
        const CHATS_MAIN: &str = r#"{"@type":"chats","@extra":"2","total_count":1,"chat_ids":[]}"#;
        const CHATS_ARCHIVE: &str =
            r#"{"@type":"chats","@extra":"4","total_count":1,"chat_ids":[]}"#;

        // Il doppio consegna la chat principale con la risposta della prima
        // lista, e quella archiviata solo con la risposta della seconda: se il
        // connettore interrogasse una lista sola, o si fermasse alla prima
        // risposta, la seconda non comparirebbe mai.
        let backend = FakeTdJson::new()
            .then_receive(Ok(Some(String::from(WAIT_TDLIB_PARAMETERS_UPDATE))))
            .then_receive(Ok(Some(String::from(READY_UPDATE))))
            .then_receive(Ok(Some(String::from(MAIN_CHAT))))
            .then_receive(Ok(Some(String::from(CHATS_MAIN))))
            .then_receive(Ok(None))
            .then_receive(Ok(Some(String::from(ARCHIVED_CHAT))))
            .then_receive(Ok(Some(String::from(CHATS_ARCHIVE))));
        let mut connector = LiveTdlibConnector::new(backend, String::from(FAKE_DATABASE_KEY));
        let Ok(()) = connector.start(&fake_client_parameters()) else {
            panic!("l'avvio deve riuscire");
        };
        for _ in 0..2 {
            let Ok(Some(_)) = connector.poll_event(Duration::from_millis(10)) else {
                panic!("gli aggiornamenti di autorizzazione devono arrivare");
            };
        }
        assert_eq!(connector.authorization_state(), AuthorizationState::Ready);

        let sent_before = connector.library.sent_requests().len();
        let Ok(chats) = connector.accessible_chats() else {
            panic!("la raccolta delle chat deve riuscire");
        };

        // Entrambe le liste sono state interrogate, ciascuna con `loadChats` e
        // `getChats`.
        let sent = connector.library.sent_requests();
        let issued = &sent[sent_before..];
        for list in ["chatListMain", "chatListArchive"] {
            for command in ["loadChats", "getChats"] {
                assert!(
                    issued
                        .iter()
                        .any(|request| request.contains(command) && request.contains(list)),
                    "manca la richiesta {command} per {list}: {issued:?}"
                );
            }
        }

        // E la chat archiviata è davvero fra le fonti disponibili.
        let titles: Vec<&str> = chats.iter().map(|chat| chat.title.as_str()).collect();
        assert!(
            titles.contains(&"Canale archiviato"),
            "la chat archiviata deve comparire fra le fonti disponibili: {titles:?}"
        );
        assert!(
            titles.contains(&"Canale nella lista principale"),
            "la chat della lista principale non deve andare persa: {titles:?}"
        );
    }

    /// Regressione del pilot del 2026-07-30: `updateNewChat` e' l'unico modo
    /// in cui TDLib annuncia una chat accessibile, e la annuncia **una volta
    /// sola** per client. Finiva fra gli aggiornamenti "ignorati" di
    /// `poll_event`, quindi il pompaggio periodico (ogni 200 ms) se lo
    /// mangiava prima che `accessible_chats` potesse vederlo: due consumatori
    /// della stessa coda, e chi arriva primo fa sparire la chat per sempre.
    /// L'operatore vedeva l'elenco delle fonti disponibili completo la prima
    /// volta e monco dopo, senza alcun errore.
    #[test]
    fn a_chat_announced_while_polling_is_not_lost_for_the_available_sources() {
        const READY_UPDATE: &str = concat!(
            r#"{"@type":"updateAuthorizationState","authorization_state":"#,
            r#"{"@type":"authorizationStateReady"}}"#
        );
        const ANNOUNCED_CHAT: &str = concat!(
            r#"{"@type":"updateNewChat","chat":{"@type":"chat","id":-1003333333333,"#,
            r#""title":"Canale annunciato durante il pompaggio","#,
            r#""type":{"@type":"chatTypeSupergroup","supergroup_id":33,"is_channel":true}}}"#
        );
        // Le risposte portano l'`@extra` della richiesta a cui appartengono,
        // come fa TDLib: senza, passerebbero per aggiornamenti spontanei e la
        // prova attraverserebbe un percorso diverso da quello vero.
        const CHATS_MAIN: &str = r#"{"@type":"chats","@extra":"2","total_count":0,"chat_ids":[]}"#;
        const CHATS_ARCHIVE: &str =
            r#"{"@type":"chats","@extra":"4","total_count":0,"chat_ids":[]}"#;

        let backend = FakeTdJson::new()
            .then_receive(Ok(Some(String::from(WAIT_TDLIB_PARAMETERS_UPDATE))))
            .then_receive(Ok(Some(String::from(READY_UPDATE))))
            // La chat viene annunciata **al pompaggio**, non durante la
            // raccolta: e' esattamente il caso che la faceva sparire.
            .then_receive(Ok(Some(String::from(ANNOUNCED_CHAT))))
            // Dopo l'annuncio la coda è vuota: la lettura che lo assorbe
            // continua a leggere (OBS-TG-1) e deve trovarla vuota, come la
            // troverebbe con TDLib, prima che la raccolta chieda le liste.
            .then_receive(Ok(None))
            .then_receive(Ok(Some(String::from(CHATS_MAIN))))
            .then_receive(Ok(None))
            .then_receive(Ok(Some(String::from(CHATS_ARCHIVE))))
            .then_receive(Ok(None))
            // La seconda raccolta: TDLib risponde di nuovo a `getChats`, ma non
            // ri-annuncia le chat. Dal 2026-10-03 (FR-008) una raccolta a cui
            // le liste non rispondono è un'attesa scaduta, non un elenco: la
            // prova dà le risposte, come le darebbe TDLib.
            .then_receive(Ok(Some(String::from(
                r#"{"@type":"chats","@extra":"6","total_count":0,"chat_ids":[]}"#,
            ))))
            .then_receive(Ok(Some(String::from(
                r#"{"@type":"chats","@extra":"8","total_count":0,"chat_ids":[]}"#,
            ))));
        let mut connector = LiveTdlibConnector::new(backend, String::from(FAKE_DATABASE_KEY));
        let Ok(()) = connector.start(&fake_client_parameters()) else {
            panic!("l'avvio deve riuscire");
        };
        for _ in 0..2 {
            let Ok(Some(_)) = connector.poll_event(Duration::from_millis(10)) else {
                panic!("gli aggiornamenti di autorizzazione devono arrivare");
            };
        }

        // Il pompaggio legge l'annuncio della chat: non produce un evento,
        // perche' non e' un contenuto, ma non deve nemmeno perderlo.
        let Ok(None) = connector.poll_event(Duration::from_millis(10)) else {
            panic!("l'annuncio di una chat non e' un evento da consegnare");
        };

        let Ok(chats) = connector.accessible_chats() else {
            panic!("la raccolta delle chat deve riuscire");
        };
        let titles: Vec<&str> = chats.iter().map(|chat| chat.title.as_str()).collect();
        assert!(
            titles.contains(&"Canale annunciato durante il pompaggio"),
            "una chat annunciata mentre il pompaggio leggeva deve restare fra \
             le fonti disponibili: {titles:?}"
        );

        // E una seconda apertura della schermata Fonti deve dare lo stesso
        // elenco: TDLib non ri-annuncia le chat gia' annunciate.
        let Ok(again) = connector.accessible_chats() else {
            panic!("la seconda raccolta deve riuscire");
        };
        assert_eq!(
            again.len(),
            chats.len(),
            "l'elenco non deve dimagrire alla seconda apertura: {again:?}"
        );
    }

    /// "start() prepara davvero lo stato perche' il primo poll_event() possa
    /// avanzare" + "un finto updateAuthorizationState arriva davvero fino a un
    /// evento restituito da poll_event" + "il primo stato atteso viene
    /// normalizzato correttamente": le tre verifiche del percorso completo
    /// (caricamento -> creazione client -> prima receive -> parsing JSON ->
    /// riconoscimento -> normalizzazione -> transizione -> evento) in un solo
    /// giro, con una libreria fittizia.
    #[test]
    fn a_fake_wait_tdlib_parameters_update_reaches_a_returned_poll_event() {
        let backend =
            FakeTdJson::new().then_receive(Ok(Some(String::from(WAIT_TDLIB_PARAMETERS_UPDATE))));
        let mut connector = LiveTdlibConnector::new(backend, String::from(FAKE_DATABASE_KEY));

        let Ok(()) = connector.start(&fake_client_parameters()) else {
            panic!("l'avvio deve riuscire e non deve contattare alcuna rete");
        };
        // `start()` da solo non fa avanzare la macchina: e' `poll_event` a
        // farlo, alla ricezione del primo aggiornamento.
        assert_eq!(
            connector.authorization_state(),
            AuthorizationState::Uninitialized
        );

        let Ok(Some(ConnectorEvent::Authorization(state))) =
            connector.poll_event(Duration::from_millis(10))
        else {
            panic!(
                "l'aggiornamento fittizio deve arrivare fino a un evento restituito da poll_event"
            );
        };
        assert_eq!(state, AuthorizationState::WaitingForTdlibParameters);
        assert_eq!(
            connector.authorization_state(),
            AuthorizationState::WaitingForTdlibParameters
        );
        let sent = connector.library.sent_requests();
        assert_eq!(
            sent.len(),
            2,
            "il risveglio del client (start) e i parametri (in risposta \
             all'aggiornamento) devono essere stati entrambi inviati"
        );
        assert!(
            sent[0].contains("getOption"),
            "la prima richiesta, inviata da start() prima di ricevere alcunché, \
             deve essere il risveglio del client"
        );
        assert!(
            sent[1].contains("setTdlibParameters"),
            "la seconda richiesta, inviata in risposta all'aggiornamento, \
             deve essere setTdlibParameters"
        );
    }

    /// "numero valido inviato una sola volta" + "`setAuthenticationPhoneNumber`
    /// verificata nel contenuto della richiesta inviata": una singola
    /// chiamata a `submit_phone_number` deve produrre esattamente una
    /// richiesta TDLib, con il tipo e il numero (fittizio) attesi.
    #[test]
    fn submit_phone_number_sends_exactly_one_correctly_composed_request() {
        let mut connector = connector_waiting_for_phone_number();
        let sent_before = connector.library.sent_requests().len();

        let Ok(phone) = PhoneNumber::try_new(FAKE_PHONE) else {
            panic!("il numero di prova deve essere valido");
        };
        let Ok(()) = connector.submit_phone_number(&phone) else {
            panic!("l'invio del numero deve riuscire");
        };

        let sent = connector.library.sent_requests();
        assert_eq!(
            sent.len(),
            sent_before + 1,
            "una singola chiamata deve inviare esattamente una richiesta"
        );
        let request = &sent[sent_before];
        assert!(request.contains(r#""@type":"setAuthenticationPhoneNumber""#));
        assert!(request.contains(r#""phone_number":"+390612345678""#));
        // Nessuna transizione sincrona: `submit_phone_number` invia soltanto,
        // la transizione arriva solo con un successivo `poll_event`.
        assert_eq!(
            connector.authorization_state(),
            AuthorizationState::WaitingForPhoneNumber
        );
    }

    /// Regressione — la causa più plausibile dell'incidente del 2026-07-29
    /// (il codice non arrivava mai, `LIVE-E009` restava mostrato):
    /// `authorizationStateWaitCode`, ricevuto **dopo** l'invio del numero,
    /// deve percorrere lo stesso cammino completo già dimostrato per
    /// `authorizationStateWaitTdlibParameters`
    /// (`a_fake_wait_tdlib_parameters_update_reaches_a_returned_poll_event`),
    /// non un cammino diverso o più corto.
    #[test]
    fn a_fake_wait_code_update_after_the_phone_number_reaches_a_returned_poll_event() {
        let mut connector = connector_waiting_for_phone_number();
        connector
            .library
            .queue_receive(Ok(Some(String::from(WAIT_CODE_UPDATE))));

        let Ok(phone) = PhoneNumber::try_new(FAKE_PHONE) else {
            panic!("il numero di prova deve essere valido");
        };
        let Ok(()) = connector.submit_phone_number(&phone) else {
            panic!("l'invio del numero deve riuscire");
        };

        let Ok(Some(ConnectorEvent::Authorization(state))) =
            connector.poll_event(Duration::from_millis(10))
        else {
            panic!(
                "l'aggiornamento authorizationStateWaitCode deve arrivare fino a un \
                 evento restituito da poll_event"
            );
        };
        assert_eq!(state, AuthorizationState::WaitingForCode);
        assert_eq!(
            connector.authorization_state(),
            AuthorizationState::WaitingForCode
        );
    }

    /// Un numero rifiutato dalla macchina di autorizzazione (stato diverso da
    /// `WaitingForPhoneNumber`) non deve mai raggiungere TDLib: nessuna
    /// richiesta va inviata.
    #[test]
    fn submitting_the_phone_number_outside_the_expected_state_never_reaches_tdlib() {
        let backend = FakeTdJson::new();
        let mut connector = LiveTdlibConnector::new(backend, String::from(FAKE_DATABASE_KEY));
        // Mai avviato: lo stato resta `Uninitialized`, non `WaitingForPhoneNumber`.

        let Ok(phone) = PhoneNumber::try_new(FAKE_PHONE) else {
            panic!("il numero di prova deve essere valido");
        };
        assert!(
            connector.submit_phone_number(&phone).is_err(),
            "il numero non deve essere accettato fuori dallo stato atteso"
        );
        assert!(
            connector.library.sent_requests().is_empty(),
            "nessuna richiesta deve raggiungere TDLib se lo stato non e' quello atteso"
        );
    }

    /// Regressione — causa più accreditata di LIVE-E010 (incidente del
    /// 2026-07-29, sessione successiva), non riconfermata con un pilot reale
    /// in questa sessione: prima di questa correzione `start()` creava il
    /// client e restituiva subito, senza inviargli nulla. Un client TDLib
    /// appena creato non emette spontaneamente `authorizationStateWaitTdlibParameters`
    /// finché non riceve almeno una richiesta (comportamento documentato dagli
    /// esempi ufficiali TDLib): senza risveglio, `poll_event`/`receive`
    /// restava in attesa per sempre, coerente con quanto il pilot ha
    /// osservato (timeout dei 20 secondi, nessun primo aggiornamento mai
    /// ricevuto). Qui si verifica che `start()`
    /// invii ora, da solo, esattamente una richiesta di risveglio di sola
    /// lettura — **prima** di attendere alcunché e **prima** di conoscere lo
    /// stato ricevuto, quindi mai `setTdlibParameters`, il cui invio resta
    /// condizionato allo stato che TDLib comunicherà.
    #[test]
    fn start_wakes_up_the_newly_created_client_before_waiting_for_any_update() {
        let backend = FakeTdJson::new();
        let mut connector = LiveTdlibConnector::new(backend, String::from(FAKE_DATABASE_KEY));

        let Ok(()) = connector.start(&fake_client_parameters()) else {
            panic!("l'avvio deve riuscire e deve inviare il risveglio del client");
        };

        let sent = connector.library.sent_requests();
        assert_eq!(
            sent.len(),
            1,
            "start() deve inviare esattamente una richiesta, il risveglio, \
             prima di attendere alcunché"
        );
        assert!(
            sent[0].contains("getOption"),
            "il risveglio deve essere una richiesta di sola lettura"
        );
        assert!(
            !sent[0].contains("setTdlibParameters"),
            "il risveglio non deve anticipare l'invio dei parametri, che resta \
             condizionato allo stato realmente ricevuto"
        );
        assert!(
            !sent[0].contains(FAKE_HASH) && !sent[0].contains(FAKE_DATABASE_KEY),
            "il risveglio è una costante fissa: non deve trasportare alcun \
             valore riservato dei parametri del client"
        );
    }

    /// Regressione — un guasto FFI proprio sul risveglio inviato da `start()`
    /// (non su un invio successivo) deve risalire come errore, senza panico,
    /// e non deve lasciare la macchina di autorizzazione mossa. `client_id` è
    /// però già stato creato per davvero dentro TDLib (irreversibile, prima
    /// del risveglio): `started` resta perciò `true` anche in questo caso, e
    /// un secondo `start()` sullo **stesso** connettore resta rifiutato, come
    /// per qualunque avvio già tentato — evita di creare un secondo client
    /// orfano dentro TDLib. Chi chiama ricostruisce un connettore nuovo (è
    /// così che `AccountRuntime::open_live` funziona già oggi).
    #[test]
    fn a_send_failure_on_the_wake_up_itself_fails_start_cleanly_without_corrupting_state() {
        let backend = FakeTdJson::new();
        backend.failing_next_send(TelegramError::Tdlib {
            reason: String::from("invio non riuscito (prova)"),
        });
        let mut connector = LiveTdlibConnector::new(backend, String::from(FAKE_DATABASE_KEY));

        let Err(error) = connector.start(&fake_client_parameters()) else {
            panic!("un risveglio non riuscito deve far fallire start()");
        };
        assert!(matches!(error, TelegramError::Tdlib { .. }));
        assert_eq!(
            connector.authorization_state(),
            AuthorizationState::Uninitialized,
            "un avvio fallito non deve aver mosso la macchina di autorizzazione"
        );

        // Un secondo tentativo sullo stesso connettore resta rifiutato: il
        // client era già stato creato per davvero prima del risveglio fallito,
        // e ricrearne un secondo lascerebbe il primo orfano dentro TDLib.
        let Err(second_error) = connector.start(&fake_client_parameters()) else {
            panic!(
                "un secondo start() sullo stesso connettore deve restare \
                 rifiutato anche dopo un risveglio fallito, non creare un \
                 secondo client"
            );
        };
        assert!(matches!(second_error, TelegramError::Tdlib { .. }));
    }

    /// Regressione — incidente del 2026-07-29, "sospetto strutturale #1": un
    /// guasto FFI nell'invio della risposta a `authorizationStateWaitTdlibParameters`
    /// deve risalire come errore (senza panico) **e** non deve lasciare la
    /// macchina bloccata in silenzio su uno stato stantio: prima della
    /// correzione l'invio avveniva prima della transizione, e un suo
    /// fallimento impediva alla transizione di avvenire affatto, bloccando la
    /// macchina su `Uninitialized` per sempre (l'aggiornamento gia' consumato
    /// da TDLib non viene mai re-inviato).
    #[test]
    fn a_send_failure_right_after_receiving_the_update_still_leaves_the_state_consistent() {
        let backend =
            FakeTdJson::new().then_receive(Ok(Some(String::from(WAIT_TDLIB_PARAMETERS_UPDATE))));
        let mut connector = LiveTdlibConnector::new(backend, String::from(FAKE_DATABASE_KEY));

        let Ok(()) = connector.start(&fake_client_parameters()) else {
            panic!("l'avvio deve riuscire, inviando con successo il risveglio del client");
        };

        // Il guasto si arma solo ORA, sul prossimo invio: deve colpire
        // `setTdlibParameters` dentro `handle_authorization`, non il risveglio
        // già avvenuto (e riuscito) dentro `start()`.
        connector.library.failing_next_send(TelegramError::Tdlib {
            reason: String::from("invio non riuscito (prova)"),
        });

        let outcome = connector.poll_event(Duration::from_millis(10));
        assert!(
            outcome.is_err(),
            "il fallimento dell'invio deve risalire come errore, non sparire in silenzio"
        );
        assert_eq!(
            connector.authorization_state(),
            AuthorizationState::WaitingForTdlibParameters,
            "lo stato deve riflettere l'aggiornamento ricevuto anche se l'invio successivo e' fallito"
        );
    }

    /// Uno stato di autorizzazione non riconosciuto non deve mai causare
    /// panico ne' una transizione illecita.
    #[test]
    fn an_unrecognized_authorization_state_does_not_panic_or_transition() {
        let backend = FakeTdJson::new().then_receive(Ok(Some(String::from(concat!(
            r#"{"@type":"updateAuthorizationState","authorization_state":"#,
            r#"{"@type":"authorizationStateWaitPremiumPurchase"}}"#
        )))));
        let mut connector = LiveTdlibConnector::new(backend, String::from(FAKE_DATABASE_KEY));
        let Ok(()) = connector.start(&fake_client_parameters()) else {
            panic!("l'avvio deve riuscire");
        };

        let Ok(None) = connector.poll_event(Duration::from_millis(10)) else {
            panic!("uno stato non riconosciuto non deve produrre un evento ne' un errore");
        };
        assert_eq!(
            connector.authorization_state(),
            AuthorizationState::Uninitialized
        );
    }

    /// Una coda vuota (nessun aggiornamento entro l'attesa) e' la condizione
    /// normale di una fonte silenziosa: non deve mai interrompere il ciclo ne'
    /// tradursi in un errore.
    #[test]
    fn an_empty_receive_is_reported_as_no_event_and_does_not_break_the_cycle() {
        let backend = FakeTdJson::new();
        let mut connector = LiveTdlibConnector::new(backend, String::from(FAKE_DATABASE_KEY));
        let Ok(()) = connector.start(&fake_client_parameters()) else {
            panic!("l'avvio deve riuscire");
        };

        for _ in 0..3 {
            let Ok(None) = connector.poll_event(Duration::from_millis(1)) else {
                panic!("una coda vuota deve restituire nessun evento, non un errore");
            };
        }
        assert_eq!(
            connector.authorization_state(),
            AuthorizationState::Uninitialized
        );
    }

    /// Non regressione — un secondo `start()` sullo stesso connettore resta
    /// rifiutato in modo pulito, senza panico e senza creare un secondo
    /// client.
    #[test]
    fn a_second_start_on_the_same_connector_is_refused_cleanly() {
        let backend = FakeTdJson::new();
        let mut connector = LiveTdlibConnector::new(backend, String::from(FAKE_DATABASE_KEY));
        let Ok(()) = connector.start(&fake_client_parameters()) else {
            panic!("il primo avvio deve riuscire");
        };

        let Err(error) = connector.start(&fake_client_parameters()) else {
            panic!("il secondo avvio deve essere rifiutato");
        };
        assert!(matches!(error, TelegramError::Tdlib { .. }));
    }

    /// L'arresto ordinato porta un connettore mai avviato direttamente allo
    /// stato chiuso, senza toccare alcuna libreria.
    #[test]
    fn shutdown_moves_an_unstarted_connector_straight_to_closed() {
        let backend = FakeTdJson::new();
        let mut connector = LiveTdlibConnector::new(backend, String::from(FAKE_DATABASE_KEY));
        let Ok(()) = connector.shutdown() else {
            panic!("l'arresto deve riuscire anche senza avvio");
        };
        assert_eq!(connector.authorization_state(), AuthorizationState::Closed);
    }

    /// Regressione diretta — incidente del 2026-07-30 (pilot Live ripetuto):
    /// prima di questa correzione, interrogare un connettore mai avviato
    /// restituiva lo stesso messaggio generico usato per "nessun
    /// aggiornamento ricevuto", indistinguibile da quel caso. Un connettore
    /// mai avviato deve invece restituire un errore tipizzato e distinto, che
    /// nomini esplicitamente il client mai creato.
    #[test]
    fn polling_a_never_started_connector_returns_a_distinct_typed_error() {
        let backend = FakeTdJson::new();
        let mut connector = LiveTdlibConnector::new(backend, String::from(FAKE_DATABASE_KEY));

        let Err(TelegramError::Tdlib { reason }) = connector.poll_event(Duration::from_millis(10))
        else {
            panic!("un connettore mai avviato deve rifiutare il polling con un errore tipizzato");
        };
        assert!(
            reason.contains("non risulta creato"),
            "il messaggio deve nominare esplicitamente il client mai creato, non un \
             generico 'nessun aggiornamento': {reason}"
        );
        assert_eq!(
            connector.authorization_state(),
            AuthorizationState::Uninitialized,
            "l'interrogazione non deve aver mosso la macchina di autorizzazione"
        );
    }

    /// Regressione — completa `a_send_failure_on_the_wake_up_itself_fails_start_cleanly_without_corrupting_state`:
    /// dopo un risveglio fallito il client esiste già per davvero dentro TDLib
    /// (irreversibile), quindi `client_id` resta `Some` e un secondo `start()`
    /// resta rifiutato — ma nessun'altra operazione deve trattare questo
    /// connettore come pienamente operativo: `poll_event` deve restituire un
    /// errore tipizzato **distinto** sia da "client mai creato" sia dal
    /// generico "nessun aggiornamento ricevuto", invece di procedere in
    /// silenzio fino a `receive` su un client mai risvegliato.
    #[test]
    fn polling_after_a_failed_wake_up_returns_a_distinct_typed_error_instead_of_silently_receiving()
    {
        let backend = FakeTdJson::new();
        backend.failing_next_send(TelegramError::Tdlib {
            reason: String::from("invio non riuscito (prova)"),
        });
        let mut connector = LiveTdlibConnector::new(backend, String::from(FAKE_DATABASE_KEY));

        let Err(_) = connector.start(&fake_client_parameters()) else {
            panic!("l'avvio deve fallire: il risveglio non e' riuscito");
        };

        let Err(TelegramError::Tdlib { reason }) = connector.poll_event(Duration::from_millis(10))
        else {
            panic!(
                "un client creato ma mai risvegliato non deve procedere fino a \
                 receive: deve restituire un errore tipizzato"
            );
        };
        assert!(
            reason.contains("risveglio"),
            "il messaggio deve nominare il risveglio non confermato, non il client \
             mai creato ne' un generico 'nessun aggiornamento': {reason}"
        );
        assert!(
            !reason.contains("non risulta creato"),
            "questo errore non deve confondersi con quello del client mai creato: {reason}"
        );
    }

    /// Un guasto del backend **dopo** un avvio riuscito (client creato e
    /// risvegliato con successo) deve risalire come l'errore reale restituito
    /// dalla libreria, non come uno dei due messaggi "non avviato" appena
    /// introdotti: sono situazioni diverse e vanno tenute distinte.
    #[test]
    fn a_backend_failure_after_a_successful_start_is_reported_distinctly() {
        let backend = FakeTdJson::new().then_receive(Err(TelegramError::Tdlib {
            reason: String::from("guasto simulato del backend dopo l'avvio"),
        }));
        let mut connector = LiveTdlibConnector::new(backend, String::from(FAKE_DATABASE_KEY));
        let Ok(()) = connector.start(&fake_client_parameters()) else {
            panic!("l'avvio deve riuscire: sia il client sia il risveglio riescono");
        };

        let Err(TelegramError::Tdlib { reason }) = connector.poll_event(Duration::from_millis(10))
        else {
            panic!("il guasto del backend deve risalire come errore");
        };
        assert_eq!(reason, "guasto simulato del backend dopo l'avvio");
        assert!(!reason.contains("non risulta creato"));
        assert!(!reason.contains("risveglio"));
    }

    /// Ogni invio, dal risveglio di `start()` in poi (compreso quello dei
    /// parametri e quello del numero), deve usare lo stesso `client_id`
    /// restituito da `create_client_id()`: non ne esiste un secondo.
    #[test]
    fn every_send_after_start_uses_the_same_client_id() {
        let mut connector = connector_waiting_for_phone_number();
        let Ok(phone) = PhoneNumber::try_new(FAKE_PHONE) else {
            panic!("il numero di prova deve essere valido");
        };
        let Ok(()) = connector.submit_phone_number(&phone) else {
            panic!("l'invio del numero deve riuscire");
        };

        let ids = connector.library.sent_client_ids();
        assert!(
            ids.len() >= 3,
            "risveglio, parametri e numero devono aver inviato almeno tre richieste: {ids:?}"
        );
        let first = ids[0];
        assert!(
            ids.iter().all(|id| *id == first),
            "tutti gli invii devono usare lo stesso client_id: {ids:?}"
        );
    }

    /// L'arresto ordinato di un connettore **avviato** (a differenza di
    /// [`shutdown_moves_an_unstarted_connector_straight_to_closed`], che copre
    /// il caso mai avviato) deve terminare senza bloccarsi anche quando nessun
    /// aggiornamento di conferma arriva mai, e lasciare il connettore in uno
    /// stato da cui interrogarlo ulteriormente restituisce l'errore di
    /// chiusura, non un altro tentativo di ricezione.
    #[test]
    fn stopping_a_started_connector_before_any_update_closes_it_cleanly() {
        let backend = FakeTdJson::new();
        let mut connector = LiveTdlibConnector::new(backend, String::from(FAKE_DATABASE_KEY));
        let Ok(()) = connector.start(&fake_client_parameters()) else {
            panic!("l'avvio deve riuscire");
        };

        let Ok(()) = connector.shutdown() else {
            panic!("l'arresto deve riuscire anche senza conferma dalla libreria");
        };
        assert_eq!(connector.authorization_state(), AuthorizationState::Closed);

        let Err(TelegramError::Closed) = connector.poll_event(Duration::from_millis(10)) else {
            panic!("un connettore chiuso deve rifiutare il polling con l'errore di chiusura");
        };
    }

    #[test]
    fn the_eight_canonical_states_map_to_the_domain() {
        for (td_type, expected) in [
            (
                "authorizationStateWaitTdlibParameters",
                AuthorizationState::WaitingForTdlibParameters,
            ),
            (
                "authorizationStateWaitPhoneNumber",
                AuthorizationState::WaitingForPhoneNumber,
            ),
            (
                "authorizationStateWaitCode",
                AuthorizationState::WaitingForCode,
            ),
            (
                "authorizationStateWaitPassword",
                AuthorizationState::WaitingForPassword,
            ),
            ("authorizationStateReady", AuthorizationState::Ready),
            ("authorizationStateLoggingOut", AuthorizationState::Closing),
            ("authorizationStateClosing", AuthorizationState::Closing),
            ("authorizationStateClosed", AuthorizationState::Closed),
        ] {
            assert_eq!(map_authorization_state(td_type), Some(expected));
        }
    }

    #[test]
    fn unmapped_authorization_states_are_none_and_never_panic() {
        for td_type in [
            "authorizationStateWaitEmailAddress",
            "authorizationStateWaitEmailCode",
            "authorizationStateWaitRegistration",
            "authorizationStateWaitOtherDeviceConfirmation",
            "authorizationStateWaitPremiumPurchase",
            "authorizationStateSomethingBrandNew",
            "",
        ] {
            assert_eq!(map_authorization_state(td_type), None);
        }
    }

    #[test]
    fn an_unknown_update_is_ignored_and_counted_not_an_error() {
        // Uno `updateOption` non è pertinente al monitoraggio: va ignorato.
        let update = r#"{"@type":"updateOption","name":"my_id","value":{"@type":"optionValueInteger","value":"42"}}"#;
        assert_eq!(normalize_update(update, 0), Normalized::Ignored);
    }

    #[test]
    fn connection_states_map_to_the_domain() {
        assert_eq!(
            map_connection_state("connectionStateReady"),
            Some(ConnectionState::Online)
        );
        assert_eq!(
            map_connection_state("connectionStateUpdating"),
            Some(ConnectionState::Online)
        );
        assert_eq!(
            map_connection_state("connectionStateConnecting"),
            Some(ConnectionState::Connecting)
        );
        assert_eq!(
            map_connection_state("connectionStateWaitingForNetwork"),
            Some(ConnectionState::Interrupted)
        );
        assert_eq!(map_connection_state("connectionStateNonsense"), None);
    }

    #[test]
    fn the_parameters_carry_the_real_fields_of_the_version() {
        let request = build_tdlib_parameters(&sample_prepared());

        assert!(request.contains(r#""@type":"setTdlibParameters""#));
        assert!(request.contains(r#""device_model":"NEXUM/97""#));
        assert!(request.contains(r#""use_message_database":true"#));
        assert!(request.contains(r#""use_file_database":true"#));
        assert!(request.contains(r#""use_secret_chats":false"#));
        assert!(request.contains(r#""api_id":1234567"#));
        assert!(request.contains(r#""use_test_dc":false"#));
        // Il percorso di Windows deve risultare correttamente sfuggito.
        assert!(request.contains(r#"C:\\dati\\account\\tdlib"#));
    }

    #[test]
    fn the_parameters_carry_the_api_hash_but_the_struct_cannot_print_it() {
        let prepared = sample_prepared();
        let request = build_tdlib_parameters(&prepared);
        // L'hash deve essere nella richiesta: senza non si potrebbe accedere.
        assert!(request.contains(FAKE_HASH));

        // Ma non deve esistere modo di stamparlo per errore dalla struttura.
        let rendered = format!("{prepared:?}");
        assert!(!rendered.contains(FAKE_HASH));
        assert!(rendered.contains(REDACTED));
    }

    #[test]
    fn a_new_message_is_normalised_with_its_fields() {
        let update = concat!(
            r#"{"@type":"updateNewMessage","message":{"@type":"message","#,
            r#""id":1048576,"sender_id":{"@type":"messageSenderUser","user_id":42},"#,
            r#""chat_id":-1001234567890,"is_outgoing":false,"date":1700000000,"#,
            r#""content":{"@type":"messageText","text":{"@type":"formattedText","#,
            r#""text":"ciao mondo","entities":[]}}}}"#
        );

        let Normalized::Event(ConnectorEvent::MessageReceived(message)) =
            normalize_update(update, 999)
        else {
            panic!("un nuovo messaggio deve normalizzarsi in un evento di ricezione");
        };
        assert_eq!(message.chat_id.get(), -1_001_234_567_890);
        assert_eq!(message.message_id.get(), 1_048_576);
        assert_eq!(message.text, "ciao mondo");
        assert_eq!(message.published_at_millis, 1_700_000_000_000);
        assert_eq!(message.author, None);

        // NESSUN COLLEGAMENTO ALL'ACQUISIZIONE (LINK-01).
        //
        // Questa asserzione ha cambiato verso due volte, e ogni volta perche'
        // e' cambiato il comportamento: prima `None` perche' il collegamento
        // non esisteva, poi l'indirizzo COMPOSTO dai due identificativi, e ora
        // di nuovo `None` — perche' un indirizzo composto da noi e' una
        // deduzione, e nell'archivio finisce solo cio' che Telegram ha dato.
        // Quello ufficiale si chiede con `message_link`, al momento.
        assert_eq!(
            message.url.as_deref(),
            None,
            "l'archivio non conserva un collegamento che Telegram non ha fornito"
        );

        // L'identificativo si legge dall'aggiornamento, senza alcuna richiesta.
        assert_eq!(message.author_identifier.as_deref(), Some("42"));
    }

    #[test]
    fn a_connector_that_cannot_recover_history_says_so_instead_of_answering_nothing() {
        // Un elenco vuoto si leggerebbe come «non c'era nulla», che e'
        // un'affermazione diversa e falsa. E' il difetto silenzioso di questa
        // funzione, ed e' quello contro cui vale la pena avere un test.
        use crate::connector::TelegramConnector;

        struct Muto;
        impl TelegramConnector for Muto {
            fn start(&mut self, _: &crate::connector::ClientParameters) -> TelegramResult<()> {
                Ok(())
            }
            fn submit_phone_number(
                &mut self,
                _: &crate::secret::PhoneNumber,
            ) -> TelegramResult<()> {
                Ok(())
            }
            fn submit_code(&mut self, _: &crate::secret::LoginCode) -> TelegramResult<()> {
                Ok(())
            }
            fn submit_password(
                &mut self,
                _: &crate::secret::TwoFactorPassword,
            ) -> TelegramResult<()> {
                Ok(())
            }
            fn poll_event(&mut self, _: Duration) -> TelegramResult<Option<ConnectorEvent>> {
                Ok(None)
            }
            fn accessible_chats(&mut self) -> TelegramResult<Vec<crate::chat::AccessibleChat>> {
                Ok(Vec::new())
            }
            fn authorization_state(&self) -> AuthorizationState {
                AuthorizationState::Ready
            }
            fn connection_state(&self) -> crate::event::ConnectionState {
                crate::event::ConnectionState::Online
            }
            fn shutdown(&mut self) -> TelegramResult<()> {
                Ok(())
            }

            fn message_link(
                &mut self,
                _chat_id: crate::identifier::ChatId,
                _message_id: crate::identifier::MessageId,
            ) -> TelegramResult<crate::link::LinkOutcome> {
                Ok(crate::link::LinkOutcome::NotProvided(
                    crate::link::LinkGap::ConnectorUnavailable,
                ))
            }

            fn fetch_context(
                &mut self,
                _chat_id: crate::identifier::ChatId,
                _around: crate::identifier::MessageId,
                _before: u32,
                _after: u32,
            ) -> TelegramResult<Vec<crate::relation::ContextMessage>> {
                Ok(Vec::new())
            }
        }

        let Ok(chat) = crate::identifier::ChatId::try_new(-1_001_234_567_890) else {
            panic!("l'identificativo di prova deve essere valido");
        };
        let outcome = Muto.fetch_history(chat, 0, 50);
        assert!(
            outcome.is_err(),
            "l'assenza della capacita' va dichiarata, non tradotta in un elenco vuoto"
        );
    }

    /// Costruisce un connettore già autorizzato che consegna gli aggiornamenti
    /// indicati, e restituisce le chat accessibili che ne risultano.
    fn chats_after(updates: &[&str]) -> Vec<crate::chat::AccessibleChat> {
        // Le risposte portano l'`@extra` della richiesta a cui appartengono,
        // come fa TDLib: senza, passerebbero per aggiornamenti spontanei e la
        // prova attraverserebbe un percorso diverso da quello vero.
        const CHATS_MAIN: &str = r#"{"@type":"chats","@extra":"2","total_count":0,"chat_ids":[]}"#;
        const CHATS_ARCHIVE: &str =
            r#"{"@type":"chats","@extra":"4","total_count":0,"chat_ids":[]}"#;
        const READY: &str = concat!(
            r#"{"@type":"updateAuthorizationState","authorization_state":"#,
            r#"{"@type":"authorizationStateReady"}}"#
        );

        let mut backend = FakeTdJson::new()
            .then_receive(Ok(Some(String::from(WAIT_TDLIB_PARAMETERS_UPDATE))))
            .then_receive(Ok(Some(String::from(READY))));
        for update in updates {
            backend = backend.then_receive(Ok(Some(String::from(*update))));
        }
        // Una risposta per ciascuna delle due liste interrogate.
        backend = backend
            .then_receive(Ok(Some(String::from(CHATS_MAIN))))
            .then_receive(Ok(Some(String::from(CHATS_ARCHIVE))));

        let mut connector = LiveTdlibConnector::new(backend, String::from(FAKE_DATABASE_KEY));
        let Ok(()) = connector.start(&fake_client_parameters()) else {
            panic!("l'avvio deve riuscire");
        };
        for _ in 0..2 {
            let Ok(Some(_)) = connector.poll_event(Duration::from_millis(10)) else {
                panic!("gli aggiornamenti di autorizzazione devono arrivare");
            };
        }

        let Ok(chats) = connector.accessible_chats() else {
            panic!("la raccolta delle chat deve riuscire");
        };
        chats
    }

    #[test]
    fn the_source_username_arrives_whichever_update_comes_first() {
        // E' il motivo per cui i due registri sono separati e la fusione avviene
        // in lettura. Fonderli all'arrivo avrebbe fatto dipendere il risultato
        // da quale aggiornamento arriva primo — lo stesso difetto che il
        // 2026-07-30 aveva prodotto un elenco delle fonti monco.
        const CHAT: &str = concat!(
            r#"{"@type":"updateNewChat","chat":{"@type":"chat","id":-1001234567890,"#,
            r#""title":"Canale con username","#,
            r#""type":{"@type":"chatTypeSupergroup","supergroup_id":1234567890,"#,
            r#""is_channel":true}}}"#
        );
        const SUPERGROUP: &str = concat!(
            r#"{"@type":"updateSupergroup","supergroup":{"@type":"supergroup","#,
            r#""id":1234567890,"usernames":{"@type":"usernames","#,
            r#""active_usernames":["canale_uno"]},"is_channel":true}}"#
        );

        for (ordine, updates) in [
            ("chat prima", [CHAT, SUPERGROUP]),
            ("supergruppo prima", [SUPERGROUP, CHAT]),
        ] {
            let chats = chats_after(&updates);
            let Some(chat) = chats
                .iter()
                .find(|chat| chat.chat_id.get() == -1_001_234_567_890)
            else {
                panic!("la chat deve comparire fra le fonti ({ordine})");
            };
            assert_eq!(
                chat.username.as_deref(),
                Some("canale_uno"),
                "lo username deve esserci con l'ordine «{ordine}»"
            );
        }
    }

    #[test]
    fn a_source_that_never_announced_a_username_simply_has_none() {
        const CHAT: &str = concat!(
            r#"{"@type":"updateNewChat","chat":{"@type":"chat","id":-1002000000001,"#,
            r#""title":"Gruppo privato","#,
            r#""type":{"@type":"chatTypeSupergroup","supergroup_id":42,"#,
            r#""is_channel":false}}}"#
        );

        let chats = chats_after(&[CHAT]);
        let Some(chat) = chats
            .iter()
            .find(|chat| chat.chat_id.get() == -1_002_000_000_001)
        else {
            panic!("la chat deve comparire fra le fonti");
        };
        assert_eq!(chat.username, None);
    }

    #[test]
    fn a_supergroup_update_yields_its_username() {
        let update = concat!(
            r#"{"@type":"updateSupergroup","supergroup":{"@type":"supergroup","id":1234567890,"#,
            r#""usernames":{"@type":"usernames","active_usernames":["canale_uno"],"#,
            r#""disabled_usernames":[],"editable_username":"canale_uno"},"#,
            r#""is_channel":true}}"#
        );

        let Some((supergroup_id, username)) = super::parse_supergroup_username(update) else {
            panic!("l'aggiornamento deve produrre uno username");
        };
        assert_eq!(supergroup_id, 1_234_567_890);
        assert_eq!(username, "canale_uno");
    }

    #[test]
    fn a_private_supergroup_is_not_given_an_empty_username() {
        // Registrare una stringa vuota lo farebbe poi comparire con una
        // chiocciola e nulla dopo, che si legge come un dato corrotto invece
        // che come l'assenza normale di un gruppo privato.
        let update = concat!(
            r#"{"@type":"updateSupergroup","supergroup":{"@type":"supergroup","id":77,"#,
            r#""usernames":{"@type":"usernames","active_usernames":[]}}}"#
        );
        assert_eq!(super::parse_supergroup_username(update), None);

        // E un supergruppo senza affatto il campo `usernames`.
        let bare = r#"{"@type":"updateSupergroup","supergroup":{"@type":"supergroup","id":78}}"#;
        assert_eq!(super::parse_supergroup_username(bare), None);
    }

    #[test]
    fn the_bridge_between_a_chat_and_its_supergroup_is_read_from_the_chat_type() {
        let update = concat!(
            r#"{"@type":"updateNewChat","chat":{"@type":"chat","id":-1001234567890,"#,
            r#""type":{"@type":"chatTypeSupergroup","supergroup_id":1234567890,"#,
            r#""is_channel":true},"title":"Canale"}}"#
        );
        assert_eq!(super::parse_chat_supergroup_id(update), Some(1_234_567_890));

        // Un gruppo semplice non ha supergruppo: non c'e' ponte da costruire.
        let basic = concat!(
            r#"{"@type":"updateNewChat","chat":{"@type":"chat","id":-1002,"#,
            r#""type":{"@type":"chatTypeBasicGroup","basic_group_id":5},"title":"Gruppo"}}"#
        );
        assert_eq!(super::parse_chat_supergroup_id(basic), None);
    }

    #[test]
    fn an_update_user_yields_the_name_and_the_username() {
        let update = concat!(
            r#"{"@type":"updateUser","user":{"@type":"user","id":42,"#,
            r#""first_name":"Mario","last_name":"Rossi","#,
            r#""usernames":{"@type":"usernames","active_usernames":["mrossi","altro"],"#,
            r#""disabled_usernames":[],"editable_username":"mrossi"},"#,
            r#""type":{"@type":"userTypeRegular"}}}"#
        );

        let Some(known) = super::parse_known_user(update) else {
            panic!("l'aggiornamento deve produrre un utente");
        };
        assert_eq!(known.user_id, 42);
        assert_eq!(known.display_name.as_deref(), Some("Mario Rossi"));
        // Si prende il **primo** username attivo, che TDLib documenta come
        // quello principale: prenderne un altro darebbe un valore che non
        // corrisponde a cio' che si vede in Telegram.
        assert_eq!(known.username.as_deref(), Some("mrossi"));
    }

    #[test]
    fn a_user_without_a_username_is_not_invented_one() {
        // La maggior parte degli utenti non ha uno username, e l'assenza non e'
        // un difetto di acquisizione: inventarne uno sarebbe molto peggio.
        let update = concat!(
            r#"{"@type":"updateUser","user":{"@type":"user","id":7,"#,
            r#""first_name":"Anna","last_name":"","#,
            r#""usernames":{"@type":"usernames","active_usernames":[]}}}"#
        );

        let Some(known) = super::parse_known_user(update) else {
            panic!("l'aggiornamento deve produrre un utente");
        };
        assert_eq!(known.display_name.as_deref(), Some("Anna"));
        assert_eq!(known.username, None);
    }

    #[test]
    fn a_user_without_any_name_stays_without_one() {
        let update = concat!(
            r#"{"@type":"updateUser","user":{"@type":"user","id":9,"#,
            r#""first_name":"","last_name":""}}"#
        );

        let Some(known) = super::parse_known_user(update) else {
            panic!("l'aggiornamento deve produrre un utente");
        };
        assert_eq!(known.display_name, None);
        assert_eq!(known.username, None);
    }

    #[test]
    fn a_history_page_becomes_the_messages_it_carries() {
        let json = concat!(
            r#"{"@type":"messages","total_count":2,"messages":["#,
            r#"{"@type":"message","id":2097152,"chat_id":-1001234567890,"date":1700000100,"#,
            r#""sender_id":{"@type":"messageSenderUser","user_id":42},"#,
            r#""content":{"@type":"messageText","text":{"@type":"formattedText","#,
            r#""text":"secondo","entities":[]}}},"#,
            r#"{"@type":"message","id":1048576,"chat_id":-1001234567890,"date":1700000000,"#,
            r#""sender_id":{"@type":"messageSenderChat","chat_id":-1001234567890},"#,
            r#""content":{"@type":"messageText","text":{"@type":"formattedText","#,
            r#""text":"primo","entities":[]}}}"#,
            r#"]}"#
        );

        let messages = super::parse_history_page(json, 999);
        assert_eq!(messages.len(), 2);

        // L'ordine e' quello della risposta - dal piu' recente - e non viene
        // invertito qui: riordinare in silenzio nasconderebbe qual e' l'ordine
        // vero a chi lo consuma.
        assert_eq!(messages[0].text, "secondo");
        assert_eq!(messages[1].text, "primo");

        // Un messaggio recuperato porta esattamente cio' che porterebbe lo
        // stesso messaggio osservato dal vivo: stessa traduzione, una sola.
        assert_eq!(messages[0].author_identifier.as_deref(), Some("42"));
        // Come dal vivo: nessun collegamento composto finisce nell'archivio
        // (LINK-01). La stessa traduzione, una sola, e la stessa regola.
        assert_eq!(messages[0].url.as_deref(), None);
        assert_eq!(messages[0].published_at_millis, 1_700_000_100_000);

        // Il messaggio di canale resta senza autore individuale anche quando
        // arriva dalla cronologia.
        assert_eq!(messages[1].author_identifier, None);
    }

    #[test]
    fn one_unreadable_message_does_not_lose_the_whole_page() {
        // Perderne novantanove per uno trasformerebbe un difetto minore in un
        // buco nell'archivio.
        let json = concat!(
            r#"{"@type":"messages","messages":["#,
            r#"{"@type":"message","chat_id":-1001234567890},"#,
            r#"{"@type":"message","id":1048576,"chat_id":-1001234567890,"date":1700000000,"#,
            r#""content":{"@type":"messageText","text":{"@type":"formattedText","#,
            r#""text":"buono","entities":[]}}}"#,
            r#"]}"#
        );

        let messages = super::parse_history_page(json, 5);
        assert_eq!(messages.len(), 1, "il messaggio leggibile arriva comunque");
        assert_eq!(messages[0].text, "buono");
    }

    #[test]
    fn an_empty_history_page_is_not_a_failure() {
        let messages = super::parse_history_page(r#"{"@type":"messages","messages":[]}"#, 5);
        assert!(messages.is_empty());
    }

    /// **Un messaggio pubblicato «come chat» resta della chat in cui sta**
    /// (FINAL-REVIEW-01, FR-002).
    ///
    /// Nell'ordine dello schema TL `sender_id` precede `chat_id`, e un mittente
    /// di tipo chat porta un suo `chat_id`: nel gruppo di discussione di un
    /// canale, i messaggi inoltrati automaticamente dal canale finivano
    /// archiviati sotto il canale.
    #[test]
    fn a_message_sent_as_a_chat_belongs_to_the_chat_it_is_in() {
        let json = concat!(
            r#"{"@type":"updateNewMessage","message":{"@type":"message","id":2097152,"#,
            r#""sender_id":{"@type":"messageSenderChat","chat_id":-1001111111111},"#,
            r#""chat_id":-1002222222222,"date":1700000000,"#,
            r#""content":{"@type":"messageText","text":{"@type":"formattedText","#,
            r#""text":"dal canale collegato","entities":[]}}}}"#
        );
        let super::Normalized::Event(ConnectorEvent::MessageReceived(message)) =
            super::normalize_update(json, 5)
        else {
            panic!("il messaggio deve essere letto");
        };
        assert_eq!(
            message.chat_id.get(),
            -1_002_222_222_222,
            "la chat del messaggio"
        );
        assert_eq!(message.text, "dal canale collegato");
    }

    /// **Il testo è quello del contenuto del messaggio, e di nessun altro.**
    ///
    /// `reply_to` precede `content` e, per una risposta a un messaggio di
    /// un'altra chat, porta il contenuto di quello; un adesivo non ha testo, e
    /// la ricerca proseguiva fino all'etichetta di un pulsante.
    #[test]
    fn the_text_is_the_message_content_and_nothing_else() {
        let risposta = concat!(
            r#"{"@type":"message","id":2097152,"chat_id":-1002222222222,"date":1700000000,"#,
            r#""reply_to":{"@type":"messageReplyToMessage","chat_id":-1003333333333,"#,
            r#""message_id":1048576,"content":{"@type":"messageText","text":{"#,
            r#""@type":"formattedText","text":"testo di un'altra chat","entities":[]}}},"#,
            r#""content":{"@type":"messageText","text":{"@type":"formattedText","#,
            r#""text":"la risposta","entities":[]}}}"#
        );
        let Some(letto) = super::parse_message(risposta, 5) else {
            panic!("la risposta deve essere letta");
        };
        assert_eq!(letto.text, "la risposta");

        let adesivo = concat!(
            r#"{"@type":"message","id":2097152,"chat_id":-1002222222222,"date":1700000000,"#,
            r#""content":{"@type":"messageSticker","sticker":{"@type":"sticker","emoji":"x"}},"#,
            r#""reply_markup":{"@type":"replyMarkupInlineKeyboard","rows":[[{"#,
            r#""@type":"inlineKeyboardButton","text":"Premi qui"}]]}}"#
        );
        let Some(letto) = super::parse_message(adesivo, 5) else {
            panic!("l'adesivo deve essere letto");
        };
        assert_eq!(letto.text, "", "un adesivo non ha testo");
    }

    /// La lettura a primo livello non si fa ingannare da stringhe e annidamenti.
    #[test]
    fn a_top_level_key_is_found_only_at_the_top_level() {
        let json = r#"{"a":{"chat_id":1},"note":"\"chat_id\":2","chat_id":3,"z":[{"chat_id":4}]}"#;
        assert_eq!(super::top_level_number(json, "chat_id"), Some(3));
        assert_eq!(super::top_level_value(json, "a"), Some(r#"{"chat_id":1}"#));
        assert_eq!(super::top_level_value(json, "assente"), None);
        // Troncato: non si indovina.
        assert_eq!(
            super::top_level_value(r#"{"a":{"chat_id":1"#, "chat_id"),
            None
        );
        assert_eq!(
            super::top_level_number(r#"{"chat_id":"12"}"#, "chat_id"),
            None
        );
    }

    /// Il contorno di un messaggio, nella forma recente di TDLib.
    const CONTORNO_RECENTE: &str = concat!(
        r#"{"@type":"messages","total_count":2,"messages":["#,
        r#"{"@type":"message","id":2097152,"chat_id":-1001234567890,"date":1700000100,"#,
        r#""reply_to":{"@type":"messageReplyToMessage","chat_id":-1001234567890,"#,
        r#""message_id":1048576},"#,
        r#""message_thread_id":1048576,"edit_date":1700000200,"#,
        r#""sender_id":{"@type":"messageSenderUser","user_id":42},"#,
        r#""content":{"@type":"messageText","text":{"@type":"formattedText","#,
        r#""text":"secondo","entities":[]}}},"#,
        r#"{"@type":"message","id":1048576,"chat_id":-1001234567890,"date":1700000000,"#,
        r#""forward_info":{"@type":"messageForwardInfo","origin":{"#,
        r#""@type":"messageOriginChannel","chat_id":-1009999999999,"message_id":3145728},"#,
        r#""date":1699000000},"#,
        r#""sender_id":{"@type":"messageSenderChat","chat_id":-1001234567890},"#,
        r#""content":{"@type":"messageText","text":{"@type":"formattedText","#,
        r#""text":"primo","entities":[]}}}"#,
        r#"]}"#
    );

    /// **Le relazioni che Telegram dichiara si leggono tutte.**
    #[test]
    fn il_contorno_porta_le_relazioni_dichiarate() {
        let letti = super::parse_context_page(CONTORNO_RECENTE, 999);
        assert_eq!(letti.len(), 2);

        // Il primo: risposta, discussione e modifica.
        let Some(risposta) = letti[0].relations.reply_to else {
            panic!("la risposta deve essere letta");
        };
        assert_eq!(risposta.message_id().get(), 1_048_576);
        assert_eq!(
            risposta.other_conversation(),
            None,
            "la stessa conversazione non e' un'altra conversazione"
        );
        let Some(discussione) = letti[0].relations.thread else {
            panic!("la discussione deve essere letta");
        };
        assert_eq!(discussione.identifier(), 1_048_576);
        assert_eq!(
            letti[0].relations.edited_at.map(Timestamp::as_millis),
            Some(1_700_000_200_000)
        );

        // Il secondo: un inoltro da un canale, con l'istante dell'originale.
        let Some(inoltro) = letti[1].relations.forwarded.as_ref() else {
            panic!("l'inoltro deve essere letto");
        };
        assert_eq!(
            inoltro.origin(),
            Some(&ForwardOrigin::Channel {
                chat_id: {
                    let Ok(chat) = ChatId::try_new(-1_009_999_999_999) else {
                        panic!("l'identificativo deve essere valido");
                    };
                    chat
                },
                message_id: {
                    let Ok(messaggio) = MessageId::try_new(3_145_728) else {
                        panic!("l'identificativo deve essere valido");
                    };
                    Some(messaggio)
                },
            })
        );
        // L'istante e' quello DELL'INOLTRO, non quello del messaggio che lo
        // contiene: sono a poche righe di distanza nello stesso JSON.
        assert_eq!(
            inoltro.published_at().map(Timestamp::as_millis),
            Some(1_699_000_000_000),
            "l'istante dell'originale non e' quello del messaggio che lo porta"
        );
        assert_eq!(letti[1].message.published_at_millis, 1_700_000_000_000);
    }

    /// **Un messaggio senza relazioni non ne acquista nessuna.**
    #[test]
    fn un_messaggio_senza_relazioni_non_ne_acquista() {
        let json = concat!(
            r#"{"@type":"messages","messages":["#,
            r#"{"@type":"message","id":1048576,"chat_id":-1001234567890,"date":1700000000,"#,
            r#""edit_date":0,"message_thread_id":0,"#,
            r#""content":{"@type":"messageText","text":{"@type":"formattedText","#,
            r#""text":"solo","entities":[]}}}"#,
            r#"]}"#
        );

        let letti = super::parse_context_page(json, 5);
        assert_eq!(letti.len(), 1);
        assert!(
            letti[0].relations.is_empty(),
            "uno zero significa «nessuna», non «il 1\u{b0} gennaio 1970» \u{2014} {:?}",
            letti[0].relations
        );
    }

    /// **La forma precedente di TDLib si legge come quella recente.**
    ///
    /// La versione della libreria non e' verificabile senza eseguirla
    /// (ADR-0008), e leggere due forme che Telegram ha realmente prodotto non
    /// e' indovinare.
    #[test]
    fn la_forma_precedente_della_risposta_si_legge_lo_stesso() {
        let json = concat!(
            r#"{"@type":"messages","messages":["#,
            r#"{"@type":"message","id":2097152,"chat_id":-1001234567890,"date":1700000100,"#,
            r#""reply_to_message_id":1048576,"reply_in_chat_id":0,"#,
            r#""forward_info":{"@type":"messageForwardInfo","origin":{"#,
            r#""@type":"messageForwardOriginUser","sender_user_id":77}},"#,
            r#""content":{"@type":"messageText","text":{"@type":"formattedText","#,
            r#""text":"vecchio","entities":[]}}}"#,
            r#"]}"#
        );

        let letti = super::parse_context_page(json, 5);
        let Some(risposta) = letti[0].relations.reply_to else {
            panic!("la risposta deve essere letta anche nella forma precedente");
        };
        assert_eq!(risposta.message_id().get(), 1_048_576);
        assert_eq!(risposta.other_conversation(), None);

        let Some(inoltro) = letti[0].relations.forwarded.as_ref() else {
            panic!("l'inoltro deve essere letto anche nella forma precedente");
        };
        assert_eq!(
            inoltro.origin().and_then(ForwardOrigin::person_identifier),
            Some("77")
        );
    }

    /// **Chi ha scelto di non mostrarsi non riceve un identificativo.**
    #[test]
    fn un_mittente_nascosto_resta_nascosto_anche_qui() {
        let json = concat!(
            r#"{"@type":"messages","messages":["#,
            r#"{"@type":"message","id":1048576,"chat_id":-1001234567890,"date":1700000000,"#,
            r#""forward_info":{"@type":"messageForwardInfo","origin":{"#,
            r#""@type":"messageOriginHiddenUser","sender_name":"Un amico"}},"#,
            r#""content":{"@type":"messageText","text":{"@type":"formattedText","#,
            r#""text":"x","entities":[]}}}"#,
            r#"]}"#
        );

        let letti = super::parse_context_page(json, 5);
        let Some(inoltro) = letti[0].relations.forwarded.as_ref() else {
            panic!("l'inoltro deve essere letto");
        };
        let Some(origine) = inoltro.origin() else {
            panic!("l'origine deve essere letta");
        };
        assert_eq!(origine.person_identifier(), None);
        assert_eq!(origine.conversation(), None);
    }

    /// **Un'origine in una forma sconosciuta non viene indovinata.**
    ///
    /// L'inoltro resta — Telegram lo ha dichiarato — ma da dove non si sa, e
    /// la frase lo dice invece di riempire il vuoto.
    #[test]
    fn un_origine_sconosciuta_non_si_indovina() {
        let json = concat!(
            r#"{"@type":"messages","messages":["#,
            r#"{"@type":"message","id":1048576,"chat_id":-1001234567890,"date":1700000000,"#,
            r#""forward_info":{"@type":"messageForwardInfo","origin":{"#,
            r#""@type":"messageOriginQualcosaDiNuovo","sender_user_id":99}},"#,
            r#""content":{"@type":"messageText","text":{"@type":"formattedText","#,
            r#""text":"x","entities":[]}}}"#,
            r#"]}"#
        );

        let letti = super::parse_context_page(json, 5);
        let Some(inoltro) = letti[0].relations.forwarded.as_ref() else {
            panic!("l'inoltro deve restare: Telegram lo ha dichiarato");
        };
        assert_eq!(inoltro.origin(), None);
    }

    /// **Una risposta che esce dalla conversazione viene riconosciuta.**
    #[test]
    fn una_risposta_a_un_altra_conversazione_si_riconosce() {
        let json = concat!(
            r#"{"@type":"messages","messages":["#,
            r#"{"@type":"message","id":2097152,"chat_id":-1001234567890,"date":1700000100,"#,
            r#""reply_to":{"@type":"messageReplyToMessage","chat_id":-1005555555555,"#,
            r#""message_id":1048576},"#,
            r#""content":{"@type":"messageText","text":{"@type":"formattedText","#,
            r#""text":"altrove","entities":[]}}}"#,
            r#"]}"#
        );

        let letti = super::parse_context_page(json, 5);
        let Some(risposta) = letti[0].relations.reply_to else {
            panic!("la risposta deve essere letta");
        };
        let Some(altra) = risposta.other_conversation() else {
            panic!("l'altra conversazione deve essere riconosciuta");
        };
        assert_eq!(altra.get(), -1_005_555_555_555);
    }

    /// **Una risposta a qualcosa che non è un messaggio non diventa una
    /// risposta a un messaggio.**
    ///
    /// TDLib sa rappresentare anche la risposta a una storia. Quella non sta in
    /// questo contorno, e trattarla come un messaggio manderebbe chi legge a
    /// cercare una riga che non c'è.
    #[test]
    fn una_risposta_a_una_storia_non_e_una_risposta_a_un_messaggio() {
        let json = concat!(
            r#"{"@type":"messages","messages":["#,
            r#"{"@type":"message","id":2097152,"chat_id":-1001234567890,"date":1700000100,"#,
            r#""reply_to":{"@type":"messageReplyToStory","story_sender_chat_id":-100777,"#,
            r#""story_id":5},"#,
            r#""content":{"@type":"messageText","text":{"@type":"formattedText","#,
            r#""text":"storia","entities":[]}}}"#,
            r#"]}"#
        );

        let letti = super::parse_context_page(json, 5);
        assert_eq!(letti[0].relations.reply_to, None);
    }

    /// **Il contorno e l'acquisizione restano due funzioni.**
    ///
    /// La stessa pagina, letta dalle due, deve dare gli stessi messaggi: le
    /// relazioni si aggiungono, non sostituiscono.
    #[test]
    fn il_contorno_porta_gli_stessi_messaggi_dell_acquisizione() {
        let acquisiti = super::parse_history_page(CONTORNO_RECENTE, 999);
        let contorno = super::parse_context_page(CONTORNO_RECENTE, 999);

        assert_eq!(acquisiti.len(), contorno.len());
        for (acquisito, letto) in acquisiti.iter().zip(contorno.iter()) {
            assert_eq!(*acquisito, letto.message);
        }
    }

    #[test]
    fn a_response_with_several_messages_is_split_into_its_objects() {
        let json = concat!(
            r#"{"@type":"messages","total_count":2,"messages":["#,
            r#"{"@type":"message","id":1048576,"chat_id":-1001},"#,
            r#"{"@type":"message","id":2097152,"chat_id":-1001}"#,
            r#"]}"#
        );

        let objects = super::split_object_array(json, "messages");
        assert_eq!(objects.len(), 2);
        assert!(objects[0].contains("1048576"));
        assert!(objects[1].contains("2097152"));
    }

    #[test]
    fn braces_written_by_someone_else_do_not_break_the_split() {
        // E' il caso che un conteggio ingenuo di graffe sbaglia, e non e' un
        // caso di laboratorio: basta che qualcuno scriva una parentesi graffa
        // in un messaggio. Il testo acquisito non deve poter decidere dove
        // finisce un oggetto.
        let json = concat!(
            r#"{"@type":"messages","messages":["#,
            r#"{"@type":"message","id":1048576,"text":"}}} ][ {{{ \" }"},"#,
            r#"{"@type":"message","id":2097152,"text":"normale"}"#,
            r#"]}"#
        );

        let objects = super::split_object_array(json, "messages");
        assert_eq!(
            objects.len(),
            2,
            "le graffe dentro una stringa non chiudono un oggetto"
        );
        assert!(objects[0].contains("1048576"));
        assert!(objects[1].contains("2097152"));
    }

    #[test]
    fn a_nested_object_does_not_end_the_element_that_contains_it() {
        let json = concat!(
            r#"{"@type":"messages","messages":["#,
            r#"{"@type":"message","id":1048576,"content":{"@type":"messageText","#,
            r#""text":{"@type":"formattedText","text":"ciao","entities":[]}}}"#,
            r#"]}"#
        );

        let objects = super::split_object_array(json, "messages");
        assert_eq!(objects.len(), 1);
        assert!(objects[0].contains("formattedText"));
        assert!(
            objects[0].ends_with("}}}"),
            "l'elemento deve comprendere i propri annidamenti"
        );
    }

    #[test]
    fn an_empty_absent_or_truncated_array_yields_nothing() {
        assert!(super::split_object_array(r#"{"messages":[]}"#, "messages").is_empty());
        assert!(super::split_object_array(r#"{"altro":[{"a":1}]}"#, "messages").is_empty());
        // Non un array.
        assert!(super::split_object_array(r#"{"messages":42}"#, "messages").is_empty());
        // Troncata: mezza risposta non e' mezza verita', e' una risposta di cui
        // non si conosce la fine.
        assert!(
            super::split_object_array(r#"{"messages":[{"a":1},{"b":2}"#, "messages").is_empty(),
            "un array non chiuso non produce elementi"
        );
    }

    #[test]
    fn the_split_stops_at_the_end_of_its_own_array() {
        // Cio' che segue l'array appartiene a un altro campo e non deve
        // finire fra gli elementi.
        let json = concat!(
            r#"{"@type":"messages","messages":[{"id":1}],"#,
            r#""altro":[{"id":999}]}"#
        );
        let objects = super::split_object_array(json, "messages");
        assert_eq!(objects.len(), 1);
        assert!(objects[0].contains("\"id\":1"));
        assert!(!objects[0].contains("999"));
    }

    #[test]
    fn a_channel_message_gets_no_individual_author() {
        // Un canale pubblica a nome proprio: il mittente e' il canale. Il
        // `chat_id` che quell'oggetto porta **non** deve finire nel campo
        // dell'autore, perche' sarebbe una falsa attribuzione a una persona.
        //
        // Il contenuto e' di proposito un `messageChatDeleteMember`, che porta
        // una chiave `user_id` **dopo** il mittente. La lettura del JSON
        // procede per scansione: senza la guardia sul tipo prenderebbe quel
        // numero e attribuirebbe il messaggio del canale a un utente che non
        // l'ha scritto. Con un contenuto testuale il test passerebbe anche a
        // guardia rimossa, cioe' non proverebbe nulla.
        let update = concat!(
            r#"{"@type":"updateNewMessage","message":{"@type":"message","#,
            r#""id":1048576,"sender_id":{"@type":"messageSenderChat","chat_id":-1001234567890},"#,
            r#""chat_id":-1001234567890,"date":1700000000,"#,
            r#""content":{"@type":"messageChatDeleteMember","user_id":777}}}"#
        );

        let Normalized::Event(ConnectorEvent::MessageReceived(message)) =
            normalize_update(update, 999)
        else {
            panic!("anche un messaggio di canale deve normalizzarsi");
        };
        assert_eq!(message.author_identifier, None);
        // Assente, non vuoto: chi rilegge deve distinguere «nessun autore
        // individuale» da «autore con identificativo vuoto».
        assert!(message.author_identifier.is_none());
    }

    #[test]
    fn a_message_without_a_sender_gets_no_author() {
        let update = concat!(
            r#"{"@type":"updateNewMessage","message":{"@type":"message","#,
            r#""id":2097152,"chat_id":-1009999,"date":1700000100,"#,
            r#""content":{"@type":"messagePhoto","photo":{"@type":"photo","id":"7"}}}}"#
        );

        let Normalized::Event(ConnectorEvent::MessageReceived(message)) =
            normalize_update(update, 5)
        else {
            panic!("il messaggio deve normalizzarsi comunque");
        };
        assert_eq!(message.author_identifier, None);
    }

    #[test]
    fn a_media_message_without_text_normalises_to_an_empty_text() {
        let update = concat!(
            r#"{"@type":"updateNewMessage","message":{"@type":"message","#,
            r#""id":2097152,"chat_id":-1009999,"date":1700000100,"#,
            r#""content":{"@type":"messagePhoto","photo":{"@type":"photo","id":"7"}}}}"#
        );

        let Normalized::Event(ConnectorEvent::MessageReceived(message)) =
            normalize_update(update, 5)
        else {
            panic!("anche un media senza testo deve essere un evento di ricezione");
        };
        assert_eq!(message.message_id.get(), 2_097_152);
        assert!(message.text.is_empty());
    }

    /// **Un allegato si descrive e non si scarica** (ATTACH-01, ADR-0177): il
    /// genere, il nome dichiarato ripulito dai caratteri che invertono la
    /// scrittura, la dimensione e il tipo dichiarati.
    #[test]
    fn un_allegato_si_descrive_e_non_si_scarica() {
        let update = concat!(
            r#"{"@type":"updateNewMessage","message":{"@type":"message","#,
            r#""id":2097152,"chat_id":-1009999,"date":1700000100,"#,
            r#""content":{"@type":"messageDocument","document":{"@type":"document","#,
            r#""file_name":"fattura\u202efdp.exe","mime_type":"Application/X-MSDownload","#,
            r#""thumbnail":{"@type":"thumbnail","file":{"@type":"file","id":3,"size":900}},"#,
            r#""document":{"@type":"file","id":4,"size":0,"expected_size":73728}},"#,
            r#""caption":{"@type":"formattedText","text":"guarda qui","entities":[]}}}}"#
        );
        let Normalized::Event(ConnectorEvent::MessageReceived(message)) =
            normalize_update(update, 5)
        else {
            panic!("il messaggio deve normalizzarsi");
        };
        assert_eq!(message.text, "guarda qui");
        let Some(allegato) = message.attachment else {
            panic!("il documento deve avere la sua descrizione");
        };
        assert_eq!(allegato.kind, AttachmentKind::Document);
        assert_eq!(allegato.declared_name.as_deref(), Some("fatturafdp.exe"));
        assert_eq!(allegato.declared_size, Some(73_728));
        assert_eq!(
            allegato.declared_mime.as_deref(),
            Some("application/x-msdownload")
        );
    }

    /// **Una foto dichiara la sua misura più grande; un genere che non si
    /// riconosce non ha descrizione; un testo non ha allegato.**
    #[test]
    fn i_generi_degli_allegati_si_riconoscono_o_si_tacciono() {
        let foto = concat!(
            r#"{"@type":"messagePhoto","photo":{"@type":"photo","sizes":["#,
            r#"{"@type":"photoSize","type":"s","photo":{"@type":"file","id":1,"size":1200}},"#,
            r#"{"@type":"photoSize","type":"y","photo":{"@type":"file","id":2,"size":245000}},"#,
            r#"{"@type":"photoSize","type":"m","photo":{"@type":"file","id":3,"size":9000}}"#,
            r#"]},"caption":{"@type":"formattedText","text":""}}"#
        );
        let Some(descrizione) = parse_attachment(foto) else {
            panic!("la foto deve avere la sua descrizione");
        };
        assert_eq!(descrizione.kind, AttachmentKind::Photo);
        assert_eq!(descrizione.declared_size, Some(245_000));
        assert_eq!(descrizione.declared_name, None);

        let vocale = concat!(
            r#"{"@type":"messageVoiceNote","voice_note":{"@type":"voiceNote","duration":3,"#,
            r#""mime_type":"audio/ogg","voice":{"@type":"file","id":9,"size":4096}}}"#
        );
        assert_eq!(
            parse_attachment(vocale),
            Some(AttachmentDescriptor {
                kind: AttachmentKind::VoiceNote,
                declared_name: None,
                declared_size: Some(4_096),
                declared_mime: Some(String::from("audio/ogg")),
            })
        );

        assert_eq!(
            parse_attachment(r#"{"@type":"messageSticker"}"#),
            Some(AttachmentDescriptor::of_kind(AttachmentKind::Sticker))
        );
        assert_eq!(
            parse_attachment(r#"{"@type":"messagePoll","poll":{"@type":"poll","id":"1"}}"#),
            None
        );
        assert_eq!(
            parse_attachment(
                r#"{"@type":"messageText","text":{"@type":"formattedText","text":"ciao"}}"#
            ),
            None
        );
    }

    #[test]
    fn a_permanent_deletion_is_normalised_with_its_identifiers() {
        let update = concat!(
            r#"{"@type":"updateDeleteMessages","chat_id":-1001234567890,"#,
            r#""message_ids":[1048576,2097152],"is_permanent":true,"from_cache":false}"#
        );

        let Normalized::Event(ConnectorEvent::MessagesDeleted(deletion)) =
            normalize_update(update, 111)
        else {
            panic!("una cancellazione permanente deve normalizzarsi in un evento");
        };
        assert_eq!(deletion.chat_id.get(), -1_001_234_567_890);
        assert_eq!(deletion.message_ids.len(), 2);
        assert_eq!(deletion.message_ids[0].get(), 1_048_576);
        assert_eq!(deletion.deleted_at_millis, 111);
    }

    #[test]
    fn a_cache_only_deletion_is_ignored_to_avoid_falsifying_the_history() {
        let update = concat!(
            r#"{"@type":"updateDeleteMessages","chat_id":-1009999,"#,
            r#""message_ids":[5],"is_permanent":false,"from_cache":true}"#
        );
        assert_eq!(normalize_update(update, 0), Normalized::Ignored);
    }

    #[test]
    fn an_edited_message_carries_the_edit_instant_even_without_new_text() {
        let update = concat!(
            r#"{"@type":"updateMessageEdited","chat_id":-1009999,"#,
            r#""message_id":1048576,"edit_date":1700000200}"#
        );

        let Normalized::Event(ConnectorEvent::MessageEdited(edit)) = normalize_update(update, 7)
        else {
            panic!("una modifica deve normalizzarsi in un evento di modifica");
        };
        assert_eq!(edit.message_id.get(), 1_048_576);
        assert_eq!(edit.edited_at_millis, 1_700_000_200_000);
        assert!(edit.text.is_empty());
    }

    #[test]
    fn a_content_change_carries_the_new_text_with_the_reception_instant() {
        let update = concat!(
            r#"{"@type":"updateMessageContent","chat_id":-1009999,"message_id":1048576,"#,
            r#""new_content":{"@type":"messageText","text":{"@type":"formattedText","#,
            r#""text":"testo corretto"}}}"#
        );

        let Normalized::Event(ConnectorEvent::MessageEdited(edit)) = normalize_update(update, 42)
        else {
            panic!("un cambio di contenuto deve normalizzarsi in una modifica");
        };
        assert_eq!(edit.text, "testo corretto");
        assert_eq!(edit.edited_at_millis, 42);
    }

    #[test]
    fn a_connection_update_maps_to_a_connection_event() {
        let update =
            r#"{"@type":"updateConnectionState","state":{"@type":"connectionStateReady"}}"#;
        assert_eq!(
            normalize_update(update, 0),
            Normalized::Event(ConnectorEvent::Connection(ConnectionState::Online))
        );
    }

    #[test]
    fn tdlib_errors_map_to_typed_domain_errors() {
        assert_eq!(
            classify_tdlib_error("PHONE_CODE_INVALID", 400),
            TelegramError::CodeRejected
        );
        assert_eq!(
            classify_tdlib_error("PASSWORD_HASH_INVALID", 400),
            TelegramError::PasswordRejected
        );
        assert_eq!(
            classify_tdlib_error("SESSION_REVOKED", 401),
            TelegramError::SessionRevoked
        );
        assert!(matches!(
            classify_tdlib_error("FLOOD_WAIT_30", 420),
            TelegramError::Tdlib { .. }
        ));
    }

    #[test]
    fn an_error_update_becomes_a_failure_event() {
        let update = r#"{"@type":"error","code":400,"message":"PHONE_CODE_INVALID"}"#;
        assert_eq!(
            normalize_update(update, 0),
            Normalized::Event(ConnectorEvent::Failure(TelegramError::CodeRejected))
        );
    }

    #[test]
    fn the_nested_type_is_extracted_from_an_authorization_update() {
        let update = concat!(
            r#"{"@type":"updateAuthorizationState","authorization_state":"#,
            r#"{"@type":"authorizationStateWaitCode","code_info":{}}}"#
        );
        assert_eq!(
            nested_type(update, "authorization_state").as_deref(),
            Some("authorizationStateWaitCode")
        );
    }

    #[test]
    fn a_number_is_read_without_confusing_similar_keys() {
        let json = r#"{"chat_id":-100,"id":55,"message_id":77}"#;
        assert_eq!(json_number_value(json, "chat_id"), Some(-100));
        assert_eq!(json_number_value(json, "id"), Some(55));
        assert_eq!(json_number_value(json, "message_id"), Some(77));
        assert_eq!(json_number_value(json, "absent"), None);
    }

    #[test]
    fn a_boolean_is_read_or_reported_absent() {
        let json = r#"{"is_permanent":true,"from_cache":false}"#;
        assert_eq!(json_bool_value(json, "is_permanent"), Some(true));
        assert_eq!(json_bool_value(json, "from_cache"), Some(false));
        assert_eq!(json_bool_value(json, "missing"), None);
    }

    #[test]
    fn message_identifiers_are_parsed_and_the_invalid_ones_dropped() {
        let json = r#"{"message_ids":[10, 20, 0, -5, 30]}"#;
        let ids = parse_message_ids(json);
        // Zero e i negativi non sono identificativi validi e vengono scartati.
        assert_eq!(
            ids.iter().map(|id| id.get()).collect::<Vec<_>>(),
            vec![10, 20, 30]
        );
    }

    #[test]
    fn json_escaping_makes_a_windows_path_safe() {
        assert_eq!(json_escape(r"C:\dati"), r"C:\\dati");
        assert_eq!(json_escape("virgoletta\""), "virgoletta\\\"");
        assert_eq!(json_escape("a\tb"), "a\\tb");
    }

    #[test]
    fn a_channel_and_a_supergroup_are_distinguished_by_the_is_channel_flag() {
        let channel = parse_accessible_chat(concat!(
            r#"{"@type":"updateNewChat","chat":{"@type":"chat","id":-1001234567890,"#,
            r#""type":{"@type":"chatTypeSupergroup","supergroup_id":123,"is_channel":true},"#,
            r#""title":"Canale di prova"}}"#
        ));
        let Some(channel) = channel else {
            panic!("un canale deve essere riconosciuto come chat accessibile");
        };
        assert_eq!(channel.chat_id.get(), -1_001_234_567_890);
        assert_eq!(channel.title, "Canale di prova");
        assert_eq!(channel.kind, ChatKind::Channel);
        assert!(channel.can_read_history);

        let supergroup = classify_chat_kind(
            r#"{"@type":"chatTypeSupergroup","supergroup_id":9,"is_channel":false}"#,
        );
        assert_eq!(supergroup, Some(ChatKind::Supergroup));
    }

    #[test]
    fn basic_groups_are_groups_and_private_chats_are_not_sources() {
        assert_eq!(
            classify_chat_kind(r#"{"@type":"chatTypeBasicGroup","basic_group_id":3}"#),
            Some(ChatKind::Group)
        );
        assert_eq!(
            classify_chat_kind(r#"{"@type":"chatTypePrivate","user_id":8}"#),
            None
        );
        assert_eq!(
            classify_chat_kind(r#"{"@type":"chatTypeSecret","secret_chat_id":1}"#),
            None
        );
    }

    // ---------------------------------------------- TDL-REQ-01: la correlazione
    //
    // Gli identificativi che `accessible_chats` conia sono deterministici,
    // perche' il correlatore parte da 1 e la sequenza di invio e' fissa:
    // `loadChats` (1) e `getChats` (2) per la lista principale, poi le stesse
    // due (3 e 4) per l'archivio. Il doppio fittizio deve rimandare indietro lo
    // stesso valore, come fa TDLib, e per farlo deve saperlo in anticipo.
    //
    // Se qualcuno aggiungesse una richiesta prima di queste, i numeri
    // cambierebbero: `le_richieste_dell_elenco_portano_un_identificativo` lo
    // dice subito, invece di lasciare che le altre prove passino in silenzio su
    // un percorso diverso da quello vero.
    const EXTRA_LOAD_MAIN: u64 = 1;
    const EXTRA_GET_MAIN: u64 = 2;
    const EXTRA_GET_ARCHIVE: u64 = 4;

    /// L'aggiornamento che porta la macchina allo stato pronto.
    const CORR_READY_UPDATE: &str = concat!(
        r#"{"@type":"updateAuthorizationState","authorization_state":"#,
        r#"{"@type":"authorizationStateReady"}}"#
    );

    /// Un connettore autorizzato, con la coda gia' caricata.
    fn connettore_pronto(risposte: Vec<String>) -> LiveTdlibConnector<FakeTdJson> {
        let mut backend = FakeTdJson::new()
            .then_receive(Ok(Some(String::from(WAIT_TDLIB_PARAMETERS_UPDATE))))
            .then_receive(Ok(Some(String::from(CORR_READY_UPDATE))));
        for risposta in risposte {
            backend = backend.then_receive(Ok(Some(risposta)));
        }

        let mut connector = LiveTdlibConnector::new(backend, String::from(FAKE_DATABASE_KEY));
        let Ok(()) = connector.start(&fake_client_parameters()) else {
            panic!("l'avvio deve riuscire");
        };
        for _ in 0..2 {
            let Ok(Some(_)) = connector.poll_event(Duration::from_millis(10)) else {
                panic!("gli aggiornamenti di autorizzazione devono arrivare");
            };
        }
        assert_eq!(connector.authorization_state(), AuthorizationState::Ready);
        connector
    }

    fn risposta_chats(extra: u64) -> String {
        format!(r#"{{"@type":"chats","@extra":"{extra}","total_count":0,"chat_ids":[]}}"#)
    }

    fn risposta_errore(extra: u64, code: i32, message: &str) -> String {
        format!(r#"{{"@type":"error","@extra":"{extra}","code":{code},"message":"{message}"}}"#)
    }

    /// **Ogni richiesta dell'elenco porta un identificativo, e sono questi.**
    ///
    /// Verifica insieme due cose: che `@extra` venga scritto davvero, e che la
    /// numerazione sia quella su cui le altre prove si appoggiano.
    #[test]
    fn le_richieste_dell_elenco_portano_un_identificativo() {
        let mut connector = connettore_pronto(vec![
            risposta_chats(EXTRA_GET_MAIN),
            risposta_chats(EXTRA_GET_ARCHIVE),
        ]);

        let Ok(_) = connector.accessible_chats() else {
            panic!("l'elenco deve potersi leggere");
        };

        let inviate = connector.library.sent_requests();
        let carichi: Vec<&String> = inviate
            .iter()
            .filter(|richiesta| richiesta.contains(r#""@type":"loadChats""#))
            .collect();
        let elenchi: Vec<&String> = inviate
            .iter()
            .filter(|richiesta| richiesta.contains(r#""@type":"getChats""#))
            .collect();

        assert_eq!(carichi.len(), 2, "una per lista");
        assert_eq!(elenchi.len(), 2, "una per lista");
        assert!(
            carichi[0].contains(&format!(r#""@extra":"{EXTRA_LOAD_MAIN}""#)),
            "{}",
            carichi[0]
        );
        assert!(
            elenchi[0].contains(&format!(r#""@extra":"{EXTRA_GET_MAIN}""#)),
            "{}",
            elenchi[0]
        );
        assert!(
            elenchi[1].contains(&format!(r#""@extra":"{EXTRA_GET_ARCHIVE}""#)),
            "{}",
            elenchi[1]
        );
    }

    /// **Un errore su `getChats` non passa piu' per benigno.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Prima di TDL-REQ-01 ogni `error` che arrivava mentre si raccoglieva
    /// l'elenco veniva assorbito, con il commento «e' quasi sempre la risposta
    /// a `loadChats`». Un limite di frequenza su `getChats` finiva nello stesso
    /// ramo, e l'elenco delle fonti risultava semplicemente piu' corto — senza
    /// errore, senza avviso, senza che nulla lo dichiarasse.
    #[test]
    fn un_errore_sull_elenco_non_passa_piu_per_benigno() {
        let mut connector = connettore_pronto(vec![risposta_errore(
            EXTRA_GET_MAIN,
            420,
            "Too Many Requests",
        )]);

        let Err(errore) = connector.accessible_chats() else {
            panic!("un errore sull'elenco deve arrivare a chi ha chiesto l'elenco");
        };
        assert!(
            errore.to_string().contains("non è stato consegnato"),
            "{errore}"
        );
    }

    /// **Un errore su `loadChats` resta benigno, e adesso si sa che e' suo.**
    ///
    /// E' l'esito normale quando l'elenco e' gia' caricato. La differenza
    /// rispetto a prima non e' nel comportamento: e' che non lo si suppone piu'.
    #[test]
    fn un_errore_sul_caricamento_resta_benigno() {
        let mut connector = connettore_pronto(vec![
            risposta_errore(EXTRA_LOAD_MAIN, 400, "Chat list is already loaded"),
            risposta_chats(EXTRA_GET_MAIN),
            risposta_chats(EXTRA_GET_ARCHIVE),
        ]);

        let Ok(chats) = connector.accessible_chats() else {
            panic!("un errore di caricamento non deve fermare l'elenco");
        };
        assert!(chats.is_empty(), "nessuna chat annunciata in questa prova");
    }

    /// **Un `@extra` mai coniato non conclude nulla.**
    ///
    /// Un messaggio che porta un identificativo che questo connettore non ha
    /// mai emesso non e' la risposta a niente: passa dall'interpretazione degli
    /// aggiornamenti, e le richieste restano in attesa.
    #[test]
    fn un_extra_mai_coniato_non_conclude_nulla() {
        let mut connector = connettore_pronto(vec![
            risposta_chats(9_999),
            risposta_chats(EXTRA_GET_MAIN),
            risposta_chats(EXTRA_GET_ARCHIVE),
        ]);

        let Ok(_) = connector.accessible_chats() else {
            panic!("l'elenco deve potersi leggere");
        };

        // Le due liste hanno risposto. Restano in attesa i due `loadChats`, che
        // in questa prova non ricevono alcuna risposta: e' il loro caso
        // normale quando l'elenco e' gia' caricato, e si chiudono per scadenza
        // o alla spazzata della chiamata successiva.
        assert_eq!(
            connector.correlator.pending_count(),
            2,
            "i due getChats hanno concluso; il messaggio estraneo non ha concluso nulla"
        );
    }

    // ------------------------------------------ LINK-01: il collegamento
    //
    // `message_link` conia un identificativo solo, quindi il primo: 1.

    const EXTRA_LINK: u64 = 1;

    fn chat_di_prova() -> crate::identifier::ChatId {
        let Ok(chat) = crate::identifier::ChatId::try_new(-1_001_234_567_890) else {
            panic!("l'identificativo di prova deve essere valido");
        };
        chat
    }

    fn messaggio_di_prova() -> crate::identifier::MessageId {
        let Ok(messaggio) = crate::identifier::MessageId::try_new(1_048_576) else {
            panic!("l'identificativo di prova deve essere valido");
        };
        messaggio
    }

    /// Un messaggio nuovo che arriva mentre si aspetta il collegamento.
    const CORR_NEW_MESSAGE: &str = concat!(
        r#"{"@type":"updateNewMessage","message":{"@type":"message","#,
        r#""id":1048576,"sender_id":{"@type":"messageSenderUser","user_id":42},"#,
        r#""chat_id":-1001234567890,"is_outgoing":false,"date":1700000000,"#,
        r#""content":{"@type":"messageText","text":{"@type":"formattedText","#,
        r#""text":"ciao mondo","entities":[]}}}}"#
    );

    fn risposta_link(extra: u64, url: &str, pubblico: bool) -> String {
        format!(
            r#"{{"@type":"messageLink","@extra":"{extra}","link":"{url}","is_public":{pubblico}}}"#
        )
    }

    /// **Il collegamento che Telegram fornisce arriva, e dice se è pubblico.**
    #[test]
    fn il_collegamento_fornito_da_telegram_arriva() {
        let mut connector = connettore_pronto(vec![risposta_link(
            EXTRA_LINK,
            "https://t.me/canale/42",
            true,
        )]);

        let Ok(esito) = connector.message_link(chat_di_prova(), messaggio_di_prova()) else {
            panic!("la richiesta deve potersi inviare");
        };

        let Some(link) = esito.link() else {
            panic!("il collegamento doveva arrivare: {}", esito.as_sentence());
        };
        assert_eq!(link.as_str(), "https://t.me/canale/42");
        assert!(link.is_public());

        // E la richiesta e' partita con il proprio identificativo.
        let inviate = connector.library.sent_requests();
        assert!(
            inviate.iter().any(|richiesta| {
                richiesta.contains(r#""@type":"getMessageLink""#)
                    && richiesta.contains(&format!(r#""@extra":"{EXTRA_LINK}""#))
            }),
            "{inviate:?}"
        );
    }

    /// **Un collegamento non pubblico si consegna dicendolo.**
    #[test]
    fn un_collegamento_non_pubblico_si_consegna_dicendolo() {
        let mut connector = connettore_pronto(vec![risposta_link(
            EXTRA_LINK,
            "https://t.me/c/1234567890/1",
            false,
        )]);

        let Ok(esito) = connector.message_link(chat_di_prova(), messaggio_di_prova()) else {
            panic!("la richiesta deve potersi inviare");
        };

        let Some(link) = esito.link() else {
            panic!("il collegamento doveva arrivare");
        };
        assert!(!link.is_public());
        assert!(esito.as_sentence().contains("Non \u{e8} pubblico"));
    }

    /// **Un rifiuto di Telegram non è un errore del programma.**
    ///
    /// È un esito, e dice quale: chi chiede un collegamento a un messaggio che
    /// non ne ha deve leggere che non ne ha, non un guasto.
    #[test]
    fn un_rifiuto_di_telegram_e_un_esito_e_non_un_errore() {
        let mut connector =
            connettore_pronto(vec![risposta_errore(EXTRA_LINK, 400, "MESSAGE_ID_INVALID")]);

        let Ok(esito) = connector.message_link(chat_di_prova(), messaggio_di_prova()) else {
            panic!("un rifiuto non deve diventare un errore della richiesta");
        };

        assert!(esito.link().is_none());
        let frase = esito.as_sentence();
        assert!(frase.contains("ha rifiutato"), "{frase}");
        assert!(frase.contains("MESSAGE_ID_INVALID"), "{frase}");
        assert!(frase.contains("Resta la fonte"), "{frase}");
    }

    /// **Nessuna risposta non è «il collegamento non esiste».**
    #[test]
    fn nessuna_risposta_non_e_il_collegamento_non_esiste() {
        let mut connector = connettore_pronto(Vec::new());

        let Ok(esito) = connector.message_link(chat_di_prova(), messaggio_di_prova()) else {
            panic!("l'assenza di risposta non deve diventare un errore");
        };

        assert!(esito.link().is_none());
        let frase = esito.as_sentence();
        assert!(
            frase.contains("Non significa che il collegamento non esista"),
            "{frase}"
        );
    }

    /// **Un indirizzo malformato non si usa.**
    ///
    /// Finirebbe in un `ContentUrl` e da lì nel browser dell'operatore
    /// (ADR-0018): meglio dire che non c'è.
    #[test]
    fn un_indirizzo_malformato_non_si_usa() {
        let mut connector = connettore_pronto(vec![risposta_link(
            EXTRA_LINK,
            "https://esempio.invalid/42",
            true,
        )]);

        let Ok(esito) = connector.message_link(chat_di_prova(), messaggio_di_prova()) else {
            panic!("la richiesta deve potersi inviare");
        };

        assert!(
            esito.link().is_none(),
            "un indirizzo che non è di Telegram non si consegna"
        );
    }

    /// **Un aggiornamento che arriva mentre si aspetta non va perso.**
    #[test]
    fn un_aggiornamento_che_arriva_mentre_si_aspetta_non_va_perso() {
        let mut connector = connettore_pronto(vec![
            String::from(CORR_NEW_MESSAGE),
            risposta_link(EXTRA_LINK, "https://t.me/canale/42", true),
        ]);

        let Ok(esito) = connector.message_link(chat_di_prova(), messaggio_di_prova()) else {
            panic!("la richiesta deve potersi inviare");
        };
        assert!(esito.link().is_some());

        // Il messaggio incrociato durante l'attesa e' conservato per chi legge
        // gli eventi: perderlo sarebbe perdere un contenuto acquisito.
        let Ok(Some(_)) = connector.poll_event(Duration::from_millis(10)) else {
            panic!("il messaggio incrociato deve essere consegnato");
        };
    }

    /// Una pagina di cronologia con l'`@extra` indicato, per la chat indicata.
    fn pagina_cronologia(extra: &str, chat: i64, testo: &str) -> String {
        format!(
            concat!(
                r#"{{"@type":"messages","@extra":"{extra}","total_count":1,"messages":["#,
                r#"{{"@type":"message","id":1048576,"chat_id":{chat},"date":1700000000,"#,
                r#""content":{{"@type":"messageText","text":{{"@type":"formattedText","#,
                r#""text":"{testo}","entities":[]}}}}}}]}}"#
            ),
            extra = extra,
            chat = chat,
            testo = testo
        )
    }

    /// **Una pagina di cronologia è la risposta alla SUA richiesta**
    /// (FINAL-REVIEW-01, FR-007).
    ///
    /// Davanti alla risposta giusta arrivano una pagina senza etichetta e una
    /// con l'etichetta di un'altra richiesta: fino al 2026-10-03 la prima delle
    /// due diventava la pagina corrente.
    #[test]
    fn una_pagina_di_cronologia_e_la_risposta_alla_sua_richiesta() {
        let mut connector = connettore_pronto(vec![
            pagina_cronologia("99", -1_009_999_999_999, "estranea etichettata"),
            pagina_cronologia("", -1_009_999_999_999, "estranea senza etichetta")
                .replace(r#""@extra":"","#, ""),
            pagina_cronologia("1", -1_001_234_567_890, "quella giusta"),
        ]);

        let Ok(pagina) = connector.fetch_history(chat_di_prova(), 0, 50) else {
            panic!("la pagina giusta deve arrivare");
        };
        assert_eq!(pagina.len(), 1, "{pagina:?}");
        assert_eq!(pagina[0].text, "quella giusta");
        let inviate = connector.library.sent_requests();
        assert!(
            inviate.iter().any(
                |richiesta| richiesta.contains(r#""@type":"getChatHistory""#)
                    && richiesta.contains(r#""@extra":"1""#)
            ),
            "la richiesta della cronologia porta il suo identificativo: {inviate:?}"
        );
    }

    /// **Un 429 arrivato in ritardo non è un guasto dell'account, e si
    /// rispetta** (FINAL-REVIEW-01, FR-008).
    #[test]
    fn un_429_tardivo_non_e_un_guasto_e_si_rispetta() {
        let mut connector = connettore_pronto(Vec::new());
        // Una richiesta di collegamento che non riceve risposta: scade.
        let Ok(_) = connector.message_link(chat_di_prova(), messaggio_di_prova()) else {
            panic!("l'assenza di risposta non è un errore");
        };

        // Poi arriva, tardi, il suo 429.
        connector.library = std::mem::take(&mut connector.library).then_receive(Ok(Some(
            risposta_errore(EXTRA_LINK, 429, "Too Many Requests: retry after 600"),
        )));
        let Ok(evento) = connector.poll_event(Duration::from_millis(10)) else {
            panic!("una risposta tardiva non è un errore del pompaggio");
        };
        assert!(
            !matches!(evento, Some(ConnectorEvent::Failure(_))),
            "un 429 tardivo non deve diventare un guasto dell'account: {evento:?}"
        );

        // E la ricerca successiva non parte: l'attesa indicata vale.
        let inviate_prima = connector.library.sent_requests().len();
        let Ok(risposta) = crate::lookup::OfficialLookup::lookup(
            &mut connector,
            &crate::lookup::LookupQuery::Username(String::from("canale")),
        ) else {
            panic!("il rifiuto locale è un esito");
        };
        assert!(
            matches!(&risposta, crate::lookup::LookupReply::Refused { code: 429, message }
                if message.contains("retry after")),
            "{risposta:?}"
        );
        assert_eq!(
            connector.library.sent_requests().len(),
            inviate_prima,
            "durante l'attesa nessuna richiesta parte"
        );
    }

    /// **Un elenco delle chat a cui le liste non rispondono non è un elenco**
    /// (FINAL-REVIEW-01, FR-008).
    #[test]
    fn un_elenco_senza_risposta_e_un_attesa_scaduta() {
        let mut connector = connettore_pronto(Vec::new());
        let esito = connector.accessible_chats();
        assert!(
            matches!(esito, Err(TelegramError::Timeout { .. })),
            "senza risposta delle liste non si restituisce un elenco: {esito:?}"
        );
    }

    #[test]
    fn l_attesa_indicata_si_legge_dalle_due_forme() {
        assert_eq!(
            super::indicated_wait_seconds("Too Many Requests: retry after 600"),
            Some(600)
        );
        assert_eq!(super::indicated_wait_seconds("FLOOD_WAIT_30"), Some(30));
        assert_eq!(super::indicated_wait_seconds("Too Many Requests"), None);
    }

    /// **Un rifiuto del contesto è un errore, non un elenco vuoto** (ADR-0151,
    /// decisione 5): la conversazione deve poter dire «fonte non più
    /// accessibile», e lo dice soltanto se il testo di TDLib arriva fin lì.
    #[test]
    fn un_rifiuto_del_contesto_e_un_errore_con_il_testo_di_tdlib() {
        let mut connector = connettore_pronto(vec![risposta_errore(1, 400, "Chat not found")]);
        let (Ok(chat), Ok(messaggio)) = (ChatId::try_new(-1001), MessageId::try_new(500)) else {
            panic!("identificativi validi");
        };
        let Err(errore) = connector.fetch_context(chat, messaggio, 20, 20) else {
            panic!("un rifiuto non deve diventare un elenco vuoto");
        };
        assert!(errore.to_string().contains("Chat not found"), "{errore}");
    }

    /// **Il tempo massimo scaduto è un errore di tempo** (ADR-0151, decisione
    /// 4): «non è arrivato nulla in tempo» non è «non c'era nulla».
    #[test]
    fn il_tempo_scaduto_del_contesto_e_un_errore_di_tempo() {
        let mut connector = connettore_pronto(Vec::new());
        let (Ok(chat), Ok(messaggio)) = (ChatId::try_new(-1001), MessageId::try_new(500)) else {
            panic!("identificativi validi");
        };
        assert!(matches!(
            connector.fetch_context(chat, messaggio, 20, 20),
            Err(TelegramError::Timeout { .. })
        ));
    }

    /// **Una risposta vuota resta un elenco vuoto**: la richiesta è riuscita e
    /// Telegram non ha messaggi da dare.
    #[test]
    fn una_risposta_vuota_del_contesto_resta_un_elenco_vuoto() {
        let mut connector = connettore_pronto(vec![String::from(
            r#"{"@type":"messages","@extra":"1","total_count":0,"messages":[]}"#,
        )]);
        let (Ok(chat), Ok(messaggio)) = (ChatId::try_new(-1001), MessageId::try_new(500)) else {
            panic!("identificativi validi");
        };
        assert!(matches!(
            connector.fetch_context(chat, messaggio, 20, 20),
            Ok(messaggi) if messaggi.is_empty()
        ));
    }

    /// Una ricerca B di prova.
    fn ricerca_b() -> crate::search::SearchQuery {
        crate::search::SearchQuery::AccountChats {
            query: String::from("ransomware"),
            offset: String::new(),
            limit: 20,
        }
    }

    /// **Una pagina di risultati si legge, con il cursore** (criterio 2).
    #[test]
    fn una_pagina_di_ricerca_si_legge_con_il_cursore() {
        let risposta = concat!(
            r#"{"@type":"foundMessages","@extra":"1","total_count":2,"messages":["#,
            r#"{"@type":"message","id":1048576,"chat_id":-1001,"date":1760000000,"#,
            r#""sender_id":{"@type":"messageSenderUser","user_id":42},"#,
            r#""content":{"@type":"messageText","text":{"@type":"formattedText","text":"nuovo ransomware","entities":[]}}},"#,
            r#"{"@type":"message","id":2097152,"chat_id":-1002,"date":1760000100,"#,
            r#""sender_id":{"@type":"messageSenderChat","chat_id":-1002},"#,
            r#""content":{"@type":"messageText","text":{"@type":"formattedText","text":"ransomware in Italia","entities":[]}}}"#,
            r#"],"next_offset":"cursore-2"}"#
        );
        let mut connector = connettore_pronto(vec![String::from(risposta)]);
        let Ok(pagina) = connector.search_messages(&ricerca_b()) else {
            panic!("la pagina deve leggersi");
        };
        assert_eq!(pagina.hits.len(), 2);
        assert_eq!(pagina.total_count, Some(2));
        assert_eq!(pagina.next_offset.as_deref(), Some("cursore-2"));
        assert!(pagina.has_more());
        assert_eq!(pagina.hits[0].text, "nuovo ransomware");

        let inviate = connector.library.sent_requests();
        let Some(inviata) = inviate
            .iter()
            .find(|r| r.contains(r#""@type":"searchMessages""#))
        else {
            panic!("la richiesta di ricerca deve essere partita");
        };
        assert!(inviata.contains(r#""query":"ransomware""#), "{inviata}");
        assert!(!inviata.contains("star_count"), "{inviata}");
    }

    /// **Un rifiuto della ricerca è un errore con il testo di TDLib** (criterio 3).
    #[test]
    fn un_rifiuto_della_ricerca_e_un_errore() {
        let mut connector = connettore_pronto(vec![risposta_errore(1, 400, "CHANNEL_PRIVATE")]);
        let Err(errore) = connector.search_messages(&ricerca_b()) else {
            panic!("un rifiuto non deve diventare una pagina vuota");
        };
        assert!(errore.to_string().contains("CHANNEL_PRIVATE"), "{errore}");
    }

    /// **Il tempo scaduto della ricerca è un errore di tempo** (criterio 3).
    #[test]
    fn il_tempo_scaduto_della_ricerca_e_un_errore_di_tempo() {
        let mut connector = connettore_pronto(Vec::new());
        assert!(matches!(
            connector.search_messages(&ricerca_b()),
            Err(TelegramError::Timeout { .. })
        ));
    }

    /// **Una ricerca senza risultati è una pagina vuota, senza seguito.**
    #[test]
    fn una_ricerca_senza_risultati_e_una_pagina_vuota() {
        let mut connector = connettore_pronto(vec![String::from(
            r#"{"@type":"foundMessages","@extra":"1","total_count":0,"messages":[],"next_offset":""}"#,
        )]);
        let Ok(pagina) = connector.search_messages(&ricerca_b()) else {
            panic!("una risposta vuota e' una pagina vuota");
        };
        assert!(pagina.hits.is_empty());
        assert!(!pagina.has_more());
    }

    /// Una quota della ricerca D, come la scrive TDLib.
    const QUOTA_D: &str = r#"{"@type":"publicPostSearchLimits","daily_free_query_count":10,"remaining_free_query_count":3,"next_free_query_in":0,"star_count":10,"is_current_query_free":true}"#;

    /// **La D chiede zero Stelle, e la pagina porta la quota e i limiti**
    /// (CYBER-SEARCH-02, criteri 1 e 3).
    #[test]
    fn una_pagina_della_d_si_legge_con_la_quota() {
        let risposta = format!(
            "{}{}{}{QUOTA_D}{}",
            r#"{"@type":"foundPublicPosts","@extra":"1","messages":["#,
            r#"{"@type":"message","id":1048576,"chat_id":-1003,"date":1760000000,"sender_id":{"@type":"messageSenderChat","chat_id":-1003},"content":{"@type":"messageText","text":{"@type":"formattedText","text":"\"are_limits_exceeded\":false #ransomware","entities":[]}}}"#,
            r#"],"next_offset":"cursore-d","search_limits":"#,
            r#","are_limits_exceeded":false}"#
        );
        let mut connector = connettore_pronto(vec![risposta]);
        let ricerca = crate::search::SearchQuery::PublicPosts {
            query: String::from("#ransomware"),
            offset: String::new(),
            limit: 20,
        };
        let Ok(pagina) = connector.search_messages(&ricerca) else {
            panic!("la pagina deve leggersi");
        };
        assert_eq!(pagina.hits.len(), 1);
        assert_eq!(pagina.next_offset.as_deref(), Some("cursore-d"));
        assert!(!pagina.limits_exceeded);
        assert_eq!(pagina.limits.map(|q| q.remaining_free), Some(3));

        let inviate = connector.library.sent_requests();
        let Some(inviata) = inviate
            .iter()
            .find(|r| r.contains(r#""@type":"searchPublicPosts""#))
        else {
            panic!("la richiesta della D deve essere partita");
        };
        assert!(inviata.contains(r#""star_count":0}"#), "{inviata}");
    }

    /// **Limiti superati, o non dichiarati, fermano la D** (criterio 3).
    #[test]
    fn i_limiti_superati_o_taciuti_fermano_la_d() {
        for risposta in [
            r#"{"@type":"foundPublicPosts","messages":[],"next_offset":"x","are_limits_exceeded":true}"#,
            r#"{"@type":"foundPublicPosts","messages":[],"next_offset":"x"}"#,
        ] {
            assert!(
                super::parse_search_page(risposta, 0).limits_exceeded,
                "{risposta}"
            );
        }
    }

    /// **La quota si legge, e una quota illeggibile è un errore** (criterio 2).
    #[test]
    fn la_quota_della_d_si_legge_o_e_un_errore() {
        let mut connector = connettore_pronto(vec![QUOTA_D.replacen(
            r#""@type":"publicPostSearchLimits","#,
            r#""@type":"publicPostSearchLimits","@extra":"1","#,
            1,
        )]);
        let Ok(quota) = connector.public_post_limits("#ransomware") else {
            panic!("la quota deve leggersi");
        };
        assert!(quota.allows_free_search());
        assert_eq!(quota.daily_free, 10);
        let inviate = connector.library.sent_requests();
        assert!(
            inviate
                .iter()
                .any(|r| r.contains(r#""@type":"getPublicPostSearchLimits""#)),
            "{inviate:?}"
        );

        let mut connector = connettore_pronto(vec![String::from(
            r#"{"@type":"publicPostSearchLimits","@extra":"1","daily_free_query_count":10}"#,
        )]);
        assert!(connector.public_post_limits("x").is_err());
        let mut connector = connettore_pronto(vec![String::from(r#"{"@type":"ok","@extra":"1"}"#)]);
        assert!(connector.public_post_limits("x").is_err());
    }
    // --- La coda arretrata (NEXUM97-FULL-OPERATIONAL-VALIDATION-01, BUG-03) --
    //
    // Dal vivo, il 2026-10-19: con l'account appena attivato e nessun
    // monitoraggio in corso, «Chiedi a Telegram chi è questo account»
    // rispondeva «attesa scaduta» in meno di un secondo, a ogni tentativo. Gli
    // aggiornamenti che Telegram manda dopo l'accesso restano in coda finché
    // nessuno li legge, e ogni lettura — anche quella che ne trova uno subito —
    // consumava un tentativo: i duecento tentativi finivano sulla coda
    // arretrata prima di arrivare alla risposta, che sta in fondo. Dopo che la
    // schermata Fonti aveva svuotato la coda, la stessa richiesta riusciva.

    /// Più aggiornamenti in coda di quanti tentativi abbia qualunque attesa.
    const CODA_ARRETRATA: usize = super::CHATS_MAX_POLLS + 100;

    /// Aggiornamenti non richiesti, come quelli che seguono l'accesso.
    fn coda_arretrata() -> Vec<String> {
        (0..CODA_ARRETRATA)
            .map(|indice| {
                format!(
                    r#"{{"@type":"updateUserStatus","user_id":{},"status":{{"@type":"userStatusRecently"}}}}"#,
                    1_000 + indice
                )
            })
            .collect()
    }

    /// Una coda arretrata e poi, in fondo, la risposta.
    fn arretrata_poi(risposte: &[String]) -> LiveTdlibConnector<FakeTdJson> {
        let mut coda = coda_arretrata();
        coda.extend(risposte.iter().cloned());
        connettore_pronto(coda)
    }

    /// **`getMe` arriva anche dietro una coda arretrata.**
    #[test]
    fn la_lettura_dell_account_arriva_dietro_la_coda_arretrata() {
        let risposta = String::from(concat!(
            r#"{"@type":"user","@extra":"1","id":777,"first_name":"Ufficio","#,
            r#""type":{"@type":"userTypeRegular"}}"#
        ));
        let mut connector = arretrata_poi(&[risposta]);
        let esito =
            crate::lookup::OfficialLookup::lookup(&mut connector, &crate::lookup::LookupQuery::Me);
        assert!(
            matches!(&esito, Ok(crate::lookup::LookupReply::Found(profilo)) if profilo.telegram_id == 777),
            "una coda arretrata non è un'attesa scaduta: {esito:?}"
        );
    }

    /// **Il contesto arriva anche dietro una coda arretrata.**
    #[test]
    fn il_contesto_arriva_dietro_la_coda_arretrata() {
        let mut connector = arretrata_poi(&[String::from(
            r#"{"@type":"messages","@extra":"1","total_count":0,"messages":[]}"#,
        )]);
        let (Ok(chat), Ok(messaggio)) = (ChatId::try_new(-1001), MessageId::try_new(500)) else {
            panic!("identificativi validi");
        };
        let esito = connector.fetch_context(chat, messaggio, 20, 20);
        assert!(
            matches!(&esito, Ok(messaggi) if messaggi.is_empty()),
            "{esito:?}"
        );
    }

    /// **Il collegamento al messaggio arriva anche dietro una coda arretrata.**
    #[test]
    fn il_collegamento_arriva_dietro_la_coda_arretrata() {
        let mut connector = arretrata_poi(&[String::from(
            r#"{"@type":"messageLink","@extra":"1","link":"https://t.me/canale/500","is_public":true}"#,
        )]);
        let esito = connector.message_link(chat_di_prova(), messaggio_di_prova());
        assert!(
            matches!(&esito, Ok(crate::link::LinkOutcome::Provided(_))),
            "una coda arretrata non è un collegamento mancante: {esito:?}"
        );
    }

    /// **Una pagina di ricerca arriva anche dietro una coda arretrata.**
    #[test]
    fn la_ricerca_arriva_dietro_la_coda_arretrata() {
        let mut connector = arretrata_poi(&[String::from(
            r#"{"@type":"foundMessages","@extra":"1","total_count":0,"messages":[],"next_offset":""}"#,
        )]);
        let esito = connector.search_messages(&ricerca_b());
        assert!(
            matches!(&esito, Ok(pagina) if pagina.hits.is_empty()),
            "{esito:?}"
        );
    }

    /// **Una pagina di cronologia arriva anche dietro una coda arretrata.**
    #[test]
    fn la_cronologia_arriva_dietro_la_coda_arretrata() {
        let mut connector = arretrata_poi(&[String::from(
            r#"{"@type":"messages","@extra":"1","total_count":0,"messages":[]}"#,
        )]);
        let Ok(chat) = ChatId::try_new(-1001) else {
            panic!("identificativo valido");
        };
        let esito = connector.fetch_history(chat, 0, 50);
        assert!(
            matches!(&esito, Ok(pagina) if pagina.is_empty()),
            "{esito:?}"
        );
    }

    /// **L'elenco delle chat arriva anche dietro una coda arretrata.**
    #[test]
    fn l_elenco_arriva_dietro_la_coda_arretrata() {
        let mut connector = arretrata_poi(&[
            risposta_chats(EXTRA_GET_MAIN),
            risposta_chats(EXTRA_GET_ARCHIVE),
        ]);
        let esito = connector.accessible_chats();
        assert!(esito.is_ok(), "{esito:?}");
    }

    /// **La chiusura si conferma anche dietro una coda arretrata.**
    #[test]
    fn la_chiusura_si_conferma_dietro_la_coda_arretrata() {
        let chiusa = String::from(concat!(
            r#"{"@type":"updateAuthorizationState","authorization_state":"#,
            r#"{"@type":"authorizationStateClosed"}}"#
        ));
        let mut connector = arretrata_poi(&[chiusa]);
        let Ok(()) = connector.shutdown() else {
            panic!("la chiusura non deve fallire");
        };
        assert!(
            connector.library.receive_queue.borrow().is_empty(),
            "la chiusura deve leggere fino alla conferma, oltre la coda arretrata"
        );
    }

    /// **Il silenzio ha ancora un limite**: senza alcun messaggio l'attesa
    /// finisce, e non gira per sempre.
    #[test]
    fn il_silenzio_ha_ancora_un_limite() {
        let mut connector = connettore_pronto(Vec::new());
        let esito =
            crate::lookup::OfficialLookup::lookup(&mut connector, &crate::lookup::LookupQuery::Me);
        assert!(
            matches!(esito, Err(TelegramError::Timeout { .. })),
            "{esito:?}"
        );
    }
}

#[cfg(test)]
mod lookup_tests {
    use super::parse_lookup;
    use crate::lookup::{LookupKind, LookupQuery, LookupReply};

    fn trovato(risposta: LookupReply) -> crate::lookup::LookupProfile {
        let LookupReply::Found(profilo) = risposta else {
            panic!("doveva essere un profilo: {risposta:?}");
        };
        profilo
    }

    /// **Un supergruppo si chiama come nelle Fonti** (LOOK-01): la ricerca
    /// diceva «gruppo», la schermata Fonti «Supergruppo», per la stessa chat.
    #[test]
    fn un_supergruppo_si_chiama_come_nelle_fonti() {
        let risposta = r#"{"@type":"chat","@extra":"8","id":-1009876543210,"type":{"@type":"chatTypeSupergroup","supergroup_id":9876543210,"is_channel":false},"title":"Gruppo di prova","photo":null}"#;
        let profilo = trovato(parse_lookup(
            risposta,
            &LookupQuery::Username(String::from("gruppo_prova")),
        ));
        assert_eq!(profilo.kind, LookupKind::Supergroup);
        assert_eq!(
            profilo.kind.label(),
            crate::chat::ChatKind::Supergroup.label().to_lowercase()
        );
    }

    /// **Un canale trovato per nome utente**: genere, identificativo e il nome
    /// utente cercato, che Telegram ha confermato trovandolo.
    #[test]
    fn un_canale_trovato_per_nome_utente() {
        let risposta = r#"{"@type":"chat","@extra":"7","id":-1001234567890,"type":{"@type":"chatTypeSupergroup","supergroup_id":1234567890,"is_channel":true},"title":"Canale di prova","photo":null}"#;
        let profilo = trovato(parse_lookup(
            risposta,
            &LookupQuery::Username(String::from("canale_prova")),
        ));
        assert_eq!(profilo.kind, LookupKind::Channel);
        assert_eq!(profilo.telegram_id, -1_001_234_567_890);
        assert_eq!(profilo.name, "Canale di prova");
        assert_eq!(profilo.username.as_deref(), Some("canale_prova"));
    }

    /// **Una persona trovata per numero**: il genere si legge dal tipo della
    /// persona anche quando un campo precedente porta un `type` annidato.
    #[test]
    fn una_persona_trovata_per_numero() {
        let risposta = r#"{"@type":"user","id":42,"first_name":"Mario","last_name":"Rossi","usernames":{"@type":"usernames","active_usernames":["mrossi","altro"],"disabled_usernames":[],"editable_username":"mrossi"},"phone_number":"","emoji_status":{"@type":"emojiStatus","type":{"@type":"emojiStatusTypeCustomEmoji","custom_emoji_id":1}},"type":{"@type":"userTypeRegular"}}"#;
        let profilo = trovato(parse_lookup(
            risposta,
            &LookupQuery::PhoneNumber(String::from("390000000000")),
        ));
        assert_eq!(profilo.kind, LookupKind::Person);
        assert_eq!(profilo.telegram_id, 42);
        assert_eq!(profilo.name, "Mario Rossi");
        assert_eq!(profilo.username.as_deref(), Some("mrossi"));
    }

    /// **Un bot si dice bot**, e un profilo senza nome utente non ne riceve uno.
    #[test]
    fn un_bot_senza_nome_utente() {
        let risposta = r#"{"@type":"user","id":7,"first_name":"Servizio","last_name":"","usernames":null,"type":{"@type":"userTypeBot","can_join_groups":false}}"#;
        let profilo = trovato(parse_lookup(risposta, &LookupQuery::UserId(7)));
        assert_eq!(profilo.kind, LookupKind::Bot);
        assert_eq!(profilo.username, None);
    }

    /// **Una risposta inattesa non diventa un profilo né un'assenza**: torna
    /// come rifiuto con codice zero, che la tabella classifica come errore
    /// operativo.
    #[test]
    fn una_risposta_inattesa_non_e_un_profilo() {
        for risposta in [
            r#"{"@type":"ok"}"#,
            r#"{"@type":"chat","title":"senza identificativo"}"#,
        ] {
            let LookupReply::Refused { code, message } =
                parse_lookup(risposta, &LookupQuery::ChatId(-1))
            else {
                panic!("una risposta inattesa non è un profilo");
            };
            assert_eq!(code, 0);
            assert!(message.starts_with("risposta inattesa"));
        }
    }

    /// **Tutti gli username attivi, nome e cognome separati** (ADR-0153, A1).
    #[test]
    fn una_persona_porta_tutti_i_suoi_username_attivi() {
        let risposta = concat!(
            r#"{"@type":"user","@extra":"9","id":42,"first_name":"Mario","last_name":"Rossi","#,
            r#""usernames":{"@type":"usernames","active_usernames":["mrossi","mario_r","m_r_42"],"#,
            r#""disabled_usernames":["vecchio"],"editable_username":"mrossi"},"#,
            r#""phone_number":"","type":{"@type":"userTypeRegular"}}"#
        );
        let profilo = trovato(parse_lookup(risposta, &LookupQuery::UserId(42)));
        assert_eq!(profilo.kind, LookupKind::Person);
        assert_eq!(profilo.first_name, "Mario");
        assert_eq!(profilo.last_name, "Rossi");
        assert_eq!(profilo.usernames, vec!["mrossi", "mario_r", "m_r_42"]);
        assert_eq!(profilo.username.as_deref(), Some("mrossi"));
        assert!(
            !profilo.usernames.contains(&String::from("vecchio")),
            "un username disattivato non e' attivo"
        );
        // A2: un telefono vuoto e' un telefono che Telegram non mostra.
        assert_eq!(profilo.phone_number, None);
    }

    /// **Il telefono arriva soltanto se Telegram lo restituisce** (A2).
    #[test]
    fn il_telefono_arriva_solo_se_telegram_lo_restituisce() {
        let con = concat!(
            r#"{"@type":"user","id":43,"first_name":"Anna","last_name":"","#,
            r#""usernames":{"@type":"usernames","active_usernames":[]},"#,
            r#""phone_number":"393401234567","type":{"@type":"userTypeRegular"}}"#
        );
        let profilo = trovato(parse_lookup(con, &LookupQuery::UserId(43)));
        assert_eq!(profilo.phone_number.as_deref(), Some("393401234567"));
        assert!(profilo.usernames.is_empty());
        assert_eq!(profilo.username, None);

        // Senza il campo, o con un valore che non e' un numero: nulla.
        let senza =
            r#"{"@type":"user","id":44,"first_name":"Bea","type":{"@type":"userTypeRegular"}}"#;
        assert_eq!(
            trovato(parse_lookup(senza, &LookupQuery::UserId(44))).phone_number,
            None
        );
        let strano = r#"{"@type":"user","id":45,"first_name":"Ciro","phone_number":"+39 abc","type":{"@type":"userTypeRegular"}}"#;
        assert_eq!(
            trovato(parse_lookup(strano, &LookupQuery::UserId(45))).phone_number,
            None
        );
    }

    /// **`getMe` restituisce un utente come gli altri** (A4).
    #[test]
    fn get_me_si_legge_come_un_utente() {
        let risposta = concat!(
            r#"{"@type":"user","@extra":"3","id":777,"first_name":"Ufficio","last_name":"Prova","#,
            r#""usernames":{"@type":"usernames","active_usernames":["ufficio_prova"]},"#,
            r#""phone_number":"390600000099","type":{"@type":"userTypeRegular"}}"#
        );
        let profilo = trovato(parse_lookup(risposta, &LookupQuery::Me));
        assert_eq!(profilo.telegram_id, 777);
        assert_eq!(profilo.usernames, vec!["ufficio_prova"]);
        assert_eq!(profilo.phone_number.as_deref(), Some("390600000099"));
    }

    /// **Un username con una forma ostile non arriva alla schermata.**
    #[test]
    fn un_username_ostile_si_scarta() {
        let risposta = concat!(
            r#"{"@type":"user","id":46,"first_name":"X","#,
            r#""usernames":{"@type":"usernames","active_usernames":["buono","<script>","ok_2"]},"#,
            r#""type":{"@type":"userTypeRegular"}}"#
        );
        let profilo = trovato(parse_lookup(risposta, &LookupQuery::UserId(46)));
        assert_eq!(profilo.usernames, vec!["buono", "ok_2"]);
    }
}

/// La lettura di foto, biografia e stato dalle risposte di TDLib
/// (PERSON-MEDIA-01, ADR-0174), su risposte sintetiche.
#[cfg(test)]
mod profilo {
    use super::{parse_bio, parse_profile_status, profile_small_photo_id, read_downloaded_photo};
    use crate::profile::{MAX_PHOTO_BYTES, ProfileStatus};

    #[test]
    fn lo_stato_si_legge_e_uno_sconosciuto_non_e_non_attivo() {
        let utente = |stato: &str| format!(r#"{{"@type":"user","id":42,"status":{stato}}}"#);
        assert_eq!(
            parse_profile_status(&utente(r#"{"@type":"userStatusOnline","expires":1}"#)),
            ProfileStatus::Online
        );
        assert_eq!(
            parse_profile_status(&utente(
                r#"{"@type":"userStatusOffline","was_online":1700000000}"#
            )),
            ProfileStatus::Offline {
                was_online_millis: 1_700_000_000_000
            }
        );
        assert_eq!(
            parse_profile_status(&utente(
                r#"{"@type":"userStatusRecently","by_my_privacy_settings":false}"#
            )),
            ProfileStatus::Recently
        );
        assert_eq!(
            parse_profile_status(&utente(r#"{"@type":"userStatusLastMonth"}"#)),
            ProfileStatus::LastMonth
        );
        assert_eq!(
            parse_profile_status(&utente(r#"{"@type":"userStatusEmpty"}"#)),
            ProfileStatus::NotShown
        );
        assert_eq!(
            parse_profile_status(r#"{"@type":"user","id":42}"#),
            ProfileStatus::NotShown,
            "senza stato non si dice «non attivo»"
        );
    }

    #[test]
    fn la_foto_piccola_e_quella_dell_account_non_di_altri_oggetti() {
        let con_foto = r#"{"@type":"user","id":42,"profile_photo":{"@type":"profilePhoto","id":"9","small":{"@type":"file","id":77,"local":{"path":""}},"big":{"@type":"file","id":78}}}"#;
        assert_eq!(profile_small_photo_id(con_foto), Some(77));
        let senza = r#"{"@type":"user","id":42,"emoji_status":{"small":{"id":5}}}"#;
        assert_eq!(
            profile_small_photo_id(senza),
            None,
            "un altro «small» non è la foto"
        );
    }

    #[test]
    fn la_biografia_si_legge_dal_testo_e_una_vuota_e_assente() {
        assert_eq!(
            parse_bio(r#"{"@type":"userFullInfo","bio":{"@type":"formattedText","text":"  Cronista \"locale\"  ","entities":[]}}"#)
                .as_deref(),
            Some("Cronista \"locale\"")
        );
        assert_eq!(
            parse_bio(
                r#"{"@type":"userFullInfo","bio":{"@type":"formattedText","text":"","entities":[]}}"#
            ),
            None
        );
        assert_eq!(parse_bio(r#"{"@type":"userFullInfo"}"#), None);
    }

    #[test]
    fn la_foto_scaricata_si_legge_soltanto_completa_e_sotto_il_tetto() {
        let cartella = std::env::temp_dir().join(format!(
            "nexum97-profilo-{}-{}",
            std::process::id(),
            super::now_millis()
        ));
        let Ok(()) = std::fs::create_dir_all(&cartella) else {
            panic!("cartella temporanea");
        };
        let file = |nome: &str, byte: usize| {
            let percorso = cartella.join(nome);
            let Ok(()) = std::fs::write(&percorso, vec![0xff_u8; byte]) else {
                panic!("il file di prova si scrive");
            };
            // Nel JSON la barra rovescia di Windows si scrive raddoppiata.
            percorso.to_string_lossy().replace('\\', "\\\\")
        };
        let risposta = |percorso: &str, completo: bool| {
            format!(
                r#"{{"@type":"file","id":77,"local":{{"path":"{percorso}","is_downloading_completed":{completo}}}}}"#
            )
        };
        let piccola = file("piccola.jpg", 4_000);
        let (byte, perche) = read_downloaded_photo(&risposta(&piccola, true));
        assert_eq!(byte.map(|b| b.len()), Some(4_000));
        assert_eq!(perche, None);

        let (byte, perche) = read_downloaded_photo(&risposta(&piccola, false));
        assert!(
            byte.is_none() && perche.is_some(),
            "incompleta non si legge"
        );

        let grande = file("grande.jpg", MAX_PHOTO_BYTES + 1);
        let (byte, perche) = read_downloaded_photo(&risposta(&grande, true));
        assert!(byte.is_none(), "oltre il tetto non si conserva");
        assert!(perche.is_some_and(|p| p.contains("tetto")));
        let _ = std::fs::remove_dir_all(&cartella);
    }

    /// **Si scarica il file dell'allegato, e di una foto la misura più
    /// grande** (ATTACH-01 parte 2): lo stesso file che la descrizione ha
    /// misurato. Prova negativa: un sondaggio non ha file.
    #[test]
    fn si_scarica_il_file_che_la_descrizione_ha_misurato() {
        use super::{attachment_parts, file_declared_size, top_level_number};

        let documento = r#"{"@type":"messageDocument","document":{"@type":"document","file_name":"a.pdf","mime_type":"application/pdf","document":{"@type":"file","id":31,"size":2048,"expected_size":2048}},"caption":{"@type":"formattedText","text":""}}"#;
        let Some((_, _, Some(file))) = attachment_parts(documento) else {
            panic!("il documento ha il suo file");
        };
        assert_eq!(top_level_number(file, "id"), Some(31));
        assert_eq!(file_declared_size(file), Some(2048));

        let foto = r#"{"@type":"messagePhoto","photo":{"@type":"photo","sizes":[{"@type":"photoSize","type":"m","photo":{"@type":"file","id":41,"size":9000}},{"@type":"photoSize","type":"y","photo":{"@type":"file","id":43,"size":245000}},{"@type":"photoSize","type":"x","photo":{"@type":"file","id":42,"size":80000}}]}}"#;
        let Some((_, _, Some(file))) = attachment_parts(foto) else {
            panic!("la foto ha il suo file");
        };
        assert_eq!(
            top_level_number(file, "id"),
            Some(43),
            "la misura più grande"
        );

        let sondaggio = r#"{"@type":"messagePoll","poll":{"@type":"poll","id":"1"}}"#;
        assert!(attachment_parts(sondaggio).is_none());
    }

    /// **L'allegato scaricato si legge soltanto completo e sotto il tetto
    /// chiesto, ricontrollato sul disco** (ADR-0177, decisione 5).
    #[test]
    fn l_allegato_scaricato_si_legge_soltanto_completo_e_sotto_il_tetto() {
        use super::read_downloaded_attachment;

        let cartella = std::env::temp_dir().join(format!(
            "nexum97-allegato-{}-{}",
            std::process::id(),
            super::now_millis()
        ));
        let Ok(()) = std::fs::create_dir_all(&cartella) else {
            panic!("cartella temporanea");
        };
        let percorso = cartella.join("31.bin");
        let Ok(()) = std::fs::write(&percorso, vec![0x25_u8; 2_048]) else {
            panic!("il file di prova si scrive");
        };
        let json = percorso.to_string_lossy().replace('\\', "\\\\");
        let risposta = |completo: bool| {
            format!(
                r#"{{"@type":"file","id":31,"local":{{"path":"{json}","is_downloading_completed":{completo}}}}}"#
            )
        };
        assert_eq!(
            read_downloaded_attachment(&risposta(true), 2_048).map(|b| b.len()),
            Ok(2_048)
        );
        assert!(
            read_downloaded_attachment(&risposta(false), 2_048).is_err(),
            "incompleto non si legge"
        );
        assert!(
            read_downloaded_attachment(&risposta(true), 2_047)
                .is_err_and(|perche| perche.contains("tetto")),
            "un byte oltre il tetto non si legge"
        );
        let _ = std::fs::remove_dir_all(&cartella);
    }
}

/// Gli iscritti di un gruppo dalle risposte di TDLib (MEMBERS-01, ADR-0201),
/// su risposte sintetiche.
#[cfg(test)]
mod iscritti {
    use super::{MemberRow, MemberSource, member_from, member_source, parse_member_page};
    use crate::members::MemberStatus;

    #[test]
    fn il_tipo_di_gruppo_si_legge_dalla_chat() {
        assert_eq!(
            member_source(
                r#"{"@type":"chat","id":-100,"type":{"@type":"chatTypeSupergroup","supergroup_id":77,"is_channel":false},"title":"x"}"#
            ),
            Some(MemberSource::Super(77))
        );
        assert_eq!(
            member_source(
                r#"{"@type":"chat","id":-5,"type":{"@type":"chatTypeBasicGroup","basic_group_id":5},"title":"x"}"#
            ),
            Some(MemberSource::Basic(5))
        );
        assert_eq!(
            member_source(
                r#"{"@type":"chat","id":9,"type":{"@type":"chatTypePrivate","user_id":9},"title":"x"}"#
            ),
            None
        );
    }

    #[test]
    fn una_pagina_da_le_persone_e_salta_le_chat() {
        let pagina = r#"{"@type":"chatMembers","total_count":3,"members":[
            {"@type":"chatMember","member_id":{"@type":"messageSenderUser","user_id":11},"inviter_user_id":99,"joined_chat_date":1700000000,"status":{"@type":"chatMemberStatusAdministrator","custom_title":"}{"}},
            {"@type":"chatMember","member_id":{"@type":"messageSenderChat","chat_id":-100},"inviter_user_id":0,"joined_chat_date":0,"status":{"@type":"chatMemberStatusMember"}},
            {"@type":"chatMember","member_id":{"@type":"messageSenderUser","user_id":12},"inviter_user_id":0,"joined_chat_date":0,"status":{"@type":"chatMemberStatusNuovo"}}
        ]}"#;
        let righe = parse_member_page(pagina);
        assert_eq!(
            righe,
            vec![
                MemberRow {
                    user_id: 11,
                    status: MemberStatus::Administrator,
                    joined_at_millis: Some(1_700_000_000_000),
                },
                MemberRow {
                    user_id: 12,
                    status: MemberStatus::Member,
                    joined_at_millis: None,
                },
            ]
        );
    }

    #[test]
    fn il_telefono_arriva_solo_mascherato_e_il_nome_si_compone() {
        let riga = MemberRow {
            user_id: 11,
            status: MemberStatus::Member,
            joined_at_millis: None,
        };
        let utente = r#"{"@type":"user","id":11,"first_name":"Ada","last_name":"Rossi","usernames":{"@type":"usernames","active_usernames":["ada_r"],"disabled_usernames":[],"editable_username":"ada_r"},"phone_number":"393331234567"}"#;
        let iscritto = member_from(riga, Some(utente));
        assert_eq!(iscritto.display_name.as_deref(), Some("Ada Rossi"));
        assert_eq!(iscritto.username.as_deref(), Some("ada_r"));
        assert_eq!(iscritto.masked_phone.as_deref(), Some("+••••••••••67"));
        assert!(!format!("{iscritto:?}").contains("393331234567"));

        let senza = member_from(riga, None);
        assert_eq!(senza.display_name, None);
        assert_eq!(senza.masked_phone, None);
        let nascosto = member_from(
            riga,
            Some(r#"{"@type":"user","id":11,"first_name":"Ada","phone_number":""}"#),
        );
        assert_eq!(nascosto.masked_phone, None);
    }
}

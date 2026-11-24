//! Astrazione del connettore.
//!
//! Il trait descrive che cosa il prodotto si aspetta da un connettore Telegram,
//! non come TDLib lo realizza. Serve a tre cose: permettere ai test di girare
//! senza rete e senza libreria; impedire che le strutture della libreria
//! filtrino nel resto dell'applicazione; consentire di sostituire il binding
//! senza riscrivere ciò che gli sta sopra.
//!
//! L'interfaccia è **sincrona**. L'applicazione non ha né richiede un runtime
//! asincrono, coerentemente con quanto già deciso per la persistenza: un
//! runtime introdotto per un solo consumatore sarebbe complessità e superficie
//! non giustificate.

use core::time::Duration;
use std::path::PathBuf;

use crate::auth::AuthorizationState;
use crate::chat::AccessibleChat;
use crate::error::{TelegramError, TelegramResult};
use crate::event::{ConnectionState, ConnectorEvent, IncomingMessage};
use crate::identifier::{ChatId, MessageId};
use crate::link::LinkOutcome;
use crate::relation::ContextMessage;
use crate::secret::{ApiHash, ApiId, LoginCode, PhoneNumber, TwoFactorPassword};

/// Parametri di avvio del client.
///
/// `Debug` è derivabile perché i due campi riservati redigono da sé il proprio
/// valore: la struttura non può stamparli nemmeno per errore.
#[derive(Debug)]
pub struct ClientParameters {
    /// Identificativo dell'applicazione.
    pub api_id: ApiId,
    /// Hash dell'applicazione.
    pub api_hash: ApiHash,
    /// Cartella in cui la libreria conserva il proprio stato.
    pub database_directory: PathBuf,
    /// Se usare l'infrastruttura di prova invece di quella di produzione.
    pub use_test_datacenter: bool,
    /// Versione dell'applicazione dichiarata alla piattaforma.
    pub application_version: String,
    /// Codice di lingua dichiarato alla piattaforma.
    pub system_language_code: String,
}

/// Attese massime applicate alle operazioni del connettore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// Attesa massima di un singolo evento.
    pub poll: Duration,
    /// Attesa massima per completare l'arresto ordinato.
    pub shutdown: Duration,
}

impl Timeouts {
    /// Attesa predefinita di un evento.
    pub const DEFAULT_POLL: Duration = Duration::from_secs(1);
    /// Attesa predefinita dell'arresto.
    pub const DEFAULT_SHUTDOWN: Duration = Duration::from_secs(10);
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            poll: Self::DEFAULT_POLL,
            shutdown: Self::DEFAULT_SHUTDOWN,
        }
    }
}

/// Connettore verso la piattaforma.
///
/// Le implementazioni non devono mai registrare nei log i valori riservati che
/// ricevono, né includerli negli errori restituiti.
pub trait TelegramConnector {
    /// Avvia il client con i parametri indicati.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il client è già stato arrestato o se
    /// l'inizializzazione non riesce.
    fn start(&mut self, parameters: &ClientParameters) -> TelegramResult<()>;

    /// Comunica il numero di telefono dell'account d'ufficio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo stato di autorizzazione non attende il
    /// numero.
    fn submit_phone_number(&mut self, phone: &PhoneNumber) -> TelegramResult<()>;

    /// Comunica il codice ricevuto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo stato di autorizzazione non attende il
    /// codice.
    fn submit_code(&mut self, code: &LoginCode) -> TelegramResult<()>;

    /// Comunica la password della verifica in due passaggi.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo stato di autorizzazione non attende la
    /// password.
    fn submit_password(&mut self, password: &TwoFactorPassword) -> TelegramResult<()>;

    /// Attende il prossimo evento.
    ///
    /// Restituisce `Ok(None)` quando non c'è nulla da consegnare e l'attesa non
    /// è scaduta: è la condizione normale di una fonte silenziosa e non un
    /// errore.
    ///
    /// # Errori
    ///
    /// Restituisce [`crate::TelegramError::Timeout`] se l'attesa scade e
    /// [`crate::TelegramError::Closed`] se il connettore è stato arrestato.
    fn poll_event(&mut self, timeout: Duration) -> TelegramResult<Option<ConnectorEvent>>;

    /// Elenca le chat a cui l'account ha **già** accesso.
    ///
    /// Non esiste alcuna operazione per cercare chat sulla piattaforma né per
    /// entrare in un gruppo: l'assenza è deliberata e fa parte del progetto.
    /// Vedere `crate::chat`.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'account non è autorizzato o se l'elenco non
    /// è ottenibile.
    fn accessible_chats(&mut self) -> TelegramResult<Vec<AccessibleChat>>;

    /// Legge una pagina di **cronologia già pubblicata** di una chat.
    ///
    /// Non entra in alcuna chat e non cerca nulla sulla piattaforma: legge ciò
    /// che l'account **vede già**, come farebbe scorrendo all'indietro la
    /// conversazione. È la stessa postura passiva di [`Self::accessible_chats`].
    ///
    /// `from_message_id` è l'identificativo da cui risalire; zero significa «dal
    /// più recente». La risposta va dal più recente al più vecchio, e non viene
    /// riordinata: chi la consuma sa che cosa farne, e riordinare in silenzio
    /// nasconderebbe quale sia l'ordine vero.
    ///
    /// **Chi conserva questi messaggi deve tenerli distinti da quelli
    /// osservati.** `published_at` e `acquired_at` restano due colonne diverse
    /// proprio per questo: l'archivio non deve affermare di aver osservato ciò
    /// che ha soltanto recuperato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'account non è autorizzato, se la chat non è
    /// accessibile o se la risposta non arriva.
    ///
    /// L'implementazione predefinita restituisce [`TelegramError::Closed`]:
    /// un connettore che non sa recuperare la cronologia deve **dirlo**, non
    /// restituire un elenco vuoto che si leggerebbe come «non c'era nulla».
    fn fetch_history(
        &mut self,
        chat_id: ChatId,
        from_message_id: i64,
        limit: u32,
    ) -> TelegramResult<Vec<IncomingMessage>> {
        let _ = (chat_id, from_message_id, limit);
        Err(TelegramError::Closed)
    }

    /// I messaggi che stanno **attorno** a uno, come Telegram li mostra adesso.
    ///
    /// # Che cosa restituisce, e che cosa non è
    ///
    /// È lo **stato corrente** della conversazione, letto ora. **Non è una
    /// prova**: la prova è ciò che l'archivio conserva, acquisito al momento in
    /// cui è stato pubblicato. Scorrere un contesto non trasforma in prova ciò
    /// che si vede, e il servizio che lo usa tiene le due cose separate per
    /// costruzione (CTX-02, e poi CTX-05 e CTX-06).
    ///
    /// # Postura passiva
    ///
    /// `getChatHistory` **legge** ciò che l'account già vede. Non entra in
    /// alcuna conversazione, non scrive, non reagisce: le richieste che lo
    /// farebbero sono vietate dal prodotto e una guardia le cerca nel sorgente
    /// (`crate::prohibitions`).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la richiesta non si può inviare, se Telegram la
    /// **rifiuta** (con il suo testo, per esempio una chat non più accessibile)
    /// o se il **tempo massimo** scade (`TelegramError::Timeout`). Una risposta
    /// riuscita senza messaggi **non è un errore**: è un contesto vuoto, e chi
    /// legge deve poterlo distinguere da un guasto (ADR-0151, decisione 5).
    ///
    /// # Perché non restituisce `IncomingMessage`
    ///
    /// Perché quel tipo attraversa l'acquisizione e diventa un contenuto
    /// **archiviato**, e da CTX-04 questo metodo porta anche le **relazioni**
    /// che Telegram dichiara adesso: risposta, inoltro e origine dell'inoltro,
    /// discussione, stato di modifica.
    ///
    /// Quelle relazioni si leggono ora e non si conservano. Se viaggiassero
    /// dentro `IncomingMessage` avrebbero una strada aperta verso la colonna
    /// dei fatti, accanto a un testo acquisito prima. [`ContextMessage`] le
    /// tiene in un campo che l'acquisizione non vede.
    fn fetch_context(
        &mut self,
        chat_id: ChatId,
        around: MessageId,
        before: u32,
        after: u32,
    ) -> TelegramResult<Vec<ContextMessage>>;

    /// Il collegamento **ufficiale** a un messaggio, chiesto a Telegram.
    ///
    /// # Perché si chiede e non si compone
    ///
    /// Perché il congelamento lo vieta: «**non si fabbrica** un collegamento
    /// che Telegram non fornisce». Un indirizzo composto dai due
    /// identificativi funziona per i membri di quella conversazione, ma è una
    /// **deduzione**, e in un archivio che ha valore probatorio starebbe nella
    /// stessa colonna di ciò che la fonte ha detto.
    ///
    /// # Perché al momento e non all'acquisizione
    ///
    /// Perché è una richiesta con risposta, e farne una per ogni messaggio
    /// acquisito costerebbe un giro di rete per riga. Si chiede quando serve —
    /// quando qualcuno vuole aprire quel messaggio — e non si conserva.
    ///
    /// # Errori
    ///
    /// Restituisce un errore soltanto se la richiesta non si può nemmeno
    /// inviare. Che Telegram non fornisca il collegamento **non è un errore**:
    /// è un esito, e [`LinkOutcome::NotProvided`] dice quale.
    fn message_link(
        &mut self,
        chat_id: ChatId,
        message_id: MessageId,
    ) -> TelegramResult<LinkOutcome>;

    /// Stato corrente dell'autorizzazione.
    fn authorization_state(&self) -> AuthorizationState;

    /// Stato corrente del collegamento.
    fn connection_state(&self) -> ConnectionState;

    /// Arresta il connettore in modo ordinato.
    ///
    /// Deve essere idempotente: chiamarlo su un connettore già arrestato non è
    /// un errore, perché l'arresto può essere richiesto da più percorsi durante
    /// la chiusura dell'applicazione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'arresto non può essere completato.
    fn shutdown(&mut self) -> TelegramResult<()>;

    /// La ricerca puntuale ufficiale (PR-09, ADR-0125), quando il connettore la
    /// offre.
    ///
    /// **Assente per ogni connettore che non è del prodotto**: la capacità è
    /// sigillata, e soltanto il connettore verso TDLib e quello simulato la
    /// restituiscono. Un connettore che non la offre lo dice restituendo
    /// `None`, e la ricerca non parte.
    fn official_lookup(&mut self) -> Option<&mut dyn crate::lookup::OfficialLookup> {
        None
    }

    /// La lettura di foto, biografia e stato di un account (PERSON-MEDIA-01,
    /// ADR-0174), quando il connettore la offre. Sigillata come la ricerca
    /// puntuale: `None` per ogni connettore che non è del prodotto.
    fn profile_media(&mut self) -> Option<&mut dyn crate::profile::ProfileMediaReader> {
        None
    }

    /// La lettura dei byte di un allegato (ATTACH-01, ADR-0177), quando il
    /// connettore la offre. Sigillata come la ricerca puntuale: `None` per
    /// ogni connettore che non è del prodotto.
    fn attachment_reader(&mut self) -> Option<&mut dyn crate::attachment::AttachmentReader> {
        None
    }

    /// La lettura degli iscritti di un gruppo (MEMBERS-01, ADR-0201), quando
    /// il connettore la offre. Sigillata come la ricerca puntuale: `None` per
    /// ogni connettore che non è del prodotto.
    fn members_reader(&mut self) -> Option<&mut dyn crate::members::MembersReader> {
        None
    }

    /// Una pagina di ricerca nei messaggi: **B** nelle chat dell'account, **C**
    /// dentro una chat indicata (NEXUM97-CYBER-SEARCH-01, ADR-0154).
    ///
    /// # Postura passiva
    ///
    /// `searchMessages` e `searchChatMessages` leggono; non entrano, non
    /// scrivono, non costano.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la richiesta non si può inviare, se Telegram la
    /// rifiuta (con il suo testo) o se il tempo massimo scade. Una risposta
    /// riuscita senza risultati **non è un errore**. Un connettore che non sa
    /// cercare lo dice con un errore: per difetto, nessuno lo sa.
    fn search_messages(
        &mut self,
        _query: &crate::search::SearchQuery,
    ) -> TelegramResult<crate::search::SearchPage> {
        Err(crate::error::TelegramError::Tdlib {
            reason: String::from("questo collegamento non offre la ricerca nei messaggi"),
        })
    }

    /// La quota della ricerca nei post pubblici per quelle parole
    /// (`getPublicPostSearchLimits`, CYBER-SEARCH-02, ADR-0161).
    ///
    /// Legge, non cerca e non costa. I servizi la chiedono **prima** di ogni
    /// pagina della ricerca D, e non cercano se la query non è gratuita.
    ///
    /// # Errori
    ///
    /// Come [`Self::search_messages`]. Un connettore che non sa leggerla lo
    /// dice con un errore: per difetto, nessuno lo sa, e la ricerca D non parte.
    fn public_post_limits(
        &mut self,
        _query: &str,
    ) -> TelegramResult<crate::search::PublicPostLimits> {
        Err(crate::error::TelegramError::Tdlib {
            reason: String::from("questo collegamento non offre la quota della ricerca pubblica"),
        })
    }
}

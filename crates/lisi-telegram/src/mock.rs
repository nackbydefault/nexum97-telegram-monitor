//! Connettore simulato, deterministico.
//!
//! Serve a provare tutto ciò che sta sopra al connettore senza rete, senza
//! credenziali e senza TDLib. È **deterministico**: non legge l'orologio, non
//! usa numeri casuali e non dorme. Un test che dipendesse dal tempo reale
//! fallirebbe a caso su una macchina carica, e un test che fallisce a caso
//! smette molto presto di essere letto.
//!
//! Il mock fa parte del codice di produzione del crate, non dei suoi test:
//! serve anche ai test degli altri crate. Vale quindi anche per lui il divieto
//! di `unwrap`, `expect` e `panic!`.

use core::time::Duration;

use crate::auth::{AuthorizationMachine, AuthorizationState};
use crate::chat::{AccessibleChat, ChatKind};
use crate::connector::{ClientParameters, TelegramConnector};
use crate::error::{TelegramError, TelegramResult};
use crate::event::{
    ConnectionState, ConnectorEvent, DeletedMessages, EditedMessage, IncomingMessage,
};
use crate::identifier::{ChatId, MessageId};
use crate::link::{LinkGap, LinkOutcome};
use crate::lookup::{LookupQuery, LookupReply, OfficialLookup};
use crate::queue::EventQueue;
use crate::secret::{LoginCode, PhoneNumber, TwoFactorPassword};

/// Chat sintetiche usate dal connettore simulato.
///
/// Sono **dati inventati** e dichiaratamente tali: nomi generici, nessun
/// riferimento a fonti reali. Servono a provare la configurazione delle fonti
/// senza un account, e coprono i tre tipi più il caso della chat accessibile
/// ma senza storico leggibile, che deve risultare non monitorabile.
fn synthetic_chats() -> Vec<AccessibleChat> {
    // L'ultimo campo è lo username: **non tutte** le chat sintetiche ne hanno
    // uno, e non è una svista. La maggior parte delle fonti reali private non
    // ce l'ha, e un insieme di prova in cui c'è sempre nasconderebbe proprio il
    // caso in cui l'interfaccia deve saper mostrare l'assenza.
    let described = [
        (
            -1_001_000_000_001_i64,
            "Canale di prova alfa",
            ChatKind::Channel,
            true,
            Some("canale_alfa"),
        ),
        (
            -1_001_000_000_002,
            "Canale di prova beta",
            ChatKind::Channel,
            true,
            Some("canale_beta"),
        ),
        (
            -1_002_000_000_001,
            "Gruppo di prova",
            ChatKind::Group,
            true,
            None,
        ),
        (
            -1_003_000_000_001,
            "Supergruppo di prova",
            ChatKind::Supergroup,
            true,
            Some("supergruppo_prova"),
        ),
        (
            -1_003_000_000_002,
            "Supergruppo senza storico",
            ChatKind::Supergroup,
            false,
            None,
        ),
    ];

    let mut chats = Vec::with_capacity(described.len());
    for (raw_id, title, kind, readable, username) in described {
        // Un identificativo non valido nei dati sintetici sarebbe un difetto di
        // questo file: viene semplicemente saltato invece di far cadere il mock.
        if let Ok(chat_id) = ChatId::try_new(raw_id) {
            chats.push(AccessibleChat {
                chat_id,
                title: String::from(title),
                kind,
                username: username.map(String::from),
                can_read_history: readable,
            });
        }
    }
    chats
}

/// Connettore simulato.
#[derive(Debug)]
pub struct MockTelegramConnector {
    machine: AuthorizationMachine,
    connection: ConnectionState,
    pending: EventQueue,
    planned_failures: Vec<TelegramError>,
    requires_two_factor: bool,
    started: bool,
    closed: bool,
    shutdown_calls: u32,
    /// Quante volte ancora il codice sarà rifiutato prima di essere accettato.
    codes_to_reject: u32,
    /// Quante volte ancora la password sarà rifiutata.
    passwords_to_reject: u32,
    /// Errore che farà fallire il prossimo avvio.
    start_failure: Option<TelegramError>,
    /// Chat sintetiche a cui l'account simulato risulta avere accesso.
    accessible: Vec<AccessibleChat>,
    /// Cronologia sintetica per chat, dal **più recente al più vecchio**.
    ///
    /// L'ordine è quello che `getChatHistory` restituisce davvero. Conservarla
    /// nell'ordine opposto avrebbe reso i test verdi su un ordinamento che il
    /// connettore reale non produce — è la stessa asimmetria doppio/reale già
    /// costata tre incidenti a questo progetto.
    history: Vec<(i64, Vec<IncomingMessage>)>,
    /// Le risposte simulate alle ricerche puntuali (PR-09), per ingresso.
    lookups: Vec<(LookupQuery, TelegramResult<LookupReply>)>,
    /// Quante ricerche puntuali sono state chieste: le prove verificano che
    /// nessuno ripeta da sé una richiesta.
    lookup_calls: u32,
    /// Le risposte simulate alle ricerche nei messaggi, nell'ordine (ADR-0154).
    searches: std::collections::VecDeque<TelegramResult<crate::search::SearchPage>>,
    /// Le ricerche chieste, nell'ordine.
    searched: Vec<crate::search::SearchQuery>,
    /// Le risposte simulate alla quota della ricerca D, nell'ordine (ADR-0161).
    limits: std::collections::VecDeque<TelegramResult<crate::search::PublicPostLimits>>,
    /// Le parole per cui la quota è stata chiesta, nell'ordine.
    limits_asked: Vec<String>,
    /// Le risposte simulate a foto, biografia e stato, per account
    /// (PERSON-MEDIA-01).
    profile_media: Vec<(i64, TelegramResult<crate::profile::ProfileMediaReply>)>,
    /// Quante letture di foto, biografia e stato sono state chieste.
    profile_media_calls: u32,
    /// Le risposte simulate agli allegati, per chat e messaggio (ATTACH-01).
    attachments: Vec<(
        (i64, i64),
        TelegramResult<crate::attachment::AttachmentReply>,
    )>,
    /// Quante letture di allegati sono state chieste.
    attachment_calls: u32,
    /// Le risposte simulate agli elenchi degli iscritti, per chat
    /// (MEMBERS-01).
    members: Vec<(i64, TelegramResult<crate::members::MembersReply>)>,
    /// Quanti elenchi degli iscritti sono stati chiesti.
    members_calls: u32,
}

impl MockTelegramConnector {
    /// Crea il connettore simulato con la capacità di coda predefinita.
    #[must_use]
    pub fn new() -> Self {
        Self::with_queue_capacity(EventQueue::DEFAULT_CAPACITY)
    }

    /// Crea il connettore simulato con la capacità di coda indicata.
    ///
    /// Una capacità piccola serve a provare il comportamento a coda piena.
    #[must_use]
    pub fn with_queue_capacity(capacity: usize) -> Self {
        Self {
            machine: AuthorizationMachine::new(),
            connection: ConnectionState::Offline,
            pending: EventQueue::with_capacity(capacity),
            planned_failures: Vec::new(),
            requires_two_factor: false,
            started: false,
            closed: false,
            shutdown_calls: 0,
            codes_to_reject: 0,
            passwords_to_reject: 0,
            start_failure: None,
            accessible: synthetic_chats(),
            // Vuota: il mock non inventa una cronologia. Chi prova il recupero
            // dichiara i messaggi che vuole vedere, e un test che non ne
            // dichiara nessuno prova il caso «non c'era nulla da recuperare»,
            // che è un caso vero.
            history: Vec::new(),
            lookups: Vec::new(),
            lookup_calls: 0,
            searches: std::collections::VecDeque::new(),
            searched: Vec::new(),
            limits: std::collections::VecDeque::new(),
            limits_asked: Vec::new(),
            profile_media: Vec::new(),
            profile_media_calls: 0,
            attachments: Vec::new(),
            attachment_calls: 0,
            members: Vec::new(),
            members_calls: 0,
        }
    }

    /// La risposta simulata a una ricerca puntuale (PR-09).
    ///
    /// Un ingresso senza risposta dichiarata riceve ciò che la piattaforma
    /// risponde per un dato che non fornisce: `404`. Il simulatore **non
    /// inventa profili**: chi prova un `Trovato` lo dichiara.
    pub fn set_lookup_reply(&mut self, query: LookupQuery, reply: TelegramResult<LookupReply>) {
        self.lookups.retain(|(esistente, _)| *esistente != query);
        self.lookups.push((query, reply));
    }

    /// La risposta simulata a foto, biografia e stato di un account
    /// (PERSON-MEDIA-01). Un account senza risposta dichiarata riceve il
    /// rifiuto di Telegram per un identificativo sconosciuto: il simulatore
    /// **non inventa profili**.
    pub fn set_profile_media_reply(
        &mut self,
        user_id: i64,
        reply: TelegramResult<crate::profile::ProfileMediaReply>,
    ) {
        self.profile_media
            .retain(|(esistente, _)| *esistente != user_id);
        self.profile_media.push((user_id, reply));
    }

    /// Quante letture di foto, biografia e stato sono state chieste.
    #[must_use]
    pub const fn profile_media_calls(&self) -> u32 {
        self.profile_media_calls
    }

    /// La risposta simulata all'elenco degli iscritti di una chat
    /// (MEMBERS-01). Una chat senza risposta dichiarata riceve il rifiuto di
    /// Telegram per una chat sconosciuta: il simulatore **non inventa
    /// iscritti**.
    pub fn set_members_reply(
        &mut self,
        chat_id: i64,
        reply: TelegramResult<crate::members::MembersReply>,
    ) {
        self.members.retain(|(esistente, _)| *esistente != chat_id);
        self.members.push((chat_id, reply));
    }

    /// Quanti elenchi degli iscritti sono stati chiesti.
    #[must_use]
    pub const fn members_calls(&self) -> u32 {
        self.members_calls
    }

    /// La risposta simulata all'allegato di un messaggio (ATTACH-01). Un
    /// messaggio senza risposta dichiarata riceve il rifiuto di Telegram per un
    /// messaggio sconosciuto: il simulatore **non inventa byte**.
    pub fn set_attachment_reply(
        &mut self,
        chat_id: i64,
        message_id: i64,
        reply: TelegramResult<crate::attachment::AttachmentReply>,
    ) {
        self.attachments
            .retain(|(esistente, _)| *esistente != (chat_id, message_id));
        self.attachments.push(((chat_id, message_id), reply));
    }

    /// Quante letture di allegati sono state chieste.
    #[must_use]
    pub const fn attachment_calls(&self) -> u32 {
        self.attachment_calls
    }

    /// Accoda la risposta simulata alla prossima ricerca nei messaggi.
    ///
    /// Senza risposta accodata, la ricerca riceve una pagina vuota: il
    /// simulatore **non inventa messaggi**.
    pub fn queue_search_reply(&mut self, reply: TelegramResult<crate::search::SearchPage>) {
        self.searches.push_back(reply);
    }

    /// Le ricerche nei messaggi chieste finora.
    #[must_use]
    pub fn searched(&self) -> &[crate::search::SearchQuery] {
        &self.searched
    }

    /// Accoda la risposta simulata alla prossima lettura della quota della
    /// ricerca D.
    ///
    /// Senza risposta accodata la lettura fallisce: il simulatore **non
    /// inventa una quota**, e la ricerca D non parte.
    pub fn queue_limits_reply(&mut self, reply: TelegramResult<crate::search::PublicPostLimits>) {
        self.limits.push_back(reply);
    }

    /// Le parole per cui la quota è stata chiesta finora.
    #[must_use]
    pub fn limits_asked(&self) -> &[String] {
        &self.limits_asked
    }

    /// Quante ricerche puntuali sono state chieste.
    #[must_use]
    pub const fn lookup_calls(&self) -> u32 {
        self.lookup_calls
    }

    /// Sostituisce l'elenco delle chat accessibili simulate.
    pub fn with_accessible_chats(mut self, chats: Vec<AccessibleChat>) -> Self {
        self.accessible = chats;
        self
    }

    /// Il prossimo avvio fallirà con l'errore indicato.
    ///
    /// Serve a provare i casi in cui la sessione non è accessibile o la rete
    /// manca: sono condizioni che nascono dal connettore, non dall'operatore.
    pub fn fail_next_start_with(&mut self, failure: TelegramError) {
        self.start_failure = Some(failure);
    }

    /// I prossimi `times` codici saranno rifiutati.
    ///
    /// Lo stato **resta** in attesa del codice: un codice sbagliato non
    /// interrompe l'accesso, lo fa ripetere.
    pub const fn reject_next_codes(&mut self, times: u32) {
        self.codes_to_reject = times;
    }

    /// Le prossime `times` password saranno rifiutate.
    pub const fn reject_next_passwords(&mut self, times: u32) {
        self.passwords_to_reject = times;
    }

    /// Simula la revoca della sessione da parte della piattaforma.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la transizione non è ammessa nello stato
    /// corrente.
    pub fn simulate_session_revoked(&mut self) -> TelegramResult<()> {
        self.connection = ConnectionState::Offline;
        let _ = self
            .pending
            .push(ConnectorEvent::Failure(TelegramError::SessionRevoked));
        self.advance(AuthorizationState::Failed)
    }

    /// Stabilisce se l'accesso simulato richiede la verifica in due passaggi.
    #[must_use]
    pub fn requiring_two_factor(mut self, required: bool) -> Self {
        self.requires_two_factor = required;
        self
    }

    /// Programma un errore che sarà restituito dalla prossima attesa.
    ///
    /// Gli errori programmati sono consumati nell'ordine in cui sono stati
    /// aggiunti e **precedono** gli eventi in coda: è così che si simula una
    /// caduta di rete che interrompe una consegna.
    pub fn plan_failure(&mut self, failure: TelegramError) {
        self.planned_failures.push(failure);
    }

    /// Accoda un evento che sarà consegnato dalle attese successive.
    ///
    /// # Errori
    ///
    /// Restituisce [`TelegramError::QueueFull`] se la coda è satura: è il
    /// comportamento reale del connettore e va potuto provare.
    pub fn enqueue(&mut self, event: ConnectorEvent) -> TelegramResult<()> {
        self.pending.push(event)
    }

    /// Aggiunge alla cronologia sintetica di una chat un messaggio già
    /// pubblicato, cioè uno che l'applicazione **non ha visto arrivare**.
    ///
    /// I messaggi vanno inseriti dal più recente al più vecchio, come li
    /// restituisce `getChatHistory`.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se gli identificativi non sono validi.
    pub fn push_history(
        &mut self,
        chat: i64,
        message: i64,
        text: &str,
        published_at_millis: i64,
    ) -> TelegramResult<()> {
        let entry = IncomingMessage {
            chat_id: ChatId::try_new(chat)?,
            message_id: MessageId::try_new(message)?,
            author: None,
            // Come per gli eventi dal vivo, il connettore simulato non finge un
            // autore: inventarne uno renderebbe i test verdi su un percorso che
            // il connettore reale percorre in modo diverso.
            author_identifier: None,
            author_username: None,
            text: text.to_owned(),
            published_at_millis,
            url: None,
            attachment: None,
        };

        if let Some((_, messages)) = self.history.iter_mut().find(|(id, _)| *id == chat) {
            messages.push(entry);
        } else {
            self.history.push((chat, vec![entry]));
        }
        Ok(())
    }

    /// Accoda la ricezione di un messaggio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se gli identificativi non sono validi o se la coda
    /// è satura.
    pub fn enqueue_message(
        &mut self,
        chat: i64,
        message: i64,
        text: &str,
        published_at_millis: i64,
    ) -> TelegramResult<()> {
        let event = ConnectorEvent::MessageReceived(IncomingMessage {
            chat_id: ChatId::try_new(chat)?,
            message_id: MessageId::try_new(message)?,
            author: None,
            // Il connettore simulato non finge un autore: inventarne uno
            // renderebbe i test verdi su un percorso che il connettore reale
            // percorre in modo diverso, ed e' la stessa asimmetria doppio/reale
            // gia' costata tre incidenti a questo progetto.
            author_identifier: None,
            author_username: None,
            text: text.to_owned(),
            published_at_millis,
            url: None,
            attachment: None,
        });
        self.enqueue(event)
    }

    /// Accoda la modifica di un messaggio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se gli identificativi non sono validi o se la coda
    /// è satura.
    pub fn enqueue_edit(
        &mut self,
        chat: i64,
        message: i64,
        text: &str,
        edited_at_millis: i64,
    ) -> TelegramResult<()> {
        let event = ConnectorEvent::MessageEdited(EditedMessage {
            chat_id: ChatId::try_new(chat)?,
            message_id: MessageId::try_new(message)?,
            text: text.to_owned(),
            edited_at_millis,
        });
        self.enqueue(event)
    }

    /// Accoda la cancellazione di uno o più messaggi.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se gli identificativi non sono validi o se la coda
    /// è satura.
    pub fn enqueue_deletion(
        &mut self,
        chat: i64,
        messages: &[i64],
        deleted_at_millis: i64,
    ) -> TelegramResult<()> {
        let mut message_ids = Vec::with_capacity(messages.len());
        for message in messages {
            message_ids.push(MessageId::try_new(*message)?);
        }

        let event = ConnectorEvent::MessagesDeleted(DeletedMessages {
            chat_id: ChatId::try_new(chat)?,
            message_ids,
            deleted_at_millis,
        });
        self.enqueue(event)
    }

    /// Simula la caduta del collegamento.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la coda è satura.
    pub fn simulate_network_drop(&mut self) -> TelegramResult<()> {
        self.connection = ConnectionState::Interrupted;
        self.enqueue(ConnectorEvent::Connection(ConnectionState::Interrupted))
    }

    /// Simula il ristabilirsi del collegamento.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la coda è satura.
    pub fn simulate_reconnection(&mut self) -> TelegramResult<()> {
        self.enqueue(ConnectorEvent::Connection(ConnectionState::Connecting))?;
        self.connection = ConnectionState::Online;
        self.enqueue(ConnectorEvent::Connection(ConnectionState::Online))
    }

    /// Numero di eventi rifiutati per coda piena.
    #[must_use]
    pub const fn rejected_events(&self) -> u64 {
        self.pending.rejected()
    }

    /// Numero di richieste di arresto ricevute.
    ///
    /// Serve a verificare che l'arresto sia idempotente.
    #[must_use]
    pub const fn shutdown_calls(&self) -> u32 {
        self.shutdown_calls
    }

    /// Applica una transizione e ne accoda la notifica.
    fn advance(&mut self, next: AuthorizationState) -> TelegramResult<()> {
        self.machine.transition_to(next)?;
        // Se la coda e' satura la transizione resta valida ma la notifica va
        // persa: e' esattamente il caso che il conteggio dei rifiuti serve a
        // rendere visibile, e non deve far fallire l'accesso.
        let _ = self.pending.push(ConnectorEvent::Authorization(next));
        Ok(())
    }

    fn ensure_open(&self) -> TelegramResult<()> {
        if self.closed {
            return Err(TelegramError::Closed);
        }
        Ok(())
    }
}

impl crate::lookup::sealed::Sealed for MockTelegramConnector {}

impl OfficialLookup for MockTelegramConnector {
    fn lookup(&mut self, query: &LookupQuery) -> TelegramResult<LookupReply> {
        self.ensure_open()?;
        self.machine.expect_state(AuthorizationState::Ready)?;
        self.lookup_calls = self.lookup_calls.saturating_add(1);
        self.lookups
            .iter()
            .find(|(richiesta, _)| richiesta == query)
            .map_or_else(
                || {
                    Ok(LookupReply::Refused {
                        code: 404,
                        message: String::from("Not Found"),
                    })
                },
                |(_, risposta)| risposta.clone(),
            )
    }
}

impl crate::attachment::AttachmentReader for MockTelegramConnector {
    fn fetch_attachment(
        &mut self,
        chat_id: i64,
        message_id: i64,
        // IL TETTO NON SI APPLICA QUI: il simulatore dà ciò che la prova ha
        // dichiarato, così la prova vede il servizio ricontrollare i byte.
        _max_bytes: u64,
    ) -> TelegramResult<crate::attachment::AttachmentReply> {
        use crate::attachment::AttachmentReply;

        self.ensure_open()?;
        self.machine.expect_state(AuthorizationState::Ready)?;
        self.attachment_calls = self.attachment_calls.saturating_add(1);
        self.attachments
            .iter()
            .find(|(chiave, _)| *chiave == (chat_id, message_id))
            .map_or_else(
                || {
                    Ok(AttachmentReply::Refused {
                        code: 400,
                        message: String::from("MESSAGE_ID_INVALID"),
                    })
                },
                |(_, risposta)| risposta.clone(),
            )
    }
}

impl crate::profile::ProfileMediaReader for MockTelegramConnector {
    fn read_profile_media(
        &mut self,
        user_id: i64,
    ) -> TelegramResult<crate::profile::ProfileMediaReply> {
        self.ensure_open()?;
        self.machine.expect_state(AuthorizationState::Ready)?;
        self.profile_media_calls = self.profile_media_calls.saturating_add(1);
        self.profile_media
            .iter()
            .find(|(account, _)| *account == user_id)
            .map_or_else(
                || {
                    Ok(crate::profile::ProfileMediaReply::Refused {
                        code: 400,
                        message: String::from("USER_ID_INVALID"),
                    })
                },
                |(_, risposta)| risposta.clone(),
            )
    }
}

impl crate::members::MembersReader for MockTelegramConnector {
    fn read_members(
        &mut self,
        chat_id: i64,
        max: usize,
    ) -> TelegramResult<crate::members::MembersReply> {
        use crate::members::{MAX_MEMBERS, MembersReply};

        self.ensure_open()?;
        self.machine.expect_state(AuthorizationState::Ready)?;
        self.members_calls = self.members_calls.saturating_add(1);
        let risposta = self
            .members
            .iter()
            .find(|(chat, _)| *chat == chat_id)
            .map_or_else(
                || {
                    Ok(MembersReply::Refused {
                        code: 400,
                        message: String::from("CHAT_ID_INVALID"),
                    })
                },
                |(_, risposta)| risposta.clone(),
            )?;
        // IL TETTO SI APPLICA ANCHE QUI: chi prova il servizio vede ciò che
        // vedrebbe dal connettore vero.
        Ok(match risposta {
            MembersReply::Found(mut elenco) => {
                let tetto = max.min(MAX_MEMBERS);
                if elenco.members.len() > tetto {
                    elenco.members.truncate(tetto);
                    elenco.stopped_at_cap = true;
                }
                MembersReply::Found(elenco)
            }
            altro => altro,
        })
    }
}

impl Default for MockTelegramConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl TelegramConnector for MockTelegramConnector {
    fn start(&mut self, _parameters: &ClientParameters) -> TelegramResult<()> {
        self.ensure_open()?;

        if let Some(failure) = self.start_failure.take() {
            // L'avvio fallito porta allo stato terminale di fallimento: la
            // sessione non e' utilizzabile e l'operatore va informato.
            self.advance(AuthorizationState::Failed)?;
            return Err(failure);
        }

        self.advance(AuthorizationState::WaitingForTdlibParameters)?;
        self.advance(AuthorizationState::WaitingForPhoneNumber)?;
        self.connection = ConnectionState::Connecting;
        let _ = self
            .pending
            .push(ConnectorEvent::Connection(ConnectionState::Connecting));
        self.started = true;
        Ok(())
    }

    fn submit_phone_number(&mut self, _phone: &PhoneNumber) -> TelegramResult<()> {
        self.ensure_open()?;
        self.machine
            .expect_state(AuthorizationState::WaitingForPhoneNumber)?;
        self.advance(AuthorizationState::WaitingForCode)
    }

    fn submit_code(&mut self, _code: &LoginCode) -> TelegramResult<()> {
        self.ensure_open()?;
        self.machine
            .expect_state(AuthorizationState::WaitingForCode)?;

        if self.codes_to_reject > 0 {
            self.codes_to_reject -= 1;
            // Nessuna transizione: si resta in attesa del codice, che e' cio'
            // che fa la piattaforma quando il codice e' sbagliato.
            return Err(TelegramError::CodeRejected);
        }

        if self.requires_two_factor {
            return self.advance(AuthorizationState::WaitingForPassword);
        }

        self.advance(AuthorizationState::Ready)?;
        self.connection = ConnectionState::Online;
        let _ = self
            .pending
            .push(ConnectorEvent::Connection(ConnectionState::Online));
        Ok(())
    }

    fn submit_password(&mut self, _password: &TwoFactorPassword) -> TelegramResult<()> {
        self.ensure_open()?;
        self.machine
            .expect_state(AuthorizationState::WaitingForPassword)?;

        if self.passwords_to_reject > 0 {
            self.passwords_to_reject -= 1;
            return Err(TelegramError::PasswordRejected);
        }

        self.advance(AuthorizationState::Ready)?;
        self.connection = ConnectionState::Online;
        let _ = self
            .pending
            .push(ConnectorEvent::Connection(ConnectionState::Online));
        Ok(())
    }

    fn poll_event(&mut self, _timeout: Duration) -> TelegramResult<Option<ConnectorEvent>> {
        if !self.closed && !self.planned_failures.is_empty() {
            let failure = self.planned_failures.remove(0);
            return Err(failure);
        }

        // Gli eventi già accettati restano leggibili anche dopo l'arresto: sono
        // stati acquisiti, e perderli renderebbe lo storico silenziosamente
        // incompleto proprio nel momento della chiusura. Solo a coda vuota
        // l'arresto diventa visibile al chiamante.
        if let Some(event) = self.pending.pop() {
            return Ok(Some(event));
        }

        self.ensure_open()?;
        Ok(None)
    }

    fn accessible_chats(&mut self) -> TelegramResult<Vec<AccessibleChat>> {
        self.ensure_open()?;
        // L'elenco richiede un account autorizzato: prima dell'accesso non
        // esiste nulla a cui l'account abbia accesso.
        self.machine.expect_state(AuthorizationState::Ready)?;
        Ok(self.accessible.clone())
    }

    fn fetch_history(
        &mut self,
        chat_id: ChatId,
        from_message_id: i64,
        limit: u32,
    ) -> TelegramResult<Vec<IncomingMessage>> {
        self.ensure_open()?;
        self.machine.expect_state(AuthorizationState::Ready)?;

        let Some((_, messages)) = self.history.iter().find(|(id, _)| *id == chat_id.get()) else {
            // Una chat senza cronologia sintetica risponde con nulla, che è
            // quello che fa la piattaforma per una conversazione vuota. Non è
            // un errore.
            return Ok(Vec::new());
        };

        // `from_message_id` zero significa «dal più recente»; altrimenti si
        // riparte **sotto** quell'identificativo, come fa `getChatHistory`. È la
        // convenzione su cui poggia la paginazione all'indietro, e sbagliarla
        // farebbe girare in tondo chi recupera.
        let start = if from_message_id == 0 {
            0
        } else {
            messages
                .iter()
                .position(|message| message.message_id.get() < from_message_id)
                .unwrap_or(messages.len())
        };

        let end = start.saturating_add(limit as usize).min(messages.len());
        Ok(messages.get(start..end).unwrap_or_default().to_vec())
    }

    fn authorization_state(&self) -> AuthorizationState {
        self.machine.state()
    }

    fn connection_state(&self) -> ConnectionState {
        self.connection
    }

    fn shutdown(&mut self) -> TelegramResult<()> {
        self.shutdown_calls = self.shutdown_calls.saturating_add(1);

        if self.closed {
            // Idempotente: l'arresto puo' essere richiesto da piu' percorsi
            // durante la chiusura dell'applicazione.
            return Ok(());
        }

        if !self.machine.state().is_final() {
            self.advance(AuthorizationState::Closing)?;
            self.advance(AuthorizationState::Closed)?;
        }

        self.connection = ConnectionState::Offline;
        let _ = self
            .pending
            .push(ConnectorEvent::Connection(ConnectionState::Offline));
        self.closed = true;
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

    /// La ricerca simulata: risponde con ciò che la prova ha accodato, oppure
    /// con una pagina vuota. Vuole l'account pronto, come quella vera.
    fn search_messages(
        &mut self,
        query: &crate::search::SearchQuery,
    ) -> TelegramResult<crate::search::SearchPage> {
        self.ensure_open()?;
        self.machine.expect_state(AuthorizationState::Ready)?;
        self.searched.push(query.clone());
        self.searches
            .pop_front()
            .unwrap_or_else(|| Ok(crate::search::SearchPage::default()))
    }

    fn public_post_limits(
        &mut self,
        query: &str,
    ) -> TelegramResult<crate::search::PublicPostLimits> {
        self.ensure_open()?;
        self.machine.expect_state(AuthorizationState::Ready)?;
        self.limits_asked.push(query.to_owned());
        self.limits.pop_front().unwrap_or_else(|| {
            Err(crate::error::TelegramError::Tdlib {
                reason: String::from("il simulatore non ha una quota da dichiarare"),
            })
        })
    }

    /// Il collegamento simulato: **il connettore finto non ne fornisce**.
    ///
    /// # Perché non ne inventa uno
    ///
    /// Perché il simulatore serve a provare il prodotto senza rete, e un
    /// collegamento inventato dal simulatore sarebbe indistinguibile da uno
    /// vero nel momento in cui qualcuno lo guardasse. Dire «Telegram non lo
    /// fornisce» è vero — questo connettore non parla con Telegram — ed è
    /// esattamente il caso che l'interfaccia deve saper gestire.
    fn message_link(
        &mut self,
        _chat_id: ChatId,
        _message_id: MessageId,
    ) -> TelegramResult<LinkOutcome> {
        Ok(LinkOutcome::NotProvided(LinkGap::ConnectorUnavailable))
    }

    /// Il contesto simulato: **il connettore finto non ne fornisce**.
    ///
    /// Un contesto inventato dal simulatore sarebbe indistinguibile da uno
    /// vero nel momento in cui qualcuno lo guardasse. Un elenco vuoto dice la
    /// verità: questo connettore non parla con Telegram.
    fn fetch_context(
        &mut self,
        _chat_id: ChatId,
        _around: MessageId,
        _before: u32,
        _after: u32,
    ) -> TelegramResult<Vec<crate::relation::ContextMessage>> {
        Ok(Vec::new())
    }
}

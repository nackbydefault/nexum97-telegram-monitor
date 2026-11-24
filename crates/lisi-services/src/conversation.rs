//! La conversazione attorno a un messaggio, **a pagine** (ADR-0151, DG-01).
//!
//! # Che cosa aggiunge al contesto
//!
//! [`crate::context`] legge una finestra fissa attorno a un messaggio: venti
//! prima e venti dopo. La pagina della conversazione parte da quella finestra e
//! permette di chiederne **altre**, un lato alla volta, fino a un tetto
//! dichiarato. Tutto il resto — la prova separata da ciò che si vede adesso, il
//! confronto fra i due testi, chi ha scritto, a che cosa si lega — resta di
//! [`crate::context`], e qui non si ricompone.
//!
//! # Guardare e caricare non scrivono niente
//!
//! Questo servizio legge l'archivio una volta, all'apertura, e poi chiede a
//! Telegram. Non riceve mai un archivio da modificare: le funzioni che caricano
//! non hanno nemmeno un `Database` fra i parametri. Una prova lo verifica sul
//! sorgente.
//!
//! # Che cosa si dice di ogni lato
//!
//! Sempre quanti messaggi sono caricati, e quale di queste condizioni vale:
//! se ne possono chiedere altri; Telegram non ne ha restituiti altri; è
//! raggiunto il tetto; l'ultima richiesta non è riuscita, e perché. «Non ne ha
//! restituiti altri» si dice **soltanto** quando una richiesta non aggiunge
//! nulla: una risposta più corta del chiesto non è la fine della conversazione,
//! è una risposta più corta.

use lisi_core::{ContentId, Timestamp};
use lisi_storage::Database;
use lisi_telegram::{ChatId, MessageId, TelegramConnector, TelegramError};

use crate::context::{self, ContextGap, MessageContext, ObservedMessage};
use crate::error::{ServiceError, ServiceResult};

/// Quanti messaggi si chiedono per volta, da un lato.
pub const PAGE: u32 = 20;

/// Quanti messaggi al massimo si caricano **per lato** in una stessa apertura.
///
/// # Perché un tetto
///
/// Perché la pagina si legge, e duecento messaggi per parte sono già più di
/// quanti una persona ne scorra cercando il senso di uno. Oltre, il comando si
/// ferma e lo dice: chi ha bisogno di leggere l'intera conversazione la apre su
/// Telegram, con il collegamento ufficiale quando c'è.
pub const MAX_PER_SIDE: usize = 200;

/// Da quale parte del messaggio si carica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Verso i messaggi più vecchi.
    Older,
    /// Verso i messaggi più recenti.
    Newer,
}

/// Perché una richiesta a Telegram non è riuscita.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreached {
    /// Telegram non ha risposto entro il tempo massimo.
    TimedOut {
        /// Il tempo atteso, in secondi interi arrotondati per eccesso.
        seconds: u64,
    },
    /// La rete non è disponibile.
    NetworkUnavailable,
    /// La fonte non è più accessibile a questo account.
    SourceNotAccessible,
    /// L'accesso dell'account è stato revocato.
    AccessRevoked,
    /// Un altro problema tecnico, di cui si dice la classe.
    Technical {
        /// La classe stabile dell'errore, la stessa dell'audit.
        kind: &'static str,
    },
}

impl Unreached {
    /// Riconosce il perché da un errore del connettore.
    ///
    /// # Il riconoscimento della fonte non accessibile
    ///
    /// Legge il messaggio d'errore di TDLib: «Chat not found»,
    /// `CHANNEL_PRIVATE`, `CHANNEL_INVALID`, `CHAT_FORBIDDEN`. È dichiarato in
    /// ADR-0151 ed è **da verificare dal vivo** (HVQ-116): un testo d'errore
    /// diverso cade in «problema tecnico», che non afferma nulla di falso.
    #[must_use]
    pub fn of(error: &TelegramError) -> Self {
        match error {
            TelegramError::Timeout { millis } => Self::TimedOut {
                seconds: millis.div_ceil(1_000),
            },
            TelegramError::NetworkUnavailable => Self::NetworkUnavailable,
            TelegramError::SessionRevoked => Self::AccessRevoked,
            TelegramError::Tdlib { reason } if e_una_fonte_non_accessibile(reason) => {
                Self::SourceNotAccessible
            }
            altro => Self::Technical { kind: altro.kind() },
        }
    }

    /// Che cosa è successo, detto a chi legge.
    #[must_use]
    pub fn as_sentence(self) -> String {
        match self {
            Self::TimedOut { seconds } => format!(
                "Telegram non ha risposto entro il tempo massimo di {seconds} secondi. I messaggi \
                 gi\u{e0} caricati restano; si pu\u{f2} riprovare."
            ),
            Self::NetworkUnavailable => String::from(
                "La rete non \u{e8} disponibile. I messaggi gi\u{e0} caricati restano; si pu\u{f2} \
                 riprovare quando torna.",
            ),
            Self::SourceNotAccessible => String::from(
                "Telegram dice che questa fonte non \u{e8} pi\u{f9} accessibile a questo account. \
                 Pu\u{f2} essere stata chiusa, oppure l'account non ne fa pi\u{f9} parte. Il \
                 contenuto dell'archivio resta quello che \u{e8}.",
            ),
            Self::AccessRevoked => String::from(
                "L'accesso dell'account a Telegram \u{e8} stato revocato: per leggere ancora serve \
                 un nuovo accesso. Il contenuto dell'archivio resta quello che \u{e8}.",
            ),
            Self::Technical { kind } => format!(
                "La richiesta a Telegram non \u{e8} riuscita per un problema tecnico ({kind}). I \
                 messaggi gi\u{e0} caricati restano; si pu\u{f2} riprovare."
            ),
        }
    }
}

/// Se un errore di TDLib dice che la conversazione non è più accessibile.
///
/// Le forme sono quelle inglesi di TDLib, confrontate per testo: sono
/// dichiarate in ADR-0151 e **da verificare dal vivo** (HVQ-116).
fn e_una_fonte_non_accessibile(reason: &str) -> bool {
    [
        "Chat not found",
        "CHAT_NOT_FOUND",
        "CHANNEL_PRIVATE",
        "CHANNEL_INVALID",
        "CHAT_FORBIDDEN",
    ]
    .iter()
    .any(|segno| reason.contains(segno))
}

/// Lo stato di un lato della conversazione.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SideState {
    /// Se ne possono chiedere altri.
    MayHaveMore,
    /// L'ultima richiesta non ha aggiunto alcun messaggio.
    NoMoreReturned,
    /// È raggiunto il tetto di [`MAX_PER_SIDE`].
    CapReached,
    /// L'ultima richiesta non è riuscita; si può ripetere.
    Failed(Unreached),
    /// Non si può chiedere: manca l'account, o il messaggio non ha
    /// identificativi che Telegram riconosca.
    CannotAsk,
}

impl SideState {
    /// Se il comando che carica questo lato ha senso.
    #[must_use]
    pub const fn can_load(self) -> bool {
        matches!(
            self,
            Self::MayHaveMore | Self::NoMoreReturned | Self::Failed(_)
        )
    }
}

/// Che cosa l'archivio sa del messaggio e della sua fonte.
///
/// Tutto viene **dall'archivio**: è ciò che fu acquisito, non ciò che Telegram
/// dice adesso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationFacts {
    /// Il nome della fonte.
    pub source_name: String,
    /// Che genere di fonte è: «Canale», «Gruppo», «Supergruppo».
    pub source_kind: &'static str,
    /// L'identificativo della fonte presso Telegram.
    pub source_identifier: String,
    /// Chi ha scritto il messaggio, come l'archivio lo conserva, in una frase.
    pub author: String,
    /// L'identificativo dell'autore, come l'archivio lo conserva; `None` per i
    /// messaggi di canale (GAP-12, ADR-0153).
    pub author_identifier: Option<String>,
    /// Il collegamento fornito da Telegram **all'acquisizione**, se c'è.
    ///
    /// Esiste soltanto per i contenuti acquisiti prima di LINK-01; dopo,
    /// l'acquisizione non ne conserva e il collegamento si chiede al momento.
    pub archived_url: Option<String>,
}

/// La conversazione attorno a un messaggio, come la pagina la mostra.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversation {
    /// La prova e tutto ciò che è stato caricato attorno, dal più vecchio.
    context: MessageContext,
    facts: ConversationFacts,
    /// La conversazione e il messaggio presso Telegram, se si possono chiedere.
    target: Option<(ChatId, i64)>,
    older: SideState,
    newer: SideState,
    /// Perché l'apertura non ha potuto leggere il contorno, quando è così.
    opening_failure: Option<Unreached>,
}

/// Apre la conversazione attorno a un contenuto dell'archivio.
///
/// Legge la prova e la finestra iniziale con [`context::read`]. Se la richiesta
/// a Telegram non riesce, **la pagina si apre lo stesso**: con la prova, la
/// lacuna [`ContextGap::RequestFailed`] e il perché.
///
/// # Errori
///
/// Restituisce un errore soltanto se l'archivio non si legge.
pub fn open(
    database: &Database,
    connector: Option<&mut dyn TelegramConnector>,
    content_id: ContentId,
    now: Timestamp,
) -> ServiceResult<Conversation> {
    let content = database.content(content_id)?;
    let source = database.source(content.source_id)?;

    let facts = ConversationFacts {
        source_name: source.display_name.as_str().to_owned(),
        source_kind: source.kind.label(),
        source_identifier: source.identifier.as_str().to_owned(),
        author: author_in_words(
            content.author.as_ref().map(lisi_core::text::Actor::as_str),
            content.author_username.as_deref(),
            content.author_identifier.as_deref(),
        ),
        archived_url: content.url.as_ref().map(|url| url.as_str().to_owned()),
        author_identifier: content
            .author_identifier
            .clone()
            .filter(|id| !id.trim().is_empty()),
    };

    let target = source
        .identifier
        .as_str()
        .parse::<i64>()
        .ok()
        .and_then(|chat| ChatId::try_new(chat).ok())
        .zip(
            content
                .remote_message_id
                .as_str()
                .parse::<i64>()
                .ok()
                .filter(|message| MessageId::try_new(*message).is_ok()),
        );

    let con_connettore = connector.is_some();
    let letto = context::read(
        database,
        connector,
        content_id,
        context::DEFAULT_WINDOW,
        context::DEFAULT_WINDOW,
        now,
    );

    let (context, opening_failure) = match letto {
        Ok(contesto) => (contesto, None),
        Err(ServiceError::Connector(errore)) => {
            // LA PAGINA SI APRE LO STESSO (ADR-0151, decisione 5): la prova e'
            // nell'archivio, e che Telegram non risponda non la toglie.
            let mut contesto = context::read(
                database,
                None,
                content_id,
                context::DEFAULT_WINDOW,
                context::DEFAULT_WINDOW,
                now,
            )?;
            contesto.gap = Some(ContextGap::RequestFailed);
            (contesto, Some(Unreached::of(&errore)))
        }
        Err(altro) => return Err(altro),
    };

    let iniziale = match (opening_failure, context.gap, target, con_connettore) {
        (Some(perche), _, _, _) => SideState::Failed(perche),
        (None, _, None, _) | (None, _, _, false) => SideState::CannotAsk,
        (None, Some(ContextGap::ConnectorUnavailable), _, _) => SideState::CannotAsk,
        (None, _, Some(_), true) => SideState::MayHaveMore,
    };

    let mut conversazione = Conversation {
        context,
        facts,
        target,
        older: iniziale,
        newer: iniziale,
        opening_failure,
    };
    conversazione.order();
    Ok(conversazione)
}

impl Conversation {
    /// La prova e tutto ciò che è caricato: è ciò che una fotografia conserva.
    #[must_use]
    pub const fn context(&self) -> &MessageContext {
        &self.context
    }

    /// Che cosa l'archivio sa del messaggio e della sua fonte.
    #[must_use]
    pub const fn facts(&self) -> &ConversationFacts {
        &self.facts
    }

    /// Se l'apertura non ha potuto leggere il contorno: allora caricare un lato
    /// non basta, e si riapre.
    #[must_use]
    pub const fn needs_reopen(&self) -> bool {
        self.opening_failure.is_some()
    }

    /// Lo stato di un lato.
    #[must_use]
    pub const fn side(&self, direction: Direction) -> SideState {
        match direction {
            Direction::Older => self.older,
            Direction::Newer => self.newer,
        }
    }

    /// Il numero del messaggio dell'avviso presso Telegram, se si legge.
    fn anchor_number(&self) -> Option<i64> {
        self.context.anchor.remote_message_id.parse::<i64>().ok()
    }

    /// I messaggi caricati da un lato, dal più vecchio al più recente.
    #[must_use]
    pub fn messages(&self, direction: Direction) -> Vec<&ObservedMessage> {
        let Some(ancora) = self.anchor_number() else {
            // Senza un numero dell'ancora non c'e' un «prima» e un «dopo»:
            // tutto cio' che c'e' sta prima, nell'ordine del tempo.
            return match direction {
                Direction::Older => self.context.surrounding.iter().collect(),
                Direction::Newer => Vec::new(),
            };
        };
        self.context
            .surrounding
            .iter()
            .filter(|messaggio| {
                numero(messaggio).is_some_and(|n| match direction {
                    Direction::Older => n < ancora,
                    Direction::Newer => n > ancora,
                })
            })
            .collect()
    }

    /// Il messaggio dell'avviso **come Telegram lo mostra adesso**, se è
    /// tornato.
    #[must_use]
    pub fn anchor_now(&self) -> Option<&ObservedMessage> {
        self.context
            .surrounding
            .iter()
            .find(|messaggio| messaggio.is_anchor)
    }

    /// Che cosa si sa di un lato, detto a chi legge.
    #[must_use]
    pub fn side_sentence(&self, direction: Direction) -> String {
        let quanti = self.messages(direction).len();
        let (parola, aggettivo) = match direction {
            Direction::Older => ("precedenti", "pi\u{f9} vecchi"),
            Direction::Newer => ("successivi", "pi\u{f9} recenti"),
        };
        let caricati = match quanti {
            0 => format!("Nessun messaggio {} caricato.", singolare(direction)),
            1 => format!("1 messaggio {} caricato.", singolare(direction)),
            n => format!("{n} messaggi {parola} caricati."),
        };
        let stato = match self.side(direction) {
            SideState::MayHaveMore => {
                format!("Se ne possono chiedere altri {PAGE} alla volta, fino a {MAX_PER_SIDE}.")
            }
            SideState::NoMoreReturned => format!(
                "Telegram non ha restituito messaggi {aggettivo} di questi: \u{e8} il limite di ci\u{f2} \
                 che questo account vede adesso. Si pu\u{f2} chiedere di nuovo."
            ),
            SideState::CapReached => format!(
                "Raggiunto il tetto di {MAX_PER_SIDE} messaggi per parte: per leggere oltre, la \
                 conversazione si apre su Telegram."
            ),
            SideState::Failed(perche) => perche.as_sentence(),
            SideState::CannotAsk => String::from(
                "Non se ne possono chiedere: serve un account collegato, e un messaggio che \
                 Telegram sappia ritrovare.",
            ),
        };
        format!("{caricati} {stato}")
    }

    /// Che cosa si sta guardando, e che cosa non è.
    ///
    /// È la frase di [`MessageContext::as_sentence`], con il perché quando
    /// l'apertura non è riuscita.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self.opening_failure {
            Some(perche) => format!("{} {}", self.context.as_sentence(), perche.as_sentence()),
            None => self.context.as_sentence(),
        }
    }

    /// Chiede a Telegram altri messaggi da un lato.
    ///
    /// Non riceve un archivio: caricare **non scrive**, e non ha come farlo.
    /// Una richiesta non riuscita **non toglie** ciò che è già caricato.
    ///
    /// Restituisce quanti messaggi nuovi sono stati aggiunti.
    pub fn load(
        &mut self,
        connector: Option<&mut dyn TelegramConnector>,
        direction: Direction,
    ) -> usize {
        let stato = self.side(direction);
        if !stato.can_load() {
            return 0;
        }
        let (Some(connector), Some((chat_id, ancora))) = (connector, self.target) else {
            self.set_side(direction, SideState::CannotAsk);
            return 0;
        };

        let gia = self.messages(direction).len();
        let restano = MAX_PER_SIDE.saturating_sub(gia);
        if restano == 0 {
            self.set_side(direction, SideState::CapReached);
            return 0;
        }
        let chiesti = u32::try_from(restano).unwrap_or(PAGE).min(PAGE);

        // DALL'ESTREMO GIA' MOSTRATO, non dall'ancora: si continua da dove la
        // pagina finisce, e la risposta comincia da quell'estremo stesso
        // (`getChatHistory` lo include), che si scarta come doppione.
        let numeri = self
            .messages(direction)
            .into_iter()
            .filter_map(numero)
            .collect::<Vec<_>>();
        let estremo = match direction {
            Direction::Older => numeri.iter().copied().min(),
            Direction::Newer => numeri.iter().copied().max(),
        }
        .unwrap_or(ancora);
        let Ok(da) = MessageId::try_new(estremo) else {
            self.set_side(direction, SideState::CannotAsk);
            return 0;
        };

        let (prima, dopo) = match direction {
            Direction::Older => (chiesti, 0),
            Direction::Newer => (0, chiesti),
        };
        let letti = match connector.fetch_context(chat_id, da, prima, dopo) {
            Ok(letti) => letti,
            Err(errore) => {
                self.set_side(direction, SideState::Failed(Unreached::of(&errore)));
                return 0;
            }
        };

        let noti: std::collections::BTreeSet<String> = self
            .context
            .surrounding
            .iter()
            .map(|messaggio| messaggio.remote_message_id.clone())
            .collect();
        let mut nuovi: Vec<ObservedMessage> = letti
            .into_iter()
            .map(|letto| context::observe(letto, ancora))
            .filter(|messaggio| {
                // SOLO DAL LATO CHIESTO: un messaggio dell'altra parte, o
                // l'estremo stesso, non e' una pagina nuova.
                numero(messaggio).is_some_and(|n| match direction {
                    Direction::Older => n < estremo,
                    Direction::Newer => n > estremo,
                }) && !noti.contains(&messaggio.remote_message_id)
            })
            .collect();

        // I PIU' VICINI PRIMA, se la risposta eccede cio' che resta sotto il
        // tetto: si taglia dal lato lontano, non a caso.
        nuovi.sort_by_key(|messaggio| numero(messaggio).unwrap_or_default());
        if direction == Direction::Older {
            nuovi.reverse();
        }
        nuovi.truncate(restano);

        let aggiunti = nuovi.len();
        self.context.surrounding.extend(nuovi);
        self.order();

        let stato = if aggiunti == 0 {
            SideState::NoMoreReturned
        } else if gia + aggiunti >= MAX_PER_SIDE {
            SideState::CapReached
        } else {
            SideState::MayHaveMore
        };
        self.set_side(direction, stato);
        aggiunti
    }

    fn set_side(&mut self, direction: Direction, stato: SideState) {
        match direction {
            Direction::Older => self.older = stato,
            Direction::Newer => self.newer = stato,
        }
    }

    /// Dal più vecchio al più recente: per istante, e a parità per numero.
    fn order(&mut self) {
        self.context.surrounding.sort_by_key(|messaggio| {
            (
                messaggio.published_at.as_millis(),
                numero(messaggio).unwrap_or_default(),
            )
        });
    }
}

/// Il numero di un messaggio presso Telegram.
fn numero(messaggio: &ObservedMessage) -> Option<i64> {
    messaggio.remote_message_id.parse::<i64>().ok()
}

const fn singolare(direction: Direction) -> &'static str {
    match direction {
        Direction::Older => "precedente",
        Direction::Newer => "successivo",
    }
}

/// Chi ha scritto il messaggio, **come l'archivio lo conserva**.
///
/// Senza identificativo non c'è una persona dichiarata: nei canali il mittente
/// è la fonte stessa, e dirlo è diverso dal tacerlo (ADR-0053).
fn author_in_words(
    nome: Option<&str>,
    username: Option<&str>,
    identificativo: Option<&str>,
) -> String {
    let nome = nome.filter(|nome| !nome.is_empty());
    let username = username.filter(|nome| !nome.is_empty());
    let Some(identificativo) = identificativo.filter(|id| !id.is_empty()) else {
        return match nome {
            Some(nome) => format!("{nome}, senza un identificativo dichiarato."),
            None => String::from(
                "Nessun autore individuale dichiarato: nei canali il messaggio \u{e8} pubblicato \
                 dalla fonte stessa.",
            ),
        };
    };
    match (nome, username) {
        (Some(nome), Some(username)) => {
            format!("{nome} (@{username}, identificativo {identificativo}).")
        }
        (Some(nome), None) => format!("{nome} (identificativo {identificativo})."),
        (None, Some(username)) => format!("@{username} (identificativo {identificativo})."),
        (None, None) => {
            format!("La persona con identificativo {identificativo}: il nome non fu dichiarato.")
        }
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::{AcquisitionOrigin, NewSession, NewSource, SessionDuration, SourceKind};
    use lisi_core::text::{Actor, ContentBody, DisplayName, RemoteMessageId, SourceIdentifier};
    use lisi_core::{ContentId, Timestamp};
    use lisi_storage::Database;
    use lisi_telegram::{
        AccessibleChat, AuthorizationState, ChatId, ClientParameters, ConnectionState,
        ConnectorEvent, ContextMessage, IncomingMessage, LinkGap, LinkOutcome, LoginCode,
        MessageId, MessageRelations, PhoneNumber, TelegramConnector, TelegramError, TelegramResult,
        TwoFactorPassword,
    };

    use super::{Direction, PAGE, SideState, Unreached, open};
    use crate::analysis::{AnalysisService, NewContentDraft};
    use crate::context::ContextGap;

    /// Questo modulo, per le guardie sul sorgente.
    const THIS_MODULE: &str = include_str!("conversation.rs");

    const ORA: i64 = 1_760_000_000_000;

    /// Il numero del messaggio dell'avviso nella conversazione simulata.
    const ANCORA: i64 = 500;

    /// Una conversazione simulata: i messaggi da `primo` a `ultimo`, uno al
    /// minuto, risposti con la regola di `getChatHistory` — dall'estremo
    /// indicato, incluso, `before` più vecchi e `after` più recenti.
    #[derive(Debug)]
    struct ConversazioneFinta {
        primo: i64,
        ultimo: i64,
        /// Se presente, ogni richiesta fallisce con questo errore.
        guasto: Option<TelegramError>,
        /// Quante risposte si accorciano: utile a provare che una risposta
        /// corta non e' la fine.
        al_massimo: Option<usize>,
        /// Le richieste ricevute: (attorno, prima, dopo).
        chieste: Vec<(i64, u32, u32)>,
    }

    impl ConversazioneFinta {
        fn da(primo: i64, ultimo: i64) -> Self {
            Self {
                primo,
                ultimo,
                guasto: None,
                al_massimo: None,
                chieste: Vec::new(),
            }
        }
    }

    fn messaggio(id: i64) -> ContextMessage {
        let (Ok(chat_id), Ok(message_id)) = (ChatId::try_new(-1001), MessageId::try_new(id)) else {
            panic!("gli identificativi di prova devono essere validi");
        };
        ContextMessage {
            message: IncomingMessage {
                chat_id,
                message_id,
                author: Some(format!("Persona {id}")),
                author_identifier: Some(format!("{}", 9000 + id)),
                author_username: None,
                text: format!("messaggio {id}"),
                published_at_millis: ORA + id * 60_000,
                url: None,
                attachment: None,
            },
            relations: MessageRelations::default(),
        }
    }

    impl TelegramConnector for ConversazioneFinta {
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
        fn poll_event(
            &mut self,
            _timeout: std::time::Duration,
        ) -> TelegramResult<Option<ConnectorEvent>> {
            Ok(None)
        }
        fn accessible_chats(&mut self) -> TelegramResult<Vec<AccessibleChat>> {
            Ok(Vec::new())
        }
        fn fetch_history(
            &mut self,
            _chat_id: ChatId,
            _from_message_id: i64,
            _limit: u32,
        ) -> TelegramResult<Vec<IncomingMessage>> {
            Ok(Vec::new())
        }
        fn fetch_context(
            &mut self,
            _chat_id: ChatId,
            around: MessageId,
            before: u32,
            after: u32,
        ) -> TelegramResult<Vec<ContextMessage>> {
            self.chieste.push((around.get(), before, after));
            if let Some(guasto) = self.guasto.clone() {
                return Err(guasto);
            }
            let da = (around.get() - i64::from(before)).max(self.primo);
            let a = (around.get() + i64::from(after)).min(self.ultimo);
            // Dal piu' recente al piu' vecchio, come `getChatHistory`.
            let mut risposta: Vec<ContextMessage> = (da..=a).rev().map(messaggio).collect();
            if let Some(quanti) = self.al_massimo {
                risposta.truncate(quanti);
            }
            Ok(risposta)
        }
        fn message_link(
            &mut self,
            _chat_id: ChatId,
            _message_id: MessageId,
        ) -> TelegramResult<LinkOutcome> {
            Ok(LinkOutcome::NotProvided(LinkGap::ConnectorUnavailable))
        }
        fn authorization_state(&self) -> AuthorizationState {
            AuthorizationState::Ready
        }
        fn connection_state(&self) -> ConnectionState {
            ConnectionState::Online
        }
        fn shutdown(&mut self) -> TelegramResult<()> {
            Ok(())
        }
    }

    /// Un archivio con il messaggio 500 di un canale, acquisito.
    fn archivio() -> (Database, ContentId) {
        let Ok(mut database) = crate::sources::open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        let (Ok(identifier), Ok(title), Ok(label), Ok(attore)) = (
            SourceIdentifier::try_new("-1001"),
            DisplayName::try_new("Canale di prova"),
            DisplayName::try_new("Sessione di prova"),
            Actor::try_new("operatore.prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(source_id) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier,
                display_name: title,
                authorized_by: attore.clone(),
                active: true,
            },
            Timestamp::from_millis(ORA),
        ) else {
            panic!("la fonte deve potersi registrare");
        };
        let Ok(session_id) = database.insert_session(
            &NewSession {
                label,
                started_by: attore.clone(),
                duration: SessionDuration::Preset { seconds: 3_600 },
                source_ids: vec![source_id],
            },
            Timestamp::from_millis(ORA),
        ) else {
            panic!("la sessione deve potersi creare");
        };
        let (Ok(remote), Ok(body)) = (
            RemoteMessageId::try_new("500"),
            ContentBody::try_new("messaggio 500"),
        ) else {
            panic!("i valori del contenuto devono essere validi");
        };
        let mut analysis = AnalysisService::new(database);
        let Ok(record) = analysis.analyse_and_record(
            &NewContentDraft {
                session_id,
                source_id,
                remote_message_id: remote,
                author: None,
                author_identifier: None,
                author_username: None,
                body,
                url: None,
                published_at: Timestamp::from_millis(ORA + ANCORA * 60_000),
                acquired_at: Timestamp::from_millis(ORA + ANCORA * 60_000 + 1_000),
                origin: AcquisitionOrigin::Observed,
            },
            &lisi_core::model::dictionary::ResolvedDictionaryConfiguration::from_terms(Vec::new()),
            &attore,
            Timestamp::from_millis(ORA),
        ) else {
            panic!("l'analisi deve riuscire");
        };
        let Some(content_id) = record.content_id else {
            panic!("il contenuto doveva essere registrato");
        };
        (analysis.into_database(), content_id)
    }

    fn numeri(conversazione: &super::Conversation, direction: Direction) -> Vec<i64> {
        conversazione
            .messages(direction)
            .into_iter()
            .filter_map(|messaggio| messaggio.remote_message_id.parse().ok())
            .collect()
    }

    /// **Si apre centrata sul messaggio**: venti prima, il messaggio, venti
    /// dopo, in ordine di tempo, e il messaggio si riconosce.
    #[test]
    fn si_apre_centrata_sul_messaggio_dell_avviso() {
        let (database, id) = archivio();
        let mut telegram = ConversazioneFinta::da(1, 1_000);
        let Ok(conversazione) = open(
            &database,
            Some(&mut telegram),
            id,
            Timestamp::from_millis(ORA),
        ) else {
            panic!("la conversazione deve aprirsi");
        };

        assert_eq!(
            numeri(&conversazione, Direction::Older),
            (480..500).collect::<Vec<_>>()
        );
        assert_eq!(
            numeri(&conversazione, Direction::Newer),
            (501..=520).collect::<Vec<_>>()
        );
        let Some(ancora) = conversazione.anchor_now() else {
            panic!("il messaggio dell'avviso deve essere tornato");
        };
        assert_eq!(ancora.remote_message_id, "500");
        assert_eq!(conversazione.side(Direction::Older), SideState::MayHaveMore);
        assert_eq!(conversazione.side(Direction::Newer), SideState::MayHaveMore);
        assert_eq!(conversazione.facts().source_name, "Canale di prova");
        assert_eq!(conversazione.facts().source_kind, "Canale");
        assert!(
            conversazione
                .facts()
                .author
                .contains("pubblicato dalla fonte"),
            "un messaggio di canale senza autore lo dice: {}",
            conversazione.facts().author
        );
    }

    /// **Le pagine continuano dagli estremi, senza doppioni.**
    #[test]
    fn le_pagine_continuano_dagli_estremi_senza_doppioni() {
        let (database, id) = archivio();
        let mut telegram = ConversazioneFinta::da(1, 1_000);
        let Ok(mut conversazione) = open(
            &database,
            Some(&mut telegram),
            id,
            Timestamp::from_millis(ORA),
        ) else {
            panic!("la conversazione deve aprirsi");
        };

        assert_eq!(
            conversazione.load(Some(&mut telegram), Direction::Older),
            20
        );
        assert_eq!(
            conversazione.load(Some(&mut telegram), Direction::Newer),
            20
        );
        assert_eq!(
            numeri(&conversazione, Direction::Older),
            (460..500).collect::<Vec<_>>()
        );
        assert_eq!(
            numeri(&conversazione, Direction::Newer),
            (501..=540).collect::<Vec<_>>()
        );
        assert_eq!(
            telegram.chieste.get(1..),
            Some(&[(480, PAGE, 0), (520, 0, PAGE)][..]),
            "si chiede dal piu' vecchio e dal piu' recente gia' mostrati"
        );

        // Tutto in ordine di tempo, e nessun messaggio due volte.
        let tutti: Vec<&str> = conversazione
            .context()
            .surrounding
            .iter()
            .map(|m| m.remote_message_id.as_str())
            .collect();
        let mut unici = tutti.clone();
        unici.dedup();
        assert_eq!(tutti, unici);
        assert_eq!(tutti.len(), 40 + 1 + 40);
    }

    /// **Oltre il tetto il comando si ferma e lo dice** (prova negativa del
    /// criterio 4: con il tetto tolto, la conversazione supererebbe 200).
    #[test]
    fn oltre_il_tetto_il_comando_si_ferma_e_lo_dice() {
        let (database, id) = archivio();
        let mut telegram = ConversazioneFinta::da(1, 1_000);
        let Ok(mut conversazione) = open(
            &database,
            Some(&mut telegram),
            id,
            Timestamp::from_millis(ORA),
        ) else {
            panic!("la conversazione deve aprirsi");
        };

        for _ in 0..20 {
            conversazione.load(Some(&mut telegram), Direction::Older);
        }
        assert_eq!(conversazione.messages(Direction::Older).len(), 200);
        assert_eq!(conversazione.side(Direction::Older), SideState::CapReached);
        let richieste = telegram.chieste.len();
        assert_eq!(conversazione.load(Some(&mut telegram), Direction::Older), 0);
        assert_eq!(
            telegram.chieste.len(),
            richieste,
            "al tetto non si chiede piu' nulla a Telegram"
        );
        assert!(
            conversazione
                .side_sentence(Direction::Older)
                .contains("Raggiunto il tetto di 200")
        );
        // L'altro lato non ne risente.
        assert_eq!(conversazione.side(Direction::Newer), SideState::MayHaveMore);
    }

    /// **Una risposta corta non è la fine; una risposta vuota sì.**
    #[test]
    fn una_risposta_corta_non_e_la_fine() {
        let (database, id) = archivio();
        let mut telegram = ConversazioneFinta::da(470, 1_000);
        let Ok(mut conversazione) = open(
            &database,
            Some(&mut telegram),
            id,
            Timestamp::from_millis(ORA),
        ) else {
            panic!("la conversazione deve aprirsi");
        };

        // Dal 480 si chiedono venti piu' vecchi e ne arrivano dieci (470…479).
        assert_eq!(
            conversazione.load(Some(&mut telegram), Direction::Older),
            10
        );
        assert_eq!(conversazione.side(Direction::Older), SideState::MayHaveMore);
        // Dal 470 non arriva nulla di nuovo: solo allora si dice.
        assert_eq!(conversazione.load(Some(&mut telegram), Direction::Older), 0);
        assert_eq!(
            conversazione.side(Direction::Older),
            SideState::NoMoreReturned
        );
        assert!(
            conversazione
                .side_sentence(Direction::Older)
                .contains("non ha restituito messaggi pi\u{f9} vecchi")
        );
    }

    /// **Una richiesta non riuscita lascia ciò che c'è, dice il perché, e si
    /// ripete.**
    #[test]
    fn una_richiesta_non_riuscita_non_toglie_nulla() {
        let (database, id) = archivio();
        let mut telegram = ConversazioneFinta::da(1, 1_000);
        let Ok(mut conversazione) = open(
            &database,
            Some(&mut telegram),
            id,
            Timestamp::from_millis(ORA),
        ) else {
            panic!("la conversazione deve aprirsi");
        };

        telegram.guasto = Some(TelegramError::Timeout { millis: 5_000 });
        assert_eq!(conversazione.load(Some(&mut telegram), Direction::Newer), 0);
        assert_eq!(numeri(&conversazione, Direction::Newer).len(), 20);
        assert_eq!(
            conversazione.side(Direction::Newer),
            SideState::Failed(Unreached::TimedOut { seconds: 5 })
        );
        assert!(
            conversazione
                .side_sentence(Direction::Newer)
                .contains("tempo massimo di 5 secondi")
        );

        telegram.guasto = None;
        assert_eq!(
            conversazione.load(Some(&mut telegram), Direction::Newer),
            20
        );
        assert_eq!(conversazione.side(Direction::Newer), SideState::MayHaveMore);
    }

    /// **Se Telegram non risponde all'apertura, la pagina si apre lo stesso**,
    /// con la prova e il perché.
    #[test]
    fn se_telegram_non_risponde_la_pagina_si_apre_con_la_prova() {
        let (database, id) = archivio();
        let mut telegram = ConversazioneFinta::da(1, 1_000);
        telegram.guasto = Some(TelegramError::Tdlib {
            reason: String::from("errore del componente per Telegram 400: Chat not found"),
        });
        let Ok(conversazione) = open(
            &database,
            Some(&mut telegram),
            id,
            Timestamp::from_millis(ORA),
        ) else {
            panic!("la pagina deve aprirsi anche quando Telegram non risponde");
        };

        assert_eq!(conversazione.context().gap, Some(ContextGap::RequestFailed));
        assert_eq!(conversazione.context().anchor.body, "messaggio 500");
        assert!(conversazione.needs_reopen());
        assert_eq!(
            conversazione.side(Direction::Older),
            SideState::Failed(Unreached::SourceNotAccessible)
        );
        let frase = conversazione.as_sentence();
        assert!(
            frase.contains("non \u{e8} pi\u{f9} accessibile a questo account"),
            "{frase}"
        );
        assert!(frase.contains("resta quello che \u{e8}"), "{frase}");
    }

    /// **Senza account si vede la prova, e non si chiede nulla.**
    #[test]
    fn senza_account_si_vede_la_prova_e_non_si_chiede() {
        let (database, id) = archivio();
        let Ok(mut conversazione) = open(&database, None, id, Timestamp::from_millis(ORA)) else {
            panic!("la pagina deve aprirsi anche senza account");
        };
        assert_eq!(
            conversazione.context().gap,
            Some(ContextGap::ConnectorUnavailable)
        );
        assert_eq!(conversazione.side(Direction::Older), SideState::CannotAsk);
        assert_eq!(conversazione.load(None, Direction::Older), 0);
        assert!(
            conversazione
                .side_sentence(Direction::Newer)
                .contains("serve un account collegato")
        );
        // Trovato guardando la pagina: «Nessun messaggio precedenti caricato».
        assert!(
            conversazione
                .side_sentence(Direction::Older)
                .starts_with("Nessun messaggio precedente caricato."),
            "{}",
            conversazione.side_sentence(Direction::Older)
        );
    }

    /// **La fonte non accessibile si riconosce, il resto non si inventa.**
    #[test]
    fn i_perche_si_riconoscono_senza_inventare() {
        assert_eq!(
            Unreached::of(&TelegramError::Tdlib {
                reason: String::from("errore 400: CHANNEL_PRIVATE"),
            }),
            Unreached::SourceNotAccessible
        );
        assert_eq!(
            Unreached::of(&TelegramError::NetworkUnavailable),
            Unreached::NetworkUnavailable
        );
        assert_eq!(
            Unreached::of(&TelegramError::SessionRevoked),
            Unreached::AccessRevoked
        );
        assert!(matches!(
            Unreached::of(&TelegramError::Tdlib {
                reason: String::from("errore 500: qualcos'altro"),
            }),
            Unreached::Technical { .. }
        ));
    }

    /// **Guardare e caricare non scrivono niente.**
    ///
    /// Il caricamento non riceve nemmeno un archivio; l'apertura lo riceve in
    /// sola lettura, e nel sorgente non c'è alcuna chiamata che scrive.
    #[test]
    fn guardare_e_caricare_non_scrivono_niente() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let codice: String = produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(codice.contains("database: &Database,"));
        assert!(
            !codice.contains("&mut Database"),
            "l'archivio non si riceve per scrivere"
        );
        for scrittura in [
            "insert_",
            "append_audit",
            "record(",
            "save_",
            "update_",
            "delete_",
            "send_message",
            "forward",
            "join",
        ] {
            assert!(
                !codice.contains(scrittura),
                "la conversazione chiama «{scrittura}»: guardare non scrive"
            );
        }
        let Some(inizio) = codice.find("pub fn load(") else {
            panic!("il caricamento deve esistere");
        };
        let Some(fine) = codice[inizio..].find(") -> usize {") else {
            panic!("la firma deve chiudersi");
        };
        assert!(
            !codice[inizio..inizio + fine].contains("Database"),
            "caricare non riceve un archivio"
        );
    }
}

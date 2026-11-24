//! Traduzione dagli eventi del connettore ai modelli di dominio.
//!
//! È il solo punto in cui il mondo remoto diventa dominio. La validazione non è
//! duplicata qui: i limiti di lunghezza, la sanitizzazione degli URL e il
//! rifiuto dei caratteri di controllo appartengono a `lisi-core`, e un contenuto
//! oltre misura viene respinto dal tipo del dominio, non da un controllo scritto
//! due volte che potrebbe divergere.
//!
//! L'interfaccia grafica non vede né questo modulo né la libreria: vede i tipi
//! di `lisi-core`.

use lisi_core::model::{AcquisitionOrigin, AnalysisLevel, NewContent};
use lisi_core::text::{Actor, ContentBody, ContentUrl, RemoteMessageId};
use lisi_core::{SessionId, SourceId, Timestamp};

use crate::error::{TelegramError, TelegramResult};
use crate::event::{EditedMessage, IncomingMessage};
use crate::identifier::{ChatId, MessageId};

/// Traduce un messaggio acquisito in un contenuto del dominio.
///
/// La sessione e la fonte non provengono dalla piattaforma ma dal contesto di
/// acquisizione: è l'applicazione a sapere per quale sessione e quale fonte
/// selezionata sta acquisendo, e la persistenza rifiuterà comunque la
/// combinazione se la fonte non era stata selezionata.
///
/// origin dichiara se il messaggio è stato **visto arrivare** o **ritrovato**
/// nella cronologia: è un'affermazione dell'archivio su ciò che ha fatto, e la
/// conosce solo chi ha chiesto il messaggio.
///
/// Il livello di analisi assegnato è 0: il contenuto è registrato prima di
/// essere analizzato, e resterà registrato anche se l'analisi lo giudicherà non
/// rilevante.
///
/// # Errori
///
/// Restituisce [`TelegramError::UnacceptableContent`] se il messaggio non
/// rispetta le invarianti del dominio: testo oltre misura, autore con caratteri
/// di controllo, URL con schema non ammesso.
pub fn to_new_content(
    message: &IncomingMessage,
    session_id: SessionId,
    source_id: SourceId,
    acquired_at: Timestamp,
    origin: AcquisitionOrigin,
) -> TelegramResult<NewContent> {
    let author = match message.author.as_deref() {
        Some(raw) => Some(Actor::try_new(raw)?),
        None => None,
    };
    let url = match message.url.as_deref() {
        Some(raw) => Some(ContentUrl::try_new(raw)?),
        None => None,
    };

    Ok(NewContent {
        session_id,
        source_id,
        remote_message_id: RemoteMessageId::try_new(&message.message_id.get().to_string())?,
        author,
        // L'identificativo passa **non validato attraverso `Actor`**, e non è
        // una dimenticanza: `Actor` è un nome di persona e ne applica le
        // regole. Qui il valore è generato da noi — sole cifre, prodotte da
        // `author::author_identifier` — e farlo passare per un tipo che
        // significa un'altra cosa renderebbe meno chiaro, non più sicuro, ciò
        // che questo campo contiene.
        author_identifier: message.author_identifier.clone(),
        author_username: None,
        body: ContentBody::try_new(&message.text)?,
        url,
        published_at: Timestamp::from_millis(message.published_at_millis),
        acquired_at,
        // L'origine la decide **chi chiama**, e non questa funzione: la stessa
        // traduzione serve l'aggiornamento dal vivo e la pagina di cronologia,
        // e fissarla qui avrebbe fatto attestare come osservato cio' che era
        // stato soltanto ritrovato.
        origin,
        analysis_level: AnalysisLevel::NOT_RELEVANT,
    })
}

/// Traduce il testo di una modifica in un corpo del dominio.
///
/// La modifica non produce un nuovo contenuto: aggiorna quello esistente. La
/// registrazione della revisione dello storico è lavoro della milestone che
/// introduce l'acquisizione; qui si valida soltanto il testo.
///
/// # Errori
///
/// Restituisce [`TelegramError::UnacceptableContent`] se il testo non rispetta
/// le invarianti del dominio.
pub fn to_edited_body(edit: &EditedMessage) -> TelegramResult<ContentBody> {
    Ok(ContentBody::try_new(&edit.text)?)
}

/// Identificativo remoto conservato nella persistenza per un messaggio.
///
/// La forma testuale è quella scritta in `contents.remote_message_id`: la
/// funzione esiste perché quella conversione avvenga in un solo punto.
///
/// # Errori
///
/// Restituisce un errore se l'identificativo non è rappresentabile.
pub fn remote_message_id(message_id: MessageId) -> TelegramResult<RemoteMessageId> {
    Ok(RemoteMessageId::try_new(&message_id.get().to_string())?)
}

/// Sorveglia l'ordine di arrivo dei messaggi di una chat.
///
/// Gli aggiornamenti vanno applicati nell'ordine in cui sono ricevuti. Un
/// messaggio con un identificativo non superiore all'ultimo accettato indica
/// una consegna fuori sequenza: il fatto va **segnalato**, perché una
/// riconnessione può farlo accadere e uno storico ricostruito nell'ordine
/// sbagliato sarebbe fuorviante.
#[derive(Debug, Default)]
pub struct SequenceGuard {
    last_seen: Vec<(ChatId, i64)>,
}

impl SequenceGuard {
    /// Crea la sentinella senza alcuna chat osservata.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last_seen: Vec::new(),
        }
    }

    /// Registra un messaggio, verificando che segua quelli già visti.
    ///
    /// # Errori
    ///
    /// Restituisce [`TelegramError::OutOfOrder`] se l'identificativo non è
    /// successivo all'ultimo accettato per quella chat. Lo stato interno resta
    /// invariato: l'ultimo identificativo accettato non arretra.
    pub fn accept(&mut self, chat_id: ChatId, message_id: MessageId) -> TelegramResult<()> {
        let value = message_id.get();

        if let Some(entry) = self.last_seen.iter_mut().find(|(chat, _)| *chat == chat_id) {
            if value <= entry.1 {
                return Err(TelegramError::OutOfOrder { last: entry.1 });
            }
            entry.1 = value;
            return Ok(());
        }

        self.last_seen.push((chat_id, value));
        Ok(())
    }

    /// Ultimo identificativo accettato per la chat indicata.
    #[must_use]
    pub fn last_accepted(&self, chat_id: ChatId) -> Option<i64> {
        self.last_seen
            .iter()
            .find(|(chat, _)| *chat == chat_id)
            .map(|(_, value)| *value)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::AcquisitionOrigin;
    use lisi_core::text::ContentBody;
    use lisi_core::{SessionId, SourceId, Timestamp};

    use super::{SequenceGuard, to_edited_body, to_new_content};
    use crate::error::TelegramError;
    use crate::event::{EditedMessage, IncomingMessage};
    use crate::identifier::{ChatId, MessageId};

    fn chat() -> ChatId {
        let Ok(chat) = ChatId::try_new(-1_001) else {
            panic!("l'identificativo di prova deve essere valido");
        };
        chat
    }

    fn message_id(value: i64) -> MessageId {
        let Ok(message) = MessageId::try_new(value) else {
            panic!("l'identificativo di prova deve essere valido");
        };
        message
    }

    fn incoming(text: &str) -> IncomingMessage {
        IncomingMessage {
            chat_id: chat(),
            message_id: message_id(42),
            author: Some(String::from("Redazione")),
            author_identifier: None,
            author_username: None,
            text: String::from(text),
            published_at_millis: 1_700_000_000_000,
            url: Some(String::from("https://t.me/canale/42")),
            attachment: None,
        }
    }

    #[test]
    fn a_message_becomes_a_content_of_the_domain() {
        let Ok(content) = to_new_content(
            &incoming("testo del messaggio"),
            SessionId::new(1),
            SourceId::new(2),
            Timestamp::from_millis(1_700_000_005_000),
            AcquisitionOrigin::Observed,
        ) else {
            panic!("il messaggio di prova doveva essere accettato");
        };

        assert_eq!(content.session_id, SessionId::new(1));
        assert_eq!(content.source_id, SourceId::new(2));
        assert_eq!(content.remote_message_id.as_str(), "42");
        assert_eq!(content.body.as_str(), "testo del messaggio");
        assert_eq!(content.published_at.as_millis(), 1_700_000_000_000);
        assert_eq!(content.acquired_at.as_millis(), 1_700_000_005_000);
        assert_eq!(
            content.author.as_ref().map(lisi_core::text::Actor::as_str),
            Some("Redazione")
        );
    }

    #[test]
    fn a_content_is_recorded_at_level_zero_before_being_analysed() {
        let Ok(content) = to_new_content(
            &incoming("testo"),
            SessionId::new(1),
            SourceId::new(1),
            Timestamp::from_millis(0),
            AcquisitionOrigin::Observed,
        ) else {
            panic!("il messaggio di prova doveva essere accettato");
        };
        assert_eq!(content.analysis_level.get(), 0);
    }

    #[test]
    fn a_message_without_author_or_url_is_accepted() {
        let mut message = incoming("solo media");
        message.author = None;
        message.url = None;

        let Ok(content) = to_new_content(
            &message,
            SessionId::new(1),
            SourceId::new(1),
            Timestamp::from_millis(0),
            AcquisitionOrigin::Observed,
        ) else {
            panic!("il messaggio senza autore e senza URL doveva essere accettato");
        };
        assert_eq!(content.author, None);
        assert_eq!(content.url, None);
    }

    #[test]
    fn an_empty_body_is_accepted_because_a_message_may_carry_only_media() {
        let Ok(content) = to_new_content(
            &incoming(""),
            SessionId::new(1),
            SourceId::new(1),
            Timestamp::from_millis(0),
            AcquisitionOrigin::Observed,
        ) else {
            panic!("il corpo vuoto doveva essere accettato");
        };
        assert_eq!(content.body.as_str(), "");
    }

    #[test]
    fn a_message_beyond_the_domain_limit_is_refused() {
        let oversized = "a".repeat(ContentBody::MAX_CHARS + 1);

        assert!(matches!(
            to_new_content(
                &incoming(&oversized),
                SessionId::new(1),
                SourceId::new(1),
                Timestamp::from_millis(0),
                AcquisitionOrigin::Observed,
            ),
            Err(TelegramError::UnacceptableContent(_))
        ));
    }

    #[test]
    fn a_message_with_a_dangerous_url_is_refused() {
        let mut message = incoming("testo");
        message.url = Some(String::from("javascript:alert(1)"));

        assert!(matches!(
            to_new_content(
                &message,
                SessionId::new(1),
                SourceId::new(1),
                Timestamp::from_millis(0),
                AcquisitionOrigin::Observed,
            ),
            Err(TelegramError::UnacceptableContent(_))
        ));
    }

    #[test]
    fn an_author_with_control_characters_is_refused() {
        let mut message = incoming("testo");
        message.author = Some(String::from("Reda\u{0}zione"));

        assert!(matches!(
            to_new_content(
                &message,
                SessionId::new(1),
                SourceId::new(1),
                Timestamp::from_millis(0),
                AcquisitionOrigin::Observed,
            ),
            Err(TelegramError::UnacceptableContent(_))
        ));
    }

    #[test]
    fn an_edit_is_validated_against_the_same_domain_limit() {
        let edit = EditedMessage {
            chat_id: chat(),
            message_id: message_id(42),
            text: "a".repeat(ContentBody::MAX_CHARS + 1),
            edited_at_millis: 1_700_000_010_000,
        };

        assert!(matches!(
            to_edited_body(&edit),
            Err(TelegramError::UnacceptableContent(_))
        ));
    }

    #[test]
    fn messages_in_increasing_order_are_accepted() {
        let mut guard = SequenceGuard::new();
        for value in [10, 11, 20, 21] {
            let Ok(()) = guard.accept(chat(), message_id(value)) else {
                panic!("il messaggio {value} doveva essere accettato");
            };
        }
        assert_eq!(guard.last_accepted(chat()), Some(21));
    }

    #[test]
    fn a_message_out_of_sequence_is_reported() {
        let mut guard = SequenceGuard::new();
        let Ok(()) = guard.accept(chat(), message_id(20)) else {
            panic!("il primo messaggio doveva essere accettato");
        };

        assert!(matches!(
            guard.accept(chat(), message_id(19)),
            Err(TelegramError::OutOfOrder { last: 20 })
        ));
        // L'ultimo accettato non arretra.
        assert_eq!(guard.last_accepted(chat()), Some(20));
    }

    #[test]
    fn the_same_message_delivered_twice_is_reported_as_out_of_sequence() {
        let mut guard = SequenceGuard::new();
        let Ok(()) = guard.accept(chat(), message_id(7)) else {
            panic!("il primo messaggio doveva essere accettato");
        };
        assert!(matches!(
            guard.accept(chat(), message_id(7)),
            Err(TelegramError::OutOfOrder { last: 7 })
        ));
    }

    #[test]
    fn each_chat_has_its_own_sequence() {
        let Ok(other_chat) = ChatId::try_new(-1_002) else {
            panic!("l'identificativo di prova deve essere valido");
        };

        let mut guard = SequenceGuard::new();
        let Ok(()) = guard.accept(chat(), message_id(100)) else {
            panic!("il messaggio doveva essere accettato");
        };
        // Un identificativo basso su un'altra chat non e' fuori sequenza.
        let Ok(()) = guard.accept(other_chat, message_id(1)) else {
            panic!("le chat hanno sequenze indipendenti");
        };

        assert_eq!(guard.last_accepted(chat()), Some(100));
        assert_eq!(guard.last_accepted(other_chat), Some(1));
    }

    #[test]
    fn an_unknown_chat_has_no_last_accepted_identifier() {
        let guard = SequenceGuard::new();
        assert_eq!(guard.last_accepted(chat()), None);
    }
}

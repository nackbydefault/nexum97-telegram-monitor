//! Eventi normalizzati del connettore.
//!
//! Sono la sola forma in cui il resto dell'applicazione vede ciò che accade su
//! Telegram. Nessuna struttura della libreria attraversa questo confine: se
//! domani il binding cambiasse, cambierebbe la traduzione e non il resto del
//! prodotto. Un evento non contiene mai un valore riservato.

use core::fmt;

use crate::auth::AuthorizationState;
use crate::error::TelegramError;
use crate::identifier::{ChatId, MessageId};

/// Stato del collegamento con la piattaforma.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionState {
    /// Nessun collegamento in corso.
    Offline,
    /// Tentativo di collegamento in corso.
    Connecting,
    /// Collegamento stabilito.
    Online,
    /// Collegamento perso, in attesa di un nuovo tentativo.
    Interrupted,
}

impl ConnectionState {
    /// Etichetta stabile per l'audit.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Connecting => "connecting",
            Self::Online => "online",
            Self::Interrupted => "interrupted",
        }
    }
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Messaggio acquisito da una fonte.
///
/// I campi sono grezzi: la validazione di dominio avviene nella traduzione verso
/// `lisi-core`, così che un contenuto oltre misura sia rifiutato da un unico
/// punto e con l'errore del dominio, senza duplicare qui i limiti.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingMessage {
    /// Chat di provenienza.
    pub chat_id: ChatId,
    /// Identificativo del messaggio nella chat.
    pub message_id: MessageId,
    /// Autore dichiarato, quando la piattaforma lo espone.
    ///
    /// È un nome leggibile. Oggi resta vuoto sul percorso reale: risolvere lo
    /// username richiede una richiesta a TDLib con risposta da correlare, e
    /// quel macchinario non esiste ancora.
    pub author: Option<String>,
    /// Identificativo dell'autore presso la piattaforma, quando il mittente è
    /// una persona.
    ///
    /// A differenza del nome, questo si legge **direttamente
    /// dall'aggiornamento**, senza alcuna richiesta in più. È assente per i
    /// messaggi di canale, che portano come mittente il canale stesso.
    pub author_identifier: Option<String>,
    /// Username dell'autore, senza chiocciola, quando ne ha uno.
    ///
    /// **Non è un'identità.** Uno username può essere rilasciato e preso da
    /// qualcun altro, il che lo rende ancora meno affidabile di un nome per
    /// rispondere a «chi ha scritto questo» a distanza di tempo. Serve a
    /// **ritrovare** una persona su Telegram oggi, non ad attribuirle un
    /// messaggio domani: per quello c'è l'identificativo numerico.
    pub author_username: Option<String>,
    /// Testo del messaggio, eventualmente vuoto per i soli media.
    pub text: String,
    /// Istante di pubblicazione dichiarato, in millisecondi dall'epoca Unix.
    pub published_at_millis: i64,
    /// URL pubblico del messaggio, quando disponibile.
    pub url: Option<String>,
    /// L'allegato, descritto e non scaricato (ATTACH-01, ADR-0177): il
    /// genere e ciò che il mittente dichiara. Assente se il messaggio non ne ha
    /// uno, o se il genere non è fra quelli che il connettore riconosce.
    pub attachment: Option<Box<crate::attachment::AttachmentDescriptor>>,
}

/// Modifica di un messaggio già acquisito.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditedMessage {
    /// Chat di provenienza.
    pub chat_id: ChatId,
    /// Messaggio modificato.
    pub message_id: MessageId,
    /// Nuovo testo.
    pub text: String,
    /// Istante della modifica, in millisecondi dall'epoca Unix.
    pub edited_at_millis: i64,
}

/// Cancellazione di uno o più messaggi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedMessages {
    /// Chat di provenienza.
    pub chat_id: ChatId,
    /// Messaggi cancellati.
    pub message_ids: Vec<MessageId>,
    /// Istante della cancellazione, in millisecondi dall'epoca Unix.
    pub deleted_at_millis: i64,
}

/// Evento normalizzato prodotto dal connettore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorEvent {
    /// Lo stato di autorizzazione è cambiato.
    Authorization(AuthorizationState),
    /// Lo stato del collegamento è cambiato.
    Connection(ConnectionState),
    /// È stato acquisito un nuovo messaggio.
    MessageReceived(IncomingMessage),
    /// Un messaggio già acquisito è stato modificato.
    MessageEdited(EditedMessage),
    /// Uno o più messaggi sono stati cancellati.
    MessagesDeleted(DeletedMessages),
    /// Si è verificato un errore.
    Failure(TelegramError),
}

impl ConnectorEvent {
    /// Etichetta stabile del tipo di evento, adatta all'audit e alle metriche.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Authorization(_) => "autorizzazione",
            Self::Connection(_) => "connessione",
            Self::MessageReceived(_) => "messaggio_ricevuto",
            Self::MessageEdited(_) => "messaggio_modificato",
            Self::MessagesDeleted(_) => "messaggi_cancellati",
            Self::Failure(_) => "errore",
        }
    }

    /// Chat interessata dall'evento, quando ne esiste una.
    #[must_use]
    pub const fn chat_id(&self) -> Option<ChatId> {
        match self {
            Self::MessageReceived(message) => Some(message.chat_id),
            Self::MessageEdited(edit) => Some(edit.chat_id),
            Self::MessagesDeleted(deletion) => Some(deletion.chat_id),
            Self::Authorization(_) | Self::Connection(_) | Self::Failure(_) => None,
        }
    }

    /// Se l'evento riguarda un contenuto e non lo stato del connettore.
    #[must_use]
    pub const fn is_content_event(&self) -> bool {
        matches!(
            self,
            Self::MessageReceived(_) | Self::MessageEdited(_) | Self::MessagesDeleted(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnectionState, ConnectorEvent, DeletedMessages, EditedMessage, IncomingMessage};
    use crate::auth::AuthorizationState;
    use crate::error::TelegramError;
    use crate::identifier::{ChatId, MessageId};

    fn chat() -> ChatId {
        let Ok(chat) = ChatId::try_new(-1_001) else {
            panic!("l'identificativo di prova deve essere valido");
        };
        chat
    }

    fn message(value: i64) -> MessageId {
        let Ok(message) = MessageId::try_new(value) else {
            panic!("l'identificativo di prova deve essere valido");
        };
        message
    }

    #[test]
    fn every_event_has_a_distinct_stable_kind() {
        let events = [
            ConnectorEvent::Authorization(AuthorizationState::Ready),
            ConnectorEvent::Connection(ConnectionState::Online),
            ConnectorEvent::MessageReceived(IncomingMessage {
                chat_id: chat(),
                message_id: message(1),
                author: None,
                author_identifier: None,
                author_username: None,
                text: String::from("testo"),
                published_at_millis: 1_700_000_000_000,
                url: None,
                attachment: None,
            }),
            ConnectorEvent::MessageEdited(EditedMessage {
                chat_id: chat(),
                message_id: message(1),
                text: String::from("testo corretto"),
                edited_at_millis: 1_700_000_001_000,
            }),
            ConnectorEvent::MessagesDeleted(DeletedMessages {
                chat_id: chat(),
                message_ids: vec![message(1)],
                deleted_at_millis: 1_700_000_002_000,
            }),
            ConnectorEvent::Failure(TelegramError::Closed),
        ];

        for (index, event) in events.iter().enumerate() {
            assert!(!event.kind().is_empty());
            for other in events.iter().skip(index + 1) {
                assert_ne!(event.kind(), other.kind());
            }
        }
    }

    #[test]
    fn only_content_events_carry_a_chat() {
        let received = ConnectorEvent::MessageReceived(IncomingMessage {
            chat_id: chat(),
            message_id: message(1),
            author: None,
            author_identifier: None,
            author_username: None,
            text: String::new(),
            published_at_millis: 0,
            url: None,
            attachment: None,
        });
        assert!(received.is_content_event());
        assert_eq!(received.chat_id(), Some(chat()));

        let authorization = ConnectorEvent::Authorization(AuthorizationState::Ready);
        assert!(!authorization.is_content_event());
        assert_eq!(authorization.chat_id(), None);
    }

    #[test]
    fn a_failure_event_does_not_reveal_any_secret() {
        let event = ConnectorEvent::Failure(TelegramError::InvalidSecret {
            field: "api_hash",
            reason: "sono ammessi solo caratteri esadecimali",
        });
        let rendered = format!("{event:?}");

        assert!(rendered.contains("api_hash"));
        assert!(!rendered.contains("0123456789abcdef"));
    }

    #[test]
    fn connection_states_have_stable_labels() {
        assert_eq!(ConnectionState::Online.as_str(), "online");
        assert_eq!(ConnectionState::Interrupted.to_string(), "interrupted");
    }
}

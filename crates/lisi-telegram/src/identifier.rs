//! Identificativi remoti.
//!
//! Non sono segreti e devono restare leggibili nei log e nella diagnostica: sono
//! ciò che permette di ricondurre un contenuto alla sua origine. Sono però dati
//! che arrivano dalla rete, quindi validati alla costruzione.

use core::fmt;

use crate::error::{TelegramError, TelegramResult};

/// Identificativo di una chat presso la piattaforma.
///
/// Il valore può essere negativo: le piattaforme distinguono così i canali e i
/// supergruppi dalle conversazioni individuali. Zero non identifica nulla.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChatId(i64);

impl ChatId {
    /// Costruisce l'identificativo verificando che non sia nullo.
    ///
    /// # Errori
    ///
    /// Restituisce [`TelegramError::InvalidIdentifier`] per il valore zero.
    pub const fn try_new(value: i64) -> TelegramResult<Self> {
        if value == 0 {
            return Err(TelegramError::InvalidIdentifier { kind: "chat" });
        }
        Ok(Self(value))
    }

    /// Valore grezzo.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl fmt::Display for ChatId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "chat#{}", self.0)
    }
}

/// Identificativo di un messaggio all'interno di una chat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageId(i64);

impl MessageId {
    /// Costruisce l'identificativo verificando che sia positivo.
    ///
    /// # Errori
    ///
    /// Restituisce [`TelegramError::InvalidIdentifier`] per valori non positivi.
    pub const fn try_new(value: i64) -> TelegramResult<Self> {
        if value <= 0 {
            return Err(TelegramError::InvalidIdentifier { kind: "messaggio" });
        }
        Ok(Self(value))
    }

    /// Valore grezzo.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "messaggio#{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{ChatId, MessageId};
    use crate::error::TelegramError;

    #[test]
    fn a_negative_chat_identifier_is_accepted_because_channels_use_them() {
        let Ok(chat) = ChatId::try_new(-1_001_234_567_890) else {
            panic!("un canale ha un identificativo negativo e deve essere accettato");
        };
        assert_eq!(chat.get(), -1_001_234_567_890);
    }

    #[test]
    fn a_zero_chat_identifier_is_rejected() {
        assert!(matches!(
            ChatId::try_new(0),
            Err(TelegramError::InvalidIdentifier { kind: "chat" })
        ));
    }

    #[test]
    fn a_non_positive_message_identifier_is_rejected() {
        for value in [0, -1, i64::MIN] {
            assert!(matches!(
                MessageId::try_new(value),
                Err(TelegramError::InvalidIdentifier { kind: "messaggio" })
            ));
        }
    }

    #[test]
    fn identifiers_are_displayed_with_their_kind() {
        let (Ok(chat), Ok(message)) = (ChatId::try_new(-42), MessageId::try_new(7)) else {
            panic!("gli identificativi di prova devono essere validi");
        };
        assert_eq!(chat.to_string(), "chat#-42");
        assert_eq!(message.to_string(), "messaggio#7");
    }

    #[test]
    fn identifiers_of_different_kinds_are_distinct_types() {
        // La verifica sostanziale e' a tempo di compilazione: assegnare un
        // ChatId dove e' atteso un MessageId non compila.
        let (Ok(chat), Ok(message)) = (ChatId::try_new(1), MessageId::try_new(1)) else {
            panic!("gli identificativi di prova devono essere validi");
        };
        assert_eq!(chat.get(), message.get());
        assert_ne!(chat.to_string(), message.to_string());
    }
}

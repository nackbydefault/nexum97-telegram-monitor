//! Coda limitata degli eventi.
//!
//! La libreria produce eventi più in fretta di quanto l'applicazione li consumi
//! quando una fonte è molto attiva. Una coda senza limite trasformerebbe quel
//! divario in consumo di memoria illimitato, cioè in un arresto del processo nel
//! momento peggiore.
//!
//! La politica adottata è **rifiutare il nuovo**, non scartare il vecchio: gli
//! eventi già accettati sono già stati considerati acquisiti, e perderli
//! renderebbe lo storico silenziosamente incompleto. Un evento rifiutato è
//! invece un fatto noto, contato e segnalabile come errore operativo.

use std::collections::VecDeque;

use crate::error::{TelegramError, TelegramResult};
use crate::event::ConnectorEvent;

/// Coda FIFO a capacità fissa.
#[derive(Debug)]
pub struct EventQueue {
    capacity: usize,
    events: VecDeque<ConnectorEvent>,
    accepted: u64,
    rejected: u64,
}

impl EventQueue {
    /// Capacità minima ammessa.
    ///
    /// Una coda di capacità zero rifiuterebbe qualunque evento e sarebbe un
    /// errore di configurazione silenzioso.
    pub const MIN_CAPACITY: usize = 1;

    /// Capacità predefinita.
    pub const DEFAULT_CAPACITY: usize = 1_024;

    /// Crea la coda con la capacità indicata, non inferiore a
    /// [`Self::MIN_CAPACITY`].
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(Self::MIN_CAPACITY);
        Self {
            capacity,
            events: VecDeque::with_capacity(capacity),
            accepted: 0,
            rejected: 0,
        }
    }

    /// Aggiunge un evento in coda.
    ///
    /// # Errori
    ///
    /// Restituisce [`TelegramError::QueueFull`] se la capacità è esaurita. In
    /// quel caso la coda resta **immutata**: nessun evento già accettato viene
    /// scartato per far posto.
    pub fn push(&mut self, event: ConnectorEvent) -> TelegramResult<()> {
        if self.events.len() >= self.capacity {
            self.rejected = self.rejected.saturating_add(1);
            return Err(TelegramError::QueueFull {
                capacity: self.capacity,
            });
        }

        self.events.push_back(event);
        self.accepted = self.accepted.saturating_add(1);
        Ok(())
    }

    /// Estrae l'evento più antico.
    pub fn pop(&mut self) -> Option<ConnectorEvent> {
        self.events.pop_front()
    }

    /// Numero di eventi in attesa.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Se la coda è vuota.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Se la coda è piena.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.events.len() >= self.capacity
    }

    /// Capacità della coda.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Numero complessivo di eventi accettati.
    #[must_use]
    pub const fn accepted(&self) -> u64 {
        self.accepted
    }

    /// Numero complessivo di eventi rifiutati per coda piena.
    ///
    /// Va riportato all'operatore: indica che l'acquisizione non ha tenuto il
    /// passo, e uno storico incompleto senza avviso sarebbe fuorviante.
    #[must_use]
    pub const fn rejected(&self) -> u64 {
        self.rejected
    }
}

impl Default for EventQueue {
    fn default() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::EventQueue;
    use crate::auth::AuthorizationState;
    use crate::error::TelegramError;
    use crate::event::{ConnectionState, ConnectorEvent, IncomingMessage};
    use crate::identifier::{ChatId, MessageId};

    fn message_event(number: i64) -> ConnectorEvent {
        let (Ok(chat_id), Ok(message_id)) = (ChatId::try_new(-1_001), MessageId::try_new(number))
        else {
            panic!("gli identificativi di prova devono essere validi");
        };

        ConnectorEvent::MessageReceived(IncomingMessage {
            chat_id,
            message_id,
            author: None,
            author_identifier: None,
            author_username: None,
            text: format!("messaggio {number}"),
            published_at_millis: 1_700_000_000_000 + number,
            url: None,
            attachment: None,
        })
    }

    #[test]
    fn events_are_returned_in_the_order_they_arrived() {
        let mut queue = EventQueue::with_capacity(8);
        for number in 1..=4 {
            let Ok(()) = queue.push(message_event(number)) else {
                panic!("la coda non doveva essere piena");
            };
        }

        for number in 1..=4 {
            assert_eq!(queue.pop(), Some(message_event(number)));
        }
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn a_full_queue_refuses_the_new_event_and_keeps_the_accepted_ones() {
        let mut queue = EventQueue::with_capacity(3);
        for number in 1..=3 {
            let Ok(()) = queue.push(message_event(number)) else {
                panic!("la coda non doveva essere ancora piena");
            };
        }

        assert!(queue.is_full());
        assert!(matches!(
            queue.push(message_event(99)),
            Err(TelegramError::QueueFull { capacity: 3 })
        ));

        // Gli eventi gia' accettati sono tutti ancora presenti e nell'ordine
        // originale: il rifiuto non ha scartato nulla.
        assert_eq!(queue.len(), 3);
        for number in 1..=3 {
            assert_eq!(queue.pop(), Some(message_event(number)));
        }
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn rejections_are_counted_so_that_they_can_be_reported() {
        let mut queue = EventQueue::with_capacity(1);
        let Ok(()) = queue.push(message_event(1)) else {
            panic!("il primo evento doveva essere accettato");
        };

        for _ in 0..5 {
            assert!(queue.push(message_event(2)).is_err());
        }

        assert_eq!(queue.accepted(), 1);
        assert_eq!(queue.rejected(), 5);
    }

    #[test]
    fn a_freed_slot_can_be_used_again() {
        let mut queue = EventQueue::with_capacity(2);
        for number in 1..=2 {
            let Ok(()) = queue.push(message_event(number)) else {
                panic!("la coda non doveva essere piena");
            };
        }
        assert!(queue.push(message_event(3)).is_err());

        assert_eq!(queue.pop(), Some(message_event(1)));
        let Ok(()) = queue.push(message_event(3)) else {
            panic!("liberato un posto, l'evento doveva essere accettato");
        };

        assert_eq!(queue.pop(), Some(message_event(2)));
        assert_eq!(queue.pop(), Some(message_event(3)));
    }

    #[test]
    fn a_capacity_of_zero_is_raised_to_the_minimum() {
        let mut queue = EventQueue::with_capacity(0);
        assert_eq!(queue.capacity(), EventQueue::MIN_CAPACITY);
        assert!(queue.push(message_event(1)).is_ok());
    }

    #[test]
    fn the_queue_does_not_grow_beyond_its_capacity_under_pressure() {
        let mut queue = EventQueue::with_capacity(16);
        for number in 1..=10_000 {
            let _ = queue.push(message_event(number));
        }

        assert_eq!(queue.len(), 16);
        assert_eq!(queue.accepted(), 16);
        assert_eq!(queue.rejected(), 10_000 - 16);
    }

    #[test]
    fn events_of_every_kind_share_the_same_queue() {
        let mut queue = EventQueue::with_capacity(4);
        let Ok(()) = queue.push(ConnectorEvent::Authorization(AuthorizationState::Ready)) else {
            panic!("l'evento doveva essere accettato");
        };
        let Ok(()) = queue.push(ConnectorEvent::Connection(ConnectionState::Online)) else {
            panic!("l'evento doveva essere accettato");
        };
        let Ok(()) = queue.push(message_event(1)) else {
            panic!("l'evento doveva essere accettato");
        };

        assert_eq!(queue.len(), 3);
        assert_eq!(
            queue.pop().map(|event| event.kind()),
            Some("autorizzazione")
        );
        assert_eq!(queue.pop().map(|event| event.kind()), Some("connessione"));
        assert_eq!(
            queue.pop().map(|event| event.kind()),
            Some("messaggio_ricevuto")
        );
    }

    #[test]
    fn an_empty_queue_is_reported_as_such() {
        let mut queue = EventQueue::default();
        assert!(queue.is_empty());
        assert!(!queue.is_full());
        assert_eq!(queue.capacity(), EventQueue::DEFAULT_CAPACITY);

        let Ok(()) = queue.push(message_event(1)) else {
            panic!("l'evento doveva essere accettato");
        };
        assert!(!queue.is_empty());
    }
}

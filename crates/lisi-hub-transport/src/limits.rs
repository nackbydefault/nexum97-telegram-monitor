//! I tetti del trasporto.
//!
//! **Valori scelti da noi, non misurati** (ADR-0083, decisione 5). Sono larghi
//! per una LAN d'ufficio e stretti abbastanza perché un client ostile o lento
//! non tenga occupato l'Hub. Una misura vera arriverà con HUB-BP-01 e con la
//! prova a due macchine (HVQ-08); fino ad allora non vanno presentati come
//! dimensionati.

use std::time::Duration;

/// I tetti dal lato della postazione che si collega.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientLimits {
    /// Quanto aspettare che la connessione TCP si apra.
    pub connect_timeout: Duration,
    /// Quanto può durare l'handshake TLS, dal primo byte all'ultimo.
    pub handshake_timeout: Duration,
    /// Quanto può restare ferma una lettura o una scrittura dopo l'handshake.
    pub io_timeout: Duration,
}

impl Default for ClientLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(60),
        }
    }
}

/// I tetti dal lato dell'Hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerLimits {
    /// Connessioni contemporanee, handshake compresi. Oltre, la connessione
    /// nuova si chiude subito.
    pub max_connections: usize,
    /// Handshake contemporanei: un tetto più basso, perché un handshake che
    /// non finisce costa senza aver dimostrato nulla.
    pub max_handshakes: usize,
    /// Quanto può durare un handshake prima che la connessione si chiuda.
    pub handshake_timeout: Duration,
    /// Quanto può restare ferma una lettura o una scrittura dopo l'handshake.
    pub io_timeout: Duration,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_connections: 64,
            max_handshakes: 16,
            handshake_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(120),
        }
    }
}

impl ClientLimits {
    /// Se i tetti sono utilizzabili: nessuna durata nulla.
    ///
    /// Una durata nulla, per un socket, significa **nessun limite**: è
    /// l'opposto di ciò che chi la scrive intende, e va rifiutata.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        !self.connect_timeout.is_zero()
            && !self.handshake_timeout.is_zero()
            && !self.io_timeout.is_zero()
    }
}

impl ServerLimits {
    /// Se i tetti sono utilizzabili: nessun tetto nullo e nessuna durata nulla.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.max_connections > 0
            && self.max_handshakes > 0
            && self.max_handshakes <= self.max_connections
            && !self.handshake_timeout.is_zero()
            && !self.io_timeout.is_zero()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{ClientLimits, ServerLimits};

    #[test]
    fn the_defaults_are_usable() {
        assert!(ClientLimits::default().is_usable());
        assert!(ServerLimits::default().is_usable());
    }

    #[test]
    fn a_zero_duration_is_not_a_limit_and_is_refused() {
        let client = ClientLimits {
            io_timeout: Duration::ZERO,
            ..ClientLimits::default()
        };
        assert!(!client.is_usable());
        let server = ServerLimits {
            handshake_timeout: Duration::ZERO,
            ..ServerLimits::default()
        };
        assert!(!server.is_usable());
        let server = ServerLimits {
            max_handshakes: 100,
            max_connections: 10,
            ..ServerLimits::default()
        };
        assert!(!server.is_usable());
    }
}

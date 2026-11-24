//! Gli esiti di una connessione, come li deve leggere chi decide che cosa fare.
//!
//! # Due esiti per l'operatore, perché portano ad azioni diverse
//!
//! ADR-0083 decisione 6 li separa:
//!
//! - **l'Hub non risponde** — rete, indirizzo, firewall: si riprova con attesa
//!   crescente e un tetto;
//! - **l'Hub risponde ma non è quello atteso** — **nessun nuovo tentativo
//!   automatico**. Può essere un Hub reinstallato **oppure qualcuno che si
//!   spaccia per lui**, e non esiste un «fidati comunque».
//!
//! [`TransportError::outcome`] porta ogni errore in uno dei due.
//!
//! # Che cosa gli errori non contengono
//!
//! Nessun dato ricevuto dall'altro capo: né byte, né impronte presentate, né
//! messaggi della libreria composti con l'ingresso. Un messaggio composto da un
//! dato ostile è un messaggio che un dato ostile può riscrivere.

use thiserror::Error;

/// Risultato del trasporto.
pub type TransportResult<T> = Result<T, TransportError>;

/// Perché una connessione con l'Hub non è stata stabilita, o è finita.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Nessuno ha risposto: connessione rifiutata, rete irraggiungibile, tempo
    /// di connessione scaduto, o la connessione è caduta prima di cominciare.
    #[error("l'Hub non risponde")]
    Unreachable,

    /// Qualcuno ha risposto, ma l'handshake non è finito nel tempo concesso.
    #[error("l'Hub non ha completato l'handshake nel tempo previsto")]
    HandshakeTimedOut,

    /// La chiave presentata non è quella attesa, oppure l'altro capo non ha
    /// dimostrato di possederne la privata.
    #[error("l'Hub ha risposto ma non è quello atteso")]
    NotTheExpectedHub,

    /// L'altro capo parla TLS ma non il protocollo dell'Hub: nessun accordo
    /// ALPN, versione diversa da TLS 1.3, chiavi nude non sostenute, o messaggi
    /// che non sono TLS.
    #[error("all'indirizzo risponde un servizio che non è l'Hub")]
    ProtocolMismatch,

    /// L'indirizzo scelto per ascoltare non è ammesso.
    #[error("indirizzo di ascolto non ammesso: {reason}")]
    AddressNotAllowed {
        /// Perché. Una costante.
        reason: &'static str,
    },

    /// La chiave dell'Hub non è utilizzabile.
    #[error("chiave dell'Hub non utilizzabile: {reason}")]
    KeyRejected {
        /// Perché. Una costante.
        reason: &'static str,
    },

    /// Il generatore casuale del sistema ha rifiutato.
    #[error("il generatore casuale del sistema non è disponibile")]
    RandomUnavailable,

    /// La configurazione TLS non si è potuta costruire.
    #[error("configurazione TLS non costruibile")]
    Configuration,

    /// Un errore d'ingresso e uscita dopo l'handshake, o sul socket locale.
    #[error("errore di rete: {kind}")]
    Io {
        /// Il tipo di errore, senza il messaggio del sistema.
        kind: std::io::ErrorKind,
    },
}

/// Che cosa l'errore significa per chi deve decidere se riprovare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// Si può riprovare, con attesa crescente e un tetto.
    HubUnreachable,
    /// **Non si riprova da soli.** Va detto all'operatore e registrato.
    NotTheExpectedHub,
    /// Un difetto di questa postazione: configurazione, chiave, indirizzo.
    LocalFault,
}

impl TransportError {
    /// L'esito per l'operatore (ADR-0083, decisione 6).
    #[must_use]
    pub const fn outcome(&self) -> ConnectOutcome {
        match self {
            Self::Unreachable | Self::HandshakeTimedOut | Self::Io { .. } => {
                ConnectOutcome::HubUnreachable
            }
            Self::NotTheExpectedHub | Self::ProtocolMismatch => ConnectOutcome::NotTheExpectedHub,
            Self::AddressNotAllowed { .. }
            | Self::KeyRejected { .. }
            | Self::RandomUnavailable
            | Self::Configuration => ConnectOutcome::LocalFault,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnectOutcome, TransportError};

    #[test]
    fn only_silence_is_worth_retrying() {
        for errore in [
            TransportError::Unreachable,
            TransportError::HandshakeTimedOut,
            TransportError::Io {
                kind: std::io::ErrorKind::ConnectionReset,
            },
        ] {
            assert_eq!(errore.outcome(), ConnectOutcome::HubUnreachable);
        }
        for errore in [
            TransportError::NotTheExpectedHub,
            TransportError::ProtocolMismatch,
        ] {
            assert_eq!(
                errore.outcome(),
                ConnectOutcome::NotTheExpectedHub,
                "un Hub che non e' quello atteso non si ritenta da soli"
            );
        }
    }

    #[test]
    fn the_operator_sentence_names_both_possibilities_without_trusting_either() {
        let frase = TransportError::NotTheExpectedHub.to_string();
        assert!(frase.contains("non è quello atteso"));
        assert!(!frase.to_lowercase().contains("fidati"));
    }
}

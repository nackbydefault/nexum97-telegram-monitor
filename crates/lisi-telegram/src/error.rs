//! Errori del connettore.
//!
//! Nessuna variante trasporta un valore riservato. I messaggi nominano il campo
//! interessato e la ragione del rifiuto, mai il contenuto: un errore finisce nei
//! log e nei rapporti, e un errore che riportasse il numero di telefono o il
//! codice ricevuto vanificherebbe la redazione dei tipi.

use lisi_core::DomainError;

/// Esito di una operazione del connettore.
pub type TelegramResult<T> = Result<T, TelegramError>;

/// Errore prodotto dal connettore.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TelegramError {
    /// Un valore riservato non rispetta il formato atteso.
    ///
    /// Il valore rifiutato **non** compare nel messaggio.
    #[error("il campo riservato '{field}' non e' valido: {reason}")]
    InvalidSecret {
        /// Nome del campo interessato.
        field: &'static str,
        /// Ragione del rifiuto, priva del valore.
        reason: &'static str,
    },

    /// La transizione di stato di autorizzazione non è ammessa.
    #[error("transizione di autorizzazione non ammessa: da '{from}' a '{to}'")]
    InvalidAuthorizationTransition {
        /// Stato di partenza.
        from: &'static str,
        /// Stato richiesto.
        to: &'static str,
    },

    /// L'operazione richiede uno stato di autorizzazione diverso.
    #[error("operazione non ammessa nello stato di autorizzazione '{state}': atteso '{expected}'")]
    UnexpectedAuthorizationState {
        /// Stato corrente.
        state: &'static str,
        /// Stato in cui l'operazione sarebbe ammessa.
        expected: &'static str,
    },

    /// Il codice di accesso è stato rifiutato dalla piattaforma.
    ///
    /// Il codice **non** compare nel messaggio: sarebbe ancora valido per pochi
    /// minuti e un log lo renderebbe utilizzabile.
    #[error("il codice di accesso non e' stato accettato")]
    CodeRejected,

    /// La password della verifica in due passaggi è stata rifiutata.
    #[error("la password della verifica in due passaggi non e' stata accettata")]
    PasswordRejected,

    /// La sessione è stata revocata dalla piattaforma o da un altro dispositivo.
    #[error("la sessione e' stata revocata: e' necessario accedere di nuovo")]
    SessionRevoked,

    /// La cartella della sessione non è utilizzabile.
    #[error("i dati della sessione non sono accessibili: {reason}")]
    SessionUnavailable {
        /// Descrizione del problema, priva di dati riservati.
        reason: &'static str,
    },

    /// La rete non è disponibile.
    #[error("la rete non e' disponibile")]
    NetworkUnavailable,

    /// La coda degli eventi è piena.
    ///
    /// L'evento nuovo viene rifiutato e quelli già accettati restano intatti.
    #[error("coda degli eventi piena: capacita' {capacity}, evento rifiutato")]
    QueueFull {
        /// Capacità massima della coda.
        capacity: usize,
    },

    /// L'attesa di un evento è scaduta.
    #[error("attesa scaduta dopo {millis} ms")]
    Timeout {
        /// Durata attesa, in millisecondi.
        millis: u64,
    },

    /// I tentativi di riconnessione sono esauriti.
    #[error("tentativi di riconnessione esauriti dopo {attempts} tentativi")]
    BackoffExhausted {
        /// Numero di tentativi effettuati.
        attempts: u32,
    },

    /// Il connettore è stato arrestato.
    #[error("il connettore e' stato arrestato e non accetta altre operazioni")]
    Closed,

    /// Un identificativo ricevuto non è valido.
    #[error("identificativo '{kind}' non valido")]
    InvalidIdentifier {
        /// Tipo di identificativo.
        kind: &'static str,
    },

    /// Un evento è arrivato fuori sequenza.
    #[error("evento fuori sequenza per la chat: atteso un numero maggiore di {last}")]
    OutOfOrder {
        /// Ultimo numero di sequenza accettato.
        last: i64,
    },

    /// Il contenuto ricevuto non rispetta le invarianti del dominio.
    ///
    /// Comprende il caso del contenuto oltre misura: il limite è quello del
    /// dominio e non viene duplicato qui.
    #[error("contenuto remoto non accettabile: {0}")]
    UnacceptableContent(#[from] DomainError),

    /// La libreria TDLib non è utilizzabile.
    ///
    /// Presente anche senza la feature `tdlib-runtime`, così che il resto del
    /// codice non debba essere compilato in due forme diverse.
    #[error("libreria TDLib non utilizzabile: {reason}")]
    Tdlib {
        /// Descrizione del problema, priva di dati riservati.
        reason: String,
    },
}

impl TelegramError {
    /// Nome breve e stabile della classe di errore, adatto all'audit.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::InvalidSecret { .. } => "segreto_non_valido",
            Self::CodeRejected => "codice_rifiutato",
            Self::PasswordRejected => "password_rifiutata",
            Self::SessionRevoked => "sessione_revocata",
            Self::SessionUnavailable { .. } => "sessione_non_accessibile",
            Self::NetworkUnavailable => "rete_non_disponibile",
            Self::InvalidAuthorizationTransition { .. } => "transizione_non_ammessa",
            Self::UnexpectedAuthorizationState { .. } => "stato_inatteso",
            Self::QueueFull { .. } => "coda_piena",
            Self::Timeout { .. } => "attesa_scaduta",
            Self::BackoffExhausted { .. } => "riconnessioni_esaurite",
            Self::Closed => "connettore_arrestato",
            Self::InvalidIdentifier { .. } => "identificativo_non_valido",
            Self::OutOfOrder { .. } => "evento_fuori_sequenza",
            Self::UnacceptableContent(_) => "contenuto_non_accettabile",
            Self::Tdlib { .. } => "tdlib_non_utilizzabile",
        }
    }

    /// Se l'errore giustifica un tentativo di riconnessione.
    ///
    /// Un formato di segreto sbagliato non migliora riprovando; una attesa
    /// scaduta sì.
    #[must_use]
    pub const fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Timeout { .. } | Self::QueueFull { .. } | Self::NetworkUnavailable
        )
    }

    /// Se l'errore va corretto dall'operatore reinserendo un dato.
    ///
    /// Distingue «hai sbagliato a digitare» da «qualcosa non funziona»: sono
    /// due situazioni che richiedono due messaggi diversi e due comportamenti
    /// diversi dell'interfaccia.
    #[must_use]
    pub const fn requires_operator_correction(&self) -> bool {
        matches!(
            self,
            Self::CodeRejected | Self::PasswordRejected | Self::InvalidSecret { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::TelegramError;

    #[test]
    fn every_kind_is_a_stable_non_empty_label() {
        for error in [
            TelegramError::InvalidSecret {
                field: "api_id",
                reason: "prova",
            },
            TelegramError::InvalidAuthorizationTransition { from: "a", to: "b" },
            TelegramError::UnexpectedAuthorizationState {
                state: "a",
                expected: "b",
            },
            TelegramError::QueueFull { capacity: 1 },
            TelegramError::Timeout { millis: 1 },
            TelegramError::BackoffExhausted { attempts: 1 },
            TelegramError::Closed,
            TelegramError::InvalidIdentifier { kind: "chat" },
            TelegramError::OutOfOrder { last: 1 },
            TelegramError::Tdlib {
                reason: String::from("prova"),
            },
        ] {
            assert!(!error.kind().is_empty());
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn only_recoverable_errors_are_transient() {
        assert!(TelegramError::Timeout { millis: 10 }.is_transient());
        assert!(TelegramError::QueueFull { capacity: 4 }.is_transient());
        assert!(!TelegramError::Closed.is_transient());
        assert!(
            !TelegramError::InvalidSecret {
                field: "api_id",
                reason: "prova"
            }
            .is_transient()
        );
    }
}

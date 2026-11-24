//! Errori della protezione locale.
//!
//! Nessuna variante trasporta il valore protetto o parte di esso, nemmeno in un
//! messaggio diagnostico: un errore finisce nei log, e un segreto in un
//! messaggio d'errore vanifica la protezione che l'errore stesso segnala.

/// Esito di una operazione di protezione.
pub type SecurityResult<T> = Result<T, SecurityError>;

/// Errore prodotto dalla protezione locale.
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    /// La protezione del dato non è riuscita.
    #[error("protezione del dato non riuscita (codice di sistema {code})")]
    ProtectionFailed {
        /// Codice restituito dal sistema.
        code: u32,
    },

    /// La rimozione della protezione non è riuscita.
    ///
    /// Le cause tipiche sono un blob prodotto da un altro profilo utente o su
    /// un'altra macchina, oppure un file danneggiato.
    #[error("rimozione della protezione non riuscita (codice di sistema {code})")]
    UnprotectionFailed {
        /// Codice restituito dal sistema.
        code: u32,
    },

    /// Il file protetto è assente.
    #[error("nessuna configurazione protetta presente")]
    NotConfigured,

    /// Il file protetto è danneggiato o troncato.
    #[error("la configurazione protetta e' danneggiata: {reason}")]
    Corrupted {
        /// Descrizione priva del contenuto.
        reason: &'static str,
    },

    /// Il contenuto protetto non è testo valido.
    #[error("la configurazione protetta non contiene testo leggibile")]
    NotValidText,

    /// Una voce attesa manca nella configurazione.
    #[error("la configurazione protetta non contiene la voce '{key}'")]
    MissingEntry {
        /// Nome della voce mancante.
        key: &'static str,
    },

    /// La dimensione del dato eccede il limite ammesso.
    #[error("il dato da proteggere supera il limite di {limit} byte")]
    TooLarge {
        /// Limite ammesso.
        limit: usize,
    },

    /// Errore di lettura o scrittura su disco.
    #[error("errore di accesso al file protetto: {0}")]
    Io(#[from] std::io::Error),

    /// Una frase di accesso non si e' lasciata derivare o verificare.
    ///
    /// Il motivo e' una costante e **non contiene mai la frase**: un errore
    /// che la citasse la scriverebbe in ogni posto in cui l'errore finisce.
    /// Una frase **sbagliata** non e' questo errore: e' una risposta, e vale
    /// «no».
    #[error("la frase di accesso non si e' potuta trattare: {reason}")]
    PassphraseFailed {
        /// Perche' non si e' potuta trattare.
        reason: &'static str,
    },

    /// La funzionalità non è disponibile su questa piattaforma.
    ///
    /// DPAPI esiste solo su Windows. Il crate compila altrove per non impedire
    /// il controllo del codice, ma non finge di proteggere nulla.
    #[error("la protezione locale e' disponibile soltanto su Windows")]
    UnsupportedPlatform,
}

impl SecurityError {
    /// Messaggio destinato all'operatore.
    #[must_use]
    pub const fn operator_message(&self) -> &'static str {
        match self {
            Self::ProtectionFailed { .. } => {
                "Non è stato possibile proteggere la configurazione. \
                 Verificare di essere connessi con il proprio profilo Windows."
            }
            Self::UnprotectionFailed { .. } => {
                "La configurazione non è leggibile con questo profilo Windows. \
                 Se il profilo o la postazione sono cambiati, va reinserita."
            }
            Self::NotConfigured => {
                "Nessuna configurazione presente: occorre inserire i parametri dell'applicazione."
            }
            Self::Corrupted { .. } | Self::NotValidText => {
                "La configurazione è danneggiata e va reinserita. \
                 Nessun contenuto già acquisito viene perso."
            }
            Self::MissingEntry { .. } => "La configurazione è incompleta e va reinserita.",
            Self::TooLarge { .. } => "Il dato da proteggere è troppo grande.",
            Self::PassphraseFailed { .. } => {
                "La frase di accesso non si è potuta verificare. Se il problema resta, chiedere a \
                 chi amministra di rimetterla."
            }
            Self::Io(_) => {
                "Non è stato possibile accedere al file di configurazione. \
                 Verificare i permessi della cartella dell'applicazione."
            }
            Self::UnsupportedPlatform => "La protezione locale è disponibile soltanto su Windows.",
        }
    }

    /// Etichetta stabile per l'audit.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::ProtectionFailed { .. } => "protezione_fallita",
            Self::UnprotectionFailed { .. } => "decifratura_fallita",
            Self::NotConfigured => "non_configurato",
            Self::Corrupted { .. } => "configurazione_danneggiata",
            Self::NotValidText => "testo_non_valido",
            Self::MissingEntry { .. } => "voce_mancante",
            Self::TooLarge { .. } => "dato_troppo_grande",
            Self::PassphraseFailed { .. } => "frase_non_trattabile",
            Self::Io(_) => "errore_di_accesso",
            Self::UnsupportedPlatform => "piattaforma_non_supportata",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SecurityError;

    #[test]
    fn every_error_offers_an_operator_message_and_a_kind() {
        for error in [
            SecurityError::ProtectionFailed { code: 5 },
            SecurityError::UnprotectionFailed { code: 13 },
            SecurityError::NotConfigured,
            SecurityError::Corrupted { reason: "prova" },
            SecurityError::NotValidText,
            SecurityError::MissingEntry { key: "api_id" },
            SecurityError::TooLarge { limit: 1 },
            SecurityError::UnsupportedPlatform,
        ] {
            assert!(!error.operator_message().is_empty());
            assert!(!error.kind().is_empty());
        }
    }

    #[test]
    fn a_failed_decryption_explains_the_profile_dependency() {
        // E' la causa piu' probabile e la meno intuitiva: va detta.
        let message = SecurityError::UnprotectionFailed { code: 13 }.operator_message();
        assert!(message.contains("profilo"));
    }

    #[test]
    fn a_corrupted_configuration_reassures_about_acquired_content() {
        let message = SecurityError::Corrupted { reason: "x" }.operator_message();
        assert!(message.contains("Nessun contenuto"));
    }
}

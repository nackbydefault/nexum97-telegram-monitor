//! Errori operativi registrati.
//!
//! Un errore che non lascia traccia rende lo storico ingannevole: un intervallo
//! senza contenuti potrebbe voler dire «nulla è stato pubblicato» oppure «la
//! rete era caduta». Registrare gli errori serve a distinguere i due casi.

use crate::id::{FaultId, SessionId, SourceId};
use crate::text::FaultMessage;
use crate::time::Timestamp;

string_enum!(
    /// Natura dell'errore registrato.
    FaultKind {
        /// Comunicazione con la piattaforma.
        Network => "network",
        /// Lettura o scrittura sulla persistenza.
        Storage => "storage",
        /// Analisi di un contenuto.
        Analysis => "analysis",
        /// Produzione di un export.
        Export => "export",
        /// Errore non riconducibile alle categorie precedenti.
        Internal => "internal",
    }
);

impl FaultKind {
    /// Il genere dell'errore, nella parola dell'operatore.
    ///
    /// Minuscola perché compare dentro una frase — «guasti registrati di
    /// genere "archivio"» nel passaggio di consegne — e in una colonna del
    /// registro, dove l'intestazione porta già la maiuscola. Sono le parole
    /// che il passaggio di consegne usava dal principio: stanno qui perché
    /// erano scritte in una funzione che confrontava **stringhe** e che per un
    /// genere non previsto rispondeva «interno» senza che nulla lo segnalasse
    /// (FINAL-PRODUCT-REVIEW-01, FPR-02).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Network => "collegamento",
            Self::Storage => "archivio",
            Self::Analysis => "analisi",
            Self::Export => "esportazione",
            Self::Internal => "interno",
        }
    }
}

/// Errore che si intende registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewFault {
    /// Sessione durante la quale l'errore si è verificato, quando applicabile.
    pub session_id: Option<SessionId>,
    /// Fonte interessata, quando applicabile.
    pub source_id: Option<SourceId>,
    /// Natura dell'errore.
    pub kind: FaultKind,
    /// Messaggio descrittivo.
    ///
    /// Deve essere comprensibile a un operatore non tecnico e non deve
    /// contenere segreti, token o credenziali.
    pub message: FaultMessage,
    /// Istante in cui l'errore si è verificato.
    pub occurred_at: Timestamp,
}

/// Errore registrato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    /// Identificatore assegnato dalla persistenza.
    pub id: FaultId,
    /// Sessione durante la quale l'errore si è verificato.
    pub session_id: Option<SessionId>,
    /// Fonte interessata.
    pub source_id: Option<SourceId>,
    /// Natura dell'errore.
    pub kind: FaultKind,
    /// Messaggio descrittivo.
    pub message: FaultMessage,
    /// Istante in cui l'errore si è verificato.
    pub occurred_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::FaultKind;
    use crate::error::DomainError;

    #[test]
    fn every_kind_survives_a_round_trip_through_its_stored_form() {
        for kind in FaultKind::all() {
            assert_eq!(FaultKind::from_str(kind.as_str()), Ok(*kind));
        }
    }

    #[test]
    fn an_unknown_kind_is_rejected() {
        assert!(matches!(
            FaultKind::from_str("sconosciuto"),
            Err(DomainError::UnknownVariant { .. })
        ));
    }

    #[test]
    fn ogni_genere_di_errore_ha_una_parola_per_chi_legge() {
        // Le stesse ragioni di `SourceKind::label`, con una differenza: queste
        // parole stanno dentro una frase — «guasti registrati di genere
        // "archivio"» — e quindi cominciano minuscole.
        let mut viste = std::collections::BTreeSet::new();
        for kind in FaultKind::all() {
            let parola = kind.label();
            assert!(!parola.is_empty(), "«{}» non ha una parola", kind.as_str());
            assert!(
                parola.chars().next().is_some_and(char::is_lowercase),
                "«{parola}» non si legge dentro una frase"
            );
            assert!(
                viste.insert(parola),
                "due generi diversi con la stessa parola: «{parola}»"
            );
        }
        assert_eq!(viste.len(), FaultKind::all().len());
    }
}

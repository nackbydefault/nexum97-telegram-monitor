//! Fonti monitorate.

use crate::id::SourceId;
use crate::text::{Actor, DisplayName, SourceIdentifier};
use crate::time::Timestamp;

string_enum!(
    /// Natura della fonte presso la piattaforma.
    ///
    /// Il supergruppo è distinto dal gruppo perché la piattaforma lo tratta
    /// come un'entità diversa, con un proprio intervallo di identificativi.
    /// Fonderli perderebbe un'informazione che serve a ricondurre un contenuto
    /// alla sua origine. La distinzione è stata introdotta dalla migrazione
    /// 0002, non modificando quella iniziale.
    SourceKind {
        /// Canale a diffusione unidirezionale.
        Channel => "channel",
        /// Gruppo con più partecipanti.
        Group => "group",
        /// Gruppo esteso, trattato dalla piattaforma come entità distinta.
        Supergroup => "supergroup",
    }
);

impl SourceKind {
    /// Descrizione mostrata all'operatore.
    ///
    /// Sta qui, accanto alla forma conservata, e per la stessa ragione di
    /// [`crate::model::SessionState::label`]: la stessa parola deve comparire
    /// nella schermata **e** nel registro che si allega a una relazione di
    /// servizio. La forma conservata (`channel`, `group`) è una chiave
    /// dell'archivio, e stamparla in un documento vorrebbe dire far tradurre a
    /// chi legge lo schema del programma (FINAL-PRODUCT-REVIEW-01, FPR-02).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Channel => "Canale",
            Self::Group => "Gruppo",
            Self::Supergroup => "Supergruppo",
        }
    }
}

/// Fonte che si intende registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSource {
    /// Natura della fonte.
    pub kind: SourceKind,
    /// Identificativo tecnico presso la piattaforma.
    pub identifier: SourceIdentifier,
    /// Nome leggibile mostrato all'operatore.
    pub display_name: DisplayName,
    /// Soggetto che ha autorizzato il monitoraggio della fonte.
    ///
    /// Il campo è obbligatorio: il prodotto monitora soltanto fonti autorizzate
    /// e l'autorizzazione deve essere riconducibile a una persona.
    pub authorized_by: Actor,
    /// Se la fonte è selezionabile per nuove sessioni.
    pub active: bool,
}

/// Fonte registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// Identificatore assegnato dalla persistenza.
    pub id: SourceId,
    /// Natura della fonte.
    pub kind: SourceKind,
    /// Identificativo tecnico presso la piattaforma.
    pub identifier: SourceIdentifier,
    /// Nome leggibile mostrato all'operatore.
    pub display_name: DisplayName,
    /// Soggetto che ha autorizzato il monitoraggio.
    pub authorized_by: Actor,
    /// Se la fonte è selezionabile per nuove sessioni.
    pub active: bool,
    /// Istante di registrazione.
    pub created_at: Timestamp,
    /// Istante dell'ultima modifica.
    pub updated_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::SourceKind;
    use crate::error::DomainError;

    #[test]
    fn every_kind_survives_a_round_trip_through_its_stored_form() {
        for kind in SourceKind::all() {
            assert_eq!(SourceKind::from_str(kind.as_str()), Ok(*kind));
        }
    }

    #[test]
    fn an_unknown_kind_is_rejected() {
        assert!(matches!(
            SourceKind::from_str("bot"),
            Err(DomainError::UnknownVariant { .. })
        ));
    }

    #[test]
    fn the_stored_form_is_lowercase_and_stable() {
        assert_eq!(SourceKind::Channel.as_str(), "channel");
        assert_eq!(SourceKind::Group.as_str(), "group");
    }

    #[test]
    fn ogni_genere_di_fonte_ha_una_parola_per_chi_legge() {
        // La forma conservata è una chiave dell'archivio: nel registro che si
        // allega a una relazione di servizio non ci va
        // (FINAL-PRODUCT-REVIEW-01, FPR-02).
        //
        // Il caso «valore sconosciuto» non esiste per costruzione: `label` è un
        // match esaustivo su un tipo chiuso, e un genere nuovo non compila
        // finché non ha la propria parola. È la differenza con la funzione che
        // il passaggio di consegne aveva, che confrontava stringhe e per un
        // genere non previsto rispondeva a caso.
        let mut viste = std::collections::BTreeSet::new();
        for kind in SourceKind::all() {
            let parola = kind.label();
            assert!(!parola.is_empty(), "«{}» non ha una parola", kind.as_str());
            assert_ne!(
                parola,
                kind.as_str(),
                "la parola mostrata è ancora la chiave conservata"
            );
            assert!(
                parola.chars().next().is_some_and(char::is_uppercase),
                "«{parola}» non comincia come una voce di tabella"
            );
            assert!(
                viste.insert(parola),
                "due generi diversi con la stessa parola: «{parola}»"
            );
        }
        assert_eq!(viste.len(), SourceKind::all().len());
    }
}

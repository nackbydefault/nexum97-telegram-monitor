//! Notifiche emesse.
//!
//! Qui vive soltanto ciò che si **conserva** di una notifica: che è stata
//! emessa, per quale contenuto, con quale livello di riservatezza. Il testo
//! mostrato all'operatore — che dipende dalla riservatezza scelta — è composto
//! dal livello dei servizi, dove la politica delle notifiche è coperta da test.
//!
//! # Perché si conserva che una notifica è stata emessa
//!
//! Per non emetterla due volte: la stessa segnalazione notificata a ogni
//! riavvio, o a ogni ripresa dopo un crash, sarebbe rumore. La deduplica è un
//! vincolo di schema — una notifica per contenuto — come per il resto
//! dell'archivio.

use crate::id::{ContentId, NotificationId, SessionId};
use crate::time::Timestamp;

string_enum!(
    /// Quanto una notifica rivela sulla schermata bloccata e altrove.
    ///
    /// La scelta è dell'ufficio: un contenuto sensibile che compare per intero
    /// su una schermata bloccata, visibile a chiunque passi, è una fuga che
    /// nessun controllo tecnico a valle recupera.
    NotificationPrivacy {
        /// Fonte, livello, estratto, motivazione, orario.
        Full => "full",
        /// Fonte e livello, senza il testo del contenuto.
        Reduced => "reduced",
        /// «Nuovo contenuto da esaminare», senza fonte né estratto.
        Confidential => "confidential",
    }
);

impl NotificationPrivacy {
    /// Descrizione mostrata all'operatore nelle impostazioni.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Full => "Completa",
            Self::Reduced => "Ridotta",
            Self::Confidential => "Riservata",
        }
    }

    /// Se la notifica può portare il testo del contenuto.
    ///
    /// Solo la modalità completa lo fa; le altre esistono apposta per non farlo.
    #[must_use]
    pub const fn shows_content(self) -> bool {
        matches!(self, Self::Full)
    }

    /// Se la notifica può nominare la fonte.
    #[must_use]
    pub const fn shows_source(self) -> bool {
        matches!(self, Self::Full | Self::Reduced)
    }
}

/// Notifica che si intende registrare come emessa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewNotification {
    /// Contenuto che ha generato la notifica.
    pub content_id: ContentId,
    /// Sessione durante la quale è stata emessa.
    pub session_id: SessionId,
    /// Riservatezza con cui è stata mostrata.
    pub privacy: NotificationPrivacy,
    /// Livello dell'allarme che l'ha generata, da 1 a 4.
    pub level: u8,
    /// Istante di emissione.
    pub emitted_at: Timestamp,
    /// Se il contenuto è stato recuperato dallo storico: si annuncia con un
    /// avviso solo per tutti, e non conta nel tetto per sessione
    /// (NOTIFY-BACKFILL-01, ADR-0188).
    pub recovered: bool,
}

/// Notifica registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmittedNotification {
    /// Identificatore assegnato dalla persistenza.
    pub id: NotificationId,
    /// Contenuto che ha generato la notifica.
    pub content_id: ContentId,
    /// Sessione durante la quale è stata emessa.
    pub session_id: SessionId,
    /// Riservatezza con cui è stata mostrata.
    pub privacy: NotificationPrivacy,
    /// Livello dell'allarme.
    pub level: u8,
    /// Istante di emissione.
    pub emitted_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::NotificationPrivacy;

    #[test]
    fn only_the_full_mode_shows_the_content() {
        assert!(NotificationPrivacy::Full.shows_content());
        assert!(!NotificationPrivacy::Reduced.shows_content());
        assert!(!NotificationPrivacy::Confidential.shows_content());
    }

    #[test]
    fn the_confidential_mode_hides_even_the_source() {
        assert!(NotificationPrivacy::Full.shows_source());
        assert!(NotificationPrivacy::Reduced.shows_source());
        assert!(
            !NotificationPrivacy::Confidential.shows_source(),
            "la modalita' riservata non nomina la fonte"
        );
    }

    #[test]
    fn every_mode_has_a_distinct_readable_label() {
        let labels: Vec<&str> = NotificationPrivacy::all()
            .iter()
            .map(|mode| mode.label())
            .collect();
        for label in &labels {
            assert!(!label.is_empty());
            assert_eq!(labels.iter().filter(|other| *other == label).count(), 1);
        }
    }
}

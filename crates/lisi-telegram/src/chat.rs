//! Chat già accessibili all'account.
//!
//! # Che cosa questo modulo non offre, e perché
//!
//! Non esiste alcuna funzione per **cercare** chat sulla piattaforma né per
//! **entrare** in un gruppo. L'assenza è deliberata e va letta come parte del
//! progetto: il prodotto monitora soltanto fonti già accessibili all'account
//! d'ufficio, e un ingresso automatico in un gruppo privato sarebbe fuori dai
//! non-obiettivi dichiarati nei requisiti.
//!
//! L'unica operazione è elencare ciò a cui l'account **ha già accesso**. La
//! ricerca che il prodotto offre all'operatore filtra quell'elenco in locale,
//! non interroga la piattaforma.

use core::fmt;

use crate::identifier::ChatId;

/// Natura di una chat presso la piattaforma.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChatKind {
    /// Canale a diffusione unidirezionale.
    Channel,
    /// Gruppo con più partecipanti.
    Group,
    /// Gruppo esteso, che la piattaforma tratta come entità distinta.
    Supergroup,
}

impl ChatKind {
    /// Tutte le varianti.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Channel, Self::Group, Self::Supergroup]
    }

    /// Etichetta stabile, che coincide con la forma conservata nel database.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Channel => "channel",
            Self::Group => "group",
            Self::Supergroup => "supergroup",
        }
    }

    /// Descrizione mostrata all'operatore.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Channel => "Canale",
            Self::Group => "Gruppo",
            Self::Supergroup => "Supergruppo",
        }
    }
}

impl fmt::Display for ChatKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Chat a cui l'account ha **già** accesso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessibleChat {
    /// Identificativo presso la piattaforma.
    pub chat_id: ChatId,
    /// Titolo leggibile.
    pub title: String,
    /// Natura della chat.
    pub kind: ChatKind,
    /// Username pubblico, senza chiocciola, quando la chat ne ha uno.
    ///
    /// È ciò che si digita per raggiungere una fonte e ciò che compare nei suoi
    /// collegamenti pubblici, e serve soprattutto a **distinguere due chat con
    /// lo stesso titolo** — che è il caso in cui un operatore rischia di
    /// configurare la fonte sbagliata.
    ///
    /// Assente per i gruppi privati e per i supergruppi che non ne hanno uno.
    /// Come per gli utenti, **non è un'identità**: uno username può essere
    /// rilasciato e ripreso da un'altra chat. L'identità è l'identificativo.
    pub username: Option<String>,
    /// Se l'account può leggere lo storico dei messaggi.
    ///
    /// Una chat accessibile ma di cui non si può leggere lo storico non è
    /// monitorabile in modo utile: va mostrata all'operatore e distinta, non
    /// nascosta, perché l'operatore possa capire perché non è selezionabile.
    pub can_read_history: bool,
}

impl AccessibleChat {
    /// Se la chat è utilizzabile come fonte di monitoraggio.
    #[must_use]
    pub const fn is_monitorable(&self) -> bool {
        self.can_read_history
    }
}

#[cfg(test)]
mod tests {
    use super::{AccessibleChat, ChatKind};
    use crate::identifier::ChatId;

    fn chat(kind: ChatKind, readable: bool) -> AccessibleChat {
        let Ok(chat_id) = ChatId::try_new(-1_001) else {
            panic!("l'identificativo di prova deve essere valido");
        };
        AccessibleChat {
            chat_id,
            title: String::from("Prova"),
            kind,
            username: None,
            can_read_history: readable,
        }
    }

    #[test]
    fn the_three_kinds_are_distinct_and_stable() {
        assert_eq!(ChatKind::all().len(), 3);
        for (index, kind) in ChatKind::all().iter().enumerate() {
            assert!(!kind.as_str().is_empty());
            assert!(!kind.label().is_empty());
            for other in ChatKind::all().iter().skip(index + 1) {
                assert_ne!(kind.as_str(), other.as_str());
                assert_ne!(kind.label(), other.label());
            }
        }
    }

    #[test]
    fn the_stored_form_matches_the_domain_kind() {
        // Le due enumerazioni vivono in crate diversi: se divergessero, una
        // fonte non sarebbe piu' salvabile. Il legame e' verificato qui.
        assert_eq!(ChatKind::Channel.as_str(), "channel");
        assert_eq!(ChatKind::Group.as_str(), "group");
        assert_eq!(ChatKind::Supergroup.as_str(), "supergroup");
    }

    #[test]
    fn a_chat_without_readable_history_is_not_monitorable() {
        assert!(chat(ChatKind::Channel, true).is_monitorable());
        assert!(!chat(ChatKind::Channel, false).is_monitorable());
    }
}

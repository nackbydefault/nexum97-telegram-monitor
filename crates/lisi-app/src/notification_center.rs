//! Collegamento fra il centro notifiche e il servizio delle notifiche.
//!
//! Come gli altri moduli di collegamento, non contiene logica: traduce le
//! notifiche emesse (`NotificationService::history`) in righe dell'interfaccia.
//! Il centro è di sola lettura, ed è una revisione in-app (DEC-105).

use std::rc::Rc;

use lisi_core::model::AnalysisLevel;
use lisi_services::notification::{NotificationEntry, NotificationService};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::{AppWindow, NotificationCard};

/// Servizio delle notifiche condiviso fra i gestori.
pub type SharedNotifications = Rc<NotificationService>;

/// Indice della pagina Notifiche nell'interfaccia.
///
/// Usato solo dal test che lo lega al file `.slint`: la navigazione avviene
/// nella voce di menu, non da Rust.
#[cfg(test)]
const NOTIFICATIONS_PAGE: i32 = 13;

/// Crea il servizio delle notifiche sull'archivio indicato.
#[must_use]
pub fn create_service(database: lisi_services::Database) -> Option<SharedNotifications> {
    Some(Rc::new(NotificationService::new(database)))
}

/// Etichetta del livello, dalla fonte unica del dominio.
///
/// Le notifiche esistono dal livello 1 in su, e il livello conservato è già
/// stato validato; se non fosse interpretabile si mostra il solo numero invece
/// di cadere.
fn level_label(level: u8) -> String {
    AnalysisLevel::try_new(level)
        .map_or_else(|_| format!("Livello {level}"), |analysis| analysis.label())
}

/// Traduce una notifica emessa in una scheda dell'interfaccia.
fn card(entry: &NotificationEntry) -> NotificationCard {
    NotificationCard {
        emitted: SharedString::from(entry.emitted_at.to_readable_local()),
        source: SharedString::from(entry.source_name.as_str()),
        level_label: SharedString::from(level_label(entry.level)),
        privacy: crate::lingua::schermo(entry.privacy.label()),
        reason: SharedString::from(entry.reason.as_str()),
        excerpt: SharedString::from(entry.excerpt.as_str()),
        url: SharedString::from(entry.url.as_deref().unwrap_or_default()),
    }
}

/// Riporta nell'interfaccia le notifiche emesse.
pub fn refresh(window: &AppWindow, service: &SharedNotifications) {
    let cards: Vec<NotificationCard> = match service.history() {
        Ok(entries) => entries.iter().map(card).collect(),
        Err(error) => {
            tracing::warn!(kind = error.kind(), "centro notifiche non leggibile");
            Vec::new()
        }
    };
    window.set_notification_cards(ModelRc::from(Rc::new(VecModel::from(cards))));
}

/// Collega i comandi della schermata al servizio.
pub fn wire(window: &AppWindow, service: &SharedNotifications) {
    let handle = window.as_weak();
    let service = Rc::clone(service);
    window.on_notifications_shown(move || {
        if let Some(window) = handle.upgrade() {
            refresh(&window, &service);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{NOTIFICATIONS_PAGE, level_label};

    /// Interfaccia, letta a tempo di compilazione per il controllo qui sotto.
    const UI: &str = include_str!("../ui/app-window.slint");

    #[test]
    fn the_notifications_page_index_matches_the_interface() {
        assert_eq!(NOTIFICATIONS_PAGE, 13);
        assert!(
            UI.contains(&format!("current-page == {NOTIFICATIONS_PAGE}: Rectangle")),
            "la pagina Notifiche con indice {NOTIFICATIONS_PAGE} non e' nell'interfaccia"
        );
        assert!(
            UI.contains(&format!("root.open-page({NOTIFICATIONS_PAGE});")),
            "la voce di menu Notifiche non naviga all'indice {NOTIFICATIONS_PAGE}"
        );
    }

    #[test]
    fn every_alert_level_has_a_readable_label() {
        for level in 1..=4 {
            let label = level_label(level);
            assert!(label.contains(&format!("Livello {level}")));
            // Ogni livello ha una parola che ne dice il senso, non solo il numero.
            assert!(label.contains('\u{2014}'), "{label}");
        }
    }
}

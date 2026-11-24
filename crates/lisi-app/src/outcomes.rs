//! Gli esiti di un'azione non seguono l'operatore in un'altra schermata
//! (OPERATOR-E2E-REMEDIATION-01, F-27).
//!
//! # Il difetto
//!
//! «Impostazioni salvate.», «Rapporto prodotto…», «Account creato e
//! selezionato…» restavano scritti dopo altre azioni e dopo un cambio di
//! schermata: tornando, l'operatore leggeva l'esito di un gesto di un'ora prima
//! come se fosse appena successo. Un esito dice che cosa ha fatto **l'ultimo
//! comando di quella schermata**, e vale finché si resta lì.
//!
//! # Che cosa non si tocca
//!
//! Gli avvisi che descrivono uno **stato** — un azzeramento in attesa, un
//! monitoraggio interrotto, la postazione bloccata, l'archivio non leggibile —
//! non sono esiti e restano finché lo stato dura. Qui si tolgono soltanto le
//! frasi che rispondono a un comando.

use slint::{ComponentHandle, SharedString};

use crate::AppWindow;

/// Toglie gli esiti dell'ultima azione, quando si cambia schermata.
pub fn wire(window: &AppWindow) {
    let handle = window.as_weak();
    window.on_page_opened(move |_pagina| {
        if crate::lock::refuse_while_locked("page_opened") {
            return;
        }
        if let Some(window) = handle.upgrade() {
            clear(&window);
        }
    });
}

/// Gli esiti che rispondono a un comando, e nient'altro.
fn clear(window: &AppWindow) {
    let vuoto = SharedString::default;
    window.set_account_management_message(vuoto());
    window.set_settings_message(vuoto());
    window.set_lock_settings_message(vuoto());
    window.set_report_message(vuoto());
    window.set_report_folder_message(vuoto());
    window.set_template_message(vuoto());
    window.set_template_form_message(vuoto());
    window.set_saved_search_message(vuoto());
    window.set_workspace_message(vuoto());
    window.set_bookmark_message(vuoto());
    window.set_dictionaries_message(vuoto());
    window.set_sources_message(vuoto());
    window.set_station_message(vuoto());
    window.set_references_message(vuoto());
    window.set_organisations_message(vuoto());
    window.set_backup_message(vuoto());
    window.set_retention_message(vuoto());
    window.set_handover_message(vuoto());
    window.set_evidence_message(vuoto());
    window.set_diagnostics_export_message(vuoto());
    window.set_team_live_backup_message(vuoto());
    window.set_team_live_people_message(vuoto());
    window.set_open_exercise_message(vuoto());
    // Gli esiti delle ricerche ricorrenti, dei suggerimenti e delle
    // valutazioni delle fonti (CYBER-WATCH-02, SOURCE-SUGGEST-01,
    // SOURCE-RELIABILITY-01).
    window.set_cyber_recurring_feedback(vuoto());
    window.set_source_suggestion_feedback(vuoto());
    window.set_source_reliability_feedback(vuoto());
}

#[cfg(test)]
mod tests {
    use slint::{ComponentHandle, LogicalSize, SharedString};

    use crate::AppWindow;

    /// **Un esito non resta scritto in un'altra schermata** (F-27).
    ///
    /// Senza il collegamento «Impostazioni salvate.» resta ancora
    /// lì dopo essere passati al Cruscotto e tornati.
    #[test]
    fn cambiando_schermata_l_esito_si_toglie() {
        i_slint_backend_testing::init_no_event_loop();
        let Ok(window) = AppWindow::new() else {
            panic!("la finestra di prova deve potersi costruire");
        };
        window.window().set_size(LogicalSize::new(1120.0, 720.0));
        super::wire(&window);
        window.invoke_open_page(11);
        window.set_settings_message(SharedString::from("Impostazioni salvate."));
        window.set_report_message(SharedString::from("Rapporto prodotto."));
        window.invoke_open_page(0);
        window.invoke_open_page(11);
        assert_eq!(window.get_settings_message(), "");
        assert_eq!(window.get_report_message(), "");
    }

    /// **Riaprire la stessa schermata non toglie l'esito appena scritto.**
    #[test]
    fn la_stessa_schermata_non_cancella() {
        i_slint_backend_testing::init_no_event_loop();
        let Ok(window) = AppWindow::new() else {
            panic!("la finestra di prova deve potersi costruire");
        };
        super::wire(&window);
        window.invoke_open_page(11);
        window.set_settings_message(SharedString::from("Impostazioni salvate."));
        window.invoke_open_page(11);
        assert_eq!(window.get_settings_message(), "Impostazioni salvate.");
    }
}

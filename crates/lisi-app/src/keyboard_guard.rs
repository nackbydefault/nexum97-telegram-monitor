//! Il menu con la tastiera (OPERATOR-E2E-REMEDIATION-01, F-15).
//!
//! OPERATOR-E2E-04 ha contato trentatré arresti del Tab prima del contenuto di
//! ogni schermata: le trentadue voci del menu, una dopo l'altra. Qui i tasti
//! arrivano davvero alla finestra: il Tab si ferma sulla voce attiva e passa
//! oltre, le frecce scorrono il menu, Invio apre.

#[cfg(test)]
mod tests {
    use i_slint_backend_testing::{AccessibleRole, ElementHandle};
    use slint::platform::{PointerEventButton, WindowEvent};
    use slint::{ComponentHandle, LogicalSize, SharedString};

    use crate::AppWindow;

    const TAB: &str = "\t";
    const INVIO: &str = "\n";
    const GIU: &str = "\u{F701}";
    const SU: &str = "\u{F700}";

    fn tasto(window: &AppWindow, testo: &str) {
        let text: SharedString = testo.into();
        window
            .window()
            .dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
        window
            .window()
            .dispatch_event(WindowEvent::KeyReleased { text });
    }

    fn finestra() -> AppWindow {
        i_slint_backend_testing::init_no_event_loop();
        let Ok(window) = AppWindow::new() else {
            panic!("la finestra di prova deve potersi costruire");
        };
        // La lingua di partenza, come fa il programma dopo aver creato la
        // finestra: da sola Slint sceglierebbe quella del sistema, e su un
        // Windows in inglese queste etichette non ci sarebbero (DEC-516).
        if slint::select_bundled_translation("").is_err() {
            panic!("la lingua di partenza deve potersi scegliere");
        }
        window.window().set_size(LogicalSize::new(1120.0, 720.0));
        if window.show().is_err() {
            panic!("la finestra di prova deve potersi mostrare");
        }
        window
    }

    /// La voce del menu con quell'etichetta.
    fn voce(window: &AppWindow, etichetta: &str) -> ElementHandle {
        let trovate: Vec<ElementHandle> =
            ElementHandle::find_by_accessible_label(window, etichetta)
                .filter(|elemento| elemento.accessible_role() == Some(AccessibleRole::Button))
                .collect();
        let Some(voce) = trovate.into_iter().next() else {
            panic!("la voce «{etichetta}» del menu non si trova");
        };
        voce
    }

    /// **Le frecce scorrono il menu, nell'ordine in cui si legge.**
    #[test]
    fn le_frecce_scorrono_il_menu() {
        let window = finestra();
        voce(&window, "Cruscotto").mock_single_click(PointerEventButton::Left);
        assert_eq!(window.get_current_page(), 0);

        tasto(&window, GIU);
        tasto(&window, INVIO);
        assert_eq!(
            window.get_current_page(),
            6,
            "la freccia giù dal Cruscotto porta a «Nuovo monitoraggio»"
        );
        tasto(&window, SU);
        tasto(&window, INVIO);
        assert_eq!(
            window.get_current_page(),
            0,
            "la freccia su riporta indietro"
        );
    }

    /// **Il Tab non attraversa il menu** (F-15): dalla voce attiva passa al
    /// contenuto.
    ///
    /// Vista rossa prima della correzione: dalla voce «Nuovo monitoraggio» il
    /// Tab andava a «Monitoraggio», e Invio la apriva.
    #[test]
    fn il_tab_non_attraversa_il_menu() {
        let window = finestra();
        voce(&window, "Nuovo monitoraggio").mock_single_click(PointerEventButton::Left);
        assert_eq!(window.get_current_page(), 6);
        tasto(&window, TAB);
        tasto(&window, INVIO);
        assert_eq!(
            window.get_current_page(),
            6,
            "il Tab ha portato a un'altra voce del menu invece che al contenuto"
        );
    }
}

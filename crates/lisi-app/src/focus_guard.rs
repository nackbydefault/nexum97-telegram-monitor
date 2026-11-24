//! Il fuoco da tastiera dopo un'azione (A11Y-02, ADR-0194, E2E01-09).
//!
//! INSTALLED-APP-E2E-01 ha visto il fuoco perdersi a ogni azione: il giro del
//! Tab ripartiva dalla barra del titolo o dal menu, e Tab più Spazio alla cieca
//! poteva premere «Chiudi». La sonda sul backend di prova ha misurato perché:
//! quando un'azione toglie l'elemento che aveva il fuoco, Slint non lo sposta,
//! e Shift+Tab riparte proprio da «Chiudi». La stessa sonda ha trovato la
//! domanda prima di chiudere chiusa alla tastiera: il Tab non usciva mai dal
//! riquadro e i due comandi non si raggiungevano.
//!
//! Il backend di prova non dice dove sta il fuoco. Queste prove lo leggono da
//! `FocusRule`, che lo dice per l'inizio della schermata, e dagli effetti dei
//! tasti: quale comando parte con Invio.

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::time::Duration;

    use slint::platform::WindowEvent;
    use slint::{ComponentHandle, LogicalSize, SharedString};

    use crate::{AppWindow, FocusRule};

    const TAB: &str = "\t";
    const SHIFT_TAB: &str = "\u{19}";
    const INVIO: &str = "\n";
    const ESC: &str = "\u{1b}";

    type Registro = Rc<RefCell<Vec<&'static str>>>;

    /// Un tasto premuto e rilasciato, poi il tempo che serve al
    /// temporizzatore della regola per riportare il fuoco.
    fn tasto(window: &AppWindow, testo: &str) {
        let text: SharedString = testo.into();
        window
            .window()
            .dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
        window
            .window()
            .dispatch_event(WindowEvent::KeyReleased { text });
        i_slint_backend_testing::mock_elapsed_time(Duration::from_millis(20));
    }

    /// La finestra sul «Nuovo monitoraggio», con i comandi della barra del
    /// titolo e della domanda prima di chiudere che scrivono nel registro.
    fn finestra(registro: &Registro) -> AppWindow {
        i_slint_backend_testing::init_no_event_loop();
        let Ok(window) = AppWindow::new() else {
            panic!("la finestra di prova deve potersi costruire");
        };
        window.window().set_size(LogicalSize::new(1120.0, 720.0));
        if window.show().is_err() {
            panic!("la finestra di prova deve potersi mostrare");
        }
        window.set_current_page(6);
        let r = registro.clone();
        window.on_minimise_window(move || r.borrow_mut().push("riduci"));
        let r = registro.clone();
        window.on_toggle_maximise_window(move || r.borrow_mut().push("ingrandisci"));
        let r = registro.clone();
        window.on_close_window(move || r.borrow_mut().push("chiudi"));
        let r = registro.clone();
        let debole = window.as_weak();
        window.on_close_withdrawn(move || {
            r.borrow_mut().push("resta aperto");
            if let Some(window) = debole.upgrade() {
                window.set_close_question_open(false);
            }
        });
        let r = registro.clone();
        let debole = window.as_weak();
        window.on_close_confirmed(move || {
            r.borrow_mut().push("chiudi comunque");
            if let Some(window) = debole.upgrade() {
                window.set_close_question_open(false);
            }
        });
        window
    }

    fn fatti(registro: &Registro) -> Vec<&'static str> {
        registro.borrow_mut().drain(..).collect()
    }

    fn all_inizio(window: &AppWindow) -> bool {
        window.global::<FocusRule>().get_at_screen_start()
    }

    fn riprese(window: &AppWindow) -> i32 {
        window.global::<FocusRule>().get_resumed()
    }

    /// **Il Tab senza fuoco riprende dall'inizio della schermata**, non dal
    /// primo elemento della finestra.
    #[test]
    fn il_tab_senza_fuoco_riprende_dall_inizio_della_schermata() {
        let registro = Registro::default();
        let window = finestra(&registro);
        tasto(&window, TAB);
        assert!(
            all_inizio(&window),
            "il fuoco non è all'inizio della schermata"
        );
        assert_eq!(riprese(&window), 1);
        tasto(&window, INVIO);
        assert_eq!(window.get_current_page(), 6);
        assert!(
            fatti(&registro).is_empty(),
            "Invio all'inizio della schermata non fa nulla"
        );
    }

    /// **Shift+Tab senza fuoco non parte da «Chiudi».**
    ///
    /// Vista rossa prima della regola: Shift+Tab e Invio chiamavano la
    /// chiusura della finestra, il secondo giro l'ingrandimento.
    #[test]
    fn shift_tab_senza_fuoco_non_parte_da_chiudi() {
        let registro = Registro::default();
        let window = finestra(&registro);
        tasto(&window, SHIFT_TAB);
        tasto(&window, INVIO);
        assert!(
            fatti(&registro).is_empty(),
            "Shift+Tab e Invio hanno premuto un comando"
        );
        assert!(all_inizio(&window));
        assert_eq!(riprese(&window), 1);
    }

    /// **La domanda prima di chiudere tiene il Tab fra le due uscite**, e
    /// parte da quella che non perde niente.
    ///
    /// Vista rossa prima della correzione: Tab e Invio non facevano nulla, il
    /// fuoco restava a un elemento che accettava ogni tasto.
    #[test]
    fn la_domanda_di_chiusura_tiene_il_tab_fra_le_due_uscite() {
        let registro = Registro::default();
        let window = finestra(&registro);

        window.set_close_question_open(true);
        tasto(&window, INVIO);
        assert_eq!(
            fatti(&registro),
            ["resta aperto"],
            "il fuoco parte da «Resta aperto»"
        );

        window.set_close_question_open(true);
        tasto(&window, TAB);
        tasto(&window, INVIO);
        assert_eq!(fatti(&registro), ["chiudi comunque"]);

        window.set_close_question_open(true);
        tasto(&window, TAB);
        tasto(&window, TAB);
        tasto(&window, INVIO);
        assert_eq!(
            fatti(&registro),
            ["resta aperto"],
            "il Tab gira, non esce dal riquadro"
        );

        window.set_close_question_open(true);
        tasto(&window, SHIFT_TAB);
        tasto(&window, ESC);
        assert_eq!(
            fatti(&registro),
            ["resta aperto"],
            "Esc resta aperto anche da un comando"
        );
    }

    /// **Dopo un'azione che toglie il comando, il fuoco riprende
    /// dall'inizio della schermata**: è il caso di E2E01-09.
    #[test]
    fn dopo_resta_aperto_il_fuoco_riprende_dall_inizio_della_schermata() {
        let registro = Registro::default();
        let window = finestra(&registro);
        window.set_close_question_open(true);
        tasto(&window, INVIO);
        assert_eq!(fatti(&registro), ["resta aperto"]);
        assert_eq!(
            riprese(&window),
            0,
            "il fuoco non si riprende finché non serve"
        );

        tasto(&window, SHIFT_TAB);
        assert!(all_inizio(&window));
        assert_eq!(riprese(&window), 1);
        tasto(&window, INVIO);
        assert!(fatti(&registro).is_empty());
    }

    /// **Il giro del Tab non si ferma sulle riprese.** Da un elemento vivo il
    /// Tab passa oltre il primo e l'ultimo elemento della finestra, e la
    /// barra del titolo resta raggiungibile.
    #[test]
    fn il_giro_del_tab_non_si_ferma_sulle_riprese() {
        let registro = Registro::default();
        let window = finestra(&registro);
        tasto(&window, TAB);
        assert_eq!(riprese(&window), 1);

        for _ in 0..120 {
            tasto(&window, TAB);
        }
        assert_eq!(
            riprese(&window),
            1,
            "il Tab da un elemento vivo è finito su una ripresa"
        );
        for _ in 0..120 {
            tasto(&window, SHIFT_TAB);
        }
        assert_eq!(
            riprese(&window),
            1,
            "Shift+Tab da un elemento vivo è finito su una ripresa"
        );
    }

    /// **La barra del titolo resta nel giro**: dall'inizio della schermata,
    /// Shift+Tab arriva al menu e poi, girando all'indietro, a «Chiudi».
    #[test]
    fn la_barra_del_titolo_resta_raggiungibile() {
        let registro = Registro::default();
        let window = finestra(&registro);
        tasto(&window, TAB);
        let mut visti = Vec::new();
        for _ in 0..120 {
            tasto(&window, SHIFT_TAB);
            tasto(&window, INVIO);
            visti.extend(fatti(&registro));
            if visti.contains(&"chiudi") {
                break;
            }
        }
        assert!(
            visti.contains(&"chiudi"),
            "«Chiudi» non si raggiunge più col Tab: {visti:?}"
        );
    }
}

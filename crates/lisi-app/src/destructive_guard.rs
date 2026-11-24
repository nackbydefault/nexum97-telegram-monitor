//! I comandi distruttivi di Account, provati come li proverebbe una mano che
//! sbaglia (OPERATOR-E2E-REMEDIATION-01, F-03, ADR-0140).
//!
//! # Perché queste prove esistono
//!
//! Fino a questa milestone la conferma di un azzeramento era un secondo clic
//! sullo **stesso** pulsante, che cambiava testo. Un doppio clic — il gesto più
//! comune di chi non è sicuro di aver premuto — armava e confermava insieme. La
//! decisione dell'ufficio (ADR-0140) lascia gli azzeramenti all'operatore, e
//! proprio per questo la protezione deve stare nel gesto: spiegazione,
//! conferma esplicita su un comando diverso, nessuna attivazione accidentale.
//!
//! Qui i pulsanti si premono dalla via delle tecnologie assistive, che è la
//! stessa per il mouse e per un programma: se il secondo colpo sullo stesso
//! punto arrivasse in fondo, il registro dei gestori lo direbbe.

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use i_slint_backend_testing::ElementHandle;
    use slint::{ComponentHandle, LogicalSize};

    use crate::AppWindow;

    /// La schermata Account.
    const ACCOUNT_PAGE: i32 = 2;

    type Registro = Rc<RefCell<Vec<&'static str>>>;

    fn finestra() -> (AppWindow, Registro) {
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
        let registro: Registro = Rc::new(RefCell::new(Vec::new()));
        {
            let registro = Rc::clone(&registro);
            window.on_reset_history(move || registro.borrow_mut().push("reset_history"));
        }
        {
            let registro = Rc::clone(&registro);
            window.on_reset_accounts(move || registro.borrow_mut().push("reset_accounts"));
        }
        {
            let registro = Rc::clone(&registro);
            window.on_remove_account(move || registro.borrow_mut().push("remove_account"));
        }
        window.set_account_selected(true);
        window.invoke_open_page(ACCOUNT_PAGE);
        (window, registro)
    }

    /// Preme il comando con quell'etichetta; falso se non c'è.
    fn premi(window: &AppWindow, etichetta: &str) -> bool {
        let trovati: Vec<ElementHandle> =
            ElementHandle::find_by_accessible_label(window, etichetta).collect();
        let Some(pulsante) = trovati.first() else {
            return false;
        };
        pulsante.invoke_accessible_default_action();
        true
    }

    /// **Un doppio clic su un comando distruttivo non conferma nulla.**
    ///
    /// Vista rossa con la conferma sul secondo clic dello stesso pulsante:
    /// «reset_history» arrivava al gestore dopo due colpi sullo stesso punto.
    #[test]
    fn un_doppio_clic_non_conferma_un_azzeramento() {
        let (window, registro) = finestra();
        assert!(
            premi(&window, "Azzeramento e rimozione…"),
            "la zona degli azzeramenti deve aprirsi"
        );
        for etichetta in [
            "Azzera l'intero archivio…",
            "Azzera account e profili…",
            "Rimuovi l'account selezionato…",
        ] {
            assert!(premi(&window, etichetta), "«{etichetta}» non si trova");
            premi(&window, etichetta);
            assert!(
                registro.borrow().is_empty(),
                "due colpi su «{etichetta}» hanno eseguito {:?}",
                registro.borrow()
            );
            assert!(
                premi(&window, "Annulla"),
                "la conferma deve offrire «Annulla»"
            );
        }
        assert!(registro.borrow().is_empty());
    }

    /// **La conferma vera esegue una cosa sola, quella annunciata.**
    #[test]
    fn la_conferma_esegue_solo_cio_che_ha_annunciato() {
        let (window, registro) = finestra();
        assert!(premi(&window, "Azzeramento e rimozione…"));
        assert!(premi(&window, "Azzera account e profili…"));
        // Annullare disarma: la conferma non resta in attesa nascosta.
        assert!(premi(&window, "Annulla"));
        assert!(!premi(&window, "Sì, azzera account e profili"));

        assert!(premi(&window, "Azzera l'intero archivio…"));
        assert!(premi(&window, "Sì, cancella tutto l'archivio"));
        assert_eq!(*registro.borrow(), vec!["reset_history"]);
        // Eseguito, il comando si disarma.
        assert!(!premi(&window, "Sì, cancella tutto l'archivio"));
    }
}

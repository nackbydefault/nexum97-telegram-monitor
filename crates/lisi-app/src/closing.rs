//! Chiudere la finestra con un monitoraggio in corso (OPERATOR-UX-REMEDIATION-01,
//! OS-09).
//!
//! # Che cosa cambia, e che cosa no
//!
//! La chiusura con un monitoraggio in corso **resta possibile**, ed è ciò che il
//! manuale descrive (§3.2): al riavvio un avviso dice che il monitoraggio è
//! stato interrotto, e il tratto resta non coperto. Ciò che mancava è dirlo
//! **prima**: la X chiudeva al primo clic, e l'operatore lo scopriva dopo.
//!
//! Quindi, se un monitoraggio acquisisce, la prima richiesta di chiusura non
//! chiude: apre una domanda nella finestra. «Chiudi comunque» chiude davvero;
//! «Resta aperto» la ritira. Nessun monitoraggio si ferma o si avvia da qui.
//!
//! # Perché non in Esercitazione
//!
//! In Esercitazione nulla acquisisce (ADR-0129) e nulla si interrompe: la
//! domanda direbbe una conseguenza che non esiste (FINAL-REVIEW-01, FR-032).

use std::cell::Cell;
use std::rc::Rc;

use lisi_services::Database;
use slint::{CloseRequestResponse, ComponentHandle};

use crate::AppWindow;

/// Frase mostrata a postazione bloccata a chi chiede di chiudere.
const CHIUSURA_A_POSTAZIONE_BLOCCATA: &str = "A postazione bloccata il programma non si chiude: prima si sblocca la postazione con la parola.";

/// Collega la domanda alla chiusura della finestra.
///
/// Senza archivio — o in Esercitazione, dove nulla acquisisce — non si sa né
/// serve sapere se qualcosa acquisisce, e la finestra si chiude come prima: una
/// domanda che non sa che cosa chiedere non si fa.
///
/// # A postazione bloccata la finestra non si chiude (OPERATOR-E2E-REMEDIATION-01, F-01)
///
/// In nessun modo, Esercitazione compresa: la richiesta di chiusura — la X,
/// Alt+F4, «Chiudi finestra» dalla barra delle applicazioni — è l'unico
/// comando del programma che arriva da Windows e non dalla schermata, e il
/// blocco esiste perché chi passa davanti non possa usare il programma. Con
/// un monitoraggio in corso, chiudere lo interromperebbe.
///
/// Il rischio che resta si dichiara: chi termina il processo da Gestione
/// attività, o chiude la sessione di Windows, lo chiude comunque, e al riavvio
/// la postazione non è bloccata. La protezione che regge fra un avvio e
/// l'altro è il blocco di Windows (si veda `lock`).
pub fn wire(window: &AppWindow, database: Option<Database>) {
    if database.is_none() {
        tracing::info!("chiusura: nessuna domanda prima di chiudere, nulla puo' acquisire");
    }
    let confermata = Rc::new(Cell::new(false));

    {
        let handle = window.as_weak();
        let confermata = Rc::clone(&confermata);
        window.window().on_close_requested(move || {
            if crate::lock::station_is_locked() {
                if let Some(window) = handle.upgrade() {
                    window.set_lock_message(crate::lingua::schermo(CHIUSURA_A_POSTAZIONE_BLOCCATA));
                }
                tracing::warn!("chiusura rifiutata: la postazione è bloccata");
                return CloseRequestResponse::KeepWindowShown;
            }
            if confermata.get() {
                return CloseRequestResponse::HideWindow;
            }
            let Some(database) = database.as_ref() else {
                return CloseRequestResponse::HideWindow;
            };
            let quanti = database.acquiring_session_count().unwrap_or_else(|errore| {
                tracing::warn!(
                    errore = %errore,
                    "chiusura: monitoraggi in corso non leggibili, si chiude senza domanda"
                );
                0
            });
            decide(quanti, &handle)
        });
    }

    {
        let handle = window.as_weak();
        window.on_close_confirmed(move || {
            if crate::lock::refuse_while_locked("close_confirmed") {
                return;
            }
            confermata.set(true);
            if let Some(window) = handle.upgrade() {
                window.set_close_question_open(false);
                if let Err(errore) = window.hide() {
                    tracing::warn!(errore = %errore, "chiusura confermata e non eseguita");
                }
            }
        });
    }

    {
        let handle = window.as_weak();
        window.on_close_withdrawn(move || {
            if crate::lock::refuse_while_locked("close_withdrawn") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                window.set_close_question_open(false);
            }
        });
    }
}

/// Chiude subito se nulla acquisisce; altrimenti apre la domanda.
fn decide(quanti: usize, handle: &slint::Weak<AppWindow>) -> CloseRequestResponse {
    if quanti == 0 {
        return CloseRequestResponse::HideWindow;
    }
    if let Some(window) = handle.upgrade() {
        window.set_close_question_open(true);
    }
    CloseRequestResponse::KeepWindowShown
}

#[cfg(test)]
mod tests {
    const MAIN: &str = include_str!("main.rs");
    const UI: &str = include_str!("../ui/app-window.slint");
    const THIS: &str = include_str!("closing.rs");

    /// **Con un monitoraggio che acquisisce, la prima chiusura chiede**; senza,
    /// chiude come prima. E la domanda non si collega in Esercitazione.
    #[test]
    fn la_chiusura_chiede_solo_quando_qualcosa_acquisisce() {
        assert!(
            THIS.contains("if quanti == 0 {\n        return CloseRequestResponse::HideWindow;")
        );
        assert!(THIS.contains("window.set_close_question_open(true);\n    }\n    CloseRequestResponse::KeepWindowShown"));
        assert!(
            MAIN.contains(
                "closing::wire(\n        &window,\n        if esercitazione_attiva {\n            None\n        } else {\n            storage.open()\n        },\n    );"
            ),
            "la domanda si collega fuori dall'Esercitazione, e il rifiuto a postazione \
             bloccata ovunque"
        );
    }

    /// **A postazione bloccata la finestra non si chiude**, e il rifiuto viene
    /// prima di ogni altra decisione (OPERATOR-E2E-REMEDIATION-01, F-01).
    #[test]
    fn a_postazione_bloccata_la_chiusura_si_rifiuta_per_prima() {
        let Some(gestore) = THIS.split("on_close_requested(move || {").nth(1) else {
            panic!("il gestore della chiusura deve esserci");
        };
        let blocco = gestore.find("station_is_locked()");
        let confermata = gestore.find("if confermata.get()");
        let (Some(blocco), Some(confermata)) = (blocco, confermata) else {
            panic!("il gestore controlla il blocco e la conferma");
        };
        assert!(
            blocco < confermata,
            "il blocco si controlla prima di tutto: nemmeno una conferma precedente chiude"
        );
        assert!(THIS.contains("return CloseRequestResponse::KeepWindowShown;\n            }\n            if confermata.get()"));
    }

    /// **La domanda ha due uscite, e dice la conseguenza.**
    #[test]
    fn la_domanda_dice_la_conseguenza_e_ha_due_uscite() {
        let Some(inizio) = UI.find("if root.close-question-open: Rectangle {") else {
            panic!("la domanda deve esserci");
        };
        let domanda = &UI[inizio..];
        let Some(fine) = domanda.find("// ---- fine della domanda di chiusura") else {
            panic!("la domanda deve chiudersi");
        };
        let domanda = &domanda[..fine];
        assert!(domanda.contains("root.close-confirmed();"));
        assert!(domanda.contains("root.close-withdrawn();"));
        assert!(
            domanda.contains("non coperto"),
            "dice che il tratto resta non coperto"
        );
    }

    /// **Arrestare e ricominciare passano da una conferma** (OS-09): il gesto
    /// che non si annulla si chiama in un punto solo, dentro il pulsante che
    /// conferma, e il primo clic apre soltanto la domanda.
    #[test]
    fn arrestare_e_ricominciare_chiedono_conferma() {
        for (gesto, conferma) in [
            (
                "root.monitoring-action(\"stop\");",
                "label: @tr(\"Sì, arresta\");",
            ),
            (
                "root.exercise-restart();",
                "label: @tr(\"Sì, ricomincia\");",
            ),
        ] {
            assert_eq!(
                UI.matches(gesto).count(),
                1,
                "{gesto} si chiama da un punto solo"
            );
            let Some(punto) = UI.find(gesto) else {
                panic!("{gesto} deve esserci");
            };
            let Some(etichetta) = UI[..punto].rfind("label: @tr(\"") else {
                panic!("{gesto} sta in un pulsante");
            };
            assert!(
                UI[etichetta..].starts_with(conferma),
                "{gesto} sta nel pulsante che conferma"
            );
        }
        assert!(UI.contains("root.monitoring-confirm-stop = true;"));
        assert!(UI.contains("root.exercise-confirm-restart = true;"));
    }
}

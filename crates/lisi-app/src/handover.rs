//! Il passaggio di consegne, nel cruscotto (PR-12, ADR-0128).
//!
//! Compone il foglio quando lo si chiede, lo mostra e lo esporta in testo o in
//! Word. **Non compone nulla da solo**, e non ha logica propria: le sei sezioni,
//! il criterio di «Da dove cominciare» e ciò che il foglio non nomina li decide
//! il servizio.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use lisi_services::Database;
use lisi_services::handover::{HANDOVER_SPANS_HOURS, Handover, HandoverFormat, HandoverService};
use slint::{ComponentHandle, SharedString};

use crate::AppWindow;

/// La sezione: il servizio e l'ultimo foglio composto.
pub struct HandoverScreen {
    service: HandoverService,
    last: Option<Handover>,
    /// La cartella dell'ultima esportazione riuscita, per «Apri la cartella»
    /// (SIM3-03). Quella che il servizio ha scritto, non un testo dello schermo.
    exported_to: Option<PathBuf>,
}

/// Sezione condivisa fra i gestori.
pub type SharedHandover = Rc<RefCell<HandoverScreen>>;

/// Crea la sezione sulla connessione indicata.
#[must_use]
pub fn create_service(database: Database) -> SharedHandover {
    Rc::new(RefCell::new(HandoverScreen {
        service: HandoverService::new(database),
        last: None,
        exported_to: None,
    }))
}

/// Compone il foglio dell'intervallo scelto.
fn compose(screen: &SharedHandover, indice: i32) -> Result<String, String> {
    let Some(ore) = usize::try_from(indice)
        .ok()
        .and_then(|indice| HANDOVER_SPANS_HOURS.get(indice).copied())
    else {
        return Err(String::from("Intervallo non riconosciuto."));
    };
    let mut screen = screen.borrow_mut();
    match screen.service.compose(ore, crate::account::now()) {
        Ok(foglio) => {
            let testo = foglio.as_text(crate::coverage::in_team());
            screen.last = Some(foglio);
            Ok(testo)
        }
        Err(errore) => Err(errore.operator_message()),
    }
}

/// Esporta l'ultimo foglio composto.
fn export(screen: &SharedHandover, formato: i32) -> String {
    let mut screen = screen.borrow_mut();
    screen.exported_to = None;
    let Some(foglio) = screen.last.as_ref() else {
        return String::from("Prima si compone il foglio, poi si esporta.");
    };
    let Ok(chi) = crate::operator::audit_actor() else {
        return String::from("Non si riesce a stabilire chi stia agendo su questa postazione.");
    };
    let formato = if formato == 1 {
        HandoverFormat::Word
    } else {
        HandoverFormat::Text
    };
    let cartella = match screen.service.destination() {
        Ok(cartella) => cartella,
        Err(errore) => return errore.operator_message(),
    };
    let esito = screen.service.export(
        foglio,
        formato,
        &cartella,
        crate::coverage::in_team(),
        &chi,
        crate::account::now(),
    );
    match esito {
        Ok(percorso) => {
            screen.exported_to = percorso.parent().map(std::path::Path::to_path_buf);
            format!("Foglio esportato in «{}».", percorso.display())
        }
        Err(errore) => errore.operator_message(),
    }
}

/// Collega i comandi della sezione.
pub fn wire(window: &AppWindow, screen: &SharedHandover) {
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_handover_compose(move || {
            if crate::lock::refuse_while_locked("handover_compose") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            match compose(&screen, window.get_handover_span()) {
                Ok(testo) => {
                    window.set_handover_text(SharedString::from(testo));
                    window.set_handover_message(SharedString::default());
                }
                Err(frase) => window.set_handover_message(crate::lingua::schermo(frase)),
            }
        });
    }
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_handover_export(move |formato| {
            if crate::lock::refuse_while_locked("handover_export") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            window.set_handover_message(SharedString::from(export(&screen, formato)));
            window.set_handover_folder_ready(screen.borrow().exported_to.is_some());
        });
    }
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_handover_open_folder(move || {
            if crate::lock::refuse_while_locked("handover_open_folder") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let cartella = screen.borrow().exported_to.clone();
            let frase = crate::report::open_folder_outcome(cartella.as_deref());
            if !frase.is_empty() {
                window.set_handover_message(crate::lingua::schermo(frase));
            }
        });
    }
}

#[cfg(test)]
mod tests {
    const THIS_MODULE: &str = include_str!("handover.rs");
    const MAIN: &str = include_str!("main.rs");

    /// **Il foglio si compone soltanto a richiesta**, e la sezione non ha
    /// logica propria.
    #[test]
    fn il_foglio_si_compone_soltanto_a_richiesta() {
        let Some((codice, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("blocco di prove riconoscibile");
        };
        assert_eq!(codice.matches("service.compose(").count(), 1);
        assert!(
            !MAIN.contains("handover::compose"),
            "nessun avvio lo compone"
        );
        for vietato in ["sort", "audit_entries", "session_contents"] {
            assert!(
                !codice.contains(vietato),
                "«{vietato}»: la logica sta nel servizio"
            );
        }
    }
}

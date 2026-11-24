//! «Risolvi dal PC» nella cronologia di un gruppo della schermata Cyber
//! Watch, e la scelta dell'amministratore in Impostazioni (IOC-RESOLVE-01,
//! ADR-0202).
//!
//! La richiesta passa dal servizio, che decide i rifiuti: risoluzione non
//! abilitata, Esercitazione, indicatore che non si risolve, richiesta troppo
//! vicina alla precedente. Qui si mostra ciò che dice. L'avvertenza su chi
//! può vedere la richiesta sta nella schermata, prima del pulsante.

use std::cell::RefCell;

use lisi_core::OperatingMode;
use lisi_services::indicator_resolution::{
    ResolutionAttempt, Resolver, StoredIndicatorResolution, choose, enabled, outcome_sentence,
    recent, resolvable, resolve,
};
use lisi_services::{Database, station};
use slint::{ComponentHandle, SharedString};

use crate::AppWindow;

thread_local! {
    /// L'archivio della sezione, aperto all'avvio.
    static ARCHIVIO: RefCell<Option<Database>> = const { RefCell::new(None) };
    /// L'indicatore della cronologia aperta: genere e valore.
    static INDICATORE: RefCell<Option<(String, String)>> = const { RefCell::new(None) };
}

/// Mette a disposizione l'archivio.
pub fn install(database: Option<Database>) {
    ARCHIVIO.with(|cella| *cella.borrow_mut() = database);
}

fn con_l_archivio<R>(lavoro: impl FnOnce(&mut Database) -> R) -> Option<R> {
    ARCHIVIO.with(|cella| cella.borrow_mut().as_mut().map(lavoro))
}

/// La cronologia di un indicatore si è aperta.
pub fn show_for(window: &AppWindow, kind: &str, value: &str) {
    INDICATORE.with(|cella| *cella.borrow_mut() = Some((kind.to_owned(), value.to_owned())));
    window.set_ioc_resolve_applicable(resolvable(kind));
    window.set_ioc_resolve_message(SharedString::default());
    refresh(window);
}

/// La cronologia si è chiusa.
pub fn hide(window: &AppWindow) {
    INDICATORE.with(|cella| *cella.borrow_mut() = None);
    window.set_ioc_resolve_applicable(false);
    window.set_ioc_resolve_message(SharedString::default());
    window.set_ioc_resolve_history(SharedString::default());
}

/// Una richiesta registrata, in una frase.
fn storia(richiesta: &StoredIndicatorResolution) -> String {
    format!(
        "{}: {} ha chiesto «{}». {}",
        richiesta.requested_at.to_readable_local(),
        richiesta.requested_by,
        richiesta.queried_name,
        outcome_sentence(&richiesta.outcome, &richiesta.answers, richiesta.error_code)
    )
}

/// Riporta in schermata la scelta, e le richieste dell'indicatore aperto.
pub fn refresh(window: &AppWindow) {
    let modalita = station::persisted_mode_or_restricted();
    window.set_ioc_resolve_administrator(modalita == OperatingMode::Administrator);
    let abilitata = con_l_archivio(|archivio| enabled(archivio)).and_then(Result::ok);
    window.set_ioc_resolve_enabled(abilitata == Some(true));
    window.set_ioc_resolve_state(crate::lingua::schermo(match abilitata {
        Some(true) => {
            "Abilitata: dalla cronologia di un gruppo si possono chiedere gli indirizzi di un dominio, o i nomi di un indirizzo. La richiesta si vede fuori."
        }
        Some(false) => "Spenta: nessun indicatore si risolve dal PC.",
        None => "L'archivio non è aperto: la scelta non si legge.",
    }));
    let Some((genere, valore)) = INDICATORE.with(|cella| cella.borrow().clone()) else {
        return;
    };
    let registro =
        con_l_archivio(|archivio| recent(archivio, &genere, &valore).unwrap_or_default())
            .unwrap_or_default();
    let righe: Vec<String> = registro.iter().map(storia).collect();
    window.set_ioc_resolve_history(SharedString::from(if righe.is_empty() {
        String::new()
    } else {
        format!("Richieste registrate:\n{}", righe.join("\n"))
    }));
}

/// Abilita o spegne la risoluzione.
fn scegli(abilita: bool) -> String {
    let Ok(attore) = crate::operator::audit_actor() else {
        return String::from(crate::account::NON_SI_SA_CHI_OPERA);
    };
    let modalita = station::persisted_mode_or_restricted();
    con_l_archivio(|archivio| {
        choose(archivio, abilita, modalita, &attore, crate::account::now())
            .unwrap_or_else(|errore| errore.operator_message())
    })
    .unwrap_or_else(|| String::from("L'archivio non è aperto: niente è cambiato."))
}

/// Risolve l'indicatore aperto. Restituisce la frase per l'operatore.
fn chiedi() -> String {
    let Some((genere, valore)) = INDICATORE.with(|cella| cella.borrow().clone()) else {
        return String::from("Nessun indicatore scelto.");
    };
    let Ok(attore) = crate::operator::audit_actor() else {
        return String::from(crate::account::NON_SI_SA_CHI_OPERA);
    };
    let esito = con_l_archivio(|archivio| {
        resolve(
            archivio,
            Resolver::of_this_pc(),
            &genere,
            &valore,
            &attore,
            lisi_services::run_mode::is_exercise(),
            crate::account::now(),
        )
    });
    match esito {
        None => String::from("L'archivio non è aperto: la richiesta non parte."),
        Some(Ok(ResolutionAttempt::Recorded { sentence, .. })) => {
            format!("Richiesta registrata. {sentence}")
        }
        Some(Ok(ResolutionAttempt::Refused(frase))) => frase,
        Some(Err(errore)) => {
            tracing::warn!(
                kind = errore.kind(),
                "risoluzione dell'indicatore non registrata"
            );
            errore.operator_message()
        }
    }
}

/// Collega i comandi della sezione e del pannello.
pub fn wire(window: &AppWindow) {
    {
        let handle = window.as_weak();
        window.on_ioc_resolve_request(move || {
            if crate::lock::refuse_while_locked("ioc_resolve_request") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let frase = chiedi();
            refresh(&window);
            window.set_ioc_resolve_message(crate::lingua::schermo(frase));
        });
    }
    {
        let handle = window.as_weak();
        window.on_ioc_resolve_enable(move || {
            if crate::lock::refuse_while_locked("ioc_resolve_enable") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                scelta_in_schermata(&window, true);
            }
        });
    }
    {
        let handle = window.as_weak();
        window.on_ioc_resolve_disable(move || {
            if crate::lock::refuse_while_locked("ioc_resolve_disable") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                scelta_in_schermata(&window, false);
            }
        });
    }
}

/// Abilita o spegne, e lo riporta in schermata.
fn scelta_in_schermata(window: &AppWindow, abilita: bool) {
    let frase = scegli(abilita);
    refresh(window);
    window.set_ioc_resolve_choice_message(crate::lingua::schermo(frase));
}

#[cfg(test)]
mod tests {
    /// L'avvertenza su chi vede la richiesta sta **prima** del pulsante, e
    /// fuori dalla condizione che lo mostra: si legge anche a risoluzione
    /// spenta.
    #[test]
    fn l_avvertenza_precede_il_pulsante() {
        let schermata = include_str!("../ui/app-window.slint");
        let (Some(avvertenza), Some(pulsante)) = (
            schermata.find("Chi gestisce il dominio chiesto la può vedere arrivare"),
            schermata.find("@tr(\"Risolvi dal PC\")"),
        ) else {
            panic!("l'avvertenza e il pulsante devono esserci");
        };
        assert!(avvertenza < pulsante, "l'avvertenza va prima del pulsante");
        let Some(condizione) = schermata.find("if root.ioc-resolve-enabled: Rectangle") else {
            panic!("il pulsante compare solo a risoluzione abilitata");
        };
        assert!(
            avvertenza < condizione,
            "l'avvertenza non dipende dall'abilitazione"
        );
    }
}

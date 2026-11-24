//! «Chi ha registrato il nome» nella cronologia di un gruppo della schermata
//! Cyber Watch, e la scelta dell'amministratore in Impostazioni (WHOIS-01,
//! ADR-0205).
//!
//! La richiesta passa dal servizio, che decide i rifiuti e a chi chiedere:
//! WHOIS non abilitato, Esercitazione, indicatore che non si chiede, richiesta
//! troppo vicina alla precedente. Qui si mostra ciò che dice. L'avvertenza su
//! chi vede la richiesta sta nella schermata, prima del pulsante.

use std::cell::RefCell;

use lisi_core::OperatingMode;
use lisi_services::registration_lookup::{
    LookupAttempt, Network, StoredRegistrationLookup, applicable, choose, enabled, lookup,
    outcome_sentence, recent,
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
    window.set_whois_applicable(applicable(kind));
    window.set_whois_message(SharedString::default());
    refresh(window);
}

/// La cronologia si è chiusa.
pub fn hide(window: &AppWindow) {
    INDICATORE.with(|cella| *cella.borrow_mut() = None);
    window.set_whois_applicable(false);
    window.set_whois_message(SharedString::default());
    window.set_whois_history(SharedString::default());
}

/// Una richiesta registrata, in poche righe.
fn storia(richiesta: &StoredRegistrationLookup) -> String {
    format!(
        "{}: {} ha chiesto «{}» a {}. {}",
        richiesta.requested_at.to_readable_local(),
        richiesta.requested_by,
        richiesta.queried_name,
        richiesta.server,
        outcome_sentence(&richiesta.outcome, &richiesta.detail, &richiesta.summary)
    )
}

/// Riporta in schermata la scelta, e le richieste dell'indicatore aperto.
pub fn refresh(window: &AppWindow) {
    let modalita = station::persisted_mode_or_restricted();
    window.set_whois_administrator(modalita == OperatingMode::Administrator);
    let abilitato = con_l_archivio(|archivio| enabled(archivio)).and_then(Result::ok);
    window.set_whois_enabled(abilitato == Some(true));
    window.set_whois_state(crate::lingua::schermo(match abilitato {
        Some(true) => {
            "Abilitato: dalla cronologia di un gruppo si può chiedere chi ha registrato un dominio o un indirizzo. Il registro vede la richiesta."
        }
        Some(false) => "Spento: dal PC non si chiede il WHOIS.",
        None => "L'archivio non è aperto: la scelta non si legge.",
    }));
    let Some((genere, valore)) = INDICATORE.with(|cella| cella.borrow().clone()) else {
        return;
    };
    let registro =
        con_l_archivio(|archivio| recent(archivio, &genere, &valore).unwrap_or_default())
            .unwrap_or_default();
    let righe: Vec<String> = registro.iter().map(storia).collect();
    window.set_whois_history(SharedString::from(if righe.is_empty() {
        String::new()
    } else {
        format!("Richieste registrate:\n{}", righe.join("\n\n"))
    }));
}

/// Abilita o spegne il WHOIS.
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

/// Chiede il WHOIS dell'indicatore aperto. Restituisce la frase per
/// l'operatore.
fn chiedi() -> String {
    let Some((genere, valore)) = INDICATORE.with(|cella| cella.borrow().clone()) else {
        return String::from("Nessun indicatore scelto.");
    };
    let Ok(attore) = crate::operator::audit_actor() else {
        return String::from(crate::account::NON_SI_SA_CHI_OPERA);
    };
    let esito = con_l_archivio(|archivio| {
        lookup(
            archivio,
            Network::of_this_pc(),
            &genere,
            &valore,
            &attore,
            lisi_services::run_mode::is_exercise(),
            crate::account::now(),
        )
    });
    match esito {
        None => String::from("L'archivio non è aperto: la richiesta non parte."),
        Some(Ok(LookupAttempt::Recorded { sentence, .. })) => {
            format!("Richiesta registrata. {sentence}")
        }
        Some(Ok(LookupAttempt::Refused(frase))) => frase,
        Some(Err(errore)) => {
            tracing::warn!(kind = errore.kind(), "richiesta WHOIS non registrata");
            errore.operator_message()
        }
    }
}

/// Collega i comandi della sezione e del pannello.
pub fn wire(window: &AppWindow) {
    {
        let handle = window.as_weak();
        window.on_whois_request(move || {
            if crate::lock::refuse_while_locked("whois_request") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let frase = chiedi();
            refresh(&window);
            window.set_whois_message(crate::lingua::schermo(frase));
        });
    }
    {
        let handle = window.as_weak();
        window.on_whois_enable(move || {
            if crate::lock::refuse_while_locked("whois_enable") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                scelta_in_schermata(&window, true);
            }
        });
    }
    {
        let handle = window.as_weak();
        window.on_whois_disable(move || {
            if crate::lock::refuse_while_locked("whois_disable") {
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
    window.set_whois_choice_message(crate::lingua::schermo(frase));
}

#[cfg(test)]
mod tests {
    /// L'avvertenza su chi vede la richiesta sta **prima** del pulsante, e
    /// fuori dalla condizione che lo mostra: si legge anche a WHOIS spento.
    #[test]
    fn l_avvertenza_precede_il_pulsante() {
        let schermata = include_str!("../ui/app-window.slint");
        let (Some(avvertenza), Some(pulsante)) = (
            schermata.find("Il registro vede da dove arriva la richiesta"),
            schermata.find("@tr(\"Chi ha registrato il nome\")"),
        ) else {
            panic!("l'avvertenza e il pulsante devono esserci");
        };
        assert!(avvertenza < pulsante, "l'avvertenza va prima del pulsante");
        let Some(condizione) = schermata.find("if root.whois-enabled: Rectangle") else {
            panic!("il pulsante compare solo a WHOIS abilitato");
        };
        assert!(
            avvertenza < condizione,
            "l'avvertenza non dipende dall'abilitazione"
        );
    }
}

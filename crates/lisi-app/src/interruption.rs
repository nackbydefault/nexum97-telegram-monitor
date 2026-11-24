//! L'avviso di un monitoraggio interrotto.
//!
//! # Questo modulo non decide nulla
//!
//! La decisione — che un monitoraggio in corso all'avvio sia **interrotto** e
//! non **fermato** — sta in `lisi_core::model::interruption`; il rilevamento in
//! `lisi_services::interruption`. Qui c'è il collegamento: chiedere, mostrare, e
//! registrare che qualcuno ha letto.
//!
//! # Perché l'avviso sparisce quando è stato letto
//!
//! Perché un avviso che riappare a ogni avvio è un avviso che si impara a
//! chiudere senza leggerlo. **Sparisce l'avviso, non il fatto**: ciò che è stato
//! visto resta in archivio (ADR-0064).

use std::cell::Cell;
use std::rc::Rc;

use lisi_core::model::interruption::{as_sentence, decision_label, decision_sentence};
use lisi_services::interruption;
use slint::{ComponentHandle, SharedString};

use crate::AppWindow;
use crate::StorageFallback;

use lisi_core::model::background::Keeper;
use lisi_services::background::Takeover;

thread_local! {
    /// Gli account che il servizio in background teneva, da riprendere
    /// (SERVICE-01, ADR-0203).
    static DA_RIPRENDERE: std::cell::RefCell<Vec<i64>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Gli account da riprendere dopo un passaggio di mano, una volta sola.
pub fn accounts_to_resume() -> Vec<i64> {
    DA_RIPRENDERE.with(|cella| std::mem::take(&mut *cella.borrow_mut()))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// Rileva i monitoraggi interrotti e collega la presa in carico.
///
/// Se il rilevamento non riesce **non è un guasto dell'applicazione**: si
/// registra e si prosegue senza avviso. L'alternativa — fermare l'avvio perché
/// una lettura non è riuscita — toglierebbe all'operatore anche ciò che
/// funziona.
///
/// # Uno alla volta, tutti (ADR-0146)
///
/// Un monitoraggio interrotto non riceve contenuti finché qualcuno non lo
/// decide. Con più monitoraggi interrotti, mostrarne soltanto il primo
/// lascerebbe gli altri fermi senza che nessuno lo sappia: presa in carico
/// un'interruzione, l'avviso passa alla successiva ancora aperta.
pub fn wire(window: &AppWindow, storage: &mut StorageFallback) {
    let Some(mut database) = storage.open() else {
        tracing::warn!("rilevamento delle interruzioni non disponibile in questa esecuzione");
        return;
    };

    // IL PASSAGGIO DI MANO VIENE PRIMA (SERVICE-01, ADR-0203): se il servizio
    // in background ha lasciato da poco, si continua e non c'è interruzione.
    match lisi_services::background::take_over(&mut database, Keeper::Window, now()) {
        Ok(Takeover::Continued { accounts, .. }) => {
            DA_RIPRENDERE.with(|cella| *cella.borrow_mut() = accounts);
        }
        Ok(Takeover::Interrupted(_)) => {}
        Err(error) => {
            tracing::warn!(
                kind = error.kind(),
                "rilevamento di un monitoraggio interrotto non riuscito"
            );
            return;
        }
    }

    let mostrata: Rc<Cell<Option<lisi_core::SessionId>>> = Rc::new(Cell::new(None));
    show_next(window, &database, &mostrata);

    let weak = window.as_weak();
    window.on_acknowledge_interruption(move || {
        if crate::lock::refuse_while_locked("acknowledge_interruption") {
            return;
        }
        // Un prerequisito della fascia di prontezza puo' essere cambiato (F-08).
        crate::preflight::mark_stale();
        let Some(window) = weak.upgrade() else {
            return;
        };
        // L'avviso sparisce comunque: se la scrittura non riuscisse, tornerebbe
        // alla prossima apertura, che e' il comportamento giusto — ma tenerlo
        // in piedi adesso, dopo che qualcuno ha premuto, sembrerebbe un guasto.
        window.set_monitoring_interruption_notice(SharedString::default());
        window.set_monitoring_interruption_decision(SharedString::default());

        let Some(session_id) = mostrata.take() else {
            return;
        };
        let Some(mut database) = crate::StorageFallback::new().open() else {
            tracing::warn!("presa in carico dell'interruzione non registrata: archivio assente");
            return;
        };
        if let Err(error) = interruption::acknowledge(&mut database, session_id, now()) {
            tracing::warn!(
                kind = error.kind(),
                "presa in carico dell'interruzione non registrata"
            );
        }
        crate::wakefulness::follow_receiving(&window, &database);
        // Il Cruscotto conta chi riceve: dopo la ripresa ridice la riga del
        // Monitoraggio, invece di aspettare che qualcuno lo riapra (BUG-UX-5).
        window.invoke_dashboard_shown();
        show_next(&window, &database, &mostrata);
    });
}

/// Mostra la prima interruzione ancora aperta, se ce n'è una.
fn show_next(
    window: &AppWindow,
    database: &lisi_services::Database,
    mostrata: &Rc<Cell<Option<lisi_core::SessionId>>>,
) {
    let aperte = match database.open_interruptions() {
        Ok(aperte) => aperte,
        Err(error) => {
            tracing::warn!(errore = %error, "interruzioni aperte non leggibili");
            return;
        }
    };
    let Some(trovata) = aperte.into_iter().next() else {
        mostrata.set(None);
        return;
    };

    tracing::info!(
        sessione = trovata.session_id.get(),
        "un monitoraggio risultava in corso alla riapertura: e' stato interrotto"
    );

    // Se acquisisce ancora, o se nel frattempo la durata e' scaduta: decide che
    // cosa c'e' da scegliere (ADR-0146).
    let acquisisce = database
        .acquiring_sessions()
        .map(|sessioni| sessioni.iter().any(|(id, _)| *id == trovata.session_id))
        .unwrap_or(true);

    // LA FRASE LA COMPONE IL DOMINIO, IN UN POSTO SOLO.
    window.set_monitoring_interruption_notice(SharedString::from(as_sentence(
        &trovata.interruption,
        lisi_core::Timestamp::to_readable_local,
    )));
    window.set_monitoring_interruption_decision(SharedString::from(decision_sentence(acquisisce)));
    window.set_monitoring_interruption_action(SharedString::from(decision_label(acquisisce)));
    mostrata.set(Some(trovata.session_id));
}

#[cfg(test)]
mod tests {
    /// Il codice di produzione del modulo, senza commenti e senza le prove.
    fn codice_di_produzione() -> String {
        let sorgente = include_str!("interruption.rs");
        let produzione = sorgente
            .split_once("\n#[cfg(test)]\nmod tests {")
            .map_or(sorgente, |(prima, _)| prima);
        produzione
            .lines()
            .filter(|riga| {
                let trimmed = riga.trim_start();
                !trimmed.starts_with("//") && !trimmed.starts_with("///")
            })
            .collect::<Vec<&str>>()
            .join("\n")
    }

    /// **Il collegamento non compone frasi proprie, e non tocca la sessione.**
    ///
    /// È la guardia che lo tiene un collegamento: la frase la compone il
    /// dominio, in un posto solo, e lo stato della sessione non si tocca perché
    /// portarlo ad «arrestata» attribuirebbe un atto a una persona.
    ///
    /// # Perché vieta di COMPORRE e non una parola
    ///
    /// Perché la prima stesura vietava la parola «interrotto», ed è diventata
    /// rossa su una **riga di registro** — un testo che nessun operatore legge e
    /// che deve poter dire che cosa è successo. Vietare una parola dentro un
    /// registro avrebbe costretto a scrivere peggio il registro.
    ///
    /// Ciò che conta è che l'avviso venga **da `as_sentence`** e che qui non si
    /// componga nulla: senza `format!`, non c'è modo di comporre una frase.
    #[test]
    fn il_collegamento_non_compone_frasi_proprie_e_non_tocca_la_sessione() {
        let codice = codice_di_produzione();

        assert!(
            codice.contains("as_sentence("),
            "l'avviso deve venire dal dominio, che è il solo posto in cui la frase si compone"
        );
        assert!(
            !codice.contains("format!"),
            "il collegamento non deve comporre testo: la frase la compone il dominio"
        );

        for vietato in ["update_session_state", "SessionState", "Stopped"] {
            assert!(
                !codice.contains(vietato),
                "il collegamento dell'interruzione non deve nominare «{vietato}»"
            );
        }
    }

    /// **Il collegamento non riprende e non recupera.**
    #[test]
    fn il_collegamento_non_riprende_e_non_recupera() {
        let codice = codice_di_produzione();
        for vietato in ["survey", "recovery", "AcquisitionService", "monitoring::"] {
            assert!(
                !codice.contains(vietato),
                "accorgersi non è ripartire: non deve nominare «{vietato}»"
            );
        }
    }
}

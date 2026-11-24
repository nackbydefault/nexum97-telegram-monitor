//! I periodi non coperti prioritari nella Coda di lavoro (PR-06, ADR-0122).
//!
//! # Perché un modulo proprio
//!
//! Perché la coda dei **contenuti** non mostra punteggi né priorità: l'ordine
//! è un confronto fra fatti, e la sua guardia lo sorveglia (WQ-01). I periodi
//! hanno invece una **priorità tecnica**, che il piano chiede di mostrare e di
//! dire per quello che è. Tenerli qui lascia la guardia della coda intatta sul
//! codice che ordina i contenuti.
//!
//! # Una priorità non è un fatto
//!
//! Ogni riga ripete che la priorità non dice che nel periodo la fonte abbia
//! pubblicato qualcosa. **Nessuna richiesta a Telegram parte da qui**: una
//! decisione consegna il periodo a una persona.

use std::rc::Rc;

use lisi_services::gap::{GapDecision, PriorityGap};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::work_queue::SharedWorkQueue;
use crate::{AppWindow, GapRow};

/// Istante corrente, o l'epoca se l'orologio non è leggibile.
fn adesso() -> lisi_core::Timestamp {
    crate::account::now()
}

/// La chiave con cui la schermata indica un periodo: fonte, inizio e fine.
fn chiave(periodo: &PriorityGap) -> String {
    format!(
        "{}:{}:{}",
        periodo.source_id.get(),
        periodo.from.as_millis(),
        periodo.to.as_millis()
    )
}

/// Mostra i periodi non coperti prioritari, sotto i contenuti.
///
/// Si leggono sull'archivio della coda, alla stessa fotografia. Una lettura
/// che non riesce lascia la sezione vuota e lo dice, invece di mostrare periodi
/// di un'altra volta.
pub fn show(window: &AppWindow, queue: &SharedWorkQueue, now: lisi_core::Timestamp) {
    let esito = match lisi_services::gap::assess(queue.borrow().database(), now) {
        Ok(esito) => esito,
        Err(errore) => {
            tracing::warn!(kind = errore.kind(), "periodi non coperti non componibili");
            window.set_gap_rows(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
            window.set_gap_summary(crate::lingua::schermo(
                "Non è stato possibile comporre i periodi non coperti prioritari.",
            ));
            return;
        }
    };

    let righe: Vec<GapRow> = esito
        .listed
        .iter()
        .map(|periodo| GapRow {
            source: SharedString::from(periodo.source_name.as_str()),
            when: crate::lingua::schermo(format!(
                "Dal {} al {}, {}: {}.",
                periodo.from.to_readable_local(),
                periodo.to.to_readable_local(),
                periodo.state.label(),
                periodo.state.reason()
            )),
            priority: crate::lingua::schermo(periodo.priority.label()),
            sentence: crate::lingua::schermo(periodo.sentence()),
            key: SharedString::from(chiave(periodo)),
        })
        .collect();

    let mut riepilogo = if righe.is_empty() {
        String::from("Nessun periodo non coperto di priorità alta o media da valutare.")
    } else {
        format!(
            "{} di priorità alta o media da valutare.",
            lisi_core::text::counted(righe.len(), "periodo", "periodi")
        )
    };
    if esito.low > 0 {
        riepilogo.push_str(&format!(
            " Altri {} di priorità bassa non sono elencati.",
            esito.low
        ));
    }
    for (fonte, quanti) in &esito.not_observable {
        riepilogo.push_str(&format!(
            " «{fonte}»: {} senza priorità, perché il ritmo della fonte non è osservabile.",
            lisi_core::text::counted(*quanti, "periodo", "periodi")
        ));
    }
    window.set_gap_summary(crate::lingua::schermo(riepilogo));
    window.set_gap_rows(ModelRc::from(Rc::new(VecModel::from(righe))));
}

/// Registra la decisione di una persona su un periodo, con il suo motivo.
///
/// # Decide soltanto su ciò che ritrova
///
/// I periodi si ricompongono adesso, e la decisione vale soltanto per quello
/// con la stessa chiave: una riga rimasta sullo schermo da una composizione
/// vecchia non decide nulla. **Nessuna richiesta a Telegram parte da qui.**
fn decide(queue: &SharedWorkQueue, chiave_scelta: &str, decisione: &str, motivo: &str) -> String {
    let decisione = match decisione {
        "da_valutare_per_recupero" => GapDecision::EvaluateRecovery,
        "dichiarato_non_coperto" => GapDecision::DeclaredNotCovered,
        _ => return String::from("Decisione non riconosciuta: nulla è stato registrato."),
    };
    let Ok(motivo) = lisi_core::model::reason::OperationalReason::try_new(motivo) else {
        return String::from(
            "Serve un motivo scritto: una decisione su un periodo resta, e chi la rilegge deve \
             sapere perché.",
        );
    };
    let Ok(attore) = crate::operator::audit_actor() else {
        return String::from("Non si riesce a stabilire chi stia agendo su questa postazione.");
    };
    let now = adesso();
    let esito = match lisi_services::gap::assess(queue.borrow().database(), now) {
        Ok(esito) => esito,
        Err(errore) => return errore.operator_message(),
    };
    let Some(periodo) = esito
        .listed
        .iter()
        .find(|periodo| chiave(periodo) == chiave_scelta)
    else {
        return String::from(
            "Il periodo non è più fra quelli da valutare: la coda è stata ricomposta.",
        );
    };
    match lisi_services::gap::record_decision(
        queue.borrow_mut().database_mut(),
        periodo,
        decisione,
        &motivo,
        &attore,
        now,
    ) {
        // Dove il periodo si ritrova (PR-07): la decisione non avvia nulla, e
        // chi l'ha presa deve sapere dove andare per guardarlo.
        Ok(()) if decisione == GapDecision::EvaluateRecovery => format!(
            "{}: decisione registrata, con il motivo. Il periodo si trova nel Monitoraggio, \
             sotto «Recupero dei periodi decisi».",
            decisione.label()
        ),
        Ok(()) => format!(
            "{}: decisione registrata, con il motivo.",
            decisione.label()
        ),
        Err(errore) => errore.operator_message(),
    }
}

/// Collega le decisioni sui periodi.
pub fn wire(window: &AppWindow, queue: &SharedWorkQueue) {
    {
        let weak = window.as_weak();
        let queue = Rc::clone(queue);
        window.on_gap_decide(move |chiave_scelta, decisione| {
            if crate::lock::refuse_while_locked("gap_decide") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            let esito = decide(
                &queue,
                chiave_scelta.as_str(),
                decisione.as_str(),
                window.get_gap_reason().as_str(),
            );
            // Il motivo si svuota dopo l'uso: scritto per un periodo, non deve
            // accompagnare la decisione su un altro.
            window.set_gap_reason(SharedString::default());
            window.set_gap_message(SharedString::from(esito));
            crate::work_queue::refresh(&window, &queue);
        });
    }
}

#[cfg(test)]
mod tests {
    const UI: &str = include_str!("../ui/app-window.slint");
    const THIS_MODULE: &str = include_str!("gaps.rs");

    /// La sezione dei periodi, dalla sua intestazione alla fine della pagina.
    fn sezione() -> &'static str {
        let Some(inizio) = UI.find("text: @tr(\"PERIODI NON COPERTI PRIORITARI\");") else {
            panic!("la sezione dei periodi deve esistere");
        };
        let Some(fine) = UI[inizio..].find("Il limite dichiarato dove chi ha letto tutto") else {
            panic!("la sezione deve chiudersi prima del limite della coda");
        };
        &UI[inizio..inizio + fine]
    }

    /// **La priorità si dice tecnica, e ogni riga dice che cosa non
    /// significa** (PR-06).
    #[test]
    fn la_priorita_si_dice_tecnica_e_non_afferma() {
        let sezione = sezione();
        assert!(sezione.contains("La priorità è tecnica"));
        assert!(sezione.contains("Non dice che nel periodo la fonte abbia pubblicato qualcosa."));
        assert!(
            sezione.contains("text: periodo.sentence;"),
            "ogni riga deve mostrare la frase del periodo, con che cosa non significa"
        );
        let minuscola = sezione.to_lowercase();
        for vietata in ["dati mancanti", "messaggi mancanti", "sicuramente"] {
            assert!(
                !minuscola.contains(vietata),
                "«{vietata}» nella sezione dei periodi"
            );
        }
    }

    /// **Una decisione non chiede nulla a Telegram**: il modulo non nomina il
    /// recupero né il connettore.
    #[test]
    fn decidere_non_chiede_dati() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("blocco di prove riconoscibile");
        };
        for vietato in [
            "recovery",
            "retro_search",
            "connector",
            "runtime",
            "invoke_",
        ] {
            assert!(
                !produzione.contains(vietato),
                "«{vietato}»: un periodo prioritario non diventa una richiesta di dati da solo"
            );
        }
        // Senza motivo scritto i comandi non si premono.
        assert_eq!(UI.matches("enabled: root.gap-reason != \"\";").count(), 2);
    }
}

//! L'affidabilità delle fonti, valutata a mano, nella pagina Fonti
//! (SOURCE-RELIABILITY-01, ADR-0167).
//!
//! Ogni fonte configurata mostra la valutazione in vigore; si dà o si ritira
//! una per volta, con il motivo. Il programma non propone nulla.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_core::SourceId;
use lisi_core::model::reason::OperationalReason;
use lisi_core::model::source_reliability::{ReliabilityAct, ReliabilityLevel};
use lisi_services::Database;
use lisi_services::source_reliability;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::{AppWindow, SourceReliabilityRow};

/// L'archivio delle valutazioni.
pub struct ReliabilityScreen {
    archive: Database,
}

/// Schermata condivisa fra i gestori.
pub type SharedReliability = Rc<RefCell<ReliabilityScreen>>;

/// Crea la schermata sulla sua connessione.
#[must_use]
pub fn create_service(archive: Database) -> SharedReliability {
    Rc::new(RefCell::new(ReliabilityScreen { archive }))
}

/// L'atto scelto nella schermata: 0, 1 e 2 le tre parole, 3 il ritiro.
fn act_of(scelta: i32) -> Option<ReliabilityAct> {
    match scelta {
        0 => Some(ReliabilityAct::Assess(ReliabilityLevel::Reliable)),
        1 => Some(ReliabilityAct::Assess(ReliabilityLevel::CaseByCase)),
        2 => Some(ReliabilityAct::Assess(ReliabilityLevel::Unreliable)),
        3 => Some(ReliabilityAct::Withdraw),
        _ => None,
    }
}

/// Ridisegna l'elenco delle fonti con la valutazione in vigore.
pub fn refresh(window: &AppWindow, screen: &SharedReliability) {
    show_rows(window, &screen.borrow().archive);
}

/// Le fonti con la valutazione in vigore, lette dall'archivio indicato: la
/// pagina Fonti lo chiama anche quando ridisegna il suo elenco.
pub fn show_rows(window: &AppWindow, archivio: &Database) {
    match source_reliability::overview(archivio) {
        Ok(righe) => {
            let righe: Vec<SourceReliabilityRow> = righe
                .iter()
                .filter_map(|riga| {
                    Some(SourceReliabilityRow {
                        source_id: i32::try_from(riga.source_id.get()).ok()?,
                        name: SharedString::from(riga.name.as_str()),
                        sentence: SharedString::from(riga.current.as_deref().unwrap_or(
                            "NON VALUTATA: l'ufficio non ha dato una valutazione di questa fonte.",
                        )),
                    })
                })
                .collect();
            window.set_source_reliability_rows(ModelRc::from(Rc::new(VecModel::from(righe))));
        }
        Err(errore) => {
            window.set_source_reliability_feedback(crate::lingua::schermo(
                errore.operator_message().as_str(),
            ));
        }
    }
}

/// Collega il comando: un atto su una fonte, con il motivo scritto.
pub fn wire(window: &AppWindow, screen: &SharedReliability) {
    let handle = window.as_weak();
    let screen = Rc::clone(screen);
    window.on_source_reliability_record(move |fonte, scelta| {
        if crate::lock::refuse_while_locked("source_reliability_record") {
            return;
        }
        let Some(window) = handle.upgrade() else {
            return;
        };
        let Some(act) = act_of(scelta) else {
            return;
        };
        let Ok(ragione) =
            OperationalReason::try_new(window.get_source_reliability_reason().as_str())
        else {
            window.set_source_reliability_feedback(crate::lingua::schermo(
                "Scrivere il motivo, almeno venti caratteri: una valutazione senza motivo non \
                 si registra.",
            ));
            return;
        };
        let Ok(operatore) = crate::operator::audit_actor() else {
            window.set_source_reliability_feedback(crate::lingua::schermo(
                "Non si riesce a stabilire chi stia agendo su questa postazione: nulla \u{e8} \
                 cambiato.",
            ));
            return;
        };
        let esito = source_reliability::record(
            &mut screen.borrow_mut().archive,
            SourceId::new(i64::from(fonte)),
            act,
            &ragione,
            &operatore,
            crate::account::now(),
        );
        window.set_source_reliability_feedback(SharedString::from(match esito {
            Ok(_) => {
                window.set_source_reliability_reason(SharedString::default());
                format!(
                    "Registrato: {}. La valutazione porta il tuo nome e il motivo.",
                    act.as_label()
                )
            }
            Err(errore) => errore.operator_message(),
        }));
        refresh(&window, &screen);
    });
}

#[cfg(test)]
mod tests {
    use lisi_core::model::source_reliability::{ReliabilityAct, ReliabilityLevel};

    use super::act_of;

    /// **Le quattro scelte della schermata sono i quattro atti, e nient'altro**
    /// (SOURCE-RELIABILITY-01, criterio 5).
    #[test]
    fn le_scelte_della_schermata_sono_i_quattro_atti() {
        assert_eq!(
            act_of(0),
            Some(ReliabilityAct::Assess(ReliabilityLevel::Reliable))
        );
        assert_eq!(
            act_of(2),
            Some(ReliabilityAct::Assess(ReliabilityLevel::Unreliable))
        );
        assert_eq!(act_of(3), Some(ReliabilityAct::Withdraw));
        assert_eq!(act_of(4), None);
        assert_eq!(act_of(-1), None);
    }
}

//! La ricerca su più rami nella schermata Segnali cyber (CYBER-SEARCH-03,
//! ADR-0163).
//!
//! Una domanda sui rami scelti, un elenco unito con le provenienze, il
//! perimetro di ciascun ramo. I risultati di Telegram si mostrano e non si
//! conservano.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_services::Database;
use lisi_services::cross_search::{self, CrossResult};
use lisi_services::history::HistoryService;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::account::SharedSession;
use crate::{AppWindow, CyberCrossRow};

/// L'archivio delle ricerche e lo Storico, su due connessioni.
pub struct CrossSearchScreen {
    archive: Database,
    history: HistoryService,
}

/// Schermata condivisa fra i gestori.
pub type SharedCrossSearch = Rc<RefCell<CrossSearchScreen>>;

/// Crea la schermata sulle sue due connessioni.
#[must_use]
pub fn create_service(archive: Database, history: Database) -> SharedCrossSearch {
    Rc::new(RefCell::new(CrossSearchScreen {
        archive,
        history: HistoryService::new(history),
    }))
}

/// Le provenienze di un risultato, a parole.
fn found_by_text(lettere: &std::collections::BTreeSet<&'static str>) -> String {
    let nomi: Vec<&str> = lettere
        .iter()
        .map(|lettera| match *lettera {
            "A" => "nell'archivio",
            "B" => "B",
            "C" => "C",
            "D" => "D",
            altro => altro,
        })
        .collect();
    format!("Trovato da: {}", nomi.join(", "))
}

/// I rami e gli indicatori, in righe.
fn report_text(esito: &CrossResult) -> String {
    let mut righe: Vec<String> = esito
        .branches
        .iter()
        .map(|ramo| format!("{} \u{2014} {} {}", ramo.letter, ramo.outcome, ramo.scope))
        .collect();
    righe.push(format!(
        "Risultati: {} prima dell'unione, {} dopo: lo stesso messaggio compare una volta.",
        esito.before_union,
        esito.rows.len()
    ));
    if !esito.indicators.is_empty() {
        let elenco: Vec<String> = esito
            .indicators
            .iter()
            .map(|voce| {
                format!(
                    "{} in {} risultati e {} chat",
                    voce.value, voce.rows, voce.chats
                )
            })
            .collect();
        righe.push(format!(
            "Indicatori negli estratti: {}. Lo stesso indicatore in due chat non vuol dire lo \
             stesso fatto.",
            elenco.join("; ")
        ));
    }
    righe.join("\n")
}

/// Collega il comando.
pub fn wire(window: &AppWindow, screen: &SharedCrossSearch, session: &SharedSession) {
    let handle = window.as_weak();
    let screen = Rc::clone(screen);
    let session = Rc::clone(session);
    window.on_cross_search_start(move |a, b, c, d, chat, parole| {
        if crate::lock::refuse_while_locked("cross_search_start") {
            return;
        }
        let Some(window) = handle.upgrade() else {
            return;
        };
        let rami = match cross_search::branches_of(a, b, c, d, chat.as_str()) {
            Ok(rami) => rami,
            Err(frase) => {
                window.set_cross_search_report(crate::lingua::schermo(frase));
                return;
            }
        };
        let Ok(operatore) = crate::operator::audit_actor() else {
            window.set_cross_search_report(crate::lingua::schermo(
                "Non si riesce a stabilire chi stia agendo su questa postazione: la ricerca non \
                 \u{e8} partita.",
            ));
            return;
        };
        let esito = {
            let mut sessione = session.borrow_mut();
            let mut schermata = screen.borrow_mut();
            let CrossSearchScreen { archive, history } = &mut *schermata;
            let connettore = sessione
                .runtime_mut()
                .map(|runtime| runtime.connector_mut());
            cross_search::search(
                connettore,
                archive,
                history,
                &operatore,
                rami,
                parole.as_str(),
                crate::account::now(),
            )
        };
        match esito {
            Ok(Ok(risultato)) => {
                let righe: Vec<CyberCrossRow> = risultato
                    .rows
                    .iter()
                    .map(|riga| CyberCrossRow {
                        chat: SharedString::from(riga.chat.as_str()),
                        when: SharedString::from(riga.published_at.to_readable_local()),
                        who: SharedString::from(riga.who.as_str()),
                        excerpt: SharedString::from(riga.excerpt.as_str()),
                        found_by: SharedString::from(found_by_text(&riga.found_by)),
                    })
                    .collect();
                window.set_cross_search_rows(ModelRc::from(Rc::new(VecModel::from(righe))));
                window.set_cross_search_report(SharedString::from(report_text(&risultato)));
            }
            Ok(Err(frase)) => {
                window.set_cross_search_rows(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
                window.set_cross_search_report(crate::lingua::schermo(frase));
            }
            Err(errore) => {
                window.set_cross_search_report(crate::lingua::schermo(
                    errore.operator_message().as_str(),
                ));
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use lisi_services::cross_search::{BranchReport, CrossResult, IndicatorCount};

    use super::{found_by_text, report_text};

    /// **Le provenienze e il perimetro si dicono, con l'avvertenza sugli
    /// indicatori** (CYBER-SEARCH-03, criterio 7).
    #[test]
    fn le_provenienze_e_il_perimetro_si_dicono() {
        assert_eq!(
            found_by_text(&BTreeSet::from(["A", "B"])),
            "Trovato da: nell'archivio, B"
        );
        let esito = CrossResult {
            rows: Vec::new(),
            branches: vec![BranchReport {
                letter: "D",
                asked: false,
                scope: String::from("Nei post pubblici."),
                outcome: String::from("Non scelto: qui non si \u{e8} cercato."),
                results: 0,
            }],
            indicators: vec![IndicatorCount {
                value: String::from("192.0.2.45"),
                rows: 2,
                chats: 2,
            }],
            before_union: 3,
        };
        let testo = report_text(&esito);
        assert!(testo.contains("D \u{2014} Non scelto"), "{testo}");
        assert!(testo.contains("3 prima dell'unione, 0 dopo"), "{testo}");
        assert!(
            testo.contains("192.0.2.45 in 2 risultati e 2 chat"),
            "{testo}"
        );
        assert!(testo.contains("non vuol dire lo stesso fatto"), "{testo}");
    }
}

//! La ricerca ricorrente E nella schermata Segnali cyber (CYBER-WATCH-02,
//! ADR-0162).
//!
//! Il programma offre al servizio un'occasione al minuto, soltanto a
//! postazione non bloccata e con l'account collegato; il servizio esegue al più
//! una ricorrente scaduta. Le novità si mostrano in questa sessione e non si
//! conservano.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use lisi_services::Database;
use lisi_services::cyber_recurring::{self, RunReport};
use slint::{ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel};

use crate::account::SharedSession;
use crate::{AppWindow, CyberRecurringRow};

/// Ogni quanto il programma offre un'occasione al servizio.
const TICK: std::time::Duration = std::time::Duration::from_secs(60);
/// Quante novità si mostrano per ricorrente.
const SHOWN_NOVELTIES: usize = 5;

/// L'archivio delle ricorrenti e le novità di questa sessione.
pub struct CyberRecurringScreen {
    archive: Database,
    /// L'ultima esecuzione di ciascuna ricorrente, in questa sessione.
    last_runs: BTreeMap<i64, RunReport>,
}

/// Schermata condivisa fra i gestori e il timer.
pub type SharedRecurring = Rc<RefCell<CyberRecurringScreen>>;

/// Crea la schermata sulla sua connessione.
#[must_use]
pub fn create_service(archive: Database) -> SharedRecurring {
    Rc::new(RefCell::new(CyberRecurringScreen {
        archive,
        last_runs: BTreeMap::new(),
    }))
}

/// Le novità dell'ultima esecuzione, in righe: la frase, poi al più
/// [`SHOWN_NOVELTIES`] messaggi con la chat, l'istante e l'estratto.
fn novelties_text(esecuzione: Option<&RunReport>) -> String {
    let Some(esecuzione) = esecuzione else {
        return String::new();
    };
    let mut righe = vec![format!("In questa sessione: {}", esecuzione.sentence)];
    for trovato in esecuzione.novelties.iter().take(SHOWN_NOVELTIES) {
        righe.push(format!(
            "\u{b7} {}, {}: {}",
            trovato.chat,
            trovato.published_at.to_readable_local(),
            trovato.excerpt
        ));
    }
    let altri = esecuzione.novelties.len().saturating_sub(SHOWN_NOVELTIES);
    if altri > 0 {
        righe.push(format!("\u{2026} e altri {altri}."));
    }
    righe.join("\n")
}

/// Ridisegna l'elenco delle ricorrenti.
pub fn refresh(window: &AppWindow, screen: &SharedRecurring) {
    let schermata = screen.borrow();
    match cyber_recurring::list(&schermata.archive, crate::account::now()) {
        Ok(viste) => {
            let righe: Vec<CyberRecurringRow> = viste
                .iter()
                .filter_map(|vista| {
                    Some(CyberRecurringRow {
                        id: i32::try_from(vista.id).ok()?,
                        title: SharedString::from(vista.title.as_str()),
                        coverage: SharedString::from(vista.coverage.as_str()),
                        novelties: SharedString::from(novelties_text(
                            schermata.last_runs.get(&vista.id),
                        )),
                        suspended: vista.suspended,
                    })
                })
                .collect();
            window.set_cyber_recurring_rows(ModelRc::from(Rc::new(VecModel::from(righe))));
        }
        Err(errore) => {
            window.set_cyber_recurring_feedback(crate::lingua::schermo(
                errore.operator_message().as_str(),
            ));
        }
    }
}

/// Collega i tre comandi: salvare, sospendere o riprendere, ritirare.
pub fn wire(window: &AppWindow, screen: &SharedRecurring) {
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_cyber_recurring_save(move |ramo, chat, parole, ore| {
            if crate::lock::refuse_while_locked("cyber_recurring_save") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let esito = crate::cyber_search::branch_of(ramo, chat.as_str())
                .map_err(String::from)
                .and_then(|branch| {
                    cyber_recurring::read_hours(ore.as_str()).map(|minuti| (branch, minuti))
                })
                .and_then(|(branch, minuti)| {
                    let operatore = crate::operator::audit_actor().map_err(|_| {
                        String::from(
                            "Non si riesce a stabilire chi stia agendo su questa postazione: \
                             la ricerca ricorrente non \u{e8} stata salvata.",
                        )
                    })?;
                    match cyber_recurring::save(
                        &mut screen.borrow_mut().archive,
                        &operatore,
                        branch,
                        parole.as_str(),
                        minuti,
                        crate::account::now(),
                    ) {
                        Ok(esito) => esito,
                        Err(errore) => Err(errore.operator_message()),
                    }
                });
            window.set_cyber_recurring_feedback(SharedString::from(match esito {
                Ok(_) => String::from(
                    "Ricerca ricorrente salvata: parte alla prima occasione, con il programma \
                     aperto e l'account collegato.",
                ),
                Err(frase) => frase,
            }));
            refresh(&window, &screen);
        });
    }
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_cyber_recurring_toggle(move |id, sospendi| {
            if crate::lock::refuse_while_locked("cyber_recurring_toggle") {
                return;
            }
            gesture(&handle, &screen, |archivio, operatore| {
                cyber_recurring::set_suspended(
                    archivio,
                    operatore,
                    i64::from(id),
                    sospendi,
                    crate::account::now(),
                )
            });
        });
    }
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_cyber_recurring_withdraw(move |id| {
            if crate::lock::refuse_while_locked("cyber_recurring_withdraw") {
                return;
            }
            gesture(&handle, &screen, |archivio, operatore| {
                cyber_recurring::withdraw(archivio, operatore, i64::from(id), crate::account::now())
            });
        });
    }
}

/// Un gesto su una ricorrente, dopo la guardia del blocco del suo gestore:
/// chi agisce, l'esito detto.
fn gesture(
    handle: &slint::Weak<AppWindow>,
    screen: &SharedRecurring,
    fai: impl FnOnce(
        &mut Database,
        &lisi_core::text::Actor,
    ) -> lisi_services::ServiceResult<Result<(), String>>,
) {
    let Some(window) = handle.upgrade() else {
        return;
    };
    let Ok(operatore) = crate::operator::audit_actor() else {
        window.set_cyber_recurring_feedback(crate::lingua::schermo(
            "Non si riesce a stabilire chi stia agendo su questa postazione: nulla \u{e8} cambiato.",
        ));
        return;
    };
    let esito = fai(&mut screen.borrow_mut().archive, &operatore);
    window.set_cyber_recurring_feedback(SharedString::from(match esito {
        Ok(Ok(())) => String::from("Fatto, e registrato."),
        Ok(Err(frase)) => frase,
        Err(errore) => errore.operator_message(),
    }));
    refresh(&window, screen);
}

/// Avvia l'occasione al minuto. Il timer lo possiede `main.rs`, che lo tiene
/// in vita quanto la finestra.
pub fn start(timer: &Timer, window: &AppWindow, screen: &SharedRecurring, session: &SharedSession) {
    let handle = window.as_weak();
    let screen = Rc::clone(screen);
    let session = Rc::clone(session);
    timer.start(TimerMode::Repeated, TICK, move || {
        // A POSTAZIONE BLOCCATA NON SI CERCA (ADR-0162, decisione 2).
        if crate::lock::station_is_locked() {
            return;
        }
        let Some(window) = handle.upgrade() else {
            return;
        };
        let Ok(operatore) = crate::operator::audit_actor() else {
            return;
        };
        let esito = {
            let mut sessione = session.borrow_mut();
            let mut schermata = screen.borrow_mut();
            let connettore = sessione
                .runtime_mut()
                .map(|runtime| runtime.connector_mut());
            cyber_recurring::run_due(
                connettore,
                &mut schermata.archive,
                &operatore,
                crate::account::now(),
            )
        };
        match esito {
            Ok(Some(esecuzione)) => {
                screen
                    .borrow_mut()
                    .last_runs
                    .insert(esecuzione.recurring_id, esecuzione);
            }
            Ok(None) => {}
            Err(errore) => {
                window.set_cyber_recurring_feedback(crate::lingua::schermo(
                    errore.operator_message().as_str(),
                ));
            }
        }
        refresh(&window, &screen);
    });
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_services::cyber_recurring::RunReport;
    use lisi_services::cyber_search::Hit;

    use super::{SHOWN_NOVELTIES, novelties_text};

    const THIS_MODULE: &str = include_str!("cyber_recurring.rs");

    fn trovato(numero: i64) -> Hit {
        Hit {
            chat: String::from("Canale di prova (fonte)"),
            chat_id: -1001,
            message_id: numero,
            published_at: Timestamp::from_millis(1_760_000_000_000),
            who: String::from("Persona"),
            excerpt: format!("ransomware {numero}"),
        }
    }

    /// **Le novità si mostrano con la frase, la chat e l'estratto, al più
    /// cinque, e il resto si conta** (CYBER-WATCH-02, criterio 7).
    #[test]
    fn le_novita_si_mostrano_al_piu_cinque_e_il_resto_si_conta() {
        assert_eq!(novelties_text(None), "");
        let esecuzione = RunReport {
            recurring_id: 1,
            novelties: (1..=7).map(trovato).collect(),
            sentence: String::from("7 messaggi nuovi dall'ultima esecuzione."),
        };
        let testo = novelties_text(Some(&esecuzione));
        assert!(
            testo.starts_with("In questa sessione: 7 messaggi nuovi"),
            "{testo}"
        );
        assert_eq!(
            testo.matches("Canale di prova (fonte)").count(),
            SHOWN_NOVELTIES
        );
        assert!(testo.contains("ransomware 5") && !testo.contains("ransomware 6"));
        assert!(testo.ends_with("e altri 2."), "{testo}");
    }

    /// **A postazione bloccata il timer non cerca, e il timer non tocca i
    /// contenuti** (CYBER-WATCH-02, criteri 2 e 6).
    #[test]
    fn a_postazione_bloccata_non_si_cerca() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]") else {
            panic!("il modulo deve avere le sue prove");
        };
        let Some((prima, _)) = produzione.split_once("cyber_recurring::run_due(") else {
            panic!("il timer deve chiamare il servizio");
        };
        let Some((_, timer)) = prima.rsplit_once("timer.start(") else {
            panic!("il servizio si chiama dal timer");
        };
        assert!(
            timer.contains("crate::lock::station_is_locked()"),
            "il blocco si controlla prima di cercare"
        );
        for vietato in ["insert_content", "history::", "write_note", "star_count"] {
            assert!(!produzione.contains(vietato), "«{vietato}»");
        }
    }
}

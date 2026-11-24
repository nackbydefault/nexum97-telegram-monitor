//! La ricerca nei messaggi, B, C e D, nella schermata Segnali cyber
//! (NEXUM97-CYBER-SEARCH-01, ADR-0154, DG-06; CYBER-SEARCH-02, ADR-0161).
//!
//! I risultati si mostrano e non si conservano: non sono acquisizioni. Ogni
//! pagina chiesta si registra, con audit, dal servizio.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_services::Database;
use lisi_services::cyber_search::{Attempt, Branch, CyberSearch};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::account::SharedSession;
use crate::{AppWindow, CyberHitRow};

/// L'archivio della ricerca e la ricerca in corso, se c'è.
pub struct CyberSearchScreen {
    archive: Database,
    current: Option<CyberSearch>,
}

/// Schermata condivisa fra i gestori.
pub type SharedCyberSearch = Rc<RefCell<CyberSearchScreen>>;

/// Crea la schermata sulla sua connessione.
#[must_use]
pub fn create_service(archive: Database) -> SharedCyberSearch {
    Rc::new(RefCell::new(CyberSearchScreen {
        archive,
        current: None,
    }))
}

/// Porta nella schermata la ricerca, o la frase del rifiuto.
fn show(window: &AppWindow, esito: Result<&CyberSearch, &str>) {
    match esito {
        Ok(ricerca) => {
            window.set_cyber_search_scope(crate::lingua::schermo(ricerca.scope_sentence()));
            window.set_cyber_search_outcome(crate::lingua::schermo(format!(
                "{} Risultati letti finora: {}.",
                ricerca.last_outcome,
                ricerca.hits.len()
            )));
            let righe: Vec<CyberHitRow> = ricerca
                .hits
                .iter()
                .map(|trovato| CyberHitRow {
                    chat: SharedString::from(trovato.chat.as_str()),
                    when: SharedString::from(trovato.published_at.to_readable_local()),
                    who: SharedString::from(trovato.who.as_str()),
                    excerpt: SharedString::from(trovato.excerpt.as_str()),
                })
                .collect();
            window.set_cyber_search_hits(ModelRc::from(Rc::new(VecModel::from(righe))));
            window.set_cyber_search_can_continue(ricerca.can_continue());
        }
        Err(frase) => {
            window.set_cyber_search_outcome(crate::lingua::schermo(frase));
        }
    }
}

/// Collega i due comandi.
pub fn wire(window: &AppWindow, screen: &SharedCyberSearch, session: &SharedSession) {
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        let session = Rc::clone(session);
        window.on_cyber_search_start(move |ramo, chat, parole| {
            if crate::lock::refuse_while_locked("cyber_search_start") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let branch = match branch_of(ramo, chat.as_str()) {
                Ok(branch) => branch,
                Err(frase) => {
                    show(&window, Err(frase));
                    return;
                }
            };
            let Ok(operatore) = crate::operator::audit_actor() else {
                show(
                    &window,
                    Err(
                        "Non si riesce a stabilire chi stia agendo su questa postazione: la \
                         ricerca non \u{e8} partita.",
                    ),
                );
                return;
            };
            let esito = {
                let mut sessione = session.borrow_mut();
                let mut schermata = screen.borrow_mut();
                match sessione.runtime_mut() {
                    Some(runtime) => lisi_services::cyber_search::start(
                        Some(runtime.connector_mut()),
                        &mut schermata.archive,
                        &operatore,
                        branch,
                        parole.as_str(),
                        crate::account::now(),
                    ),
                    None => lisi_services::cyber_search::start(
                        None,
                        &mut schermata.archive,
                        &operatore,
                        branch,
                        parole.as_str(),
                        crate::account::now(),
                    ),
                }
            };
            settle(&window, &screen, esito, true);
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        let session = Rc::clone(session);
        window.on_cyber_search_next(move || {
            if crate::lock::refuse_while_locked("cyber_search_next") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let Ok(operatore) = crate::operator::audit_actor() else {
                return;
            };
            let Some(ricerca) = screen.borrow_mut().current.take() else {
                return;
            };
            let esito = {
                let mut sessione = session.borrow_mut();
                let mut schermata = screen.borrow_mut();
                match sessione.runtime_mut() {
                    Some(runtime) => lisi_services::cyber_search::next(
                        Some(runtime.connector_mut()),
                        &mut schermata.archive,
                        &operatore,
                        ricerca,
                        crate::account::now(),
                    ),
                    None => lisi_services::cyber_search::next(
                        None,
                        &mut schermata.archive,
                        &operatore,
                        ricerca,
                        crate::account::now(),
                    ),
                }
            };
            settle(&window, &screen, esito, false);
        });
    }
}

/// Il ramo scelto nella schermata: 1 la C, 2 la D (ADR-0161), altrimenti la B.
pub(crate) fn branch_of(ramo: i32, chat: &str) -> Result<Branch, &'static str> {
    match ramo {
        // IL NUMERO DELLA CHAT NON SI INDOVINA.
        1 => Branch::in_chat(chat).ok_or(
            "Scrivere il numero della chat: si legge nella Ricerca puntuale o nelle Fonti. La \
             ricerca non \u{e8} partita.",
        ),
        2 => Ok(Branch::PublicPosts),
        _ => Ok(Branch::AccountChats),
    }
}

/// Porta l'esito nella schermata e tiene la ricerca per la pagina successiva.
fn settle(
    window: &AppWindow,
    screen: &SharedCyberSearch,
    esito: lisi_services::ServiceResult<Attempt>,
    nuova: bool,
) {
    match esito {
        Ok(Attempt::Done(ricerca)) => {
            show(window, Ok(&ricerca));
            screen.borrow_mut().current = Some(ricerca);
        }
        Ok(Attempt::Refused(frase)) => {
            if nuova {
                window.set_cyber_search_hits(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
                window.set_cyber_search_can_continue(false);
                window.set_cyber_search_scope(SharedString::default());
            }
            show(window, Err(frase.as_str()));
        }
        Err(errore) => show(window, Err(errore.operator_message().as_str())),
    }
}

#[cfg(test)]
mod tests {
    const THIS_MODULE: &str = include_str!("cyber_search.rs");
    const UI: &str = include_str!("../ui/app-window.slint");

    /// **La pagina dice quale ricerca fa che cosa: la D attiva soltanto dentro
    /// la quota gratuita, la E a programma aperto** (CYBER-SEARCH-01 criterio
    /// 7, CYBER-SEARCH-02 criterio 6, CYBER-WATCH-02 criterio 7).
    #[test]
    fn la_pagina_dice_quale_ricerca_fa_che_cosa() {
        for ramo in [
            "A — nell'archivio",
            "B — nelle chat di questo account",
            "C — dentro una chat",
            "D — nei post dei canali pubblici, anche di canali non seguiti: attiva qui, soltanto \
             dentro la quota gratuita di oggi; il prodotto non spende Stelle.",
            "E — ricerche ripetute nel tempo: attiva qui, a programma aperto.",
            "selected: root.cyber-search-branch == 2;",
        ] {
            assert!(UI.contains(ramo), "la pagina deve dire «{ramo}»");
        }
    }

    /// **Il ramo scelto diventa la ricerca giusta, e un numero di chat che non
    /// si legge non si indovina** (CYBER-SEARCH-02, criterio 6).
    #[test]
    fn il_ramo_scelto_diventa_la_ricerca_giusta() {
        use lisi_services::cyber_search::Branch;
        assert_eq!(super::branch_of(0, ""), Ok(Branch::AccountChats));
        assert_eq!(super::branch_of(2, "-1001"), Ok(Branch::PublicPosts));
        assert!(super::branch_of(1, "non un numero").is_err());
        assert!(matches!(
            super::branch_of(1, "-1001"),
            Ok(Branch::InChat(chat)) if chat.get() == -1001
        ));
    }

    /// **Le ricerche partono soltanto da un comando, e i risultati non si
    /// conservano** (criteri 6, 8).
    #[test]
    fn le_ricerche_partono_da_un_comando_e_non_si_conservano() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]") else {
            panic!("il modulo deve avere le sue prove");
        };
        assert!(!produzione.contains("Timer"), "nessuna ricerca automatica");
        for scrittura in [
            "insert_content",
            "analyse_and_record",
            "history::",
            "write_note",
        ] {
            assert!(!produzione.contains(scrittura), "«{scrittura}»");
        }
    }
}

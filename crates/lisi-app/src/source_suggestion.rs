//! I suggerimenti di fonti dall'archivio, nella pagina Fonti
//! (SOURCE-SUGGEST-01, ADR-0164).
//!
//! Si calcolano dai contenuti acquisiti; si ignorano con un motivo o si
//! aggiungono, una per volta, soltanto se la chat è già accessibile
//! all'account, con la stessa strada della pagina Fonti.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_services::Database;
use lisi_services::history::HistoryService;
use lisi_services::source_suggestion::{self, Suggestion};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::account::SharedSession;
use crate::sources::{SharedHealth, SharedSources};
use crate::{AppWindow, SourceSuggestionRow};

/// L'archivio delle decisioni e lo Storico, su due connessioni.
pub struct SuggestionScreen {
    decisions: Database,
    history: HistoryService,
}

/// Schermata condivisa fra i gestori.
pub type SharedSuggestions = Rc<RefCell<SuggestionScreen>>;

/// Crea la schermata sulle sue due connessioni.
#[must_use]
pub fn create_service(decisions: Database, history: Database) -> SharedSuggestions {
    Rc::new(RefCell::new(SuggestionScreen {
        decisions,
        history: HistoryService::new(history),
    }))
}

/// La riga di un suggerimento.
fn row_of(suggerimento: &Suggestion) -> SourceSuggestionRow {
    SourceSuggestionRow {
        address: SharedString::from(suggerimento.address.as_str()),
        title: crate::lingua::schermo(format!("@{}", suggerimento.address.as_str())),
        reason: SharedString::from(suggerimento.reason()),
    }
}

/// Ricalcola i suggerimenti dall'archivio.
pub fn refresh(window: &AppWindow, screen: &SharedSuggestions) {
    let schermata = screen.borrow();
    match source_suggestion::suggestions(&schermata.history, &schermata.decisions) {
        Ok(elenco) => {
            if elenco.is_empty() {
                window.set_source_suggestion_feedback(crate::lingua::schermo(
                    "Nessun suggerimento: nessuna fonte sorvegliata ha citato un post di una \
                     chat che non sia gi\u{e0} fra le fonti o gi\u{e0} decisa.",
                ));
            }
            let righe: Vec<SourceSuggestionRow> = elenco.iter().map(row_of).collect();
            window.set_source_suggestions(ModelRc::from(Rc::new(VecModel::from(righe))));
        }
        Err(errore) => {
            window.set_source_suggestion_feedback(crate::lingua::schermo(
                errore.operator_message().as_str(),
            ));
        }
    }
}

/// Collega i tre comandi: ricalcolare, aggiungere, ignorare.
pub fn wire(
    window: &AppWindow,
    screen: &SharedSuggestions,
    sources: &SharedSources,
    health: Option<&SharedHealth>,
    session: &SharedSession,
) {
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_source_suggestions_refresh(move || {
            if crate::lock::refuse_while_locked("source_suggestions_refresh") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            window.set_source_suggestion_feedback(SharedString::default());
            refresh(&window, &screen);
        });
    }
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_source_suggestion_ignore(move |indirizzo, motivo| {
            if crate::lock::refuse_while_locked("source_suggestion_ignore") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let Ok(operatore) = crate::operator::audit_actor() else {
                window.set_source_suggestion_feedback(crate::lingua::schermo(
                    "Non si riesce a stabilire chi stia agendo su questa postazione: nulla \u{e8} \
                     cambiato.",
                ));
                return;
            };
            let esito = source_suggestion::ignore(
                &mut screen.borrow_mut().decisions,
                &operatore,
                indirizzo.as_str(),
                motivo.as_str(),
                crate::account::now(),
            );
            window.set_source_suggestion_feedback(SharedString::from(match esito {
                Ok(Ok(())) => {
                    window.set_source_suggestion_reason(SharedString::default());
                    format!(
                        "@{indirizzo} ignorata, con il motivo: non torner\u{e0} fra i \
                         suggerimenti."
                    )
                }
                Ok(Err(frase)) => frase,
                Err(errore) => errore.operator_message(),
            }));
            refresh(&window, &screen);
        });
    }
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        let sources = Rc::clone(sources);
        let health = health.map(Rc::clone);
        let session = Rc::clone(session);
        window.on_source_suggestion_add(move |indirizzo| {
            if crate::lock::refuse_while_locked("source_suggestion_add") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let Ok(operatore) = crate::operator::audit_actor() else {
                window.set_source_suggestion_feedback(crate::lingua::schermo(
                    "Non si riesce a stabilire chi stia agendo su questa postazione: nulla \u{e8} \
                     stato aggiunto.",
                ));
                return;
            };
            let esito = {
                let mut sessione = session.borrow_mut();
                let fonti = sources.borrow();
                let mut schermata = screen.borrow_mut();
                let connettore = sessione
                    .runtime_mut()
                    .map(|runtime| runtime.connector_mut());
                source_suggestion::add(
                    connettore,
                    &fonti,
                    &mut schermata.decisions,
                    &operatore,
                    indirizzo.as_str(),
                    crate::account::now(),
                )
            };
            let frase = match esito {
                Ok(Ok(_)) => format!(
                    "@{indirizzo} aggiunta come fonte, con il tuo nome: \u{e8} nell'elenco delle \
                     fonti qui sopra."
                ),
                Ok(Err(frase)) => frase,
                Err(errore) => errore.operator_message(),
            };
            window.set_source_suggestion_feedback(SharedString::from(frase.as_str()));
            crate::sources::refresh(&window, &sources, health.as_ref(), &session, None);
            refresh(&window, &screen);
        });
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use lisi_core::Timestamp;
    use lisi_core::model::discovery::PublicAddress;
    use lisi_services::source_suggestion::Suggestion;

    use super::row_of;

    /// **La riga dice l'indirizzo con la chiocciola e il motivo, con
    /// l'avvertenza** (SOURCE-SUGGEST-01, criterio 7).
    #[test]
    fn la_riga_dice_l_indirizzo_e_il_motivo() {
        let Some(indirizzo) = PublicAddress::try_new("canale_cyber") else {
            panic!("indirizzo valido");
        };
        let riga = row_of(&Suggestion {
            address: indirizzo,
            mentions: 1,
            contents: 1,
            sources: BTreeSet::from([String::from("Canale di prova")]),
            first_at: Timestamp::from_millis(1_760_000_000_000),
            last_at: Timestamp::from_millis(1_760_000_000_000),
        });
        assert_eq!(riga.title.as_str(), "@canale_cyber");
        assert_eq!(riga.address.as_str(), "canale_cyber");
        assert!(
            riga.reason.contains("citato una volta in un contenuto"),
            "{}",
            riga.reason
        );
        assert!(riga.reason.contains("Citare non \u{e8} garantire"));
    }
}

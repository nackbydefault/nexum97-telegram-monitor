//! «Scopri che cosa è cambiato», dalla parte dell'interfaccia (NEWS-01,
//! ADR-0169).
//!
//! # Che cosa sta qui
//!
//! - la traduzione delle novità nelle righe del disegno, con la schermata di
//!   ciascuna;
//! - all'avvio, la decisione del servizio se aprire il giro da sé;
//! - il collegamento dei due comandi: il giro è comparso, il giro è chiesto.
//!
//! # Che cosa non sta qui
//!
//! Il registro delle novità e la regola «una volta per edizione»: li tiene
//! `lisi_services::news`. Il giro sta fra gli strati di Scopri NEXUM, e la
//! guardia del tour vale anche per lui: chiama soltanto `open-page` e i propri
//! comandi.

use std::rc::Rc;

use lisi_services::Database;
use lisi_services::news::{NewsItem, NewsService, latest_items, place_label};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::{AppWindow, NewsRow};

/// Il giro, condiviso fra i comandi.
pub struct NewsScreen {
    service: NewsService,
}

/// Crea il giro attorno al suo archivio.
#[must_use]
pub fn create(database: Option<Database>) -> Option<Rc<NewsScreen>> {
    database.map(|database| {
        Rc::new(NewsScreen {
            service: NewsService::new(database),
        })
    })
}

/// Una novità, come la legge il disegno.
fn row(item: &NewsItem) -> NewsRow {
    NewsRow {
        title: SharedString::from(item.title),
        sentence: SharedString::from(item.sentence),
        place: SharedString::from(place_label(item.place)),
        page: crate::tour::page_of(item.place),
    }
}

/// Mette le novità nel disegno.
fn show(window: &AppWindow, items: &[NewsItem]) {
    let righe: Vec<NewsRow> = items.iter().map(row).collect();
    window.set_tour_news_rows(ModelRc::from(Rc::new(VecModel::from(righe))));
    window.set_tour_news_index(0);
}

/// All'avvio: se ci sono novità non viste, prepara il giro. Compare soltanto
/// sulla Dashboard operativa, dopo la domanda del primo avvio (ADR-0169 §3).
pub fn propose_if_due(window: &AppWindow, news: &NewsScreen, exercise: bool) {
    match news.service.on_start(exercise, crate::account::now()) {
        Ok(novita) if !novita.is_empty() => {
            show(window, &novita);
            window.set_tour_news_pending(true);
        }
        Ok(_) => window.set_tour_news_pending(false),
        Err(errore) => {
            // Nel dubbio non si apre: le novità restano raggiungibili dal
            // pannello di Scopri NEXUM.
            tracing::warn!(errore = %errore, "stato delle novità non leggibile: nessun giro");
            window.set_tour_news_pending(false);
        }
    }
}

/// Collega i comandi del giro.
pub fn wire(window: &AppWindow, news: &Rc<NewsScreen>) {
    {
        let news = Rc::clone(news);
        window.on_tour_news_shown(move || {
            if crate::lock::refuse_while_locked("tour_news_shown") {
                return;
            }
            if let Err(errore) = news.service.mark_shown(crate::account::now()) {
                tracing::warn!(errore = %errore, "comparsa delle novità non registrata");
            }
        });
    }
    {
        let handle = window.as_weak();
        window.on_tour_news_requested(move || {
            if crate::lock::refuse_while_locked("tour_news_requested") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                show(&window, &latest_items());
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use lisi_services::Database;
    use lisi_services::news::{items_after, latest_items};
    use slint::{ComponentHandle, Model};

    use super::{create, propose_if_due, row, show, wire};
    use crate::page_guard::UI;
    use crate::{AppWindow, DocumentProfile};

    /// **Ogni novità porta a una schermata vera** (NEWS-01, criterio 5): il
    /// luogo «resta dove sei» non è un luogo per una novità.
    #[test]
    fn ogni_novita_porta_a_una_schermata() {
        for novita in items_after(0) {
            let riga = row(&novita);
            assert!(riga.page >= 0, "{}", novita.key);
            assert!(!riga.place.is_empty(), "{}", novita.key);
        }
    }

    /// **Il «Dove» di ogni novità è la voce del menu che apre la sua
    /// schermata** (NEWS-01, criterio 5; prova negativa: il luogo chiamato
    /// «Dashboard», che il menu chiama «Cruscotto» → rossa). Un nome che il
    /// menu non porta manda a cercare una voce che non c'è.
    #[test]
    fn il_luogo_di_ogni_novita_e_una_voce_del_menu() {
        for novita in items_after(0) {
            let riga = row(&novita);
            // La voce si scrive anche tradotta, con `@tr` (I18N-01).
            let voce = format!("label: \"{}\";", riga.place);
            let tradotta = format!("label: @tr(\"{}\");", riga.place);
            let Some((_, dopo)) = UI
                .split_once(voce.as_str())
                .or_else(|| UI.split_once(tradotta.as_str()))
            else {
                panic!("«{}»: il menu non ha la voce «{}»", novita.key, riga.place);
            };
            let vicino: String = dopo.chars().take(240).collect();
            assert!(
                vicino.contains(&format!("root.open-page({});", riga.page)),
                "«{}»: la voce «{}» non apre la schermata {}",
                novita.key,
                riga.place,
                riga.page
            );
        }
    }

    /// **Il giro sta fra gli strati di Scopri NEXUM**, dove la guardia del tour
    /// lo legge, e si registra come visto soltanto quando compare da sé
    /// (criterio 5; prova negativa: il giro fuori dal tratto → rossa).
    #[test]
    fn il_giro_sta_fra_gli_strati_del_tour() {
        let Some((_, dopo)) = UI.split_once("TOUR-01 — strati, inizio") else {
            panic!("il tratto degli strati deve esistere");
        };
        let Some((strati, _)) = dopo.split_once("TOUR-01 — strati, fine") else {
            panic!("il tratto degli strati deve chiudersi");
        };
        let Some((_, giro)) = strati.split_once("if root.tour-news-visible: Rectangle {") else {
            panic!("il giro delle novità deve stare fra gli strati del tour");
        };
        let Some((apertura, _)) = giro.split_once("TouchArea { }") else {
            panic!("il giro deve avere il suo velo");
        };
        assert!(
            apertura.contains("if (!root.tour-news-open) {")
                && apertura.contains("root.tour-news-shown();"),
            "il giro si registra soltanto quando compare da sé"
        );
    }

    /// **Il giro sulla finestra vera** (NEWS-01, criterio 5; prova negativa:
    /// il giro aperto insieme alla proposta del tour → rossa). Compare solo
    /// sulla Dashboard dopo la domanda del primo avvio, mai con la proposta
    /// del tour; una postazione nuova non lo riceve; «Che cosa è cambiato» lo
    /// prepara con l'ultima edizione.
    #[test]
    fn il_giro_sulla_finestra_vera() {
        i_slint_backend_testing::init_no_event_loop();
        let Ok(window) = AppWindow::new() else {
            panic!("la finestra di prova deve nascere");
        };
        let Ok(database) = Database::open_in_memory() else {
            panic!("l'archivio di prova deve aprirsi");
        };
        let Some(news) = create(Some(database)) else {
            panic!("il giro deve nascere");
        };
        wire(&window, &news);

        // Una postazione nuova: il tour non è mai stato proposto, niente giro.
        propose_if_due(&window, &news, false);
        assert!(!window.get_tour_news_pending());
        assert!(!window.get_tour_news_visible());

        // Le novità pronte: prima della domanda del primo avvio non compaiono.
        show(&window, &items_after(0));
        window.set_tour_news_pending(true);
        window.global::<DocumentProfile>().set_answered(false);
        window.invoke_open_page(0);
        assert!(!window.get_tour_news_visible(), "prima del primo avvio");

        // Risposta data, Dashboard: compare.
        window.global::<DocumentProfile>().set_answered(true);
        assert!(window.get_tour_news_visible());

        // Su un'altra schermata no, e mai con la proposta del tour.
        window.invoke_open_page(3);
        assert!(!window.get_tour_news_visible(), "fuori dalla Dashboard");
        window.invoke_open_page(0);
        window.set_tour_proposal_pending(true);
        assert!(window.get_tour_proposal_visible());
        assert!(
            !window.get_tour_news_visible(),
            "il giro insieme alla proposta del tour"
        );
        window.set_tour_proposal_pending(false);
        assert!(window.get_tour_news_visible());

        // «Che cosa è cambiato»: le novità dell'ultima edizione.
        window.set_tour_news_pending(false);
        window.invoke_tour_news_requested();
        assert_eq!(
            window.get_tour_news_rows().row_count(),
            latest_items().len()
        );
        assert_eq!(window.get_tour_news_index(), 0);
    }
}

//! Gli elenchi non stanno in una fessura (COLLAUDO-FIX-01, CU01-014, DEC-507).
//!
//! Il collaudo della 0.2.2 ha trovato i gruppi di «Segnali cyber» in una fascia
//! di circa 30 pixel, fra il menu del monitoraggio e l'avvertenza sul settore, e
//! la libreria dei «Dizionari» in una di circa 200 sotto le sezioni fisse di
//! importazione e scaricamento. Ogni schermata sta già in un'area che scorre per
//! intero (`schermata`); quegli elenchi ne aprivano un'altra, annidata, che
//! riceveva soltanto ciò che restava. Ora l'elenco è alto quanto il suo
//! contenuto, e scorre con la schermata.
//!
//! Qui la finestra si costruisce davvero, alla misura del collaudo, e la si
//! scorre con la rotellina come farebbe l'operatore. Il motore di prova vede
//! soltanto ciò che sta nella parte visibile: si conta quante voci si vedono
//! insieme, e quanto è alta l'area che scorre attorno a ciascuna.

#[cfg(test)]
mod tests {
    use std::rc::Rc;
    use std::time::Duration;

    use i_slint_backend_testing::{ElementHandle, ElementRoot};
    use slint::{ComponentHandle, LogicalSize, ModelRc, SharedString, VecModel};

    use crate::{AppWindow, CyberCandidateEntry, CyberEventEntry, DictionaryEntry};

    /// La finestra del collaudo: la più grande che il lavoro consentiva su uno
    /// schermo 1920×1080.
    const LARGHEZZA: f32 = 1366.0;
    const ALTEZZA: f32 = 1040.0;

    /// Sotto questa altezza un'area che scorre non è un elenco ma una fessura:
    /// la fessura del collaudo era di 30 pixel, quella dei dizionari di 200.
    const VISTA_MINIMA: f32 = 400.0;

    /// Un passo della rotellina, e quanti se ne fanno al più.
    const PASSO: f32 = -60.0;
    const PASSI: usize = 80;

    const PAGINA_DIZIONARI: i32 = 4;
    const PAGINA_SEGNALI_CYBER: i32 = 16;

    fn finestra(pagina: i32) -> AppWindow {
        i_slint_backend_testing::init_no_event_loop();
        let Ok(window) = AppWindow::new() else {
            panic!("la finestra di prova deve potersi costruire");
        };
        // La lingua di partenza, come fa il programma dopo aver creato la
        // finestra: da sola Slint sceglierebbe quella del sistema, e su un
        // Windows in inglese queste etichette non ci sarebbero (DEC-516).
        if slint::select_bundled_translation("").is_err() {
            panic!("la lingua di partenza deve potersi scegliere");
        }
        window
            .window()
            .set_size(LogicalSize::new(LARGHEZZA, ALTEZZA));
        if window.show().is_err() {
            panic!("la finestra di prova deve potersi mostrare");
        }
        window.set_current_page(pagina);
        window
    }

    /// L'area che scorre attorno a tutte le schermate.
    fn schermata(window: &AppWindow) -> ElementHandle {
        let Some(area) = ElementHandle::find_by_element_id(window, "AppWindow::schermata").next()
        else {
            panic!("l'area che scorre attorno alle schermate si chiama «schermata»");
        };
        area
    }

    fn con_etichetta(etichetta: &'static str) -> impl Fn(&ElementHandle) -> bool + 'static {
        move |elemento| {
            elemento
                .accessible_label()
                .is_some_and(|nome| nome.starts_with(etichetta))
        }
    }

    /// Gli elementi con quell'etichetta che si vedono adesso.
    fn visibili(window: &AppWindow, etichetta: &'static str) -> Vec<ElementHandle> {
        window
            .root_element()
            .query_descendants()
            .match_predicate(con_etichetta(etichetta))
            .find_all()
    }

    /// Le aree a scorrimento che contengono un elemento visibile con
    /// quell'etichetta.
    fn aree_attorno(window: &AppWindow, etichetta: &'static str) -> Vec<ElementHandle> {
        ElementHandle::find_by_element_type_name(window, "HudScroll")
            .filter(|area| {
                area.query_descendants()
                    .match_predicate(con_etichetta(etichetta))
                    .find_first()
                    .is_some()
            })
            .collect()
    }

    /// Scorre la schermata dall'inizio alla fine, un passo di rotellina alla
    /// volta, e dice quante voci con quell'etichetta si sono viste **insieme**,
    /// al più. A ogni passo, ogni area che scorre attorno a una voce visibile
    /// dev'essere alta almeno [`VISTA_MINIMA`].
    fn al_massimo_insieme(window: &AppWindow, etichetta: &'static str) -> usize {
        let area = schermata(window);
        let mut massimo = 0;
        for _ in 0..PASSI {
            let viste = visibili(window, etichetta).len();
            if viste > 0 {
                for attorno in aree_attorno(window, etichetta) {
                    let altezza = attorno.size().height;
                    assert!(
                        altezza >= VISTA_MINIMA,
                        "«{etichetta}» sta in un'area che scorre alta {altezza} px, a finestra \
                         {LARGHEZZA}×{ALTEZZA}: è una fessura, non un elenco (CU01-014)"
                    );
                }
            }
            massimo = massimo.max(viste);
            area.scroll(0.0, PASSO);
        }
        massimo
    }

    /// Scorre finché l'elemento si vede, e lo restituisce.
    fn scorri_fino_a(window: &AppWindow, etichetta: &'static str) -> ElementHandle {
        let area = schermata(window);
        for _ in 0..PASSI {
            if let Some(trovato) = visibili(window, etichetta).into_iter().next() {
                return trovato;
            }
            area.scroll(0.0, PASSO);
        }
        panic!("«{etichetta}» non si vede nemmeno scorrendo la schermata fino in fondo");
    }

    /// I giri dopo un clic, come nel ciclo degli eventi: nel primo il `Timer`
    /// che porta in vista si accende e ciò che si è appena aperto prende
    /// posto; nel secondo il `Timer` scatta.
    fn giro_dopo() {
        i_slint_backend_testing::mock_elapsed_time(Duration::from_millis(50));
        i_slint_backend_testing::mock_elapsed_time(Duration::from_millis(50));
    }

    /// L'elemento si vede per intero, senza bisogno di scorrere.
    fn in_vista(window: &AppWindow, etichetta: &'static str) {
        let Some(voce) = visibili(window, etichetta).into_iter().next() else {
            panic!(
                "«{etichetta}» non si vede: sta fuori dalla parte visibile, e il clic sembra \
                 non aver fatto nulla (CU01-014)"
            );
        };
        let area = schermata(window);
        let cima = voce.absolute_position().y;
        let fondo = cima + voce.size().height;
        let inizio = area.absolute_position().y;
        let fine = inizio + area.size().height;
        assert!(
            cima >= inizio && fondo <= fine,
            "«{etichetta}» sta fra {cima} e {fondo}, e la parte visibile va da {inizio} a \
             {fine}: si vede soltanto in parte"
        );
    }

    fn modello<T: Clone + 'static>(voci: Vec<T>) -> ModelRc<T> {
        ModelRc::from(Rc::new(VecModel::from(voci)))
    }

    fn gruppi(quanti: usize) -> ModelRc<CyberEventEntry> {
        modello(
            (0..quanti)
                .map(|indice| CyberEventEntry {
                    reason: SharedString::from(format!(
                        "{} contenuti che nominano il dominio esempio-{indice}.test",
                        indice + 2
                    )),
                    reason_kind: SharedString::from("domain"),
                    search_key: SharedString::from(format!("esempio-{indice}.test")),
                    contents: 3,
                    distinct_sources: 2,
                    ..CyberEventEntry::default()
                })
                .collect(),
        )
    }

    fn dizionari(quanti: usize) -> ModelRc<DictionaryEntry> {
        modello(
            (0..quanti)
                .map(|indice| DictionaryEntry {
                    dictionary_id: i32::try_from(indice + 1).unwrap_or(i32::MAX),
                    name: SharedString::from(format!("Dizionario di prova {indice}")),
                    status: SharedString::from("pubblicato"),
                    published_version: 1,
                    published_terms: 12,
                    has_open_draft: indice == 0,
                    usable: true,
                    ..DictionaryEntry::default()
                })
                .collect(),
        )
    }

    /// **I gruppi di un monitoraggio non stanno in una fessura** (CU01-014).
    ///
    /// Vista rossa sulla disposizione del collaudo: l'elenco stava in un'area
    /// a scorrimento sua, alta 40 pixel, e se ne vedeva al più uno alla volta.
    #[test]
    fn i_gruppi_di_un_monitoraggio_non_stanno_in_una_fessura() {
        let window = finestra(PAGINA_SEGNALI_CYBER);
        window.set_cyber_has_session(true);
        window.set_cyber_events(gruppi(3));
        let insieme = al_massimo_insieme(&window, "Cronologia");
        assert!(
            insieme >= 3,
            "dei tre gruppi se ne vedono insieme al più {insieme}, a finestra \
             {LARGHEZZA}×{ALTEZZA} (CU01-014)"
        );
    }

    /// **Neppure gli eventi candidati di tutto l'archivio**, che stanno nello
    /// stesso posto quando nessun monitoraggio è scelto.
    #[test]
    fn gli_eventi_candidati_non_stanno_in_una_fessura() {
        let window = finestra(PAGINA_SEGNALI_CYBER);
        window.set_cyber_has_session(false);
        window.set_cyber_candidates(modello(
            (0..3)
                .map(|indice| CyberCandidateEntry {
                    sentence: SharedString::from(format!(
                        "Il dominio esempio-{indice}.test è nominato da due fonti."
                    )),
                    first_content_id: indice + 1,
                    ..CyberCandidateEntry::default()
                })
                .collect(),
        ));
        let insieme = al_massimo_insieme(&window, "Apri la conversazione");
        assert!(
            insieme >= 3,
            "dei tre eventi candidati se ne vedono insieme al più {insieme} (CU01-014)"
        );
    }

    /// **La cronologia aperta si porta in vista** (CU01-014): sta sotto
    /// l'elenco dei gruppi, e senza scorrere il clic su «Cronologia» sembrava
    /// non aver fatto nulla.
    #[test]
    fn la_cronologia_aperta_si_porta_in_vista() {
        let window = finestra(PAGINA_SEGNALI_CYBER);
        window.set_cyber_has_session(true);
        window.set_cyber_events(gruppi(8));
        let handle = window.as_weak();
        window.on_cyber_timeline_requested(move |_, _| {
            if let Some(window) = handle.upgrade() {
                window
                    .set_cyber_timeline_title(SharedString::from("Cronologia del gruppo di prova"));
                window.set_cyber_timeline_open(true);
            }
        });
        scorri_fino_a(&window, "Cronologia").invoke_accessible_default_action();
        giro_dopo();
        assert!(window.get_cyber_timeline_open());
        in_vista(&window, "Cronologia del gruppo di prova");
    }

    /// **La libreria dei dizionari e l'editor della bozza non stanno in una
    /// fessura** (CU01-014): stavano in una fascia sotto l'importazione e lo
    /// scaricamento.
    #[test]
    fn la_libreria_dei_dizionari_non_sta_in_una_fessura() {
        let window = finestra(PAGINA_DIZIONARI);
        window.set_dictionaries(dizionari(6));
        let insieme = al_massimo_insieme(&window, "Dizionario di prova");
        assert!(
            insieme >= 5,
            "dei sei dizionari se ne vedono insieme al più {insieme} (CU01-014)"
        );
        window.set_draft_open(true);
        let editor = al_massimo_insieme(&window, "Termine da aggiungere alla bozza");
        assert_eq!(editor, 1, "l'editor della bozza si raggiunge scorrendo");
    }

    /// **La bozza aperta si porta in vista**: sta sotto la libreria, come la
    /// cronologia sotto i gruppi.
    #[test]
    fn la_bozza_aperta_si_porta_in_vista() {
        let window = finestra(PAGINA_DIZIONARI);
        window.set_dictionaries(dizionari(8));
        let handle = window.as_weak();
        window.on_preview_dictionary(move |_| {
            if let Some(window) = handle.upgrade() {
                window.set_draft_open(true);
                window.set_preview_title(SharedString::from("Anteprima di prova"));
            }
        });
        scorri_fino_a(&window, "Modifica la bozza").invoke_accessible_default_action();
        giro_dopo();
        assert!(window.get_draft_open());
        in_vista(&window, "Termine da aggiungere alla bozza");
    }
}

//! Le ricerche salvate: si salvano dove si cerca, si rifanno da un elenco
//! (SEARCH-01).
//!
//! # Dove si salva
//!
//! **Nello Storico**, davanti al risultato che si sta guardando. Chiedere in
//! un'altra schermata di ricostruire la domanda produrrebbe ricerche diverse da
//! quella che si aveva davanti, senza che nulla lo dica.
//!
//! # Dove si rifà, e dove compaiono i risultati
//!
//! Si rifà dalla schermata Ricerche, e i risultati compaiono **nello Storico**:
//! il filtro salvato viene applicato lì, e la schermata cambia.
//!
//! Non c'è una seconda lista di risultati. Ce ne fosse una, sarebbe una seconda
//! nozione di ricerca — che è esattamente ciò che questa milestone esisteva per
//! non fare.
//!
//! # Che cosa questo modulo dice, e nessun altro direbbe
//!
//! Che **rifare una ricerca non riproduce il risultato di allora**. Le ragioni
//! ovvie — materiale nuovo, contenuti modificati, decisioni cambiate — chi
//! lavora le conosce. Quella che nessuno vedrebbe da sé è che i livelli **non
//! si ricalcolano**: li ha prodotti una versione del motore, e se quella
//! cambia, due esecuzioni della stessa domanda misurano con metri diversi.
//!
//! La frase lo dice con i numeri, e mai con un allarme generico.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_core::model::saved_search::{NewSavedSearch, SavedQuery};
use lisi_core::text::DisplayName;
use lisi_core::{SavedSearchId, Timestamp};
use lisi_services::history::HistoryService;
use lisi_services::saved_search::SavedSearchService;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::{AppWindow, SavedSearchRow};

/// I due servizi che questa schermata usa.
///
/// # Perché due archivi e non uno
///
/// Perché rifare una ricerca **legge lo storico**, e salvarne una **scrive**.
/// Sono due connessioni, come in tutto il resto del prodotto: prestarne una
/// avanti e indietro fra un servizio che scrive e uno che legge
/// significherebbe farli contendere la stessa.
pub struct SearchScreens {
    searches: SavedSearchService,
    /// Lo storico, per rifare la ricerca.
    ///
    /// **È lo stesso servizio della schermata Storico**, non una copia della
    /// sua logica: la ricerca è una sola, e questa è la funzione che la esegue.
    history: HistoryService,
}

/// La pagina dello Storico, dove i risultati compaiono.
///
/// # Perché una costante e non il numero sparso
///
/// Perché il giorno in cui le pagine si rinumerano, un numero scritto in mezzo
/// al codice porterebbe altrove **in silenzio**.
const PAGINA_STORICO: i32 = 8;

/// Servizi delle ricerche salvate, condivisi fra i gestori dei comandi.
pub type SharedSearches = Rc<RefCell<SearchScreens>>;

/// Costruisce i servizi sugli archivi indicati.
#[must_use]
pub fn create_service(
    searches: Option<lisi_services::Database>,
    history: Option<lisi_services::Database>,
) -> Option<SharedSearches> {
    Some(Rc::new(RefCell::new(SearchScreens {
        searches: SavedSearchService::new(searches?),
        history: HistoryService::new(history?),
    })))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> Timestamp {
    lisi_core::time::anchored_now()
}

/// Rilegge l'elenco delle ricerche salvate.
pub fn refresh(window: &AppWindow, searches: &SharedSearches) {
    let Ok(elenco) = searches.borrow().searches.all() else {
        window.set_saved_search_message(crate::lingua::schermo(
            "Le ricerche salvate non sono leggibili in questo momento: quello qui sotto non dice \
             che non ce ne siano.",
        ));
        window.set_saved_search_rows(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        return;
    };

    let righe: Vec<SavedSearchRow> = elenco
        .iter()
        .map(|ricerca| SavedSearchRow {
            id: i32::try_from(ricerca.id.get()).unwrap_or(i32::MAX),
            name: SharedString::from(ricerca.name.as_str()),
            // LA FRASE LA COMPONE IL MODELLO (DEC-252): dice chi, quando, e che
            // cosa la ricerca chiede — per esteso.
            sentence: crate::lingua::schermo(ricerca.as_sentence()),
        })
        .collect();
    window.set_saved_search_rows(ModelRc::from(Rc::new(VecModel::from(righe))));
}

/// Salva la ricerca che si sta guardando.
fn save(window: &AppWindow, searches: &SharedSearches, name: &str) {
    let Ok(nome) = DisplayName::try_new(name) else {
        window.set_saved_search_message(crate::lingua::schermo(
            "Una ricerca salvata ha bisogno di un nome: \u{e8} quello con cui la si \
             ritrover\u{e0}.",
        ));
        return;
    };
    let Ok(attore) = crate::operator::audit_actor() else {
        window.set_saved_search_message(crate::lingua::schermo(
            "Non si riesce a stabilire chi stia agendo su questa postazione.",
        ));
        return;
    };

    // LA DOMANDA E' QUELLA CHE SI STA GUARDANDO, letta dalle stesse proprieta'
    // che lo Storico usa per filtrare. Ricostruirla altrove darebbe una
    // ricerca diversa da quella che si aveva davanti.
    let query = SavedQuery {
        query: window.get_history_filter().to_string(),
        // Lo Storico non espone ancora un livello minimo: la ricerca salvata lo
        // conserva comunque, perche' il filtro ce l'ha. Il giorno in cui la
        // schermata lo offrira', qui non ci sara' nulla da cambiare.
        minimum_level: 0,
        only_pending: window.get_history_only_pending(),
        session: None,
    };

    let Ok(nuova) = NewSavedSearch::of(nome, query, attore) else {
        window.set_saved_search_message(crate::lingua::schermo(
            "Questa ricerca non chiede niente: restituirebbe tutto, che \u{e8} ci\u{f2} che lo \
             Storico mostra gi\u{e0}. Scrivere che cosa cercare, oppure scegliere «Solo da \
             esaminare».",
        ));
        return;
    };

    match searches.borrow().searches.save(&nuova, now()) {
        Ok(_) => {
            window.set_history_save_search_name(SharedString::default());
            window.set_saved_search_message(crate::lingua::schermo(
                "Ricerca salvata. Si rif\u{e0} dalla schermata Ricerche, e i risultati compaiono \
                 qui nello Storico.",
            ));
        }
        Err(errore) => {
            window.set_saved_search_message(crate::lingua::schermo(errore.operator_message()));
        }
    }

    refresh(window, searches);
}

/// Rifà una ricerca salvata, e porta ai risultati.
///
/// # Perché porta allo Storico invece di mostrare qui
///
/// Perché una seconda lista di risultati sarebbe una seconda nozione di
/// ricerca. Il filtro salvato viene applicato alla lista che c'è già, e la
/// schermata cambia.
fn run(
    window: &AppWindow,
    searches: &SharedSearches,
    history: &crate::history::SharedHistory,
    id: i32,
) {
    if id <= 0 {
        return;
    }

    let esito = {
        let screens = searches.borrow();
        screens
            .searches
            .run(SavedSearchId::new(i64::from(id)), &screens.history)
    };

    let esecuzione = match esito {
        Ok(esecuzione) => esecuzione,
        Err(errore) => {
            window.set_saved_search_message(crate::lingua::schermo(errore.operator_message()));
            return;
        }
    };

    // IL FILTRO TORNA DOV'ERA, e la schermata lo rilegge.
    window.set_history_filter(SharedString::from(esecuzione.search.query.query.as_str()));
    window.set_history_only_pending(esecuzione.search.query.only_pending);

    // CHE COSA SI E' MOSSO, con i numeri.
    //
    // Compare accanto ai risultati, perche' e' li' che serve: una frase su
    // un'altra schermata non la leggerebbe nessuno.
    window.set_history_search_drift(crate::lingua::schermo(esecuzione.drift.as_sentence()));
    window.set_history_search_comparable(esecuzione.drift.is_comparable());

    window.set_saved_search_message(SharedString::default());
    window.set_current_page(PAGINA_STORICO);
    crate::history::refresh(window, history, None);
}

/// Cancella una ricerca salvata.
fn delete(window: &AppWindow, searches: &SharedSearches, id: i32) {
    if id <= 0 {
        return;
    }
    let Ok(attore) = crate::operator::audit_actor() else {
        window.set_saved_search_message(crate::lingua::schermo(
            "Non si riesce a stabilire chi stia agendo su questa postazione.",
        ));
        return;
    };

    match searches
        .borrow()
        .searches
        .delete(SavedSearchId::new(i64::from(id)), &attore, now())
    {
        Ok(()) => window.set_saved_search_message(crate::lingua::schermo(
            "Ricerca cancellata. I contenuti restano dov'erano: una ricerca salvata \u{e8} \
             una domanda, e cancellarla non cancella nulla di ci\u{f2} che trovava.",
        )),
        Err(errore) => {
            window.set_saved_search_message(crate::lingua::schermo(errore.operator_message()));
        }
    }

    refresh(window, searches);
}

/// Collega i comandi.
pub fn wire(
    window: &AppWindow,
    searches: &SharedSearches,
    history: &crate::history::SharedHistory,
) {
    {
        let handle = window.as_weak();
        let searches = Rc::clone(searches);
        window.on_searches_shown(move || {
            if let Some(window) = handle.upgrade() {
                refresh(&window, &searches);
            }
        });
    }

    {
        let handle = window.as_weak();
        let searches = Rc::clone(searches);
        window.on_history_save_search(move |name| {
            if crate::lock::refuse_while_locked("history_save_search") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                save(&window, &searches, name.as_str());
            }
        });
    }

    {
        let handle = window.as_weak();
        let searches = Rc::clone(searches);
        let history = Rc::clone(history);
        window.on_run_saved_search(move |id| {
            if crate::lock::refuse_while_locked("run_saved_search") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                run(&window, &searches, &history, id);
            }
        });
    }

    {
        let handle = window.as_weak();
        let searches = Rc::clone(searches);
        window.on_delete_saved_search(move |id| {
            if crate::lock::refuse_while_locked("delete_saved_search") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                delete(&window, &searches, id);
            }
        });
    }
}

/// Quante righe l'elenco mostra: serve alle prove.
#[cfg(test)]
fn conta_ricerche(window: &AppWindow) -> usize {
    use slint::Model as _;
    window.get_saved_search_rows().iter().count()
}

#[cfg(test)]
mod tests {
    use super::{PAGINA_STORICO, conta_ricerche};

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("saved_search.rs");

    /// Il file dell'interfaccia.
    const UI: &str = include_str!("../ui/app-window.slint");

    /// Il codice di produzione senza i commenti.
    fn codice_senza_commenti() -> String {
        let Some((produzione, prove)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        for riga in prove.lines() {
            let e_codice = ["impl ", "fn ", "struct ", "enum ", "const ", "use ", "pub "]
                .iter()
                .any(|inizio| riga.starts_with(inizio));
            assert!(
                !e_codice,
                "c'e' del codice dopo il blocco di prove, invisibile a ogni guardia: «{riga}»"
            );
        }
        produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Il blocco della pagina 23, e nient'altro.
    ///
    /// # Perché estratto e senza ripiego
    ///
    /// Perché una guardia che cercasse in tutto il file troverebbe la parola
    /// giusta in un'altra schermata e resterebbe verde per la ragione
    /// sbagliata. Se il blocco non si trovasse, il ripiego «cerca ovunque»
    /// farebbe passare qualunque cosa: qui non c'è ripiego, si rompe.
    fn pagina_delle_ricerche() -> String {
        // L'ESTRATTORE E' UNO SOLO, E DIMOSTRA DI AVER LETTO QUALCOSA.
        //
        // Prima di HARDEN-02 ogni modulo ritagliava il corpo della propria
        // pagina per conto proprio, e un ritaglio che coglieva troppo poco
        // non faceva fallire niente: ogni divieto restava vero perche' non
        // c'era niente da vietare (ADR-0111).
        crate::page_guard::corpo_della_pagina(23)
    }

    /// **La schermata delle ricerche non ha una lista di risultati.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una seconda nozione di ricerca — quella che NOTE-01 aveva dichiarato di
    /// non voler creare, aprendo questa milestone. Due liste di risultati
    /// divergono: filtrano diverso, mostrano colonne diverse, e il giorno in cui
    /// una regola cambia cambia in una sola.
    #[test]
    fn la_schermata_delle_ricerche_non_ha_una_lista_di_risultati() {
        let pagina = pagina_delle_ricerche();
        for lista in [
            "history-rows",
            "ContentScreen",
            "for contenuto in",
            "SelectableRow",
        ] {
            assert!(
                !pagina.contains(lista),
                "la schermata dichiara «{lista}»: sarebbe una seconda lista di risultati, cioe' \
                 una seconda nozione di ricerca"
            );
        }
        assert!(
            pagina.contains("root.run-saved-search"),
            "rifare deve esserci, e porta allo Storico"
        );
    }

    /// **La schermata delle ricerche non salva.**
    ///
    /// # Perché conta
    ///
    /// Perché si salva dove si cerca. Un campo qui chiederebbe di ricostruire
    /// la domanda, e produrrebbe una ricerca diversa da quella che si stava
    /// guardando.
    #[test]
    fn la_schermata_delle_ricerche_non_salva() {
        let pagina = pagina_delle_ricerche();
        assert!(
            !pagina.contains("HudInput"),
            "questa schermata rifà e cancella; salvare avviene dove si cerca"
        );
        assert!(
            pagina.contains("Si salva nello Storico"),
            "la schermata deve dire dove si salva, invece di lasciare cercare"
        );
    }

    /// **Rifare porta alla pagina dello Storico, e non a un numero a caso.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un rinumero delle pagine che porta altrove **in silenzio**: chi rifà una
    /// ricerca si troverebbe in una schermata qualsiasi, e crederebbe che la
    /// ricerca non abbia funzionato.
    #[test]
    fn rifare_porta_alla_pagina_dello_storico() {
        assert!(
            UI.contains(&format!(
                "if root.current-page == {PAGINA_STORICO}: ContentScreen {{"
            )),
            "la pagina {PAGINA_STORICO} deve essere lo Storico"
        );
        let codice = codice_senza_commenti();
        assert!(
            codice.contains("window.set_current_page(PAGINA_STORICO)"),
            "rifare deve portare li', per nome e non per numero sparso"
        );
    }

    /// **Rifare dichiara che cosa si è mosso, accanto ai risultati.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Risultati senza il confronto. Un elenco da solo si legge come «ecco che
    /// cosa quella ricerca trova», e non è vero: è che cosa trova **adesso**,
    /// con metri che possono non essere quelli di allora.
    ///
    /// E la frase deve comparire **dove i risultati sono**: una dichiarazione
    /// lasciata sulla schermata Ricerche non la leggerebbe nessuno, perché chi
    /// rifà una ricerca in quel momento sta guardando lo Storico.
    #[test]
    fn rifare_dichiara_che_cosa_si_e_mosso() {
        let codice = codice_senza_commenti();
        let Some(inizio) = codice.find("fn run(") else {
            panic!("la funzione deve esistere");
        };
        let Some(fine) = codice[inizio..].find("\n}\n") else {
            panic!("la funzione deve chiudersi");
        };
        let corpo = &codice[inizio..inizio + fine];

        assert!(
            corpo.contains("set_history_search_drift"),
            "la frase del confronto deve comparire accanto ai risultati"
        );
        assert!(
            corpo.contains("set_history_search_comparable"),
            "e deve dire se le due esecuzioni siano confrontabili"
        );
        assert!(
            UI.contains("if root.search-drift != \"\": Text {"),
            "la frase deve comparire nello Storico"
        );
    }

    /// **La domanda salvata è quella che si sta guardando.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una ricerca salvata costruita da valori diversi da quelli del filtro in
    /// uso. Chi la rifà otterrebbe altro, e crederebbe di aver salvato male.
    #[test]
    fn la_domanda_salvata_e_quella_che_si_sta_guardando() {
        let codice = codice_senza_commenti();
        let Some(inizio) = codice.find("fn save(") else {
            panic!("la funzione deve esistere");
        };
        let Some(fine) = codice[inizio..].find("\n}\n") else {
            panic!("la funzione deve chiudersi");
        };
        let corpo = &codice[inizio..inizio + fine];

        for lettura in ["get_history_filter()", "get_history_only_pending()"] {
            assert!(
                corpo.contains(lettura),
                "la domanda si legge da «{lettura}», cioe' da cio' che lo Storico sta usando"
            );
        }
    }

    /// **Il campo del nome si svuota solo se la ricerca è stata salvata.**
    #[test]
    fn il_campo_si_svuota_solo_se_salvata() {
        let codice = codice_senza_commenti();
        let Some(inizio) = codice.find("match searches.borrow().searches.save(") else {
            panic!("il salvataggio deve esistere");
        };
        let Some(fine) = codice[inizio..].find("\n    }\n") else {
            panic!("il blocco deve chiudersi");
        };
        let corpo = &codice[inizio..inizio + fine];
        let Some(ramo_ok) = corpo.find("Ok(_) => {") else {
            panic!("il ramo riuscito deve esistere");
        };
        let Some(ramo_err) = corpo.find("Err(errore) => {") else {
            panic!("il ramo fallito deve esistere");
        };
        let Some(svuotamento) = corpo.find("set_history_save_search_name(SharedString::default())")
        else {
            panic!("lo svuotamento deve esistere");
        };
        assert!(
            svuotamento > ramo_ok && svuotamento < ramo_err,
            "il campo si svuota solo nel ramo riuscito: chi sbaglia altro perderebbe le parole"
        );
    }

    /// **La schermata non conosce l'archivio.**
    ///
    /// ADR-0010: l'interfaccia dipende soltanto dai servizi applicativi.
    #[test]
    fn la_schermata_non_conosce_l_archivio() {
        assert!(
            !codice_senza_commenti().contains("lisi_storage"),
            "l'interfaccia dipende soltanto dai servizi applicativi (ADR-0010)"
        );
    }

    /// **La schermata esiste, ed è raggiungibile.**
    #[test]
    fn la_schermata_si_raggiunge() {
        assert!(
            crate::surface_text::assegna(UI, "label", "Ricerche"),
            "la voce di navigazione deve esistere"
        );
        assert!(
            UI.contains("page == 23) {\n            root.searches-shown();"),
            "aprirla deve rileggere"
        );
    }

    /// **L'elenco parte vuoto.**
    #[test]
    fn l_elenco_parte_vuoto() {
        // L'EVENT LOOP DI WINIT SI CREA UNA VOLTA SOLA PER PROCESSO: senza il
        // backend di prova le prove che costruiscono una finestra si
        // contendono l'unica occasione (NOTE-01).
        i_slint_backend_testing::init_no_event_loop();
        let Ok(window) = crate::AppWindow::new() else {
            panic!("la finestra di prova deve potersi costruire");
        };
        assert_eq!(conta_ricerche(&window), 0);
    }
}

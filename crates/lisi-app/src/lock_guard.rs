//! La postazione bloccata, provata come la proverebbe chi passa davanti
//! (OPERATOR-E2E-REMEDIATION-01, F-01).
//!
//! # Perché queste prove esistono
//!
//! OPERATOR-E2E-04 ha bloccato la postazione e premuto Tab sei volte e Invio:
//! sbloccando, la schermata sotto era cambiata. Il blocco fermava il mouse con
//! un `TouchArea` e dichiarava nel commento di fermare anche la tastiera, ma il
//! suo `FocusScope` riceveva i tasti **solo quando aveva il fuoco**, e il Tab
//! portava il fuoco lungo la catena di tutta la finestra, comandi coperti
//! compresi. Nessuna prova lo guardava: le prove del blocco erano sullo stato
//! in Rust, e lo stato era giusto.
//!
//! Qui i tasti arrivano davvero alla finestra, e i comandi coperti si provano
//! anche dalla via delle tecnologie assistive — la stessa che usa un lettore di
//! schermo o un programma di automazione — perché un blocco che ferma la
//! tastiera e lascia premere i pulsanti a un altro programma non blocca nulla.

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use i_slint_backend_testing::{AccessibleRole, ElementHandle};
    use slint::platform::WindowEvent;
    use slint::{ComponentHandle, LogicalSize, SharedString};

    use crate::AppWindow;

    /// Tasti come li manda Windows, nella forma che Slint riceve.
    const TAB: &str = "\t";
    const MAIUSC_TAB: &str = "\u{19}";
    const INVIO: &str = "\n";
    const SPAZIO: &str = " ";
    const ESC: &str = "\u{1b}";
    const GIU: &str = "\u{F701}";
    const SU: &str = "\u{F700}";

    /// La schermata da cui si blocca: Impostazioni, che è piena di comandi.
    const PAGINA_SOTTO: i32 = 11;

    /// I comandi che a postazione bloccata non devono mai arrivare al codice.
    ///
    /// Non sono tutti i comandi della finestra: sono quelli che cambiano la
    /// postazione, cancellano o spostano chi lavora. Il cambio di schermata,
    /// che è il gesto più comune, si sorveglia a parte leggendo la pagina.
    type Registro = Rc<RefCell<Vec<&'static str>>>;

    fn finestra() -> (AppWindow, Registro) {
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
        window.window().set_size(LogicalSize::new(1120.0, 720.0));
        if window.show().is_err() {
            panic!("la finestra di prova deve potersi mostrare");
        }

        let registro: Registro = Rc::new(RefCell::new(Vec::new()));

        macro_rules! sorveglia {
            ($($setter:ident),* $(,)?) => {$({
                let registro = Rc::clone(&registro);
                window.$setter(move || registro.borrow_mut().push(stringify!($setter)));
            })*};
        }
        macro_rules! sorveglia_intero {
            ($($setter:ident),* $(,)?) => {$({
                let registro = Rc::clone(&registro);
                window.$setter(move |_| registro.borrow_mut().push(stringify!($setter)));
            })*};
        }

        sorveglia!(
            on_reset_accounts,
            on_reset_history,
            on_remove_account,
            on_unprotect_account,
            on_protect_account,
            on_switch_to_operator,
            on_switch_to_administrator,
            on_publish_draft,
            on_exercise_restart,
            on_team_live_activate,
            on_team_live_deactivate,
            on_close_confirmed,
            on_close_window,
            on_dictionaries_import,
            on_import_fascicolo,
            on_save_lock_minutes,
            on_background_service_install,
            on_background_service_remove,
            on_settings_shown,
            on_wizard_shown,
        );
        sorveglia_intero!(
            on_archive_dictionary,
            on_remove_source,
            on_delete_template,
            on_workspace_close,
            on_set_autostart,
        );

        (window, registro)
    }

    fn tasto(window: &AppWindow, testo: &str) {
        let text: SharedString = testo.into();
        window
            .window()
            .dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
        window
            .window()
            .dispatch_event(WindowEvent::KeyReleased { text });
    }

    /// Apre la schermata, svuota il registro e blocca.
    fn blocca_sopra(window: &AppWindow, registro: &Registro) {
        window.invoke_open_page(PAGINA_SOTTO);
        registro.borrow_mut().clear();
        window.set_station_locked(true);
    }

    /// **A postazione bloccata la tastiera non aziona nulla di ciò che sta
    /// sotto** (F-01).
    ///
    /// Prima della correzione era rossa: il Tab portava il fuoco sulla fascia e
    /// sul menu coperti, e Invio apriva un'altra schermata.
    #[test]
    fn la_tastiera_non_raggiunge_nulla_sotto_il_blocco() {
        let (window, registro) = finestra();
        blocca_sopra(&window, &registro);

        // Avanti per tutta la catena, provando ogni fermata con Invio e Spazio,
        // e con le frecce che dal 2026-10-16 scorrono il menu (F-15).
        for _ in 0..120 {
            tasto(&window, TAB);
            tasto(&window, INVIO);
            tasto(&window, SPAZIO);
            tasto(&window, GIU);
            tasto(&window, INVIO);
        }
        // E all'indietro.
        for _ in 0..120 {
            tasto(&window, MAIUSC_TAB);
            tasto(&window, INVIO);
            tasto(&window, SPAZIO);
            tasto(&window, SU);
            tasto(&window, INVIO);
        }
        tasto(&window, ESC);
        tasto(&window, INVIO);

        assert_eq!(
            window.get_current_page(),
            PAGINA_SOTTO,
            "a postazione bloccata la tastiera ha cambiato la schermata coperta"
        );
        assert!(
            registro.borrow().is_empty(),
            "a postazione bloccata la tastiera ha azionato: {:?}",
            registro.borrow()
        );
        assert!(window.get_station_locked(), "la postazione resta bloccata");
    }

    /// **A postazione bloccata nemmeno le tecnologie assistive azionano ciò
    /// che sta sotto.**
    ///
    /// È la via di un lettore di schermo, e di qualunque programma di
    /// automazione aperto sulla stessa sessione di Windows: chiede al
    /// pulsante la sua azione predefinita, per un riferimento ottenuto quando
    /// il pulsante era in vista. Si prova su **ogni** pulsante della schermata
    /// e del menu, raccolti prima del blocco.
    #[test]
    fn le_tecnologie_assistive_non_azionano_nulla_sotto_il_blocco() {
        let (window, registro) = finestra();
        window.invoke_open_page(PAGINA_SOTTO);

        // I riferimenti si prendono a schermo libero: dopo, il contenuto è
        // nascosto e la ricerca non lo vede più — ma un programma che li aveva
        // già presi li ha ancora in mano.
        let tutti: Vec<ElementHandle> = i_slint_backend_testing::ElementQuery::from_root(&window)
            .match_descendants()
            .match_accessible_role(AccessibleRole::Button)
            .find_all();
        assert!(
            tutti.len() > 30,
            "la prova deve trovare i comandi coperti, non una finestra vuota: {}",
            tutti.len()
        );

        blocca_sopra(&window, &registro);
        for pulsante in &tutti {
            pulsante.invoke_accessible_default_action();
        }

        assert_eq!(
            window.get_current_page(),
            PAGINA_SOTTO,
            "a postazione bloccata un'azione di accessibilità ha cambiato la schermata coperta"
        );
        assert!(
            registro.borrow().is_empty(),
            "a postazione bloccata un'azione di accessibilità ha azionato: {:?}",
            registro.borrow()
        );
    }

    /// **Il Tab gira fra il campo e «Sblocca», e basta.**
    ///
    /// Si vede da dove finisce ciò che si scrive: con il fuoco sul campo le
    /// lettere entrano nella parola, con il fuoco sul pulsante no, e Invio
    /// chiede lo sblocco.
    #[test]
    fn il_tab_gira_fra_il_campo_e_sblocca() {
        let (window, registro) = finestra();
        let tentativi = Rc::new(std::cell::Cell::new(0_u32));
        {
            let tentativi = Rc::clone(&tentativi);
            window.on_unlock_station(move || tentativi.set(tentativi.get() + 1));
        }
        blocca_sopra(&window, &registro);

        // All'apertura il fuoco è sul campo.
        tasto(&window, "a");
        assert_eq!(window.get_lock_attempt().as_str(), "a");

        // Un Tab porta su «Sblocca»: le lettere non entrano più nel campo.
        tasto(&window, TAB);
        tasto(&window, "b");
        assert_eq!(window.get_lock_attempt().as_str(), "a");

        // Un secondo Tab riporta al campo, e non a un comando coperto.
        tasto(&window, TAB);
        tasto(&window, "c");
        assert_eq!(window.get_lock_attempt().as_str(), "ac");

        // Maiusc+Tab fa lo stesso giro all'indietro.
        tasto(&window, MAIUSC_TAB);
        tasto(&window, INVIO);
        assert_eq!(tentativi.get(), 1, "Invio su «Sblocca» chiede lo sblocco");
        tasto(&window, MAIUSC_TAB);
        tasto(&window, "d");
        assert_eq!(window.get_lock_attempt().as_str(), "acd");

        assert_eq!(window.get_current_page(), PAGINA_SOTTO);
        assert!(registro.borrow().is_empty(), "{:?}", registro.borrow());
    }

    /// **Ogni gestore di un comando dell'interfaccia rifiuta a postazione
    /// bloccata**, salvo le eccezioni dichiarate qui.
    ///
    /// È la terza barriera di ADR-0139, resa obbligatoria: un gestore nuovo
    /// senza la guardia fa diventare rossa questa prova, invece di aspettare
    /// che una revisione se ne accorga. La revisione di sicurezza della prima
    /// stesura ne aveva contati 45 su 257: il commento diceva «tutti».
    #[test]
    fn ogni_gestore_rifiuta_a_postazione_bloccata() {
        // Le sole eccezioni, ciascuna con la sua ragione:
        // - lo sblocco e il blocco, che sono il blocco stesso;
        // - il calcolo della posizione del fumetto del tour, che non è un
        //   comando ma una funzione pura;
        // - le tre decisioni della scoperta, il cui gestore comune porta la
        //   guardia dentro (`discovery_decision`), e lo si verifica sotto;
        // - i `*_shown`, che rileggono una schermata quando la si apre e non
        //   cambiano nulla.
        const ECCEZIONI: [&str; 6] = [
            "unlock_station",
            "lock_station",
            "tour_place",
            "discovery_open_candidate",
            "discovery_add_candidate",
            "discovery_ignore_candidate",
        ];
        let cartella = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let Ok(voci) = std::fs::read_dir(cartella) else {
            panic!("la cartella dei sorgenti deve leggersi");
        };
        let mut scoperti = Vec::new();
        let mut esaminati = 0_usize;
        for voce in voci.flatten() {
            let percorso = voce.path();
            if percorso.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let Ok(testo) = std::fs::read_to_string(&percorso) else {
                continue;
            };
            let produzione = testo
                .split_once("#[cfg(test)]\nmod tests {")
                .or_else(|| testo.split_once("#[cfg(test)]\nmod guardie {"))
                .map_or(testo.as_str(), |(prima, _)| prima);
            let righe: Vec<&str> = produzione.lines().collect();
            for (indice, riga) in righe.iter().enumerate() {
                // Tre forme di registrazione: `window.on_x(`, quella di un
                // `global` (`.global::<X>().on_x(move`, anche spezzata su due
                // righe) e quella dentro una macro (`window.$nome(move`). La
                // prima stesura guardava solo la prima, e i gestori dei
                // Riferimenti informatici e del profilo documentale passavano
                // senza guardia senza che nessuno se ne accorgesse.
                let nome: String = if let Some(inizio) = riga.find("window.on_") {
                    let resto = &riga[inizio + "window.on_".len()..];
                    let nome: String = resto
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    if !resto[nome.len()..].starts_with('(') {
                        continue;
                    }
                    nome
                } else if let Some(inizio) = riga.find(".on_")
                    && riga.contains("(move")
                {
                    riga[inizio + ".on_".len()..]
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect()
                } else if riga.contains("window.$") && riga.contains("(move") {
                    String::from("macro")
                } else {
                    continue;
                };
                esaminati += 1;
                if nome.ends_with("_shown")
                    || ECCEZIONI.contains(&nome.as_str())
                    // Il segnale di attività non comanda nulla: tiene il tempo
                    // del blocco automatico.
                    || nome == "touched"
                {
                    continue;
                }
                let seguente = righe
                    .iter()
                    .skip(indice + 1)
                    .find(|r| !r.trim().is_empty())
                    .copied()
                    .unwrap_or_default();
                // La chiusura della finestra non rifiuta in silenzio: risponde
                // «resta aperta», e per questo legge lo stato invece di
                // rifiutare.
                if !seguente.contains("refuse_while_locked")
                    && !(nome == "close_requested" && seguente.contains("station_is_locked()"))
                {
                    scoperti.push(format!(
                        "{}: {nome}",
                        percorso.file_name().unwrap_or_default().to_string_lossy()
                    ));
                }
            }
        }
        assert!(
            esaminati > 200,
            "la prova deve trovare i gestori, non una cartella vuota: {esaminati}"
        );
        assert!(
            scoperti.is_empty(),
            "gestori senza la guardia del blocco: {scoperti:?}"
        );

        // Il gestore comune delle tre decisioni della scoperta porta la
        // guardia dentro.
        let scoperta = include_str!("discovery.rs");
        let Some(gestore) = scoperta.split("let gestore = move || {").nth(1) else {
            panic!("il gestore comune della scoperta deve esserci");
        };
        assert!(
            gestore
                .lines()
                .take(3)
                .any(|r| r.contains("refuse_while_locked(\"discovery_decision\")"))
        );
    }

    /// **A postazione bloccata la finestra non si chiude**: la richiesta di
    /// chiusura arriva davvero alla finestra, e la finestra resta.
    #[test]
    fn a_postazione_bloccata_la_finestra_non_si_chiude() {
        let (window, _registro) = finestra();
        crate::closing::wire(&window, None);
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let stato = crate::lock::state_for_tests(&cartella.path().join("blocco.protetto"));
        crate::lock::engage(&window, &stato);
        assert!(
            crate::lock::station_is_locked(),
            "la prova deve bloccare davvero"
        );

        window.window().dispatch_event(WindowEvent::CloseRequested);
        assert!(
            window.window().is_visible(),
            "a postazione bloccata la richiesta di chiusura è stata accolta"
        );
        assert!(
            window.get_lock_message().contains("non si chiude"),
            "e chi l'ha chiesta legge perché: «{}»",
            window.get_lock_message()
        );

        crate::lock::release_for_tests(&window, &stato);
        window.window().dispatch_event(WindowEvent::CloseRequested);
        assert!(
            !window.window().is_visible(),
            "sbloccata, senza monitoraggi la finestra si chiude come prima"
        );
    }

    /// **Caselle, tendine e campi numerici non cambiano a postazione bloccata**,
    /// nemmeno dalle tecnologie assistive.
    #[test]
    fn caselle_e_tendine_non_cambiano_sotto_il_blocco() {
        let (window, registro) = finestra();
        // Le schermate che, vuote, mostrano già in cima caselle, tendine o campi
        // numerici. Una schermata per volta: i suoi elementi esistono solo
        // finché è aperta.
        let mut trovati = 0_usize;
        for pagina in [7, 8, 11, 16, 25, 31] {
            window.invoke_open_page(pagina);
            let elementi: Vec<ElementHandle> =
                i_slint_backend_testing::ElementQuery::from_root(&window)
                    .match_descendants()
                    .match_predicate(|e| {
                        matches!(
                            e.accessible_role(),
                            Some(
                                AccessibleRole::Checkbox
                                    | AccessibleRole::Combobox
                                    | AccessibleRole::Spinbox
                            )
                        )
                    })
                    .find_all();
            trovati += elementi.len();
            let prima: Vec<(Option<bool>, Option<SharedString>)> = elementi
                .iter()
                .map(|e| (e.accessible_checked(), e.accessible_value()))
                .collect();

            registro.borrow_mut().clear();
            window.set_station_locked(true);
            for elemento in &elementi {
                elemento.invoke_accessible_default_action();
                elemento.invoke_accessible_increment_action();
                elemento.invoke_accessible_decrement_action();
            }
            let dopo: Vec<(Option<bool>, Option<SharedString>)> = elementi
                .iter()
                .map(|e| (e.accessible_checked(), e.accessible_value()))
                .collect();
            assert_eq!(
                prima, dopo,
                "a postazione bloccata un controllo della pagina {pagina} è cambiato"
            );
            assert_eq!(window.get_current_page(), pagina);
            assert!(registro.borrow().is_empty(), "{:?}", registro.borrow());
            window.set_station_locked(false);
        }
        assert!(
            trovati >= 3,
            "la prova deve trovare caselle e tendine: {trovati}"
        );
    }

    /// **Il monitoraggio non dipende dal blocco**: il ciclo che acquisisce non
    /// passa da alcuna guardia, e bloccare non ferma nulla.
    #[test]
    fn l_acquisizione_non_passa_dalla_guardia() {
        let acquisizione = include_str!("acquisition.rs");
        let produzione = acquisizione
            .split_once("#[cfg(test)]\nmod tests {")
            .map_or(acquisizione, |(prima, _)| prima);
        assert!(
            !produzione.contains("refuse_while_locked"),
            "l'acquisizione non si rifiuta a postazione bloccata: il blocco nasconde, non ferma"
        );
        // L'unica lettura del blocco nell'acquisizione è la riservatezza delle
        // notifiche.
        assert_eq!(produzione.matches("station_is_locked").count(), 1);
    }

    /// **Sbloccata, la postazione si comanda di nuovo**: la guardia non spegne
    /// il programma per sempre.
    #[test]
    fn sbloccata_la_postazione_risponde_di_nuovo() {
        let (window, registro) = finestra();
        blocca_sopra(&window, &registro);
        window.set_station_locked(false);

        // Una voce vicina a Impostazioni: il menu scorre con la voce attiva, e
        // una voce fuori dalla vista non si trova cercandola.
        let voci =
            ElementHandle::find_by_accessible_label(&window, "Diagnostica").collect::<Vec<_>>();
        assert!(!voci.is_empty(), "la voce del menu deve esistere");
        for voce in &voci {
            voce.invoke_accessible_default_action();
        }
        assert_eq!(
            window.get_current_page(),
            17,
            "sbloccata la postazione, la voce del menu deve rispondere"
        );

        // E la tastiera ritrova la strada: il Tab porta il fuoco su qualcosa
        // di visibile, e Invio lo aziona. Dal 2026-10-16 il Tab si ferma sulla
        // sola voce attiva del menu e le frecce scorrono le altre (F-15): la
        // strada è Tab fino al menu, freccia giù, Invio.
        registro.borrow_mut().clear();
        window.invoke_open_page(PAGINA_SOTTO);
        let prima = window.get_current_page();
        let mut cambiata = false;
        for _ in 0..40 {
            tasto(&window, TAB);
            tasto(&window, GIU);
            tasto(&window, INVIO);
            if window.get_current_page() != prima {
                cambiata = true;
                break;
            }
        }
        assert!(
            cambiata,
            "dopo lo sblocco la tastiera deve tornare a raggiungere i comandi"
        );
    }
}

//! I comandi condivisi, provati come li usa l'operatore: con il puntatore e
//! con la tastiera, su una finestra vera del backend di prova (UX-EXCELLENCE-02).
//!
//! # Perché queste prove esistono
//!
//! OPERATOR-SIM-03 (SIM3-01) ha trovato che nessuna tendina del prodotto
//! cambiava valore col mouse: l'elenco si apriva, il clic su una voce lo
//! chiudeva e la scelta restava quella di prima. Le prove esistenti leggevano
//! il file `.slint` e controllavano che le voci avessero una `TouchArea` che
//! chiama `choose`: erano verdi, e il difetto c'era. Una stringa nel sorgente
//! non dice dove cade un clic.
//!
//! Qui il clic cade davvero: si costruisce una finestra con il componente
//! condiviso, si recapitano alla finestra gli stessi eventi del puntatore che
//! manda Windows, e si guarda il valore che l'applicazione legge.

#[cfg(test)]
mod tests {
    use slint::platform::{PointerEventButton, WindowEvent};
    use slint::{ComponentHandle, LogicalPosition, LogicalSize};

    slint::slint! {
        import { HudSelect } from "ui/components.slint";

        export component SondaTendina inherits Window {
            width: 480px;
            height: 480px;

            in-out property <int> scelto: 0;
            in property <[string]> voci: ["Prima", "Seconda", "Terza", "Quarta"];
            out property <int> richiami: 0;
            out property <int> ultimo-richiamo: -1;
            in property <length> sel-y: 20px;

            sel := HudSelect {
                x: 20px;
                y: root.sel-y;
                width: 220px;
                label: "Sonda";
                model: root.voci;
                current-index <=> root.scelto;
                selected(indice) => {
                    root.richiami += 1;
                    root.ultimo-richiamo = indice;
                }
            }
        }
    }

    /// Altezza del campo e della riga dell'elenco, come in `components.slint`.
    const CAMPO: f32 = 34.0;
    const RIGA: f32 = 30.0;
    /// `Spacing.xs`: lo scarto fra campo ed elenco e il margine interno.
    const XS: f32 = 4.0;

    fn sonda() -> SondaTendina {
        i_slint_backend_testing::init_no_event_loop();
        let Ok(sonda) = SondaTendina::new() else {
            panic!("la finestra di prova deve potersi costruire");
        };
        sonda.window().set_size(LogicalSize::new(480.0, 480.0));
        if sonda.show().is_err() {
            panic!("la finestra di prova deve potersi mostrare");
        }
        sonda
    }

    fn clic(sonda: &SondaTendina, x: f32, y: f32) {
        let position = LogicalPosition::new(x, y);
        sonda
            .window()
            .dispatch_event(WindowEvent::PointerMoved { position });
        sonda.window().dispatch_event(WindowEvent::PointerPressed {
            position,
            button: PointerEventButton::Left,
        });
        sonda.window().dispatch_event(WindowEvent::PointerReleased {
            position,
            button: PointerEventButton::Left,
        });
        sonda.window().dispatch_event(WindowEvent::PointerExited);
    }

    fn tasto(sonda: &SondaTendina, testo: &str) {
        let text: slint::SharedString = testo.into();
        sonda
            .window()
            .dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
        sonda
            .window()
            .dispatch_event(WindowEvent::KeyReleased { text });
    }

    /// Apre l'elenco con un clic al centro del campo.
    fn apri(sonda: &SondaTendina) {
        let y = sonda.get_sel_y() + CAMPO / 2.0;
        clic(sonda, 130.0, y);
    }

    /// Il centro della voce `indice` dell'elenco aperto sotto il campo.
    fn centro_voce(sonda: &SondaTendina, indice: usize) -> (f32, f32) {
        let cima_elenco = sonda.get_sel_y() + CAMPO + XS;
        #[allow(clippy::cast_precision_loss)]
        let y = cima_elenco + XS + RIGA * (indice as f32) + RIGA / 2.0;
        (130.0, y)
    }

    fn scegli_col_mouse(sonda: &SondaTendina, indice: usize) {
        apri(sonda);
        let (x, y) = centro_voce(sonda, indice);
        clic(sonda, x, y);
    }

    /// **Il clic su una voce diversa dalla corrente la sceglie** (SIM3-01).
    ///
    /// È la prova che mancava. Prima della correzione era rossa: l'elenco
    /// aperto aveva l'altezza del solo margine, le voci si disegnavano fuori
    /// dal suo riquadro e il clic su di esse era un «clic fuori», che chiude
    /// l'elenco senza scegliere.
    #[test]
    fn il_clic_su_una_voce_la_sceglie() {
        let sonda = sonda();
        assert_eq!(sonda.get_scelto(), 0);

        scegli_col_mouse(&sonda, 2);

        assert_eq!(
            sonda.get_scelto(),
            2,
            "il clic sulla terza voce deve sceglierla: l'elenco si chiudeva senza scegliere"
        );
        assert_eq!(sonda.get_richiami(), 1, "la scelta deve arrivare al codice");
        assert_eq!(sonda.get_ultimo_richiamo(), 2);
    }

    /// **La prima, l'ultima, e di nuovo la stessa.**
    #[test]
    fn prima_ultima_e_ripetuta() {
        let sonda = sonda();

        scegli_col_mouse(&sonda, 3);
        assert_eq!(sonda.get_scelto(), 3, "l'ultima voce");

        scegli_col_mouse(&sonda, 0);
        assert_eq!(sonda.get_scelto(), 0, "la prima voce");

        scegli_col_mouse(&sonda, 1);
        assert_eq!(sonda.get_scelto(), 1, "una voce centrale");

        // Scegliere di nuovo la voce corrente non è un errore e non cambia
        // nulla: il valore resta, l'elenco si chiude.
        scegli_col_mouse(&sonda, 1);
        assert_eq!(sonda.get_scelto(), 1, "la stessa voce, di nuovo");
        assert_eq!(sonda.get_richiami(), 4);
    }

    /// **Un clic fuori chiude senza scegliere, e il campo si riapre.**
    #[test]
    fn il_clic_fuori_chiude_senza_scegliere() {
        let sonda = sonda();
        apri(&sonda);
        // Lontano dal campo e dall'elenco.
        clic(&sonda, 420.0, 460.0);
        assert_eq!(sonda.get_scelto(), 0);
        assert_eq!(sonda.get_richiami(), 0, "nessuna scelta fantasma");

        // Il clic successivo sul campo riapre l'elenco, e la scelta funziona.
        scegli_col_mouse(&sonda, 2);
        assert_eq!(sonda.get_scelto(), 2);
    }

    /// **La tastiera continua a funzionare**: frecce sul campo chiuso, Invio
    /// per aprire, frecce ed Esc nell'elenco aperto.
    #[test]
    fn la_tastiera_continua_a_funzionare() {
        let sonda = sonda();
        // Il primo clic dà il fuoco al campo e apre l'elenco; Esc lo chiude.
        apri(&sonda);
        tasto(&sonda, "\u{1b}");
        assert_eq!(sonda.get_scelto(), 0, "Esc non sceglie");

        tasto(&sonda, "\u{F701}"); // freccia giù
        assert_eq!(sonda.get_scelto(), 1);
        tasto(&sonda, "\u{F701}");
        tasto(&sonda, "\u{F701}");
        tasto(&sonda, "\u{F701}");
        assert_eq!(sonda.get_scelto(), 3, "la freccia si ferma all'ultima voce");
        tasto(&sonda, "\u{F700}"); // freccia su
        assert_eq!(sonda.get_scelto(), 2);

        // Invio apre l'elenco; le frecce lo percorrono; Invio lo chiude.
        tasto(&sonda, "\n");
        tasto(&sonda, "\u{F700}");
        tasto(&sonda, "\n");
        assert_eq!(sonda.get_scelto(), 1);

        // Dopo la tastiera, il mouse: la scelta col clic funziona ancora.
        scegli_col_mouse(&sonda, 3);
        assert_eq!(sonda.get_scelto(), 3);
    }

    /// **Un elenco lungo si scorre, e la voce in fondo si sceglie.**
    ///
    /// Il tetto è di sette voci e mezzo: la decima voce si raggiunge con la
    /// rotellina dentro l'elenco aperto.
    #[test]
    fn un_elenco_lungo_si_scorre_e_si_sceglie() {
        let sonda = sonda();
        let voci: Vec<slint::SharedString> = (1..=12).map(|n| format!("Voce {n}").into()).collect();
        sonda.set_voci(std::rc::Rc::new(slint::VecModel::from(voci)).into());

        apri(&sonda);
        let (x, y) = centro_voce(&sonda, 3);
        sonda.window().dispatch_event(WindowEvent::PointerMoved {
            position: LogicalPosition::new(x, y),
        });
        sonda.window().dispatch_event(WindowEvent::PointerScrolled {
            position: LogicalPosition::new(x, y),
            delta_x: 0.0,
            delta_y: -400.0,
        });
        // Dopo lo scorrimento in fondo, l'ultima voce visibile è la dodicesima,
        // in fondo al riquadro alto 232 pixel.
        let cima_elenco = sonda.get_sel_y() + CAMPO + XS;
        let fondo = cima_elenco + 232.0 - XS - RIGA / 2.0;
        clic(&sonda, x, fondo);
        assert_eq!(
            sonda.get_scelto(),
            11,
            "la voce in fondo a un elenco lungo deve potersi scegliere col mouse"
        );
    }

    // ------------------------------------------------------------------
    // Gli altri comandi condivisi (UX-EXCELLENCE-02, §11): pulsante, casella,
    // campo numerico, contatore. Posizioni fisse, cosi' il clic cade dove
    // cadrebbe quello di una persona; il nome per l'accessibilita' si legge
    // dalla proprieta' del componente, perche' la ricerca per nome del backend
    // di prova non vede i componenti compilati con la macro.
    // ------------------------------------------------------------------

    slint::slint! {
        import { HudButton, HudCheck, HudNumber, Counter } from "ui/components.slint";

        export component SondaComandi inherits Window {
            width: 520px;
            height: 320px;

            out property <int> premuti: 0;
            out property <int> premuti-spento: 0;
            in-out property <bool> spunta: false;
            out property <int> cambi-spunta: 0;
            in-out property <int> numero: 2;
            out property <int> contati: 0;
            out property <int> contati-fermo: 0;
            in property <bool> scelto: false;
            out property <string> nome-acceso: acceso.accessible-label;
            out property <string> nome-spento: spento.accessible-label;

            acceso := HudButton {
                x: 20px;
                y: 20px;
                width: 120px;
                label: "Acceso";
                selected: root.scelto;
                clicked => { root.premuti += 1; }
            }
            spento := HudButton {
                x: 160px;
                y: 20px;
                width: 120px;
                label: "Spento";
                enabled: false;
                reason: "Non si può adesso.";
                clicked => { root.premuti-spento += 1; }
            }
            HudCheck {
                x: 20px;
                y: 70px;
                width: 300px;
                height: 34px;
                text: "Casella di prova";
                checked <=> root.spunta;
                toggled => { root.cambi-spunta += 1; }
            }
            HudNumber {
                x: 20px;
                y: 120px;
                width: 200px;
                label: "Quantità";
                minimum: 1;
                maximum: 3;
                value <=> root.numero;
            }
            Counter {
                x: 20px;
                y: 170px;
                width: 200px;
                caption: "da guardare";
                value: 4;
                actionable: true;
                clicked => { root.contati += 1; }
            }
            Counter {
                x: 240px;
                y: 170px;
                width: 200px;
                caption: "soltanto cifra";
                value: 7;
                clicked => { root.contati-fermo += 1; }
            }
        }
    }

    fn sonda_comandi() -> SondaComandi {
        i_slint_backend_testing::init_no_event_loop();
        let Ok(sonda) = SondaComandi::new() else {
            panic!("la finestra di prova deve potersi costruire");
        };
        sonda.window().set_size(LogicalSize::new(520.0, 320.0));
        if sonda.show().is_err() {
            panic!("la finestra di prova deve potersi mostrare");
        }
        sonda
    }

    fn premi(sonda: &SondaComandi, x: f32, y: f32) {
        let position = LogicalPosition::new(x, y);
        sonda
            .window()
            .dispatch_event(WindowEvent::PointerMoved { position });
        sonda.window().dispatch_event(WindowEvent::PointerPressed {
            position,
            button: PointerEventButton::Left,
        });
        sonda.window().dispatch_event(WindowEvent::PointerReleased {
            position,
            button: PointerEventButton::Left,
        });
        sonda.window().dispatch_event(WindowEvent::PointerExited);
    }

    // I centri degli elementi, dalle posizioni fisse qui sopra. Il campo
    // numerico ha i due comandi a destra: «+» occupa circa gli ultimi 33 pixel
    // prima del margine di 4, «−» i 33 prima di quello.
    const ACCESO: (f32, f32) = (80.0, 37.0);
    const SPENTO: (f32, f32) = (220.0, 37.0);
    const CASELLA: (f32, f32) = (60.0, 87.0);
    const PIU: (f32, f32) = (200.0, 137.0);
    const MENO: (f32, f32) = (163.0, 137.0);
    const CONTATORE: (f32, f32) = (120.0, 196.0);
    const CIFRA: (f32, f32) = (340.0, 196.0);

    /// **Un pulsante acceso risponde al clic, uno spento no**, e lo spento dice
    /// perché nel nome.
    #[test]
    fn il_pulsante_acceso_risponde_quello_spento_no() {
        let sonda = sonda_comandi();
        premi(&sonda, ACCESO.0, ACCESO.1);
        premi(&sonda, ACCESO.0, ACCESO.1);
        assert_eq!(sonda.get_premuti(), 2);
        premi(&sonda, SPENTO.0, SPENTO.1);
        assert_eq!(
            sonda.get_premuti_spento(),
            0,
            "un comando spento non agisce"
        );
        assert_eq!(sonda.get_nome_spento(), "Spento. Non si può adesso.");
    }

    /// **Il pulsante scelto lo dice anche a parole** (SIM3-15): non solo con il
    /// colore del bordo.
    #[test]
    fn il_pulsante_scelto_lo_dice_a_parole() {
        let sonda = sonda_comandi();
        assert_eq!(sonda.get_nome_acceso(), "Acceso");
        sonda.set_scelto(true);
        assert_eq!(
            sonda.get_nome_acceso(),
            "Acceso, scelto",
            "la scelta corrente si annuncia come «scelto»"
        );
        premi(&sonda, ACCESO.0, ACCESO.1);
        assert_eq!(
            sonda.get_premuti(),
            1,
            "scelto o no, il pulsante resta un comando"
        );
    }

    /// **La casella cambia stato al clic, e lo stato arriva al codice.**
    #[test]
    fn la_casella_cambia_e_lo_dice() {
        let sonda = sonda_comandi();
        premi(&sonda, CASELLA.0, CASELLA.1);
        assert!(sonda.get_spunta());
        assert_eq!(sonda.get_cambi_spunta(), 1);
        premi(&sonda, CASELLA.0, CASELLA.1);
        assert!(!sonda.get_spunta());
        assert_eq!(sonda.get_cambi_spunta(), 2);
    }

    /// **Il campo numerico sale e scende col mouse, e si ferma agli estremi.**
    #[test]
    fn il_campo_numerico_si_ferma_agli_estremi() {
        let sonda = sonda_comandi();
        premi(&sonda, PIU.0, PIU.1);
        assert_eq!(sonda.get_numero(), 3);
        // Al massimo il «+» è spento: un altro clic non oltrepassa il tetto.
        premi(&sonda, PIU.0, PIU.1);
        assert_eq!(sonda.get_numero(), 3);
        premi(&sonda, MENO.0, MENO.1);
        premi(&sonda, MENO.0, MENO.1);
        assert_eq!(sonda.get_numero(), 1);
        premi(&sonda, MENO.0, MENO.1);
        assert_eq!(sonda.get_numero(), 1, "sotto il minimo non si scende");
    }

    /// **Un contatore che porta da qualche parte risponde; una cifra no**
    /// (SIM3-09): un numero che sembra una porta e non lo è insegna a non
    /// cliccare più nulla.
    #[test]
    fn solo_il_contatore_comando_risponde() {
        let sonda = sonda_comandi();
        premi(&sonda, CONTATORE.0, CONTATORE.1);
        assert_eq!(sonda.get_contati(), 1);
        premi(&sonda, CIFRA.0, CIFRA.1);
        assert_eq!(sonda.get_contati_fermo(), 0);
    }

    /// **Vicino al bordo inferiore della finestra l'elenco resta raggiungibile.**
    ///
    /// Slint sposta un elenco che uscirebbe dalla finestra; la prova accerta
    /// che la voce scelta col mouse sia quella che l'operatore vede sotto il
    /// puntatore, cercandola nella posizione in cui è stata spostata.
    #[test]
    fn vicino_al_bordo_inferiore_si_sceglie() {
        let sonda = sonda();
        // Il campo a 40 pixel dal fondo: l'elenco (4 voci, 128 pixel) non ci sta
        // sotto.
        sonda.set_sel_y(406.0);
        apri(&sonda);
        // L'elenco è stato riportato dentro la finestra: il suo fondo coincide
        // con quello della finestra.
        let altezza = 4.0 * RIGA + 2.0 * XS;
        let cima = 480.0 - altezza;
        let y = cima + XS + RIGA * 2.0 + RIGA / 2.0;
        clic(&sonda, 130.0, y);
        assert_eq!(
            sonda.get_scelto(),
            2,
            "vicino al bordo l'elenco si sposta, e il clic sceglie la voce sotto il puntatore"
        );
    }

    /// **Nessun `Flickable` inoltra alla finestra la larghezza del contenuto** (F-05).
    ///
    /// Slint dà a un `Flickable` senza `width` né `max-width` la larghezza
    /// massima del suo contenuto. Un elemento a larghezza fissa la rende finita,
    /// il vincolo sale fino alla finestra e la finestra si restringe da sola:
    /// OPERATOR-E2E-04 l'ha vista passare da 1136×759 a 1016×798 aprendo
    /// «Provenienza, note e contesto».
    #[test]
    fn nessun_flickable_inoltra_la_larghezza() {
        let mut scoperti = Vec::new();
        for (nome, sorgente) in [
            ("app-window.slint", include_str!("../ui/app-window.slint")),
            ("components.slint", include_str!("../ui/components.slint")),
        ] {
            let righe: Vec<&str> = sorgente.lines().collect();
            for (indice, riga) in righe.iter().enumerate() {
                let pulita = riga.trim();
                if !(pulita == "Flickable {" || pulita.ends_with(":= Flickable {")) {
                    continue;
                }
                let dichiara = righe
                    .iter()
                    .skip(indice + 1)
                    .take(12)
                    .take_while(|r| !r.trim().ends_with('{'))
                    .any(|r| {
                        let r = r.trim();
                        r.starts_with("width:") || r.starts_with("max-width:")
                    });
                if !dichiara {
                    scoperti.push(format!("{nome}:{}", indice + 1));
                }
            }
        }
        assert!(
            scoperti.is_empty(),
            "Flickable senza larghezza dichiarata: {scoperti:?}"
        );
    }

    /// **Un layout ripetuto con testo a capo sta dentro un riquadro con l'altezza
    /// del suo contenuto** (F-03).
    ///
    /// In Slint 1.17 un layout creato da `for` o da `if` misura il testo a capo su
    /// una riga sola: la riga riceve meno altezza di quella che serve, e il
    /// pulsante sotto copre il testo seguente. Provato in un banco a parte:
    /// righe ripetute nude, sovrapposte; avvolte in un `Rectangle` con
    /// `min-height` dal layout, giuste. Un blocco che scorre, che si allarga o che
    /// ha un tetto resta com'è: la sua altezza la decide chi lo contiene.
    #[test]
    fn nessun_layout_ripetuto_resta_nudo() {
        let sorgente = include_str!("../ui/app-window.slint");
        let righe: Vec<&str> = sorgente.lines().collect();
        let mut nudi = Vec::new();
        for (indice, riga) in righe.iter().enumerate() {
            let pulita = riga.trim_end();
            if pulita.trim_start().starts_with("//") {
                continue;
            }
            let ripetuto =
                pulita.ends_with(": VerticalLayout {") || pulita.ends_with(": HorizontalLayout {");
            if !ripetuto || pulita.contains(":= ") {
                continue;
            }
            let mut profondita = 0_i32;
            let mut corpo = String::new();
            for r in righe.iter().skip(indice) {
                corpo.push_str(r);
                corpo.push('\n');
                let senza_commento = r.split("//").next().unwrap_or_default();
                profondita += i32::try_from(senza_commento.matches('{').count()).unwrap_or(0);
                profondita -= i32::try_from(senza_commento.matches('}').count()).unwrap_or(0);
                if profondita <= 0 {
                    break;
                }
            }
            let escluso = [
                "HudScroll",
                "Flickable",
                "vertical-stretch: 1",
                "max-height:",
            ]
            .iter()
            .any(|segno| corpo.contains(segno));
            if !escluso {
                nudi.push(indice + 1);
            }
        }
        assert!(
            nudi.is_empty(),
            "layout ripetuti senza il riquadro che ne tiene l'altezza, righe {nudi:?}"
        );
    }

    // ------------------------------------------------------------------
    // E2E01-10: i clic simulati, qualificati al livello di Slint.
    //
    // Il collaudo del 16 ottobre ha visto molti pulsanti ignorare i clic di
    // Computer Use e di `SendInput`, mentre il mouse vero e la tastiera
    // funzionavano. Queste sonde recapitano alla finestra le sequenze che uno
    // strumento automatico puo' produrre — con e senza il movimento prima,
    // dentro l'area a scorrimento delle schermate — e dicono se il componente
    // risponde. Se rispondono, la causa non sta nel componente ma fra Windows
    // e la finestra, e va cercata li' (HVQ-114).
    // ------------------------------------------------------------------

    mod scorrimento {
        use slint::platform::{PointerEventButton, WindowEvent};
        use slint::{ComponentHandle, LogicalPosition, LogicalSize};

        slint::slint! {
            import { HudButton, HudScroll } from "ui/components.slint";

            export component SondaScorrimento inherits Window {
                width: 400px;
                height: 300px;
                out property <int> premuti: 0;

                HudScroll {
                    VerticalLayout {
                        padding: 20px;
                        spacing: 10px;
                        Rectangle { height: 40px; }
                        HorizontalLayout {
                            HudButton {
                                label: "Nella pagina";
                                clicked => { root.premuti += 1; }
                            }
                            Rectangle { horizontal-stretch: 1; }
                        }
                        Rectangle { height: 600px; }
                    }
                }
            }
        }

        fn sonda_scorrimento() -> SondaScorrimento {
            i_slint_backend_testing::init_no_event_loop();
            let Ok(sonda) = SondaScorrimento::new() else {
                panic!("la finestra di prova deve potersi costruire");
            };
            sonda.window().set_size(LogicalSize::new(400.0, 300.0));
            if sonda.show().is_err() {
                panic!("la finestra di prova deve potersi mostrare");
            }
            sonda
        }

        /// Il centro del pulsante: margine 20, riga vuota 40, spaziatura 10, metà
        /// dei 34 di altezza; in orizzontale dentro i 96 di larghezza minima.
        const NELLA_PAGINA: (f32, f32) = (60.0, 87.0);

        /// **Dentro l'area a scorrimento il clic arriva, anche senza movimento
        /// prima e anche ripetuto subito** (E2E01-10).
        #[test]
        fn il_clic_simulato_arriva_dentro_l_area_a_scorrimento() {
            let sonda = sonda_scorrimento();
            let position = LogicalPosition::new(NELLA_PAGINA.0, NELLA_PAGINA.1);

            // Come una persona: movimento, pressione, rilascio.
            sonda
                .window()
                .dispatch_event(WindowEvent::PointerMoved { position });
            sonda.window().dispatch_event(WindowEvent::PointerPressed {
                position,
                button: PointerEventButton::Left,
            });
            sonda.window().dispatch_event(WindowEvent::PointerReleased {
                position,
                button: PointerEventButton::Left,
            });
            assert_eq!(
                sonda.get_premuti(),
                1,
                "il clic con movimento deve arrivare"
            );

            // Come un clic sintetico che non ripete il movimento: pressione e
            // rilascio soltanto, nello stesso punto.
            sonda.window().dispatch_event(WindowEvent::PointerPressed {
                position,
                button: PointerEventButton::Left,
            });
            sonda.window().dispatch_event(WindowEvent::PointerReleased {
                position,
                button: PointerEventButton::Left,
            });
            assert_eq!(
                sonda.get_premuti(),
                2,
                "il clic senza movimento deve arrivare"
            );

            // Dopo che il puntatore e' uscito dalla finestra, un clic che arriva
            // con un solo movimento nel punto.
            sonda.window().dispatch_event(WindowEvent::PointerExited);
            sonda
                .window()
                .dispatch_event(WindowEvent::PointerMoved { position });
            sonda.window().dispatch_event(WindowEvent::PointerPressed {
                position,
                button: PointerEventButton::Left,
            });
            sonda.window().dispatch_event(WindowEvent::PointerReleased {
                position,
                button: PointerEventButton::Left,
            });
            assert_eq!(
                sonda.get_premuti(),
                3,
                "il clic dopo l'uscita deve arrivare"
            );
        }
    }
}

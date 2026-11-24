//! Collegamento fra la schermata del grafo e l'Evidence Graph (GRAPH-02).
//!
//! # Che cosa questa schermata non fa, e non deve fare
//!
//! Rispondere a «A e B sono collegati?».
//!
//! Non c'è un comando che lo chieda, non c'è una funzione che lo calcoli, e la
//! figura non disegna alcuna linea fra due vicini: nessun arco li unisce nei
//! fatti, e disegnarne una sarebbe l'affermazione che GRAPH-01 si è rifiutata di
//! calcolare (DEC-288).
//!
//! La guardia del dominio e quella del servizio non coprono l'interfaccia. Qui
//! ce n'è una terza, e sta nelle prove di questo modulo: è il punto da cui la
//! tentazione entrerebbe, perché un pulsante «mostra come sono collegati questi
//! due» è la cosa più naturale da mettere in una schermata di grafo.
//!
//! # Perché si scrive l'identificativo invece di sceglierlo da un elenco
//!
//! Perché un elenco di elementi da cui partire sarebbe un elenco prodotto senza
//! che nessuno se lo sia chiesto, e quando quegli elementi sono persone diventa
//! l'elenco che ADR-0024 vuole motivato. È la scelta di PERS-06, e vale qui per
//! la stessa ragione.
//!
//! # Perché il ricentramento va per posizione e non per nome
//!
//! Perché un nome che torna dall'interfaccia andrebbe interpretato per capire
//! che cosa sia, e quell'interpretazione è il posto da cui si potrebbe
//! **fabbricare** un nodo che l'archivio non ha — per esempio un fascicolo.
//!
//! La posizione, invece, indica una riga del vicinato che questo programma ha
//! appena composto: non c'è niente da interpretare, e non c'è niente da
//! inventare.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_core::ContentId;
use lisi_core::model::evidence_graph::{GraphNode, Neighbourhood};
use lisi_core::model::graph_layout::{GraphLayout, layout_of};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::history::SharedHistory;
use crate::{AppWindow, GraphNodeEntry};

/// I nodi che la figura mostra adesso, nell'ordine in cui li mostra.
///
/// Serve al ricentramento: la posizione che l'interfaccia restituisce indica una
/// di queste righe. Vedere la nota di modulo.
type CurrentNeighbours = Rc<RefCell<Vec<GraphNode>>>;

/// Collega i comandi della schermata ai servizi.
pub fn wire(window: &AppWindow, screens: &SharedHistory) {
    let vicini: CurrentNeighbours = Rc::new(RefCell::new(Vec::new()));

    {
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        window.on_graph_shown(move || {
            if let Some(window) = handle.upgrade() {
                refresh_sessions(&window, &screens);
                forget_stale_message(&window);
            }
        });
    }

    {
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        let vicini = Rc::clone(&vicini);
        window.on_graph_session_chosen(move |index| {
            if crate::lock::refuse_while_locked("graph_session_chosen") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            window.set_graph_session_index(index);
            // CAMBIARE MONITORAGGIO SVUOTA LA FIGURA.
            //
            // Gli archi si ricavano dentro un monitoraggio: lasciare quella di
            // prima accanto al nome nuovo mostrerebbe una figura di un'attivita'
            // e il nome di un'altra.
            clear(&window, &vicini);
            refresh_sessions(&window, &screens);
        });
    }

    {
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        let vicini = Rc::clone(&vicini);
        window.on_graph_start_requested(move || {
            if crate::lock::refuse_while_locked("graph_start_requested") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let scritto = window.get_graph_start_content();
            open_from_written(&window, &screens, &vicini, scritto.as_str());
        });
    }

    {
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        let vicini = Rc::clone(&vicini);
        window.on_graph_open_content(move |content_id| {
            if crate::lock::refuse_while_locked("graph_open_content") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                open_content(&window, &screens, &vicini, content_id);
            }
        });
    }

    {
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        let vicini = Rc::clone(&vicini);
        window.on_graph_recentre(move |posizione| {
            if crate::lock::refuse_while_locked("graph_recentre") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let scelto = {
                let elenco = vicini.borrow();
                usize::try_from(posizione)
                    .ok()
                    .and_then(|posizione| elenco.get(posizione).cloned())
            };
            // UNA POSIZIONE FUORI DALL'ELENCO NON SI INDOVINA: significherebbe
            // ricentrare su un nodo diverso da quello toccato, e chi guarda non
            // avrebbe modo di accorgersene.
            if let Some(nodo) = scelto {
                show(&window, &screens, &vicini, &nodo);
            }
        });
    }
}

/// Svuota la figura e ogni riga che la riguarda.
///
/// # Perché si svuota tutto
///
/// Perché un'avvertenza o una ragione rimaste dietro una figura chiusa
/// tornerebbero a comparire accanto a un nodo diverso, e una frase che parla di
/// un altro nodo è peggio di nessuna frase.
fn clear(window: &AppWindow, vicini: &CurrentNeighbours) {
    vicini.borrow_mut().clear();
    window.set_graph_has_node(false);
    window.set_graph_centre_label(SharedString::new());
    window.set_graph_centre_kind(SharedString::new());
    window.set_graph_centre_content(0);
    window.set_graph_caveat(SharedString::new());
    window.set_graph_message(SharedString::new());
    window.set_graph_neighbours(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
}

/// Toglie l'avviso rimasto da una visita precedente, se nessuna figura è aperta
/// (INSTALLED-APP-E2E-01, E2E01-20; CAPABILITY-AUDIT-02, CA02-10).
///
/// Un rifiuto per la ragione mancante restava sotto il campo anche dopo che la
/// ragione era stata scritta altrove: tornando, la pagina diceva ancora il
/// rifiuto, e il nuovo «Apri» riscriveva la stessa frase senza che nulla
/// cambiasse a vista. Con una figura aperta l'avviso la riguarda, e resta.
fn forget_stale_message(window: &AppWindow) {
    if !window.get_graph_has_node() {
        window.set_graph_message(SharedString::new());
    }
}

/// Riporta nell'interfaccia l'elenco dei monitoraggi.
pub fn refresh_sessions(window: &AppWindow, screens: &SharedHistory) {
    let borrowed = screens.borrow();

    // La prima voce ripete quella dello Storico, e qui **non** e' una scelta
    // valida: gli archi si ricavano dentro un monitoraggio, e mescolarne due
    // metterebbe insieme atti diversi (DEC-221).
    let mut labels = vec![crate::lingua::schermo("Nessun monitoraggio scelto")];
    match borrowed.sessions() {
        Ok(sessions) => labels.extend(
            sessions
                .iter()
                .map(|summary| crate::lingua::schermo(summary.label())),
        ),
        Err(error) => {
            tracing::warn!(kind = error.kind(), "elenco delle sessioni non leggibile");
        }
    }

    let chosen = window.get_graph_session_index();
    let chosen = if usize::try_from(chosen).is_ok_and(|value| value < labels.len()) {
        chosen
    } else {
        0
    };
    window.set_graph_session_index(chosen);
    window.set_graph_sessions(ModelRc::from(Rc::new(VecModel::from(labels))));
}

/// Apre la figura a partire dall'identificativo scritto.
fn open_from_written(
    window: &AppWindow,
    screens: &SharedHistory,
    vicini: &CurrentNeighbours,
    scritto: &str,
) {
    clear(window, vicini);

    let scritto = scritto.trim();
    if scritto.is_empty() {
        window.set_graph_message(crate::lingua::schermo(
            "Scrivere l'identificativo del contenuto da cui partire.",
        ));
        return;
    }

    // UN IDENTIFICATIVO CHE NON E' UN NUMERO NON SI INDOVINA. Si accetta anche
    // la forma con cui lo Storico lo mostra, «n. 128».
    let senza_prefisso = scritto
        .strip_prefix("n.")
        .or_else(|| scritto.strip_prefix("N."))
        .map_or(scritto, str::trim);
    let Ok(numero) = senza_prefisso.parse::<i64>() else {
        window.set_graph_message(crate::lingua::schermo(
            "Il contenuto si indica con il suo numero: nello Storico e negli Avvisi è scritto \
             accanto a ogni messaggio, come «n. 128». Dal messaggio aperto, «Apri nel Grafo» lo \
             porta qui da sé.",
        ));
        return;
    };
    if numero <= 0 {
        window.set_graph_message(crate::lingua::schermo(
            "Gli identificativi dell'archivio partono da uno.",
        ));
        return;
    }

    show(
        window,
        screens,
        vicini,
        &GraphNode::Content(ContentId::new(numero)),
    );
}

/// Mostra la figura attorno al nodo indicato.
///
/// # Tre casi, e non due (OPERATOR-E2E-REMEDIATION-01, F-02)
///
/// Un contenuto che **non esiste**, uno che esiste **senza collegamenti** e uno
/// che esiste **con** collegamenti sono tre cose diverse. Prima il primo si
/// disegnava come il secondo: un riquadro «Contenuto n. 999» al centro di una
/// figura vuota, per un contenuto che l'archivio non ha. Ora il primo non
/// disegna nulla e lo dice; il secondo disegna il solo centro e lo dice.
///
/// Un contenuto di un altro monitoraggio si apre nel suo: i collegamenti si
/// ricavano dentro un'attività, e il programma sa già in quale sta.
fn show(window: &AppWindow, screens: &SharedHistory, vicini: &CurrentNeighbours, nodo: &GraphNode) {
    let borrowed = screens.borrow();

    if let GraphNode::Content(contenuto) = nodo {
        match borrowed.content_session(*contenuto) {
            Ok(None) => {
                clear(window, vicini);
                window.set_graph_message(crate::lingua::schermo(format!(
                    "Nell'archivio non c'è un contenuto n. {}. Il numero si legge nello Storico, \
                     accanto a ogni messaggio.",
                    contenuto.get()
                )));
                return;
            }
            Ok(Some(sessione)) => {
                let scelta = borrowed.session_at(window.get_graph_session_index());
                if scelta != Some(sessione)
                    && let Some(indice) = borrowed.session_index_of(sessione)
                {
                    window.set_graph_session_index(indice);
                }
            }
            Err(error) => {
                tracing::warn!(kind = error.kind(), "contenuto del grafo non leggibile");
                clear(window, vicini);
                window.set_graph_message(crate::lingua::schermo(error.operator_message()));
                return;
            }
        }
    }

    let indice = window.get_graph_session_index();
    let Some(session_id) = borrowed.session_at(indice) else {
        clear(window, vicini);
        window.set_graph_message(crate::lingua::schermo(
            "Scegliere il monitoraggio in cui guardare: i collegamenti si ricavano \
             dentro un'attività, e mescolarne due metterebbe insieme atti diversi.",
        ));
        return;
    };

    match borrowed.evidence_neighbourhood(session_id, nodo) {
        Ok(vicinato) => {
            present(window, vicini, &vicinato);
            if vicini.borrow().is_empty() {
                window.set_graph_message(crate::lingua::schermo(
                    "Questo elemento esiste, e in questo monitoraggio non ha collegamenti: la \
                     figura mostra soltanto lui.",
                ));
            }
        }
        Err(error) => {
            tracing::warn!(kind = error.kind(), "vicinato del grafo non leggibile");
            clear(window, vicini);
            window.set_graph_message(crate::lingua::schermo(error.operator_message()));
        }
    }
}

/// Apre il Grafo sul contenuto scelto nello Storico o negli Avvisi (F-21).
fn open_content(
    window: &AppWindow,
    screens: &SharedHistory,
    vicini: &CurrentNeighbours,
    content_id: i32,
) {
    if content_id <= 0 {
        return;
    }
    window.set_graph_start_content(SharedString::from(content_id.to_string()));
    window.invoke_open_page(GRAPH_PAGE);
    clear(window, vicini);
    show(
        window,
        screens,
        vicini,
        &GraphNode::Content(ContentId::new(i64::from(content_id))),
    );
}

/// La pagina del Grafo delle prove.
const GRAPH_PAGE: i32 = 25;

/// Porta il vicinato nell'interfaccia, con la sua figura e le sue ragioni.
fn present(window: &AppWindow, vicini: &CurrentNeighbours, vicinato: &Neighbourhood) {
    let figura = layout_of(vicinato);

    *vicini.borrow_mut() = figura
        .neighbours
        .iter()
        .map(|posto| posto.node.clone())
        .collect();

    window.set_graph_message(SharedString::new());
    window.set_graph_has_node(true);
    window.set_graph_centre_kind(crate::lingua::schermo(vicinato.node().kind_label()));
    window.set_graph_centre_label(SharedString::from(etichetta(vicinato.node())));
    // IL CONTENUTO AL CENTRO, per aprirne la conversazione (ADR-0151): 0 quando
    // il centro e' una fonte, un soggetto o un indicatore.
    window.set_graph_centre_content(match vicinato.node() {
        GraphNode::Content(contenuto) => i32::try_from(contenuto.get()).unwrap_or_default(),
        _ => 0,
    });
    window.set_graph_caveat(SharedString::from(vicinato.caveat()));
    window.set_graph_neighbours(neighbour_model(vicinato, &figura));
}

/// I vicini, come la figura li mostra.
///
/// # Perché la ragione non si ricompone qui
///
/// Perché la compone il dominio, e due composizioni della stessa frase divergono
/// alla prima modifica: quella nella figura direbbe una cosa, quella nel
/// documento di GRAPH-03 un'altra, e nessuno saprebbe quale delle due leggere.
fn neighbour_model(vicinato: &Neighbourhood, figura: &GraphLayout) -> ModelRc<GraphNodeEntry> {
    let entries: Vec<GraphNodeEntry> = figura
        .neighbours
        .iter()
        .zip(vicinato.edges())
        .map(|(posto, arco)| GraphNodeEntry {
            label: SharedString::from(etichetta(&posto.node)),
            kind: crate::lingua::schermo(posto.node.kind_label()),
            why: SharedString::from(arco.why()),
            is_human_act: arco.provenance().is_a_human_act(),
            x: posto.x,
            y: posto.y,
        })
        .collect();

    ModelRc::from(Rc::new(VecModel::from(entries)))
}

/// Il nome breve di un nodo, per il riquadro che lo disegna.
///
/// # Perché non la frase intera
///
/// Perché nel riquadro non ci sta, e un testo tagliato a metà dice meno di un
/// nome breve. La frase intera — quella che dichiara che un'identità osservata
/// **non è un fascicolo** — sta nella colonna delle ragioni, dove c'è spazio per
/// leggerla.
fn etichetta(nodo: &GraphNode) -> String {
    match nodo {
        GraphNode::Content(id) => format!("#{}", id.get()),
        GraphNode::Source(id) => format!("#{}", id.get()),
        GraphNode::ObservedIdentity(identifier) => identifier.clone(),
        GraphNode::Subject(id) => format!("#{}", id.get()),
        GraphNode::CyberEvent { value, .. } | GraphNode::Indicator { value, .. } => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    /// Interfaccia principale, letta a tempo di compilazione.
    /// Questo modulo, per le guardie che guardano la forma del codice.
    const THIS_MODULE: &str = include_str!("graph.rs");

    /// Il blocco della schermata del grafo, dal suo marcatore **alla schermata
    /// successiva**.
    ///
    /// # Perché non fino alla fine del file
    ///
    /// Perché le pagine che seguono usano legittimamente parole che qui sono
    /// vietate — «percorso» di una cartella, per esempio — e una guardia che
    /// leggesse anche loro diventerebbe rossa per un motivo che non la riguarda.
    /// Una guardia che si accende dove non deve è una guardia che qualcuno
    /// allenta.
    fn schermata() -> String {
        // L'ESTRATTORE E' UNO SOLO, E DIMOSTRA DI AVER LETTO QUALCOSA.
        //
        // Prima di HARDEN-02 ogni modulo ritagliava il corpo della propria
        // pagina per conto proprio, e un ritaglio che coglieva troppo poco
        // non faceva fallire niente: ogni divieto restava vero perche' non
        // c'era niente da vietare (ADR-0111).
        crate::page_guard::corpo_della_pagina(25)
    }

    /// **La schermata non chiede se due nodi sono collegati.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che il prodotto affermi, in una figura, che due elementi collegati
    /// attraverso un terzo abbiano a che fare l'uno con l'altro. E' la
    /// decisione centrale di GRAPH-01 (DEC-288), e le sue guardie stanno sul
    /// dominio e sul servizio: **l'interfaccia non era coperta**, ed e' il punto
    /// da cui la tentazione entrerebbe, perche' un comando del genere e' la cosa
    /// piu' naturale da mettere in una schermata di grafo.
    ///
    /// # Il controllo negativo
    ///
    /// Aggiungendo alla schermata un comando che colleghi due nodi scelti,
    /// questa prova diventa rossa.
    #[test]
    fn la_schermata_non_chiede_se_due_nodi_sono_collegati() {
        let testo = schermata().to_lowercase();

        for vietata in [
            "come sono collegati",
            "cerca collegamento",
            "trova il collegamento",
            "collega questi",
            "percorso",
            "cammino",
            "distanza fra",
            "quanto distano",
        ] {
            assert!(
                !testo.contains(vietata),
                "la schermata del grafo contiene «{vietata}»: due nodi collegati \
                 attraverso un terzo non hanno per questo a che fare l'uno con l'altro"
            );
        }

        // L'UNICA FORMA AMMESSA DI «sono collegati» E' LA DOMANDA DELLA
        // MILESTONE.
        //
        // «Perche' sono collegati?» chiede la ragione di un collegamento **che
        // esiste**, e la risposta e' un fatto con la sua provenienza. Qualunque
        // altra forma — «questi due sono collegati?» — chiede al programma di
        // **trovarne** uno, e quella risposta il prodotto non ce l'ha.
        //
        // La guardia non vieta la parola: pretende che ogni volta che compare
        // sia preceduta da «perche'».
        let quante = testo.matches("sono collegati").count();
        let legittime = testo.matches("perch\u{e9} sono collegati?").count();
        assert_eq!(
            quante, legittime,
            "«sono collegati» compare {quante} volte e soltanto {legittime} come domanda \
             sulla ragione: ogni altra forma chiede al programma di trovare un collegamento"
        );
    }

    /// **Non si disegnano linee fra due vicini.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che la figura affermi da sola cio' che nessun comando chiede. Una linea
    /// fra due vicini non corrisponde ad alcun arco, e disegnarla sarebbe
    /// esattamente l'affermazione che il dominio si rifiuta di calcolare.
    ///
    /// # Come lo verifica
    ///
    /// Ogni percorso disegnato parte dal centro della figura — 0.5, 0.5 — e
    /// arriva a un vicino. Non ce n'e' alcuno che parta da un vicino.
    #[test]
    fn nessuna_linea_unisce_due_vicini() {
        let testo = schermata();

        let Some(inizio) = testo.find("for vicino in root.graph-neighbours: Path {") else {
            panic!("la figura deve disegnare le linee dal centro ai vicini");
        };
        let Some(fine) = testo[inizio..].find("// I VICINI.") else {
            panic!("il blocco delle linee deve chiudersi prima dei riquadri");
        };
        let linee = &testo[inizio..inizio + fine];

        assert!(
            linee.contains("MoveTo { x: 0.5; y: 0.5; }"),
            "ogni linea parte dal centro: {linee}"
        );
        assert!(
            !linee.contains("MoveTo { x: vicino"),
            "nessuna linea parte da un vicino: {linee}"
        );
        assert_eq!(
            linee.matches("MoveTo").count(),
            1,
            "un percorso solo per ogni vicino, e parte dal centro"
        );
    }

    /// **L'avvertenza sta accanto alla figura, non sotto.**
    ///
    /// Sotto arriva dopo che l'impressione si e' formata, ed e' la stessa
    /// lezione della schermata Cyber Watch.
    #[test]
    fn l_avvertenza_sta_accanto_alla_figura() {
        let testo = schermata();

        let Some(dichiarazione) = testo.find("Non è una rete di relazioni") else {
            panic!("la schermata deve dichiarare che cosa non e'");
        };
        let Some(figura) = testo.find("for vicino in root.graph-neighbours: Path") else {
            panic!("la schermata deve disegnare la figura");
        };

        assert!(
            dichiarazione < figura,
            "la dichiarazione arriva DOPO la figura: chi guarda si e' gia' fatto \
             un'idea di cio' che sta vedendo"
        );
        assert!(
            testo.contains("root.graph-caveat"),
            "l'avvertenza del vicinato deve comparire nella schermata"
        );
    }

    /// **Ogni nodo dice che genere di cosa è.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che un pallino con un nome sopra si legga per quello che non e'. Un
    /// fascicolo accanto a un'identita' osservata sembra la stessa cosa se
    /// nessuno scrive quale delle due sia — ed e' la distinzione su cui poggia
    /// l'intera Fase 6.
    #[test]
    fn ogni_nodo_dice_che_genere_di_cosa_e() {
        let testo = schermata();
        assert!(
            testo.contains("text: vicino.kind;"),
            "ogni vicino deve mostrare il proprio genere"
        );
        assert!(
            testo.contains("text: root.graph-centre-kind;"),
            "anche il centro deve mostrare il proprio genere"
        );
    }

    /// **La ragione non si ricompone nella schermata.**
    ///
    /// La compone il dominio: due composizioni della stessa frase divergono alla
    /// prima modifica, e quella nella figura direbbe una cosa e quella nel
    /// documento di GRAPH-03 un'altra.
    #[test]
    fn la_ragione_arriva_dal_dominio_e_non_si_ricompone() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };

        assert!(
            produzione.contains("why: SharedString::from(arco.why())"),
            "la ragione deve arrivare da GraphEdge::why, non essere ricomposta"
        );
        for pezzo in ["rule().as_sentence()", "provenance().as_sentence()"] {
            assert!(
                !produzione.contains(pezzo),
                "la schermata non ricompone la frase dai suoi pezzi: trovato «{pezzo}»"
            );
        }
    }

    /// **L'atto di una persona non si rende come un'osservazione.**
    #[test]
    fn un_atto_di_una_persona_si_distingue_nella_figura() {
        let testo = schermata();
        assert!(
            testo.contains("vicino.is-human-act"),
            "la figura deve distinguere l'atto di una persona"
        );
        assert!(
            testo.contains("vicino.is-human-act ? Origine.operatore : Origine.osservato"),
            "la figura deve segnare l'origine di ogni collegamento con le parole di ADR-0118"
        );
    }

    /// **Non c'è un elenco da cui scegliere il nodo di partenza.**
    ///
    /// Un elenco di elementi da cui partire sarebbe un elenco prodotto senza che
    /// nessuno se lo sia chiesto, e quando quegli elementi sono persone diventa
    /// l'elenco che ADR-0024 vuole motivato. E' la scelta di PERS-06.
    #[test]
    fn il_nodo_di_partenza_si_scrive_e_non_si_sceglie() {
        let testo = schermata();
        assert!(
            testo.contains("Contenuto da cui partire"),
            "il nodo di partenza si scrive"
        );
        assert!(
            !testo.contains("graph-candidates") && !testo.contains("graph-suggestions"),
            "non c'e' un elenco di candidati da cui scegliere"
        );
    }

    /// **La posizione non si calcola nella schermata.**
    ///
    /// Arriva da `graph_layout`, dove si prova che due letture danno la stessa
    /// figura. Una figura calcolata nel disegno sarebbe diversa da quella che
    /// GRAPH-03 stampera' nel documento.
    #[test]
    fn la_posizione_arriva_gia_calcolata() {
        let testo = schermata();
        assert!(
            testo.contains("parent.width * vicino.x"),
            "la schermata usa la posizione ricevuta"
        );
        for calcolo in ["Math.cos", "Math.sin", "Math.atan"] {
            assert!(
                !testo.contains(calcolo),
                "la schermata non calcola posizioni: trovato «{calcolo}»"
            );
        }
    }
}

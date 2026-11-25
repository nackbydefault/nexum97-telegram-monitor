//! «Scopri NEXUM», il tour guidato, dalla parte dell'interfaccia (TOUR-01,
//! ADR-0134).
//!
//! # Che cosa sta qui
//!
//! - la traduzione dei luoghi del servizio nelle schermate ([`page_of`]);
//! - **dove mettere il fumetto** ([`place_callout`]), una funzione pura che il
//!   disegno chiama con le misure vere;
//! - il collegamento dei comandi del tour al servizio, che conserva lo stato;
//! - la decisione, schermata per schermata, se stia nel tour
//!   (`TOUR_COVERAGE`, fra le prove);
//! - le guardie: il tour chiama soltanto `open-page` e i propri comandi, la
//!   voce si raggiunge da tastiera, il fumetto dice a che punto si è.
//!
//! # Che cosa non sta qui
//!
//! Chi vede quali passi, e i loro testi: li decide `lisi_services::tour`. Il
//! ruolo lo legge il servizio dei dizionari, il modo del processo
//! `lisi_services::run_mode`: qui si passano, non si ricavano.

use std::rc::Rc;

use lisi_services::Database;
use lisi_services::tour::{
    PanelOffer, TourContext, TourPlace, TourService, TourStep, TourZone, steps,
};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::{AppWindow, TourPoint, TourRect, TourStepRow};

/// La schermata di un luogo; -1 per «resta dove sei».
#[must_use]
pub const fn page_of(place: TourPlace) -> i32 {
    match place {
        TourPlace::Here => -1,
        TourPlace::Dashboard => 0,
        TourPlace::Account => 2,
        TourPlace::Sources => 3,
        TourPlace::Dictionaries => 4,
        TourPlace::Station => 5,
        TourPlace::NewMonitoring => 6,
        TourPlace::History => 8,
        TourPlace::Monitoring => 9,
        TourPlace::Guide => 10,
        TourPlace::Settings => 11,
        TourPlace::People => 14,
        TourPlace::Report => 15,
        TourPlace::CyberWatch => 16,
        TourPlace::Diagnostics => 17,
        TourPlace::WorkQueue => 18,
        TourPlace::Workspace => 20,
        TourPlace::SharedLive => 27,
        TourPlace::Lookup => 30,
        TourPlace::References => 31,
    }
}

/// La zona, come la legge il disegno: 0 la voce del menu, 1 la schermata, 2 la
/// voce Scopri NEXUM, 3 la testata.
#[must_use]
pub const fn zone_code(zone: TourZone) -> i32 {
    match zone {
        TourZone::MenuItem => 0,
        TourZone::Content => 1,
        TourZone::DiscoverEntry => 2,
        TourZone::Status => 3,
    }
}

/// Un riquadro, in pixel logici.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Area {
    /// Bordo sinistro.
    pub x: f32,
    /// Bordo superiore.
    pub y: f32,
    /// Larghezza.
    pub width: f32,
    /// Altezza.
    pub height: f32,
}

/// La distanza fra la zona illuminata e il fumetto.
const GAP: f32 = 16.0;
/// Il margine che il fumetto lascia dai bordi della finestra.
const MARGIN: f32 = 12.0;

/// **Dove mettere il fumetto** (ADR-0134 §8).
///
/// Prova, nell'ordine: a destra della zona, a sinistra, sotto, sopra. Se
/// nessun lato basta — la schermata intera è la zona — lo mette dentro, in
/// basso a destra. Infine lo stringe dentro la finestra, sotto la barra del
/// titolo: **non esce mai**, se la finestra è abbastanza grande da
/// contenerlo; se non lo è, si appoggia all'angolo in alto a sinistra.
#[must_use]
pub fn place_callout(
    target: Area,
    callout: (f32, f32),
    viewport: (f32, f32),
    top: f32,
) -> (f32, f32) {
    let (larghezza, altezza) = callout;
    let (finestra_l, finestra_a) = viewport;
    let min_x = MARGIN;
    let min_y = top + MARGIN;
    let max_x = finestra_l - MARGIN - larghezza;
    let max_y = finestra_a - MARGIN - altezza;

    let destra = target.x + target.width + GAP;
    let sinistra = target.x - GAP - larghezza;
    let sotto = target.y + target.height + GAP;
    let sopra = target.y - GAP - altezza;

    let (x, y) = if destra <= max_x {
        (destra, target.y)
    } else if sinistra >= min_x {
        (sinistra, target.y)
    } else if sotto <= max_y {
        (target.x, sotto)
    } else if sopra >= min_y {
        (target.x, sopra)
    } else {
        (
            target.x + target.width - GAP - larghezza,
            target.y + target.height - GAP - altezza,
        )
    };

    (x.min(max_x).max(min_x), y.min(max_y).max(min_y))
}

/// Che cosa chiede l'argomento `--tour=`: serve alla verifica a vista e alla
/// coda umana, come `--pagina=` (ADR-0130). Non cambia lo stato del tour oltre
/// ciò che i comandi del tour cambierebbero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartRequest {
    /// Aprire il pannello.
    Panel,
    /// Avviare il tour al passo indicato, da zero.
    Step(usize),
}

/// L'argomento che apre il tour all'avvio.
const TOUR_ARGUMENT: &str = "--tour=";

/// La richiesta di `--tour=pannello` o `--tour=N` (N da 1), se c'è.
#[must_use]
pub fn start_request<I, S>(argomenti: I) -> Option<StartRequest>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    argomenti.into_iter().find_map(|argomento| {
        let valore = argomento.as_ref().strip_prefix(TOUR_ARGUMENT)?;
        if valore == "pannello" {
            return Some(StartRequest::Panel);
        }
        valore
            .parse::<usize>()
            .ok()
            .filter(|numero| (1..=64).contains(numero))
            .map(|numero| StartRequest::Step(numero - 1))
    })
}

/// Chi fornisce i fatti della postazione, al momento in cui servono: la
/// modalità può cambiare mentre il programma è aperto.
pub type ContextSource = Rc<dyn Fn() -> TourContext>;

/// Il tour, condiviso fra i comandi.
pub struct TourScreen {
    service: TourService,
    context: ContextSource,
}

/// Il tour, condiviso.
pub type SharedTour = Rc<TourScreen>;

/// Crea il tour attorno al suo archivio.
#[must_use]
pub fn create(database: Option<Database>, context: ContextSource) -> Option<SharedTour> {
    database.map(|database| {
        Rc::new(TourScreen {
            service: TourService::new(database),
            context,
        })
    })
}

fn now() -> lisi_core::Timestamp {
    crate::account::now()
}

/// Un passo, come lo legge il disegno.
fn row(step: &TourStep, context: &TourContext) -> TourStepRow {
    TourStepRow {
        key: SharedString::from(step.key),
        page: page_of(step.place),
        zone: zone_code(step.zone),
        title: SharedString::from(step.title),
        body: SharedString::from(step.body),
        note: SharedString::from(if context.exercise {
            step.exercise_note
        } else {
            ""
        }),
    }
}

/// Riporta nell'interfaccia «Nuovo», l'offerta del pannello e quanti passi.
pub fn refresh(window: &AppWindow, tour: &TourScreen) {
    let stato = match tour.service.status() {
        Ok(stato) => stato,
        Err(errore) => {
            tracing::warn!(errore = %errore, "stato del tour non leggibile");
            window.set_tour_fresh(false);
            window.set_tour_offer(0);
            return;
        }
    };
    window.set_tour_fresh(TourService::shows_new(&stato));
    window.set_tour_offer(match TourService::panel_offer(&stato) {
        PanelOffer::Start => 0,
        PanelOffer::Continue => 1,
        PanelOffer::Redo => 2,
    });
    let quanti = steps(&(tour.context)()).len();
    window.set_tour_step_count(i32::try_from(quanti).unwrap_or(i32::MAX));
}

/// All'avvio: se il tour non è mai stato proposto, prepara la proposta. Compare
/// soltanto sulla Dashboard operativa (ADR-0134 §2).
pub fn propose_if_due(window: &AppWindow, tour: &TourScreen) {
    let contesto = (tour.context)();
    match tour.service.status() {
        Ok(stato) => {
            window.set_tour_proposal_pending(TourService::should_propose(&stato, &contesto));
        }
        Err(errore) => {
            // Nel dubbio non si propone: il tour resta raggiungibile dalla voce.
            tracing::warn!(errore = %errore, "stato del tour non leggibile: nessuna proposta");
            window.set_tour_proposal_pending(false);
        }
    }
}

/// Prepara i passi per chi guarda, e avvia: dal passo conservato se `resume`,
/// altrimenti da `from`.
fn start(window: &AppWindow, tour: &TourScreen, resume: bool, from: usize) {
    let contesto = (tour.context)();
    let percorso = steps(&contesto);
    let righe: Vec<TourStepRow> = percorso.iter().map(|step| row(step, &contesto)).collect();
    window.set_tour_steps(ModelRc::from(Rc::new(VecModel::from(righe))));
    let indice = if resume {
        tour.service
            .status()
            .map(|stato| TourService::resume_index(&stato, &percorso))
            .unwrap_or(0)
    } else {
        from
    };
    window.invoke_tour_start(i32::try_from(indice).unwrap_or(0));
}

/// Collega i comandi del tour.
pub fn wire(window: &AppWindow, tour: &SharedTour) {
    window.on_tour_place(
        |target: TourRect, larghezza, altezza, finestra_l, finestra_a, alto| {
            let (x, y) = place_callout(
                Area {
                    x: target.x,
                    y: target.y,
                    width: target.width,
                    height: target.height,
                },
                (larghezza, altezza),
                (finestra_l, finestra_a),
                alto,
            );
            TourPoint { x, y }
        },
    );

    {
        let handle = window.as_weak();
        let tour = Rc::clone(tour);
        window.on_tour_proposal_shown(move || {
            if let Err(errore) = tour.service.mark_proposed(now()) {
                tracing::warn!(errore = %errore, "proposta del tour non registrata");
            }
            if let Some(window) = handle.upgrade() {
                refresh(&window, &tour);
            }
        });
    }
    {
        let handle = window.as_weak();
        let tour = Rc::clone(tour);
        window.on_tour_proposal_skipped(move || {
            if crate::lock::refuse_while_locked("tour_proposal_skipped") {
                return;
            }
            if let Err(errore) = tour.service.skip(now()) {
                tracing::warn!(errore = %errore, "salto del tour non registrato");
            }
            if let Some(window) = handle.upgrade() {
                window.set_tour_proposal_pending(false);
                refresh(&window, &tour);
            }
        });
    }
    {
        let handle = window.as_weak();
        let tour = Rc::clone(tour);
        window.on_tour_proposal_dismissed(move || {
            if crate::lock::refuse_while_locked("tour_proposal_dismissed") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                window.set_tour_proposal_pending(false);
                refresh(&window, &tour);
            }
        });
    }
    {
        let handle = window.as_weak();
        let tour = Rc::clone(tour);
        window.on_tour_panel_opened(move || {
            if crate::lock::refuse_while_locked("tour_panel_opened") {
                return;
            }
            if let Err(errore) = tour.service.skip(now()) {
                tracing::warn!(errore = %errore, "apertura del pannello del tour non registrata");
            }
            if let Some(window) = handle.upgrade() {
                refresh(&window, &tour);
            }
        });
    }
    {
        let handle = window.as_weak();
        let tour = Rc::clone(tour);
        window.on_tour_requested(move |resume| {
            if crate::lock::refuse_while_locked("tour_requested") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                start(&window, &tour, resume, 0);
            }
        });
    }
    {
        let handle = window.as_weak();
        let tour = Rc::clone(tour);
        window.on_tour_step_reached(move |chiave| {
            if crate::lock::refuse_while_locked("tour_step_reached") {
                return;
            }
            if let Err(errore) = tour.service.reach(chiave.as_str(), now()) {
                tracing::warn!(errore = %errore, "passo del tour non conservato");
            }
            if let Some(window) = handle.upgrade() {
                refresh(&window, &tour);
            }
        });
    }
    {
        let handle = window.as_weak();
        let tour = Rc::clone(tour);
        window.on_tour_finished(move || {
            if crate::lock::refuse_while_locked("tour_finished") {
                return;
            }
            if let Err(errore) = tour.service.complete(now()) {
                tracing::warn!(errore = %errore, "fine del tour non conservata");
            }
            if let Some(window) = handle.upgrade() {
                refresh(&window, &tour);
            }
        });
    }
}

/// Esegue la richiesta di `--tour=`.
pub fn apply_start_request(window: &AppWindow, tour: &TourScreen, request: StartRequest) {
    match request {
        StartRequest::Panel => window.invoke_tour_open_panel(),
        StartRequest::Step(passo) => {
            let quanti = steps(&(tour.context)()).len();
            start(window, tour, false, passo.min(quanti.saturating_sub(1)));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::BTreeSet;
    use std::rc::Rc;

    use lisi_services::Database;
    use lisi_services::tour::{
        ADMINISTRATOR_STEPS, COMMON_STEPS, LAST_STEP, TourContext, TourZone, steps,
    };
    use slint::ComponentHandle;
    use slint::platform::{Key, WindowEvent};

    use super::{
        Area, StartRequest, create, page_of, place_callout, propose_if_due, refresh, start_request,
        wire,
    };
    use crate::navigation::SCREENS;
    use crate::page_guard::UI;
    use crate::{AppWindow, DocumentProfile};

    /// Se una schermata sta nel tour (ADR-0134 §17). La guardia
    /// `ogni_schermata_ha_una_decisione_sul_tour` pretende una riga per ogni
    /// schermata: una schermata nuova senza la sua riga la fa diventare rossa.
    ///
    /// Sta fra le prove perché serve soltanto alla guardia: è una decisione
    /// scritta, non un dato che il programma legge.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TourCoverage {
        /// Nel percorso comune, con la chiave del passo.
        Common(&'static str),
        /// Nell'estensione dell'amministratore, con la chiave del passo.
        Administrator(&'static str),
        /// Fuori dal tour, con la ragione.
        Outside(&'static str),
    }

    /// Una riga per schermata, nell'ordine dei numeri.
    const TOUR_COVERAGE: [(i32, TourCoverage); 32] = [
        (0, TourCoverage::Common("dashboard")),
        (
            1,
            TourCoverage::Outside("informazioni e licenze: non è un'attività"),
        ),
        (2, TourCoverage::Common("account")),
        (3, TourCoverage::Common("fonti")),
        (
            4,
            TourCoverage::Outside("i dizionari si usano scegliendoli nel nuovo monitoraggio"),
        ),
        (5, TourCoverage::Administrator("postazione")),
        (6, TourCoverage::Common("nuovo_monitoraggio")),
        (
            7,
            TourCoverage::Outside("gli alert sono nominati nel passo dello storico"),
        ),
        (8, TourCoverage::Common("storico")),
        (9, TourCoverage::Common("monitoraggio")),
        (10, TourCoverage::Common("esercitazione")),
        (11, TourCoverage::Administrator("impostazioni")),
        (
            12,
            TourCoverage::Outside("la verifica è nominata nel passo del report"),
        ),
        (
            13,
            TourCoverage::Outside("le notifiche sono nominate nel passo del monitoraggio"),
        ),
        (14, TourCoverage::Common("persone")),
        (15, TourCoverage::Common("report")),
        (16, TourCoverage::Common("cyber_watch")),
        (17, TourCoverage::Administrator("diagnostica")),
        (18, TourCoverage::Common("coda_di_lavoro")),
        (
            19,
            TourCoverage::Outside("rule lab: lavoro sui dizionari, non del primo giorno"),
        ),
        (20, TourCoverage::Common("workspace")),
        (
            21,
            TourCoverage::Outside("segnalibri: parte del lavoro su un caso, come il workspace"),
        ),
        (
            22,
            TourCoverage::Outside("note: parte del lavoro su un caso, come il workspace"),
        ),
        (
            23,
            TourCoverage::Outside("ricerche salvate: parte del lavoro su un caso"),
        ),
        (
            24,
            TourCoverage::Outside("modelli: una scorciatoia del nuovo monitoraggio"),
        ),
        (
            25,
            TourCoverage::Outside("grafo: un'altra forma di ciò che mostrano persone e workspace"),
        ),
        (
            26,
            TourCoverage::Outside("scoperta pubblica: oggi non cerca su Telegram"),
        ),
        (27, TourCoverage::Administrator("live_condiviso")),
        (
            28,
            TourCoverage::Outside("revisione condivisa: solo con un Hub, si impara in squadra"),
        ),
        (
            29,
            TourCoverage::Outside("raccoglitori dell'ufficio: solo con un Hub"),
        ),
        (30, TourCoverage::Common("ricerca_puntuale")),
        (
            31,
            TourCoverage::Outside(
                "riferimenti informatici: strumento di approfondimento, spiegato nella guida",
            ),
        ),
    ];

    // ------------------------------------------------------------ collocazione

    /// 15 — **Il fumetto non esce mai dalla finestra**: bersagli ai quattro
    /// bordi, al centro, grandi quanto la finestra, su finestre di più misure.
    #[test]
    fn il_fumetto_resta_dentro_la_finestra() {
        let fumetto = (380.0_f32, 220.0_f32);
        let alto = 38.0_f32;
        for finestra in [
            (900.0_f32, 600.0_f32),
            (1120.0, 720.0),
            (1920.0, 1080.0),
            (1280.0, 640.0),
        ] {
            let (l, a) = finestra;
            let bersagli = [
                Area {
                    x: 0.0,
                    y: alto,
                    width: 252.0,
                    height: 34.0,
                },
                Area {
                    x: 0.0,
                    y: a - 60.0,
                    width: 252.0,
                    height: 52.0,
                },
                Area {
                    x: l - 40.0,
                    y: alto,
                    width: 40.0,
                    height: 40.0,
                },
                Area {
                    x: l - 40.0,
                    y: a - 40.0,
                    width: 40.0,
                    height: 40.0,
                },
                Area {
                    x: l / 2.0,
                    y: a / 2.0,
                    width: 10.0,
                    height: 10.0,
                },
                Area {
                    x: 252.0,
                    y: 200.0,
                    width: l - 252.0,
                    height: a - 200.0,
                },
                Area {
                    x: 0.0,
                    y: 0.0,
                    width: l,
                    height: a,
                },
                Area {
                    x: -50.0,
                    y: -50.0,
                    width: 20.0,
                    height: 20.0,
                },
                Area {
                    x: l + 10.0,
                    y: a + 10.0,
                    width: 20.0,
                    height: 20.0,
                },
            ];
            for bersaglio in bersagli {
                let (x, y) = place_callout(bersaglio, fumetto, finestra, alto);
                assert!(
                    x >= 0.0 && x + fumetto.0 <= l,
                    "{finestra:?} {bersaglio:?}: x = {x}"
                );
                assert!(
                    y >= alto && y + fumetto.1 <= a,
                    "{finestra:?} {bersaglio:?}: y = {y}"
                );
            }
        }
    }

    /// La strategia: a destra di una voce del menu; dentro la schermata quando
    /// la zona è la schermata; sopra o accanto quando il bordo lo impone.
    #[test]
    fn il_fumetto_sceglie_il_lato_e_ripiega() {
        let finestra = (1120.0, 720.0);
        let voce = Area {
            x: 24.0,
            y: 300.0,
            width: 204.0,
            height: 34.0,
        };
        assert_eq!(
            place_callout(voce, (380.0, 200.0), finestra, 38.0),
            (244.0, 300.0)
        );

        // Una voce in fondo: a destra, ma rialzato per restare dentro.
        let in_fondo = Area {
            x: 24.0,
            y: 680.0,
            width: 204.0,
            height: 34.0,
        };
        let (_, y) = place_callout(in_fondo, (380.0, 200.0), finestra, 38.0);
        assert!((y - (720.0 - 12.0 - 200.0)).abs() < f32::EPSILON);

        // La schermata intera: dentro, in basso a destra.
        let schermata = Area {
            x: 252.0,
            y: 150.0,
            width: 868.0,
            height: 570.0,
        };
        let (x, y) = place_callout(schermata, (380.0, 200.0), finestra, 38.0);
        assert!(x > 252.0 && y > 150.0, "dentro la schermata: {x}, {y}");

        // Vicino al bordo destro: a sinistra.
        let a_destra = Area {
            x: 1000.0,
            y: 300.0,
            width: 100.0,
            height: 30.0,
        };
        assert_eq!(
            place_callout(a_destra, (380.0, 200.0), finestra, 38.0).0,
            1000.0 - 16.0 - 380.0
        );
    }

    // ------------------------------------------------------------- argomenti

    #[test]
    fn l_argomento_del_tour_apre_soltanto_il_tour() {
        assert_eq!(
            start_request(["nexum", "--tour=pannello"]),
            Some(StartRequest::Panel)
        );
        assert_eq!(start_request(["--tour=3"]), Some(StartRequest::Step(2)));
        for ignorato in [
            "--tour=0",
            "--tour=-1",
            "--tour=65",
            "--tour=avvia",
            "--tour",
        ] {
            assert_eq!(start_request([ignorato]), None, "«{ignorato}»");
        }
        assert_eq!(start_request(["--pagina=3"]), None);
    }

    // --------------------------------------------------------------- guardie

    /// Il tratto dell'interfaccia fra due marcatori, o una prova che si ferma.
    fn tratto(inizio: &str, fine: &str) -> &'static str {
        let Some((_, dopo)) = UI.split_once(inizio) else {
            panic!("il marcatore «{inizio}» deve esistere");
        };
        let Some((corpo, _)) = dopo.split_once(fine) else {
            panic!("il marcatore «{fine}» deve esistere");
        };
        assert!(
            corpo.len() > 2_000,
            "il tratto «{inizio}» è troppo corto: la guardia non guarda"
        );
        corpo
    }

    fn tratti_del_tour() -> [&'static str; 2] {
        [
            tratto("TOUR-01 — comandi, inizio", "TOUR-01 — comandi, fine"),
            tratto("TOUR-01 — strati, inizio", "TOUR-01 — strati, fine"),
        ]
    }

    /// 13 — **Il tour chiama soltanto `open-page` e i propri comandi**
    /// (ADR-0134 §1; controllo negativo B). Ogni chiamata a un comando della
    /// finestra nei due tratti del tour è `open-page` oppure comincia con
    /// `tour-`; nessun comando di un globale.
    #[test]
    fn il_tour_chiama_soltanto_open_page_e_i_propri_comandi() {
        let mut viste = 0;
        for corpo in tratti_del_tour() {
            for (posizione, _) in corpo.match_indices("root.") {
                let nome: String = corpo[posizione + 5..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                    .collect();
                let dopo = &corpo[posizione + 5 + nome.len()..];
                if !dopo.starts_with('(') {
                    continue;
                }
                viste += 1;
                assert!(
                    nome == "open-page" || nome.starts_with("tour-"),
                    "il tour chiama «root.{nome}(»: il tour mostra, e non tocca"
                );
            }
            for globale in ["DocumentProfile.", "Activity.", "Appearance."] {
                for (posizione, _) in corpo.match_indices(globale) {
                    let nome: String = corpo[posizione + globale.len()..]
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                        .collect();
                    assert!(
                        !corpo[posizione + globale.len() + nome.len()..].starts_with('('),
                        "il tour chiama «{globale}{nome}(»"
                    );
                }
            }
        }
        assert!(
            viste >= 20,
            "solo {viste} chiamate viste: la guardia non guarda"
        );
    }

    /// 4, 16 — **Scopri NEXUM si raggiunge da tastiera, ed è sempre lì**
    /// (controllo negativo C): il componente ha il fuoco, Invio e Spazio, il
    /// ruolo di pulsante e l'anello; la voce sta nella colonna del menu, fuori
    /// dallo scorrimento e fuori da ogni condizione.
    #[test]
    fn scopri_nexum_si_raggiunge_da_tastiera_ed_e_sempre_li() {
        let Some((_, dopo)) = UI.split_once("component DiscoverEntry inherits Rectangle {") else {
            panic!("il componente della voce deve esistere");
        };
        let Some((componente, _)) = dopo.split_once("\n}\n") else {
            panic!("il componente della voce deve chiudersi");
        };
        for atteso in [
            "focus := FocusScope {",
            "event.text == Key.Return || event.text == \" \"",
            "accessible-role: button;",
            "accessible-action-default",
            "border-width: focus.has-focus ? 2px : 0px;",
            "public function take-focus()",
        ] {
            assert!(
                componente.contains(atteso),
                "la voce Scopri NEXUM non ha «{atteso}»"
            );
        }
        // Il fuoco non ha condizioni: un `enabled` lo potrebbe spegnere.
        let Some((_, fuoco)) = componente.split_once("focus := FocusScope {") else {
            panic!("il fuoco della voce deve esistere");
        };
        let fuoco = fuoco
            .split_once("key-pressed")
            .map_or(fuoco, |(prima, _)| prima);
        assert!(
            !fuoco.contains("enabled:"),
            "il fuoco della voce Scopri NEXUM ha una condizione: deve restare sempre raggiungibile"
        );

        let Some((prima, dopo_voce)) = UI.split_once("scopri := DiscoverEntry {") else {
            panic!("la voce deve stare nella colonna del menu");
        };
        assert!(
            dopo_voce
                .find("text: @tr(\"Versione {}\"")
                .is_some_and(|posizione| posizione < 600),
            "la voce sta subito sopra la versione, fuori dallo scorrimento"
        );
        let riga = prima.rsplit('\n').next().unwrap_or_default();
        assert!(
            !riga.contains("if "),
            "la voce non dipende da una condizione"
        );
        assert!(
            prima
                .rfind("menu-voci := HudScroll {")
                .is_some_and(|scorrimento| {
                    prima[scorrimento..].matches('{').count()
                        == prima[scorrimento..].matches('}').count()
                }),
            "la voce sta fuori dallo scorrimento del menu"
        );
        assert!(
            !UI.contains("NavigationItem {\n                        label: \"Scopri"),
            "Scopri NEXUM non è una schermata"
        );
    }

    /// **Il fumetto dice a che punto si è** (controllo negativo E): «3 di 16»,
    /// scritto, dal numero vero dei passi.
    #[test]
    fn il_fumetto_dice_a_che_punto_si_e() {
        let [_, strati] = tratti_del_tour();
        let Some((_, dopo)) = strati.split_once("tour-progress := Text {") else {
            panic!("l'indicazione dell'avanzamento deve esistere");
        };
        // L'elemento si chiude con una graffa su una riga sola: dentro il
        // testo, `{}` è il segnaposto della traduzione (I18N-01).
        let Some((testo, _)) = dopo.split_once("\n                    }") else {
            panic!("l'indicazione dell'avanzamento deve chiudersi");
        };
        assert!(
            testo.contains(
                "text: @tr(\"{} di {}\", (root.tour-index + 1), root.tour-steps.length);"
            ),
            "l'avanzamento non dice più «N di M»: {testo}"
        );
    }

    /// 18 — **Il movimento del tour obbedisce alla preferenza**: ogni
    /// animazione dei due tratti si azzera quando il movimento è ridotto.
    #[test]
    fn il_movimento_del_tour_obbedisce_alla_preferenza() {
        let mut animazioni = 0;
        for corpo in tratti_del_tour() {
            for (posizione, _) in corpo.match_indices("animate ") {
                animazioni += 1;
                let blocco: String = corpo[posizione..].chars().take(200).collect();
                assert!(
                    blocco.contains("duration: Appearance.motion-enabled ? Motion.quick : 0ms;"),
                    "un'animazione del tour non rispetta il movimento ridotto: {blocco}"
                );
            }
        }
        assert!(
            animazioni >= 1,
            "nessuna animazione trovata: la guardia non guarda"
        );
    }

    /// **Ogni schermata ha una decisione sul tour** (ADR-0134 §17): una
    /// schermata nuova senza la sua riga fa diventare rossa questa prova, e
    /// ogni passo corrisponde a una riga.
    #[test]
    fn ogni_schermata_ha_una_decisione_sul_tour() {
        let numeri: Vec<i32> = TOUR_COVERAGE.iter().map(|(pagina, _)| *pagina).collect();
        assert_eq!(
            numeri,
            (0..SCREENS).collect::<Vec<_>>(),
            "una riga per schermata, in ordine"
        );

        let comuni: BTreeSet<&str> = COMMON_STEPS.iter().map(|step| step.key).collect();
        let amministratore: BTreeSet<&str> =
            ADMINISTRATOR_STEPS.iter().map(|step| step.key).collect();
        for (pagina, decisione) in TOUR_COVERAGE {
            match decisione {
                TourCoverage::Common(chiave) => assert!(
                    COMMON_STEPS
                        .iter()
                        .any(|s| s.key == chiave && page_of(s.place) == pagina),
                    "schermata {pagina}: «{chiave}» non è un passo comune che la apre"
                ),
                TourCoverage::Administrator(chiave) => assert!(
                    ADMINISTRATOR_STEPS
                        .iter()
                        .any(|s| s.key == chiave && page_of(s.place) == pagina),
                    "schermata {pagina}: «{chiave}» non è un passo dell'amministratore che la apre"
                ),
                TourCoverage::Outside(ragione) => {
                    assert!(
                        ragione.len() >= 12,
                        "schermata {pagina}: la ragione è troppo corta"
                    );
                }
            }
        }
        for step in COMMON_STEPS.iter().chain(ADMINISTRATOR_STEPS.iter()) {
            let pagina = page_of(step.place);
            assert!(
                (0..SCREENS).contains(&pagina),
                "«{}» non porta a una schermata",
                step.key
            );
            assert!(comuni.contains(step.key) || amministratore.contains(step.key));
        }
        assert_eq!(page_of(LAST_STEP.place), -1);
    }

    /// **Ogni zona ha il suo elemento vero**: la voce del menu di ogni
    /// schermata ha un nome, e il registro del disegno lo traduce.
    #[test]
    fn ogni_zona_del_tour_ha_il_suo_elemento() {
        let [comandi, _] = tratti_del_tour();
        for pagina in 0..SCREENS {
            assert!(
                UI.contains(&format!("voce-{pagina} := NavigationItem {{")),
                "la voce della schermata {pagina} non ha un nome"
            );
            assert!(
                comandi.contains(&format!(
                    "if (page == {pagina}) {{ return {{ x: voce-{pagina}.absolute-position.x"
                )),
                "il registro del disegno non conosce la voce {pagina}"
            );
        }
        for zona in [
            "zone == 3",
            "corpo-finestra.absolute-position",
            "zone == 2",
            "zone == 1",
            "scopri.absolute-position",
            "contenuto.absolute-position",
        ] {
            assert!(
                comandi.contains(zona),
                "il registro del disegno non conosce «{zona}»"
            );
        }
        assert!(COMMON_STEPS.iter().any(|s| s.zone == TourZone::Content));
    }

    /// **Ogni comando che il tour nomina esiste**, con quell'etichetta.
    #[test]
    fn ogni_comando_nominato_dal_tour_esiste() {
        let componenti = include_str!("../ui/components.slint");
        let mut nominati = 0;
        for step in COMMON_STEPS
            .iter()
            .chain(ADMINISTRATOR_STEPS.iter())
            .chain([&LAST_STEP])
        {
            for pezzo in step.body.split('«').skip(1) {
                let Some((etichetta, _)) = pezzo.split_once('»') else {
                    panic!("«{}»: virgolette non chiuse", step.key);
                };
                nominati += 1;
                let cercata = format!("\"{etichetta}\"");
                assert!(
                    UI.contains(&cercata) || componenti.contains(&cercata),
                    "il passo «{}» nomina «{etichetta}», che l'interfaccia non ha",
                    step.key
                );
            }
        }
        assert!(
            nominati >= 6,
            "solo {nominati} comandi nominati: la guardia non guarda"
        );
    }

    // ------------------------------------------------------ la finestra vera

    fn contesto() -> TourContext {
        TourContext {
            administrator: false,
            exercise: false,
            team_services: true,
        }
    }

    fn premi(window: &AppWindow, tasto: Key) {
        let testo: slint::SharedString = tasto.into();
        window.window().dispatch_event(WindowEvent::KeyPressed {
            text: testo.clone(),
        });
        window
            .window()
            .dispatch_event(WindowEvent::KeyReleased { text: testo });
    }

    /// 1, 2, 3, 5-9, 13, 16, 17 — **Il tour sulla finestra vera**: la proposta
    /// compare solo dopo la domanda del primo avvio e solo una volta; Tab gira
    /// fra i comandi del fumetto; le frecce avanzano; Esc esce e torna alla
    /// schermata di partenza; nessun comando operativo viene chiamato.
    ///
    /// Una prova sola: il backend di prova si inizializza una volta per
    /// processo e la finestra vuole un solo filo.
    /// **Il tour si legge con un lettore di schermo**: il fumetto dice a che
    /// punto si è e che cosa dice il passo, e i suoi comandi sono pulsanti che
    /// si premono (COLLAUDO-FIX-01, CU01-012).
    ///
    /// Il motore di prova non passa dal ponte verso Windows: questa prova
    /// tiene la struttura che il lettore di schermo legge, e la prova a vista
    /// con l'Assistente vocale resta in HVQ-175 (campagna 5).
    #[test]
    fn il_tour_si_legge_con_un_lettore_di_schermo() {
        use i_slint_backend_testing::{AccessibleRole, ElementHandle, ElementRoot};

        i_slint_backend_testing::init_no_event_loop();
        let Ok(window) = AppWindow::new() else {
            panic!("la finestra di prova deve nascere");
        };
        if slint::select_bundled_translation("").is_err() {
            panic!("la lingua di partenza deve potersi scegliere");
        }
        let Ok(database) = Database::open_in_memory() else {
            panic!("l'archivio di prova deve aprirsi");
        };
        let Some(tour) = create(Some(database), Rc::new(contesto)) else {
            panic!("il tour deve nascere");
        };
        wire(&window, &tour);
        window.global::<DocumentProfile>().set_answered(true);
        window.invoke_open_page(3);
        window.show().ok();
        window.invoke_tour_open_panel();
        window.invoke_tour_requested(false);
        assert!(window.get_tour_active());

        let pulsante = |etichetta: &str| -> ElementHandle {
            let trovati: Vec<ElementHandle> =
                ElementHandle::find_by_accessible_label(&window, etichetta)
                    .filter(|e| e.accessible_role() == Some(AccessibleRole::Button))
                    .collect();
            let Some(primo) = trovati.into_iter().next() else {
                panic!("«{etichetta}» deve essere un pulsante per chi ascolta");
            };
            primo
        };
        for etichetta in ["Indietro", "Avanti", "Esci dal tour"] {
            pulsante(etichetta);
        }
        let fumetto = window
            .root_element()
            .query_descendants()
            .match_accessible_role(AccessibleRole::Groupbox)
            .match_predicate(|e| {
                e.accessible_label()
                    .is_some_and(|etichetta| etichetta.starts_with("1 di "))
            })
            .find_all();
        assert_eq!(fumetto.len(), 1, "il fumetto deve dire «1 di …» e il passo");

        // Premuto da un lettore di schermo, «Avanti» va avanti.
        pulsante("Avanti").invoke_accessible_default_action();
        assert_eq!(window.get_tour_index(), 1);
        pulsante("Esci dal tour").invoke_accessible_default_action();
        assert!(!window.get_tour_active());
    }

    /// **Nello strato del tour nasce un elemento quando il tour comincia**, e
    /// il ponte verso Windows rifà l'albero di accessibilità con il fumetto
    /// dentro (COLLAUDO-FIX-01, CU01-012). Vista rossa con la 0.2.2: lo strato
    /// era soltanto nascosto e mostrato, senza un elemento che nascesse.
    #[test]
    fn il_fumetto_nasce_con_il_tour() {
        let inizio = UI
            .find("tour-layer := Rectangle {")
            .unwrap_or_else(|| panic!("lo strato del tour deve esistere"));
        let strato = &UI[inizio..];
        let fine = strato
            .find("\n    }\n")
            .unwrap_or_else(|| panic!("lo strato del tour deve chiudersi"));
        assert!(
            strato[..fine].contains(concat!("if root.tour-", "active: Text {")),
            "nello strato del tour deve nascere un elemento con il tour"
        );
    }

    #[test]
    fn il_tour_sulla_finestra_vera() {
        i_slint_backend_testing::init_no_event_loop();
        let Ok(window) = AppWindow::new() else {
            panic!("la finestra di prova deve nascere");
        };
        let Ok(database) = Database::open_in_memory() else {
            panic!("l'archivio di prova deve aprirsi");
        };
        let Some(tour) = create(Some(database), Rc::new(contesto)) else {
            panic!("il tour deve nascere");
        };
        wire(&window, &tour);

        // Nessun comando operativo, per tutta la prova.
        let toccato = Rc::new(Cell::new(0_u32));
        {
            let t = Rc::clone(&toccato);
            window.on_start_monitoring(move || t.set(t.get() + 1));
            let t = Rc::clone(&toccato);
            window.on_start_login(move || t.set(t.get() + 1));
            let t = Rc::clone(&toccato);
            window.on_remove_account(move || t.set(t.get() + 1));
            let t = Rc::clone(&toccato);
            window.on_reset_history(move || t.set(t.get() + 1));
        }

        // 2 — La domanda del primo avvio senza risposta: niente proposta.
        window.global::<DocumentProfile>().set_answered(false);
        propose_if_due(&window, &tour);
        refresh(&window, &tour);
        assert!(window.get_tour_proposal_pending());
        assert!(
            !window.get_tour_proposal_visible(),
            "prima del primo avvio non si propone"
        );

        // 1 — Risposta data, Dashboard: la proposta compare.
        window.global::<DocumentProfile>().set_answered(true);
        window.invoke_open_page(0);
        assert!(window.get_tour_proposal_visible());
        window.invoke_tour_proposal_shown();
        assert!(window.get_tour_fresh(), "proposto e non scelto: «Nuovo»");

        // 3 — «Salta per ora»: sparisce, e a un nuovo avvio non torna.
        window.invoke_tour_proposal_skipped();
        assert!(!window.get_tour_proposal_visible());
        propose_if_due(&window, &tour);
        assert!(
            !window.get_tour_proposal_pending(),
            "saltato: non si ripropone"
        );
        assert!(!window.get_tour_fresh());

        // 4, 5 — Dal pannello, si avvia da capo; si parte dalla schermata 3.
        window.invoke_open_page(3);
        window.show().ok();
        window.invoke_tour_open_panel();
        assert!(window.get_tour_panel_open());
        window.invoke_tour_requested(false);
        assert!(window.get_tour_active());
        assert!(!window.get_tour_panel_open());
        assert_eq!(window.get_tour_index(), 0);
        assert_eq!(
            window.get_current_page(),
            0,
            "il primo passo apre la Dashboard"
        );

        // 16 — Le frecce avanzano e tornano.
        premi(&window, Key::RightArrow);
        assert_eq!(window.get_tour_index(), 1);
        premi(&window, Key::RightArrow);
        premi(&window, Key::LeftArrow);
        assert_eq!(window.get_tour_index(), 1);

        // Tab gira fra i tre comandi e non esce: da «Avanti», tre Tab
        // riportano ad «Avanti», e Invio va avanti.
        window.invoke_tour_start(1);
        premi(&window, Key::Tab);
        premi(&window, Key::Tab);
        premi(&window, Key::Tab);
        premi(&window, Key::Return);
        assert_eq!(window.get_tour_index(), 2, "il fuoco è rimasto nel fumetto");
        assert!(window.get_tour_active());

        // 17 — Esc esce subito, e torna alla schermata di partenza.
        premi(&window, Key::Escape);
        assert!(!window.get_tour_active());
        assert_eq!(
            window.get_current_page(),
            3,
            "si torna da dove si era partiti"
        );

        // 6 — Il pannello offre di continuare, dal passo conservato.
        window.invoke_tour_open_panel();
        assert_eq!(window.get_tour_offer(), 1);
        window.invoke_tour_requested(true);
        assert_eq!(window.get_tour_index(), 2, "si continua dal terzo passo");

        // 7, 8 — Fino in fondo: «Fine» completa.
        let quanti = steps(&contesto()).len();
        for _ in 2..quanti {
            premi(&window, Key::RightArrow);
        }
        assert!(
            !window.get_tour_active(),
            "l'ultimo «avanti» chiude il tour"
        );
        refresh(&window, &tour);
        assert_eq!(window.get_tour_offer(), 2, "completato: «Rifai il tour»");

        // 9 — Un nuovo avvio dopo il completamento non propone niente.
        propose_if_due(&window, &tour);
        assert!(!window.get_tour_proposal_pending());

        // 13 — Nessun comando operativo è stato chiamato.
        assert_eq!(toccato.get(), 0, "il tour ha premuto un comando operativo");
    }
}

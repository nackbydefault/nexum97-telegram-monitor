//! Collegamento fra la Dashboard e i servizi che ne compongono le risposte.
//!
//! # Che cosa questo modulo non fa
//!
//! **Non compone alcuna risposta.** Le raccoglie: la salute dal servizio della
//! salute, la coda da quello della coda, l'archivio e le notifiche dal centro
//! diagnostico. Ricomporle qui creerebbe una seconda derivazione, e due
//! schermate direbbero cose diverse nello stesso istante — sulla schermata che
//! esiste per orientare, che è il posto peggiore in cui accada (DEC-252).

use std::cell::RefCell;
use std::rc::Rc;

use lisi_services::dashboard::{
    AnswerState, DashboardFacts, RECENT_WINDOW_MS, compose as compose_dashboard,
};
use lisi_services::diagnostics::{DiagnosticReport, StationFacts};
use lisi_services::source_health::HealthSummary;
use lisi_services::work_queue::WorkQueue;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::diagnostics::SharedDiagnostics;
use crate::sources::SharedHealth;
use crate::work_queue::SharedWorkQueue;
use crate::{AppWindow, DashboardRow, TrendRow};

/// L'archivio da cui il cruscotto legge i propri due conteggi.
///
/// Sono i soli due numeri che nessun altro servizio compone: i contenuti
/// recenti e i grappoli nelle sessioni attive di recente.
pub type SharedDashboard = Rc<RefCell<lisi_services::Database>>;

/// Crea l'accesso all'archivio per il cruscotto.
#[must_use]
pub fn create_service(database: lisi_services::Database) -> Option<SharedDashboard> {
    Some(Rc::new(RefCell::new(database)))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn adesso() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// I servizi da cui il cruscotto raccoglie le risposte.
///
/// Sono facoltativi ciascuno per conto proprio: un servizio non disponibile in
/// questa esecuzione non deve svuotare la schermata, e la risposta che ne
/// dipende dirà che non è disponibile invece di dire zero.
pub struct Sources<'a> {
    /// La salute delle fonti.
    pub health: Option<&'a SharedHealth>,
    /// La coda di lavoro.
    pub queue: Option<&'a SharedWorkQueue>,
    /// Il centro diagnostico.
    pub diagnostics: Option<&'a SharedDiagnostics>,
    /// L'archivio, per i due conteggi propri.
    pub database: Option<&'a SharedDashboard>,
}

/// Raccoglie le risposte e le riporta nell'interfaccia.
pub fn refresh(window: &AppWindow, services: &Sources<'_>) {
    let now = adesso();
    let inizio = lisi_core::Timestamp::from_millis(now.as_millis() - RECENT_WINDOW_MS);

    let sources = services
        .health
        .map_or_else(HealthSummary::default, |health| {
            health
                .borrow()
                .service()
                .summary()
                .unwrap_or_else(|_| HealthSummary::default())
        });

    let queue = services.queue.map_or_else(
        || WorkQueue {
            items: Vec::new(),
            composed_at: now,
        },
        |queue| {
            queue.borrow().compose(now).unwrap_or_else(|_| WorkQueue {
                items: Vec::new(),
                composed_at: now,
            })
        },
    );

    let station = StationFacts {
        mode: lisi_services::station::persisted_mode_or_restricted(),
        telegram_runtime_started: crate::account::telegram_live_connected(window),
        sources,
    };

    let diagnostics = services.diagnostics.map_or_else(
        || DiagnosticReport {
            taken_at: now,
            checks: Vec::new(),
        },
        |service| {
            service
                .borrow()
                .compose(&station, now)
                .unwrap_or_else(|_| DiagnosticReport {
                    taken_at: now,
                    checks: Vec::new(),
                })
        },
    );

    let (recent_contents, cyber_events) = services.database.map_or((0, 0), |database| {
        let database = database.borrow();
        let contenuti = database.contents_acquired_since(inizio).unwrap_or(0);
        // I grappoli si correlano SOLO nelle sessioni che hanno acquisito
        // qualcosa di recente: il costo cresce con cio' che e' successo, non
        // con la storia dell'ufficio.
        let grappoli = database
            .sessions_active_since(inizio)
            .map(|sessioni| {
                sessioni
                    .into_iter()
                    .filter_map(|sessione| {
                        lisi_services::cyber_watch::events_of(&database, sessione).ok()
                    })
                    .map(|grappoli| grappoli.len())
                    .sum()
            })
            .unwrap_or(0);
        (contenuti, grappoli)
    });

    // CHE COSA COMPARE PIU' DI PRIMA (TREND-01).
    //
    // Il confronto lo esegue `lisi_services::trend`, che NON CONOSCE
    // L'ARCHIVIO; `emerging` legge e gli passa le occorrenze. Qui non si conta
    // e non si confronta nulla: si riceve.
    //
    // Una lettura non riuscita non diventa «nulla emerge»: diventa `None`, e la
    // riga del cruscotto dichiara di non essere disponibile.
    let analisi = services.database.and_then(|database| {
        lisi_services::emerging::compose_now(&database.borrow(), now)
            .inspect_err(|errore| {
                tracing::warn!(errore = %errore, "analisi temporali non eseguite");
            })
            .ok()
            .flatten()
    });

    mostra_emergenti(window, analisi.as_ref());
    let trend = analisi.map(|analisi| analisi.trend);

    // QUANTI ACQUISISCONO, LETTO DALL'ARCHIVIO (OPERATOR-UX-REMEDIATION-01, OS-06).
    //
    // La riga leggeva `monitoring-active` dalla finestra, che la schermata
    // Monitoraggio scrive solo quando si apre: all'avvio la Dashboard diceva
    // «Fermo» con un monitoraggio in corso, e cambiava idea quando il Tour
    // apriva il Monitoraggio. L'archivio sa la risposta senza aspettare
    // nessuno. In corso vuol dire che acquisisce, anche con gli avvisi sospesi;
    // non un monitoraggio interrotto in attesa di decisione (E2E01-22).
    let acquisiscono = services.database.map(|database| {
        database
            .borrow()
            .receiving_session_count()
            .unwrap_or_else(|errore| {
                tracing::warn!(errore = %errore, "monitoraggi in corso non leggibili");
                0
            })
    });
    // QUANTI DI QUESTI HANNO L'ACQUISIZIONE IN PAUSA (COLLAUDO-FIX-01,
    // CU01-004, DEC-509): nell'archivio restano «in corso», ma non acquisiscono.
    let in_pausa = services.database.map(|database| {
        let database = database.borrow();
        crate::wakefulness::follow_pause(window, &database);
        database
            .paused_receiving_session_count()
            .unwrap_or_else(|errore| {
                tracing::warn!(errore = %errore, "monitoraggi in pausa non leggibili");
                0
            })
    });
    let facts = DashboardFacts {
        monitoring_active: acquisiscono.map_or_else(|| window.get_monitoring_active(), |n| n > 0),
        // Le fonti vengono dalla schermata Monitoraggio, e valgono solo per il
        // monitoraggio che mostra: si contano soltanto se quello è in corso
        // (si può arrestare). Altrimenti zero, e la risposta non le nomina.
        monitoring_sources: if window.get_monitoring_can_stop() {
            usize::try_from(window.get_monitoring_source_count()).unwrap_or(0)
        } else {
            0
        },
        // QUANTI, e non le fonti di uno solo (ADR-0065 §2.4).
        monitoring_running: acquisiscono.unwrap_or(0),
        monitoring_paused: in_pausa.unwrap_or(0),
        sources,
        queue,
        diagnostics,
        recent_contents,
        cyber_events,
        telegram_ready: window.get_auth_authenticated(),
        exercise: lisi_services::run_mode::is_exercise(),
        trend,
    };

    let cruscotto = compose_dashboard(&facts, now);

    let righe: Vec<DashboardRow> = cruscotto
        .answers
        .iter()
        .map(|answer| DashboardRow {
            question: crate::lingua::schermo(answer.question.label()),
            value: SharedString::from(answer.value.as_str()),
            note: SharedString::from(answer.note.as_str()),
            attention: answer.state.needs_attention(),
            unavailable: answer.state == AnswerState::Unavailable,
        })
        .collect();

    window.set_dashboard_summary(crate::lingua::schermo(cruscotto.as_sentence()));
    window.set_dashboard_attention(i32::try_from(cruscotto.needing_attention()).unwrap_or(0));
    window.set_dashboard_answers(ModelRc::from(Rc::new(VecModel::from(righe))));
}

/// Riporta nell'interfaccia che cosa compare più di prima.
///
/// # Perché l'elenco si prepara anche quando il pannello è chiuso
///
/// Perché non costa una seconda lettura: le righe vengono dallo **stesso**
/// confronto che ha prodotto il numero della riga «Segnali emergenti». Il
/// pannello si limita a mostrarle, e non ricompone niente (DEC-252).
fn mostra_emergenti(
    window: &AppWindow,
    analisi: Option<&lisi_services::emerging::EmergingAnalysis>,
) {
    let vuoto = || ModelRc::from(Rc::new(VecModel::from(Vec::<TrendRow>::new())));

    let Some(analisi) = analisi else {
        window.set_trend_count(0);
        window.set_trend_summary(SharedString::default());
        window.set_trend_rows(vuoto());
        window.set_spike_count(0);
        window.set_spike_summary(SharedString::default());
        window.set_spike_rows(vuoto());
        return;
    };

    let emergenti: Vec<TrendRow> = analisi
        .trend
        .findings()
        .iter()
        .map(|voce| TrendRow {
            what: crate::lingua::schermo(format!("{} «{}»", voce.kind.label(), voce.key)),
            counts: crate::lingua::schermo(voce.as_sentence()),
        })
        .collect();

    let aumenti: Vec<TrendRow> = analisi
        .spikes
        .findings()
        .iter()
        .map(|voce| TrendRow {
            what: crate::lingua::schermo(format!("{} «{}»", voce.kind.label(), voce.key)),
            counts: crate::lingua::schermo(voce.as_sentence()),
        })
        .collect();

    // `emerging_count` e `anomalous_count` sono `None` quando l'analisi non si
    // è potuta fare, e zero quando si è fatta e non ha trovato nulla: qui le due
    // cose portano allo stesso pannello chiuso, ma le FRASI le distinguono.
    //
    // I due conteggi non si sommano mai: vengono da due metodi diversi, e una
    // cifra che li mettesse insieme non sarebbe la risposta di nessuno dei due.
    window.set_trend_count(conteggio(analisi.trend.emerging_count()));
    window.set_trend_summary(crate::lingua::schermo(analisi.trend.as_sentence()));
    window.set_trend_rows(ModelRc::from(Rc::new(VecModel::from(emergenti))));

    window.set_spike_count(conteggio(analisi.spikes.anomalous_count()));
    window.set_spike_summary(crate::lingua::schermo(analisi.spikes.as_sentence()));
    window.set_spike_rows(ModelRc::from(Rc::new(VecModel::from(aumenti))));
}

/// Quante voci, per l'interfaccia; zero quando l'analisi non si è potuta fare.
///
/// Il pannello resta chiuso in entrambi i casi, e la differenza fra «zero» e
/// «non misurato» la porta la frase, che è composta dal servizio.
fn conteggio(quante: Option<usize>) -> i32 {
    quante
        .and_then(|quante| i32::try_from(quante).ok())
        .unwrap_or(0)
}

/// Registra i gestori dei comandi della schermata.
pub fn wire(
    window: &AppWindow,
    health: Option<&SharedHealth>,
    queue: Option<&SharedWorkQueue>,
    diagnostics: Option<&SharedDiagnostics>,
    database: Option<&SharedDashboard>,
) {
    let weak = window.as_weak();
    let health = health.map(Rc::clone);
    let queue = queue.map(Rc::clone);
    let diagnostics = diagnostics.map(Rc::clone);
    let database = database.map(Rc::clone);

    window.on_dashboard_shown(move || {
        let Some(window) = weak.upgrade() else { return };
        refresh(
            &window,
            &Sources {
                health: health.as_ref(),
                queue: queue.as_ref(),
                diagnostics: diagnostics.as_ref(),
                database: database.as_ref(),
            },
        );
    });

    {
        let weak = window.as_weak();
        window.on_open_trend(move || {
            if crate::lock::refuse_while_locked("open_trend") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            window.set_trend_open(true);
        });
    }

    {
        let weak = window.as_weak();
        window.on_close_trend(move || {
            if crate::lock::refuse_while_locked("close_trend") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            window.set_trend_open(false);
        });
    }
}

#[cfg(test)]
mod guardie {
    /// Il file dell'interfaccia, per le guardie testuali.
    const UI: &str = include_str!("../ui/app-window.slint");

    /// Questo modulo, per verificare che cosa il codice di produzione fa.
    const THIS_MODULE: &str = include_str!("dashboard.rs");

    /// **«IN CORSO» si dice solo se la postazione acquisisce** (F-04).
    ///
    /// Dopo un riavvio con l'account scollegato il Cruscotto diceva «IN CORSO»
    /// e il radar girava: lo stato registrato del monitoraggio non è la prova
    /// che si stia ascoltando. La guardia lega le tre frasi a quella condizione.
    #[test]
    fn in_corso_vuole_una_postazione_che_acquisisce() {
        assert!(
            UI.contains(
                "property <bool> station-acquiring: root.auth-authenticated && !root.exercise-mode;"
            ),
            "la condizione di acquisizione non c'è più"
        );
        assert!(
            UI.contains("(root.station-acquiring ? @tr(\"IN CORSO\") : @tr(\"NON ACQUISISCE\"))"),
            "«IN CORSO» non dipende più dall'acquisizione"
        );
        assert!(
            UI.contains(
                "running: root.monitoring-active && root.station-acquiring && !root.acquisition-paused;"
            ),
            "il radar gira senza che la postazione acquisisca, o con l'acquisizione in pausa"
        );
    }

    /// **In pausa il Cruscotto non dice «IN CORSO»** (COLLAUDO-FIX-01,
    /// CU01-004, DEC-509): il radar si ferma e dice «IN PAUSA», il marchio non
    /// pulsa, la frase della testata dice la pausa e il periodo non coperto, e
    /// lo stato della pausa viene dall'archivio come quello di «in corso».
    #[test]
    fn in_pausa_il_cruscotto_non_dice_in_corso() {
        assert!(
            UI.contains(
                "!root.monitoring-active ? @tr(\"FERMO\") : root.acquisition-paused ? @tr(\"IN PAUSA\")"
            ),
            "la didascalia del radar non dice la pausa"
        );
        assert!(
            UI.contains(
                "active: root.monitoring-active && root.station-acquiring && !root.acquisition-paused;"
            ),
            "il marchio pulsa con l'acquisizione in pausa"
        );
        assert!(
            UI.contains("root.monitoring-active && root.acquisition-paused ? @tr(\"L'acquisizione è in pausa"),
            "la frase della testata non dice la pausa"
        );
        assert!(
            THIS_MODULE.contains("crate::wakefulness::follow_pause(window, &database);"),
            "il Cruscotto non legge la pausa dall'archivio"
        );
    }

    /// Il codice di produzione senza i commenti.
    fn codice_senza_commenti() -> String {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod guardie {") else {
            panic!("il modulo deve avere un blocco di guardie riconoscibile");
        };
        produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Le righe che un operatore **legge** nell'interfaccia.
    fn testi_mostrati() -> Vec<&'static str> {
        UI.lines()
            .map(str::trim)
            .filter(|riga| {
                riga.starts_with("text:") || riga.starts_with("label:") || riga.starts_with("+ \"")
            })
            .collect()
    }

    /// **«Non disponibile» ha un colore proprio, e non è quello del calmo.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// I segnali emergenti non esistono ancora, e la loro riga è sempre non
    /// disponibile. Dipingerla come le altre direbbe che il prodotto ha
    /// guardato e non ha trovato nulla.
    #[test]
    fn cio_che_non_e_disponibile_ha_un_colore_proprio() {
        let Some(inizio) = UI.find("text: risposta.value;") else {
            panic!("la risposta breve deve esistere");
        };
        let Some(fine) = UI[inizio..].find("horizontal-stretch: 0;") else {
            panic!("il blocco della risposta deve avere una fine riconoscibile");
        };
        let blocco = &UI[inizio..inizio + fine];

        assert!(
            blocco.contains("risposta.unavailable"),
            "la risposta non disponibile deve avere un ramo proprio"
        );

        let Some(ramo) = blocco.find("risposta.unavailable") else {
            panic!("il ramo del non disponibile deve esistere");
        };
        let dopo = &blocco[ramo..];
        let Some(scelta) = dopo.find("Palette.") else {
            panic!("il ramo deve scegliere un colore");
        };
        assert!(
            dopo[scelta..].starts_with("Palette.text-muted"),
            "una risposta non disponibile non va colorata né come allarme né come \
             conferma"
        );
    }

    /// **Nessuna percentuale e nessun punteggio nel cruscotto.**
    ///
    /// È il posto in cui una metrica riassuntiva sembra più innocua e fa più
    /// danno: verrebbe letta come un giudizio sulla postazione.
    #[test]
    fn il_cruscotto_non_mostra_percentuali_ne_punteggi() {
        let codice = codice_senza_commenti();
        for vietato in ["score", "punteggio", "percentuale", "health_index"] {
            assert!(!codice.contains(vietato), "il cruscotto nomina «{vietato}»");
        }

        for riga in testi_mostrati() {
            for vietato in ["Punteggio", "Percentuale", "Copertura", "Salute generale"] {
                assert!(
                    !riga.contains(vietato),
                    "l'interfaccia mostra «{vietato}»: undici risposte non si \
                     riassumono in un giudizio — «{riga}»"
                );
            }
        }
    }

    /// Il cruscotto **riceve** le risposte, non le ricompone.
    ///
    /// Due derivazioni dello stesso stato divergono, e la Dashboard è la
    /// schermata su cui la divergenza si nota di meno e conta di più.
    #[test]
    fn il_cruscotto_riceve_le_risposte_e_non_le_ricompone() {
        let codice = codice_senza_commenti();

        assert!(
            codice.contains("compose_dashboard(&facts, now)"),
            "le risposte le mette in fila il servizio, non questo modulo"
        );
        // La salute e la coda arrivano dai loro servizi, non da una lettura
        // fatta qui.
        for ricomposizione in ["health_facts()", "pending_work()", "derive("] {
            assert!(
                !codice.contains(ricomposizione),
                "il cruscotto chiama «{ricomposizione}»: ricomporrebbe uno stato che \
                 un altro servizio compone già"
            );
        }
    }

    /// Guardare il cruscotto non cambia nulla.
    #[test]
    fn guardare_il_cruscotto_non_cambia_nulla() {
        let codice = codice_senza_commenti();

        for scrittura in ["append_audit", "insert_", "verify_all", "export_to"] {
            assert!(
                !codice.contains(scrittura),
                "il cruscotto chiama «{scrittura}»: aprirlo è una lettura"
            );
        }
    }

    /// **Il pannello dei segnali emergenti non compare se non c'è nulla.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un comando che apre un elenco vuoto è un comando che si impara a non
    /// premere, e il giorno in cui qualcosa emerge davvero nessuno lo preme.
    #[test]
    fn il_pannello_degli_emergenti_non_compare_se_non_c_e_nulla() {
        assert!(
            UI.contains(
                "if (root.trend-count > 0 || root.spike-count > 0) && !root.trend-open: Rectangle {"
            ),
            "il comando deve dipendere dall'esserci qualcosa da mostrare"
        );
        assert!(
            UI.contains("in property <bool> trend-open: false;"),
            "il pannello deve partire chiuso"
        );
    }

    /// **Ogni riga emergente porta due conteggi, e li compone il servizio.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un numero solo — «14 volte» — si leggerebbe come una misura
    /// dell'emergenza, e non esiste una misura dell'emergenza: ci sono due
    /// conteggi di fatti registrati e la loro differenza. Comporre la frase qui
    /// creerebbe inoltre una seconda derivazione, e il pannello e il servizio
    /// potrebbero dire due cose diverse (DEC-252).
    #[test]
    fn ogni_riga_emergente_porta_due_conteggi_composti_dal_servizio() {
        let codice = codice_senza_commenti();

        assert!(
            codice.contains("counts: crate::lingua::schermo(voce.as_sentence())"),
            "la frase dei conteggi la compone il servizio, non la schermata"
        );
        assert!(
            UI.contains("text: voce.counts;"),
            "la riga deve mostrare i conteggi"
        );
    }

    /// **Il cruscotto non conta e non confronta: riceve.**
    ///
    /// L'aritmetica sta in `lisi_services::trend`, che non conosce l'archivio
    /// ed è provato da solo. Rifarla qui creerebbe due risposte alla stessa
    /// domanda, e il giorno in cui divergessero nessuna delle due sarebbe
    /// contestabile più dell'altra.
    #[test]
    fn il_cruscotto_non_conta_e_non_confronta_le_occorrenze() {
        let codice = codice_senza_commenti();

        for aritmetica in [
            "observations_between",
            "earliest_publication",
            "ComparisonWindows::",
            "analyse(",
        ] {
            assert!(
                !codice.contains(aritmetica),
                "il cruscotto chiama «{aritmetica}»: il confronto lo compone il servizio"
            );
        }
    }

    /// **Il pannello dichiara di non essere una tendenza.**
    ///
    /// Due finestre non sono una serie. La frase arriva composta dal servizio,
    /// e questa guardia impone che la schermata la mostri invece di sostituirla
    /// con un titolo più breve.
    #[test]
    fn il_pannello_mostra_la_frase_che_nega_di_essere_una_tendenza() {
        assert!(
            UI.contains("text: root.trend-summary;"),
            "la frase del confronto deve comparire nel pannello"
        );

        let Some(inizio) = UI.find("if root.trend-open: Rectangle {") else {
            panic!("il pannello deve esistere");
        };
        let Some(fine) = UI[inizio..].find("text: voce.counts;") else {
            panic!("il pannello deve avere le righe");
        };
        let blocco = &UI[inizio..inizio + fine];

        let Some(riepilogo) = blocco.find("text: root.trend-summary;") else {
            panic!("il riepilogo deve stare nel pannello");
        };
        let Some(prima_riga) = blocco.find("for voce in root.trend-rows:") else {
            panic!("le righe devono stare nel pannello");
        };
        assert!(
            riepilogo < prima_riga,
            "le finestre e la cautela vanno lette PRIMA dei numeri che qualificano"
        );
    }

    /// **I due conteggi non si sommano mai in una cifra sola.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// «Tre cose da guardare» che mette insieme il confronto fra periodi e gli
    /// aumenti oltre soglia non è la risposta di nessuno dei due metodi, e
    /// nessuno saprebbe dire come sia stata calcolata. Sono due domande diverse
    /// sugli stessi fatti, e restano due numeri.
    #[test]
    fn i_due_conteggi_non_si_sommano_mai() {
        let codice = codice_senza_commenti();

        assert!(
            codice.contains("window.set_trend_count(conteggio(analisi.trend.emerging_count()))"),
            "il conteggio del confronto deve venire dal confronto"
        );
        assert!(
            codice.contains("window.set_spike_count(conteggio(analisi.spikes.anomalous_count()))"),
            "il conteggio degli aumenti deve venire dagli aumenti"
        );
        for somma in [
            "trend_count + spike",
            "spike_count + trend",
            "emerging_count() + ",
            "anomalous_count() + ",
        ] {
            assert!(
                !codice.contains(somma),
                "«{somma}»: i due metodi non producono una cifra sola"
            );
        }
    }

    /// **Il metodo degli aumenti è dichiarato accanto alle righe.**
    ///
    /// Il congelamento chiede metodo e soglie **documentati**. Una sezione che
    /// elencasse gli aumenti senza dire con quale soglia sono stati trovati
    /// darebbe un verdetto, e un verdetto non si controlla.
    #[test]
    fn il_metodo_degli_aumenti_e_dichiarato_prima_delle_righe() {
        let Some(inizio) = UI.find("AUMENTI OLTRE LA SOGLIA DICHIARATA") else {
            panic!("la sezione degli aumenti deve esistere");
        };
        let blocco = &UI[inizio..];

        let Some(metodo) = blocco.find("text: root.spike-summary;") else {
            panic!("il metodo deve comparire nella sezione");
        };
        let Some(righe) = blocco.find("for aumento in root.spike-rows:") else {
            panic!("le righe degli aumenti devono esistere");
        };
        assert!(
            metodo < righe,
            "il metodo e le soglie vanno letti PRIMA delle righe che ne discendono"
        );
    }

    /// **La schermata non ricompone le frasi degli aumenti.**
    ///
    /// Le compone il servizio, che è dove le soglie vivono: una frase composta
    /// qui potrebbe citare una soglia diversa da quella usata per decidere.
    #[test]
    fn le_frasi_degli_aumenti_le_compone_il_servizio() {
        let codice = codice_senza_commenti();

        assert!(
            codice.contains("counts: crate::lingua::schermo(voce.as_sentence())"),
            "la frase dei numeri la compone il servizio"
        );
        for ricomposizione in ["mediana", "soglia", "scarto", "DEVIATION_MULTIPLIER"] {
            assert!(
                !codice.contains(ricomposizione),
                "la schermata nomina «{ricomposizione}»: ricomporrebbe una soglia che il \
                 servizio ha già dichiarato"
            );
        }
    }

    /// Il blocco dell'interfaccia che disegna il pannello delle due analisi.
    ///
    /// # Perché non tutto il file
    ///
    /// Perché parole come «attacco» **esistono e devono esistere** altrove, e
    /// vi compaiono **negate**: la schermata delle impostazioni dice che un
    /// avviso di Cyber Watch «non dice che un attacco sia avvenuto», ed è
    /// esattamente la frase giusta al posto giusto.
    ///
    /// Cercarla nell'intero file faceva diventare rossa questa prova per una
    /// negazione corretta — lo stesso errore già corretto in LAB-02 e, prima,
    /// in HEALTH-01. Una prova che si accende su ciò che è giusto non verifica
    /// quello che dichiara di verificare.
    fn pannello_delle_analisi() -> &'static str {
        let Some(inizio) = UI.find("if root.trend-open: Rectangle {") else {
            panic!("il pannello delle analisi deve esistere");
        };
        let Some(fine) = UI[inizio..].find("title: @tr(\"Che cosa questa versione fa e non fa\");")
        else {
            panic!("il pannello deve avere una fine riconoscibile");
        };
        &UI[inizio..inizio + fine]
    }

    /// **Nessuna parola del pannello attribuisce un'intenzione.**
    ///
    /// «Aumento delle occorrenze», mai «attacco». Il salto fra un conteggio che
    /// cresce e una parola che dice «attacco» è l'attribuzione automatica di
    /// responsabilità che il confine della decisione umana vieta — e
    /// l'interfaccia è il punto in cui quel salto verrebbe letto come una
    /// conclusione del prodotto.
    #[test]
    fn nessuna_parola_del_pannello_attribuisce_un_intenzione() {
        let righe: Vec<&str> = pannello_delle_analisi()
            .lines()
            .map(str::trim)
            .filter(|riga| {
                riga.starts_with("text:") || riga.starts_with("label:") || riga.starts_with("+ \"")
            })
            .collect();
        assert!(!righe.is_empty(), "il pannello deve mostrare qualcosa");

        for riga in righe {
            let minuscolo = riga.to_lowercase();
            for vietata in [
                "attacco",
                "attacchi",
                "minaccia",
                "campagna",
                "colpevole",
                "malevol",
                "criminal",
            ] {
                assert!(
                    !minuscolo.contains(vietata),
                    "l'interfaccia dice «{vietata}»: un aumento delle occorrenze non \
                     attribuisce un'intenzione a nessuno — «{riga}»"
                );
            }
        }
    }
}

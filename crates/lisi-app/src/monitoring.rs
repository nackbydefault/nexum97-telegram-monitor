//! Collegamento fra la schermata Monitoraggio e il servizio del ciclo di vita.
//!
//! Come gli altri moduli di collegamento, non contiene logica: traduce lo stato
//! del servizio in proprietà dell'interfaccia e i comandi dell'operatore in
//! chiamate al servizio.
//!
//! In particolare **non decide** quali comandi siano ammessi: quell'insieme lo
//! calcola `MonitoringService`, dove è coperto da test. L'interfaccia riceve i
//! flag `can-*` già calcolati e si limita a disabilitare i pulsanti.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_core::model::{SessionDuration, SessionState};
use lisi_services::monitoring::{MonitoringAction, MonitoringService, MonitoringView};
use lisi_services::wizard::{MonitoringWizard, WizardStart};
use lisi_services::{ServiceError, ServiceResult};
use slint::{ComponentHandle, SharedString};

use crate::AppWindow;

/// Servizio del monitoraggio condiviso fra i gestori dei comandi.
pub type SharedMonitoring = Rc<RefCell<MonitoringService>>;

/// Composizione del wizard, per avviare un monitoraggio dalla sua conferma.
pub type SharedWizard = Rc<RefCell<MonitoringWizard>>;

/// Indice della pagina Monitoraggio nell'interfaccia.
const MONITORING_PAGE: i32 = 9;

/// La risposta a un monitoraggio programmato (SCHEDULE-01): come «Monitoraggio
/// avviato.», porta alla schermata Monitoraggio e svuota la procedura.
const MONITORAGGIO_PROGRAMMATO: &str = "Monitoraggio programmato.";

/// Crea il servizio del monitoraggio sull'archivio indicato.
#[must_use]
pub fn create_service(database: lisi_services::Database) -> Option<SharedMonitoring> {
    Some(Rc::new(RefCell::new(MonitoringService::new(database))))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// Attore dell'audit.
fn actor() -> ServiceResult<lisi_core::text::Actor> {
    crate::operator::audit_actor()
}

/// Durata resa leggibile per l'operatore: le parole le compone il dominio
/// (ADR-0150). Diceva «1 ore».
fn duration_label(duration: SessionDuration) -> String {
    duration.in_words()
}

/// La fine prevista di un monitoraggio a tempo avviato: avvio + durata, al
/// secondo (ADR-0145, ADR-0150). Vuota per l'arresto manuale e prima dell'avvio.
fn planned_end_label(
    started_at: Option<lisi_core::Timestamp>,
    duration: SessionDuration,
) -> String {
    started_at
        .zip(duration.planned_seconds())
        .map(|(avvio, secondi)| {
            lisi_core::Timestamp::from_millis(
                avvio
                    .as_millis()
                    .saturating_add(secondi.saturating_mul(1_000)),
            )
            .to_readable_local()
        })
        .unwrap_or_default()
}

/// Quale monitoraggio la schermata sta mostrando.
///
/// # Perché una scelta e non «l'ultimo»
///
/// Perché i monitoraggi possono essere più d'uno (ADR-0065), e una schermata che
/// mostrasse sempre l'ultimo avviato **cambierebbe sotto gli occhi** di chi ne
/// sta guardando un altro, alla prima sessione nuova.
///
/// Vive quanto la finestra: riaprendo si riparte dal più recente, che è la
/// risposta di prima e resta quella giusta quando ce n'è uno solo.
fn selected() -> &'static std::thread::LocalKey<std::cell::Cell<Option<lisi_core::SessionId>>> {
    thread_local! {
        static SELECTED: std::cell::Cell<Option<lisi_core::SessionId>> =
            const { std::cell::Cell::new(None) };
    }
    &SELECTED
}

/// Quale monitoraggio l'operatore ha scelto, se ne ha scelto uno.
///
/// # Perché altri moduli hanno bisogno di saperlo
///
/// Perché il **recupero** riguarda un monitoraggio, non «il monitoraggio»: con
/// più d'uno in corso, recuperare su quello sbagliato porterebbe in archivio
/// messaggi dentro il perimetro di una decisione che non li aveva chiesti
/// (ADR-0065 §7).
#[must_use]
pub fn selected_session() -> Option<lisi_core::SessionId> {
    selected().with(std::cell::Cell::get)
}

/// Registra quale monitoraggio l'operatore ha scelto dall'elenco.
///
/// L'indice viene dalla posizione nell'elenco mostrato: è la stessa lista, letta
/// due volte, e non un numero che l'interfaccia si è inventata.
pub fn select(window: &AppWindow, monitoring: &SharedMonitoring, index: i32) {
    let elenco = match monitoring.borrow().summaries() {
        Ok(elenco) => elenco,
        Err(error) => {
            tracing::warn!(kind = error.kind(), "elenco dei monitoraggi non leggibile");
            return;
        }
    };

    let Ok(index) = usize::try_from(index) else {
        return;
    };
    let Some(scelto) = elenco.get(index) else {
        // Un indice fuori elenco non e' un guasto: l'elenco puo' essere
        // cambiato fra il disegno e il clic. Si lascia la scelta com'era.
        return;
    };

    selected().with(|corrente| corrente.set(Some(scelto.session_id)));
    refresh(window, monitoring, None);
}

/// Riporta nell'interfaccia lo stato del monitoraggio **scelto**.
pub fn refresh(window: &AppWindow, monitoring: &SharedMonitoring, message: Option<&str>) {
    if let Some(text) = message {
        // Al confine con lo schermo, come ogni testo del Rust: le frasi dei
        // comandi hanno la loro voce nel catalogo (COLLAUDO-FIX-01, CU01-010).
        window.set_monitoring_message(crate::lingua::schermo(text));
    }

    let elenco = monitoring.borrow().summaries().unwrap_or_else(|error| {
        tracing::warn!(kind = error.kind(), "elenco dei monitoraggi non leggibile");
        Vec::new()
    });

    // LA SCELTA VALE SOLO SE QUEL MONITORAGGIO ESISTE ANCORA.
    //
    // Un archivio azzerato, o una scelta fatta prima, lascerebbero la schermata
    // vuota senza spiegazione: si ricade sul piu' recente, che e' la risposta di
    // prima.
    let scelto = selected().with(|corrente| corrente.get()).filter(|scelto| {
        elenco
            .iter()
            .any(|riepilogo| riepilogo.session_id == *scelto)
    });
    selected().with(|corrente| corrente.set(scelto));

    show_list(window, &elenco, scelto);

    let view = match scelto {
        Some(session_id) => monitoring.borrow().view(session_id).map(Some),
        None => monitoring.borrow().latest_view(),
    };
    let view = match view {
        Ok(view) => view,
        Err(error) => {
            tracing::warn!(kind = error.kind(), "stato del monitoraggio non leggibile");
            window.set_monitoring_message(crate::lingua::schermo(error.operator_message()));
            None
        }
    };

    let Some(view) = view else {
        // Nessuna sessione: la schermata mostra lo stato vuoto.
        window.set_monitoring_present(false);
        window.set_monitoring_active(false);
        crate::wakefulness::follow_wakefulness(false);
        return;
    };

    // L'ELENCO SEGNA QUELLO DAVVERO MOSTRATO (UX-EXCELLENCE-02, SIM3-15): senza
    // una scelta esplicita si mostra il piu' recente, e nessuna riga lo diceva.
    show_list(window, &elenco, Some(view.session_id));

    // LA VEGLIA SEGUE **QUANTI** ACQUISISCONO, NON L'ULTIMO (ADR-0065).
    //
    // Con piu' monitoraggi, guardare la sola vista corrente spegnerebbe la
    // veglia quando finisce l'ultimo avviato **mentre un altro osserva**: la
    // postazione si addormenterebbe, e il prodotto se ne accorgerebbe solo dal
    // buco nell'archivio.
    //
    // Si contano quelli che RICEVONO: un monitoraggio interrotto, in attesa che
    // l'operatore decida, resta «in corso» nell'archivio ma non acquisisce, e
    // non deve tenere sveglia la postazione (E2E01-22, ADR-0146).
    //
    // Se il conteggio non e' leggibile si ricade sulla vista corrente: e' la
    // risposta di prima, che con un monitoraggio solo e' esatta.
    let acquiring = match monitoring.borrow().database().receiving_session_count() {
        Ok(quanti) => quanti > 0,
        Err(error) => {
            tracing::warn!(
                errore = %error,
                "numero dei monitoraggi che acquisiscono non leggibile: si usa la vista corrente"
            );
            matches!(view.state, SessionState::Running | SessionState::Paused)
        }
    };
    // La stessa condizione che tiene sveglia la postazione muove il marchio e
    // il radar della Dashboard. Deve venire da qui e non essere ricalcolata
    // altrove: due definizioni di «in corso» prima o poi divergono, e allora il
    // prodotto sembrerebbe attivo mentre la postazione si addormenta.
    window.set_monitoring_active(acquiring);
    crate::wakefulness::follow_wakefulness(acquiring);
    crate::wakefulness::follow_pause(window, monitoring.borrow().database());

    show(window, &view);
    show_coverage(window, monitoring, &view);
}

/// Che cosa ha guardato il monitoraggio scelto, fonte per fonte (PR-05).
///
/// Si legge sull'archivio del monitoraggio, alla fotografia di adesso: un
/// monitoraggio in corso finisce lì. Una lettura che non riesce lascia le barre
/// vuote invece di mostrarne di inventate.
fn show_coverage(window: &AppWindow, monitoring: &SharedMonitoring, view: &MonitoringView) {
    let adesso = now();
    let copertura = lisi_services::coverage::for_monitoring(
        monitoring.borrow().database(),
        view.session_id,
        adesso,
    );
    let (righe, generale) = match copertura {
        Ok(copertura) => {
            let (dal, al) = (
                copertura.overall.start().unwrap_or(adesso),
                copertura.overall.end().unwrap_or(adesso),
            );
            let righe: Vec<crate::CoperturaFonte> = copertura
                .sources
                .iter()
                .map(|(fonte, nome, tratti)| {
                    // Lo strato dei periodi recuperati dopo (PR-08), a parte.
                    let recuperati = lisi_services::coverage::recovered_spans(
                        monitoring.borrow().database(),
                        *fonte,
                        dal,
                        al,
                    )
                    .unwrap_or_else(|errore| {
                        tracing::warn!(
                            kind = errore.kind(),
                            "periodi recuperati non leggibili: lo strato resta vuoto"
                        );
                        Vec::new()
                    });
                    let (barra, strato) = crate::coverage::bars(tratti, &recuperati, dal, al);
                    crate::CoperturaFonte {
                        name: SharedString::from(nome.as_str()),
                        tratti: slint::ModelRc::from(Rc::new(slint::VecModel::from(barra))),
                        summary: SharedString::from(crate::coverage::in_words_with_recovered(
                            tratti,
                            &recuperati,
                        )),
                        recuperati: slint::ModelRc::from(Rc::new(slint::VecModel::from(strato))),
                    }
                })
                .collect();
            (righe, crate::coverage::overall_in_words(&copertura.overall))
        }
        Err(errore) => {
            tracing::warn!(
                kind = errore.kind(),
                "copertura del monitoraggio non leggibile"
            );
            (Vec::new(), String::new())
        }
    };
    window.set_monitoring_coverage(slint::ModelRc::from(Rc::new(slint::VecModel::from(righe))));
    window.set_monitoring_coverage_overall(SharedString::from(generale));
    window.set_coverage_meaning(SharedString::from(crate::coverage::meaning()));
    window.set_coverage_scope_note(SharedString::from(crate::coverage::scope_note(
        crate::coverage::in_team(),
    )));
}

/// Scrive una vista nell'interfaccia.
/// Mostra l'elenco dei monitoraggi, segnando quale è mostrato.
///
/// **Nomi e stati, e nient'altro.** Questa è la schermata, non il vassoio: qui i
/// nomi si possono leggere, perché la finestra è aperta e chi la guarda ha
/// sbloccato (ADR-0065 §3.4).
fn show_list(
    window: &AppWindow,
    elenco: &[lisi_services::monitoring::MonitoringSummary],
    scelto: Option<lisi_core::SessionId>,
) {
    let righe: Vec<crate::MonitoringRow> = elenco
        .iter()
        .map(|riepilogo| crate::MonitoringRow {
            label: SharedString::from(riepilogo.label.as_str()),
            state: crate::lingua::schermo(riepilogo.state.label()),
            selected: scelto.is_some_and(|scelto| scelto == riepilogo.session_id),
        })
        .collect();

    window.set_monitoring_list(slint::ModelRc::new(slint::VecModel::from(righe)));
}

fn show(window: &AppWindow, view: &MonitoringView) {
    window.set_monitoring_present(true);
    window.set_monitoring_label(SharedString::from(view.label.as_str()));
    // La pausa dell'acquisizione prima dello stato (CU01-004, DEC-509).
    window.set_monitoring_state(crate::lingua::schermo(view.state_label()));
    window.set_monitoring_state_code(state_code(view.state));
    window.set_monitoring_health(crate::lingua::schermo(view.health.label()));
    window.set_monitoring_health_attention(view.health.is_attention());
    window.set_monitoring_started_by(SharedString::from(view.started_by.as_str()));
    window.set_monitoring_created(SharedString::from(view.created_at.to_readable_local()));
    window.set_monitoring_started(SharedString::from(
        view.started_at
            .map(lisi_core::Timestamp::to_readable_local)
            .unwrap_or_default(),
    ));
    window.set_monitoring_ended(SharedString::from(
        view.ended_at
            .map(lisi_core::Timestamp::to_readable_local)
            .unwrap_or_default(),
    ));
    window.set_monitoring_duration(SharedString::from(duration_label(view.duration)));
    window.set_monitoring_planned_end(SharedString::from(planned_end_label(
        view.started_at,
        view.duration,
    )));
    window.set_monitoring_schedule(SharedString::from(schedule_sentence(view)));
    window.set_monitoring_pause(SharedString::from(pause_sentence(view)));
    window.set_monitoring_can_pause_acquisition(view.can_pause_acquisition);
    window.set_monitoring_can_resume_acquisition(view.can_resume_acquisition);
    window.set_monitoring_checkpoint(SharedString::from(
        view.last_checkpoint
            .map(lisi_core::Timestamp::to_readable_local)
            .unwrap_or_default(),
    ));

    window.set_monitoring_source_count(count(view.source_count));
    window.set_monitoring_contents(count(view.contents_total));
    window.set_monitoring_alerts(count(view.alerts_total));
    window.set_monitoring_pending(count(view.pending_review));
    window.set_monitoring_inbox_pending(count(view.inbox_pending));
    window.set_monitoring_inbox_failed(count(view.inbox_failed));

    window.set_monitoring_can_start(view.allows(MonitoringAction::Start));
    window.set_monitoring_can_suspend(view.allows(MonitoringAction::SuspendAlerts));
    window.set_monitoring_can_resume(view.allows(MonitoringAction::Resume));
    window.set_monitoring_can_stop(view.allows(MonitoringAction::Stop));
}

/// Che cosa dire della pausa dell'acquisizione (PAUSE-01, ADR-0172): quella
/// aperta, con chi e perché, oppure l'ultima chiusa, con il periodo non
/// coperto. Vuota se il monitoraggio non è mai stato in pausa.
fn pause_sentence(view: &MonitoringView) -> String {
    if let Some(aperta) = view.pauses.iter().find(|pausa| pausa.is_open()) {
        return format!(
            "Acquisizione in pausa dal {}, decisa da {}: «{}». I contenuti di questo periodo \
             non vengono acquisiti.",
            aperta.paused_at.to_readable_local(),
            aperta.paused_by.as_str(),
            aperta.reason.as_str()
        );
    }
    view.pauses
        .last()
        .and_then(|ultima| ultima.resumed_at.map(|ripresa| (ultima.paused_at, ripresa)))
        .map_or_else(String::new, |(da, a)| {
            format!(
                "Ultima pausa dal {} al {}: periodo non coperto. I suoi contenuti si possono \
                 cercare più sotto, con il recupero della cronologia.",
                da.to_readable_local(),
                a.to_readable_local()
            )
        })
}

/// Che cosa dire dell'inizio programmato (SCHEDULE-01, ADR-0171): quando
/// parte, che è partito, che è mancato e perché, o che è stato annullato.
/// Vuota se il monitoraggio non è stato programmato.
fn schedule_sentence(view: &MonitoringView) -> String {
    let Some(inizio) = view.schedule.as_ref() else {
        return String::new();
    };
    let quando = inizio.start_at.to_readable_local();
    if let Some(mancato) = inizio.missed {
        let mut frase = format!(
            "Avvio programmato per {quando} non avvenuto: {}.",
            mancato.reason.sentence()
        );
        if view.state == SessionState::Planned {
            frase.push_str(
                " Il programma non lo avvia più da sé: si può avviare a mano, o arrestarlo per \
                 annullarlo.",
            );
        }
        return frase;
    }
    match (view.state, view.started_at) {
        (SessionState::Planned, _) => format!(
            "Parte da sé il {quando}, se il programma è aperto e l'account collegato. \
             Programmato da {}.",
            inizio.scheduled_by.as_str()
        ),
        (_, None) => format!("Annullato prima dell'inizio programmato per {quando}."),
        (_, Some(_)) => format!("Avviato come programmato: inizio previsto {quando}."),
    }
}

/// Lo stato del monitoraggio mostrato, come lo legge il disegno (SIM3-15):
/// 0 pianificato, 1 in corso, 2 in corso con gli avvisi sospesi, 3 concluso.
const fn state_code(state: SessionState) -> i32 {
    match state {
        SessionState::Running => 1,
        SessionState::Paused => 2,
        SessionState::Planned => 0,
        SessionState::Completed | SessionState::Stopped => 3,
    }
}

/// Converte un conteggio nel tipo dell'interfaccia, saturando se enorme.
fn count(value: usize) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

/// Annuncia sul live condiviso l'avvio o la fine di un monitoraggio, se questa
/// postazione fa da Hub (FINAL-REVIEW-01, FR-051).
///
/// La schermata «Live condiviso» promette di mostrare «quali monitoraggi sono
/// partiti» (ADR-0093), e le due pubblicazioni esistevano senza chiamanti. Il
/// soggetto è il nome del monitoraggio, mai un contenuto. Un guasto qui non
/// ferma il monitoraggio: il live è ciò che gli altri vedono, l'archivio è ciò
/// che resta.
fn annuncia_sul_live(avviato: bool, nome: &str, istante: lisi_core::Timestamp) {
    if !crate::team_live::questa_postazione_e_un_hub() {
        return;
    }
    let Some(database) = crate::StorageFallback::new().open() else {
        return;
    };
    let mut live = lisi_services::hub_live::HubLivePublisher::new(database);
    let esito = if avviato {
        live.publish_monitoring_started(nome, "monitoraggio avviato", istante)
    } else {
        live.publish_monitoring_stopped(nome, "monitoraggio concluso", istante)
    };
    if let Err(errore) = esito {
        tracing::warn!(
            errore = errore.kind(),
            "il monitoraggio non e' stato annunciato sul live condiviso"
        );
    }
}

/// Se il motivo scritto basta per una pausa (COLLAUDO-FIX-01, CU01-005).
///
/// La regola è quella del dominio, `OperationalReason`, e non una sua copia:
/// il pulsante si accende esattamente quando il servizio accetterebbe.
fn motivo_della_pausa_basta(scritto: &str) -> bool {
    lisi_core::model::reason::OperationalReason::try_new(scritto).is_ok()
}

/// La frase accanto al campo del motivo, mentre si scrive (CU01-005).
///
/// Vuota quando il campo è vuoto, perché un campo appena aperto non è un
/// errore, e quando il motivo basta. Altrimenti dice quanti caratteri
/// mancano, contati come li conta il dominio: senza gli spazi ai bordi, così
/// un campo di soli spazi ne chiede venti.
fn suggerimento_del_motivo(scritto: &str) -> String {
    use lisi_core::model::reason::{MAX_REASON_CHARS, MIN_REASON_CHARS};

    let scritti = scritto.trim().chars().count();
    if scritto.is_empty() || motivo_della_pausa_basta(scritto) {
        return String::new();
    }
    if scritti > MAX_REASON_CHARS {
        // Il numero è quello di `MAX_REASON_CHARS`: una prova li tiene uguali.
        return String::from("Il motivo è troppo lungo: al massimo 500 caratteri.");
    }
    match MIN_REASON_CHARS.saturating_sub(scritti) {
        1 => String::from("Il motivo è corto: manca ancora 1 carattere."),
        mancano => format!("Il motivo è corto: mancano ancora {mancano} caratteri."),
    }
}

/// Mette in pausa l'acquisizione del monitoraggio mostrato, con il motivo, o
/// la riprende se il motivo manca (PAUSE-01, ADR-0172).
fn pause_or_resume(monitoring: &SharedMonitoring, motivo: Option<&str>) -> String {
    let service = monitoring.borrow();
    let vista = match selected_session() {
        Some(scelto) => service.view(scelto).map(Some),
        None => service.latest_view(),
    };
    let session_id = match vista {
        Ok(Some(view)) => view.session_id,
        Ok(None) => return String::from("Nessun monitoraggio da comandare."),
        Err(error) => return error.operator_message(),
    };
    drop(service);

    let esito = match motivo {
        Some(scritto) => {
            let Ok(motivo) = lisi_core::model::reason::OperationalReason::try_new(scritto) else {
                return String::from(
                    "Scrivere perché la pausa, in almeno 20 caratteri: resta accanto al periodo \
                     non coperto.",
                );
            };
            actor().and_then(|actor| {
                monitoring
                    .borrow_mut()
                    .pause_acquisition(session_id, &actor, &motivo, now())
            })
        }
        None => actor().and_then(|actor| {
            monitoring
                .borrow_mut()
                .resume_acquisition(session_id, &actor, now())
        }),
    };
    match (esito, motivo.is_some()) {
        (Ok(()), true) => String::from(
            "Acquisizione in pausa: il periodo da adesso resta non coperto finché non si riprende.",
        ),
        (Ok(()), false) => String::from("Acquisizione ripresa."),
        (Err(error), _) => describe(&error),
    }
}

/// Esegue un'azione sul monitoraggio più recente e riporta la risposta.
fn perform(monitoring: &SharedMonitoring, action: &str) -> String {
    let Some(action) = MonitoringAction::from_identifier(action) else {
        tracing::error!(azione = action, "azione di monitoraggio non riconosciuta");
        return String::from("Comando non riconosciuto: segnalarlo all'assistenza.");
    };

    let service = monitoring.borrow();
    // IL COMANDO VALE PER IL MONITORAGGIO MOSTRATO (MFX01-B). Fino al
    // 2026-10-17 si leggeva sempre l'ultimo avviato: con due monitoraggi,
    // «Arresta» premuto sul primo, scelto dall'elenco, arrestava il secondo.
    let vista = match selected_session() {
        Some(scelto) => service.view(scelto).map(Some),
        None => service.latest_view(),
    };
    let (session_id, nome) = match vista {
        Ok(Some(view)) => (view.session_id, view.label),
        Ok(None) => return String::from("Nessun monitoraggio da comandare."),
        Err(error) => return error.operator_message(),
    };
    drop(service);

    let outcome = actor().and_then(|actor| {
        monitoring
            .borrow_mut()
            .perform(session_id, action, &actor, now())
    });

    if outcome.is_ok() && action == MonitoringAction::Stop {
        annuncia_sul_live(false, &nome, now());
    }

    match outcome {
        Ok(()) => String::from(action_done(action)),
        Err(error) => describe(&error),
    }
}

/// Che cosa è cambiato, detto per esteso (UX-EXCELLENCE-02, SIM3-11).
///
/// Era «Sospendi avvisi: fatto.»: il nome del comando seguito da un timbro.
/// La frase dice ora lo stato in cui il monitoraggio si trova, e per la
/// sospensione che cosa continua.
pub const fn action_done(action: MonitoringAction) -> &'static str {
    match action {
        MonitoringAction::Start => "Monitoraggio avviato.",
        MonitoringAction::SuspendAlerts => {
            "Avvisi sospesi: la raccolta continua, ma non arrivano notifiche finché non si \
             riprendono."
        }
        MonitoringAction::Resume => "Avvisi ripresi: le notifiche tornano ad arrivare.",
        MonitoringAction::Stop => {
            "Monitoraggio arrestato. Ciò che ha già raccolto resta nello Storico."
        }
    }
}

/// Traduce un errore del servizio in un messaggio per l'operatore.
fn describe(error: &ServiceError) -> String {
    tracing::warn!(kind = error.kind(), "azione di monitoraggio non riuscita");
    error.operator_message()
}

/// Avvia un monitoraggio dalla composizione del wizard.
///
/// Legge fonti, durata e configurazione risolta dalla composizione, crea la
/// sessione e la porta in corso. Il nome è generato dall'istante: un
/// monitoraggio si riconosce da quando è stato avviato.
fn start_from_wizard(
    monitoring: &SharedMonitoring,
    wizard: &SharedWizard,
    accounts: Option<&crate::account::SharedSession>,
) -> String {
    let composition = wizard.borrow();
    let sources = composition.sources().to_vec();
    if sources.is_empty() {
        return String::from("Scegliere almeno una fonte prima di avviare.");
    }
    let duration = composition.duration();
    // QUANDO PARTE (SCHEDULE-01, ADR-0171): adesso, o all'istante scelto.
    let start = composition.start();
    // La configurazione risolta e' quella calcolata al riepilogo: e' la
    // fotografia con cui il monitoraggio analizzera' i contenuti.
    let configuration = composition.preview().cloned();
    // E CHE COSA È STATO SCELTO (FINAL-REVIEW-01, FR-049): le versioni che il
    // riepilogo ha fotografato e le parole aggiunte. La relazione le dichiara.
    let choice = lisi_services::monitoring::DictionaryChoice {
        versions: composition
            .selected_dictionaries()
            .unwrap_or_default()
            .iter()
            .map(|scelto| (scelto.id, scelto.version_id))
            .collect(),
        custom_terms: composition.selection().ad_hoc_terms,
    };
    drop(composition);

    let instant = now();
    // Il nome dice quando il monitoraggio parte: adesso, o all'inizio scelto.
    let partenza = match start {
        WizardStart::Now => instant,
        WizardStart::At(inizio) => inizio,
    };
    let Ok(label) = lisi_core::text::DisplayName::try_new(&format!(
        "Monitoraggio del {}",
        partenza.to_label_local()
    )) else {
        return String::from("Nome del monitoraggio non valido.");
    };
    let label_testo = String::from(label.as_str());
    // CON QUALE ACCOUNT (MULTI-ACCOUNT-02, ADR-0173, decisione 3): quello
    // selezionato, se aperto. Il monitoraggio riceverà soltanto ciò che arriva
    // a quell'account; senza, riceverà soltanto con un account solo aperto.
    let legame = accounts.and_then(|sessione| sessione.borrow().binding_for_new_monitoring());

    if let WizardStart::At(inizio) = start {
        // Programmato: nasce pianificato e parte da sé all'ora detta, dal
        // giro che conclude le durate. Si annuncia sul live quando parte.
        let outcome = actor().and_then(|actor| {
            monitoring.borrow_mut().schedule_on(
                legame.as_ref(),
                label,
                &actor,
                duration,
                &sources,
                configuration.as_ref(),
                &choice,
                inizio,
                instant,
            )
        });
        return match outcome {
            Ok(_) => String::from(MONITORAGGIO_PROGRAMMATO),
            Err(error) => describe(&error),
        };
    }

    let outcome = actor().and_then(|actor| {
        monitoring.borrow_mut().begin_on(
            legame.as_ref(),
            label,
            &actor,
            duration,
            &sources,
            configuration.as_ref(),
            &choice,
            instant,
        )
    });

    if outcome.is_ok() {
        annuncia_sul_live(true, label_testo.as_str(), instant);
    }

    match outcome {
        Ok(_) => String::from("Monitoraggio avviato."),
        Err(error) => describe(&error),
    }
}

/// Collega il controllo del motivo della pausa, mentre si scrive (CU01-005).
///
/// A sé perché non tocca il servizio: la prova della schermata lo collega da
/// sola, senza archivio.
fn wire_pause_reason(window: &AppWindow) {
    window.on_monitoring_pause_reason_ok(|scritto| motivo_della_pausa_basta(&scritto));
    window.on_monitoring_pause_reason_hint(|scritto| {
        crate::lingua::schermo(suggerimento_del_motivo(&scritto))
    });
}

/// Collega i comandi della schermata al servizio.
///
/// Riceve anche la composizione del wizard perché l'avvio parte da lì: è il
/// wizard a comporre le fonti e i termini, e il monitoraggio a metterli in
/// corso.
pub fn wire(
    window: &AppWindow,
    monitoring: &SharedMonitoring,
    wizard: &SharedWizard,
    accounts: Option<&crate::account::SharedSession>,
) {
    {
        let handle = window.as_weak();
        let monitoring = Rc::clone(monitoring);
        window.on_monitoring_shown(move || {
            if let Some(window) = handle.upgrade() {
                window.set_monitoring_pause_outcome(SharedString::default());
                refresh(&window, &monitoring, Some(""));
            }
        });
    }

    {
        let handle = window.as_weak();
        let monitoring = Rc::clone(monitoring);
        window.on_select_monitoring(move |index| {
            if crate::lock::refuse_while_locked("select_monitoring") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                // L'esito della pausa era di un altro monitoraggio (CU01-005).
                window.set_monitoring_pause_outcome(SharedString::default());
                select(&window, &monitoring, index);
            }
        });
    }

    {
        let handle = window.as_weak();
        let monitoring = Rc::clone(monitoring);
        window.on_monitoring_action(move |action| {
            if crate::lock::refuse_while_locked("monitoring_action") {
                return;
            }
            // Un prerequisito della fascia di prontezza puo' essere cambiato (F-08).
            crate::preflight::mark_stale();
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = perform(&monitoring, action.as_str());
            refresh(&window, &monitoring, Some(&message));
        });
    }

    wire_pause_reason(window);

    {
        // LA PAUSA VERA (PAUSE-01, ADR-0172): con il motivo, che resta accanto
        // al periodo non coperto. Riuscita, il campo si svuota; rifiutata, il
        // testo resta e l'esito si legge accanto ai comandi (CU01-005).
        let handle = window.as_weak();
        let monitoring = Rc::clone(monitoring);
        window.on_monitoring_pause_acquisition(move |motivo| {
            if crate::lock::refuse_while_locked("monitoring_pause_acquisition") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = pause_or_resume(&monitoring, Some(motivo.as_str()));
            if message.starts_with("Acquisizione in pausa") {
                window.set_monitoring_pause_reason(SharedString::default());
            }
            window.set_monitoring_pause_outcome(crate::lingua::schermo(&message));
            refresh(&window, &monitoring, Some(&message));
        });
    }

    {
        let handle = window.as_weak();
        let monitoring = Rc::clone(monitoring);
        window.on_monitoring_resume_acquisition(move || {
            if crate::lock::refuse_while_locked("monitoring_resume_acquisition") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = pause_or_resume(&monitoring, None);
            window.set_monitoring_pause_outcome(crate::lingua::schermo(&message));
            refresh(&window, &monitoring, Some(&message));
        });
    }

    {
        let handle = window.as_weak();
        let monitoring = Rc::clone(monitoring);
        let wizard = Rc::clone(wizard);
        let accounts = accounts.map(Rc::clone);
        window.on_start_monitoring(move || {
            if crate::lock::refuse_while_locked("start_monitoring") {
                return;
            }
            // Un prerequisito della fascia di prontezza puo' essere cambiato (F-08).
            crate::preflight::mark_stale();
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = start_from_wizard(&monitoring, &wizard, accounts.as_ref());
            // Avviato: si va alla schermata Monitoraggio, dove il nuovo
            // monitoraggio compare con il suo stato e i suoi comandi.
            if message == "Monitoraggio avviato." || message == MONITORAGGIO_PROGRAMMATO {
                // E LA PROCEDURA RICOMINCIA VUOTA (UX-EXCELLENCE-02, SIM3-07).
                //
                // Riaprendo «Nuovo monitoraggio» si ritrovava il passo 6, «La
                // configurazione è pronta», con «Avvia monitoraggio» attivo e
                // le fonti di prima: un secondo clic avviava un doppione. Un
                // monitoraggio avviato chiude la sua composizione; chi vuole
                // ripartire dalle stesse scelte lo fa dichiaratamente, da
                // «Modelli».
                *wizard.borrow_mut() = MonitoringWizard::new();
                window.set_wizard_message(SharedString::default());
                // La nota del modello apparteneva a quella composizione.
                window.set_wizard_template_note(SharedString::default());
                window.set_current_page(MONITORING_PAGE);
            }
            refresh(&window, &monitoring, Some(&message));
        });
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::SessionDuration;

    use super::{MONITORING_PAGE, duration_label};

    /// **Accanto al campo, quanti caratteri mancano; niente se il campo è vuoto
    /// o se il motivo basta** (COLLAUDO-FIX-01, CU01-005).
    #[test]
    fn il_motivo_della_pausa_dice_quanti_caratteri_mancano() {
        use super::{motivo_della_pausa_basta, suggerimento_del_motivo};

        assert_eq!(suggerimento_del_motivo(""), "");
        assert_eq!(
            suggerimento_del_motivo("del collaudo"),
            "Il motivo è corto: mancano ancora 8 caratteri."
        );
        assert_eq!(
            suggerimento_del_motivo("riunione d'ufficio "),
            "Il motivo è corto: mancano ancora 2 caratteri.",
            "gli spazi ai bordi non contano"
        );
        assert_eq!(
            suggerimento_del_motivo("riunione dell'ufficio"),
            "",
            "ventun caratteri bastano"
        );
        assert_eq!(
            suggerimento_del_motivo("riunione d'ufficio."),
            "Il motivo è corto: manca ancora 1 carattere."
        );
        assert_eq!(
            suggerimento_del_motivo("   "),
            "Il motivo è corto: mancano ancora 20 caratteri."
        );
        assert_eq!(
            suggerimento_del_motivo(&"x".repeat(501)),
            "Il motivo è troppo lungo: al massimo 500 caratteri."
        );
        assert_eq!(
            lisi_core::model::reason::MAX_REASON_CHARS,
            500,
            "la frase dice 500"
        );

        // La regola è quella del dominio, ai due lati della soglia.
        assert!(!motivo_della_pausa_basta(&"è".repeat(19)));
        assert!(motivo_della_pausa_basta(&"è".repeat(20)));
        assert!(!motivo_della_pausa_basta(&format!(
            "  {}  ",
            "x".repeat(19)
        )));
    }

    /// Una finestra di prova sulla sezione della pausa, con il controllo del
    /// motivo collegato e un registro dei comandi arrivati.
    fn finestra_della_pausa() -> (
        crate::AppWindow,
        std::rc::Rc<std::cell::RefCell<Vec<String>>>,
    ) {
        use slint::ComponentHandle;

        i_slint_backend_testing::init_no_event_loop();
        let Ok(window) = crate::AppWindow::new() else {
            panic!("la finestra di prova deve potersi costruire");
        };
        if slint::select_bundled_translation("").is_err() {
            panic!("la lingua di partenza deve potersi scegliere");
        }
        window
            .window()
            .set_size(slint::LogicalSize::new(1366.0, 1040.0));
        if window.show().is_err() {
            panic!("la finestra di prova deve potersi mostrare");
        }
        super::wire_pause_reason(&window);
        let registro = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        {
            let registro = std::rc::Rc::clone(&registro);
            window.on_monitoring_pause_acquisition(move |motivo| {
                registro.borrow_mut().push(motivo.to_string());
            });
        }
        window.set_monitoring_present(true);
        window.set_monitoring_can_pause_acquisition(true);
        window.invoke_open_page(MONITORING_PAGE);
        (window, registro)
    }

    /// **Con un motivo corto il comando della pausa è spento e non parte; la
    /// frase accanto al campo dice perché** (COLLAUDO-FIX-01, CU01-005, UX-07).
    ///
    /// Vista rossa con il pulsante acceso dalla sola `monitoring-can-pause-
    /// acquisition`, com'era nella 0.2.2: con dodici caratteri il comando
    /// partiva, e il rifiuto si leggeva soltanto in cima alla schermata.
    #[test]
    fn un_motivo_corto_non_mette_in_pausa() {
        use i_slint_backend_testing::ElementHandle;

        const SPENTO: &str = "Metti in pausa l'acquisizione. Scrivere prima perché la pausa, in almeno 20 caratteri.";
        const ACCESO: &str = "Metti in pausa l'acquisizione";

        let (window, registro) = finestra_della_pausa();
        window.set_monitoring_pause_reason("del collaudo".into());

        // Che cosa la finestra espone sulla pausa: serve a leggere un fallimento.
        let sulla_pausa = |window: &crate::AppWindow| -> Vec<String> {
            use i_slint_backend_testing::ElementRoot;
            window
                .root_element()
                .query_descendants()
                .match_predicate(|e| e.accessible_label().is_some_and(|l| l.contains("pausa")))
                .find_all()
                .iter()
                .filter_map(ElementHandle::accessible_label)
                .map(|l| l.to_string())
                .collect()
        };
        let spenti: Vec<ElementHandle> =
            ElementHandle::find_by_accessible_label(&window, SPENTO).collect();
        let Some(pulsante) = spenti.first() else {
            panic!(
                "con un motivo corto il pulsante deve dire perché è spento; sulla pausa: {:#?}",
                sulla_pausa(&window)
            );
        };
        assert_eq!(pulsante.accessible_enabled(), Some(false));
        pulsante.invoke_accessible_default_action();
        assert!(
            registro.borrow().is_empty(),
            "partito: {:?}",
            registro.borrow()
        );
        assert_eq!(
            ElementHandle::find_by_accessible_label(&window, ACCESO)
                .filter(|e| e.accessible_role()
                    == Some(i_slint_backend_testing::AccessibleRole::Button))
                .count(),
            0,
            "spento, il nome del pulsante non può essere quello del comando pronto"
        );
        assert_eq!(
            ElementHandle::find_by_accessible_label(
                &window,
                "Il motivo è corto: mancano ancora 8 caratteri."
            )
            .count(),
            1,
            "la frase accanto al campo deve dire quanti caratteri mancano"
        );

        // Il testo scritto resta: non si perde con il rifiuto.
        assert_eq!(window.get_monitoring_pause_reason(), "del collaudo");

        // Con il motivo che basta, il comando si accende e parte una volta.
        window.set_monitoring_pause_reason("del collaudo: verifica della pausa".into());
        let accesi: Vec<ElementHandle> = ElementHandle::find_by_accessible_label(&window, ACCESO)
            .filter(|e| {
                e.accessible_role() == Some(i_slint_backend_testing::AccessibleRole::Button)
            })
            .collect();
        let Some(pulsante) = accesi.first() else {
            panic!("con un motivo che basta il pulsante deve chiamarsi come il comando");
        };
        assert_eq!(pulsante.accessible_enabled(), Some(true));
        pulsante.invoke_accessible_default_action();
        assert_eq!(
            *registro.borrow(),
            vec!["del collaudo: verifica della pausa"]
        );
    }

    /// Interfaccia, letta a tempo di compilazione per il controllo qui sotto.
    const UI: &str = include_str!("../ui/app-window.slint");

    /// Una vista con lo stato, l'avvio e l'inizio programmato indicati.
    fn vista(
        state: lisi_core::model::SessionState,
        started_at: Option<lisi_core::Timestamp>,
        schedule: Option<lisi_core::model::schedule::ScheduledStart>,
    ) -> lisi_services::monitoring::MonitoringView {
        lisi_services::monitoring::MonitoringView {
            session_id: lisi_core::SessionId::new(1),
            label: String::from("Programmato"),
            state,
            health: lisi_services::monitoring::HealthState::NotStarted,
            started_by: String::from("operatore.prova"),
            created_at: lisi_core::Timestamp::from_millis(0),
            started_at,
            ended_at: None,
            duration: SessionDuration::Manual,
            source_count: 1,
            contents_total: 0,
            alerts_total: 0,
            pending_review: 0,
            inbox_pending: 0,
            inbox_failed: 0,
            last_checkpoint: None,
            permitted: Vec::new(),
            schedule,
            pauses: Vec::new(),
            can_pause_acquisition: false,
            can_resume_acquisition: false,
        }
    }

    /// **La scheda dice la pausa aperta, con chi e perché, o l'ultima chiusa,
    /// con il periodo non coperto** (PAUSE-01, ADR-0172, criterio 5).
    #[test]
    fn la_scheda_dice_la_pausa() {
        use lisi_core::model::SessionState;
        use lisi_core::model::acquisition_pause::AcquisitionPause;

        let (Ok(chi), Ok(motivo)) = (
            lisi_core::text::Actor::try_new("operatore.prova"),
            lisi_core::model::reason::OperationalReason::try_new("Riunione d'ufficio fino alle 15"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let pausa = |ripresa: Option<i64>| AcquisitionPause {
            session_id: lisi_core::SessionId::new(1),
            paused_at: lisi_core::Timestamp::from_millis(1_800_000_000_000),
            paused_by: chi.clone(),
            reason: motivo.clone(),
            resumed_at: ripresa.map(lisi_core::Timestamp::from_millis),
            resumed_by: ripresa.map(|_| chi.clone()),
        };
        let avviato = Some(lisi_core::Timestamp::from_millis(1_799_999_000_000));
        let mut vista_aperta = vista(SessionState::Running, avviato, None);
        assert_eq!(super::pause_sentence(&vista_aperta), "");
        vista_aperta.pauses = vec![pausa(None)];
        let frase = super::pause_sentence(&vista_aperta);
        assert!(frase.starts_with("Acquisizione in pausa dal "), "{frase}");
        assert!(frase.contains("Riunione d'ufficio"), "{frase}");
        vista_aperta.pauses = vec![pausa(Some(1_800_000_600_000))];
        let frase = super::pause_sentence(&vista_aperta);
        assert!(frase.starts_with("Ultima pausa dal "), "{frase}");
        assert!(frase.contains("non coperto"), "{frase}");
    }

    /// **La scheda dice quando parte, che è partito, che è mancato e perché,
    /// o che è stato annullato** (SCHEDULE-01, ADR-0171, criterio 5).
    #[test]
    fn la_scheda_dice_che_cosa_e_dell_inizio_programmato() {
        use lisi_core::model::SessionState;
        use lisi_core::model::schedule::{MissedStart, MissedStartReason, ScheduledStart};

        let Ok(chi) = lisi_core::text::Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        let inizio = |missed: Option<MissedStart>| ScheduledStart {
            session_id: lisi_core::SessionId::new(1),
            start_at: lisi_core::Timestamp::from_millis(1_800_000_000_000),
            scheduled_by: chi.clone(),
            scheduled_at: lisi_core::Timestamp::from_millis(1_799_999_000_000),
            missed,
        };
        let mancato = Some(MissedStart {
            at: lisi_core::Timestamp::from_millis(1_800_000_090_000),
            reason: MissedStartReason::ProgramClosed,
        });
        let avviato = Some(lisi_core::Timestamp::from_millis(1_800_000_000_000));

        assert_eq!(
            super::schedule_sentence(&vista(SessionState::Running, avviato, None)),
            ""
        );
        let frase =
            super::schedule_sentence(&vista(SessionState::Planned, None, Some(inizio(None))));
        assert!(frase.starts_with("Parte da sé il "), "{frase}");
        assert!(frase.contains("operatore.prova"), "{frase}");
        let frase =
            super::schedule_sentence(&vista(SessionState::Planned, None, Some(inizio(mancato))));
        assert!(frase.contains("il programma era chiuso"), "{frase}");
        assert!(frase.contains("non lo avvia più da sé"), "{frase}");
        let frase = super::schedule_sentence(&vista(
            SessionState::Running,
            avviato,
            Some(inizio(mancato)),
        ));
        assert!(
            !frase.contains("non lo avvia più"),
            "avviato poi a mano: {frase}"
        );
        let frase =
            super::schedule_sentence(&vista(SessionState::Running, avviato, Some(inizio(None))));
        assert!(frase.starts_with("Avviato come programmato"), "{frase}");
        let frase =
            super::schedule_sentence(&vista(SessionState::Stopped, None, Some(inizio(None))));
        assert!(frase.starts_with("Annullato prima dell'inizio"), "{frase}");
    }

    /// **L'avvio dal wizard porta con sé le versioni dei dizionari scelti**
    /// (FINAL-REVIEW-01, FR-049). La prova funzionale sta in
    /// `lisi-services/tests/dizionari_in_vigore.rs`; questa guardia dice che la
    /// schermata le passa davvero.
    #[test]
    fn the_wizard_start_passes_the_dictionary_choice() {
        const QUESTO_FILE: &str = include_str!("monitoring.rs");
        let Some((_, corpo)) = QUESTO_FILE.split_once("fn start_from_wizard(") else {
            panic!("l'avvio dal wizard deve esistere");
        };
        let Some((corpo, _)) = corpo.split_once("\n}\n") else {
            panic!("l'avvio dal wizard deve finire");
        };
        assert!(corpo.contains(".selected_dictionaries()"));
        assert!(corpo.contains("custom_terms: composition.selection().ad_hoc_terms"));
        assert!(corpo.contains("&choice,"));
    }

    /// **L'avvio e la fine di un monitoraggio si annunciano sul live
    /// condiviso** (FINAL-REVIEW-01, FR-051): le due pubblicazioni esistevano
    /// senza chiamanti, e la schermata prometteva di mostrarle.
    #[test]
    fn start_and_stop_are_announced_on_the_shared_live() {
        const QUESTO_FILE: &str = include_str!("monitoring.rs");
        let Some((produzione, _)) = QUESTO_FILE.split_once("#[cfg(test)]") else {
            panic!("il modulo deve avere le sue prove");
        };
        assert!(produzione.contains("annuncia_sul_live(true, label_testo.as_str(), instant);"));
        assert!(produzione.contains("annuncia_sul_live(false, &nome, now());"));
        assert!(produzione.contains("live.publish_monitoring_started("));
        assert!(produzione.contains("live.publish_monitoring_stopped("));
    }

    #[test]
    fn the_monitoring_page_index_matches_the_interface() {
        // L'indice e' condiviso con il file .slint: se cambia in un posto solo,
        // il comando «Avvia monitoraggio» porterebbe alla pagina sbagliata.
        // Verificare solo la costante Rust non basta — un rinumero delle pagine
        // nello .slint lascerebbe il test verde e la navigazione rotta. Quindi
        // si legge l'interfaccia e si controlla che la pagina esista davvero
        // con quell'indice.
        assert_eq!(MONITORING_PAGE, 9);

        let page = format!("current-page == {MONITORING_PAGE}: Rectangle");
        assert!(
            UI.contains(&page),
            "la pagina Monitoraggio con indice {MONITORING_PAGE} non e' nell'interfaccia: \
             se le pagine sono state rinumerate, aggiornare MONITORING_PAGE"
        );

        // E la voce di menu che vi naviga usa lo stesso indice.
        assert!(
            UI.contains(&format!("root.open-page({MONITORING_PAGE});")),
            "la voce di menu Monitoraggio non naviga all'indice {MONITORING_PAGE}"
        );
    }

    #[test]
    fn a_duration_is_rendered_readably() {
        assert_eq!(
            duration_label(SessionDuration::Preset { seconds: 3_600 }),
            "1 ora"
        );
        assert_eq!(
            duration_label(SessionDuration::Preset { seconds: 1_800 }),
            "30 minuti"
        );
        assert_eq!(
            duration_label(SessionDuration::Manual),
            "Fino all'arresto manuale"
        );
    }

    /// **La fine prevista è avvio + durata** (ADR-0150), e non c'è per
    /// l'arresto manuale né prima dell'avvio.
    #[test]
    fn la_fine_prevista_e_avvio_piu_durata() {
        use super::planned_end_label;
        let avvio = lisi_core::Timestamp::from_millis(1_760_000_000_000);
        let durata = SessionDuration::Custom { seconds: 8_100 };
        assert_eq!(
            planned_end_label(Some(avvio), durata),
            lisi_core::Timestamp::from_millis(1_760_008_100_000).to_readable_local()
        );
        assert_eq!(planned_end_label(None, durata), "");
        assert_eq!(planned_end_label(Some(avvio), SessionDuration::Manual), "");
        assert_eq!(duration_label(durata), "2 ore e 15 minuti (personalizzata)");
    }
}

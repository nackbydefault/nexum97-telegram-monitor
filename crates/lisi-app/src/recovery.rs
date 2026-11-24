//! Collegamento fra i comandi di recupero e il servizio che li esegue.
//!
//! # Perché due comandi e non uno
//!
//! «Cerca cosa manca» **legge e non scrive**: dice quanti messaggi mancano
//! all'archivio dall'inizio del monitoraggio. «Recupera e archivia» è l'atto che
//! scrive, e avviene solo dopo che l'operatore ha visto il numero.
//!
//! È la scelta dell'ufficio — *«dire quanti ne mancano e chiedere conferma prima
//! di partire»* — e non è una formalità: su un canale attivo lasciato un fine
//! settimana un recupero silenzioso porterebbe in archivio migliaia di messaggi
//! che nessuno ha deciso di acquisire.
//!
//! # Perché la ricognizione resta in memoria
//!
//! Fra il «cerca» e il «conferma» i messaggi trovati stanno qui, non in
//! archivio: è precisamente ciò che rende il primo comando innocuo. Se
//! l'applicazione si chiude prima della conferma, non resta nulla — e va bene
//! così, perché nulla era stato deciso.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_core::SourceId;
use lisi_services::acquisition::{AcquisitionService, SessionContext};
use lisi_services::interval_recovery::{self, IntervalRecoveryRequest, IntervalSurvey};
use lisi_services::monitoring::MonitoringService;
use lisi_services::recovery::{self, RecoverySurvey, SurveyRun};
use lisi_services::retro_search::{RetroSearchOutcome, RetroSearchRun};
use lisi_services::source_history::{self, HistoryRequest, HistoryRun};
use lisi_services::{Database, ServiceError, ServiceResult};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::account::SharedSession;
use crate::{AppWindow, IntervalRow, PriorHistoryRow, RetroMatchEntry};

/// Servizi e stato del recupero.
pub struct RecoveryScreen {
    /// Applica ciò che il recupero trova, passando dall'inbox durevole.
    acquisition: AcquisitionService,
    /// Connessione propria, per sapere quale sessione sia in corso.
    ///
    /// Ogni servizio apre la sua: è l'idioma già usato dal resto
    /// dell'applicazione.
    monitoring: MonitoringService,
    /// Connessione propria, per sapere che cosa l'archivio già contiene.
    archive: Database,
    /// Ricognizione in corso, che il ciclo periodico fa avanzare di una fonte
    /// per volta.
    running: Option<SurveyRun>,
    /// Ciò che l'ultima ricognizione ha trovato, in attesa di conferma.
    pending: Option<RecoverySurvey>,
    /// Ricerca retroattiva in corso, anch'essa guidata dal ciclo periodico.
    searching: Option<RetroSearchRun>,
    /// Esito dell'ultima ricerca. Vive in memoria e basta: la ricerca **non
    /// archivia**, quindi non c'è nulla da conservare oltre la sessione di
    /// lavoro di chi l'ha chiesta.
    search_result: RetroSearchOutcome,
    /// Recupero di un periodo deciso (PR-07): la richiesta preparata, che il
    /// ciclo periodico esegue al giro successivo.
    interval_running: Option<IntervalRecoveryRequest>,
    /// Ciò che la ricognizione del periodo ha trovato, in attesa di conferma.
    interval_pending: Option<(IntervalRecoveryRequest, IntervalSurvey)>,
    /// Storico precedente all'avvio (PR-08): la lettura in corso, che il ciclo
    /// periodico fa avanzare di una pagina per giro.
    history_running: Option<HistoryRun>,
    /// La lettura finita, in attesa di conferma.
    history_pending: Option<HistoryRun>,
    /// La conferma è stata data: l'archiviazione si esegue al giro successivo
    /// del ciclo periodico, così la schermata dice prima che sta archiviando e
    /// i comandi si spengono (E2E01-08).
    history_applying: bool,
}

/// Schermata condivisa fra i gestori.
pub type SharedRecovery = Rc<RefCell<RecoveryScreen>>;

/// Crea la schermata sulle connessioni indicate.
#[must_use]
pub fn create_service(
    acquisition: Database,
    monitoring: Database,
    archive: Database,
) -> Option<SharedRecovery> {
    Some(Rc::new(RefCell::new(RecoveryScreen {
        acquisition: AcquisitionService::new(acquisition),
        monitoring: MonitoringService::new(monitoring),
        archive,
        running: None,
        pending: None,
        searching: None,
        search_result: RetroSearchOutcome::default(),
        interval_running: None,
        interval_pending: None,
        history_running: None,
        history_pending: None,
        history_applying: false,
    })))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// Contesto del monitoraggio **scelto**, con l'istante in cui è stato avviato.
///
/// Restituisce `None` quando non c'è alcun monitoraggio in corso: senza una
/// sessione non esiste un «inizio» fino a cui risalire, e recuperare fino a un
/// istante inventato riempirebbe l'archivio di ciò che nessuno ha chiesto di
/// sorvegliare.
///
/// # Perché quello scelto e non l'ultimo
///
/// Perché il recupero **archivia**, e con più monitoraggi in corso (ADR-0065)
/// recuperare su quello sbagliato porterebbe messaggi dentro il perimetro di una
/// decisione che non li aveva chiesti — e li porterebbe **con il nome di chi ha
/// avviato quell'altro monitoraggio**.
///
/// La scelta è quella della schermata del monitoraggio: **una sola**, perché due
/// modi di sapere «di quale monitoraggio stiamo parlando» divergono, e qui
/// divergerebbero verso l'archivio.
fn current_session(
    screen: &mut RecoveryScreen,
) -> ServiceResult<Option<(SessionContext, lisi_core::Timestamp)>> {
    let view = match crate::monitoring::selected_session() {
        Some(session_id) => Some(screen.monitoring.view(session_id)?),
        None => screen.monitoring.latest_view()?,
    };
    let Some(view) = view else {
        return Ok(None);
    };
    let Some(started_at) = view.started_at else {
        return Ok(None);
    };

    let actor = crate::operator::audit_actor()?;
    let context = screen.acquisition.load_context(view.session_id, actor)?;
    Ok(Some((context, started_at)))
}

/// Avvia la ricognizione. Non la esegue: la **prepara**.
///
/// La lettura vera avviene un passo alla volta in [`advance`], guidata dal ciclo
/// periodico. Farla tutta qui bloccherebbe l'interfaccia per tutto il tempo, e
/// nessun messaggio d'attesa comparirebbe — perché la schermata non si ridisegna
/// finché il comando non è tornato.
fn begin_survey(screen: &SharedRecovery) -> String {
    // In Esercitazione la frase dell'Esercitazione, non «account non
    // collegato» (CA02-06).
    if let Some(frase) = crate::account::exercise_refusal("«Cerca cosa manca»") {
        return frase;
    }
    let mut screen = screen.borrow_mut();

    let outcome = match current_session(&mut screen) {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            return String::from(
                "Nessun monitoraggio in corso: il recupero risale all'inizio del monitoraggio, \
                 e senza monitoraggio non c'è un inizio fino a cui risalire.",
            );
        }
        Err(error) => return describe(&error),
    };
    let (context, started_at) = outcome;

    // Una ricognizione nuova sostituisce quella in attesa: il numero mostrato
    // deve riferirsi a ciò che si sta leggendo adesso, non a una lettura
    // precedente rimasta appesa.
    screen.pending = None;
    let run = SurveyRun::new(&context, started_at);
    let message = run.progress_message();
    screen.running = Some(run);
    message
}

/// Fa avanzare la ricognizione di una fonte, se ce n'è una in corso.
///
/// Restituisce il messaggio da mostrare quando qualcosa è cambiato, e `None`
/// quando non c'era nulla da fare — così il ciclo periodico non riscrive la
/// schermata sessanta volte al secondo con lo stesso testo.
pub fn advance(screen: &SharedRecovery, session: &SharedSession) -> Option<String> {
    let mut screen = screen.borrow_mut();
    screen.running.as_ref()?;

    // La lettura passa dal connettore dell'account: senza collegamento non c'è
    // nulla da leggere, e la ricognizione si chiude dicendolo invece di restare
    // appesa a mostrare un avanzamento che non avanza.
    let mut session = session.borrow_mut();
    let Some(runtime) = session.runtime_mut() else {
        screen.running = None;
        return Some(String::from(
            "L'account non è collegato: la lettura della cronologia si è interrotta.",
        ));
    };

    // I due prestiti si prendono insieme dallo stesso `&mut`: l'archivio si
    // legge, la ricognizione si fa avanzare, e il compilatore non li accetta
    // presi uno dopo l'altro dalla struttura intera.
    let RecoveryScreen {
        archive, running, ..
    } = &mut *screen;
    let run = running.as_mut()?;

    if let Err(error) = run.step(runtime.connector_mut(), archive) {
        let message = describe(&error);
        screen.running = None;
        return Some(message);
    }

    if !run.is_finished() {
        return Some(run.progress_message());
    }

    let found = screen.running.take().map(SurveyRun::into_found)?;
    let message = found.operator_message();
    // Si conserva **solo** se c'è qualcosa da confermare: tenere da parte una
    // ricognizione vuota accenderebbe il comando che archivia per poi non
    // archiviare nulla.
    screen.pending = (!found.is_empty()).then_some(found);
    Some(message)
}

/// Prepara la ricerca retroattiva sulle fonti configurate.
///
/// Il perimetro sono le **fonti della sessione in corso**, ed è la risposta
/// data dall'ufficio: cercare in qualunque chat accessibile sarebbe uno
/// strumento diverso da questo.
fn begin_retro_search(screen: &SharedRecovery) -> String {
    if let Some(frase) = crate::account::exercise_refusal("«Cerca nel passato»") {
        return frase;
    }
    let mut screen = screen.borrow_mut();

    let outcome = match current_session(&mut screen) {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            return String::from(
                "Nessun monitoraggio in corso: la ricerca agisce sulle fonti del monitoraggio, \
                 e senza monitoraggio non ci sono fonti su cui cercare.",
            );
        }
        Err(error) => return describe(&error),
    };
    let (context, _) = outcome;

    let sources: Vec<(i64, SourceId)> = context.monitored_chats().collect();
    if sources.is_empty() {
        return String::from("Il monitoraggio non ha fonti configurate: non c'è dove cercare.");
    }

    // La configurazione è quella **conservata con la sessione**, non i dizionari
    // di adesso: cercare con termini diversi da quelli con cui il monitoraggio
    // sta giudicando darebbe due risposte diverse alla stessa domanda.
    let run = RetroSearchRun::new(&sources, context.configuration().clone(), None);
    let message = run.progress_message();
    screen.searching = Some(run);
    message
}

/// Fa avanzare la ricerca retroattiva di una fonte, se ce n'è una in corso.
pub fn advance_search(screen: &SharedRecovery, session: &SharedSession) -> Option<String> {
    let mut screen = screen.borrow_mut();
    screen.searching.as_ref()?;

    let mut session = session.borrow_mut();
    let Some(runtime) = session.runtime_mut() else {
        screen.searching = None;
        return Some(String::from(
            "L'account non è collegato: la ricerca si è interrotta.",
        ));
    };

    let run = screen.searching.as_mut()?;

    if let Err(error) = run.step(runtime.connector_mut()) {
        let message = describe(&error);
        screen.searching = None;
        return Some(message);
    }

    if !run.is_finished() {
        return Some(run.progress_message());
    }

    let found = screen.searching.take().map(RetroSearchRun::into_outcome)?;
    let message = found.operator_message();
    screen.search_result = found;
    Some(message)
}

/// Archivia ciò che la ricognizione ha trovato.
fn run_apply(screen: &SharedRecovery) -> String {
    let mut screen = screen.borrow_mut();

    let Some(found) = screen.pending.take() else {
        // Non può accadere — il comando esiste solo quando c'è qualcosa — ma
        // dirlo è meglio che archiviare il nulla in silenzio.
        return String::from("Non c'è alcuna ricognizione da confermare.");
    };

    let outcome = match current_session(&mut screen) {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            return String::from(
                "Il monitoraggio si è concluso nel frattempo: il recupero non è stato eseguito.",
            );
        }
        Err(error) => return describe(&error),
    };
    let (context, _) = outcome;

    // CHI LO CHIEDE si registra con l'operazione (PR-07, ADR-0123): un
    // recupero senza chi l'ha chiesto non si esegue.
    let Ok(operatore) = crate::operator::audit_actor() else {
        return String::from(
            "Non si riesce a stabilire chi stia agendo su questa postazione: il recupero non è \
             stato eseguito.",
        );
    };

    match recovery::apply(&found, &mut screen.acquisition, &context, &operatore, now()) {
        Ok(report) => {
            crate::freshness::mark();
            crate::acquisition::mark_recovered();
            format!(
                "Recupero eseguito: {} messaggi registrati come recuperati dalla cronologia.",
                report.applied
            )
        }
        Err(error) => describe(&error),
    }
}

/// Prepara la ricognizione di un periodo deciso. Non la esegue: la lettura
/// avviene al giro successivo del ciclo periodico, così la schermata dice
/// prima che sta leggendo.
///
/// # Decide soltanto su ciò che ritrova
///
/// I periodi si ricompongono adesso e si cerca quello con la stessa chiave: una
/// riga rimasta sullo schermo da una composizione vecchia non avvia nulla.
fn begin_interval(screen: &SharedRecovery, session: &SharedSession, chiave: &str) -> String {
    let mut screen = screen.borrow_mut();
    if screen.interval_running.is_some() || screen.interval_pending.is_some() {
        return String::from("C'è già un periodo in lettura o in attesa di conferma.");
    }
    let candidati = match interval_recovery::candidates(&screen.archive, now()) {
        Ok(candidati) => candidati,
        Err(error) => return describe(&error),
    };
    let Some(candidato) = candidati.iter().find(|candidato| candidato.key() == chiave) else {
        return String::from("Il periodo non è più fra quelli decisi: l'elenco è cambiato.");
    };
    if let Err(motivo) = &candidato.target {
        return String::from(*motivo);
    }
    let Ok(operatore) = crate::operator::audit_actor() else {
        return String::from(
            "Non si riesce a stabilire chi stia agendo su questa postazione: la lettura non parte.",
        );
    };
    // L'AUTORITÀ DI ACQUISIZIONE (ADR-0092): senza, la richiesta non esiste.
    // Una postazione che segue un Hub non la ottiene, e qui si ferma.
    let sessione = session.borrow();
    let Some(autorita) = sessione.authority() else {
        return sessione.refused("Il recupero");
    };
    let Some(richiesta) = IntervalRecoveryRequest::for_candidate(autorita, candidato, operatore)
    else {
        return String::from("Il periodo non ha un intervallo valido: la lettura non parte.");
    };
    screen.interval_running = Some(richiesta);
    format!(
        "Lettura in corso della cronologia di «{}» per il periodo scelto.",
        candidato.source_name
    )
}

/// Esegue la ricognizione del periodo preparata, se ce n'è una.
///
/// Una fonte e un intervallo: è la stessa misura di un passo della
/// ricognizione dall'inizio del monitoraggio, con lo stesso tetto di pagine.
pub fn advance_interval(screen: &SharedRecovery, session: &SharedSession) -> Option<String> {
    let mut screen = screen.borrow_mut();
    let richiesta = screen.interval_running.take()?;

    let mut session = session.borrow_mut();
    let Some(runtime) = session.runtime_mut() else {
        return Some(String::from(
            "L'account non è collegato: la lettura della cronologia non è partita.",
        ));
    };
    let trovato = interval_recovery::survey(runtime.connector_mut(), &screen.archive, &richiesta);
    let message = trovato.operator_message();
    // Si conserva **solo** se c'è qualcosa da archiviare: un periodo non
    // recuperabile, o in cui non manca nulla, non accende il comando che scrive.
    let da_archiviare = trovato.not_recoverable.is_none()
        && (!trovato.missing.is_empty() || !trovato.changed.is_empty());
    screen.interval_pending = da_archiviare.then_some((richiesta, trovato));
    Some(message)
}

/// Archivia ciò che la ricognizione del periodo ha trovato.
fn run_interval_apply(screen: &SharedRecovery) -> String {
    let mut screen = screen.borrow_mut();
    let Some((richiesta, trovato)) = screen.interval_pending.take() else {
        return String::from("Non c'è alcuna ricognizione da confermare.");
    };
    let attore = match crate::operator::audit_actor() {
        Ok(attore) => attore,
        Err(error) => return describe(&error),
    };
    let contesto = match screen
        .acquisition
        .load_context(richiesta.session_id(), attore)
    {
        Ok(contesto) => contesto,
        Err(error) => return describe(&error),
    };
    match interval_recovery::archive(
        &richiesta,
        &trovato,
        &mut screen.acquisition,
        &contesto,
        now(),
    ) {
        Ok(esito) => {
            crate::freshness::mark();
            crate::acquisition::mark_recovered();
            format!(
                "Recupero eseguito: {} messaggi archiviati come recuperati, {} versioni aggiunte a \
                 messaggi già in archivio. L'operazione è registrata con chi l'ha chiesta.",
                esito.archived, esito.new_versions
            )
        }
        Err(error) => describe(&error),
    }
}

/// Le righe dei periodi decisi, ricomposte adesso.
fn interval_rows(screen: &RecoveryScreen) -> Vec<IntervalRow> {
    match interval_recovery::candidates(&screen.archive, now()) {
        Ok(candidati) => candidati
            .iter()
            .map(|candidato| IntervalRow {
                source: SharedString::from(candidato.source_name.as_str()),
                sentence: crate::lingua::schermo(candidato.sentence()),
                recoverable: candidato.target.is_ok(),
                key: SharedString::from(candidato.key()),
            })
            .collect(),
        Err(error) => {
            tracing::warn!(kind = error.kind(), "periodi decisi non componibili");
            Vec::new()
        }
    }
}

/// Prepara la lettura dello storico di una fonte (PR-08). Non legge: la prima
/// pagina arriva al giro successivo del ciclo periodico.
///
/// # Vuole una ragione, e l'autorità
///
/// Senza una ragione operativa scritta la richiesta non esiste; senza
/// l'autorità di acquisizione nemmeno. Le righe si ricompongono adesso: una
/// rimasta sullo schermo da una composizione vecchia non avvia nulla.
fn begin_history(
    screen: &SharedRecovery,
    session: &SharedSession,
    chiave: &str,
    durata: i32,
    motivo: &str,
) -> String {
    let mut screen = screen.borrow_mut();
    if screen.history_running.is_some() || screen.history_pending.is_some() {
        return String::from("C'è già uno storico in lettura o in attesa di conferma.");
    }
    let Ok(ragione) = lisi_core::model::reason::OperationalReason::try_new(motivo) else {
        return String::from(
            "Serve una ragione operativa scritta: lo storico va oltre l'avvio del monitoraggio, e \
             chi lo rilegge deve sapere perché.",
        );
    };
    let Some(giorni) = usize::try_from(durata)
        .ok()
        .and_then(|indice| source_history::HISTORY_SPANS_DAYS.get(indice).copied())
    else {
        return String::from("Durata non riconosciuta: la lettura non parte.");
    };
    let righe = match source_history::targets(&screen.archive) {
        Ok(righe) => righe,
        Err(error) => return describe(&error),
    };
    let Some(riga) = righe.iter().find(|riga| riga.key() == chiave) else {
        return String::from(
            "La fonte non è più in un monitoraggio in corso: l'elenco è cambiato.",
        );
    };
    let Ok(operatore) = crate::operator::audit_actor() else {
        return String::from(
            "Non si riesce a stabilire chi stia agendo su questa postazione: la lettura non parte.",
        );
    };
    let sessione = session.borrow();
    let Some(autorita) = sessione.authority() else {
        return sessione.refused("La lettura dello storico della fonte");
    };
    let Some(richiesta) = HistoryRequest::new(autorita, riga, giorni, operatore, ragione) else {
        return String::from(source_history::NO_CHAT_IDENTIFIER);
    };
    match HistoryRun::new(&screen.archive, richiesta) {
        Ok(lettura) => {
            let frase = lettura.progress_message();
            screen.history_running = Some(lettura);
            frase
        }
        Err(error) => describe(&error),
    }
}

/// Fa avanzare lo storico di **una** pagina, se ce n'è uno in lettura.
pub fn advance_history(screen: &SharedRecovery, session: &SharedSession) -> Option<String> {
    let mut screen = screen.borrow_mut();
    screen.history_running.as_ref()?;

    let mut session = session.borrow_mut();
    let Some(runtime) = session.runtime_mut() else {
        // Senza collegamento non si legge: ciò che è stato trovato resta.
        let mut lettura = screen.history_running.take()?;
        lettura.stop();
        let frase = format!(
            "L'account non è collegato: la lettura si è fermata. {}",
            lettura.operator_message()
        );
        screen.history_pending = lettura.has_something().then_some(lettura);
        return Some(frase);
    };
    let lettura = screen.history_running.as_mut()?;
    lettura.step(runtime.connector_mut());
    if !lettura.is_finished() {
        return Some(lettura.progress_message());
    }
    let lettura = screen.history_running.take()?;
    let frase = lettura.operator_message();
    screen.history_pending = lettura.has_something().then_some(lettura);
    Some(frase)
}

/// Archivia lo storico letto, con la sua ragione.
fn run_history_apply(screen: &SharedRecovery) -> String {
    let mut screen = screen.borrow_mut();
    let Some(lettura) = screen.history_pending.take() else {
        return String::from("Non c'è alcuno storico da confermare.");
    };
    let attore = match crate::operator::audit_actor() {
        Ok(attore) => attore,
        Err(error) => return describe(&error),
    };
    let contesto = match screen
        .acquisition
        .load_context(lettura.request().session_id(), attore)
    {
        Ok(contesto) => contesto,
        Err(error) => return describe(&error),
    };
    match source_history::archive(&lettura, &mut screen.acquisition, &contesto, now()) {
        Ok(esito) => {
            // I contatori del Monitoraggio devono dirlo subito (E2E01-05).
            crate::freshness::mark();
            crate::acquisition::mark_recovered();
            let mut frase = format!(
                "Storico archiviato: {} messaggi registrati come recuperati, con la ragione e chi \
                 l'ha chiesto.",
                esito.archived
            );
            // La differenza si spiega, non si lascia al lettore (E2E01-08).
            if let Some(differenza) = esito.difference_sentence() {
                frase.push(' ');
                frase.push_str(&differenza);
            }
            frase
        }
        Err(error) => describe(&error),
    }
}

/// Prepara l'archiviazione dello storico confermato. **Non archivia**: lo fa
/// [`advance_history_apply`] al giro successivo del ciclo periodico.
///
/// Archiviare centinaia di messaggi richiede secondi, e dentro il gestore del
/// clic la finestra non si ridisegna: il 16 ottobre la conferma restava a
/// schermo con i pulsanti accesi, senza nessun segno che qualcosa stesse
/// accadendo (E2E01-08). Così la schermata dice prima che sta archiviando.
fn begin_history_apply(screen: &SharedRecovery) -> String {
    let mut screen = screen.borrow_mut();
    let Some(lettura) = screen.history_pending.as_ref() else {
        return String::from("Non c'è alcuno storico da confermare.");
    };
    let quanti = lettura.missing().len();
    screen.history_applying = true;
    format!(
        "Archiviazione in corso: {quanti} messaggi da registrare come recuperati. Può richiedere \
         qualche secondo; l'esito compare qui."
    )
}

/// Esegue l'archiviazione dello storico preparata, se ce n'è una.
pub fn advance_history_apply(screen: &SharedRecovery) -> Option<String> {
    {
        let mut screen = screen.borrow_mut();
        if !screen.history_applying {
            return None;
        }
        screen.history_applying = false;
    }
    Some(run_history_apply(screen))
}

/// Le righe dello storico, ricomposte adesso.
fn history_rows(screen: &RecoveryScreen) -> Vec<PriorHistoryRow> {
    match source_history::targets(&screen.archive) {
        Ok(righe) => righe
            .iter()
            .map(|riga| PriorHistoryRow {
                source: SharedString::from(riga.source_name.as_str()),
                session: SharedString::from(riga.session_label.as_str()),
                sentence: crate::lingua::schermo(riga.sentence()),
                readable: riga.chat_id.is_some(),
                key: SharedString::from(riga.key()),
            })
            .collect(),
        Err(error) => {
            tracing::warn!(kind = error.kind(), "fonti per lo storico non componibili");
            Vec::new()
        }
    }
}

/// Anteprima del testo mostrata in una riga di risultato.
///
/// Taglia in **caratteri** e non in byte: tagliare in byte spezzerebbe una
/// lettera accentata a metà, proprio dove l'italiano ne ha di più.
fn excerpt(body: &str) -> String {
    const LIMIT: usize = 220;

    let single_line: String = body
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    let trimmed = single_line.trim();

    if trimmed.chars().count() <= LIMIT {
        return String::from(trimmed);
    }
    let head: String = trimmed.chars().take(LIMIT).collect();
    format!("{head}\u{2026}")
}

/// Traduce un errore del servizio in un messaggio per l'operatore.
fn describe(error: &ServiceError) -> String {
    tracing::warn!(
        kind = error.kind(),
        "recupero della cronologia non riuscito"
    );
    error.operator_message()
}

/// Riporta nell'interfaccia lo stato del recupero.
pub fn refresh(window: &AppWindow, screen: &SharedRecovery, message: Option<&str>) {
    if let Some(text) = message {
        window.set_recovery_message(SharedString::from(text));
    }
    let screen = screen.borrow();

    window.set_retro_busy(screen.searching.is_some());
    let rows: Vec<RetroMatchEntry> = screen
        .search_result
        .matches
        .iter()
        .map(|found| RetroMatchEntry {
            // LA FONTE CON IL SUO NOME (INSTALLED-APP-E2E-01, E2E01-19): «Fonte
            // 1» chiedeva di sapere quale fonte avesse l'identificativo 1. La
            // lettura in più è una riga per risultato, su un elenco breve; se la
            // fonte non si legge, resta l'identificativo, detto come tale.
            source: SharedString::from(screen.archive.source(found.source_id).map_or_else(
                |_| format!("fonte con identificativo {}", found.source_id.get()),
                |fonte| fonte.display_name.as_str().to_owned(),
            )),
            published: SharedString::from(
                lisi_core::Timestamp::from_millis(found.message.published_at_millis)
                    .to_readable_local(),
            ),
            level_label: crate::lingua::schermo(format!("Livello {}", found.level)),
            terms: SharedString::from(found.terms.join(", ")),
            excerpt: SharedString::from(excerpt(&found.message.text)),
            url: found
                .message
                .url
                .as_deref()
                .map_or_else(SharedString::default, SharedString::from),
        })
        .collect();
    window.set_retro_matches(ModelRc::from(Rc::new(VecModel::from(rows))));

    window.set_recovery_awaiting_confirmation(screen.pending.is_some());
    // «Occupato» significa che una lettura è in corso, e mentre lo è il comando
    // che l'avvia resta spento: due letture insieme userebbero lo stesso
    // connettore da due punti.
    window.set_recovery_busy(screen.running.is_some());

    window.set_interval_rows(ModelRc::from(Rc::new(VecModel::from(interval_rows(
        &screen,
    )))));
    window.set_interval_awaiting_confirmation(screen.interval_pending.is_some());
    window.set_interval_busy(screen.interval_running.is_some());

    window.set_prior_history_rows(ModelRc::from(Rc::new(VecModel::from(history_rows(
        &screen,
    )))));
    // Mentre archivia la conferma sparisce e i comandi restano spenti: è
    // «occupato» quanto una lettura (E2E01-08).
    window.set_prior_history_awaiting_confirmation(
        screen.history_pending.is_some() && !screen.history_applying,
    );
    window.set_prior_history_busy(screen.history_running.is_some() || screen.history_applying);
}

/// Collega i comandi dello storico precedente all'avvio (PR-08).
pub fn wire_history(window: &AppWindow, screen: &SharedRecovery, session: &SharedSession) {
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        let session = Rc::clone(session);
        window.on_prior_history_start(move |chiave| {
            if crate::lock::refuse_while_locked("prior_history_start") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = begin_history(
                &screen,
                &session,
                chiave.as_str(),
                window.get_prior_history_span(),
                window.get_prior_history_reason().as_str(),
            );
            window.set_prior_history_message(crate::lingua::schermo(message));
            refresh(&window, &screen, None);
        });
    }
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_prior_history_confirm(move || {
            if crate::lock::refuse_while_locked("prior_history_confirm") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = begin_history_apply(&screen);
            // La ragione si svuota dopo l'uso: scritta per uno storico, non
            // deve accompagnare il successivo.
            window.set_prior_history_reason(SharedString::default());
            window.set_prior_history_message(crate::lingua::schermo(message));
            refresh(&window, &screen, None);
        });
    }
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_prior_history_stop(move || {
            if crate::lock::refuse_while_locked("prior_history_stop") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            // Un comando per due situazioni, come nel recupero: fermare una
            // lettura in corso, conservando ciò che ha trovato, o rinunciare a
            // un risultato già pronto.
            let message = {
                let mut screen = screen.borrow_mut();
                if let Some(mut lettura) = screen.history_running.take() {
                    lettura.stop();
                    let frase = lettura.operator_message();
                    screen.history_pending = lettura.has_something().then_some(lettura);
                    format!("Lettura interrotta. {frase}")
                } else {
                    // Anche un'archiviazione preparata e non ancora eseguita:
                    // fino al giro successivo non è stato scritto nulla.
                    screen.history_applying = false;
                    screen.history_pending = None;
                    String::from("Storico annullato: nulla è stato archiviato.")
                }
            };
            window.set_prior_history_message(crate::lingua::schermo(message));
            refresh(&window, &screen, None);
        });
    }
}

/// Collega i comandi del recupero dei periodi decisi (PR-07).
pub fn wire_interval(window: &AppWindow, screen: &SharedRecovery, session: &SharedSession) {
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        let session = Rc::clone(session);
        window.on_interval_survey(move |chiave| {
            if crate::lock::refuse_while_locked("interval_survey") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = begin_interval(&screen, &session, chiave.as_str());
            window.set_interval_message(crate::lingua::schermo(message));
            refresh(&window, &screen, None);
        });
    }
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_interval_confirm(move || {
            if crate::lock::refuse_while_locked("interval_confirm") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = run_interval_apply(&screen);
            window.set_interval_message(crate::lingua::schermo(message));
            refresh(&window, &screen, None);
        });
    }
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_interval_discard(move || {
            if crate::lock::refuse_while_locked("interval_discard") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            {
                let mut screen = screen.borrow_mut();
                screen.interval_running = None;
                screen.interval_pending = None;
            }
            window.set_interval_message(crate::lingua::schermo(
                "Recupero del periodo annullato: nulla è stato archiviato.",
            ));
            refresh(&window, &screen, None);
        });
    }
}

/// Collega i comandi del recupero.
pub fn wire(window: &AppWindow, screen: &SharedRecovery) {
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_survey_recovery(move || {
            if crate::lock::refuse_while_locked("survey_recovery") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            // Si **prepara** soltanto: la lettura vera avanza dal ciclo
            // periodico, una fonte per volta, così la schermata può ridisegnarsi
            // fra un passo e l'altro e dire a che punto è.
            let message = begin_survey(&screen);
            refresh(&window, &screen, Some(&message));
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_start_retro_search(move || {
            if crate::lock::refuse_while_locked("start_retro_search") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = begin_retro_search(&screen);
            window.set_retro_message(crate::lingua::schermo(message));
            refresh(&window, &screen, None);
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_stop_retro_search(move || {
            if crate::lock::refuse_while_locked("stop_retro_search") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = {
                let mut screen = screen.borrow_mut();
                if let Some(run) = screen.searching.as_mut() {
                    run.stop();
                }
                match screen.searching.take().map(RetroSearchRun::into_outcome) {
                    Some(found) => {
                        let message = format!("Ricerca interrotta. {}", found.operator_message());
                        screen.search_result = found;
                        message
                    }
                    None => String::from("Nessuna ricerca in corso."),
                }
            };
            window.set_retro_message(crate::lingua::schermo(message));
            refresh(&window, &screen, None);
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_confirm_recovery(move || {
            if crate::lock::refuse_while_locked("confirm_recovery") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = run_apply(&screen);
            refresh(&window, &screen, Some(&message));
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_discard_recovery(move || {
            if crate::lock::refuse_while_locked("discard_recovery") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            // Un comando solo per due situazioni: fermare una lettura in corso
            // e rinunciare a un risultato già pronto. Sono due modi di dire
            // «non ora», e distinguerli in due pulsanti avrebbe chiesto
            // all'operatore di sapere in quale dei due stati si trova.
            let message = {
                let mut screen = screen.borrow_mut();
                if screen.running.is_some() {
                    if let Some(run) = screen.running.as_mut() {
                        run.stop();
                    }
                    let found = screen.running.take().map(SurveyRun::into_found);
                    // Ciò che era già stato trovato **resta**: buttarlo via
                    // punirebbe chi si è accorto che stava durando troppo.
                    match found.filter(|found| !found.is_empty()) {
                        Some(found) => {
                            let message =
                                format!("Lettura interrotta. {}", found.operator_message());
                            screen.pending = Some(found);
                            message
                        }
                        None => {
                            String::from("Lettura interrotta: non era ancora stato trovato nulla.")
                        }
                    }
                } else {
                    screen.pending = None;
                    String::from("Recupero annullato: nulla è stato archiviato.")
                }
            };
            refresh(&window, &screen, Some(&message));
        });
    }
}

#[cfg(test)]
mod tests {
    const THIS_MODULE: &str = include_str!("recovery.rs");
    const MAIN: &str = include_str!("main.rs");

    fn produzione() -> &'static str {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("blocco di prove riconoscibile");
        };
        produzione
    }

    /// **Il recupero di un periodo non parte da solo** (PR-07): la lettura si
    /// prepara in un punto solo, il comando di una persona, e nessun avvio la
    /// chiama.
    #[test]
    fn il_recupero_di_un_periodo_parte_solo_da_un_comando() {
        let codice = produzione();
        assert_eq!(
            codice.matches("interval_running = Some(").count(),
            1,
            "la lettura di un periodo si prepara in un punto solo"
        );
        let Some(inizio) = codice.find("fn begin_interval(") else {
            panic!("la preparazione deve esistere");
        };
        let Some(dove) = codice.find("interval_running = Some(") else {
            panic!("la preparazione deve esistere");
        };
        let Some(fine) = codice[inizio..].find("\n}\n") else {
            panic!("la funzione deve chiudersi");
        };
        assert!(
            dove > inizio && dove < inizio + fine,
            "la lettura si prepara soltanto in begin_interval"
        );
        assert_eq!(
            codice.matches("begin_interval(&").count(),
            1,
            "soltanto il comando dell'operatore la chiama"
        );
        assert!(!MAIN.contains("begin_interval"), "nessun avvio la chiama");
    }

    /// **Il limite dello storico si dice prima del comando** (PR-08, controllo
    /// negativo 4), con la stessa frase del servizio, e con il tetto.
    #[test]
    fn il_limite_dello_storico_si_dice_prima_del_comando() {
        const UI: &str = include_str!("../ui/app-window.slint");
        let limite = format!(
            "text: @tr(\"{}\");",
            lisi_services::source_history::HISTORY_LIMITS
        );
        let Some(dove_il_limite) = UI.find(&limite) else {
            panic!("il limite dello storico deve comparire, identico, nella schermata");
        };
        let Some(dove_il_comando) = UI.find("label: @tr(\"Leggi i messaggi precedenti\");") else {
            panic!("il comando dello storico deve esistere");
        };
        assert!(
            dove_il_limite < dove_il_comando,
            "il limite viene prima del comando"
        );
        let tetto = format!(
            "al più {} pagine",
            lisi_services::source_history::HISTORY_MAX_PAGES
        );
        assert!(
            UI[dove_il_limite..dove_il_comando].contains(&tetto),
            "il tetto si dichiara"
        );
    }

    /// **Senza una ragione scritta lo storico non parte** (PR-08, controllo
    /// negativo 3), e non parte da solo.
    #[test]
    fn lo_storico_vuole_una_ragione_e_un_comando() {
        const UI: &str = include_str!("../ui/app-window.slint");
        assert!(
            UI.contains("enabled: root.prior-history-reason != \"\" && !root.prior-history-busy")
        );
        let codice = produzione();
        assert!(codice.contains("OperationalReason::try_new(motivo) else {"));
        assert_eq!(codice.matches("history_running = Some(").count(), 1);
        assert!(!MAIN.contains("begin_history"), "nessun avvio la chiama");
    }

    /// **Il recupero di un periodo chiede l'autorità di acquisizione**: senza,
    /// la richiesta non si costruisce, e il comando lo dice.
    #[test]
    fn il_recupero_di_un_periodo_chiede_l_autorita() {
        let codice = produzione();
        assert!(codice.contains("let Some(autorita) = sessione.authority() else {"));
        assert!(codice.contains("IntervalRecoveryRequest::for_candidate(autorita,"));
    }
}

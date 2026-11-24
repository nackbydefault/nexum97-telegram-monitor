//! Collegamento fra le schermate Storico e Alert e il servizio dello storico.
//!
//! Come gli altri moduli di collegamento, questo non contiene logica: traduce
//! le righe del servizio in righe dell'interfaccia e i comandi dell'operatore
//! in chiamate al servizio.
//!
//! Due punti meritano di essere detti, perché è dove sarebbe stato facile
//! sbagliare.
//!
//! **La decisione non viene giudicata qui.** Se una nota è obbligatoria, se uno
//! stato ripete quello corrente, se una revisione contraddice il motore: lo
//! decide `ReviewService`, dove è coperto da test. Qui si mostra la risposta.
//!
//! **Il livello mostrato è quello registrato.** Nessuna riga viene rianalizzata
//! per riempire la schermata: un livello ricalcolato oggi con una formula
//! diversa da quella di ieri racconterebbe una storia che non è avvenuta.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_core::model::ReviewState;

use lisi_core::model::ExportDestination;
use lisi_services::cyber_watch::CyberWatchService;
use lisi_services::export::{ExportOptions, ExportService};
use lisi_services::history::{HistoryEntry, HistoryFilter, HistoryScope, HistoryService};
use lisi_services::participants::ParticipantService;
use lisi_services::provenance::ProvenanceService;
use lisi_services::review::ReviewService;
use lisi_services::{ServiceError, ServiceResult};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::account::SharedSession;
use crate::{AppWindow, ContentEntry, ResemblanceRow};

/// Servizi dello storico e della revisione, condivisi fra i gestori.
///
/// Sono due servizi su **due connessioni allo stesso archivio**: lo storico
/// legge, la revisione scrive, e ciascuno possiede la propria connessione. Una
/// sola connessione condivisa fra i due richiederebbe di prestarla avanti e
/// indietro a ogni comando.
pub struct HistoryScreens {
    history: HistoryService,
    review: ReviewService,
    export: ExportService,
    /// Compone l'elenco delle persone da allegare al rapporto.
    ///
    /// Sta qui e non nella schermata Persone perché è **il rapporto** ad averne
    /// bisogno al momento dell'esportazione. È lo stesso servizio, e con esso
    /// viene la regola che possiede: senza una ragione registrata nell'audit
    /// l'elenco non si produce, e il rapporto lo dichiara invece di tacere.
    participants: ParticipantService,
    /// Compone i grappoli di segnali che condividono un indicatore.
    ///
    /// Sta qui perche' la schermata Alert e' il posto dove si guarda cio' che
    /// merita attenzione, e un grappolo e' esattamente quello: un invito a
    /// guardare, non un allarme.
    cyber: CyberWatchService,
    /// Ricostruisce perché un risultato è come l'operatore lo vede.
    ///
    /// Sta qui perché la domanda «perché sto vedendo questo?» si pone davanti
    /// alla riga, e la riga è nello Storico. Legge soltanto: non ha metodi di
    /// scrittura, e non ne servono.
    provenance: ProvenanceService,
    /// La conversazione **già letta e mostrata** (ADR-0151), tenuta qui perché
    /// conservarla non debba rileggerla (CTX-06): sono tutti i messaggi caricati.
    ///
    /// # Perché in memoria e non riletto al momento della fotografia
    ///
    /// Perché una fotografia deve conservare **ciò che una persona ha visto**.
    /// Rileggere da Telegram al momento del gesto conserverebbe qualcosa che
    /// nessuno ha guardato, e che potrebbe essere già cambiato fra il momento
    /// in cui si è deciso di conservare e quello in cui si è premuto.
    ///
    /// È l'altra metà della garanzia: il servizio che conserva non ha un
    /// connettore, e non ne ha bisogno perché ciò che deve conservare è qui.
    ///
    /// `None` quando nessuna conversazione è aperta: allora non c'è nulla da
    /// conservare, e il comando lo dice invece di conservare un vuoto.
    pub(crate) conversazione: Option<lisi_services::conversation::Conversation>,
    /// Il contenuto per cui è stato chiesto il collegamento mostrato (CA02-14).
    ///
    /// La frase resta finché si guarda lo stesso contenuto, anche se l'elenco
    /// si ridisegna; scegliendone un altro sparisce, perché un collegamento
    /// sotto la riga sbagliata sarebbe una falsa attribuzione.
    collegamento_per: Option<i32>,
}

/// Servizi dello storico condivisi fra i gestori dei comandi.
pub type SharedHistory = Rc<RefCell<HistoryScreens>>;

/// Lunghezza massima dell'anteprima del corpo mostrata in una riga.
///
/// Il corpo intero non entra in una riga di elenco. Il taglio è dichiarato con
/// un carattere di ellissi: un testo troncato in silenzio farebbe credere
/// completo un messaggio che non lo è.
const EXCERPT_CHARS: usize = 220;

/// La pagina degli Avvisi, dove la Coda di lavoro apre un messaggio (OS-10).
const PAGINA_AVVISI: i32 = 7;

/// Crea i servizi sugli archivi indicati.
///
/// Riceve **sei** archivi già aperti perché i servizi non condividono una
/// connessione. Restituisce `None` se uno dei sei manca.
#[must_use]
pub fn create_service(
    for_history: Option<lisi_services::Database>,
    for_review: Option<lisi_services::Database>,
    for_export: Option<lisi_services::Database>,
    for_participants: Option<lisi_services::Database>,
    for_cyber: Option<lisi_services::Database>,
    for_provenance: Option<lisi_services::Database>,
) -> Option<SharedHistory> {
    let (Some(first), Some(second), Some(third), Some(fourth), Some(fifth), Some(sixth)) = (
        for_history,
        for_review,
        for_export,
        for_participants,
        for_cyber,
        for_provenance,
    ) else {
        return None;
    };

    Some(Rc::new(RefCell::new(HistoryScreens {
        history: HistoryService::new(first),
        review: ReviewService::new(second),
        export: ExportService::new(third),
        cyber: CyberWatchService::new(fifth),
        participants: ParticipantService::new(fourth),
        provenance: ProvenanceService::new(sixth),
        conversazione: None,
        collegamento_per: None,
    })))
}

impl HistoryScreens {
    /// L'archivio in lettura, per la pagina della conversazione (ADR-0151).
    pub(crate) const fn database(&self) -> &lisi_services::Database {
        self.provenance.database()
    }

    /// L'archivio in scrittura, per la sola fotografia del contesto (CTX-06).
    pub(crate) const fn database_mut(&mut self) -> &mut lisi_services::Database {
        self.provenance.database_mut()
    }
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// Attore dell'audit.
fn actor() -> ServiceResult<lisi_core::text::Actor> {
    crate::operator::audit_actor()
}

/// Anteprima del corpo, tagliata in caratteri e non in byte.
///
/// Tagliare in byte spezzerebbe una lettera accentata a metà e produrrebbe un
/// testo illeggibile proprio dove l'italiano ne ha di più.
pub(crate) fn excerpt(body: &str) -> String {
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

    if trimmed.chars().count() <= EXCERPT_CHARS {
        return String::from(trimmed);
    }

    let head: String = trimmed.chars().take(EXCERPT_CHARS).collect();
    format!("{head}\u{2026}")
}

/// La parola del modo di acquisizione per una riga (PR-07, ADR-0123).
///
/// Vuota **soltanto** per ciò che è stato acquisito dal vivo: è il caso
/// normale, e ripeterlo su ogni riga renderebbe invisibile l'eccezione. Un
/// contenuto recuperato, o di cui il modo non si può determinare, lo dice: un
/// modo non determinabile mostrato come «dal vivo» sarebbe un'attestazione che
/// l'archivio non può fare.
fn mode_label(modo: &lisi_core::model::AcquisitionMode) -> SharedString {
    if modo.is_live() {
        return SharedString::default();
    }
    SharedString::from(lisi_services::acquisition_mode::short_label(modo))
}

/// L'ora di pubblicazione per la riga, **soltanto** per ciò che non è arrivato
/// dal vivo (E2E01-06).
///
/// Dal vivo pubblicazione e acquisizione coincidono a meno di secondi, e
/// ripeterle raddoppierebbe la riga. Per un contenuto recuperato no: l'elenco
/// mostrava solo l'ora del recupero, uguale per centinaia di messaggi, e la
/// pubblicazione si leggeva soltanto aprendo la provenienza.
fn published_label(
    mode: &lisi_core::model::AcquisitionMode,
    published_at: lisi_core::Timestamp,
) -> String {
    if mode.is_live() {
        return String::new();
    }
    format!("pubblicato {}", published_at.to_readable_local())
}

/// L'ora di acquisizione per la riga: nuda dal vivo, con la sua parola
/// accanto alla pubblicazione, così le due ore non si scambiano.
fn acquired_label(
    mode: &lisi_core::model::AcquisitionMode,
    acquired_at: lisi_core::Timestamp,
) -> String {
    let quando = acquired_at.to_readable_local();
    if mode.is_live() {
        quando
    } else {
        format!("acquisito {quando}")
    }
}

/// I nomi delle tecniche della fotografia ATT&CK più recente, per dire che
/// cosa un testo cita (ATTACK-03, ADR-0185). Si leggono una volta per ogni
/// aggiornamento dell'elenco.
struct Citazioni {
    nomi: std::collections::HashMap<String, String>,
    versione: Option<String>,
}

impl Citazioni {
    fn da(database: &lisi_services::Database) -> Self {
        let ultima = database
            .attack_snapshots()
            .unwrap_or_default()
            .into_iter()
            .max_by_key(|fotografia| fotografia.imported_at);
        let Some(ultima) = ultima else {
            return Self {
                nomi: std::collections::HashMap::new(),
                versione: None,
            };
        };
        let nomi = database
            .attack_techniques(ultima.id)
            .unwrap_or_default()
            .into_iter()
            .map(|tecnica| (tecnica.id().as_str().to_owned(), tecnica.name().to_owned()))
            .collect();
        Self {
            nomi,
            versione: Some(ultima.attack_version),
        }
    }

    /// La frase delle citazioni di un testo, vuota se non ne cita.
    fn frase(&self, testo: &str) -> String {
        let citate: Vec<_> = lisi_core::model::attack_citation::cited_techniques(testo)
            .into_iter()
            .map(|id| {
                let nome = self.nomi.get(id.as_str()).cloned();
                (id, nome)
            })
            .collect();
        lisi_core::model::attack_citation::citation_sentence(&citate, self.versione.as_deref())
    }
}

/// Traduce una riga del servizio in una riga dell'interfaccia.
fn row(entry: &HistoryEntry, citazioni: &Citazioni) -> ContentEntry {
    ContentEntry {
        content_id: i32::try_from(entry.content.id.get()).unwrap_or(0),
        source: SharedString::from(entry.source_name.as_str()),
        acquired: SharedString::from(acquired_label(&entry.mode, entry.content.acquired_at)),
        published: SharedString::from(published_label(&entry.mode, entry.content.published_at)),
        level: i32::from(entry.level()),
        // L'etichetta del livello vive nel dominio (AnalysisLevel::label), unica
        // per storico, avvisi e centro notifiche.
        level_label: crate::lingua::schermo(entry.content.analysis_level.label()),
        reason: SharedString::from(entry.reason()),
        terms: SharedString::from(entry.matched_terms().join(", ")),
        excerpt: SharedString::from(excerpt(entry.content.body.as_str())),
        author_identifier: entry
            .content
            .author_identifier
            .as_deref()
            .map_or_else(SharedString::default, SharedString::from),
        author_username: entry
            .content
            .author_username
            .as_deref()
            .map_or_else(SharedString::default, |username| {
                crate::lingua::schermo(format!("@{username}"))
            }),
        mode_label: mode_label(&entry.mode),
        url: entry
            .content
            .url
            .as_ref()
            .map_or_else(SharedString::default, |url| {
                SharedString::from(url.as_str())
            }),
        review_state: crate::lingua::schermo(entry.review_state().label()),
        awaiting: entry.awaits_a_decision(),
        duplicate: entry.content.is_duplicate(),
        // Vuota quando dopo l'acquisizione non è successo nulla, che è il caso
        // normale: stessa ragione di `mode_label`.
        history_label: entry
            .history
            .short_label()
            .map_or_else(SharedString::default, SharedString::from),
        has_history: entry.history.has_anything_to_show(),
        revised: entry.history.was_revised(),
        cited: SharedString::from(citazioni.frase(entry.content.body.as_str())),
    }
}

/// Quanti fra i soli contenuti segnalati attendono una decisione.
///
/// È il numero della schermata Alert. Mostrarvi il totale dello storico
/// direbbe che ci sono più avvisi da esaminare di quanti se ne vedono, e chi
/// li ha appena esaminati tutti continuerebbe a leggere una cifra diversa da
/// zero senza sapere dove cercare.
fn alert_pending(history: &HistoryService, scope: HistoryScope) -> i32 {
    let count = history
        .matching(scope, &HistoryFilter::alerts_only())
        .map(|entries| {
            entries
                .iter()
                .filter(|entry| entry.awaits_a_decision())
                .count()
        });

    match count {
        Ok(value) => i32::try_from(value).unwrap_or(i32::MAX),
        Err(error) => {
            tracing::warn!(kind = error.kind(), "avvisi in attesa non contabili");
            0
        }
    }
}

/// Sessioni mostrate nel selettore, nell'ordine in cui compaiono.
///
/// La prima voce non è una sessione: è «tutte». L'indice scelto
/// nell'interfaccia si traduce qui, e non nell'interfaccia, perché una lista di
/// etichette non deve portare con sé degli identificatori.
fn session_scope(screens: &HistoryScreens, index: i32) -> HistoryScope {
    if index <= 0 {
        return HistoryScope::Everything;
    }

    let position = usize::try_from(index - 1).unwrap_or(usize::MAX);
    match screens.history.sessions() {
        Ok(sessions) => sessions
            .get(position)
            .map_or(HistoryScope::Everything, |summary| {
                HistoryScope::Session(summary.session.id)
            }),
        Err(error) => {
            tracing::warn!(kind = error.kind(), "elenco delle sessioni non leggibile");
            HistoryScope::Everything
        }
    }
}

impl HistoryScreens {
    /// Le sessioni condotte, per il selettore di una schermata.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn sessions(
        &self,
    ) -> lisi_services::ServiceResult<Vec<lisi_services::history::SessionSummary>> {
        self.history.sessions()
    }

    /// La sessione all'indice indicato nel selettore, se ce n'è una.
    ///
    /// L'indice **0 non è una sessione**: è «tutte» nello Storico e «nessun
    /// monitoraggio scelto» in Cyber Watch. La traduzione da indice a
    /// identificativo vive qui, e non nell'interfaccia, perché un elenco di
    /// etichette non deve portare con sé degli identificatori.
    #[must_use]
    pub fn session_at(&self, index: i32) -> Option<lisi_core::SessionId> {
        if index <= 0 {
            return None;
        }
        let position = usize::try_from(index - 1).ok()?;
        match self.history.sessions() {
            Ok(sessions) => sessions.get(position).map(|summary| summary.session.id),
            Err(error) => {
                tracing::warn!(kind = error.kind(), "elenco delle sessioni non leggibile");
                None
            }
        }
    }

    /// I grappoli di segnali della sessione indicata.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn cyber_events(
        &self,
        session: lisi_core::SessionId,
    ) -> lisi_services::ServiceResult<Vec<lisi_services::cyber_watch::WatchEvent>> {
        self.cyber.events(session)
    }

    /// Gli eventi candidati di tutto l'archivio (CYBER-EVENTS-02, ADR-0189).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn cyber_candidates(
        &self,
        now: lisi_core::Timestamp,
    ) -> lisi_services::ServiceResult<Vec<lisi_core::model::cyber_candidate::CandidateEvent>> {
        self.cyber.archive_candidates(now)
    }

    /// La cronologia di un grappolo di quella sessione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce, o se il monitoraggio non
    /// risulta avviato e quindi non ha un periodo di osservazione.
    pub fn cyber_timeline(
        &self,
        session: lisi_core::SessionId,
        reason: &lisi_core::model::cyber_event::CorrelationReason,
    ) -> lisi_services::ServiceResult<lisi_core::model::cyber_timeline::CyberTimeline> {
        self.cyber.timeline(session, reason)
    }

    /// Il vicinato di un nodo nel grafo delle prove (GRAPH-02).
    ///
    /// # Perché passa l'archivio del Cyber Watch
    ///
    /// Perché gli archi si ricavano dagli stessi contenuti e dagli stessi
    /// grappoli, e aprire un settimo archivio per la stessa domanda
    /// significherebbe tenerne allineati due.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se nessuna ragione operativa è registrata
    /// (ADR-0024), o se l'archivio non è leggibile.
    pub fn evidence_neighbourhood(
        &self,
        session: lisi_core::SessionId,
        node: &lisi_core::model::evidence_graph::GraphNode,
    ) -> lisi_services::ServiceResult<lisi_core::model::evidence_graph::Neighbourhood> {
        lisi_services::evidence_graph::neighbourhood_of_session(
            self.cyber.database(),
            session,
            node,
        )
    }

    /// In quale monitoraggio sta un contenuto, se esiste (F-02).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce per una ragione diversa
    /// dall'assenza.
    pub fn content_session(
        &self,
        content: lisi_core::ContentId,
    ) -> lisi_services::ServiceResult<Option<lisi_core::SessionId>> {
        lisi_services::evidence_graph::content_session(self.cyber.database(), content)
    }

    /// La posizione di un monitoraggio nel selettore (0 è «nessuno»), se c'è.
    #[must_use]
    pub fn session_index_of(&self, session: lisi_core::SessionId) -> Option<i32> {
        let sessioni = self.history.sessions().ok()?;
        let posizione = sessioni.iter().position(|s| s.session.id == session)?;
        i32::try_from(posizione + 1).ok()
    }
}

/// Riporta nell'interfaccia lo storico e gli avvisi.
pub fn refresh(window: &AppWindow, screens: &SharedHistory, message: Option<&str>) {
    if let Some(text) = message {
        window.set_history_message(SharedString::from(text));
    }

    let screens = screens.borrow();

    // La cartella si rilegge a ogni aggiornamento invece di essere scritta una
    // volta all'avvio: cosi' la schermata non puo' mostrare una cartella
    // diversa da quella in cui l'esportazione scrivera' davvero.
    window.set_export_destination(SharedString::from(
        screens.export.destination().map_or_else(
            |_| String::from("non determinabile su questa postazione"),
            |path| path.display().to_string(),
        ),
    ));

    let filter = HistoryFilter {
        query: window.get_history_filter().to_string(),
        minimum_level: 0,
        only_pending: window.get_history_only_pending(),
    };

    // Il selettore delle sessioni: la prima voce e' «tutte», e non e' una
    // sessione. Il rapporto documenta una sessione sola, quindi con «tutte»
    // scelto l'esportazione resta indisponibile e la schermata lo dice.
    let mut labels = vec![crate::lingua::schermo("Tutte le sessioni")];
    match screens.history.sessions() {
        Ok(sessions) => labels.extend(
            sessions
                .iter()
                .map(|summary| crate::lingua::schermo(summary.label())),
        ),
        Err(error) => {
            tracing::warn!(kind = error.kind(), "elenco delle sessioni non leggibile");
        }
    }

    // Un indice rimasto oltre la fine — perche' l'elenco si e' accorciato —
    // tornerebbe a puntare a una sessione diversa da quella scelta.
    let chosen = window.get_history_session_index();
    let chosen = if usize::try_from(chosen).is_ok_and(|value| value < labels.len()) {
        chosen
    } else {
        0
    };
    window.set_history_session_index(chosen);
    window.set_history_sessions(ModelRc::from(Rc::new(VecModel::from(labels))));
    window.set_can_export(chosen > 0);

    let scope = session_scope(&screens, chosen);

    // I grappoli di segnali della sessione osservata.
    //
    // Solo quando una sessione e' scelta: mettere insieme contenuti di due
    // monitoraggi diversi produrrebbe un grappolo che non appartiene a nessuno
    // dei due (DEC-221).
    //
    // Vuoto quando non c'e' nulla: una riga che compare sempre e' una riga che
    // nessuno legge.
    let cyber = match scope {
        HistoryScope::Session(session_id) => {
            screens.cyber.count(session_id).unwrap_or_else(|error| {
                tracing::warn!(kind = error.kind(), "grappoli non leggibili");
                0
            })
        }
        HistoryScope::Everything => 0,
    };
    window.set_cyber_watch_summary(SharedString::from(if cyber == 0 {
        String::new()
    } else {
        format!(
            " In questo monitoraggio ci sono {cyber} gruppi di contenuti che \
             nominano lo stesso indicatore tecnico: è un invito a guardarli \
             insieme, non un allarme."
        )
    }));

    // I conteggi vengono dall'insieme scelto, il filtro solo dagli elenchi:
    // un totale che cambia con la ricerca non e' piu' un totale.
    match screens.history.summary(scope) {
        Ok(summary) => {
            window.set_history_total(i32::try_from(summary.total).unwrap_or(i32::MAX));
            window.set_history_alerted(i32::try_from(summary.alerted).unwrap_or(i32::MAX));
            window.set_history_pending(i32::try_from(summary.pending).unwrap_or(i32::MAX));
        }
        Err(error) => {
            tracing::warn!(kind = error.kind(), "conteggi dello storico non leggibili");
            window.set_history_message(crate::lingua::schermo(error.operator_message()));
            window.set_history_total(0);
            window.set_history_alerted(0);
            window.set_history_pending(0);
        }
    }

    let entries = match screens.history.matching(scope, &filter) {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!(kind = error.kind(), "storico non leggibile");
            window.set_history_message(crate::lingua::schermo(error.operator_message()));
            Vec::new()
        }
    };

    let citazioni = Citazioni::da(screens.history.database());
    let alerts: Vec<ContentEntry> = entries
        .iter()
        .filter(|entry| entry.raised_alert())
        .map(|entry| row(entry, &citazioni))
        .collect();
    let all: Vec<ContentEntry> = entries.iter().map(|entry| row(entry, &citazioni)).collect();

    // Dov'e' la riga aperta, nei due elenchi: con il pannello aperto l'elenco
    // mostra una riga sola, e deve essere quella (SIM3-19).
    let aperta = window.get_selected_content();
    let posizione = |righe: &[ContentEntry]| {
        righe
            .iter()
            .position(|riga| riga.content_id == aperta)
            .and_then(|indice| i32::try_from(indice).ok())
            .unwrap_or(-1)
    };
    window.set_alert_selected_row(posizione(&alerts));
    window.set_history_selected_row(posizione(&all));

    window.set_alert_pending(alert_pending(&screens.history, scope));

    window.set_alert_entries(ModelRc::from(Rc::new(VecModel::from(alerts))));
    window.set_history_entries(ModelRc::from(Rc::new(VecModel::from(all))));

    refresh_selection(window, &screens, &entries);
}

/// Chiude il pannello della cronologia e ne svuota il contenuto.
///
/// Svuotare **e** chiudere, non solo chiudere: un pannello nascosto che
/// conserva le versioni di un altro contenuto è un pannello che, riaperto per
/// sbaglio, mostrerebbe la storia sbagliata.
fn close_story(window: &AppWindow) {
    window.set_history_story_open(false);
    window.set_history_story(SharedString::default());
    window.set_history_story_subject(SharedString::default());
    window.set_history_story_deleted(false);
    window.set_history_versions(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
}

/// Apre la cronologia di un contenuto.
///
/// # Che cosa questa funzione non fa
///
/// Non scrive nulla. È una lettura, e le versioni sono comunque immutabili per
/// costruzione: due trigger dell'archivio abortiscono modifica e cancellazione.
fn open_story(window: &AppWindow, screens: &SharedHistory, content_id: i32) {
    let id = lisi_core::ContentId::new(i64::from(content_id));

    let storia = match screens.borrow().history.content_history(id) {
        Ok(storia) => storia,
        Err(errore) => {
            window.set_history_message(crate::lingua::schermo(errore.operator_message()));
            close_story(window);
            return;
        }
    };

    // Le righe del pannello: la prima versione e poi ogni passaggio. La prima
    // non ha un «che cosa e' cambiato»: non proviene da nulla.
    let mut righe: Vec<crate::ContentVersionEntry> = Vec::new();

    if let Some(prima) = storia.versions.first() {
        righe.push(crate::ContentVersionEntry {
            heading: crate::lingua::schermo("Versione 1 \u{2014} acquisita e analizzata"),
            observed: SharedString::from(prima.observed_at.to_readable_local()),
            remote_edit: SharedString::default(),
            body: SharedString::from(prima.body.as_str()),
            change: SharedString::default(),
            delta: SharedString::default(),
            original: true,
        });
    }

    for passaggio in storia.steps() {
        let versione = &passaggio.version;
        righe.push(crate::ContentVersionEntry {
            heading: crate::lingua::schermo(format!(
                "Versione {} \u{2014} modifica osservata",
                versione.version_number
            )),
            observed: SharedString::from(versione.observed_at.to_readable_local()),
            // L'istante dichiarato da Telegram, quando c'e'. Vuoto altrimenti:
            // e' un dato della fonte, e un trattino si leggerebbe come
            // «sconosciuto» invece che «non dichiarato».
            remote_edit: versione.remote_edit_timestamp.map_or_else(
                SharedString::default,
                |istante| {
                    crate::lingua::schermo(format!(
                        "Telegram dichiara la modifica alle {}",
                        istante.to_readable_local()
                    ))
                },
            ),
            body: SharedString::from(versione.body.as_str()),
            change: crate::lingua::schermo(passaggio.change.as_sentence()),
            delta: SharedString::from(match passaggio.length_delta {
                0 => String::from("stessa lunghezza"),
                delta if delta > 0 => format!("+{delta} caratteri"),
                delta => format!("{delta} caratteri"),
            }),
            original: false,
        });
    }

    // Il soggetto: quale messaggio si sta guardando. Senza, un pannello aperto
    // e' un elenco di testi che non si sa a chi appartengano.
    //
    // Si riusa il riepilogo del pannello della decisione — «fonte — istante —
    // estratto» — invece di ricomporlo: e' gia' in mano, dice esattamente
    // questo, e ricomporlo qui creerebbe due frasi da tenere allineate.
    window.set_history_story_subject(window.get_selected_summary());
    window.set_history_story(crate::lingua::schermo(storia.as_sentence()));
    window.set_history_story_deleted(storia.was_deleted());
    window.set_history_versions(ModelRc::from(Rc::new(VecModel::from(righe))));
    window.set_history_story_open(true);
}

/// Chiude il replay e svuota le due frasi.
///
/// Svuotarle conta: un'ipotesi che restasse sotto gli occhi dopo aver scelto
/// un'altra riga sarebbe l'ipotesi di un contenuto diverso, e nessuno se ne
/// accorgerebbe — i livelli si assomigliano tutti.
fn close_replay(window: &AppWindow) {
    window.set_history_replay_open(false);
    window.set_history_replay_historical(SharedString::default());
    window.set_history_replay_hypothetical(SharedString::default());
    window.set_history_replay_attribution(SharedString::default());
    window.set_history_replay_differs(false);
}

/// Riesegue l'analisi del contenuto scelto con il motore di adesso.
///
/// # Che cosa NON fa
///
/// **Non scrive niente e non cambia il livello registrato.** Non perché questo
/// modulo stia attento: `lisi-services::replay` non conosce l'archivio, e il
/// livello ipotetico non può nemmeno essere passato dove si attende quello
/// storico — il tipo non lo permette (REPLAY-01, DEC-261).
fn open_replay(window: &AppWindow, screens: &SharedHistory, content_id: i32) {
    let id = lisi_core::ContentId::new(i64::from(content_id));

    let esito = match screens.borrow().provenance.replay_of(id) {
        Ok(esito) => esito,
        Err(errore) => {
            window.set_history_message(crate::lingua::schermo(errore.operator_message()));
            close_replay(window);
            return;
        }
    };

    let Some(finding) = esito else {
        // Senza la fotografia della sessione il replay non si esegue: con i
        // dizionari di oggi misurerebbe insieme il cambio di motore e il cambio
        // di dizionari, e il numero che ne uscirebbe non direbbe niente di
        // nessuno dei due.
        window.set_history_replay_historical(crate::lingua::schermo(
            "Di questa sessione non risulta la configurazione con cui fu condotta.",
        ));
        window.set_history_replay_hypothetical(SharedString::default());
        window.set_history_replay_attribution(crate::lingua::schermo(
            "Senza di essa la rilettura non si può fare. Rifarla con i dizionari di oggi \
             misurerebbe insieme il cambio di motore e il cambio di dizionari. Il livello \
             che ne uscirebbe non direbbe niente né dell'uno né dell'altro.",
        ));
        window.set_history_replay_differs(false);
        window.set_history_replay_open(true);
        return;
    };

    window.set_history_replay_historical(crate::lingua::schermo(finding.historical_sentence()));
    window.set_history_replay_hypothetical(crate::lingua::schermo(finding.hypothetical_sentence()));
    window.set_history_replay_attribution(crate::lingua::schermo(finding.attribution_sentence()));
    window.set_history_replay_differs(!finding.agrees());
    window.set_history_replay_open(true);
}

/// Quanti contenuti al massimo entrano in un confronto di somiglianza.
///
/// # Perché un limite, e perché si rifiuta invece di troncare
///
/// Perché il confronto è sincrono e legge tutti i contenuti della sessione.
/// **Duemila** è lo stesso limite del Rule Lab, e per la stessa ragione: oltre,
/// la finestra resterebbe ferma senza dire nulla.
///
/// Oltre il limite il confronto **non si esegue**: un confronto su una parte
/// direbbe «nessun contenuto simile» avendone guardato una frazione.
const MAX_RESEMBLING_CONTENTS: u32 = 2_000;

/// Quante sequenze condivise si mostrano per riga.
///
/// Sono l'**evidenza**, non un ornamento: bastano poche righe a far capire che
/// cosa i due contenuti abbiano in comune, e l'elenco intero renderebbe la
/// riga illeggibile.
const EVIDENCE_LINES: usize = 3;

/// Chiude le somiglianze e ne svuota le righe.
///
/// Svuotarle conta per la stessa ragione del replay: righe che restassero sotto
/// gli occhi dopo aver scelto un'altra riga sarebbero le somiglianze di un
/// contenuto diverso, e nessuno se ne accorgerebbe.
fn close_resembling(window: &AppWindow) {
    window.set_history_resembling_open(false);
    window.set_history_resembling_summary(SharedString::default());
    window.set_history_resembling_rows(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
}

/// Cerca i contenuti della sessione che somigliano a quello scelto.
///
/// # Che cosa NON fa
///
/// **Non scrive niente, e non dice che siano duplicati.** «Duplicato» è uno
/// stato della revisione, cioè la decisione di una persona presa con motivo,
/// istante e audit; questa sezione dice che due contenuti si somigliano e
/// quanto (SIM-01, ADR-0055).
fn open_resembling(window: &AppWindow, screens: &SharedHistory, content_id: i32) {
    let id = lisi_core::ContentId::new(i64::from(content_id));

    let esito = match screens
        .borrow()
        .provenance
        .resembling_to(id, MAX_RESEMBLING_CONTENTS)
    {
        Ok(esito) => esito,
        Err(errore) => {
            window.set_history_message(crate::lingua::schermo(errore.operator_message()));
            close_resembling(window);
            return;
        }
    };

    let righe: Vec<ResemblanceRow> = esito
        .resemblances()
        .iter()
        .map(|somiglianza| {
            let (sinistra, destra) = somiglianza.pair();
            // L'altro contenuto: quello dei due che non e' quello scelto.
            let altro = if sinistra.get() == id.get() {
                destra
            } else {
                sinistra
            };

            ResemblanceRow {
                other: crate::lingua::schermo(format!("Contenuto {}", altro.get())),
                // LA CHIAVE DELLA COPPIA, in numeri: «Contenuto 128» e' una
                // frase per chi legge, e una frase non identifica niente.
                pair_key: crate::lingua::schermo(format!("{}-{}", id.get(), altro.get())),
                why: crate::lingua::schermo(somiglianza.as_sentence()),
                evidence: SharedString::from(
                    somiglianza
                        .evidence(EVIDENCE_LINES)
                        .iter()
                        .map(|sequenza| format!("\u{ab}{sequenza}\u{bb}"))
                        .collect::<Vec<_>>()
                        .join("  \u{b7}  "),
                ),
            }
        })
        .collect();

    window.set_history_resembling_summary(crate::lingua::schermo(esito.as_sentence()));
    window.set_history_resembling_rows(ModelRc::from(Rc::new(VecModel::from(righe))));
    window.set_history_resembling_open(true);
}

/// Toglie la frase e l'indirizzo dell'ultima richiesta di collegamento.
fn clear_link_request(window: &AppWindow) {
    window.set_history_link_sentence(SharedString::default());
    window.set_history_link_url(SharedString::default());
}

/// Chiede a Telegram il collegamento ufficiale al messaggio (CA02-14, DG-02).
///
/// Come il contesto: il servizio riceve il runtime dell'account autorizzato,
/// se c'è, e non scrive nulla. Senza account la frase dice che il collegamento
/// si ottiene al momento e che manca un collegamento attivo a Telegram.
fn request_link(
    window: &AppWindow,
    screens: &SharedHistory,
    session: Option<&SharedSession>,
    content_id: i32,
) {
    let id = lisi_core::ContentId::new(i64::from(content_id));
    let esito = {
        let schermate = screens.borrow();
        let database = schermate.provenance.database();
        match session {
            Some(session) => {
                let mut sessione = session.borrow_mut();
                match sessione.runtime_mut() {
                    Some(runtime) => lisi_services::message_link::request(
                        database,
                        Some(runtime.connector_mut()),
                        id,
                        now(),
                    ),
                    None => lisi_services::message_link::request(database, None, id, now()),
                }
            }
            None => lisi_services::message_link::request(database, None, id, now()),
        }
    };

    match esito {
        Ok(richiesta) => {
            window.set_history_link_sentence(crate::lingua::schermo(richiesta.as_sentence()));
            window.set_history_link_url(SharedString::from(richiesta.url().unwrap_or_default()));
            screens.borrow_mut().collegamento_per = Some(content_id);
        }
        Err(errore) => {
            clear_link_request(window);
            window.set_history_link_sentence(crate::lingua::schermo(errore.operator_message()));
            screens.borrow_mut().collegamento_per = Some(content_id);
        }
    }
}

/// Chiude il percorso del risultato e ne svuota le righe.
///
/// Svuotare non è cosmetico: un pannello chiuso che conserva le righe le
/// rimostrerebbe alla riapertura, e per un istante quelle righe
/// apparterrebbero al contenuto sbagliato.
fn close_why(window: &AppWindow) {
    window.set_history_why_open(false);
    window.set_history_why_subject(SharedString::default());
    window.set_history_why_origin(SharedString::default());
    window.set_history_why_version_warning(SharedString::default());
    window.set_history_why_engine(SharedString::default());
    window.set_history_why_scoring(SharedString::default());
    window.set_history_why_scoring_trustworthy(false);
    window.set_history_why_alert(SharedString::default());
    window.set_history_why_terms(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
    window.set_history_why_decisions(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
}

/// Apre il percorso che ha portato un risultato davanti all'operatore.
///
/// # Che cosa questa funzione non fa
///
/// Non scrive nulla: né audit, né revisione, né contatori. È una lettura, ed è
/// la ragione di ADR-0052 Decisione 4 — l'audit documenta le **azioni**, e
/// chiedersi perché si sta vedendo qualcosa non è un'azione di cui qualcuno
/// risponda.
fn open_why(window: &AppWindow, screens: &SharedHistory, content_id: i32) {
    let id = lisi_core::ContentId::new(i64::from(content_id));

    let percorso = match screens.borrow().provenance.explain(id) {
        Ok(percorso) => percorso,
        Err(errore) => {
            window.set_history_message(crate::lingua::schermo(errore.operator_message()));
            close_why(window);
            return;
        }
    };

    // I termini trovati, ciascuno con il dizionario da cui veniva. Un termine
    // di cui la fotografia della sessione non sa nulla resta nell'elenco e lo
    // dichiara: toglierlo farebbe credere completo un elenco che non lo e'.
    let termini: Vec<crate::ProvenanceTermEntry> = percorso
        .scoring
        .contributions
        .iter()
        .map(|contributo| crate::ProvenanceTermEntry {
            text: crate::lingua::schermo(contributo.as_sentence()),
            origin: SharedString::from(if contributo.dictionaries.is_empty() {
                String::from("provenienza non registrata")
            } else {
                contributo.dictionaries.join(", ")
            }),
            position: crate::lingua::schermo(format!(
                "dal carattere {}",
                contributo.first_position.start()
            )),
            mitigating: contributo.is_mitigating(),
            known: contributo.has_documentary_origin(),
        })
        .collect();

    let decisioni: Vec<crate::ProvenanceDecisionEntry> = percorso
        .decisions
        .iter()
        .map(|decisione| crate::ProvenanceDecisionEntry {
            heading: crate::lingua::schermo(decisione.as_sentence()),
            note: SharedString::from(decisione.note.clone().unwrap_or_default()),
        })
        .collect();

    // Il soggetto: quale riga si sta guardando. Si riusa il riepilogo del
    // pannello della decisione invece di ricomporlo, come fa la cronologia:
    // due frasi da tenere allineate diventano due frasi che divergono.
    window.set_history_why_subject(window.get_selected_summary());
    window.set_history_why_origin(crate::lingua::schermo(percorso.origin.as_sentence()));
    window.set_history_why_version_warning(SharedString::from(
        percorso.version_warning().unwrap_or_default(),
    ));
    // CHI ha prodotto il livello, accanto a COME (ENGINE-01). Un livello e' il
    // prodotto di due cose: quali termini si cercavano — il dizionario, con la
    // sua versione — e come i riscontri diventano un numero — il motore, con la
    // sua. Fino a ENGINE-01 la seconda meta' non era scritta da nessuna parte.
    window.set_history_why_engine(crate::lingua::schermo(percorso.engine_sentence()));
    window.set_history_why_scoring(crate::lingua::schermo(
        percorso.scoring.explanation.as_sentence(),
    ));
    window.set_history_why_scoring_trustworthy(percorso.scoring_is_trustworthy());
    window.set_history_why_alert(SharedString::from(
        percorso
            .alert
            .as_ref()
            .map_or_else(String::new, |avviso| avviso.as_sentence()),
    ));
    window.set_history_why_terms(ModelRc::from(Rc::new(VecModel::from(termini))));
    window.set_history_why_decisions(ModelRc::from(Rc::new(VecModel::from(decisioni))));
    window.set_history_why_open(true);
}

/// «Perché vedo questo?» su ciò che si spiega da un contenuto (PR-02).
///
/// # Perché i fatti si leggono dall'archivio
///
/// Perché il livello e il riscontro vanno detti con la versione del motore
/// **registrata** con il contenuto, e la schermata non la conosce. La lettura
/// è la stessa del percorso intero (PROV-01), e come quella non scrive nulla.
///
/// # La porta
///
/// Porta al percorso dello stesso contenuto, tranne che dal riscontro: il
/// riscontro sta già dentro il percorso.
fn explain(
    window: &AppWindow,
    screens: &SharedHistory,
    genere: crate::Spiegabile,
    content_id: i32,
    fatti: &str,
) {
    if content_id <= 0 {
        return;
    }
    let id = lisi_core::ContentId::new(i64::from(content_id));
    let percorso = match screens.borrow().provenance.explain(id) {
        Ok(percorso) => percorso,
        Err(errore) => {
            window.set_history_message(crate::lingua::schermo(errore.operator_message()));
            return;
        }
    };

    let (risposta, porta) = match genere {
        crate::Spiegabile::Contenuto => (
            lisi_services::why::explain_content(&percorso),
            crate::explain::Door::ContentPath(content_id),
        ),
        crate::Spiegabile::Avviso => (
            lisi_services::why::explain_alert(&percorso),
            crate::explain::Door::ContentPath(content_id),
        ),
        crate::Spiegabile::Livello => (
            lisi_services::why::explain_level(&percorso),
            crate::explain::Door::ContentPath(content_id),
        ),
        crate::Spiegabile::Riscontro => (
            lisi_services::why::explain_recorded_match(&percorso, fatti),
            crate::explain::Door::Nowhere,
        ),
        // Gli altri generi non si spiegano da un contenuto: hanno la loro
        // strada (`crate::explain`), e rispondere qui darebbe loro la regola
        // sbagliata.
        _ => (None, crate::explain::Door::Nowhere),
    };

    if let Some(risposta) = risposta {
        crate::explain::show(window, &risposta, &porta);
    }
}

/// Aggiorna il pannello della decisione secondo la riga scelta.
///
/// Se la riga scelta non è più nell'elenco — perché la ricerca è cambiata — la
/// selezione si annulla: un pannello che decide su un contenuto non più
/// visibile agirebbe alla cieca.
fn refresh_selection(window: &AppWindow, screens: &HistoryScreens, entries: &[HistoryEntry]) {
    let selected = window.get_selected_content();
    if screens.collegamento_per != Some(selected) {
        clear_link_request(window);
    }
    let Some(entry) = entries
        .iter()
        .find(|entry| i32::try_from(entry.content.id.get()).unwrap_or(0) == selected)
    else {
        window.set_selected_content(-1);
        window.set_selected_summary(SharedString::default());
        window.set_selected_state(SharedString::default());
        window.set_selected_url(SharedString::default());
        window.set_selected_has_history(false);
        window.set_selected_revised(false);
        // La cronologia aperta riguardava la riga che non c'e' piu': lasciarla
        // aperta mostrerebbe le versioni di un contenuto che l'elenco non
        // contiene, e chi legge crederebbe che appartengano alla riga scelta
        // dopo. Vale identico per il percorso del risultato: una spiegazione
        // e' la spiegazione DI QUALCOSA, e sotto la riga sbagliata diventa una
        // falsa attribuzione.
        close_story(window);
        close_why(window);
        close_replay(window);
        window.set_selected_author_identifier(SharedString::default());
        window.set_selected_author_subjects(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        window.set_history_attachment_sentence(SharedString::default());
        crate::attachment::close(window);
        return;
    };

    // L'ALLEGATO (ATTACH-01): la frase della riga scelta. La scheda aperta per
    // un altro contenuto si chiude: chiederebbe per la riga sbagliata.
    window.set_history_attachment_sentence(SharedString::from(crate::attachment::sentence(
        screens.database(),
        entry.content.id,
    )));
    if window.get_history_attachment_content() != selected {
        crate::attachment::close(window);
    }

    let summary = format!(
        "{} \u{2014} {} \u{2014} {}",
        entry.source_name.as_str(),
        entry.content.acquired_at.to_readable_local(),
        excerpt(entry.content.body.as_str())
    );
    window.set_selected_summary(SharedString::from(summary));
    window.set_selected_state(crate::lingua::schermo(entry.review_state().label()));
    // Il collegamento del contenuto, per l'apertura sicura dal pannello. Vuoto
    // se il contenuto non ne ha uno.
    window.set_selected_url(SharedString::from(
        entry.content.url.as_ref().map_or("", |url| url.as_str()),
    ));
    window.set_selected_has_history(entry.history.has_anything_to_show());
    window.set_selected_revised(entry.history.was_revised());

    // Nulla da leggere dal servizio della revisione: lo stato e' gia' nella
    // riga. Il servizio serve per scrivere, e resta qui perche' il pannello
    // possa dirlo con la stessa parola del dominio.
    // DALL'AUTORE AL SOGGETTO (GAP-12): i soggetti collegati da una persona
    // all'autore del messaggio scelto, se ha un identificativo.
    let identificativo = entry
        .content
        .author_identifier
        .clone()
        .filter(|id| !id.trim().is_empty())
        .unwrap_or_default();
    window.set_selected_author_subjects(crate::author_subject::rows(
        screens.database(),
        &identificativo,
    ));
    window.set_selected_author_identifier(SharedString::from(identificativo));
}

/// Registra la decisione e riporta la risposta del servizio.
fn decide(screens: &SharedHistory, content_id: i32, state: &str, note: &str) -> String {
    let Ok(state) = state.parse::<ReviewState>() else {
        // Le varianti arrivano dall'interfaccia come testo del dominio: una
        // non riconosciuta e' un difetto del prodotto, non un errore
        // dell'operatore, e va detto come tale.
        tracing::error!(stato = state, "stato di revisione non riconosciuto");
        return String::from("Comando non riconosciuto: segnalarlo all'assistenza.");
    };

    let outcome = actor().and_then(|actor| {
        screens.borrow().review.record(
            lisi_core::ContentId::new(i64::from(content_id)),
            state,
            &actor,
            Some(note),
            now(),
        )
    });

    match outcome {
        Ok(()) => format!("Decisione registrata: {}.", state.label()),
        Err(error) => describe(&error),
    }
}

/// Produce il rapporto della sessione scelta.
///
/// I contenuti esportati sono quelli **della sessione**, non quelli filtrati
/// dalla ricerca: un rapporto che documentasse solo ciò che l'operatore stava
/// cercando in quel momento sarebbe un documento parziale che non dichiara di
/// esserlo.
fn export(screens: &SharedHistory, index: i32, options: ExportOptions) -> String {
    let screens = screens.borrow();

    let HistoryScope::Session(session_id) = session_scope(&screens, index) else {
        return String::from(
            "Il rapporto documenta una sola sessione: sceglierne una dall'elenco.",
        );
    };

    // La cartella la decide il servizio: tiene conto della scelta conservata
    // e ripiega sulla predefinita. Deciderlo qui vorrebbe dire che esportare e
    // verificare possono guardare in due cartelle diverse.
    let directory = match screens.export.destination() {
        Ok(directory) => directory,
        Err(error) => return describe(&error),
    };

    // L'elenco delle persone si allega **solo** a un rapporto che riporta gli
    // identificativi: un documento che dichiara di non nominare nessuno e poi
    // allega l'elenco di chi ha scritto direbbe una cosa e ne farebbe un'altra.
    //
    // Chi compone l'elenco è il servizio che possiede la regola: senza una
    // ragione registrata nell'audit rifiuta, e qui si passa `None`. Il rapporto
    // lo dice invece di tacere, perché dall'assenza di una sezione non si deve
    // poter dedurre che non ci fossero autori.
    let people = if options.include_author_identifiers {
        screens
            .participants
            .list(session_id)
            .map_err(|error| {
                tracing::info!(
                    kind = error.kind(),
                    "elenco delle persone non allegato al rapporto"
                );
            })
            .ok()
    } else {
        None
    };

    let outcome = screens
        .history
        .entries(HistoryScope::Session(session_id))
        .and_then(|entries| {
            let actor = actor()?;
            screens.export.export_session(
                session_id,
                &entries,
                &directory,
                &actor,
                now(),
                options,
                people.as_ref(),
            )
        });

    match outcome {
        Ok(produced) => produced.operator_message(),
        Err(error) => describe(&error),
    }
}

/// Traduce un errore del servizio in un messaggio per l'operatore.
fn describe(error: &ServiceError) -> String {
    tracing::warn!(kind = error.kind(), "decisione non registrata");
    error.operator_message()
}

/// Collega i comandi delle schermate ai servizi.
/// Chiede all'operatore la cartella dei documenti.
///
/// Il percorso si sceglie e non si digita: una cartella scelta da una finestra
/// di sistema esiste per costruzione, e non c'e' un testo da convalidare che
/// possa contenere qualcosa di inatteso (DEC-113).
fn export_destination_dialog(current: Option<&std::path::Path>) -> rfd::AsyncFileDialog {
    let mut dialog = rfd::AsyncFileDialog::new().set_title("Scegliere la cartella dei documenti");
    if let Some(path) = current {
        dialog = dialog.set_directory(path);
    }
    dialog
}

/// Conserva la cartella scelta e ne riporta l'esito all'operatore.
fn save_destination(screens: &SharedHistory, chosen: &std::path::Path) -> String {
    // Convalidata comunque, benche' venga da una finestra di sistema: il tipo
    // di dominio e' l'unico posto dove questa regola vive, e farla valere solo
    // per la strada che sembra pericolosa significa non farla valere.
    let destination = match ExportDestination::try_new(chosen) {
        Ok(destination) => destination,
        Err(error) => return describe(&error.into()),
    };

    let outcome = actor().and_then(|actor| {
        screens
            .borrow()
            .export
            .save_destination(Some(&destination), &actor, now())
    });

    match outcome {
        Ok(()) => format!(
            "I documenti andranno in {}. Vale anche per la verifica.",
            destination.as_str()
        ),
        Err(error) => describe(&error),
    }
}

pub fn wire(window: &AppWindow, screens: &SharedHistory, session: Option<&SharedSession>) {
    {
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        window.on_history_shown(move || {
            if let Some(window) = handle.upgrade() {
                refresh(&window, &screens, Some(""));
            }
        });
    }

    {
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        window.on_filter_history(move || {
            if crate::lock::refuse_while_locked("filter_history") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                refresh(&window, &screens, None);
            }
        });
    }

    {
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        window.on_choose_session(move |index| {
            if crate::lock::refuse_while_locked("choose_session") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            // Cambiare sessione svuota la selezione: il contenuto scelto
            // potrebbe non appartenere alla sessione ora mostrata.
            window.set_history_session_index(index);
            window.set_selected_content(-1);
            window.set_review_note(SharedString::default());
            refresh(&window, &screens, Some(""));
        });
    }

    {
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        window.on_export_session(move || {
            if crate::lock::refuse_while_locked("export_session") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            // La scelta si legge **al momento del comando**, non si conserva:
            // vale per questo rapporto e non diventa una preferenza.
            let options = if window.get_include_author_identifiers() {
                ExportOptions::with_identifiers()
            } else {
                ExportOptions::without_identifiers()
            };
            let message = export(&screens, window.get_history_session_index(), options);
            refresh(&window, &screens, Some(&message));
        });
    }

    {
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        window.on_choose_export_destination(move || {
            if crate::lock::refuse_while_locked("choose_export_destination") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let corrente = screens.borrow().export.destination().ok();
            // Finestra chiusa senza scegliere: non e' un errore e non cambia
            // nulla.
            let screens = Rc::clone(&screens);
            crate::dialogs::ask(
                &window,
                export_destination_dialog(corrente.as_deref()),
                crate::dialogs::Pick::Folder,
                "export_destination",
                move |window, scelta| {
                    let message = save_destination(&screens, &scelta);
                    refresh(window, &screens, Some(&message));
                },
            );
        });
    }

    {
        // DALLA CODA DI LAVORO AL MESSAGGIO (OPERATOR-UX-REMEDIATION-01, OS-10).
        //
        // La coda diceva che cosa aspettava e non permetteva di guardarlo: il
        // clic su una voce non apriva nulla. Ora apre gli Avvisi su tutte le
        // sessioni, senza filtro, con il messaggio scelto e il pannello della
        // decisione: è lo stesso pannello in cui si decide ogni altro messaggio,
        // non un secondo.
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        window.on_work_queue_open(move |content_id| {
            if crate::lock::refuse_while_locked("work_queue_open") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            window.invoke_open_page(PAGINA_AVVISI);
            window.set_history_filter(SharedString::default());
            window.set_history_session_index(0);
            window.set_selected_content(content_id);
            window.set_review_note(SharedString::default());
            close_story(&window);
            close_why(&window);
            close_replay(&window);
            close_resembling(&window);
            // IL CAMBIO DI SCHERMATA SI DICE (UX-EXCELLENCE-02, SIM3-19): dalla
            // Coda si arrivava negli Avvisi senza che nulla lo segnalasse.
            refresh(
                &window,
                &screens,
                Some(
                    "Aperto dalla Coda di lavoro: si decide qui sotto. Per tornare, «Coda \
                     di lavoro» nel menu.",
                ),
            );
            // LA RIGA APERTA IN VISTA, A SCHERMATA DISPOSTA (SIM3-19). La
            // schermata Avvisi nasce dopo questo gestore: si chiede di portare in
            // vista la riga un istante dopo, quando l'elenco esiste.
            let ancora = window.as_weak();
            slint::Timer::single_shot(std::time::Duration::from_millis(150), move || {
                if let Some(window) = ancora.upgrade() {
                    window.set_history_reveal_request(
                        window.get_history_reveal_request().wrapping_add(1),
                    );
                }
            });
        });
    }

    {
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        window.on_select_content(move |content_id| {
            if crate::lock::refuse_while_locked("select_content") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            // Scegliere un'altra riga svuota la nota: una motivazione scritta
            // per un contenuto non deve accompagnare la decisione su un altro.
            let already = window.get_selected_content() == content_id;
            window.set_selected_content(if already { -1 } else { content_id });
            window.set_review_note(SharedString::default());
            // Cambiare riga chiude la cronologia aperta, per la stessa ragione
            // per cui svuota la nota: le versioni di un contenuto non devono
            // restare sotto gli occhi di chi ne ha scelto un altro. E con essa
            // il percorso del risultato, che risponde a «perche' STO VEDENDO
            // QUESTO» e non un altro.
            close_story(&window);
            close_why(&window);
            // E con essi l'ipotesi del replay: e' l'ipotesi su un contenuto,
            // e su un altro contenuto sarebbe l'ipotesi sbagliata.
            close_replay(&window);
            close_resembling(&window);
            refresh(&window, &screens, None);
        });
    }

    {
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        window.on_history_open_story(move |content_id| {
            if crate::lock::refuse_while_locked("history_open_story") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            open_story(&window, &screens, content_id);
        });
    }

    {
        let handle = window.as_weak();
        window.on_history_close_story(move || {
            if crate::lock::refuse_while_locked("history_close_story") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                close_story(&window);
            }
        });
    }

    {
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        window.on_history_open_why(move |content_id| {
            if crate::lock::refuse_while_locked("history_open_why") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            open_why(&window, &screens, content_id);
        });
    }

    {
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        window.on_history_explain(move |genere, content_id, fatti| {
            if crate::lock::refuse_while_locked("history_explain") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            explain(&window, &screens, genere, content_id, fatti.as_str());
        });
    }

    {
        let handle = window.as_weak();
        window.on_history_close_why(move || {
            if crate::lock::refuse_while_locked("history_close_why") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                close_why(&window);
            }
        });
    }

    {
        // IL REPLAY, su richiesta.
        //
        // Riesegue l'analisi del contenuto scelto con il motore di adesso, e
        // mostra il fatto accanto all'ipotesi. Non scrive nulla.
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        window.on_history_open_replay(move |content_id| {
            if crate::lock::refuse_while_locked("history_open_replay") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            open_replay(&window, &screens, content_id);
        });
    }

    {
        // LE SOMIGLIANZE, su richiesta.
        //
        // Cerca nella sessione i contenuti che somigliano a quello scelto, e
        // mostra le sequenze condivise: sono il perché. Non scrive nulla, e non
        // dice che siano duplicati — quello è uno stato della revisione, cioè
        // la decisione di una persona (SIM-01, ADR-0055).
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        window.on_history_open_resembling(move |content_id| {
            if crate::lock::refuse_while_locked("history_open_resembling") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            open_resembling(&window, &screens, content_id);
        });
    }

    {
        let handle = window.as_weak();
        window.on_history_close_resembling(move || {
            if crate::lock::refuse_while_locked("history_close_resembling") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                close_resembling(&window);
            }
        });
    }

    {
        // CHIEDERE IL COLLEGAMENTO, su richiesta (CA02-14, DG-02): al momento,
        // mai conservato.
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        let session = session.map(Rc::clone);
        window.on_history_request_link(move |content_id| {
            if crate::lock::refuse_while_locked("history_request_link") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            request_link(&window, &screens, session.as_ref(), content_id);
        });
    }

    {
        let handle = window.as_weak();
        window.on_history_close_replay(move || {
            if crate::lock::refuse_while_locked("history_close_replay") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                close_replay(&window);
            }
        });
    }

    {
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        window.on_record_review(move |state| {
            if crate::lock::refuse_while_locked("record_review") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let content_id = window.get_selected_content();
            if content_id < 0 {
                refresh(
                    &window,
                    &screens,
                    Some("Scegliere prima il contenuto su cui decidere."),
                );
                return;
            }

            let note = window.get_review_note().to_string();
            let message = decide(&screens, content_id, state.as_str(), &note);

            // La nota si svuota solo se la decisione e' stata accettata: se il
            // servizio l'ha rifiutata, cancellarla costringerebbe a riscriverla.
            if message.starts_with("Decisione registrata") {
                window.set_review_note(SharedString::default());
            }
            refresh(&window, &screens, Some(&message));
        });
    }
}

/// Questo stesso file, letto a tempo di compilazione.
///
/// Serve alla guardia strutturale sull'elenco delle persone allegato ai
/// rapporti: che venga davvero chiesto non è verificabile senza un archivio
/// popolato e una cartella scrivibile, ma la sua **assenza** sì.
#[cfg(test)]
const THIS_MODULE: &str = include_str!("history.rs");

#[cfg(test)]
mod tests {
    use super::{EXCERPT_CHARS, excerpt};

    /// **Per un contenuto recuperato l'elenco mostra la pubblicazione**
    /// (E2E01-06), e l'acquisizione con la sua parola: le due ore non si
    /// scambiano. Dal vivo la riga resta com'era.
    #[test]
    fn un_contenuto_recuperato_mostra_quando_e_stato_pubblicato() {
        use lisi_core::Timestamp;
        use lisi_core::model::AcquisitionMode;

        let pubblicato = Timestamp::from_millis(1_760_000_000_000);
        let recuperato = Timestamp::from_millis(1_760_600_000_000);
        let modo = AcquisitionMode::Recovered {
            at: recuperato,
            interval: None,
            operator: None,
        };

        let pubblicazione = super::published_label(&modo, pubblicato);
        assert_eq!(
            pubblicazione,
            format!("pubblicato {}", pubblicato.to_readable_local())
        );
        assert_eq!(
            super::acquired_label(&modo, recuperato),
            format!("acquisito {}", recuperato.to_readable_local())
        );
        assert_eq!(
            super::published_label(&AcquisitionMode::Undetermined, pubblicato),
            pubblicazione,
            "anche un modo non determinabile mostra la pubblicazione"
        );

        assert_eq!(
            super::published_label(&AcquisitionMode::Live, pubblicato),
            ""
        );
        assert_eq!(
            super::acquired_label(&AcquisitionMode::Live, recuperato),
            recuperato.to_readable_local()
        );
    }

    /// **Un modo non determinabile non si mostra come «dal vivo»** (PR-07,
    /// controllo negativo 10): la riga resta vuota soltanto per ciò che è
    /// stato acquisito dal vivo.
    #[test]
    fn solo_il_dal_vivo_lascia_la_riga_senza_etichetta() {
        use lisi_core::Timestamp;
        use lisi_core::model::AcquisitionMode;

        assert_eq!(super::mode_label(&AcquisitionMode::Live).as_str(), "");
        assert_eq!(
            super::mode_label(&AcquisitionMode::Undetermined).as_str(),
            "modo non determinabile"
        );
        let recuperato = AcquisitionMode::Recovered {
            at: Timestamp::from_millis(0),
            interval: None,
            operator: None,
        };
        assert_eq!(super::mode_label(&recuperato).as_str(), "recuperato");
    }

    /// **La schermata del recupero dice ciò che un recupero non vede**, con la
    /// stessa frase dell'atto e dell'allegato (ADR-0123 §5).
    #[test]
    fn la_sezione_del_recupero_dice_cio_che_non_vede() {
        const UI: &str = include_str!("../ui/app-window.slint");
        assert!(
            crate::surface_text::assegna(UI, "text", lisi_core::model::RECOVERY_LIMITS),
            "la frase dei limiti del recupero deve comparire, identica, nella schermata"
        );
        // Il comando che archivia un periodo esiste soltanto dopo la
        // ricognizione: prima non c'è nulla che si sappia di dover archiviare.
        let Some(posizione) = UI.find("label: @tr(\"Archivia come recuperati\");") else {
            panic!("il comando che archivia un periodo deve esistere");
        };
        let prima = &UI[posizione.saturating_sub(120)..posizione];
        assert!(prima.contains("if root.interval-awaiting-confirmation: HudButton {"));
    }

    /// Guardia strutturale: il rapporto chiede davvero l'elenco delle persone.
    ///
    /// **Il difetto da cui protegge** è quello che in questa serie si è già
    /// ripetuto cinque volte: un motore costruito, collaudato e mai invocato.
    /// `render_participants` in `lisi-services` è coperto da tre test e
    /// compone la sezione correttamente; se questo modulo passasse `None` per
    /// sempre, quei tre test resterebbero verdi e **nessun rapporto porterebbe
    /// mai l'elenco**. Il quality gate non se ne accorgerebbe: misura ciò che
    /// esiste, non ciò che nessuno chiama.
    ///
    /// Verifica anche il vincolo che conta: l'elenco si chiede **soltanto**
    /// quando il rapporto riporta già gli identificativi. Un documento che
    /// dichiara di non nominare nessuno e poi allega chi ha scritto direbbe una
    /// cosa e ne farebbe un'altra.
    #[test]
    fn the_report_actually_asks_for_the_list_of_people() {
        // Si scarta il modulo di prova: le stringhe cercate compaiono qui
        // sotto, e senza questo taglio il test **si soddisferebbe da solo** e
        // resterebbe verde dopo aver cancellato la chiamata vera.
        let Some((production, _)) = super::THIS_MODULE.split_once("#[cfg(test)]\nmod tests {")
        else {
            panic!("il modulo di prova deve essere riconoscibile per poterlo escludere");
        };
        let code: String = production
            .lines()
            .map(str::trim_start)
            .filter(|line| !line.starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            code.contains(".participants\n.list(session_id)"),
            "il rapporto non chiede piu' l'elenco delle persone: la sezione \
             esiste in lisi-services e non la riempirebbe nessuno"
        );
        assert!(
            code.contains("if options.include_author_identifiers"),
            "l'elenco delle persone non e' piu' subordinato alla scelta sugli \
             identificativi: un rapporto che dichiara di non nominare nessuno \
             potrebbe allegare chi ha scritto"
        );
    }

    #[test]
    fn a_short_body_is_shown_whole() {
        assert_eq!(excerpt("messaggio breve"), "messaggio breve");
    }

    #[test]
    fn a_long_body_is_cut_and_says_so() {
        let body = "a".repeat(EXCERPT_CHARS + 50);
        let shown = excerpt(&body);

        assert_eq!(shown.chars().count(), EXCERPT_CHARS + 1);
        assert!(
            shown.ends_with('\u{2026}'),
            "un testo troncato in silenzio farebbe credere completo un messaggio che non lo e'"
        );
    }

    #[test]
    fn the_cut_falls_between_characters_and_not_inside_one() {
        // Tagliare in byte spezzerebbe una lettera accentata a meta'.
        let body = "città".repeat(EXCERPT_CHARS);
        let shown = excerpt(&body);

        assert_eq!(shown.chars().count(), EXCERPT_CHARS + 1);
        assert!(shown.starts_with("città"));
    }

    #[test]
    fn control_characters_do_not_break_the_row() {
        // Un ritorno a capo dentro una riga di elenco ne romperebbe l'altezza,
        // e il contenuto arriva da una fonte remota: si tratta come ostile.
        assert_eq!(excerpt("prima\nseconda\tterza"), "prima seconda terza");
    }

    // L'etichetta del livello («Livello N — senso») vive ora nel dominio
    // (`AnalysisLevel::meaning`/`label`) ed è verificata da un test in
    // `lisi-core`: qui non si ripete, così che la fonte resti una sola.

    /// # Perche' una guardia strutturale e non un test di comportamento
    ///
    /// Perche' il difetto che questa guardia previene e' **silenzioso**:
    /// esportare in una cartella e verificare in un'altra non produce alcun
    /// errore. La schermata di verifica direbbe «nessun rapporto» guardando
    /// dove i rapporti non sono, e l'operatore concluderebbe che l'esportazione
    /// non ha funzionato.
    #[test]
    fn the_export_asks_the_service_where_to_write_instead_of_deciding_alone() {
        let Some((production, _)) = super::THIS_MODULE.split_once("#[cfg(test)]\nmod tests {")
        else {
            panic!("il modulo di prova deve essere riconoscibile per poterlo escludere");
        };
        let code: String = production
            .lines()
            .map(str::trim_start)
            .filter(|line| !line.starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            code.contains("screens.export.destination()"),
            "l'esportazione non chiede piu' al servizio dove scrivere: la \
             cartella scelta dall'ufficio verrebbe ignorata"
        );
        assert!(
            !code.contains("export_directory()"),
            "l'esportazione e' tornata a decidere da se' la cartella: la scelta \
             dell'ufficio e la verifica guarderebbero in due posti diversi"
        );
    }

    #[test]
    fn the_chosen_folder_is_validated_even_though_it_comes_from_a_system_dialog() {
        let Some((production, _)) = super::THIS_MODULE.split_once("#[cfg(test)]\nmod tests {")
        else {
            panic!("il modulo di prova deve essere riconoscibile per poterlo escludere");
        };
        let code: String = production
            .lines()
            .map(str::trim_start)
            .filter(|line| !line.starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            code.contains("ExportDestination::try_new(chosen)"),
            "la cartella scelta non passa piu' dal tipo di dominio: far valere \
             la regola solo sulla strada che sembra pericolosa significa non \
             farla valere"
        );
    }

    // ----------------------------------------------- CTX-01: la cronologia

    /// Interfaccia principale, letta a tempo di compilazione.
    const UI: &str = include_str!("../ui/app-window.slint");

    /// **L'etichetta della cancellazione nomina Telegram.**
    ///
    /// «Eliminato» da solo, accanto a una riga di NEXUM/97, si legge come «il
    /// programma lo ha eliminato». Il programma non cancella nulla: ha
    /// osservato che la fonte non espone piu' il messaggio.
    ///
    /// La verifica sta sul **dominio**, dove la frase nasce, e non
    /// sull'interfaccia, che la riceve gia' composta.
    #[test]
    fn letichetta_della_cancellazione_non_attribuisce_la_cancellazione_al_prodotto() {
        use lisi_core::model::content_history::ContentHistorySummary;

        let cancellato = ContentHistorySummary {
            revisions: 0,
            last_revision_at: None,
            deleted_at: Some(lisi_core::Timestamp::from_millis(1_000)),
        };

        let Some(etichetta) = cancellato.short_label() else {
            panic!("un contenuto cancellato deve avere un'etichetta");
        };
        assert!(
            etichetta.contains("su Telegram"),
            "l'etichetta deve dire DOVE il messaggio non e' piu' esposto: «{etichetta}»"
        );
    }

    /// **Il pannello dice che il livello riguarda la versione acquisita.**
    ///
    /// E' la cosa che nessuna schermata diceva, ed e' quella che cambia il modo
    /// di leggere una riga: il testo e il livello mostrati nello Storico sono
    /// quelli del corpo con cui il contenuto e' stato acquisito, perche'
    /// l'analisi non viene rifatta su una modifica.
    #[test]
    fn il_pannello_dichiara_che_il_livello_riguarda_la_versione_acquisita() {
        assert!(
            UI.contains("sono quelli della versione acquisita"),
            "il pannello della decisione deve avvertire che il livello non \
             riguarda l'ultima versione osservata"
        );
        assert!(
            UI.contains("Versione 1 \\u{2014} acquisita e analizzata")
                || UI.contains("versione.original"),
            "la cronologia deve distinguere la versione analizzata dalle altre"
        );
    }

    /// **Il pannello dichiara che l'archivio conserva cio' che aveva gia'
    /// acquisito.**
    ///
    /// Chi apre la cronologia di un messaggio non piu' esposto deve sapere che
    /// cio' che legge resta, e che non e' stato il prodotto a rimuoverlo.
    #[test]
    fn il_pannello_di_un_messaggio_eliminato_dice_che_larchivio_conserva() {
        assert!(
            UI.contains("non risulta più esposto da Telegram"),
            "il pannello deve dire che e' la fonte a non esporlo piu'"
        );
        assert!(
            UI.contains("resta nell'archivio"),
            "il pannello deve dire che cio' che era stato acquisito resta"
        );
    }

    /// **La cronologia si apre solo dove c'e' qualcosa da aprire.**
    ///
    /// Un comando offerto su ogni riga per mostrare «nessuna modifica» e' un
    /// comando che non porta da nessuna parte.
    #[test]
    fn il_comando_della_cronologia_compare_solo_dove_serve() {
        assert!(
            UI.contains("if root.selected-has-history:"),
            "il comando deve essere condizionato all'esistenza di una storia"
        );
        assert!(
            UI.contains("if root.story-open:"),
            "il pannello deve comparire solo quando e' stato aperto"
        );
    }

    /// **L'etichetta della storia viene letta ad alta voce.**
    ///
    /// Chi usa una tecnologia assistiva non vede il colore ambra, e senza
    /// l'etichetta nel testo accessibile perderebbe l'informazione piu' utile
    /// della riga.
    #[test]
    fn letichetta_della_storia_entra_nel_testo_accessibile() {
        assert!(
            UI.contains("entry.history-label != \"\" ? \", \" + entry.history-label"),
            "l'etichetta deve entrare nell'accessible-label della riga"
        );
    }

    /// **Il pannello non promette un confronto parola per parola.**
    ///
    /// Su un testo riscritto un allineamento automatico accosta pezzi che
    /// nessuno ha messo in relazione, e chi legge crede di vedere una modifica
    /// mirata dove c'e' stata una riscrittura. Il prodotto mostra le relazioni
    /// **esatte** e, quando non ne vale nessuna, i due testi interi.
    #[test]
    fn il_confronto_dichiara_i_propri_limiti() {
        use lisi_core::model::content_history::VersionChange;

        let frase = VersionChange::Rewritten.as_sentence();
        assert!(
            frase.contains("si leggono per intero"),
            "una riscrittura deve rimandare alla lettura dei due testi"
        );
        assert!(
            !UI.contains("differenze parola per parola"),
            "l'interfaccia non deve promettere un confronto che il prodotto non fa"
        );
    }

    /// **Consultare la cronologia non scrive nulla.**
    ///
    /// La verifica e' testuale e lo dichiara: il codice di produzione di questo
    /// modulo, nella funzione che apre il pannello, non deve chiamare alcun
    /// servizio di scrittura. Le versioni sono comunque immutabili per
    /// costruzione — due trigger dell'archivio lo impongono — e questa prova
    /// serve a che non venga aggiunta una scrittura accanto alla lettura.
    #[test]
    fn aprire_la_cronologia_non_scrive_nulla() {
        let Some((produzione, _)) = super::THIS_MODULE.split_once("#[cfg(test)]\nmod tests {")
        else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };

        let Some(inizio) = produzione.find("fn open_story(") else {
            panic!("la funzione che apre la cronologia deve esistere");
        };
        let Some(fine) = produzione[inizio..].find("\n}\n") else {
            panic!("la funzione deve avere una fine riconoscibile");
        };
        let corpo = &produzione[inizio..inizio + fine];

        for scrittura in ["review.", "append_", "insert_", "record(", "decide("] {
            assert!(
                !corpo.contains(scrittura),
                "aprire la cronologia chiama «{scrittura}»: la consultazione \
                 non deve toccare la storia"
            );
        }
    }

    /// Chiedere perché non scrive nulla.
    ///
    /// Vale la stessa ragione della cronologia (ADR-0052 Decisione 4): l'audit
    /// documenta le **azioni**, e chiedersi perché si sta vedendo qualcosa non
    /// è un'azione di cui qualcuno risponda. La verifica è testuale e lo
    /// dichiara: la funzione che apre il pannello non deve chiamare alcun
    /// servizio di scrittura.
    #[test]
    fn chiedere_perche_non_scrive_nulla() {
        let Some((produzione, _)) = super::THIS_MODULE.split_once("#[cfg(test)]\nmod tests {")
        else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };

        let Some(inizio) = produzione.find("fn open_why(") else {
            panic!("la funzione che apre il percorso deve esistere");
        };
        let Some(fine) = produzione[inizio..].find("\n}\n") else {
            panic!("la funzione deve avere una fine riconoscibile");
        };
        let corpo = &produzione[inizio..inizio + fine];

        for scrittura in [
            "review.", "append_", "insert_", "record(", "decide(", "audit",
        ] {
            assert!(
                !corpo.contains(scrittura),
                "aprire il percorso chiama «{scrittura}»: la consultazione non \
                 deve toccare la storia"
            );
        }
    }

    /// Il pannello tiene separate le tre nature, e in quest'ordine.
    ///
    /// È l'invariante che rende leggibile il percorso: **fatto osservato**,
    /// **elaborazione automatica**, **decisione umana**. Mescolarle
    /// produrrebbe esattamente la confusione che questo prodotto rifiuta —
    /// che ciò che la macchina ha calcolato si legga come ciò che qualcuno ha
    /// deciso.
    ///
    /// Da PR-03 le tre nature si chiamano come in ogni altra schermata —
    /// Osservato, Calcolato, Operatore — e si mostrano con il segno d'origine
    /// (ADR-0118). Prima il pannello le chiamava con tre nomi suoi.
    #[test]
    fn il_percorso_tiene_separate_le_tre_nature() {
        let Some(osservato) = UI.find("// ---------------------------------- osservato (ADR-0118)")
        else {
            panic!("il pannello deve dichiarare ciò che è osservato");
        };
        let Some(automatica) =
            UI.find("// ---------------------------------- calcolato (ADR-0118)")
        else {
            panic!("il pannello deve dichiarare ciò che è calcolato");
        };
        let Some(umana) = UI.find("// ---------------------------------- operatore (ADR-0118)")
        else {
            panic!("il pannello deve dichiarare ciò che ha deciso una persona");
        };
        for (marcatore, origine) in [
            (osservato, "Origine.osservato"),
            (automatica, "Origine.calcolato"),
            (umana, "Origine.operatore"),
        ] {
            let dopo = UI.get(marcatore..marcatore + 300).unwrap_or_default();
            assert!(
                dopo.contains(&format!("OrigineSegno {{ origine: {origine}; }}")),
                "la sezione deve mostrare il segno «{origine}»"
            );
        }

        assert!(
            osservato < automatica,
            "il fatto osservato viene prima di ciò che la macchina ne ha fatto"
        );
        assert!(
            automatica < umana,
            "l'elaborazione automatica viene prima della decisione umana"
        );
    }

    /// Una spiegazione non verificata non si presenta come la causa.
    ///
    /// È la regola centrale di PROV-01. Nel pannello si traduce in un colore:
    /// la frase dello scoring è in ambra quando `why-scoring-trustworthy` è
    /// falso, cioè quando dichiara una lacuna o una discordanza invece di
    /// spiegare. Senza quella distinzione, «non lo so» si leggerebbe come
    /// «ecco perché».
    #[test]
    fn una_spiegazione_non_verificata_si_distingue_a_vista() {
        assert!(
            UI.contains("root.why-scoring-trustworthy ? Palette.text : Palette.amber"),
            "la frase dello scoring deve distinguere a vista una spiegazione \
             verificata da una lacuna dichiarata"
        );
    }

    /// I comandi del livello e di tutta la provenienza compaiono per ogni riga
    /// scelta, non solo per quelle segnalate.
    ///
    /// La domanda ha senso anche — e forse soprattutto — davanti a un livello
    /// 0: la risposta è «nessun termine della configurazione compare qui», ed è
    /// esattamente ciò che un operatore ha bisogno di sapere quando si chiede
    /// perché un contenuto **non** è stato segnalato.
    #[test]
    fn il_comando_del_percorso_non_dipende_da_un_avviso() {
        let Some(comando) = UI.find("label: @tr(\"Provenienza, note e contesto\")") else {
            panic!("il comando deve esistere");
        };

        // Si risale al blocco che lo contiene: non deve essere condizionato
        // alla presenza di una storia o di un avviso.
        let inizio = UI[..comando].rfind("HorizontalLayout {").unwrap_or(0);
        let blocco = &UI[inizio..comando];

        for condizione in ["selected-has-history", "selected-revised", "level >"] {
            assert!(
                !blocco.contains(condizione),
                "il comando è condizionato a «{condizione}»: la domanda vale per \
                 ogni riga, anche per un livello 0"
            );
        }
    }

    /// Chiudere il percorso ne svuota le righe.
    ///
    /// Un pannello chiuso che conserva le righe le rimostrerebbe alla
    /// riapertura, e per un istante quelle righe apparterrebbero al contenuto
    /// sbagliato: è una falsa attribuzione, breve ma vera.
    #[test]
    fn chiudere_il_percorso_ne_svuota_le_righe() {
        let Some((produzione, _)) = super::THIS_MODULE.split_once("#[cfg(test)]\nmod tests {")
        else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };

        let Some(inizio) = produzione.find("fn close_why(") else {
            panic!("la funzione che chiude il percorso deve esistere");
        };
        let Some(fine) = produzione[inizio..].find("\n}\n") else {
            panic!("la funzione deve avere una fine riconoscibile");
        };
        let corpo = &produzione[inizio..inizio + fine];

        for svuotata in [
            "set_history_why_open(false)",
            "set_history_why_terms",
            "set_history_why_decisions",
            "set_history_why_scoring_trustworthy(false)",
        ] {
            assert!(
                corpo.contains(svuotata),
                "chiudere il percorso non azzera «{svuotata}»"
            );
        }
    }

    /// Cambiare riga chiude il percorso aperto.
    ///
    /// Una spiegazione è la spiegazione **di qualcosa**: lasciata sotto la riga
    /// sbagliata diventa una falsa attribuzione.
    #[test]
    fn cambiare_riga_chiude_il_percorso() {
        let Some((produzione, _)) = super::THIS_MODULE.split_once("#[cfg(test)]\nmod tests {")
        else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };

        let Some(inizio) = produzione.find("window.on_select_content(") else {
            panic!("la scelta della riga deve essere gestita");
        };
        let Some(fine) = produzione[inizio..].find("\n        });") else {
            panic!("il gestore deve avere una fine riconoscibile");
        };
        let corpo = &produzione[inizio..inizio + fine];

        assert!(
            corpo.contains("close_why(&window)"),
            "cambiare riga non chiude il percorso del risultato"
        );
    }
}

#[cfg(test)]
mod motore {
    /// Il file dell'interfaccia, per le guardie testuali.
    const UI: &str = include_str!("../ui/app-window.slint");

    /// **Il pannello dice con quale motore il livello fu prodotto.**
    ///
    /// # Perché è una guardia e non una convenzione
    ///
    /// Perché un livello è il prodotto di **due** cose: quali termini si
    /// cercavano — il dizionario, con la sua versione — e come i riscontri
    /// diventano un numero — il motore, con la sua. Fino a ENGINE-01 la seconda
    /// metà non era scritta da nessuna parte, e chi rileggeva un atto poteva
    /// sapere quali termini erano stati usati ma non quale formula li avesse
    /// pesati.
    #[test]
    fn il_pannello_dice_con_quale_motore_il_livello_fu_prodotto() {
        assert!(
            UI.contains("text: root.why-engine;"),
            "il motore che ha prodotto il livello deve comparire nel pannello"
        );

        let (Some(motore), Some(punteggio)) = (
            UI.find("text: root.why-engine;"),
            UI.find("text: root.why-scoring;"),
        ) else {
            panic!("entrambe le righe devono esistere");
        };
        assert!(
            motore < punteggio,
            "chi ha prodotto il livello va detto prima di come lo ha prodotto"
        );
    }
}

#[cfg(test)]
mod replay_ipotetico {
    /// Il file dell'interfaccia, per le guardie testuali.
    const UI: &str = include_str!("../ui/app-window.slint");

    /// Questo modulo, per verificare che cosa il codice di produzione fa.
    const THIS_MODULE: &str = include_str!("history.rs");

    /// Il corpo di un blocco del codice di produzione, fino al terminatore
    /// indicato.
    ///
    /// # Perché il terminatore si passa
    ///
    /// Perché una funzione libera finisce con `\n}\n`, ma la chiusura di un
    /// gestore di comandi finisce con `\n        });` — e cercare il primo
    /// terminatore su un gestore restituirebbe **tutto il resto della
    /// funzione che lo registra**, comprese le chiusure successive.
    ///
    /// Il primo controllo negativo di questa milestone lo ha mostrato: tolto
    /// `close_replay` dal gestore giusto, la guardia e' rimasta verde perche'
    /// lo trovava in un gestore piu' sotto. Era la prova a essere debole.
    fn blocco_di(nome: &str, terminatore: &str) -> &'static str {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let Some(inizio) = produzione.find(nome) else {
            panic!("«{nome}» deve esistere");
        };
        let Some(fine) = produzione[inizio..].find(terminatore) else {
            panic!("«{nome}» deve avere una fine riconoscibile");
        };
        &produzione[inizio..inizio + fine]
    }

    /// **Il fatto viene prima dell'ipotesi, e sono due righe.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Su una riga sola, o con l'ipotesi in cima, i due numeri si leggerebbero
    /// come due misure della stessa cosa — e la seconda finirebbe per essere
    /// presa per buona quanto la prima. Il livello registrato è ciò su cui gli
    /// avvisi sono stati emessi e i rapporti scritti; l'ipotesi non è stata
    /// applicata a nulla.
    #[test]
    fn il_fatto_viene_prima_dell_ipotesi_e_sono_due_righe() {
        let (Some(fatto), Some(ipotesi)) = (
            UI.find("text: root.replay-historical;"),
            UI.find("text: root.replay-hypothetical;"),
        ) else {
            panic!("le due righe devono esistere entrambe");
        };

        assert!(
            fatto < ipotesi,
            "il livello registrato va detto prima dell'ipotesi: è il fatto, e l'altra è \
             una domanda che qualcuno si è posto oggi"
        );
        assert!(
            !UI.contains("root.replay-historical + root.replay-hypothetical"),
            "il fatto e l'ipotesi non vanno uniti in una riga sola"
        );
    }

    /// **L'ipotesi non compare da sola: qualcuno deve chiederla.**
    ///
    /// Un livello ipotetico mostrato senza che nessuno lo abbia chiesto
    /// verrebbe letto come un secondo livello del contenuto, e il contenuto ne
    /// ha uno solo.
    #[test]
    fn l_ipotesi_compare_solo_se_qualcuno_la_chiede() {
        assert!(
            UI.contains("if root.replay-open: Rectangle {"),
            "il replay deve aprirsi su richiesta"
        );
        assert!(
            UI.contains("root.open-replay(root.selected);"),
            "deve esistere il comando che lo chiede"
        );
        assert!(
            UI.contains("root.close-replay();"),
            "il replay deve potersi chiudere"
        );
    }

    /// **Cambiare riga chiude l'ipotesi.**
    ///
    /// Un'ipotesi che restasse sotto gli occhi dopo aver scelto un'altra riga
    /// sarebbe l'ipotesi di un contenuto diverso, e nessuno se ne accorgerebbe:
    /// i livelli si assomigliano tutti.
    #[test]
    fn cambiare_riga_chiude_l_ipotesi() {
        let corpo = blocco_di("window.on_select_content(", "\n        });");

        assert!(
            corpo.contains("close_replay(&window)"),
            "scegliere un'altra riga deve chiudere l'ipotesi della precedente"
        );
    }

    /// **Il replay non scrive nulla, e non tocca il livello registrato.**
    #[test]
    fn il_replay_non_scrive_e_non_tocca_il_livello_registrato() {
        let corpo = blocco_di("fn open_replay(", "\n}\n");

        for scrittura in [
            "record(",
            "insert_",
            "append_audit",
            "set_history_review",
            "AnalysisLevel",
        ] {
            assert!(
                !corpo.contains(scrittura),
                "aprire il replay nomina «{scrittura}»: il risultato storico è \
                 immutabile, e l'ipotesi non deve poterlo sostituire"
            );
        }
    }

    /// Senza la fotografia della sessione il replay lo dichiara.
    ///
    /// Rieseguire con i dizionari di oggi misurerebbe insieme il cambio di
    /// motore e il cambio di dizionari, e il livello che ne uscirebbe non
    /// direbbe niente di nessuno dei due.
    #[test]
    fn senza_la_fotografia_della_sessione_il_replay_lo_dichiara() {
        let corpo = blocco_di("fn open_replay(", "\n}\n");

        assert!(
            corpo.contains("non risulta la configurazione con cui fu condotta"),
            "l'assenza della fotografia va dichiarata"
        );
        assert!(
            corpo.contains("misurerebbe insieme il cambio di motore e il cambio di"),
            "va detto PERCHE' non si può eseguire"
        );
    }
}

/// Le somiglianze, come la schermata le mostra (SIM-01).
#[cfg(test)]
mod somiglianze {
    /// Il file dell'interfaccia, per le guardie testuali.
    const UI: &str = include_str!("../ui/app-window.slint");

    /// Questo modulo, per verificare che cosa il codice di produzione fa.
    const THIS_MODULE: &str = include_str!("history.rs");

    /// Il codice di produzione senza i commenti.
    fn codice_senza_commenti() -> String {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Il blocco che disegna la sezione delle somiglianze.
    ///
    /// # Perché non tutto il file
    ///
    /// Perché la parola «duplicato» **esiste e deve esistere** altrove: è uno
    /// degli stati della revisione, ed è la decisione che una persona registra.
    /// Cercarla nell'intero file farebbe diventare rossa una guardia per il
    /// comando giusto al posto giusto — l'errore già corretto in SPIKE-01, in
    /// LAB-02 e in HEALTH-01.
    /// # E perché non c'è un ripiego
    ///
    /// La prima scrittura di questo estrattore, non trovando la fine, tornava
    /// **tutto il resto del file**: la guardia si accendeva su una parola che
    /// stava trecento righe più in là, in un comando corretto. Un estrattore
    /// che allarga in silenzio è peggio di uno che non trova niente — la prova
    /// sembra funzionare, e sta guardando altro.
    ///
    /// Ora, se la fine non c'è, fallisce.
    fn sezione_delle_somiglianze() -> &'static str {
        let Some(inizio) = UI.find("if root.resembling-open: Rectangle {") else {
            panic!("la sezione delle somiglianze deve esistere");
        };
        let Some(fine) = UI[inizio..].find("text: root.why-scoring;") else {
            panic!("la sezione delle somiglianze deve avere una fine riconoscibile");
        };
        &UI[inizio..inizio + fine]
    }

    /// **La sezione non chiama «duplicato» ciò che si somiglia.**
    ///
    /// «Duplicato» è uno stato della revisione, cioè la decisione di una
    /// persona presa con motivo, istante e audit. Un algoritmo che producesse
    /// la stessa parola confonderebbe una misura con un giudizio registrato, e
    /// chi legge lo storico non saprebbe più quale delle due stia guardando.
    #[test]
    fn la_sezione_non_chiama_duplicato_cio_che_si_somiglia() {
        let sezione = sezione_delle_somiglianze().to_lowercase();
        for vietata in ["duplicato", "duplicati", "copia di", "identico a"] {
            assert!(
                !sezione.contains(vietata),
                "la sezione dice «{vietata}»: somigliarsi non e' la decisione di una persona"
            );
        }
    }

    /// **L'evidenza si mostra, non solo la percentuale.**
    ///
    /// Una percentuale non è un perché: è il risultato di un conto che chi
    /// legge non ha visto. Le sequenze condivise sono l'esito dell'algoritmo.
    #[test]
    fn l_evidenza_si_mostra_accanto_alla_percentuale() {
        let sezione = sezione_delle_somiglianze();

        assert!(
            sezione.contains("text: somiglianza.why;"),
            "la riga deve dire quanto si somigliano"
        );
        assert!(
            sezione.contains("text: somiglianza.evidence;"),
            "la riga deve mostrare le sequenze condivise: sono il perche'"
        );

        let Some(perche) = sezione.find("text: somiglianza.why;") else {
            panic!("la frase deve esserci");
        };
        let Some(evidenza) = sezione.find("text: somiglianza.evidence;") else {
            panic!("l'evidenza deve esserci");
        };
        assert!(
            perche < evidenza,
            "il conto si legge prima delle sequenze che lo giustificano"
        );
    }

    /// Le somiglianze **non compaiono se nessuno le chiede**.
    ///
    /// Il confronto legge tutti i contenuti della sessione, e costa.
    #[test]
    fn le_somiglianze_non_compaiono_se_nessuno_le_chiede() {
        assert!(
            UI.contains("in property <bool> resembling-open: false;"),
            "la sezione deve partire chiusa"
        );
        assert!(
            UI.contains("if !root.resembling-open: Rectangle {"),
            "deve esserci un comando che le chiede"
        );
    }

    /// **Cambiare riga chiude le somiglianze.**
    ///
    /// Righe che restassero sotto gli occhi dopo aver scelto un'altra riga
    /// sarebbero le somiglianze di un contenuto diverso, e nessuno se ne
    /// accorgerebbe.
    #[test]
    fn cambiare_riga_chiude_le_somiglianze() {
        let codice = codice_senza_commenti();
        let Some(inizio) = codice.find("window.on_select_content(move |content_id| {") else {
            panic!("il gestore del cambio di riga deve esistere");
        };
        let resto = &codice[inizio..];
        let Some(fine) = resto.find("\n        });") else {
            panic!("il gestore deve chiudersi");
        };
        assert!(
            resto[..fine].contains("close_resembling(&window)"),
            "cambiando riga le somiglianze precedenti devono sparire"
        );
    }

    /// **Il confronto non scrive, e la schermata non lo rifà.**
    ///
    /// L'algoritmo sta in `lisi-services::similarity`, che non conosce
    /// l'archivio: rifarlo qui creerebbe due nozioni di somiglianza nello
    /// stesso prodotto.
    #[test]
    fn la_schermata_non_rifa_il_confronto() {
        let codice = codice_senza_commenti();

        for aritmetica in [
            "shingles(",
            "intersection(",
            "MINIMUM_SHARED_PERCENT",
            "SHINGLE_WORDS",
        ] {
            assert!(
                !codice.contains(aritmetica),
                "la schermata usa «{aritmetica}»: il confronto lo compone il servizio"
            );
        }
        assert!(
            codice.contains("why: crate::lingua::schermo(somiglianza.as_sentence())"),
            "la frase la compone il servizio, non la schermata"
        );
    }
}

/// Le guardie di OPERATOR-UX-REMEDIATION-01 sulla schermata dei contenuti
/// (Avvisi e Storico): OS-01 e OS-02 del walkthrough OPERATOR-SIM-01.
#[cfg(test)]
mod remediation_ux {
    const UI: &str = include_str!("../ui/app-window.slint");

    /// Il corpo della componente `ContentScreen`.
    fn schermata() -> &'static str {
        let Some(inizio) = UI.find("component ContentScreen inherits Rectangle {") else {
            panic!("la schermata dei contenuti deve esistere");
        };
        let Some(fine) = UI[inizio..].find("\ncomponent WindowCommand") else {
            panic!("la schermata dei contenuti deve chiudersi");
        };
        &UI[inizio..inizio + fine]
    }

    /// Il pannello del messaggio scelto, dall'apertura alla fine della schermata.
    fn pannello() -> &'static str {
        let corpo = schermata();
        let Some(inizio) = corpo.find("if root.selected >= 0: Rectangle {") else {
            panic!("il pannello del messaggio scelto deve esistere");
        };
        &corpo[inizio..]
    }

    /// Il pannello «Tutta la provenienza», fino al pannello del messaggio scelto.
    fn provenienza() -> &'static str {
        let corpo = schermata();
        let (Some(inizio), Some(fine)) = (
            corpo.find("if root.why-open: Rectangle {"),
            corpo.find("if root.selected >= 0: Rectangle {"),
        ) else {
            panic!("i due pannelli devono esistere");
        };
        &corpo[inizio..fine]
    }

    /// **Il messaggio aperto si chiude** (OS-01): con un comando e con Esc,
    /// e cambiando schermata.
    #[test]
    fn il_messaggio_aperto_si_chiude() {
        let pannello = pannello();
        let Some(chiudi) = pannello.find("label: @tr(\"Chiudi\");") else {
            panic!("il pannello deve avere «Chiudi»");
        };
        assert!(
            pannello[chiudi..].starts_with(
                "label: @tr(\"Chiudi\");\n                        clicked => {\n                            root.select(root.selected);"
            ),
            "«Chiudi» sceglie di nuovo la riga aperta, che la finestra chiude"
        );
        assert!(
            schermata().contains("if (event.text == Key.Escape && root.selected >= 0) {"),
            "Esc chiude il messaggio aperto"
        );
        let Some(apertura) = UI.find("public function open-page(page: int) {") else {
            panic!("open-page deve esistere");
        };
        assert!(
            UI[apertura..].contains(
                "if (page != root.current-page && root.selected-content >= 0) {\n            root.select-content(root.selected-content);"
            ),
            "cambiare schermata chiude il messaggio aperto"
        );
    }

    /// **Il pannello non ha più un'altezza fissa, e ha un tetto** (OS-01): a
    /// 184 px fissi le ultime righe uscivano dal bordo; senza tetto l'elenco
    /// resterebbe senza spazio.
    #[test]
    fn il_pannello_ha_un_tetto_e_l_elenco_un_minimo() {
        let pannello = pannello();
        assert!(!pannello.contains("height: 184px;"));
        assert!(
            pannello.contains("preferred-height: min(dettaglio.preferred-height + 8px, 268px);")
        );
        // A finestra bassa il pannello scende e scorre invece di uscire dal
        // bordo (verifica a vista a 1136×759).
        assert!(pannello.contains("min-height: min(dettaglio.preferred-height + 8px, 120px);"));
        assert!(
            schermata().contains(
                "elenco := HudScroll {\n            min-height: root.compatta ? 0px : 150px;"
            ),
            "l'elenco ha almeno una riga in vista, salvo cederla al messaggio aperto"
        );
        assert!(
            schermata().contains("property <bool> compatta: root.selected >= 0;"),
            "l'elenco cede la riga soltanto con un messaggio aperto"
        );
    }

    /// **Segnare e raccogliere stanno nel pannello del messaggio, non nella
    /// provenienza** (OS-02): dentro «Tutta la provenienza» l'operatore
    /// simulato non li ha trovati.
    #[test]
    fn organizzare_sta_nel_pannello_del_messaggio() {
        let pannello = pannello();
        let provenienza = provenienza();
        for comando in [
            "label: root.marked ? @tr(\"Togli dai segnalibri\") : @tr(\"Aggiungi ai segnalibri\");",
            "root.collect-in-workspace(root.selected);",
        ] {
            assert!(pannello.contains(comando), "{comando} nel pannello");
            assert!(
                !provenienza.contains(comando),
                "{comando} non più nella provenienza"
            );
        }
        // E vengono prima della decisione: la prima riga dopo il nome.
        let (Some(segna), Some(decisione)) = (
            pannello.find("\"Aggiungi ai segnalibri\""),
            pannello.find("label: @tr(\"In esame\");"),
        ) else {
            panic!("i comandi devono esserci");
        };
        assert!(segna < decisione);
    }

    /// **Salvare ed esportare si aprono su richiesta** (OS-01): tre righe
    /// fisse sopra l'elenco erano lo spazio che mancava.
    #[test]
    fn salvare_ed_esportare_si_aprono_su_richiesta() {
        let corpo = schermata();
        assert!(corpo.contains("in-out property <bool> tools-open: false;"));
        for comando in [
            "label: @tr(\"Salva la ricerca\");",
            "label: @tr(\"Esporta rapporto\");",
            "label: @tr(\"Verifica esportati\");",
            r#"label: @tr("Cambia cartella\u{2026}");"#,
        ] {
            let Some(posizione) = corpo.find(comando) else {
                panic!("{comando} deve restare raggiungibile");
            };
            let Some(condizione) = corpo[..posizione].rfind("if root.tools-open: Rectangle {")
            else {
                panic!("{comando} sta in una riga che si apre su richiesta");
            };
            assert!(
                !corpo[condizione..posizione].contains("\n        }\n"),
                "{comando} sta dentro la riga condizionata"
            );
        }
    }

    /// **Dalla Coda di lavoro si apre il messaggio** (OS-10): la riga ne mostra
    /// l'inizio e «Apri il messaggio» porta agli Avvisi con il messaggio
    /// scelto, nello stesso pannello in cui si decide ogni altro.
    #[test]
    fn dalla_coda_si_apre_il_messaggio() {
        assert!(UI.contains("root.work-queue-open(riga.content-id);"));
        assert!(UI.contains("text: riga.excerpt;"));
        assert!(UI.contains(&format!(
            "if root.current-page == {}: ContentScreen {{",
            super::PAGINA_AVVISI
        )));
        let codice = include_str!("history.rs");
        let Some(inizio) = codice.find("window.on_work_queue_open(") else {
            panic!("il comando deve essere collegato");
        };
        let corpo = &codice[inizio..];
        let Some(fine) = corpo.find("\n        });") else {
            panic!("il gestore deve chiudersi");
        };
        let corpo = &corpo[..fine];
        assert!(corpo.contains("window.invoke_open_page(PAGINA_AVVISI);"));
        let apre = corpo.find("invoke_open_page").unwrap_or(usize::MAX);
        let sceglie = corpo.find("set_selected_content(content_id)").unwrap_or(0);
        assert!(
            apre < sceglie,
            "la pagina si apre prima: aprirla chiude il messaggio scelto"
        );
    }
}

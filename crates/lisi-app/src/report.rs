//! Collegamento fra la schermata Report e il sottosistema del reporting.
//!
//! È il modulo che rende raggiungibile ciò che MP-18B, MP-18C e MP-18F avevano
//! costruito e che **nessuna riga di `main` chiamava**: fino a MP-18G il
//! generatore `.docx` esisteva, era collaudato e non finiva nemmeno nel binario,
//! perché il linker scarta ciò che non si raggiunge. È la settima volta in
//! questa serie che compare un motore costruito e mai invocato, e il test
//! strutturale in fondo a questo file esiste perché non diventi l'ottava.
//!
//! # Che cosa questo modulo fa, e che cosa non fa
//!
//! Traduce le righe dei servizi in righe dell'interfaccia e i comandi
//! dell'operatore in una chiamata a [`ReportService::generate`]. **Non
//! ricostruisce alcuna logica di reporting**: la fotografia, la cartella del
//! pacchetto, la composizione della relazione, il documento e il manifest li
//! decide `lisi-services`, dove sono coperti da test.
//!
//! Qui vive una cosa sola che i servizi non hanno: lo **stato del percorso** —
//! a che passo si è, che cosa è stato scelto, che cosa è stato compilato. È
//! [`ReportFlow`], è puro, e ha i propri test.
//!
//! # La regola che governa la selezione
//!
//! La selezione è un **atto umano esplicito** (ADR-0031 Decisione 1). Nessun
//! livello la produce, nessun filtro la modifica, e cambiare filtro non toglie
//! nulla a ciò che è già stato scelto: filtrare cambia che cosa si vede, non
//! che cosa si è deciso. Zero elementi selezionati è uno stato **valido**, ed è
//! la relazione a esito negativo.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::rc::Rc;

use lisi_core::model::hub_report::SharedReport as RelazioneDellUfficio;
use lisi_core::model::report::{ReportArtifactKind, ReportOutcome, ReportSelection};
use lisi_core::model::report_template::{ReportTemplateProfile, TemplateEmblem, TemplateField};
use lisi_core::{ContentId, SessionId};
use lisi_services::acquisition_authority::StationAuthorityService;
use lisi_services::device_identity::DeviceIdentityService;
use lisi_services::export::resolved_destination;
use lisi_services::history::{HistoryEntry, HistoryFilter, HistoryScope, HistoryService};
use lisi_services::hub_catchup::HubCatchUpService;
use lisi_services::hub_client::{HubClientService, HubConnectionStore, ReviewSessionOutcome};
use lisi_services::report::{
    GeneratedReport, PRODUCIBLE_KINDS, ReportGenerationRequest, ReportService,
};
use lisi_services::report_package::verify_package_manifest;
use lisi_services::{ServiceError, ServiceResult};
use slint::{ComponentHandle, Model as _, ModelRc, SharedString, VecModel};

use crate::history::excerpt;
use crate::{
    AppWindow, DocumentProfile, ReportArtifactRow, ReportContentRow, ReportFormatRow,
    ReportSessionEntry, ReportSummaryRow, SharedReportRow, WizardStepEntry,
};

/// Relazioni dell'ufficio che questa schermata chiede.
const RELAZIONI_A_SCHERMO: usize = 50;

/// I sette passi del percorso, nell'ordine.
///
/// «Documenti» e «Riepilogo», non «Formati» e «Anteprima» (UX-EXCELLENCE-02,
/// SIM3-18): al passo 4 non si sceglie un formato — il pacchetto li contiene
/// tutti — e il passo 5 e' una tabella riassuntiva, non l'anteprima del
/// documento. I nomi dicono ora che cosa c'e'.
const STEPS: [&str; 7] = [
    "Sessione",
    "Contenuti",
    "Dati",
    "Documenti",
    "Riepilogo",
    "Generazione",
    "Esito",
];

/// Primo e ultimo passo.
const FIRST_STEP: u8 = 1;
const LAST_STEP: u8 = 7;

/// Il passo in cui si genera davvero.
const GENERATION_STEP: u8 = 6;

/// Servizi della schermata Report.
///
/// Due servizi su **due connessioni allo stesso archivio**: lo storico legge i
/// contenuti, il reporting scrive il pacchetto, e ciascuno possiede la propria
/// connessione. È la stessa scelta già fatta per Storico e revisione.
pub struct ReportScreen {
    history: HistoryService,
    reports: ReportService,
    flow: ReportFlow,
    /// Il profilo documentale in lavorazione: quello conservato, oppure quello
    /// che l'operatore sta compilando.
    profile: ReportFields,
    /// Se all'operatore la domanda è già stata posta.
    ///
    /// Falso **soltanto al primo avvio**. Chi risponde «non li inserisco» ha
    /// risposto, e non se la sente richiedere a ogni apertura (DEC-180).
    profile_answered: bool,
    /// Versione conservata del profilo; 0 se non è mai stato salvato.
    profile_version: u32,
    /// La frase che dice quali dati di chi firma non si aprono su questa
    /// postazione e vanno reinseriti (ADR-0160); vuota se si aprono tutti.
    profile_unreadable: String,
    /// La sessione dell'account, per chiedere i collegamenti (ADR-0165).
    session: Option<crate::account::SharedSession>,
    /// I collegamenti chiesti per la prossima relazione: si usano una volta.
    asked_links: Option<lisi_services::message_link::LinkBook>,
    /// I monitoraggi spuntati per il rapporto complessivo, nell'ordine in cui
    /// sono stati spuntati (REPORT-MULTI-01).
    overview_chosen: Vec<i32>,
}

/// Servizi condivisi fra i gestori dei comandi.
pub type SharedReport = Rc<RefCell<ReportScreen>>;

/// Il manifest del pacchetto appena prodotto, se c'è: la copia per chi
/// riceve si fa soltanto di quello (ENCRYPT-02, ADR-0190).
pub fn produced_manifest(screen: &SharedReport) -> Option<std::path::PathBuf> {
    screen
        .borrow()
        .flow
        .produced
        .as_ref()
        .map(|prodotto| prodotto.manifest.clone())
}

impl ReportScreen {
    /// La versione del profilo con cui la relazione nasce (E2E01-11).
    ///
    /// Quella conservata se i dati dell'ufficio della relazione sono
    /// **identici** al profilo conservato; 0 se l'operatore li ha cambiati per
    /// questa relazione, o se nessun profilo è conservato. Prima era sempre 0, e
    /// la relazione scriveva «versione 0» accanto a Impostazioni che diceva 1.
    fn flow_profile_version(&self) -> u32 {
        flow_profile_version(&self.flow.fields, &self.profile, self.profile_version)
    }
}

/// La regola di [`ReportScreen::flow_profile_version`], pura per le prove.
fn flow_profile_version(fields: &ReportFields, saved: &ReportFields, saved_version: u32) -> u32 {
    if saved_version > 0 && fields == saved {
        saved_version
    } else {
        0
    }
}

/// I campi del profilo documentale, come l'operatore li ha compilati.
///
/// Sono **vuoti per costruzione**: nessun dato istituzionale sta nel sorgente
/// (ADR-0031 Decisione 15), e un profilo vuoto produce una relazione senza
/// intestazione, non una relazione con un'intestazione inventata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReportFields {
    pub organisation: String,
    pub office: String,
    pub recipient: String,
    pub recipient_cc: String,
    pub subject: String,
    pub place: String,
    pub role: String,
    pub signer: String,
    pub footer: String,
    /// Sede, indirizzo e recapiti: la terza riga dell'intestazione.
    pub premises: String,
    /// Stemma scelto, già letto dal disco e validato dal dominio.
    ///
    /// I byte stanno qui e non nell'interfaccia: Slint mostra il nome del file,
    /// e l'immagine non attraversa mai il confine grafico.
    pub emblem: Option<TemplateEmblem>,
    /// Nome del file scelto, per mostrarlo all'operatore.
    pub emblem_label: String,
}

impl ReportFields {
    /// Traduce i campi nel profilo documentale del dominio.
    ///
    /// # Errori
    ///
    /// Restituisce il messaggio da mostrare se un valore non è accettabile:
    /// troppo lungo, o con caratteri di controllo o di alterazione dell'ordine
    /// di lettura. La validazione è quella del dominio, non una seconda scritta
    /// qui: due validazioni divergono alla prima correzione fatta su una sola.
    pub fn to_profile(&self) -> Result<ReportTemplateProfile, String> {
        Ok(ReportTemplateProfile {
            // Nessun profilo è ancora conservato nell'archivio: questi valori
            // valgono per **questa** relazione. La versione 0 dice «nessun
            // profilo salvato» invece di dichiararne una che non esiste.
            version: 0,
            organisation: field(&self.organisation, "Denominazione dell'amministrazione")?,
            office: field(&self.office, "Ufficio di appartenenza")?,
            header_line: field(&self.premises, "Sede, indirizzo e recapiti")?,
            recipient: field(&self.recipient, "Destinatario")?,
            recipient_cc: field(&self.recipient_cc, "E, per conoscenza")?,
            place: field(&self.place, "Luogo")?,
            signer_role: field(&self.role, "Qualifica di chi sottoscrive")?,
            signer_name: field(&self.signer, "Nome di chi sottoscrive")?,
            footer_line: field(&self.footer, "Riga di piè di pagina")?,
            subject_base: field(&self.subject, "Oggetto")?,
            emblem: self.emblem.clone(),
        })
    }
}

/// Dimensione oltre la quale il file dello stemma non viene nemmeno letto.
///
/// Il dominio ha il proprio limite e lo applica sui byte; questo lo anticipa al
/// **disco**, così che un file enorme non venga caricato in memoria per essere
/// poi rifiutato.
const EMBLEM_READ_CAP: u64 = TemplateEmblem::MAX_BYTES as u64;

/// Legge e valida il file scelto come stemma.
///
/// # Errori
///
/// Restituisce il messaggio da mostrare se il file non si legge o se il dominio
/// lo rifiuta. Il percorso non compare nel messaggio: è un dato della
/// postazione, e un messaggio che lo riportasse finirebbe in una schermata da
/// cui qualcuno lo fotografa.
fn read_emblem(path: &std::path::Path) -> Result<TemplateEmblem, String> {
    let metadata = std::fs::metadata(path).map_err(|_| {
        String::from("Il file scelto non è leggibile: verificare che esista ancora.")
    })?;
    if metadata.len() > EMBLEM_READ_CAP {
        return Err(String::from(
            "Il file supera i due megabyte: scegliere uno stemma più piccolo.",
        ));
    }

    let bytes = std::fs::read(path)
        .map_err(|_| String::from("Il file scelto non è leggibile: verificare i permessi."))?;

    TemplateEmblem::from_png(bytes).map_err(|error| {
        tracing::info!(errore = error.kind(), "stemma rifiutato");
        String::from(
            "L'immagine non è utilizzabile: serve un file PNG, entro i due megabyte \
             e con dimensioni ragionevoli.",
        )
    })
}

impl ReportFields {
    /// I campi che vengono da un profilo conservato.
    #[must_use]
    pub fn from_profile(profile: &ReportTemplateProfile) -> Self {
        let text = |field: Option<&TemplateField>| {
            field.map_or_else(String::new, |value| value.as_str().to_owned())
        };

        Self {
            organisation: text(profile.organisation.as_ref()),
            office: text(profile.office.as_ref()),
            recipient: text(profile.recipient.as_ref()),
            recipient_cc: text(profile.recipient_cc.as_ref()),
            subject: text(profile.subject_base.as_ref()),
            place: text(profile.place.as_ref()),
            role: text(profile.signer_role.as_ref()),
            signer: text(profile.signer_name.as_ref()),
            footer: text(profile.footer_line.as_ref()),
            premises: text(profile.header_line.as_ref()),
            emblem: profile.emblem.clone(),
            // Il nome del file non viene conservato: dell'immagine restano i
            // byte, che è ciò che serve al documento. Si dichiara la presenza
            // invece di inventare un nome che nessuno ha più.
            emblem_label: if profile.emblem.is_some() {
                String::from("stemma conservato")
            } else {
                String::new()
            },
        }
    }
}

/// Un campo facoltativo, validato dal dominio.
fn field(value: &str, name: &str) -> Result<Option<TemplateField>, String> {
    if value.trim().is_empty() {
        return Ok(None);
    }
    TemplateField::try_new(value).map(Some).map_err(|_| {
        format!(
            "Il campo «{name}» non è utilizzabile: al massimo {} caratteri, \
             senza ritorni a capo né caratteri invisibili.",
            TemplateField::MAX_CHARS
        )
    })
}

/// Che cosa la generazione ha prodotto, come la schermata lo mostra.
#[derive(Debug, Clone)]
struct Produced {
    report_id: String,
    folder: String,
    artifacts: Vec<ReportArtifactRow>,
    manifest_state: String,
    warning: String,
    /// Il manifest, per firmarlo (SIGN-01, DEC-465).
    manifest: PathBuf,
    /// I nomi dei PDF del pacchetto, per firmarne una copia.
    pdfs: Vec<String>,
}

/// Lo stato del percorso: dove si è, che cosa è stato scelto, che cosa scritto.
///
/// È puro: non conosce Slint, non conosce l'archivio, e per questo si prova
/// senza aprire una finestra.
#[derive(Debug, Clone)]
pub struct ReportFlow {
    step: u8,
    session: Option<SessionId>,
    /// La scelta umana. `BTreeSet` e non `Vec`: ordinato e senza ripetizioni
    /// per costruzione, che sono due delle tre invarianti di `ReportSelection`.
    selection: BTreeSet<ContentId>,
    fields: ReportFields,
    destination: Option<PathBuf>,
    busy: bool,
    produced: Option<Produced>,
    /// Se l'ultimo esito è stato un fallimento: decide il **tono** della fascia,
    /// non il testo. Il testo lo passa chi chiama [`refresh`], perché è un
    /// riscontro a un comando e non uno stato del percorso.
    failed: bool,
}

impl Default for ReportFlow {
    fn default() -> Self {
        Self {
            step: FIRST_STEP,
            session: None,
            selection: BTreeSet::new(),
            fields: ReportFields::default(),
            // Riempita da chi costruisce la schermata con la cartella scelta
            // dall'ufficio. Qui resta vuota perche' `Default` non ha un archivio
            // da interrogare, e un valore inventato sarebbe una cartella diversa
            // da quella in cui lo Storico scrive.
            destination: None,
            busy: false,
            produced: None,
            failed: false,
        }
    }
}

impl ReportFlow {
    /// Passo corrente, da 1 a 7.
    #[must_use]
    pub const fn step(&self) -> u8 {
        self.step
    }

    /// Sessione scelta, se ce n'è una.
    #[must_use]
    pub const fn session(&self) -> Option<SessionId> {
        self.session
    }

    /// Gli elementi scelti, nella forma che il dominio pretende.
    #[must_use]
    pub fn selection(&self) -> ReportSelection {
        ReportSelection::from_contents(self.selection.iter().copied())
    }

    /// Se una generazione è in corso.
    #[must_use]
    pub const fn is_busy(&self) -> bool {
        self.busy
    }

    /// Sceglie la sessione da documentare.
    ///
    /// Cambiare sessione **azzera la selezione**: un contenuto scelto in un
    /// monitoraggio non appartiene a un altro, e portarselo dietro produrrebbe
    /// il rifiuto del servizio invece di una relazione.
    pub fn choose_session(&mut self, session: SessionId) {
        if self.session == Some(session) {
            return;
        }
        self.session = Some(session);
        self.selection.clear();
        self.failed = false;
    }

    /// Aggiunge o toglie un contenuto dalla selezione.
    pub fn toggle(&mut self, content: ContentId) {
        if !self.selection.remove(&content) {
            self.selection.insert(content);
        }
    }

    /// Aggiunge alla selezione i contenuti indicati.
    ///
    /// Si chiama **solo** da un comando premuto: nessuna selezione nasce da un
    /// filtro, da un livello o dall'apertura di una schermata.
    pub fn select_all(&mut self, contents: impl IntoIterator<Item = ContentId>) {
        self.selection.extend(contents);
    }

    /// Toglie tutto dalla selezione.
    pub fn clear_selection(&mut self) {
        self.selection.clear();
    }

    /// Se un contenuto è fra quelli scelti.
    #[must_use]
    pub fn contains(&self, content: ContentId) -> bool {
        self.selection.contains(&content)
    }

    /// Quanti elementi sono stati scelti.
    #[must_use]
    pub fn selected_count(&self) -> usize {
        self.selection.len()
    }

    /// Perché non si può avanzare, o la stringa vuota se si può.
    ///
    /// **Zero elementi selezionati non compare qui**, ed è la riga più
    /// importante di questa funzione: è uno stato valido, e trattarlo come un
    /// impedimento renderebbe impossibile la relazione a esito negativo.
    #[must_use]
    pub fn blocking_reason(&self) -> String {
        if self.busy {
            return String::from("Generazione in corso.");
        }
        match self.step {
            1 => {
                if self.session.is_none() {
                    String::from("Scegliere il monitoraggio da documentare.")
                } else {
                    String::new()
                }
            }
            3 => self.fields.to_profile().err().unwrap_or_default(),
            GENERATION_STEP => String::from(
                "Il documento si produce con «Genera la relazione»: nulla viene \
                 scritto prima di quel comando.",
            ),
            _ => String::new(),
        }
    }

    /// Se si può passare al passo successivo.
    #[must_use]
    pub fn can_advance(&self) -> bool {
        // Il passo 7 non avanza: ricomincia, e il comando lo dice.
        if self.step == LAST_STEP {
            return !self.busy;
        }
        self.blocking_reason().is_empty()
    }

    /// Se si può tornare indietro.
    #[must_use]
    pub const fn can_go_back(&self) -> bool {
        self.step > FIRST_STEP && !self.busy
    }

    /// Se il comando di generazione è ammesso.
    #[must_use]
    pub fn can_generate(&self) -> bool {
        self.step == GENERATION_STEP
            && !self.busy
            && self.session.is_some()
            && self.destination.is_some()
            && self.fields.to_profile().is_ok()
    }

    /// Va al passo successivo, o ricomincia se si è all'ultimo.
    pub fn advance(&mut self) {
        if !self.can_advance() {
            return;
        }
        if self.step == LAST_STEP {
            self.restart();
            return;
        }
        self.step += 1;
        self.failed = false;
    }

    /// Torna al passo precedente **conservando la selezione**.
    ///
    /// È il vincolo esplicito del percorso: tornare indietro per rileggere che
    /// cosa si è scelto non deve costare la scelta.
    pub fn back(&mut self) {
        if !self.can_go_back() {
            return;
        }
        self.step -= 1;
        self.failed = false;
    }

    /// Ricomincia da capo, azzerando ogni scelta.
    pub fn restart(&mut self) {
        let destination = self.destination.clone();
        *self = Self {
            destination,
            ..Self::default()
        };
    }
}

/// Crea i servizi sugli archivi indicati.
///
/// Riceve **due** archivi già aperti perché i servizi non condividono una
/// connessione. Restituisce `None` se uno dei due manca.
#[must_use]
pub fn create_service(
    for_history: Option<lisi_services::Database>,
    for_reports: Option<lisi_services::Database>,
) -> Option<SharedReport> {
    let (Some(first), Some(second)) = (for_history, for_reports) else {
        return None;
    };

    let reports = ReportService::new(second);

    // Il profilo conservato si legge **all'avvio**, una volta: da qui vengono
    // sia la schermata di benvenuto sia i valori con cui ogni relazione nasce
    // già intestata.
    let loaded = reports.loaded_profile().unwrap_or_else(|error| {
        tracing::warn!(
            kind = error.kind(),
            "profilo documentale non leggibile: si procede senza"
        );
        None
    });
    // I dati di chi firma cifrati per un altro utente o un'altra postazione
    // (ADR-0160) si leggono vuoti: la schermata dice quali reinserire.
    let profile_unreadable = loaded.as_ref().map_or_else(
        String::new,
        lisi_services::report_profile::LoadedProfile::unreadable_message,
    );
    let saved = loaded.map(|letto| letto.profile);
    let profile_version = saved.as_ref().map_or(0, |profile| profile.version);
    let profile = saved
        .as_ref()
        .map_or_else(ReportFields::default, ReportFields::from_profile);

    // Letta prima che il servizio entri nella struttura: dopo, `reports` non e'
    // piu' disponibile per essere interrogato.
    let destination = resolved_destination(reports.database()).ok();

    Some(Rc::new(RefCell::new(ReportScreen {
        history: HistoryService::new(first),
        reports,
        // Ogni relazione parte dai dati dell'ufficio: è il punto della
        // conservazione, e l'operatore li modifica solo se vuole.
        flow: ReportFlow {
            fields: profile.clone(),
            // La stessa cartella in cui scrive lo Storico. Senza un valore
            // iniziale il percorso si fermerebbe al passo 6 su ogni postazione
            // in cui la finestra di sistema non si puo' aprire; con una cartella
            // decisa qui per conto proprio, il pacchetto uscirebbe altrove
            // rispetto ai rapporti.
            destination,
            ..ReportFlow::default()
        },
        profile,
        profile_answered: saved.is_some(),
        profile_version,
        profile_unreadable,
        session: None,
        asked_links: None,
        overview_chosen: Vec::new(),
    })))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// Attore dell'audit.
fn actor() -> ServiceResult<lisi_core::text::Actor> {
    crate::operator::audit_actor()
}

/// Dimensione in byte, con il separatore delle migliaia.
///
/// Un numero di sette cifre senza separatori non si legge, e questo numero
/// serve a confrontare un file con ciò che il manifest dichiara.
fn readable_size(bytes: u64) -> String {
    let digits = bytes.to_string();
    let mut grouped = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push('\u{202f}');
        }
        grouped.push(digit);
    }
    format!("{grouped} byte")
}

/// Le sessioni fra cui scegliere, dalla più recente.
fn sessions(screen: &ReportScreen) -> Vec<ReportSessionEntry> {
    let summaries = match screen.history.sessions() {
        Ok(summaries) => summaries,
        Err(error) => {
            tracing::warn!(kind = error.kind(), "elenco delle sessioni non leggibile");
            return Vec::new();
        }
    };

    summaries
        .into_iter()
        .map(|summary| {
            let session = &summary.session;
            let sources = source_names(screen, session.id);
            ReportSessionEntry {
                session_id: i32::try_from(session.id.get()).unwrap_or(0),
                label: SharedString::from(session.label.as_str()),
                // Le due righe sono frasi intere e non due estremi di un
                // intervallo: una sessione mai avviata non ha un «dal», e
                // scrivere «Dal non avviata» e' esattamente cio' che usciva
                // dalla prima stesura di questa schermata.
                started: SharedString::from(session.started_at.map_or_else(
                    || {
                        format!(
                            "Non avviata, creata il {}",
                            session.created_at.to_readable_local()
                        )
                    },
                    |instant| format!("Avviata il {}", instant.to_readable_local()),
                )),
                // Una sessione ancora aperta non ha un termine: lo dice invece
                // di mostrarne uno che non esiste.
                ended: SharedString::from(session.ended_at.map_or_else(
                    || {
                        String::from(if session.state.is_final() {
                            "conclusa senza un istante di fine registrato"
                        } else {
                            "ancora in corso"
                        })
                    },
                    |instant| format!("conclusa il {}", instant.to_readable_local()),
                )),
                state: crate::lingua::schermo(session.state.label()),
                operator: SharedString::from(session.started_by.as_str()),
                sources: SharedString::from(if sources.is_empty() {
                    String::from("nessuna fonte registrata")
                } else {
                    sources.join(", ")
                }),
                contents: i32::try_from(summary.counts.total).unwrap_or(i32::MAX),
                alerts: i32::try_from(summary.counts.alerted).unwrap_or(i32::MAX),
                chosen: screen.flow.session == Some(session.id),
            }
        })
        .collect()
}

/// Nomi delle fonti di una sessione.
fn source_names(screen: &ReportScreen, session_id: SessionId) -> Vec<String> {
    let database = screen.history.database();
    let Ok(source_ids) = database.session_source_ids(session_id) else {
        return Vec::new();
    };

    source_ids
        .into_iter()
        .map(|source_id| {
            database.source(source_id).map_or_else(
                |_| String::from("fonte non più disponibile"),
                |source| source.display_name.as_str().to_owned(),
            )
        })
        .collect()
}

/// Traduce una riga dello storico in una riga della selezione.
fn content_row(screen: &ReportScreen, entry: &HistoryEntry) -> ReportContentRow {
    ReportContentRow {
        content_id: i32::try_from(entry.content.id.get()).unwrap_or(0),
        chosen: screen.flow.contains(entry.content.id),
        level: i32::from(entry.level()),
        level_label: crate::lingua::schermo(entry.content.analysis_level.label()),
        source: SharedString::from(entry.source_name.as_str()),
        published: SharedString::from(entry.content.published_at.to_readable_local()),
        excerpt: SharedString::from(excerpt(entry.content.body.as_str())),
        review_state: crate::lingua::schermo(entry.review_state().label()),
        alert: entry.raised_alert(),
        // Scritto e non dedotto da un segno assente: l'assenza non si legge.
        link: SharedString::from(if entry.content.url.is_some() {
            "collegamento disponibile"
        } else {
            "senza collegamento"
        }),
    }
}

/// I contenuti della sessione scelta, filtrati come la schermata chiede.
fn visible_contents(screen: &ReportScreen, window: &AppWindow) -> Vec<HistoryEntry> {
    let Some(session_id) = screen.flow.session() else {
        return Vec::new();
    };

    let filter = HistoryFilter {
        query: window.get_report_filter().to_string(),
        // «Solo con avviso» è la stessa soglia della schermata Alert: gli
        // avvisi sono lo storico dal livello 1 in su.
        minimum_level: u8::from(window.get_report_only_alerts()),
        only_pending: false,
    };

    let mut entries = match screen
        .history
        .matching(HistoryScope::Session(session_id), &filter)
    {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!(
                kind = error.kind(),
                "contenuti della sessione non leggibili"
            );
            return Vec::new();
        }
    };

    if window.get_report_only_selected() {
        entries.retain(|entry| screen.flow.contains(entry.content.id));
    }

    // Il rovescio: cio' che restera' fuori dalla relazione. Serve a
    // rileggere le esclusioni prima di firmare, che e' il momento in cui
    // una svista costa; ed e' il filtro che il contatore «non
    // rappresentati» accende. I due non possono valere insieme:
    // l'interfaccia spegne l'uno quando accende l'altro, e qui il vincolo
    // e' ribadito perche' un elenco sempre vuoto sarebbe indistinguibile
    // da un guasto.
    if window.get_report_only_excluded() && !window.get_report_only_selected() {
        entries.retain(|entry| !screen.flow.contains(entry.content.id));
    }
    entries
}

/// I formati, con la verità su ciascuno.
///
/// I tre non ancora costruiti compaiono **dichiarati come tali**: toglierli
/// farebbe credere che non siano previsti, e mostrarli spuntabili farebbe
/// credere che si producano. Nessun file finto, mai.
fn formats() -> Vec<ReportFormatRow> {
    let mut rows = vec![ReportFormatRow {
        label: crate::lingua::schermo(ReportArtifactKind::NarrativeDocx.operator_label()),
        available: true,
        note: crate::lingua::schermo(
            "Il documento che si firma, modificabile in Word. Rappresenta gli \
             elementi selezionati dall'operatore.",
        ),
    }];

    for (kind, note) in [
        (
            ReportArtifactKind::AnalyticalXlsx,
            // Il numero dei fogli non si scrive: diceva «nove» e il registro ne
            // ha undici (F-13). Un numero scritto a mano accanto a un elenco che
            // cresce diverge alla prima aggiunta.
            "Il registro di tutto il monitorato, per riga e per colonna: un foglio per \
             genere di dato, livello 0 compreso, e non la sola selezione.",
        ),
        (
            ReportArtifactKind::NarrativePdf,
            "La stessa relazione, non modificabile e a impaginazione stabile: quella che si allega \
             quando il documento non deve poter essere ritoccato.",
        ),
        (
            ReportArtifactKind::TechnicalAnnexPdf,
            "Tutto il monitorato, un contenuto dopo l'altro e in forma leggibile: gli stessi fatti \
             del registro, per chi legge invece di filtrare.",
        ),
        (
            ReportArtifactKind::PlainTxt,
            "Lo stesso registro, in testo semplice: si legge ovunque, anche \
             fra vent'anni e senza il programma che lo ha scritto.",
        ),
    ] {
        rows.push(ReportFormatRow {
            label: crate::lingua::schermo(kind.operator_label()),
            available: PRODUCIBLE_KINDS.contains(&kind),
            note: SharedString::from(note),
        });
    }

    rows
}

/// Il riepilogo deterministico di ciò che verrà prodotto.
fn preview(screen: &ReportScreen, window: &AppWindow) -> Vec<ReportSummaryRow> {
    let mut rows = Vec::new();
    let mut add = |label: &str, value: String| {
        rows.push(ReportSummaryRow {
            label: SharedString::from(label),
            value: SharedString::from(value),
        });
    };

    let chosen = window
        .get_report_sessions()
        .iter()
        .find(|entry| entry.chosen);

    add(
        "Monitoraggio",
        chosen
            .as_ref()
            .map_or_else(|| String::from("nessuno"), |entry| entry.label.to_string()),
    );
    add(
        "Periodo",
        chosen.as_ref().map_or_else(
            || String::from("non disponibile"),
            |entry| format!("{} \u{00b7} {}", entry.started, entry.ended),
        ),
    );
    add(
        "Fonti monitorate",
        chosen.as_ref().map_or_else(
            || String::from("non disponibili"),
            |entry| entry.sources.to_string(),
        ),
    );
    add(
        "Contenuti monitorati",
        window.get_report_total().to_string(),
    );
    add(
        "Contenuti selezionati dall'operatore",
        window.get_report_selected().to_string(),
    );
    add(
        "Tipo di relazione",
        String::from(outcome_sentence(screen.flow.selected_count())),
    );
    add(
        "Profilo documentale",
        if screen
            .flow
            .fields
            .to_profile()
            .is_ok_and(|profile| profile.is_empty())
        {
            String::from("nessun dato dell'ufficio compilato: la relazione non porta intestazione")
        } else {
            // La stessa regola con cui la relazione nasce (E2E01-11): prima
            // questa riga diceva «compilato per questa relazione» anche per i
            // dati del profilo conservato, mai toccati.
            match screen.flow_profile_version() {
                0 => String::from("compilato per questa relazione (non salvato come profilo)"),
                versione => format!("profilo conservato, versione {versione}"),
            }
        },
    );
    // I DOCUMENTI SONO QUELLI CHE SI PRODUCONO DAVVERO (OPERATOR-E2E-REMEDIATION-01,
    // F-13): la riga diceva «Relazione in Word ed elenco delle impronte», fissa,
    // mentre il pacchetto ne porta cinque e l'elenco. Ora si legge dallo stesso
    // elenco con cui la generazione li chiede.
    add(
        "Documenti prodotti",
        PRODUCIBLE_KINDS
            .iter()
            .map(|kind| kind.operator_label())
            .chain(std::iter::once(
                ReportArtifactKind::Manifest.operator_label(),
            ))
            .collect::<Vec<_>>()
            .join(", "),
    );
    add(
        "Cartella di destinazione",
        screen.flow.destination.as_ref().map_or_else(
            || String::from("nessuna cartella scelta"),
            |path| path.to_string_lossy().into_owned(),
        ),
    );

    rows
}

/// La frase che dichiara il tipo di relazione.
///
/// **Non è un giudizio sui fatti**: è una constatazione su una scelta. La
/// formulazione che il documento userà vive nel dominio, sotto un test che ne
/// vieta le parole di un giudizio; questa è la sua parafrasi per la schermata.
const fn outcome_sentence(selected: usize) -> &'static str {
    if selected == 0 {
        "senza risultanze selezionate: descriverà l'attività svolta e dichiarerà \
         che nessun elemento è stato selezionato dall'operatore per essere \
         rappresentato"
    } else {
        "con risultanze selezionate: rappresenterà i soli elementi scelti"
    }
}

/// Riporta nell'interfaccia il profilo documentale conservato.
///
/// Il modulo del profilo vive in un `global` di Slint perché compare in **due**
/// schermate — il benvenuto del primo avvio e le Impostazioni — e due copie
/// dello stesso stato divergono alla prima modifica fatta su una sola.
pub fn refresh_profile(window: &AppWindow, screen: &SharedReport, message: Option<&str>) {
    let screen = screen.borrow();
    let profile = &screen.profile;
    let global = window.global::<DocumentProfile>();

    global.set_organisation(SharedString::from(profile.organisation.as_str()));
    global.set_office(SharedString::from(profile.office.as_str()));
    global.set_premises(SharedString::from(profile.premises.as_str()));
    global.set_recipient(SharedString::from(profile.recipient.as_str()));
    global.set_recipient_cc(SharedString::from(profile.recipient_cc.as_str()));
    global.set_place(SharedString::from(profile.place.as_str()));
    global.set_signer_role(SharedString::from(profile.role.as_str()));
    global.set_signer_name(SharedString::from(profile.signer.as_str()));
    global.set_footer_line(SharedString::from(profile.footer.as_str()));
    global.set_subject_base(SharedString::from(profile.subject.as_str()));
    global.set_emblem_name(SharedString::from(profile.emblem_label.as_str()));
    global.set_answered(screen.profile_answered);
    global.set_version(i32::try_from(screen.profile_version).unwrap_or(i32::MAX));

    if let Some(text) = message {
        global.set_message(SharedString::from(text));
    }
}

/// Aggiorna **soltanto** cio' che lo stemma cambia.
///
/// # Perche' non `refresh_profile`
///
/// `refresh_profile` riscrive tutti e dieci i campi di testo prendendoli dal
/// profilo **conservato**. Chiamarla mentre il modulo e' aperto cancella cio'
/// che l'operatore ha appena digitato e non ha ancora salvato.
///
/// Il 2026-08-19, alla prima compilazione reale, e' successo esattamente
/// questo: l'operatore ha compilato i dieci campi, ha scelto lo stemma, ha
/// premuto «Salva», e nell'archivio e' finito un profilo con lo stemma e
/// **zero** campi di testo. Lo stemma si era conservato perche' vive in Rust;
/// il testo no, perche' passava dai campi che la scelta dello stemma aveva
/// appena svuotato.
///
/// La regola che ne discende: **un gestore riscrive solo cio' che possiede.**
fn refresh_emblem(window: &AppWindow, label: &str, message: &str) {
    let global = window.global::<DocumentProfile>();
    global.set_emblem_name(SharedString::from(label));
    global.set_message(crate::lingua::schermo(message));
}

/// Porta nei campi della relazione i valori con cui il percorso è partito.
///
/// # Perché non a ogni ridisegno
///
/// I campi del passo 3 sono `in-out`: l'operatore ci scrive dentro. Riscriverli
/// a ogni ridisegno significherebbe cancellargli sotto le dita ciò che sta
/// digitando. Si scrivono quando il percorso **nasce** — all'avvio, dopo un
/// «Ricomincia», dopo che il profilo è stato conservato — e poi si lasciano a
/// chi li compila.
pub fn publish_fields(window: &AppWindow, screen: &SharedReport) {
    let screen = screen.borrow();
    let fields = &screen.flow.fields;

    window.set_report_organisation(SharedString::from(fields.organisation.as_str()));
    window.set_report_office(SharedString::from(fields.office.as_str()));
    window.set_report_premises(SharedString::from(fields.premises.as_str()));
    window.set_report_recipient(SharedString::from(fields.recipient.as_str()));
    window.set_report_recipient_cc(SharedString::from(fields.recipient_cc.as_str()));
    window.set_report_subject(SharedString::from(fields.subject.as_str()));
    window.set_report_place(SharedString::from(fields.place.as_str()));
    window.set_report_role(SharedString::from(fields.role.as_str()));
    window.set_report_signer(SharedString::from(fields.signer.as_str()));
    window.set_report_footer(SharedString::from(fields.footer.as_str()));
}

/// Legge dal `global` i campi che l'operatore sta compilando.
fn profile_from_window(window: &AppWindow) -> ReportFields {
    let global = window.global::<DocumentProfile>();
    ReportFields {
        organisation: global.get_organisation().to_string(),
        office: global.get_office().to_string(),
        premises: global.get_premises().to_string(),
        recipient: global.get_recipient().to_string(),
        recipient_cc: global.get_recipient_cc().to_string(),
        place: global.get_place().to_string(),
        role: global.get_signer_role().to_string(),
        signer: global.get_signer_name().to_string(),
        footer: global.get_footer_line().to_string(),
        subject: global.get_subject_base().to_string(),
        // Lo stemma non viene dall'interfaccia: i byte stanno già nel modulo,
        // letti e validati quando l'operatore lo ha scelto.
        emblem: None,
        emblem_label: String::new(),
    }
}

/// Riporta nell'interfaccia lo stato del percorso.
pub fn refresh(window: &AppWindow, screen: &SharedReport, message: Option<&str>) {
    let screen = screen.borrow();
    let flow = &screen.flow;

    // `None` significa «non ho un riscontro nuovo da dare»: la fascia resta
    // com'è. È il caso di chi spunta una riga o cambia il filtro, dove far
    // sparire il messaggio precedente toglierebbe la risposta al comando che lo
    // ha prodotto un istante prima.
    if let Some(text) = message {
        window.set_report_message(SharedString::from(text));
    }
    window.set_report_failed(flow.failed);

    // --------------------------------------------------------------- passi
    let steps: Vec<WizardStepEntry> = STEPS
        .iter()
        .enumerate()
        .map(|(index, title)| {
            let number = u8::try_from(index + 1).unwrap_or(u8::MAX);
            WizardStepEntry {
                number: i32::from(number),
                title: SharedString::from(*title),
                reached: number <= flow.step(),
                current: number == flow.step(),
            }
        })
        .collect();
    window.set_report_steps(ModelRc::from(Rc::new(VecModel::from(steps))));
    window.set_report_step(i32::from(flow.step()));
    window.set_report_title(SharedString::from(step_title(flow.step())));
    window.set_report_prompt(SharedString::from(step_prompt(flow.step())));
    window.set_report_can_advance(flow.can_advance());
    window.set_report_can_go_back(flow.can_go_back());
    window.set_report_can_generate(flow.can_generate());
    window.set_report_blocking_reason(SharedString::from(flow.blocking_reason()));
    window.set_report_busy(flow.busy);
    window.set_report_session_chosen(flow.session().is_some());

    // ------------------------------------------------------------ sessioni
    let elenco = sessions(&screen);
    // IL RAPPORTO COMPLESSIVO (REPORT-MULTI-01, ADR-0192): gli stessi
    // monitoraggi, da spuntare.
    window.set_overview_rows(ModelRc::from(Rc::new(VecModel::from(overview_rows(
        &elenco,
        &screen.overview_chosen,
    )))));
    window.set_report_sessions(ModelRc::from(Rc::new(VecModel::from(elenco))));

    // ------------------------------------------------------------ contenuti
    let entries = visible_contents(&screen, window);
    let rows: Vec<ReportContentRow> = entries
        .iter()
        .map(|entry| content_row(&screen, entry))
        .collect();
    let shown = rows.len();
    window.set_report_contents(ModelRc::from(Rc::new(VecModel::from(rows))));

    // I conteggi vengono dall'insieme completo della sessione, non da quello
    // filtrato: un totale che cambia con la ricerca non è più un totale.
    if let Some(session_id) = flow.session() {
        match screen.history.summary(HistoryScope::Session(session_id)) {
            Ok(summary) => {
                let total = i32::try_from(summary.total).unwrap_or(i32::MAX);
                let selected = i32::try_from(flow.selected_count()).unwrap_or(i32::MAX);
                window.set_report_total(total);
                window.set_report_selected(selected);
                window.set_report_excluded((total - selected).max(0));
                window.set_report_alerts(i32::try_from(summary.alerted).unwrap_or(i32::MAX));
                window.set_report_pending(i32::try_from(summary.pending).unwrap_or(i32::MAX));
                window.set_report_reviewed(
                    i32::try_from(summary.total.saturating_sub(summary.pending))
                        .unwrap_or(i32::MAX),
                );
                let levels: Vec<i32> = summary
                    .by_level
                    .iter()
                    .map(|value| i32::try_from(*value).unwrap_or(i32::MAX))
                    .collect();
                window.set_report_levels(ModelRc::from(Rc::new(VecModel::from(levels))));
                window.set_report_visible_note(nota_dei_visibili(
                    shown,
                    summary.total,
                    flow.selected_count(),
                ));
            }
            Err(error) => {
                tracing::warn!(kind = error.kind(), "conteggi del report non leggibili");
                window.set_report_message(crate::lingua::schermo(error.operator_message()));
            }
        }
    } else {
        window.set_report_total(0);
        window.set_report_selected(0);
        window.set_report_excluded(0);
        window.set_report_alerts(0);
        window.set_report_pending(0);
        window.set_report_reviewed(0);
        window.set_report_levels(ModelRc::from(Rc::new(VecModel::from(Vec::<i32>::new()))));
        window.set_report_visible_note(SharedString::default());
    }

    // ---------------------------------------------------------------- dati
    window.set_report_emblem(SharedString::from(flow.fields.emblem_label.as_str()));
    // I dati di chi firma che su questa postazione non si aprono (ADR-0160)
    // si dicono PRIMA della nota: sono la ragione per cui un campo è vuoto.
    let nota_del_profilo = "Questi campi compongono l'intestazione e i riferimenti della \
                            relazione. Sono facoltativi: dove un dato manca, il documento lo \
                            dichiara invece di inventarlo. Valgono per questa relazione e non \
                            vengono conservati come profilo dell'ufficio.";
    window.set_report_profile_note(SharedString::from(
        if screen.profile_unreadable.is_empty() {
            String::from(nota_del_profilo)
        } else {
            format!("{} {nota_del_profilo}", screen.profile_unreadable)
        },
    ));

    // ------------------------------------------------------------- formati
    window.set_report_formats(ModelRc::from(Rc::new(VecModel::from(formats()))));

    // ------------------------------------------------------------ anteprima
    window.set_report_preview(ModelRc::from(Rc::new(VecModel::from(preview(
        &screen, window,
    )))));
    window.set_report_outcome_label(crate::lingua::schermo(format!(
        "La relazione sarà {}.",
        outcome_sentence(flow.selected_count())
    )));

    // ------------------------------------------------------- destinazione
    window.set_report_destination(SharedString::from(
        flow.destination
            .as_ref()
            .map_or_else(String::new, |path| path.to_string_lossy().into_owned()),
    ));

    // L'avvertenza sulla cartella, quando ce n'e' una.
    //
    // Su una condivisione di rete il prodotto NON sa e non puo' sapere chi ha
    // accesso ai documenti (ADR-0041). Tacerlo lascerebbe credere che siano
    // protetti come l'archivio, e non lo sono.
    //
    // Non impedisce la scelta: consegnare un atto su un condiviso e' il modo
    // normale di lavorare di un ufficio.
    let avvertenza = flow
        .destination
        .as_ref()
        .and_then(|path| lisi_core::model::destination::ExportDestination::try_new(path).ok())
        .and_then(|destinazione| destinazione.caution())
        .unwrap_or_default();
    window.set_report_destination_caution(SharedString::from(avvertenza));

    // ------------------------------------------------------------- esito
    match &flow.produced {
        Some(produced) => {
            window.set_report_completed(true);
            window.set_report_identifier(SharedString::from(produced.report_id.as_str()));
            window.set_report_status(crate::lingua::schermo("COMPLETATO"));
            window.set_report_folder(SharedString::from(produced.folder.as_str()));
            window.set_report_folder_message(SharedString::default());
            window.set_report_manifest_state(SharedString::from(produced.manifest_state.as_str()));
            window.set_report_warning(SharedString::from(produced.warning.as_str()));
            window.set_report_artifacts(ModelRc::from(Rc::new(VecModel::from(
                produced.artifacts.clone(),
            ))));
        }
        None => {
            window.set_report_completed(false);
            window.set_report_identifier(SharedString::default());
            window.set_report_status(SharedString::default());
            window.set_report_folder(SharedString::default());
            window.set_report_folder_message(SharedString::default());
            window.set_report_manifest_state(SharedString::default());
            window.set_report_warning(SharedString::default());
            window.set_report_artifacts(ModelRc::from(Rc::new(VecModel::from(Vec::<
                ReportArtifactRow,
            >::new(
            )))));
        }
    }
}

/// Titolo del passo.
const fn step_title(step: u8) -> &'static str {
    match step {
        1 => "Monitoraggio da documentare",
        2 => "Contenuti della relazione",
        3 => "Dati della relazione",
        4 => "Documenti del pacchetto",
        5 => "Riepilogo prima di produrre",
        GENERATION_STEP => "Generazione",
        _ => "Esito",
    }
}

/// Che cosa si chiede all'operatore, a questo passo.
const fn step_prompt(step: u8) -> &'static str {
    match step {
        1 => "Una relazione documenta un monitoraggio condotto. Scegliere quale.",
        2 => {
            "I contenuti raccolti dal monitoraggio. Spuntare quelli da rappresentare \
              nella relazione: la scelta è dell'operatore, non del livello proposto \
              dal programma. Si può anche non spuntarne nessuno."
        }
        3 => {
            "I dati dell'ufficio che compaiono nella relazione. Tutti facoltativi: \
              dove un dato manca, il documento dichiara che manca."
        }
        4 => {
            "I documenti che il pacchetto contiene sempre: qui non si sceglie nulla, si \
              controlla e si va avanti. Quelli non ancora costruiti sono dichiarati tali \
              e non vengono prodotti."
        }
        5 => {
            "Riepilogo di ciò che verrà prodotto. Nulla è ancora stato scritto: si scrive \
              al passo successivo."
        }
        GENERATION_STEP => {
            "Scegliere la cartella e produrre il pacchetto. L'elenco delle impronte \
                            è l'ultimo file scritto: finché non c'è, il pacchetto \
                            non è completo."
        }
        _ => "Che cosa è stato prodotto, dove, e con quali impronte.",
    }
}

/// Esegue la generazione e ne traduce l'esito.
/// Le relazioni dell'ufficio, lette dall'Hub.
///
/// Su una postazione che **ha** i fatti non compaiono: lì le relazioni sono
/// quelle di casa, e mostrarne due elenchi farebbe chiedere quale dei due sia
/// quello vero.
///
/// Porta **nomi e impronte**, mai documenti (ADR-0100, decisione 2).
fn relazioni_dell_ufficio() -> (Vec<SharedReportRow>, String) {
    let Some(radice) = crate::account::data_root() else {
        return (Vec::new(), String::new());
    };
    if StationAuthorityService::in_directory(&radice)
        .role()
        .may_acquire()
    {
        return (Vec::new(), String::new());
    }

    let (Ok(identita), Ok(configurazione)) = (
        DeviceIdentityService::default_location(),
        HubConnectionStore::default_location(),
    ) else {
        return (
            Vec::new(),
            String::from("La configurazione dell'Hub non è leggibile."),
        );
    };
    let Ok(archivio) = lisi_services::sources::open_application_database() else {
        return (
            Vec::new(),
            String::from("L'archivio di questa postazione non è apribile."),
        );
    };
    let client = HubClientService::new(HubCatchUpService::new(archivio), identita, configurazione)
        .with_default_office_networks()
        .with_screen_limits();

    let mut sessione = match client.open_review_session(now()) {
        Ok(ReviewSessionOutcome::Ready(sessione)) => *sessione,
        Ok(altro) => {
            return (
                Vec::new(),
                altro
                    .refusal_message()
                    .unwrap_or_else(|| String::from("Il collegamento all'Hub non si è aperto.")),
            );
        }
        Err(errore) => return (Vec::new(), errore.operator_message()),
    };
    let esito = sessione.shared_reports(RELAZIONI_A_SCHERMO);
    sessione.close();

    match esito {
        Ok(Some(relazioni)) => {
            let quante = relazioni.len();
            let righe = relazioni
                .iter()
                .map(riga_della_relazione)
                .collect::<Vec<_>>();
            let frase = if quante == 0 {
                String::from("L'ufficio non ha ancora relazioni.")
            } else {
                format!("{quante} relazioni dell'ufficio. I documenti restano sull'Hub.")
            };
            (righe, frase)
        }
        Ok(None) => (
            Vec::new(),
            String::from("Questo Hub non tiene le relazioni dell'ufficio."),
        ),
        Err(errore) => (Vec::new(), errore.operator_message()),
    }
}

/// Una relazione dell'ufficio, come si legge.
fn riga_della_relazione(relazione: &RelazioneDellUfficio) -> SharedReportRow {
    let documenti = relazione
        .artifacts
        .iter()
        .map(|documento| {
            format!(
                "{} ({} byte, impronta {})",
                documento.file_name, documento.size_bytes, documento.sha256
            )
        })
        .collect::<Vec<_>>()
        .join(" · ");

    SharedReportRow {
        report_id: SharedString::from(relazione.report_id.as_str()),
        who: crate::lingua::schermo(format!(
            "sessione {} · chiesta da {} il {}",
            relazione.session_id.get(),
            relazione.requested_by,
            relazione.requested_at.to_readable_local()
        )),
        state: crate::lingua::schermo(relazione.status.operator_label()),
        counts: crate::lingua::schermo(format!(
            "{} monitorati · {} rappresentati · {} esclusi",
            relazione.monitored,
            relazione.selected,
            relazione.excluded()
        )),
        documents: SharedString::from(documenti),
    }
}

/// Riporta nell'interfaccia le relazioni dell'ufficio.
fn refresh_office(window: &AppWindow) {
    let (righe, frase) = relazioni_dell_ufficio();
    window.set_report_hub_reports(ModelRc::from(Rc::new(VecModel::from(righe))));
    window.set_report_hub_message(crate::lingua::schermo(frase));
}

fn il_documento_lo_produce_chi_ha_i_fatti() -> Option<String> {
    let radice = crate::account::data_root()?;
    let autorita = StationAuthorityService::in_directory(&radice);
    if autorita.role().may_acquire() {
        return None;
    }
    Some(String::from(
        "Questa postazione segue un Hub, e non produce relazioni. I fatti stanno sull'Hub. Un \
         documento prodotto qui parlerebbe di un monitoraggio che questa postazione non ha \
         seguito. Le relazioni dell'ufficio si vedono nella Revisione condivisa, e si chiede \
         all'Hub di congelarne una.",
    ))
}

/// Produce il pacchetto, se questa postazione ha i fatti.
/// Le righe del rapporto complessivo: gli stessi monitoraggi dell'elenco.
fn overview_rows(elenco: &[ReportSessionEntry], spuntati: &[i32]) -> Vec<crate::OverviewRow> {
    elenco
        .iter()
        .map(|voce| crate::OverviewRow {
            session_id: voce.session_id,
            label: voce.label.clone(),
            chosen: spuntati.contains(&voce.session_id),
        })
        .collect()
}

/// Spunta o toglie un monitoraggio dal rapporto complessivo.
fn toggle_overview(screen: &SharedReport, session_id: i32) {
    let mut screen = screen.borrow_mut();
    if let Some(posizione) = screen
        .overview_chosen
        .iter()
        .position(|scelto| *scelto == session_id)
    {
        screen.overview_chosen.remove(posizione);
    } else {
        screen.overview_chosen.push(session_id);
    }
}

/// Produce il rapporto complessivo dei monitoraggi spuntati (REPORT-MULTI-01,
/// ADR-0192): stessa cartella e stessi dati documentali della relazione.
fn generate_overview(screen: &SharedReport, name: &str, role: &str) -> String {
    if let Some(frase) = il_documento_lo_produce_chi_ha_i_fatti() {
        return frase;
    }
    let mut screen = screen.borrow_mut();
    let Some(destination) = screen.flow.destination.clone() else {
        return String::from("Scegliere prima la cartella in cui produrre il pacchetto.");
    };
    let mut profile = match screen.flow.fields.to_profile() {
        Ok(profile) => profile,
        Err(message) => return message,
    };
    profile.version = screen.flow_profile_version();
    let Ok(actor) = actor() else {
        return String::from("Identità dell'operatore non utilizzabile: segnalarlo.");
    };
    let sessions = screen
        .overview_chosen
        .iter()
        .map(|id| lisi_core::SessionId::new(i64::from(*id)))
        .collect();
    let request = lisi_services::report_overview::OverviewRequest {
        sessions,
        responsible: lisi_services::report_overview::DocumentResponsible {
            name: name.to_owned(),
            role: role.to_owned(),
        },
        profile: &profile,
        destination: &destination,
        requested_by: actor,
        requested_at: now(),
    };
    match screen.reports.generate_overview(&request) {
        Ok(prodotto) => {
            screen.overview_chosen.clear();
            prodotto.operator_message()
        }
        Err(error) => {
            tracing::warn!(kind = error.kind(), "rapporto complessivo non prodotto");
            error.operator_message()
        }
    }
}

fn generate(screen: &SharedReport) -> String {
    // UNA POSTAZIONE CHE SEGUE UN HUB NON PRODUCE RELAZIONI (TEAM-REPORT-01,
    // ADR-0100, decisione 1).
    //
    // Qui i fatti non ci sono: il contenuto si chiede uno per volta e non si
    // conserva (ADR-0094), e il live e' una proiezione potata (ADR-0093). Un
    // documento prodotto qui parlerebbe di una sessione con i numeri
    // sbagliati, o con nessun numero, e porterebbe una firma e una data che
    // lo farebbero sembrare autorevole.
    //
    // Si RIFIUTA invece di produrne uno parziale: un documento parziale non si
    // riconosce dal documento - ha la stessa forma, la stessa intestazione e
    // la stessa data di uno completo.
    if let Some(frase) = il_documento_lo_produce_chi_ha_i_fatti() {
        return frase;
    }

    let mut screen = screen.borrow_mut();

    let Some(session_id) = screen.flow.session() else {
        return String::from("Scegliere prima il monitoraggio da documentare.");
    };
    let Some(destination) = screen.flow.destination.clone() else {
        return String::from("Scegliere prima la cartella in cui produrre il pacchetto.");
    };
    let mut profile = match screen.flow.fields.to_profile() {
        Ok(profile) => profile,
        Err(message) => return message,
    };
    profile.version = screen.flow_profile_version();
    let Ok(actor) = actor() else {
        return String::from("Identità dell'operatore non utilizzabile: segnalarlo.");
    };

    let selection = screen.flow.selection();
    // I COLLEGAMENTI CHIESTI PER QUESTA RELAZIONE, una volta sola (ADR-0165).
    let collegamenti = screen.asked_links.take();
    let request = ReportGenerationRequest {
        session_id,
        selection,
        profile: &profile,
        destination: &destination,
        requested_kinds: PRODUCIBLE_KINDS.to_vec(),
        requested_by: actor,
        requested_at: now(),
        asked_links: collegamenti.as_ref(),
    };

    let outcome = screen.reports.generate(&request);
    match outcome {
        Ok(produced) => {
            let message = describe_success(&produced);
            screen.flow.produced = Some(record(&produced));
            screen.flow.failed = false;
            screen.flow.step = LAST_STEP;
            message
        }
        Err(error) => {
            // Il messaggio tecnico non si perde: va nel registro diagnostico,
            // dove serve a capire, e non nella schermata, dove non aiuterebbe.
            tracing::warn!(
                kind = error.kind(),
                dettaglio = %error,
                "generazione della relazione non riuscita"
            );
            screen.flow.produced = None;
            screen.flow.failed = true;
            screen.flow.step = LAST_STEP;
            describe(&error)
        }
    }
}

/// Traduce l'esito riuscito in ciò che la schermata mostra.
fn record(produced: &GeneratedReport) -> Produced {
    // Il manifest appena scritto viene **riletto e verificato**: è lo stesso
    // verificatore della schermata Verifica, e dice se i file sul disco
    // corrispondono alle impronte dichiarate. Fidarsi di ciò che si è appena
    // scritto senza rileggerlo è precisamente la fiducia che un manifest esiste
    // per non dover chiedere.
    let verification = verify_package_manifest(&produced.manifest);
    let intact = verification.is_intact();

    Produced {
        report_id: produced.report_id.as_str().to_owned(),
        folder: produced.directory.to_string_lossy().into_owned(),
        artifacts: produced
            .artifacts
            .iter()
            .map(|artifact| ReportArtifactRow {
                name: SharedString::from(artifact.file_name.as_str()),
                kind: crate::lingua::schermo(artifact.kind.operator_label()),
                size: SharedString::from(readable_size(artifact.size_bytes)),
                sha256: SharedString::from(artifact.sha256.as_str()),
            })
            .collect(),
        manifest_state: verification.operator_message(),
        manifest: produced.manifest.clone(),
        pdfs: produced
            .artifacts
            .iter()
            .filter(|artifact| artifact.file_name.to_ascii_lowercase().ends_with(".pdf"))
            .map(|artifact| artifact.file_name.clone())
            .collect(),
        warning: if intact {
            String::new()
        } else {
            String::from(
                "Il pacchetto è stato prodotto ma la verifica delle impronte non \
                 torna: non consegnarlo e rigenerarlo.",
            )
        },
    }
}

/// Messaggio di riuscita, con i numeri che contano.
fn describe_success(produced: &GeneratedReport) -> String {
    let kind = match produced.outcome {
        ReportOutcome::NothingSelected => {
            "La relazione descrive l'attività svolta e dichiara che nessun elemento \
             è stato selezionato dall'operatore."
        }
        ReportOutcome::WithFindings => {
            "La relazione rappresenta i soli elementi selezionati dall'operatore."
        }
    };

    // Il singolare si scrive: oggi il pacchetto contiene un documento solo, e
    // «1 documenti» sarebbe la prima cosa che l'operatore legge.
    let documenti = if produced.artifacts.len() == 1 {
        String::from("un documento")
    } else {
        format!("{} documenti", produced.artifacts.len())
    };

    // CHI PUO' APRIRLO (SEC-01, ADR-0157): la cartella del pacchetto e' del
    // solo utente, e consegnarlo e' una copia, che prende i permessi del posto.
    format!(
        "Pacchetto {} prodotto: {documenti} su {} contenuti monitorati, {} \
         selezionati. {kind} La cartella del pacchetto si apre soltanto con \
         l'utente Windows «{}». Copiato altrove per la consegna, il pacchetto \
         prende i permessi del posto in cui arriva.",
        produced.report_id.as_str(),
        produced.monitored,
        produced.selected,
        produced.owner.name,
    )
}

/// Traduce un errore del servizio in un messaggio per l'operatore.
fn describe(error: &ServiceError) -> String {
    error.operator_message()
}

/// Apre la cartella dei documenti prodotti, e dice che cosa è successo.
///
/// Stringa vuota quando la cartella si è aperta: la finestra di Esplora file è
/// già il riscontro, e una frase in più la ripeterebbe.
pub fn open_folder_outcome(cartella: Option<&std::path::Path>) -> &'static str {
    let Some(cartella) = cartella else {
        return "Non c'è ancora una cartella da aprire: si apre dopo aver prodotto i documenti.";
    };
    match lisi_platform::folder::open(cartella) {
        Ok(()) => "",
        Err(lisi_platform::PlatformError::NotAFolder) => {
            "La cartella non c'è più: forse è stata spostata o rinominata. Il percorso è \
             scritto qui sopra."
        }
        Err(errore) => {
            tracing::warn!(errore = %errore, "cartella dei documenti non aperta");
            "Windows non ha aperto la cartella. Il percorso è scritto qui sopra: si può \
             aprire da Esplora file."
        }
    }
}

/// Chiede all'operatore la cartella in cui produrre il pacchetto.
///
/// Restituisce `None` se l'operatore annulla — che non è un errore e non
/// produce alcun messaggio. Vale qui la ragione di DEC-113: una cartella scelta
/// da una finestra di sistema **esiste per costruzione**, e un percorso digitato
/// a mano produce un rifiuto che sembra un guasto del prodotto.
/// Chiede all'operatore il file dello stemma.
///
/// **Solo PNG**, e solo un file locale: nulla viene scaricato dalla rete
/// durante la generazione (ADR-0031 Decisione 7). Il filtro dichiara il formato
/// invece di lasciarlo scoprire con un rifiuto.
fn emblem_dialog() -> rfd::AsyncFileDialog {
    rfd::AsyncFileDialog::new()
        .set_title("Scegliere lo stemma dell'ufficio")
        .add_filter("Immagine PNG", &["png"])
}

fn destination_dialog(current: Option<&PathBuf>) -> rfd::AsyncFileDialog {
    let mut dialog = rfd::AsyncFileDialog::new().set_title("Scegliere la cartella del pacchetto");
    if let Some(path) = current {
        dialog = dialog.set_directory(path);
    }
    dialog
}

/// Conserva il profilo compilato e ne riporta l'esito.
fn save_profile(window: &AppWindow, screen: &SharedReport, keep_emblem: bool) -> String {
    let mut fields = profile_from_window(window);

    {
        // Lo stemma sopravvive alla scrittura dei campi di testo: sta nel
        // modulo, non nell'interfaccia.
        let current = screen.borrow();
        if keep_emblem {
            fields.emblem = current.profile.emblem.clone();
            fields.emblem_label = current.profile.emblem_label.clone();
        }
    }

    let profile = match fields.to_profile() {
        Ok(profile) => profile,
        Err(message) => return message,
    };
    let Ok(actor) = actor() else {
        return String::from("Identità dell'operatore non utilizzabile: segnalarlo.");
    };

    let saved = screen
        .borrow()
        .reports
        .save_profile(&profile, &actor, now());
    match saved {
        Ok(version) => {
            let mut screen = screen.borrow_mut();
            screen.profile = fields;
            screen.profile_answered = true;
            screen.profile_version = version;
            // I dati appena conservati diventano anche quelli con cui la
            // prossima relazione nasce intestata.
            screen.flow.fields = screen.profile.clone();
            format!("Profilo conservato, versione {version}. Le relazioni useranno questi dati.")
        }
        Err(error) => {
            tracing::warn!(kind = error.kind(), "profilo documentale non conservato");
            error.operator_message()
        }
    }
}

/// Collega i comandi della schermata ai servizi.
pub fn wire(window: &AppWindow, screen: &SharedReport) {
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.global::<DocumentProfile>().on_save(move || {
            if crate::lock::refuse_while_locked("document_profile_save") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = save_profile(&window, &screen, true);
            refresh_profile(&window, &screen, Some(&message));
            publish_fields(&window, &screen);
            refresh(&window, &screen, None);
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.global::<DocumentProfile>().on_decline(move || {
            if crate::lock::refuse_while_locked("document_profile_decline") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            // Si conserva un profilo **vuoto**: è ciò che distingue «non ho
            // risposto» da «ho risposto di no», e senza quella distinzione la
            // domanda tornerebbe a ogni avvio.
            {
                let mut screen = screen.borrow_mut();
                screen.profile = ReportFields::default();
                screen.flow.fields = ReportFields::default();
            }
            window
                .global::<DocumentProfile>()
                .set_organisation(SharedString::default());
            let message = save_profile(&window, &screen, false);
            refresh_profile(&window, &screen, Some(&message));
            publish_fields(&window, &screen);
            refresh(&window, &screen, None);
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window
            .global::<DocumentProfile>()
            .on_choose_emblem(move || {
                if crate::lock::refuse_while_locked("choose_emblem") {
                    return;
                }
                let Some(window) = handle.upgrade() else {
                    return;
                };
                let screen = Rc::clone(&screen);
                crate::dialogs::ask(
                    &window,
                    emblem_dialog(),
                    crate::dialogs::Pick::File,
                    "choose_emblem",
                    move |window, chosen| {
                        let message = match read_emblem(&chosen) {
                            Ok(emblem) => {
                                let label = chosen.file_name().map_or_else(String::new, |name| {
                                    name.to_string_lossy().into_owned()
                                });
                                let mut screen = screen.borrow_mut();
                                screen.profile.emblem = Some(emblem);
                                screen.profile.emblem_label = label;
                                String::from(
                                    "Stemma acquisito: resta nel profilo quando il profilo si salva.",
                                )
                            }
                            Err(message) => message,
                        };
                        // **Non** `refresh_profile`: riscriverebbe i dieci campi
                        // prendendoli dal profilo conservato, cancellando cio' che
                        // l'operatore ha appena digitato e non ha ancora salvato.
                        let label = screen.borrow().profile.emblem_label.clone();
                        refresh_emblem(window, &label, &message);
                    },
                );
            });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.global::<DocumentProfile>().on_clear_emblem(move || {
            if crate::lock::refuse_while_locked("document_profile_clear_emblem") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            {
                let mut screen = screen.borrow_mut();
                screen.profile.emblem = None;
                screen.profile.emblem_label.clear();
            }
            // Lo stemma tolto non tocca i campi di testo: si aggiorna solo
            // cio' che e' cambiato davvero.
            refresh_emblem(
                &window,
                "",
                "Stemma tolto: la scelta resta quando il profilo si salva.",
            );
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_report_shown(move || {
            if let Some(window) = handle.upgrade() {
                refresh(&window, &screen, Some(""));
                refresh_office(&window);
            }
        });
    }

    {
        let handle = window.as_weak();
        window.on_report_hub_refresh(move || {
            if crate::lock::refuse_while_locked("report_hub_refresh") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                refresh_office(&window);
            }
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_report_advance(move || {
            if crate::lock::refuse_while_locked("report_advance") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            {
                let mut screen = screen.borrow_mut();
                let was_last = screen.flow.step() == LAST_STEP;
                screen.flow.advance();
                // «Nuova relazione» ricomincia: i campi tornano ai dati
                // dell'ufficio, non al vuoto.
                if was_last {
                    screen.flow.fields = screen.profile.clone();
                }
            }
            publish_fields(&window, &screen);
            refresh(&window, &screen, Some(""));
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_report_back(move || {
            if crate::lock::refuse_while_locked("report_back") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            screen.borrow_mut().flow.back();
            refresh(&window, &screen, Some(""));
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_report_restart(move || {
            if crate::lock::refuse_while_locked("report_restart") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            {
                let mut screen = screen.borrow_mut();
                if screen.flow.is_busy() {
                    return;
                }
                screen.flow.restart();
                // Ricominciare riporta ai dati dell'ufficio, non al vuoto:
                // sono il punto di partenza di ogni relazione.
                screen.flow.fields = screen.profile.clone();
            }
            window.set_report_filter(SharedString::default());
            window.set_report_only_selected(false);
            window.set_report_only_alerts(false);
            window.set_report_only_excluded(false);
            publish_fields(&window, &screen);
            refresh(&window, &screen, Some(""));
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_report_choose_session(move |session_id| {
            if crate::lock::refuse_while_locked("report_choose_session") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            screen
                .borrow_mut()
                .flow
                .choose_session(SessionId::new(i64::from(session_id)));
            refresh(&window, &screen, Some(""));
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_overview_toggle(move |session_id| {
            if crate::lock::refuse_while_locked("overview_toggle") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            toggle_overview(&screen, session_id);
            refresh(&window, &screen, None);
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_overview_generate(move || {
            if crate::lock::refuse_while_locked("overview_generate") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let frase = generate_overview(
                &screen,
                window.get_overview_name().as_str(),
                window.get_overview_role().as_str(),
            );
            window.set_overview_message(crate::lingua::schermo(frase));
            refresh(&window, &screen, None);
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_report_toggle_content(move |content_id| {
            if crate::lock::refuse_while_locked("report_toggle_content") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            screen
                .borrow_mut()
                .flow
                .toggle(ContentId::new(i64::from(content_id)));
            refresh(&window, &screen, None);
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_report_select_visible(move || {
            if crate::lock::refuse_while_locked("report_select_visible") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            // Le righe visibili sono quelle che l'operatore sta guardando: si
            // leggono dall'interfaccia, che è dove il filtro vive.
            let visible: Vec<ContentId> = window
                .get_report_contents()
                .iter()
                .map(|row| ContentId::new(i64::from(row.content_id)))
                .collect();
            let quante = visible.len();
            screen.borrow_mut().flow.select_all(visible);
            refresh(
                &window,
                &screen,
                Some(&format!(
                    "{quante} contenuti aggiunti alla selezione della relazione."
                )),
            );
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_report_clear_selection(move || {
            if crate::lock::refuse_while_locked("report_clear_selection") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            screen.borrow_mut().flow.clear_selection();
            refresh(
                &window,
                &screen,
                Some(
                    "Selezione azzerata. La relazione descriverà l'attività svolta \
                     senza elementi rappresentati.",
                ),
            );
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_report_filter_contents(move || {
            if crate::lock::refuse_while_locked("report_filter_contents") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                refresh(&window, &screen, None);
            }
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_report_fields_edited(move || {
            if crate::lock::refuse_while_locked("report_fields_edited") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            {
                let mut screen = screen.borrow_mut();
                // Lo stemma non viene dall'interfaccia: sta già nel flusso,
                // letto e validato quando l'operatore lo ha scelto.
                let emblem = screen.flow.fields.emblem.clone();
                let emblem_label = screen.flow.fields.emblem_label.clone();
                // Sede e recapiti sono la terza riga dell'intestazione: il
                // documento la stampa, e fino alla 0.2.2 veniva dal profilo
                // senza comparire fra questi campi (CU01-008). Ora si vede e si
                // cambia qui, come le altre due.
                let premises = window.get_report_premises().to_string();
                screen.flow.fields = ReportFields {
                    organisation: window.get_report_organisation().to_string(),
                    office: window.get_report_office().to_string(),
                    recipient: window.get_report_recipient().to_string(),
                    recipient_cc: window.get_report_recipient_cc().to_string(),
                    subject: window.get_report_subject().to_string(),
                    place: window.get_report_place().to_string(),
                    role: window.get_report_role().to_string(),
                    signer: window.get_report_signer().to_string(),
                    footer: window.get_report_footer().to_string(),
                    premises,
                    emblem,
                    emblem_label,
                };
            }
            refresh(&window, &screen, None);
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_report_choose_emblem(move || {
            if crate::lock::refuse_while_locked("report_choose_emblem") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            // Annullare non è un errore e non produce alcun messaggio.
            let screen = Rc::clone(&screen);
            crate::dialogs::ask(
                &window,
                emblem_dialog(),
                crate::dialogs::Pick::File,
                "report_choose_emblem",
                move |window, chosen| {
                    let message = match read_emblem(&chosen) {
                        Ok(emblem) => {
                            let label = chosen.file_name().map_or_else(String::new, |name| {
                                name.to_string_lossy().into_owned()
                            });
                            let mut screen = screen.borrow_mut();
                            screen.flow.fields.emblem = Some(emblem);
                            screen.flow.fields.emblem_label = label;
                            String::from("Stemma acquisito: comparirà in cima alla prima pagina.")
                        }
                        Err(message) => message,
                    };
                    refresh(window, &screen, Some(&message));
                },
            );
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_report_clear_emblem(move || {
            if crate::lock::refuse_while_locked("report_clear_emblem") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            {
                let mut screen = screen.borrow_mut();
                screen.flow.fields.emblem = None;
                screen.flow.fields.emblem_label.clear();
            }
            refresh(
                &window,
                &screen,
                Some("Stemma tolto: l'intestazione lascerà lo spazio vuoto."),
            );
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_report_choose_destination(move || {
            if crate::lock::refuse_while_locked("report_choose_destination") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let current = screen.borrow().flow.destination.clone();
            // Annullare non è un errore e non produce alcun messaggio.
            let screen = Rc::clone(&screen);
            crate::dialogs::ask(
                &window,
                destination_dialog(current.as_ref()),
                crate::dialogs::Pick::Folder,
                "report_choose_destination",
                move |window, chosen| {
                    screen.borrow_mut().flow.destination = Some(chosen);
                    refresh(window, &screen, Some(""));
                },
            );
        });
    }

    // «APRI LA CARTELLA» (UX-EXCELLENCE-02, SIM3-03, ADR-0137).
    //
    // La cartella e' quella che il servizio ha restituito producendo il
    // pacchetto, conservata nel percorso: non il testo della schermata, e
    // nessun percorso arriva da un contenuto acquisito. La piattaforma la apre
    // solo se e' una cartella che esiste; nulla si apre senza il comando.
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_report_open_folder(move || {
            if crate::lock::refuse_while_locked("report_open_folder") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let cartella = screen
                .borrow()
                .flow
                .produced
                .as_ref()
                .map(|prodotto| PathBuf::from(&prodotto.folder));
            window.set_report_folder_message(SharedString::from(open_folder_outcome(
                cartella.as_deref(),
            )));
        });
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_report_generate(move || {
            if crate::lock::refuse_while_locked("report_generate") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };

            // La guardia contro la doppia generazione. Il servizio produrrebbe
            // due pacchetti distinti, quindi il difetto non sarebbe un archivio
            // rotto: sarebbero due cartelle sul disco di cui una che nessuno ha
            // chiesto, e un identificativo consumato senza ragione.
            {
                let mut screen = screen.borrow_mut();
                if screen.flow.is_busy() || !screen.flow.can_generate() {
                    return;
                }
                screen.flow.busy = true;
            }
            refresh(&window, &screen, Some(""));

            // La generazione parte al giro **successivo** del ciclo di eventi,
            // non qui: è sincrona e dura quanto dura, e chiamandola subito la
            // finestra non farebbe in tempo a disegnare lo stato di attesa.
            // Chi guarda vedrebbe l'interfaccia ferma senza sapere perché.
            let deferred = handle.clone();
            let screen = Rc::clone(&screen);
            slint::Timer::single_shot(std::time::Duration::from_millis(50), move || {
                // I COLLEGAMENTI, SE SCELTI, PRIMA DI COMPORRE (ADR-0165).
                let chiesti = deferred
                    .upgrade()
                    .is_some_and(|window| window.get_report_ask_links())
                    .then(|| ask_links(&screen));
                // LA FIRMA, SE CHIESTA, DOPO IL PACCHETTO (ADR-0181,
                // decisione 7): si firma soltanto ciò che si è appena prodotto.
                let firma = deferred.upgrade().is_some_and(|window| {
                    window.get_report_sign() && window.get_signing_available()
                });
                let message = generate(&screen);
                let message = match chiesti {
                    Some(avviso) => format!("{avviso} {message}"),
                    None => message,
                };
                let prodotto = screen
                    .borrow()
                    .flow
                    .produced
                    .as_ref()
                    .map(|prodotto| (prodotto.manifest.clone(), prodotto.pdfs.clone()));
                let message = match (firma, prodotto) {
                    (true, Some((manifest, pdfs))) => {
                        let esito = crate::signing::sign_report(&manifest, &pdfs);
                        // La verifica del pacchetto legge anche la firma
                        // accanto al manifest (ADR-0181, conseguenze).
                        if let Some(prodotto) = screen.borrow_mut().flow.produced.as_mut() {
                            prodotto.manifest_state = format!(
                                "{} {}",
                                prodotto.manifest_state,
                                crate::signing::signature_sentence(&manifest)
                            );
                        }
                        format!("{message} {esito}")
                    }
                    _ => message,
                };
                screen.borrow_mut().flow.busy = false;
                if let Some(window) = deferred.upgrade() {
                    refresh(&window, &screen, Some(&message));
                }
            });
        });
    }
}

/// Collega la sessione dell'account alla schermata, per chiedere i
/// collegamenti della relazione (ADR-0165).
pub fn attach_session(screen: &SharedReport, session: &crate::account::SharedSession) {
    screen.borrow_mut().session = Some(Rc::clone(session));
}

/// Chiede a Telegram il collegamento dei contenuti scelti, per la prossima
/// relazione (ADR-0165, decisione 1). Senza account non chiede nulla, e lo
/// dice.
fn ask_links(screen: &SharedReport) -> String {
    let senza = "Senza un account collegato i collegamenti non si chiedono: la relazione dice \
                 che non li ha chiesti.";
    let mut schermata = screen.borrow_mut();
    let scelti: Vec<ContentId> = schermata.flow.selection.iter().copied().collect();
    let Some(session) = schermata.session.clone() else {
        schermata.asked_links = None;
        return String::from(senza);
    };
    let mut sessione = session.borrow_mut();
    let Some(runtime) = sessione.runtime_mut() else {
        schermata.asked_links = None;
        return String::from(senza);
    };
    let esito = lisi_services::message_link::ask_for_documents(
        schermata.reports.database(),
        runtime.connector_mut(),
        &scelti,
        now(),
    );
    match esito {
        Ok(libro) => {
            let frase = format!(
                "Chiesti a Telegram i collegamenti dei contenuti scelti, al pi\u{f9} {}: ciascuno \
                 dice nel documento quando \u{e8} stato chiesto.",
                lisi_services::message_link::MAX_DOCUMENT_LINKS
            );
            schermata.asked_links = Some(libro);
            frase
        }
        Err(errore) => {
            schermata.asked_links = None;
            errore.operator_message()
        }
    }
}

/// Quante righe il filtro mostra, su quante, e quante restano scelte, con il
/// numero concordato (COLLAUDO-FIX-01, CU01-007).
///
/// Fino alla 0.2.2 la frase era una sola, al plurale: «1 righe mostrate su 1
/// monitorate», «1 elementi restano scelti». Ogni forma è una frase intera,
/// con la sua voce nel catalogo: un nome passato come valore resterebbe
/// italiano nell'interfaccia inglese. Le due frasi passano il confine una per
/// volta, perché il catalogo le conosce una per volta.
fn nota_dei_visibili(shown: usize, total: usize, selected: usize) -> SharedString {
    let (mostrate, scelte) = frasi_dei_visibili(shown, total, selected);
    SharedString::from(format!(
        "{} {}",
        crate::lingua::schermo(mostrate),
        crate::lingua::schermo(scelte)
    ))
}

/// Le due frasi della nota, in italiano, prima del confine con lo schermo.
fn frasi_dei_visibili(shown: usize, total: usize, selected: usize) -> (String, String) {
    let mostrate = match (shown, total) {
        (1, 1) => String::from("1 riga mostrata su 1 monitorata."),
        (1, _) => format!("1 riga mostrata su {total} monitorate."),
        (_, 1) => format!("{shown} righe mostrate su 1 monitorata."),
        _ => format!("{shown} righe mostrate su {total} monitorate."),
    };
    let scelte = if selected == 1 {
        String::from("Il filtro non tocca la selezione: 1 elemento resta scelto.")
    } else {
        format!("Il filtro non tocca la selezione: {selected} elementi restano scelti.")
    };
    (mostrate, scelte)
}

/// Questo stesso file, letto a tempo di compilazione.
///
/// Serve alla guardia strutturale sulla chiamata al generatore: che il pulsante
/// «Genera» arrivi davvero al sottosistema del reporting non è verificabile
/// senza una finestra, un archivio popolato e una cartella scrivibile, ma la
/// sua **assenza** sì.
#[cfg(test)]
const THIS_MODULE: &str = include_str!("report.rs");

#[cfg(test)]
mod tests {
    use lisi_core::model::report::ReportOutcome;
    use lisi_core::{ContentId, SessionId};

    /// **La terza riga dell'intestazione si vede e si cambia nella procedura del
    /// Report**, come le altre due (COLLAUDO-FIX-01, CU01-008). Vista rossa con
    /// la 0.2.2: la sede veniva dal profilo e non c'era fra i campi.
    #[test]
    fn la_sede_si_cambia_nella_procedura() {
        let interfaccia = include_str!("../ui/app-window.slint");
        assert!(interfaccia.contains(concat!("value <=> root.report-", "premises;")));
        let modulo = super::THIS_MODULE;
        assert!(modulo.contains(concat!(
            "let premises = window.get_report_",
            "premises().to_string();"
        )));
        assert!(modulo.contains(concat!(
            "window.set_report_",
            "premises(SharedString::from(fields.premises.as_str()));"
        )));
    }

    /// **Con 1 il singolare: «1 riga mostrata su 1 monitorata», «1 elemento
    /// resta scelto»** (COLLAUDO-FIX-01, CU01-007). Vista rossa con la frase
    /// della 0.2.2, sempre al plurale.
    #[test]
    fn la_nota_dei_visibili_concorda_con_il_numero() {
        use super::frasi_dei_visibili;

        let frasi = |a, b, c| {
            let (prima, seconda) = frasi_dei_visibili(a, b, c);
            format!("{prima} {seconda}")
        };
        assert_eq!(
            frasi(1, 1, 1),
            "1 riga mostrata su 1 monitorata. Il filtro non tocca la selezione: 1 elemento \
             resta scelto."
        );
        assert_eq!(
            frasi(1, 7, 0),
            "1 riga mostrata su 7 monitorate. Il filtro non tocca la selezione: 0 elementi \
             restano scelti."
        );
        assert_eq!(
            frasi(0, 1, 1),
            "0 righe mostrate su 1 monitorata. Il filtro non tocca la selezione: 1 elemento \
             resta scelto."
        );
        assert_eq!(
            frasi(3, 12, 2),
            "3 righe mostrate su 12 monitorate. Il filtro non tocca la selezione: 2 elementi \
             restano scelti."
        );
    }

    use super::{
        FIRST_STEP, GENERATION_STEP, LAST_STEP, ReportFields, ReportFlow, outcome_sentence,
        readable_size,
    };

    /// **Le righe del rapporto complessivo seguono le spunte** (REPORT-MULTI-01,
    /// ADR-0192): tutti i monitoraggi dell'elenco, spuntati quelli scelti.
    #[test]
    fn le_righe_del_rapporto_complessivo_seguono_le_spunte() {
        let voce = |id: i32, nome: &str| crate::ReportSessionEntry {
            session_id: id,
            label: slint::SharedString::from(nome),
            ..Default::default()
        };
        let righe = super::overview_rows(&[voce(1, "Primo"), voce(2, "Secondo")], &[2]);
        assert_eq!(righe.len(), 2);
        assert_eq!(righe[0].label.as_str(), "Primo");
        assert!(!righe[0].chosen);
        assert!(righe[1].chosen);
    }

    /// Il codice di questo file senza il modulo di prova e senza i commenti.
    ///
    /// Il taglio non è pignoleria: le stringhe cercate compaiono qui sotto, e
    /// senza il taglio il test **si soddisferebbe da solo** e resterebbe verde
    /// dopo aver cancellato la chiamata vera.
    fn production_code() -> String {
        let Some((production, _)) = super::THIS_MODULE.split_once("#[cfg(test)]\nmod tests {")
        else {
            panic!("il modulo di prova deve essere riconoscibile per poterlo escludere");
        };

        production
            .lines()
            .map(str::trim_start)
            .filter(|line| !line.starts_with("//") && !line.starts_with("///"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Guardia strutturale: la schermata chiama davvero il generatore.
    ///
    /// **Il difetto da cui protegge** è quello che questo progetto ha già
    /// incontrato sei volte, e che MP-18C aveva dichiarato apertamente: un
    /// motore costruito, collaudato e mai invocato. `ReportService::generate`
    /// ha i suoi test in `lisi-services` e resterebbero tutti verdi se questa
    /// schermata non lo chiamasse mai — e il binario di release non
    /// conterrebbe nemmeno il generatore, perché il linker scarta ciò che non
    /// si raggiunge.
    ///
    /// **Che cosa prova e che cosa no.** Prova che il collegamento esiste, cioè
    /// esattamente ciò che mancava. Non prova che il documento si apra in Word:
    /// quello è la sezione T del pilot, e nessun test può chiuderlo.
    #[test]
    fn the_screen_actually_calls_the_generator() {
        let code = production_code();

        assert!(
            code.contains("screen.reports.generate(&request)"),
            "la schermata non chiama piu' il generatore: il sottosistema del \
             reporting esisterebbe senza che nulla lo raggiunga"
        );
        assert!(
            code.contains("window.on_report_generate(move ||"),
            "il comando «Genera» non e' piu' collegato: il generatore resterebbe \
             irraggiungibile dall'interfaccia"
        );
        assert!(
            code.contains("verify_package_manifest(&produced.manifest)"),
            "il pacchetto appena prodotto non viene piu' riletto e verificato"
        );
    }

    /// Guardia strutturale: nessun formato inesistente viene prodotto.
    #[test]
    fn only_the_formats_the_services_declare_are_requested() {
        let code = production_code();

        assert!(
            code.contains("requested_kinds: PRODUCIBLE_KINDS.to_vec()"),
            "i formati richiesti non vengono piu' dall'elenco dei servizi: \
             l'interfaccia potrebbe chiedere un documento che nessuno produce"
        );
    }

    #[test]
    fn a_fresh_flow_starts_at_the_first_step_without_a_session() {
        let flow = ReportFlow::default();

        assert_eq!(flow.step(), FIRST_STEP);
        assert!(flow.session().is_none());
        assert!(!flow.can_advance(), "senza sessione non si avanza");
        assert!(!flow.can_go_back());
        assert!(!flow.can_generate());
        assert!(
            flow.blocking_reason().contains("monitoraggio"),
            "il motivo del divieto deve nominare cio' che manca"
        );
    }

    #[test]
    fn choosing_a_session_opens_the_way_forward() {
        let mut flow = ReportFlow::default();
        flow.choose_session(SessionId::new(1));

        assert!(flow.can_advance());
        assert!(flow.blocking_reason().is_empty());
    }

    #[test]
    fn zero_selected_contents_is_a_valid_state_and_not_an_error() {
        // È la riga più importante di questo modulo: la relazione a esito
        // negativo si produce, e un percorso che si fermasse qui la renderebbe
        // impossibile.
        let mut flow = ReportFlow::default();
        flow.choose_session(SessionId::new(1));
        flow.advance();

        assert_eq!(flow.step(), 2);
        assert_eq!(flow.selected_count(), 0);
        assert!(
            flow.can_advance(),
            "zero selezionati non impedisce di avanzare"
        );
        assert!(flow.blocking_reason().is_empty());
        assert_eq!(flow.selection().outcome(), ReportOutcome::NothingSelected);
    }

    #[test]
    fn a_single_selected_content_reaches_the_domain_selection() {
        let mut flow = ReportFlow::default();
        flow.choose_session(SessionId::new(1));
        flow.toggle(ContentId::new(7));

        assert_eq!(flow.selected_count(), 1);
        assert!(flow.contains(ContentId::new(7)));
        assert_eq!(flow.selection().contents(), &[ContentId::new(7)]);
        assert_eq!(flow.selection().outcome(), ReportOutcome::WithFindings);
    }

    #[test]
    fn a_second_touch_on_the_same_row_takes_it_out_again() {
        let mut flow = ReportFlow::default();
        flow.toggle(ContentId::new(3));
        flow.toggle(ContentId::new(3));

        assert_eq!(flow.selected_count(), 0);
        assert!(!flow.contains(ContentId::new(3)));
    }

    #[test]
    fn a_multiple_selection_stays_ordered_and_without_repetitions() {
        let mut flow = ReportFlow::default();
        flow.select_all([ContentId::new(9), ContentId::new(1), ContentId::new(9)]);
        flow.toggle(ContentId::new(5));

        assert_eq!(flow.selected_count(), 3);
        assert_eq!(
            flow.selection().contents(),
            &[ContentId::new(1), ContentId::new(5), ContentId::new(9)]
        );
    }

    #[test]
    fn going_back_and_forth_never_loses_the_selection() {
        // Il vincolo esplicito del percorso: rileggere che cosa si è scelto non
        // deve costare la scelta.
        let mut flow = ReportFlow::default();
        flow.choose_session(SessionId::new(1));
        flow.advance();
        flow.select_all([ContentId::new(2), ContentId::new(4)]);

        flow.advance();
        flow.advance();
        flow.back();
        flow.back();

        assert_eq!(flow.step(), 2);
        assert_eq!(flow.selected_count(), 2);
        assert!(flow.contains(ContentId::new(2)));
        assert!(flow.contains(ContentId::new(4)));
    }

    #[test]
    fn changing_session_clears_a_selection_that_would_not_belong_to_it() {
        // Un contenuto scelto in un monitoraggio non appartiene a un altro, e
        // portarselo dietro produrrebbe il rifiuto del servizio invece di una
        // relazione.
        let mut flow = ReportFlow::default();
        flow.choose_session(SessionId::new(1));
        flow.select_all([ContentId::new(1), ContentId::new(2)]);
        flow.choose_session(SessionId::new(2));

        assert_eq!(flow.selected_count(), 0);
        assert_eq!(flow.session(), Some(SessionId::new(2)));
    }

    #[test]
    fn choosing_the_same_session_again_keeps_the_selection() {
        // Ripremere la riga già scelta non è un cambio di sessione: azzerare
        // qui costerebbe la selezione a chi ha cliccato due volte.
        let mut flow = ReportFlow::default();
        flow.choose_session(SessionId::new(1));
        flow.select_all([ContentId::new(1)]);
        flow.choose_session(SessionId::new(1));

        assert_eq!(flow.selected_count(), 1);
    }

    #[test]
    fn clearing_the_selection_leaves_a_legitimate_state() {
        let mut flow = ReportFlow::default();
        flow.select_all([ContentId::new(1), ContentId::new(2)]);
        flow.clear_selection();

        assert_eq!(flow.selected_count(), 0);
        assert_eq!(flow.selection().outcome(), ReportOutcome::NothingSelected);
    }

    #[test]
    fn a_generation_in_progress_blocks_every_other_command() {
        // Impedisce la doppia generazione: il servizio produrrebbe due
        // pacchetti distinti, di cui uno che nessuno ha chiesto.
        let mut flow = ReportFlow {
            destination: Some(std::path::PathBuf::from("C:\\prova")),
            ..ReportFlow::default()
        };
        flow.choose_session(SessionId::new(1));
        while flow.step() < GENERATION_STEP {
            flow.advance();
        }
        assert!(flow.can_generate(), "al passo 6 la generazione e' ammessa");

        flow.busy = true;

        assert!(
            !flow.can_generate(),
            "una seconda generazione non e' ammessa"
        );
        assert!(!flow.can_advance());
        assert!(!flow.can_go_back());
        assert!(flow.blocking_reason().contains("in corso"));
    }

    #[test]
    fn without_a_destination_nothing_can_be_generated() {
        let mut flow = ReportFlow::default();
        flow.choose_session(SessionId::new(1));
        while flow.step() < GENERATION_STEP {
            flow.advance();
        }
        flow.destination = None;

        assert!(!flow.can_generate());
    }

    #[test]
    fn the_generation_step_says_that_advancing_is_not_the_way_to_produce() {
        let mut flow = ReportFlow::default();
        flow.choose_session(SessionId::new(1));
        while flow.step() < GENERATION_STEP {
            flow.advance();
        }

        assert!(!flow.can_advance());
        assert!(flow.blocking_reason().contains("Genera la relazione"));
    }

    #[test]
    fn restarting_forgets_every_choice_but_keeps_the_folder() {
        let mut flow = ReportFlow {
            destination: Some(std::path::PathBuf::from("C:\\prova")),
            ..ReportFlow::default()
        };
        flow.choose_session(SessionId::new(1));
        flow.select_all([ContentId::new(1)]);
        flow.fields.place = String::from("Località di prova");
        flow.advance();

        flow.restart();

        assert_eq!(flow.step(), FIRST_STEP);
        assert!(flow.session().is_none());
        assert_eq!(flow.selected_count(), 0);
        assert_eq!(flow.fields, ReportFields::default());
        assert_eq!(
            flow.destination,
            Some(std::path::PathBuf::from("C:\\prova")),
            "la cartella scelta non e' una scelta da rifare a ogni relazione"
        );
    }

    #[test]
    fn the_last_step_restarts_instead_of_advancing_into_nothing() {
        let mut flow = ReportFlow {
            step: LAST_STEP,
            session: Some(SessionId::new(1)),
            ..ReportFlow::default()
        };

        flow.advance();

        assert_eq!(flow.step(), FIRST_STEP);
    }

    // ------------------------------------------------- dati della relazione

    /// **La relazione porta la versione del profilo che ha usato** (E2E01-11):
    /// quella conservata se i dati sono identici, 0 se sono stati cambiati per
    /// questa relazione o se nessun profilo è conservato.
    #[test]
    fn la_relazione_porta_la_versione_del_profilo_usato() {
        let conservato = ReportFields {
            office: String::from("Ufficio di prova"),
            ..ReportFields::default()
        };
        assert_eq!(
            super::flow_profile_version(&conservato.clone(), &conservato, 3),
            3
        );
        let cambiato = ReportFields {
            office: String::from("Altro ufficio"),
            ..conservato.clone()
        };
        assert_eq!(super::flow_profile_version(&cambiato, &conservato, 3), 0);
        assert_eq!(
            super::flow_profile_version(&conservato.clone(), &conservato, 0),
            0
        );
    }

    #[test]
    fn an_empty_form_produces_an_empty_profile_and_not_an_invented_one() {
        // Criterio 22 dal lato dell'interfaccia: nessun dato istituzionale sta
        // nel sorgente, e un modulo vuoto produce un documento senza
        // intestazione, non un documento con l'intestazione di qualcun altro.
        let Ok(profile) = ReportFields::default().to_profile() else {
            panic!("un modulo vuoto deve produrre un profilo valido");
        };
        assert!(profile.is_empty());
        assert_eq!(profile.version, 0);
    }

    #[test]
    fn the_compiled_fields_reach_the_profile() {
        let fields = ReportFields {
            organisation: String::from("Ente"),
            recipient: String::from("Al Responsabile"),
            place: String::from("Località di prova"),
            ..ReportFields::default()
        };
        let Ok(profile) = fields.to_profile() else {
            panic!("i campi compilati devono essere accettati");
        };

        assert!(!profile.is_empty());
        assert_eq!(
            profile.organisation.map(|value| value.as_str().to_owned()),
            Some(String::from("Ente"))
        );
        assert_eq!(
            profile.recipient.map(|value| value.as_str().to_owned()),
            Some(String::from("Al Responsabile"))
        );
        assert_eq!(
            profile.place.map(|value| value.as_str().to_owned()),
            Some(String::from("Località di prova"))
        );
    }

    #[test]
    fn the_chosen_emblem_reaches_the_profile() {
        use lisi_core::model::report_template::TemplateEmblem;

        let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        bytes.extend_from_slice(&13_u32.to_be_bytes());
        bytes.extend_from_slice(b"IHDR");
        bytes.extend_from_slice(&48_u32.to_be_bytes());
        bytes.extend_from_slice(&48_u32.to_be_bytes());
        bytes.extend_from_slice(&[8, 6, 0, 0, 0]);

        let fields = ReportFields {
            emblem: TemplateEmblem::from_png(bytes).ok(),
            emblem_label: String::from("stemma.png"),
            ..ReportFields::default()
        };
        let Ok(profile) = fields.to_profile() else {
            panic!("uno stemma valido deve essere accettato");
        };

        assert!(profile.emblem.is_some(), "lo stemma non arriva nel profilo");
        assert!(
            !profile.is_empty(),
            "un profilo con il solo stemma non e' vuoto"
        );
    }

    #[test]
    fn a_field_with_hidden_characters_is_refused_and_says_which_one() {
        // La validazione è quella del dominio: un carattere che altera l'ordine
        // di lettura mostrerebbe nell'intestazione qualcosa di diverso da ciò
        // che il documento contiene.
        let fields = ReportFields {
            office: String::from("Ufficio\u{202e}osrevor"),
            ..ReportFields::default()
        };

        let Err(message) = fields.to_profile() else {
            panic!("un carattere invisibile non deve essere accettato");
        };
        assert!(
            message.contains("Ufficio di appartenenza"),
            "il messaggio deve nominare il campo: {message}"
        );
    }

    #[test]
    fn a_saved_profile_becomes_the_starting_point_of_every_report() {
        // È il punto della conservazione: i dati dell'ufficio si compilano una
        // volta e da lì in poi ogni relazione parte già intestata.
        use lisi_core::model::report_template::{ReportTemplateProfile, TemplateField};

        let profile = ReportTemplateProfile {
            organisation: TemplateField::try_new("Ente conservato").ok(),
            header_line: TemplateField::try_new("Via di Prova 1").ok(),
            signer_name: TemplateField::try_new("Nome COGNOME").ok(),
            ..ReportTemplateProfile::default()
        };
        let fields = ReportFields::from_profile(&profile);

        assert_eq!(fields.organisation, "Ente conservato");
        assert_eq!(fields.premises, "Via di Prova 1");
        assert_eq!(fields.signer, "Nome COGNOME");
        // I campi che il profilo non porta restano vuoti, non inventati.
        assert!(fields.recipient.is_empty());

        // E il giro completo torna al punto di partenza.
        let Ok(ritorno) = fields.to_profile() else {
            panic!("i campi conservati devono essere validi");
        };
        assert_eq!(
            ritorno.organisation.map(|f| f.as_str().to_owned()),
            Some(String::from("Ente conservato"))
        );
        assert_eq!(
            ritorno.header_line.map(|f| f.as_str().to_owned()),
            Some(String::from("Via di Prova 1"))
        );
    }

    #[test]
    fn an_emblem_kept_in_the_profile_is_declared_without_inventing_a_file_name() {
        // Del file conservato restano i byte, non il nome: dichiararne uno che
        // nessuno ha più sarebbe un'informazione falsa.
        use lisi_core::model::report_template::{ReportTemplateProfile, TemplateEmblem};

        let mut png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        png.extend_from_slice(&13_u32.to_be_bytes());
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&10_u32.to_be_bytes());
        png.extend_from_slice(&10_u32.to_be_bytes());
        png.extend_from_slice(&[8, 6, 0, 0, 0]);

        let profile = ReportTemplateProfile {
            emblem: TemplateEmblem::from_png(png).ok(),
            ..ReportTemplateProfile::default()
        };
        let fields = ReportFields::from_profile(&profile);

        assert!(fields.emblem.is_some());
        assert_eq!(fields.emblem_label, "stemma conservato");
    }

    #[test]
    fn a_field_that_is_only_whitespace_counts_as_missing() {
        let fields = ReportFields {
            recipient: String::from("   "),
            ..ReportFields::default()
        };
        let Ok(profile) = fields.to_profile() else {
            panic!("uno spazio non e' un valore da rifiutare");
        };
        assert!(profile.recipient.is_none());
    }

    #[test]
    fn an_invalid_field_stops_the_third_step_and_the_generation() {
        let mut flow = ReportFlow::default();
        flow.choose_session(SessionId::new(1));
        flow.advance();
        flow.advance();
        flow.fields.place = "a".repeat(1_000);

        assert_eq!(flow.step(), 3);
        assert!(!flow.can_advance());
        assert!(flow.blocking_reason().contains("Luogo"));
    }

    // ----------------------------------------------------------- messaggi

    #[test]
    fn the_negative_report_is_described_as_a_choice_and_never_as_a_fact() {
        // La stessa regola della costante del dominio, applicata alla frase
        // che l'operatore legge **prima** di generare: una schermata che
        // dicesse «nessun illecito rilevato» affermerebbe un fatto che nessuno
        // ha accertato.
        let sentence = outcome_sentence(0).to_lowercase();

        assert!(sentence.contains("selezionato dall'operatore"));
        for forbidden in [
            "illecit",
            "non risultano element",
            "nulla di rilevante",
            "non sussist",
            "reato",
        ] {
            assert!(
                !sentence.contains(forbidden),
                "la frase dell'esito negativo contiene «{forbidden}»"
            );
        }
    }

    #[test]
    fn a_report_with_findings_says_that_it_represents_only_the_chosen_ones() {
        assert!(outcome_sentence(3).contains("soli elementi scelti"));
    }

    #[test]
    fn a_size_is_readable_at_a_glance() {
        assert_eq!(readable_size(0), "0 byte");
        assert_eq!(readable_size(512), "512 byte");
        assert_eq!(readable_size(20_913_664), "20\u{202f}913\u{202f}664 byte");
    }

    #[test]
    fn the_seven_steps_are_the_seven_of_the_design() {
        assert_eq!(super::STEPS.len(), usize::from(LAST_STEP));
        assert_eq!(super::STEPS[0], "Sessione");
        assert_eq!(super::STEPS[usize::from(LAST_STEP) - 1], "Esito");
    }
}

#[cfg(test)]
mod prove_del_profilo {
    use super::*;

    /// I dieci campi con cui l'operatore compila il profilo, e un valore
    /// riconoscibile per ciascuno. Se un giorno il profilo ne acquista uno,
    /// questa tabella e' il posto dove aggiungerlo.
    const COMPILATI: [(&str, &str); 10] = [
        ("organisation", "Amministrazione di prova"),
        ("office", "Ufficio di prova"),
        ("premises", "Via di prova 1"),
        ("recipient", "Destinatario di prova"),
        ("recipient_cc", "Per conoscenza di prova"),
        ("place", "Luogo di prova"),
        ("signer_role", "Qualifica di prova"),
        ("signer_name", "Nome di prova"),
        ("footer_line", "Riga in calce di prova"),
        ("subject_base", "Oggetto di prova"),
    ];

    /// Che cosa i campi contengono, nell'ordine di `COMPILATI`.
    fn letti(global: &DocumentProfile) -> Vec<String> {
        vec![
            global.get_organisation().to_string(),
            global.get_office().to_string(),
            global.get_premises().to_string(),
            global.get_recipient().to_string(),
            global.get_recipient_cc().to_string(),
            global.get_place().to_string(),
            global.get_signer_role().to_string(),
            global.get_signer_name().to_string(),
            global.get_footer_line().to_string(),
            global.get_subject_base().to_string(),
        ]
    }

    fn compila(global: &DocumentProfile) {
        global.set_organisation(SharedString::from(COMPILATI[0].1));
        global.set_office(SharedString::from(COMPILATI[1].1));
        global.set_premises(SharedString::from(COMPILATI[2].1));
        global.set_recipient(SharedString::from(COMPILATI[3].1));
        global.set_recipient_cc(SharedString::from(COMPILATI[4].1));
        global.set_place(SharedString::from(COMPILATI[5].1));
        global.set_signer_role(SharedString::from(COMPILATI[6].1));
        global.set_signer_name(SharedString::from(COMPILATI[7].1));
        global.set_footer_line(SharedString::from(COMPILATI[8].1));
        global.set_subject_base(SharedString::from(COMPILATI[9].1));
    }

    /// **La prova del difetto del 2026-08-19.**
    ///
    /// L'operatore compila i dieci campi, poi sceglie lo stemma. Se scegliere
    /// lo stemma svuota i campi, quello che poi si salva e' un profilo vuoto —
    /// ed e' esattamente cio' che e' finito nell'archivio della prima
    /// installazione reale.
    ///
    /// La prova gira in un solo `#[test]` perche' il backend di prova si
    /// inizializza una volta sola per processo e la finestra vuole un solo
    /// filo di esecuzione.
    #[test]
    fn lo_stemma_non_cancella_cio_che_l_operatore_ha_digitato() {
        i_slint_backend_testing::init_no_event_loop();
        let window = AppWindow::new().expect("la finestra di prova deve nascere");
        let global = window.global::<DocumentProfile>();

        compila(&global);
        let atteso: Vec<String> = COMPILATI.iter().map(|(_, v)| (*v).to_string()).collect();
        assert_eq!(
            letti(&global),
            atteso,
            "i campi non si sono nemmeno riempiti"
        );

        // 1. Lo stemma viene scelto.
        refresh_emblem(&window, "stemma.png", "Stemma acquisito.");
        for (indice, (nome, _)) in COMPILATI.iter().enumerate() {
            assert_eq!(
                letti(&global)[indice],
                atteso[indice],
                "scegliere lo stemma ha cancellato il campo «{nome}»"
            );
        }
        assert_eq!(global.get_emblem_name().to_string(), "stemma.png");
        assert_eq!(global.get_message().to_string(), "Stemma acquisito.");

        // 2. Lo stemma viene tolto: stessa garanzia.
        refresh_emblem(&window, "", "Stemma tolto.");
        for (indice, (nome, _)) in COMPILATI.iter().enumerate() {
            assert_eq!(
                letti(&global)[indice],
                atteso[indice],
                "togliere lo stemma ha cancellato il campo «{nome}»"
            );
        }
        assert_eq!(global.get_emblem_name().to_string(), "");
    }

    /// I due gestori dello stemma devono usare l'aggiornamento stretto.
    ///
    /// La prova qui sopra dimostra che `refresh_emblem` non cancella nulla;
    /// questa dimostra che i gestori la chiamano davvero. Senza la seconda, il
    /// difetto potrebbe tornare rimettendo `refresh_profile` in un gestore, e
    /// la prima resterebbe verde.
    #[test]
    fn i_gestori_dello_stemma_non_riscrivono_tutto_il_profilo() {
        // Si guarda soltanto il codice **prima** del modulo di prova: dentro
        // le prove i due nomi compaiono per forza, e cercarli qui dentro
        // renderebbe la guardia sempre rossa.
        let sorgente = include_str!("report.rs");
        let (codice, _) = sorgente
            .split_once("\n#[cfg(test)]")
            .expect("il modulo di prova deve stare in coda");

        for gestore in ["on_choose_emblem", "on_clear_emblem"] {
            let inizio = codice
                .find(gestore)
                .unwrap_or_else(|| panic!("gestore «{gestore}» non trovato"));
            // Il corpo del gestore finisce dove comincia il blocco successivo.
            let corpo = &codice[inizio..];
            let fine = corpo.find("\n    {\n").unwrap_or(corpo.len());
            let corpo = &corpo[..fine];

            assert!(
                corpo.contains("refresh_emblem("),
                "«{gestore}» non chiama refresh_emblem"
            );
            assert!(
                !corpo.contains("refresh_profile("),
                "«{gestore}» chiama refresh_profile: cancellerebbe i campi \
                 che l'operatore sta compilando"
            );
        }
    }
    /// **Una postazione che segue un Hub non produce relazioni.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Su una postazione che segue un Hub i fatti non ci sono: il contenuto si
    /// chiede uno per volta e non si conserva, e il live e' una proiezione
    /// potata. Un documento prodotto li' parlerebbe di una sessione con i
    /// numeri sbagliati, o con nessun numero, e porterebbe una firma e una data
    /// che lo farebbero sembrare autorevole (TEAM-REPORT-01, ADR-0100,
    /// decisione 1).
    ///
    /// La guardia legge il **codice**: il controllo deve stare **prima** di
    /// tutto il resto, perche' un controllo in mezzo e' un controllo che si
    /// puo' scavalcare spostando una riga.
    #[test]
    fn una_postazione_che_segue_un_hub_non_produce_relazioni() {
        let Some((_, corpo)) =
            super::THIS_MODULE.split_once("fn generate(screen: &SharedReport) -> String {")
        else {
            panic!("la funzione che genera deve esistere");
        };
        let Some((prime_righe, _)) = corpo.split_once("let mut screen = screen.borrow_mut();")
        else {
            panic!("la funzione deve prendere lo stato della schermata");
        };
        assert!(
            prime_righe.contains("il_documento_lo_produce_chi_ha_i_fatti()"),
            "il controllo del ruolo non e' la prima cosa che `generate` fa"
        );
    }
}

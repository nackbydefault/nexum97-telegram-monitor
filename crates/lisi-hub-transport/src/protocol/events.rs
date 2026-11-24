//! I messaggi del recupero (HUB-CATCHUP-01, ADR-0087).
//!
//! # La forma
//!
//! ```text
//! postazione -> Hub : Resume { stream, after, limit }
//! Hub -> postazione : Page          { events[], latest }
//!                   | NotOurStream  { stream, latest }
//!                   | AheadOfHub    { latest }
//! ```
//!
//! Il client chiede **ciò che viene dopo** un numero, non «tutto»; l'Hub
//! risponde con una pagina e dice **fin dove è arrivato**, così che il client
//! sappia se ne restano altre.
//!
//! # Che cosa questo modulo non fa
//!
//! Non legge l'archivio e non decide: traduce messaggi in frame e viceversa,
//! con i limiti di ADR-0084. Chi risponde davvero sta nei servizi, e non
//! conosce il trasporto.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::protocol::frame::{FrameError, TimedStream, read_frame, write_frame};

/// Il tetto di un frame di questo scambio.
///
/// Una pagina piena di eventi corti sta molto sotto: il tetto esiste perché
/// **nessun** messaggio faccia allocare più di così, non perché serva.
pub const EVENTS_MAX_FRAME_BYTES: u32 = 256 * 1024;

/// Quanti eventi può contenere una pagina.
///
/// È lo stesso tetto di lettura dell'Hub (ADR-0086): una pagina più lunga
/// sarebbe un messaggio che l'Hub non può produrre, e accettarla sarebbe
/// accettare qualcosa che solo un interlocutore ostile manderebbe.
pub const MAX_PAGE_EVENTS: usize = 500;

/// Quanto si aspetta una pagina.
pub const PAGE_TIMEOUT: Duration = Duration::from_secs(30);

/// Elementi al piu' in una pagina della coda di revisione (ADR-0094).
pub const MAX_REVIEW_QUEUE_PAGE: usize = lisi_core::model::hub_review::MAX_REVIEW_QUEUE_PAGE;

/// Caratteri al piu' del testo di un contenuto consegnato per la revisione.
pub const MAX_REVIEW_BODY_CHARS: usize = lisi_core::model::hub_review::MAX_REVIEW_BODY_CHARS;

/// Righe al piu' in una fotografia della coda dell'ufficio (ADR-0095).
pub const MAX_WORK_QUEUE_PAGE: usize = 100;

/// Righe al più in una pagina della presenza (TEAM-PRESENCE-01, ADR-0096).
///
/// Coincide con quante postazioni l'Hub ricorda: una pagina più corta
/// taglierebbe senza che il conteggio totale lo faccia capire.
pub const MAX_PRESENCE_PAGE: usize = 64;

/// Caratteri al più di una frase di accesso che arriva dalla rete
/// (TEAM-ASSIGN-01, ADR-0097).
///
/// È lo stesso limite che il dominio impone alla frase: qui si ripete perché
/// ciò che arriva dalla rete **non è** ciò che abbiamo scritto noi, e perché
/// la verifica è **lenta apposta** — una frase lunghissima sarebbe un modo per
/// occupare l'Hub.
pub const MAX_PASSPHRASE_CHARS: usize = 128;

/// Persone al più in una pagina dell'elenco dei colleghi.
///
/// Un ufficio che usa questo prodotto ha unità o decine di persone. Il tetto
/// esiste perché ogni cosa che viaggia ne ha uno.
pub const MAX_PEOPLE_PAGE: usize = 128;

/// Note condivise al più in una pagina (TEAM-WS-01, ADR-0099).
pub const MAX_SHARED_NOTES_PAGE: usize = 50;

/// Raccoglitori al più in una pagina.
pub const MAX_SHARED_WORKSPACES_PAGE: usize = 50;

/// Elementi di un raccoglitore al più in una pagina.
pub const MAX_WORKSPACE_ITEMS_PAGE: usize = 200;

/// Caratteri al più del testo di una nota che arriva dalla rete.
///
/// È lo stesso limite che il dominio impone a una nota: qui si ripete perché
/// ciò che arriva dalla rete **non è** ciò che abbiamo scritto noi.
pub const MAX_NOTE_CHARS: usize = 2_000;

/// Relazioni al più in una pagina (TEAM-REPORT-01, ADR-0100).
pub const MAX_SHARED_REPORTS_PAGE: usize = 50;

/// Contenuti al più in una selezione che arriva da una postazione.
pub const MAX_REPORT_SELECTION: usize = 500;

/// Documenti al più in una relazione che arriva dalla rete.
pub const MAX_REPORT_ARTIFACTS: usize = 16;

/// Caratteri al più del nome di un documento.
pub const MAX_FILE_NAME_CHARS: usize = 255;

/// Grappoli cyber al più in una pagina (TEAM-CYBER-01, ADR-0102).
pub const MAX_SHARED_CYBER_PAGE: usize = 25;

/// Indicatori al più per grappolo.
pub const MAX_INDICATORS_PER_EVENT: usize = 20;

/// Caratteri al più di una frase che descrive un grappolo.
pub const MAX_CYBER_SENTENCE_CHARS: usize = 1_000;

/// Monitoraggi al più in una pagina (TEAM-CYBER-01, ADR-0102).
pub const MAX_SHARED_SESSIONS_PAGE: usize = 50;

/// Tratti al più di una copertura che viaggia (HUB-COVERAGE-01, ADR-0199).
///
/// Una copertura **non si accorcia**: un tratto in meno direbbe il falso su un
/// periodo. Oltre il tetto l'Hub rifiuta, e la copertura si legge sull'Hub.
pub const MAX_COVERAGE_STRETCHES: usize = 500;

/// Fonti al più di una copertura che viaggia.
pub const MAX_COVERAGE_SOURCES: usize = 64;

/// Caratteri al più del nome stabile di un comando a distanza.
pub const MAX_REMOTE_ACTION_CHARS: usize = 16;

/// Caratteri al più del motivo di un comando a distanza.
pub const MAX_REMOTE_REASON_CHARS: usize = 500;

/// Caratteri al più del nome stabile di uno stato della copertura.
pub const MAX_COVERAGE_STATE_CHARS: usize = 48;

/// Caratteri al più dell'identificativo di una postazione che arriva dalla
/// rete.
///
/// Il dominio ne impone ventiquattro più i separatori; qui si ripete perché
/// ciò che arriva dalla rete **non è** ciò che abbiamo scritto noi.
pub const MAX_DEVICE_ID_CHARS: usize = 64;

/// Caratteri al piu' di un identificativo di comando.
pub const MAX_COMMAND_ID_CHARS: usize = 64;

/// Caratteri al piu' del nome di uno stato o di un verdetto.
pub const MAX_REVIEW_STATE_CHARS: usize = 32;

/// Caratteri al piu' della motivazione di una revisione.
pub const MAX_REVIEW_NOTE_CHARS: usize = 512;

/// Caratteri al piu' della frase che accompagna un esito.
pub const MAX_REVIEW_DETAIL_CHARS: usize = 512;

/// Caratteri al piu' del nome di una fonte che viaggia.
pub const MAX_REVIEW_SOURCE_CHARS: usize = 128;

/// Un evento come viaggia.
///
/// I campi sono gli stessi dell'archivio, e restano **corti**: soggetto e
/// dettaglio hanno già un limite nel dominio, e qui si verifica di nuovo —
/// ciò che arriva dalla rete non è ciò che è stato scritto da noi.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireEvent {
    /// Il numero progressivo.
    pub sequence: u64,
    /// Il tipo, come lo scrive il dominio.
    pub kind: String,
    /// Di che cosa parla.
    pub subject: String,
    /// Il dettaglio, se c'è.
    pub detail: Option<String>,
    /// Quando l'Hub lo ha scritto, in millisecondi.
    pub recorded_at: i64,
}

/// Che cosa la postazione chiede.
///
/// **I messaggi della revisione esistono dalla versione 2** (ADR-0094,
/// decisione 6): chi ha negoziato la versione 1 non li manda, e un Hub
/// versione 1 non li riceverebbe comunque in modo interpretabile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientRequest {
    /// «Dammi ciò che viene dopo questo numero, di questa storia.»
    Resume {
        /// Il nome della storia che la postazione crede di seguire.
        stream: String,
        /// L'ultimo numero applicato.
        after: u64,
        /// Quanti eventi al più.
        limit: usize,
    },
    /// «Che cosa c'è da rivedere, dopo questo elemento?» (versione 2)
    ///
    /// La risposta porta **metadati**, mai il testo dei contenuti.
    ReviewQueue {
        /// L'identificativo del contenuto dopo il quale continuare. Zero per
        /// cominciare.
        after_content_id: i64,
        /// Quanti elementi al più.
        limit: usize,
    },
    /// «Fammi leggere **questo** contenuto.» (versione 2)
    ///
    /// Uno per volta, e l'Hub registra chi lo ha chiesto.
    ReviewContent {
        /// Quale contenuto.
        content_id: i64,
    },
    /// «Qual è la coda dell'ufficio?» (capacità `coda-di-lavoro`)
    ///
    /// La risposta è una **fotografia**: le prime righe nell'ordine deciso
    /// dall'Hub, con i conteggi di tutto e l'istante in cui è stata composta
    /// (ADR-0095).
    WorkQueue {
        /// Quante righe al più.
        limit: usize,
    },
    /// «Chi c'è adesso?» (capacità `presenza`)
    ///
    /// Non esiste un messaggio «sono qui»: la presenza è **un'osservazione
    /// dell'Hub**, che sa chi è connesso perché lo ha autenticato lui
    /// (ADR-0096, decisione 3). Questa richiesta chiede soltanto di vederla.
    Presence {
        /// Quante righe al più.
        limit: usize,
    },
    /// «Sono io, ed ecco come lo dimostro.» (capacità `persona`)
    ///
    /// L'identità la tiene l'Hub: questo messaggio **non dichiara** chi si è,
    /// presenta una frase e chiede di essere verificato (ADR-0097,
    /// decisione 1).
    SignIn {
        /// Chi dice di essere.
        person: String,
        /// Come lo dimostra. **Redatta in ogni resa.**
        passphrase: WireSecret,
    },
    /// «Chi sono i colleghi?» (capacità `persona`)
    ///
    /// **L'elenco è di chi è già dentro**: a chi non si è dimostrato l'Hub
    /// non dice quali identificativi esistono (ADR-0097).
    People,
    /// «Questo lavoro è di questa persona.» (capacità `assegnazione`)
    ///
    /// Comando idempotente con concorrenza ottimistica (ADR-0098,
    /// decisione 3). `to` vale `None` per la revoca.
    Assign {
        /// L'identificativo del comando: ripeterlo non raddoppia.
        command_id: String,
        /// Quale contenuto.
        content_id: i64,
        /// Quanti cambi ci si aspetta che abbia avuto.
        expected_version: u64,
        /// A chi, o a nessuno.
        to: Option<String>,
    },
    /// «Che cosa ha scritto l'ufficio su questo?» (capacità
    /// `blocco-condiviso`)
    SharedNotes {
        /// Su che genere di cosa.
        kind: String,
        /// Su quale.
        target_id: i64,
        /// Quante righe al più.
        limit: usize,
    },
    /// «Annoto questo.» (capacità `blocco-condiviso`)
    WriteSharedNote {
        /// Su che genere di cosa.
        kind: String,
        /// Su quale.
        target_id: i64,
        /// Le parole.
        body: String,
    },
    /// «Ritiro ciò che avevo annotato.» (capacità `blocco-condiviso`)
    ///
    /// **Non cancella**: la nota resta, e dice chi l'ha ritirata.
    WithdrawSharedNote {
        /// Quale nota.
        note_id: i64,
    },
    /// «Quali raccoglitori tiene l'ufficio?» (capacità
    /// `raccoglitore-condiviso`)
    SharedWorkspaces {
        /// Quante righe al più.
        limit: usize,
    },
    /// «Che cosa ha raccolto questo?» (capacità `raccoglitore-condiviso`)
    SharedWorkspaceItems {
        /// Quale raccoglitore.
        workspace_id: i64,
        /// Quante righe al più.
        limit: usize,
    },
    /// «Apro un raccoglitore.» (capacità `raccoglitore-condiviso`)
    OpenSharedWorkspace {
        /// Come lo chiama l'ufficio.
        name: String,
        /// A che cosa serve, quando qualcuno lo scrive.
        description: Option<String>,
    },
    /// «Chiudo questo raccoglitore.» (capacità `raccoglitore-condiviso`)
    ///
    /// **Non cancella niente**: smette di accettare elementi.
    CloseSharedWorkspace {
        /// Quale raccoglitore.
        workspace_id: i64,
    },
    /// «Metto questo nel raccoglitore.» (capacità `raccoglitore-condiviso`)
    CollectInWorkspace {
        /// Quale raccoglitore.
        workspace_id: i64,
        /// Che genere di cosa.
        kind: String,
        /// Quale.
        target_id: i64,
    },
    /// «Tolgo questo dal raccoglitore.» (capacità `raccoglitore-condiviso`)
    DropFromWorkspace {
        /// Quale raccoglitore.
        workspace_id: i64,
        /// Che genere di cosa.
        kind: String,
        /// Quale.
        target_id: i64,
    },
    /// «Quali relazioni ha l'ufficio?» (capacità `relazione-condivisa`)
    SharedReports {
        /// Quante righe al più.
        limit: usize,
    },
    /// «Congelate una fotografia di questa sessione.» (capacità
    /// `relazione-condivisa`)
    ///
    /// **Non chiede un documento**: chiede che i fatti di adesso vengano
    /// fissati. Il documento nasce dove stanno i fatti (ADR-0100,
    /// decisione 1).
    FreezeSharedReport {
        /// L'identificativo del comando: ripeterlo non apre un secondo
        /// pacchetto.
        command_id: String,
        /// Quale sessione.
        session_id: i64,
        /// Che cosa rappresentare. **Vuota è uno stato legittimo**: è la
        /// relazione a esito negativo.
        contents: Vec<i64>,
    },
    /// «Quali grappoli cyber ha l'ufficio in questa sessione?» (capacità
    /// `cyber-condiviso`)
    ///
    /// **Si guarda, non si rifà**: l'analisi gira dove stanno i contenuti
    /// (ADR-0102, decisione 1).
    SharedCyberEvents {
        /// Quale sessione. I grappoli si costruiscono **dentro** una
        /// sessione, e mescolarne due produrrebbe un gruppo che non
        /// appartiene a nessuna delle due (DEC-221).
        session_id: i64,
        /// Quante righe al più.
        limit: usize,
    },
    /// «Quali monitoraggi ha l'ufficio?» (capacità `sessioni-condivise`)
    ///
    /// Senza questo elenco una postazione non può chiedere né i grappoli di
    /// una sessione né che se ne congeli una fotografia: non saprebbe come
    /// nominarla.
    SharedSessions {
        /// Quante righe al più.
        limit: usize,
    },
    /// «Che cosa stava guardando l'ufficio in questo monitoraggio?»
    /// (capacità `copertura-condivisa`, HUB-COVERAGE-01, ADR-0199)
    SharedCoverage {
        /// Quale monitoraggio.
        session_id: i64,
    },
    /// «Metti in pausa, riprendi o arresta questo monitoraggio, perché…»
    /// (capacità `comando-a-distanza`, HUB-REMOTE-01, ADR-0200)
    ///
    /// Lo manda soltanto una persona entrata con la propria frase; l'Hub
    /// risponde con un esito, anche quando rifiuta.
    RemoteCommand {
        /// L'identificativo del comando: ripeterlo non raddoppia.
        command_id: String,
        /// Quale monitoraggio.
        session_id: i64,
        /// `pausa`, `ripresa` o `arresto`.
        action: String,
        /// Perché.
        reason: String,
    },
    /// «Ho deciso: questo contenuto è così.» (versione 2)
    ///
    /// Comando idempotente con concorrenza ottimistica (ADR-0089).
    SubmitReview {
        /// L'identificativo del comando: ripeterlo non raddoppia.
        command_id: String,
        /// Quale contenuto.
        content_id: i64,
        /// Quante revisioni la postazione aveva visto.
        expected_version: u64,
        /// Lo stato deciso, nella forma conservata dal dominio.
        state: String,
        /// La motivazione, quando serve.
        note: Option<String>,
    },
}

/// Che cosa l'Hub risponde.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum HubResponse {
    /// Una pagina, e fin dove l'Hub è arrivato.
    Page {
        /// Gli eventi, in ordine di numero.
        events: Vec<WireEvent>,
        /// L'ultimo numero emesso dall'Hub.
        latest: u64,
    },
    /// La storia dell'Hub è un'altra. **Non è «nulla di nuovo».**
    NotOurStream {
        /// Il nome vero della storia dell'Hub.
        stream: String,
        /// L'ultimo numero di quella storia.
        latest: u64,
    },
    /// Il numero dichiarato non è mai stato emesso.
    AheadOfHub {
        /// L'ultimo numero emesso davvero.
        latest: u64,
    },
    /// La pagina della coda di revisione: **metadati, mai testo** (versione 2).
    ReviewQueuePage {
        /// Gli elementi, in ordine di identificativo.
        items: Vec<WireReviewItem>,
    },
    /// Il contenuto chiesto per la revisione (versione 2).
    ReviewContentPage {
        /// Il contenuto, se esiste ed è stato segnalato.
        content: Option<WireReviewContent>,
    },
    /// La coda dell'ufficio, come l'Hub l'ha composta.
    WorkQueuePage {
        /// Le righe, nell'ordine in cui vanno guardate.
        items: Vec<WireWorkItem>,
        /// Quando l'Hub l'ha composta, in millisecondi.
        composed_at: i64,
        /// Quante righe non sono mai state esaminate, in tutta la coda.
        untouched: usize,
        /// Quante sono già in esame, in tutta la coda.
        in_review: usize,
        /// Quante righe ha la coda in tutto.
        total: usize,
    },
    /// Chi è connesso all'Hub adesso, come l'Hub lo vede.
    PresencePage {
        /// Le righe, dalla più recentemente vista alla più vecchia.
        stations: Vec<WirePresentStation>,
        /// Quando l'Hub l'ha composta, in millisecondi.
        composed_at: i64,
        /// Quante postazioni sono presenti in tutto.
        total: usize,
    },
    /// Che cosa l'ufficio ha scritto su qualcosa.
    SharedNotesPage {
        /// Le note, dalla più recente. **Comprese quelle ritirate**: chi le
        /// aveva lette deve poter capire che cosa è successo.
        notes: Vec<WireSharedNote>,
    },
    /// I raccoglitori dell'ufficio.
    SharedWorkspacesPage {
        /// I raccoglitori, dal più recente.
        workspaces: Vec<WireSharedWorkspace>,
    },
    /// Che cosa un raccoglitore ha raccolto.
    SharedWorkspaceItemsPage {
        /// I riferimenti, **mai i testi**.
        items: Vec<WireWorkspaceItem>,
    },
    /// Le relazioni dell'ufficio.
    SharedReportsPage {
        /// Le relazioni, dalla più recente.
        reports: Vec<WireSharedReport>,
    },
    /// I grappoli cyber dell'ufficio.
    SharedCyberPage {
        /// I grappoli, nell'ordine in cui l'Hub li ha composti.
        events: Vec<WireCyberEvent>,
    },
    /// I monitoraggi dell'ufficio.
    SharedSessionsPage {
        /// I monitoraggi, dal più recente.
        sessions: Vec<WireSharedSession>,
    },
    /// La copertura di un monitoraggio dell'ufficio, **intera**.
    SharedCoveragePage {
        /// Quale monitoraggio.
        session_id: i64,
        /// L'istante in cui l'Hub l'ha calcolata, in millisecondi.
        taken_at: i64,
        /// Il programma e il collegamento, sulla finestra del monitoraggio.
        overall: Vec<WireCoverageStretch>,
        /// Ciascuna fonte del monitoraggio.
        sources: Vec<WireSourceCoverage>,
    },
    /// I colleghi dell'ufficio.
    PeoplePage {
        /// Le persone, per identificativo.
        people: Vec<WirePerson>,
    },
    /// L'esito di un tentativo di entrare come persona.
    ///
    /// **Non dice mai perché** un rifiuto è un rifiuto oltre ciò che la frase
    /// per l'operatore dichiara: distinguere «non esiste» da «frase sbagliata»
    /// direbbe a chi prova quali identificativi esistono (ADR-0097,
    /// decisione 5).
    SignInOutcome {
        /// Che cosa è successo: `entrata`, `non_riconosciuta`, `sospesa`.
        verdict: String,
        /// Il ruolo con cui è entrata, quando è entrata.
        role: Option<String>,
        /// La frase per l'operatore. Mai la frase di accesso.
        detail: String,
    },
    /// L'esito di una revisione inviata (versione 2).
    ReviewOutcome {
        /// Che cosa è successo: `applicata`, `ripetuta`, `conflitto`,
        /// `rifiutata`.
        verdict: String,
        /// La frase per l'operatore. Mai contenuto monitorato.
        detail: String,
        /// La versione che il contenuto ha adesso.
        current_version: u64,
    },
}

/// Una riga della coda dell'ufficio, come viaggia.
///
/// Porta i fatti e il **perché sta qui** — gli stessi fatti su cui l'ordine
/// lavora — e **mai il testo** del contenuto (ADR-0095, decisione 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireWorkItem {
    /// Quale contenuto.
    pub content_id: i64,
    /// Il nome della fonte, come l'ufficio l'ha chiamata.
    pub source_name: String,
    /// Il livello attribuito dal motore.
    pub level: u8,
    /// Quando l'avviso è scattato, in millisecondi.
    pub raised_at: i64,
    /// Lo stato della revisione, se qualcuno l'ha già toccato.
    pub state: Option<String>,
    /// Perché sta dov'è: i fatti, nella precedenza in cui contano.
    pub why_here: String,
    /// A chi è assegnato, quando lo è (TEAM-ASSIGN-01, ADR-0098,
    /// decisione 6).
    ///
    /// **Si omette quando è vuoto**, e si accetta assente: un Hub della
    /// generazione precedente non lo manda, e un client della generazione
    /// precedente non lo vede. È per questo che l'assegnazione è una capacità
    /// e non una versione nuova del protocollo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_to: Option<String>,
    /// Quanti cambi di assegnazione ha avuto, per chi vuole scriverne uno.
    ///
    /// Chi assegna deve dichiarare la versione che si aspetta (ADR-0098,
    /// decisione 3), e senza questo numero dovrebbe indovinarla. Viaggia
    /// **solo verso chi ha negoziato la capacità**, e si omette quando è zero.
    #[serde(default, skip_serializing_if = "e_zero")]
    pub assignment_version: u64,
}

/// Se un contatore è a zero, e quindi non ha niente da dire.
fn e_zero(valore: &u64) -> bool {
    *valore == 0
}

/// Se un istante è a zero, e quindi non è un istante.
fn istante_assente(valore: &i64) -> bool {
    *valore == 0
}

/// Un monitoraggio dell'ufficio, come viaggia.
///
/// **Nessun contenuto**: come si chiama, quando è cominciato, quando è
/// finito, e quanti contenuti ha raccolto.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireSharedSession {
    /// Quale monitoraggio.
    pub session_id: i64,
    /// Come lo chiama l'ufficio.
    pub label: String,
    /// In quale stato è.
    pub state: String,
    /// Quando è cominciato, in millisecondi.
    #[serde(default, skip_serializing_if = "istante_assente")]
    pub started_at: i64,
    /// Quando è finito, in millisecondi.
    #[serde(default, skip_serializing_if = "istante_assente")]
    pub ended_at: i64,
}

/// Un tratto di copertura, come viaggia (HUB-COVERAGE-01, ADR-0199).
///
/// Lo stato viaggia con il suo **nome stabile**, mai con la frase dello
/// schermo: la postazione lo rilegge con i tipi del dominio, e un nome che non
/// conosce rende la risposta inutilizzabile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireCoverageStretch {
    /// Da quando, compreso, in millisecondi.
    pub from: i64,
    /// Fino a quando, escluso, in millisecondi.
    pub to: i64,
    /// Il nome stabile dello stato, con la sua ragione.
    pub state: String,
}

/// La copertura di una fonte del monitoraggio, come viaggia.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireSourceCoverage {
    /// Il nome della fonte, come l'ufficio la conosce.
    pub name: String,
    /// I tratti, in ordine.
    pub stretches: Vec<WireCoverageStretch>,
}

/// Un indicatore, come viaggia.
///
/// È **vocabolario** — una CVE, un dominio, un indirizzo — e non contenuto
/// monitorato (DEC-292).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireIndicator {
    /// Di che genere è.
    pub kind: String,
    /// Il valore normalizzato.
    pub value: String,
}

/// Un grappolo cyber dell'ufficio, come viaggia.
///
/// **Gli osservabili e i fatti, mai il testo dei messaggi** (ADR-0102,
/// decisione 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireCyberEvent {
    /// Il posto che occupa nell'elenco della sua sessione.
    pub position: usize,
    /// In quale sessione si è formato.
    pub session_id: i64,
    /// **Perché** questi contenuti stanno insieme.
    pub reason: String,
    /// Quanti contenuti.
    pub contents: usize,
    /// Quante fonti **distinte**.
    pub distinct_sources: usize,
    /// Quanti sembrano ripubblicazioni.
    pub apparent_reposts: usize,
    /// I segnali di rilevanza per l'Italia, già in parole.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub italy: String,
    /// I settori in cui il fatto ricadrebbe, già in parole.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sectors: String,
    /// Gli indicatori nominati.
    pub indicators: Vec<WireIndicator>,
    /// Quanti contenuti hanno una decisione conclusa.
    pub decided: usize,
    /// Quanti sono in esame.
    pub in_progress: usize,
    /// Quanti non sono mai stati guardati.
    pub untouched: usize,
    /// Il primo istante di pubblicazione, in millisecondi.
    #[serde(default, skip_serializing_if = "istante_assente")]
    pub first_seen: i64,
    /// L'ultimo istante di pubblicazione, in millisecondi.
    #[serde(default, skip_serializing_if = "istante_assente")]
    pub last_seen: i64,
}

/// Un documento prodotto, come viaggia.
///
/// **Nome e impronta, mai byte** (ADR-0100, decisione 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireArtifact {
    /// Come si chiama il file.
    pub file_name: String,
    /// Quanto è grande, in byte.
    pub size_bytes: u64,
    /// L'impronta SHA-256.
    pub sha256: String,
}

/// Una relazione dell'ufficio, come viaggia.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireSharedReport {
    /// L'identificativo citabile.
    pub report_id: String,
    /// Quale sessione documenta.
    pub session_id: i64,
    /// Chi l'ha chiesta.
    pub requested_by: String,
    /// In quale stato è.
    pub status: String,
    /// Quando è stata chiesta, in millisecondi.
    pub requested_at: i64,
    /// Quando è stata completata, in millisecondi.
    #[serde(default, skip_serializing_if = "istante_assente")]
    pub completed_at: i64,
    /// Quanti contenuti la sessione aveva al momento della fotografia.
    pub monitored: usize,
    /// Quanti se ne rappresentano.
    pub selected: usize,
    /// I documenti prodotti: **nomi e impronte**.
    pub artifacts: Vec<WireArtifact>,
}

/// Una nota dell'ufficio, come viaggia.
///
/// Porta **le parole di chi annota**, mai quelle del messaggio annotato: il
/// contenuto si chiede uno per volta (ADR-0094).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireSharedNote {
    /// Quale nota.
    pub id: i64,
    /// Su che genere di cosa.
    pub kind: String,
    /// Su quale.
    pub target_id: i64,
    /// Le parole.
    pub body: String,
    /// Chi l'ha scritta.
    pub author: String,
    /// Quando, in millisecondi.
    pub written_at: i64,
    /// Chi l'ha ritirata, se è stata ritirata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn_by: Option<String>,
    /// Quando è stata ritirata, in millisecondi.
    #[serde(default, skip_serializing_if = "istante_assente")]
    pub withdrawn_at: i64,
}

/// Un raccoglitore dell'ufficio, come viaggia.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireSharedWorkspace {
    /// Quale raccoglitore.
    pub id: i64,
    /// Come lo chiama l'ufficio.
    pub name: String,
    /// A che cosa serve.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// `aperto` oppure `chiuso`.
    pub state: String,
    /// Chi l'ha aperto.
    pub opened_by: String,
    /// Quando, in millisecondi.
    pub opened_at: i64,
    /// Quanti elementi ha raccolto.
    pub items: usize,
}

/// Un riferimento raccolto, come viaggia.
///
/// **Che cosa e quale**, mai il testo (ADR-0099, decisione 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireWorkspaceItem {
    /// Che genere di cosa.
    pub kind: String,
    /// Quale.
    pub target_id: i64,
    /// Chi l'ha raccolto.
    pub added_by: String,
    /// Quando, in millisecondi.
    pub added_at: i64,
}

/// Una persona dell'ufficio, come viaggia.
///
/// **Nessun verificatore**: ciò che l'Hub conserva al posto di una frase non
/// esce da lì, perché è da quello che si provano le frasi offline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WirePerson {
    /// Come si chiama negli atti.
    pub person: String,
    /// Come la chiama l'ufficio.
    pub label: String,
    /// Che cosa le è consentito.
    pub role: String,
    /// Se può entrare.
    pub state: String,
}

/// Un segreto che attraversa il filo.
///
/// Esiste per una ragione sola: **una richiesta si stampa con la stessa
/// facilità con cui si legge**, e una frase dentro una struttura che deriva
/// `Debug` finirebbe in ogni riga di diagnostica che la mostra (ADR-0097,
/// decisione 4).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WireSecret(String);

impl WireSecret {
    /// Mette un segreto sul filo.
    #[must_use]
    pub fn new(secret: &str) -> Self {
        Self(String::from(secret))
    }

    /// Espone il segreto a chi deve verificarlo.
    ///
    /// Il nome è scomodo apposta.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Quanti caratteri ha, per i limiti.
    #[must_use]
    pub fn chars(&self) -> usize {
        self.0.chars().count()
    }
}

impl core::fmt::Debug for WireSecret {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("«redatto»")
    }
}

/// Una postazione presente, come viaggia.
///
/// Tre cose, e nessuna in più: quale postazione, da quando, e quando l'Hub
/// l'ha vista l'ultima volta. **Non** la schermata aperta, **non** il
/// contenuto in lettura, **non** l'indirizzo di rete (ADR-0096, decisione 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WirePresentStation {
    /// Quale postazione.
    pub device: String,
    /// Da quando è connessa, in millisecondi.
    pub connected_since: i64,
    /// Quando l'Hub l'ha vista l'ultima volta, in millisecondi.
    pub last_seen: i64,
}

/// Un elemento della coda di revisione, come viaggia.
///
/// **Nessun testo**: identificativo, fonte, livello, istante, stato e versione
/// (ADR-0094, decisione 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireReviewItem {
    /// Quale contenuto.
    pub content_id: i64,
    /// Da quale fonte, nella forma tecnica.
    pub source: String,
    /// Il livello attribuito dal motore.
    pub level: u8,
    /// Quando l'avviso è scattato, in millisecondi.
    pub raised_at: i64,
    /// Lo stato della revisione, se qualcuno ha già deciso.
    pub state: Option<String>,
    /// Quante revisioni sono già registrate.
    pub version: u64,
}

/// Il contenuto consegnato per una revisione, come viaggia.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireReviewContent {
    /// Quale contenuto.
    pub content_id: i64,
    /// Da quale fonte, nella forma tecnica.
    pub source: String,
    /// Il nome leggibile della fonte.
    pub source_name: String,
    /// Quando il messaggio è stato pubblicato, in millisecondi.
    pub published_at: i64,
    /// Il testo acquisito.
    pub body: String,
    /// Il livello attribuito dal motore.
    pub level: u8,
    /// Quante revisioni sono già registrate.
    pub version: u64,
}

/// Perché uno scambio di recupero non è riuscito.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventsError {
    /// Il frame non si è potuto leggere o scrivere.
    Frame(FrameError),
    /// Ciò che è arrivato non è un messaggio di questo scambio, o non rispetta
    /// i limiti.
    Malformed,
}

/// Quanto può durare la scrittura di un frame (FINAL-REVIEW-01, FR-022).
///
/// La lettura imposta sul socket il tempo che le resta, e il socket lo tiene
/// anche per la scrittura: una risposta mandata subito dopo una richiesta
/// arrivata a fine attesa partiva con pochi millisecondi, e si interrompeva a
/// metà. Ogni invio ricomincia da questo termine.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

fn prepara_la_scrittura<S: TimedStream + ?Sized>(stream: &mut S) -> Result<(), EventsError> {
    stream
        .set_io_timeout(WRITE_TIMEOUT)
        .map_err(|errore| EventsError::from(FrameError::Io(errore.kind())))
}

impl From<FrameError> for EventsError {
    fn from(errore: FrameError) -> Self {
        Self::Frame(errore)
    }
}

/// Manda una richiesta.
///
/// # Errori
///
/// [`EventsError::Malformed`] se la richiesta non rispetta i limiti; gli errori
/// del frame.
pub fn send_request<S: TimedStream + ?Sized>(
    stream: &mut S,
    request: &ClientRequest,
) -> Result<(), EventsError> {
    if !request_is_valid(request) {
        return Err(EventsError::Malformed);
    }
    let serializzato = serde_json::to_vec(request).map_err(|_| EventsError::Malformed)?;
    prepara_la_scrittura(stream)?;
    write_frame(stream, &serializzato, EVENTS_MAX_FRAME_BYTES)?;
    Ok(())
}

/// Legge una richiesta.
///
/// # Errori
///
/// [`EventsError::Malformed`] se non è una richiesta ben formata e dentro i
/// limiti; gli errori del frame.
pub fn read_request<S: TimedStream + ?Sized>(
    stream: &mut S,
    timeout: Duration,
) -> Result<ClientRequest, EventsError> {
    let ricevuto = read_frame(stream, EVENTS_MAX_FRAME_BYTES, Instant::now() + timeout)?;
    let richiesta: ClientRequest =
        serde_json::from_slice(&ricevuto).map_err(|_| EventsError::Malformed)?;
    if !request_is_valid(&richiesta) {
        return Err(EventsError::Malformed);
    }
    Ok(richiesta)
}

/// Manda una risposta.
///
/// # Errori
///
/// [`EventsError::Malformed`] se la risposta non rispetta i limiti; gli errori
/// del frame.
pub fn send_response<S: TimedStream + ?Sized>(
    stream: &mut S,
    response: &HubResponse,
) -> Result<(), EventsError> {
    if !response_is_valid(response) {
        return Err(EventsError::Malformed);
    }
    let serializzato = serde_json::to_vec(response).map_err(|_| EventsError::Malformed)?;
    prepara_la_scrittura(stream)?;
    write_frame(stream, &serializzato, EVENTS_MAX_FRAME_BYTES)?;
    Ok(())
}

/// Legge una risposta.
///
/// # Errori
///
/// [`EventsError::Malformed`] se non è una risposta ben formata e dentro i
/// limiti; gli errori del frame.
pub fn read_response<S: TimedStream + ?Sized>(
    stream: &mut S,
    timeout: Duration,
) -> Result<HubResponse, EventsError> {
    let ricevuto = read_frame(stream, EVENTS_MAX_FRAME_BYTES, Instant::now() + timeout)?;
    let risposta: HubResponse =
        serde_json::from_slice(&ricevuto).map_err(|_| EventsError::Malformed)?;
    if !response_is_valid(&risposta) {
        return Err(EventsError::Malformed);
    }
    Ok(risposta)
}

/// Se una richiesta rispetta i limiti.
fn request_is_valid(request: &ClientRequest) -> bool {
    match request {
        ClientRequest::Resume {
            stream,
            after: _,
            limit,
        } => nome_di_flusso_valido(stream) && *limit > 0 && *limit <= MAX_PAGE_EVENTS,
        // UN CLIENT NON DECIDE QUANTO LAVORO FA L'HUB: il tetto della pagina
        // e' quello del dominio, e un numero negativo non e' un cursore.
        ClientRequest::ReviewQueue {
            after_content_id,
            limit,
        } => *after_content_id >= 0 && *limit > 0 && *limit <= MAX_REVIEW_QUEUE_PAGE,
        ClientRequest::ReviewContent { content_id } => *content_id > 0,
        ClientRequest::WorkQueue { limit } => *limit > 0 && *limit <= MAX_WORK_QUEUE_PAGE,
        ClientRequest::Presence { limit } => *limit > 0 && *limit <= MAX_PRESENCE_PAGE,
        ClientRequest::SignIn { person, passphrase } => {
            !person.is_empty()
                && person.chars().count() <= MAX_DEVICE_ID_CHARS
                && passphrase.chars() > 0
                && passphrase.chars() <= MAX_PASSPHRASE_CHARS
        }
        ClientRequest::People => true,
        ClientRequest::SharedSessions { limit } => *limit > 0 && *limit <= MAX_SHARED_SESSIONS_PAGE,
        ClientRequest::SharedCoverage { session_id } => *session_id > 0,
        ClientRequest::RemoteCommand {
            command_id,
            session_id,
            action,
            reason,
        } => {
            !command_id.is_empty()
                && command_id.chars().count() <= MAX_COMMAND_ID_CHARS
                && *session_id > 0
                && !action.is_empty()
                && action.chars().count() <= MAX_REMOTE_ACTION_CHARS
                && reason.chars().count() <= MAX_REMOTE_REASON_CHARS
        }
        ClientRequest::SharedCyberEvents { session_id, limit } => {
            *session_id > 0 && *limit > 0 && *limit <= MAX_SHARED_CYBER_PAGE
        }
        ClientRequest::SharedReports { limit } => *limit > 0 && *limit <= MAX_SHARED_REPORTS_PAGE,
        ClientRequest::FreezeSharedReport {
            command_id,
            session_id,
            contents,
        } => {
            !command_id.is_empty()
                && command_id.chars().count() <= MAX_COMMAND_ID_CHARS
                && *session_id > 0
                && contents.len() <= MAX_REPORT_SELECTION
                && contents.iter().all(|contenuto| *contenuto > 0)
        }
        ClientRequest::SharedNotes {
            kind,
            target_id,
            limit,
        } => genere_valido(kind) && *target_id > 0 && *limit > 0 && *limit <= MAX_SHARED_NOTES_PAGE,
        ClientRequest::WriteSharedNote {
            kind,
            target_id,
            body,
        } => {
            genere_valido(kind)
                && *target_id > 0
                && !body.trim().is_empty()
                && body.chars().count() <= MAX_NOTE_CHARS
        }
        ClientRequest::WithdrawSharedNote { note_id } => *note_id > 0,
        ClientRequest::SharedWorkspaces { limit } => {
            *limit > 0 && *limit <= MAX_SHARED_WORKSPACES_PAGE
        }
        ClientRequest::SharedWorkspaceItems {
            workspace_id,
            limit,
        } => *workspace_id > 0 && *limit > 0 && *limit <= MAX_WORKSPACE_ITEMS_PAGE,
        ClientRequest::OpenSharedWorkspace { name, description } => {
            !name.trim().is_empty()
                && name.chars().count() <= MAX_REVIEW_SOURCE_CHARS
                && description.as_ref().is_none_or(|testo| {
                    !testo.trim().is_empty() && testo.chars().count() <= MAX_NOTE_CHARS
                })
        }
        ClientRequest::CloseSharedWorkspace { workspace_id } => *workspace_id > 0,
        ClientRequest::CollectInWorkspace {
            workspace_id,
            kind,
            target_id,
        }
        | ClientRequest::DropFromWorkspace {
            workspace_id,
            kind,
            target_id,
        } => *workspace_id > 0 && genere_valido(kind) && *target_id > 0,
        ClientRequest::Assign {
            command_id,
            content_id,
            expected_version: _,
            to,
        } => {
            !command_id.is_empty()
                && command_id.chars().count() <= MAX_COMMAND_ID_CHARS
                && *content_id > 0
                && to.as_ref().is_none_or(|persona| {
                    !persona.is_empty() && persona.chars().count() <= MAX_DEVICE_ID_CHARS
                })
        }
        ClientRequest::SubmitReview {
            command_id,
            content_id,
            expected_version: _,
            state,
            note,
        } => {
            *content_id > 0
                && !command_id.is_empty()
                && command_id.chars().count() <= MAX_COMMAND_ID_CHARS
                && !state.is_empty()
                && state.chars().count() <= MAX_REVIEW_STATE_CHARS
                && note
                    .as_ref()
                    .is_none_or(|nota| nota.chars().count() <= MAX_REVIEW_NOTE_CHARS)
        }
    }
}

/// Se una risposta rispetta i limiti.
///
/// **Una pagina deve essere ordinata, senza ripetizioni e dopo il numero
/// zero.** Non è pignoleria: un client che applicasse una pagina disordinata
/// vedrebbe buchi dove non ce ne sono, e ne chiederebbe altre per sempre.
///
/// Pubblica perché l'Hub possa **dire** che una risposta non sta nei limiti
/// (HUB-COVERAGE-01), invece di chiudere la connessione senza una parola.
#[must_use]
pub fn response_is_valid(response: &HubResponse) -> bool {
    match response {
        HubResponse::Page { events, latest } => {
            if events.len() > MAX_PAGE_EVENTS {
                return false;
            }
            let mut precedente = 0_u64;
            for evento in events {
                if evento.sequence == 0
                    || evento.sequence <= precedente
                    || evento.sequence > *latest
                    || !evento_valido(evento)
                {
                    return false;
                }
                precedente = evento.sequence;
            }
            true
        }
        HubResponse::NotOurStream { stream, .. } => nome_di_flusso_valido(stream),
        HubResponse::AheadOfHub { .. } => true,
        HubResponse::ReviewQueuePage { items } => {
            items.len() <= MAX_REVIEW_QUEUE_PAGE && items.iter().all(elemento_valido)
        }
        HubResponse::ReviewContentPage { content } => content.as_ref().is_none_or(contenuto_valido),
        HubResponse::WorkQueuePage {
            items,
            composed_at,
            untouched,
            in_review,
            total,
        } => {
            *composed_at >= 0
                && items.len() <= MAX_WORK_QUEUE_PAGE
                && *untouched <= *total
                && *in_review <= *total
                && items.iter().all(riga_di_coda_valida)
        }
        HubResponse::SharedNotesPage { notes } => {
            notes.len() <= MAX_SHARED_NOTES_PAGE && notes.iter().all(nota_valida)
        }
        HubResponse::SharedWorkspacesPage { workspaces } => {
            workspaces.len() <= MAX_SHARED_WORKSPACES_PAGE
                && workspaces.iter().all(raccoglitore_valido)
        }
        HubResponse::SharedWorkspaceItemsPage { items } => {
            items.len() <= MAX_WORKSPACE_ITEMS_PAGE && items.iter().all(elemento_raccolto_valido)
        }
        HubResponse::SharedReportsPage { reports } => {
            reports.len() <= MAX_SHARED_REPORTS_PAGE && reports.iter().all(relazione_valida)
        }
        HubResponse::SharedCyberPage { events } => {
            events.len() <= MAX_SHARED_CYBER_PAGE && events.iter().all(grappolo_valido)
        }
        HubResponse::SharedSessionsPage { sessions } => {
            sessions.len() <= MAX_SHARED_SESSIONS_PAGE && sessions.iter().all(monitoraggio_valido)
        }
        HubResponse::SharedCoveragePage {
            session_id,
            taken_at,
            overall,
            sources,
        } => {
            *session_id > 0
                && *taken_at >= 0
                && tratti_validi(overall)
                && sources.len() <= MAX_COVERAGE_SOURCES
                && sources.iter().all(|fonte| {
                    !fonte.name.is_empty()
                        && fonte.name.chars().count() <= MAX_REVIEW_SOURCE_CHARS
                        && tratti_validi(&fonte.stretches)
                })
        }
        HubResponse::PeoplePage { people } => {
            people.len() <= MAX_PEOPLE_PAGE && people.iter().all(persona_valida)
        }
        HubResponse::SignInOutcome {
            verdict,
            role,
            detail,
        } => {
            !verdict.is_empty()
                && verdict.chars().count() <= MAX_REVIEW_STATE_CHARS
                && role.as_ref().is_none_or(|ruolo| {
                    !ruolo.is_empty() && ruolo.chars().count() <= MAX_REVIEW_STATE_CHARS
                })
                && detail.chars().count() <= MAX_REVIEW_DETAIL_CHARS
        }
        HubResponse::PresencePage {
            stations,
            composed_at,
            total,
        } => {
            *composed_at >= 0
                && stations.len() <= MAX_PRESENCE_PAGE
                && stations.len() <= *total
                && stations.iter().all(postazione_valida)
        }
        HubResponse::ReviewOutcome {
            verdict,
            detail,
            current_version: _,
        } => {
            !verdict.is_empty()
                && verdict.chars().count() <= MAX_REVIEW_STATE_CHARS
                && detail.chars().count() <= MAX_REVIEW_DETAIL_CHARS
        }
    }
}

/// I generi di riferimento che questo protocollo trasporta.
///
/// L'elenco è **qui** e non dedotto dal dominio: ciò che arriva dalla rete si
/// riconosce prima di attraversare i tipi, non dopo.
fn genere_valido(kind: &str) -> bool {
    matches!(
        kind,
        "fonte" | "contenuto" | "rapporto" | "segnalibro" | "workspace"
    )
}

/// I limiti di una nota condivisa che arriva dalla rete.
fn nota_valida(nota: &WireSharedNote) -> bool {
    nota.id > 0
        && genere_valido(&nota.kind)
        && nota.target_id > 0
        && !nota.body.trim().is_empty()
        && nota.body.chars().count() <= MAX_NOTE_CHARS
        && !nota.author.is_empty()
        && nota.author.chars().count() <= MAX_DEVICE_ID_CHARS
        && nota.written_at >= 0
        && nota.withdrawn_at >= 0
        && nota
            .withdrawn_by
            .as_ref()
            .is_none_or(|chi| !chi.is_empty() && chi.chars().count() <= MAX_DEVICE_ID_CHARS)
}

/// I limiti di un raccoglitore che arriva dalla rete.
fn raccoglitore_valido(raccoglitore: &WireSharedWorkspace) -> bool {
    raccoglitore.id > 0
        && !raccoglitore.name.trim().is_empty()
        && raccoglitore.name.chars().count() <= MAX_REVIEW_SOURCE_CHARS
        && raccoglitore
            .description
            .as_ref()
            .is_none_or(|testo| testo.chars().count() <= MAX_NOTE_CHARS)
        && matches!(raccoglitore.state.as_str(), "aperto" | "chiuso")
        && !raccoglitore.opened_by.is_empty()
        && raccoglitore.opened_by.chars().count() <= MAX_DEVICE_ID_CHARS
        && raccoglitore.opened_at >= 0
}

/// I limiti di un riferimento raccolto che arriva dalla rete.
fn elemento_raccolto_valido(elemento: &WireWorkspaceItem) -> bool {
    genere_valido(&elemento.kind)
        && elemento.target_id > 0
        && !elemento.added_by.is_empty()
        && elemento.added_by.chars().count() <= MAX_DEVICE_ID_CHARS
        && elemento.added_at >= 0
}

/// I limiti di una relazione che arriva dalla rete.
fn relazione_valida(relazione: &WireSharedReport) -> bool {
    !relazione.report_id.is_empty()
        && relazione.report_id.chars().count() <= MAX_REVIEW_STATE_CHARS
        && relazione.session_id > 0
        && !relazione.requested_by.is_empty()
        && relazione.requested_by.chars().count() <= MAX_DEVICE_ID_CHARS
        && !relazione.status.is_empty()
        && relazione.status.chars().count() <= MAX_REVIEW_STATE_CHARS
        && relazione.requested_at >= 0
        && relazione.completed_at >= 0
        && relazione.artifacts.len() <= MAX_REPORT_ARTIFACTS
        && relazione.artifacts.iter().all(documento_valido)
}

/// I limiti di un documento che arriva dalla rete.
///
/// L'impronta è **esadecimale di sessantaquattro cifre**, e si guarda: un
/// valore che non lo è non è un'impronta, e mostrarlo come tale farebbe
/// credere a chi verifica di avere qualcosa da confrontare.
fn documento_valido(documento: &WireArtifact) -> bool {
    !documento.file_name.is_empty()
        && documento.file_name.chars().count() <= MAX_FILE_NAME_CHARS
        && documento.sha256.len() == 64
        && documento
            .sha256
            .bytes()
            .all(|cifra| cifra.is_ascii_hexdigit())
}

/// I limiti di un monitoraggio che arriva dalla rete.
fn monitoraggio_valido(monitoraggio: &WireSharedSession) -> bool {
    monitoraggio.session_id > 0
        && !monitoraggio.label.is_empty()
        && monitoraggio.label.chars().count() <= MAX_REVIEW_SOURCE_CHARS
        && !monitoraggio.state.is_empty()
        && monitoraggio.state.chars().count() <= MAX_REVIEW_STATE_CHARS
        && monitoraggio.started_at >= 0
        && monitoraggio.ended_at >= 0
}

/// I limiti di una copertura che arriva dalla rete: tratti in ordine, uno dopo
/// l'altro senza buchi, ciascuno non vuoto e con un nome di stato corto.
fn tratti_validi(tratti: &[WireCoverageStretch]) -> bool {
    tratti.len() <= MAX_COVERAGE_STRETCHES
        && tratti.iter().all(|tratto| {
            tratto.from >= 0
                && tratto.to > tratto.from
                && !tratto.state.is_empty()
                && tratto.state.chars().count() <= MAX_COVERAGE_STATE_CHARS
        })
        && tratti
            .windows(2)
            .all(|coppia| coppia[0].to == coppia[1].from)
}

/// I limiti di un grappolo che arriva dalla rete.
fn grappolo_valido(grappolo: &WireCyberEvent) -> bool {
    !grappolo.reason.is_empty()
        && grappolo.reason.chars().count() <= MAX_CYBER_SENTENCE_CHARS
        && grappolo.session_id > 0
        && grappolo.italy.chars().count() <= MAX_CYBER_SENTENCE_CHARS
        && grappolo.sectors.chars().count() <= MAX_CYBER_SENTENCE_CHARS
        && grappolo.indicators.len() <= MAX_INDICATORS_PER_EVENT
        && grappolo.indicators.iter().all(indicatore_valido)
        && grappolo.first_seen >= 0
        && grappolo.last_seen >= 0
        && grappolo.distinct_sources <= grappolo.contents
        && grappolo.apparent_reposts <= grappolo.contents
}

/// I limiti di un indicatore che arriva dalla rete.
fn indicatore_valido(indicatore: &WireIndicator) -> bool {
    !indicatore.kind.is_empty()
        && indicatore.kind.chars().count() <= MAX_REVIEW_STATE_CHARS
        && !indicatore.value.is_empty()
        && indicatore.value.chars().count() <= MAX_REVIEW_SOURCE_CHARS
}

/// I limiti di una persona che arriva dalla rete.
fn persona_valida(persona: &WirePerson) -> bool {
    !persona.person.is_empty()
        && persona.person.chars().count() <= MAX_DEVICE_ID_CHARS
        && !persona.label.is_empty()
        && persona.label.chars().count() <= MAX_REVIEW_SOURCE_CHARS
        && !persona.role.is_empty()
        && persona.role.chars().count() <= MAX_REVIEW_STATE_CHARS
        && !persona.state.is_empty()
        && persona.state.chars().count() <= MAX_REVIEW_STATE_CHARS
}

/// I limiti di una postazione presente che arriva dalla rete.
fn postazione_valida(postazione: &WirePresentStation) -> bool {
    !postazione.device.is_empty()
        && postazione.device.chars().count() <= MAX_DEVICE_ID_CHARS
        && postazione.connected_since >= 0
        && postazione.last_seen >= 0
        && postazione.last_seen >= postazione.connected_since
}

/// I limiti di una riga della coda dell'ufficio che arriva dalla rete.
fn riga_di_coda_valida(riga: &WireWorkItem) -> bool {
    riga.content_id > 0
        && !riga.source_name.is_empty()
        && riga.source_name.chars().count() <= MAX_REVIEW_SOURCE_CHARS
        && riga.level <= 4
        && riga.raised_at >= 0
        && riga.state.as_ref().is_none_or(|stato| {
            !stato.is_empty() && stato.chars().count() <= MAX_REVIEW_STATE_CHARS
        })
        && !riga.why_here.is_empty()
        && riga.why_here.chars().count() <= MAX_REVIEW_DETAIL_CHARS
        && riga.assigned_to.as_ref().is_none_or(|persona| {
            !persona.is_empty() && persona.chars().count() <= MAX_DEVICE_ID_CHARS
        })
}

/// I limiti di un elemento della coda che arriva dalla rete.
fn elemento_valido(elemento: &WireReviewItem) -> bool {
    elemento.content_id > 0
        && !elemento.source.is_empty()
        && elemento.source.chars().count() <= MAX_REVIEW_SOURCE_CHARS
        && elemento.level <= 4
        && elemento.raised_at >= 0
        && elemento.state.as_ref().is_none_or(|stato| {
            !stato.is_empty() && stato.chars().count() <= MAX_REVIEW_STATE_CHARS
        })
}

/// I limiti di un contenuto consegnato per la revisione.
///
/// **Il tetto del corpo e' quello del dominio**: cio' che arriva dalla rete non
/// e' cio' che abbiamo scritto noi, e un testo senza limite farebbe allocare a
/// chi legge quanto l'altro capo dichiara.
fn contenuto_valido(contenuto: &WireReviewContent) -> bool {
    contenuto.content_id > 0
        && !contenuto.source.is_empty()
        && contenuto.source.chars().count() <= MAX_REVIEW_SOURCE_CHARS
        && !contenuto.source_name.is_empty()
        && contenuto.source_name.chars().count() <= MAX_REVIEW_SOURCE_CHARS
        && contenuto.published_at >= 0
        && contenuto.body.chars().count() <= MAX_REVIEW_BODY_CHARS
        && contenuto.level <= 4
}

/// I limiti di un evento che arriva dalla rete.
fn evento_valido(evento: &WireEvent) -> bool {
    !evento.kind.is_empty()
        && evento.kind.chars().count() <= 128
        && !evento.subject.is_empty()
        && evento.subject.chars().count() <= 128
        && evento
            .detail
            .as_ref()
            .is_none_or(|detail| detail.chars().count() <= 512)
}

/// Trentadue cifre esadecimali minuscole.
fn nome_di_flusso_valido(stream: &str) -> bool {
    stream.len() == 32
        && stream
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        ClientRequest, EventsError, HubResponse, MAX_COVERAGE_STRETCHES, MAX_PAGE_EVENTS,
        WireCoverageStretch, WireEvent, WireSourceCoverage, read_request, read_response,
        send_request, send_response,
    };
    use crate::protocol::frame::tests::Memoria;

    const FLUSSO: &str = "0123456789abcdef0123456789abcdef";

    fn evento(sequence: u64) -> WireEvent {
        WireEvent {
            sequence,
            kind: String::from("dispositivo_ammesso"),
            subject: String::from("ABCD-EFGH"),
            detail: None,
            recorded_at: 1_758_300_000_000,
        }
    }

    fn andata_e_ritorno_richiesta(request: &ClientRequest) -> Result<ClientRequest, EventsError> {
        let mut uscita = Memoria::con(Vec::new());
        send_request(&mut uscita, request)?;
        let mut entrata = Memoria::con(uscita.output);
        read_request(&mut entrata, Duration::from_secs(1))
    }

    fn andata_e_ritorno_risposta(response: &HubResponse) -> Result<HubResponse, EventsError> {
        let mut uscita = Memoria::con(Vec::new());
        send_response(&mut uscita, response)?;
        let mut entrata = Memoria::con(uscita.output);
        read_response(&mut entrata, Duration::from_secs(1))
    }

    #[test]
    fn a_request_and_a_page_survive_the_wire() {
        let richiesta = ClientRequest::Resume {
            stream: String::from(FLUSSO),
            after: 39,
            limit: 200,
        };
        assert_eq!(andata_e_ritorno_richiesta(&richiesta), Ok(richiesta));

        let pagina = HubResponse::Page {
            events: vec![evento(40), evento(41)],
            latest: 41,
        };
        assert_eq!(andata_e_ritorno_risposta(&pagina), Ok(pagina));
    }

    fn tratto(from: i64, to: i64, state: &str) -> WireCoverageStretch {
        WireCoverageStretch {
            from,
            to,
            state: String::from(state),
        }
    }

    #[test]
    fn un_comando_a_distanza_viaggia_e_uno_fuori_misura_no() {
        let comando = ClientRequest::RemoteCommand {
            command_id: String::from("cmd-7-pausa-1"),
            session_id: 7,
            action: String::from("pausa"),
            reason: String::from("la fonte pubblica dati di una persona per errore"),
        };
        assert_eq!(andata_e_ritorno_richiesta(&comando), Ok(comando));
        for storto in [
            ClientRequest::RemoteCommand {
                command_id: String::new(),
                session_id: 7,
                action: String::from("pausa"),
                reason: String::from("motivo"),
            },
            ClientRequest::RemoteCommand {
                command_id: String::from("cmd-7-pausa-1"),
                session_id: 0,
                action: String::from("pausa"),
                reason: String::from("motivo"),
            },
            ClientRequest::RemoteCommand {
                command_id: String::from("cmd-7-pausa-1"),
                session_id: 7,
                action: String::from("pausa"),
                reason: "x".repeat(super::MAX_REMOTE_REASON_CHARS + 1),
            },
        ] {
            assert_eq!(
                andata_e_ritorno_richiesta(&storto),
                Err(EventsError::Malformed)
            );
        }
    }

    #[test]
    fn una_copertura_viaggia_intera_e_una_con_buchi_non_parte() {
        let richiesta = ClientRequest::SharedCoverage { session_id: 7 };
        assert_eq!(andata_e_ritorno_richiesta(&richiesta), Ok(richiesta));
        assert_eq!(
            andata_e_ritorno_richiesta(&ClientRequest::SharedCoverage { session_id: 0 }),
            Err(EventsError::Malformed)
        );

        let copertura = |overall: Vec<WireCoverageStretch>| HubResponse::SharedCoveragePage {
            session_id: 7,
            taken_at: 3_000,
            overall,
            sources: vec![WireSourceCoverage {
                name: String::from("Canale sintetico"),
                stretches: vec![tratto(1_000, 3_000, "coperto")],
            }],
        };
        let intera = copertura(vec![
            tratto(1_000, 2_000, "coperto"),
            tratto(2_000, 3_000, "non_determinabile.programma_fermo"),
        ]);
        assert_eq!(andata_e_ritorno_risposta(&intera), Ok(intera));

        // Un buco fra due tratti, un tratto vuoto, troppi tratti: non partono.
        for storta in [
            vec![
                tratto(1_000, 2_000, "coperto"),
                tratto(2_500, 3_000, "coperto"),
            ],
            vec![tratto(1_000, 1_000, "coperto")],
            (0..=MAX_COVERAGE_STRETCHES)
                .map(|k| {
                    let k = i64::try_from(k).unwrap_or(0);
                    tratto(k, k + 1, "coperto")
                })
                .collect(),
        ] {
            assert_eq!(
                andata_e_ritorno_risposta(&copertura(storta)),
                Err(EventsError::Malformed)
            );
        }
    }

    #[test]
    fn the_two_answers_that_are_not_silence_survive_the_wire() {
        for risposta in [
            HubResponse::NotOurStream {
                stream: String::from(FLUSSO),
                latest: 3,
            },
            HubResponse::AheadOfHub { latest: 11 },
        ] {
            assert_eq!(andata_e_ritorno_risposta(&risposta), Ok(risposta));
        }
    }

    #[test]
    fn a_request_out_of_limits_never_leaves_and_is_never_accepted() {
        for limite in [0, MAX_PAGE_EVENTS + 1] {
            let richiesta = ClientRequest::Resume {
                stream: String::from(FLUSSO),
                after: 0,
                limit: limite,
            };
            assert_eq!(
                andata_e_ritorno_richiesta(&richiesta),
                Err(EventsError::Malformed)
            );
        }
        let storto = ClientRequest::Resume {
            stream: String::from("NON-UN-FLUSSO"),
            after: 0,
            limit: 10,
        };
        assert_eq!(
            andata_e_ritorno_richiesta(&storto),
            Err(EventsError::Malformed)
        );
    }

    #[test]
    fn a_page_that_is_not_ordered_is_refused_before_anyone_applies_it() {
        // Fuori ordine: chi la applicasse vedrebbe buchi che non esistono.
        let disordinata = HubResponse::Page {
            events: vec![evento(41), evento(40)],
            latest: 41,
        };
        assert_eq!(
            andata_e_ritorno_risposta(&disordinata),
            Err(EventsError::Malformed)
        );
        // Ripetuta.
        let ripetuta = HubResponse::Page {
            events: vec![evento(40), evento(40)],
            latest: 41,
        };
        assert_eq!(
            andata_e_ritorno_risposta(&ripetuta),
            Err(EventsError::Malformed)
        );
        // Oltre cio' che l'Hub dichiara di avere.
        let oltre = HubResponse::Page {
            events: vec![evento(42)],
            latest: 41,
        };
        assert_eq!(
            andata_e_ritorno_risposta(&oltre),
            Err(EventsError::Malformed)
        );
        // Numero zero.
        let zero = HubResponse::Page {
            events: vec![evento(0)],
            latest: 41,
        };
        assert_eq!(
            andata_e_ritorno_risposta(&zero),
            Err(EventsError::Malformed)
        );
    }

    #[test]
    fn a_page_longer_than_the_hub_can_produce_is_refused() {
        let troppi: Vec<WireEvent> = (1..=u64::try_from(MAX_PAGE_EVENTS).unwrap_or(0) + 1)
            .map(evento)
            .collect();
        let pagina = HubResponse::Page {
            events: troppi,
            latest: 1000,
        };
        assert_eq!(
            andata_e_ritorno_risposta(&pagina),
            Err(EventsError::Malformed)
        );
    }

    #[test]
    fn an_event_with_unbounded_fields_is_refused() {
        let mut lungo = evento(1);
        lungo.subject = "x".repeat(129);
        assert_eq!(
            andata_e_ritorno_risposta(&HubResponse::Page {
                events: vec![lungo],
                latest: 1
            }),
            Err(EventsError::Malformed)
        );

        let mut vuoto = evento(1);
        vuoto.kind = String::new();
        assert_eq!(
            andata_e_ritorno_risposta(&HubResponse::Page {
                events: vec![vuoto],
                latest: 1
            }),
            Err(EventsError::Malformed)
        );
    }

    #[test]
    fn what_is_not_a_message_of_this_exchange_is_refused() {
        let mut flusso = Memoria::con(Vec::new());
        let _ = crate::protocol::frame::write_frame(&mut flusso, b"{\"type\":\"hello\"}", 4096);
        let mut entrata = Memoria::con(flusso.output);
        assert_eq!(
            read_response(&mut entrata, Duration::from_secs(1)),
            Err(EventsError::Malformed)
        );
    }
}

#[cfg(test)]
mod write_timeout_tests {
    use std::io::{self, Read, Write};
    use std::time::Duration;

    use super::{ClientRequest, WRITE_TIMEOUT, send_request};
    use crate::protocol::frame::TimedStream;

    /// Un flusso che ricorda l'ultimo termine impostato prima di ogni scrittura.
    #[derive(Default)]
    struct Registra {
        termine: Option<Duration>,
        termini_alla_scrittura: Vec<Option<Duration>>,
    }

    impl Read for Registra {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for Registra {
        fn write(&mut self, dati: &[u8]) -> io::Result<usize> {
            self.termini_alla_scrittura.push(self.termine);
            Ok(dati.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl TimedStream for Registra {
        fn set_io_timeout(&mut self, timeout: Duration) -> io::Result<()> {
            self.termine = Some(timeout);
            Ok(())
        }
    }

    /// **Una scrittura non eredita il termine residuo dell'ultima lettura**
    /// (FINAL-REVIEW-01, FR-022).
    #[test]
    fn a_write_does_not_inherit_the_last_read_deadline() {
        let mut flusso = Registra {
            // Ciò che una lettura arrivata a fine attesa lascia sul socket.
            termine: Some(Duration::from_millis(1)),
            ..Registra::default()
        };
        let richiesta = ClientRequest::Presence { limit: 10 };
        let Ok(()) = send_request(&mut flusso, &richiesta) else {
            panic!("l'invio deve riuscire");
        };
        assert!(!flusso.termini_alla_scrittura.is_empty());
        assert!(
            flusso
                .termini_alla_scrittura
                .iter()
                .all(|termine| *termine == Some(WRITE_TIMEOUT)),
            "ogni scrittura parte con il termine pieno: {:?}",
            flusso.termini_alla_scrittura
        );
    }
}

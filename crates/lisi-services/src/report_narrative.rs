//! Che cosa dice la relazione, prima e indipendentemente da come e' scritta.
//!
//! Motivato in ADR-0031 Decisione 4. Questo modulo compone il documento come
//! **struttura di blocchi**; il modulo `report_docx` la traduce in OOXML.
//!
//! # Perche' due livelli e non uno
//!
//! I criteri 3, 4 e 5 di accettazione della Milestone 18 riguardano *che cosa
//! il documento dice*: che la relazione a esito negativo descriva l'attivita',
//! che non affermi l'assenza di elementi illeciti, che le risultanze contengano
//! solo gli elementi selezionati. Se la composizione vivesse dentro il
//! generatore DOCX, verificare quelle tre cose vorrebbe dire aprire un archivio
//! ZIP, estrarne l'XML e cercarci dentro delle frasi — una prova indiretta, che
//! fallisce per ragioni che non c'entrano con cio' che si voleva provare.
//!
//! Cosi' invece la parte delicata e' testo puro, e la prova e' diretta.
//!
//! # La regola che governa ogni campo
//!
//! **Dove un dato non c'e', il documento dice che non c'e'.** Non lo deduce,
//! non lo completa, non lo lascia vuoto lasciando credere a una dimenticanza.
//! E' [`NOT_AVAILABLE`], e compare tale e quale in tutti i punti.
//!
//! # La forma, riconciliata con un modello di riferimento (MP-18C-R)
//!
//! Fino al 2026-08-17 questo modulo componeva un **modulo**: quaranta coppie
//! etichetta/valore una sotto l'altra. Il confronto con un modello di
//! relazione, documentato nell'archivio del progetto, ha
//! mostrato che una relazione e' **prosa**: periodi continui, giustificati, con
//! l'attacco in grassetto dove serve a ritrovare una data o un'etichetta, e
//! nient'altro.
//!
//! Da qui [`Block::Lead`], che e' il blocco piu' importante del modulo:
//! `OGGETTO:` in grassetto seguito dal testo in tondo, `In data 01.07.2026` in
//! grassetto seguito dal racconto. Un paragrafo solo, due pesi.
//!
//! **Che cosa NON e' stato preso dal modello:** nessuna denominazione, nessun
//! nome, nessun luogo, nessuna data, nessuna formula di esito. In particolare
//! non la sua conclusione, che e' una valutazione, e che un programma non ha
//! titolo per scrivere da solo.

use lisi_core::model::report::{ReportId, ReportOutcome, ReportSnapshot};
use lisi_core::model::report_template::{ReportTemplateProfile, TemplateEmblem};
use lisi_core::model::{AnalysisLevel, ReviewState};
use lisi_core::text::Actor;
use lisi_core::{ContentId, Timestamp};

use crate::report_ledger::{
    CHE_COSA_E_UN_CONTORNO, CHE_COSA_E_UNA_REVISIONE, LedgerContext, LedgerRevision,
};

/// Come il documento dichiara un dato che non possiede.
pub const NOT_AVAILABLE: &str = "non disponibile";

/// Come il documento dichiara un contenuto che nessuno ha ancora esaminato.
///
/// Non è un dato mancante: è una revisione che non c'è stata. Allegato e
/// registro scrivevano «non disponibile», che in un documento si legge
/// «dato perso» (FULL-OPERATIONAL-VALIDATION-01, OBS-REP-2); la relazione
/// diceva già «non esaminato», e ora lo dicono tutti e tre.
pub const NOT_REVIEWED: &str = "non esaminato";

/// La legenda d'origine dei documenti (PR-03, ADR-0118): chi dice ciò che il
/// documento riporta.
///
/// # Perché si compone dal dominio
///
/// Perché le tre parole e le loro frasi sono quelle di
/// [`lisi_core::model::origin::Origin`], le stesse che l'operatore legge sullo
/// schermo. Una seconda copia qui divergerebbe alla prima riformulazione, e il
/// documento direbbe una cosa e la schermata un'altra.
#[must_use]
pub fn origin_legend() -> String {
    let mut testo =
        String::from("Origine dei dati. Ogni dato di questo documento ha una di tre origini.");
    for origine in lisi_core::model::origin::Origin::ALL {
        testo.push_str(&format!(" {}: {}", origine.label(), origine.as_sentence()));
    }
    testo
}

/// Oltre questo numero di fonti l'elenco in prosa diventa illeggibile e si passa
/// a una tabella.
///
/// Il facsimile non ha tabelle, ed e' la forma giusta finche' le fonti si
/// contano su una mano. Dodici fonti dentro un periodo sarebbero un elenco
/// travestito da frase.
const SOURCES_IN_PROSE: usize = 6;

/// Un blocco del documento.
///
/// E' volutamente povero: righe di intestazione, titoli, paragrafi, paragrafi
/// con l'attacco in grassetto, righe allineate a destra, tabelle e la
/// sottoscrizione. Un generatore che avesse bisogno di piu' di questo starebbe
/// impaginando, e l'impaginazione non e' una decisione di contenuto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    /// Titolo di sezione.
    Heading(String),
    /// Paragrafo di testo corrente, giustificato.
    Paragraph(String),
    /// Paragrafo con l'attacco in grassetto e il seguito in tondo.
    ///
    /// E' la forma che il facsimile usa per l'oggetto e per ogni voce
    /// cronologica: **un paragrafo solo**, non due, perche' due paragrafi
    /// spezzerebbero la giustificazione e farebbero rientrare il seguito.
    Lead { lead: String, body: String },
    /// Riga a se', in grassetto: il destinatario.
    Emphasis(String),
    /// Riga a se', allineata a destra: il destinatario per conoscenza.
    RightLine(String),
    /// Tabella con intestazione.
    Table {
        headers: Vec<String>,
        rows: Vec<Vec<String>>,
    },
    /// Luogo, data e sottoscrizione.
    Signature {
        /// Luogo e data, a sinistra.
        place_and_date: String,
        /// Qualifica di chi sottoscrive, a destra.
        role: Option<String>,
        /// Nome di chi sottoscrive, a destra sotto la qualifica.
        name: Option<String>,
    },
}

impl Block {
    /// Il testo che il blocco porta, per le verifiche.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::Heading(text)
            | Self::Paragraph(text)
            | Self::Emphasis(text)
            | Self::RightLine(text) => text.clone(),
            Self::Lead { lead, body } => format!("{lead} {body}"),
            Self::Table { headers, rows } => {
                let mut collected = headers.join(" | ");
                for row in rows {
                    collected.push('\n');
                    collected.push_str(&row.join(" | "));
                }
                collected
            }
            Self::Signature {
                place_and_date,
                role,
                name,
            } => {
                let mut collected = place_and_date.clone();
                for line in [role, name].into_iter().flatten() {
                    collected.push('\n');
                    collected.push_str(line);
                }
                collected
            }
        }
    }
}

/// Un contenuto che l'operatore ha scelto di rappresentare.
///
/// Porta i dati **realmente conservati**. I campi facoltativi sono facoltativi
/// perche' l'archivio li ha facoltativi: un autore che la fonte non espone non
/// si inventa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarrativeFinding {
    /// Record interno a cui l'elemento e' riconducibile.
    pub content_id: ContentId,
    /// Fonte da cui proviene, come l'operatore la conosce.
    pub source_label: String,
    /// Istante di pubblicazione dichiarato dalla fonte.
    pub published_at: Timestamp,
    /// Istante in cui NEXUM lo ha registrato nell'archivio (E2E01-03).
    pub acquired_at: Timestamp,
    /// Se è stato ritrovato nella cronologia invece che visto arrivare: allora
    /// l'acquisizione coincide con il recupero, e la relazione lo dice.
    pub recovered: bool,
    /// URL del messaggio, quando la piattaforma ne espone uno.
    pub url: Option<String>,
    /// Il collegamento chiesto a Telegram per questo documento, già in frase
    /// (ADR-0165); `None` se il documento non l'ha chiesto.
    pub asked_link: Option<String>,
    /// L'allegato, già in frase: ciò che il mittente dichiara e, se
    /// conservato, l'impronta (ATTACH-01, ADR-0177, decisione 9). Mai i byte.
    pub attachment: Option<String>,
    /// Testo conservato.
    pub body: String,
    /// Livello proposto dal motore.
    pub level: AnalysisLevel,
    /// Motivazione tecnica del motore, quando c'e'.
    pub engine_reason: Option<String>,
    /// Stato della revisione umana, quando ce n'e' stata una.
    pub review_state: Option<ReviewState>,
    /// Il motivo scritto con quella revisione, quando c'era (E2E01-12): la nota
    /// della revisione valida all'istante della fotografia.
    pub review_note: Option<String>,
    /// Che cosa e' stato osservato DOPO l'acquisizione, quando qualcosa e'
    /// stato osservato: «modificato», «eliminato su Telegram», e simili.
    ///
    /// `None` significa **nessuna revisione e nessuna cancellazione
    /// osservate**, non «nessuna avvenuta»: se il monitoraggio era fermo
    /// quando il messaggio e' stato modificato, quella modifica non e' nei
    /// dati (ADR-0051, rischio residuo 1). La relazione lo scrive per esteso.
    pub after_acquisition: Option<String>,
    /// Le versioni osservate dopo l'acquisizione, entro il tetto del documento.
    pub revisions: Vec<LedgerRevision>,
    /// Quante versioni restano fuori dal documento.
    pub revisions_beyond: usize,
    /// Le fotografie del contesto, entro il tetto del documento.
    pub contexts: Vec<LedgerContext>,
    /// Quante fotografie restano fuori dal documento.
    pub contexts_beyond: usize,
    /// Il modo di acquisizione dichiarato (PR-07): la frase, e per un
    /// contenuto recuperato ciò che il recupero non vede.
    pub acquisition_mode: String,
}

/// Una fonte monitorata nella sessione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarrativeSource {
    /// Nome con cui l'operatore la riconosce.
    pub label: String,
    /// Quanti contenuti ne sono stati acquisiti nella sessione.
    pub acquired: usize,
    /// La valutazione dell'ufficio sull'affidabilità della fonte, in vigore al
    /// momento della relazione, già in frase (ADR-0167); `None` se la fonte
    /// non è valutata.
    pub reliability: Option<String>,
}

/// I fatti della sessione che la relazione descrive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarrativeSession {
    /// Nome della sessione.
    pub label: String,
    /// Inizio dell'attivita'.
    pub started_at: Timestamp,
    /// Fine dell'attivita', se conclusa.
    pub ended_at: Option<Timestamp>,
    /// Il nome dell'account d'ufficio con cui il monitoraggio è stato condotto,
    /// com'era quando è nato (MULTI-ACCOUNT-02, ADR-0173). `None` per un
    /// monitoraggio nato prima che il programma lo registrasse: la relazione
    /// allora non nomina un account, e non ne indovina uno.
    pub account: Option<String>,
    /// Le osservazioni di foto, biografia e stato che l'operatore ha scelto
    /// per i documenti (PERSON-MEDIA-01 parte 3, ADR-0174). Vuoto per difetto:
    /// nessuna entra se nessuno la sceglie.
    pub profile_observations: Vec<NarrativeProfileObservation>,
}

/// Un'osservazione di profilo scelta per i documenti, già in parole.
///
/// **La foto non c'è**: soltanto la sua impronta, che basta a ritrovarla
/// nell'archivio (ADR-0174, parte 3). Un volto accanto a un nome in un atto è
/// il rischio più alto di tutta la milestone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarrativeProfileObservation {
    /// Quando è stata chiesta.
    pub requested_at: Timestamp,
    /// Chi l'ha chiesta.
    pub requested_by: String,
    /// Perché.
    pub reason: String,
    /// L'identificativo Telegram dell'autore.
    pub author_identifier: String,
    /// Lo stato in parole.
    pub status: String,
    /// La biografia, se visibile.
    pub bio: Option<String>,
    /// L'impronta SHA-256 della foto conservata, se c'è.
    pub photo_sha256: Option<String>,
}

impl NarrativeSession {
    /// Durata dell'attivita' in forma leggibile.
    ///
    /// Una sessione ancora aperta non ha una durata: lo dice, invece di
    /// calcolarne una fino a «adesso» che il giorno dopo sarebbe diversa.
    #[must_use]
    pub fn duration(&self) -> String {
        let Some(ended_at) = self.ended_at else {
            return String::from("attività non ancora conclusa");
        };

        let millis = ended_at.millis_since(self.started_at);
        if millis < 0 {
            return String::from(NOT_AVAILABLE);
        }

        let total_minutes = millis / 60_000;
        let hours = total_minutes / 60;
        let minutes = total_minutes % 60;
        format!("{hours} ore e {minutes} minuti")
    }
}

/// Tutto cio' che serve a comporre la relazione.
#[derive(Debug, Clone)]
pub struct NarrativeInput<'a> {
    /// Identificativo del pacchetto.
    pub report_id: &'a ReportId,
    /// Profilo documentale dell'ufficio.
    pub profile: &'a ReportTemplateProfile,
    /// Fotografia dei dati con cui il documento e' prodotto.
    pub snapshot: &'a ReportSnapshot,
    /// Operatore che ha richiesto la generazione.
    pub operator: &'a Actor,
    /// Istante di generazione.
    pub generated_at: Timestamp,
    /// Fatti della sessione documentata.
    pub session: &'a NarrativeSession,
    /// Fonti monitorate.
    pub sources: &'a [NarrativeSource],
    /// Elementi selezionati dall'operatore, gia' risolti dall'archivio.
    pub findings: &'a [NarrativeFinding],
    /// Anomalie tecniche significative della sessione.
    pub faults: &'a [String],
    /// Che cosa la postazione ha guardato, fonte per fonte (PR-05).
    pub coverage: &'a [crate::coverage::CoverageLine],
    /// Con quali termini l'analisi è stata condotta: versioni di dizionario,
    /// configurazione risolta con la sua impronta, parole aggiunte per la
    /// sessione (ADR-0156).
    ///
    /// Le versioni si scrivono per nome e numero, «Incendi v3»
    /// (OPERATOR-E2E-REMEDIATION-01, F-13), e vengono dalla stessa
    /// composizione del registro, dell'allegato e del rapporto: quattro
    /// documenti dello stesso archivio non devono dire quattro cose.
    pub configuration: &'a crate::analysis_configuration::AnalysisConfiguration,
}

/// La relazione composta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarrativeReport {
    /// Istante di generazione, che finisce anche nei metadati del documento.
    ///
    /// # Perche' un istante dentro una struttura che deve essere deterministica
    ///
    /// E' un **ingresso**, non una lettura dell'orologio: a parita' di istante
    /// il documento e' identico. ADR-0031 Decisione 3 elenca la data e l'ora di
    /// generazione fra gli unici elementi legittimamente variabili, e chiede che
    /// siano **registrati**. Senza di esso il documento dichiarerebbe nelle
    /// proprie proprieta' di essere stato creato il primo gennaio 1970, che e'
    /// deterministico e falso.
    pub generated_at: Timestamp,
    /// Carta intestata: stemma e righe di identificazione dell'ufficio.
    ///
    /// Finisce nell'**intestazione di pagina** vera del documento, non fra i
    /// blocchi del corpo: e' li' che un ufficio si aspetta di trovarla quando
    /// apre il file per adattarlo.
    pub letterhead: Letterhead,
    /// Righe del piede, accanto alla numerazione delle pagine.
    pub footer: Vec<LetterheadLine>,
    /// Corpo del documento.
    pub blocks: Vec<Block>,
}

/// Una riga della carta intestata o del piede.
///
/// # Perche' esiste un segnaposto invece del nulla
///
/// Un profilo non compilato produceva un documento **senza** intestazione. Per
/// un documento che nasce per essere completato in Word e' la scelta sbagliata:
/// chi lo apre non ha modo di sapere dove va scritta la denominazione
/// dell'ufficio, e finisce per aggiungerla dove capita.
///
/// Un segnaposto fra parentesi quadre dice **dove** scrivere e **che cosa**, e
/// resta visibile se qualcuno se ne dimentica — che e' la stessa disciplina di
/// [`NOT_AVAILABLE`] applicata a un campo da compilare invece che a un dato
/// mancante.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LetterheadLine {
    /// Valore configurato nel profilo documentale.
    Configured(String),
    /// Spazio lasciato a chi compila, con l'indicazione di che cosa scriverci.
    Placeholder(String),
}

impl LetterheadLine {
    /// Il testo che la riga porta nel documento.
    ///
    /// Il segnaposto si scrive fra parentesi quadre: e' la convenzione che
    /// chiunque riconosce come «da sostituire».
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::Configured(value) => value.clone(),
            Self::Placeholder(what) => format!("[{what}]"),
        }
    }

    /// Se la riga attende ancora di essere compilata.
    #[must_use]
    pub const fn is_placeholder(&self) -> bool {
        matches!(self, Self::Placeholder(_))
    }
}

/// La carta intestata del documento.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Letterhead {
    /// Stemma dell'ufficio, quando configurato.
    pub emblem: Option<TemplateEmblem>,
    /// Righe di identificazione, configurate o da compilare.
    pub lines: Vec<LetterheadLine>,
}

impl NarrativeReport {
    /// Tutto il testo del documento, per le verifiche.
    #[must_use]
    pub fn text(&self) -> String {
        let mut collected = String::new();
        for line in &self.letterhead.lines {
            collected.push_str(&line.text());
            collected.push('\n');
        }
        for block in &self.blocks {
            collected.push_str(&block.text());
            collected.push('\n');
        }
        for line in &self.footer {
            collected.push_str(&line.text());
            collected.push('\n');
        }
        collected
    }

    /// Le righe della carta intestata, come compaiono nel documento.
    #[must_use]
    pub fn institutional_lines(&self) -> Vec<String> {
        self.letterhead
            .lines
            .iter()
            .map(LetterheadLine::text)
            .collect()
    }
}

/// Compone la relazione a partire dai fatti.
///
/// # Perche' non prende decisioni
///
/// L'unico ramo che questa funzione sceglie e' quello fra relazione con
/// risultanze e relazione a esito negativo, e lo sceglie **contando la
/// selezione dell'operatore**, non giudicando i contenuti. Ogni frase che il
/// documento pronuncia sull'esito viene da
/// [`ReportOutcome::declaration`], che sta nel dominio sotto un test che ne
/// vieta le formulazioni pericolose.
#[must_use]
pub fn compose(input: &NarrativeInput<'_>) -> NarrativeReport {
    let outcome = input.snapshot.outcome();
    let mut blocks = Vec::new();

    destination(input, &mut blocks);
    subject(input, &mut blocks);
    preamble(input, &mut blocks);
    activity(input, &mut blocks);
    results(input, outcome, &mut blocks);
    profile_observations(input, &mut blocks);
    conclusions(input, outcome, &mut blocks);
    signature(input, &mut blocks);

    NarrativeReport {
        generated_at: input.generated_at,
        letterhead: letterhead(input),
        footer: footer(input),
        blocks,
    }
}

/// Le osservazioni di profilo scelte dall'operatore (PERSON-MEDIA-01 parte
/// 3, ADR-0174). Nessuna sezione se nessuna è scelta; la foto non entra,
/// soltanto la sua impronta.
fn profile_observations(input: &NarrativeInput<'_>, blocks: &mut Vec<Block>) {
    let scelte = &input.session.profile_observations;
    if scelte.is_empty() {
        return;
    }
    blocks.push(Block::Heading(String::from(
        "Osservazioni di profilo scelte dall'operatore",
    )));
    blocks.push(Block::Paragraph(String::from(
        "Le osservazioni che seguono riportano ciò che Telegram mostrava all'account \
         d'ufficio in un istante, su richiesta motivata. Non identificano una persona: una \
         foto può ritrarre un'altra persona o essere stata cambiata, e lo stato dipende dalle \
         impostazioni di riservatezza. Le foto non sono riprodotte nel documento; ciascuna è \
         conservata nell'archivio con l'impronta indicata.",
    )));
    for osservazione in scelte {
        let mut testo = format!(
            "In data {}, su richiesta di {} per la ragione «{}», per l'autore con \
             identificativo {} Telegram mostrava lo stato «{}»",
            osservazione.requested_at.to_readable_utc(),
            osservazione.requested_by,
            osservazione.reason,
            osservazione.author_identifier,
            osservazione.status,
        );
        match osservazione.bio.as_deref() {
            Some(bio) => testo.push_str(&format!(" e la biografia «{bio}»")),
            None => testo.push_str(" e nessuna biografia visibile"),
        }
        match osservazione.photo_sha256.as_deref() {
            Some(impronta) => testo.push_str(&format!(
                ". La foto del profilo è conservata con impronta SHA-256 {impronta}."
            )),
            None => testo.push_str(". Nessuna foto è conservata."),
        }
        blocks.push(Block::Paragraph(testo));
    }
}

/// La carta intestata: stemma e righe di identificazione dell'ufficio.
///
/// **Nessuna riga inventata, e nessuna riga taciuta.** Dove il profilo ha un
/// valore, compare quel valore; dove non ce l'ha, compare uno spazio da
/// compilare che dice che cosa scriverci. Nessun dato istituzionale sta nel
/// sorgente: i segnaposto sono nomi di campo, non denominazioni (ADR-0031
/// Decisione 15).
fn letterhead(input: &NarrativeInput<'_>) -> Letterhead {
    let profile = input.profile;
    Letterhead {
        emblem: profile.emblem.clone(),
        lines: vec![
            line(
                profile.organisation.as_ref().map(|f| f.as_str()),
                "Denominazione dell'amministrazione",
            ),
            line(
                profile.office.as_ref().map(|f| f.as_str()),
                "Ufficio o articolazione",
            ),
            line(
                profile.header_line.as_ref().map(|f| f.as_str()),
                "Sede, indirizzo e recapiti",
            ),
        ],
    }
}

/// Le righe del piede, accanto alla numerazione delle pagine.
fn footer(input: &NarrativeInput<'_>) -> Vec<LetterheadLine> {
    vec![line(
        input.profile.footer_line.as_ref().map(|f| f.as_str()),
        "Riferimenti dell'ufficio",
    )]
}

/// Una riga configurata, oppure lo spazio da compilare che la sostituisce.
fn line(configured: Option<&str>, what: &str) -> LetterheadLine {
    configured.map_or_else(
        || LetterheadLine::Placeholder(what.to_owned()),
        |value| LetterheadLine::Configured(value.to_owned()),
    )
}

/// Destinatario ed eventuale destinatario per conoscenza.
///
/// Il destinatario e' una **riga a se'**, non una coppia etichetta/valore: e'
/// cosi' che si legge in cima a una relazione di servizio. Quando manca, la
/// riga lo dichiara invece di sparire — un documento senza destinatario e' un
/// documento a cui manca qualcosa, e chi lo rilegge deve accorgersene.
fn destination(input: &NarrativeInput<'_>, blocks: &mut Vec<Block>) {
    match input.profile.recipient.as_ref() {
        Some(recipient) => blocks.push(Block::Emphasis(recipient.as_str().to_owned())),
        None => blocks.push(Block::Lead {
            lead: String::from("Destinatario:"),
            body: String::from(NOT_AVAILABLE),
        }),
    }

    if let Some(cc) = &input.profile.recipient_cc {
        blocks.push(Block::RightLine(cc.as_str().to_owned()));
    }
}

/// Oggetto della relazione.
///
/// `OGGETTO:` in grassetto e il seguito in tondo, **nello stesso paragrafo**:
/// e' la forma del facsimile, ed e' quella che permette all'occhio di trovare
/// l'oggetto senza cercarlo.
fn subject(input: &NarrativeInput<'_>, blocks: &mut Vec<Block>) {
    let base = input.profile.subject_base.as_ref().map_or_else(
        || String::from("Relazione di servizio"),
        |field| field.as_str().to_owned(),
    );
    blocks.push(Block::Lead {
        lead: String::from("OGGETTO:"),
        body: format!(
            "{base} — attività di monitoraggio «{}».",
            input.session.label
        ),
    });
}

/// La premessa: chi riferisce, e a quale documento appartiene questa pagina.
///
/// # Perche' i dati identificativi stanno in un periodo e non in un elenco
///
/// Sono cinque valori — identificativo, sessione, versione del profilo, istante
/// della fotografia — e messi in colonna facevano di questa pagina un modulo.
/// Dentro un periodo restano tutti, restano ritrovabili, e la relazione resta
/// una relazione.
fn preamble(input: &NarrativeInput<'_>, blocks: &mut Vec<Block>) {
    blocks.push(Block::Paragraph(format!(
        "{}, riferisce quanto segue.",
        subscriber(input)
    )));

    blocks.push(Block::Lead {
        lead: String::from("Identificativo della relazione:"),
        body: format!(
            "{}. Attività documentata: «{}», identificativo interno {}. \
             {} Fotografia dei dati presa il {}.",
            input.report_id.as_str(),
            input.session.label,
            input.snapshot.session_id.get(),
            profile_sentence(input.snapshot.template_version),
            input.snapshot.taken_at.to_readable_utc(),
        ),
    });
}

/// Lo stato della revisione, con il motivo che la persona ha scritto
/// (INSTALLED-APP-E2E-01, E2E01-12).
///
/// «Segnalato» da solo diceva una decisione senza la sua ragione: chi legge la
/// relazione non può chiedere a chi ha deciso. Il motivo si riporta tra
/// virgolette, come la persona lo ha scritto; se non c'era, lo si dice.
fn review_sentence(state: Option<ReviewState>, note: Option<&str>) -> String {
    let Some(state) = state else {
        return String::from(NOT_REVIEWED);
    };
    match note.map(str::trim).filter(|nota| !nota.is_empty()) {
        Some(nota) => format!("{}. Motivo scritto: «{nota}»", state.label()),
        None => format!("{}, senza motivo scritto", state.label()),
    }
}

/// Da dove vengono i dati dell'ufficio (INSTALLED-APP-E2E-01, E2E01-11).
///
/// «Profilo documentale in versione 0» si leggeva accanto a Impostazioni che
/// diceva «versione 1»: lo 0 era il segno «nessun profilo conservato», e nessuno
/// lo poteva sapere. La versione si scrive solo quando c'è.
fn profile_sentence(version: u32) -> String {
    if version == 0 {
        String::from(
            "Dati dell'ufficio compilati per questa relazione, non conservati come profilo.",
        )
    } else {
        format!("Profilo documentale conservato, versione {version}.")
    }
}

/// Chi sottoscrive, come la premessa lo nomina.
///
/// Con qualifica e nome configurati si legge «Il sottoscritto <qualifica>
/// <nome>»; senza, si ripiega sull'identificativo dell'operatore che ha chiesto
/// la generazione, che e' l'unico nome che il programma conosce davvero.
fn subscriber(input: &NarrativeInput<'_>) -> String {
    let role = input.profile.signer_role.as_ref().map(|f| f.as_str());
    let name = input.profile.signer_name.as_ref().map(|f| f.as_str());

    let mut sentence = match (role, name) {
        (Some(role), Some(name)) => format!("Il sottoscritto {role} {name}"),
        (None, Some(name)) => format!("Il sottoscritto {name}"),
        (Some(role), None) => format!(
            "Il sottoscritto {role}, operatore {}",
            input.operator.as_str()
        ),
        (None, None) => format!("L'operatore {}", input.operator.as_str()),
    };

    if let Some(office) = input.profile.office.as_ref() {
        sentence.push_str(&format!(", in servizio presso {}", office.as_str()));
    }
    sentence
}

/// Descrizione dell'attivita' svolta: che cosa, quando, per quanto.
///
/// E' la sezione che rende la relazione senza risultanze un documento con un
/// contenuto proprio invece che una dichiarazione di nulla (criterio 3).
fn activity(input: &NarrativeInput<'_>, blocks: &mut Vec<Block>) {
    blocks.push(Block::Heading(String::from("Attività svolta")));

    blocks.push(Block::Lead {
        lead: format!("In data {}", input.session.started_at.to_readable_utc()),
        body: String::from(
            "veniva avviata l'attività di monitoraggio delle fonti di seguito indicate.",
        ),
    });
    if let Some(account) = input.session.account.as_deref() {
        blocks.push(Block::Paragraph(format!(
            "L'attività è stata condotta con l'account d'ufficio «{account}»."
        )));
    }

    match input.session.ended_at {
        Some(ended_at) => blocks.push(Block::Lead {
            lead: format!("In data {}", ended_at.to_readable_utc()),
            body: format!(
                "l'attività veniva conclusa, per una durata complessiva di {}.",
                input.session.duration()
            ),
        }),
        None => blocks.push(Block::Paragraph(String::from(
            "L'attività non risulta ancora conclusa, e la presente relazione ne \
             documenta lo stato alla data di generazione.",
        ))),
    }

    monitored_sources(input, blocks);
    push_coverage(blocks, input.coverage);

    blocks.push(Block::Paragraph(format!(
        "Nel periodo indicato sono stati acquisiti e analizzati {} contenuti. \
         Di questi, {} sono stati selezionati dall'operatore per essere \
         rappresentati nella presente relazione e {} non sono rappresentati.",
        input.snapshot.monitored_count(),
        input.snapshot.selected_count(),
        input.snapshot.excluded_count(),
    )));

    // CON QUALI TERMINI (ADR-0156): «nessuna» si scriveva per ogni
    // monitoraggio anteriore alla registrazione delle scelte, mentre l'archivio
    // ne conservava i termini (BUG-REP-1). Le frasi vengono dalla composizione
    // comune ai quattro documenti.
    input.configuration.push_blocks(blocks);

    technical_faults(input, blocks);
}

/// Che cosa la postazione ha guardato, fonte per fonte (PR-05, ADR-0121).
///
/// # Una dichiarazione di limite
///
/// La sezione dice **su che cosa** il documento si basa: un tratto non coperto
/// o non determinabile non è un periodo senza messaggi. La frase che lo fissa
/// viene prima delle fonti, perché va letta prima.
///
/// Le frasi sono quelle dello schermo (`crate::coverage`): l'atto non deve dire
/// una cosa diversa dalla schermata.
pub fn push_coverage(blocks: &mut Vec<Block>, lines: &[crate::coverage::CoverageLine]) {
    blocks.push(Block::Lead {
        lead: String::from("Che cosa questa postazione ha guardato:"),
        body: String::from(lisi_core::model::coverage::COVERAGE_MEANING),
    });
    if lines.is_empty() {
        blocks.push(Block::Paragraph(String::from(
            "La copertura non è stata calcolata per il presente documento: il documento non dice \
             quando si guardava.",
        )));
        return;
    }
    for riga in lines {
        blocks.push(Block::Paragraph(format!(
            "«{}»: {} {}",
            riga.source,
            crate::coverage::totals_in_words(&riga.coverage),
            crate::coverage::gaps_in_words(&riga.coverage)
        )));
    }
}

/// Le fonti effettivamente monitorate.
///
/// In prosa finche' si contano su una mano, in tabella oltre: dodici fonti
/// dentro un periodo sarebbero un elenco travestito da frase.
fn monitored_sources(input: &NarrativeInput<'_>, blocks: &mut Vec<Block>) {
    if input.sources.is_empty() {
        blocks.push(Block::Paragraph(String::from(
            "Nella sessione non risulta monitorata alcuna fonte.",
        )));
        return;
    }

    if input.sources.len() > SOURCES_IN_PROSE {
        blocks.push(Block::Paragraph(String::from(
            "Le fonti monitorate, con il numero di contenuti acquisiti da ciascuna, \
             sono le seguenti.",
        )));
        blocks.push(Block::Table {
            headers: vec![String::from("Fonte"), String::from("Contenuti acquisiti")],
            rows: input
                .sources
                .iter()
                .map(|source| vec![source.label.clone(), source.acquired.to_string()])
                .collect(),
        });
        reliability_of_sources(input, blocks);
        return;
    }

    let listed = input
        .sources
        .iter()
        .map(|source| {
            format!(
                "«{}» ({} contenuti acquisiti)",
                source.label, source.acquired
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    blocks.push(Block::Paragraph(format!(
        "Le fonti monitorate risultano le seguenti: {listed}."
    )));
    reliability_of_sources(input, blocks);
}

/// Le valutazioni dell'ufficio sull'affidabilità delle fonti, se ce ne sono
/// (ADR-0167): attribuite a chi le ha date, separate dai contenuti.
fn reliability_of_sources(input: &NarrativeInput<'_>, blocks: &mut Vec<Block>) {
    for fonte in input.sources {
        let Some(valutazione) = fonte.reliability.as_deref() else {
            continue;
        };
        blocks.push(Block::Paragraph(format!(
            "Valutazione dell'ufficio sulla fonte \u{ab}{}\u{bb}: {valutazione} \u{c8} il giudizio di \
             chi l'ha data, non un'analisi del programma, e non riguarda i singoli contenuti.",
            fonte.label
        )));
    }
}

/// Anomalie tecniche significative.
fn technical_faults(input: &NarrativeInput<'_>, blocks: &mut Vec<Block>) {
    if input.faults.is_empty() {
        blocks.push(Block::Paragraph(String::from(
            "Nel corso dell'attività non sono state registrate anomalie tecniche \
             significative.",
        )));
        return;
    }

    blocks.push(Block::Paragraph(String::from(
        "Nel corso dell'attività sono state registrate le anomalie tecniche di \
         seguito indicate.",
    )));
    for fault in input.faults {
        blocks.push(Block::Paragraph(fault.clone()));
    }
}

/// Le risultanze: **solo** gli elementi selezionati.
fn results(input: &NarrativeInput<'_>, outcome: ReportOutcome, blocks: &mut Vec<Block>) {
    blocks.push(Block::Heading(String::from("Risultanze")));
    blocks.push(Block::Paragraph(outcome.declaration().to_owned()));
    blocks.push(Block::Paragraph(origin_legend()));

    for finding in input.findings {
        // L'attacco in grassetto porta la data, come ogni voce cronologica del
        // facsimile: e' cio' che permette di scorrere la relazione e trovare
        // «quando», senza leggerla tutta.
        blocks.push(Block::Lead {
            // L'ATTACCO E' L'ACQUISIZIONE, NON LA PUBBLICAZIONE (E2E01-03). La
            // frase dice «veniva acquisito»: fino al 2026-10-17 la data era quella
            // dichiarata dalla fonte, e per un messaggio recuperato giorni dopo
            // l'atto affermava il falso sul momento dell'acquisizione.
            lead: format!("In data {}", finding.acquired_at.to_readable_utc()),
            body: format!(
                "veniva acquisito, dalla fonte «{}», il contenuto registrato con \
                 l'identificativo interno {}, di seguito riportato.",
                finding.source_label,
                finding.content_id.get(),
            ),
        });
        // OGNI ISTANTE CON IL SUO NOME (E2E01-03): pubblicazione, recupero,
        // acquisizione e analisi, composti in un posto solo del dominio.
        blocks.push(Block::Lead {
            lead: String::from("Date del contenuto:"),
            body: lisi_core::model::dates_sentence(
                finding.published_at,
                finding.acquired_at,
                finding.recovered,
            ),
        });
        blocks.push(Block::Lead {
            lead: String::from("Testo conservato:"),
            body: format!("«{}»", finding.body),
        });
        blocks.push(Block::Lead {
            lead: String::from("Collegamento:"),
            body: crate::message_link::in_documents_with(
                finding.asked_link.as_deref(),
                finding.url.as_deref(),
            ),
        });
        // L'ALLEGATO (ATTACH-01, ADR-0177, decisione 9): la descrizione e,
        // se conservato, l'impronta. Mai i byte, mai un nome di file.
        if let Some(allegato) = &finding.attachment {
            blocks.push(Block::Paragraph(allegato.clone()));
        }
        // Che cosa e' successo DOPO l'acquisizione.
        //
        // # Perche' sta fra il testo e le valutazioni
        //
        // Perche' cambia il modo di leggere entrambi: il testo qui sopra e'
        // quello acquisito, e il livello qui sotto e' stato calcolato su
        // quello. Una relazione che riportasse il testo di un messaggio senza
        // dire che e' stato poi modificato direbbe una cosa vera in un modo
        // che induce in errore.
        //
        // # Perche' qui la riga c'e' SEMPRE, e nell'allegato no
        //
        // Nell'allegato tecnico il blocco compare solo quando c'e' qualcosa da
        // dire: l'allegato porta centinaia di contenuti, e una riga «nessuna
        // modifica osservata» ripetuta ovunque insegnerebbe a saltarla.
        //
        // La relazione porta i **soli elementi selezionati**, che sono pochi e
        // che qualcuno firma. Qui l'assenza della riga si leggerebbe come «non
        // e' successo niente» per omissione, ed e' esattamente l'affermazione
        // che nessuno ha verificato: il monitoraggio sa che cosa ha
        // **osservato**, non che cosa e' avvenuto. Quindi la riga si scrive
        // sempre, e quando non c'e' nulla dice «non osservate», non «non
        // avvenute».
        // COME E' ENTRATO (PR-07, ADR-0123): visto allora, ritrovato dopo, o non
        // determinabile. Un contenuto recuperato porta sempre ciò che il
        // recupero non vede.
        blocks.push(Block::Lead {
            lead: String::from("Modo di acquisizione:"),
            body: finding.acquisition_mode.clone(),
        });
        blocks.push(Block::Lead {
            lead: String::from("Dopo l'acquisizione:"),
            body: finding.after_acquisition.as_ref().map_or_else(
                || {
                    String::from(
                        "nessuna revisione e nessuna cancellazione osservate dal \
                         monitoraggio. Ciò non esclude che siano avvenute mentre \
                         il monitoraggio non era in esecuzione.",
                    )
                },
                |dopo| {
                    format!(
                        "{dopo}. Il testo conservato e il livello riportati di \
                         seguito sono quelli della versione acquisita: l'analisi \
                         non viene rifatta sulle versioni successive. NEXUM/97 non \
                         cancella contenuti, e che la fonte non esponga più un \
                         messaggio non dice chi lo abbia rimosso."
                    )
                },
            ),
        });
        // La valutazione della macchina e quella della persona sono due cose
        // diverse e il documento non le mescola (ADR-0031 Decisione 4).
        blocks.push(Block::Lead {
            lead: String::from("Livello proposto dal motore (informazione tecnica):"),
            body: finding.level.label(),
        });
        blocks.push(Block::Lead {
            lead: String::from("Motivazione del motore (informazione tecnica):"),
            body: optional(finding.engine_reason.as_deref()),
        });
        blocks.push(Block::Lead {
            lead: String::from("Stato della revisione dell'operatore:"),
            body: review_sentence(finding.review_state, finding.review_note.as_deref()),
        });

        // Le versioni e il contorno vengono DOPO i tre gruppi, e non dentro:
        // sono materiale che il motore non ha giudicato, e mescolarlo alle
        // valutazioni direbbe che il livello lo riguarda (ADR-0104).
        push_revisions(blocks, &finding.revisions, finding.revisions_beyond);
        push_contexts(blocks, &finding.contexts, finding.contexts_beyond);
    }
}

/// Il gruppo delle versioni osservate dopo l'acquisizione.
///
/// # Perché una sola composizione per due documenti
///
/// Perché l'avvertenza — «livello e riscontri riguardano il testo acquisito» —
/// deve essere **la stessa** nell'allegato e nella relazione. Due composizioni
/// della stessa avvertenza divergono alla prima modifica, e la differenza fra
/// il testo giudicato e i testi osservati dopo è la cosa che questa frase
/// esiste per tenere ferma (ADR-0104, decisione 2).
///
/// Non scrive nulla quando non c'è stata alcuna modifica: che cosa dire di
/// un'assenza lo decide il documento, che qui sopra ha già la propria riga.
pub fn push_revisions(blocks: &mut Vec<Block>, revisions: &[LedgerRevision], beyond: usize) {
    if revisions.is_empty() {
        return;
    }

    blocks.push(Block::Lead {
        lead: String::from("Le versioni osservate."),
        body: String::from(CHE_COSA_E_UNA_REVISIONE),
    });

    for revision in revisions {
        blocks.push(Block::Lead {
            lead: format!("Versione {} —", revision.version),
            body: format!(
                "osservata il {}. {} Lunghezza: {}. Testo: «{}»",
                revision.observed_at.to_readable_utc(),
                revision.change,
                lunghezza(revision.length_delta),
                revision.body
            ),
        });
    }

    // IL TAGLIO SI DICHIARA. Un documento che tace ciò che ha tolto trasforma
    // «non mostrato» in «non esistente» (ADR-0104, decisione 5).
    if beyond > 0 {
        blocks.push(Block::Paragraph(format!(
            "Di questo contenuto sono state osservate altre {beyond} versioni, non \
             riprodotte nel presente documento per ragioni di estensione. Sono \
             conservate nell'archivio del programma."
        )));
    }
}

/// Come si dice di quanto un testo si è allungato o accorciato.
///
/// Si contano i **caratteri** e non i byte, perché è così che sono stati
/// contati, e si dice «invariata» invece di «più 0 caratteri».
fn lunghezza(delta: i64) -> String {
    match delta {
        0 => String::from("lunghezza invariata"),
        positivo if positivo > 0 => format!("più {positivo} caratteri"),
        negativo => format!("meno {} caratteri", negativo.abs()),
    }
}

/// Il gruppo del contorno: che cosa l'operatore ha visto attorno al contenuto.
///
/// # Che cosa questo gruppo tiene separato
///
/// Il contorno è **dato originale**; l'istante, l'ancora e l'esito della
/// verifica sono **metadati del sistema**; la ragione della fotografia è
/// **valutazione dell'operatore**. I tre gruppi di ADR-0031 restano tre anche
/// qui, ed è la ragione per cui la ragione non sta nella stessa riga delle
/// righe viste (ADR-0104, decisione 3).
pub fn push_contexts(blocks: &mut Vec<Block>, contexts: &[LedgerContext], beyond: usize) {
    if contexts.is_empty() {
        return;
    }

    blocks.push(Block::Lead {
        lead: String::from("Il contorno osservato."),
        body: String::from(CHE_COSA_E_UN_CONTORNO),
    });

    for context in contexts {
        blocks.push(Block::Lead {
            lead: format!("Fotografia del {} —", context.taken_at.to_readable_utc()),
            body: format!(
                "contorno letto il {}, attorno al messaggio {}. Presa da {}.",
                context.observed_at.to_readable_utc(),
                context.anchor_remote_message_id,
                context.taken_by
            ),
        });
        blocks.push(Block::Lead {
            lead: String::from("Ragione dichiarata dall'operatore:"),
            body: format!("«{}»", context.reason),
        });

        // UNA FOTOGRAFIA CHE NON SI VERIFICA NON SI RIPRODUCE (ADR-0104,
        // decisione 4). L'avvertenza da sola non basterebbe: un contorno
        // stampato è un contorno letto, e chi legge ricorderebbe il testo.
        if !context.verified {
            blocks.push(Block::Paragraph(String::from(
                "L'impronta registrata al momento della fotografia non si è ricalcolata \
                 uguale sui dati riletti: il presente documento non riproduce il \
                 contorno di questa fotografia, perché non è dimostrabile che sia \
                 quello che fu osservato.",
            )));
            continue;
        }

        for line in &context.lines {
            blocks.push(Block::Lead {
                lead: format!(
                    "{}{} —",
                    if line.is_anchor {
                        "Messaggio scelto, "
                    } else {
                        ""
                    },
                    line.remote_message_id
                ),
                body: format!(
                    "pubblicato il {}. {}. Testo: «{}»",
                    line.published_at.to_readable_utc(),
                    line.author_sentence,
                    line.body
                ),
            });
        }

        if context.lines_beyond > 0 {
            blocks.push(Block::Paragraph(format!(
                "Il contorno conservato comprende altre {} righe, non riprodotte nel \
                 presente documento per ragioni di estensione.",
                context.lines_beyond
            )));
        }
    }

    if beyond > 0 {
        blocks.push(Block::Paragraph(format!(
            "Di questo contenuto sono state conservate altre {beyond} fotografie del \
             contesto, non riprodotte nel presente documento per ragioni di \
             estensione."
        )));
    }
}

/// Conclusioni.
///
/// # Perche' la dichiarazione dell'esito si ripete solo in un caso
///
/// [`ReportOutcome::WithFindings`] dice «gli elementi **di seguito**
/// rappresentati»: e' scritta per stare in testa alle risultanze, e ripeterla
/// in conclusione la fa puntare a un seguito che non c'e'. In conclusione, in
/// quel caso, si scrive un **numero**, che e' un fatto e non una formula.
///
/// Nel caso a esito negativo la dichiarazione si ripete, e deve: e' la frase
/// piu' importante del documento, e chi salta alla conclusione deve trovarcela.
fn conclusions(input: &NarrativeInput<'_>, outcome: ReportOutcome, blocks: &mut Vec<Block>) {
    blocks.push(Block::Heading(String::from("Conclusioni")));

    let closing = match outcome {
        ReportOutcome::NothingSelected => format!(
            "L'attività descritta si è svolta nei termini sopra riportati. {}",
            outcome.declaration()
        ),
        ReportOutcome::WithFindings => format!(
            "L'attività descritta si è svolta nei termini sopra riportati. Nella \
             presente relazione sono rappresentati {} elementi, selezionati \
             dall'operatore fra i {} acquisiti nel corso dell'attività.",
            input.snapshot.selected_count(),
            input.snapshot.monitored_count(),
        ),
    };
    blocks.push(Block::Paragraph(closing));
}

/// Luogo, data e sottoscrizione.
///
/// Il facsimile spinge la firma a destra **con degli spazi**; qui si usa un
/// allineamento, che ottiene lo stesso risultato e non dipende dalla larghezza
/// del carattere.
fn signature(input: &NarrativeInput<'_>, blocks: &mut Vec<Block>) {
    blocks.push(Block::Signature {
        place_and_date: format!(
            "{}, {}",
            optional(input.profile.place.as_ref().map(|f| f.as_str())),
            input.generated_at.to_readable_utc()
        ),
        role: input
            .profile
            .signer_role
            .as_ref()
            .map(|field| field.as_str().to_owned()),
        name: input
            .profile
            .signer_name
            .as_ref()
            .map(|field| field.as_str().to_owned()),
    });
}

/// Un valore facoltativo, con la dichiarazione al posto del vuoto.
fn optional(value: Option<&str>) -> String {
    value.map_or_else(|| String::from(NOT_AVAILABLE), str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report_ledger::LedgerContextLine;
    use lisi_core::digest::Sha256Digest;
    use lisi_core::model::report::ReportContentSnapshot;
    use lisi_core::{ContentId, SessionId};

    /// **Lo stato della revisione porta il suo motivo** (E2E01-12), o dice che
    /// non ce n'era uno.
    #[test]
    fn lo_stato_della_revisione_porta_il_suo_motivo() {
        let snapshot = snapshot(&[1], &[1]);
        let mut con_motivo = finding(1);
        con_motivo.review_note = Some(String::from("fonte da tenere d'occhio"));
        let testo =
            compose_with(&ReportTemplateProfile::default(), &snapshot, &[con_motivo]).text();
        assert!(
            testo.contains("Rilevante. Motivo scritto: «fonte da tenere d'occhio»"),
            "{testo}"
        );

        let testo =
            compose_with(&ReportTemplateProfile::default(), &snapshot, &[finding(1)]).text();
        assert!(testo.contains("Rilevante, senza motivo scritto"), "{testo}");
    }

    /// **La relazione non scrive «versione 0»** (E2E01-11): scrive da dove
    /// vengono i dati dell'ufficio.
    #[test]
    fn la_relazione_dice_da_dove_vengono_i_dati_dell_ufficio() {
        let compilati = profile_sentence(0);
        assert!(!compilati.contains("versione 0"), "{compilati}");
        assert!(
            compilati.contains("compilati per questa relazione"),
            "{compilati}"
        );
        assert_eq!(
            profile_sentence(2),
            "Profilo documentale conservato, versione 2."
        );
    }

    fn timestamp(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    fn operator() -> Actor {
        Actor::try_new("operatore").expect("attore valido")
    }

    fn report_id() -> ReportId {
        ReportId::from_sequence(2026, 42)
    }

    fn snapshot(selected: &[i64], monitored: &[i64]) -> ReportSnapshot {
        ReportSnapshot {
            taken_at: timestamp(1_700_000_000_000),
            session_id: SessionId::new(1),
            source_ids: Vec::new(),
            dictionary_version_ids: Vec::new(),
            template_version: 1,
            contents: monitored
                .iter()
                .map(|raw| ReportContentSnapshot {
                    content_id: ContentId::new(*raw),
                    level: AnalysisLevel::try_new(0).expect("livello valido"),
                    review_state: None,
                    body_sha256: Sha256Digest::of_text("corpo"),
                    selected: selected.contains(raw),
                })
                .collect(),
        }
    }

    fn session() -> NarrativeSession {
        NarrativeSession {
            label: String::from("Sessione di prova"),
            started_at: timestamp(1_700_000_000_000),
            ended_at: Some(timestamp(1_700_007_200_000)),
            account: None,
            profile_observations: Vec::new(),
        }
    }

    fn finding(raw: i64) -> NarrativeFinding {
        NarrativeFinding {
            acquisition_mode: String::from("Acquisito dal vivo."),
            content_id: ContentId::new(raw),
            source_label: String::from("Canale di prova"),
            published_at: timestamp(1_700_000_500_000),
            // Recuperato una settimana dopo la pubblicazione (E2E01-03).
            acquired_at: timestamp(1_700_605_300_000),
            recovered: true,
            url: None,
            asked_link: None,
            attachment: None,
            body: format!("testo del contenuto {raw}"),
            level: AnalysisLevel::try_new(3).expect("livello valido"),
            engine_reason: None,
            review_state: Some(ReviewState::Relevant),
            review_note: None,
            after_acquisition: None,
            revisions: Vec::new(),
            revisions_beyond: 0,
            contexts: Vec::new(),
            contexts_beyond: 0,
        }
    }

    /// Una versione osservata dopo l'acquisizione.
    fn revisione(version: u32, body: &str) -> LedgerRevision {
        LedgerRevision {
            version,
            observed_at: timestamp(1_700_003_000_000),
            change: String::from(
                "il testo precedente è l'inizio del nuovo: è stato aggiunto in coda",
            ),
            length_delta: 12,
            body: String::from(body),
        }
    }

    /// Una fotografia del contesto, integra salvo indicazione contraria.
    fn fotografia(verified: bool) -> LedgerContext {
        LedgerContext {
            taken_by: String::from("operatore.anna"),
            reason: String::from("il messaggio precedente cambia il senso di questo"),
            taken_at: timestamp(1_700_004_000_000),
            observed_at: timestamp(1_700_003_900_000),
            anchor_remote_message_id: String::from("4242"),
            verified,
            lines: vec![LedgerContextLine {
                remote_message_id: String::from("4241"),
                published_at: timestamp(1_700_003_800_000),
                body: String::from("riga di contorno mai acquisita"),
                author_sentence: String::from("autore non esposto dalla fonte"),
                is_anchor: false,
            }],
            lines_beyond: 0,
        }
    }

    /// **Il testo che accompagna il livello resta quello acquisito.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un documento che stampasse l'ultima versione osservata accanto al
    /// livello attribuirebbe a quel testo un'analisi che nessuno ha eseguito su
    /// quel testo: il livello e' stato calcolato sul corpo acquisito e nessuno
    /// lo ricalcola (ADR-0104, decisione 1).
    ///
    /// Sarebbe piu' pericoloso di non dire niente, perche' ha l'aspetto della
    /// completezza.
    /// **E2E01-03: «In data … veniva acquisito» porta la data dell'acquisizione,
    /// e la pubblicazione ha il suo nome.** Il contenuto di prova è pubblicato
    /// il 14 novembre 2023 e recuperato il 21: la relazione del collaudo
    /// scriveva la prima data accanto a «veniva acquisito».
    #[test]
    fn la_relazione_non_confonde_pubblicazione_e_acquisizione() {
        let snapshot = snapshot(&[1], &[1]);
        let report = compose_with(&ReportTemplateProfile::default(), &snapshot, &[finding(1)]);
        let text = report.text();

        let pubblicato = timestamp(1_700_000_500_000).to_readable_utc();
        let acquisito = timestamp(1_700_605_300_000).to_readable_utc();
        assert!(
            text.contains(&format!("In data {acquisito} veniva acquisito")),
            "l'attacco deve portare la data dell'acquisizione: {text}"
        );
        assert!(
            !text.contains(&format!("In data {pubblicato} veniva acquisito")),
            "la data di pubblicazione non deve stare accanto a «veniva acquisito»"
        );
        assert!(
            text.contains(&format!("pubblicato dalla fonte il {pubblicato}")),
            "la pubblicazione deve essere detta con il suo nome"
        );
        assert!(
            text.contains(&format!(
                "recuperato dalla cronologia e acquisito nell'archivio il {acquisito}"
            )),
            "il recupero deve essere detto"
        );
        assert!(text.contains(&format!("analizzato all'acquisizione, il {acquisito}")));

        // Dal vivo: nessuna parola sul recupero.
        let mut dal_vivo = finding(1);
        dal_vivo.recovered = false;
        let testo = compose_with(&ReportTemplateProfile::default(), &snapshot, &[dal_vivo]).text();
        assert!(!testo.contains("recuperato dalla cronologia"));
        assert!(testo.contains(&format!("acquisito nell'archivio il {acquisito}")));
    }

    #[test]
    fn il_testo_conservato_resta_quello_acquisito_anche_dopo_una_modifica() {
        let snapshot = snapshot(&[1], &[1]);
        let mut modificato = finding(1);
        modificato.after_acquisition = Some(String::from("modificato"));
        modificato.revisions = vec![revisione(2, "testo della seconda versione")];

        let report = compose_with(&ReportTemplateProfile::default(), &snapshot, &[modificato]);
        let text = report.text();

        assert!(
            text.contains("Testo conservato: «testo del contenuto 1»"),
            "il testo conservato non e' piu' quello acquisito"
        );
        assert!(
            text.contains("Le versioni osservate."),
            "le versioni non hanno un gruppo proprio"
        );
        assert!(
            text.contains("non sono stati ricalcolati sulle versioni"),
            "manca l'avvertenza che apre il gruppo delle versioni"
        );

        // La seconda versione c'e' — altrimenti il gruppo non servirebbe — ma
        // DOPO l'avvertenza, non al posto del testo acquisito.
        let Some(posizione_avvertenza) = text.find("non sono stati ricalcolati") else {
            panic!("l'avvertenza deve esserci");
        };
        let Some(posizione_versione) = text.find("testo della seconda versione") else {
            panic!("la versione deve esserci");
        };
        assert!(
            posizione_avvertenza < posizione_versione,
            "la versione compare prima dell'avvertenza che la spiega"
        );
    }

    /// **Il taglio delle versioni si dichiara, e dice quante ne restano.**
    ///
    /// Un documento che tacesse cio' che ha tolto trasformerebbe «non
    /// mostrato» in «non esistente» — la regola di PD-PLAN-01, qui applicata a
    /// un atto (ADR-0104, decisione 5).
    #[test]
    fn le_versioni_tagliate_si_dichiarano_con_il_loro_numero() {
        let snapshot = snapshot(&[1], &[1]);
        let mut modificato = finding(1);
        modificato.after_acquisition = Some(String::from("modificato 15 volte"));
        modificato.revisions = vec![revisione(2, "seconda")];
        modificato.revisions_beyond = 5;

        let report = compose_with(&ReportTemplateProfile::default(), &snapshot, &[modificato]);
        let text = report.text();

        assert!(
            text.contains("altre 5 versioni"),
            "il taglio non dice quante versioni restano fuori"
        );
        assert!(
            text.contains("conservate nell'archivio del programma"),
            "il taglio non dice dove sono finite"
        );
    }

    /// **Il contorno dice di non essere stato analizzato.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Le righe di una fotografia non sono mai state acquisite ne' analizzate.
    /// Messe accanto a un livello e a una motivazione del motore, sembrano
    /// materiale giudicato: chi legge un fascicolo non ha modo di distinguerle
    /// guardando, perche' sono composte con lo stesso carattere sotto lo stesso
    /// titolo (ADR-0104, decisione 3; R-11).
    #[test]
    fn il_contorno_dichiara_di_non_essere_stato_analizzato() {
        let snapshot = snapshot(&[1], &[1]);
        let mut con_contorno = finding(1);
        con_contorno.contexts = vec![fotografia(true)];

        let report = compose_with(
            &ReportTemplateProfile::default(),
            &snapshot,
            &[con_contorno],
        );
        let text = report.text();

        for atteso in [
            "Non sono state acquisite",
            "non sono oggetto di alcun livello",
            "riga di contorno mai acquisita",
        ] {
            assert!(text.contains(atteso), "il contorno non dice «{atteso}»");
        }

        // La ragione e' una VALUTAZIONE dell'operatore e sta in una riga sua,
        // non mescolata alle righe viste (ADR-0031).
        assert!(
            text.contains("Ragione dichiarata dall'operatore:"),
            "la ragione della fotografia non ha una riga propria"
        );
    }

    /// **Una fotografia che non si verifica non si riproduce.**
    ///
    /// # Perche' non basterebbe un avviso sopra il contorno
    ///
    /// Perche' un contorno stampato e' un contorno letto: l'avvertenza sta in
    /// cima e il testo sotto, e chi legge ricordera' il testo. Un dato che non
    /// si puo' dimostrare integro non entra in un atto (ADR-0104, decisione 4).
    #[test]
    fn una_fotografia_non_verificata_non_porta_il_contorno_nel_documento() {
        let snapshot = snapshot(&[1], &[1]);
        let mut manomessa = finding(1);
        manomessa.contexts = vec![fotografia(false)];

        let report = compose_with(&ReportTemplateProfile::default(), &snapshot, &[manomessa]);
        let text = report.text();

        assert!(
            !text.contains("riga di contorno mai acquisita"),
            "il contorno di una fotografia non verificata e' finito nel documento"
        );
        assert!(
            text.contains("non si è ricalcolata uguale"),
            "il documento non dice perche' il contorno manca"
        );
        // La fotografia resta nominata: sparire sarebbe peggio che entrare
        // dichiarata, perche' nessuno saprebbe che e' esistita.
        assert!(
            text.contains("operatore.anna"),
            "la fotografia non verificata e' sparita invece di essere dichiarata"
        );
    }

    /// **Senza modifiche e senza fotografie non compare nulla di nuovo.**
    ///
    /// Due gruppi vuoti ripetuti su ogni contenuto insegnerebbero a saltarli, e
    /// li renderebbero inutili proprio dove contano.
    #[test]
    fn senza_versioni_e_senza_fotografie_i_due_gruppi_non_compaiono() {
        let snapshot = snapshot(&[1], &[1]);
        let report = compose_with(&ReportTemplateProfile::default(), &snapshot, &[finding(1)]);
        let text = report.text();

        assert!(!text.contains("Le versioni osservate."));
        assert!(!text.contains("Il contorno osservato."));
    }

    fn compose_with(
        profile: &ReportTemplateProfile,
        snapshot: &ReportSnapshot,
        findings: &[NarrativeFinding],
    ) -> NarrativeReport {
        let session = session();
        let identifier = report_id();
        let actor = operator();
        compose(&NarrativeInput {
            report_id: &identifier,
            profile,
            snapshot,
            operator: &actor,
            generated_at: timestamp(1_700_010_000_000),
            session: &session,
            sources: &[],
            findings,
            coverage: &[],
            faults: &[],
            configuration: &crate::analysis_configuration::AnalysisConfiguration::unknown(),
        })
    }

    #[test]
    fn a_finding_declares_what_happened_after_the_acquisition() {
        // CTX-01: la relazione riporta il testo conservato e un livello. Se
        // quel messaggio e' stato modificato dopo l'acquisizione, riportarli
        // senza dirlo direbbe una cosa vera in un modo che induce in errore.
        let snapshot = snapshot(&[1], &[1]);
        let mut modificato = finding(1);
        modificato.after_acquisition = Some(String::from("modificato 2 volte"));
        let report = compose_with(&ReportTemplateProfile::default(), &snapshot, &[modificato]);
        let text = report.text();

        assert!(text.contains("Dopo l'acquisizione: modificato 2 volte."));
        // Le due cose che rendono leggibile il resto della voce.
        assert!(text.contains("sono quelli della versione acquisita"));
        assert!(text.contains("l'analisi non viene rifatta sulle versioni successive"));
    }

    #[test]
    fn a_deletion_is_never_attributed_to_anyone_in_the_relazione() {
        // ADR-0051 Decisione 3: che la fonte non esponga piu' un messaggio non
        // dice chi lo abbia rimosso, e NEXUM/97 non cancella nulla.
        let snapshot = snapshot(&[1], &[1]);
        let mut eliminato = finding(1);
        eliminato.after_acquisition = Some(String::from("eliminato su Telegram"));
        let report = compose_with(&ReportTemplateProfile::default(), &snapshot, &[eliminato]);
        let text = report.text();

        assert!(text.contains("eliminato su Telegram"));
        assert!(text.contains("NEXUM/97 non cancella contenuti"));
        assert!(text.contains("non dice chi lo abbia rimosso"));
    }

    #[test]
    fn without_a_history_the_relazione_says_not_observed_and_not_not_happened() {
        // La riga c'e' sempre — l'assenza si leggerebbe come «non e' successo
        // niente» per omissione — ma dice cio' che il monitoraggio SA: di non
        // averne osservate. «Nessuna modifica e' avvenuta» sarebbe
        // un'affermazione che nessuno ha verificato (ADR-0051, rischio 1).
        let snapshot = snapshot(&[1], &[1]);
        let report = compose_with(&ReportTemplateProfile::default(), &snapshot, &[finding(1)]);
        let text = report.text();

        assert!(text.contains(
            "Dopo l'acquisizione: nessuna revisione e nessuna cancellazione \
             osservate dal monitoraggio."
        ));
        assert!(text.contains("non era in esecuzione"));
        // La frase che NON deve comparire: il monitoraggio non puo' dirlo.
        assert!(!text.contains("nessuna revisione e nessuna cancellazione avvenute"));
    }

    #[test]
    fn a_report_without_selection_still_describes_the_activity() {
        // Criterio 3: senza selezione il documento si produce **e ha un
        // contenuto proprio**.
        let snapshot = snapshot(&[], &[1, 2, 3]);
        let report = compose_with(&ReportTemplateProfile::default(), &snapshot, &[]);
        let text = report.text();

        assert!(text.contains("Attività svolta"));
        // I numeri ci sono tutti e tre, e ora stanno dentro un periodo invece
        // che in colonna: il criterio chiede che il documento **dica** che cosa
        // e' stato osservato, non che lo dica in forma di modulo.
        assert!(text.contains(
            "sono stati acquisiti e analizzati 3 contenuti. Di questi, 0 sono stati \
             selezionati dall'operatore per essere rappresentati nella presente \
             relazione e 3 non sono rappresentati."
        ));
        assert!(text.contains("per una durata complessiva di 2 ore e 0 minuti."));
        assert!(text.contains(ReportOutcome::NothingSelected.declaration()));
    }

    #[test]
    fn a_report_without_selection_still_names_the_sources_and_the_period() {
        // Il resto di cio' che rende la relazione senza risultanze un documento
        // con un contenuto proprio: quando e' cominciata, quando e' finita, e
        // che cosa e' stato guardato.
        let snapshot = snapshot(&[], &[1]);
        let session = session();
        let identifier = report_id();
        let actor = operator();
        let sources = [NarrativeSource {
            label: String::from("Canale di prova"),
            acquired: 1,
            reliability: None,
        }];
        let report = compose(&NarrativeInput {
            report_id: &identifier,
            profile: &ReportTemplateProfile::default(),
            snapshot: &snapshot,
            operator: &actor,
            generated_at: timestamp(1_700_010_000_000),
            session: &session,
            sources: &sources,
            findings: &[],
            coverage: &[],
            faults: &[],
            configuration: &crate::analysis_configuration::AnalysisConfiguration::unknown(),
        });
        let text = report.text();

        assert!(text.contains("In data 2023-11-14 22:13:20 UTC veniva avviata"));
        assert!(text.contains("In data 2023-11-15 00:13:20 UTC l'attività veniva conclusa"));
        assert!(text.contains("«Canale di prova» (1 contenuti acquisiti)"));
    }

    /// **La valutazione dell'ufficio sulla fonte compare accanto alla fonte,
    /// attribuita e separata dai contenuti; una fonte non valutata non porta
    /// nulla** (SOURCE-RELIABILITY-01, criterio 6).
    #[test]
    fn la_valutazione_della_fonte_compare_attribuita() {
        let snapshot = snapshot(&[], &[1]);
        let session = session();
        let identifier = report_id();
        let actor = operator();
        let sources = [
            NarrativeSource {
                label: String::from("Canale valutato"),
                acquired: 1,
                reliability: Some(String::from(
                    "POCO AFFIDABILE PER L'ESPERIENZA DELL'UFFICIO, valutazione data da \
                     operatore.prova il 23/10/2026, perché: «riscontri dei tre mesi».",
                )),
            },
            NarrativeSource {
                label: String::from("Canale non valutato"),
                acquired: 1,
                reliability: None,
            },
        ];
        let report = compose(&NarrativeInput {
            report_id: &identifier,
            profile: &ReportTemplateProfile::default(),
            snapshot: &snapshot,
            operator: &actor,
            generated_at: timestamp(1_700_010_000_000),
            session: &session,
            sources: &sources,
            findings: &[],
            coverage: &[],
            faults: &[],
            configuration: &crate::analysis_configuration::AnalysisConfiguration::unknown(),
        });
        let text = report.text();
        assert!(
            text.contains(
                "Valutazione dell'ufficio sulla fonte «Canale valutato»: POCO AFFIDABILE"
            ),
            "{text}"
        );
        assert!(text.contains("non un'analisi del programma"));
        assert!(!text.contains("Valutazione dell'ufficio sulla fonte «Canale non valutato»"));
    }

    /// **Le versioni di dizionario si scrivono per nome e numero**, non con gli
    /// identificativi interni delle righe (F-13).
    ///
    /// Prima della correzione la relazione scriveva «2, 3, 4»
    /// mentre il registro dello stesso pacchetto scriveva «v3».
    #[test]
    fn the_dictionary_versions_are_written_by_name_and_number() {
        let snapshot = snapshot(&[], &[1]);
        let session = session();
        let identifier = report_id();
        let actor = operator();
        use crate::analysis_configuration::{
            AnalysisConfiguration, ConfiguredDictionary, CustomTerms, Dictionaries, Resolution,
        };
        let configurazione = AnalysisConfiguration {
            dictionaries: Dictionaries::Recorded(vec![
                ConfiguredDictionary {
                    name: String::from("Incendi"),
                    version: 3,
                    terms: 10,
                },
                ConfiguredDictionary {
                    name: String::from("Ordine pubblico"),
                    version: 2,
                    terms: 5,
                },
            ]),
            resolution: Resolution::NotRecorded,
            custom_terms: CustomTerms::NoneAdded,
        };
        let report = compose(&NarrativeInput {
            report_id: &identifier,
            profile: &ReportTemplateProfile::default(),
            snapshot: &snapshot,
            operator: &actor,
            generated_at: timestamp(1_700_010_000_000),
            session: &session,
            sources: &[],
            findings: &[],
            coverage: &[],
            faults: &[],
            configuration: &configurazione,
        });
        let text = report.text();
        assert!(
            text.contains("Versioni di dizionario in vigore: Incendi v3, Ordine pubblico v2."),
            "{text}"
        );
    }

    #[test]
    fn a_report_without_selection_never_claims_that_nothing_unlawful_exists() {
        // Criterio 4. E' il test piu' importante di questo modulo: una
        // relazione che affermasse un fatto che nessuno ha accertato sarebbe un
        // difetto grave, non un difetto di forma.
        let snapshot = snapshot(&[], &[1, 2]);
        let report = compose_with(&ReportTemplateProfile::default(), &snapshot, &[]);
        let text = report.text().to_lowercase();

        for forbidden in [
            "illecit",
            "non risultano element",
            "non sono emersi element",
            "nulla di rilevante",
            "esito negativo",
            "reato",
            "non sussist",
            "assenza di element",
        ] {
            assert!(
                !text.contains(forbidden),
                "la relazione contiene la formulazione vietata «{forbidden}»"
            );
        }
    }

    #[test]
    fn the_results_contain_only_the_selected_elements() {
        // Criterio 5: la sessione ne ha monitorati quattro, l'operatore ne ha
        // scelti due, e nella narrativa compaiono quei due.
        let snapshot = snapshot(&[2, 4], &[1, 2, 3, 4]);
        let findings = [finding(2), finding(4)];
        let report = compose_with(&ReportTemplateProfile::default(), &snapshot, &findings);
        let text = report.text();

        assert!(text.contains("testo del contenuto 2"));
        assert!(text.contains("testo del contenuto 4"));
        assert!(!text.contains("testo del contenuto 1"));
        assert!(!text.contains("testo del contenuto 3"));
        assert!(text.contains(ReportOutcome::WithFindings.declaration()));
    }

    #[test]
    fn every_finding_is_traceable_to_its_record() {
        let snapshot = snapshot(&[7], &[7]);
        let findings = [finding(7)];
        let report = compose_with(&ReportTemplateProfile::default(), &snapshot, &findings);
        let text = report.text();

        // La riconducibilita' al record resta, dentro il periodo che racconta
        // l'acquisizione invece che in una riga di modulo: e' il criterio 5, e
        // cio' che conta e' che l'identificativo ci sia e sia ritrovabile.
        assert!(text.contains("l'identificativo interno 7"));
        assert!(text.contains("Identificativo della relazione: R-2026-000042"));
    }

    #[test]
    fn a_missing_value_is_declared_and_not_left_blank() {
        let snapshot = snapshot(&[1], &[1]);
        let findings = [finding(1)];
        let report = compose_with(&ReportTemplateProfile::default(), &snapshot, &findings);
        let text = report.text();

        // Profilo vuoto e contenuto senza URL: entrambi lo dicono.
        assert!(text.contains(&format!("Destinatario: {NOT_AVAILABLE}")));
        assert!(text.contains(&format!(
            "Collegamento: {}",
            crate::message_link::IN_DOCUMENTS_NOT_KEPT
        )));
        assert!(text.contains(&format!(
            "Motivazione del motore (informazione tecnica): {NOT_AVAILABLE}"
        )));
    }

    /// **L'allegato entra nella relazione con la descrizione e l'impronta, e
    /// un contenuto senza allegato non ne parla** (ATTACH-01 parte 3,
    /// ADR-0177, decisione 9).
    #[test]
    fn l_allegato_entra_con_la_descrizione_e_l_impronta() {
        let snapshot = snapshot(&[1, 2], &[1, 2]);
        let mut con = finding(1);
        con.attachment = Some(String::from(
            "Allegato: documento, nome dichiarato «fattura.pdf». Conservato nell'archivio, 18 \
             byte, impronta abc.",
        ));
        let findings = [con, finding(2)];
        let report = compose_with(&ReportTemplateProfile::default(), &snapshot, &findings);
        let text = report.text();
        assert_eq!(
            text.matches("Allegato: documento").count(),
            1,
            "una volta, per il solo contenuto che ha un allegato"
        );
        assert!(text.contains("impronta abc"));
    }

    #[test]
    fn the_engine_verdict_and_the_human_review_stay_distinct() {
        let snapshot = snapshot(&[1], &[1]);
        let findings = [finding(1)];
        let report = compose_with(&ReportTemplateProfile::default(), &snapshot, &findings);
        let text = report.text();

        assert!(text.contains("Livello proposto dal motore (informazione tecnica)"));
        assert!(text.contains("Stato della revisione dell'operatore: Rilevante"));
    }

    /// **La relazione nomina l'account d'ufficio del monitoraggio, e non ne
    /// inventa uno quando non è registrato** (MULTI-ACCOUNT-02 parte 3,
    /// ADR-0173; catalogo F-019: «documenti e audit nominano l'account»).
    #[test]
    fn la_relazione_nomina_l_account_del_monitoraggio() {
        let snapshot = snapshot(&[], &[1]);
        let identifier = report_id();
        let actor = operator();
        let profile = ReportTemplateProfile::default();
        let testo = |account: Option<&str>| {
            let mut sessione = session();
            sessione.account = account.map(String::from);
            compose(&NarrativeInput {
                report_id: &identifier,
                profile: &profile,
                snapshot: &snapshot,
                operator: &actor,
                generated_at: timestamp(1_700_010_000_000),
                session: &sessione,
                sources: &[],
                findings: &[],
                coverage: &[],
                faults: &[],
                configuration: &crate::analysis_configuration::AnalysisConfiguration::unknown(),
            })
            .text()
        };
        assert!(
            testo(Some("Ufficio A"))
                .contains("L'attività è stata condotta con l'account d'ufficio «Ufficio A»."),
            "con l'account registrato la relazione lo nomina"
        );
        assert!(
            !testo(None).contains("account d'ufficio"),
            "senza account registrato la relazione non ne nomina uno"
        );
    }

    /// **La relazione riporta le osservazioni di profilo soltanto se scelte, con
    /// l'impronta e senza la foto** (PERSON-MEDIA-01 parte 3, ADR-0174). Prova
    /// negativa: senza scelte, nessuna sezione.
    #[test]
    fn la_relazione_riporta_le_osservazioni_scelte_senza_la_foto() {
        let snapshot = snapshot(&[], &[1]);
        let identifier = report_id();
        let actor = operator();
        let profile = ReportTemplateProfile::default();
        let testo = |scelte: Vec<NarrativeProfileObservation>| {
            let mut sessione = session();
            sessione.profile_observations = scelte;
            compose(&NarrativeInput {
                report_id: &identifier,
                profile: &profile,
                snapshot: &snapshot,
                operator: &actor,
                generated_at: timestamp(1_700_010_000_000),
                session: &sessione,
                sources: &[],
                findings: &[],
                coverage: &[],
                faults: &[],
                configuration: &crate::analysis_configuration::AnalysisConfiguration::unknown(),
            })
            .text()
        };
        assert!(
            !testo(Vec::new()).contains("Osservazioni di profilo"),
            "per difetto nessuna osservazione entra"
        );
        let impronta = "a".repeat(64);
        let con = testo(vec![NarrativeProfileObservation {
            requested_at: timestamp(1_700_003_000_000),
            requested_by: String::from("operatore.prova"),
            reason: String::from("Verifica dell'autore di un messaggio di minaccia"),
            author_identifier: String::from("42"),
            status: String::from("visto di recente"),
            bio: Some(String::from("Cronista")),
            photo_sha256: Some(impronta.clone()),
        }]);
        assert!(con.contains("Osservazioni di profilo scelte dall'operatore"));
        assert!(con.contains("Non identificano una persona"));
        assert!(con.contains("identificativo 42"));
        assert!(con.contains("«visto di recente»"));
        assert!(con.contains("«Cronista»"));
        assert!(con.contains(&impronta), "l'impronta c'è");
        assert!(con.contains("non sono riprodotte"), "la foto no");
    }

    #[test]
    fn an_unfinished_session_has_no_invented_duration() {
        let unfinished = NarrativeSession {
            label: String::from("Sessione aperta"),
            started_at: timestamp(1_700_000_000_000),
            ended_at: None,
            account: None,
            profile_observations: Vec::new(),
        };
        assert_eq!(unfinished.duration(), "attività non ancora conclusa");
    }

    #[test]
    fn an_empty_profile_produces_blanks_to_fill_and_no_invented_office() {
        // Criterio 22 visto dal lato del documento: **nessuna denominazione
        // inventata**, e al suo posto uno spazio che dice che cosa scriverci.
        // Un documento che nasce per essere completato in Word deve dire dove
        // va scritta la denominazione dell'ufficio; tacere lascerebbe chi lo
        // apre a metterla dove capita.
        let snapshot = snapshot(&[], &[1]);
        let report = compose_with(&ReportTemplateProfile::default(), &snapshot, &[]);

        assert_eq!(
            report.institutional_lines(),
            vec![
                "[Denominazione dell'amministrazione]",
                "[Ufficio o articolazione]",
                "[Sede, indirizzo e recapiti]",
            ]
        );
        assert!(
            report
                .letterhead
                .lines
                .iter()
                .all(LetterheadLine::is_placeholder)
        );
        assert!(report.letterhead.emblem.is_none());
        assert_eq!(
            report.footer,
            vec![LetterheadLine::Placeholder(String::from(
                "Riferimenti dell'ufficio"
            ))]
        );
    }

    #[test]
    fn a_placeholder_is_written_between_square_brackets() {
        // La convenzione che chiunque riconosce come «da sostituire».
        let line = LetterheadLine::Placeholder(String::from("Ufficio"));
        assert_eq!(line.text(), "[Ufficio]");
        assert!(line.is_placeholder());

        let line = LetterheadLine::Configured(String::from("Ufficio Analisi"));
        assert_eq!(line.text(), "Ufficio Analisi");
        assert!(!line.is_placeholder());
    }

    #[test]
    fn a_configured_emblem_reaches_the_letterhead() {
        use lisi_core::model::report_template::TemplateEmblem;

        let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        bytes.extend_from_slice(&13_u32.to_be_bytes());
        bytes.extend_from_slice(b"IHDR");
        bytes.extend_from_slice(&64_u32.to_be_bytes());
        bytes.extend_from_slice(&72_u32.to_be_bytes());
        bytes.extend_from_slice(&[8, 6, 0, 0, 0]);

        let profile = ReportTemplateProfile {
            emblem: TemplateEmblem::from_png(bytes).ok(),
            ..ReportTemplateProfile::default()
        };
        let snapshot = snapshot(&[], &[1]);
        let report = compose_with(&profile, &snapshot, &[]);

        let Some(emblem) = report.letterhead.emblem else {
            panic!("lo stemma configurato deve arrivare nella carta intestata");
        };
        assert_eq!(emblem.width_px(), 64);
        assert_eq!(emblem.height_px(), 72);
    }

    #[test]
    fn without_a_signer_the_document_names_the_operator_and_invents_nobody() {
        // Il ripiego della premessa: senza qualifica ne' nome configurati resta
        // l'identificativo di chi ha chiesto la generazione, che e' l'unico
        // nome che il programma conosce davvero.
        let snapshot = snapshot(&[], &[1]);
        let report = compose_with(&ReportTemplateProfile::default(), &snapshot, &[]);
        let text = report.text();

        assert!(text.contains("L'operatore operatore, riferisce quanto segue."));
        assert!(!text.contains("Il sottoscritto"));
    }

    #[test]
    fn the_signer_is_named_in_the_preamble_and_under_the_signature() {
        use lisi_core::model::report_template::TemplateField;

        let profile = ReportTemplateProfile {
            office: Some(TemplateField::try_new("Ufficio Analisi").expect("valido")),
            signer_role: Some(TemplateField::try_new("Vice Ispettore").expect("valido")),
            signer_name: Some(TemplateField::try_new("Mario ROSSI").expect("valido")),
            ..ReportTemplateProfile::default()
        };
        let snapshot = snapshot(&[], &[1]);
        let report = compose_with(&profile, &snapshot, &[]);
        let text = report.text();

        assert!(text.contains(
            "Il sottoscritto Vice Ispettore Mario ROSSI, in servizio presso \
             Ufficio Analisi, riferisce quanto segue."
        ));
        // E in calce, sotto luogo e data.
        assert!(text.contains("Vice Ispettore\nMario ROSSI"));
    }

    #[test]
    fn the_configured_profile_reaches_the_document() {
        use lisi_core::model::report_template::TemplateField;

        let profile = ReportTemplateProfile {
            version: 3,
            organisation: Some(TemplateField::try_new("Ente di prova").expect("valido")),
            office: Some(TemplateField::try_new("Ufficio Analisi").expect("valido")),
            recipient: Some(TemplateField::try_new("Al Responsabile").expect("valido")),
            place: Some(TemplateField::try_new("Roma").expect("valido")),
            footer_line: Some(TemplateField::try_new("pagina interna").expect("valido")),
            ..ReportTemplateProfile::default()
        };
        let snapshot = snapshot(&[], &[1]);
        let report = compose_with(&profile, &snapshot, &[]);

        // Le due righe configurate compaiono per quello che sono; la terza,
        // che il profilo non ha, resta uno spazio da compilare.
        assert_eq!(
            report.institutional_lines(),
            vec![
                "Ente di prova",
                "Ufficio Analisi",
                "[Sede, indirizzo e recapiti]",
            ]
        );
        assert_eq!(
            report.footer,
            vec![LetterheadLine::Configured(String::from("pagina interna"))]
        );
        // Il destinatario e' una riga a se', non piu' una coppia
        // etichetta/valore: e' cosi' che si legge in cima a una relazione.
        assert!(
            report
                .blocks
                .contains(&Block::Emphasis(String::from("Al Responsabile")))
        );
        assert!(report.text().contains("Roma, "));
    }

    #[test]
    fn the_conclusion_never_points_at_a_list_that_is_not_there() {
        // La dichiarazione con risultanze dice «gli elementi **di seguito**
        // rappresentati»: in testa alle risultanze e' giusta, in conclusione
        // punterebbe a un seguito che non c'e'. Trovato leggendo il documento
        // prodotto, non da una prova.
        let snapshot = snapshot(&[2], &[1, 2, 3]);
        let findings = [finding(2)];
        let report = compose_with(&ReportTemplateProfile::default(), &snapshot, &findings);

        let conclusione = report
            .blocks
            .iter()
            .skip_while(|block| **block != Block::Heading(String::from("Conclusioni")))
            .find_map(|block| match block {
                Block::Paragraph(text) => Some(text.clone()),
                _ => None,
            })
            .expect("la relazione deve avere una conclusione");

        assert!(
            !conclusione.contains("di seguito"),
            "la conclusione punta a un seguito che non c'e': {conclusione}"
        );
        assert!(conclusione.contains("sono rappresentati 1 elementi"));
        assert!(conclusione.contains("fra i 3 acquisiti"));
    }

    #[test]
    fn the_negative_conclusion_repeats_the_declaration_because_it_must() {
        // Chi salta alla conclusione di una relazione senza risultanze deve
        // trovarci la frase che conta.
        let snapshot = snapshot(&[], &[1, 2]);
        let report = compose_with(&ReportTemplateProfile::default(), &snapshot, &[]);

        let conclusione = report
            .blocks
            .iter()
            .skip_while(|block| **block != Block::Heading(String::from("Conclusioni")))
            .find_map(|block| match block {
                Block::Paragraph(text) => Some(text.clone()),
                _ => None,
            })
            .expect("la relazione deve avere una conclusione");

        assert!(conclusione.contains(ReportOutcome::NothingSelected.declaration()));
    }

    #[test]
    fn the_courtesy_recipient_goes_to_the_right_when_configured() {
        use lisi_core::model::report_template::TemplateField;

        let profile = ReportTemplateProfile {
            recipient: Some(TemplateField::try_new("Al Responsabile").expect("valido")),
            recipient_cc: Some(TemplateField::try_new("S E D E").expect("valido")),
            ..ReportTemplateProfile::default()
        };
        let snapshot = snapshot(&[], &[1]);
        let report = compose_with(&profile, &snapshot, &[]);

        assert!(
            report
                .blocks
                .contains(&Block::RightLine(String::from("S E D E")))
        );
    }

    #[test]
    fn the_subject_carries_its_label_in_capitals_and_in_its_own_run() {
        // `OGGETTO:` in grassetto e il seguito in tondo, nello stesso paragrafo:
        // e' la forma del facsimile, ed e' quella che permette di trovare
        // l'oggetto senza cercarlo.
        let snapshot = snapshot(&[], &[1]);
        let report = compose_with(&ReportTemplateProfile::default(), &snapshot, &[]);

        let subject = report
            .blocks
            .iter()
            .find_map(|block| match block {
                Block::Lead { lead, body } if lead == "OGGETTO:" => Some(body.clone()),
                _ => None,
            })
            .expect("la relazione deve dichiarare un oggetto");
        assert!(subject.starts_with("Relazione di servizio"));
        assert!(subject.contains("«Sessione di prova»"));
    }

    #[test]
    fn many_sources_become_a_table_and_few_stay_in_prose() {
        let snapshot = snapshot(&[], &[1]);
        let session = session();
        let identifier = report_id();
        let actor = operator();

        let compose_sources = |count: usize| {
            let sources: Vec<NarrativeSource> = (0..count)
                .map(|index| NarrativeSource {
                    label: format!("Fonte {index}"),
                    acquired: index,
                    reliability: None,
                })
                .collect();
            compose(&NarrativeInput {
                report_id: &identifier,
                profile: &ReportTemplateProfile::default(),
                snapshot: &snapshot,
                operator: &actor,
                generated_at: timestamp(1_700_010_000_000),
                session: &session,
                sources: &sources,
                findings: &[],
                coverage: &[],
                faults: &[],
                configuration: &crate::analysis_configuration::AnalysisConfiguration::unknown(),
            })
        };

        let few = compose_sources(SOURCES_IN_PROSE);
        assert!(
            !few.blocks
                .iter()
                .any(|block| matches!(block, Block::Table { .. })),
            "poche fonti restano in prosa"
        );

        let many = compose_sources(SOURCES_IN_PROSE + 1);
        assert!(
            many.blocks
                .iter()
                .any(|block| matches!(block, Block::Table { .. })),
            "molte fonti diventano una tabella"
        );
    }

    #[test]
    fn no_source_monitored_is_stated_and_not_omitted() {
        let snapshot = snapshot(&[], &[]);
        let report = compose_with(&ReportTemplateProfile::default(), &snapshot, &[]);
        assert!(
            report
                .text()
                .contains("non risulta monitorata alcuna fonte")
        );
    }

    /// **La copertura entra nel documento come dichiarazione di limite**, con
    /// la frase che ne fissa il senso prima delle fonti, e senza copertura il
    /// documento lo dice invece di tacere (PR-05).
    #[test]
    fn il_documento_dice_che_cosa_si_guardava() {
        use lisi_core::model::coverage::{
            COVERAGE_MEANING, Coverage, CoverageState, UndeterminedReason,
        };

        let mut vuoto = Vec::new();
        push_coverage(&mut vuoto, &[]);
        let testo: String = vuoto.iter().map(Block::text).collect::<Vec<_>>().join("\n");
        assert!(testo.contains(COVERAGE_MEANING), "{testo}");
        assert!(testo.contains("non è stata calcolata"), "{testo}");

        let copertura = Coverage::single(
            timestamp(1_790_294_400_000),
            timestamp(1_790_298_000_000),
            CoverageState::Undetermined(UndeterminedReason::AfterLastFact),
        );
        let mut blocchi = Vec::new();
        push_coverage(
            &mut blocchi,
            &[crate::coverage::CoverageLine {
                source: String::from("Canale di prova"),
                coverage: copertura,
            }],
        );
        let testo: String = blocchi
            .iter()
            .map(Block::text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            testo.contains("«Canale di prova»: Non determinabile per 1 ora."),
            "{testo}"
        );
        assert!(testo.contains("dopo l'ultimo fatto registrato"), "{testo}");
    }
}

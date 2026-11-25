//! Preparazione, generazione e registrazione dei pacchetti di report.
//!
//! Motivato in ADR-0031. Il modulo prepara il pacchetto, ne fotografa i dati,
//! registra gli artefatti e tiene l'audit; da MP-18G **conduce anche l'intera
//! generazione** ([`ReportService::generate`]), che mette in fila la fotografia,
//! la cartella del pacchetto, la composizione della relazione, la scrittura del
//! `.docx` e il manifest.
//!
//! # Perche' l'orchestrazione sta qui e non nell'interfaccia
//!
//! Sono nove passi, e cinque di essi possono fallire lasciando qualcosa a
//! meta'. Scriverli nella schermata significherebbe metterli dove non esiste un
//! test che li percorra, e riscriverli daccapo alla prima seconda schermata che
//! generi un report. La schermata raccoglie una scelta umana e la consegna; che
//! cosa comporti quella scelta lo sa questo modulo.
//!
//! # Perche' la fotografia si prende **prima** di generare
//!
//! L'archivio e' vivo. Se la si prendesse dopo, o durante, due documenti dello
//! stesso pacchetto potrebbero raccontare due archivi diversi — e un allegato
//! tecnico che non torna con la relazione che accompagna e' peggio di un
//! allegato mancante.
//!
//! # Che cosa finisce nell'audit, e che cosa no
//!
//! Finiscono chi, quando, quale sessione, quanti contenuti erano monitorati e
//! quanti sono stati scelti. **Non** finisce il contenuto dei messaggi: dove
//! basta un identificativo o un numero, si registra quello. Moltiplicare le
//! copie di un testo monitorato moltiplica i posti da proteggere.

use std::path::{Path, PathBuf};

use std::collections::BTreeMap;

use lisi_core::WorkspaceId;
use lisi_core::model::assessment::{SubjectAssessment, current_assessment};
use lisi_core::model::cyber_event::CorrelationReason;
use lisi_core::model::evidence_graph::GraphNode;
use lisi_core::model::identity_link::current_links;
use lisi_core::model::note::OperatorNote;
use lisi_core::model::reference::{ArchiveRef, ArchiveRefKind};
use lisi_core::model::report::{
    NewReportArtifact, ReportArtifactKind, ReportContentSnapshot, ReportGenerationStatus, ReportId,
    ReportOutcome, ReportPackage, ReportRequest, ReportSelection, ReportSnapshot,
};
use lisi_core::model::report_template::ReportTemplateProfile;
use lisi_core::model::{NewAuditEntry, ReviewState};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{ContentId, ReportArtifactId, ReportPackageId, SessionId, Timestamp};
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};
use crate::report_annex::AnnexInput;
use crate::report_ledger::{
    LedgerAlert, LedgerContent, LedgerContext, LedgerContextLine, LedgerFault, LedgerGraphNode,
    LedgerInput, LedgerNeighbourhood, LedgerNote, LedgerOfficialSource, LedgerReview,
    LedgerRevision, LedgerSession, LedgerSource, LedgerSubject, LedgerSubjectIdentity,
    LedgerTaxonomyReference, LedgerTimeline, LedgerWorkspace, MAX_CONTEXT_LINES_IN_DOCUMENT,
    MAX_CONTEXTS_IN_DOCUMENT, MAX_LEGEND_ROWS_IN_DOCUMENT, MAX_NEIGHBOURHOODS_IN_DOCUMENT,
    MAX_NOTES_IN_DOCUMENT, MAX_REVISIONS_IN_DOCUMENT, MAX_SUBJECT_IDENTITIES_IN_DOCUMENT,
    MAX_TAXONOMY_REFERENCES_IN_DOCUMENT, MAX_TIMELINE_ROWS_IN_DOCUMENT, MAX_WORKSPACES_IN_DOCUMENT,
};
use crate::report_narrative::{
    NarrativeFinding, NarrativeInput, NarrativeSession, NarrativeSource,
};
use crate::report_package::{PackageOutcome, PackageWriter};
use crate::report_pdf::PdfKind;

/// Entita' con cui il reporting compare nell'audit.
const ENTITY_REPORT: &str = "report";

/// Azione: il pacchetto e' stato preparato, con la sua fotografia.
const ACTION_PREPARED: &str = "report.preparato";
/// Azione: un artefatto e' stato prodotto e registrato.
const ACTION_ARTIFACT: &str = "report.artefatto";
/// Azione: il pacchetto e' completo e consegnabile.
const ACTION_COMPLETED: &str = "report.completato";
/// Azione: la generazione si e' interrotta.
const ACTION_FAILED: &str = "report.fallito";
/// Azione: il profilo documentale e' stato conservato o modificato.
const ACTION_PROFILE: &str = "report.profilo";

/// Quanti identificativi si provano prima di rinunciare.
///
/// Il progressivo letto dall'archivio non e' una prenotazione: fra la lettura e
/// l'inserimento un'altra esecuzione puo' averlo preso. Tre tentativi coprono
/// quel caso; se ne servissero di piu', il problema non e' la collisione.
const IDENTIFIER_ATTEMPTS: u32 = 3;

/// I generi di artefatto che questa versione sa **davvero** produrre.
///
/// # Perche' esiste un elenco invece di un `match` dentro la generazione
///
/// Perche' la schermata deve poter dire in anticipo che cosa produrra', e
/// dirlo dalla stessa fonte da cui la generazione lo decide. Due elenchi —
/// uno nell'interfaccia per mostrare i formati e uno qui per produrli — sono
/// due elenchi che divergono, e il giorno in cui divergono l'operatore spunta
/// una casella che non produce alcun file.
///
/// XLSX (MP-18D), i due PDF (MP-18E) e il rapporto TXT dentro il pacchetto non
/// sono qui: non esistono, e un pacchetto che li dichiarasse mentirebbe.
pub const PRODUCIBLE_KINDS: &[ReportArtifactKind] = &[
    ReportArtifactKind::NarrativeDocx,
    ReportArtifactKind::NarrativePdf,
    ReportArtifactKind::TechnicalAnnexPdf,
    ReportArtifactKind::AnalyticalXlsx,
    ReportArtifactKind::PlainTxt,
];

/// Che cosa l'operatore ha chiesto di produrre dalla schermata Report.
///
/// Un tipo solo invece di sette argomenti sciolti: sette valori dello stesso
/// genere sono sette occasioni di scambiarne due senza che il compilatore se ne
/// accorga.
#[derive(Debug, Clone)]
pub struct ReportGenerationRequest<'a> {
    /// Sessione documentata.
    pub session_id: SessionId,
    /// Elementi che l'operatore ha scelto di rappresentare.
    ///
    /// **Vuota e' uno stato legittimo**: e' la relazione a esito negativo, e si
    /// produce ugualmente (ADR-0031 Decisione 4).
    pub selection: ReportSelection,
    /// Dati documentali dell'ufficio, compilati per questa relazione.
    pub profile: &'a ReportTemplateProfile,
    /// Cartella **dentro** la quale nascera' la cartella del pacchetto.
    pub destination: &'a Path,
    /// Generi richiesti. Quelli fuori da [`PRODUCIBLE_KINDS`] sono rifiutati.
    pub requested_kinds: Vec<ReportArtifactKind>,
    /// Chi ha chiesto la generazione.
    pub requested_by: Actor,
    /// Istante della richiesta.
    pub requested_at: Timestamp,
    /// I collegamenti chiesti a Telegram per questa relazione, se l'operatore
    /// li ha chiesti (ADR-0165): vivono nei documenti, non nell'archivio.
    pub asked_links: Option<&'a crate::message_link::LinkBook>,
}

/// Mette in ogni contenuto il collegamento chiesto per questo documento, se
/// c'è (ADR-0165).
fn with_asked_links<T>(
    mut elementi: Vec<T>,
    libro: Option<&crate::message_link::LinkBook>,
    numero: impl Fn(&T) -> lisi_core::ContentId,
    metti: impl Fn(&mut T, String),
) -> Vec<T> {
    if let Some(libro) = libro {
        for elemento in &mut elementi {
            if let Some(frase) = libro.sentence_for(numero(elemento)) {
                metti(elemento, frase.to_owned());
            }
        }
    }
    elementi
}

/// Esito di una generazione riuscita.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedReport {
    /// Riga del pacchetto nell'archivio.
    pub package_id: ReportPackageId,
    /// Identificativo citabile, quello che compare dentro i documenti.
    pub report_id: ReportId,
    /// Cartella del pacchetto.
    pub directory: PathBuf,
    /// Percorso del manifest, che e' l'ultimo file scritto.
    pub manifest: PathBuf,
    /// Documenti prodotti, manifest escluso.
    pub artifacts: Vec<NewReportArtifact>,
    /// Contenuti che la sessione aveva monitorato.
    pub monitored: usize,
    /// Contenuti che l'operatore aveva scelto di rappresentare.
    pub selected: usize,
    /// Esito documentale: con o senza risultanze selezionate.
    pub outcome: ReportOutcome,
    /// L'utente Windows che solo può aprire la cartella del pacchetto
    /// (SEC-01, ADR-0157).
    pub owner: crate::report_package::CurrentUser,
}

/// Servizio del reporting.
#[derive(Debug)]
pub struct ReportService {
    database: Database,
}

impl ReportService {
    /// Costruisce il servizio su un archivio gia' aperto.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Archivio sottostante.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Archivio sottostante in scrittura, per il rapporto complessivo
    /// (REPORT-MULTI-01).
    pub(crate) const fn database_mut(&mut self) -> &mut Database {
        &mut self.database
    }

    /// Restituisce l'archivio al chiamante.
    #[must_use]
    pub fn into_database(self) -> Database {
        self.database
    }

    /// Prepara un pacchetto: fotografa i dati della sessione e registra la
    /// selezione dell'operatore.
    ///
    /// La selezione e' un **atto umano**: questo metodo la riceve, non la
    /// deduce. Un contenuto indicato nella selezione ma non presente nella
    /// sessione viene rifiutato, perche' un pacchetto che dichiarasse di
    /// rappresentare qualcosa che non ha monitorato sarebbe inspiegabile.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::Storage`] se la lettura o la scrittura non
    /// riescono, e [`ServiceError::ReportSelectionOutsideSession`] se la selezione contiene
    /// contenuti estranei alla sessione.
    pub fn prepare(&mut self, request: &ReportRequest) -> ServiceResult<ReportPackageId> {
        let snapshot = self.take_snapshot(
            request.session_id,
            &request.selection,
            request.template_version,
            request.requested_at,
        )?;

        let package_id = self.database.open_report_package(request, &snapshot)?;

        self.record_audit(
            &request.requested_by,
            ACTION_PREPARED,
            package_id.get(),
            // Numeri, non contenuti: quanti erano e quanti se ne rappresentano.
            Some(&format!(
                "sessione {}; monitorati {}; selezionati {}",
                request.session_id.get(),
                snapshot.monitored_count(),
                snapshot.selected_count()
            )),
            request.requested_at,
        )?;

        Ok(package_id)
    }

    /// Il profilo documentale conservato, se l'operatore ha gia' risposto.
    ///
    /// `None` significa che **la domanda non e' ancora stata posta**: e' il
    /// primo avvio, e la schermata lo chiede. Un profilo presente ma vuoto
    /// significa che l'operatore ha scelto di non compilarlo, che e' una
    /// risposta legittima e non si richiede piu' (DEC-180).
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::Storage`] se la lettura non riesce.
    pub fn profile(&self) -> ServiceResult<Option<ReportTemplateProfile>> {
        Ok(self.loaded_profile()?.map(|letto| letto.profile))
    }

    /// Il profilo conservato, con i campi personali che su questa postazione
    /// non si aprono (ADR-0160): la schermata li fa reinserire.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::Storage`] se la lettura non riesce.
    pub fn loaded_profile(&self) -> ServiceResult<Option<crate::report_profile::LoadedProfile>> {
        crate::report_profile::load(&self.database)
    }

    /// Il profilo da usare per comporre un documento, anche quando non ce n'e'.
    ///
    /// Dove il profilo manca si usa quello vuoto: il documento lascia gli spazi
    /// da compilare invece di inventare un ufficio (DEC-179).
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::Storage`] se la lettura non riesce.
    pub fn profile_or_empty(&self) -> ServiceResult<ReportTemplateProfile> {
        Ok(self.profile()?.unwrap_or_default())
    }

    /// Conserva il profilo documentale e ne registra la modifica nell'audit.
    ///
    /// Restituisce la versione assegnata, che **cresce a ogni salvataggio**: e'
    /// il numero che la fotografia di ogni report registra, e senza di esso un
    /// profilo modificato renderebbe inspiegabile un report vecchio.
    ///
    /// # Che cosa finisce nell'audit
    ///
    /// La versione e quanti campi risultano compilati. **Non i valori**: sono
    /// dati dell'ufficio, stanno gia' nel profilo, e ripeterli nel registro
    /// moltiplicherebbe i posti da proteggere senza aggiungere nulla a «chi ha
    /// fatto che cosa e quando».
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::Storage`] se la scrittura non riesce.
    pub fn save_profile(
        &self,
        profile: &ReportTemplateProfile,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<u32> {
        // I campi personali si cifrano prima di entrare nell'archivio (ADR-0160).
        let version = crate::report_profile::save(&self.database, profile, actor, now)?;

        self.record_audit(
            actor,
            ACTION_PROFILE,
            i64::from(version),
            Some(&format!(
                "versione {version}; campi compilati {}; stemma {}",
                profile.filled_fields(),
                if profile.emblem.is_some() {
                    "presente"
                } else {
                    "assente"
                }
            )),
            now,
        )?;

        Ok(version)
    }

    /// Conduce l'intera generazione: fotografia, cartella, documenti, manifest.
    ///
    /// E' il punto in cui la selezione dell'operatore diventa un pacchetto sul
    /// disco. Nell'ordine: si controlla che i generi richiesti siano davvero
    /// producibili, si compone un identificativo libero, si prepara il pacchetto
    /// con la propria fotografia, si crea la cartella, si compone la relazione
    /// dai dati dell'archivio, la si scrive, e **per ultimo** si scrive il
    /// manifest (DEC-165).
    ///
    /// # Che cosa succede quando qualcosa va storto
    ///
    /// | Dove | Che cosa resta |
    /// |---|---|
    /// | generi non producibili | niente: non e' stato aperto alcun pacchetto |
    /// | cartella non creabile | il pacchetto e' registrato **fallito** |
    /// | documento non composto | cartella rimossa, pacchetto fallito |
    /// | documento non scritto | i file scritti prima vengono rimossi |
    /// | manifest non scritto | i file **restano senza manifest**, cioe' riconoscibili come incompleti |
    ///
    /// L'ultima riga e' voluta e non e' una svista: la cartella incompleta e' il
    /// segnale, e cancellarla toglierebbe a chi guarda il disco l'unica traccia
    /// che qualcosa era cominciato.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::DocumentGeneration`] se un genere richiesto
    /// non e' producibile o se la composizione del documento fallisce,
    /// [`ServiceError::ExportNotWritten`] se la cartella o un file non si
    /// scrivono, [`ServiceError::ReportSelectionOutsideSession`] se la selezione
    /// esce dalla sessione, e [`ServiceError::Storage`] se una lettura o una
    /// registrazione non riescono.
    pub fn generate(
        &mut self,
        request: &ReportGenerationRequest<'_>,
    ) -> ServiceResult<GeneratedReport> {
        let kinds = producible(&request.requested_kinds)?;

        // La fotografia si prende PRIMA di scrivere qualunque cosa: se la
        // selezione uscisse dalla sessione, il rifiuto arriva senza che nulla
        // sia stato creato ne' sul disco ne' nell'archivio.
        let (package_id, report_id, snapshot) = self.open(request)?;

        let mut writer = match PackageWriter::create(request.destination, &report_id) {
            Ok(writer) => writer,
            Err(error) => {
                let motivo = if matches!(error, ServiceError::ProtectionNotGuaranteed { .. }) {
                    "cartella del pacchetto non ristretta al solo utente"
                } else {
                    "cartella del pacchetto non creata"
                };
                self.fail_quietly(package_id, motivo, request);
                return Err(error);
            }
        };

        for kind in kinds {
            let bytes = match self.compose(kind, &report_id, &snapshot, request) {
                Ok(bytes) => bytes,
                Err(error) => {
                    let removed = writer.abort();
                    tracing::warn!(
                        genere = kind.as_str(),
                        rimossi = removed,
                        "documento non composto: pacchetto annullato"
                    );
                    self.fail_quietly(package_id, "documento non composto", request);
                    return Err(error);
                }
            };

            if let Err(error) = self.write_artifact(
                package_id,
                &mut writer,
                kind,
                &bytes,
                &request.requested_by,
                request.requested_at,
            ) {
                let removed = writer.abort();
                tracing::warn!(
                    genere = kind.as_str(),
                    rimossi = removed,
                    "documento non scritto: pacchetto annullato"
                );
                self.fail_quietly(package_id, "documento non scritto", request);
                return Err(error);
            }
        }

        // `seal` scrive il manifest e solo dopo dichiara completo il pacchetto.
        // Se il manifest non si scrive, `writer` e' gia' stato consumato: i file
        // restano, senza manifest, ed e' esattamente il segnale che DEC-165
        // vuole che resti.
        let outcome = match self.seal(
            package_id,
            writer,
            &request.requested_by,
            request.requested_at,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                let motivo = if matches!(error, ServiceError::ProtectionNotGuaranteed { .. }) {
                    "permessi della cartella del pacchetto non più del solo utente"
                } else {
                    "elenco delle impronte non scritto"
                };
                self.fail_quietly(package_id, motivo, request);
                return Err(error);
            }
        };

        Ok(GeneratedReport {
            package_id,
            report_id,
            directory: outcome.directory,
            manifest: outcome.manifest,
            artifacts: outcome.artifacts,
            monitored: snapshot.monitored_count(),
            owner: outcome.owner,
            selected: snapshot.selected_count(),
            outcome: snapshot.outcome(),
        })
    }

    /// Apre il pacchetto con un identificativo libero e la propria fotografia.
    ///
    /// Il progressivo letto dall'archivio non e' una prenotazione: se un altro
    /// lo ha preso nel frattempo, l'inserimento cade sul vincolo di unicita' e
    /// si riprova con il successivo.
    fn open(
        &mut self,
        request: &ReportGenerationRequest<'_>,
    ) -> ServiceResult<(ReportPackageId, ReportId, ReportSnapshot)> {
        let year = request.requested_at.year_utc();
        let first = self.database.next_report_sequence(year)?;

        let mut last = None;
        for attempt in 0..IDENTIFIER_ATTEMPTS {
            let report_id = ReportId::from_sequence(year, first.saturating_add(attempt));
            let prepared = ReportRequest {
                report_id: report_id.clone(),
                session_id: request.session_id,
                requested_by: request.requested_by.clone(),
                selection: request.selection.clone(),
                requested_kinds: request.requested_kinds.clone(),
                // Nessun profilo documentale e' ancora persistito: i campi
                // arrivano compilati per questa relazione, e la versione 0 dice
                // «nessun profilo salvato» invece di inventarne una.
                template_version: request.profile.version,
                requested_at: request.requested_at,
            };

            match self.prepare(&prepared) {
                Ok(package_id) => {
                    let snapshot = self.snapshot(package_id)?;
                    return Ok((package_id, report_id, snapshot));
                }
                Err(error) if is_duplicate_identifier(&error) => {
                    tracing::info!(
                        identificativo = report_id.as_str(),
                        "identificativo già usato: riprovo con il successivo"
                    );
                    last = Some(error);
                }
                Err(error) => return Err(error),
            }
        }

        Err(last.unwrap_or(ServiceError::DocumentGeneration {
            reason: String::from("nessun identificativo libero per questo anno"),
        }))
    }

    /// Compone il documento di un genere, in byte.
    fn compose(
        &self,
        kind: ReportArtifactKind,
        report_id: &ReportId,
        snapshot: &ReportSnapshot,
        request: &ReportGenerationRequest<'_>,
    ) -> ServiceResult<Vec<u8>> {
        match kind {
            ReportArtifactKind::NarrativeDocx => {
                let session = self.narrative_session(request.session_id)?;
                let sources = self.narrative_sources(request.session_id)?;
                let findings = with_asked_links(
                    self.narrative_findings(snapshot)?,
                    request.asked_links,
                    |f| f.content_id,
                    |f, frase| f.asked_link = Some(frase),
                );
                let coverage = self.coverage_lines(request.session_id, request.requested_at)?;
                let configurazione =
                    crate::analysis_configuration::of_report(&self.database, snapshot)?;

                let report = crate::report_narrative::compose(&NarrativeInput {
                    report_id,
                    profile: request.profile,
                    snapshot,
                    operator: &request.requested_by,
                    generated_at: request.requested_at,
                    session: &session,
                    sources: &sources,
                    // Le anomalie tecniche della sessione non sono ancora
                    // raccolte in una forma che una relazione possa citare: il
                    // documento lo dichiara («non sono state registrate»)
                    // invece di tacere. Fingerne una sarebbe peggio.
                    findings: &findings,
                    coverage: &coverage,
                    faults: &[],
                    configuration: &configurazione,
                });

                crate::report_docx::render(&report)
            }
            ReportArtifactKind::NarrativePdf => {
                // **La stessa composizione del `.docx`**, e non una seconda
                // scrittura del testo: due composizioni della stessa relazione
                // sarebbero due documenti che un giorno dicono cose diverse.
                let session = self.narrative_session(request.session_id)?;
                let sources = self.narrative_sources(request.session_id)?;
                let findings = with_asked_links(
                    self.narrative_findings(snapshot)?,
                    request.asked_links,
                    |f| f.content_id,
                    |f, frase| f.asked_link = Some(frase),
                );
                let coverage = self.coverage_lines(request.session_id, request.requested_at)?;
                let configurazione =
                    crate::analysis_configuration::of_report(&self.database, snapshot)?;

                let report = crate::report_narrative::compose(&NarrativeInput {
                    report_id,
                    profile: request.profile,
                    snapshot,
                    operator: &request.requested_by,
                    generated_at: request.requested_at,
                    session: &session,
                    sources: &sources,
                    findings: &findings,
                    coverage: &coverage,
                    faults: &[],
                    configuration: &configurazione,
                });

                crate::report_pdf::render(&report, PdfKind::Narrative)
            }
            ReportArtifactKind::TechnicalAnnexPdf => {
                let session = self.ledger_session(request.session_id)?;
                let sources = self.ledger_sources(request.session_id)?;
                let contents = with_asked_links(
                    self.ledger_contents(snapshot)?,
                    request.asked_links,
                    |c| c.content_id,
                    |c, frase| c.asked_link = Some(frase),
                );
                let alerts = self.ledger_alerts(request.session_id)?;
                let faults = self.ledger_faults(request.session_id)?;
                let cyber_events = self.ledger_cyber_events(request.session_id)?;
                let (subjects, investigative_basis) = self.ledger_subjects(&contents, &alerts)?;
                let coverage = self.coverage_lines(request.session_id, request.requested_at)?;
                let (taxonomy, taxonomy_beyond) = self.ledger_taxonomy(&contents)?;
                let official_sources = self.ledger_official_sources()?;
                let (notes, notes_beyond) = self.ledger_notes(&contents, request.session_id)?;
                let (workspaces, workspaces_beyond) = self.ledger_workspaces(&contents)?;
                let configurazione =
                    crate::analysis_configuration::of_report(&self.database, snapshot)?;

                let annex = crate::report_annex::compose(&AnnexInput {
                    report_id,
                    profile: request.profile,
                    operator: &request.requested_by,
                    generated_at: request.requested_at,
                    session: &session,
                    sources: &sources,
                    contents: &contents,
                    alerts: &alerts,
                    faults: &faults,
                    cyber_events: &cyber_events,
                    subjects: &subjects,
                    taxonomy: &taxonomy,
                    taxonomy_beyond,
                    official_sources: &official_sources,
                    notes: &notes,
                    notes_beyond,
                    workspaces: &workspaces,
                    workspaces_beyond,
                    investigative_basis,
                    coverage: &coverage,
                    configuration: &configurazione,
                });

                crate::report_pdf::render(&annex, PdfKind::TechnicalAnnex)
            }
            // **UNA COMPOSIZIONE, DUE RESE.**
            //
            // Il registro Excel e il registro in testo dicono la stessa cosa
            // in due formati: entrambi rappresentano TUTTO il monitorato,
            // livello 0 compreso. Comporli separatamente avrebbe significato
            // due definizioni di «che cosa contiene il registro», e due
            // definizioni della stessa cosa prima o poi divergono — uno
            // direbbe novantatre' contenuti e l'altro novantadue, e nessuno
            // saprebbe quale credere in un atto.
            //
            // La composizione e' quindi UNA, e i due rami la rendono. E' la
            // stessa relazione che c'e' fra la relazione .docx e la .pdf.
            ReportArtifactKind::AnalyticalXlsx => {
                let ledger = self.compose_ledger(report_id, snapshot, request)?;
                crate::report_xlsx::render(&ledger)
            }
            ReportArtifactKind::PlainTxt => {
                let ledger = self.compose_ledger(report_id, snapshot, request)?;
                crate::report_txt::render(&ledger)
            }
            // Irraggiungibile: `producible` ha gia' rifiutato tutto il resto.
            // Resta scritto perche' il compilatore fermi chi aggiunge un genere
            // a `PRODUCIBLE_KINDS` senza portare qui il proprio generatore.
            other => Err(ServiceError::DocumentGeneration {
                reason: format!("{} non è prodotto da questa versione", other.as_str()),
            }),
        }
    }

    /// Compone il registro, una volta sola, per entrambe le sue rese.
    ///
    /// Sta in un metodo e non ripetuto nei due rami perche' e' **la stessa
    /// composizione**: il registro Excel e quello in testo devono dire la
    /// stessa cosa, e l'unico modo per garantirlo e' che la dicano a partire
    /// dagli stessi dati letti nello stesso momento.
    fn compose_ledger(
        &self,
        report_id: &ReportId,
        snapshot: &ReportSnapshot,
        request: &ReportGenerationRequest<'_>,
    ) -> ServiceResult<crate::report_ledger::Ledger> {
        let session = self.ledger_session(request.session_id)?;
        let sources = self.ledger_sources(request.session_id)?;
        let contents = with_asked_links(
            self.ledger_contents(snapshot)?,
            request.asked_links,
            |c| c.content_id,
            |c, frase| c.asked_link = Some(frase),
        );
        let alerts = self.ledger_alerts(request.session_id)?;
        let reviews = self.ledger_reviews(snapshot)?;
        let faults = self.ledger_faults(request.session_id)?;
        let configuration = crate::analysis_configuration::of_report(&self.database, snapshot)?;
        let cyber_events = self.ledger_cyber_events(request.session_id)?;
        let (subjects, investigative_basis) = self.ledger_subjects(&contents, &alerts)?;
        let (taxonomy, taxonomy_beyond) = self.ledger_taxonomy(&contents)?;
        let official_sources = self.ledger_official_sources()?;
        let (notes, notes_beyond) = self.ledger_notes(&contents, request.session_id)?;
        let (workspaces, workspaces_beyond) = self.ledger_workspaces(&contents)?;

        Ok(crate::report_ledger::compose(&LedgerInput {
            report_id,
            profile: request.profile,
            snapshot,
            operator: &request.requested_by,
            generated_at: request.requested_at,
            session: &session,
            sources: &sources,
            contents: &contents,
            alerts: &alerts,
            reviews: &reviews,
            faults: &faults,
            configuration: &configuration,
            cyber_events: &cyber_events,
            subjects: &subjects,
            taxonomy: &taxonomy,
            taxonomy_beyond,
            official_sources: &official_sources,
            notes: &notes,
            notes_beyond,
            workspaces: &workspaces,
            workspaces_beyond,
            investigative_basis,
        }))
    }

    /// I gruppi di segnali della sessione, per il registro e per l'allegato.
    ///
    /// # Perché si ricalcolano invece di rileggere una fotografia
    ///
    /// I gruppi **non si conservano** (DEC-221): nascono dalla correlazione dei
    /// contenuti, e conservarli sarebbe una seconda verità da tenere allineata.
    /// Il documento li ricalcola dai contenuti della sessione, che sono gli
    /// stessi che la fotografia rappresenta.
    ///
    /// # Che cosa questo comporta, e va detto
    ///
    /// Un documento rigenerato dopo che la sessione ha acquisito altri
    /// contenuti mostrerebbe gruppi **più grandi**. Non è un'incoerenza del
    /// documento: è la differenza fra una fotografia dei contenuti — che c'è, ed
    /// è fissata — e una correlazione, che è una lettura di quei contenuti. La
    /// relazione dichiara l'istante in cui è stata generata, ed è quello a cui i
    /// gruppi si riferiscono.
    fn ledger_cyber_events(
        &self,
        session_id: SessionId,
    ) -> ServiceResult<Vec<crate::report_ledger::LedgerCyberEvent>> {
        let events = crate::cyber_watch::events_of(&self.database, session_id)?;

        // IL CANCELLO DELLA RAGIONE OPERATIVA, letto UNA volta per la sessione:
        // e' lo stesso che autorizza gli elenchi di persone, e chiederlo per
        // ogni grappolo sarebbe una lettura dell'audit per riga.
        let ragione_registrata = crate::evidence_graph::basis_recorded_on(&self.database)?;

        Ok(events
            .iter()
            .enumerate()
            .map(|(posizione, event)| {
                let (kind, value) = match &event.event.reason {
                    lisi_core::model::cyber_event::CorrelationReason::SameIndicator {
                        kind,
                        value,
                    } => (kind.label().to_owned(), value.clone()),
                };

                crate::report_ledger::LedgerCyberEvent {
                    reason: event.event.reason.as_sentence(),
                    indicator_kind: kind,
                    indicator_value: value,
                    contents: event.assessment.contents,
                    distinct_sources: event.assessment.distinct_sources,
                    apparent_reposts: event.assessment.apparent_reposts,
                    first_seen: event.seen_between.map(|(primo, _)| primo),
                    last_seen: event.seen_between.map(|(_, ultimo)| ultimo),
                    italy: event.italy.as_sentence(),
                    // `None` invece di una frase «nessun settore»: e' il tipo a
                    // dire se c'e' qualcosa da stampare, non un confronto di
                    // stringhe che si rompe quando la frase cambia.
                    sectors: if event.sectors.is_empty() {
                        None
                    } else {
                        Some(event.sectors.as_sentence())
                    },
                    indicators: event
                        .indicators
                        .iter()
                        .map(|indicatore| {
                            format!("{}: {}", indicatore.kind.label(), indicatore.value)
                        })
                        .collect(),
                    review: event.review.as_sentence(),
                    timeline: self.cronologia_del_grappolo(session_id, &event.event.reason),
                    neighbourhood: if ragione_registrata
                        && posizione < MAX_NEIGHBOURHOODS_IN_DOCUMENT
                    {
                        self.vicinato_del_grappolo(session_id, &event.event.reason)
                    } else {
                        None
                    },
                }
            })
            .collect())
    }

    /// La cronologia di un grappolo, entro il tetto del documento.
    ///
    /// # Perché un errore di lettura non ferma la generazione
    ///
    /// Perché il documento si regge sui contenuti e sui gruppi, non sulle loro
    /// cronologie. Un monitoraggio senza finestra di osservazione — mai avviato,
    /// o interrotto prima di cominciare — non ha una linea del tempo da
    /// comporre, e comporla senza finestra direbbe che un periodo senza righe è
    /// un periodo senza fatti (ADR-0106, decisione 2).
    fn cronologia_del_grappolo(
        &self,
        session_id: SessionId,
        reason: &CorrelationReason,
    ) -> Option<LedgerTimeline> {
        let Ok(cronologia) = crate::cyber_watch::timeline_of(&self.database, session_id, reason)
        else {
            tracing::warn!(
                sessione = session_id.get(),
                "cronologia del grappolo non componibile: il gruppo entra senza linea del tempo"
            );
            return None;
        };

        let righe = cronologia.entries();
        let oltre = righe.len().saturating_sub(MAX_TIMELINE_ROWS_IN_DOCUMENT);

        Some(LedgerTimeline {
            window: cronologia.window().as_sentence(),
            caveat: cronologia.caveat(),
            rows: righe
                .iter()
                .take(MAX_TIMELINE_ROWS_IN_DOCUMENT)
                .map(|riga| riga.as_sentence())
                .collect(),
            rows_beyond: oltre,
        })
    }

    /// Il vicinato di un grappolo nel grafo delle prove.
    ///
    /// # Perché il centro non si sceglie
    ///
    /// Perché il grappolo **è già** un nodo del grafo: la ragione che tiene
    /// insieme i contenuti lo identifica. Su uno schermo il centro lo sceglie
    /// chi guarda; in un documento non c'è nessuno che scelga, e un centro
    /// deciso dal programma sarebbe una scelta mascherata da fatto (ADR-0106,
    /// decisione 3).
    fn vicinato_del_grappolo(
        &self,
        session_id: SessionId,
        reason: &CorrelationReason,
    ) -> Option<LedgerNeighbourhood> {
        let CorrelationReason::SameIndicator { kind, value } = reason;
        let centro = GraphNode::CyberEvent {
            kind: *kind,
            value: value.clone(),
        };

        let Ok(vicinato) =
            crate::evidence_graph::neighbourhood_of_session(&self.database, session_id, &centro)
        else {
            tracing::warn!(
                sessione = session_id.get(),
                "vicinato del grappolo non componibile: il gruppo entra senza legenda"
            );
            return None;
        };

        let Ok(figura) = crate::graph_figure::render(&vicinato) else {
            tracing::warn!(
                sessione = session_id.get(),
                "legenda del vicinato non componibile: il gruppo entra senza legenda"
            );
            return None;
        };

        // LA LEGENDA VIENE DALLA FIGURA, e non da una seconda composizione.
        //
        // La figura di GRAPH-03 numera i nodi e compone le voci; rifare qui
        // quella numerazione significherebbe due elenchi che il giorno in cui
        // uno cambia divergono, e il documento direbbe «3» dove l'immagine dice
        // «4». È anche il primo chiamante che quel modulo abbia mai avuto fuori
        // dalle proprie prove.
        let voci = figura.legend();
        let oltre = voci.len().saturating_sub(MAX_LEGEND_ROWS_IN_DOCUMENT);

        Some(LedgerNeighbourhood {
            centre: centro.as_sentence(),
            caveat: String::from(figura.caveat()),
            legend: voci
                .iter()
                .take(MAX_LEGEND_ROWS_IN_DOCUMENT)
                .map(|voce| LedgerGraphNode {
                    number: voce.number,
                    kind: voce.kind.clone(),
                    label: voce.label.clone(),
                    why: voce.why.clone(),
                    decided_by_a_person: voce.decided_by_a_person,
                })
                .collect(),
            legend_beyond: oltre,
            edges_omitted: vicinato.omitted(),
        })
    }

    /// I fatti della sessione, per il registro.
    fn ledger_session(&self, session_id: SessionId) -> ServiceResult<LedgerSession> {
        let session = self.database.session(session_id)?;
        Ok(LedgerSession {
            label: session.label.as_str().to_owned(),
            started_at: session.started_at.unwrap_or(session.created_at),
            ended_at: session.ended_at,
            // LA PAROLA DELL'OPERATORE, non la chiave dell'archivio: lo
            // stesso stato che lo schermo chiama «In corso» si leggeva
            // «running» nel registro che esce dall'ufficio
            // (FINAL-PRODUCT-REVIEW-01, FPR-02).
            state: session.state.label().to_owned(),
            pauses: self.pauses_in_words(session_id)?,
        })
    }

    /// Le pause dell'acquisizione di un monitoraggio, in parole, nell'ordine
    /// in cui sono state decise (COLLAUDO-FIX-01, CU01-015).
    fn pauses_in_words(&self, session_id: SessionId) -> ServiceResult<Vec<String>> {
        Ok(self
            .database
            .acquisition_pauses(session_id)?
            .iter()
            .map(crate::report_narrative::pause_in_words)
            .collect())
    }

    /// Le fonti monitorate, con quanto ciascuna ha portato.
    fn ledger_sources(&self, session_id: SessionId) -> ServiceResult<Vec<LedgerSource>> {
        let contents = self.database.session_contents(session_id)?;

        let mut sources = Vec::new();
        for source_id in self.database.session_source_ids(session_id)? {
            let acquired = contents
                .iter()
                .filter(|content| content.source_id == source_id)
                .count();
            // Una fonte rimossa non fa sparire cio' che era stato acquisito
            // attraverso di essa: la stessa regola della relazione.
            let source = self.database.source(source_id).ok();
            sources.push(LedgerSource {
                label: source.as_ref().map_or_else(
                    || {
                        format!(
                            "Fonte non più disponibile (identificativo {})",
                            source_id.get()
                        )
                    },
                    |source| source.display_name.as_str().to_owned(),
                ),
                kind: source.as_ref().map_or_else(
                    || String::from(crate::report_narrative::NOT_AVAILABLE),
                    |source| source.kind.label().to_owned(),
                ),
                identifier: source
                    .as_ref()
                    .map(|source| source.identifier.as_str().to_owned()),
                acquired,
            });
        }
        Ok(sources)
    }

    /// **Tutti** i contenuti fotografati, non solo i selezionati.
    ///
    /// E' la differenza fra il registro e la relazione, ed e' il criterio del
    /// registro: nessun record sparisce perche' non ha generato un alert.
    ///
    /// Livello e stato della revisione vengono dalla **fotografia** e non
    /// dall'archivio: sono i valori di allora (DEC-152).
    fn ledger_contents(&self, snapshot: &ReportSnapshot) -> ServiceResult<Vec<LedgerContent>> {
        let contents = self.database.session_contents(snapshot.session_id)?;
        // Il modo di acquisizione di ogni contenuto, alla fotografia (PR-07).
        let modi = crate::acquisition_mode::for_session(
            &self.database,
            snapshot.session_id,
            snapshot.taken_at,
        )?;

        // Che cosa e' successo dopo l'acquisizione, letto UNA volta per la
        // sessione invece che per contenuto: due interrogazioni in tutto.
        let storia = self.database.session_content_history(snapshot.session_id)?;

        // Quante fotografie ha ciascun contenuto, letto UNA volta per la
        // sessione e senza corpi. I contorni si leggono solo per i contenuti
        // che ne hanno: la maggioranza non ne ha nessuno, e leggerli tutti
        // costerebbe i corpi di ogni contorno per dire «niente».
        let quante_fotografie = self
            .database
            .session_context_snapshot_counts(snapshot.session_id)?;

        // I riscontri di TUTTA la sessione, in una lettura sola, e la
        // fotografia dei termini con cui la sessione fu condotta. Chiederli
        // contenuto per contenuto sarebbe un'interrogazione per riga.
        //
        // La fotografia puo' mancare — sessioni anteriori, o selezioni non piu'
        // conservate — e allora la provenienza si dichiara ignota invece di
        // essere ricostruita dai dizionari di oggi, che sarebbe una causa
        // inventata.
        let riscontri = self.database.session_matches(snapshot.session_id)?;
        let fotografia = self
            .database
            .session_resolved_configuration(snapshot.session_id)
            .unwrap_or(None);

        let mut ledger = Vec::new();
        for photographed in &snapshot.contents {
            let Some(content) = contents
                .iter()
                .find(|content| content.id == photographed.content_id)
            else {
                tracing::warn!(
                    contenuto = photographed.content_id.get(),
                    "contenuto fotografato non più leggibile: non entra nel registro"
                );
                continue;
            };

            let source_label = self.database.source(content.source_id).map_or_else(
                |_| String::from("Fonte non più disponibile"),
                |source| source.display_name.as_str().to_owned(),
            );

            let (revisions, revisions_beyond) = self.revisioni_del_contenuto(
                content.id,
                storia.get(&content.id.get()).is_some_and(
                    lisi_core::model::content_history::ContentHistorySummary::was_revised,
                ),
            );
            let (contexts, contexts_beyond) = self.contorni_del_contenuto(
                content.id,
                quante_fotografie.get(&content.id.get()).copied(),
            );

            ledger.push(LedgerContent {
                content_id: content.id,
                source_label,
                author: content.author_identifier.clone(),
                published_at: content.published_at,
                acquired_at: content.acquired_at,
                // IL MODO DICHIARATO, non il percorso registrato (PR-07,
                // ADR-0123): «osservato» nella colonna non basta a dire «dal vivo».
                origin: modi.get(&content.id.get()).map_or_else(
                    || lisi_core::model::AcquisitionMode::Undetermined.as_sentence(),
                    crate::acquisition_mode::declared,
                ),
                body: content.body.as_str().to_owned(),
                url: content.url.as_ref().map(|url| url.as_str().to_owned()),
                asked_link: None,
                attachment: crate::attachment_keeping::describe(&self.database, content.id)?,
                level: photographed.level.get(),
                review_state: photographed
                    .review_state
                    .map(|state| state.label().to_owned()),
                selected: photographed.selected,
                body_digest: photographed.body_sha256.as_str().to_owned(),
                // Da dove venivano i termini che hanno prodotto il livello.
                // Vuoto quando non ci sono riscontri: non c'e' provenienza da
                // dichiarare, perche' non c'e' nulla che l'abbia prodotta.
                analysis_origin: analysis_origin(
                    riscontri
                        .get(&content.id.get())
                        .map_or(&[][..], Vec::as_slice),
                    fotografia.as_ref(),
                ),
                // Lo stato di OGGI, non quello della fotografia: la fotografia
                // fissa il livello e la revisione con cui il rapporto e' stato
                // prodotto, mentre una modifica osservata dopo e' un fatto
                // nuovo che chi legge deve conoscere. Il documento porta
                // l'istante di generazione, quindi la frase e' databile.
                after_acquisition: storia.get(&content.id.get()).and_then(
                    lisi_core::model::content_history::ContentHistorySummary::short_label,
                ),
                revisions,
                revisions_beyond,
                contexts,
                contexts_beyond,
            });
        }
        Ok(ledger)
    }

    /// Le versioni osservate dopo l'acquisizione, entro il tetto del documento.
    ///
    /// # Perché prende un booleano invece di scoprirlo da sé
    ///
    /// Perché il riassunto della sessione è già stato letto una volta per
    /// tutti i contenuti, e rileggerne i corpi per scoprire che non ce ne sono
    /// costerebbe un'interrogazione per riga (ADR-0104). Un contenuto mai
    /// modificato — la maggioranza — non tocca l'archivio.
    ///
    /// # Perché un errore di lettura non ferma il documento
    ///
    /// Perché il documento si regge sui contenuti, non sulle loro versioni: un
    /// archivio che non risponde su una storia lascia una riga di registro e il
    /// contenuto entra lo stesso, con la sua frase «dopo l'acquisizione» che
    /// viene dal riassunto e che quindi resta vera.
    fn revisioni_del_contenuto(
        &self,
        content_id: ContentId,
        modificato: bool,
    ) -> (Vec<LedgerRevision>, usize) {
        if !modificato {
            return (Vec::new(), 0);
        }

        let Ok(storia) = self.database.content_history(content_id) else {
            tracing::warn!(
                contenuto = content_id.get(),
                "storia delle versioni non leggibile: il contenuto entra senza le versioni"
            );
            return (Vec::new(), 0);
        };

        let passaggi = storia.steps();
        let oltre = passaggi.len().saturating_sub(MAX_REVISIONS_IN_DOCUMENT);
        let riprodotte = passaggi
            .into_iter()
            .take(MAX_REVISIONS_IN_DOCUMENT)
            .map(|passaggio| LedgerRevision {
                version: passaggio.version.version_number,
                observed_at: passaggio.version.observed_at,
                change: String::from(passaggio.change.as_sentence()),
                length_delta: passaggio.length_delta,
                body: passaggio.version.body.as_str().to_owned(),
            })
            .collect();

        (riprodotte, oltre)
    }

    /// Le fotografie del contesto, verificate e entro il tetto del documento.
    ///
    /// # La verifica non è un ornamento
    ///
    /// L'impronta si ricalcola sui dati riletti. Quando non corrisponde, la
    /// fotografia entra **senza il contorno**: il documento dirà che non è
    /// quella che fu presa, e un dato che non si può dimostrare integro non si
    /// riproduce in un atto (ADR-0104, decisione 4).
    fn contorni_del_contenuto(
        &self,
        content_id: ContentId,
        quante: Option<usize>,
    ) -> (Vec<LedgerContext>, usize) {
        if quante.is_none_or(|quante| quante == 0) {
            return (Vec::new(), 0);
        }

        let Ok(fotografie) = self.database.context_snapshots_of(content_id) else {
            tracing::warn!(
                contenuto = content_id.get(),
                "fotografie del contesto non leggibili: il contenuto entra senza contorni"
            );
            return (Vec::new(), 0);
        };

        let oltre = fotografie.len().saturating_sub(MAX_CONTEXTS_IN_DOCUMENT);
        let riprodotte = fotografie
            .into_iter()
            .take(MAX_CONTEXTS_IN_DOCUMENT)
            .map(|fotografia| {
                let integra = fotografia.verify();
                let quante_righe = fotografia.messages.len();
                let righe = if integra {
                    fotografia
                        .messages
                        .iter()
                        .take(MAX_CONTEXT_LINES_IN_DOCUMENT)
                        .map(|riga| LedgerContextLine {
                            remote_message_id: riga.remote_message_id.clone(),
                            published_at: riga.published_at,
                            body: riga.body.clone(),
                            author_sentence: riga.author_sentence.clone(),
                            is_anchor: riga.is_anchor,
                        })
                        .collect()
                } else {
                    tracing::warn!(
                        contenuto = content_id.get(),
                        "fotografia del contesto non verificata: il contorno non entra nel documento"
                    );
                    Vec::new()
                };
                let righe_oltre = if integra {
                    quante_righe.saturating_sub(MAX_CONTEXT_LINES_IN_DOCUMENT)
                } else {
                    0
                };

                LedgerContext {
                    taken_by: fotografia.taken_by.as_str().to_owned(),
                    reason: fotografia.reason.as_str().to_owned(),
                    taken_at: fotografia.taken_at,
                    observed_at: fotografia.observed_at,
                    anchor_remote_message_id: fotografia.anchor_remote_message_id.clone(),
                    verified: integra,
                    lines: righe,
                    lines_beyond: righe_oltre,
                }
            })
            .collect();

        (riprodotte, oltre)
    }

    /// I soggetti aperti a cui questo monitoraggio ha osservato qualcosa.
    ///
    /// Restituisce anche **se la ragione operativa è registrata**: quando non lo
    /// è, l'elenco resta vuoto e il documento dichiara perché, invece di
    /// stampare una sezione vuota che si leggerebbe come «nessuna persona di
    /// interesse» (ADR-0105, decisione 5).
    ///
    /// # Perché i conteggi vengono dalle righe già composte
    ///
    /// Perché due derivazioni della stessa cosa divergono, e un atto che
    /// dicesse dodici contenuti nell'elenco e undici sotto un nome non sarebbe
    /// difendibile da nessuno (ADR-0105, decisione 3). Qui non si interroga
    /// l'archivio per i contenuti: si contano quelli che il documento **porta
    /// già**.
    ///
    /// # Perché un soggetto senza osservazioni qui non entra
    ///
    /// Perché il documento è l'atto di **un** monitoraggio. Un fascicolo che
    /// questo monitoraggio non ha incontrato non ha nulla da dire qui, e
    /// nominarlo lo farebbe comparire in un atto che non lo riguarda.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'archivio non è leggibile.
    fn ledger_subjects(
        &self,
        contents: &[LedgerContent],
        alerts: &[LedgerAlert],
    ) -> ServiceResult<(Vec<LedgerSubject>, bool)> {
        // IL CANCELLO DELLA RAGIONE OPERATIVA, letto dove nessuno lo può
        // cambiare senza lasciare traccia: è la stessa voce d'audit che
        // guardano le schermate, non una seconda.
        let ragione_registrata = self.database.operational_basis_recorded()?;
        if !ragione_registrata {
            return Ok((Vec::new(), false));
        }

        let mut soggetti = Vec::new();
        for persona in self.database.persons()? {
            let legami = current_links(&self.database.identity_link_history(persona.id)?);
            if legami.is_empty() {
                continue;
            }

            let valutazione = current_assessment(&self.database.assessment_history(persona.id)?);

            let mut identita = Vec::new();
            for legame in legami {
                let righe: Vec<&LedgerContent> = contents
                    .iter()
                    .filter(|content| content.author.as_deref() == Some(legame.identifier.as_str()))
                    .collect();
                if righe.is_empty() {
                    continue;
                }

                let con_avviso = righe
                    .iter()
                    .filter(|content| {
                        alerts
                            .iter()
                            .any(|alert| alert.content_id == content.content_id)
                    })
                    .count();
                let mut fonti: Vec<&str> = righe
                    .iter()
                    .map(|content| content.source_label.as_str())
                    .collect();
                fonti.sort_unstable();
                fonti.dedup();

                identita.push(LedgerSubjectIdentity {
                    identifier: legame.identifier.clone(),
                    linked_by: legame.by.as_str().to_owned(),
                    linked_at: legame.at,
                    link_reason: legame.reason.as_str().to_owned(),
                    link_basis: legame.basis_sentence(),
                    contents_here: righe.len(),
                    alerts_here: con_avviso,
                    distinct_sources_here: fonti.len(),
                    first_seen_here: righe.iter().map(|content| content.published_at).min(),
                    last_seen_here: righe.iter().map(|content| content.published_at).max(),
                });
            }

            if identita.is_empty() {
                continue;
            }

            let oltre = identita
                .len()
                .saturating_sub(MAX_SUBJECT_IDENTITIES_IN_DOCUMENT);
            identita.truncate(MAX_SUBJECT_IDENTITIES_IN_DOCUMENT);

            soggetti.push(LedgerSubject {
                label: persona.label.as_str().to_owned(),
                dossier_sentence: persona.as_sentence(),
                dossier_reason: persona.reason.as_str().to_owned(),
                open: persona.is_open(),
                assessment_label: String::from(valutazione.as_label()),
                assessment_sentence: valutazione.as_sentence(),
                assessment_reason: match &valutazione {
                    SubjectAssessment::NotAssessed => None,
                    SubjectAssessment::Assessed { reason, .. } => Some(reason.as_str().to_owned()),
                },
                identities: identita,
                identities_beyond: oltre,
            });
        }

        Ok((soggetti, true))
    }

    /// I riferimenti tassonomici dichiarati per i contenuti del monitoraggio.
    ///
    /// # Perché si parte dai contenuti già composti
    ///
    /// Perché il documento rappresenta quei contenuti, e un riferimento
    /// dichiarato su un contenuto che il documento non porta non avrebbe nulla a
    /// cui riferirsi. È la stessa regola dei soggetti: i fatti vengono dalle
    /// righe che il documento porta già.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'archivio non è leggibile.
    fn ledger_taxonomy(
        &self,
        contents: &[LedgerContent],
    ) -> ServiceResult<(Vec<LedgerTaxonomyReference>, usize)> {
        let mut riferimenti = Vec::new();
        for content in contents {
            for associazione in self
                .database
                .standing_associations_for_content(content.content_id)?
            {
                riferimenti.push(LedgerTaxonomyReference {
                    content_id: content.content_id,
                    term: associazione.term().normalised().to_owned(),
                    term_category: associazione.term().category().to_owned(),
                    technique: associazione.technique().as_str().to_owned(),
                    technique_name: associazione.technique_name().to_owned(),
                    attack_version: associazione.attack_version().to_owned(),
                    deprecated: associazione.is_deprecated(),
                    revoked: associazione.is_revoked(),
                    reason: associazione.reason().to_owned(),
                    declared_by: associazione.declared_by().as_str().to_owned(),
                    declared_at: associazione.declared_at(),
                });
            }
        }

        let oltre = riferimenti
            .len()
            .saturating_sub(MAX_TAXONOMY_REFERENCES_IN_DOCUMENT);
        riferimenti.truncate(MAX_TAXONOMY_REFERENCES_IN_DOCUMENT);
        Ok((riferimenti, oltre))
    }

    /// Le fotografie dei cataloghi ufficiali che l'archivio conserva.
    ///
    /// # Perché tutte e non «quella in vigore»
    ///
    /// Perché «in vigore» sarebbe una semantica che il prodotto non ha: le
    /// fotografie di CVE coprono anni diversi e convivono, e sceglierne una
    /// direbbe a chi legge che le altre non contano. Il documento riporta ciò
    /// che l'archivio **ha**, e ciascuna porta la propria data.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'archivio non è leggibile.
    fn ledger_official_sources(&self) -> ServiceResult<Vec<LedgerOfficialSource>> {
        let mut fonti = Vec::new();

        for fotografia in self.database.attack_snapshots()? {
            fonti.push(LedgerOfficialSource {
                catalogue: String::from("MITRE ATT&CK"),
                identity: format!(
                    "dominio {}, versione {}, specifica {}",
                    fotografia.domain, fotografia.attack_version, fotografia.spec_version
                ),
                imported_by: fotografia.imported_by.as_str().to_owned(),
                imported_at: fotografia.imported_at,
                digest: Some(fotografia.source_sha256.as_str().to_owned()),
                counts: format!(
                    "{} tecniche e {} tattiche.",
                    fotografia.technique_count, fotografia.tactic_count
                ),
                attribution: fotografia.attribution,
            });
        }

        for fotografia in self.database.cve_snapshots()? {
            fonti.push(LedgerOfficialSource {
                catalogue: String::from("CVE"),
                identity: format!(
                    "fonte {}, {}",
                    fotografia.source,
                    fotografia.coverage.as_sentence()
                ),
                imported_by: fotografia.imported_by.as_str().to_owned(),
                imported_at: fotografia.imported_at,
                // LE FOTOGRAFIE CVE NON PORTANO UN'IMPRONTA UNICA: ne portano
                // una per anno acquisito, e comporne una sola qui sarebbe
                // inventare un numero che nessuno ha calcolato.
                digest: None,
                counts: format!("{} voci.", fotografia.record_count),
                attribution: fotografia.attribution,
            });
        }

        for fotografia in self.database.kev_snapshots()? {
            fonti.push(LedgerOfficialSource {
                catalogue: String::from("CISA KEV"),
                identity: format!(
                    "catalogo versione {}, rilasciato il {}",
                    fotografia.catalog.version(),
                    fotografia.catalog.released_at()
                ),
                imported_by: fotografia.imported_by.as_str().to_owned(),
                imported_at: fotografia.imported_at,
                digest: Some(fotografia.acquired_sha256),
                counts: format!(
                    "{} voci acquisite, {} dichiarate dal catalogo, {} lasciate fuori.",
                    fotografia.entry_count, fotografia.declared_count, fotografia.omitted_count
                ),
                attribution: fotografia.attribution,
            });
        }

        Ok(fonti)
    }

    /// Le annotazioni scritte sulle cose che il documento rappresenta.
    ///
    /// # Perché contenuti e fonti, e non tutto l'archivio
    ///
    /// Perché una nota su un rapporto diverso o su un raccoglitore che questo
    /// monitoraggio non ha toccato non ha nulla a cui riferirsi qui: entrerebbe
    /// in un atto che non la riguarda. Le cose che il documento rappresenta sono
    /// i suoi contenuti e le sue fonti, e sono quelle di cui si riportano le
    /// annotazioni.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'archivio non è leggibile.
    fn ledger_notes(
        &self,
        contents: &[LedgerContent],
        session_id: SessionId,
    ) -> ServiceResult<(Vec<LedgerNote>, usize)> {
        let mut note = Vec::new();

        for content in contents {
            let Ok(riferimento) = ArchiveRef::to(ArchiveRefKind::Content, content.content_id.get())
            else {
                continue;
            };
            for annotazione in self.database.notes_about(riferimento)? {
                note.push(Self::nota_del_documento(
                    &annotazione,
                    format!("il contenuto {}", content.content_id.get()),
                ));
            }
        }

        // LE FONTI SI LEGGONO DALL'ARCHIVIO e non dalle righe gia' composte:
        // quelle portano il nome, non l'identificativo, e una nota si riferisce
        // a un identificativo. Sono poche, ed e' una lettura per sessione.
        for source_id in self.database.session_source_ids(session_id)? {
            let Ok(riferimento) = ArchiveRef::to(ArchiveRefKind::Source, source_id.get()) else {
                continue;
            };
            let annotazioni = self.database.notes_about(riferimento)?;
            if annotazioni.is_empty() {
                continue;
            }
            let nome = self.database.source(source_id).map_or_else(
                |_| String::from("Fonte non più disponibile"),
                |fonte| fonte.display_name.as_str().to_owned(),
            );
            for annotazione in annotazioni {
                note.push(Self::nota_del_documento(
                    &annotazione,
                    format!("la fonte «{nome}»"),
                ));
            }
        }

        let oltre = note.len().saturating_sub(MAX_NOTES_IN_DOCUMENT);
        note.truncate(MAX_NOTES_IN_DOCUMENT);
        Ok((note, oltre))
    }

    /// I raccoglitori che contengono contenuti di questo monitoraggio.
    ///
    /// # Perché i conteggi vengono dalle righe già composte
    ///
    /// Perché è la stessa regola dei soggetti: due derivazioni della stessa cosa
    /// divergono, e un documento che dicesse quattro elementi in un posto e tre
    /// in un altro non sarebbe difendibile (ADR-0108, decisione 4).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'archivio non è leggibile.
    fn ledger_workspaces(
        &self,
        contents: &[LedgerContent],
    ) -> ServiceResult<(Vec<LedgerWorkspace>, usize)> {
        // QUANTI CONTENUTI DI QUESTO MONITORAGGIO ha ciascun raccoglitore,
        // contati sulle righe che il documento porta gia'.
        let mut quanti: BTreeMap<i64, usize> = BTreeMap::new();
        for content in contents {
            for raccoglitore in self
                .database
                .workspaces_holding_content(content.content_id)?
            {
                *quanti.entry(raccoglitore.get()).or_default() += 1;
            }
        }

        let mut raccoglitori = Vec::new();
        for (identificativo, contenuti) in &quanti {
            let Ok(raccoglitore) = self.database.workspace(WorkspaceId::new(*identificativo))
            else {
                tracing::warn!(
                    raccoglitore = identificativo,
                    "raccoglitore non più leggibile: non entra nel documento"
                );
                continue;
            };

            raccoglitori.push(LedgerWorkspace {
                name: raccoglitore.name.as_str().to_owned(),
                description: raccoglitore
                    .description
                    .as_ref()
                    .map(|scopo| scopo.as_str().to_owned()),
                created_by: raccoglitore.created_by.as_str().to_owned(),
                created_at: raccoglitore.created_at,
                open: raccoglitore.accepts_items(),
                contents_here: *contenuti,
            });
        }

        let oltre = raccoglitori
            .len()
            .saturating_sub(MAX_WORKSPACES_IN_DOCUMENT);
        raccoglitori.truncate(MAX_WORKSPACES_IN_DOCUMENT);
        Ok((raccoglitori, oltre))
    }

    /// Gli avvisi emessi durante la sessione.
    fn ledger_alerts(&self, session_id: SessionId) -> ServiceResult<Vec<LedgerAlert>> {
        Ok(self
            .database
            .session_alerts(session_id)?
            .into_iter()
            .map(|alert| LedgerAlert {
                content_id: alert.content_id,
                level: alert.level.get(),
                reason: alert.reason.as_str().to_owned(),
                raised_at: alert.raised_at,
            })
            .collect())
    }

    /// Le decisioni umane sui contenuti fotografati.
    ///
    /// Si scorrono i contenuti della fotografia e non l'intero archivio: una
    /// revisione su un contenuto di un'altra sessione non riguarda questo
    /// registro.
    fn ledger_reviews(&self, snapshot: &ReportSnapshot) -> ServiceResult<Vec<LedgerReview>> {
        let mut reviews = Vec::new();
        for photographed in &snapshot.contents {
            for review in self.database.content_reviews(photographed.content_id)? {
                reviews.push(LedgerReview {
                    content_id: review.content_id,
                    state: review.state.label().to_owned(),
                    note: review.note.as_ref().map(|note| note.as_str().to_owned()),
                    actor: review.reviewer.as_str().to_owned(),
                    decided_at: review.decided_at,
                });
            }
        }
        Ok(reviews)
    }

    /// Le anomalie tecniche registrate durante la sessione.
    fn ledger_faults(&self, session_id: SessionId) -> ServiceResult<Vec<LedgerFault>> {
        Ok(self
            .database
            .session_faults(session_id)?
            .into_iter()
            .map(|fault| LedgerFault {
                kind: fault.kind.label().to_owned(),
                detail: fault.message.as_str().to_owned(),
                happened_at: fault.occurred_at,
            })
            .collect())
    }

    /// I fatti della sessione che la relazione descrive.
    fn narrative_session(&self, session_id: SessionId) -> ServiceResult<NarrativeSession> {
        let session = self.database.session(session_id)?;
        Ok(NarrativeSession {
            pauses: self.pauses_in_words(session_id)?,
            label: session.label.as_str().to_owned(),
            // Una sessione mai avviata non ha un inizio proprio: si usa
            // l'istante di creazione, che e' il primo fatto documentabile.
            started_at: session.started_at.unwrap_or(session.created_at),
            ended_at: session.ended_at,
            // L'account d'ufficio, com'era quando il monitoraggio è nato
            // (MULTI-ACCOUNT-02, ADR-0173).
            account: self
                .database
                .session_account(session_id)?
                .map(|legame| legame.account_label.as_str().to_owned()),
            // Soltanto le osservazioni di profilo che l'operatore ha scelto
            // (PERSON-MEDIA-01 parte 3, ADR-0174): per difetto nessuna.
            profile_observations: self
                .database
                .chosen_profile_media_for_session(session_id)?
                .into_iter()
                .map(
                    |osservazione| crate::report_narrative::NarrativeProfileObservation {
                        requested_at: osservazione.requested_at,
                        requested_by: osservazione.requested_by,
                        reason: osservazione.reason,
                        author_identifier: osservazione.author_identifier,
                        status: osservazione
                            .status
                            .as_deref()
                            .map_or_else(String::new, |chiave| {
                                crate::profile_media::status_in_words(
                                    chiave,
                                    osservazione.status_was_online,
                                )
                            }),
                        bio: osservazione.bio,
                        photo_sha256: osservazione.photo_sha256,
                    },
                )
                .collect(),
        })
    }

    /// Che cosa la postazione ha guardato, fonte per fonte, sulla finestra del
    /// monitoraggio e alla fotografia della richiesta (PR-05, ADR-0121).
    fn coverage_lines(
        &self,
        session_id: SessionId,
        until: Timestamp,
    ) -> ServiceResult<Vec<crate::coverage::CoverageLine>> {
        let copertura = crate::coverage::for_monitoring(&self.database, session_id, until)?;
        Ok(copertura
            .sources
            .into_iter()
            .map(|(_, source, coverage)| crate::coverage::CoverageLine { source, coverage })
            .collect())
    }

    /// Le fonti monitorate, con quanto ciascuna ha prodotto.
    fn narrative_sources(&self, session_id: SessionId) -> ServiceResult<Vec<NarrativeSource>> {
        let contents = self.database.session_contents(session_id)?;

        let mut sources = Vec::new();
        for source_id in self.database.session_source_ids(session_id)? {
            let acquired = contents
                .iter()
                .filter(|content| content.source_id == source_id)
                .count();
            // Una fonte rimossa non fa sparire cio' che era stato acquisito
            // attraverso di essa: il documento la nomina come non piu'
            // disponibile invece di ometterla.
            let label = self.database.source(source_id).map_or_else(
                |_| {
                    format!(
                        "Fonte non più disponibile (identificativo {})",
                        source_id.get()
                    )
                },
                |source| source.display_name.as_str().to_owned(),
            );
            // LA VALUTAZIONE DELL'UFFICIO SULLA FONTE (ADR-0167): in vigore adesso,
            // attribuita a chi l'ha data. Una lettura che non riesce non la inventa.
            let reliability =
                crate::source_reliability::current_sentence(&self.database, source_id)
                    .ok()
                    .flatten();
            sources.push(NarrativeSource {
                label,
                acquired,
                reliability,
            });
        }
        Ok(sources)
    }

    /// Gli elementi selezionati, risolti dall'archivio.
    ///
    /// **Solo quelli selezionati**, ed e' il criterio 5: la fotografia dice
    /// quali sono, e da li' si parte. Un contenuto non piu' leggibile viene
    /// saltato con una riga di registro invece di far fallire l'intera
    /// generazione — ma il numero dei selezionati nel documento viene dalla
    /// fotografia, quindi la differenza resta visibile.
    fn narrative_findings(
        &self,
        snapshot: &ReportSnapshot,
    ) -> ServiceResult<Vec<NarrativeFinding>> {
        let contents = self.database.session_contents(snapshot.session_id)?;
        // Il modo di acquisizione di ogni contenuto, alla fotografia (PR-07).
        let modi = crate::acquisition_mode::for_session(
            &self.database,
            snapshot.session_id,
            snapshot.taken_at,
        )?;

        // La stessa lettura in blocco del registro: due interrogazioni per la
        // sessione, i corpi non si toccano.
        let storia = self.database.session_content_history(snapshot.session_id)?;

        // Gli stessi conteggi del registro: i contorni si leggono solo per i
        // contenuti che ne hanno.
        let quante_fotografie = self
            .database
            .session_context_snapshot_counts(snapshot.session_id)?;

        let mut findings = Vec::new();
        for photographed in snapshot.contents.iter().filter(|entry| entry.selected) {
            let Some(content) = contents
                .iter()
                .find(|content| content.id == photographed.content_id)
            else {
                tracing::warn!(
                    contenuto = photographed.content_id.get(),
                    "contenuto selezionato non più leggibile: non entra nella relazione"
                );
                continue;
            };

            let source_label = self.database.source(content.source_id).map_or_else(
                |_| String::from("Fonte non più disponibile"),
                |source| source.display_name.as_str().to_owned(),
            );

            let (revisions, revisions_beyond) = self.revisioni_del_contenuto(
                content.id,
                storia.get(&content.id.get()).is_some_and(
                    lisi_core::model::content_history::ContentHistorySummary::was_revised,
                ),
            );
            let (contexts, contexts_beyond) = self.contorni_del_contenuto(
                content.id,
                quante_fotografie.get(&content.id.get()).copied(),
            );

            findings.push(NarrativeFinding {
                content_id: content.id,
                source_label,
                published_at: content.published_at,
                acquired_at: content.acquired_at,
                recovered: modi
                    .get(&content.id.get())
                    .is_some_and(lisi_core::model::AcquisitionMode::is_recovered),
                url: content.url.as_ref().map(|url| url.as_str().to_owned()),
                asked_link: None,
                attachment: crate::attachment_keeping::describe(&self.database, content.id)?,
                body: content.body.as_str().to_owned(),
                // Il livello e lo stato della revisione vengono dalla
                // FOTOGRAFIA e non dall'archivio: e' il valore di allora, ed e'
                // la ragione per cui la fotografia esiste (DEC-152).
                level: photographed.level,
                engine_reason: self
                    .database
                    .content_alert(content.id)?
                    .map(|alert| alert.reason.as_str().to_owned()),
                review_state: photographed.review_state,
                // IL MOTIVO DELLA REVISIONE FOTOGRAFATA (E2E01-12): quella decisa
                // entro l'istante della fotografia, e solo se ha lo stato
                // fotografato. Una revisione successiva non cambia il documento.
                review_note: self
                    .database
                    .review_as_of(content.id, snapshot.taken_at)?
                    .filter(|review| Some(review.state) == photographed.review_state)
                    .and_then(|review| review.note.map(|nota| nota.as_str().to_owned())),
                after_acquisition: storia.get(&content.id.get()).and_then(
                    lisi_core::model::content_history::ContentHistorySummary::short_label,
                ),
                revisions,
                revisions_beyond,
                contexts,
                contexts_beyond,
                acquisition_mode: modi.get(&content.id.get()).map_or_else(
                    || lisi_core::model::AcquisitionMode::Undetermined.as_sentence(),
                    crate::acquisition_mode::declared,
                ),
            });
        }
        Ok(findings)
    }

    /// Una nota dell'archivio, come il documento la porta.
    ///
    /// # Perché il ritiro diventa una coppia e non resta un tipo
    ///
    /// Perché il registro e l'allegato non devono conoscere la forma del ritiro:
    /// devono sapere **chi** e **quando**, che è tutto ciò che stampano. Il tipo del
    /// dominio resta dove le regole vivono.
    fn nota_del_documento(note: &OperatorNote, about: String) -> LedgerNote {
        LedgerNote {
            about,
            body: note.body.as_str().to_owned(),
            author: note.author.as_str().to_owned(),
            written_at: note.written_at,
            withdrawal: note
                .withdrawal
                .as_ref()
                .map(|ritiro| (ritiro.by.as_str().to_owned(), ritiro.at)),
        }
    }

    /// Registra il fallimento senza sostituire l'errore che lo ha causato.
    ///
    /// Se anche la registrazione fallisce, resta una riga di registro: l'errore
    /// da riportare all'operatore e' il primo, non il secondo.
    fn fail_quietly(
        &self,
        package_id: ReportPackageId,
        reason: &str,
        request: &ReportGenerationRequest<'_>,
    ) {
        if let Err(error) = self.fail(
            package_id,
            reason,
            &request.requested_by,
            request.requested_at,
        ) {
            tracing::error!(
                errore = error.kind(),
                "fallimento della generazione non registrato"
            );
        }
    }

    /// Fotografa i dati della sessione con cui il pacchetto sara' prodotto.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::ReportSelectionOutsideSession`] se la selezione contiene
    /// contenuti che la sessione non ha monitorato.
    pub fn take_snapshot(
        &self,
        session_id: SessionId,
        selection: &ReportSelection,
        template_version: u32,
        now: Timestamp,
    ) -> ServiceResult<ReportSnapshot> {
        let contents = self.database.session_contents(session_id)?;

        let mut snapshot_contents = Vec::with_capacity(contents.len());
        for content in &contents {
            // Lo stato della revisione **al momento della generazione**: e' il
            // valore che domani potrebbe essere diverso, ed e' per questo che
            // si conserva qui invece di rileggerlo dal vivo.
            let review_state = self
                .database
                .latest_review(content.id)?
                .map(|review| review.state);

            snapshot_contents.push(ReportContentSnapshot {
                content_id: content.id,
                level: content.analysis_level,
                review_state,
                body_sha256: content.body_sha256.clone(),
                selected: selection.contains(content.id),
            });
        }

        // Un contenuto selezionato che la sessione non ha monitorato non e' un
        // dettaglio da assorbire: significherebbe rappresentare in una
        // relazione qualcosa che questa attivita' non ha osservato.
        let monitored = snapshot_contents.len();
        let selected_here = snapshot_contents
            .iter()
            .filter(|content| content.selected)
            .count();
        if selected_here != selection.len() {
            return Err(ServiceError::ReportSelectionOutsideSession);
        }
        debug_assert!(selected_here <= monitored);

        let source_ids = self.database.session_source_ids(session_id)?;
        let dictionary_version_ids = self.database.session_dictionary_version_ids(session_id)?;

        Ok(ReportSnapshot {
            taken_at: now,
            session_id,
            source_ids,
            dictionary_version_ids,
            template_version,
            contents: snapshot_contents,
        })
    }

    /// Registra un artefatto prodotto, con la sua impronta.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::Storage`] se la registrazione non riesce.
    pub fn record_artifact(
        &self,
        package_id: ReportPackageId,
        artifact: &NewReportArtifact,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<ReportArtifactId> {
        let id = self
            .database
            .record_report_artifact(package_id, artifact, now)?;

        self.record_audit(
            actor,
            ACTION_ARTIFACT,
            package_id.get(),
            Some(&format!(
                "{}; {} byte; impronta {}",
                artifact.kind.as_str(),
                artifact.size_bytes,
                artifact.sha256.as_str()
            )),
            now,
        )?;

        Ok(id)
    }

    /// Scrive un artefatto sul disco **e** lo registra, in quest'ordine.
    ///
    /// # Perche' le due cose stanno in un metodo solo
    ///
    /// Un file scritto e non registrato e' un documento che il pacchetto non
    /// dichiara; una registrazione senza file e' un pacchetto che dichiara un
    /// documento che non c'e'. Sono due divergenze diverse e ugualmente
    /// difficili da spiegare a chi riceve il pacchetto, e l'unico modo per non
    /// doverle spiegare e' non lasciare a chi chiama la scelta di fare solo una
    /// delle due.
    ///
    /// L'ordine e' quello: **prima il disco**. Se la registrazione fallisce
    /// resta un file in piu' dentro una cartella che non verra' chiusa da un
    /// manifest, quindi riconoscibile come incompleta. All'inverso resterebbe un
    /// pacchetto che dichiara un documento inesistente, e il manifest lo
    /// direbbe integro.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::ExportNotWritten`] se il file non si scrive e
    /// [`ServiceError::Storage`] se la registrazione non riesce.
    pub fn write_artifact(
        &self,
        package_id: ReportPackageId,
        writer: &mut PackageWriter,
        kind: lisi_core::model::report::ReportArtifactKind,
        bytes: &[u8],
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<ReportArtifactId> {
        let artifact = writer.write(kind, bytes)?;
        self.record_artifact(package_id, &artifact, actor, now)
    }

    /// Chiude il pacchetto: scrive il manifest e lo dichiara completo.
    ///
    /// L'ordine non e' negoziabile e vale il criterio 19: **il manifest e'
    /// l'ultimo file**, e lo stato `completed` arriva dopo che c'e'. Se il
    /// manifest non si scrive, il pacchetto resta `generating` e la cartella
    /// resta senza manifest: due segnali indipendenti che dicono la stessa cosa
    /// a chi guarda l'archivio e a chi guarda il disco.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::ExportNotWritten`] se il manifest non si
    /// scrive e [`ServiceError::Storage`] se l'aggiornamento non riesce.
    pub fn seal(
        &self,
        package_id: ReportPackageId,
        writer: PackageWriter,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<PackageOutcome> {
        let outcome = writer.finish(actor, now)?;
        self.complete(package_id, actor, now)?;
        Ok(outcome)
    }

    /// Annulla una generazione: toglie i file scritti e dichiara il fallimento.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::Storage`] se l'aggiornamento non riesce. La
    /// pulizia del disco non produce errori: l'errore da riportare e' quello che
    /// ha causato l'annullamento, non l'esito della pulizia.
    pub fn discard(
        &self,
        package_id: ReportPackageId,
        writer: PackageWriter,
        reason: &str,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<usize> {
        let removed = writer.abort();
        self.fail(package_id, reason, actor, now)?;
        Ok(removed)
    }

    /// Dichiara il pacchetto completo e consegnabile.
    ///
    /// Si chiama **dopo** che il manifest e' stato scritto: e' l'ultimo file
    /// del pacchetto, ed e' il segnale che distingue un pacchetto completo da
    /// uno interrotto a meta'.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::Storage`] se l'aggiornamento non riesce.
    pub fn complete(
        &self,
        package_id: ReportPackageId,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.database.set_report_package_status(
            package_id,
            ReportGenerationStatus::Completed,
            Some(now),
        )?;
        self.record_audit(actor, ACTION_COMPLETED, package_id.get(), None, now)
    }

    /// Dichiara la generazione non riuscita.
    ///
    /// Il motivo entra nell'audit perche' e' cio' che permette di capire in
    /// seguito perche' un pacchetto non c'e'. Deve essere una **ragione**, non
    /// il contenuto di cio' che si stava scrivendo.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::Storage`] se l'aggiornamento non riesce.
    pub fn fail(
        &self,
        package_id: ReportPackageId,
        reason: &str,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.database.set_report_package_status(
            package_id,
            ReportGenerationStatus::Failed,
            None,
        )?;
        self.record_audit(actor, ACTION_FAILED, package_id.get(), Some(reason), now)
    }

    /// Pacchetto con i suoi artefatti.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::Storage`] se il pacchetto non esiste.
    pub fn package(&self, package_id: ReportPackageId) -> ServiceResult<ReportPackage> {
        Ok(self.database.report_package(package_id)?)
    }

    /// La fotografia con cui il pacchetto e' stato prodotto.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::Storage`] se il pacchetto non esiste.
    pub fn snapshot(&self, package_id: ReportPackageId) -> ServiceResult<ReportSnapshot> {
        Ok(self.database.report_snapshot(package_id)?)
    }

    /// Registra una voce di audit del reporting.
    fn record_audit(
        &self,
        actor: &Actor,
        action: &str,
        entity_id: i64,
        detail: Option<&str>,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let detail = match detail {
            Some(text) if !text.trim().is_empty() => Some(AuditDetail::try_new(text)?),
            _ => None,
        };

        let entry = NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new(action)?,
            entity: AuditEntity::try_new(ENTITY_REPORT)?,
            entity_id: Some(entity_id),
            // Il reporting non conosce la modalita' operativa, che vive nel
            // servizio dei dizionari: `None` significa «non registrata».
            actor_mode: None,
            detail,
            recorded_at: now,
        };

        self.database.append_audit(&entry)?;
        Ok(())
    }
}

/// Filtra i generi richiesti tenendo l'ordine di [`PRODUCIBLE_KINDS`].
///
/// # Perche' un genere non producibile e' un rifiuto e non un silenzio
///
/// Ignorarlo produrrebbe un pacchetto privo di un documento che l'operatore
/// crede di aver chiesto, con un manifest che lo dichiara completo. Un rifiuto
/// costa un messaggio; un silenzio costa la fiducia nel manifest.
fn producible(requested: &[ReportArtifactKind]) -> ServiceResult<Vec<ReportArtifactKind>> {
    if let Some(unsupported) = requested
        .iter()
        .find(|kind| !PRODUCIBLE_KINDS.contains(kind))
    {
        return Err(ServiceError::DocumentGeneration {
            reason: format!("{} non è prodotto da questa versione", unsupported.as_str()),
        });
    }

    let mut kinds: Vec<ReportArtifactKind> = PRODUCIBLE_KINDS
        .iter()
        .filter(|kind| requested.contains(kind))
        .copied()
        .collect();
    kinds.dedup();

    if kinds.is_empty() {
        return Err(ServiceError::DocumentGeneration {
            reason: String::from("nessun documento richiesto"),
        });
    }
    Ok(kinds)
}

/// Se l'errore dice che l'identificativo citabile e' gia' in uso.
fn is_duplicate_identifier(error: &ServiceError) -> bool {
    matches!(
        error,
        ServiceError::Storage(lisi_storage::StorageError::DuplicateReportId)
    )
}

/// Stato della revisione di un contenuto, per chi compone i documenti.
///
/// Esiste perche' i renderer non debbano conoscere l'assenza: un contenuto mai
/// preso in carico non ha una revisione, e dirlo con una frase e' meglio che
/// lasciare un vuoto in un documento.
#[must_use]
pub fn review_label(state: Option<ReviewState>) -> &'static str {
    match state {
        None => "non ancora esaminato",
        Some(ReviewState::New) => "non ancora esaminato",
        Some(ReviewState::InReview) => "in esame",
        Some(ReviewState::Relevant) => "confermato rilevante",
        Some(ReviewState::NotRelevant) => "giudicato non rilevante",
        Some(ReviewState::Duplicate) => "ripetizione di un contenuto già valutato",
        Some(ReviewState::Archived) => "concluso e messo da parte",
        Some(ReviewState::Reported) => "portato all'attenzione di terzi",
    }
}

/// Da dove venivano i termini che hanno prodotto il livello di un contenuto.
///
/// Restituisce `None` quando non ci sono riscontri: su un contenuto in cui
/// nessun termine è comparso non c'è provenienza da dichiarare.
///
/// # Perché la frase cambia quando la fotografia manca
///
/// Perché senza la fotografia della sessione si sa **che cosa** fu trovato ma
/// non **da dove veniva**, e i dizionari di oggi non lo dicono: un dizionario
/// può essere stato modificato, archiviato o sostituito dopo. Nominarli
/// attribuirebbe il risultato a una configurazione che potrebbe non essere
/// quella che lo produsse — che è precisamente la falsa spiegazione che questo
/// prodotto rifiuta di dare.
fn analysis_origin(
    matches: &[lisi_core::model::ContentMatch],
    configuration: Option<&lisi_core::model::dictionary::ResolvedDictionaryConfiguration>,
) -> Option<String> {
    if matches.is_empty() {
        return None;
    }

    let Some(configuration) = configuration else {
        return Some(String::from(
            "I termini che hanno prodotto questo livello risultano dai riscontri \
             registrati. L'elenco dei termini con cui il monitoraggio fu condotto, però, \
             non è più conservato. Non è possibile dire da quale dizionario e da quale \
             versione provenissero. Il livello registrato resta quello attribuito \
             allora.",
        ));
    };

    // I dizionari nominati una volta sola, in ordine, come l'operatore li
    // conosce. Un termine che la fotografia non conosce non porta provenienza:
    // si conta, e la frase lo dichiara invece di far credere completo un
    // elenco che non lo e'.
    let mut dizionari: Vec<String> = Vec::new();
    let mut senza_provenienza = 0_usize;

    for entry in matches {
        let normalised = entry.rule_id.as_str();
        let Some(term) = configuration
            .terms
            .iter()
            .find(|term| term.normalised == normalised)
        else {
            senza_provenienza += 1;
            continue;
        };

        for provenance in &term.provenances {
            if !dizionari.contains(&provenance.label) {
                dizionari.push(provenance.label.clone());
            }
        }
    }

    dizionari.sort_unstable();

    let mut frase = if dizionari.is_empty() {
        String::from(
            "Nessuno dei termini riscontrati risulta nell'elenco conservato con la sessione.",
        )
    } else {
        format!(
            "I termini che hanno prodotto questo livello provenivano da: {}. \
             È l'elenco conservato con la sessione, non i dizionari correnti.",
            dizionari.join("; ")
        )
    };

    if senza_provenienza > 0 {
        frase.push_str(&format!(
            " Per {senza_provenienza} riscontro/i l'elenco della sessione non riporta il \
             termine: di quelli si sa che furono trovati, non da dove venissero."
        ));
    }

    Some(frase)
}

#[cfg(test)]
mod tests {
    use lisi_core::digest::Sha256Digest;
    use lisi_core::model::dictionary::{
        ConfigurationResolver, MatchMode, ResolvedDictionaryConfiguration, TermProvenance,
    };
    use lisi_core::model::report::{
        NewReportArtifact, ReportArtifactKind, ReportId, ReportOutcome, ReportRequest,
        ReportSelection,
    };
    use lisi_core::model::report_template::ReportTemplateProfile;
    use lisi_core::model::{
        AcquisitionOrigin, NewReview, NewSession, NewSource, ReviewState, SessionDuration,
        SourceKind,
    };
    use lisi_core::text::{
        Actor, ContentBody, DisplayName, LanguageTag, RemoteMessageId, SourceIdentifier,
        TermCategory, TermText,
    };
    use lisi_core::{ContentId, SessionId, Timestamp};
    use lisi_storage::Database;

    use super::{ReportGenerationRequest, ReportService};
    use crate::analysis::{AnalysisService, NewContentDraft};
    use crate::error::ServiceError;
    use crate::sources::open_in_memory_database;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn later(seconds: i64) -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000 + seconds * 1_000)
    }

    fn operator() -> Actor {
        let Ok(value) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        value
    }

    fn configuration() -> ResolvedDictionaryConfiguration {
        let mut resolver = ConfigurationResolver::new();
        let (Ok(text), Ok(category), Ok(language)) = (
            TermText::try_new("molotov"),
            TermCategory::try_new("oggetto"),
            LanguageTag::try_new("it"),
        ) else {
            panic!("i valori del termine devono essere validi");
        };
        let Ok(()) = resolver.add(
            text,
            category,
            language,
            MatchMode::NormalizedWord,
            3,
            TermProvenance::ad_hoc(),
        ) else {
            panic!("il termine doveva essere accettato");
        };
        resolver.finish()
    }

    /// Archivio con una sessione e tre contenuti acquisiti.
    fn archive() -> (Database, SessionId, Vec<ContentId>) {
        let Ok(mut database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };

        let (Ok(identifier), Ok(title), Ok(label)) = (
            SourceIdentifier::try_new("canale_uno"),
            DisplayName::try_new("Canale di prova"),
            DisplayName::try_new("Sessione di prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(source_id) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier,
                display_name: title,
                authorized_by: operator(),
                active: true,
            },
            now(),
        ) else {
            panic!("la fonte deve potersi registrare");
        };
        let Ok(session_id) = database.insert_session(
            &NewSession {
                label,
                started_by: operator(),
                duration: SessionDuration::Preset { seconds: 3_600 },
                source_ids: vec![source_id],
            },
            now(),
        ) else {
            panic!("la sessione deve potersi creare");
        };

        let configuration = configuration();
        let mut analysis = AnalysisService::new(database);
        let mut contents = Vec::new();
        for (index, body) in ["una molotov", "buongiorno a tutti", "nulla di che"]
            .iter()
            .enumerate()
        {
            let Ok(index) = i64::try_from(index) else {
                panic!("l'indice deve stare in un intero");
            };
            let (Ok(remote), Ok(body)) = (
                RemoteMessageId::try_new(&format!("m{index}")),
                ContentBody::try_new(body),
            ) else {
                panic!("i valori del contenuto devono essere validi");
            };
            let Ok(outcome) = analysis.analyse_and_record(
                &NewContentDraft {
                    session_id,
                    source_id,
                    remote_message_id: remote,
                    author: None,
                    author_identifier: None,
                    author_username: None,
                    body,
                    url: None,
                    published_at: now(),
                    acquired_at: now(),
                    origin: AcquisitionOrigin::Observed,
                },
                &configuration,
                &operator(),
                now(),
            ) else {
                panic!("il contenuto deve potersi registrare");
            };
            let Some(content_id) = outcome.content_id else {
                panic!("il contenuto di prova non deve risultare duplicato");
            };
            contents.push(content_id);
        }

        (analysis.into_database(), session_id, contents)
    }

    fn request(session_id: SessionId, selection: ReportSelection, sequence: u32) -> ReportRequest {
        ReportRequest {
            report_id: ReportId::from_sequence(2026, sequence),
            session_id,
            requested_by: operator(),
            selection,
            requested_kinds: vec![ReportArtifactKind::NarrativeDocx],
            template_version: 1,
            requested_at: now(),
        }
    }

    #[test]
    fn il_registro_non_porta_le_parole_conservate() {
        // Lo stato della sessione e il genere della fonte arrivavano al registro
        // nella forma con cui l'archivio li conserva: `running` dove lo schermo
        // dice «In corso», `channel` dove dice «Canale»
        // (FINAL-PRODUCT-REVIEW-01, FPR-02). Il registro esce dall'ufficio
        // allegato a una relazione di servizio, e chi lo legge non deve
        // tradurre lo schema del programma.
        let (database, session_id, _) = archive();
        let service = ReportService::new(database);

        let (Ok(sessione), Ok(fonti)) = (
            service.ledger_session(session_id),
            service.ledger_sources(session_id),
        ) else {
            panic!("i fatti del registro devono potersi leggere");
        };
        let Ok(vera) = service.database.session(session_id) else {
            panic!("la sessione deve potersi rileggere");
        };

        assert_eq!(sessione.state, vera.state.label());
        assert_eq!(fonti.len(), 1, "la prova prepara una fonte sola");
        assert_eq!(fonti[0].kind, "Canale");

        // Nessuna delle chiavi conservate arriva al documento.
        for chiave in [
            "planned",
            "running",
            "paused",
            "completed",
            "stopped",
            "channel",
            "group",
            "supergroup",
        ] {
            assert_ne!(sessione.state, chiave, "lo stato è ancora una chiave");
            assert!(
                fonti.iter().all(|fonte| fonte.kind != chiave),
                "il genere della fonte è ancora una chiave: «{chiave}»"
            );
        }
    }

    /// **La relazione prende l'account dal legame del monitoraggio**
    /// (MULTI-ACCOUNT-02 parte 3). Prova negativa: il legame non letto → rossa.
    #[test]
    fn la_relazione_prende_l_account_dal_legame_del_monitoraggio() {
        let (database, session_id, _) = archive();
        let service = ReportService::new(database);
        let Ok(sessione) = service.narrative_session(session_id) else {
            panic!("i fatti della sessione si leggono");
        };
        assert_eq!(sessione.account, None, "senza legame, nessun account");
        let Ok(nome) = lisi_core::text::DisplayName::try_new("Ufficio A") else {
            panic!("nome valido");
        };
        let Ok(()) = service.database.insert_session_account(
            session_id,
            &lisi_core::model::AccountUuid::from_bytes([0xa1; 16]),
            &nome,
            now(),
        ) else {
            panic!("il legame si registra");
        };
        let Ok(sessione) = service.narrative_session(session_id) else {
            panic!("i fatti della sessione si leggono");
        };
        assert_eq!(sessione.account.as_deref(), Some("Ufficio A"));
    }

    /// **Nella relazione entrano soltanto le osservazioni scelte**
    /// (PERSON-MEDIA-01 parte 3). Prova negativa: la scelta non letta → rossa.
    #[test]
    fn nella_relazione_entrano_soltanto_le_osservazioni_scelte() {
        let (mut database, session_id, _) = archive();
        let audit = |quando: i64| lisi_core::model::NewAuditEntry {
            actor: operator(),
            action: lisi_core::text::AuditAction::try_new("profilo_chiesto")
                .unwrap_or_else(|_| panic!("azione valida")),
            entity: lisi_core::text::AuditEntity::try_new("profilo")
                .unwrap_or_else(|_| panic!("entità valida")),
            entity_id: None,
            detail: None,
            recorded_at: later(quando),
            actor_mode: None,
        };
        let osservazione =
            |quando: i64| lisi_storage::repository::profile_media::NewProfileMediaObservation {
                session_id,
                author_identifier: String::from("42"),
                account_uuid: None,
                requested_by: String::from("operatore.prova"),
                reason: String::from("Verifica dell'autore di un messaggio di minaccia"),
                requested_at: later(quando),
                outcome: String::from("osservato"),
                outcome_detail: None,
                bio: Some(format!("Biografia {quando}")),
                status: Some(String::from("di_recente")),
                status_was_online: None,
                photo: None,
                photo_not_read: None,
            };
        let (Ok(scelta), Ok(_altra)) = (
            database.insert_profile_media_observation(&osservazione(1), &audit(1)),
            database.insert_profile_media_observation(&osservazione(2), &audit(2)),
        ) else {
            panic!("le osservazioni si registrano");
        };
        let Ok(()) = database.insert_profile_media_mark(
            scelta,
            true,
            "operatore.prova",
            later(3),
            &audit(3),
        ) else {
            panic!("la scelta si registra");
        };
        let service = ReportService::new(database);
        let Ok(sessione) = service.narrative_session(session_id) else {
            panic!("i fatti della sessione si leggono");
        };
        assert_eq!(
            sessione
                .profile_observations
                .iter()
                .map(|o| o.bio.clone())
                .collect::<Vec<_>>(),
            vec![Some(String::from("Biografia 1"))]
        );
        assert_eq!(
            sessione
                .profile_observations
                .first()
                .map(|o| o.status.as_str()),
            Some("visto di recente")
        );
    }

    #[test]
    fn preparing_a_package_photographs_every_monitored_content() {
        let (database, session_id, contents) = archive();
        let mut service = ReportService::new(database);

        let selection = ReportSelection::from_contents([contents[0]]);
        let Ok(package_id) = service.prepare(&request(session_id, selection, 1)) else {
            panic!("il pacchetto deve potersi preparare");
        };

        let Ok(snapshot) = service.snapshot(package_id) else {
            panic!("la fotografia deve potersi rileggere");
        };
        assert_eq!(snapshot.monitored_count(), 3);
        assert_eq!(snapshot.selected_count(), 1);
        assert_eq!(snapshot.excluded_count(), 2);
        assert_eq!(snapshot.outcome(), ReportOutcome::WithFindings);
    }

    #[test]
    fn a_package_without_a_selection_photographs_everything_just_the_same() {
        // La relazione a esito negativo descrive comunque l'attivita' svolta:
        // per farlo servono tutti i contenuti, non nessuno.
        let (database, session_id, _) = archive();
        let mut service = ReportService::new(database);

        let Ok(package_id) = service.prepare(&request(session_id, ReportSelection::empty(), 2))
        else {
            panic!("il pacchetto senza selezione deve potersi preparare");
        };

        let Ok(snapshot) = service.snapshot(package_id) else {
            panic!("la fotografia deve potersi rileggere");
        };
        assert_eq!(snapshot.monitored_count(), 3);
        assert_eq!(snapshot.selected_count(), 0);
        assert_eq!(snapshot.outcome(), ReportOutcome::NothingSelected);
    }

    #[test]
    fn a_selection_outside_the_session_is_refused() {
        let (database, session_id, _) = archive();
        let mut service = ReportService::new(database);

        let estranged = ReportSelection::from_contents([ContentId::new(9_999)]);
        assert!(matches!(
            service.prepare(&request(session_id, estranged, 3)),
            Err(ServiceError::ReportSelectionOutsideSession)
        ));
    }

    #[test]
    fn the_snapshot_freezes_the_review_state_it_found() {
        // E' la ragione per cui la fotografia esiste. Si prepara un pacchetto
        // quando il contenuto non e' ancora stato esaminato, poi lo si giudica
        // non rilevante: la fotografia deve continuare a dire come stava
        // ALLORA, altrimenti un report vecchio racconterebbe un archivio che
        // non e' quello con cui e' stato prodotto.
        let (database, session_id, contents) = archive();
        let mut service = ReportService::new(database);

        let selection = ReportSelection::from_contents([contents[0]]);
        let Ok(package_id) = service.prepare(&request(session_id, selection, 4)) else {
            panic!("il pacchetto deve potersi preparare");
        };

        let Ok(before) = service.snapshot(package_id) else {
            panic!("la fotografia deve potersi rileggere");
        };
        let state_then = before
            .contents
            .iter()
            .find(|content| content.content_id == contents[0])
            .map(|content| content.review_state);

        let Ok(_) = service.database().insert_review(&NewReview {
            content_id: contents[0],
            state: ReviewState::NotRelevant,
            reviewer: operator(),
            note: None,
            decided_at: later(60),
        }) else {
            panic!("la revisione deve potersi registrare");
        };

        let Ok(after) = service.snapshot(package_id) else {
            panic!("la fotografia deve potersi rileggere");
        };
        let state_now = after
            .contents
            .iter()
            .find(|content| content.content_id == contents[0])
            .map(|content| content.review_state);

        assert_eq!(
            state_then, state_now,
            "la fotografia e' cambiata insieme all'archivio: non e' piu' una fotografia"
        );
        assert_ne!(state_now, Some(Some(ReviewState::NotRelevant)));
    }

    #[test]
    fn preparing_recording_and_completing_leave_a_trail_in_the_audit() {
        let (database, session_id, contents) = archive();
        let mut service = ReportService::new(database);

        let selection = ReportSelection::from_contents([contents[1]]);
        let Ok(package_id) = service.prepare(&request(session_id, selection, 5)) else {
            panic!("il pacchetto deve potersi preparare");
        };

        let artifact = NewReportArtifact {
            kind: ReportArtifactKind::NarrativeDocx,
            file_name: String::from("Relazione_R-2026-000005.docx"),
            size_bytes: 2048,
            sha256: Sha256Digest::of_text("documento di prova"),
        };
        let Ok(_) = service.record_artifact(package_id, &artifact, &operator(), later(10)) else {
            panic!("l'artefatto deve potersi registrare");
        };
        let Ok(()) = service.complete(package_id, &operator(), later(20)) else {
            panic!("il completamento deve potersi registrare");
        };

        let Ok(entries) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let actions: Vec<&str> = entries
            .iter()
            .map(|entry| entry.action.as_str())
            .filter(|action| action.starts_with("report."))
            .collect();
        assert!(actions.contains(&"report.preparato"));
        assert!(actions.contains(&"report.artefatto"));
        assert!(actions.contains(&"report.completato"));
    }

    #[test]
    fn the_audit_of_a_report_never_carries_the_body_of_a_message() {
        // Dove basta un identificativo o un numero si registra quello:
        // moltiplicare le copie di un testo monitorato moltiplica i posti da
        // proteggere (THREAT_MODEL_REPORTING, R-03).
        let (database, session_id, contents) = archive();
        let mut service = ReportService::new(database);

        let selection = ReportSelection::from_contents([contents[0]]);
        let Ok(_) = service.prepare(&request(session_id, selection, 6)) else {
            panic!("il pacchetto deve potersi preparare");
        };

        let Ok(entries) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        for entry in &entries {
            let detail = entry.detail.as_ref().map_or("", |value| value.as_str());
            assert!(
                !detail.contains("molotov"),
                "il corpo di un messaggio e' finito nell'audit: {detail}"
            );
        }
    }

    #[test]
    fn a_failed_package_is_not_deliverable_and_carries_no_completion() {
        let (database, session_id, _) = archive();
        let mut service = ReportService::new(database);

        let Ok(package_id) = service.prepare(&request(session_id, ReportSelection::empty(), 7))
        else {
            panic!("il pacchetto deve potersi preparare");
        };
        let Ok(()) = service.fail(package_id, "disco pieno", &operator(), later(5)) else {
            panic!("il fallimento deve potersi registrare");
        };

        let Ok(package) = service.package(package_id) else {
            panic!("il pacchetto deve potersi rileggere");
        };
        assert!(!package.status.is_deliverable());
        assert!(package.completed_at.is_none());
    }

    /// Compone e scrive la relazione vera per il pacchetto indicato.
    ///
    /// Sta qui e non nel modulo del pacchetto perche' e' l'unico punto in cui
    /// il documento vero, l'archivio e il disco si incontrano: se un giorno
    /// divergessero, il test che se ne accorge deve vederli tutti e tre.
    fn relazione_vera(report_id: &ReportId, session_id: SessionId) -> Vec<u8> {
        use crate::report_narrative::{NarrativeInput, NarrativeSession, compose};
        use lisi_core::model::report::ReportSnapshot;
        use lisi_core::model::report_template::ReportTemplateProfile;

        let profile = ReportTemplateProfile::default();
        let snapshot = ReportSnapshot {
            taken_at: now(),
            session_id,
            source_ids: Vec::new(),
            dictionary_version_ids: Vec::new(),
            template_version: 1,
            contents: Vec::new(),
        };
        let session = NarrativeSession {
            pauses: Vec::new(),
            label: String::from("Sessione di prova"),
            started_at: now(),
            ended_at: Some(later(3_600)),
            account: None,
            profile_observations: Vec::new(),
        };
        let report = compose(&NarrativeInput {
            report_id,
            profile: &profile,
            snapshot: &snapshot,
            operator: &operator(),
            generated_at: later(10),
            session: &session,
            sources: &[],
            findings: &[],
            coverage: &[],
            faults: &[],
            configuration: &crate::analysis_configuration::AnalysisConfiguration::unknown(),
        });

        let Ok(bytes) = crate::report_docx::render(&report) else {
            panic!("la relazione deve potersi scrivere");
        };
        bytes
    }

    #[test]
    fn a_sealed_package_agrees_with_the_archive_and_with_the_disk() {
        // Criteri 11 e 12 percorsi per intero: si prepara, si scrive la
        // relazione **vera**, si sigilla, e poi si chiede a tre fonti diverse
        // se dicono la stessa cosa.
        use crate::report_package::{PackageWriter, verify_package_manifest};

        let (database, session_id, contents) = archive();
        let mut service = ReportService::new(database);
        let cartella = tempfile::tempdir().expect("cartella temporanea");

        let selection = ReportSelection::from_contents([contents[0]]);
        let richiesta = request(session_id, selection, 8);
        let report_id = richiesta.report_id.clone();
        let Ok(package_id) = service.prepare(&richiesta) else {
            panic!("il pacchetto deve potersi preparare");
        };

        let mut writer =
            PackageWriter::create(cartella.path(), &report_id).expect("cartella del pacchetto");
        let documento = relazione_vera(&report_id, session_id);
        let Ok(_) = service.write_artifact(
            package_id,
            &mut writer,
            ReportArtifactKind::NarrativeDocx,
            &documento,
            &operator(),
            later(10),
        ) else {
            panic!("l'artefatto deve potersi scrivere e registrare");
        };
        let Ok(outcome) = service.seal(package_id, writer, &operator(), later(20)) else {
            panic!("il pacchetto deve potersi sigillare");
        };

        // 1. Il disco: il manifest c'e' e i file corrispondono alle impronte.
        let verifica = verify_package_manifest(&outcome.manifest);
        assert!(verifica.is_intact(), "{}", verifica.operator_message());
        assert_eq!(verifica.report_id.as_deref(), Some(report_id.as_str()));

        // 2. L'archivio: il pacchetto e' completo e dichiara quell'artefatto,
        //    con lo stesso nome e la stessa impronta che stanno sul disco.
        let Ok(package) = service.package(package_id) else {
            panic!("il pacchetto deve potersi rileggere");
        };
        assert!(package.status.is_deliverable());
        assert!(package.completed_at.is_some());
        assert_eq!(package.artifacts.len(), 1);
        assert_eq!(
            package.artifacts[0].file_name,
            outcome.artifacts[0].file_name
        );
        assert_eq!(package.artifacts[0].sha256, outcome.artifacts[0].sha256);

        // 3. Il documento: porta dentro di se' lo stesso identificativo del
        //    manifest. E' il criterio 12, ed e' quello che permette di
        //    ricongiungere un file staccato dalla propria cartella.
        let dentro = {
            use std::io::Read as _;
            let mut archivio = zip::ZipArchive::new(std::io::Cursor::new(documento.clone()))
                .expect("il .docx e' uno ZIP");
            let mut raccolto = String::new();
            for indice in 0..archivio.len() {
                let mut voce = archivio.by_index(indice).expect("voce leggibile");
                let mut parte = String::new();
                if voce.read_to_string(&mut parte).is_ok() {
                    raccolto.push_str(&parte);
                }
            }
            raccolto
        };
        assert!(
            dentro.contains(report_id.as_str()),
            "il documento non porta il proprio identificativo"
        );
    }

    // ------------------------------------------------------- generazione MP-18G

    /// Testo di ogni voce del `.docx`, concatenato.
    ///
    /// L'archivio si apre davvero: uno ZIP comprime, e cercare una frase nei
    /// byte grezzi darebbe verde anche a un documento che la contiene.
    fn dentro(path: &std::path::Path) -> String {
        use std::io::Read as _;

        let bytes = std::fs::read(path).expect("il documento deve potersi leggere");
        let mut archivio =
            zip::ZipArchive::new(std::io::Cursor::new(bytes)).expect("il .docx e' uno ZIP");
        let mut raccolto = String::new();
        for indice in 0..archivio.len() {
            let mut voce = archivio.by_index(indice).expect("voce leggibile");
            let mut parte = String::new();
            if voce.read_to_string(&mut parte).is_ok() {
                raccolto.push_str(&parte);
            }
        }
        raccolto
    }

    fn generation<'a>(
        session_id: SessionId,
        selection: ReportSelection,
        profile: &'a ReportTemplateProfile,
        destination: &'a std::path::Path,
    ) -> ReportGenerationRequest<'a> {
        ReportGenerationRequest {
            session_id,
            selection,
            profile,
            destination,
            requested_kinds: vec![ReportArtifactKind::NarrativeDocx],
            requested_by: operator(),
            requested_at: now(),
            asked_links: None,
        }
    }

    /// **Le versioni e il contorno arrivano dall'archivio al documento.**
    ///
    /// # Che cosa questa prova copre, e che cosa no
    ///
    /// Copre la **rilettura**: che la storia si legga solo per i contenuti che
    /// ne hanno, che il contorno si legga solo per quelli fotografati, che
    /// l'impronta si ricalcoli e che i tetti si applichino.
    ///
    /// Non copre la composizione: che cosa il documento dica di una versione e
    /// di un contorno lo verificano le prove di `report_narrative`, sulle
    /// stesse due funzioni che compongono l'allegato e la relazione.
    ///
    /// # Perche' un contenuto senza nulla deve restare senza nulla
    ///
    /// Perche' e' la meta' del comportamento che tiene i documenti leggibili:
    /// un allegato con centinaia di contenuti in cui ognuno porta due gruppi
    /// vuoti insegna a saltarli, e li rende inutili proprio dove contano.
    #[test]
    fn le_versioni_e_il_contorno_arrivano_dall_archivio_al_registro() {
        use lisi_core::model::AnalysisLevel;
        use lisi_core::model::acquisition::{
            IdempotencyKey, InboxEventKind, NewContentVersion, NewInboxEntry,
        };
        use lisi_core::model::context_snapshot::{NewContextSnapshot, SnapshotMessage};
        use lisi_core::model::report::{ReportContentSnapshot, ReportSnapshot};
        use lisi_core::text::Note;

        let (mut database, session_id, contents) = archive();
        let Some(&modificato) = contents.first() else {
            panic!("l'archivio di prova deve avere contenuti");
        };
        let Some(&intatto) = contents.get(1) else {
            panic!("serve un secondo contenuto, mai toccato");
        };

        // UNA MODIFICA OSSERVATA. La versione 1 e' il corpo acquisito, seminato
        // alla prima modifica; la 2 e' quella osservata dopo.
        let Ok(()) = database.seed_original_version(modificato, "una molotov", now()) else {
            panic!("la versione originale deve potersi seminare");
        };
        let Ok(remote) = RemoteMessageId::try_new("m0") else {
            panic!("l'identificativo remoto deve essere valido");
        };
        let chiave = IdempotencyKey::derive(
            session_id,
            None,
            InboxEventKind::EditedMessage,
            Some("m0"),
            Some("revisione-di-prova"),
        );
        let Ok(voce) = database.enqueue_inbox(&NewInboxEntry {
            session_id,
            source_id: None,
            event_kind: InboxEventKind::EditedMessage,
            remote_event_id: Some(remote),
            idempotency_key: chiave,
            remote_timestamp: None,
            received_at: now(),
            payload_json: None,
            format_version: 1,
        }) else {
            panic!("la voce d'inbox deve potersi accodare");
        };
        let Ok(corpo) = lisi_core::text::ContentBody::try_new("una molotov, e poi altro") else {
            panic!("il corpo della versione deve essere valido");
        };
        let Ok(_) = database.append_content_version(
            voce.id(),
            &NewContentVersion {
                content_id: modificato,
                body: corpo,
                remote_edit_timestamp: None,
                observed_at: later(60),
            },
        ) else {
            panic!("la versione deve potersi scrivere");
        };

        // UNA FOTOGRAFIA DEL CONTESTO, con la sua ragione.
        let Ok(fonti) = database.session_source_ids(session_id) else {
            panic!("le fonti della sessione devono potersi leggere");
        };
        let Some(&source_id) = fonti.first() else {
            panic!("la sessione deve avere una fonte");
        };
        let (Ok(ragione), Ok(attore)) = (
            Note::try_new("il messaggio precedente cambia il senso di questo"),
            Actor::try_new("operatore"),
        ) else {
            panic!("i valori della fotografia devono essere validi");
        };
        let Ok(fotografia) = NewContextSnapshot::prepare(
            modificato,
            source_id,
            &attore,
            &ragione,
            now(),
            now(),
            "m0",
            "una molotov",
            None,
            None,
            vec![SnapshotMessage {
                remote_message_id: String::from("m-precedente"),
                published_at: now(),
                body: String::from("riga di contorno mai acquisita"),
                author_sentence: String::from("autore non esposto dalla fonte"),
                relations_sentence: None,
                is_anchor: false,
            }],
        ) else {
            panic!("la fotografia deve potersi comporre");
        };
        let Ok(_) = database.insert_context_snapshot(&fotografia) else {
            panic!("la fotografia deve potersi scrivere");
        };

        let service = ReportService::new(database);
        let snapshot = ReportSnapshot {
            taken_at: now(),
            session_id,
            source_ids: Vec::new(),
            dictionary_version_ids: Vec::new(),
            template_version: 1,
            contents: contents
                .iter()
                .map(|content_id| ReportContentSnapshot {
                    content_id: *content_id,
                    level: AnalysisLevel::try_new(0).expect("livello valido"),
                    review_state: None,
                    body_sha256: Sha256Digest::of_text("irrilevante"),
                    selected: false,
                })
                .collect(),
        };

        let Ok(registro) = service.ledger_contents(&snapshot) else {
            panic!("il registro deve potersi comporre");
        };

        let Some(riga) = registro
            .iter()
            .find(|content| content.content_id == modificato)
        else {
            panic!("il contenuto modificato deve essere nel registro");
        };
        assert_eq!(riga.revisions.len(), 1, "la versione osservata non arriva");
        assert_eq!(riga.revisions_beyond, 0);
        assert_eq!(
            riga.revisions[0].body, "una molotov, e poi altro",
            "la versione arriva con il corpo sbagliato"
        );
        assert_eq!(riga.contexts.len(), 1, "la fotografia non arriva");
        assert!(
            riga.contexts[0].verified,
            "una fotografia appena scritta deve verificarsi"
        );
        assert_eq!(
            riga.contexts[0].reason, "il messaggio precedente cambia il senso di questo",
            "la ragione dell'operatore non arriva al documento"
        );
        assert_eq!(riga.contexts[0].lines.len(), 1);

        // Il corpo acquisito resta quello, accanto al livello: la versione
        // osservata dopo non lo sostituisce (ADR-0104, decisione 1).
        assert_eq!(riga.body, "una molotov");

        let Some(altra) = registro
            .iter()
            .find(|content| content.content_id == intatto)
        else {
            panic!("il contenuto intatto deve essere nel registro");
        };
        assert!(
            altra.revisions.is_empty() && altra.contexts.is_empty(),
            "un contenuto senza storia e senza fotografie porta gruppi vuoti"
        );
    }

    /// **Il cancello della ragione operativa vale anche sui documenti, e solo
    /// chi è stato aperto e collegato entra.**
    ///
    /// # Che cosa questa prova copre
    ///
    /// La **rilettura**: il cancello d'audit, la corrispondenza fra identità
    /// collegata e autore osservato, i conteggi ricavati dalle righe che il
    /// documento porta già, e l'esclusione di chi questo monitoraggio non ha
    /// incontrato.
    ///
    /// Non copre la composizione: che cosa il documento dica di un soggetto lo
    /// verificano le prove di `report_annex`.
    ///
    /// # Perché i contenuti sono costruiti qui e non letti dall'archivio
    ///
    /// Perché è esattamente la decisione 3 di ADR-0105: i conteggi vengono
    /// dalle righe **già composte** per il documento, e non da una seconda
    /// interrogazione. Una prova che rileggesse l'archivio verificherebbe una
    /// strada che il prodotto non percorre.
    #[test]
    fn nei_documenti_entra_solo_chi_e_stato_aperto_e_collegato() {
        use crate::report_ledger::LedgerAlert;
        use lisi_core::model::audit::NewAuditEntry;
        use lisi_core::model::identity_link::{LinkAct, NewIdentityLink};
        use lisi_core::model::person::NewPerson;
        use lisi_core::model::reason::OperationalReason;
        use lisi_core::text::{AuditAction, AuditEntity};

        let (database, _, _) = archive();

        let (Ok(etichetta), Ok(ragione), Ok(altra_etichetta)) = (
            DisplayName::try_new("PERSONA OSSERVATA"),
            OperationalReason::try_new("segnalazione ricevuta il primo settembre"),
            DisplayName::try_new("PERSONA ALTROVE"),
        ) else {
            panic!("i valori del soggetto devono essere validi");
        };
        let Ok(osservata) = database.insert_person(
            &NewPerson::open(etichetta, ragione.clone()),
            &operator(),
            now(),
        ) else {
            panic!("il soggetto deve potersi aprire");
        };
        let Ok(altrove) = database.insert_person(
            &NewPerson::open(altra_etichetta, ragione.clone()),
            &operator(),
            now(),
        ) else {
            panic!("il secondo soggetto deve potersi aprire");
        };

        for (persona, identificativo) in [(osservata, "@tale"), (altrove, "@nessuno")] {
            let Ok(_) = database.insert_identity_link(&NewIdentityLink {
                person: persona,
                identifier: String::from(identificativo),
                act: LinkAct::Link,
                reason: ragione.clone(),
                by: operator(),
                at: now(),
                resolution: None,
            }) else {
                panic!("il legame deve potersi registrare");
            };
        }

        // LE RIGHE CHE IL DOCUMENTO PORTA GIA'.
        let righe = [
            contenuto_di_prova(1, "@tale", "Canale uno"),
            contenuto_di_prova(2, "@tale", "Canale due"),
            contenuto_di_prova(3, "@estraneo", "Canale uno"),
        ];
        let avvisi = [LedgerAlert {
            content_id: ContentId::new(1),
            level: 3,
            reason: String::from("motivo del motore"),
            raised_at: now(),
        }];

        let service = ReportService::new(database);

        // SENZA LA RAGIONE OPERATIVA non si elenca nessuno, e il fatto si
        // riporta al documento perche' lo dichiari.
        let Ok((vuoti, cancello_aperto)) = service.ledger_subjects(&righe, &avvisi) else {
            panic!("la lettura dei soggetti deve riuscire");
        };
        assert!(
            vuoti.is_empty() && !cancello_aperto,
            "un elenco di persone e' stato prodotto senza la ragione operativa"
        );

        let Ok(azione) = AuditAction::try_new("elenco_persone_motivato") else {
            panic!("l'azione d'audit deve essere valida");
        };
        let Ok(entita) = AuditEntity::try_new("persone") else {
            panic!("l'entita' d'audit deve essere valida");
        };
        let Ok(_) = service.database.append_audit(&NewAuditEntry {
            actor: operator(),
            action: azione,
            entity: entita,
            entity_id: None,
            actor_mode: None,
            detail: None,
            recorded_at: now(),
        }) else {
            panic!("la ragione operativa deve potersi registrare");
        };

        let Ok((soggetti, cancello_aperto)) = service.ledger_subjects(&righe, &avvisi) else {
            panic!("la lettura dei soggetti deve riuscire");
        };
        assert!(cancello_aperto);
        assert_eq!(
            soggetti.len(),
            1,
            "un soggetto che questo monitoraggio non ha incontrato e' entrato nel documento"
        );

        let soggetto = &soggetti[0];
        assert_eq!(soggetto.label, "PERSONA OSSERVATA");
        assert_eq!(soggetto.assessment_label, "NON VALUTATO");
        assert!(soggetto.assessment_reason.is_none());
        assert_eq!(soggetto.identities.len(), 1);

        let identita = &soggetto.identities[0];
        assert_eq!(identita.identifier, "@tale");
        assert_eq!(
            identita.contents_here, 2,
            "i contenuti dell'estraneo sono stati contati"
        );
        assert_eq!(identita.alerts_here, 1);
        assert_eq!(identita.distinct_sources_here, 2);
    }

    /// Una riga del registro attribuita a un autore, per le prove dei soggetti.
    fn contenuto_di_prova(
        raw: i64,
        autore: &str,
        fonte: &str,
    ) -> crate::report_ledger::LedgerContent {
        crate::report_ledger::LedgerContent {
            content_id: ContentId::new(raw),
            source_label: String::from(fonte),
            author: Some(String::from(autore)),
            published_at: now(),
            acquired_at: now(),
            origin: String::from("osservato"),
            body: String::from("testo che non deve entrare in un elenco di persone"),
            url: None,
            asked_link: None,
            attachment: None,
            level: 0,
            review_state: None,
            selected: false,
            body_digest: String::from("impronta"),
            analysis_origin: None,
            after_acquisition: None,
            revisions: Vec::new(),
            revisions_beyond: 0,
            contexts: Vec::new(),
            contexts_beyond: 0,
        }
    }

    /// **Il collegamento chiesto per la relazione entra nei contenuti che lo
    /// hanno, e soltanto in quelli** (CONTEXT-02, criterio 1).
    #[test]
    fn il_collegamento_chiesto_entra_soltanto_nei_contenuti_che_lo_hanno() {
        let contenuti = vec![
            contenuto_di_prova(1, "@uno", "Canale"),
            contenuto_di_prova(2, "@due", "Canale"),
        ];
        let mut libro = crate::message_link::LinkBook::default();
        libro.insert(
            ContentId::new(2),
            String::from("https://t.me/canale/2 (fornito da Telegram il 23/10/2026, pubblico)"),
        );
        let senza = super::with_asked_links(
            contenuti.clone(),
            None,
            |c| c.content_id,
            |c, frase| c.asked_link = Some(frase),
        );
        assert!(senza.iter().all(|c| c.asked_link.is_none()));
        let con = super::with_asked_links(
            contenuti,
            Some(&libro),
            |c| c.content_id,
            |c, frase| c.asked_link = Some(frase),
        );
        assert_eq!(
            con[0].asked_link, None,
            "il contenuto non chiesto resta com'era"
        );
        assert_eq!(
            con[1].asked_link.as_deref(),
            Some("https://t.me/canale/2 (fornito da Telegram il 23/10/2026, pubblico)")
        );
    }

    /// **Nel documento prodotto non deve esserci alcun collegamento cliccabile.**
    ///
    /// # Perché è un requisito e non una mancanza
    ///
    /// Gli indirizzi dei messaggi compaiono nella relazione come **testo**, e
    /// non come collegamenti. È deliberato, e la ragione non è tipografica.
    ///
    /// Un collegamento cliccabile dentro un atto d'ufficio è un invito a
    /// **contattare la fonte**: chi apre il documento in Word e ci clicca sopra
    /// apre Telegram su quel messaggio, e lo fa dal proprio profilo, in un
    /// momento che nessuno ha deciso. ADR-0035 Decisione 8 dice che un
    /// indicatore si estrae e non si contatta; qui vale la stessa regola,
    /// applicata al documento invece che al motore.
    ///
    /// C'è una seconda ragione, indipendente dalla prima. Un `.docx` con
    /// collegamenti porta relazioni esterne in `word/_rels/document.xml.rels`,
    /// e ADR-0031 le vieta esplicitamente: sono la superficie da cui un
    /// documento può puntare a risorse che non controlliamo.
    ///
    /// # Che cosa verifica davvero
    ///
    /// Apre l'archivio voce per voce e cerca gli elementi che OOXML usa per un
    /// collegamento — `w:hyperlink` e il tipo di relazione `hyperlink`. Non
    /// cerca `http`, che comparirebbe legittimamente come testo di un indirizzo.
    #[test]
    fn la_relazione_prodotta_non_contiene_alcun_collegamento_cliccabile() {
        let (database, session_id, _) = archive();
        let mut service = ReportService::new(database);
        let cartella = tempfile::tempdir().expect("cartella temporanea");
        let profile = ReportTemplateProfile::default();

        let Ok(prodotto) = service.generate(&generation(
            session_id,
            ReportSelection::empty(),
            &profile,
            cartella.path(),
        )) else {
            panic!("la relazione deve potersi produrre");
        };

        let documento = prodotto.directory.join(&prodotto.artifacts[0].file_name);
        let testo = dentro(&documento);

        // La premessa, verificata e non presunta: se l'archivio non si fosse
        // aperto, `dentro` restituirebbe una stringa vuota e la prova passerebbe
        // senza aver guardato nulla.
        assert!(
            testo.contains("w:document") || testo.contains("<w:body"),
            "l'archivio non e' stato letto: la prova non ha guardato nulla"
        );

        for vietato in ["w:hyperlink", "hyperlink\"", "/hyperlink"] {
            assert!(
                !testo.contains(vietato),
                "il documento contiene «{vietato}»: un collegamento cliccabile in \
                 un atto d'ufficio invita a contattare la fonte con un clic"
            );
        }
    }

    #[test]
    fn a_report_without_a_selection_is_produced_all_the_same() {
        // Criterio 3 percorso per intero, dall'ingresso della schermata al file
        // sul disco: zero elementi selezionati **non** e' un errore.
        let (database, session_id, _) = archive();
        let mut service = ReportService::new(database);
        let cartella = tempfile::tempdir().expect("cartella temporanea");
        let profile = ReportTemplateProfile::default();

        let Ok(prodotto) = service.generate(&generation(
            session_id,
            ReportSelection::empty(),
            &profile,
            cartella.path(),
        )) else {
            panic!("la relazione a esito negativo deve potersi produrre");
        };

        assert_eq!(prodotto.outcome, ReportOutcome::NothingSelected);
        assert_eq!(prodotto.monitored, 3);
        assert_eq!(prodotto.selected, 0);
        assert_eq!(prodotto.artifacts.len(), 1);
        assert!(prodotto.manifest.exists(), "il manifest deve esistere");

        let documento = prodotto.directory.join(&prodotto.artifacts[0].file_name);
        assert!(documento.exists());
        // Le frasi cercate non contengono apostrofi: in OOXML l'apostrofo viene
        // scritto come entita' XML, e cercarlo in chiaro darebbe rosso a un
        // documento corretto.
        let testo = dentro(&documento);
        assert!(testo.contains("Attivit"));
        assert!(testo.contains("acquisiti e analizzati 3 contenuti"));
        assert!(testo.contains("Risultanze"));
        assert!(testo.contains(prodotto.report_id.as_str()));

        let Ok(package) = service.package(prodotto.package_id) else {
            panic!("il pacchetto deve potersi rileggere");
        };
        assert!(package.status.is_deliverable());
    }

    #[test]
    fn a_report_with_a_selection_represents_only_the_chosen_elements() {
        // Criterio 5 sul documento **prodotto**, non sul testo composto: la
        // sessione ne ha monitorati tre, l'operatore ne sceglie uno.
        let (database, session_id, contents) = archive();
        let mut service = ReportService::new(database);
        let cartella = tempfile::tempdir().expect("cartella temporanea");
        let profile = ReportTemplateProfile::default();

        let Ok(prodotto) = service.generate(&generation(
            session_id,
            ReportSelection::from_contents([contents[0]]),
            &profile,
            cartella.path(),
        )) else {
            panic!("la relazione con risultanze deve potersi produrre");
        };

        assert_eq!(prodotto.outcome, ReportOutcome::WithFindings);
        assert_eq!(prodotto.selected, 1);
        assert_eq!(prodotto.monitored, 3);

        let testo = dentro(&prodotto.directory.join(&prodotto.artifacts[0].file_name));
        assert!(
            testo.contains("una molotov"),
            "l'elemento selezionato non compare nella relazione"
        );
        assert!(
            !testo.contains("buongiorno a tutti"),
            "un elemento NON selezionato e' finito nelle risultanze"
        );
        assert!(!testo.contains("nulla di che"));
    }

    #[test]
    fn the_document_carries_neither_the_destination_path_nor_the_machine_user() {
        // Criterio 20 dal lato del documento prodotto: un percorso di lavoro e
        // il nome dell'utente della macchina non spiegano l'attivita' svolta, e
        // viaggerebbero con ogni copia del file.
        let (database, session_id, contents) = archive();
        let mut service = ReportService::new(database);
        let cartella = tempfile::tempdir().expect("cartella temporanea");
        let profile = ReportTemplateProfile::default();

        let Ok(prodotto) = service.generate(&generation(
            session_id,
            ReportSelection::from_contents([contents[0]]),
            &profile,
            cartella.path(),
        )) else {
            panic!("la relazione deve potersi produrre");
        };

        let testo = dentro(&prodotto.directory.join(&prodotto.artifacts[0].file_name));
        let percorso = cartella.path().to_string_lossy().into_owned();
        assert!(
            !testo.contains(&percorso),
            "il documento contiene il percorso della cartella di destinazione"
        );
        let utente = std::env::var("USERNAME").unwrap_or_default();
        if !utente.is_empty() {
            assert!(
                !testo.contains(&utente),
                "il documento contiene il nome utente della macchina"
            );
        }
    }

    #[test]
    fn two_generations_take_two_identifiers_and_two_folders() {
        let (database, session_id, _) = archive();
        let mut service = ReportService::new(database);
        let cartella = tempfile::tempdir().expect("cartella temporanea");
        let profile = ReportTemplateProfile::default();

        let Ok(primo) = service.generate(&generation(
            session_id,
            ReportSelection::empty(),
            &profile,
            cartella.path(),
        )) else {
            panic!("la prima generazione deve riuscire");
        };
        let Ok(secondo) = service.generate(&generation(
            session_id,
            ReportSelection::empty(),
            &profile,
            cartella.path(),
        )) else {
            panic!("la seconda generazione deve riuscire");
        };

        assert_ne!(primo.report_id, secondo.report_id);
        assert_ne!(primo.directory, secondo.directory);
        assert!(primo.manifest.exists() && secondo.manifest.exists());
    }

    #[test]
    fn a_format_this_version_cannot_produce_is_refused_instead_of_faked() {
        // **Nessun file finto.** Chiedere un genere che questa versione non
        // produce da' un rifiuto **prima** che il pacchetto sia aperto, e non
        // lascia nulla sul disco.
        //
        // L'esempio e' cambiato tre volte, via via che ciascun generatore e'
        // arrivato: prima l'XLSX, poi il PDF, poi il rapporto in testo. Oggi
        // resta il MANIFEST, che non e' un documento da generare ma la
        // dichiarazione di cio' che il pacchetto contiene: lo scrive il
        // pacchetto stesso, per ultimo, quando sa che cosa dichiarare.
        //
        // Se un giorno anche questo diventasse producibile, il principio
        // andra' provato con un genere nuovo, non cancellato.
        let (database, session_id, _) = archive();
        let mut service = ReportService::new(database);
        let cartella = tempfile::tempdir().expect("cartella temporanea");
        let profile = ReportTemplateProfile::default();

        let mut richiesta = generation(
            session_id,
            ReportSelection::empty(),
            &profile,
            cartella.path(),
        );
        richiesta.requested_kinds = vec![ReportArtifactKind::Manifest];

        assert!(matches!(
            service.generate(&richiesta),
            Err(ServiceError::DocumentGeneration { .. })
        ));
        let Ok(letta) = std::fs::read_dir(cartella.path()) else {
            panic!("la cartella deve potersi leggere");
        };
        assert_eq!(letta.count(), 0, "non deve restare nulla sul disco");
    }

    #[test]
    fn a_relative_destination_is_refused_and_the_package_is_marked_failed() {
        // Percorso non valido: il pacchetto e' gia' registrato quando la
        // cartella si rivela impossibile, e resta registrato come **fallito**
        // invece di restare in attesa per sempre.
        let (database, session_id, _) = archive();
        let mut service = ReportService::new(database);
        let profile = ReportTemplateProfile::default();

        let esito = service.generate(&generation(
            session_id,
            ReportSelection::empty(),
            &profile,
            std::path::Path::new("documenti"),
        ));
        assert!(matches!(esito, Err(ServiceError::ExportNotWritten { .. })));

        let Ok(packages) = service.database().session_report_packages(session_id) else {
            panic!("i pacchetti devono potersi rileggere");
        };
        assert_eq!(packages.len(), 1);
        assert!(!packages[0].status.is_deliverable());
        assert!(packages[0].completed_at.is_none());
    }

    #[test]
    fn a_write_that_cannot_succeed_leaves_no_package_and_no_manifest() {
        // Criterio 19 percorso dalla generazione intera: si occupa il nome del
        // documento con una cartella, che e' il modo riproducibile di
        // provocare lo stesso errore di sistema di un file aperto in Word.
        let (database, session_id, _) = archive();
        let mut service = ReportService::new(database);
        let cartella = tempfile::tempdir().expect("cartella temporanea");
        let profile = ReportTemplateProfile::default();

        // La cartella del pacchetto e il nome del documento si conoscono in
        // anticipo: sono composti, non scelti da chi scrive.
        let atteso = ReportId::from_sequence(now().year_utc(), 1);
        let pacchetto = cartella.path().join(atteso.as_str());
        std::fs::create_dir_all(&pacchetto).expect("cartella del pacchetto");
        std::fs::create_dir(pacchetto.join(format!("Relazione_{atteso}.docx")))
            .expect("ostacolo alla scrittura");

        let esito = service.generate(&generation(
            session_id,
            ReportSelection::empty(),
            &profile,
            cartella.path(),
        ));
        assert!(
            esito.is_err(),
            "una scrittura impossibile deve produrre un esito dichiarato"
        );

        assert!(
            !pacchetto.join(format!("Manifest_{atteso}.txt")).exists(),
            "un pacchetto interrotto non deve avere un manifest"
        );
        let Ok(packages) = service.database().session_report_packages(session_id) else {
            panic!("i pacchetti devono potersi rileggere");
        };
        assert!(
            packages
                .iter()
                .all(|package| !package.status.is_deliverable())
        );
    }

    #[test]
    fn a_full_generation_leaves_the_expected_trail_in_the_audit() {
        // Criterio 14 sul percorso vero, non sui singoli metodi.
        let (database, session_id, contents) = archive();
        let mut service = ReportService::new(database);
        let cartella = tempfile::tempdir().expect("cartella temporanea");
        let profile = ReportTemplateProfile::default();

        let Ok(_) = service.generate(&generation(
            session_id,
            ReportSelection::from_contents([contents[0]]),
            &profile,
            cartella.path(),
        )) else {
            panic!("la relazione deve potersi produrre");
        };

        let Ok(entries) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let actions: Vec<&str> = entries
            .iter()
            .map(|entry| entry.action.as_str())
            .filter(|action| action.starts_with("report."))
            .collect();
        for atteso in ["report.preparato", "report.artefatto", "report.completato"] {
            assert!(actions.contains(&atteso), "manca la voce «{atteso}»");
        }

        // Criterio 15: nel registro non finisce il corpo dei messaggi.
        for entry in &entries {
            let detail = entry.detail.as_ref().map_or("", |value| value.as_str());
            assert!(!detail.contains("molotov"), "il corpo e' finito nell'audit");
        }
    }

    #[test]
    fn the_saved_profile_reaches_the_produced_document_without_being_retyped() {
        // È il punto della conservazione: l'operatore compila una volta, e da
        // lì in poi ogni relazione esce già intestata.
        use lisi_core::model::report_template::TemplateField;

        let (database, session_id, _) = archive();
        let mut service = ReportService::new(database);
        let cartella = tempfile::tempdir().expect("cartella temporanea");

        assert!(
            service.profile().expect("lettura").is_none(),
            "al primo avvio la domanda non e' ancora stata posta"
        );

        let salvato = ReportTemplateProfile {
            organisation: TemplateField::try_new("Ente conservato").ok(),
            place: TemplateField::try_new("Città conservata").ok(),
            signer_name: TemplateField::try_new("Nome CONSERVATO").ok(),
            ..ReportTemplateProfile::default()
        };
        let Ok(versione) = service.save_profile(&salvato, &operator(), now()) else {
            panic!("il profilo deve potersi conservare");
        };
        assert_eq!(versione, 1);

        // Il profilo si rilegge dall'archivio, non si ripassa a mano.
        let Ok(riletto) = service.profile_or_empty() else {
            panic!("il profilo deve potersi rileggere");
        };
        let Ok(prodotto) = service.generate(&generation(
            session_id,
            ReportSelection::empty(),
            &riletto,
            cartella.path(),
        )) else {
            panic!("la relazione deve potersi produrre");
        };

        let testo = dentro(&prodotto.directory.join(&prodotto.artifacts[0].file_name));
        assert!(testo.contains("Ente conservato"));
        assert!(testo.contains("Nome CONSERVATO"));

        // E la fotografia registra **con quale versione** del profilo il
        // documento è stato prodotto.
        let Ok(fotografia) = service.snapshot(prodotto.package_id) else {
            panic!("la fotografia deve potersi rileggere");
        };
        assert_eq!(fotografia.template_version, 1);
    }

    #[test]
    fn an_empty_saved_profile_is_remembered_as_an_answer() {
        // Chi sceglie di non compilare nulla non deve ritrovarsi la stessa
        // domanda al prossimo avvio.
        let (database, _, _) = archive();
        let service = ReportService::new(database);

        let Ok(_) = service.save_profile(&ReportTemplateProfile::default(), &operator(), now())
        else {
            panic!("un profilo vuoto deve potersi conservare");
        };

        let Ok(Some(riletto)) = service.profile() else {
            panic!("la risposta «non li inserisco» deve restare registrata");
        };
        assert!(riletto.is_empty());
    }

    #[test]
    fn saving_the_profile_is_audited_without_writing_down_its_values() {
        use lisi_core::model::report_template::TemplateField;

        let (database, _, _) = archive();
        let service = ReportService::new(database);

        let profile = ReportTemplateProfile {
            organisation: TemplateField::try_new("Ente riservato").ok(),
            ..ReportTemplateProfile::default()
        };
        let Ok(_) = service.save_profile(&profile, &operator(), now()) else {
            panic!("il profilo deve potersi conservare");
        };

        let Ok(entries) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let voce = entries
            .iter()
            .find(|entry| entry.action.as_str() == "report.profilo")
            .expect("il salvataggio del profilo deve lasciare una traccia");

        let detail = voce.detail.as_ref().map_or("", |value| value.as_str());
        assert!(detail.contains("versione 1"));
        assert!(detail.contains("campi compilati 1"));
        assert!(
            !detail.contains("Ente riservato"),
            "i valori del profilo non vanno ripetuti nel registro"
        );
    }

    #[test]
    fn the_configured_fields_reach_the_produced_document() {
        // Criterio 22 dal lato del file: i dati dell'ufficio arrivano dal
        // profilo compilato, e nessuno di essi sta nel sorgente.
        use lisi_core::model::report_template::TemplateField;

        let (database, session_id, _) = archive();
        let mut service = ReportService::new(database);
        let cartella = tempfile::tempdir().expect("cartella temporanea");
        let profile = ReportTemplateProfile {
            recipient: Some(TemplateField::try_new("Al Responsabile").expect("valido")),
            place: Some(TemplateField::try_new("Località di prova").expect("valido")),
            ..ReportTemplateProfile::default()
        };

        let Ok(prodotto) = service.generate(&generation(
            session_id,
            ReportSelection::empty(),
            &profile,
            cartella.path(),
        )) else {
            panic!("la relazione deve potersi produrre");
        };

        let testo = dentro(&prodotto.directory.join(&prodotto.artifacts[0].file_name));
        assert!(testo.contains("Al Responsabile"));
        assert!(testo.contains("Località di prova"));
    }

    #[test]
    fn the_monitored_sources_reach_the_document_with_their_counts() {
        let (database, session_id, _) = archive();
        let mut service = ReportService::new(database);
        let cartella = tempfile::tempdir().expect("cartella temporanea");
        let profile = ReportTemplateProfile::default();

        let Ok(prodotto) = service.generate(&generation(
            session_id,
            ReportSelection::empty(),
            &profile,
            cartella.path(),
        )) else {
            panic!("la relazione deve potersi produrre");
        };

        let testo = dentro(&prodotto.directory.join(&prodotto.artifacts[0].file_name));
        assert!(
            testo.contains("Canale di prova"),
            "la fonte monitorata non compare nella relazione"
        );
    }

    #[test]
    fn the_registry_reaches_the_package_as_a_real_xlsx() {
        // **La prova che il registro esca davvero.** Il generatore puo' essere
        // scritto, compilato e coperto di test, e non essere invocato da
        // nessuno: e' il difetto che questo progetto ha gia' incontrato sei
        // volte. Qui si chiede il registro alla generazione vera e si apre il
        // file che ne esce.
        let (database, session_id, _) = archive();
        let mut service = ReportService::new(database);
        let cartella = tempfile::tempdir().expect("cartella temporanea");
        let profile = ReportTemplateProfile::default();

        let mut richiesta = generation(
            session_id,
            ReportSelection::empty(),
            &profile,
            cartella.path(),
        );
        richiesta.requested_kinds = vec![ReportArtifactKind::AnalyticalXlsx];

        let Ok(prodotto) = service.generate(&richiesta) else {
            panic!("il registro deve potersi produrre");
        };

        assert_eq!(prodotto.artifacts.len(), 1);
        let artefatto = &prodotto.artifacts[0];
        assert!(
            artefatto.file_name.ends_with(".xlsx"),
            "il registro non esce con l'estensione giusta: {}",
            artefatto.file_name
        );

        let percorso = prodotto.directory.join(&artefatto.file_name);
        let Ok(bytes) = std::fs::read(&percorso) else {
            panic!("il registro deve potersi rileggere dal disco");
        };
        assert!(
            zip::ZipArchive::new(std::io::Cursor::new(bytes)).is_ok(),
            "il file prodotto non e' un archivio valido"
        );
    }

    #[test]
    fn the_registry_and_the_report_travel_in_the_same_package() {
        // Chiedendoli insieme escono insieme, con lo stesso identificativo:
        // e' il legame che ADR-0031 chiede fra gli artefatti di un pacchetto.
        let (database, session_id, _) = archive();
        let mut service = ReportService::new(database);
        let cartella = tempfile::tempdir().expect("cartella temporanea");
        let profile = ReportTemplateProfile::default();

        let mut richiesta = generation(
            session_id,
            ReportSelection::empty(),
            &profile,
            cartella.path(),
        );
        richiesta.requested_kinds = vec![
            ReportArtifactKind::NarrativeDocx,
            ReportArtifactKind::AnalyticalXlsx,
        ];

        let Ok(prodotto) = service.generate(&richiesta) else {
            panic!("i due documenti devono potersi produrre");
        };

        assert_eq!(prodotto.artifacts.len(), 2);
        assert!(
            prodotto
                .artifacts
                .iter()
                .any(|a| a.file_name.ends_with(".docx"))
        );
        assert!(
            prodotto
                .artifacts
                .iter()
                .any(|a| a.file_name.ends_with(".xlsx"))
        );

        // **La voce T89 del pilot.** Non basta che i due file esistano: il
        // manifest deve dichiararli entrambi, con la propria impronta. Un
        // pacchetto il cui manifest ne nomina uno solo consegna un documento
        // di cui nessuno puo' piu' dire se e' quello prodotto.
        let Ok(manifest) = std::fs::read_to_string(&prodotto.manifest) else {
            panic!("il manifest deve potersi rileggere");
        };
        for artefatto in &prodotto.artifacts {
            assert!(
                manifest.contains(&artefatto.file_name),
                "il manifest non dichiara «{}»",
                artefatto.file_name
            );
            assert!(
                manifest.contains(artefatto.sha256.as_str()),
                "il manifest non porta l'impronta di «{}»",
                artefatto.file_name
            );
        }
        assert!(
            manifest.contains(prodotto.report_id.as_str()),
            "il manifest non porta l'identificativo del report"
        );
    }

    /// **Il pacchetto completo: cinque documenti e il manifest.**
    ///
    /// ADR-0031 ne prevedeva cinque e il pacchetto ne produceva quattro. Dal
    /// 2026-08-20 li produce tutti.
    ///
    /// La prova chiede l'elenco autorevole invece di riscriverlo: se un
    /// generatore nuovo entrasse domani, questa prova lo esercita da sola
    /// invece di ignorarlo.
    #[test]
    fn il_pacchetto_completo_produce_ogni_genere_dichiarato_producibile() {
        let (database, session_id, _) = archive();
        let mut service = ReportService::new(database);
        let cartella = tempfile::tempdir().expect("cartella temporanea");
        let profile = ReportTemplateProfile::default();

        let mut richiesta = generation(
            session_id,
            ReportSelection::empty(),
            &profile,
            cartella.path(),
        );
        richiesta.requested_kinds = super::PRODUCIBLE_KINDS.to_vec();

        let Ok(prodotto) = service.generate(&richiesta) else {
            panic!("ogni genere dichiarato producibile deve potersi produrre");
        };

        assert_eq!(
            prodotto.artifacts.len(),
            super::PRODUCIBLE_KINDS.len(),
            "un genere e' dichiarato producibile e non e' stato prodotto"
        );

        for estensione in [".docx", ".pdf", ".xlsx", ".txt"] {
            assert!(
                prodotto
                    .artifacts
                    .iter()
                    .any(|artefatto| artefatto.file_name.ends_with(estensione)),
                "manca un documento «{estensione}» nel pacchetto"
            );
        }

        // Il registro in testo e' una SECONDA RESA della composizione del
        // registro Excel, e deve dichiarare la propria portata: e' il
        // documento che qualcuno potrebbe scambiare per la relazione.
        let testo = prodotto
            .artifacts
            .iter()
            .find(|artefatto| artefatto.file_name.ends_with(".txt"))
            .map(|artefatto| prodotto.directory.join(&artefatto.file_name));
        let Some(percorso) = testo else {
            panic!("il registro in testo deve essere nel pacchetto");
        };
        let Ok(contenuto) = std::fs::read_to_string(&percorso) else {
            panic!("il registro in testo deve potersi rileggere come UTF-8");
        };
        assert!(
            contenuto.contains("TUTTO il monitorato"),
            "il registro in testo non dichiara la propria portata"
        );
    }

    #[test]
    fn only_the_formats_this_version_produces_are_declared_producible() {
        // Se un genere entrasse in questo elenco senza il proprio generatore,
        // `compose` lo rifiuterebbe **dopo** aver aperto il pacchetto: questo
        // test tiene le due cose allineate.
        //
        // Dal 2026-08-20 il pacchetto produce tutti e cinque i documenti che
        // ADR-0031 prevede. Resta fuori il solo MANIFEST, che non e' un
        // documento ma la dichiarazione di cio' che il pacchetto contiene: lo
        // scrive il pacchetto, per ultimo.
        assert_eq!(
            super::PRODUCIBLE_KINDS,
            &[
                ReportArtifactKind::NarrativeDocx,
                ReportArtifactKind::NarrativePdf,
                ReportArtifactKind::TechnicalAnnexPdf,
                ReportArtifactKind::AnalyticalXlsx,
                ReportArtifactKind::PlainTxt
            ]
        );
    }

    #[test]
    fn a_request_without_any_format_is_refused() {
        let (database, session_id, _) = archive();
        let mut service = ReportService::new(database);
        let cartella = tempfile::tempdir().expect("cartella temporanea");
        let profile = ReportTemplateProfile::default();

        let mut richiesta = generation(
            session_id,
            ReportSelection::empty(),
            &profile,
            cartella.path(),
        );
        richiesta.requested_kinds = Vec::new();

        assert!(matches!(
            service.generate(&richiesta),
            Err(ServiceError::DocumentGeneration { .. })
        ));
    }

    #[test]
    fn a_selection_outside_the_session_never_reaches_the_disk() {
        let (database, session_id, _) = archive();
        let mut service = ReportService::new(database);
        let cartella = tempfile::tempdir().expect("cartella temporanea");
        let profile = ReportTemplateProfile::default();

        let esito = service.generate(&generation(
            session_id,
            ReportSelection::from_contents([ContentId::new(9_999)]),
            &profile,
            cartella.path(),
        ));

        assert!(matches!(
            esito,
            Err(ServiceError::ReportSelectionOutsideSession)
        ));
        let Ok(letta) = std::fs::read_dir(cartella.path()) else {
            panic!("la cartella deve potersi leggere");
        };
        assert_eq!(letta.count(), 0, "non deve restare nulla sul disco");
    }

    #[test]
    fn a_discarded_package_leaves_neither_files_nor_a_deliverable_record() {
        // Criterio 19 dall'altro capo: quando la generazione si interrompe,
        // il disco e l'archivio devono dire la stessa cosa.
        use crate::report_package::PackageWriter;

        let (database, session_id, _) = archive();
        let mut service = ReportService::new(database);
        let cartella = tempfile::tempdir().expect("cartella temporanea");

        let richiesta = request(session_id, ReportSelection::empty(), 9);
        let report_id = richiesta.report_id.clone();
        let Ok(package_id) = service.prepare(&richiesta) else {
            panic!("il pacchetto deve potersi preparare");
        };

        let mut writer =
            PackageWriter::create(cartella.path(), &report_id).expect("cartella del pacchetto");
        let directory = writer.layout().directory().to_path_buf();
        let Ok(_) = service.write_artifact(
            package_id,
            &mut writer,
            ReportArtifactKind::NarrativeDocx,
            b"documento interrotto",
            &operator(),
            later(10),
        ) else {
            panic!("l'artefatto deve potersi scrivere");
        };

        let Ok(removed) =
            service.discard(package_id, writer, "disco pieno", &operator(), later(20))
        else {
            panic!("l'annullamento deve potersi registrare");
        };

        assert_eq!(removed, 1);
        assert!(!directory.exists(), "non deve restare nulla sul disco");

        let Ok(package) = service.package(package_id) else {
            panic!("il pacchetto deve potersi rileggere");
        };
        assert!(!package.status.is_deliverable());
        assert!(package.completed_at.is_none());
    }
}

#[cfg(test)]
mod origine_dell_analisi {
    use lisi_core::model::dictionary::{
        ConfigurationResolver, MatchMode, ResolvedDictionaryConfiguration, TermProvenance,
    };
    use lisi_core::model::{AnalysisLevel, ContentMatch, MatchRange};
    use lisi_core::text::{LanguageTag, MatchedText, RuleCategory, RuleId, TermCategory, TermText};
    use lisi_core::{ContentId, MatchId, Timestamp};

    use super::analysis_origin;

    fn configuration(entries: &[(&str, &str, &str)]) -> ResolvedDictionaryConfiguration {
        let Ok(language) = LanguageTag::try_new("it") else {
            panic!("la lingua di prova deve essere valida");
        };
        let mut resolver = ConfigurationResolver::new();
        for (text, category, provenienza) in entries {
            let (Ok(text), Ok(category)) =
                (TermText::try_new(text), TermCategory::try_new(category))
            else {
                panic!("il termine di prova deve essere valido");
            };
            let Ok(()) = resolver.add(
                text,
                category,
                language.clone(),
                MatchMode::NormalizedWord,
                3,
                TermProvenance {
                    dictionary_id: None,
                    version_id: None,
                    label: String::from(*provenienza),
                },
            ) else {
                panic!("il termine doveva essere accettato");
            };
        }
        resolver.finish()
    }

    fn riscontro(normalised: &str) -> ContentMatch {
        ContentMatch {
            id: MatchId::new(1),
            content_id: ContentId::new(1),
            rule_id: RuleId::try_new(normalised).expect("regola valida"),
            rule_category: RuleCategory::try_new("violenza").expect("categoria valida"),
            matched_text: MatchedText::try_new(normalised).expect("testo valido"),
            range: MatchRange::try_new(0, normalised.len()).expect("intervallo valido"),
            level: AnalysisLevel::NOT_RELEVANT,
            created_at: Timestamp::from_millis(1_700_000_000_000),
        }
    }

    #[test]
    fn un_contenuto_senza_riscontri_non_dichiara_alcuna_origine() {
        // Non c'e' provenienza da dichiarare: non c'e' nulla che l'abbia
        // prodotta. Una riga ripetuta a vuoto insegnerebbe a saltare anche
        // quelle che contano.
        let configurazione = configuration(&[("incendio", "violenza", "Prova v1")]);
        assert!(analysis_origin(&[], Some(&configurazione)).is_none());
    }

    #[test]
    fn l_origine_nomina_i_dizionari_della_fotografia_e_non_quelli_correnti() {
        let configurazione = configuration(&[
            ("incendio", "violenza", "Cyber core v4"),
            ("corteo", "ordine", "Dizionario locale v2"),
        ]);
        let riscontri = [riscontro("incendio"), riscontro("corteo")];

        let Some(frase) = analysis_origin(&riscontri, Some(&configurazione)) else {
            panic!("l'origine doveva essere dichiarata");
        };

        assert!(frase.contains("Cyber core v4"));
        assert!(frase.contains("Dizionario locale v2"));
        // La frase dice CHE elenco: senza, chi legge crederebbe che siano i
        // dizionari di oggi.
        assert!(frase.contains("non i dizionari correnti"));
    }

    #[test]
    fn senza_la_fotografia_l_origine_si_dichiara_ignota_invece_di_essere_inventata() {
        // E' il punto: i dizionari di oggi NON dicono da dove venisse un
        // termine allora. Nominarli attribuirebbe il risultato a una
        // configurazione che potrebbe non essere quella che lo produsse.
        let riscontri = [riscontro("incendio")];

        let Some(frase) = analysis_origin(&riscontri, None) else {
            panic!("l'origine doveva dichiarare la lacuna");
        };

        assert!(frase.contains("non è più conservato"));
        assert!(frase.contains("Il livello registrato resta quello attribuito allora"));
        // E non nomina alcun dizionario.
        assert!(!frase.contains("Cyber core"));
    }

    #[test]
    fn un_riscontro_che_la_fotografia_non_conosce_viene_contato_e_dichiarato() {
        let configurazione = configuration(&[("incendio", "violenza", "Cyber core v4")]);
        let riscontri = [riscontro("incendio"), riscontro("sconosciuto")];

        let Some(frase) = analysis_origin(&riscontri, Some(&configurazione)) else {
            panic!("l'origine doveva essere dichiarata");
        };

        assert!(frase.contains("Cyber core v4"));
        assert!(frase.contains("Per 1 riscontro/i l'elenco della sessione non riporta il termine"));
    }

    #[test]
    fn lo_stesso_dizionario_si_nomina_una_volta_sola() {
        let configurazione = configuration(&[
            ("incendio", "violenza", "Cyber core v4"),
            ("corteo", "ordine", "Cyber core v4"),
        ]);
        let riscontri = [riscontro("incendio"), riscontro("corteo")];

        let Some(frase) = analysis_origin(&riscontri, Some(&configurazione)) else {
            panic!("l'origine doveva essere dichiarata");
        };

        assert_eq!(frase.matches("Cyber core v4").count(), 1);
    }
}

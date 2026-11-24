//! Reporting professionale: il pacchetto di evidenze.
//!
//! Motivato in ADR-0031. Qui vivono i tipi **puri**: che cosa e' un pacchetto,
//! quali artefatti puo' contenere, che cosa ciascuno rappresenta, e che cosa
//! l'operatore ha scelto di rappresentare. Non c'e' persistenza, non c'e'
//! rendering e non c'e' alcun formato di file: quelli arrivano dopo, e
//! dipenderanno da questi tipi invece che il contrario.
//!
//! # La distinzione che questo modulo esiste per rendere impossibile da perdere
//!
//! Un rapporto che elenca tutto cio' che il programma ha visto e' un documento
//! diverso da una relazione che rappresenta cio' che una persona ha scelto di
//! rappresentare. Il primo e' una registrazione, il secondo e' un atto.
//!
//! [`ReportScope`] porta quella distinzione **nel tipo**: ogni artefatto
//! dichiara se narra la selezione dell'operatore o se rappresenta tutto il
//! monitorato, e un test verifica che l'insieme dei documenti narrativi sia
//! esattamente quello atteso. Se un giorno qualcuno aggiungesse un formato
//! narrativo e dimenticasse di dirlo, quel test lo fermerebbe.

use core::fmt;

use crate::digest::Sha256Digest;
use crate::error::{DomainError, DomainResult};
use crate::id::{
    ContentId, DictionaryVersionId, ReportArtifactId, ReportPackageId, SessionId, SourceId,
};
use crate::model::analysis::AnalysisLevel;
use crate::model::review::ReviewState;
use crate::text::Actor;
use crate::time::Timestamp;

/// Che cosa un artefatto del pacchetto rappresenta.
///
/// E' la Decisione 1 di ADR-0031 espressa come tipo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReportScope {
    /// Soltanto gli elementi che **l'operatore** ha scelto di rappresentare.
    OperatorSelection,
    /// Tutto cio' che e' stato monitorato nella sessione, compresi i contenuti
    /// di livello 0, quelli senza alert e quelli giudicati non rilevanti.
    EverythingMonitored,
    /// Il pacchetto stesso: elenca gli artefatti, non i contenuti.
    ThePackageItself,
}

impl ReportScope {
    /// Frase destinata all'operatore, per la schermata e per i documenti.
    #[must_use]
    pub const fn operator_label(self) -> &'static str {
        match self {
            Self::OperatorSelection => "solo gli elementi selezionati",
            Self::EverythingMonitored => "tutto il monitorato",
            Self::ThePackageItself => "l'elenco degli artefatti",
        }
    }
}

string_enum!(
    /// Genere di artefatto che un pacchetto puo' contenere.
    ///
    /// **Non e' una stringa.** Un insieme chiuso e' cio' che permette al
    /// compilatore di accorgersi di un formato aggiunto e non gestito da
    /// qualche parte: con `String` quel difetto si scoprirebbe aprendo un
    /// pacchetto incompleto.
    ReportArtifactKind {
        /// La relazione narrativa, editabile in Word.
        NarrativeDocx => "relazione_docx",
        /// La stessa relazione, a impaginazione stabile.
        NarrativePdf => "relazione_pdf",
        /// L'allegato tecnico: tutto il monitorato, per contenuto.
        TechnicalAnnexPdf => "allegato_tecnico_pdf",
        /// Il registro analitico: tutto il monitorato, per record.
        AnalyticalXlsx => "registro_xlsx",
        /// Il rapporto in testo semplice, il formato gia' in vigore.
        PlainTxt => "rapporto_txt",
        /// Il manifest con le impronte di ogni artefatto prodotto.
        Manifest => "manifest_txt",
    }
);

impl ReportArtifactKind {
    /// Estensione del file, senza punto.
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::NarrativeDocx => "docx",
            Self::NarrativePdf | Self::TechnicalAnnexPdf => "pdf",
            Self::AnalyticalXlsx => "xlsx",
            Self::PlainTxt | Self::Manifest => "txt",
        }
    }

    /// Che cosa questo artefatto rappresenta.
    #[must_use]
    pub const fn scope(self) -> ReportScope {
        match self {
            // I due documenti narrativi raccontano **la selezione**, e nient'altro.
            Self::NarrativeDocx | Self::NarrativePdf => ReportScope::OperatorSelection,
            // L'allegato tecnico e il registro rappresentano l'intera sessione.
            // Il TXT sta qui perche' e' cio' che gia' fa: elenca i contenuti
            // della sessione, compreso il livello 0.
            Self::TechnicalAnnexPdf | Self::AnalyticalXlsx | Self::PlainTxt => {
                ReportScope::EverythingMonitored
            }
            Self::Manifest => ReportScope::ThePackageItself,
        }
    }

    /// Se l'artefatto e' **modificabile** da chi lo riceve.
    ///
    /// Solo il DOCX lo e', ed e' il motivo per cui esiste: il perfezionamento
    /// del testo lo fa una persona, in Word, dopo la generazione.
    #[must_use]
    pub const fn is_editable(self) -> bool {
        matches!(self, Self::NarrativeDocx)
    }

    /// Nome del documento destinato all'operatore, senza estensione.
    ///
    /// E' il nome che compare nel pacchetto e nel manifest. Non contiene
    /// spazi ne' caratteri che un file system debba interpretare: la
    /// sanificazione del nome finale resta comunque compito di chi scrive su
    /// disco, ma partire da un nome gia' innocuo toglie un'occasione di
    /// sbagliare.
    #[must_use]
    pub const fn file_stem(self) -> &'static str {
        match self {
            Self::NarrativeDocx | Self::NarrativePdf => "Relazione",
            Self::TechnicalAnnexPdf => "Allegato_tecnico",
            Self::AnalyticalXlsx => "Registro_monitoraggio",
            Self::PlainTxt => "Monitoraggio",
            Self::Manifest => "Manifest",
        }
    }

    /// Titolo leggibile, per l'interfaccia e per i documenti.
    #[must_use]
    pub const fn operator_label(self) -> &'static str {
        match self {
            Self::NarrativeDocx => "Relazione modificabile (Word)",
            Self::NarrativePdf => "Relazione (PDF)",
            Self::TechnicalAnnexPdf => "Allegato tecnico (PDF)",
            Self::AnalyticalXlsx => "Registro analitico (Excel)",
            Self::PlainTxt => "Rapporto in testo semplice",
            Self::Manifest => "Elenco delle impronte",
        }
    }
}

/// Identificativo del pacchetto che compare **dentro** i documenti.
///
/// # Perche' non e' [`crate::id::ReportPackageId`]
///
/// Quello e' l'identificatore della riga nell'archivio, un intero. Questo e' il
/// riferimento che una persona **cita**: sta in testa alla relazione, nel
/// manifest e in ogni allegato, e serve a rispondere alla domanda che cinque
/// file sparsi in una cartella altrimenti non permettono — *appartengono alla
/// stessa generazione?*
///
/// # Perche' e' composto e non casuale
///
/// Un identificativo casuale sarebbe piu' semplice da produrre e impossibile da
/// ricostruire. Questo si compone dall'anno e da un progressivo, quindi due
/// generazioni distinte non collidono e chiunque puo' rileggerlo ad alta voce
/// senza sbagliarlo.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReportId(String);

impl ReportId {
    /// Nome del campo, usato nei messaggi di errore.
    pub const FIELD: &'static str = "identificativo_report";

    /// Lunghezza massima ammessa, in caratteri.
    pub const MAX_CHARS: usize = 40;

    /// Compone l'identificativo dall'anno e dal progressivo.
    ///
    /// La forma e' `R-<anno>-<progressivo a sei cifre>`, per esempio
    /// `R-2026-000042`. Sei cifre coprono un milione di report l'anno; se un
    /// giorno non bastassero, il progressivo cresce e la forma resta leggibile.
    #[must_use]
    pub fn from_sequence(year: i32, sequence: u32) -> Self {
        Self(format!("R-{year}-{sequence:06}"))
    }

    /// Costruisce l'identificativo validandolo.
    ///
    /// Ammessi: lettere ASCII maiuscole, cifre e il trattino. Nient'altro.
    ///
    /// # Errori
    ///
    /// Restituisce un [`DomainError`] se il testo e' vuoto, se supera
    /// [`Self::MAX_CHARS`] o se contiene caratteri fuori dall'alfabeto ammesso.
    ///
    /// # Perche' l'alfabeto e' cosi' stretto
    ///
    /// Questo valore finisce in un **nome di file**, in un documento e in una
    /// riga di manifest. Uno spazio, una barra o un carattere che alteri
    /// l'ordine di lettura lo trasformerebbero in un problema in almeno uno di
    /// quei tre posti. Vietarli qui costa una riga; ripulirli in tre posti
    /// diversi costa tre occasioni di dimenticarsene.
    pub fn try_new(raw: &str) -> DomainResult<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(DomainError::Empty { field: Self::FIELD });
        }

        let length = trimmed.chars().count();
        if length > Self::MAX_CHARS {
            return Err(DomainError::TooLong {
                field: Self::FIELD,
                max: Self::MAX_CHARS,
                actual: length,
            });
        }

        if !trimmed.chars().all(|character| {
            character.is_ascii_uppercase() || character.is_ascii_digit() || character == '-'
        }) {
            return Err(DomainError::ControlCharacters { field: Self::FIELD });
        }

        Ok(Self(trimmed.to_owned()))
    }

    /// Contenuto validato.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consuma il valore restituendo la stringa interna.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for ReportId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Gli elementi che l'operatore ha scelto di rappresentare nella relazione.
///
/// # Le tre invarianti, e perche' ognuna serve
///
/// 1. **Nessun duplicato.** Lo stesso contenuto scelto due volte comparirebbe
///    due volte nella relazione, e chi la legge concluderebbe che i fatti sono
///    due.
/// 2. **Ordine stabile.** Gli identificativi sono tenuti ordinati, cosi' che
///    due generazioni dalla stessa selezione producano lo stesso documento:
///    e' meta' del determinismo chiesto da DEC-152, e l'altra meta' e' del
///    renderer.
/// 3. **Il vuoto e' legittimo.** Una selezione vuota non e' un errore: e' il
///    caso della relazione a esito negativo, che si produce ugualmente.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReportSelection {
    contents: Vec<ContentId>,
}

impl ReportSelection {
    /// La selezione vuota: nessun elemento scelto.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            contents: Vec::new(),
        }
    }

    /// Costruisce la selezione da un elenco qualunque, deduplicando e
    /// ordinando.
    ///
    /// Accetta ripetizioni e disordine invece di rifiutarli: chi seleziona
    /// nell'interfaccia clicca, e il doppio clic su una riga non e' un errore
    /// da segnalare — e' una cosa da assorbire.
    #[must_use]
    pub fn from_contents(contents: impl IntoIterator<Item = ContentId>) -> Self {
        let mut collected: Vec<ContentId> = contents.into_iter().collect();
        collected.sort_unstable();
        collected.dedup();
        Self {
            contents: collected,
        }
    }

    /// Gli identificativi scelti, ordinati e senza ripetizioni.
    #[must_use]
    pub fn contents(&self) -> &[ContentId] {
        &self.contents
    }

    /// Quanti elementi sono stati scelti.
    #[must_use]
    pub fn len(&self) -> usize {
        self.contents.len()
    }

    /// Se non e' stato scelto alcun elemento.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.contents.is_empty()
    }

    /// Se un contenuto e' fra quelli scelti.
    #[must_use]
    pub fn contains(&self, content: ContentId) -> bool {
        self.contents.binary_search(&content).is_ok()
    }

    /// Esito documentale che discende dalla selezione.
    #[must_use]
    pub const fn outcome(&self) -> ReportOutcome {
        if self.contents.is_empty() {
            ReportOutcome::NothingSelected
        } else {
            ReportOutcome::WithFindings
        }
    }
}

/// Che tipo di relazione si sta producendo.
///
/// Non e' un giudizio sui fatti: e' una constatazione su una **scelta**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportOutcome {
    /// L'operatore non ha selezionato alcun elemento.
    NothingSelected,
    /// L'operatore ha selezionato uno o piu' elementi.
    WithFindings,
}

impl ReportOutcome {
    /// Frase che la relazione usa per dichiarare il proprio esito.
    ///
    /// # Perche' questa frase sta in una costante e non in un template
    ///
    /// E' la frase piu' delicata dell'intero prodotto. Una relazione che
    /// dicesse «non risultano elementi illeciti» affermerebbe un **fatto** che
    /// nessuno ha accertato; questa dichiara una **scelta**, che e' l'unica
    /// cosa che il programma sappia davvero. Tenerla qui, sotto un test che ne
    /// vieta le formulazioni sbagliate, la mette al riparo da una riscrittura
    /// distratta dentro un template.
    #[must_use]
    pub const fn declaration(self) -> &'static str {
        match self {
            // Gli accenti si scrivono per esteso, e non e' un vezzo: questa
            // frase finisce **stampata** in un documento che un ufficio
            // consegna, dove «e'» al posto di «è» e' italiano sbagliato. La
            // convenzione ASCII di questo repository riguarda i commenti; il
            // testo destinato alla carta no (MP-18C-R).
            Self::NothingSelected => {
                "Nessun elemento è stato selezionato dall'operatore per essere \
                 rappresentato nella presente relazione."
            }
            Self::WithFindings => {
                "Gli elementi di seguito rappresentati sono stati selezionati \
                 dall'operatore fra quelli acquisiti nel corso dell'attività."
            }
        }
    }
}

/// Come stava **un** contenuto al momento della generazione.
///
/// # Perche' si conserva l'impronta e non il testo
///
/// Il corpo del messaggio ha gia' la propria impronta nell'archivio
/// (`contents.body_sha256`). Conservarla qui permette di rispondere in seguito
/// alla domanda *il testo di allora e' il testo di adesso?* senza tenere una
/// seconda copia del contenuto. Duplicare i testi moltiplicherebbe i luoghi da
/// proteggere, ed e' esattamente cio' che il threat model del reporting chiede
/// di non fare (R-03, R-06).
///
/// **Il prezzo, dichiarato:** se un contenuto venisse cancellato dall'archivio,
/// dallo snapshot si sapra' che c'era, con quale livello, con quale stato di
/// revisione e con quale impronta — non che cosa diceva.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportContentSnapshot {
    /// Contenuto fotografato.
    pub content_id: ContentId,
    /// Livello proposto dal motore **al momento della generazione**.
    pub level: AnalysisLevel,
    /// Stato della revisione umana al momento della generazione, se ce n'era una.
    pub review_state: Option<ReviewState>,
    /// Impronta del corpo, per dire in seguito se il testo e' lo stesso.
    pub body_sha256: Sha256Digest,
    /// Se questo contenuto e' fra quelli che l'operatore ha scelto di
    /// rappresentare nella relazione.
    pub selected: bool,
}

/// Fotografia logica dei dati con cui un pacchetto e' stato prodotto.
///
/// L'archivio e' vivo: arrivano contenuti, cambiano stati di revisione, si
/// aggiornano i dizionari. Senza questa fotografia, alla domanda *con quali
/// dati e' stato prodotto quel documento?* si potrebbe rispondere soltanto
/// «non e' piu' ricostruibile» — e un documento che non si sa spiegare vale
/// molto meno di uno che si sa spiegare (DEC-152).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportSnapshot {
    /// Istante in cui la fotografia e' stata presa.
    pub taken_at: Timestamp,
    /// Sessione documentata.
    pub session_id: SessionId,
    /// Fonti effettivamente monitorate nella sessione.
    pub source_ids: Vec<SourceId>,
    /// Versioni di dizionario in vigore al momento della generazione.
    pub dictionary_version_ids: Vec<DictionaryVersionId>,
    /// Versione del profilo di template che ha prodotto i documenti.
    pub template_version: u32,
    /// Tutti i contenuti monitorati, selezionati e non.
    pub contents: Vec<ReportContentSnapshot>,
}

impl ReportSnapshot {
    /// Quanti contenuti la sessione aveva al momento della generazione.
    #[must_use]
    pub fn monitored_count(&self) -> usize {
        self.contents.len()
    }

    /// Quanti contenuti l'operatore aveva scelto di rappresentare.
    #[must_use]
    pub fn selected_count(&self) -> usize {
        self.contents
            .iter()
            .filter(|content| content.selected)
            .count()
    }

    /// Quanti contenuti **non** sono stati rappresentati.
    ///
    /// Non e' un dettaglio di comodita': e' il numero che la schermata deve
    /// mostrare accanto a quello dei selezionati, perche' una selezione si
    /// giudica sapendo che cosa resta fuori.
    #[must_use]
    pub fn excluded_count(&self) -> usize {
        self.monitored_count() - self.selected_count()
    }

    /// La selezione ricostruita dalla fotografia.
    ///
    /// Serve a verificare che il pacchetto e la sua fotografia dicano la stessa
    /// cosa: due fonti della stessa verita' che divergono sono peggio di una
    /// sola.
    #[must_use]
    pub fn selection(&self) -> ReportSelection {
        ReportSelection::from_contents(
            self.contents
                .iter()
                .filter(|content| content.selected)
                .map(|content| content.content_id),
        )
    }

    /// Esito documentale che discende dalla fotografia.
    #[must_use]
    pub fn outcome(&self) -> ReportOutcome {
        if self.selected_count() == 0 {
            ReportOutcome::NothingSelected
        } else {
            ReportOutcome::WithFindings
        }
    }
}

/// Artefatto che si intende registrare dopo averlo prodotto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewReportArtifact {
    /// Genere dell'artefatto.
    pub kind: ReportArtifactKind,
    /// Nome del file consegnato, senza percorso.
    pub file_name: String,
    /// Dimensione in byte del file prodotto.
    pub size_bytes: u64,
    /// Impronta del file prodotto.
    pub sha256: Sha256Digest,
}

/// Artefatto registrato dentro un pacchetto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportArtifact {
    /// Identificatore assegnato dalla persistenza.
    pub id: ReportArtifactId,
    /// Pacchetto che lo contiene.
    pub package_id: ReportPackageId,
    /// Genere dell'artefatto.
    pub kind: ReportArtifactKind,
    /// Nome del file consegnato, senza percorso.
    pub file_name: String,
    /// Dimensione in byte.
    pub size_bytes: u64,
    /// Impronta del file.
    pub sha256: Sha256Digest,
}

string_enum!(
    /// Stato della generazione di un pacchetto.
    ///
    /// Gli stati esistono perche' una generazione puo' fallire **a meta'**:
    /// cinque documenti sono cinque scritture, e un pacchetto interrotto deve
    /// essere riconoscibile come tale invece di sembrare completo.
    ReportGenerationStatus {
        /// Selezione e dati raccolti; nessun file ancora scritto.
        Prepared => "prepared",
        /// Scrittura in corso.
        Generating => "generating",
        /// Tutti gli artefatti richiesti sono stati prodotti e il manifest e'
        /// stato scritto per ultimo.
        Completed => "completed",
        /// La generazione si e' interrotta. Cio' che era stato scritto e'
        /// stato rimosso, o e' dichiarato incompleto.
        Failed => "failed",
    }
);

impl ReportGenerationStatus {
    /// Se il pacchetto e' utilizzabile da chi lo riceve.
    #[must_use]
    pub const fn is_deliverable(self) -> bool {
        matches!(self, Self::Completed)
    }

    /// Frase destinata all'operatore.
    #[must_use]
    pub const fn operator_label(self) -> &'static str {
        match self {
            Self::Prepared => "Pronto per la generazione",
            Self::Generating => "Generazione in corso",
            Self::Completed => "Completato",
            Self::Failed => "Non riuscito",
        }
    }
}

/// Che cosa l'operatore ha chiesto di produrre.
///
/// E' l'ingresso della generazione: un solo tipo invece di sette argomenti
/// sciolti, perche' sette argomenti dello stesso genere sono sette occasioni di
/// scambiarne due senza che il compilatore se ne accorga.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportRequest {
    /// Identificativo citabile, presente in ogni artefatto.
    pub report_id: ReportId,
    /// Sessione documentata.
    pub session_id: SessionId,
    /// Chi ha chiesto la generazione.
    pub requested_by: Actor,
    /// Elementi scelti per la parte narrativa.
    ///
    /// **E' un atto umano**, e il servizio la riceve: non la deduce, non la
    /// completa e non la corregge.
    pub selection: ReportSelection,
    /// Generi di artefatto richiesti.
    ///
    /// Nessun formato e' obbligatorio: il manifest coprira' quelli prodotti.
    pub requested_kinds: Vec<ReportArtifactKind>,
    /// Versione del profilo di template con cui comporre i documenti.
    pub template_version: u32,
    /// Istante della richiesta.
    pub requested_at: Timestamp,
}

/// Pacchetto registrato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportPackage {
    /// Identificatore assegnato dalla persistenza.
    pub id: ReportPackageId,
    /// Identificativo citabile.
    pub report_id: ReportId,
    /// Sessione documentata.
    pub session_id: SessionId,
    /// Chi ha chiesto la generazione.
    pub requested_by: Actor,
    /// Elementi scelti per la parte narrativa.
    pub selection: ReportSelection,
    /// Stato della generazione.
    pub status: ReportGenerationStatus,
    /// Istante della richiesta.
    pub requested_at: Timestamp,
    /// Istante del completamento, quando c'e' stato.
    pub completed_at: Option<Timestamp>,
    /// Artefatti prodotti.
    pub artifacts: Vec<ReportArtifact>,
}

impl ReportPackage {
    /// Esito documentale del pacchetto.
    #[must_use]
    pub const fn outcome(&self) -> ReportOutcome {
        self.selection.outcome()
    }

    /// Se il pacchetto contiene un artefatto di quel genere.
    #[must_use]
    pub fn contains(&self, kind: ReportArtifactKind) -> bool {
        self.artifacts.iter().any(|artifact| artifact.kind == kind)
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::{
        ReportArtifactKind, ReportContentSnapshot, ReportGenerationStatus, ReportId, ReportOutcome,
        ReportScope, ReportSelection, ReportSnapshot,
    };
    use crate::digest::Sha256Digest;
    use crate::error::DomainError;
    use crate::id::{ContentId, SessionId, SourceId};
    use crate::model::analysis::AnalysisLevel;
    use crate::time::Timestamp;

    // --------------------------------------------------------------- generi

    #[test]
    fn every_kind_survives_a_round_trip_through_its_stored_form() {
        for kind in ReportArtifactKind::all() {
            assert_eq!(ReportArtifactKind::from_str(kind.as_str()), Ok(*kind));
        }
    }

    #[test]
    fn the_six_artefacts_of_the_package_are_present() {
        assert_eq!(
            ReportArtifactKind::all(),
            &[
                ReportArtifactKind::NarrativeDocx,
                ReportArtifactKind::NarrativePdf,
                ReportArtifactKind::TechnicalAnnexPdf,
                ReportArtifactKind::AnalyticalXlsx,
                ReportArtifactKind::PlainTxt,
                ReportArtifactKind::Manifest,
            ]
        );
    }

    #[test]
    fn the_legacy_word_format_is_not_a_variant() {
        // Il `.doc` binario non e' supportato, ed e' una decisione (ADR-0031).
        assert!(matches!(
            ReportArtifactKind::from_str("relazione_doc"),
            Err(DomainError::UnknownVariant { .. })
        ));
    }

    #[test]
    fn only_the_two_narrative_documents_represent_the_selection() {
        // E' la Decisione 1 di ADR-0031 provata sul tipo: se un giorno
        // qualcuno aggiungesse un documento narrativo dimenticando di
        // dichiararne l'ambito, questo test lo fermerebbe.
        let narrative: Vec<_> = ReportArtifactKind::all()
            .iter()
            .filter(|kind| kind.scope() == ReportScope::OperatorSelection)
            .copied()
            .collect();
        assert_eq!(
            narrative,
            vec![
                ReportArtifactKind::NarrativeDocx,
                ReportArtifactKind::NarrativePdf
            ]
        );
    }

    #[test]
    fn the_technical_annex_and_the_register_represent_everything_monitored() {
        assert_eq!(
            ReportArtifactKind::TechnicalAnnexPdf.scope(),
            ReportScope::EverythingMonitored
        );
        assert_eq!(
            ReportArtifactKind::AnalyticalXlsx.scope(),
            ReportScope::EverythingMonitored
        );
        assert_eq!(
            ReportArtifactKind::PlainTxt.scope(),
            ReportScope::EverythingMonitored
        );
    }

    #[test]
    fn the_manifest_describes_the_package_and_not_the_contents() {
        assert_eq!(
            ReportArtifactKind::Manifest.scope(),
            ReportScope::ThePackageItself
        );
    }

    #[test]
    fn only_the_docx_is_editable() {
        let editable: Vec<_> = ReportArtifactKind::all()
            .iter()
            .filter(|kind| kind.is_editable())
            .copied()
            .collect();
        assert_eq!(editable, vec![ReportArtifactKind::NarrativeDocx]);
    }

    #[test]
    fn every_kind_declares_an_extension_without_a_dot() {
        for kind in ReportArtifactKind::all() {
            let extension = kind.extension();
            assert!(!extension.is_empty());
            assert!(!extension.contains('.'));
        }
    }

    #[test]
    fn the_two_pdf_documents_have_different_names() {
        // Portano la stessa estensione e finirebbero nella stessa cartella:
        // un nome uguale significherebbe che il secondo cancella il primo.
        assert_ne!(
            ReportArtifactKind::NarrativePdf.file_stem(),
            ReportArtifactKind::TechnicalAnnexPdf.file_stem()
        );
    }

    #[test]
    fn no_file_stem_contains_a_separator_or_a_space() {
        for kind in ReportArtifactKind::all() {
            let stem = kind.file_stem();
            assert!(!stem.contains(' '), "{stem} contiene uno spazio");
            assert!(!stem.contains('/'), "{stem} contiene una barra");
            assert!(!stem.contains('\\'), "{stem} contiene una barra rovescia");
        }
    }

    // ------------------------------------------------------- identificativo

    #[test]
    fn a_composed_identifier_has_the_expected_shape() {
        assert_eq!(ReportId::from_sequence(2026, 42).as_str(), "R-2026-000042");
    }

    #[test]
    fn a_composed_identifier_is_always_valid() {
        for sequence in [0, 1, 42, 999_999] {
            let composed = ReportId::from_sequence(2026, sequence);
            assert_eq!(ReportId::try_new(composed.as_str()), Ok(composed));
        }
    }

    #[test]
    fn two_sequences_never_produce_the_same_identifier() {
        assert_ne!(
            ReportId::from_sequence(2026, 1),
            ReportId::from_sequence(2026, 2)
        );
        assert_ne!(
            ReportId::from_sequence(2026, 1),
            ReportId::from_sequence(2027, 1)
        );
    }

    #[test]
    fn an_empty_identifier_is_rejected() {
        assert!(matches!(
            ReportId::try_new("   "),
            Err(DomainError::Empty { .. })
        ));
    }

    #[test]
    fn an_identifier_longer_than_the_limit_is_rejected() {
        let long = "R".repeat(ReportId::MAX_CHARS + 1);
        assert!(matches!(
            ReportId::try_new(&long),
            Err(DomainError::TooLong { .. })
        ));
    }

    #[test]
    fn an_identifier_that_could_break_a_file_name_is_rejected() {
        // Questo valore finisce in un nome di file, in un documento e in una
        // riga di manifest: uno solo di questi caratteri basterebbe a
        // rovinarne almeno uno.
        for hostile in [
            "R-2026-000001/..",
            "R-2026-000001 001",
            "R:2026:000001",
            "R-2026-000001\u{202e}",
            "r-2026-000001",
        ] {
            assert!(
                ReportId::try_new(hostile).is_err(),
                "accettato un identificativo ostile: {hostile}"
            );
        }
    }

    // ------------------------------------------------------------ selezione

    #[test]
    fn an_empty_selection_is_legitimate_and_says_so() {
        let selection = ReportSelection::empty();
        assert!(selection.is_empty());
        assert_eq!(selection.len(), 0);
        assert_eq!(selection.outcome(), ReportOutcome::NothingSelected);
    }

    #[test]
    fn a_selection_removes_duplicates() {
        // Il doppio clic su una riga non e' un errore da segnalare: e' una
        // cosa da assorbire. Un contenuto rappresentato due volte farebbe
        // concludere a chi legge che i fatti sono due.
        let selection = ReportSelection::from_contents([
            ContentId::new(7),
            ContentId::new(3),
            ContentId::new(7),
        ]);
        assert_eq!(selection.len(), 2);
        assert_eq!(
            selection.contents(),
            &[ContentId::new(3), ContentId::new(7)]
        );
    }

    #[test]
    fn a_selection_keeps_a_stable_order() {
        // Meta' del determinismo chiesto da DEC-152: due generazioni dalla
        // stessa selezione devono partire dallo stesso elenco.
        let one = ReportSelection::from_contents([ContentId::new(9), ContentId::new(1)]);
        let other = ReportSelection::from_contents([ContentId::new(1), ContentId::new(9)]);
        assert_eq!(one, other);
        assert_eq!(one.contents(), other.contents());
    }

    #[test]
    fn a_selection_answers_whether_it_contains_a_content() {
        let selection = ReportSelection::from_contents([ContentId::new(4), ContentId::new(8)]);
        assert!(selection.contains(ContentId::new(4)));
        assert!(!selection.contains(ContentId::new(5)));
    }

    #[test]
    fn a_selection_with_contents_declares_findings() {
        let selection = ReportSelection::from_contents([ContentId::new(1)]);
        assert_eq!(selection.outcome(), ReportOutcome::WithFindings);
    }

    // ---------------------------------------------------------------- esito

    #[test]
    fn the_negative_declaration_speaks_of_a_choice_and_not_of_a_fact() {
        let declaration = ReportOutcome::NothingSelected.declaration();
        assert!(declaration.contains("selezionato dall'operatore"));
    }

    #[test]
    fn the_negative_declaration_never_asserts_the_absence_of_offences() {
        // E' il criterio 4 di accettazione della Milestone 18, provato qui
        // sulla costante invece che a valle sul documento prodotto: piu' e'
        // vicino alla fonte, meno strade ci sono per aggirarlo.
        let declaration = ReportOutcome::NothingSelected.declaration().to_lowercase();
        for forbidden in [
            "illecit",
            "non sussist",
            "nulla di rilevante",
            "non risultano element",
            "reato",
        ] {
            assert!(
                !declaration.contains(forbidden),
                "la dichiarazione a esito negativo contiene «{forbidden}»"
            );
        }
    }

    // ------------------------------------------------------------ fotografia

    fn snapshot(selected: &[i64], monitored: &[i64]) -> ReportSnapshot {
        let contents = monitored
            .iter()
            .map(|raw| ReportContentSnapshot {
                content_id: ContentId::new(*raw),
                level: AnalysisLevel::try_new(0).expect("il livello 0 e' valido"),
                review_state: None,
                body_sha256: Sha256Digest::of_text("corpo di prova"),
                selected: selected.contains(raw),
            })
            .collect();

        ReportSnapshot {
            taken_at: Timestamp::from_millis(0),
            session_id: SessionId::new(1),
            source_ids: vec![SourceId::new(1)],
            dictionary_version_ids: Vec::new(),
            template_version: 1,
            contents,
        }
    }

    #[test]
    fn a_snapshot_counts_what_was_monitored_and_what_was_chosen() {
        let taken = snapshot(&[2, 4], &[1, 2, 3, 4, 5]);
        assert_eq!(taken.monitored_count(), 5);
        assert_eq!(taken.selected_count(), 2);
        assert_eq!(taken.excluded_count(), 3);
    }

    #[test]
    fn a_snapshot_rebuilds_the_selection_it_was_taken_with() {
        // Il pacchetto e la sua fotografia devono dire la stessa cosa: due
        // fonti della stessa verita' che divergono sono peggio di una sola.
        let taken = snapshot(&[3, 1], &[1, 2, 3]);
        assert_eq!(
            taken.selection(),
            ReportSelection::from_contents([ContentId::new(1), ContentId::new(3)])
        );
    }

    #[test]
    fn a_snapshot_without_selected_contents_declares_a_negative_outcome() {
        let taken = snapshot(&[], &[1, 2, 3]);
        assert_eq!(taken.outcome(), ReportOutcome::NothingSelected);
        assert_eq!(taken.excluded_count(), 3);
    }

    #[test]
    fn a_snapshot_of_an_empty_session_is_still_a_snapshot() {
        // Una sessione che non ha acquisito nulla produce ugualmente una
        // relazione: e' il caso a esito negativo piu' estremo.
        let taken = snapshot(&[], &[]);
        assert_eq!(taken.monitored_count(), 0);
        assert_eq!(taken.outcome(), ReportOutcome::NothingSelected);
    }

    // ----------------------------------------------------------------- stato

    #[test]
    fn only_a_completed_package_is_deliverable() {
        let deliverable: Vec<_> = ReportGenerationStatus::all()
            .iter()
            .filter(|status| status.is_deliverable())
            .copied()
            .collect();
        assert_eq!(deliverable, vec![ReportGenerationStatus::Completed]);
    }

    #[test]
    fn every_status_survives_a_round_trip_through_its_stored_form() {
        for status in ReportGenerationStatus::all() {
            assert_eq!(
                ReportGenerationStatus::from_str(status.as_str()),
                Ok(*status)
            );
        }
    }
}

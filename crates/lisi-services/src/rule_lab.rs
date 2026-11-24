//! «Che cosa cambierebbe, se pubblicassi questa versione del dizionario?»
//!
//! # La garanzia strutturale, e perché non è una convenzione
//!
//! Questo modulo **non conosce l'archivio**. Non importa `Database`, non ne
//! riceve uno, non ne apre uno: riceve i contenuti già letti e restituisce un
//! confronto. Non può scrivere un risultato operativo perché **non ha nulla con
//! cui scrivere**.
//!
//! È la stessa forma di garanzia con cui questo prodotto tiene fuori
//! l'intelligenza artificiale (ADR-0048): la guardia forte non è un elenco di
//! divieti, è l'assenza della capacità. Un divieto si dimentica; una capacità
//! che non c'è non si usa per sbaglio.
//!
//! Una prova negativa legge questo file e fallisce se vi compare `Database`.
//!
//! # Il confronto non è una simulazione: è lo stesso motore
//!
//! `analyse` è una funzione **pura** di `lisi-core`, e il laboratorio la chiama
//! esattamente come la chiama l'acquisizione. Se il laboratorio avesse un
//! motore proprio, direbbe che cosa farebbe **quel** motore, e la risposta non
//! varrebbe niente per decidere se pubblicare.
//!
//! # La trappola che questo modulo esiste per evitare
//!
//! Attribuire al candidato una differenza che viene da altro. I livelli
//! nell'archivio sono stati calcolati con la configurazione **di quella
//! sessione**: se la versione pubblicata che si passa qui non è quella, i
//! livelli non coincideranno, e la differenza sarebbe del confronto, non del
//! candidato.
//!
//! Il laboratorio **ricalcola anche il pubblicato** e verifica che riproduca il
//! livello archiviato. Quando non lo riproduce, lo **dichiara** invece di
//! tacerlo: è la disciplina di PROV-01, applicata al laboratorio.

use std::collections::{BTreeMap, BTreeSet};

use lisi_core::analysis::analyse;
use lisi_core::model::dictionary::{
    DictionaryTerm, MatchMode, ResolvedDictionaryConfiguration, normalise_for_matching,
};
use lisi_core::text::counted;
use lisi_core::{ContentId, DictionaryId, DictionaryVersionId};

/// Un contenuto archiviato, come il laboratorio lo vede.
///
/// Tre cose e nient'altro: chi è, che cosa dice, e che livello gli fu
/// attribuito. L'autore, la fonte, l'URL e gli istanti non entrano: il
/// confronto non li guarda, e ciò che non entra non si può mostrare per
/// sbaglio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabContent {
    /// Quale contenuto.
    pub content_id: ContentId,
    /// Il corpo su cui il motore lavora.
    pub body: String,
    /// Il livello registrato nell'archivio.
    pub recorded_level: u8,
}

impl LabContent {
    /// Compone i contenuti del laboratorio da righe già lette.
    ///
    /// # Perché una tupla e non un tipo dell'archivio
    ///
    /// Perché il laboratorio non deve conoscere l'archivio, e un tipo
    /// dell'archivio lo costringerebbe a importarlo. La tupla è il confine: chi
    /// legge sta di là, chi confronta sta di qua, e ciò che passa sono tre
    /// valori.
    #[must_use]
    pub fn from_rows(rows: Vec<(ContentId, String, u8)>) -> Vec<Self> {
        rows.into_iter()
            .map(|(content_id, body, recorded_level)| Self {
                content_id,
                body,
                recorded_level,
            })
            .collect()
    }
}

/// Come il livello si muove fra pubblicato e candidato.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LevelShift {
    /// Stesso livello.
    Unchanged,
    /// Il candidato alza il livello.
    Raised,
    /// Il candidato abbassa il livello.
    Lowered,
}

/// Che cosa cambia su un contenuto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabFinding {
    /// Quale contenuto.
    pub content_id: ContentId,
    /// Livello che la versione pubblicata produce **adesso**.
    pub published_level: u8,
    /// Livello che il candidato produce.
    pub candidate_level: u8,
    /// Livello che risulta nell'archivio.
    pub recorded_level: u8,
    /// Come il livello si muove.
    pub shift: LevelShift,
    /// Termini che il candidato trova e il pubblicato no.
    pub new_terms: Vec<String>,
    /// Termini che il pubblicato trova e il candidato no.
    pub lost_terms: Vec<String>,
}

impl LabFinding {
    /// Se il pubblicato riproduce il livello che sta nell'archivio.
    ///
    /// # Perché conta
    ///
    /// Perché quando **non** lo riproduce, la differenza che si sta guardando
    /// non è necessariamente del candidato: può venire dal fatto che quel
    /// contenuto fu analizzato con una configurazione diversa da quella che si
    /// è passata come «pubblicata». Attribuirla al candidato sarebbe una falsa
    /// attribuzione.
    #[must_use]
    pub const fn reproduces_archive(&self) -> bool {
        self.published_level == self.recorded_level
    }

    /// Se qualcosa cambia davvero fra pubblicato e candidato.
    #[must_use]
    pub fn is_a_difference(&self) -> bool {
        !matches!(self.shift, LevelShift::Unchanged)
            || !self.new_terms.is_empty()
            || !self.lost_terms.is_empty()
    }

    /// La ragione, detta con i fatti del confronto.
    #[must_use]
    pub fn reason(&self) -> String {
        let mut parti = Vec::new();
        match self.shift {
            LevelShift::Raised => parti.push(format!(
                "livello da {} a {}",
                self.published_level, self.candidate_level
            )),
            LevelShift::Lowered => parti.push(format!(
                "livello da {} a {}",
                self.published_level, self.candidate_level
            )),
            LevelShift::Unchanged => {
                parti.push(format!("livello {} invariato", self.published_level))
            }
        }
        if !self.new_terms.is_empty() {
            parti.push(lisi_core::text::counted(
                self.new_terms.len(),
                "termine nuovo",
                "termini nuovi",
            ));
        }
        if !self.lost_terms.is_empty() {
            parti.push(lisi_core::text::counted(
                self.lost_terms.len(),
                "termine perso",
                "termini persi",
            ));
        }
        if !self.reproduces_archive() {
            parti.push(format!(
                "ATTENZIONE: la versione pubblicata produce {} ma l'archivio registra {}. \
                 Questo contenuto fu analizzato con una configurazione diversa: la \
                 differenza non è attribuibile alla bozza",
                self.published_level, self.recorded_level
            ));
        }
        parti.join(" · ")
    }
}

/// L'esito del confronto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabComparison {
    /// I contenuti su cui **qualcosa cambia**, in ordine di contenuto.
    pub findings: Vec<LabFinding>,
    /// Quanti contenuti sono stati esaminati.
    pub examined: usize,
    /// Su quanti la versione pubblicata **non** riproduce l'archivio.
    pub not_reproducing: usize,
}

impl LabComparison {
    /// Quanti contenuti salgono di livello.
    #[must_use]
    pub fn raised(&self) -> usize {
        self.count(LevelShift::Raised)
    }

    /// Quanti contenuti scendono di livello.
    #[must_use]
    pub fn lowered(&self) -> usize {
        self.count(LevelShift::Lowered)
    }

    fn count(&self, shift: LevelShift) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.shift == shift)
            .count()
    }

    /// Quanti contenuti guadagnano almeno un termine.
    #[must_use]
    pub fn with_new_terms(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| !finding.new_terms.is_empty())
            .count()
    }

    /// Quanti contenuti perdono almeno un termine.
    #[must_use]
    pub fn with_lost_terms(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| !finding.lost_terms.is_empty())
            .count()
    }

    /// La frase dell'esito.
    ///
    /// # Perché nomina sempre quanti contenuti sono stati esaminati
    ///
    /// Perché «tre contenuti salgono di livello» significa una cosa su dieci
    /// contenuti e un'altra su diecimila, e senza il denominatore chi legge non
    /// può giudicare se la modifica sia piccola o grande.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        if self.examined == 0 {
            return String::from(
                "Nessun contenuto esaminato: il confronto non dice nulla del candidato.",
            );
        }
        if self.findings.is_empty() {
            return format!(
                "Su {} contenuti esaminati, nessuna differenza fra la versione pubblicata \
                 e la candidata.",
                self.examined
            );
        }

        let mut frase = format!(
            "Su {} contenuti esaminati, {} cambiano",
            self.examined,
            self.findings.len()
        );
        if self.raised() > 0 {
            frase.push_str(&format!(", {} salgono di livello", self.raised()));
        }
        if self.lowered() > 0 {
            frase.push_str(&format!(", {} scendono", self.lowered()));
        }
        if self.with_new_terms() > 0 {
            frase.push_str(&format!(", {} guadagnano termini", self.with_new_terms()));
        }
        if self.with_lost_terms() > 0 {
            frase.push_str(&format!(", {} ne perdono", self.with_lost_terms()));
        }
        frase.push('.');

        if self.not_reproducing > 0 {
            frase.push_str(&format!(
                " Su {} dei contenuti esaminati la versione pubblicata NON riproduce il livello \
                 registrato nell'archivio: quelle differenze non sono attribuibili al \
                 candidato.",
                self.not_reproducing
            ));
        }
        frase
    }
}

/// Dove sta, nella sessione, il dizionario che si confronta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceInSession {
    /// Con la stessa versione che il confronto usa come pubblicata.
    SameVersion,
    /// Con un'altra versione.
    OtherVersion,
    /// La sessione non lo usava.
    Absent,
}

/// Che cosa distingue la configurazione **registrata** della sessione da quella
/// del confronto (E2E01-14).
///
/// # Perché serve
///
/// «Su 153 la versione pubblicata NON riproduce il livello registrato» era
/// vero e non diceva perché. Il livello registrato fu calcolato con **tutti** i
/// dizionari della sessione e con le parole aggiunte alla sola sessione; il
/// Laboratorio ne confronta uno. Questi tre fatti stanno nell'archivio, e
/// bastano a dirlo. Quando nessuno dei tre distingue le due configurazioni, la
/// causa non è registrata, e la frase lo dice invece di indovinarla.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionDifference {
    /// Dizionari della sessione diversi da quello confrontato.
    pub other_dictionaries: usize,
    /// Parole aggiunte alla sola sessione.
    pub session_words: usize,
    /// Il dizionario confrontato, nella sessione.
    pub reference: ReferenceInSession,
}

impl SessionDifference {
    /// Ricava la differenza dai fatti della sessione.
    ///
    /// `selection` sono i dizionari scelti per la sessione con la loro
    /// versione; `reference` il dizionario e la versione che il confronto usa
    /// come pubblicata.
    #[must_use]
    pub fn from_selection(
        selection: &[(DictionaryId, DictionaryVersionId)],
        reference: (DictionaryId, DictionaryVersionId),
        session_words: usize,
    ) -> Self {
        let (dizionario, versione) = reference;
        let nella_sessione = selection.iter().find(|(id, _)| *id == dizionario);
        Self {
            other_dictionaries: selection.iter().filter(|(id, _)| *id != dizionario).count(),
            session_words,
            reference: match nella_sessione {
                Some((_, scelta)) if *scelta == versione => ReferenceInSession::SameVersion,
                Some(_) => ReferenceInSession::OtherVersion,
                None => ReferenceInSession::Absent,
            },
        }
    }

    /// La frase che spiega perché il pubblicato non riproduce l'archivio.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let mut parti = Vec::new();
        if self.other_dictionaries > 0 {
            parti.push(counted(
                self.other_dictionaries,
                "altro dizionario",
                "altri dizionari",
            ));
        }
        if self.session_words > 0 {
            parti.push(counted(
                self.session_words,
                "parola aggiunta alla sola sessione",
                "parole aggiunte alla sola sessione",
            ));
        }
        match self.reference {
            ReferenceInSession::SameVersion => {}
            ReferenceInSession::OtherVersion => {
                parti.push(String::from("un'altra versione del dizionario confrontato"));
            }
            ReferenceInSession::Absent => {
                parti.push(String::from("nessuna versione del dizionario confrontato"));
            }
        }
        if parti.is_empty() {
            return String::from(
                "La configurazione registrata della sessione coincide con quella confrontata: \
                 la causa della differenza non è registrata, per esempio il motore che analizzò \
                 quei contenuti.",
            );
        }
        let elenco = match parti.split_last() {
            Some((ultima, prime)) if !prime.is_empty() => {
                format!("{} e {ultima}", prime.join(", "))
            }
            _ => parti.concat(),
        };
        format!(
            "Perché: il livello registrato fu calcolato con la configurazione della sessione, \
             che aveva {elenco}. Il confronto usa soltanto il dizionario scelto."
        )
    }
}

/// Confronta due configurazioni su contenuti già archiviati.
///
/// # Che cosa questa funzione non ha, ed è la garanzia
///
/// Non ha un archivio, non ha un attore, non ha un istante. Non può registrare
/// nulla perché non ha nulla con cui registrare: la garanzia che
/// un'esecuzione a vuoto non scriva risultati operativi non è una regola che
/// qualcuno deve ricordare, è l'assenza della capacità.
///
/// # Il pubblicato si ricalcola, e non si legge dall'archivio
///
/// Perché il confronto deve essere **fra le due configurazioni**, sullo stesso
/// testo e con lo stesso motore. Prendere il livello archiviato come «il
/// pubblicato» confronterebbe due cose calcolate in momenti diversi, e ogni
/// differenza di configurazione passata si sommerebbe a quella del candidato.
///
/// Il livello archiviato entra comunque nel risultato, e serve a **verificare**:
/// se il pubblicato non lo riproduce, il confronto lo dichiara.
#[must_use]
pub fn compare(
    contents: &[LabContent],
    published: &ResolvedDictionaryConfiguration,
    candidate: &ResolvedDictionaryConfiguration,
) -> LabComparison {
    let mut findings = Vec::new();
    let mut not_reproducing = 0;

    for content in contents {
        let con_pubblicato = analyse(&content.body, published);
        let con_candidato = analyse(&content.body, candidate);

        let livello_pubblicato = con_pubblicato.outcome.level.get();
        let livello_candidato = con_candidato.outcome.level.get();

        let termini_pubblicato = termini_trovati(&con_pubblicato, published);
        let termini_candidato = termini_trovati(&con_candidato, candidate);

        let finding = LabFinding {
            content_id: content.content_id,
            published_level: livello_pubblicato,
            candidate_level: livello_candidato,
            recorded_level: content.recorded_level,
            shift: match livello_candidato.cmp(&livello_pubblicato) {
                std::cmp::Ordering::Greater => LevelShift::Raised,
                std::cmp::Ordering::Less => LevelShift::Lowered,
                std::cmp::Ordering::Equal => LevelShift::Unchanged,
            },
            new_terms: differenza(&termini_candidato, &termini_pubblicato),
            lost_terms: differenza(&termini_pubblicato, &termini_candidato),
        };

        if !finding.reproduces_archive() {
            not_reproducing += 1;
        }

        // Solo i contenuti su cui qualcosa cambia: un elenco che riporta anche
        // gli invariati costringe a cercare le differenze dentro il rumore, ed
        // è precisamente quello che il laboratorio deve evitare.
        if finding.is_a_difference() {
            findings.push(finding);
        }
    }

    LabComparison {
        findings,
        examined: contents.len(),
        not_reproducing,
    }
}

/// I termini trovati, nel testo originale e senza ripetizioni.
fn termini_trovati(
    analysed: &lisi_core::analysis::AnalysedContent,
    configuration: &ResolvedDictionaryConfiguration,
) -> Vec<String> {
    let mut trovati: Vec<String> = analysed
        .occurrences
        .iter()
        .filter_map(|occorrenza| configuration.terms.get(occorrenza.term_index))
        .map(|termine| termine.original.as_str().to_owned())
        .collect();
    trovati.sort_unstable();
    trovati.dedup();
    trovati
}

/// Che cosa sta nel primo elenco e non nel secondo.
fn differenza(primo: &[String], secondo: &[String]) -> Vec<String> {
    primo
        .iter()
        .filter(|termine| !secondo.contains(termine))
        .cloned()
        .collect()
}

// ------------------------------------------------- che cosa la bozza cambia
//
// LE DIFFERENZE DEI TERMINI (OPERATOR-E2E-REMEDIATION-01, F-07).
//
// Il confronto sui contenuti dice **che effetto** avrebbe la bozza su ciò che è
// già archiviato, e richiede un monitoraggio con dei contenuti. Questo dice
// **che cosa** la bozza cambia nel dizionario, e non richiede nulla: è la
// risposta alla prima domanda di chi sta per pubblicare — «che cosa ho
// toccato?» — e c'è anche sulla postazione appena installata.
//
// Funzione pura, come il resto del modulo: riceve due elenchi di termini già
// letti e non ha nulla con cui scrivere.

/// Un termine, come il confronto lo mostra.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TermSummary {
    /// Come lo ha scritto chi ha compilato il dizionario.
    pub text: String,
    /// Come viene cercato.
    pub match_mode: MatchMode,
    /// Il livello suggerito, con il segno.
    pub level: i8,
    /// La categoria.
    pub category: String,
}

impl TermSummary {
    fn of(term: &DictionaryTerm) -> Self {
        Self {
            text: term.text.as_str().to_owned(),
            match_mode: term.match_mode,
            level: term.suggested_level.get(),
            category: term.category.as_str().to_owned(),
        }
    }
}

/// Come un termine cambia fra la versione di riferimento e la bozza.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TermChange {
    /// C'è nella bozza e non nel riferimento.
    Added(TermSummary),
    /// C'era nel riferimento e la bozza non l'ha più.
    Removed(TermSummary),
    /// C'è in entrambi, cercato nello stesso modo, con livello o categoria
    /// diversi.
    Changed {
        /// Com'era nel riferimento.
        before: TermSummary,
        /// Com'è nella bozza.
        after: TermSummary,
    },
}

impl TermChange {
    /// La riga del confronto, detta a chi legge.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self {
            Self::Added(termine) => format!(
                "Aggiunto «{}» ({}, livello {:+}, categoria {}).",
                termine.text,
                termine.match_mode.label(),
                termine.level,
                termine.category
            ),
            Self::Removed(termine) => format!(
                "Tolto «{}» ({}, livello {:+}).",
                termine.text,
                termine.match_mode.label(),
                termine.level
            ),
            Self::Changed { before, after } => {
                let mut parti = Vec::new();
                if before.level != after.level {
                    parti.push(format!("livello da {:+} a {:+}", before.level, after.level));
                }
                if before.category != after.category {
                    parti.push(format!(
                        "categoria da «{}» a «{}»",
                        before.category, after.category
                    ));
                }
                format!("Cambiato «{}»: {}.", after.text, parti.join(", "))
            }
        }
    }

    /// Il segno del cambiamento, per la colonna dell'elenco.
    #[must_use]
    pub const fn sign(&self) -> &'static str {
        match self {
            Self::Added(_) => "+",
            Self::Removed(_) => "\u{2212}",
            Self::Changed { .. } => "~",
        }
    }
}

/// Che cosa la bozza cambia rispetto alla versione di riferimento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TermDifferences {
    /// I cambiamenti, in ordine di termine.
    pub changes: Vec<TermChange>,
    /// Quanti termini restano uguali.
    pub unchanged: usize,
    /// Quanti termini ha il riferimento.
    pub baseline_terms: usize,
    /// Quanti termini ha la bozza.
    pub candidate_terms: usize,
}

impl TermDifferences {
    /// Quanti termini la bozza aggiunge.
    #[must_use]
    pub fn added(&self) -> usize {
        self.changes
            .iter()
            .filter(|c| matches!(c, TermChange::Added(_)))
            .count()
    }

    /// Quanti termini la bozza toglie.
    #[must_use]
    pub fn removed(&self) -> usize {
        self.changes
            .iter()
            .filter(|c| matches!(c, TermChange::Removed(_)))
            .count()
    }

    /// Quanti termini la bozza cambia.
    #[must_use]
    pub fn changed(&self) -> usize {
        self.changes
            .iter()
            .filter(|c| matches!(c, TermChange::Changed { .. }))
            .count()
    }

    /// Se la bozza è identica al riferimento.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// La frase del confronto. Dice sempre i due totali: «due aggiunti» vale
    /// una cosa su dieci termini e un'altra su tremila.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        if self.is_empty() {
            return format!(
                "La bozza è uguale alla versione di riferimento: {} termini, nessuna \
                 differenza. Pubblicarla produrrebbe una versione nuova con gli stessi \
                 termini.",
                self.candidate_terms
            );
        }
        format!(
            "Rispetto alla versione di riferimento ({} termini), la bozza ({} termini) \
             aggiunge {}, toglie {} e cambia {} termini; {} restano uguali.",
            self.baseline_terms,
            self.candidate_terms,
            self.added(),
            self.removed(),
            self.changed(),
            self.unchanged
        )
    }
}

/// Confronta i termini della versione di riferimento con quelli della bozza.
///
/// Due termini sono **lo stesso** quando coincidono il testo normalizzato e la
/// modalità di riscontro: è la stessa identità con cui l'archivio impedisce
/// due righe uguali nella stessa versione, e la stessa del motore. Una parola
/// cercata come parola e come frase sono due termini.
#[must_use]
pub fn term_differences(
    baseline: &[DictionaryTerm],
    candidate: &[DictionaryTerm],
) -> TermDifferences {
    fn chiave(term: &DictionaryTerm) -> (String, &'static str) {
        (
            normalise_for_matching(term.text.as_str()),
            term.match_mode.as_str(),
        )
    }

    let prima: BTreeMap<_, _> = baseline.iter().map(|t| (chiave(t), t)).collect();
    let dopo: BTreeMap<_, _> = candidate.iter().map(|t| (chiave(t), t)).collect();

    let mut changes = Vec::new();
    let mut unchanged = 0_usize;
    let chiavi: BTreeSet<_> = prima.keys().chain(dopo.keys()).cloned().collect();
    for k in chiavi {
        match (prima.get(&k), dopo.get(&k)) {
            (None, Some(nuovo)) => changes.push(TermChange::Added(TermSummary::of(nuovo))),
            (Some(vecchio), None) => changes.push(TermChange::Removed(TermSummary::of(vecchio))),
            (Some(vecchio), Some(nuovo)) => {
                let (a, b) = (TermSummary::of(vecchio), TermSummary::of(nuovo));
                if a.level == b.level && a.category == b.category {
                    unchanged += 1;
                } else {
                    changes.push(TermChange::Changed {
                        before: a,
                        after: b,
                    });
                }
            }
            (None, None) => {}
        }
    }

    TermDifferences {
        changes,
        unchanged,
        baseline_terms: baseline.len(),
        candidate_terms: candidate.len(),
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::ContentId;
    use lisi_core::model::dictionary::MatchMode;
    use lisi_core::model::dictionary::{ResolvedDictionaryConfiguration, ResolvedTerm};
    use lisi_core::text::{LanguageTag, TermCategory, TermText};

    use lisi_core::model::dictionary::{DictionaryTerm, SuggestedLevel};
    use lisi_core::text::TermNote;
    use lisi_core::{DictionaryTermId, DictionaryVersionId};

    use super::{LabContent, LevelShift, TermChange, compare, term_differences};

    /// **Un termine si dice al singolare** (E2E01-15): «1 termini nuovi» era
    /// sullo schermo.
    #[test]
    fn un_termine_si_dice_al_singolare() {
        let riga = super::LabFinding {
            content_id: ContentId::new(1),
            published_level: 1,
            candidate_level: 2,
            recorded_level: 1,
            shift: LevelShift::Raised,
            new_terms: vec![String::from("rogo")],
            lost_terms: vec![String::from("fuoco")],
        };
        let frase = riga.reason();
        assert!(frase.contains("1 termine nuovo"), "{frase}");
        assert!(frase.contains("1 termine perso"), "{frase}");
    }

    /// **Il Laboratorio dice perché il pubblicato non riproduce l'archivio**
    /// (E2E01-14): altri dizionari, parole della sessione, versione diversa; e
    /// quando nulla le distingue, che la causa non è registrata.
    #[test]
    fn il_laboratorio_dice_perche_il_pubblicato_non_riproduce() {
        use super::{ReferenceInSession, SessionDifference};
        use lisi_core::DictionaryId;

        let (confrontato, altro) = (DictionaryId::new(1), DictionaryId::new(2));
        let (v1, v2, v9) = (
            DictionaryVersionId::new(1),
            DictionaryVersionId::new(2),
            DictionaryVersionId::new(9),
        );

        let differenza = SessionDifference::from_selection(
            &[(confrontato, v1), (altro, v9)],
            (confrontato, v2),
            3,
        );
        assert_eq!(differenza.other_dictionaries, 1);
        assert_eq!(differenza.reference, ReferenceInSession::OtherVersion);
        let frase = differenza.as_sentence();
        assert!(
            frase.contains(
                "1 altro dizionario, 3 parole aggiunte alla sola sessione e un'altra versione"
            ),
            "{frase}"
        );

        let uguale = SessionDifference::from_selection(&[(confrontato, v2)], (confrontato, v2), 0);
        assert_eq!(uguale.reference, ReferenceInSession::SameVersion);
        assert!(
            uguale.as_sentence().contains("non è registrata"),
            "{}",
            uguale.as_sentence()
        );

        let assente = SessionDifference::from_selection(&[(altro, v9)], (confrontato, v2), 1);
        let frase = assente.as_sentence();
        assert!(
            frase.contains("1 parola aggiunta alla sola sessione"),
            "{frase}"
        );
        assert!(
            frase.contains("nessuna versione del dizionario confrontato"),
            "{frase}"
        );
    }

    /// Questo modulo, per la guardia strutturale.
    const THIS_MODULE: &str = include_str!("rule_lab.rs");

    /// Una configurazione con i termini indicati.
    fn configurazione(termini: &[(&str, i8)]) -> ResolvedDictionaryConfiguration {
        let risolti: Vec<ResolvedTerm> = termini
            .iter()
            .map(|(testo, livello)| {
                let (Ok(original), Ok(language)) =
                    (TermText::try_new(testo), LanguageTag::try_new("it"))
                else {
                    panic!("i valori di prova devono essere validi");
                };
                ResolvedTerm {
                    normalised: testo.to_lowercase(),
                    original,
                    category: TermCategory::try_new("prova").expect("categoria valida"),
                    language,
                    match_mode: MatchMode::NormalizedWord,
                    suggested_level: *livello,
                    provenances: Vec::new(),
                }
            })
            .collect();

        ResolvedDictionaryConfiguration::from_terms(risolti)
    }

    fn contenuto(id: i64, body: &str, recorded_level: u8) -> LabContent {
        LabContent {
            content_id: ContentId::new(id),
            body: body.to_owned(),
            recorded_level,
        }
    }

    /// **Il laboratorio non conosce l'archivio, e non può scriverci.**
    ///
    /// # Perché è una guardia strutturale e non una convenzione
    ///
    /// Perché non vieta di scrivere: toglie il modo di farlo. Un divieto si
    /// dimentica; una capacità che non c'è non si usa per sbaglio. È la stessa
    /// forma con cui questo prodotto tiene fuori l'intelligenza artificiale.
    #[test]
    fn il_laboratorio_non_ha_alcun_modo_di_scrivere() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let codice: String = produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        for capacita in [
            "Database",
            "insert_",
            "append_audit",
            "NewMatch",
            "NewAlert",
            "NewContent",
            "&mut self",
        ] {
            assert!(
                !codice.contains(capacita),
                "il laboratorio nomina «{capacita}»: la garanzia che un'esecuzione a \
                 vuoto non scriva non è un divieto da ricordare, è l'assenza della \
                 capacità di scrivere"
            );
        }
    }

    /// Un candidato che aggiunge un termine fa salire il livello, e lo dice.
    #[test]
    fn un_termine_nuovo_alza_il_livello_e_compare_fra_i_nuovi() {
        let pubblicato = configurazione(&[("alfa", 1)]);
        let candidato = configurazione(&[("alfa", 1), ("beta", 4)]);
        let contenuti = [contenuto(1, "qui c'e' alfa e anche beta", 1)];

        let esito = compare(&contenuti, &pubblicato, &candidato);

        assert_eq!(esito.examined, 1);
        assert_eq!(esito.findings.len(), 1);
        assert_eq!(esito.raised(), 1);
        assert_eq!(esito.findings[0].shift, LevelShift::Raised);
        assert_eq!(esito.findings[0].new_terms, vec![String::from("beta")]);
        assert!(esito.findings[0].lost_terms.is_empty());
    }

    /// Un candidato che toglie un termine lo dichiara fra i persi.
    #[test]
    fn un_termine_tolto_compare_fra_i_persi() {
        let pubblicato = configurazione(&[("alfa", 3), ("beta", 1)]);
        let candidato = configurazione(&[("alfa", 3)]);
        let contenuti = [contenuto(1, "alfa e beta insieme", 3)];

        let esito = compare(&contenuti, &pubblicato, &candidato);

        assert_eq!(esito.findings.len(), 1);
        assert_eq!(esito.findings[0].lost_terms, vec![String::from("beta")]);
        assert_eq!(esito.with_lost_terms(), 1);
    }

    /// I contenuti su cui nulla cambia non entrano nell'elenco.
    ///
    /// Un elenco che riporta anche gli invariati costringe a cercare le
    /// differenze dentro il rumore.
    #[test]
    fn cio_che_non_cambia_non_entra_nell_elenco() {
        let configurazione = configurazione(&[("alfa", 2)]);
        let contenuti = [
            contenuto(1, "solo alfa", 2),
            contenuto(2, "niente di niente", 0),
        ];

        let esito = compare(&contenuti, &configurazione, &configurazione);

        assert_eq!(esito.examined, 2);
        assert!(esito.findings.is_empty());
        assert!(esito.as_sentence().contains("nessuna differenza"));
    }

    /// **Una differenza che non viene dal candidato si dichiara.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// I livelli nell'archivio sono stati calcolati con la configurazione di
    /// quella sessione. Se la versione «pubblicata» che si passa al laboratorio
    /// non è quella, i livelli non coincidono — e attribuire al candidato una
    /// differenza che viene da lì significherebbe far bocciare o approvare una
    /// modifica per la ragione sbagliata.
    #[test]
    fn una_differenza_che_non_viene_dal_candidato_si_dichiara() {
        let pubblicato = configurazione(&[("alfa", 1)]);
        let candidato = configurazione(&[("alfa", 1), ("beta", 3)]);
        // L'archivio registra 4: quel contenuto fu analizzato con altro.
        let contenuti = [contenuto(1, "alfa e beta", 4)];

        let esito = compare(&contenuti, &pubblicato, &candidato);

        assert_eq!(esito.not_reproducing, 1);
        assert!(!esito.findings[0].reproduces_archive());
        let ragione = esito.findings[0].reason();
        assert!(
            ragione.contains("non è attribuibile alla bozza"),
            "la ragione deve dichiarare che la differenza non viene dal candidato: \
             «{ragione}»"
        );
        assert!(
            esito.as_sentence().contains("NON riproduce il livello"),
            "l'esito complessivo deve dichiararlo: «{}»",
            esito.as_sentence()
        );
    }

    /// Senza contenuti il confronto non dice nulla, e lo dice.
    ///
    /// Un laboratorio che su zero contenuti rispondesse «nessuna differenza»
    /// farebbe approvare una modifica per non aver guardato niente.
    #[test]
    fn senza_contenuti_il_confronto_non_dice_nulla() {
        let configurazione = configurazione(&[("alfa", 2)]);

        let esito = compare(&[], &configurazione, &configurazione);

        assert_eq!(esito.examined, 0);
        let frase = esito.as_sentence();
        assert!(
            frase.contains("non dice nulla del candidato"),
            "zero contenuti non sono una promozione: «{frase}»"
        );
        assert!(!frase.contains("nessuna differenza"));
    }

    /// Il confronto è ripetibile: due esecuzioni danno lo stesso esito.
    #[test]
    fn due_esecuzioni_danno_lo_stesso_esito() {
        let pubblicato = configurazione(&[("alfa", 1)]);
        let candidato = configurazione(&[("alfa", 1), ("beta", 4), ("gamma", 2)]);
        let contenuti = [
            contenuto(1, "alfa beta", 1),
            contenuto(2, "gamma soltanto", 0),
        ];

        let prima = compare(&contenuti, &pubblicato, &candidato);
        let poi = compare(&contenuti, &pubblicato, &candidato);

        assert_eq!(prima, poi, "il laboratorio deve essere riproducibile");
    }

    // ----------------------------------- le differenze dei termini (F-07)

    fn termine(testo: &str, modo: MatchMode, livello: i8, categoria: &str) -> DictionaryTerm {
        let (Ok(text), Ok(category), Ok(language), Ok(suggested_level), Ok(note)) = (
            TermText::try_new(testo),
            TermCategory::try_new(categoria),
            LanguageTag::try_new("it"),
            SuggestedLevel::try_new(livello),
            TermNote::try_new(""),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        DictionaryTerm {
            id: DictionaryTermId::new(1),
            version_id: DictionaryVersionId::new(1),
            text,
            category,
            language,
            match_mode: modo,
            suggested_level,
            note,
        }
    }

    /// **Una bozza uguale al riferimento lo dice, con i totali.**
    #[test]
    fn una_bozza_uguale_non_ha_differenze() {
        let riferimento = [termine("incendio", MatchMode::NormalizedWord, 3, "azione")];
        let bozza = [termine("Incendio", MatchMode::NormalizedWord, 3, "azione")];
        let esito = term_differences(&riferimento, &bozza);
        assert!(esito.is_empty(), "le maiuscole non fanno un termine nuovo");
        assert_eq!(esito.unchanged, 1);
        assert!(esito.as_sentence().contains("nessuna differenza"));
    }

    /// **Aggiunti, tolti e cambiati si contano a parte, e la frase dice i
    /// due totali.**
    #[test]
    fn aggiunti_tolti_e_cambiati_si_contano() {
        let riferimento = [
            termine("incendio", MatchMode::NormalizedWord, 3, "azione"),
            termine("molotov", MatchMode::NormalizedWord, 2, "oggetto"),
            termine("corteo", MatchMode::NormalizedWord, 1, "evento"),
        ];
        let bozza = [
            termine("incendio", MatchMode::NormalizedWord, 3, "azione"),
            termine("molotov", MatchMode::NormalizedWord, 4, "oggetto"),
            termine("rogo", MatchMode::NormalizedWord, 2, "azione"),
        ];
        let esito = term_differences(&riferimento, &bozza);
        assert_eq!((esito.added(), esito.removed(), esito.changed()), (1, 1, 1));
        assert_eq!(esito.unchanged, 1);
        let righe: Vec<String> = esito.changes.iter().map(TermChange::as_sentence).collect();
        assert!(
            righe.iter().any(|r| r.contains("Tolto «corteo»")),
            "{righe:?}"
        );
        assert!(
            righe.iter().any(|r| r.contains("Aggiunto «rogo»")),
            "{righe:?}"
        );
        assert!(
            righe
                .iter()
                .any(|r| r.contains("«molotov»: livello da +2 a +4")),
            "{righe:?}"
        );
        let frase = esito.as_sentence();
        assert!(frase.contains("(3 termini)"), "{frase}");
        assert!(frase.contains("aggiunge 1, toglie 1 e cambia 1"), "{frase}");
    }

    /// **La stessa parola cercata in due modi sono due termini**, come
    /// nell'archivio e nel motore.
    #[test]
    fn la_stessa_parola_cercata_in_due_modi_sono_due_termini() {
        let riferimento = [termine("fuoco", MatchMode::NormalizedWord, 2, "azione")];
        let bozza = [
            termine("fuoco", MatchMode::NormalizedWord, 2, "azione"),
            termine("fuoco", MatchMode::ExactWord, 2, "azione"),
        ];
        let esito = term_differences(&riferimento, &bozza);
        assert_eq!(esito.added(), 1);
        assert_eq!(esito.unchanged, 1);
    }
}

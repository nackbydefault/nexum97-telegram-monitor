//! Composizione guidata di un nuovo monitoraggio.
//!
//! Il wizard è una **macchina a stati**, non una sequenza di schermate. La
//! differenza conta: se «si può passare avanti» fosse deciso dall'interfaccia,
//! la regola vivrebbe in un file che nessun test guarda, e la prima schermata
//! costruita male la aggirerebbe.
//!
//! Qui, come per l'autenticazione, **l'insieme dei comandi ammessi è calcolato
//! dal servizio** e l'interfaccia si limita a mostrarlo. Vedere
//! `docs/adr/ADR-0010-APPLICATION-SERVICES.md`.
//!
//! # Il passo che giustifica il wizard
//!
//! Il riepilogo mostra **quanti termini distinti** produrrà la scelta e quanti
//! provengono da più dizionari, calcolati davvero e non stimati. È l'unico
//! momento in cui l'operatore può accorgersi di avere selezionato tre
//! dizionari che dicono la stessa cosa, o nessuno che dica quella che gli
//! serve. L'anteprima **non scrive nulla**: usa la stessa risoluzione
//! dell'avvio, così che ciò che viene mostrato sia ciò che verrà usato.

use lisi_core::model::dictionary::{
    DictionarySelection, MatchMode, ResolvedDictionaryConfiguration, SessionCustomTerm,
    SuggestedLevel, is_digits_only, normalise_for_matching,
};
use lisi_core::model::schedule::{LeadRefusal, check_lead};
use lisi_core::model::session::{self, SessionDuration};
use lisi_core::text::TermText;
use lisi_core::{DictionaryId, DomainError, SourceId, Timestamp};

use crate::dictionaries::{DictionaryService, SelectedDictionary};
use crate::error::{ServiceError, ServiceResult};

/// Passo del wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WizardStep {
    /// Quali fonti monitorare.
    Sources,
    /// Quali dizionari usare.
    Dictionaries,
    /// Parole valide per questa sola sessione.
    CustomTerms,
    /// Per quanto tempo.
    Duration,
    /// Che cosa ne risulta.
    Summary,
    /// Conferma e avvio.
    Confirmation,
}

impl WizardStep {
    /// Tutti i passi, in ordine.
    pub const ALL: [Self; 6] = [
        Self::Sources,
        Self::Dictionaries,
        Self::CustomTerms,
        Self::Duration,
        Self::Summary,
        Self::Confirmation,
    ];

    /// Posizione, da 1.
    #[must_use]
    pub fn number(self) -> u32 {
        u32::try_from(
            Self::ALL
                .iter()
                .position(|step| *step == self)
                .unwrap_or_default(),
        )
        .unwrap_or(0)
            + 1
    }

    /// Titolo mostrato all'operatore.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Sources => "Fonti",
            Self::Dictionaries => "Dizionari",
            Self::CustomTerms => "Parole aggiuntive",
            Self::Duration => "Durata",
            Self::Summary => "Riepilogo",
            Self::Confirmation => "Avvio",
        }
    }

    /// Che cosa il passo chiede.
    #[must_use]
    pub const fn prompt(self) -> &'static str {
        match self {
            Self::Sources => "Scegliere le fonti già configurate da monitorare.",
            Self::Dictionaries => {
                "Scegliere i dizionari. Un dizionario di contesto riduttivo abbassa \
                 il peso dei riscontri fuorvianti: conviene selezionarlo insieme agli altri."
            }
            Self::CustomTerms => {
                "Aggiungere parole valide solo per questo monitoraggio. \
                 Non entrano in alcun dizionario."
            }
            Self::Duration => "Indicare per quanto tempo il monitoraggio deve durare.",
            Self::Summary => {
                "Che cosa verrà monitorato, per quanto tempo e con quali dizionari. \
                 È l'ultimo momento per cambiare la scelta."
            }
            Self::Confirmation => {
                "All'avvio la configurazione viene fissata e non cambia più, \
                 nemmeno se un dizionario viene modificato nel frattempo."
            }
        }
    }

    /// Passo successivo, se esiste.
    #[must_use]
    pub fn next(self) -> Option<Self> {
        let index = Self::ALL.iter().position(|step| *step == self)?;
        Self::ALL.get(index + 1).copied()
    }

    /// Passo precedente, se esiste.
    #[must_use]
    pub fn previous(self) -> Option<Self> {
        let index = Self::ALL.iter().position(|step| *step == self)?;
        index
            .checked_sub(1)
            .and_then(|before| Self::ALL.get(before).copied())
    }
}

/// Quando parte il monitoraggio (SCHEDULE-01, ADR-0171).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardStart {
    /// Alla conferma.
    Now,
    /// All'istante indicato, controllato con `check_lead`.
    At(Timestamp),
}

/// Durata scelta per il monitoraggio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardDuration {
    /// Durata preimpostata, in secondi.
    Preset(u32),
    /// Durata scelta dall'operatore, in secondi (ADR-0150): si costruisce con
    /// [`WizardDuration::custom`], che ne verifica i limiti.
    Custom(u32),
    /// Arresto deciso dall'operatore.
    Manual,
}

impl WizardDuration {
    /// Durate proposte, nell'ordine deciso dal committente (ADR-0144, DG-03;
    /// ADR-0150). I pulsanti della procedura ripetono queste etichette.
    pub const PRESETS: [(u32, &'static str); 7] = [
        (1_800, "30 minuti"),
        (3_600, "1 ora"),
        (7_200, "2 ore"),
        (14_400, "4 ore"),
        (28_800, "8 ore"),
        (43_200, "12 ore"),
        (86_400, "24 ore"),
    ];

    /// Una durata personalizzata di `hours` ore e `minutes` minuti, se sta fra
    /// un minuto e sette giorni; altrimenti `None`, e la scelta di prima resta.
    #[must_use]
    pub fn custom(hours: u32, minutes: u32) -> Option<Self> {
        if minutes >= 60 {
            return None;
        }
        let seconds = i64::from(hours) * 3_600 + i64::from(minutes) * 60;
        if !(session::CUSTOM_MIN_SECONDS..=session::CUSTOM_MAX_SECONDS).contains(&seconds) {
            return None;
        }
        u32::try_from(seconds).ok().map(Self::Custom)
    }

    /// La frase del rifiuto di una durata personalizzata fuori dai limiti.
    pub const CUSTOM_LIMITS: &'static str = "Una durata personalizzata va da 1 minuto a 7 giorni \
                                             (168 ore), con i minuti fra 0 e 59. La durata scelta \
                                             prima resta valida.";

    /// La durata del dominio che questa scelta produce.
    #[must_use]
    pub fn to_session_duration(self) -> SessionDuration {
        match self {
            Self::Preset(seconds) => SessionDuration::Preset {
                seconds: i64::from(seconds),
            },
            Self::Custom(seconds) => SessionDuration::Custom {
                seconds: i64::from(seconds),
            },
            Self::Manual => SessionDuration::Manual,
        }
    }

    /// Descrizione mostrata all'operatore: le parole le compone il dominio.
    #[must_use]
    pub fn label(self) -> String {
        match self {
            Self::Preset(seconds) => Self::PRESETS
                .iter()
                .find(|(value, _)| *value == seconds)
                .map_or_else(
                    || self.to_session_duration().in_words(),
                    |(_, label)| String::from(*label),
                ),
            Self::Custom(_) | Self::Manual => self.to_session_duration().in_words(),
        }
    }
}

/// Un avviso del riepilogo: qualcosa che vale la pena sapere, e che **non
/// impedisce** di proseguire.
///
/// # Perché un avviso non è un motivo di blocco
///
/// Il criterio 39 di M3C chiedeva «un campo avvisi distinto dal motivo di
/// blocco», e la distinzione non è di forma. Sono due cose con due
/// conseguenze diverse:
///
/// - il **motivo di blocco** dice che il passo non è completo, e il pulsante
///   «Avanti» resta spento finché non lo si risolve. È una porta chiusa;
/// - un **avviso** dice che la configurazione, così com'è, produrrà un certo
///   risultato — che può essere esattamente quello voluto. È un cartello.
///
/// Mescolarli fa uno dei due danni: o un avviso blocca un monitoraggio
/// legittimo, o un vero blocco si legge come un consiglio e chi ha fretta lo
/// salta. Il prodotto mostra i due in due posti diversi e con due forme
/// diverse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WizardNotice {
    /// Che cosa succede.
    pub text: String,
    /// Che cosa si può fare, se qualcosa si può fare.
    pub remedy: Option<String>,
}

impl WizardNotice {
    /// Avviso senza rimedio: dice un fatto, non chiede nulla.
    fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            remedy: None,
        }
    }

    /// Avviso con il gesto che lo scioglie.
    fn with_remedy(text: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            remedy: Some(remedy.into()),
        }
    }
}

/// Stato della composizione, con i comandi ammessi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WizardView {
    /// Passo corrente.
    pub step: WizardStep,
    /// Fonti scelte.
    pub source_count: usize,
    /// Dizionari scelti.
    pub dictionary_count: usize,
    /// Parole aggiunte.
    pub custom_term_count: usize,
    /// Durata scelta.
    pub duration: WizardDuration,
    /// Quando parte (SCHEDULE-01).
    pub start: WizardStart,
    /// Termini distinti risultanti, noti solo dal riepilogo in avanti.
    pub resolved_terms: Option<usize>,
    /// Termini presenti in più di un dizionario.
    pub shared_terms: Option<usize>,
    /// Impronta abbreviata della configurazione.
    pub digest: Option<String>,
    /// I dizionari scelti **con la versione** che verrà usata, noti dal
    /// riepilogo in avanti.
    ///
    /// Prima del riepilogo la fotografia non esiste: mostrarla vuota
    /// direbbe che nessun dizionario è stato scelto, che è un'altra cosa.
    pub selected_dictionaries: Option<Vec<SelectedDictionary>>,
    /// Che cosa vale la pena sapere prima di avviare, senza che impedisca di
    /// farlo.
    pub notices: Vec<WizardNotice>,
    /// Se si può passare al passo successivo.
    pub can_advance: bool,
    /// Se si può tornare indietro.
    pub can_go_back: bool,
    /// Perché non si può proseguire, quando non si può.
    pub blocking_reason: Option<String>,
}

/// Composizione guidata di un monitoraggio.
///
/// Non scrive nulla finché non viene chiesto esplicitamente: l'anteprima del
/// riepilogo risolve la configurazione senza toccare il database.
#[derive(Debug)]
pub struct MonitoringWizard {
    step: WizardStep,
    sources: Vec<SourceId>,
    dictionaries: Vec<DictionaryId>,
    custom_terms: Vec<SessionCustomTerm>,
    duration: WizardDuration,
    /// Quando parte: adesso, o a un istante programmato (SCHEDULE-01).
    start: WizardStart,
    preview: Option<ResolvedDictionaryConfiguration>,
    /// I dizionari scelti con la versione che verrà usata, fotografati
    /// **insieme** all'anteprima.
    ///
    /// Devono nascere e morire con `preview`: se sopravvivessero a un cambio di
    /// scelta, il riepilogo elencherebbe una versione e i conteggi ne
    /// descriverebbero un'altra — che è peggio di non elencarla affatto.
    selected: Option<Vec<SelectedDictionary>>,
}

impl Default for MonitoringWizard {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitoringWizard {
    /// Composizione vuota, al primo passo.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            step: WizardStep::Sources,
            sources: Vec::new(),
            dictionaries: Vec::new(),
            custom_terms: Vec::new(),
            duration: WizardDuration::Preset(3_600),
            start: WizardStart::Now,
            preview: None,
            selected: None,
        }
    }

    /// Passo corrente.
    #[must_use]
    pub const fn step(&self) -> WizardStep {
        self.step
    }

    /// Butta via l'anteprima **e la fotografia delle versioni**, insieme.
    ///
    /// Sono due facce dello stesso calcolo: i conteggi e i dizionari da cui
    /// vengono. Invalidarne una sola lascerebbe il riepilogo a raccontare una
    /// scelta con i numeri di un'altra, che è peggio che non raccontarla.
    fn invalidate_preview(&mut self) {
        self.preview = None;
        self.selected = None;
    }

    /// Selezione composta finora.
    #[must_use]
    pub fn selection(&self) -> DictionarySelection {
        DictionarySelection {
            dictionary_ids: self.dictionaries.clone(),
            ad_hoc_terms: self.custom_terms.clone(),
        }
    }

    /// Aggiunge o toglie una fonte.
    pub fn toggle_source(&mut self, id: SourceId) {
        toggle(&mut self.sources, id);
        self.invalidate_preview();
    }

    /// Aggiunge o toglie un dizionario.
    ///
    /// Invalida l'anteprima: un riepilogo calcolato su una scelta precedente
    /// mostrerebbe numeri che non corrispondono più a nulla.
    pub fn toggle_dictionary(&mut self, id: DictionaryId) {
        toggle(&mut self.dictionaries, id);
        self.invalidate_preview();
    }

    /// Se il dizionario è selezionato.
    #[must_use]
    pub fn has_dictionary(&self, id: DictionaryId) -> bool {
        self.dictionaries.contains(&id)
    }

    /// Se la fonte è selezionata.
    #[must_use]
    pub fn has_source(&self, id: SourceId) -> bool {
        self.sources.contains(&id)
    }

    /// Fonti selezionate per il monitoraggio.
    #[must_use]
    pub fn sources(&self) -> &[SourceId] {
        &self.sources
    }

    /// Aggiunge una parola valida per la sola sessione.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::Domain`] se il testo non è ammesso dal
    /// dominio.
    /// `suggested_level` dice **quanto sia grave** la comparsa della parola,
    /// da 1 a 4: è la stessa scala dei termini di dizionario. Un valore fuori
    /// intervallo viene respinto invece che corretto in silenzio, perché
    /// silenziosamente ridurre a zero riporterebbe il difetto che questa
    /// firma esiste per togliere — una parola sorvegliata che non può
    /// produrre alcun avviso.
    pub fn add_custom_term(
        &mut self,
        text: &str,
        match_mode: MatchMode,
        suggested_level: SuggestedLevel,
    ) -> ServiceResult<()> {
        // Un codice numerico entra soltanto da un dizionario che una persona ha
        // rivisto e pubblicato; un numero da solo, fra le parole di una
        // sessione, coinciderebbe con date e prezzi (DICT-CODES-01, ADR-0170,
        // decisione 5).
        if match_mode == MatchMode::NumericCode || is_digits_only(text) {
            return Err(ServiceError::Domain(DomainError::InvalidNumericCode {
                reason: "un numero da solo non si cerca fra le parole di una sessione: un \
                         codice numerico entra soltanto da un dizionario rivisto e pubblicato",
            }));
        }
        let text = TermText::try_new(text)?;
        let added = SessionCustomTerm {
            text,
            match_mode,
            suggested_level,
        };

        // La stessa parola con la stessa modalità resta una: con un altro
        // livello sarebbero due righe uguali, e quale dei due livelli vale non
        // lo saprebbe nessuno. «Stessa» come la intende il risolutore, dopo la
        // normalizzazione: «pdf» e «PDF» erano due righe qui e un termine solo
        // nell'analisi (NEXUM97-FULL-OPERATIONAL-VALIDATION-01).
        let already = self.has_custom_term(added.text.as_str(), added.match_mode);
        if !already {
            self.custom_terms.push(added);
            self.invalidate_preview();
        }
        Ok(())
    }

    /// Se una parola è già fra quelle aggiunte, con la stessa modalità.
    ///
    /// Serve a dirlo (F-11): prima una parola ripetuta si ignorava in silenzio
    /// e il campo si svuotava, come se fosse entrata.
    #[must_use]
    pub fn has_custom_term(&self, text: &str, match_mode: MatchMode) -> bool {
        TermText::try_new(text).is_ok_and(|text| {
            let cercata = normalise_for_matching(text.as_str());
            self.custom_terms.iter().any(|term| {
                term.match_mode == match_mode
                    && normalise_for_matching(term.text.as_str()) == cercata
            })
        })
    }

    /// Toglie una parola aggiunta.
    pub fn remove_custom_term(&mut self, index: usize) {
        if index < self.custom_terms.len() {
            self.custom_terms.remove(index);
            self.invalidate_preview();
        }
    }

    /// Parole aggiunte.
    #[must_use]
    pub fn custom_terms(&self) -> &[SessionCustomTerm] {
        &self.custom_terms
    }

    /// Fissa la durata.
    pub const fn set_duration(&mut self, duration: WizardDuration) {
        self.duration = duration;
    }

    /// Durata scelta.
    #[must_use]
    pub const fn duration(&self) -> WizardDuration {
        self.duration
    }

    /// Quando parte (SCHEDULE-01, ADR-0171).
    #[must_use]
    pub const fn start(&self) -> WizardStart {
        self.start
    }

    /// Parte adesso, alla conferma.
    pub const fn set_start_now(&mut self) {
        self.start = WizardStart::Now;
    }

    /// Parte all'istante indicato, se è fra un minuto e sette giorni da
    /// `now`.
    ///
    /// # Errori
    ///
    /// Restituisce il rifiuto, e la scelta di prima resta.
    pub const fn set_start_at(
        &mut self,
        start_at: Timestamp,
        now: Timestamp,
    ) -> Result<(), LeadRefusal> {
        match check_lead(start_at, now) {
            Ok(()) => {
                self.start = WizardStart::At(start_at);
                Ok(())
            }
            Err(rifiuto) => Err(rifiuto),
        }
    }

    /// Torna al passo precedente.
    ///
    /// Sempre consentito: un wizard da cui non si può tornare indietro
    /// costringe a ricominciare per correggere una svista.
    pub fn go_back(&mut self) {
        if let Some(previous) = self.step.previous() {
            self.step = previous;
        }
    }

    /// Passa al passo successivo, calcolando l'anteprima quando serve.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::CommandNotAllowed`] se il passo corrente non
    /// è completo, e gli errori della risoluzione quando si entra nel riepilogo.
    pub fn advance(&mut self, dictionaries: &DictionaryService) -> ServiceResult<()> {
        if let Some(reason) = self.blocking_reason() {
            let _ = reason;
            return Err(ServiceError::CommandNotAllowed {
                command: "avanti",
                state: self.step.title(),
            });
        }

        let Some(next) = self.step.next() else {
            return Err(ServiceError::CommandNotAllowed {
                command: "avanti",
                state: self.step.title(),
            });
        };

        // L'anteprima si calcola entrando nel riepilogo, non prima: risolvere
        // a ogni spunta significherebbe rileggere i dizionari a ogni clic.
        //
        // Su una configurazione senza alcun termine non c'è nulla da risolvere,
        // e tentarlo restituirebbe un errore tecnico al posto della spiegazione
        // che il riepilogo sa dare. La condizione è **la stessa** di
        // [`Self::has_no_terms`] usata da `blocking_reason`: se le due
        // divergessero, l'operatore riceverebbe un guasto invece di un motivo.
        if next == WizardStep::Summary && !self.has_no_terms() {
            // Le due letture vanno insieme, e nell'ordine: se la risoluzione
            // fallisce non si fotografa nulla, e il riepilogo non mostra
            // versioni di una configurazione che non si e' potuta calcolare.
            self.preview = Some(dictionaries.resolve(&self.selection())?);
            self.selected = Some(dictionaries.selected_versions(&self.dictionaries)?);
        }

        self.step = next;
        Ok(())
    }

    /// Configurazione risolta, quando è stata calcolata.
    #[must_use]
    pub const fn preview(&self) -> Option<&ResolvedDictionaryConfiguration> {
        self.preview.as_ref()
    }

    /// I dizionari scelti con la versione che verrà usata, quando la
    /// fotografia è stata scattata.
    #[must_use]
    pub fn selected_dictionaries(&self) -> Option<&[SelectedDictionary]> {
        self.selected.as_deref()
    }

    /// Che cosa vale la pena sapere prima di avviare, senza che impedisca di
    /// farlo.
    ///
    /// # Perché gli avvisi nascono dalla fotografia e non dalla scelta
    ///
    /// Un avviso che si calcolasse dai soli identificativi scelti direbbe cose
    /// sui dizionari **come si chiamano**; questi le dicono su ciò che i
    /// dizionari **contengono davvero nella versione che verrà usata**. È la
    /// differenza fra «hai scelto Cyber Core» e «nessuno dei termini scelti
    /// abbassa il peso di un riscontro».
    ///
    /// Prima del riepilogo l'elenco è vuoto: non ci sono avvisi da dare su una
    /// configurazione che non è ancora stata calcolata.
    #[must_use]
    pub fn notices(&self) -> Vec<WizardNotice> {
        let Some(selected) = self.selected.as_ref() else {
            return Vec::new();
        };

        let mut avvisi = Vec::new();

        // 1. Nessun contesto riduttivo, e qualcosa che alza il livello.
        //
        // È la condizione che le due metodologie più delicate del prodotto
        // nominano per prime: Cyber Core dice che «malware» e «phishing» sono
        // ormai parole divulgative, e un'altra metodologia tematica che «un
        // archivio di giornale ben monitorato produrrebbe centinaia di
        // riscontri e nemmeno un segnale utile».
        //
        // La condizione si legge dai TERMINI, non dai nomi: un dizionario
        // porta contesto riduttivo se ha almeno un termine di livello
        // negativo. Riconoscerlo dal nome funzionerebbe finché qualcuno non
        // rinomina il proprio, e fallirebbe in silenzio.
        //
        // Un dizionario tematico può portare i propri riduttori, ed è per
        // questo che sceglierlo da solo **non** produce questo avviso: la
        // regola guarda che cosa c'è, non quale voce è stata spuntata.
        let riduce = selected
            .iter()
            .any(SelectedDictionary::provides_reductive_context);
        let alza =
            selected.iter().any(SelectedDictionary::can_raise) || !self.custom_terms.is_empty();
        if alza && !riduce {
            avvisi.push(WizardNotice::with_remedy(
                "Nessun termine scelto abbassa il peso di un riscontro fuorviante: \
                 una citazione, una cronaca o una battuta peseranno quanto il fatto.",
                "Tornare al passo «Dizionari» e aggiungere un dizionario di contesto riduttivo.",
            ));
        }

        // 2. Nessun dizionario: solo parole aggiunte a mano.
        //
        // È una configurazione legittima — si sorvegliano quelle parole e
        // basta — e proprio per questo non blocca. Ma chi arriva qui dopo aver
        // saltato il passo dei dizionari deve sapere che cosa ha davanti.
        if selected.is_empty() && !self.custom_terms.is_empty() {
            avvisi.push(WizardNotice::plain(format!(
                "Nessun dizionario scelto: il monitoraggio userà soltanto le {} parole \
                 aggiunte a mano, e nient'altro.",
                self.custom_terms.len()
            )));
        }

        // Un avviso che NON c'e', e la ragione per cui non serve.
        //
        // Scrivendo questi avvisi ne era stato aggiunto un terzo: «questo
        // dizionario e' stato scelto ma non contiene termini, e non cerchera'
        // nulla». La prova che doveva dimostrarlo non e' riuscita a costruire
        // il caso: una versione **senza termini non si pubblica**
        // (`DictionaryService::publish`), e un dizionario senza versione
        // pubblicata **non e' selezionabile** (`usable_version`). Lo stato che
        // l'avviso descriveva non puo' esistere.
        //
        // L'avviso e' stato tolto invece di essere lasciato «per sicurezza».
        // Un avviso che non puo' scattare e' peggio di nessun avviso: occupa
        // spazio nel riepilogo, chiede di essere mantenuto, e lascia credere
        // che il caso sia sorvegliato quando e' semplicemente impossibile. La
        // prova che resta dimostra l'impossibilita', che e' la garanzia vera.

        // 3. Durata manuale.
        //
        // Non è un difetto ed è spesso la scelta giusta. Ma è l'unica durata
        // che non finisce da sola, e il riepilogo è l'ultimo posto in cui
        // dirlo prima che il monitoraggio giri per giorni.
        if matches!(self.duration, WizardDuration::Manual) {
            avvisi.push(WizardNotice::plain(
                "La durata è «fino all'arresto manuale»: il monitoraggio prosegue \
                 finché qualcuno lo ferma.",
            ));
        }

        avvisi
    }

    /// Se la composizione non porta alcun termine, da dizionario o aggiunto.
    ///
    /// Un monitoraggio così acquisirebbe contenuti senza poterne segnalare
    /// alcuno, e sembrerebbe funzionare: è la condizione che il riepilogo
    /// rifiuta, e la stessa per cui non c'è anteprima da risolvere.
    const fn has_no_terms(&self) -> bool {
        self.dictionaries.is_empty() && self.custom_terms.is_empty()
    }

    /// Motivo per cui il passo corrente non è completo.
    ///
    /// È un testo per l'operatore: dice che cosa manca, non che qualcosa manca.
    #[must_use]
    pub fn blocking_reason(&self) -> Option<String> {
        match self.step {
            WizardStep::Sources if self.sources.is_empty() => Some(String::from(
                "Scegliere almeno una fonte: senza, il monitoraggio non acquisirebbe nulla.",
            )),
            // Fino al 2026-08-04 il blocco stava **qui**, e il suo stesso testo
            // lo smentiva: diceva «oppure aggiungere una parola al passo
            // successivo» mentre impediva di raggiungerlo. Chi non voleva un
            // dizionario restava fermo; chi ne sceglieva uno, avanzava,
            // aggiungeva le parole, tornava indietro e lo deselezionava passava
            // — stessa configurazione, esito diverso, a seconda dell'ordine dei
            // gesti. Rilevato in campo. La condizione non era sbagliata: era
            // applicata prima del passo che la può soddisfare.
            WizardStep::Summary if self.has_no_terms() => Some(String::from(
                "Nessun dizionario scelto e nessuna parola aggiunta: così il monitoraggio \
                     acquisirebbe i contenuti senza poter segnalare nulla. Tornare indietro e \
                     scegliere un dizionario, oppure aggiungere almeno una parola.",
            )),
            // Fino al 2026-07-30 questo messaggio dichiarava che l'acquisizione
            // non era collegata, il che era vero: `AcquisitionService` non era
            // chiamato da nessuna parte. Collegato il ciclo, quella frase e'
            // diventata **falsa**, e una dichiarazione falsa all'operatore e'
            // peggio di nessuna dichiarazione. Il messaggio dice ora la
            // condizione che resta davvero necessaria - un account autorizzato
            // in modalita' reale - senza promettere che i contenuti arriveranno
            // comunque.
            // «Modalità dimostrativa» era un terzo nome per ciò che il resto del
            // programma chiama Esercitazione (OPERATOR-SIM-01, OS-13), e la
            // frase non diceva dove guardare dopo l'avvio (task 05).
            WizardStep::Confirmation if crate::run_mode::is_exercise() => Some(String::from(
                "La configurazione è pronta. Avviando, il monitoraggio si crea con queste fonti \
                 e queste parole, e parte subito. In Esercitazione da Telegram non arriva \
                 nulla: i messaggi di prova sono già in «Avvisi» e nello «Storico».",
            )),
            WizardStep::Confirmation => Some(String::from(
                "La configurazione è pronta. Avviando, il monitoraggio si crea con queste fonti \
                 e queste parole, e parte subito. I messaggi arrivano soltanto mentre il \
                 monitoraggio è in corso e l'account d'ufficio è collegato, e compaiono in \
                 «Avvisi» e nello «Storico». Senza account collegato il monitoraggio esiste e \
                 si può comandare, ma da Telegram non arriva nulla.",
            )),
            _ => None,
        }
    }

    /// Stato osservabile, con i comandi ammessi.
    #[must_use]
    pub fn view(&self) -> WizardView {
        let blocking_reason = self.blocking_reason();

        WizardView {
            step: self.step,
            source_count: self.sources.len(),
            dictionary_count: self.dictionaries.len(),
            custom_term_count: self.custom_terms.len(),
            duration: self.duration,
            start: self.start,
            resolved_terms: self.preview.as_ref().map(|preview| preview.unique_count),
            shared_terms: self.preview.as_ref().map(|preview| preview.shared_count),
            digest: self.preview.as_ref().map(|preview| preview.digest.short()),
            selected_dictionaries: self.selected.clone(),
            notices: self.notices(),
            can_advance: blocking_reason.is_none() && self.step.next().is_some(),
            can_go_back: self.step.previous().is_some(),
            blocking_reason,
        }
    }
}

/// Aggiunge o toglie un valore da un elenco.
fn toggle<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if let Some(index) = values.iter().position(|existing| *existing == value) {
        values.remove(index);
    } else {
        values.push(value);
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::dictionary::{
        DictionaryScope, DictionaryVisibility, MatchMode, NewDictionaryTerm, SuggestedLevel,
    };
    use lisi_core::text::{
        Actor, DictionaryDescription, DictionaryName, LanguageTag, TermCategory, TermNote, TermText,
    };
    use lisi_core::{DictionaryId, SourceId, Timestamp};

    use super::{MonitoringWizard, WizardDuration, WizardStep};
    use crate::dictionaries::{DictionaryProposal, DictionaryService};
    use crate::error::ServiceError;
    use crate::sources::open_in_memory_database;
    use lisi_core::model::SessionDuration;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn operator() -> Actor {
        let Ok(value) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        value
    }

    /// Servizio con un dizionario pubblicato che contiene i termini indicati.
    fn service_with(terms: &[&str]) -> (DictionaryService, DictionaryId) {
        let Ok(database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        let mut service = DictionaryService::new(database);

        let (Ok(name), Ok(description)) = (
            DictionaryName::try_new("Prova"),
            DictionaryDescription::try_new("dizionario di prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok((dictionary, version)) = service.create(
            &DictionaryProposal {
                name,
                description,
                scope: DictionaryScope::Thematic,
                visibility: DictionaryVisibility::Personal,
            },
            &operator(),
            now(),
        ) else {
            panic!("il dizionario deve potersi creare");
        };

        let (Ok(category), Ok(language), Ok(note), Ok(level)) = (
            TermCategory::try_new("prova"),
            LanguageTag::try_new("it"),
            TermNote::try_new(""),
            SuggestedLevel::try_new(2),
        ) else {
            panic!("i valori del termine devono essere validi");
        };
        let collected: Vec<NewDictionaryTerm> = terms
            .iter()
            .map(|text| {
                let Ok(text) = TermText::try_new(text) else {
                    panic!("il termine di prova deve essere valido");
                };
                NewDictionaryTerm {
                    version_id: version,
                    text,
                    category: category.clone(),
                    language: language.clone(),
                    match_mode: MatchMode::NormalizedWord,
                    suggested_level: level,
                    note: note.clone(),
                }
            })
            .collect();

        let Ok(_) = service.add_terms(version, &collected, &operator(), now()) else {
            panic!("i termini devono potersi aggiungere");
        };
        let Ok(()) = service.publish(version, &operator(), now()) else {
            panic!("la pubblicazione deve riuscire");
        };

        (service, dictionary)
    }

    /// Aggiunge al servizio un altro dizionario pubblicato, con i termini e i
    /// **livelli** indicati.
    ///
    /// Il livello porta il segno: negativo significa contesto riduttivo. Serve
    /// alle prove sugli avvisi, che guardano che cosa i termini fanno e non
    /// come si chiama il dizionario che li contiene.
    fn add_dictionary(
        service: &mut DictionaryService,
        name: &str,
        terms: &[(&str, i8)],
    ) -> DictionaryId {
        let (Ok(nome), Ok(descrizione)) = (
            DictionaryName::try_new(name),
            DictionaryDescription::try_new("dizionario di prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok((dictionary, version)) = service.create(
            &DictionaryProposal {
                name: nome,
                description: descrizione,
                scope: DictionaryScope::Thematic,
                visibility: DictionaryVisibility::Personal,
            },
            &operator(),
            now(),
        ) else {
            panic!("il dizionario «{name}» deve potersi creare");
        };

        let (Ok(category), Ok(language), Ok(note)) = (
            TermCategory::try_new("prova"),
            LanguageTag::try_new("it"),
            TermNote::try_new(""),
        ) else {
            panic!("i valori del termine devono essere validi");
        };

        let collected: Vec<NewDictionaryTerm> = terms
            .iter()
            .map(|(text, level)| {
                let (Ok(text), Ok(suggested_level)) =
                    (TermText::try_new(text), SuggestedLevel::try_new(*level))
                else {
                    panic!("il termine di prova deve essere valido");
                };
                NewDictionaryTerm {
                    version_id: version,
                    text,
                    category: category.clone(),
                    language: language.clone(),
                    match_mode: MatchMode::NormalizedWord,
                    suggested_level,
                    note: note.clone(),
                }
            })
            .collect();

        if !collected.is_empty() {
            let Ok(_) = service.add_terms(version, &collected, &operator(), now()) else {
                panic!("i termini devono potersi aggiungere");
            };
        }
        let Ok(()) = service.publish(version, &operator(), now()) else {
            panic!("la pubblicazione di «{name}» deve riuscire");
        };

        dictionary
    }

    /// Wizard portato fino al passo indicato.
    fn wizard_at(
        step: WizardStep,
        service: &DictionaryService,
        dictionary: DictionaryId,
    ) -> MonitoringWizard {
        let mut wizard = MonitoringWizard::new();
        wizard.toggle_source(SourceId::new(1));
        wizard.toggle_dictionary(dictionary);

        while wizard.step() != step {
            let Ok(()) = wizard.advance(service) else {
                panic!("l'avanzamento fino a {} deve riuscire", step.title());
            };
        }
        wizard
    }

    // ------------------------------------------------------------- i passi

    #[test]
    fn the_steps_are_six_and_each_says_what_it_asks() {
        assert_eq!(WizardStep::ALL.len(), 6);
        for (index, step) in WizardStep::ALL.iter().enumerate() {
            assert_eq!(step.number(), u32::try_from(index).unwrap_or(0) + 1);
            assert!(!step.title().is_empty());
            assert!(!step.prompt().is_empty());
        }
    }

    #[test]
    fn the_first_step_has_nothing_before_and_the_last_nothing_after() {
        assert_eq!(WizardStep::Sources.previous(), None);
        assert_eq!(WizardStep::Confirmation.next(), None);
        assert_eq!(WizardStep::Sources.next(), Some(WizardStep::Dictionaries));
        assert_eq!(
            WizardStep::Confirmation.previous(),
            Some(WizardStep::Summary)
        );
    }

    // -------------------------------------------------------- avanzamento

    #[test]
    fn without_a_source_the_wizard_does_not_move_and_says_why() {
        let (service, _) = service_with(&["incendio"]);
        let mut wizard = MonitoringWizard::new();

        let view = wizard.view();
        assert!(!view.can_advance);
        assert!(!view.can_go_back);
        let Some(reason) = view.blocking_reason else {
            panic!("il motivo deve essere presente");
        };
        assert!(reason.contains("fonte"));

        assert!(matches!(
            wizard.advance(&service),
            Err(ServiceError::CommandNotAllowed { .. })
        ));
        assert_eq!(wizard.step(), WizardStep::Sources);
    }

    #[test]
    fn choosing_no_dictionary_does_not_block_the_way_to_the_words() {
        // Il blocco stava al passo dei dizionari, e il suo testo lo smentiva:
        // mandava «al passo successivo» impedendo di raggiungerlo. Chi non
        // voleva dizionari restava fermo. Rilevato in campo il 2026-08-04.
        let (service, _) = service_with(&["incendio"]);
        let mut wizard = MonitoringWizard::new();
        wizard.toggle_source(SourceId::new(1));

        let Ok(()) = wizard.advance(&service) else {
            panic!("il primo passo deve essere superabile");
        };
        assert_eq!(wizard.step(), WizardStep::Dictionaries);
        assert!(
            wizard.view().can_advance,
            "senza dizionari si deve poter raggiungere il passo delle parole"
        );

        let Ok(()) = wizard.advance(&service) else {
            panic!("il passo dei dizionari deve essere superabile senza sceglierne alcuno");
        };
        assert_eq!(wizard.step(), WizardStep::CustomTerms);
    }

    #[test]
    fn the_same_configuration_is_judged_the_same_whatever_the_order_of_the_gestures() {
        // Il difetto vero non era la severita' della regola ma la sua
        // incoerenza: scegliere un dizionario, avanzare, tornare indietro e
        // deselezionarlo dava esito diverso dal non sceglierne mai uno, a
        // parita' di configurazione.
        let (service, dictionary) = service_with(&["incendio"]);
        let mut wizard = MonitoringWizard::new();
        wizard.toggle_source(SourceId::new(1));
        let Ok(()) = wizard.advance(&service) else {
            panic!("il primo passo deve essere superabile");
        };

        wizard.toggle_dictionary(dictionary);
        wizard.toggle_dictionary(dictionary);

        assert!(
            wizard.view().can_advance,
            "scelto e poi deselezionato deve valere quanto mai scelto"
        );
    }

    #[test]
    fn without_any_term_the_summary_refuses_to_go_on() {
        // La condizione resta, spostata dove puo' essere soddisfatta: un
        // monitoraggio senza termini acquisirebbe contenuti senza poterne
        // segnalare alcuno, e sembrerebbe funzionare.
        let (service, _) = service_with(&["incendio"]);
        let mut wizard = MonitoringWizard::new();
        wizard.toggle_source(SourceId::new(1));

        for expected in [
            WizardStep::Dictionaries,
            WizardStep::CustomTerms,
            WizardStep::Duration,
            WizardStep::Summary,
        ] {
            let Ok(()) = wizard.advance(&service) else {
                panic!("il passo prima di {expected:?} deve essere superabile");
            };
            assert_eq!(wizard.step(), expected);
        }

        assert!(
            !wizard.view().can_advance,
            "dal riepilogo senza alcun termine non si deve poter proseguire"
        );
        assert!(matches!(
            wizard.advance(&service),
            Err(ServiceError::CommandNotAllowed { .. })
        ));
    }

    #[test]
    fn a_word_added_by_hand_is_enough_to_proceed() {
        // Una sessione con sole parole aggiuntive e' legittima.
        let (service, _) = service_with(&["incendio"]);
        let mut wizard = MonitoringWizard::new();
        wizard.toggle_source(SourceId::new(1));
        let Ok(()) = wizard.add_custom_term(
            "parola",
            MatchMode::NormalizedWord,
            SuggestedLevel::weakest_that_alerts(),
        ) else {
            panic!("la parola deve potersi aggiungere");
        };

        let Ok(()) = wizard.advance(&service) else {
            panic!("il primo passo deve essere superabile");
        };
        assert!(wizard.view().can_advance);
    }

    /// **La stessa parola in maiuscolo è la stessa parola**
    /// (NEXUM97-FULL-OPERATIONAL-VALIDATION-01, BUG-UX-4).
    ///
    /// Dal vivo, il 2026-10-19: «pdf» e poi «PDF» comparivano come due righe,
    /// mentre il risolutore le fonde in un termine solo dopo la
    /// normalizzazione. L'elenco diceva due parole, l'analisi ne usava una.
    #[test]
    fn la_stessa_parola_in_maiuscolo_resta_una() {
        let mut wizard = MonitoringWizard::new();
        for testo in ["pdf", "PDF", "Pdf"] {
            let Ok(()) = wizard.add_custom_term(
                testo,
                MatchMode::NormalizedWord,
                SuggestedLevel::weakest_that_alerts(),
            ) else {
                panic!("la parola deve potersi aggiungere");
            };
        }
        assert_eq!(wizard.custom_terms().len(), 1, "è la stessa parola");
        assert!(wizard.has_custom_term("PDF", MatchMode::NormalizedWord));
    }

    /// **L'inizio si sceglie adesso o fra un minuto e sette giorni; un rifiuto
    /// lascia la scelta di prima** (SCHEDULE-01, ADR-0171, criterio 2).
    #[test]
    fn l_inizio_si_sceglie_entro_la_misura() {
        use super::WizardStart;
        use lisi_core::model::schedule::LeadRefusal;

        let adesso = Timestamp::from_millis(1_800_000_000_000);
        let tra = |secondi: i64| adesso.plus_seconds(secondi);
        let mut wizard = MonitoringWizard::new();
        assert_eq!(wizard.start(), WizardStart::Now);
        assert_eq!(
            wizard.set_start_at(tra(30), adesso),
            Err(LeadRefusal::TooSoon)
        );
        assert_eq!(
            wizard.start(),
            WizardStart::Now,
            "il rifiuto non cambia niente"
        );
        assert_eq!(wizard.set_start_at(tra(3_600), adesso), Ok(()));
        assert_eq!(wizard.view().start, WizardStart::At(tra(3_600)));
        assert_eq!(
            wizard.set_start_at(tra(8 * 86_400), adesso),
            Err(LeadRefusal::TooFar)
        );
        assert_eq!(wizard.start(), WizardStart::At(tra(3_600)));
        wizard.set_start_now();
        assert_eq!(wizard.start(), WizardStart::Now);
    }

    /// **Un numero da solo non entra fra le parole di una sessione**
    /// (DICT-CODES-01, ADR-0170, criterio 5; prova negativa: il rifiuto tolto
    /// → rossa). Un codice entra soltanto da un dizionario rivisto e
    /// pubblicato.
    #[test]
    fn un_numero_da_solo_non_entra_fra_le_parole_di_una_sessione() {
        let mut wizard = MonitoringWizard::new();
        for (testo, modo) in [
            ("88", MatchMode::NormalizedWord),
            (" 1488 ", MatchMode::ExactWord),
            ("88", MatchMode::NumericCode),
        ] {
            assert!(
                matches!(
                    wizard.add_custom_term(testo, modo, SuggestedLevel::weakest_that_alerts()),
                    Err(ServiceError::Domain(
                        lisi_core::DomainError::InvalidNumericCode { .. }
                    ))
                ),
                "«{testo}» come {modo:?}"
            );
        }
        assert!(wizard.custom_terms().is_empty());
        let Ok(()) = wizard.add_custom_term(
            "ore 88",
            MatchMode::Phrase,
            SuggestedLevel::weakest_that_alerts(),
        ) else {
            panic!("una frase con un numero dentro resta una frase");
        };
    }

    #[test]
    fn going_back_is_always_possible_after_the_first_step() {
        let (service, dictionary) = service_with(&["incendio"]);
        let mut wizard = wizard_at(WizardStep::CustomTerms, &service, dictionary);

        assert!(wizard.view().can_go_back);
        wizard.go_back();
        assert_eq!(wizard.step(), WizardStep::Dictionaries);
        wizard.go_back();
        assert_eq!(wizard.step(), WizardStep::Sources);
        wizard.go_back();
        assert_eq!(
            wizard.step(),
            WizardStep::Sources,
            "non si va oltre l'inizio"
        );
    }

    // ----------------------------------------------------------- anteprima

    #[test]
    fn the_summary_counts_the_terms_that_will_really_be_used() {
        let (service, dictionary) = service_with(&["incendio", "molotov", "appiccare"]);
        let mut wizard = wizard_at(WizardStep::Duration, &service, dictionary);
        let Ok(()) = wizard.add_custom_term(
            "parola in piu'",
            MatchMode::Phrase,
            SuggestedLevel::weakest_that_alerts(),
        ) else {
            panic!("la parola deve potersi aggiungere");
        };

        let Ok(()) = wizard.advance(&service) else {
            panic!("il riepilogo deve essere raggiungibile");
        };
        assert_eq!(wizard.step(), WizardStep::Summary);

        let view = wizard.view();
        assert_eq!(view.resolved_terms, Some(4));
        assert_eq!(view.shared_terms, Some(0));
        let Some(digest) = view.digest else {
            panic!("l'impronta deve essere presente");
        };
        assert_eq!(digest.len(), 12);
    }

    #[test]
    fn before_the_summary_the_number_of_terms_is_not_claimed() {
        // Mostrare un numero prima di averlo calcolato significherebbe
        // inventarlo.
        let (service, dictionary) = service_with(&["incendio"]);
        let wizard = wizard_at(WizardStep::Dictionaries, &service, dictionary);

        let view = wizard.view();
        assert_eq!(view.resolved_terms, None);
        assert_eq!(view.digest, None);
    }

    #[test]
    fn changing_the_choice_invalidates_a_preview_already_calculated() {
        // Un riepilogo calcolato su una scelta precedente mostrerebbe numeri
        // che non corrispondono piu' a nulla.
        let (service, dictionary) = service_with(&["incendio"]);
        let mut wizard = wizard_at(WizardStep::Summary, &service, dictionary);
        assert_eq!(wizard.view().resolved_terms, Some(1));

        wizard.go_back();
        wizard.toggle_dictionary(dictionary);
        assert_eq!(wizard.view().resolved_terms, None);
    }

    #[test]
    fn the_preview_writes_nothing() {
        // L'anteprima usa la stessa risoluzione dell'avvio: cio' che viene
        // mostrato e' cio' che verrebbe usato, ma nulla e' stato fissato.
        let (service, dictionary) = service_with(&["incendio"]);
        let wizard = wizard_at(WizardStep::Summary, &service, dictionary);

        assert!(wizard.preview().is_some());
        let Ok(sessions) = service.database().sessions() else {
            panic!("le sessioni devono potersi leggere");
        };
        assert!(
            sessions.is_empty(),
            "nessuna sessione deve essere stata creata"
        );
    }

    // ------------------------------------------------------------- durata

    #[test]
    fn every_proposed_duration_has_a_readable_label() {
        for (seconds, label) in WizardDuration::PRESETS {
            assert_eq!(WizardDuration::Preset(seconds).label(), label);
        }
        assert!(WizardDuration::Manual.label().contains("manuale"));
        assert_eq!(WizardDuration::Preset(600).label(), "10 minuti");
    }

    /// **Le durate decise sono sette, nell'ordine deciso** (ADR-0144, DG-03).
    #[test]
    fn le_durate_proposte_sono_quelle_decise() {
        let etichette: Vec<&str> = WizardDuration::PRESETS
            .iter()
            .map(|(_, etichetta)| *etichetta)
            .collect();
        assert_eq!(
            etichette,
            [
                "30 minuti",
                "1 ora",
                "2 ore",
                "4 ore",
                "8 ore",
                "12 ore",
                "24 ore"
            ]
        );
        for (seconds, etichetta) in WizardDuration::PRESETS {
            assert_eq!(
                WizardDuration::Preset(seconds)
                    .to_session_duration()
                    .in_words(),
                etichetta,
                "l'etichetta della procedura e le parole del dominio coincidono"
            );
        }
    }

    /// **Una durata personalizzata sta fra un minuto e sette giorni**, e
    /// diventa una durata `Custom` del dominio (ADR-0150).
    #[test]
    fn la_durata_personalizzata_ha_i_suoi_limiti() {
        assert_eq!(
            WizardDuration::custom(2, 15),
            Some(WizardDuration::Custom(8_100))
        );
        assert_eq!(
            WizardDuration::custom(0, 1),
            Some(WizardDuration::Custom(60))
        );
        assert_eq!(
            WizardDuration::custom(168, 0),
            Some(WizardDuration::Custom(604_800))
        );

        assert_eq!(WizardDuration::custom(0, 0), None, "zero non è una durata");
        assert_eq!(WizardDuration::custom(168, 1), None, "oltre sette giorni");
        assert_eq!(
            WizardDuration::custom(1, 60),
            None,
            "i minuti vanno da 0 a 59"
        );
        assert_eq!(WizardDuration::custom(u32::MAX, 59), None);

        let Some(scelta) = WizardDuration::custom(2, 15) else {
            panic!("la durata di prova è nei limiti");
        };
        assert_eq!(
            scelta.to_session_duration(),
            SessionDuration::Custom { seconds: 8_100 }
        );
        assert_eq!(scelta.label(), "2 ore e 15 minuti (personalizzata)");
    }

    #[test]
    fn the_default_duration_is_one_hour() {
        let wizard = MonitoringWizard::new();
        assert_eq!(wizard.duration(), WizardDuration::Preset(3_600));
    }

    #[test]
    fn the_chosen_duration_is_kept() {
        let mut wizard = MonitoringWizard::new();
        wizard.set_duration(WizardDuration::Manual);
        assert_eq!(wizard.view().duration, WizardDuration::Manual);
    }

    // -------------------------------------------------------- selezione

    #[test]
    fn selecting_the_same_thing_twice_deselects_it() {
        let mut wizard = MonitoringWizard::new();
        let dictionary = DictionaryId::new(7);

        wizard.toggle_dictionary(dictionary);
        assert!(wizard.has_dictionary(dictionary));
        wizard.toggle_dictionary(dictionary);
        assert!(!wizard.has_dictionary(dictionary));

        wizard.toggle_source(SourceId::new(3));
        assert!(wizard.has_source(SourceId::new(3)));
    }

    fn livello_quattro() -> SuggestedLevel {
        let Ok(livello) = SuggestedLevel::try_new(4) else {
            panic!("il livello 4 è nella scala");
        };
        livello
    }

    #[test]
    fn the_same_word_is_not_added_twice() {
        let mut wizard = MonitoringWizard::new();
        for _ in 0..3 {
            let Ok(()) = wizard.add_custom_term(
                "incendio",
                MatchMode::NormalizedWord,
                SuggestedLevel::weakest_that_alerts(),
            ) else {
                panic!("la parola deve potersi aggiungere");
            };
        }
        assert_eq!(wizard.custom_terms().len(), 1);
        assert!(wizard.has_custom_term("incendio", MatchMode::NormalizedWord));
        assert!(!wizard.has_custom_term("incendio", MatchMode::Phrase));

        // Con un altro livello resta una sola riga (F-11).
        let Ok(()) =
            wizard.add_custom_term("incendio", MatchMode::NormalizedWord, livello_quattro())
        else {
            panic!("la parola deve potersi aggiungere");
        };
        assert_eq!(wizard.custom_terms().len(), 1);

        // La stessa parola con un'altra modalita' e' un'altra cosa.
        let Ok(()) = wizard.add_custom_term(
            "incendio",
            MatchMode::Phrase,
            SuggestedLevel::weakest_that_alerts(),
        ) else {
            panic!("la parola deve potersi aggiungere");
        };
        assert_eq!(wizard.custom_terms().len(), 2);
    }

    #[test]
    fn a_word_the_domain_refuses_does_not_enter_the_selection() {
        let mut wizard = MonitoringWizard::new();
        assert!(matches!(
            wizard.add_custom_term(
                "   ",
                MatchMode::NormalizedWord,
                SuggestedLevel::weakest_that_alerts()
            ),
            Err(ServiceError::Domain(_))
        ));
        assert!(wizard.custom_terms().is_empty());
    }

    #[test]
    fn a_word_can_be_removed_and_a_missing_index_changes_nothing() {
        let mut wizard = MonitoringWizard::new();
        let Ok(()) = wizard.add_custom_term(
            "incendio",
            MatchMode::NormalizedWord,
            SuggestedLevel::weakest_that_alerts(),
        ) else {
            panic!("la parola deve potersi aggiungere");
        };

        wizard.remove_custom_term(9);
        assert_eq!(wizard.custom_terms().len(), 1);
        wizard.remove_custom_term(0);
        assert!(wizard.custom_terms().is_empty());
    }

    // ---------------------------------------------------------- conferma

    #[test]
    fn the_last_step_says_plainly_that_the_start_is_not_available_yet() {
        // Un pulsante che finge di avviare qualcosa che non esiste sarebbe
        // peggio di un pulsante assente.
        let (service, dictionary) = service_with(&["incendio"]);
        let mut wizard = wizard_at(WizardStep::Summary, &service, dictionary);
        let Ok(()) = wizard.advance(&service) else {
            panic!("la conferma deve essere raggiungibile");
        };

        let view = wizard.view();
        assert_eq!(view.step, WizardStep::Confirmation);
        assert!(!view.can_advance, "non c'e' un passo successivo");
        let Some(reason) = view.blocking_reason else {
            panic!("la ragione deve essere detta");
        };
        // La conferma dichiara la condizione che serve davvero perche' i
        // contenuti arrivino - sessione in corso **e** account reale collegato -
        // senza promettere che arriveranno comunque.
        assert!(
            reason.contains("mentre il monitoraggio è in corso"),
            "la conferma deve dire quando i contenuti vengono acquisiti: {reason}"
        );
        // «modalità reale» e «modalità dimostrativa» erano nomi tecnici; la
        // frase dice la stessa condizione con le parole dell'operatore
        // (OPERATOR-UX-REMEDIATION-01, OS-13), e dice dove guardare (task 05).
        assert!(
            reason.contains("l'account d'ufficio è collegato"),
            "la conferma deve dire che serve l'account collegato: {reason}"
        );
        assert!(reason.contains("«Avvisi»"), "dice dove arrivano: {reason}");
        assert!(!reason.contains("dimostrativa"), "{reason}");
        // E non deve piu' dichiarare scollegata un'acquisizione che dal
        // 2026-07-30 e' collegata: una dichiarazione falsa all'operatore e'
        // peggio di nessuna dichiarazione.
        assert!(
            !reason.contains("non e' ancora collegata"),
            "l'acquisizione e' collegata: il messaggio non deve dire il contrario"
        );
    }

    #[test]
    fn an_unusable_dictionary_stops_the_summary_by_name() {
        use lisi_core::model::dictionary::DictionaryStatus;

        let (service, dictionary) = service_with(&["incendio"]);
        let Ok(()) = service.set_status(dictionary, DictionaryStatus::Archived, &operator(), now())
        else {
            panic!("l'archiviazione deve riuscire");
        };

        let mut wizard = MonitoringWizard::new();
        wizard.toggle_source(SourceId::new(1));
        wizard.toggle_dictionary(dictionary);
        let Ok(()) = wizard.advance(&service) else {
            panic!("il primo passo deve essere superabile");
        };
        let Ok(()) = wizard.advance(&service) else {
            panic!("il secondo passo deve essere superabile");
        };
        let Ok(()) = wizard.advance(&service) else {
            panic!("il terzo passo deve essere superabile");
        };

        assert!(matches!(
            wizard.advance(&service),
            Err(ServiceError::DictionaryNotSelectable { .. })
        ));
        assert_eq!(wizard.step(), WizardStep::Duration, "resta dove era");
    }

    // ------------------------------- DICT-01: la scelta multipla e le versioni

    /// **Zero, uno o molti: la selezione multipla è definita per tutti e tre.**
    ///
    /// Il criterio 38 di M3C chiedeva la selezione multipla e ne lasciava aperto
    /// il comportamento agli estremi. Sono tre casi con tre esiti distinti, e
    /// nessuno di essi è un errore:
    ///
    /// - **zero** dizionari si può, purché ci sia almeno una parola aggiunta:
    ///   il blocco guarda i **termini**, non i dizionari;
    /// - **uno** è il caso ordinario;
    /// - **molti** si compongono, e i termini in comune si contano una volta
    ///   sola conservando tutte le provenienze.
    #[test]
    fn zero_uno_o_molti_dizionari_sono_tre_esiti_definiti() {
        let (mut service, primo) = service_with(&["incendio"]);
        let secondo = add_dictionary(&mut service, "Secondo", &[("incendio", 3), ("dolo", 2)]);

        // Zero dizionari e nessuna parola: si ARRIVA al riepilogo, ed e' li'
        // che il blocco compare.
        //
        // Fino al 2026-08-04 il blocco stava al passo dei dizionari e il suo
        // stesso testo lo smentiva: mandava «al passo successivo» impedendo di
        // raggiungerlo. La condizione non era sbagliata, era applicata prima
        // del passo che la puo' soddisfare. Questa prova fissa dove sta ora.
        let mut vuoto = MonitoringWizard::new();
        vuoto.toggle_source(SourceId::new(1));
        while vuoto.step() != WizardStep::Summary {
            let Ok(()) = vuoto.advance(&service) else {
                panic!("il riepilogo deve essere raggiungibile anche senza termini");
            };
        }

        let vista = vuoto.view();
        assert!(
            !vista.can_advance,
            "dal riepilogo, senza termini, non si passa"
        );
        let Some(motivo) = vista.blocking_reason else {
            panic!("il blocco deve dire perche'");
        };
        assert!(
            motivo.contains("dizionario") && motivo.contains("parola"),
            "il motivo deve nominare ENTRAMBE le vie d'uscita: «{motivo}»"
        );
        assert!(
            vista.notices.is_empty(),
            "un blocco non e' un avviso, e non si duplica come tale"
        );

        // Uno.
        let uno = wizard_at(WizardStep::Summary, &service, primo);
        assert_eq!(uno.view().dictionary_count, 1);
        let Some(scelti) = uno.selected_dictionaries() else {
            panic!("la fotografia deve esistere dal riepilogo");
        };
        assert_eq!(scelti.len(), 1);

        // Molti: i due dizionari condividono «incendio», che si conta una volta.
        let mut molti = MonitoringWizard::new();
        molti.toggle_source(SourceId::new(1));
        molti.toggle_dictionary(primo);
        molti.toggle_dictionary(secondo);
        while molti.step() != WizardStep::Summary {
            let Ok(()) = molti.advance(&service) else {
                panic!("l'avanzamento con due dizionari deve riuscire");
            };
        }

        let vista = molti.view();
        assert_eq!(vista.dictionary_count, 2, "due dizionari scelti");
        assert_eq!(
            vista.resolved_terms,
            Some(2),
            "«incendio» e «dolo»: il termine comune si conta una volta sola"
        );
        assert_eq!(
            vista.shared_terms,
            Some(1),
            "«incendio» viene da entrambi, e il riepilogo lo dice"
        );
    }

    /// **Il riepilogo dice quale VERSIONE di ogni dizionario verrà usata.**
    ///
    /// È la metà che mancava al criterio 39. Un nome senza numero di versione
    /// dice quale dizionario, non quale contenuto: fra il monitoraggio di marzo
    /// e quello di ottobre lo stesso «Incendi» può avere trenta termini in più.
    #[test]
    fn il_riepilogo_porta_il_numero_di_versione_di_ogni_dizionario() {
        let (service, dictionary) = service_with(&["incendio"]);
        let wizard = wizard_at(WizardStep::Summary, &service, dictionary);

        let vista = wizard.view();
        let Some(scelti) = vista.selected_dictionaries else {
            panic!("il riepilogo deve portare la fotografia dei dizionari");
        };
        let Some(primo) = scelti.first() else {
            panic!("il dizionario scelto deve comparire");
        };

        assert_eq!(primo.name.as_str(), "Prova");
        assert_eq!(primo.version_number, 1);
        assert_eq!(
            primo.label(),
            "Prova v1",
            "si legge come si scrive in un atto"
        );
        assert_eq!(primo.terms, 1);
    }

    /// **La fotografia non sopravvive a un cambio di scelta.**
    ///
    /// Se le versioni restassero mentre i conteggi si azzerano, il riepilogo
    /// elencherebbe dizionari che la configurazione non contiene più: sarebbe
    /// peggio che non elencarli affatto.
    #[test]
    fn cambiare_scelta_butta_via_anche_le_versioni() {
        let (service, dictionary) = service_with(&["incendio"]);
        let mut wizard = wizard_at(WizardStep::Summary, &service, dictionary);
        assert!(wizard.selected_dictionaries().is_some());

        wizard.toggle_dictionary(dictionary);

        assert!(
            wizard.selected_dictionaries().is_none(),
            "la fotografia va invalidata insieme all'anteprima"
        );
        assert!(wizard.preview().is_none());
        assert!(
            wizard.view().notices.is_empty(),
            "senza fotografia, nessun avviso"
        );
    }

    // --------------------------------- WIZARD-01: gli avvisi non sono blocchi

    /// **Un avviso non spegne «Avanti».**
    ///
    /// È la distinzione che il criterio 39 chiedeva. Se un avviso bloccasse, un
    /// monitoraggio legittimo resterebbe fermo; se un blocco si mostrasse come
    /// avviso, chi ha fretta lo salterebbe.
    #[test]
    fn un_avviso_non_e_un_blocco_e_non_ferma_il_wizard() {
        let (service, dictionary) = service_with(&["incendio"]);
        let wizard = wizard_at(WizardStep::Summary, &service, dictionary);

        let vista = wizard.view();
        assert!(
            !vista.notices.is_empty(),
            "senza contesto riduttivo l'avviso deve esserci"
        );
        assert_eq!(
            vista.blocking_reason, None,
            "e non deve essere un motivo di blocco"
        );
        assert!(vista.can_advance, "il riepilogo si supera lo stesso");
    }

    /// **L'avviso sul contesto riduttivo guarda i TERMINI, non i nomi.**
    ///
    /// Le due metodologie più delicate del prodotto lo prescrivono: Cyber Core
    /// perché «malware» e «phishing» sono parole divulgative, un dizionario
    /// tematico perché senza riduttori un archivio di giornale produce
    /// centinaia di riscontri e nemmeno un segnale utile.
    ///
    /// La regola si legge dal segno del livello suggerito. Riconoscere il
    /// contesto riduttivo dal **nome** funzionerebbe finché qualcuno non
    /// rinomina il proprio, e fallirebbe in silenzio.
    #[test]
    fn l_avviso_sul_contesto_riduttivo_legge_i_livelli_e_non_i_nomi() {
        let (mut service, alza) = service_with(&["incendio"]);
        // Nome deliberatamente muto: la regola non deve poterlo usare.
        let riduce = add_dictionary(&mut service, "Zeta", &[("nel film", -3), ("citazione", -2)]);

        let solo = wizard_at(WizardStep::Summary, &service, alza);
        assert!(
            solo.view()
                .notices
                .iter()
                .any(|avviso| avviso.text.contains("abbassa il peso")),
            "senza riduttori l'avviso deve comparire"
        );

        let mut insieme = MonitoringWizard::new();
        insieme.toggle_source(SourceId::new(1));
        insieme.toggle_dictionary(alza);
        insieme.toggle_dictionary(riduce);
        while insieme.step() != WizardStep::Summary {
            let Ok(()) = insieme.advance(&service) else {
                panic!("l'avanzamento deve riuscire");
            };
        }

        assert!(
            !insieme
                .view()
                .notices
                .iter()
                .any(|avviso| avviso.text.contains("abbassa il peso")),
            "con un dizionario di termini negativi l'avviso non ha ragione di esserci"
        );
    }

    /// **Un dizionario che porta i propri riduttori non fa scattare l'avviso.**
    ///
    /// È il caso di un dizionario tematico che contiene sia condotte sia
    /// riduttori. Una regola che guardasse i nomi lo segnalerebbe comunque; una
    /// che guarda i termini vede che il contesto riduttivo c'è già.
    #[test]
    fn un_dizionario_che_porta_i_propri_riduttori_basta_a_se_stesso() {
        let (mut service, _) = service_with(&["incendio"]);
        let misto = add_dictionary(
            &mut service,
            "Condotte e riduttori",
            &[("condotta", 3), ("secondo la stampa", -3)],
        );

        let wizard = wizard_at(WizardStep::Summary, &service, misto);
        assert!(
            !wizard
                .view()
                .notices
                .iter()
                .any(|avviso| avviso.text.contains("abbassa il peso")),
            "il dizionario porta i propri riduttori: nessun avviso"
        );
    }

    /// **Un dizionario scelto e vuoto non può esistere, e questa prova lo
    /// dimostra.**
    ///
    /// # L'avviso che non è stato scritto
    ///
    /// Scrivendo gli avvisi ne era stato aggiunto un terzo: «questo dizionario
    /// è stato scelto ma non contiene termini, e non cercherà nulla». Sembrava
    /// prudente.
    ///
    /// La prova che doveva dimostrarlo **non è riuscita a costruire il caso**:
    /// una versione senza termini non si pubblica, e un dizionario senza
    /// versione pubblicata non è selezionabile. Le due regole si incastrano, e
    /// lo stato che l'avviso descriveva non è raggiungibile.
    ///
    /// L'avviso è stato tolto, e resta questa prova. Un avviso che non può
    /// scattare occupa spazio nel riepilogo, chiede di essere mantenuto, e
    /// lascia credere che il caso sia sorvegliato quando è semplicemente
    /// impossibile. La prova dell'impossibilità è la garanzia vera.
    #[test]
    fn un_dizionario_senza_termini_non_arriva_al_riepilogo() {
        let (service, _) = service_with(&["incendio"]);

        let (Ok(nome), Ok(descrizione)) = (
            DictionaryName::try_new("Vuoto"),
            DictionaryDescription::try_new("nessun termine"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok((vuoto, versione)) = service.create(
            &DictionaryProposal {
                name: nome,
                description: descrizione,
                scope: DictionaryScope::Thematic,
                visibility: DictionaryVisibility::Personal,
            },
            &operator(),
            now(),
        ) else {
            panic!("il dizionario deve potersi creare");
        };

        // Prima regola: una versione senza termini non si pubblica.
        assert!(
            service.publish(versione, &operator(), now()).is_err(),
            "una versione vuota non deve potersi pubblicare"
        );

        // Seconda regola: senza versione pubblicata non e' selezionabile, e la
        // fotografia lo rifiuta invece di trattarlo come un dizionario a zero
        // termini.
        assert!(
            matches!(
                service.selected_versions(&[vuoto]),
                Err(ServiceError::DictionaryNotSelectable { .. })
            ),
            "un dizionario senza versione pubblicata non e' selezionabile"
        );
    }

    /// **La durata «fino all'arresto manuale» è un avviso, non un difetto.**
    #[test]
    fn la_durata_manuale_si_dichiara_nel_riepilogo() {
        let (service, dictionary) = service_with(&["incendio"]);

        let preimpostata = wizard_at(WizardStep::Summary, &service, dictionary);
        assert!(
            !preimpostata
                .view()
                .notices
                .iter()
                .any(|avviso| avviso.text.contains("arresto manuale")),
            "una durata preimpostata non produce l'avviso"
        );

        let mut manuale = MonitoringWizard::new();
        manuale.toggle_source(SourceId::new(1));
        manuale.toggle_dictionary(dictionary);
        manuale.set_duration(WizardDuration::Manual);
        while manuale.step() != WizardStep::Summary {
            let Ok(()) = manuale.advance(&service) else {
                panic!("l'avanzamento deve riuscire");
            };
        }

        assert!(
            manuale
                .view()
                .notices
                .iter()
                .any(|avviso| avviso.text.contains("arresto manuale")),
            "la durata senza fine va detta prima di avviare"
        );
    }

    /// **Un avviso offre un rimedio solo quando ce n'è uno.**
    ///
    /// «Manca il contesto riduttivo» ha un gesto che lo scioglie. «La durata è
    /// manuale» no: è una scelta, non una mancanza, e offrire un rimedio
    /// suggerirebbe che sia da correggere.
    #[test]
    fn un_avviso_offre_un_rimedio_solo_quando_ce_n_e_uno() {
        let (service, dictionary) = service_with(&["incendio"]);
        let mut wizard = MonitoringWizard::new();
        wizard.toggle_source(SourceId::new(1));
        wizard.toggle_dictionary(dictionary);
        wizard.set_duration(WizardDuration::Manual);
        while wizard.step() != WizardStep::Summary {
            let Ok(()) = wizard.advance(&service) else {
                panic!("l'avanzamento deve riuscire");
            };
        }

        let avvisi = wizard.view().notices;
        let Some(riduttivo) = avvisi
            .iter()
            .find(|avviso| avviso.text.contains("abbassa il peso"))
        else {
            panic!("l'avviso sul contesto riduttivo deve esserci: {avvisi:?}");
        };
        assert!(
            riduttivo
                .remedy
                .as_ref()
                .is_some_and(|rimedio| rimedio.contains("Dizionari")),
            "un rimedio deve dire dove tornare"
        );

        let Some(durata) = avvisi
            .iter()
            .find(|avviso| avviso.text.contains("arresto manuale"))
        else {
            panic!("l'avviso sulla durata deve esserci");
        };
        assert_eq!(
            durata.remedy, None,
            "una scelta legittima non ha un rimedio da proporre"
        );
    }

    /// **Prima del riepilogo non ci sono avvisi da dare.**
    ///
    /// Mostrarli prima significherebbe darli su una configurazione non ancora
    /// calcolata: sarebbero indovinati.
    #[test]
    fn prima_del_riepilogo_non_si_danno_avvisi() {
        let (service, dictionary) = service_with(&["incendio"]);

        for passo in [
            WizardStep::Sources,
            WizardStep::Dictionaries,
            WizardStep::CustomTerms,
            WizardStep::Duration,
        ] {
            let wizard = wizard_at(passo, &service, dictionary);
            assert!(
                wizard.view().notices.is_empty(),
                "al passo «{}» non ci sono avvisi da dare",
                passo.title()
            );
            assert!(wizard.view().selected_dictionaries.is_none());
        }
    }
}

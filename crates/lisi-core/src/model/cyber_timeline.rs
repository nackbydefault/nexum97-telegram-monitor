//! La cronologia di un grappolo di segnali (CYT-01).
//!
//! # Che cosa è, e che cosa non è
//!
//! Un [`CyberEvent`](crate::model::cyber_event::CyberEvent) dice **che cosa sta
//! insieme**; questa cronologia dice **in che ordine è arrivato**: la prima
//! osservazione, il momento in cui i contenuti sono diventati due, una fonte
//! che non si era ancora vista, un indicatore che prima non c'era, una
//! revisione avviata, una decisione presa da una persona.
//!
//! Non è la cronologia di un attacco. È la cronologia di **ciò che questo
//! archivio ha visto e di ciò che questo ufficio ha fatto**, e le due cose
//! stanno sulla stessa linea perché è lì che servono — non perché siano la
//! stessa cosa.
//!
//! # La cosa che nessuno vedrebbe da sé: gli istanti vengono da due orologi
//!
//! Le righe dei contenuti portano l'istante che **la fonte dichiara**. Le righe
//! delle revisioni portano l'istante che **questo programma ha misurato**.
//!
//! Sono due orologi diversi, e nessuno li ha sincronizzati. Il primo arriva da
//! Telegram e non è verificabile da qui; il secondo è l'orologio della
//! postazione, che qualcuno può aver spostato, e che in una sede può differire
//! da quello di un'altra.
//!
//! Su una linea del tempo la differenza sparisce: due righe una sotto l'altra
//! **sembrano** dire «prima questo, poi quello». Se la prima è dichiarata e la
//! seconda è misurata, quella successione **non è un fatto osservato**, ed è
//! esattamente il genere di frase che, in una relazione, pesa: «il messaggio è
//! stato pubblicato dopo che l'operatore lo aveva già esaminato» descriverebbe
//! un'anomalia che potrebbe essere soltanto uno scarto fra due orologi.
//!
//! Perciò **ogni riga dichiara di quale orologio è il proprio istante**, e la
//! dichiarazione non è un campo che qualcuno compila: discende dal genere della
//! riga ([`EventMoment::clock`]). Non esiste una riga che possa sbagliarlo,
//! perché non esiste un posto dove scriverlo.
//!
//! # Ogni voce porta i propri rimandi, e non è costruibile senza
//!
//! Il congelamento chiede che ogni voce rimandi al **contenuto**, al
//! **contesto** e al **messaggio originale** dove possibile. Qui il rimando è
//! dentro il tipo: [`TimelineEntry`] ha i campi privati e un solo costruttore,
//! che vuole un [`EventReference`]. Una voce senza rimandi **non si scrive**.
//!
//! È la garanzia di PERS-03 applicata a un'altra cosa: il compilatore, non una
//! convenzione.
//!
//! # Il messaggio originale: un identificativo, non un indirizzo
//!
//! [`EventReference`] **non porta un URL**, e non può portarlo.
//!
//! LINK-01 ha stabilito che un collegamento a un messaggio è ciò che Telegram
//! restituisce al momento, non qualcosa che si compone da due numeri, e che
//! nell'archivio finisce soltanto ciò che Telegram ha dato. Una cronologia che
//! si fabbricasse un indirizzo per ogni riga rimetterebbe in piedi proprio la
//! composizione locale che quella milestone ha tolto — e lo farebbe dentro un
//! documento che qualcuno consegna.
//!
//! Qui c'è l'identificativo remoto, che è **ciò che l'archivio possiede**. Il
//! collegamento si chiede a Telegram nel momento in cui serve.
//!
//! # Nessun punteggio, nessuna conclusione
//!
//! Nessun campo numerico riassume la cronologia. Una linea del tempo con
//! accanto un numero si legge come un punteggio, e un punteggio accanto a un
//! grappolo di segnali è la conclusione che questo prodotto non trae
//! (ADR-0035, ADR-0048).

use crate::model::cyber_event::CorrelationReason;
use crate::model::indicator::IndicatorKind;
use crate::model::observation_window::ObservationWindow;
use crate::model::review::ReviewState;
use crate::text::{Actor, RemoteMessageId};
use crate::time::Timestamp;
use crate::{ContentId, ContextSnapshotId, SourceId};

/// Da quale orologio viene l'istante di una riga.
///
/// # Perché due e non uno
///
/// Perché sono due misure diverse della stessa grandezza, e soltanto una delle
/// due è stata fatta qui. Chiamarle entrambe «quando» renderebbe confrontabili
/// due numeri che nessuno ha allineato.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Clock {
    /// L'istante **dichiarato dalla fonte**.
    ///
    /// Arriva con il messaggio, da Telegram. Questo programma non lo ha
    /// misurato e non può verificarlo.
    DeclaredBySource,
    /// L'istante **misurato da questo programma**.
    ///
    /// È l'orologio della postazione al momento in cui il fatto è stato
    /// registrato. «Misurato» non significa «esatto»: significa che a misurarlo
    /// è stato questo programma, e non qualcun altro.
    MeasuredHere,
}

impl Clock {
    /// Come si nomina a chi legge.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::DeclaredBySource => "istante dichiarato dalla fonte",
            Self::MeasuredHere => "istante misurato da questo programma",
        }
    }

    /// Che cosa significa, per esteso.
    #[must_use]
    pub const fn as_sentence(self) -> &'static str {
        match self {
            Self::DeclaredBySource => {
                "Questo istante lo dichiara la fonte: arriva con il messaggio, e questo programma \
                 non lo ha misurato n\u{e9} pu\u{f2} verificarlo."
            }
            Self::MeasuredHere => {
                "Questo istante lo ha misurato questo programma, con l'orologio della postazione."
            }
        }
    }
}

/// Se del contorno di un messaggio esiste una fotografia conservata.
///
/// # Perché non un `Option`
///
/// Perché `None` si legge come «niente», e le due cose non sono equivalenti:
/// **nessuno ha fotografato** non è **non c'era nulla attorno**. La prima è un
/// fatto sull'ufficio, la seconda sarebbe un fatto su Telegram, e questo
/// programma non lo ha osservato (ADR-0053).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextAvailability {
    /// Una fotografia del contorno esiste, e si può riaprire.
    Snapshot(ContextSnapshotId),
    /// Nessuna fotografia è stata presa attorno a questo messaggio.
    NeverTaken,
}

impl ContextAvailability {
    /// Che cosa c'è, o che cosa non c'è, detto a chi legge.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self {
            Self::Snapshot(id) => format!(
                "Contesto: esiste la fotografia #{}, presa da una persona, e si pu\u{f2} \
                 riaprire com'era allora.",
                id.get()
            ),
            Self::NeverTaken => String::from(
                "Contesto: nessuno ha fotografato ci\u{f2} che stava attorno a questo \
                 messaggio. Non significa che attorno non ci fosse nulla: significa che non \
                 \u{e8} stato conservato. Il contorno di adesso si pu\u{f2} chiedere a Telegram, \
                 e non \u{e8} una prova di allora.",
            ),
        }
    }
}

/// I rimandi di una voce: **contenuto, contesto, messaggio originale**.
///
/// # Perché i campi sono privati e il costruttore è uno solo
///
/// Perché il congelamento chiede che ogni voce li porti tutti e tre, e un campo
/// pubblico è un campo che qualcuno lascerà vuoto. Il costruttore li vuole; non
/// c'è `Default`, non c'è un `Option` da passare `None`.
///
/// # Perché non c'è un indirizzo
///
/// Vedere la nota di modulo: un collegamento al messaggio si chiede a Telegram
/// al momento e non si compone da due numeri (LINK-01).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventReference {
    /// Il contenuto nell'archivio. **È la prova.**
    content: ContentId,
    /// La fonte da cui proviene.
    source: SourceId,
    /// L'identificativo del messaggio presso Telegram.
    ///
    /// È ciò con cui si chiede il collegamento, quando qualcuno lo chiede: non
    /// è il collegamento.
    remote_message_id: RemoteMessageId,
    /// Se del contorno esiste una fotografia.
    context: ContextAvailability,
}

impl EventReference {
    /// I tre rimandi, tutti e tre.
    #[must_use]
    pub const fn new(
        content: ContentId,
        source: SourceId,
        remote_message_id: RemoteMessageId,
        context: ContextAvailability,
    ) -> Self {
        Self {
            content,
            source,
            remote_message_id,
            context,
        }
    }

    /// Il contenuto nell'archivio.
    #[must_use]
    pub const fn content(&self) -> ContentId {
        self.content
    }

    /// La fonte.
    #[must_use]
    pub const fn source(&self) -> SourceId {
        self.source
    }

    /// L'identificativo del messaggio presso Telegram.
    #[must_use]
    pub const fn remote_message_id(&self) -> &RemoteMessageId {
        &self.remote_message_id
    }

    /// Se del contorno esiste una fotografia.
    #[must_use]
    pub const fn context(&self) -> &ContextAvailability {
        &self.context
    }

    /// I rimandi, detti a chi legge.
    ///
    /// Nomina il messaggio originale **per identificativo**, e dice perché non
    /// c'è un indirizzo: chi legge un rapporto deve sapere che quel
    /// collegamento va chiesto, non che manchi.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        format!(
            "Contenuto #{} della fonte #{}. Messaggio originale: {} presso Telegram \u{2014} il \
             collegamento lo fornisce Telegram al momento, e non viene conservato. {}",
            self.content.get(),
            self.source.get(),
            self.remote_message_id.as_str(),
            self.context.as_sentence()
        )
    }
}

/// Che cosa è successo, in un grappolo.
///
/// # Perché sei generi e non uno solo con un'etichetta
///
/// Perché sono sei fatti di natura diversa, e due di essi sono atti di una
/// persona mentre gli altri quattro sono osservazioni dell'archivio. Una sola
/// variante con una stringa dentro renderebbe la distinzione una questione di
/// come è scritta l'etichetta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventMoment {
    /// **Osservazione dell'archivio:** il primo contenuto di questo grappolo.
    ///
    /// # Perché non «la prima volta che se ne è parlato»
    ///
    /// Perché il grappolo vive dentro **un monitoraggio**, e nomina i contenuti
    /// di quel monitoraggio. Di quell'indicatore si può essere parlato per mesi
    /// altrove, o in una sessione precedente. Questa riga dice soltanto qual è
    /// il primo contenuto **qui dentro**.
    FirstObservation,
    /// **Osservazione dell'archivio:** i contenuti sono diventati due.
    ///
    /// È il momento in cui il grappolo diventa un grappolo: prima c'era un
    /// contenuto che nominava un indicatore, che non è una correlazione.
    CorrelationFormed {
        /// Il contenuto con cui si è formata: il primo.
        with: ContentId,
    },
    /// **Osservazione dell'archivio:** una fonte che non si era ancora vista.
    ///
    /// # Perché non si chiama «conferma»
    ///
    /// Perché fonti distinte non sono conferme indipendenti: possono riprendere
    /// la stessa origine. È la distinzione che regge tutto il Cyber Watch.
    AdditionalSource,
    /// **Osservazione dell'archivio:** un indicatore che nel grappolo non c'era.
    ///
    /// Non l'indicatore che tiene insieme il grappolo — quello è in ogni membro
    /// per costruzione, ed è la ragione stessa: un altro, portato da questo
    /// contenuto.
    NewIndicator {
        /// Il genere.
        kind: IndicatorKind,
        /// Il valore normalizzato.
        value: String,
    },
    /// **Atto di una persona:** ha preso in carico un contenuto.
    ReviewStarted {
        /// Chi.
        reviewer: Actor,
    },
    /// **Atto di una persona:** ha concluso l'esame di un contenuto.
    HumanDecision {
        /// Chi.
        reviewer: Actor,
        /// Che cosa ha deciso.
        state: ReviewState,
    },
}

impl EventMoment {
    /// Da quale orologio viene l'istante di questa riga.
    ///
    /// # Perché è una funzione e non un campo
    ///
    /// Perché un campo si compila, e ciò che si compila si può sbagliare. Qui
    /// l'orologio **discende dal genere del fatto**: un contenuto porta con sé
    /// l'istante che la fonte dichiara, una revisione porta quello che questa
    /// postazione ha misurato. Non esiste una riga che possa dichiarare
    /// l'orologio sbagliato, perché non esiste un posto dove scriverlo.
    #[must_use]
    pub const fn clock(&self) -> Clock {
        match self {
            Self::FirstObservation
            | Self::CorrelationFormed { .. }
            | Self::AdditionalSource
            | Self::NewIndicator { .. } => Clock::DeclaredBySource,
            Self::ReviewStarted { .. } | Self::HumanDecision { .. } => Clock::MeasuredHere,
        }
    }

    /// Se il fatto è l'atto di una persona.
    ///
    /// Serve a chi mostra la linea: un atto di una persona e un'osservazione
    /// dell'archivio non vanno resi allo stesso modo, perché non sono la stessa
    /// cosa e chi legge deve poterlo vedere senza leggere la frase.
    #[must_use]
    pub const fn is_human_act(&self) -> bool {
        matches!(
            self,
            Self::ReviewStarted { .. } | Self::HumanDecision { .. }
        )
    }

    /// Che cosa è successo, detto a chi legge.
    ///
    /// # Che cosa nessuna di queste frasi dice
    ///
    /// Nessuna dice che sia avvenuto un attacco, che una fonte sia attendibile,
    /// o che il grappolo *sia* qualcosa. Dicono che cosa è arrivato e chi ha
    /// fatto che cosa.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self {
            Self::FirstObservation => String::from(
                "Primo contenuto di questo grappolo. Non \u{e8} la prima volta che di questo \
                 indicatore si \u{e8} parlato: \u{e8} il primo che questo monitoraggio ha \
                 acquisito.",
            ),
            Self::CorrelationFormed { with } => format!(
                "I contenuti diventano due, con il contenuto #{}: da qui il grappolo esiste. Un \
                 solo contenuto che nomina un indicatore non \u{e8} una correlazione.",
                with.get()
            ),
            Self::AdditionalSource => String::from(
                "Una fonte che in questo grappolo non si era ancora vista. Fonti distinte non \
                 sono conferme indipendenti: possono riprendere la stessa origine.",
            ),
            Self::NewIndicator { kind, value } => format!(
                "Questo contenuto porta anche {} \u{ab}{value}\u{bb}, che nel grappolo non c'era.",
                kind.label()
            ),
            Self::ReviewStarted { reviewer } => {
                format!("{} ha preso in carico il contenuto.", reviewer.as_str())
            }
            Self::HumanDecision { reviewer, state } => format!(
                "{} ha concluso l'esame del contenuto: {}.",
                reviewer.as_str(),
                state.label()
            ),
        }
    }
}

/// Una riga della cronologia, **con i suoi rimandi**.
///
/// I campi sono privati e il costruttore è uno solo: vedere la nota di modulo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineEntry {
    /// Quando, secondo l'orologio che [`EventMoment::clock`] dichiara.
    at: Timestamp,
    /// Che cosa.
    moment: EventMoment,
    /// A che cosa rimanda.
    reference: EventReference,
}

impl TimelineEntry {
    /// Una riga, che **richiede** i propri rimandi.
    #[must_use]
    pub const fn new(at: Timestamp, moment: EventMoment, reference: EventReference) -> Self {
        Self {
            at,
            moment,
            reference,
        }
    }

    /// Quando.
    #[must_use]
    pub const fn at(&self) -> Timestamp {
        self.at
    }

    /// Che cosa.
    #[must_use]
    pub const fn moment(&self) -> &EventMoment {
        &self.moment
    }

    /// A che cosa rimanda.
    #[must_use]
    pub const fn reference(&self) -> &EventReference {
        &self.reference
    }

    /// Da quale orologio viene l'istante di questa riga.
    #[must_use]
    pub const fn clock(&self) -> Clock {
        self.moment.clock()
    }

    /// La riga intera, detta a chi legge.
    ///
    /// L'orologio è nominato **in ogni riga**, e non una volta in fondo alla
    /// schermata: una riga citata in un documento viaggia da sola.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        format!(
            "{} ({}) \u{2014} {} {}",
            self.at.to_readable_utc(),
            self.clock().as_label(),
            self.moment.as_sentence(),
            self.reference.as_sentence()
        )
    }
}

/// La cronologia di un grappolo, **con la sua finestra di osservazione**.
///
/// # Perché la finestra è obbligatoria
///
/// Per la ragione di PERS-04: senza, un periodo senza righe si legge come «non
/// è successo niente», che è un fatto che nessuno ha misurato. Il campo è
/// privato, il costruttore la vuole, non c'è `Default`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CyberTimeline {
    /// Perché quei contenuti stanno insieme.
    reason: CorrelationReason,
    /// Le righe, dalla più antica.
    entries: Vec<TimelineEntry>,
    /// Quando si stava guardando.
    window: ObservationWindow,
}

impl CyberTimeline {
    /// Una cronologia, che **richiede** la propria finestra di osservazione.
    #[must_use]
    pub const fn new(
        reason: CorrelationReason,
        entries: Vec<TimelineEntry>,
        window: ObservationWindow,
    ) -> Self {
        Self {
            reason,
            entries,
            window,
        }
    }

    /// Perché quei contenuti stanno insieme.
    #[must_use]
    pub const fn reason(&self) -> &CorrelationReason {
        &self.reason
    }

    /// Le righe, dalla più antica.
    #[must_use]
    pub fn entries(&self) -> &[TimelineEntry] {
        &self.entries
    }

    /// Quando si stava guardando.
    #[must_use]
    pub const fn window(&self) -> &ObservationWindow {
        &self.window
    }

    /// Le righe di **un solo orologio**, nell'ordine in cui stanno.
    ///
    /// # Perché serve
    ///
    /// Perché l'ordine fra righe dello stesso orologio è una successione
    /// misurata allo stesso modo, e regge; quello fra orologi diversi no. Chi
    /// deve affermare «prima questo, poi quello» deve poter guardare un
    /// orologio alla volta.
    #[must_use]
    pub fn entries_from(&self, clock: Clock) -> Vec<&TimelineEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.clock() == clock)
            .collect()
    }

    /// L'avvertenza che accompagna la cronologia.
    ///
    /// # Perché la prima parte compare sempre
    ///
    /// Per la ragione di PERS-04: «c'è un vuoto» è già un giudizio, e una
    /// cronologia è sempre parziale.
    ///
    /// # Perché la seconda no
    ///
    /// Perché l'avvertenza sui due orologi riguarda **la mescolanza**, e una
    /// linea che venga da un orologio solo non la contiene. Una guardia che
    /// compare anche dove non serve è una guardia che si impara a saltare, ed è
    /// esattamente la domanda che HVQ-41 pone su un'altra avvertenza.
    #[must_use]
    pub fn caveat(&self) -> String {
        let mut testo = String::from(
            "Queste righe dicono che cosa si \u{e8} osservato e che cosa questo ufficio ha \
             fatto. Si \u{e8} osservato soltanto durante il monitoraggio indicato, e soltanto \
             nelle sue fonti. Un periodo senza righe non significa che non sia successo \
             niente: pu\u{f2} significare che nessuno stava guardando.",
        );

        let dichiarati = self
            .entries
            .iter()
            .any(|entry| entry.clock() == Clock::DeclaredBySource);
        let misurati = self
            .entries
            .iter()
            .any(|entry| entry.clock() == Clock::MeasuredHere);

        if dichiarati && misurati {
            testo.push_str(
                " Gli istanti vengono da due orologi diversi: quelli dei contenuti li \
                 dichiara la fonte, quelli delle revisioni li ha misurati questa postazione. \
                 Nessuno li ha sincronizzati. L'ordine fra una riga dichiarata e una misurata \
                 non \u{e8} un dato osservato.",
            );
        }

        testo
    }
}

/// Una revisione già registrata, come fatto d'ingresso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewFact {
    /// Che cosa è stato deciso, o preso in carico.
    pub state: ReviewState,
    /// Chi.
    pub reviewer: Actor,
    /// Quando, **misurato da questo programma**.
    pub at: Timestamp,
}

/// Un membro del grappolo, con ciò che serve a comporne le righe.
///
/// # Perché senza il corpo del messaggio
///
/// Per la ragione di PERS-02, PERS-03 e PERS-04: alla composizione non serve il
/// testo, e **una funzione che non riceve una cosa non può usarla**. Il testo di
/// un messaggio su una linea del tempo sarebbe una citazione senza contesto, che
/// è il modo più rapido di trasformare un elenco in un'accusa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventFact {
    /// Quale contenuto.
    pub content: ContentId,
    /// Da quale fonte.
    pub source: SourceId,
    /// L'identificativo del messaggio presso Telegram.
    pub remote_message_id: RemoteMessageId,
    /// Quando la fonte dichiara che è stato pubblicato.
    pub published_at: Timestamp,
    /// Gli indicatori che quel contenuto nomina.
    pub indicators: Vec<(IndicatorKind, String)>,
    /// Se del contorno esiste una fotografia.
    pub context: ContextAvailability,
    /// Le revisioni registrate su quel contenuto, in qualunque ordine.
    pub reviews: Vec<ReviewFact>,
}

/// L'indicatore che tiene insieme il grappolo, quando la ragione ne nomina uno.
///
/// Serve a non ripetere come «indicatore nuovo» proprio quello che è la ragione
/// del grappolo: comparirebbe sulla prima riga di ogni cronologia, dicendo a chi
/// legge una cosa che il titolo dice già.
fn indicatore_della_ragione(reason: &CorrelationReason) -> Option<(IndicatorKind, &str)> {
    match reason {
        CorrelationReason::SameIndicator { kind, value } => Some((*kind, value.as_str())),
    }
}

/// Il rango di un genere di riga, a parità di istante.
///
/// # Perché serve un ordine fra righe simultanee
///
/// Perché due letture dello stesso archivio devono dare la stessa cronologia.
/// Righe con lo stesso istante e nessun criterio secondario uscirebbero in un
/// ordine che dipende da come il motore ha risposto quel giorno, e una
/// cronologia che cambia ordine non è una cronologia.
///
/// L'ordine sceglie il **racconto**: prima ciò che rende il grappolo un
/// grappolo, poi ciò che il contenuto aggiunge, infine ciò che una persona ha
/// fatto.
const fn rango(moment: &EventMoment) -> u8 {
    match moment {
        EventMoment::FirstObservation => 0,
        EventMoment::CorrelationFormed { .. } => 1,
        EventMoment::AdditionalSource => 2,
        EventMoment::NewIndicator { .. } => 3,
        EventMoment::ReviewStarted { .. } => 4,
        EventMoment::HumanDecision { .. } => 5,
    }
}

/// Compone la cronologia di un grappolo.
///
/// # Perché una funzione pura
///
/// Perché la composizione è la parte che merita una prova, e una prova non deve
/// costruire un archivio per esercitarla. È la scelta di PERS-02, PERS-03 e
/// PERS-04.
///
/// # La finestra arriva da fuori, e non si indovina
///
/// Perché è un fatto del **monitoraggio**, non dei contenuti: un monitoraggio
/// che ha guardato senza raccogliere nulla ha comunque guardato, e dedurre la
/// finestra dai contenuti perderebbe esattamente il caso in cui un vuoto va
/// spiegato.
#[must_use]
pub fn timeline_for(
    reason: CorrelationReason,
    facts: &[EventFact],
    window: ObservationWindow,
) -> CyberTimeline {
    // ORDINE RIPETIBILE.
    //
    // A parita' di istante dichiarato decide l'identificativo del contenuto:
    // senza un criterio secondario, due letture darebbero due cronologie
    // diverse.
    let mut ordinati: Vec<&EventFact> = facts.iter().collect();
    ordinati.sort_by(|a, b| {
        a.published_at
            .cmp(&b.published_at)
            .then(a.content.get().cmp(&b.content.get()))
    });

    let indicatore_ragione = indicatore_della_ragione(&reason);
    let mut righe: Vec<TimelineEntry> = Vec::new();
    let mut fonti_viste: Vec<SourceId> = Vec::new();
    let mut indicatori_visti: Vec<(IndicatorKind, String)> = Vec::new();
    let mut primo_contenuto: Option<ContentId> = None;

    for (posizione, fatto) in ordinati.iter().enumerate() {
        let rimando = EventReference::new(
            fatto.content,
            fatto.source,
            fatto.remote_message_id.clone(),
            fatto.context.clone(),
        );

        if posizione == 0 {
            righe.push(TimelineEntry::new(
                fatto.published_at,
                EventMoment::FirstObservation,
                rimando.clone(),
            ));
            primo_contenuto = Some(fatto.content);
        } else {
            // LA CORRELAZIONE SI FORMA UNA VOLTA SOLA, al secondo contenuto.
            if posizione == 1 {
                if let Some(primo) = primo_contenuto {
                    righe.push(TimelineEntry::new(
                        fatto.published_at,
                        EventMoment::CorrelationFormed { with: primo },
                        rimando.clone(),
                    ));
                }
            } else if !fonti_viste.contains(&fatto.source) {
                // UNA FONTE NUOVA MERITA UNA RIGA; la stessa fonte no.
                //
                // Il contenuto che forma la correlazione NON produce anche una
                // riga «fonte aggiuntiva»: due righe allo stesso istante che
                // raccontano lo stesso arrivo sono l'elenco che nessuno scorre,
                // ed e' la lezione di PERS-02.
                righe.push(TimelineEntry::new(
                    fatto.published_at,
                    EventMoment::AdditionalSource,
                    rimando.clone(),
                ));
            }
        }

        if !fonti_viste.contains(&fatto.source) {
            fonti_viste.push(fatto.source);
        }

        // UN INDICATORE NUOVO MERITA UNA RIGA.
        //
        // Non quello che tiene insieme il grappolo: e' in ogni membro per
        // costruzione, ed e' gia' il titolo.
        for (kind, value) in &fatto.indicators {
            if indicatore_ragione == Some((*kind, value.as_str())) {
                continue;
            }
            let chiave = (*kind, value.clone());
            if indicatori_visti.contains(&chiave) {
                continue;
            }
            indicatori_visti.push(chiave);
            righe.push(TimelineEntry::new(
                fatto.published_at,
                EventMoment::NewIndicator {
                    kind: *kind,
                    value: value.clone(),
                },
                rimando.clone(),
            ));
        }

        // LE REVISIONI, con l'orologio di questa postazione.
        //
        // `New` non produce una riga: significa «non ancora esaminato», che e'
        // quello che dice anche l'assenza di una revisione. Una riga che lo
        // annunciasse direbbe che qualcuno ha fatto qualcosa, e nessuno ha
        // fatto niente.
        let mut revisioni: Vec<&ReviewFact> = fatto.reviews.iter().collect();
        revisioni.sort_by(|a, b| a.at.cmp(&b.at).then(a.state.as_str().cmp(b.state.as_str())));

        for revisione in revisioni {
            let momento = if revisione.state.is_decided() {
                EventMoment::HumanDecision {
                    reviewer: revisione.reviewer.clone(),
                    state: revisione.state,
                }
            } else if revisione.state == ReviewState::InReview {
                EventMoment::ReviewStarted {
                    reviewer: revisione.reviewer.clone(),
                }
            } else {
                continue;
            };

            righe.push(TimelineEntry::new(revisione.at, momento, rimando.clone()));
        }
    }

    // L'ORDINE FINALE.
    //
    // Per istante, poi per rango del genere, poi per contenuto: tre criteri che
    // non lasciano alcun pareggio al caso.
    righe.sort_by(|a, b| {
        a.at()
            .cmp(&b.at())
            .then(rango(a.moment()).cmp(&rango(b.moment())))
            .then(
                a.reference()
                    .content()
                    .get()
                    .cmp(&b.reference().content().get()),
            )
    });

    CyberTimeline::new(reason, righe, window)
}

#[cfg(test)]
mod tests {
    use super::{
        Clock, ContextAvailability, CyberTimeline, EventFact, EventMoment, EventReference,
        ReviewFact, TimelineEntry, timeline_for,
    };
    use crate::model::cyber_event::CorrelationReason;
    use crate::model::indicator::IndicatorKind;
    use crate::model::observation_window::ObservationWindow;
    use crate::model::review::ReviewState;
    use crate::text::{Actor, RemoteMessageId};
    use crate::time::Timestamp;
    use crate::{ContentId, ContextSnapshotId, SessionId, SourceId};

    /// Il testo di questo modulo, per le guardie che guardano la forma del
    /// codice e non il suo esito.
    const THIS_MODULE: &str = include_str!("cyber_timeline.rs");

    const PUBBLICATO: i64 = 1_760_000_000_000;

    /// La parte di produzione di questo modulo, senza le prove.
    fn produzione() -> &'static str {
        let Some((codice, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        codice
    }

    fn attore(nome: &str) -> Actor {
        Actor::try_new(nome).expect("attore valido nelle prove")
    }

    fn remoto(valore: &str) -> RemoteMessageId {
        RemoteMessageId::try_new(valore).expect("identificativo remoto valido nelle prove")
    }

    fn ragione() -> CorrelationReason {
        CorrelationReason::SameIndicator {
            kind: IndicatorKind::Cve,
            value: String::from("CVE-2026-1234"),
        }
    }

    fn finestra() -> ObservationWindow {
        ObservationWindow {
            session: SessionId::new(9),
            from: Timestamp::from_millis(PUBBLICATO - 3_600_000),
            to: Some(Timestamp::from_millis(PUBBLICATO + 3_600_000)),
        }
    }

    fn fatto(content: i64, source: i64, quando: i64) -> EventFact {
        EventFact {
            content: ContentId::new(content),
            source: SourceId::new(source),
            remote_message_id: remoto(&format!("{content}00")),
            published_at: Timestamp::from_millis(quando),
            indicators: vec![(IndicatorKind::Cve, String::from("CVE-2026-1234"))],
            context: ContextAvailability::NeverTaken,
            reviews: Vec::new(),
        }
    }

    /// Quante righe di un dato genere ha la cronologia.
    fn quante(cronologia: &CyberTimeline, predicato: fn(&EventMoment) -> bool) -> usize {
        cronologia
            .entries()
            .iter()
            .filter(|riga| predicato(riga.moment()))
            .count()
    }

    /// Una cronologia con un contenuto revisionato e uno soltanto acquisito.
    fn cronologia_mista(stato: ReviewState) -> CyberTimeline {
        let mut primo = fatto(1, 10, PUBBLICATO);
        primo.reviews = vec![ReviewFact {
            state: stato,
            reviewer: attore("operatore"),
            at: Timestamp::from_millis(PUBBLICATO + 60_000),
        }];
        timeline_for(
            ragione(),
            &[primo, fatto(2, 11, PUBBLICATO + 1)],
            finestra(),
        )
    }

    // ------------------------------------------------------------------
    // La guardia centrale: due orologi, e nessuna riga che possa sbagliarlo.
    // ------------------------------------------------------------------

    /// **L'istante di una revisione non e' mai dichiarato da una fonte.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che una decisione presa in questo ufficio venga presentata come un
    /// istante che Telegram ha dichiarato. Chi legge una relazione ne
    /// dedurrebbe che quell'istante e' verificabile presso la piattaforma, e
    /// non lo e': e' l'orologio di una postazione, che nessuno ha confrontato
    /// con niente.
    ///
    /// # Il controllo negativo
    ///
    /// Portando `ReviewStarted` e `HumanDecision` nel primo braccio di
    /// `EventMoment::clock` - cioe' dichiarandoli «dichiarati dalla fonte» -
    /// questa prova diventa rossa.
    #[test]
    fn l_orologio_discende_dal_genere_del_fatto() {
        let dichiarati = [
            EventMoment::FirstObservation,
            EventMoment::CorrelationFormed {
                with: ContentId::new(1),
            },
            EventMoment::AdditionalSource,
            EventMoment::NewIndicator {
                kind: IndicatorKind::Domain,
                value: String::from("esempio.it"),
            },
        ];
        for momento in &dichiarati {
            assert_eq!(
                momento.clock(),
                Clock::DeclaredBySource,
                "un fatto sul contenuto porta l'istante che la fonte dichiara: {momento:?}"
            );
            assert!(
                !momento.is_human_act(),
                "{momento:?} non e' l'atto di una persona"
            );
        }

        let misurati = [
            EventMoment::ReviewStarted {
                reviewer: attore("operatore"),
            },
            EventMoment::HumanDecision {
                reviewer: attore("operatore"),
                state: ReviewState::Relevant,
            },
        ];
        for momento in &misurati {
            assert_eq!(
                momento.clock(),
                Clock::MeasuredHere,
                "un atto di una persona porta l'istante misurato qui: {momento:?}"
            );
            assert!(
                momento.is_human_act(),
                "{momento:?} e' l'atto di una persona"
            );
        }
    }

    /// **L'orologio non e' un campo che qualcuno compila.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che il giorno in cui qualcuno aggiunge un genere di riga possa anche
    /// scriverne l'orologio a mano, e scriverlo sbagliato. Finche' discende dal
    /// genere, un genere nuovo costringe a decidere dentro il `match`, sotto gli
    /// occhi di chi rivede.
    #[test]
    fn l_orologio_non_e_un_campo() {
        let codice = produzione();
        let Some(inizio) = codice.find("pub enum EventMoment {") else {
            panic!("l'enumerazione dei fatti deve esistere");
        };
        let Some(lunghezza) = codice[inizio..].find("\n}\n") else {
            panic!("l'enumerazione dei fatti deve chiudersi");
        };
        let enumerazione = &codice[inizio..inizio + lunghezza];

        assert!(
            !enumerazione.contains("Clock"),
            "nessuna variante deve poter dichiarare il proprio orologio: {enumerazione}"
        );
        assert!(
            codice.contains("pub const fn clock(&self) -> Clock {"),
            "l'orologio deve discendere dal genere del fatto"
        );
    }

    /// **La cronologia mescolata avverte che gli orologi sono due.**
    #[test]
    fn una_linea_che_mescola_i_due_orologi_lo_dichiara() {
        let avvertenza = cronologia_mista(ReviewState::Relevant).caveat();
        assert!(
            avvertenza.contains("due orologi diversi"),
            "una linea mescolata deve dirlo: {avvertenza}"
        );
        assert!(
            avvertenza.contains("non \u{e8} un dato osservato"),
            "deve dire che l'ordine fra i due orologi non e' osservato: {avvertenza}"
        );
    }

    /// **Una linea di un orologio solo non porta l'avvertenza sui due.**
    ///
    /// # Perche' e' una prova e non una dimenticanza
    ///
    /// Perche' una guardia che compare sempre e' una guardia che si impara a
    /// saltare, e chi la salta salta anche le volte in cui serviva. E' la stessa
    /// domanda che HVQ-41 pone su un'altra avvertenza.
    #[test]
    fn una_linea_di_un_solo_orologio_non_avverte_di_due() {
        let cronologia = timeline_for(
            ragione(),
            &[fatto(1, 10, PUBBLICATO), fatto(2, 11, PUBBLICATO + 1)],
            finestra(),
        );

        let avvertenza = cronologia.caveat();
        assert!(
            !avvertenza.contains("due orologi diversi"),
            "senza revisioni non c'e' alcuna mescolanza da avvertire: {avvertenza}"
        );
        assert!(
            avvertenza.contains("non significa che non sia successo niente"),
            "l'avvertenza sul vuoto resta comunque: {avvertenza}"
        );
    }

    /// **Le righe si possono guardare un orologio alla volta.**
    #[test]
    fn le_righe_si_separano_per_orologio() {
        let cronologia = cronologia_mista(ReviewState::InReview);

        let dichiarate = cronologia.entries_from(Clock::DeclaredBySource);
        let misurate = cronologia.entries_from(Clock::MeasuredHere);

        assert_eq!(
            misurate.len(),
            1,
            "una sola revisione, una sola riga misurata"
        );
        assert_eq!(
            dichiarate.len() + misurate.len(),
            cronologia.entries().len(),
            "ogni riga sta in uno dei due orologi, e in uno solo"
        );
        assert!(
            misurate
                .iter()
                .all(|riga| riga.clock() == Clock::MeasuredHere)
        );
    }

    /// **Ogni riga nomina il proprio orologio, anche estratta da sola.**
    #[test]
    fn ogni_riga_nomina_il_proprio_orologio() {
        let cronologia = cronologia_mista(ReviewState::Relevant);

        for riga in cronologia.entries() {
            let frase = riga.as_sentence();
            assert!(
                frase.contains(riga.clock().as_label()),
                "una riga citata da sola deve dire di quale orologio e': {frase}"
            );
        }
    }

    // ------------------------------------------------------------------
    // I rimandi.
    // ------------------------------------------------------------------

    /// **Ogni voce porta i propri rimandi.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che una riga di cronologia arrivi in un documento senza il modo di
    /// risalire al contenuto da cui viene. Una riga senza rimando e'
    /// un'affermazione che nessuno puo' verificare.
    #[test]
    fn ogni_voce_porta_i_propri_rimandi() {
        let cronologia = cronologia_mista(ReviewState::Relevant);

        assert!(!cronologia.entries().is_empty());
        for riga in cronologia.entries() {
            assert!(riga.reference().content().get() > 0);
            assert!(riga.reference().source().get() > 0);
            assert!(!riga.reference().remote_message_id().as_str().is_empty());
        }
    }

    /// **Una voce senza rimandi non e' costruibile.**
    ///
    /// # Il controllo negativo
    ///
    /// Rendendo pubblici i campi di `TimelineEntry`, o aggiungendo un
    /// costruttore che non voglia un `EventReference`, questa prova diventa
    /// rossa. E' la stessa forma di garanzia di PERS-03: la si verifica sulla
    /// forma del codice perche' sulla forma del codice riposa.
    #[test]
    fn una_voce_senza_rimandi_non_e_costruibile() {
        let codice = produzione();
        let Some(inizio) = codice.find("pub struct TimelineEntry {") else {
            panic!("la riga di cronologia deve esistere");
        };
        let Some(lunghezza) = codice[inizio..].find("\n}\n") else {
            panic!("la riga di cronologia deve chiudersi");
        };
        let campi = &codice[inizio..inizio + lunghezza];

        assert!(
            !campi.contains("pub at:")
                && !campi.contains("pub moment:")
                && !campi.contains("pub reference:"),
            "i campi di una riga restano privati: {campi}"
        );
        assert!(
            codice.contains(
                "pub const fn new(at: Timestamp, moment: EventMoment, reference: EventReference)"
            ),
            "l'unico costruttore di una riga deve volere i rimandi"
        );
        assert!(
            !codice.contains("impl Default for TimelineEntry"),
            "nessun valore predefinito puo' aggirare il costruttore"
        );
    }

    /// **Il rimando al messaggio originale non e' un indirizzo fabbricato.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che questa milestone rimetta in piedi la composizione locale dei
    /// collegamenti che LINK-01 ha tolto, e lo faccia dentro un documento che
    /// qualcuno consegna. Un indirizzo composto da noi e' una deduzione, non un
    /// fatto osservato.
    ///
    /// # Il controllo negativo
    ///
    /// Aggiungendo alla frase dei rimandi la composizione di un indirizzo di
    /// Telegram, questa prova diventa rossa.
    #[test]
    fn il_messaggio_originale_non_porta_un_indirizzo_fabbricato() {
        let codice = produzione();
        assert!(
            !codice.contains("t.me"),
            "il dominio non compone collegamenti a Telegram"
        );
        assert!(
            !codice.contains("tg://"),
            "il dominio non compone collegamenti all'applicazione Telegram"
        );

        let rimando = EventReference::new(
            ContentId::new(4),
            SourceId::new(7),
            remoto("400"),
            ContextAvailability::NeverTaken,
        );
        let frase = rimando.as_sentence();
        assert!(
            !frase.contains("http"),
            "nessun indirizzo nella frase: {frase}"
        );
        assert!(
            frase.contains("il collegamento lo fornisce Telegram al momento"),
            "la frase deve dire dove si prende il collegamento: {frase}"
        );
    }

    /// **«Nessuno ha fotografato» non e' «non c'era nulla attorno».**
    #[test]
    fn un_contesto_mai_fotografato_lo_dice_senza_dire_altro() {
        let mai = ContextAvailability::NeverTaken.as_sentence();
        assert!(mai.contains("nessuno ha fotografato"), "{mai}");
        assert!(
            mai.contains("Non significa che attorno non ci fosse nulla"),
            "{mai}"
        );

        let presa = ContextAvailability::Snapshot(ContextSnapshotId::new(3)).as_sentence();
        assert!(presa.contains("fotografia #3"), "{presa}");
        assert!(!presa.contains("nessuno ha fotografato"), "{presa}");
    }

    // ------------------------------------------------------------------
    // La composizione.
    // ------------------------------------------------------------------

    /// **La correlazione si forma una volta sola, al secondo contenuto.**
    #[test]
    fn la_correlazione_si_forma_una_volta_sola() {
        let cronologia = timeline_for(
            ragione(),
            &[
                fatto(1, 10, PUBBLICATO),
                fatto(2, 11, PUBBLICATO + 1),
                fatto(3, 12, PUBBLICATO + 2),
            ],
            finestra(),
        );

        assert_eq!(
            quante(&cronologia, |momento| matches!(
                momento,
                EventMoment::CorrelationFormed { .. }
            )),
            1,
            "il grappolo diventa grappolo una volta sola"
        );
    }

    /// **Il contenuto che forma la correlazione non e' anche «fonte aggiunta».**
    ///
    /// # Perche' conta
    ///
    /// Perche' due righe allo stesso istante che raccontano lo stesso arrivo
    /// sono l'elenco che nessuno scorre, e in mezzo al quale la riga che conta
    /// sparisce. E' la lezione di PERS-02.
    #[test]
    fn il_secondo_contenuto_non_produce_due_righe_per_lo_stesso_arrivo() {
        let cronologia = timeline_for(
            ragione(),
            &[fatto(1, 10, PUBBLICATO), fatto(2, 11, PUBBLICATO + 1)],
            finestra(),
        );

        assert_eq!(
            quante(&cronologia, |momento| matches!(
                momento,
                EventMoment::AdditionalSource
            )),
            0,
            "il secondo contenuto e' gia' raccontato dalla correlazione"
        );
    }

    /// **Una fonte gia' vista non produce una riga «fonte aggiuntiva».**
    #[test]
    fn la_stessa_fonte_non_torna_come_fonte_aggiuntiva() {
        let cronologia = timeline_for(
            ragione(),
            &[
                fatto(1, 10, PUBBLICATO),
                fatto(2, 11, PUBBLICATO + 1),
                fatto(3, 10, PUBBLICATO + 2),
                fatto(4, 12, PUBBLICATO + 3),
            ],
            finestra(),
        );

        assert_eq!(
            quante(&cronologia, |momento| matches!(
                momento,
                EventMoment::AdditionalSource
            )),
            1,
            "solo la fonte #12 non si era ancora vista"
        );
    }

    /// **L'indicatore che tiene insieme il grappolo non compare come «nuovo».**
    #[test]
    fn l_indicatore_della_ragione_non_e_un_indicatore_nuovo() {
        let mut primo = fatto(1, 10, PUBBLICATO);
        primo.indicators = vec![
            (IndicatorKind::Cve, String::from("CVE-2026-1234")),
            (IndicatorKind::Domain, String::from("esempio.it")),
        ];
        let cronologia = timeline_for(
            ragione(),
            &[primo, fatto(2, 11, PUBBLICATO + 1)],
            finestra(),
        );

        let nuovi: Vec<String> = cronologia
            .entries()
            .iter()
            .filter_map(|riga| match riga.moment() {
                EventMoment::NewIndicator { value, .. } => Some(value.clone()),
                _ => None,
            })
            .collect();

        assert_eq!(nuovi, vec![String::from("esempio.it")]);
    }

    /// **Uno stesso indicatore nuovo non si ripete a ogni contenuto.**
    #[test]
    fn un_indicatore_gia_visto_non_torna() {
        let mut primo = fatto(1, 10, PUBBLICATO);
        primo
            .indicators
            .push((IndicatorKind::Domain, String::from("esempio.it")));
        let mut secondo = fatto(2, 11, PUBBLICATO + 1);
        secondo
            .indicators
            .push((IndicatorKind::Domain, String::from("esempio.it")));

        let cronologia = timeline_for(ragione(), &[primo, secondo], finestra());
        assert_eq!(
            quante(&cronologia, |momento| matches!(
                momento,
                EventMoment::NewIndicator { .. }
            )),
            1,
            "un indicatore e' nuovo una volta sola"
        );
    }

    /// **«Da esaminare» non e' un atto, e non produce una riga.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che una cronologia dichiari che qualcuno ha fatto qualcosa quando
    /// nessuno ha fatto niente. `New` significa «non ancora esaminato», che e'
    /// quello che dice anche l'assenza di una revisione.
    #[test]
    fn una_revisione_mai_iniziata_non_produce_una_riga() {
        let cronologia = cronologia_mista(ReviewState::New);

        assert!(
            cronologia.entries_from(Clock::MeasuredHere).is_empty(),
            "nessun atto di una persona: nessuna riga misurata"
        );
    }

    /// **Presa in carico e decisione restano due righe diverse.**
    #[test]
    fn la_presa_in_carico_e_la_decisione_restano_distinte() {
        let mut primo = fatto(1, 10, PUBBLICATO);
        primo.reviews = vec![
            ReviewFact {
                state: ReviewState::Relevant,
                reviewer: attore("operatore"),
                at: Timestamp::from_millis(PUBBLICATO + 120_000),
            },
            ReviewFact {
                state: ReviewState::InReview,
                reviewer: attore("operatore"),
                at: Timestamp::from_millis(PUBBLICATO + 60_000),
            },
        ];
        let cronologia = timeline_for(
            ragione(),
            &[primo, fatto(2, 11, PUBBLICATO + 1)],
            finestra(),
        );

        let misurate = cronologia.entries_from(Clock::MeasuredHere);
        assert_eq!(misurate.len(), 2);
        assert!(matches!(
            misurate[0].moment(),
            EventMoment::ReviewStarted { .. }
        ));
        assert!(matches!(
            misurate[1].moment(),
            EventMoment::HumanDecision { .. }
        ));
    }

    /// **Due letture degli stessi fatti danno la stessa cronologia.**
    ///
    /// Un ordine che cambia rende impossibile confrontare due letture, e una
    /// cronologia che cambia ordine non e' una cronologia.
    #[test]
    fn l_ordine_e_ripetibile() {
        let uno = fatto(1, 10, PUBBLICATO);
        let due = fatto(2, 11, PUBBLICATO);
        let tre = fatto(3, 12, PUBBLICATO);

        let primo = timeline_for(
            ragione(),
            &[uno.clone(), due.clone(), tre.clone()],
            finestra(),
        );
        let secondo = timeline_for(ragione(), &[tre, due, uno], finestra());

        let frasi = |cronologia: &CyberTimeline| -> Vec<String> {
            cronologia
                .entries()
                .iter()
                .map(TimelineEntry::as_sentence)
                .collect()
        };
        assert_eq!(frasi(&primo), frasi(&secondo));
    }

    /// **La prima osservazione non dichiara di essere la prima in assoluto.**
    #[test]
    fn la_prima_osservazione_dice_di_essere_solo_la_prima_qui() {
        let cronologia = timeline_for(
            ragione(),
            &[fatto(1, 10, PUBBLICATO), fatto(2, 11, PUBBLICATO + 1)],
            finestra(),
        );

        let frase = cronologia.entries()[0].moment().as_sentence();
        assert!(
            frase.contains("Non \u{e8} la prima volta che di questo indicatore si \u{e8} parlato"),
            "{frase}"
        );
    }

    /// **Una cronologia porta sempre la propria finestra di osservazione.**
    #[test]
    fn una_cronologia_porta_sempre_la_sua_finestra() {
        let cronologia = timeline_for(
            ragione(),
            &[fatto(1, 10, PUBBLICATO), fatto(2, 11, PUBBLICATO + 1)],
            finestra(),
        );

        assert_eq!(cronologia.window().session, SessionId::new(9));
        assert!(
            cronologia
                .window()
                .as_sentence()
                .contains("Monitoraggio #9")
        );
        assert!(
            cronologia
                .caveat()
                .contains("non significa che non sia successo niente")
        );
    }

    /// **Nessun campo riassume la cronologia in un numero.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che un conteggio accanto a un grappolo diventi un punteggio. E' il
    /// confine che PERS-07 ha dichiarato, e che una fase successiva non e'
    /// autorizzata ad aprire.
    #[test]
    fn nessun_campo_riassume_la_cronologia_in_un_numero() {
        let codice = produzione();
        let Some(inizio) = codice.find("pub struct CyberTimeline {") else {
            panic!("la cronologia deve esistere");
        };
        let Some(lunghezza) = codice[inizio..].find("\n}\n") else {
            panic!("la cronologia deve chiudersi");
        };
        let campi = &codice[inizio..inizio + lunghezza];

        for tipo in [": usize", ": u8", ": u32", ": i64", ": f32", ": f64"] {
            assert!(
                !campi.contains(tipo),
                "la cronologia non porta alcun numero riassuntivo: trovato {tipo}"
            );
        }
        assert!(
            !codice.contains("fn score") && !codice.contains("fn rank("),
            "il dominio non calcola alcun punteggio"
        );
    }

    /// Una cronologia senza fatti non inventa righe, e continua a dire la sua
    /// finestra: e' il caso in cui l'avvertenza serve di piu'.
    #[test]
    fn una_cronologia_senza_fatti_non_inventa_righe() {
        let cronologia = timeline_for(ragione(), &[], finestra());
        assert!(cronologia.entries().is_empty());
        assert!(cronologia.caveat().contains("nessuno stava guardando"));
        assert!(!cronologia.caveat().contains("due orologi diversi"));
    }
}

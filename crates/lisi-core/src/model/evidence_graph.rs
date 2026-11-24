//! Il dominio dell'Evidence Graph (GRAPH-01).
//!
//! # Che cos'è, e che cosa non è
//!
//! È **ciò che risulta collegato a che cosa, e per quale fatto**. Ogni arco
//! nasce da qualcosa che sta già nell'archivio — questo contenuto viene da
//! quella fonte, questo contenuto nomina quell'indicatore, questa identità ha
//! scritto quel contenuto — oppure da qualcosa che **una persona ha deciso**, e
//! porta con sé quale delle due cose sia.
//!
//! Non è una rete di contatti, non è una mappa di relazioni fra persone, e non
//! contiene alcuna inferenza.
//!
//! # La cosa che nessuno vedrebbe da sé: un percorso è un'affermazione
//!
//! Questo è il primo punto del prodotto in cui **la composizione di fatti veri
//! produce un'impressione falsa**, e nessun singolo arco è sbagliato.
//!
//! L'identità A ha scritto un contenuto che nomina il dominio X. L'identità B ha
//! scritto un altro contenuto che nomina lo stesso dominio X. Ogni arco è un
//! fatto osservato, verificabile, con la sua provenienza. Ma disegnati insieme,
//! A e B **risultano collegate** — e in una relazione «risultano collegate»
//! diventa una frase che nessun fatto sostiene: A e B possono non essersi mai
//! incontrate, e il dominio X può essere un sito di notizie che cita mezzo mondo.
//!
//! Un grafo rende quell'affermazione **strutturale**: non la scrive nessuno, la
//! fa la figura.
//!
//! # Come il tipo lo impedisce: **non esistono percorsi**
//!
//! Questo modulo **non offre** e non deve offrire: ricerca di cammini,
//! raggiungibilità, chiusura transitiva, componenti connesse, «quanto distano A
//! e B», «A e B sono collegati?». Una prova sul testo del modulo lo verifica.
//!
//! Offre un **vicinato**: gli archi che partono da un nodo, ognuno con la sua
//! provenienza. Chi vuole andare oltre lo chiede di nuovo, e ogni passo mostra la
//! propria ragione. Non è una limitazione tecnica: è la differenza fra «da questo
//! contenuto si arriva a quel dominio, per questo fatto» e «A e B sono
//! collegate», che è ciò che il prodotto non ha titolo per dire.
//!
//! # Il vicinato dichiara il proprio taglio
//!
//! Un nodo con cinquecento vicini troncato in silenzio farebbe sembrare **rado**
//! ciò che è fitto — e in un grafo la radità si legge come isolamento, che è
//! un'affermazione su una persona. [`Neighbourhood`] porta quanti archi ha
//! lasciato fuori, e lo dice.
//!
//! # Un arco senza provenienza non è costruibile
//!
//! Il congelamento lo chiede con queste parole: «ogni arco ha una provenienza, e
//! **un arco senza provenienza non è costruibile**».
//!
//! «Non costruibile» non significa «rifiutato a tempo di esecuzione»: significa
//! che **non esiste la forma**. [`GraphEdge`] ha i campi privati e un solo
//! costruttore, che vuole una [`EdgeProvenance`]. Non c'è `Default`, non c'è un
//! campo pubblico da lasciare vuoto, non c'è un `Option` da passare `None`.
//!
//! È la stessa forma di garanzia di PERS-03 e di CYT-01: il compilatore, non una
//! convenzione.
//!
//! # Due provenienze, e non si confondono
//!
//! Un arco osservato dall'archivio e un arco **deciso da una persona** non sono
//! la stessa cosa, e il prodotto è costruito su quella differenza: il dato
//! originale, l'analisi deterministica e la valutazione dell'operatore restano
//! separati.
//!
//! [`EdgeProvenance`] ha due varianti, e la frase di ognuna dice quale sia. Un
//! solo tipo renderebbe indistinguibile un legame che qualcuno ha stabilito da un
//! fatto che l'archivio ha visto — che è esattamente ciò che, dentro una figura,
//! nessuno andrebbe a verificare.
//!
//! # Un soggetto non è un'identità osservata, nemmeno qui
//!
//! Il congelamento elenca fra i nodi la «Persona». Qui sono **due nodi diversi**:
//! [`GraphNode::ObservedIdentity`], che è un fatto della fonte, e
//! [`GraphNode::Subject`], che è un fascicolo che qualcuno ha aperto.
//!
//! Fonderli in un nodo solo disferebbe in una figura la distinzione su cui poggia
//! l'intera Fase 6 — e la disferebbe nel posto in cui è più difficile
//! accorgersene, perché un pallino con un nome sopra non dichiara che cosa sia.
//!
//! # Nessun numero
//!
//! Nessun nodo e nessun arco porta un campo numerico. Il grado di un nodo — di
//! quanti archi è capo — non è un campo: chi vuole saperlo conta le righe. Un
//! numero accanto a un pallino con un nome sopra diventa un punteggio, comunque
//! si chiami.

use crate::model::indicator::IndicatorKind;
use crate::model::reason::OperationalReason;
use crate::text::Actor;
use crate::time::Timestamp;
use crate::{ContentId, PersonId, SourceId};

/// Che cosa sta ai capi di un arco.
///
/// # Perché i generi sono questi
///
/// Sono quelli del congelamento — contenuto, fonte, persona, CyberEvent, CVE,
/// dominio, indirizzo, impronta — con due precisazioni che il congelamento non
/// poteva fare in una riga di tabella: gli indicatori tecnici stanno in un genere
/// solo, distinti dal loro [`IndicatorKind`], perché è così che l'archivio li
/// conserva; e la «persona» è **due nodi**, per la ragione scritta nella nota di
/// modulo.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum GraphNode {
    /// Un contenuto acquisito.
    Content(ContentId),
    /// Una fonte monitorata.
    Source(SourceId),
    /// Un'identità **osservata** presso la piattaforma.
    ///
    /// È un fatto della fonte: quel contenuto dichiarava quell'autore. **Non è
    /// un fascicolo**, e non lo diventa stando in un grafo.
    ObservedIdentity(String),
    /// Un **soggetto**: un fascicolo che qualcuno ha aperto.
    ///
    /// È un atto d'ufficio, non un'osservazione. L'unico arco che lo raggiunge è
    /// quello che una persona ha deciso (PERS-06).
    Subject(PersonId),
    /// Un grappolo di segnali, identificato dalla ragione che lo tiene insieme.
    ///
    /// # Perché la ragione e non un identificativo
    ///
    /// Perché un grappolo **non è una riga dell'archivio**: si ricava
    /// correlando i contenuti di un monitoraggio, e non ha un identificativo da
    /// citare. Inventargliene uno lo farebbe sembrare una cosa conservata.
    CyberEvent {
        /// Il genere dell'indicatore che lo tiene insieme.
        kind: IndicatorKind,
        /// Il valore normalizzato.
        value: String,
    },
    /// Un indicatore tecnico: CVE, dominio, indirizzo, impronta, indirizzo web.
    Indicator {
        /// Che genere.
        kind: IndicatorKind,
        /// Il valore **normalizzato**, che è la forma su cui il prodotto correla.
        value: String,
    },
}

impl GraphNode {
    /// Come si nomina il genere di nodo.
    #[must_use]
    pub const fn kind_label(&self) -> &'static str {
        match self {
            Self::Content(_) => "Contenuto",
            Self::Source(_) => "Fonte",
            Self::ObservedIdentity(_) => "Identità osservata",
            Self::Subject(_) => "Soggetto",
            Self::CyberEvent { .. } => "Gruppo di segnali",
            Self::Indicator { .. } => "Indicatore",
        }
    }

    /// Il nodo, detto a chi legge.
    ///
    /// # Perché l'identità osservata dichiara che cosa non è
    ///
    /// Perché in una figura un pallino con un nome sopra non dice che cosa sia,
    /// e un'identità osservata accanto a un fascicolo si legge come la stessa
    /// cosa. La frase lo separa.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self {
            Self::Content(id) => format!("Contenuto #{}", id.get()),
            Self::Source(id) => format!("Fonte #{}", id.get()),
            Self::ObservedIdentity(identifier) => format!(
                "Identit\u{e0} osservata {identifier} \u{2014} \u{e8} ci\u{f2} che la fonte ha \
                 dichiarato, non un fascicolo."
            ),
            Self::Subject(id) => format!(
                "Soggetto #{} \u{2014} un fascicolo che qualcuno ha aperto, non \
                 un'osservazione.",
                id.get()
            ),
            Self::CyberEvent { kind, value } => format!(
                "Gruppo di segnali che nominano {} \u{ab}{value}\u{bb}",
                kind.label()
            ),
            Self::Indicator { kind, value } => {
                format!("{} \u{ab}{value}\u{bb}", kind.label())
            }
        }
    }
}

/// Per quale fatto due nodi risultano collegati.
///
/// # Perché un'enumerazione chiusa
///
/// Per la ragione di PERS-03: l'insieme delle ragioni per cui questo prodotto
/// collega qualcosa a qualcos'altro deve essere **leggibile per intero in una
/// schermata**, e deve poter essere discusso. Una regola che si aggiunge è una
/// decisione, non un dettaglio: passa da qui, e si vede.
///
/// Non c'è, e non deve esserci, una variante «somiglia a», «probabilmente»,
/// «vicino a».
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EdgeRule {
    /// Un'identità osservata ha scritto un contenuto.
    IdentityAuthoredContent,
    /// Un contenuto proviene da una fonte.
    ContentFromSource,
    /// Un contenuto nomina un indicatore.
    ContentCarriesIndicator,
    /// Un gruppo di segnali raccoglie un contenuto.
    EventGroupsContent,
    /// Un gruppo di segnali è tenuto insieme da un indicatore.
    EventTurnsOnIndicator,
    /// **Una persona ha collegato** un'identità osservata a un soggetto.
    ///
    /// È l'unica regola che non descrive un'osservazione: descrive **un atto**
    /// (PERS-06). La sua provenienza è [`EdgeProvenance::DecidedByAPerson`], e
    /// non può essere l'altra.
    PersonLinkedIdentityToSubject,
}

impl EdgeRule {
    /// Etichetta stabile, quella che non cambia con le parole dell'interfaccia.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IdentityAuthoredContent => "identita_ha_scritto_contenuto",
            Self::ContentFromSource => "contenuto_dalla_fonte",
            Self::ContentCarriesIndicator => "contenuto_porta_indicatore",
            Self::EventGroupsContent => "gruppo_raccoglie_contenuto",
            Self::EventTurnsOnIndicator => "gruppo_verte_su_indicatore",
            Self::PersonLinkedIdentityToSubject => "persona_ha_collegato_identita",
        }
    }

    /// Il fatto, detto a chi legge: **la risposta a «perché sono collegati?»**.
    ///
    /// # Che cosa nessuna di queste frasi dice
    ///
    /// Nessuna dice che qualcuno **sia** qualcosa, che due persone si conoscano,
    /// o che un collegamento significhi qualcosa. Dicono quale fatto mette quei
    /// due nodi ai capi di quell'arco.
    #[must_use]
    pub const fn as_sentence(self) -> &'static str {
        match self {
            Self::IdentityAuthoredContent => {
                "La fonte dichiara che questa identit\u{e0} ha scritto questo contenuto."
            }
            Self::ContentFromSource => "Questo contenuto \u{e8} stato acquisito da questa fonte.",
            Self::ContentCarriesIndicator => "Il testo di questo contenuto nomina questo valore.",
            Self::EventGroupsContent => {
                "Questo contenuto sta in questo gruppo perch\u{e9} nomina l'indicatore che lo \
                 tiene insieme."
            }
            Self::EventTurnsOnIndicator => {
                "\u{c8} l'indicatore che tiene insieme questo gruppo: \u{e8} la ragione per cui \
                 il gruppo esiste."
            }
            Self::PersonLinkedIdentityToSubject => {
                "Una persona ha collegato questa identit\u{e0} a questo fascicolo. Non lo ha \
                 trovato il programma."
            }
        }
    }

    /// Se la regola descrive un **atto** invece di un'osservazione.
    #[must_use]
    pub const fn is_a_human_act(self) -> bool {
        matches!(self, Self::PersonLinkedIdentityToSubject)
    }
}

/// Da dove viene un arco: **osservato**, oppure **deciso da una persona**.
///
/// # Perché due varianti e non un tipo solo
///
/// Perché sono due cose diverse, e il prodotto è costruito su quella differenza.
/// Un solo tipo renderebbe indistinguibile, dentro una figura, un legame che
/// qualcuno ha stabilito da un fatto che l'archivio ha visto — e in una figura
/// nessuno va a verificare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeProvenance {
    /// L'archivio lo ha osservato in un contenuto.
    Observed {
        /// Quale contenuto stabilisce il fatto.
        content: ContentId,
        /// Da quale fonte quel contenuto proviene.
        source: SourceId,
        /// Quando quel contenuto è stato **pubblicato**, secondo la fonte.
        ///
        /// Non è l'istante in cui l'arco è stato costruito: nessuno lo ha
        /// costruito, si ricava. È la distinzione di PERS-03, e l'orologio è
        /// quello di CYT-01: **lo dichiara la fonte**.
        at: Timestamp,
    },
    /// Una persona lo ha deciso, e ha detto perché.
    DecidedByAPerson {
        /// Chi.
        by: Actor,
        /// Quando, **misurato da questo programma**.
        at: Timestamp,
        /// Perché.
        reason: OperationalReason,
    },
}

impl EdgeProvenance {
    /// Se l'arco è l'atto di una persona.
    #[must_use]
    pub const fn is_a_human_act(&self) -> bool {
        matches!(self, Self::DecidedByAPerson { .. })
    }

    /// Da dove viene, detto a chi legge.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self {
            Self::Observed {
                content,
                source,
                at,
            } => format!(
                "Osservato nel contenuto #{}, dalla fonte #{}, pubblicato il {} \u{2014} istante \
                 dichiarato dalla fonte.",
                content.get(),
                source.get(),
                at.to_readable_utc()
            ),
            Self::DecidedByAPerson { by, at, reason } => format!(
                "Deciso da {} il {} \u{2014} istante misurato da questo programma. Motivo: {}",
                by.as_str(),
                at.to_readable_utc(),
                reason.as_str()
            ),
        }
    }
}

/// Un arco del grafo, **con la sua provenienza**.
///
/// I campi sono privati e il costruttore è uno solo: vedere la nota di modulo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphEdge {
    /// Da dove parte.
    from: GraphNode,
    /// Dove arriva.
    to: GraphNode,
    /// Per quale fatto.
    rule: EdgeRule,
    /// Da dove viene il fatto.
    provenance: EdgeProvenance,
}

impl GraphEdge {
    /// Un arco, che **richiede** la propria provenienza.
    ///
    /// # Perché non ci sono varianti con meno argomenti
    ///
    /// Perché una comodità che ne omettesse una sarebbe la strada per cui un arco
    /// senza provenienza entra in una figura, e in una figura nessuno se ne
    /// accorge.
    #[must_use]
    pub const fn new(
        from: GraphNode,
        to: GraphNode,
        rule: EdgeRule,
        provenance: EdgeProvenance,
    ) -> Self {
        Self {
            from,
            to,
            rule,
            provenance,
        }
    }

    /// Da dove parte.
    #[must_use]
    pub const fn from(&self) -> &GraphNode {
        &self.from
    }

    /// Dove arriva.
    #[must_use]
    pub const fn to(&self) -> &GraphNode {
        &self.to
    }

    /// Per quale fatto.
    #[must_use]
    pub const fn rule(&self) -> EdgeRule {
        self.rule
    }

    /// Da dove viene il fatto.
    #[must_use]
    pub const fn provenance(&self) -> &EdgeProvenance {
        &self.provenance
    }

    /// **Perché sono collegati?**, la domanda che GRAPH-02 mette sullo schermo.
    ///
    /// La risposta è sempre due frasi: il fatto, e da dove viene. Nessuna delle
    /// due dice che il collegamento significhi qualcosa.
    #[must_use]
    pub fn why(&self) -> String {
        format!(
            "{} \u{2192} {}. {} {}",
            self.from.as_sentence(),
            self.to.as_sentence(),
            self.rule.as_sentence(),
            self.provenance.as_sentence()
        )
    }
}

/// Gli archi che partono da un nodo, **con quanto è rimasto fuori**.
///
/// # Perché il taglio è parte del risultato e non un contorno
///
/// Perché un nodo con cinquecento vicini troncato in silenzio farebbe sembrare
/// **rado** ciò che è fitto, e in un grafo la radità si legge come isolamento —
/// che è un'affermazione su una persona, non un fatto misurato.
///
/// Il campo è privato e il costruttore lo vuole: non c'è modo di comporre un
/// vicinato che ometta di dire quanto ha lasciato fuori.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbourhood {
    /// Di quale nodo.
    node: GraphNode,
    /// Gli archi che partono da lì, in ordine stabile.
    edges: Vec<GraphEdge>,
    /// Quanti archi sono stati lasciati fuori dal tetto.
    omitted: usize,
}

impl Neighbourhood {
    /// Un vicinato, che **richiede** di dire quanto ha lasciato fuori.
    #[must_use]
    pub const fn new(node: GraphNode, edges: Vec<GraphEdge>, omitted: usize) -> Self {
        Self {
            node,
            edges,
            omitted,
        }
    }

    /// Di quale nodo.
    #[must_use]
    pub const fn node(&self) -> &GraphNode {
        &self.node
    }

    /// Gli archi che partono da lì.
    #[must_use]
    pub fn edges(&self) -> &[GraphEdge] {
        &self.edges
    }

    /// Quanti archi sono rimasti fuori.
    #[must_use]
    pub const fn omitted(&self) -> usize {
        self.omitted
    }

    /// Che cosa questo vicinato dice, e che cosa non dice.
    ///
    /// # Perché l'avvertenza sul percorso compare sempre
    ///
    /// Perché non dipende da quanti archi ci sono: la tentazione di leggere una
    /// figura come una rete di relazioni c'è **anche con tre archi**, e chi guarda
    /// il vicinato di un'identità osservata sta già componendo la frase.
    #[must_use]
    pub fn caveat(&self) -> String {
        let mut testo = String::from(
            "Ogni collegamento dice per quale fatto esiste e da dove viene quel fatto. Due \
             elementi collegati attraverso un terzo non hanno per questo a che fare l'uno con \
             l'altro. Due persone che nominano lo stesso dominio possono non essersi mai \
             incontrate.",
        );

        if self.omitted > 0 {
            testo.push_str(&format!(
                " Non \u{e8} tutto: {} archi non sono elencati. Ci\u{f2} che si vede \u{e8} \
                 pi\u{f9} rado di ci\u{f2} che c'\u{e8}.",
                self.omitted
            ));
        }

        testo
    }
}

/// I fatti di un contenuto, da cui si ricavano i suoi archi.
///
/// # Perché senza il corpo del messaggio
///
/// Per la ragione di PERS-02, PERS-03, PERS-04 e CYT-01: alla derivazione non
/// serve il testo, e **una funzione che non riceve una cosa non può usarla**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentFacts {
    /// Quale contenuto.
    pub content: ContentId,
    /// Da quale fonte proviene.
    pub source: SourceId,
    /// Quando la fonte dichiara che è stato pubblicato.
    pub at: Timestamp,
    /// Chi lo ha scritto presso la piattaforma, quando la fonte lo dichiara.
    ///
    /// # Perché è opzionale
    ///
    /// Perché **i messaggi di canale non hanno un autore individuale**.
    /// Attribuirli a qualcuno significherebbe attribuire a una persona ciò che
    /// una persona non ha scritto: è la scelta di PERS-02, e in un grafo
    /// costerebbe di più, perché un arco disegnato non si rilegge.
    pub identifier: Option<String>,
    /// Gli indicatori che il contenuto nomina.
    pub indicators: Vec<(IndicatorKind, String)>,
}

/// Un legame deciso da una persona, da cui si ricava il suo arco.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkFacts {
    /// Quale soggetto.
    pub person: PersonId,
    /// Quale identità osservata.
    pub identifier: String,
    /// Chi lo ha deciso.
    pub by: Actor,
    /// Quando.
    pub at: Timestamp,
    /// Perché.
    pub reason: OperationalReason,
}

/// La ragione di un grappolo, da cui si ricavano i suoi archi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventFacts {
    /// Il genere dell'indicatore che lo tiene insieme.
    pub kind: IndicatorKind,
    /// Il valore normalizzato.
    pub value: String,
    /// I contenuti che raccoglie, con la loro provenienza.
    pub members: Vec<(ContentId, SourceId, Timestamp)>,
}

/// L'ordine stabile di un arco, per non farlo dipendere dalla lettura.
///
/// Due letture dello stesso archivio devono dare lo stesso vicinato: un ordine
/// che cambia rende impossibile confrontare due figure, e due figure diverse
/// della stessa cosa sono due figure di cui una mente.
fn chiave(edge: &GraphEdge) -> (String, &'static str, String) {
    (
        edge.to().kind_label().to_owned(),
        edge.rule().as_str(),
        edge.to().as_sentence(),
    )
}

/// Gli archi che un contenuto stabilisce.
///
/// Ognuno porta la provenienza **osservata**: quale contenuto, quale fonte,
/// quale istante dichiarato dalla fonte.
#[must_use]
pub fn edges_of_content(facts: &ContentFacts) -> Vec<GraphEdge> {
    let provenienza = || EdgeProvenance::Observed {
        content: facts.content,
        source: facts.source,
        at: facts.at,
    };

    let mut archi = vec![GraphEdge::new(
        GraphNode::Content(facts.content),
        GraphNode::Source(facts.source),
        EdgeRule::ContentFromSource,
        provenienza(),
    )];

    // UN MESSAGGIO DI CANALE NON HA UN AUTORE INDIVIDUALE, e senza autore non
    // si disegna un arco verso nessuno.
    if let Some(identifier) = &facts.identifier {
        archi.push(GraphEdge::new(
            GraphNode::ObservedIdentity(identifier.clone()),
            GraphNode::Content(facts.content),
            EdgeRule::IdentityAuthoredContent,
            provenienza(),
        ));
    }

    for (kind, value) in &facts.indicators {
        archi.push(GraphEdge::new(
            GraphNode::Content(facts.content),
            GraphNode::Indicator {
                kind: *kind,
                value: value.clone(),
            },
            EdgeRule::ContentCarriesIndicator,
            provenienza(),
        ));
    }

    archi
}

/// L'arco che un legame deciso da una persona stabilisce.
///
/// # Perché uno solo, e perché è l'unico che raggiunge un soggetto
///
/// Perché è l'unico modo lecito di arrivare a un fascicolo: PERS-02, PERS-03,
/// PERS-04 e PERS-05 hanno rifiutato quattro volte di collegarvi qualcosa da sé,
/// e le loro guardie restano dove sono. Qui il collegamento c'è **perché
/// qualcuno lo ha deciso**, e la provenienza lo dice.
#[must_use]
pub fn edge_of_link(facts: &LinkFacts) -> GraphEdge {
    GraphEdge::new(
        GraphNode::Subject(facts.person),
        GraphNode::ObservedIdentity(facts.identifier.clone()),
        EdgeRule::PersonLinkedIdentityToSubject,
        EdgeProvenance::DecidedByAPerson {
            by: facts.by.clone(),
            at: facts.at,
            reason: facts.reason.clone(),
        },
    )
}

/// Gli archi che un grappolo di segnali stabilisce.
#[must_use]
pub fn edges_of_event(facts: &EventFacts) -> Vec<GraphEdge> {
    let gruppo = || GraphNode::CyberEvent {
        kind: facts.kind,
        value: facts.value.clone(),
    };

    let mut archi = Vec::with_capacity(facts.members.len() + 1);

    for (content, source, at) in &facts.members {
        archi.push(GraphEdge::new(
            gruppo(),
            GraphNode::Content(*content),
            EdgeRule::EventGroupsContent,
            EdgeProvenance::Observed {
                content: *content,
                source: *source,
                at: *at,
            },
        ));
    }

    // L'ARCO VERSO L'INDICATORE che tiene insieme il gruppo.
    //
    // La sua provenienza e' il membro PIU' ANTICO: e' il contenuto da cui quel
    // gruppo ha cominciato a esistere, e sceglierne un altro renderebbe la
    // provenienza dipendente dall'ordine di lettura. Senza membri l'arco non si
    // costruisce: non ci sarebbe nulla che lo osservi.
    if let Some((content, source, at)) = facts
        .members
        .iter()
        .min_by(|a, b| a.2.cmp(&b.2).then(a.0.get().cmp(&b.0.get())))
    {
        archi.push(GraphEdge::new(
            gruppo(),
            GraphNode::Indicator {
                kind: facts.kind,
                value: facts.value.clone(),
            },
            EdgeRule::EventTurnsOnIndicator,
            EdgeProvenance::Observed {
                content: *content,
                source: *source,
                at: *at,
            },
        ));
    }

    archi
}

/// Il vicinato di un nodo: **gli archi che lo toccano, e nient'altro**.
///
/// # Perché prende gli archi già costruiti invece di esplorare
///
/// Perché esplorare significherebbe seguire i collegamenti, e seguire i
/// collegamenti è il primo passo verso un percorso — che è l'affermazione che
/// questo modulo non fa (vedere la nota di modulo). Qui si filtra un insieme di
/// archi che qualcun altro ha già ricavato dai fatti.
///
/// # Il tetto
///
/// Chi guarda un vicinato vuole vederne la forma, non caricarne l'archivio. Ciò
/// che resta fuori **si dichiara**, e il vicinato lo porta con sé.
#[must_use]
pub fn neighbourhood_of(node: &GraphNode, edges: &[GraphEdge], limit: usize) -> Neighbourhood {
    let mut toccanti: Vec<GraphEdge> = edges
        .iter()
        .filter(|edge| edge.from() == node || edge.to() == node)
        .cloned()
        .collect();

    // ORDINE STABILE, prima del taglio: tagliare un elenco disordinato
    // significherebbe mostrare vicini diversi a ogni lettura.
    toccanti.sort_by(|a, b| chiave(a).cmp(&chiave(b)));
    toccanti.dedup();

    let totali = toccanti.len();
    toccanti.truncate(limit);
    let omessi = totali - toccanti.len();

    Neighbourhood::new(node.clone(), toccanti, omessi)
}

#[cfg(test)]
mod tests {
    use super::{
        ContentFacts, EdgeProvenance, EdgeRule, EventFacts, GraphEdge, GraphNode, LinkFacts,
        Neighbourhood, edge_of_link, edges_of_content, edges_of_event, neighbourhood_of,
    };
    use crate::model::indicator::IndicatorKind;
    use crate::model::reason::OperationalReason;
    use crate::text::Actor;
    use crate::time::Timestamp;
    use crate::{ContentId, PersonId, SourceId};

    /// Il testo di questo modulo, per le guardie che guardano la forma del
    /// codice e non il suo esito.
    const THIS_MODULE: &str = include_str!("evidence_graph.rs");

    const ORA: Timestamp = Timestamp::from_millis(1_760_000_000_000);

    /// La parte di produzione di questo modulo, senza le prove.
    fn produzione() -> &'static str {
        let Some((codice, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        codice
    }

    /// La produzione **senza i commenti**: il codice, non la prosa.
    ///
    /// # Perché serve
    ///
    /// Perché le guardie di vocabolario vietano al codice di nominare certe
    /// cose, e la nota di modulo deve poter spiegare **quali** e **perché**. Un
    /// controllo che leggesse anche i commenti obbligherebbe a tacere proprio la
    /// ragione della guardia — e una guardia senza ragione scritta è una guardia
    /// che il primo che ha fretta toglie.
    fn codice_senza_commenti() -> String {
        produzione()
            .lines()
            .filter(|riga| {
                let pulita = riga.trim_start();
                !pulita.starts_with("//")
            })
            .collect::<Vec<&str>>()
            .join("\n")
    }

    fn attore(nome: &str) -> Actor {
        Actor::try_new(nome).expect("attore valido nelle prove")
    }

    fn motivo() -> OperationalReason {
        OperationalReason::try_new("riscontro verificato sul documento acquisito agli atti")
            .expect("motivo valido nelle prove")
    }

    fn contenuto(content: i64, identifier: Option<&str>) -> ContentFacts {
        ContentFacts {
            content: ContentId::new(content),
            source: SourceId::new(7),
            at: ORA,
            identifier: identifier.map(str::to_owned),
            indicators: vec![(IndicatorKind::Domain, String::from("esempio.it"))],
        }
    }

    // ------------------------------------------------------------------
    // La guardia centrale: un percorso è un'affermazione, e non si calcola.
    // ------------------------------------------------------------------

    /// **Il grafo non sa dire se due nodi sono collegati.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che qualcuno chieda al programma «A e B sono collegati?» e riceva un sì.
    /// Ogni arco puo' essere vero e la risposta essere falsa: due persone che
    /// nominano lo stesso dominio possono non essersi mai incontrate, e un
    /// percorso fra loro non e' un fatto che qualcuno abbia osservato.
    ///
    /// E' l'unico punto del prodotto in cui **la composizione di fatti veri
    /// produce un'affermazione falsa**, e non c'e' un arco da correggere.
    ///
    /// # Il controllo negativo
    ///
    /// Aggiungendo al modulo una funzione che cerchi un cammino fra due nodi —
    /// comunque si chiami — questa prova diventa rossa.
    #[test]
    fn il_grafo_non_calcola_percorsi() {
        let codice = codice_senza_commenti().to_lowercase();

        for vietata in [
            "fn path",
            "fn shortest",
            "fn reachab",
            "fn transitive",
            "fn closure",
            "fn connected_",
            "fn components",
            "fn traverse",
            "fn walk",
            "fn bfs",
            "fn dfs",
            "fn distance",
            "fn hops",
            "fn are_connected",
            "fn is_linked_to",
        ] {
            assert!(
                !codice.contains(vietata),
                "il dominio non deve poter rispondere a «A e B sono collegati?»: trovato \
                 «{vietata}»"
            );
        }
    }

    /// **L'avvertenza sul percorso c'è, e non dipende da quanti archi ci sono.**
    ///
    /// Con tre archi la tentazione di leggere la figura come una rete c'e' gia',
    /// e chi guarda il vicinato di un'identita' sta gia' componendo la frase.
    #[test]
    fn il_vicinato_avverte_sempre_che_un_percorso_non_e_un_fatto() {
        let archi = edges_of_content(&contenuto(1, Some("111")));
        let vicinato = neighbourhood_of(&GraphNode::Content(ContentId::new(1)), &archi, 50);

        let avvertenza = vicinato.caveat();
        assert!(
            avvertenza.contains("non hanno per questo a che fare l'uno con l'altro"),
            "{avvertenza}"
        );
        assert!(
            avvertenza.contains("possono non essersi mai incontrate"),
            "{avvertenza}"
        );
    }

    /// **Un vicinato tagliato dichiara che non è tutto.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che una figura faccia sembrare rado cio' che e' fitto. In un grafo la
    /// radita' si legge come isolamento, e l'isolamento di una persona e'
    /// un'affermazione, non un fatto misurato.
    #[test]
    fn un_vicinato_tagliato_dichiara_quanto_ha_lasciato_fuori() {
        let mut fatti = contenuto(1, Some("111"));
        fatti.indicators = (0..10)
            .map(|i| (IndicatorKind::Domain, format!("esempio{i}.it")))
            .collect();
        let archi = edges_of_content(&fatti);

        let vicinato = neighbourhood_of(&GraphNode::Content(ContentId::new(1)), &archi, 4);

        assert_eq!(vicinato.edges().len(), 4);
        assert!(vicinato.omitted() > 0);
        assert!(
            vicinato.caveat().contains("Non \u{e8} tutto"),
            "{}",
            vicinato.caveat()
        );
        assert!(
            vicinato
                .caveat()
                .contains("pi\u{f9} rado di ci\u{f2} che c'\u{e8}"),
            "{}",
            vicinato.caveat()
        );
    }

    /// **Un vicinato completo non dichiara un taglio che non c'è.**
    #[test]
    fn un_vicinato_completo_non_dichiara_un_taglio() {
        let archi = edges_of_content(&contenuto(1, Some("111")));
        let vicinato = neighbourhood_of(&GraphNode::Content(ContentId::new(1)), &archi, 50);

        assert_eq!(vicinato.omitted(), 0);
        assert!(!vicinato.caveat().contains("Non \u{e8} tutto"));
    }

    // ------------------------------------------------------------------
    // La provenienza.
    // ------------------------------------------------------------------

    /// **Un arco senza provenienza non è costruibile.**
    ///
    /// # Il controllo negativo
    ///
    /// Rendendo pubblici i campi di `GraphEdge`, o aggiungendo un costruttore
    /// che non voglia una `EdgeProvenance`, questa prova diventa rossa. E' la
    /// stessa forma di garanzia di PERS-03 e di CYT-01.
    #[test]
    fn un_arco_senza_provenienza_non_e_costruibile() {
        let codice = produzione();
        let Some(inizio) = codice.find("pub struct GraphEdge {") else {
            panic!("l'arco deve esistere");
        };
        let Some(lunghezza) = codice[inizio..].find("\n}\n") else {
            panic!("l'arco deve chiudersi");
        };
        let campi = &codice[inizio..inizio + lunghezza];

        assert!(
            !campi.contains("pub from:")
                && !campi.contains("pub to:")
                && !campi.contains("pub rule:")
                && !campi.contains("pub provenance:"),
            "i campi di un arco restano privati: {campi}"
        );
        assert!(
            campi.contains("provenance: EdgeProvenance,")
                && !campi.contains("Option<EdgeProvenance>"),
            "la provenienza non e' opzionale: {campi}"
        );
        assert!(
            codice.contains("provenance: EdgeProvenance,\n    ) -> Self {"),
            "l'unico costruttore di un arco deve volere la provenienza"
        );
        assert!(
            !codice.contains("impl Default for GraphEdge"),
            "nessun valore predefinito puo' aggirare il costruttore"
        );
    }

    /// **Ogni arco che si ricava dai fatti porta la sua provenienza.**
    #[test]
    fn ogni_arco_ricavato_porta_la_sua_provenienza() {
        let archi = edges_of_content(&contenuto(1, Some("111")));
        assert!(!archi.is_empty());

        for arco in &archi {
            let EdgeProvenance::Observed {
                content, source, ..
            } = arco.provenance()
            else {
                panic!("un arco ricavato da un contenuto e' osservato, non deciso");
            };
            assert_eq!(*content, ContentId::new(1));
            assert_eq!(*source, SourceId::new(7));
        }
    }

    /// **Un arco osservato e un arco deciso da una persona non si confondono.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che dentro una figura un legame che qualcuno ha stabilito sia
    /// indistinguibile da un fatto che l'archivio ha visto. In una figura
    /// nessuno va a verificare, e la differenza fra le due cose e' quella su cui
    /// il prodotto e' costruito.
    ///
    /// # Il controllo negativo
    ///
    /// Facendo dire alla frase della provenienza decisa le stesse parole di
    /// quella osservata, questa prova diventa rossa.
    #[test]
    fn un_arco_deciso_da_una_persona_lo_dichiara() {
        let legame = LinkFacts {
            person: PersonId::new(3),
            identifier: String::from("111"),
            by: attore("operatore.prova"),
            at: ORA,
            reason: motivo(),
        };
        let arco = edge_of_link(&legame);

        assert!(arco.provenance().is_a_human_act());
        assert!(arco.rule().is_a_human_act());

        let perche = arco.why();
        assert!(
            perche.contains("Una persona ha collegato"),
            "la regola deve dire che e' un atto: {perche}"
        );
        assert!(
            perche.contains("Non lo ha trovato il programma"),
            "la frase deve negare che sia un risultato del programma: {perche}"
        );
        assert!(
            perche.contains("Deciso da operatore.prova"),
            "la provenienza deve nominare chi ha deciso: {perche}"
        );
        assert!(
            !perche.contains("Osservato nel contenuto"),
            "un atto non si presenta come un'osservazione: {perche}"
        );
    }

    /// **Un arco osservato non si presenta come una decisione.**
    #[test]
    fn un_arco_osservato_non_si_presenta_come_una_decisione() {
        let archi = edges_of_content(&contenuto(1, Some("111")));

        for arco in &archi {
            assert!(!arco.provenance().is_a_human_act());
            assert!(!arco.rule().is_a_human_act());
            let perche = arco.why();
            assert!(perche.contains("Osservato nel contenuto"), "{perche}");
            assert!(!perche.contains("Deciso da"), "{perche}");
        }
    }

    // ------------------------------------------------------------------
    // I nodi.
    // ------------------------------------------------------------------

    /// **Un soggetto non è un'identità osservata, nemmeno in un grafo.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che la distinzione su cui poggia l'intera Fase 6 si disfi in una figura,
    /// dove un pallino con un nome sopra non dichiara che cosa sia.
    #[test]
    fn un_soggetto_e_un_identita_osservata_sono_due_nodi_diversi() {
        let soggetto = GraphNode::Subject(PersonId::new(3));
        let identita = GraphNode::ObservedIdentity(String::from("111"));

        assert_ne!(soggetto.kind_label(), identita.kind_label());
        assert!(
            soggetto.as_sentence().contains("non un'osservazione"),
            "{}",
            soggetto.as_sentence()
        );
        assert!(
            identita.as_sentence().contains("non un fascicolo"),
            "{}",
            identita.as_sentence()
        );
    }

    /// **Solo un atto umano raggiunge un soggetto.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che il grafo riapra dalla finestra la porta che PERS-02, PERS-03,
    /// PERS-04 e PERS-05 hanno tenuto chiusa quattro volte. Le loro guardie
    /// restano dove sono; questa e' la loro in un posto nuovo.
    #[test]
    fn nessun_arco_osservato_raggiunge_un_soggetto() {
        let mut archi = edges_of_content(&contenuto(1, Some("111")));
        archi.extend(edges_of_event(&EventFacts {
            kind: IndicatorKind::Cve,
            value: String::from("CVE-2026-1234"),
            members: vec![(ContentId::new(1), SourceId::new(7), ORA)],
        }));

        for arco in &archi {
            assert!(
                !matches!(arco.from(), GraphNode::Subject(_))
                    && !matches!(arco.to(), GraphNode::Subject(_)),
                "un arco osservato non tocca un fascicolo: {}",
                arco.why()
            );
        }
    }

    /// **Un messaggio di canale non produce un arco verso un autore.**
    ///
    /// Attribuirlo a qualcuno significherebbe attribuire a una persona cio' che
    /// una persona non ha scritto, e in un grafo un arco disegnato non si
    /// rilegge.
    #[test]
    fn un_contenuto_senza_autore_non_produce_un_arco_di_autore() {
        let archi = edges_of_content(&contenuto(1, None));

        assert!(
            !archi
                .iter()
                .any(|arco| arco.rule() == EdgeRule::IdentityAuthoredContent),
            "senza autore dichiarato non si disegna un arco verso nessuno"
        );
        assert!(
            archi
                .iter()
                .any(|arco| arco.rule() == EdgeRule::ContentFromSource),
            "gli altri archi restano"
        );
    }

    /// **Nessuna regola descrive una somiglianza.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che il grafo introduca l'inferenza che il congelamento vieta, e la
    /// introduca nel posto in cui e' piu' persuasiva: un arco disegnato fra due
    /// nomi somiglianti.
    #[test]
    fn nessuna_regola_descrive_una_somiglianza() {
        let codice = codice_senza_commenti().to_lowercase();

        for vietata in [
            "similar",
            "somigli",
            "levenshtein",
            "fuzzy",
            "probabil",
            "candidate",
            "suggest",
            "propose",
            "infer",
        ] {
            assert!(
                !codice.contains(vietata),
                "il dominio del grafo non deve nominare «{vietata}»: nessuna inferenza"
            );
        }
    }

    /// **Nessun nodo e nessun arco porta un numero.**
    ///
    /// Un numero accanto a un pallino con un nome sopra diventa un punteggio,
    /// comunque si chiami.
    #[test]
    fn nessun_arco_porta_un_campo_numerico() {
        let codice = produzione();

        for (nome, apertura) in [
            ("GraphEdge", "pub struct GraphEdge {"),
            ("Neighbourhood", "pub struct Neighbourhood {"),
        ] {
            let Some(inizio) = codice.find(apertura) else {
                panic!("{nome} deve esistere");
            };
            let Some(lunghezza) = codice[inizio..].find("\n}\n") else {
                panic!("{nome} deve chiudersi");
            };
            let campi = &codice[inizio..inizio + lunghezza];

            for tipo in [": f32", ": f64", ": i32", ": u32"] {
                assert!(
                    !campi.contains(tipo),
                    "{nome} non porta alcun numero: trovato {tipo}"
                );
            }
        }
        assert!(
            !codice.contains("fn score")
                && !codice.contains("fn weight")
                && !codice.contains("fn degree"),
            "il dominio non calcola alcun punteggio, peso o grado"
        );
    }

    // ------------------------------------------------------------------
    // La derivazione.
    // ------------------------------------------------------------------

    /// **L'arco verso l'indicatore del gruppo ha per provenienza il membro più
    /// antico.**
    ///
    /// Sceglierne un altro renderebbe la provenienza dipendente dall'ordine di
    /// lettura, e due letture darebbero due provenienze per lo stesso fatto.
    #[test]
    fn la_provenienza_del_gruppo_e_il_membro_piu_antico() {
        let fatti = EventFacts {
            kind: IndicatorKind::Cve,
            value: String::from("CVE-2026-1234"),
            members: vec![
                (ContentId::new(9), SourceId::new(2), ORA),
                (
                    ContentId::new(3),
                    SourceId::new(1),
                    Timestamp::from_millis(ORA.as_millis() - 1_000),
                ),
            ],
        };
        let archi = edges_of_event(&fatti);

        let verso_indicatore: Vec<&GraphEdge> = archi
            .iter()
            .filter(|arco| arco.rule() == EdgeRule::EventTurnsOnIndicator)
            .collect();
        assert_eq!(verso_indicatore.len(), 1);

        let EdgeProvenance::Observed { content, .. } = verso_indicatore[0].provenance() else {
            panic!("l'arco del gruppo e' osservato");
        };
        assert_eq!(*content, ContentId::new(3), "il membro piu' antico");
    }

    /// **Un gruppo senza membri non produce l'arco verso il proprio indicatore.**
    ///
    /// Non ci sarebbe nulla che lo osservi, e un arco senza qualcosa che lo
    /// osservi e' un arco senza provenienza.
    #[test]
    fn un_gruppo_senza_membri_non_produce_archi() {
        let archi = edges_of_event(&EventFacts {
            kind: IndicatorKind::Cve,
            value: String::from("CVE-2026-1234"),
            members: Vec::new(),
        });
        assert!(archi.is_empty());
    }

    /// **Due letture degli stessi archi danno lo stesso vicinato.**
    ///
    /// Due figure diverse della stessa cosa sono due figure di cui una mente.
    #[test]
    fn il_vicinato_e_ripetibile() {
        let mut fatti = contenuto(1, Some("111"));
        fatti.indicators = vec![
            (IndicatorKind::Domain, String::from("zeta.it")),
            (IndicatorKind::Cve, String::from("CVE-2026-1234")),
            (IndicatorKind::Domain, String::from("alfa.it")),
        ];
        let archi = edges_of_content(&fatti);

        let mut rovesciati = archi.clone();
        rovesciati.reverse();

        let nodo = GraphNode::Content(ContentId::new(1));
        let primo = neighbourhood_of(&nodo, &archi, 50);
        let secondo = neighbourhood_of(&nodo, &rovesciati, 50);

        let frasi = |vicinato: &Neighbourhood| -> Vec<String> {
            vicinato.edges().iter().map(GraphEdge::why).collect()
        };
        assert_eq!(frasi(&primo), frasi(&secondo));
    }

    /// **Il vicinato prende gli archi in entrambe le direzioni.**
    ///
    /// Un'identita' e' capo di partenza dell'arco verso il contenuto; il
    /// contenuto e' capo d'arrivo. Un vicinato che guardasse una sola direzione
    /// mostrerebbe un contenuto senza il suo autore.
    #[test]
    fn il_vicinato_guarda_entrambe_le_direzioni() {
        let archi = edges_of_content(&contenuto(1, Some("111")));

        let del_contenuto = neighbourhood_of(&GraphNode::Content(ContentId::new(1)), &archi, 50);
        assert!(
            del_contenuto
                .edges()
                .iter()
                .any(|arco| arco.rule() == EdgeRule::IdentityAuthoredContent),
            "il vicinato di un contenuto contiene l'arco del suo autore"
        );

        let dell_identita = neighbourhood_of(
            &GraphNode::ObservedIdentity(String::from("111")),
            &archi,
            50,
        );
        assert_eq!(dell_identita.edges().len(), 1);
    }

    /// Un nodo che nessun arco tocca ha un vicinato vuoto, e lo dice senza
    /// dichiarare un taglio che non c'è.
    #[test]
    fn un_nodo_senza_archi_ha_un_vicinato_vuoto() {
        let archi = edges_of_content(&contenuto(1, Some("111")));
        let vicinato = neighbourhood_of(&GraphNode::Content(ContentId::new(99)), &archi, 50);

        assert!(vicinato.edges().is_empty());
        assert_eq!(vicinato.omitted(), 0);
        assert!(!vicinato.caveat().contains("Non \u{e8} tutto"));
    }
}

//! Che cosa contiene il registro analitico, prima e indipendentemente da come
//! e' scritto.
//!
//! Stessa separazione di [`crate::report_narrative`] e per la stessa ragione
//! (ADR-0031 Decisione 4): qui si decide **quali fatti** il registro riporta,
//! `report_xlsx` li traduce in un foglio di calcolo. I criteri che contano —
//! che nessun record sparisca, che i livelli 0 ci siano, che le celle non
//! diventino formule — si provano su questa struttura senza aprire un archivio
//! ZIP.
//!
//! # Che cosa rappresenta, e in che cosa differisce dalla relazione
//!
//! La relazione narrativa racconta **la selezione dell'operatore**. Il registro
//! rappresenta **tutto cio' che e' stato monitorato**, compresi i contenuti di
//! livello 0, quelli senza alert e quelli giudicati non rilevanti
//! ([`lisi_core::model::report::ReportScope::EverythingMonitored`]).
//!
//! **Nessun record sparisce perche' non ha generato un alert.** E' la stessa
//! ragione per cui lo Storico comprende il livello 0: un registro che mostrasse
//! solo cio' che ha superato una soglia direbbe che il resto non e' stato
//! guardato, e non e' vero.
//!
//! # I dieci fogli
//!
//! I primi nove sono quelli previsti da ADR-0031 Decisione 5, e sono nove
//! perche' tengono separate cose che e' facile confondere: i **dati originali**
//! (cio' che la fonte ha pubblicato), i **metadati del sistema** (quando
//! l'abbiamo visto, con che impronta) e le **valutazioni** (livello proposto dal
//! motore, decisione della persona). Mescolarle in un foglio solo produrrebbe
//! una tabella in cui non si distingue piu' cio' che e' stato osservato da cio'
//! che e' stato giudicato.
//!
//! Il decimo, `10 — Gruppi di segnali`, e' arrivato con CYBER-REPORT ed e' di una
//! quarta natura: non e' un dato osservato ne' una valutazione umana, ma un
//! **risultato di correlazione prodotto dal programma**. Sta in un foglio suo
//! proprio per questo — mescolarlo ai contenuti direbbe che un gruppo e' un
//! contenuto, e chi filtrasse quella colonna conterebbe i contenuti credendo di
//! contare i gruppi.
//!
//! # Dove un dato non c'e'
//!
//! Il registro **lo dichiara**, con [`crate::report_narrative::NOT_AVAILABLE`],
//! invece di lasciare la cella vuota. Una cella vuota in un foglio di calcolo si
//! legge come «zero», «nessuno» o «dimenticato», e le tre cose sono diverse.

use lisi_core::model::origin::Origin;
use lisi_core::model::report::{ReportId, ReportSnapshot};
use lisi_core::model::report_template::ReportTemplateProfile;
use lisi_core::text::Actor;
use lisi_core::{ContentId, Timestamp};

use crate::report_narrative::NOT_AVAILABLE;

/// Un foglio del registro: un nome e una tabella.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sheet {
    /// Nome del foglio, come compare nella linguetta in basso.
    pub name: String,
    /// Intestazioni di colonna. Non vuote: un foglio senza intestazioni e' una
    /// tabella che nessuno sa rileggere fra sei mesi.
    pub headers: Vec<String>,
    /// Una riga per record.
    pub rows: Vec<Vec<Cell>>,
}

/// Il contenuto di una cella.
///
/// # Perche' un tipo e non una stringa
///
/// Perche' la differenza fra un numero e un testo che sembra un numero deve
/// essere **decisa qui**, dove si sa che cosa il dato e', e non nel renderer,
/// dove si vedrebbe solo una stringa. Un identificativo scritto come numero
/// perde gli zeri iniziali; un livello scritto come testo non si puo' ordinare.
///
/// E soprattutto: [`Cell::Text`] e' cio' che il renderer scrive **sempre come
/// testo**, qualunque cosa contenga. E' li' che l'iniezione di formule si
/// neutralizza, ed e' il motivo per cui il tipo esiste.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cell {
    /// Testo. Puo' provenire da una fonte remota, e va trattato come ostile.
    Text(String),
    /// Un intero: identificativi, conteggi, livelli.
    Number(i64),
    /// Il **corpo di un contenuto monitorato**: l'unica cella che una resa può
    /// accorciare.
    ///
    /// # Perché una variante e non un testo come gli altri
    ///
    /// Perché il registro in testo semplice tagliava **ogni** cella oltre i
    /// duecento caratteri, e fra quelle celle ci sono la motivazione di un
    /// avviso, il motivo di una revisione, la descrizione di un errore e la
    /// frase che dichiara che cosa un recupero non vede: testo probatorio,
    /// interrotto nei puntini, che chi rilegge il documento fra sei mesi non ha
    /// modo di ricostruire (FINAL-PRODUCT-REVIEW-01, FPR-05).
    ///
    /// Il corpo è l'eccezione perché, e soltanto perché, **è riportato per
    /// intero altrove**: nell'allegato tecnico, che è fatto per essere letto, e
    /// nel registro in Excel. Un taglio che rimanda a un testo completo e
    /// raggiungibile non perde nulla; un taglio che non rimanda a niente sì.
    ///
    /// Per il foglio di calcolo è un testo come gli altri, e si scrive
    /// **sempre come testo**: è la cella che più facilmente contiene una
    /// formula scritta da una fonte remota.
    Body(String),
}

impl Cell {
    /// Una cella di testo.
    fn text(value: impl Into<String>) -> Self {
        Self::Text(value.into())
    }

    /// Il testo indicato, o la dichiarazione che il dato non c'e'.
    fn optional(value: Option<impl Into<String>>) -> Self {
        value.map_or_else(
            || Self::Text(String::from(NOT_AVAILABLE)),
            |inner| Self::Text(inner.into()),
        )
    }

    /// Il corpo di un contenuto monitorato.
    fn body(value: impl Into<String>) -> Self {
        Self::Body(value.into())
    }

    /// Il testo della cella, per le prove e per il renderer.
    #[must_use]
    pub fn as_text(&self) -> String {
        match self {
            Self::Text(value) | Self::Body(value) => value.clone(),
            Self::Number(value) => value.to_string(),
        }
    }
}

/// Il registro completo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ledger {
    /// Istante di generazione, che finisce nelle proprieta' del file.
    pub generated_at: Timestamp,
    /// I dieci fogli, nell'ordine in cui compaiono nelle linguette.
    pub sheets: Vec<Sheet>,
}

/// I fatti della sessione, gia' letti dall'archivio.
#[derive(Debug, Clone)]
pub struct LedgerSession {
    /// Etichetta scelta dall'operatore.
    pub label: String,
    /// Inizio effettivo.
    pub started_at: Timestamp,
    /// Fine effettiva, se la sessione e' conclusa.
    pub ended_at: Option<Timestamp>,
    /// Stato dichiarato dalla sessione.
    pub state: String,
    /// Le pause dell'acquisizione, già in parole: quando, chi e perché
    /// (COLLAUDO-FIX-01, CU01-015). Vuoto se non ce ne sono state.
    pub pauses: Vec<String>,
}

/// Quante righe di cronologia un documento riproduce per grappolo.
pub const MAX_TIMELINE_ROWS_IN_DOCUMENT: usize = 30;

/// Per quanti grappoli un documento riproduce il vicinato del grafo.
///
/// # Perché pochi
///
/// Perché un vicinato è una pagina di legenda, e cinque vicinati sono cinque
/// pagine che nessuno legge. Il superamento **si dichiara** (ADR-0106).
pub const MAX_NEIGHBOURHOODS_IN_DOCUMENT: usize = 5;

/// Quante voci di legenda un documento riproduce per vicinato.
pub const MAX_LEGEND_ROWS_IN_DOCUMENT: usize = 20;

/// Perché la rappresentazione grafica non è riprodotta.
///
/// # Perché si dichiara invece di tacere
///
/// Perché un silenzio si leggerebbe come «non c'è niente da disegnare», che è
/// un'affermazione e non un'assenza. E perché la ragione è precisa: il
/// generatore `.docx` sa incorporare un'immagine e quello `.pdf` no, e farla
/// entrare in uno solo dei due produrrebbe **due documenti che dicono cose
/// diverse** — ciò che GRAPH-03 ha rifiutato decidendo «una figura sola, non una
/// per formato» (ADR-0106, decisione 4).
pub const PERCHE_LA_FIGURA_NON_E_RIPRODOTTA: &str = "La rappresentazione grafica di questo vicinato non è riprodotta nel \
     presente documento: sarebbe incorporabile in uno solo dei formati prodotti, \
     e due documenti dello stesso fascicolo mostrerebbero cose diverse. Le voci \
     elencate qui sotto sono le stesse che la figura porterebbe, e portano in \
     più il testo — che in una figura non si potrebbe né cercare né citare.";

/// Che cosa il documento dice quando la ragione operativa manca, sul vicinato.
///
/// # Perché una frase diversa da quella dei soggetti
///
/// Perché la cosa che manca è diversa: lì manca un elenco di persone, qui manca
/// la mappa di ciò che tocca un gruppo. Una frase sola per due assenze direbbe
/// a chi legge che si tratta della stessa mancanza.
pub const SENZA_RAGIONE_OPERATIVA_NON_SI_COMPONE_IL_VICINATO: &str = "Il vicinato di questo \
     gruppo nel grafo delle prove non è stato composto: la ragione operativa che ne autorizza la \
     compilazione non risulta registrata. Ciò NON significa che il gruppo non sia collegato a \
     nulla: significa che la condizione per comporne la mappa non è stata soddisfatta.";

/// Quante note un documento riproduce.
pub const MAX_NOTES_IN_DOCUMENT: usize = 100;

/// Quanti raccoglitori un documento riproduce.
pub const MAX_WORKSPACES_IN_DOCUMENT: usize = 20;

/// Che cosa il documento dice prima di riportare una nota.
///
/// # Perché «non modificano la prova originale» sta qui
///
/// Perché è la frase del congelamento, e perché una nota accanto al testo
/// acquisito potrebbe far credere che il testo sia stato corretto. Il contenuto
/// è quello, e nessuna nota lo tocca (ADR-0108, decisione 1; R-18).
pub const CHE_COSA_E_UNA_NOTA: &str = "Le annotazioni che seguono sono LE PAROLE DI UNA PERSONA su qualcosa che sta \
     nell'archivio. Non sono osservazioni del programma, non sono decisioni — le \
     decisioni stanno fra le valutazioni, con la loro motivazione — e NON \
     MODIFICANO LA PROVA ORIGINALE: il testo acquisito è quello riportato più \
     sopra, e nessuna nota lo altera. Ciascuna porta chi l'ha scritta e quando.";

/// Che cosa il documento dice prima di elencare un raccoglitore.
pub const CHE_COSA_E_UN_RACCOGLITORE: &str = "I raccoglitori che seguono sono insiemi di cose che un operatore ha voluto \
     guardare insieme. RACCOGLIERE NON È CONCLUDERE: un raccoglitore non è il \
     risultato di un ragionamento concluso, e il fatto che due elementi vi \
     compaiano insieme non afferma che abbiano a che fare l'uno con l'altro. Di \
     ciascuno si riportano SOLTANTO gli elementi di questo monitoraggio: i \
     raccoglitori attraversano le attività, il presente documento no.";

/// Che cosa il documento dice quando nessuno ha annotato né raccolto.
pub const NESSUNA_NOTA_E_NESSUN_RACCOGLITORE: &str = "Per i contenuti del presente monitoraggio non risultano annotazioni scritte \
     né raccoglitori aperti. Ciò NON significa che non vi fosse nulla da \
     annotare: significa che nessuno lo ha fatto.";

/// Una nota dell'operatore, come entra in un documento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerNote {
    /// Su che cosa è stata scritta, detto a chi legge.
    pub about: String,
    /// Le parole, come sono state scritte.
    pub body: String,
    /// Chi.
    pub author: String,
    /// Quando.
    pub written_at: Timestamp,
    /// Chi l'ha ritirata e quando, se è stata ritirata.
    ///
    /// # Perché una nota ritirata resta nel documento
    ///
    /// Perché omettendola si riscriverebbe che cosa avevano davanti quelli che
    /// ci hanno lavorato sopra: la nota c'era, e qualcuno può averla letta prima
    /// del ritiro (ADR-0108, decisione 2).
    pub withdrawal: Option<(String, Timestamp)>,
}

/// Un raccoglitore dell'operatore, come entra in un documento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerWorkspace {
    /// Il nome.
    pub name: String,
    /// A che cosa serve, quando chi lo ha aperto lo ha scritto.
    pub description: Option<String>,
    /// Chi lo ha aperto.
    pub created_by: String,
    /// Quando.
    pub created_at: Timestamp,
    /// Se è ancora aperto.
    pub open: bool,
    /// Quanti contenuti **di questo monitoraggio** contiene.
    pub contents_here: usize,
}

/// Quanti riferimenti tassonomici un documento riproduce.
pub const MAX_TAXONOMY_REFERENCES_IN_DOCUMENT: usize = 100;

/// Che cosa il documento dice prima di elencare un riferimento ATT&CK.
///
/// # Perché l'ultima frase non è prudenza
///
/// Perché dentro il programma è vera per costruzione — una guardia verifica che
/// il modulo della mappatura non nomini né il livello né gli avvisi — ma su
/// carta, stampata accanto al livello, sembrerebbe esserne la ragione
/// (ADR-0107, decisione 1; R-16).
pub const CHE_COSA_E_UN_RIFERIMENTO_TASSONOMICO: &str = "MITRE ATT&CK è un vocabolario condiviso per nominare tecniche. I riferimenti \
     che seguono dicono che UN TERMINE trovato in un contenuto è stato associato \
     da un operatore a una tecnica di quel vocabolario: NON dicono che una \
     tecnica sia stata impiegata, e NON attribuiscono alcuna condotta ad alcuna \
     persona. Ciascuno è l'atto di chi lo ha dichiarato, con il motivo che ha \
     scritto. Un riferimento tassonomico NON alza il livello di analisi e NON \
     genera alcun avviso: non è un segnale.";

/// Che cosa il documento dice quando nessun riferimento è stato dichiarato.
pub const NESSUN_RIFERIMENTO_TASSONOMICO_DICHIARATO: &str = "Nessun operatore ha dichiarato riferimenti tassonomici per i contenuti del \
     presente monitoraggio. Ciò NON significa che nessuna tecnica sia pertinente: \
     significa che nessuno si è espresso, e il programma non associa nulla da sé.";

/// Che cosa il documento dice dei cataloghi ufficiali, prima di elencarli.
pub const UNA_FOTOGRAFIA_NON_E_OGGI: &str = "I cataloghi che seguono sono FOTOGRAFIE: file acquisiti in un dato momento, \
     con la copertura e l'impronta che si dichiarano. Non sono lo stato odierno \
     delle rispettive fonti. Ciò che non vi compare può esservi entrato dopo, e \
     il programma non ha modo di saperlo: sa quando la fotografia è stata presa, \
     e lo scrive. Chi rilegge il presente documento deve confrontarle con i \
     cataloghi del giorno in cui lo rilegge.";

/// Un riferimento tassonomico dichiarato da una persona.
///
/// # Che cosa questo tipo non ha
///
/// Una probabilità, un punteggio, una confidenza. Un riferimento **o è stato
/// dichiarato o non lo è**: non esiste una via di mezzo da misurare, e un campo
/// numerico accanto a una tecnica diventerebbe una stima di quanto quella
/// tecnica sia stata impiegata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerTaxonomyReference {
    /// A quale contenuto il termine appartiene.
    pub content_id: ContentId,
    /// Il termine, nella forma su cui il prodotto confronta.
    pub term: String,
    /// La categoria del termine.
    pub term_category: String,
    /// L'identificativo della tecnica.
    pub technique: String,
    /// Il nome della tecnica, come la tassonomia lo scrive.
    pub technique_name: String,
    /// La versione di ATT&CK.
    ///
    /// **Obbligatoria**: un identificativo significa cose diverse in versioni
    /// diverse, e citarlo senza versione cita una cosa che non si sa quale sia.
    pub attack_version: String,
    /// Se la tassonomia ha deprecato la tecnica.
    pub deprecated: bool,
    /// Se la tassonomia l'ha revocata.
    pub revoked: bool,
    /// Perché è stata dichiarata, con le parole di chi l'ha dichiarata.
    pub reason: String,
    /// Chi.
    pub declared_by: String,
    /// Quando.
    pub declared_at: Timestamp,
}

/// Una fotografia di un catalogo ufficiale, come entra in un documento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerOfficialSource {
    /// Quale catalogo.
    pub catalogue: String,
    /// Che cosa lo identifica: versione, copertura, istante di rilascio.
    pub identity: String,
    /// Chi l'ha importato.
    pub imported_by: String,
    /// Quando.
    pub imported_at: Timestamp,
    /// L'impronta di ciò che è stato acquisito, dove la fotografia ne porta una.
    pub digest: Option<String>,
    /// I conteggi, come la fotografia li dichiara.
    pub counts: String,
    /// **La designazione che ogni copia deve riprodurre.**
    ///
    /// Un documento consegnato è una copia. Non è una decisione di sicurezza: è
    /// la condizione a cui quei dati si possono usare (ADR-0107, decisione 4).
    pub attribution: String,
}

/// Una riga di cronologia già composta, con il suo orologio dichiarato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerTimeline {
    /// Quando si stava guardando.
    ///
    /// **Obbligatoria**: senza, un periodo senza righe si leggerebbe come «non è
    /// successo niente», che è un fatto che nessuno ha misurato.
    pub window: String,
    /// L'avvertenza che accompagna la linea, compresa quella sui due orologi
    /// **quando e solo quando** la linea ne mescola davvero due.
    pub caveat: String,
    /// Le righe, dalla più antica, ciascuna con il proprio orologio nominato.
    pub rows: Vec<String>,
    /// Quante righe restano fuori dal documento.
    pub rows_beyond: usize,
}

/// Una voce della legenda del vicinato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerGraphNode {
    /// Il numero con cui la voce si nomina.
    pub number: usize,
    /// Che genere di cosa è.
    pub kind: String,
    /// Come si chiama.
    pub label: String,
    /// **Per quale fatto è collegata al centro**, con la provenienza del fatto.
    pub why: String,
    /// Se l'arco che la collega è l'atto di una persona.
    pub decided_by_a_person: bool,
}

/// Il vicinato di un nodo, come entra in un documento.
///
/// # Che cosa questo tipo non ha
///
/// Un percorso. Nessuna voce è collegata a un'altra voce: **un arco è un fatto,
/// un percorso è un'affermazione**, e la composizione di fatti veri produce
/// un'impressione falsa (GRAPH-01, R-15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerNeighbourhood {
    /// Di quale nodo, detto a chi legge.
    pub centre: String,
    /// L'avvertenza del vicinato, **come testo e non come immagine**.
    pub caveat: String,
    /// Le voci, entro il tetto del documento.
    pub legend: Vec<LedgerGraphNode>,
    /// Quante voci restano fuori dal documento per via del tetto.
    pub legend_beyond: usize,
    /// Quanti archi il vicinato stesso aveva già lasciato fuori.
    pub edges_omitted: usize,
}

/// Un gruppo di segnali, come il registro e l'allegato lo riportano.
///
/// # Che cosa questo tipo esiste per non lasciare implicito
///
/// Un gruppo è **un risultato di correlazione di NEXUM/97**, non una
/// constatazione che un fatto sia avvenuto. Il tipo porta i numeri e la
/// ragione; la frase che lo dichiara la scrivono i due generatori, in cima alla
/// sezione, perché un documento che finisce in un fascicolo va letto anche da
/// chi non ha mai visto il programma.
///
/// # Perché i campi sono questi
///
/// Sono ciò che si può **verificare riaprendo i contenuti**: quanti sono, da
/// quante fonti distinte, quando, quali indicatori, che cosa una persona ha
/// deciso. Non c'è un campo «gravità» e non c'è un campo «autore»: il primo
/// confonderebbe la correlazione con il livello (ADR-0035 Decisione 10), il
/// secondo sarebbe un'attribuzione, e il prodotto non attribuisce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerCyberEvent {
    /// Perché quei contenuti stanno insieme, in una frase verificabile.
    pub reason: String,
    /// Il genere dell'indicatore che li tiene insieme.
    pub indicator_kind: String,
    /// Il valore normalizzato.
    pub indicator_value: String,
    /// Quanti contenuti.
    pub contents: usize,
    /// Quante fonti **distinte**. Mai «indipendenti».
    pub distinct_sources: usize,
    /// Quanti contenuti hanno testo identico a un altro del gruppo.
    pub apparent_reposts: usize,
    /// Quando il primo contenuto è stato pubblicato.
    pub first_seen: Option<Timestamp>,
    /// Quando l'ultimo.
    pub last_seen: Option<Timestamp>,
    /// I segnali di rilevanza per l'Italia, in una frase. **Non è gravità.**
    pub italy: String,
    /// I settori delle organizzazioni dichiarate che i contenuti nominano, con
    /// la provenienza di ciascuna attribuzione. **Non è gravità.**
    ///
    /// # Perché la provenienza entra nel documento consegnato
    ///
    /// Un settore in un fascicolo che esce dall'ufficio è un'affermazione che
    /// qualcuno leggerà senza poter chiedere spiegazioni. Portare con sé chi
    /// ha dichiarato l'organizzazione, e che cosa ha riscontrato, è ciò che la
    /// rende verificabile invece che autorevole.
    ///
    /// `None` quando nessuna organizzazione dichiarata e' stata nominata, che
    /// e' lo stato di ogni postazione senza elenco. **Non e' una stringa
    /// vuota**: chi consuma questo campo decide se stampare guardando il tipo,
    /// non confrontando il testo con una frase che un giorno cambia.
    pub sectors: Option<String>,
    /// Gli indicatori nominati dai contenuti del gruppo.
    pub indicators: Vec<String>,
    /// Che cosa una persona ha deciso, in una frase.
    pub review: String,
    /// La cronologia del grappolo, quando il monitoraggio ha una finestra.
    ///
    /// `None` quando il monitoraggio non risulta avviato: senza finestra una
    /// linea del tempo non si compone, perche un periodo senza righe si
    /// leggerebbe come «non e successo niente» (ADR-0106, decisione 2).
    pub timeline: Option<LedgerTimeline>,
    /// Il vicinato del grappolo nel grafo delle prove.
    ///
    /// `None` quando la ragione operativa non e registrata, o quando il tetto
    /// dei vicinati riprodotti e gia stato raggiunto.
    pub neighbourhood: Option<LedgerNeighbourhood>,
}

/// Una fonte monitorata.
#[derive(Debug, Clone)]
pub struct LedgerSource {
    /// Nome mostrato all'operatore.
    pub label: String,
    /// Genere della fonte.
    pub kind: String,
    /// Identificativo pubblico, dove esiste.
    pub identifier: Option<String>,
    /// Quanti contenuti sono stati acquisiti da questa fonte.
    pub acquired: usize,
}

/// Quante versioni di un contenuto un documento riproduce, al massimo.
///
/// Oltre questo numero il documento **dice quante ne restano** invece di
/// tagliare in silenzio (ADR-0104, decisione 5): un taglio taciuto trasforma
/// «non mostrato» in «non esistente».
pub const MAX_REVISIONS_IN_DOCUMENT: usize = 10;

/// Quante fotografie del contesto un documento riproduce per contenuto.
pub const MAX_CONTEXTS_IN_DOCUMENT: usize = 3;

/// Quante righe di contorno un documento riproduce per fotografia.
pub const MAX_CONTEXT_LINES_IN_DOCUMENT: usize = 20;

/// Che cosa il documento dice del contorno, prima di riprodurlo.
///
/// # Perché sta qui e non nel generatore
///
/// Perché deve essere **la stessa frase** nell'allegato e nella relazione. Due
/// composizioni della stessa avvertenza divergono alla prima modifica, e la
/// differenza fra ciò che è stato analizzato e ciò che è stato soltanto visto è
/// la cosa che questa frase esiste per tenere ferma (ADR-0104, decisione 3).
pub const CHE_COSA_E_UN_CONTORNO: &str = "Le righe che seguono sono il contorno che l'operatore ha visto attorno al \
     contenuto, all'istante dichiarato. Non sono state acquisite, non sono state \
     analizzate e non sono oggetto di alcun livello: sono riprodotte perché una \
     persona ha deciso di conservarle, e perché ha scritto per quale ragione.";

/// Che cosa il documento dice delle versioni, prima di elencarle.
pub const CHE_COSA_E_UNA_REVISIONE: &str = "Livello, riscontri ed eventuale avviso riguardano il testo con cui il \
     contenuto è stato ACQUISITO, e non sono stati ricalcolati sulle versioni \
     che seguono. Le versioni sono riportate per mostrare che cosa è cambiato \
     dopo, non per sostituire il testo analizzato.";

/// Una versione osservata dopo l'acquisizione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerRevision {
    /// Il numero della versione a cui si è arrivati.
    pub version: u32,
    /// Quando la modifica è stata osservata.
    pub observed_at: Timestamp,
    /// Che cosa è cambiato rispetto alla versione precedente.
    ///
    /// È una **relazione esatta** — o vale o non vale — e mai il risultato di
    /// un allineamento parola per parola, che mostrerebbe modifiche mirate dove
    /// c'è stata una riscrittura (ADR-0104, decisione 2).
    pub change: String,
    /// Di quanti caratteri il testo si è allungato o accorciato.
    pub length_delta: i64,
    /// Il testo di questa versione. **Non fidato.**
    pub body: String,
}

/// Una riga del contorno di una fotografia.
///
/// **Non è un contenuto acquisito.** È stata vista una volta e non è mai
/// passata per il motore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerContextLine {
    /// L'identificativo che la fonte le dà.
    pub remote_message_id: String,
    /// Quando la fonte dichiara che è stata pubblicata.
    pub published_at: Timestamp,
    /// Il testo, come fu letto. **Non fidato.**
    pub body: String,
    /// Che cosa si sapeva di chi l'ha scritta, come frase già composta.
    pub author_sentence: String,
    /// Se è la riga attorno a cui si guardava.
    pub is_anchor: bool,
}

/// Una fotografia del contesto, come entra in un documento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerContext {
    /// Chi l'ha presa.
    pub taken_by: String,
    /// Perché. **Valutazione dell'operatore**, e mai dato originale.
    pub reason: String,
    /// Quando è stata presa.
    pub taken_at: Timestamp,
    /// Quando il contorno era stato letto.
    pub observed_at: Timestamp,
    /// L'identificativo remoto del messaggio attorno a cui si guardava.
    pub anchor_remote_message_id: String,
    /// Se l'impronta registrata si è ricalcolata uguale.
    ///
    /// Quando è falso il documento **lo dice e non riproduce il contorno**: un
    /// dato che non si può dimostrare integro non entra in un atto (ADR-0104,
    /// decisione 4). Le righe sono allora vuote, e non è la stessa cosa di una
    /// fotografia senza contorno.
    pub verified: bool,
    /// Le righe, nell'ordine in cui furono viste.
    pub lines: Vec<LedgerContextLine>,
    /// Quante righe restano fuori dal documento.
    pub lines_beyond: usize,
}

/// Quante identità collegate un documento riproduce per soggetto.
pub const MAX_SUBJECT_IDENTITIES_IN_DOCUMENT: usize = 10;

/// Che cosa il documento dice prima di nominare un soggetto.
///
/// # Perché la dichiarazione viene prima, e sempre
///
/// Dentro il programma si vede che un fascicolo è nato da una decisione: c'è la
/// schermata, la storia degli atti, il motivo accanto a ogni gesto. **Su carta
/// non si vede niente di tutto questo**, e un elenco di nomi con sotto dei
/// numeri si legge come un profilo (ADR-0105, R-13).
pub const CHE_COSA_E_UN_SOGGETTO: &str = "Le persone che seguono non sono state individuate dal programma. Ciascuna \
     è qui perché un operatore ha aperto un fascicolo con un motivo scritto e ha \
     collegato a quel fascicolo un'identità osservata, anch'essa con un motivo \
     scritto. NEXUM/97 non crea profili, non elenca chi appare in una fonte e non \
     attribuisce alcun punteggio a una persona. Di ciascun soggetto si riporta \
     soltanto ciò che QUESTO monitoraggio ha osservato: il fascicolo contiene \
     altro, raccolto in altre attività, e quella parte non entra nel presente \
     documento.";

/// Che cosa il documento dice quando la ragione operativa non è stata registrata.
///
/// # Perché non basta una sezione vuota
///
/// Perché una sezione vuota si legge come «nessuna persona di interesse», che è
/// un'affermazione e non un'assenza (ADR-0105, decisione 5).
pub const SENZA_RAGIONE_OPERATIVA_NON_SI_ELENCA: &str = "Nessun elenco di persone è stato prodotto per il presente documento: la \
     ragione operativa che ne autorizza la compilazione non risulta registrata. \
     Ciò NON significa che nessuna persona sia di interesse: significa che la \
     condizione per compilarne un elenco non è stata soddisfatta, ed è la stessa \
     condizione che vale nelle schermate del programma.";

/// Un'identità collegata a un soggetto, e ciò che questo monitoraggio ne ha visto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerSubjectIdentity {
    /// L'identificativo osservato presso la piattaforma.
    pub identifier: String,
    /// Chi l'ha collegata al fascicolo.
    pub linked_by: String,
    /// Quando.
    pub linked_at: Timestamp,
    /// Perché. **Valutazione dell'operatore**, e mai un fatto osservato.
    pub link_reason: String,
    /// Su che cosa il legame è stato deciso (PR-10): un'identità osservata nei
    /// monitoraggi, o una ricerca puntuale.
    pub link_basis: String,
    /// Quanti contenuti di questo monitoraggio le risultano attribuiti.
    pub contents_here: usize,
    /// Quanti di quelli hanno prodotto un avviso.
    pub alerts_here: usize,
    /// Da quante fonti distinte di questo monitoraggio.
    pub distinct_sources_here: usize,
    /// Il primo istante di pubblicazione fra quei contenuti.
    pub first_seen_here: Option<Timestamp>,
    /// L'ultimo.
    pub last_seen_here: Option<Timestamp>,
}

/// Un soggetto investigativo, come entra in un documento.
///
/// # Che cosa questo tipo non ha, e non avrà
///
/// Un punteggio. È la stessa scelta di `Person`: **nessun campo numerico sulla
/// persona**, perché un campo numerico accanto a un nome diventa una misura il
/// giorno in cui qualcuno lo stampa. I numeri che questo tipo porta riguardano
/// **ciò che il monitoraggio ha raccolto**, e stanno sull'identità osservata,
/// non sul soggetto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerSubject {
    /// Come l'ufficio lo chiama.
    pub label: String,
    /// Come il fascicolo è nato, detto a chi legge.
    pub dossier_sentence: String,
    /// Perché è stato aperto.
    pub dossier_reason: String,
    /// Se è ancora aperto.
    pub open: bool,
    /// Come la valutazione si nomina: `NON VALUTATO` compreso.
    pub assessment_label: String,
    /// La valutazione, detta a chi legge, con chi e quando.
    pub assessment_sentence: String,
    /// Il motivo della valutazione, quando qualcuno si è espresso.
    pub assessment_reason: Option<String>,
    /// Le identità collegate, entro il tetto del documento.
    pub identities: Vec<LedgerSubjectIdentity>,
    /// Quante identità restano fuori dal documento.
    pub identities_beyond: usize,
}

/// Un contenuto monitorato, con i propri metadati e le proprie valutazioni.
#[derive(Debug, Clone)]
pub struct LedgerContent {
    /// Identificativo interno.
    pub content_id: ContentId,
    /// Fonte di provenienza.
    pub source_label: String,
    /// Identificativo pubblico di chi ha scritto, dove disponibile.
    pub author: Option<String>,
    /// Quando la fonte l'ha pubblicato.
    pub published_at: Timestamp,
    /// Quando il programma l'ha acquisito.
    pub acquired_at: Timestamp,
    /// Il **modo di acquisizione dichiarato** (PR-07, ADR-0123): la frase del
    /// criterio, e per un recupero ciò che il recupero non vede. Non è la
    /// colonna del percorso: «osservato» lì non basta a dire «dal vivo».
    pub origin: String,
    /// Testo del messaggio. **Non fidato.**
    pub body: String,
    /// Collegamento, dove esiste.
    pub url: Option<String>,
    /// Il collegamento chiesto a Telegram per questo documento, già in frase
    /// (ADR-0165); `None` se il documento non l'ha chiesto.
    pub asked_link: Option<String>,
    /// L'allegato, già in frase: ciò che il mittente dichiara e, se
    /// conservato, l'impronta (ATTACH-01, ADR-0177, decisione 9). Mai i byte.
    pub attachment: Option<String>,
    /// Livello proposto dal motore, come fotografato.
    pub level: u8,
    /// Stato della revisione, come fotografato.
    pub review_state: Option<String>,
    /// Se l'operatore l'ha scelto per la relazione.
    pub selected: bool,
    /// Impronta del corpo al momento della fotografia.
    pub body_digest: String,
    /// Da dove venivano i termini che hanno prodotto il livello.
    ///
    /// # Perché entra nei documenti consegnati
    ///
    /// Perché è ciò che rende il risultato **contestabile**. «Il motore ha
    /// proposto il livello 3» è un'affermazione che nessuno può discutere;
    /// «lo ha proposto per termini che stavano nel dizionario X, versione 4,
    /// scelto per questa sessione» è un'affermazione che qualcuno può andare a
    /// verificare — ed è la differenza fra un documento tecnico e un documento
    /// che regge in un fascicolo.
    ///
    /// `None` quando il contenuto non ha riscontri: non c'è provenienza da
    /// dichiarare perché non c'è nulla che l'abbia prodotta.
    pub analysis_origin: Option<String>,
    /// Che cosa è successo al messaggio dopo l'acquisizione, in una frase.
    ///
    /// # Perché entra nel registro consegnato
    ///
    /// Un registro che riportasse il testo di un messaggio senza dire che
    /// quel messaggio è stato poi **modificato**, o che la fonte non lo espone
    /// più, direbbe una cosa vera in un modo che induce in errore: chi legge
    /// crederebbe di avere davanti lo stato attuale.
    ///
    /// `None` quando non è successo nulla, che è il caso normale.
    pub after_acquisition: Option<String>,
    /// Le versioni osservate dopo l'acquisizione, dalla prima alla più recente.
    ///
    /// Vuoto per un contenuto mai modificato, che è il caso normale.
    pub revisions: Vec<LedgerRevision>,
    /// Quante versioni restano fuori dal documento per via del tetto.
    pub revisions_beyond: usize,
    /// Le fotografie del contesto, dalla più recente.
    pub contexts: Vec<LedgerContext>,
    /// Quante fotografie restano fuori dal documento per via del tetto.
    pub contexts_beyond: usize,
}

impl LedgerContent {
    /// Quante versioni sono state osservate in tutto, tetto compreso.
    #[must_use]
    pub const fn revisions_observed(&self) -> usize {
        self.revisions.len() + self.revisions_beyond
    }

    /// Quante fotografie sono state prese in tutto, tetto compreso.
    #[must_use]
    pub const fn contexts_taken(&self) -> usize {
        self.contexts.len() + self.contexts_beyond
    }
}

/// Un avviso emesso durante la sessione.
#[derive(Debug, Clone)]
pub struct LedgerAlert {
    /// Contenuto a cui si riferisce.
    pub content_id: ContentId,
    /// Livello dell'avviso.
    pub level: u8,
    /// Perche' il motore l'ha emesso. **Non fidato:** contiene termini del
    /// dizionario e frammenti del contenuto.
    pub reason: String,
    /// Quando e' stato emesso.
    pub raised_at: Timestamp,
}

/// Una decisione umana su un contenuto.
#[derive(Debug, Clone)]
pub struct LedgerReview {
    /// Contenuto giudicato.
    pub content_id: ContentId,
    /// Stato scelto.
    pub state: String,
    /// Motivazione scritta dall'operatore, dove c'e'. **Non fidata:** e' testo
    /// libero, e un testo libero che comincia per `=` e' una formula.
    pub note: Option<String>,
    /// Chi ha deciso.
    pub actor: String,
    /// Quando.
    pub decided_at: Timestamp,
}

/// Un'anomalia tecnica registrata durante la sessione.
#[derive(Debug, Clone)]
pub struct LedgerFault {
    /// Genere dell'anomalia.
    pub kind: String,
    /// Descrizione. **Non fidata:** puo' contenere un messaggio del server.
    pub detail: String,
    /// Quando e' avvenuta.
    pub happened_at: Timestamp,
}

/// Tutto cio' che serve a comporre il registro.
#[derive(Debug, Clone)]
pub struct LedgerInput<'a> {
    /// Identificativo del report.
    pub report_id: &'a ReportId,
    /// Profilo documentale dell'ufficio.
    pub profile: &'a ReportTemplateProfile,
    /// La fotografia su cui il registro e' costruito.
    pub snapshot: &'a ReportSnapshot,
    /// Chi ha chiesto la generazione.
    pub operator: &'a Actor,
    /// Istante della generazione.
    pub generated_at: Timestamp,
    /// I fatti della sessione.
    pub session: &'a LedgerSession,
    /// Le fonti monitorate.
    pub sources: &'a [LedgerSource],
    /// **Tutti** i contenuti monitorati, non solo i selezionati.
    pub contents: &'a [LedgerContent],
    /// Gli avvisi emessi.
    pub alerts: &'a [LedgerAlert],
    /// Le decisioni umane.
    pub reviews: &'a [LedgerReview],
    /// Le anomalie tecniche.
    pub faults: &'a [LedgerFault],
    /// Con quali termini l'analisi è stata condotta (ADR-0156): la stessa
    /// composizione della relazione, dell'allegato e del rapporto.
    pub configuration: &'a crate::analysis_configuration::AnalysisConfiguration,
    /// I gruppi di segnali tecnici, se ce ne sono.
    ///
    /// **Non sono incidenti confermati.** Vedere [`LedgerCyberEvent`].
    pub cyber_events: &'a [LedgerCyberEvent],
    /// I soggetti aperti a cui questo monitoraggio ha osservato qualcosa.
    ///
    /// Vuoto quando nessuno ne ha aperti, o quando nessuno dei fascicoli aperti
    /// ha un'identità osservata qui.
    pub subjects: &'a [LedgerSubject],
    /// I riferimenti tassonomici dichiarati per i contenuti del monitoraggio.
    pub taxonomy: &'a [LedgerTaxonomyReference],
    /// Quanti riferimenti restano fuori dal documento per via del tetto.
    pub taxonomy_beyond: usize,
    /// Le fotografie dei cataloghi ufficiali che l'archivio conserva.
    pub official_sources: &'a [LedgerOfficialSource],
    /// Le annotazioni scritte sulle cose che il documento rappresenta.
    pub notes: &'a [LedgerNote],
    /// Quante annotazioni restano fuori dal documento per via del tetto.
    pub notes_beyond: usize,
    /// I raccoglitori che contengono contenuti di questo monitoraggio.
    pub workspaces: &'a [LedgerWorkspace],
    /// Quanti raccoglitori restano fuori dal documento per via del tetto.
    pub workspaces_beyond: usize,
    /// Se la ragione operativa che autorizza il lavoro investigativo è registrata.
    ///
    /// **È un cancello solo, non due**: la stessa voce d'audit autorizza gli
    /// elenchi di persone e la composizione del vicinato del grafo. Due campi
    /// per lo stesso fatto divergerebbero il giorno in cui uno si muovesse
    /// senza l'altro (ADR-0105 decisione 5, ADR-0106 decisione 5).
    ///
    /// Quando è falso i soggetti **non si elencano** e il vicinato **non si
    /// compone**, e il documento dichiara perché.
    pub investigative_basis: bool,
}

/// L'origine di ogni colonna del registro (PR-03, ADR-0118): foglio,
/// intestazione, origine. `None` per ciò che non è un dato di una sola origine —
/// un identificativo, o le coppie «Voce, Valore» in cui ogni riga ha la propria.
///
/// # Perché un elenco chiuso
///
/// Perché una colonna nuova senza origine dichiarata fa fallire la prova qui
/// sotto: un foglio di calcolo esce dall'ufficio, e chi lo legge fra sei mesi
/// deve sapere se un numero l'ha osservato Telegram, l'ha calcolato il
/// programma o l'ha scritto una persona.
const COLUMN_ORIGINS: &[(&str, &str, Option<Origin>)] = &[
    ("01 — Sessione", "Voce", None),
    ("01 — Sessione", "Valore", None),
    ("02 — Fonti", "Fonte", Some(Origin::Observed)),
    ("02 — Fonti", "Genere", Some(Origin::Observed)),
    ("02 — Fonti", "Identificativo", Some(Origin::Observed)),
    ("02 — Fonti", "Contenuti acquisiti", Some(Origin::Computed)),
    ("03 — Contenuti", "ID", None),
    ("03 — Contenuti", "Fonte", Some(Origin::Observed)),
    ("03 — Contenuti", "Autore", Some(Origin::Observed)),
    (
        "03 — Contenuti",
        "Pubblicato il (UTC)",
        Some(Origin::Observed),
    ),
    (
        "03 — Contenuti",
        "Acquisito il (UTC)",
        Some(Origin::Computed),
    ),
    (
        "03 — Contenuti",
        "Modo di acquisizione",
        Some(Origin::Computed),
    ),
    ("03 — Contenuti", "Livello", Some(Origin::Computed)),
    ("03 — Contenuti", "Revisione", Some(Origin::Operator)),
    ("03 — Contenuti", "Nella relazione", Some(Origin::Operator)),
    (
        "03 — Contenuti",
        "Dopo l'acquisizione",
        Some(Origin::Observed),
    ),
    (
        "03 — Contenuti",
        "Versioni osservate",
        Some(Origin::Computed),
    ),
    (
        "03 — Contenuti",
        "Fotografie del contesto",
        Some(Origin::Computed),
    ),
    ("03 — Contenuti", "Allegato", Some(Origin::Observed)),
    ("03 — Contenuti", "Collegamento", Some(Origin::Observed)),
    ("03 — Contenuti", "Testo", Some(Origin::Observed)),
    ("04 — Avvisi", "Contenuto", None),
    ("04 — Avvisi", "Livello", Some(Origin::Computed)),
    ("04 — Avvisi", "Emesso il (UTC)", Some(Origin::Computed)),
    (
        "04 — Avvisi",
        "Motivazione del motore",
        Some(Origin::Computed),
    ),
    ("05 — Revisioni", "Contenuto", None),
    ("05 — Revisioni", "Decisione", Some(Origin::Operator)),
    ("05 — Revisioni", "Decisa il (UTC)", Some(Origin::Operator)),
    ("05 — Revisioni", "Da", Some(Origin::Operator)),
    ("05 — Revisioni", "Motivazione", Some(Origin::Operator)),
    ("06 — Errori", "Avvenuto il (UTC)", Some(Origin::Computed)),
    ("06 — Errori", "Genere", Some(Origin::Computed)),
    ("06 — Errori", "Descrizione", Some(Origin::Computed)),
    ("07 — Dizionari", "Dizionario", Some(Origin::Operator)),
    ("07 — Dizionari", "Versione", Some(Origin::Operator)),
    ("07 — Dizionari", "Termini", Some(Origin::Operator)),
    ("07 — Dizionari", "Da dove è noto", Some(Origin::Computed)),
    ("08 — Configurazione", "Voce", None),
    ("08 — Configurazione", "Valore", None),
    ("09 — Integrità", "Contenuto", None),
    (
        "09 — Integrità",
        "Impronta SHA-256 del corpo",
        Some(Origin::Computed),
    ),
    (
        "10 — Gruppi di segnali",
        "Perché stanno insieme",
        Some(Origin::Computed),
    ),
    (
        "10 — Gruppi di segnali",
        "Genere indicatore",
        Some(Origin::Computed),
    ),
    (
        "10 — Gruppi di segnali",
        "Valore indicatore",
        Some(Origin::Observed),
    ),
    (
        "10 — Gruppi di segnali",
        "Contenuti",
        Some(Origin::Computed),
    ),
    (
        "10 — Gruppi di segnali",
        "Fonti distinte",
        Some(Origin::Computed),
    ),
    (
        "10 — Gruppi di segnali",
        "Testi identici nel gruppo",
        Some(Origin::Computed),
    ),
    (
        "10 — Gruppi di segnali",
        "Primo contenuto (UTC)",
        Some(Origin::Computed),
    ),
    (
        "10 — Gruppi di segnali",
        "Ultimo contenuto (UTC)",
        Some(Origin::Computed),
    ),
    (
        "10 — Gruppi di segnali",
        "Rilevanza Italia (non è gravità)",
        Some(Origin::Computed),
    ),
    (
        "10 — Gruppi di segnali",
        "Settore dichiarato (non è gravità)",
        Some(Origin::Computed),
    ),
    (
        "10 — Gruppi di segnali",
        "Indicatori nominati",
        Some(Origin::Computed),
    ),
    (
        "10 — Gruppi di segnali",
        "Revisione umana",
        Some(Origin::Operator),
    ),
    ("11 — Soggetti", "Soggetto", Some(Origin::Operator)),
    ("11 — Soggetti", "Fascicolo", Some(Origin::Operator)),
    (
        "11 — Soggetti",
        "Perché è stato aperto",
        Some(Origin::Operator),
    ),
    ("11 — Soggetti", "Valutazione", Some(Origin::Operator)),
    (
        "11 — Soggetti",
        "Motivo della valutazione",
        Some(Origin::Operator),
    ),
    (
        "11 — Soggetti",
        "Identità collegata",
        Some(Origin::Operator),
    ),
    ("11 — Soggetti", "Collegata da", Some(Origin::Operator)),
    (
        "11 — Soggetti",
        "Collegata il (UTC)",
        Some(Origin::Operator),
    ),
    (
        "11 — Soggetti",
        "Perché è stata collegata",
        Some(Origin::Operator),
    ),
    (
        "11 — Soggetti",
        "Contenuti in questo monitoraggio",
        Some(Origin::Computed),
    ),
    ("11 — Soggetti", "Di cui con avviso", Some(Origin::Computed)),
    ("11 — Soggetti", "Fonti distinte", Some(Origin::Computed)),
    ("12 — Parole aggiunte", "Parola", Some(Origin::Operator)),
    ("12 — Parole aggiunte", "Livello", Some(Origin::Operator)),
    (
        "12 — Parole aggiunte",
        "Modalità di riscontro",
        Some(Origin::Operator),
    ),
    (
        "12 — Parole aggiunte",
        "Da dove è noto",
        Some(Origin::Computed),
    ),
];

/// L'intestazione con la sua origine: «Livello [calcolato]».
fn with_origin(sheet: &str, header: &str) -> String {
    match COLUMN_ORIGINS
        .iter()
        .find(|(foglio, colonna, _)| *foglio == sheet && *colonna == header)
    {
        Some((_, _, Some(origine))) => {
            format!("{header} [{}]", origine.label().to_lowercase())
        }
        _ => header.to_owned(),
    }
}

/// Compone il registro dai fatti indicati.
#[must_use]
pub fn compose(input: &LedgerInput<'_>) -> Ledger {
    let mut ledger = compose_without_origins(input);
    for sheet in &mut ledger.sheets {
        let nome = sheet.name.clone();
        for header in &mut sheet.headers {
            *header = with_origin(&nome, header);
        }
    }
    ledger
}

/// Il registro, con le intestazioni come le scrive ciascun foglio.
fn compose_without_origins(input: &LedgerInput<'_>) -> Ledger {
    Ledger {
        generated_at: input.generated_at,
        sheets: vec![
            session_sheet(input),
            sources_sheet(input),
            contents_sheet(input),
            alerts_sheet(input),
            reviews_sheet(input),
            faults_sheet(input),
            dictionaries_sheet(input),
            configuration_sheet(input),
            integrity_sheet(input),
            cyber_sheet(input),
            subjects_sheet(input),
            custom_terms_sheet(input),
        ],
    }
}

/// `11 — Soggetti` — chi l'ufficio ha aperto, e che cosa questo monitoraggio ne ha
/// visto.
///
/// # Perché nessun testo
///
/// Perché una scheda si filtra e si conta, e perché un corpo di messaggio in una
/// cella è la superficie dell'iniezione di formule (R-01). Le frasi che spiegano
/// come un fascicolo è nato stanno nell'allegato, che è fatto per essere letto.
///
/// # Perché il motivo del legame invece resta
///
/// Perché non è testo monitorato: è ciò che un operatore ha scritto, ed è la
/// cosa che rende la riga contestabile. Senza, resterebbe un nome accanto a dei
/// numeri, che è precisamente la forma del profilo (ADR-0105).
fn subjects_sheet(input: &LedgerInput<'_>) -> Sheet {
    let mut rows = Vec::new();
    for subject in input.subjects {
        for identity in &subject.identities {
            rows.push(vec![
                Cell::text(&subject.label),
                Cell::text(if subject.open { "aperto" } else { "chiuso" }),
                Cell::text(&subject.dossier_reason),
                Cell::text(&subject.assessment_label),
                Cell::optional(subject.assessment_reason.as_deref()),
                Cell::text(&identity.identifier),
                Cell::text(&identity.linked_by),
                Cell::text(identity.linked_at.to_readable_utc()),
                Cell::text(&identity.link_reason),
                Cell::Number(i64::try_from(identity.contents_here).unwrap_or(i64::MAX)),
                Cell::Number(i64::try_from(identity.alerts_here).unwrap_or(i64::MAX)),
                Cell::Number(i64::try_from(identity.distinct_sources_here).unwrap_or(i64::MAX)),
            ]);
        }
    }

    Sheet {
        name: String::from("11 — Soggetti"),
        headers: vec![
            String::from("Soggetto"),
            String::from("Fascicolo"),
            String::from("Perché è stato aperto"),
            String::from("Valutazione"),
            String::from("Motivo della valutazione"),
            String::from("Identità collegata"),
            String::from("Collegata da"),
            String::from("Collegata il (UTC)"),
            String::from("Perché è stata collegata"),
            String::from("Contenuti in questo monitoraggio"),
            String::from("Di cui con avviso"),
            String::from("Fonti distinte"),
        ],
        rows,
    }
}

/// `01 — Sessione` — che cosa e' stato monitorato, quando e da chi.
fn session_sheet(input: &LedgerInput<'_>) -> Sheet {
    let monitored = input.snapshot.contents.len();
    let selected = input
        .snapshot
        .contents
        .iter()
        .filter(|entry| entry.selected)
        .count();

    let mut sheet = Sheet {
        name: String::from("01 — Sessione"),
        headers: vec![String::from("Voce"), String::from("Valore")],
        rows: vec![
            row(
                "Identificativo del report",
                Cell::text(input.report_id.as_str()),
            ),
            row("Monitoraggio", Cell::text(&input.session.label)),
            row("Stato", Cell::text(&input.session.state)),
            row(
                "Inizio (UTC)",
                Cell::text(input.session.started_at.to_readable_utc()),
            ),
            row(
                "Fine (UTC)",
                Cell::optional(input.session.ended_at.map(Timestamp::to_readable_utc)),
            ),
            row(
                "Generato il (UTC)",
                Cell::text(input.generated_at.to_readable_utc()),
            ),
            row("Generato da", Cell::text(input.operator.as_str())),
            row(
                "Versione del profilo documentale",
                Cell::Number(i64::from(input.snapshot.template_version)),
            ),
            // I due numeri stanno **accanto**, perche' e' la coppia a dire
            // qualcosa: «12 selezionati» da solo non si sa su quanti.
            row(
                "Contenuti monitorati",
                Cell::Number(i64::try_from(monitored).unwrap_or(i64::MAX)),
            ),
            row(
                "Contenuti selezionati per la relazione",
                Cell::Number(i64::try_from(selected).unwrap_or(i64::MAX)),
            ),
            row(
                "Amministrazione",
                Cell::optional(input.profile.organisation.as_ref().map(|f| f.as_str())),
            ),
            row(
                "Ufficio",
                Cell::optional(input.profile.office.as_ref().map(|f| f.as_str())),
            ),
        ],
    };
    // Una riga per pausa, con chi l'ha decisa e perché (CU01-015).
    sheet.rows.extend(
        input
            .session
            .pauses
            .iter()
            .map(|pausa| row("Pausa dell'acquisizione", Cell::text(pausa))),
    );
    sheet
}

/// `02 — Fonti` — da dove i contenuti sono arrivati.
fn sources_sheet(input: &LedgerInput<'_>) -> Sheet {
    Sheet {
        name: String::from("02 — Fonti"),
        headers: vec![
            String::from("Fonte"),
            String::from("Genere"),
            String::from("Identificativo"),
            String::from("Contenuti acquisiti"),
        ],
        rows: input
            .sources
            .iter()
            .map(|source| {
                vec![
                    Cell::text(&source.label),
                    Cell::text(&source.kind),
                    Cell::optional(source.identifier.as_deref()),
                    Cell::Number(i64::try_from(source.acquired).unwrap_or(i64::MAX)),
                ]
            })
            .collect(),
    }
}

/// `03 — Contenuti` — il foglio principale: **tutto** il monitorato.
fn contents_sheet(input: &LedgerInput<'_>) -> Sheet {
    Sheet {
        name: String::from("03 — Contenuti"),
        headers: vec![
            String::from("ID"),
            String::from("Fonte"),
            String::from("Autore"),
            String::from("Pubblicato il (UTC)"),
            String::from("Acquisito il (UTC)"),
            String::from("Modo di acquisizione"),
            String::from("Livello"),
            String::from("Revisione"),
            String::from("Nella relazione"),
            String::from("Dopo l'acquisizione"),
            String::from("Versioni osservate"),
            String::from("Fotografie del contesto"),
            String::from("Allegato"),
            String::from("Collegamento"),
            String::from("Testo"),
        ],
        rows: input
            .contents
            .iter()
            .map(|content| {
                vec![
                    Cell::Number(content.content_id.get()),
                    Cell::text(&content.source_label),
                    Cell::optional(content.author.as_deref()),
                    Cell::text(content.published_at.to_readable_utc()),
                    Cell::text(content.acquired_at.to_readable_utc()),
                    Cell::text(&content.origin),
                    Cell::Number(i64::from(content.level)),
                    // Non revisionato e' un fatto, non un vuoto: la cella lo
                    // dice, perche' una cella vuota qui si leggerebbe come
                    // «nessuno se n'e' occupato» oppure come «va bene cosi'», e
                    // le due cose sono diverse. E non e' nemmeno un dato
                    // mancante: «non disponibile» si leggeva cosi' (OBS-REP-2).
                    Cell::text(
                        content
                            .review_state
                            .as_deref()
                            .unwrap_or(crate::report_narrative::NOT_REVIEWED),
                    ),
                    Cell::text(if content.selected { "si" } else { "no" }),
                    // Vuota quando non e' successo nulla: qui, a differenza
                    // della revisione, il vuoto NON e' ambiguo. «Nessuna
                    // modifica osservata» ripetuto su ogni riga insegnerebbe a
                    // saltare la colonna, e la renderebbe inutile proprio dove
                    // conta.
                    Cell::optional(content.after_acquisition.as_deref()),
                    // CONTEGGI, NON CORPI (ADR-0104, decisione 6). Una cella
                    // che contenesse il testo di una versione moltiplicherebbe
                    // per il numero delle versioni la superficie
                    // dell'iniezione di formule, e renderebbe illeggibile una
                    // tabella che serve a filtrare e a contare. I testi stanno
                    // nell'allegato, che e' fatto per essere letto.
                    Cell::Number(i64::try_from(content.revisions_observed()).unwrap_or(i64::MAX)),
                    Cell::Number(i64::try_from(content.contexts_taken()).unwrap_or(i64::MAX)),
                    // L'allegato: descrizione e impronta, mai i byte (ATTACH-01).
                    Cell::optional(content.attachment.as_deref()),
                    Cell::Text(crate::message_link::in_documents_with(
                        content.asked_link.as_deref(),
                        content.url.as_deref(),
                    )),
                    Cell::body(&content.body),
                ]
            })
            .collect(),
    }
}

/// `04 — Avvisi` — che cosa il motore ha segnalato, e perche'.
fn alerts_sheet(input: &LedgerInput<'_>) -> Sheet {
    Sheet {
        name: String::from("04 — Avvisi"),
        headers: vec![
            String::from("Contenuto"),
            String::from("Livello"),
            String::from("Emesso il (UTC)"),
            String::from("Motivazione del motore"),
        ],
        rows: input
            .alerts
            .iter()
            .map(|alert| {
                vec![
                    Cell::Number(alert.content_id.get()),
                    Cell::Number(i64::from(alert.level)),
                    Cell::text(alert.raised_at.to_readable_utc()),
                    Cell::text(&alert.reason),
                ]
            })
            .collect(),
    }
}

/// `05 — Revisioni` — che cosa una persona ha deciso, e quando.
fn reviews_sheet(input: &LedgerInput<'_>) -> Sheet {
    Sheet {
        name: String::from("05 — Revisioni"),
        headers: vec![
            String::from("Contenuto"),
            String::from("Decisione"),
            String::from("Decisa il (UTC)"),
            String::from("Da"),
            String::from("Motivazione"),
        ],
        rows: input
            .reviews
            .iter()
            .map(|review| {
                vec![
                    Cell::Number(review.content_id.get()),
                    Cell::text(&review.state),
                    Cell::text(review.decided_at.to_readable_utc()),
                    Cell::text(&review.actor),
                    Cell::optional(review.note.as_deref()),
                ]
            })
            .collect(),
    }
}

/// `06 — Errori` — che cosa non ha funzionato durante l'acquisizione.
///
/// Il foglio c'e' **anche quando e' vuoto**: un registro senza questo foglio
/// lascerebbe credere che non ci siano stati problemi, mentre un foglio vuoto
/// dice che non ne sono stati registrati. Sono due affermazioni diverse.
fn faults_sheet(input: &LedgerInput<'_>) -> Sheet {
    Sheet {
        name: String::from("06 — Errori"),
        headers: vec![
            String::from("Avvenuto il (UTC)"),
            String::from("Genere"),
            String::from("Descrizione"),
        ],
        rows: input
            .faults
            .iter()
            .map(|fault| {
                vec![
                    Cell::text(fault.happened_at.to_readable_utc()),
                    Cell::text(&fault.kind),
                    Cell::text(&fault.detail),
                ]
            })
            .collect(),
    }
}

/// `07 — Dizionari` — con quali termini l'analisi e' stata fatta.
///
/// # Perché la colonna «Da dove è noto»
///
/// Per i monitoraggi anteriori alla registrazione delle scelte il foglio era
/// vuoto, e il registro in testo diceva «(nessun record)» accanto a una
/// configurazione di centinaia di termini (BUG-REP-1). Le versioni si ricavano
/// ora dalle provenienze dei termini risolti, e la colonna lo dice riga per
/// riga (ADR-0156).
fn dictionaries_sheet(input: &LedgerInput<'_>) -> Sheet {
    Sheet {
        name: String::from("07 — Dizionari"),
        headers: vec![
            String::from("Dizionario"),
            String::from("Versione"),
            String::from("Termini"),
            String::from("Da dove è noto"),
        ],
        rows: input
            .configuration
            .dictionary_rows()
            .into_iter()
            .map(|(dictionary, da_dove)| {
                vec![
                    Cell::text(&dictionary.name),
                    Cell::Number(i64::from(dictionary.version)),
                    Cell::Number(i64::try_from(dictionary.terms).unwrap_or(i64::MAX)),
                    Cell::text(da_dove),
                ]
            })
            .collect(),
    }
}

/// `08 — Configurazione` — che cosa era in vigore al momento della fotografia.
///
/// Dopo le quattro voci della fotografia vengono le frasi sulla configurazione
/// dell'analisi, **le stesse** della relazione, dell'allegato e del rapporto
/// (ADR-0156): versioni, configurazione risolta con la sua impronta,
/// provenienza dei termini, parole aggiunte.
fn configuration_sheet(input: &LedgerInput<'_>) -> Sheet {
    let mut rows = vec![
        row(
            "Fotografia presa il (UTC)",
            Cell::text(input.snapshot.taken_at.to_readable_utc()),
        ),
        row(
            "Fonti nella fotografia",
            Cell::Number(i64::try_from(input.snapshot.source_ids.len()).unwrap_or(i64::MAX)),
        ),
        row(
            "Versioni di dizionario nella fotografia",
            Cell::Number(
                i64::try_from(input.snapshot.dictionary_version_ids.len()).unwrap_or(i64::MAX),
            ),
        ),
        row(
            "Versione del profilo documentale",
            Cell::Number(i64::from(input.snapshot.template_version)),
        ),
    ];
    for statement in input.configuration.statements() {
        rows.push(row(
            statement.lead.trim_end_matches(':'),
            Cell::text(&statement.body),
        ));
    }
    Sheet {
        name: String::from("08 — Configurazione"),
        headers: vec![String::from("Voce"), String::from("Valore")],
        rows,
    }
}

/// `12 — Parole aggiunte` — le parole aggiunte per la sola sessione
/// (BUG-REP-2, ADR-0156).
///
/// Nessun documento le riportava: una parola che aveva fatto scattare un
/// avviso non si ritrovava nella configurazione dichiarata. Un foglio a sé,
/// perché si filtrano e si contano come le versioni; quando non ce ne sono, o
/// non si sa, lo dice la voce «Parole aggiunte per la sessione» del foglio
/// «08 — Configurazione».
fn custom_terms_sheet(input: &LedgerInput<'_>) -> Sheet {
    Sheet {
        name: String::from("12 — Parole aggiunte"),
        headers: vec![
            String::from("Parola"),
            String::from("Livello"),
            String::from("Modalità di riscontro"),
            String::from("Da dove è noto"),
        ],
        rows: input
            .configuration
            .custom_term_rows()
            .into_iter()
            .map(|(term, da_dove)| {
                vec![
                    Cell::text(&term.text),
                    Cell::Number(i64::from(term.level)),
                    Cell::text(term.match_mode.label()),
                    Cell::text(da_dove),
                ]
            })
            .collect(),
    }
}

/// `09 — Integrità` — l'impronta di ogni corpo, come fotografata.
///
/// Serve a rispondere a una domanda sola, ed e' quella che conta in giudizio:
/// **il testo qui riportato e' quello che il programma ha visto?** L'impronta
/// del corpo al momento della fotografia lo dice, e un testo modificato dopo
/// produrrebbe un'impronta diversa.
fn integrity_sheet(input: &LedgerInput<'_>) -> Sheet {
    Sheet {
        name: String::from("09 — Integrità"),
        headers: vec![
            String::from("Contenuto"),
            String::from("Impronta SHA-256 del corpo"),
        ],
        rows: input
            .contents
            .iter()
            .map(|content| {
                vec![
                    Cell::Number(content.content_id.get()),
                    Cell::text(&content.body_digest),
                ]
            })
            .collect(),
    }
}

/// `10 — Gruppi di segnali` — le correlazioni tecniche, e che cosa NON sono.
///
/// # Perché un foglio e non una colonna
///
/// Un gruppo non è un contenuto: è un **insieme** di contenuti, e metterlo in
/// una colonna del foglio dei contenuti costringerebbe a ripetere lo stesso
/// gruppo su ogni riga che vi appartiene. Chi filtrasse quella colonna
/// conterebbe i contenuti e crederebbe di contare i gruppi.
///
/// # La riga che il foglio porta anche quando è vuoto
///
/// Le intestazioni ci sono sempre, e la prima colonna dichiara che cosa un
/// gruppo è. Un foglio vuoto e senza spiegazione, in un fascicolo consegnato,
/// si legge come «non è stato cercato».
fn cyber_sheet(input: &LedgerInput<'_>) -> Sheet {
    Sheet {
        name: String::from("10 — Gruppi di segnali"),
        headers: vec![
            String::from("Perché stanno insieme"),
            String::from("Genere indicatore"),
            String::from("Valore indicatore"),
            String::from("Contenuti"),
            // «Distinte», mai «indipendenti»: stabilire l'indipendenza
            // richiederebbe sapere chi ha scritto per primo.
            String::from("Fonti distinte"),
            String::from("Testi identici nel gruppo"),
            String::from("Primo contenuto (UTC)"),
            String::from("Ultimo contenuto (UTC)"),
            String::from("Rilevanza Italia (non è gravità)"),
            String::from("Settore dichiarato (non è gravità)"),
            String::from("Indicatori nominati"),
            String::from("Revisione umana"),
        ],
        rows: input
            .cyber_events
            .iter()
            .map(|event| {
                vec![
                    Cell::text(&event.reason),
                    Cell::text(&event.indicator_kind),
                    Cell::text(&event.indicator_value),
                    Cell::Number(i64::try_from(event.contents).unwrap_or(i64::MAX)),
                    Cell::Number(i64::try_from(event.distinct_sources).unwrap_or(i64::MAX)),
                    Cell::Number(i64::try_from(event.apparent_reposts).unwrap_or(i64::MAX)),
                    Cell::optional(event.first_seen.map(Timestamp::to_readable_utc)),
                    Cell::optional(event.last_seen.map(Timestamp::to_readable_utc)),
                    Cell::text(&event.italy),
                    Cell::optional(event.sectors.clone()),
                    Cell::text(event.indicators.join(", ")),
                    Cell::text(&event.review),
                ]
            })
            .collect(),
    }
}
/// Una riga a due colonne, per i fogli fatti di coppie voce/valore.
fn row(label: &str, value: Cell) -> Vec<Cell> {
    vec![Cell::text(label), value]
}

#[cfg(test)]
mod tests {
    use lisi_core::SessionId;
    use lisi_core::digest::Sha256Digest;
    use lisi_core::model::analysis::AnalysisLevel;
    use lisi_core::model::report::{ReportContentSnapshot, ReportSnapshot};

    use super::*;

    fn snapshot(selected: &[i64], monitored: &[i64]) -> ReportSnapshot {
        ReportSnapshot {
            taken_at: Timestamp::from_millis(1_752_000_000_000),
            session_id: SessionId::new(1),
            source_ids: Vec::new(),
            dictionary_version_ids: Vec::new(),
            template_version: 3,
            contents: monitored
                .iter()
                .map(|raw| ReportContentSnapshot {
                    content_id: ContentId::new(*raw),
                    level: AnalysisLevel::try_new(u8::try_from(raw % 5).unwrap_or(0))
                        .expect("livello valido"),
                    review_state: None,
                    body_sha256: Sha256Digest::of_text(&format!("corpo {raw}")),
                    selected: selected.contains(raw),
                })
                .collect(),
        }
    }

    fn content(id: i64, level: u8, selected: bool, body: &str) -> LedgerContent {
        LedgerContent {
            content_id: ContentId::new(id),
            source_label: String::from("Canale di prova"),
            author: None,
            published_at: Timestamp::from_millis(1_752_001_000_000),
            acquired_at: Timestamp::from_millis(1_752_001_500_000),
            origin: String::from("osservato"),
            body: String::from(body),
            url: None,
            asked_link: None,
            attachment: None,
            level,
            review_state: None,
            selected,
            body_digest: Sha256Digest::of_text(body).as_str().to_owned(),
            after_acquisition: None,
            revisions: Vec::new(),
            revisions_beyond: 0,
            contexts: Vec::new(),
            contexts_beyond: 0,
            analysis_origin: None,
        }
    }

    fn input<'a>(
        report_id: &'a ReportId,
        profile: &'a ReportTemplateProfile,
        snapshot: &'a ReportSnapshot,
        operator: &'a Actor,
        session: &'a LedgerSession,
        contents: &'a [LedgerContent],
    ) -> LedgerInput<'a> {
        // Una configurazione di cui non si sa nulla, che vive quanto il
        // registro restituito.
        static NON_NOTA: crate::analysis_configuration::AnalysisConfiguration =
            crate::analysis_configuration::AnalysisConfiguration::unknown();
        LedgerInput {
            report_id,
            profile,
            snapshot,
            operator,
            generated_at: Timestamp::from_millis(1_752_086_400_000),
            session,
            sources: &[],
            contents,
            alerts: &[],
            reviews: &[],
            faults: &[],
            configuration: &NON_NOTA,
            cyber_events: &[],
            subjects: &[],
            taxonomy: &[],
            taxonomy_beyond: 0,
            official_sources: &[],
            notes: &[],
            notes_beyond: 0,
            workspaces: &[],
            workspaces_beyond: 0,
            investigative_basis: true,
        }
    }

    fn session() -> LedgerSession {
        LedgerSession {
            pauses: Vec::new(),
            label: String::from("Monitoraggio di prova"),
            started_at: Timestamp::from_millis(1_752_000_000_000),
            ended_at: None,
            state: String::from("conclusa"),
        }
    }

    #[test]
    fn the_ledger_always_has_the_twelve_sheets_in_order() {
        // Dodici fogli, e sempre gli stessi: un registro che ne omettesse uno
        // perche' vuoto lascerebbe credere che quella categoria di fatti non
        // esista, invece che essere vuota.
        //
        // L'undicesimo e' arrivato con REPORT-PERS-01, e la prova e' stata VISTA
        // ROSSA e poi estesa: dichiarare un foglio in piu' e' rafforzarla, e
        // toglierla avrebbe tolto la difesa insieme alla sua ragione. Il
        // dodicesimo, le parole aggiunte per la sessione, con
        // NEXUM97-REPORT-CONFIG-01 (BUG-REP-2, ADR-0156): stessa regola.
        let report_id = ReportId::from_sequence(2026, 1);
        let profile = ReportTemplateProfile::default();
        let snapshot = snapshot(&[], &[1]);
        let operator = Actor::try_new("operatore").expect("attore valido");
        let session = session();
        let contents = [content(1, 0, false, "testo")];

        let ledger = compose(&input(
            &report_id, &profile, &snapshot, &operator, &session, &contents,
        ));

        let nomi: Vec<&str> = ledger
            .sheets
            .iter()
            .map(|sheet| sheet.name.as_str())
            .collect();
        assert_eq!(
            nomi,
            vec![
                "01 — Sessione",
                "02 — Fonti",
                "03 — Contenuti",
                "04 — Avvisi",
                "05 — Revisioni",
                "06 — Errori",
                "07 — Dizionari",
                "08 — Configurazione",
                "09 — Integrità",
                "10 — Gruppi di segnali",
                "11 — Soggetti",
                "12 — Parole aggiunte",
            ]
        );
    }

    /// **Il registro porta i conteggi, e non i corpi.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una cella di foglio di calcolo che contenesse il testo di una versione
    /// moltiplicherebbe per il numero delle versioni la superficie
    /// dell'iniezione di formule (R-01), e renderebbe illeggibile una tabella
    /// che serve a filtrare e a contare. I testi stanno nell'allegato, che e'
    /// fatto per essere letto (ADR-0104, decisione 6).
    ///
    /// La prova verifica anche che i conteggi comprendano cio' che il tetto ha
    /// lasciato fuori: un registro che contasse le sole righe riprodotte
    /// direbbe che di quel contenuto esistono meno versioni di quante ne
    /// esistano.
    #[test]
    fn il_registro_porta_i_conteggi_delle_versioni_e_non_i_loro_corpi() {
        let report_id = ReportId::from_sequence(2026, 1);
        let profile = ReportTemplateProfile::default();
        let snapshot = snapshot(&[], &[1]);
        let operator = Actor::try_new("operatore").expect("attore valido");
        let session = session();

        let mut contenuto = content(1, 3, true, "testo acquisito");
        contenuto.revisions = vec![LedgerRevision {
            version: 2,
            observed_at: Timestamp::from_millis(1_752_002_000_000),
            change: String::from("nessuna relazione riconoscibile"),
            length_delta: -4,
            body: String::from("CORPO DELLA SECONDA VERSIONE"),
        }];
        contenuto.revisions_beyond = 2;
        contenuto.contexts = vec![LedgerContext {
            taken_by: String::from("operatore"),
            reason: String::from("serve il messaggio precedente"),
            taken_at: Timestamp::from_millis(1_752_003_000_000),
            observed_at: Timestamp::from_millis(1_752_002_900_000),
            anchor_remote_message_id: String::from("77"),
            verified: true,
            lines: vec![LedgerContextLine {
                remote_message_id: String::from("76"),
                published_at: Timestamp::from_millis(1_752_002_800_000),
                body: String::from("RIGA DI CONTORNO"),
                author_sentence: String::from("autore non esposto"),
                is_anchor: false,
            }],
            lines_beyond: 0,
        }];
        contenuto.contexts_beyond = 1;
        let contents = [contenuto];

        let ledger = compose(&input(
            &report_id, &profile, &snapshot, &operator, &session, &contents,
        ));

        let Some(foglio) = ledger
            .sheets
            .iter()
            .find(|sheet| sheet.name == "03 — Contenuti")
        else {
            panic!("il foglio dei contenuti deve esserci");
        };

        let testo_del_foglio = foglio
            .rows
            .iter()
            .flat_map(|riga| riga.iter().map(Cell::as_text))
            .collect::<Vec<String>>()
            .join("\n");

        assert!(
            !testo_del_foglio.contains("CORPO DELLA SECONDA VERSIONE"),
            "il corpo di una versione e' finito in una cella del registro"
        );
        assert!(
            !testo_del_foglio.contains("RIGA DI CONTORNO"),
            "una riga di contorno e' finita in una cella del registro"
        );

        // 1 riprodotta + 2 oltre il tetto; 1 riprodotta + 1 oltre il tetto.
        assert_eq!(contents[0].revisions_observed(), 3);
        assert_eq!(contents[0].contexts_taken(), 2);
        assert!(
            testo_del_foglio.contains('3') && testo_del_foglio.contains('2'),
            "i conteggi non compaiono nel foglio"
        );
    }

    #[test]
    fn i_nomi_dei_fogli_si_leggono_e_stanno_nelle_regole_del_foglio_di_calcolo() {
        // Si chiamavano `01_SESSIONE` … `04_ALERT`: forma di macchina in un
        // documento per una persona, e in più «ALERT» era la parola che il
        // prodotto ha tolto dallo schermo l'8 ottobre
        // (FINAL-PRODUCT-REVIEW-01, FPR-03). Il prefisso numerico resta, perché
        // tiene l'ordine delle linguette e rende citabile una sezione.
        //
        // La seconda metà della prova è il vincolo del formato: un nome di
        // foglio oltre i trentun caratteri, o con uno dei caratteri che Excel
        // riserva, non produce un file illeggibile — produce un errore in
        // scrittura, cioè nessun registro.
        let report_id = ReportId::from_sequence(2026, 1);
        let profile = ReportTemplateProfile::default();
        let snapshot = snapshot(&[], &[1]);
        let operator = Actor::try_new("operatore").expect("attore valido");
        let session = session();
        let contents = [content(1, 0, false, "corpo")];

        let ledger = compose(&input(
            &report_id, &profile, &snapshot, &operator, &session, &contents,
        ));

        for sheet in &ledger.sheets {
            let nome = sheet.name.as_str();
            assert!(
                !nome.contains('_'),
                "«{nome}» porta ancora il trattino basso della forma di macchina"
            );
            assert!(
                !nome.contains("ALERT") && !nome.contains("Alert"),
                "«{nome}» usa ancora la parola che il menu non usa più"
            );
            assert!(
                nome.chars().count() <= 31,
                "«{nome}» supera i trentun caratteri che il formato ammette"
            );
            for vietato in [':', '\\', '/', '?', '*', '[', ']'] {
                assert!(
                    !nome.contains(vietato),
                    "«{nome}» contiene «{vietato}», che il formato riserva"
                );
            }
            // Il prefisso numerico tiene l'ordine: senza, le linguette si
            // ordinerebbero come capita e la citazione «foglio 03» non
            // significherebbe niente.
            assert!(
                nome.starts_with(|primo: char| primo.is_ascii_digit()),
                "«{nome}» non comincia con il proprio numero"
            );
        }
    }

    #[test]
    fn every_sheet_declares_its_headers() {
        let report_id = ReportId::from_sequence(2026, 1);
        let profile = ReportTemplateProfile::default();
        let snapshot = snapshot(&[], &[1]);
        let operator = Actor::try_new("operatore").expect("attore valido");
        let session = session();
        let contents = [content(1, 0, false, "testo")];

        let ledger = compose(&input(
            &report_id, &profile, &snapshot, &operator, &session, &contents,
        ));

        for sheet in &ledger.sheets {
            assert!(
                !sheet.headers.is_empty(),
                "il foglio «{}» non ha intestazioni: nessuno saprebbe rileggerlo",
                sheet.name
            );
            for (index, riga) in sheet.rows.iter().enumerate() {
                assert_eq!(
                    riga.len(),
                    sheet.headers.len(),
                    "riga {index} del foglio «{}» ha un numero di celle diverso \
                     dalle intestazioni",
                    sheet.name
                );
            }
        }
    }

    /// **Ogni colonna dichiara chi dice il dato** (PR-03, ADR-0118).
    ///
    /// Una colonna nuova senza origine dichiarata fa fallire questa prova;
    /// una dichiarata e sparita anche.
    #[test]
    fn every_column_declares_its_origin() {
        let report_id = ReportId::from_sequence(2026, 1);
        let profile = ReportTemplateProfile::default();
        let snapshot = snapshot(&[], &[1]);
        let operator = Actor::try_new("operatore").expect("attore valido");
        let session = session();
        let contents = [content(1, 0, false, "testo")];

        let grezzo = super::compose_without_origins(&input(
            &report_id, &profile, &snapshot, &operator, &session, &contents,
        ));
        let mut viste = std::collections::BTreeSet::new();
        for sheet in &grezzo.sheets {
            for header in &sheet.headers {
                assert!(
                    super::COLUMN_ORIGINS
                        .iter()
                        .any(|(f, c, _)| *f == sheet.name && c == header),
                    "la colonna «{header}» del foglio «{}» non dichiara la propria origine",
                    sheet.name
                );
                viste.insert((sheet.name.clone(), header.clone()));
            }
        }
        for (foglio, colonna, _) in super::COLUMN_ORIGINS {
            assert!(
                viste.contains(&((*foglio).to_owned(), (*colonna).to_owned())),
                "l'origine è dichiarata per «{colonna}» di «{foglio}», che non esiste più"
            );
        }

        let finito = compose(&input(
            &report_id, &profile, &snapshot, &operator, &session, &contents,
        ));
        let contenuti = finito
            .sheets
            .iter()
            .find(|foglio| foglio.name == "03 — Contenuti")
            .expect("il foglio dei contenuti deve esistere");
        assert!(
            contenuti
                .headers
                .contains(&String::from("Livello [calcolato]"))
        );
        assert!(
            contenuti
                .headers
                .contains(&String::from("Testo [osservato]"))
        );
        assert!(
            contenuti
                .headers
                .contains(&String::from("Revisione [operatore]"))
        );
        assert!(
            !contenuti.headers.iter().any(|h| h.starts_with("Origine")),
            "il modo di acquisizione non si chiama «Origine»: l'origine è un altro asse"
        );
    }

    #[test]
    fn nothing_disappears_for_lack_of_an_alert() {
        // **Il criterio del registro.** Il foglio dei contenuti riporta tutto
        // il monitorato: livello 0 compreso, non selezionati compresi, senza
        // alert compresi. Un registro che mostrasse solo cio' che ha superato
        // una soglia direbbe che il resto non e' stato guardato.
        let report_id = ReportId::from_sequence(2026, 1);
        let profile = ReportTemplateProfile::default();
        let snapshot = snapshot(&[3], &[1, 2, 3, 4, 5]);
        let operator = Actor::try_new("operatore").expect("attore valido");
        let session = session();
        let contents = [
            content(1, 0, false, "livello zero"),
            content(2, 0, false, "un altro livello zero"),
            content(3, 4, true, "selezionato"),
            content(4, 1, false, "non selezionato"),
            content(5, 2, false, "nemmeno questo"),
        ];

        let ledger = compose(&input(
            &report_id, &profile, &snapshot, &operator, &session, &contents,
        ));

        let foglio = ledger
            .sheets
            .iter()
            .find(|sheet| sheet.name == "03 — Contenuti")
            .expect("il foglio dei contenuti deve esistere");
        assert_eq!(
            foglio.rows.len(),
            5,
            "il registro ha perso dei record: rappresenta tutto il monitorato"
        );

        let livelli_zero = foglio
            .rows
            .iter()
            .filter(|riga| riga[6] == Cell::Number(0))
            .count();
        assert_eq!(livelli_zero, 2, "i contenuti di livello 0 devono restare");
    }

    #[test]
    fn a_content_never_reviewed_says_so_instead_of_leaving_a_blank() {
        // Una cella vuota in un foglio di calcolo si legge come «zero»,
        // «nessuno» o «dimenticato», e le tre cose sono diverse.
        let report_id = ReportId::from_sequence(2026, 1);
        let profile = ReportTemplateProfile::default();
        let snapshot = snapshot(&[], &[1]);
        let operator = Actor::try_new("operatore").expect("attore valido");
        let session = session();
        let contents = [content(1, 0, false, "testo")];

        let ledger = compose(&input(
            &report_id, &profile, &snapshot, &operator, &session, &contents,
        ));

        let foglio = ledger
            .sheets
            .iter()
            .find(|sheet| sheet.name == "03 — Contenuti")
            .expect("il foglio dei contenuti deve esistere");
        assert_eq!(
            foglio.rows[0][7],
            Cell::Text(String::from(crate::report_narrative::NOT_REVIEWED))
        );
    }

    #[test]
    fn the_faults_sheet_exists_even_with_nothing_to_report() {
        // Un registro senza questo foglio lascerebbe credere che non ci siano
        // stati problemi; un foglio vuoto dice che non ne sono stati
        // registrati. Sono due affermazioni diverse.
        let report_id = ReportId::from_sequence(2026, 1);
        let profile = ReportTemplateProfile::default();
        let snapshot = snapshot(&[], &[1]);
        let operator = Actor::try_new("operatore").expect("attore valido");
        let session = session();
        let contents = [content(1, 0, false, "testo")];

        let ledger = compose(&input(
            &report_id, &profile, &snapshot, &operator, &session, &contents,
        ));

        let foglio = ledger
            .sheets
            .iter()
            .find(|sheet| sheet.name == "06 — Errori")
            .expect("il foglio delle anomalie deve esistere anche vuoto");
        assert!(foglio.rows.is_empty());
        assert!(!foglio.headers.is_empty());
    }

    #[test]
    fn the_body_of_a_message_stays_a_text_cell() {
        // La cella che porta il testo remoto deve essere `Body`, sempre, e
        // `Body` e' un testo: e' su questa distinzione che il renderer
        // neutralizza le formule: se un corpo finisse in una cella `Number` la
        // neutralizzazione non avrebbe niente su cui agire.
        //
        // `Body` invece di `Text` da FINAL-PRODUCT-REVIEW-01 (FPR-05): dice al
        // registro in testo semplice che questa, e nessun'altra, e' la cella
        // che si puo' accorciare, perche' e' l'unica riportata per intero in
        // altri due documenti.
        let report_id = ReportId::from_sequence(2026, 1);
        let profile = ReportTemplateProfile::default();
        let snapshot = snapshot(&[], &[1]);
        let operator = Actor::try_new("operatore").expect("attore valido");
        let session = session();
        let contents = [content(1, 0, false, "=SOMMA(A1:A9)")];

        let ledger = compose(&input(
            &report_id, &profile, &snapshot, &operator, &session, &contents,
        ));

        let foglio = ledger
            .sheets
            .iter()
            .find(|sheet| sheet.name == "03 — Contenuti")
            .expect("il foglio dei contenuti deve esistere");

        // La colonna si cerca per **intestazione**, non per indice.
        //
        // L'indice era 10, e CTX-01 ha inserito una colonna prima: la prova e'
        // diventata rossa leggendo la cella sbagliata, e aveva ragione a
        // rompersi. Ma il difetto che segnalava non c'era — era il proprio
        // appiglio a essersi spostato.
        //
        // Cercare per nome toglie di mezzo quel falso allarme e lascia intatto
        // quello vero: se il corpo smettesse di essere una cella di testo, la
        // prova resterebbe rossa per la ragione giusta.
        let colonna = foglio
            .headers
            .iter()
            .position(|intestazione| intestazione == "Testo [osservato]")
            .expect("il foglio dei contenuti deve avere una colonna «Testo»");

        assert_eq!(
            foglio.rows[0][colonna],
            Cell::Body(String::from("=SOMMA(A1:A9)")),
            "il corpo non e' piu' la cella del corpo: la neutralizzazione delle \
             formule perderebbe il suo appiglio"
        );
        assert_eq!(
            foglio.rows[0][colonna].as_text(),
            "=SOMMA(A1:A9)",
            "il corpo deve restare leggibile come testo"
        );
    }

    #[test]
    fn the_integrity_sheet_carries_one_digest_per_content() {
        let report_id = ReportId::from_sequence(2026, 1);
        let profile = ReportTemplateProfile::default();
        let snapshot = snapshot(&[], &[1, 2]);
        let operator = Actor::try_new("operatore").expect("attore valido");
        let session = session();
        let contents = [
            content(1, 0, false, "primo"),
            content(2, 0, false, "secondo"),
        ];

        let ledger = compose(&input(
            &report_id, &profile, &snapshot, &operator, &session, &contents,
        ));

        let foglio = ledger
            .sheets
            .iter()
            .find(|sheet| sheet.name == "09 — Integrità")
            .expect("il foglio dell'integrita' deve esistere");
        assert_eq!(foglio.rows.len(), 2);
        assert_ne!(
            foglio.rows[0][1], foglio.rows[1][1],
            "due corpi diversi devono avere impronte diverse"
        );
    }

    #[test]
    fn the_session_sheet_carries_both_numbers_and_not_just_the_selected_one() {
        // «12 selezionati» da solo non dice niente: e' la coppia a dire
        // qualcosa, ed e' la stessa ragione per cui la schermata Report mostra
        // sempre monitorati e selezionati insieme.
        let report_id = ReportId::from_sequence(2026, 1);
        let profile = ReportTemplateProfile::default();
        let snapshot = snapshot(&[2], &[1, 2, 3]);
        let operator = Actor::try_new("operatore").expect("attore valido");
        let session = session();
        let contents = [
            content(1, 0, false, "a"),
            content(2, 3, true, "b"),
            content(3, 0, false, "c"),
        ];

        let ledger = compose(&input(
            &report_id, &profile, &snapshot, &operator, &session, &contents,
        ));

        let foglio = &ledger.sheets[0];
        let testo: String = foglio
            .rows
            .iter()
            .map(|riga| format!("{}={}", riga[0].as_text(), riga[1].as_text()))
            .collect::<Vec<_>>()
            .join("|");
        assert!(testo.contains("Contenuti monitorati=3"));
        assert!(testo.contains("Contenuti selezionati per la relazione=1"));
    }
}

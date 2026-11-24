//! Che cosa la revisione umana dice dei dizionari.
//!
//! Ogni volta che una persona conclude l'esame di un contenuto segnalato,
//! esprime — senza volerlo — un giudizio sulle **regole** che lo avevano
//! segnalato. «Non rilevante» su un contenuto trovato da un termine dice
//! qualcosa di quel termine. Una volta non dice nulla; venti volte sì.
//!
//! Questo modulo raccoglie quei giudizi e li ordina per dizionario, versione,
//! regola e categoria. Non fa altro, e le due cose che **non** fa sono la
//! ragione per cui esiste separato.
//!
//! # NEXUM suggerisce, e non modifica mai un dizionario
//!
//! È la regola del piano, alla lettera. La garanzia però non è una regola: è
//! la **forma del suggerimento**.
//!
//! Un suggerimento qui non contiene un valore nuovo. Non dice «porta il
//! livello da 3 a 1», non dice «togli questo termine», non propone alcuna
//! modifica applicabile. Dice **quale regola guardare** e **che cosa hanno
//! deciso le persone**, e si ferma.
//!
//! Non è una sfumatura di linguaggio. Un suggerimento che contenesse il valore
//! nuovo sarebbe una modifica in attesa di un pulsante, e prima o poi il
//! pulsante lo aggiungerebbe qualcuno: accanto a un numero che sembra già
//! calcolato, premerlo costa niente. **Poiché il valore nuovo non esiste, non
//! c'è nulla da applicare.** Chi vuole cambiare una regola la compone nel Rule
//! Lab, la confronta, e la pubblica altrove — LAB-02 ha già stabilito che la
//! pubblicazione non si compie accanto a un esito che sembrava buono.
//!
//! # Si contano gli esiti; nessuno riceve un punteggio
//!
//! Qui non compare alcun numero con la virgola. Una regola non «vale 0,73»:
//! quel numero sarebbe una valutazione appresa travestita da statistica, e
//! NEXUM non ne produce (ADR-0048). Ci sono conteggi di fatti registrati —
//! quante decisioni confermano, quante smentiscono, quante non giudicano — e
//! chi legge giudica.
//!
//! Una prova impone che nel sorgente di questo modulo non esistano `f32` né
//! `f64`. Un punteggio non si aggiunge per sbaglio: si aggiunge per comodità.
//!
//! # Questo modulo non conosce l'archivio
//!
//! Come il Rule Lab e come il replay: riceve ciò che è già stato letto e
//! restituisce un'aggregazione. Non importa `Database`, non ne riceve uno, e
//! **non potrebbe modificare un dizionario nemmeno volendo**, perché non ha
//! con che cosa. La lettura sta in [`crate::review::ReviewService`].
//!
//! # Le tre cose che si dichiarano invece di tacerle
//!
//! 1. **Le decisioni ancora da prendere.** «Cinque su cinque non rilevanti»
//!    con quaranta contenuti ancora da esaminare non è ciò che sembra. Ogni
//!    riga porta accanto quanti contenuti aspettano ancora una persona.
//! 2. **Lo stesso termine in più dizionari.** Una decisione compare sotto
//!    **ogni** dizionario che conteneva il termine, perché sotto ognuno è vera;
//!    ma allora i totali delle righe non si sommano al numero dei contenuti, e
//!    va detto invece di lasciarlo scoprire.
//! 3. **L'insieme vuoto.** «Nessuna smentita» su zero decisioni è la stessa
//!    frase pericolosa di «nessuna differenza» su zero contenuti: entrambe
//!    suonano come un esito, e sono l'assenza di una misura (ADR-0053).

use std::collections::{BTreeMap, BTreeSet};

use lisi_core::ContentId;
use lisi_core::id::{DictionaryId, DictionaryVersionId};
use lisi_core::model::ReviewState;
use lisi_core::model::dictionary::ResolvedDictionaryConfiguration;

/// Quante decisioni concluse servono prima che valga la pena di suggerire.
///
/// # Perché una soglia, e perché è dichiarata
///
/// Perché senza soglia il primo «non rilevante» produrrebbe un invito a
/// rivedere la regola, e un invito che arriva sempre non viene più letto.
///
/// Il numero è costante e compare nella frase che l'operatore legge, insieme ai
/// conteggi da cui l'invito nasce: chi non è d'accordo con la soglia vede da sé
/// quante decisioni ci sono e conclude diversamente. Una soglia nascosta
/// sarebbe una regola che nessuno può discutere.
pub const MINIMUM_DECISIONS: u32 = 5;

/// Da dove viene la regola che ha prodotto il riscontro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleOrigin {
    /// Da un dizionario, in una versione precisa.
    Dictionary {
        /// Quale dizionario.
        dictionary_id: DictionaryId,
        /// Quale versione: la stessa regola in due versioni è due regole.
        version_id: DictionaryVersionId,
        /// Nome mostrabile, come l'operatore conosce il dizionario.
        label: String,
    },
    /// Da una parola aggiunta alla singola sessione.
    ///
    /// Non c'è un dizionario da valutare: la parola è finita con la sessione.
    AdHoc,
}

impl RuleOrigin {
    /// Nome mostrabile della provenienza.
    #[must_use]
    pub fn label(&self) -> &str {
        match self {
            Self::Dictionary { label, .. } => label.as_str(),
            Self::AdHoc => "aggiunta alla sessione",
        }
    }

    /// Se esiste un dizionario da aprire nel Rule Lab.
    #[must_use]
    pub const fn is_a_dictionary(&self) -> bool {
        matches!(self, Self::Dictionary { .. })
    }
}

/// Che cosa una decisione umana dice del motore.
///
/// # Perché la definizione non nasce qui
///
/// Perché esiste già in [`ReviewState`], e la usa anche
/// [`crate::review::ReviewService`] per pretendere una motivazione da chi
/// smentisce il motore. Due definizioni della stessa cosa diventerebbero, alla
/// prima aggiunta di uno stato, due cose diverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineJudgement {
    /// La persona ha confermato ciò che il motore aveva segnalato.
    Confirms,
    /// La persona ha smentito il motore.
    Contradicts,
    /// Decisione conclusa che **non** giudica il motore.
    ///
    /// «Archiviato» chiude un esame senza dire se la segnalazione fosse
    /// giusta. Contarlo con le conferme o con le smentite attribuirebbe alla
    /// persona un'opinione che non ha espresso.
    Silent,
}

impl EngineJudgement {
    /// Come si legge una decisione conclusa.
    ///
    /// `None` per gli stati che non sono decisioni: un esame in corso non è un
    /// esito, e trattarlo come tale conterebbe due volte lo stesso contenuto —
    /// una adesso e una quando finirà.
    #[must_use]
    pub const fn of(state: ReviewState) -> Option<Self> {
        if !state.is_decided() {
            return None;
        }
        if state.contradicts_the_engine() {
            return Some(Self::Contradicts);
        }
        if state.confirms_the_engine() {
            return Some(Self::Confirms);
        }
        Some(Self::Silent)
    }
}

/// Un contenuto già letto, come l'aggregazione lo vede.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedContent {
    /// Quale contenuto.
    pub content_id: ContentId,
    /// L'ultima decisione registrata, se qualcuno ha deciso.
    pub decision: Option<ReviewState>,
    /// Le regole che hanno prodotto un riscontro, nella forma normalizzata.
    ///
    /// Possono ripetersi: un termine trovato tre volte in un contenuto è tre
    /// riscontri. L'aggregazione le riduce, perché la decisione è **una**.
    pub rules: Vec<String>,
}

/// Che cosa la revisione dice di una regola, in un dizionario e una versione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleFeedback {
    /// Dizionario e versione, oppure la parola aggiunta alla sessione.
    pub origin: RuleOrigin,
    /// Forma normalizzata: è la chiave con cui riscontri e fotografia si legano.
    pub rule: String,
    /// Il termine come l'operatore lo conosce.
    pub display: String,
    /// Categoria dichiarata dal dizionario.
    pub category: String,
    /// Se lo stesso termine viene anche da un'altra provenienza.
    pub shared: bool,
    /// Decisioni che confermano il motore.
    pub confirming: u32,
    /// Decisioni che lo smentiscono.
    pub contradicting: u32,
    /// Decisioni concluse che non lo giudicano.
    pub silent: u32,
    /// Contenuti in cui la regola ha inciso e che nessuno ha ancora deciso.
    pub undecided: u32,
}

impl RuleFeedback {
    /// Quante decisioni concluse riguardano questa regola.
    #[must_use]
    pub const fn decided(&self) -> u32 {
        self.confirming + self.contradicting + self.silent
    }

    /// In quanti contenuti la regola ha inciso, decisi o no.
    #[must_use]
    pub const fn touched(&self) -> u32 {
        self.decided() + self.undecided
    }

    /// Se le smentite superano le conferme.
    ///
    /// È un **confronto fra due conteggi**, non un punteggio: entrambi i
    /// numeri restano visibili accanto, e chi legge può concludere altro.
    #[must_use]
    pub const fn contradicted_more_than_confirmed(&self) -> bool {
        self.contradicting > self.confirming
    }

    /// Quale regola, di quale categoria, da quale dizionario e versione.
    #[must_use]
    pub fn identity(&self) -> String {
        format!(
            "\u{ab}{}\u{bb} ({}, {})",
            self.display,
            self.category,
            self.origin.label()
        )
    }

    /// I conteggi, e la copertura che li qualifica.
    ///
    /// Numeri interi di fatti registrati: nessuna proporzione, nessuna media,
    /// nessun numero con la virgola. Chi legge giudica.
    #[must_use]
    pub fn counts_sentence(&self) -> String {
        if self.decided() == 0 {
            return format!(
                "Nessuna decisione conclusa. {} \u{2014} non c'\u{e8} ancora nulla da leggere.",
                self.contenuti_toccati(),
            );
        }

        format!(
            "{} confermano il motore, {} lo smentiscono, {} non lo giudicano. {}.",
            self.confirming,
            self.contradicting,
            self.silent,
            self.contenuti_toccati(),
        )
    }

    /// Che cosa la revisione dice di questa regola, in una frase sola.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        format!("{}: {}", self.identity(), self.counts_sentence())
    }

    /// La copertura: quanti contenuti, e quanti aspettano ancora una persona.
    fn contenuti_toccati(&self) -> String {
        let toccati = match self.touched() {
            1 => String::from("Un contenuto"),
            altri => format!("{altri} contenuti"),
        };
        match self.undecided {
            0 => format!("{toccati}, tutti decisi"),
            1 => format!("{toccati}, di cui uno ancora da esaminare"),
            aperti => format!("{toccati}, di cui {aperti} ancora da esaminare"),
        }
    }

    /// Il suggerimento, quando ce n'è uno.
    ///
    /// # Le tre condizioni, tutte necessarie
    ///
    /// 1. la regola viene da un **dizionario**: una parola aggiunta alla
    ///    sessione non ha nulla da rivedere, è finita con la sessione;
    /// 2. le decisioni concluse sono almeno [`MINIMUM_DECISIONS`];
    /// 3. le smentite **superano** le conferme.
    ///
    /// Fuori da qui NEXUM non dice niente, ed è la scelta giusta: un invito che
    /// compare sempre smette di essere un invito.
    #[must_use]
    pub fn suggestion(&self) -> Option<Suggestion> {
        if !self.origin.is_a_dictionary() {
            return None;
        }
        if self.decided() < MINIMUM_DECISIONS {
            return None;
        }
        if !self.contradicted_more_than_confirmed() {
            return None;
        }
        Some(Suggestion {
            rule: self.rule.clone(),
            display: self.display.clone(),
            origin_label: self.origin.label().to_owned(),
            contradicting: self.contradicting,
            confirming: self.confirming,
        })
    }
}

/// L'invito a guardare una regola.
///
/// # Che cosa non c'è dentro
///
/// **Nessun valore nuovo.** Nessun livello proposto, nessun termine da
/// togliere, nessuna modifica applicabile: soltanto l'identità della regola e i
/// conteggi da cui l'invito nasce.
///
/// È la garanzia strutturale della milestone. Un suggerimento che portasse il
/// valore nuovo sarebbe una modifica in attesa di un pulsante; poiché il valore
/// nuovo non esiste, **non c'è nulla da applicare** — e nessuno può aggiungere
/// il pulsante senza prima aggiungere il campo, che una prova impedisce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    /// Forma normalizzata della regola da guardare.
    pub rule: String,
    /// Il termine come l'operatore lo conosce.
    pub display: String,
    /// Dizionario e versione da cui viene.
    pub origin_label: String,
    /// Quante decisioni concluse smentiscono il motore.
    pub contradicting: u32,
    /// Quante lo confermano.
    pub confirming: u32,
}

impl Suggestion {
    /// L'invito, come l'operatore lo legge.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        format!(
            "Valuta la regola \u{ab}{}\u{bb} di {} nel «Laboratorio regole»: su {} decisioni concluse, {} \
             smentiscono la segnalazione e {} la confermano. NEXUM non modifica alcun \
             dizionario: che cosa cambiare, e se cambiarlo, lo decide una persona.",
            self.display,
            self.origin_label,
            self.contradicting + self.confirming,
            self.contradicting,
            self.confirming,
        )
    }
}

/// L'aggregazione, per una sessione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DictionaryFeedback {
    /// Le regole, in ordine stabile: dizionario, regola, categoria.
    pub rules: Vec<RuleFeedback>,
    /// Contenuti passati all'aggregazione.
    pub examined_contents: u32,
    /// Contenuti con una decisione conclusa.
    pub decided_contents: u32,
    /// Regole riscontrate che la fotografia della sessione non conosce.
    ///
    /// Non si possono attribuire ad alcun dizionario, e scartarle in silenzio
    /// farebbe sembrare completo un quadro che non lo è.
    pub rules_without_origin: u32,
    /// Se almeno una regola viene da più di una provenienza.
    ///
    /// Quando è vero i totali delle righe **non** si sommano al numero dei
    /// contenuti, e la frase dell'esito lo dice.
    pub has_shared_rules: bool,
}

impl DictionaryFeedback {
    /// Se non c'è alcuna decisione conclusa da leggere.
    #[must_use]
    pub const fn says_nothing(&self) -> bool {
        self.decided_contents == 0
    }

    /// I suggerimenti, nell'ordine delle regole.
    #[must_use]
    pub fn suggestions(&self) -> Vec<Suggestion> {
        self.rules
            .iter()
            .filter_map(RuleFeedback::suggestion)
            .collect()
    }

    /// Che cosa l'aggregazione dice, compreso quando non dice nulla.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        if self.examined_contents == 0 {
            return String::from(
                "Nessun contenuto con riscontri in questa sessione: non c'\u{e8} nulla da \
                 aggregare. Non significa che i dizionari vadano bene \u{2014} significa che \
                 nessuno li ha ancora messi alla prova.",
            );
        }

        if self.says_nothing() {
            return format!(
                "{} con riscontri, e nessuna revisione conclusa. Non si pu\u{f2} dire che i \
                 dizionari stiano funzionando: non \u{e8} stato misurato.",
                contenuti(self.examined_contents),
            );
        }

        let mut frase = format!(
            "{} con riscontri, {} con una decisione conclusa, su {} fra regola, dizionario e \
             versione.",
            contenuti(self.examined_contents),
            self.decided_contents,
            self.combinazioni(),
        );

        if self.has_shared_rules {
            frase.push_str(
                " Un termine presente in pi\u{f9} dizionari compare sotto ciascuno: i totali \
                 delle righe non si sommano al numero dei contenuti.",
            );
        }
        if self.rules_without_origin > 0 {
            frase.push_str(&format!(
                " {} riscontrate non compaiono nella fotografia della sessione e non sono \
                 attribuibili ad alcun dizionario.",
                regole(self.rules_without_origin),
            ));
        }
        frase
    }

    fn combinazioni(&self) -> String {
        match self.rules.len() {
            1 => String::from("una combinazione"),
            altre => format!("{altre} combinazioni"),
        }
    }
}

fn contenuti(quanti: u32) -> String {
    match quanti {
        1 => String::from("Un contenuto"),
        altri => format!("{altri} contenuti"),
    }
}

fn regole(quante: u32) -> String {
    match quante {
        1 => String::from("Una regola"),
        altre => format!("{altre} regole"),
    }
}

/// Chiave di aggregazione: provenienza, regola, categoria.
type AggregationKey = (String, String, String);

/// Aggrega gli esiti della revisione per dizionario, versione, regola e categoria.
///
/// # Che cosa entra, e che cosa no
///
/// Entrano i contenuti **con almeno un riscontro**: senza riscontri non c'è
/// alcuna regola a cui attribuire la decisione. Entra la fotografia della
/// sessione, che è l'unica cosa che sappia da quale dizionario e in quale
/// versione un termine veniva: rileggere i dizionari di oggi attribuirebbe le
/// decisioni di ieri a regole che nel frattempo sono cambiate.
///
/// # Non scrive nulla
///
/// Non può: non conosce l'archivio.
#[must_use]
pub fn aggregate(
    contents: &[ReviewedContent],
    configuration: &ResolvedDictionaryConfiguration,
) -> DictionaryFeedback {
    let mut per_chiave: BTreeMap<AggregationKey, RuleFeedback> = BTreeMap::new();
    let mut senza_provenienza: BTreeSet<String> = BTreeSet::new();
    let mut decisi = 0_u32;
    let mut condivise = false;

    for content in contents {
        let giudizio = content.decision.and_then(EngineJudgement::of);
        if giudizio.is_some() {
            decisi += 1;
        }

        // Un termine trovato tre volte in un contenuto resta **una** regola: la
        // decisione della persona è una sola, e contarla tre volte
        // moltiplicherebbe l'opinione di chi ha esaminato un testo ripetitivo.
        let regole_distinte: BTreeSet<&str> = content.rules.iter().map(String::as_str).collect();

        for regola in regole_distinte {
            let Some(term) = configuration
                .terms
                .iter()
                .find(|term| term.normalised == regola)
            else {
                senza_provenienza.insert(regola.to_owned());
                continue;
            };

            let shared = term.is_shared();
            condivise |= shared;

            for provenance in &term.provenances {
                let origin = match (provenance.dictionary_id, provenance.version_id) {
                    (Some(dictionary_id), Some(version_id)) => RuleOrigin::Dictionary {
                        dictionary_id,
                        version_id,
                        label: provenance.label.clone(),
                    },
                    _ => RuleOrigin::AdHoc,
                };

                let chiave = (
                    origin.label().to_owned(),
                    regola.to_owned(),
                    term.category.as_str().to_owned(),
                );

                let riga = per_chiave.entry(chiave).or_insert_with(|| RuleFeedback {
                    origin,
                    rule: regola.to_owned(),
                    display: term.original.as_str().to_owned(),
                    category: term.category.as_str().to_owned(),
                    shared,
                    confirming: 0,
                    contradicting: 0,
                    silent: 0,
                    undecided: 0,
                });

                match giudizio {
                    Some(EngineJudgement::Confirms) => riga.confirming += 1,
                    Some(EngineJudgement::Contradicts) => riga.contradicting += 1,
                    Some(EngineJudgement::Silent) => riga.silent += 1,
                    None => riga.undecided += 1,
                }
            }
        }
    }

    DictionaryFeedback {
        rules: per_chiave.into_values().collect(),
        examined_contents: u32::try_from(contents.len()).unwrap_or(u32::MAX),
        decided_contents: decisi,
        rules_without_origin: u32::try_from(senza_provenienza.len()).unwrap_or(u32::MAX),
        has_shared_rules: condivise,
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::ContentId;
    use lisi_core::id::{DictionaryId, DictionaryVersionId};
    use lisi_core::model::ReviewState;
    use lisi_core::model::dictionary::{
        MatchMode, ResolvedDictionaryConfiguration, ResolvedTerm, TermProvenance,
    };
    use lisi_core::text::{DictionaryName, LanguageTag, TermCategory, TermText};

    use super::{MINIMUM_DECISIONS, ReviewedContent, RuleOrigin, aggregate};

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("feedback.rs");

    /// Il codice di produzione senza i commenti.
    fn codice_senza_commenti() -> String {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Il blocco di una dichiarazione, dal nome alla graffa che la chiude.
    fn blocco_di(nome: &str) -> String {
        let produzione = codice_senza_commenti();
        let Some(inizio) = produzione.find(nome) else {
            panic!("il modulo deve dichiarare {nome}");
        };
        let resto = &produzione[inizio..];
        let Some(fine) = resto.find("\n}\n") else {
            panic!("la dichiarazione {nome} deve chiudersi");
        };
        resto[..fine].to_owned()
    }

    fn provenienza(nome: &str, dizionario: i64, versione: i64, numero: u32) -> TermProvenance {
        let Ok(nome) = DictionaryName::try_new(nome) else {
            panic!("il nome di prova deve essere valido");
        };
        TermProvenance::from_dictionary(
            DictionaryId::new(dizionario),
            DictionaryVersionId::new(versione),
            &nome,
            numero,
        )
    }

    fn termine(
        normalised: &str,
        categoria: &str,
        provenienze: Vec<TermProvenance>,
    ) -> ResolvedTerm {
        let (Ok(original), Ok(language), Ok(category)) = (
            TermText::try_new(normalised),
            LanguageTag::try_new("it"),
            TermCategory::try_new(categoria),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        ResolvedTerm {
            normalised: normalised.to_owned(),
            original,
            category,
            language,
            match_mode: MatchMode::NormalizedWord,
            suggested_level: 2,
            provenances: provenienze,
        }
    }

    fn configurazione(termini: Vec<ResolvedTerm>) -> ResolvedDictionaryConfiguration {
        ResolvedDictionaryConfiguration::from_terms(termini)
    }

    fn contenuto(id: i64, decisione: Option<ReviewState>, regole: &[&str]) -> ReviewedContent {
        ReviewedContent {
            content_id: ContentId::new(id),
            decision: decisione,
            rules: regole.iter().map(|regola| (*regola).to_owned()).collect(),
        }
    }

    /// Contenuti tutti decisi allo stesso modo, su una sola regola.
    fn contenuti(quanti: i64, decisione: ReviewState, regola: &str) -> Vec<ReviewedContent> {
        (1..=quanti)
            .map(|id| contenuto(id, Some(decisione), &[regola]))
            .collect()
    }

    /// **NEXUM non ha alcun modo di modificare un dizionario.**
    ///
    /// La garanzia non è il divieto scritto nel piano: è che questo modulo non
    /// conosce l'archivio. Non importa `Database`, non ne riceve uno, e non
    /// potrebbe scrivere nemmeno volendo — la stessa forma di LAB-01.
    #[test]
    fn il_riscontro_non_ha_alcun_modo_di_modificare_un_dizionario() {
        let produzione = codice_senza_commenti();
        assert!(
            !produzione.contains("lisi_storage"),
            "l'aggregazione non deve conoscere la persistenza"
        );
        assert!(
            !produzione.contains("Database"),
            "l'aggregazione non deve poter scrivere"
        );
    }

    /// **Il suggerimento non porta mai un valore nuovo.**
    ///
    /// È la garanzia strutturale della milestone. Un suggerimento che dicesse
    /// «porta il livello da 3 a 1» sarebbe una modifica in attesa di un
    /// pulsante; poiché il valore nuovo non esiste, non c'è nulla da applicare.
    #[test]
    fn il_suggerimento_non_porta_mai_un_valore_nuovo() {
        let blocco = blocco_di("pub struct Suggestion {");
        for vietato in [
            "level", "livello", "value", "valore", "proposed", "proposta", "apply", "applica",
        ] {
            assert!(
                !blocco.contains(vietato),
                "il suggerimento non deve contenere «{vietato}»: sarebbe una modifica in attesa \
                 di un pulsante"
            );
        }
    }

    /// **Nessun punteggio: si contano gli esiti.**
    ///
    /// Un numero che dicesse «questa regola vale 0,73» sarebbe una valutazione
    /// appresa travestita da statistica. Un punteggio non si aggiunge per
    /// sbaglio: si aggiunge per comodità, ed è quella comodità che questa
    /// guardia toglie.
    #[test]
    fn nessun_numero_con_la_virgola_puo_entrare_in_questo_modulo() {
        let produzione = codice_senza_commenti();
        for vietato in ["f32", "f64", "as f", "percent", "punteggio", "score"] {
            assert!(
                !produzione.contains(vietato),
                "«{vietato}» apre la strada a un punteggio della regola"
            );
        }
    }

    /// Una decisione sola non dice nulla di una regola.
    #[test]
    fn sotto_la_soglia_nessun_invito_compare() {
        let configurazione = configurazione(vec![termine(
            "assalto",
            "violenza",
            vec![provenienza("Ordine pubblico", 7, 3, 2)],
        )]);
        let esito = aggregate(
            &contenuti(2, ReviewState::NotRelevant, "assalto"),
            &configurazione,
        );

        assert_eq!(esito.rules.len(), 1);
        assert_eq!(esito.rules[0].contradicting, 2);
        assert!(
            esito.suggestions().is_empty(),
            "due decisioni non bastano a invitare a rivedere una regola"
        );
    }

    /// Sopra la soglia, con più smentite che conferme, l'invito compare — e
    /// porta con sé i conteggi da cui nasce.
    #[test]
    fn sopra_la_soglia_l_invito_compare_e_mostra_i_numeri() {
        let configurazione = configurazione(vec![termine(
            "assalto",
            "violenza",
            vec![provenienza("Ordine pubblico", 7, 3, 2)],
        )]);
        let quanti = i64::from(MINIMUM_DECISIONS);
        let esito = aggregate(
            &contenuti(quanti, ReviewState::NotRelevant, "assalto"),
            &configurazione,
        );

        let inviti = esito.suggestions();
        assert_eq!(inviti.len(), 1);

        let frase = inviti[0].as_sentence();
        assert!(frase.contains("Laboratorio regole"), "{frase}");
        assert!(frase.contains("non modifica alcun dizionario"), "{frase}");
        assert!(
            frase.contains(&MINIMUM_DECISIONS.to_string()),
            "l'invito deve mostrare su quante decisioni si fonda: {frase}"
        );
    }

    /// Tante conferme quante smentite non sono un segnale.
    #[test]
    fn con_altrettante_conferme_non_si_invita_a_nulla() {
        let configurazione = configurazione(vec![termine(
            "assalto",
            "violenza",
            vec![provenienza("Ordine pubblico", 7, 3, 2)],
        )]);
        let mut contenuti_misti = contenuti(3, ReviewState::NotRelevant, "assalto");
        for id in 4..=6 {
            contenuti_misti.push(contenuto(id, Some(ReviewState::Relevant), &["assalto"]));
        }
        let esito = aggregate(&contenuti_misti, &configurazione);

        assert_eq!(esito.rules[0].contradicting, 3);
        assert_eq!(esito.rules[0].confirming, 3);
        assert!(
            esito.suggestions().is_empty(),
            "un pareggio non è un motivo per rivedere una regola"
        );
    }

    /// Una parola aggiunta alla sessione non ha un dizionario da rivedere.
    #[test]
    fn una_parola_della_sessione_non_manda_nessuno_nel_rule_lab() {
        let configurazione = configurazione(vec![termine(
            "assalto",
            "violenza",
            vec![TermProvenance::ad_hoc()],
        )]);
        let esito = aggregate(
            &contenuti(20, ReviewState::NotRelevant, "assalto"),
            &configurazione,
        );

        assert_eq!(esito.rules.len(), 1);
        assert_eq!(esito.rules[0].origin, RuleOrigin::AdHoc);
        assert_eq!(esito.rules[0].contradicting, 20);
        assert!(
            esito.suggestions().is_empty(),
            "la parola è finita con la sessione: non c'è nulla da valutare nel Rule Lab"
        );
    }

    /// **Un esame in corso non è un esito.**
    ///
    /// Contarlo come tale conterebbe due volte lo stesso contenuto: una adesso
    /// e una quando la persona avrà finito.
    #[test]
    fn un_esame_in_corso_non_e_un_esito() {
        let configurazione = configurazione(vec![termine(
            "assalto",
            "violenza",
            vec![provenienza("Ordine pubblico", 7, 3, 2)],
        )]);
        let esito = aggregate(
            &[
                contenuto(1, Some(ReviewState::InReview), &["assalto"]),
                contenuto(2, Some(ReviewState::New), &["assalto"]),
                contenuto(3, None, &["assalto"]),
            ],
            &configurazione,
        );

        let riga = &esito.rules[0];
        assert_eq!(riga.decided(), 0);
        assert_eq!(riga.undecided, 3);
        assert_eq!(esito.decided_contents, 0);
        assert!(esito.says_nothing());
    }

    /// «Archiviato» chiude un esame senza dire se il motore avesse ragione.
    #[test]
    fn archiviato_non_giudica_il_motore() {
        let configurazione = configurazione(vec![termine(
            "assalto",
            "violenza",
            vec![provenienza("Ordine pubblico", 7, 3, 2)],
        )]);
        let esito = aggregate(
            &contenuti(4, ReviewState::Archived, "assalto"),
            &configurazione,
        );

        let riga = &esito.rules[0];
        assert_eq!(riga.silent, 4);
        assert_eq!(riga.confirming, 0);
        assert_eq!(riga.contradicting, 0);
        assert_eq!(riga.decided(), 4);
    }

    /// **Su zero decisioni non si dice che non ci sono smentite.**
    ///
    /// È la stessa frase pericolosa di «nessuna differenza» su zero contenuti:
    /// suona come un esito, ed è l'assenza di una misura.
    #[test]
    fn su_zero_decisioni_l_esito_dichiara_di_non_aver_misurato() {
        let configurazione = configurazione(vec![termine(
            "assalto",
            "violenza",
            vec![provenienza("Ordine pubblico", 7, 3, 2)],
        )]);
        let esito = aggregate(&[contenuto(1, None, &["assalto"])], &configurazione);

        let frase = esito.as_sentence();
        assert!(esito.says_nothing());
        assert!(frase.contains("non è stato misurato"), "{frase}");
        assert!(
            !frase.contains("nessuna smentita"),
            "l'assenza di misura non è un esito favorevole: {frase}"
        );
    }

    /// Senza contenuti, l'aggregazione dice che nessuno ha messo alla prova i
    /// dizionari — non che vadano bene.
    #[test]
    fn senza_contenuti_non_si_dice_che_i_dizionari_vanno_bene() {
        let configurazione = configurazione(vec![termine(
            "assalto",
            "violenza",
            vec![provenienza("Ordine pubblico", 7, 3, 2)],
        )]);
        let esito = aggregate(&[], &configurazione);

        let frase = esito.as_sentence();
        assert!(esito.rules.is_empty());
        assert!(frase.contains("nulla da aggregare"), "{frase}");
        assert!(
            frase.contains("nessuno li ha ancora messi alla prova"),
            "{frase}"
        );
    }

    /// **Lo stesso termine in due dizionari conta sotto entrambi, e si dice.**
    ///
    /// Sotto ciascuno la decisione è vera; ma allora i totali delle righe non
    /// si sommano al numero dei contenuti, e chi legge deve saperlo.
    #[test]
    fn un_termine_condiviso_conta_sotto_ogni_dizionario_e_lo_dichiara() {
        let configurazione = configurazione(vec![termine(
            "assalto",
            "violenza",
            vec![
                provenienza("Ordine pubblico", 7, 3, 2),
                provenienza("Tematico incendi", 9, 4, 1),
            ],
        )]);
        let esito = aggregate(
            &contenuti(6, ReviewState::NotRelevant, "assalto"),
            &configurazione,
        );

        assert_eq!(esito.rules.len(), 2, "una riga per dizionario");
        assert!(esito.rules.iter().all(|riga| riga.contradicting == 6));
        assert!(esito.rules.iter().all(|riga| riga.shared));
        assert!(esito.has_shared_rules);
        assert!(
            esito.as_sentence().contains("non si sommano"),
            "{}",
            esito.as_sentence()
        );
        assert_eq!(esito.decided_contents, 6, "i contenuti restano sei");
    }

    /// Un termine trovato tre volte in un contenuto resta **una** decisione.
    #[test]
    fn un_termine_ripetuto_nel_contenuto_resta_una_decisione_sola() {
        let configurazione = configurazione(vec![termine(
            "assalto",
            "violenza",
            vec![provenienza("Ordine pubblico", 7, 3, 2)],
        )]);
        let esito = aggregate(
            &[contenuto(
                1,
                Some(ReviewState::NotRelevant),
                &["assalto", "assalto", "assalto"],
            )],
            &configurazione,
        );

        assert_eq!(
            esito.rules[0].contradicting, 1,
            "un testo ripetitivo non moltiplica l'opinione di chi lo ha esaminato"
        );
    }

    /// Una regola che la fotografia non conosce non si attribuisce a nessuno,
    /// e non si scarta in silenzio.
    #[test]
    fn una_regola_senza_provenienza_viene_dichiarata() {
        let configurazione = configurazione(vec![termine(
            "assalto",
            "violenza",
            vec![provenienza("Ordine pubblico", 7, 3, 2)],
        )]);
        let esito = aggregate(
            &[contenuto(
                1,
                Some(ReviewState::Relevant),
                &["assalto", "parola-sconosciuta"],
            )],
            &configurazione,
        );

        assert_eq!(esito.rules.len(), 1);
        assert_eq!(esito.rules_without_origin, 1);
        assert!(
            esito
                .as_sentence()
                .contains("non sono attribuibili ad alcun dizionario"),
            "{}",
            esito.as_sentence()
        );
    }

    /// Ogni riga dice quanti contenuti aspettano ancora una persona.
    ///
    /// «Cinque su cinque non rilevanti» con quaranta ancora da esaminare non è
    /// ciò che sembra.
    #[test]
    fn ogni_riga_dice_quanti_contenuti_aspettano_ancora_una_persona() {
        let configurazione = configurazione(vec![termine(
            "assalto",
            "violenza",
            vec![provenienza("Ordine pubblico", 7, 3, 2)],
        )]);
        let mut misti = contenuti(2, ReviewState::NotRelevant, "assalto");
        for id in 3..=7 {
            misti.push(contenuto(id, None, &["assalto"]));
        }
        let esito = aggregate(&misti, &configurazione);

        let riga = &esito.rules[0];
        assert_eq!(riga.decided(), 2);
        assert_eq!(riga.undecided, 5);
        assert_eq!(riga.touched(), 7);
        assert!(
            riga.as_sentence().contains("5 ancora da esaminare"),
            "{}",
            riga.as_sentence()
        );
    }

    /// Due esecuzioni sugli stessi fatti danno lo stesso esito.
    #[test]
    fn due_esecuzioni_danno_lo_stesso_esito() {
        let configurazione = configurazione(vec![
            termine(
                "assalto",
                "violenza",
                vec![provenienza("Ordine pubblico", 7, 3, 2)],
            ),
            termine("corteo", "ordine", vec![provenienza("Tematico", 9, 4, 1)]),
        ]);
        let ingresso = vec![
            contenuto(1, Some(ReviewState::NotRelevant), &["assalto", "corteo"]),
            contenuto(2, Some(ReviewState::Relevant), &["corteo"]),
            contenuto(3, None, &["assalto"]),
        ];

        assert_eq!(
            aggregate(&ingresso, &configurazione),
            aggregate(&ingresso, &configurazione)
        );
    }
}

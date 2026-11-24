//! Contenuti che si somigliano, e **perché** si somigliano.
//!
//! # L'algoritmo, e perché questo (ADR-0055)
//!
//! **Jaccard esatto su n-grammi di tre parole normalizzate.** Il congelamento
//! ne nominava quattro; due — SimHash e MinHash — non possono dire perché, per
//! costruzione: confrontano impronte e stime, non contenuti, e buttano via
//! l'evidenza per tenere un numero. Il quarto, Jaccard sui soli token, perde
//! l'ordine e considera identici «il cane morde l'uomo» e «l'uomo morde il
//! cane».
//!
//! Le sequenze condivise **sono** l'esito: si possono leggere, e chi legge
//! giudica.
//!
//! # La garanzia strutturale: una somiglianza senza il perché non si scrive
//!
//! [`Resemblance`] ha i campi **privati** e un costruttore che restituisce
//! `None` quando le sequenze condivise sono zero. Non esiste un valore di
//! questo tipo che non porti con sé la propria evidenza.
//!
//! Il modo naturale in cui questa capacità si degraderebbe è che qualcuno
//! aggiunga un percorso rapido che calcola il numero senza conservare le
//! sequenze — «tanto il numero basta». Da lì l'evidenza diventa facoltativa,
//! poi assente, e il risultato smette di essere spiegabile senza che nessuna
//! riga lo dichiari.
//!
//! # «Si somigliano» non è «è un duplicato»
//!
//! `ReviewState::Duplicate` esiste già ed è **la decisione di una persona**,
//! presa con motivo, istante e audit. Questo modulo dice che due contenuti si
//! somigliano e quanto; che siano la stessa cosa lo stabilisce una persona.
//!
//! Il modulo **non conosce `ReviewState`**, e una prova lo impone.
//!
//! # La percentuale c'è, ma non è mai sola
//!
//! Si calcola in aritmetica intera e compare sempre accanto ai due conteggi da
//! cui nasce. Nessun `f32` e nessun `f64`: un numero con la virgola non
//! misurerebbe niente di più e introdurrebbe il valore che qualcuno finirebbe
//! per citare come «somiglianza 0,87» — cioè un punteggio (ADR-0048).
//!
//! # Questo modulo non conosce l'archivio
//!
//! Come il Rule Lab, il replay, il riscontro sui dizionari e le due analisi
//! temporali: riceve contenuti già letti e restituisce un confronto.

use std::collections::BTreeSet;

use lisi_core::model::dictionary::normalise_for_matching;
use lisi_core::{ContentId, Timestamp};

/// Quante parole compongono una sequenza confrontata.
///
/// # Perché tre
///
/// Due parole producono sequenze così comuni — «per il», «e la» — che due testi
/// qualunque ne condividono molte, e la somiglianza perderebbe significato.
/// Quattro rendono il confronto fragile: una sola parola cambiata spezza quattro
/// sequenze invece di tre.
///
/// **Tre** è la scelta di questo prodotto, non una verità. Compare nella frase
/// che l'operatore legge.
pub const SHINGLE_WORDS: usize = 3;

/// Quale percentuale di sequenze condivise basta perché due contenuti si
/// dichiarino somiglianti.
///
/// La percentuale si calcola sul contenuto **più corto**: un messaggio breve
/// interamente contenuto in uno lungo gli somiglia, e calcolarla sull'unione lo
/// nasconderebbe dietro la lunghezza dell'altro.
///
/// **Sessanta** è dichiarato e compare nella frase, perché chi lo ritiene
/// sbagliato veda subito su che cosa il giudizio si è formato.
pub const MINIMUM_SHARED_PERCENT: u32 = 60;

/// Un contenuto già letto, come il confronto lo vede.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparableContent {
    /// Quale contenuto.
    pub content_id: ContentId,
    /// Il corpo su cui si costruiscono le sequenze.
    pub body: String,
    /// Istante di pubblicazione, per la distanza fra i due.
    pub published_at: Timestamp,
    /// Indicatori tecnici trovati nel contenuto, già normalizzati.
    ///
    /// Il congelamento chiede che l'esito dica anche «stesso CVE, stesso
    /// dominio»: sono parte del perché, e non un ornamento.
    pub indicators: Vec<(String, String)>,
}

/// Le sequenze di un contenuto, con la sua identità.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Shingled {
    content_id: ContentId,
    published_at: Timestamp,
    shingles: BTreeSet<String>,
    indicators: BTreeSet<(String, String)>,
}

/// Divide un testo nelle sequenze di [`SHINGLE_WORDS`] parole normalizzate.
///
/// La normalizzazione è **quella del motore di analisi**: una seconda avrebbe
/// prodotto, alla prima correzione, due nozioni diverse di «stessa parola» nello
/// stesso prodotto.
///
/// Un testo con meno parole di una sequenza non ne produce alcuna: **non è
/// confrontabile**, e chi chiama lo dichiara invece di trattarlo come privo di
/// somiglianze.
#[must_use]
pub fn shingles(body: &str) -> BTreeSet<String> {
    let parole: Vec<String> = body
        .split_whitespace()
        .map(normalise_for_matching)
        .filter(|parola| !parola.is_empty())
        .collect();

    if parole.len() < SHINGLE_WORDS {
        return BTreeSet::new();
    }

    parole
        .windows(SHINGLE_WORDS)
        .map(|finestra| finestra.join(" "))
        .collect()
}

/// Due contenuti che si somigliano, con il perché.
///
/// # Perché i campi sono privati
///
/// Perché il solo costruttore rifiuta una somiglianza senza sequenze condivise.
/// Se fossero pubblici, esisterebbe un valore di questo tipo che dichiara una
/// percentuale e non sa dire su che cosa — ed è precisamente il modo in cui un
/// risultato spiegabile smette di esserlo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resemblance {
    /// Il primo contenuto, quello con l'identificatore minore.
    left: ContentId,
    /// Il secondo.
    right: ContentId,
    /// Le sequenze che i due contenuti hanno in comune: **è il perché**.
    shared: BTreeSet<String>,
    /// Quante sequenze ha il più corto dei due.
    shorter_total: usize,
    /// Gli indicatori tecnici in comune.
    shared_indicators: BTreeSet<(String, String)>,
    /// Distanza fra i due istanti di pubblicazione, in millisecondi.
    apart_ms: i64,
}

impl Resemblance {
    /// Costruisce una somiglianza, **se c'è qualcosa da mostrare**.
    ///
    /// `None` quando le sequenze condivise sono zero: una somiglianza senza
    /// evidenza non è una somiglianza debole, è un valore che questo modulo non
    /// deve poter produrre.
    #[must_use]
    fn new(
        left: ContentId,
        right: ContentId,
        shared: BTreeSet<String>,
        shorter_total: usize,
        shared_indicators: BTreeSet<(String, String)>,
        apart_ms: i64,
    ) -> Option<Self> {
        if shared.is_empty() || shorter_total == 0 {
            return None;
        }
        // L'ordine dei due contenuti è quello degli identificatori: la
        // somiglianza è simmetrica, e due righe che dicono la stessa cosa in
        // ordine diverso sarebbero due voci per un fatto solo.
        let (left, right) = if left.get() <= right.get() {
            (left, right)
        } else {
            (right, left)
        };
        Some(Self {
            left,
            right,
            shared,
            shorter_total,
            shared_indicators,
            apart_ms,
        })
    }

    /// I due contenuti, in ordine di identificatore.
    #[must_use]
    pub const fn pair(&self) -> (ContentId, ContentId) {
        (self.left, self.right)
    }

    /// **Il perché**: le sequenze che i due contenuti hanno in comune.
    #[must_use]
    pub const fn shared_shingles(&self) -> &BTreeSet<String> {
        &self.shared
    }

    /// Gli indicatori tecnici in comune.
    #[must_use]
    pub const fn shared_indicators(&self) -> &BTreeSet<(String, String)> {
        &self.shared_indicators
    }

    /// Quante sequenze in comune.
    #[must_use]
    pub fn shared_count(&self) -> usize {
        self.shared.len()
    }

    /// Quante sequenze ha il più corto dei due contenuti.
    #[must_use]
    pub const fn shorter_total(&self) -> usize {
        self.shorter_total
    }

    /// La percentuale di sequenze del più corto che sono in comune.
    ///
    /// Aritmetica **intera**, arrotondata per difetto: mostra meno di quanto
    /// c'è invece di più, che è il verso prudente per un numero che avvicina
    /// due contenuti.
    #[must_use]
    pub fn shared_percent(&self) -> u32 {
        percentuale(self.shared.len(), self.shorter_total)
    }

    /// Distanza fra i due istanti di pubblicazione.
    #[must_use]
    pub const fn apart_ms(&self) -> i64 {
        self.apart_ms
    }

    /// Se i due contenuti condividono **tutte** le sequenze del più corto.
    ///
    /// Non vuol dire che siano lo stesso contenuto: uno può essere l'altro con
    /// una coda in più. Vuol dire che il più corto è interamente dentro
    /// l'altro.
    #[must_use]
    pub fn shorter_is_contained(&self) -> bool {
        self.shared.len() == self.shorter_total
    }

    /// Che cosa i due contenuti hanno in comune, e quanto.
    ///
    /// # Perché la frase porta anche le sequenze
    ///
    /// Perché il piano chiede che il risultato dica **perché**, e una
    /// percentuale non è un perché: è il risultato di un conto che chi legge
    /// non ha visto.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let contenimento = if self.shorter_is_contained() {
            " Il pi\u{f9} corto \u{e8} interamente contenuto nell'altro."
        } else {
            ""
        };

        let indicatori = if self.shared_indicators.is_empty() {
            String::new()
        } else {
            let elenco: Vec<String> = self
                .shared_indicators
                .iter()
                .map(|(genere, valore)| format!("{genere} \u{ab}{valore}\u{bb}"))
                .collect();
            format!(" In comune anche: {}.", elenco.join(", "))
        };

        format!(
            "Contenuto {} e contenuto {}: {} sequenze di {SHINGLE_WORDS} parole in comune su {} \
             del pi\u{f9} corto ({}%). Pubblicati a {} di distanza.{contenimento}{indicatori} \
             Che siano lo stesso contenuto lo stabilisce una persona.",
            self.left.get(),
            self.right.get(),
            self.shared.len(),
            self.shorter_total,
            self.shared_percent(),
            distanza_in_parole(self.apart_ms),
        )
    }

    /// Le prime sequenze condivise, per chi le mostra.
    ///
    /// Sono l'evidenza: un elenco tagliato **dichiara** di esserlo, e chi
    /// chiama lo dice.
    #[must_use]
    pub fn evidence(&self, quante: usize) -> Vec<String> {
        self.shared.iter().take(quante).cloned().collect()
    }
}

/// La percentuale, in aritmetica intera e arrotondata per difetto.
const fn percentuale(parte: usize, totale: usize) -> u32 {
    if totale == 0 {
        return 0;
    }
    let valore = parte * 100 / totale;
    if valore > u32::MAX as usize {
        return u32::MAX;
    }
    valore as u32
}

/// La distanza fra due istanti, in parole.
fn distanza_in_parole(millis: i64) -> String {
    let assoluti = millis.abs();
    let minuti = assoluti / 60_000;
    if minuti == 0 {
        return String::from("meno di un minuto");
    }
    if minuti < 60 {
        return match minuti {
            1 => String::from("un minuto"),
            altri => format!("{altri} minuti"),
        };
    }
    let ore = minuti / 60;
    if ore < 24 {
        return match ore {
            1 => String::from("un'ora"),
            altre => format!("{altre} ore"),
        };
    }
    match ore / 24 {
        1 => String::from("un giorno"),
        altri => format!("{altri} giorni"),
    }
}

/// Perché il confronto non si è potuto fare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimilarityGap {
    /// Nessun contenuto era abbastanza lungo da produrre una sequenza.
    ///
    /// Non è «nessuna somiglianza»: è **nessun confronto**.
    NothingComparable {
        /// Quanti contenuti sono stati scartati perché troppo corti.
        too_short: usize,
    },
    /// I contenuti superano il limite del confronto.
    ///
    /// **Non si tronca**: un confronto su una parte che si spacciasse per un
    /// confronto su tutto direbbe «nessun quasi-duplicato» avendo guardato un
    /// decimo dei contenuti.
    TooManyContents {
        /// Il limite oltre il quale il confronto si ferma.
        limit: usize,
    },
}

impl SimilarityGap {
    /// Che cosa manca, detto a chi legge.
    #[must_use]
    pub fn as_sentence(self) -> String {
        match self {
            Self::NothingComparable { too_short } => format!(
                "Nessun contenuto \u{e8} abbastanza lungo da poter essere confrontato: servono \
                 almeno {SHINGLE_WORDS} parole, e {too_short} contenuti non le raggiungono. Non \
                 significa che non ci siano contenuti simili \u{2014} significa che non si \u{e8} \
                 potuto guardare."
            ),
            Self::TooManyContents { limit } => format!(
                "I contenuti superano il limite di {limit} del confronto. Il confronto non viene \
                 eseguito su una parte: direbbe \u{ab}nessun contenuto simile\u{bb} avendone \
                 guardato una frazione."
            ),
        }
    }
}

/// L'esito del confronto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimilarityOutcome {
    /// Il confronto è stato eseguito.
    Compared {
        /// Le coppie che si somigliano, dalla più somigliante.
        resemblances: Vec<Resemblance>,
        /// Quanti contenuti sono stati confrontati.
        compared: usize,
        /// Quanti erano troppo corti per produrre una sequenza.
        too_short: usize,
    },
    /// Il confronto non si è potuto fare, e si dice perché.
    NotComparable(SimilarityGap),
}

/// Che cosa si somiglia, in un insieme di contenuti.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimilarityReport {
    /// L'esito.
    pub outcome: SimilarityOutcome,
}

impl SimilarityReport {
    /// Quante coppie si somigliano, quando il confronto è stato fatto.
    ///
    /// `None` quando non si è potuto fare: **zero e «non confrontato» non sono
    /// la stessa cosa**.
    #[must_use]
    pub fn resembling_count(&self) -> Option<usize> {
        match &self.outcome {
            SimilarityOutcome::Compared { resemblances, .. } => Some(resemblances.len()),
            SimilarityOutcome::NotComparable(_) => None,
        }
    }

    /// Le coppie; vuoto quando il confronto non si è potuto fare.
    #[must_use]
    pub fn resemblances(&self) -> &[Resemblance] {
        match &self.outcome {
            SimilarityOutcome::Compared { resemblances, .. } => resemblances,
            SimilarityOutcome::NotComparable(_) => &[],
        }
    }

    /// L'esito, con il metodo e ciò che non si è potuto guardare.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match &self.outcome {
            SimilarityOutcome::NotComparable(gap) => gap.as_sentence(),
            SimilarityOutcome::Compared {
                resemblances,
                compared,
                too_short,
            } => {
                let quante = match resemblances.len() {
                    0 => String::from("Nessuna coppia di contenuti si somiglia oltre la soglia."),
                    1 => String::from("Una coppia di contenuti si somiglia oltre la soglia."),
                    altre => format!("{altre} coppie di contenuti si somigliano oltre la soglia."),
                };

                let scartati = if *too_short == 0 {
                    String::new()
                } else {
                    format!(
                        " {too_short} contenuti erano troppo corti per essere confrontati e non \
                         entrano in questo esito."
                    )
                };

                format!(
                    "{quante} Confrontati {compared} contenuti con sequenze di {SHINGLE_WORDS} \
                     parole normalizzate; la soglia dichiarata \u{e8} {MINIMUM_SHARED_PERCENT}% \
                     delle sequenze del pi\u{f9} corto.{scartati} Somigliarsi non vuol dire \
                     essere lo stesso contenuto: quello lo stabilisce una persona."
                )
            }
        }
    }
}

/// Confronta un contenuto con gli altri dell'insieme.
///
/// # Perché a uno contro gli altri, e non tutte le coppie
///
/// Perché la domanda che una persona si pone davanti a una riga è «a che cosa
/// somiglia **questo**», non «che cosa si somiglia qui dentro». La seconda
/// confronta tutte le coppie e costa con il quadrato dei contenuti; la prima
/// costa con il loro numero.
///
/// Il confronto su tutte le coppie non è stato scritto: sarebbe una capacità
/// che nessuna schermata raggiunge, ed è il debito che LAB-01 ha insegnato a
/// non lasciare. La milestone che la mostrerà dirà anche quanto costa.
///
/// # Non scrive nulla
///
/// Non può: questo modulo non conosce l'archivio.
#[must_use]
pub fn compare_against(
    subject: ContentId,
    contents: &[ComparableContent],
    limit: usize,
) -> SimilarityReport {
    if contents.len() > limit {
        return SimilarityReport {
            outcome: SimilarityOutcome::NotComparable(SimilarityGap::TooManyContents { limit }),
        };
    }

    let mut soggetto: Option<Shingled> = None;
    let mut altri: Vec<Shingled> = Vec::new();
    let mut troppo_corti = 0_usize;

    for content in contents {
        let sequenze = shingles(&content.body);
        if sequenze.is_empty() {
            troppo_corti += 1;
            continue;
        }
        let confrontabile = Shingled {
            content_id: content.content_id,
            published_at: content.published_at,
            shingles: sequenze,
            indicators: content.indicators.iter().cloned().collect(),
        };
        if confrontabile.content_id.get() == subject.get() {
            soggetto = Some(confrontabile);
        } else {
            altri.push(confrontabile);
        }
    }

    // Se il contenuto di partenza non produce sequenze, non c'è confronto
    // possibile: non è «non somiglia a nulla», è «non si è potuto guardare».
    let Some(soggetto) = soggetto else {
        return SimilarityReport {
            outcome: SimilarityOutcome::NotComparable(SimilarityGap::NothingComparable {
                too_short: troppo_corti,
            }),
        };
    };

    if altri.is_empty() {
        return SimilarityReport {
            outcome: SimilarityOutcome::NotComparable(SimilarityGap::NothingComparable {
                too_short: troppo_corti,
            }),
        };
    }

    let mut resemblances: Vec<Resemblance> = altri
        .iter()
        .filter_map(|altro| {
            let comuni: BTreeSet<String> = soggetto
                .shingles
                .intersection(&altro.shingles)
                .cloned()
                .collect();
            let piu_corto = soggetto.shingles.len().min(altro.shingles.len());

            if percentuale(comuni.len(), piu_corto) < MINIMUM_SHARED_PERCENT {
                return None;
            }

            Resemblance::new(
                soggetto.content_id,
                altro.content_id,
                comuni,
                piu_corto,
                soggetto
                    .indicators
                    .intersection(&altro.indicators)
                    .cloned()
                    .collect(),
                altro.published_at.as_millis() - soggetto.published_at.as_millis(),
            )
        })
        .collect();

    // L'ordine è quanto si somigliano, e ogni riga porta accanto i numeri che
    // l'hanno collocata (WQ-01). A parità, gli identificatori: due esecuzioni
    // sugli stessi contenuti danno lo stesso elenco.
    resemblances.sort_by(|left, right| {
        right
            .shared_percent()
            .cmp(&left.shared_percent())
            .then_with(|| right.shared_count().cmp(&left.shared_count()))
            .then_with(|| left.pair().cmp(&right.pair()))
    });

    SimilarityReport {
        outcome: SimilarityOutcome::Compared {
            resemblances,
            compared: altri.len() + 1,
            too_short: troppo_corti,
        },
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::{ContentId, Timestamp};

    use super::{
        ComparableContent, MINIMUM_SHARED_PERCENT, SHINGLE_WORDS, SimilarityGap, SimilarityOutcome,
        compare_against, shingles,
    };

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("similarity.rs");

    const MINUTO: i64 = 60_000;
    const ORA_ZERO: i64 = 1_700_000_000_000;

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

    fn contenuto(id: i64, corpo: &str, minuti_dopo: i64) -> ComparableContent {
        ComparableContent {
            content_id: ContentId::new(id),
            body: corpo.to_owned(),
            published_at: Timestamp::from_millis(ORA_ZERO + minuti_dopo * MINUTO),
            indicators: Vec::new(),
        }
    }

    fn con_indicatori(
        id: i64,
        corpo: &str,
        minuti_dopo: i64,
        indicatori: &[(&str, &str)],
    ) -> ComparableContent {
        ComparableContent {
            indicators: indicatori
                .iter()
                .map(|(genere, valore)| ((*genere).to_owned(), (*valore).to_owned()))
                .collect(),
            ..contenuto(id, corpo, minuti_dopo)
        }
    }

    /// Un testo lungo abbastanza da produrre parecchie sequenze.
    const LUNGO: &str =
        "il corteo si e' radunato davanti alla stazione centrale nel primo pomeriggio di ieri";

    /// **Una somiglianza senza il perché non si può costruire.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che qualcuno aggiunga un percorso rapido che calcola la percentuale
    /// senza conservare le sequenze — «tanto il numero basta». Da lì l'evidenza
    /// diventa facoltativa, poi assente, e il risultato smette di essere
    /// spiegabile senza che nessuna riga lo dichiari.
    #[test]
    fn una_somiglianza_senza_il_perche_non_si_puo_costruire() {
        let blocco = blocco_di("pub struct Resemblance {");
        for riga in blocco.lines().filter(|riga| riga.contains(':')) {
            assert!(
                !riga.trim_start().starts_with("pub "),
                "i campi della somiglianza devono restare privati: «{}»",
                riga.trim()
            );
        }

        let costruttore = blocco_di("    fn new(");
        assert!(
            costruttore.contains("if shared.is_empty()"),
            "il costruttore deve rifiutare una somiglianza senza sequenze condivise"
        );

        // E ogni somiglianza prodotta porta davvero la propria evidenza.
        let esito = compare_against(
            ContentId::new(1),
            &[contenuto(1, LUNGO, 0), contenuto(2, LUNGO, 3)],
            100,
        );
        for somiglianza in esito.resemblances() {
            assert!(
                !somiglianza.shared_shingles().is_empty(),
                "una somiglianza deve portare le sequenze che la giustificano"
            );
        }
    }

    /// **Nessun embedding, e nessun punteggio.**
    ///
    /// ADR-0048 vieta gli embedding; un numero con la virgola qui aprirebbe la
    /// strada a «somiglianza 0,87», che è un punteggio.
    ///
    /// # Perché «model» non è in questo elenco
    ///
    /// Perché lo strato di dominio di questo prodotto si chiama `model`, e
    /// `lisi_core::model::dictionary` è precisamente l'import che rende questa
    /// somiglianza coerente con il motore. Una guardia che lo vietasse si
    /// accenderebbe sulla riga più giusta del modulo — lo stesso errore già
    /// corretto in SPIKE-01, in LAB-02 e in HEALTH-01.
    ///
    /// Le parole elencate qui sono quelle che **non possono** comparire per
    /// un'altra ragione.
    #[test]
    fn nessun_embedding_e_nessun_punteggio() {
        let codice = codice_senza_commenti().to_lowercase();
        for vietato in [
            "f32",
            "f64",
            "as f",
            "embedding",
            "cosine",
            "coseno",
            "score",
            "punteggio",
            "simhash",
            "minhash",
            "neural",
            "classificatore",
            "addestr",
        ] {
            assert!(
                !codice.contains(vietato),
                "«{vietato}» non appartiene a un confronto deterministico e spiegabile"
            );
        }
    }

    /// **Questo modulo non conosce l'archivio, né la revisione.**
    ///
    /// `ReviewState::Duplicate` è la decisione di una persona; una misura che
    /// producesse la stessa parola confonderebbe un giudizio registrato con un
    /// conteggio.
    #[test]
    fn il_confronto_non_conosce_l_archivio_ne_la_revisione() {
        let codice = codice_senza_commenti();
        assert!(!codice.contains("lisi_storage"));
        assert!(!codice.contains("Database"));
        assert!(
            !codice.contains("ReviewState"),
            "somigliarsi non è la decisione di una persona"
        );
    }

    /// Un testo più corto di una sequenza non ne produce alcuna.
    #[test]
    fn un_testo_piu_corto_di_una_sequenza_non_ne_produce() {
        assert!(shingles("due parole").is_empty());
        assert_eq!(shingles("tre parole esatte").len(), 1);
    }

    /// La normalizzazione è quella del motore: maiuscole e minuscole non
    /// distinguono.
    #[test]
    fn le_maiuscole_non_distinguono_due_sequenze() {
        assert_eq!(shingles("Il Corteo Passa"), shingles("il corteo passa"));
    }

    /// **L'ordine delle parole conta.**
    ///
    /// È la ragione per cui l'algoritmo usa n-grammi e non i soli token:
    /// «il cane morde l'uomo» e «l'uomo morde il cane» non sono la stessa cosa.
    #[test]
    fn l_ordine_delle_parole_conta() {
        let uno = shingles("il cane morde l'uomo per la strada");
        let altro = shingles("l'uomo morde il cane per la strada");

        assert_ne!(uno, altro, "le sequenze devono distinguere l'ordine");
    }

    /// Due contenuti identici si somigliano al cento per cento, e si dice che
    /// il più corto è contenuto nell'altro.
    #[test]
    fn due_contenuti_identici_si_somigliano_per_intero() {
        let esito = compare_against(
            ContentId::new(1),
            &[contenuto(1, LUNGO, 0), contenuto(2, LUNGO, 17)],
            100,
        );

        let SimilarityOutcome::Compared { resemblances, .. } = &esito.outcome else {
            panic!("il confronto doveva eseguirsi");
        };
        assert_eq!(resemblances.len(), 1);
        assert_eq!(resemblances[0].shared_percent(), 100);
        assert!(resemblances[0].shorter_is_contained());

        let frase = resemblances[0].as_sentence();
        assert!(frase.contains("17 minuti"), "{frase}");
        assert!(frase.contains("lo stabilisce una persona"), "{frase}");
    }

    /// Due contenuti che non hanno nulla in comune non producono alcuna riga.
    #[test]
    fn due_contenuti_diversi_non_producono_alcuna_riga() {
        let esito = compare_against(
            ContentId::new(1),
            &[
                contenuto(1, LUNGO, 0),
                contenuto(
                    2,
                    "la partita di ieri sera si e' conclusa senza reti segnate",
                    5,
                ),
            ],
            100,
        );

        assert_eq!(esito.resembling_count(), Some(0));
        assert!(esito.resemblances().is_empty());
    }

    /// Un contenuto breve interamente dentro uno lungo gli somiglia.
    ///
    /// La percentuale si calcola sul **più corto**: calcolarla sull'unione lo
    /// nasconderebbe dietro la lunghezza dell'altro.
    #[test]
    fn un_contenuto_breve_dentro_uno_lungo_gli_somiglia() {
        let esito = compare_against(
            ContentId::new(1),
            &[
                contenuto(1, LUNGO, 0),
                contenuto(2, "il corteo si e' radunato davanti", 2),
            ],
            100,
        );

        let SimilarityOutcome::Compared { resemblances, .. } = &esito.outcome else {
            panic!("il confronto doveva eseguirsi");
        };
        assert_eq!(resemblances.len(), 1, "{resemblances:?}");
        assert!(resemblances[0].shorter_is_contained());
        assert_eq!(resemblances[0].shared_percent(), 100);
    }

    /// **La somiglianza è simmetrica: la coppia è la stessa da qualunque
    /// contenuto la si guardi.**
    ///
    /// # Che cosa questa prova verifica davvero
    ///
    /// Non che l'ordine degli argomenti non conti — quello lo garantisce già la
    /// forma dei dati. Verifica che **partendo dall'altro contenuto** si ottenga
    /// la stessa coppia e la stessa percentuale: se così non fosse, lo stesso
    /// fatto comparirebbe due volte con due numeri diversi, e chi legge non
    /// saprebbe quale credere.
    #[test]
    fn la_coppia_e_la_stessa_da_qualunque_contenuto_la_si_guardi() {
        let contenuti = [contenuto(1, LUNGO, 0), contenuto(2, LUNGO, 3)];

        let dal_primo = compare_against(ContentId::new(1), &contenuti, 100);
        let dal_secondo = compare_against(ContentId::new(2), &contenuti, 100);

        assert_eq!(dal_primo.resembling_count(), Some(1));
        assert_eq!(dal_secondo.resembling_count(), Some(1));
        assert_eq!(
            dal_primo.resemblances()[0].pair(),
            dal_secondo.resemblances()[0].pair(),
            "la coppia deve essere la stessa da entrambi i lati"
        );
        assert_eq!(
            dal_primo.resemblances()[0].shared_percent(),
            dal_secondo.resemblances()[0].shared_percent(),
            "lo stesso fatto non puo' avere due numeri diversi"
        );
    }

    /// **Un contenuto non somiglia a se stesso.**
    ///
    /// Non è una sottigliezza: il soggetto è dentro l'insieme che gli viene
    /// passato — è il modo in cui il servizio legge una sessione intera — e
    /// senza escluderlo ogni riga avrebbe una somiglianza al cento per cento
    /// con se stessa, in cima all'elenco.
    #[test]
    fn un_contenuto_non_somiglia_a_se_stesso() {
        let esito = compare_against(
            ContentId::new(1),
            &[contenuto(1, LUNGO, 0), contenuto(2, LUNGO, 3)],
            100,
        );

        assert_eq!(esito.resembling_count(), Some(1));
        let (sinistra, destra) = esito.resemblances()[0].pair();
        assert_ne!(
            sinistra, destra,
            "una coppia non e' un contenuto con se stesso"
        );
    }

    /// **Ciò che non si è potuto confrontare si dichiara.**
    ///
    /// Contenuti troppo corti non sono contenuti «senza somiglianze».
    #[test]
    fn i_contenuti_troppo_corti_si_dichiarano() {
        let esito = compare_against(
            ContentId::new(1),
            &[
                contenuto(1, LUNGO, 0),
                contenuto(2, LUNGO, 4),
                contenuto(3, "ciao", 6),
                contenuto(4, "due parole", 8),
            ],
            100,
        );

        let SimilarityOutcome::Compared {
            compared,
            too_short,
            ..
        } = esito.outcome
        else {
            panic!("il confronto doveva eseguirsi");
        };
        assert_eq!(compared, 2);
        assert_eq!(too_short, 2);
        assert!(
            esito.as_sentence().contains("troppo corti"),
            "{}",
            esito.as_sentence()
        );
    }

    /// **Se nulla era confrontabile, non si dice «nessuna somiglianza».**
    #[test]
    fn se_nulla_era_confrontabile_non_si_dice_nessuna_somiglianza() {
        let esito = compare_against(
            ContentId::new(1),
            &[contenuto(1, "ciao", 0), contenuto(2, "a domani", 1)],
            100,
        );

        assert!(matches!(
            esito.outcome,
            SimilarityOutcome::NotComparable(SimilarityGap::NothingComparable { too_short: 2 })
        ));
        assert_eq!(esito.resembling_count(), None);
        assert!(
            esito
                .as_sentence()
                .contains("non si \u{e8} potuto guardare"),
            "{}",
            esito.as_sentence()
        );
    }

    /// **Oltre il limite si rifiuta invece di troncare.**
    #[test]
    fn oltre_il_limite_il_confronto_si_rifiuta() {
        let esito = compare_against(
            ContentId::new(1),
            &[
                contenuto(1, LUNGO, 0),
                contenuto(2, LUNGO, 1),
                contenuto(3, LUNGO, 2),
            ],
            2,
        );

        assert!(matches!(
            esito.outcome,
            SimilarityOutcome::NotComparable(SimilarityGap::TooManyContents { limit: 2 })
        ));
        assert_eq!(
            esito.resembling_count(),
            None,
            "un rifiuto non è zero somiglianze"
        );
    }

    /// Gli indicatori in comune entrano nel perché, come chiede il congelamento.
    #[test]
    fn gli_indicatori_in_comune_entrano_nel_perche() {
        let esito = compare_against(
            ContentId::new(1),
            &[
                con_indicatori(
                    1,
                    LUNGO,
                    0,
                    &[("cve", "cve-2026-1234"), ("domain", "a.example")],
                ),
                con_indicatori(
                    2,
                    LUNGO,
                    6,
                    &[("cve", "cve-2026-1234"), ("domain", "b.example")],
                ),
            ],
            100,
        );

        let SimilarityOutcome::Compared { resemblances, .. } = &esito.outcome else {
            panic!("il confronto doveva eseguirsi");
        };
        assert_eq!(resemblances[0].shared_indicators().len(), 1);

        let frase = resemblances[0].as_sentence();
        assert!(frase.contains("cve-2026-1234"), "{frase}");
        assert!(!frase.contains("b.example"), "{frase}");
    }

    /// **La frase porta le sequenze, non solo la percentuale.**
    ///
    /// Una percentuale non è un perché: è il risultato di un conto che chi
    /// legge non ha visto.
    #[test]
    fn l_evidenza_si_puo_leggere() {
        let esito = compare_against(
            ContentId::new(1),
            &[contenuto(1, LUNGO, 0), contenuto(2, LUNGO, 1)],
            100,
        );
        let somiglianza = &esito.resemblances()[0];

        let prove = somiglianza.evidence(3);
        assert_eq!(prove.len(), 3);
        for sequenza in &prove {
            assert_eq!(
                sequenza.split_whitespace().count(),
                SHINGLE_WORDS,
                "ogni prova è una sequenza di {SHINGLE_WORDS} parole: «{sequenza}»"
            );
        }
    }

    /// La soglia dichiarata compare nella frase dell'esito.
    #[test]
    fn la_soglia_dichiarata_compare_nella_frase() {
        let esito = compare_against(
            ContentId::new(1),
            &[contenuto(1, LUNGO, 0), contenuto(2, LUNGO, 1)],
            100,
        );
        let frase = esito.as_sentence();

        assert!(
            frase.contains(&MINIMUM_SHARED_PERCENT.to_string()),
            "{frase}"
        );
        assert!(frase.contains(&SHINGLE_WORDS.to_string()), "{frase}");
    }

    /// Due esecuzioni sugli stessi contenuti danno lo stesso esito.
    #[test]
    fn due_esecuzioni_danno_lo_stesso_esito() {
        let contenuti = vec![
            contenuto(1, LUNGO, 0),
            contenuto(2, LUNGO, 3),
            contenuto(3, "la partita di ieri sera si e' conclusa senza reti", 5),
            contenuto(4, "il corteo si e' radunato davanti", 7),
        ];

        assert_eq!(
            compare_against(ContentId::new(1), &contenuti, 100),
            compare_against(ContentId::new(1), &contenuti, 100)
        );
    }
}

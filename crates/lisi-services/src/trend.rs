//! Che cosa compare adesso e prima non compariva.
//!
//! # Che cosa questo modulo dice, e che cosa non dice
//!
//! Dice: «questo termine compare 14 volte nel periodo recente e 2 volte nel
//! periodo di confronto». È un **confronto fra due conteggi di fatti
//! registrati**, e ciascuno dei due numeri è visibile.
//!
//! Non dice che ci sia una tendenza. **Due finestre non sono una serie**: dicono
//! che cosa è cambiato fra due periodi, non che cosa stia crescendo. Una parola
//! che compare molto questa settimana e mai la scorsa può essere un fatto di
//! cronaca finito il giorno dopo. Chiamarla «tendenza» attribuirebbe una
//! direzione a due punti, ed è il modo più comune di far dire a una statistica
//! ciò che non ha misurato.
//!
//! # La garanzia strutturale: non esiste una finestra sbilanciata
//!
//! Confrontare sette giorni con trenta e chiamare «crescita» la differenza è la
//! bugia più facile di questa milestone: il periodo più lungo contiene più di
//! tutto, e il confronto misura la durata invece del fenomeno.
//!
//! [`ComparisonWindows`] ha i campi **privati** e **un solo costruttore**, che
//! prende un istante di fine e una durata e ne ricava due finestre **adiacenti
//! e della stessa durata**. Non esiste un modo di costruirne una sbilanciata:
//! non è una regola da rispettare, è una forma che non si può scrivere.
//!
//! È la stessa forma di garanzia di REPLAY-01, dove un'ipotesi non può
//! diventare un fatto perché il tipo non passa.
//!
//! # Perché una linea di partenza vuota non è una linea di partenza
//!
//! Un archivio comincia vuoto. Il giorno dopo il primo monitoraggio, **ogni**
//! parola mai vista risulta «comparsa adesso e mai prima» — non perché stia
//! emergendo, ma perché prima non c'era nulla da nessuna parte.
//!
//! Perciò il confronto **si rifiuta** quando il periodo di confronto comincia
//! prima del primo contenuto archiviato, e quando quel periodo non contiene
//! alcuna osservazione. Non produce un elenco vuoto: dichiara di non aver
//! potuto confrontare, e dice perché. «Nessun segnale emergente» su una finestra
//! senza dati è la stessa frase pericolosa di «nessuna differenza» su zero
//! contenuti (ADR-0053, sesta superficie).
//!
//! # Nessun punteggio dell'emergenza
//!
//! Un numero che dicesse «questo termine è emergente al 78%» sarebbe una
//! valutazione appresa travestita da statistica, ed è ciò che ADR-0048 esclude
//! dal prodotto. Qui ci sono due conteggi interi e la loro differenza, e una
//! prova impone che nel sorgente non compaiano `f32` né `f64`.
//!
//! L'ordine è **la differenza fra i due conteggi**, e ogni riga porta accanto i
//! numeri che l'hanno collocata: è la scelta di WQ-01, dove l'ordine è un
//! confronto fra fatti registrati e ogni riga elenca quelli che la collocano.
//! Non è il caso di FEEDBACK-01, dove ordinare per smentite avrebbe composto una
//! classifica della **qualità** di una regola: qui l'ordine è il fatto stesso
//! che si riferisce.
//!
//! # Questo modulo non conosce l'archivio
//!
//! Come il Rule Lab, il replay e il riscontro sui dizionari: riceve osservazioni
//! già lette e restituisce un confronto.

use std::collections::BTreeMap;

use lisi_core::Timestamp;

/// Durata predefinita di ciascuna delle due finestre: **sette giorni**.
///
/// # Perché sette e non trenta
///
/// Perché una settimana è il periodo che un operatore ricorda: chi legge
/// «compare 14 volte in questi sette giorni e 2 volte nei sette precedenti» può
/// confrontare la frase con la propria memoria di che cosa è successo. Trenta
/// giorni contro trenta direbbero qualcosa di più stabile e di meno
/// verificabile.
///
/// Non è una verità: è una scelta, ed è **dichiarata in ogni frase** insieme
/// alle date esatte, così che chi la ritiene sbagliata veda subito su che cosa
/// il numero è stato calcolato.
pub const DEFAULT_WINDOW_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

/// Quante occorrenze servono nel periodo recente perché valga la pena di dirlo.
///
/// Una parola comparsa **una volta** e mai prima non è un segnale: è una
/// parola. Senza una soglia l'elenco sarebbe lungo quanto il vocabolario di una
/// settimana, e un elenco che contiene tutto non si legge.
///
/// Il numero è costante e compare nella frase dell'esito.
pub const MINIMUM_OCCURRENCES: u32 = 3;

/// Che cosa è stato osservato.
///
/// # Perché sette generi e non i sei del congelamento
///
/// Il congelamento elenca termini, CVE, domini, impronte, URL e volumi per
/// fonte. L'archivio conserva anche gli **indirizzi IP**, con la stessa
/// struttura degli altri indicatori. Lasciarli fuori avrebbe prodotto un punto
/// cieco senza una ragione: un indirizzo che comincia a comparire ovunque è
/// esattamente ciò che questa analisi esiste per mostrare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ObservationKind {
    /// Un termine dei dizionari, nella forma normalizzata.
    Term,
    /// Un identificativo di vulnerabilità.
    Cve,
    /// Un nome di dominio.
    Domain,
    /// Un indirizzo web completo.
    Url,
    /// Un'impronta MD5, SHA-1 o SHA-256.
    Fingerprint,
    /// Un indirizzo IPv4 o IPv6.
    Address,
    /// Il volume di una fonte: ogni contenuto è un'occorrenza.
    SourceVolume,
}

impl ObservationKind {
    /// Come si chiama, per l'operatore.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Term => "termine",
            Self::Cve => "vulnerabilità",
            Self::Domain => "dominio",
            Self::Url => "indirizzo web",
            Self::Fingerprint => "impronta",
            Self::Address => "indirizzo di rete",
            Self::SourceVolume => "volume della fonte",
        }
    }

    /// La forma con cui l'archivio la conserva.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Term => "term",
            Self::Cve => "cve",
            Self::Domain => "domain",
            Self::Url => "url",
            Self::Fingerprint => "fingerprint",
            Self::Address => "address",
            Self::SourceVolume => "source",
        }
    }

    /// Tutti i generi, nell'ordine in cui si mostrano.
    #[must_use]
    pub const fn all() -> [Self; 7] {
        [
            Self::Term,
            Self::Cve,
            Self::Domain,
            Self::Url,
            Self::Fingerprint,
            Self::Address,
            Self::SourceVolume,
        ]
    }
}

/// Una singola occorrenza, con l'istante a cui appartiene.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// Che cosa è stato osservato.
    pub kind: ObservationKind,
    /// Il valore, nella forma su cui si conta.
    pub key: String,
    /// Quando.
    ///
    /// # Quale orologio, e il limite che ne deriva
    ///
    /// È l'istante di **pubblicazione** dichiarato dalla fonte, non quello di
    /// acquisizione: la domanda è quando una cosa è stata detta, non quando
    /// NEXUM è passato a guardare. Il limite è che l'istante lo dichiara la
    /// fonte, e una fonte che lo falsifica sposta le proprie occorrenze da una
    /// finestra all'altra.
    pub at: Timestamp,
}

/// Le due finestre del confronto.
///
/// # Perché i campi sono privati
///
/// Perché il solo costruttore garantisce che siano **adiacenti e della stessa
/// durata**. Se fossero pubblici qualcuno potrebbe comporre un confronto fra
/// sette giorni e trenta, e la differenza fra i conteggi misurerebbe la durata
/// invece del fenomeno.
///
/// Non è una regola da ricordare: è una forma che non si può scrivere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComparisonWindows {
    /// Inizio del periodo recente, che è anche la fine del periodo di confronto.
    recent_start: Timestamp,
    /// Fine del periodo recente.
    recent_end: Timestamp,
    /// Inizio del periodo di confronto.
    baseline_start: Timestamp,
    /// Durata di **ciascuna** finestra, in millisecondi.
    duration_ms: i64,
}

impl ComparisonWindows {
    /// L'unico modo di costruire un confronto.
    ///
    /// Il periodo recente finisce a `end` e dura `duration_ms`; il periodo di
    /// confronto è quello immediatamente precedente, **della stessa durata**.
    ///
    /// Restituisce `None` per una durata non positiva: una finestra lunga zero
    /// non contiene nulla, e una negativa non è una finestra.
    #[must_use]
    pub const fn ending_at(end: Timestamp, duration_ms: i64) -> Option<Self> {
        if duration_ms <= 0 {
            return None;
        }
        let recent_start = Timestamp::from_millis(end.as_millis() - duration_ms);
        Some(Self {
            recent_start,
            recent_end: end,
            baseline_start: Timestamp::from_millis(recent_start.as_millis() - duration_ms),
            duration_ms,
        })
    }

    /// Inizio del periodo recente.
    #[must_use]
    pub const fn recent_start(&self) -> Timestamp {
        self.recent_start
    }

    /// Fine del periodo recente.
    #[must_use]
    pub const fn recent_end(&self) -> Timestamp {
        self.recent_end
    }

    /// Inizio del periodo di confronto.
    #[must_use]
    pub const fn baseline_start(&self) -> Timestamp {
        self.baseline_start
    }

    /// Durata di ciascuna delle due finestre.
    #[must_use]
    pub const fn duration_ms(&self) -> i64 {
        self.duration_ms
    }

    /// Se l'istante cade nel periodo recente.
    ///
    /// L'inizio è compreso, la fine è esclusa: così un'occorrenza appartiene a
    /// una finestra sola, e le due non se ne contendono nessuna.
    #[must_use]
    const fn is_recent(&self, at: Timestamp) -> bool {
        at.as_millis() >= self.recent_start.as_millis()
            && at.as_millis() < self.recent_end.as_millis()
    }

    /// Se l'istante cade nel periodo di confronto.
    #[must_use]
    const fn is_baseline(&self, at: Timestamp) -> bool {
        at.as_millis() >= self.baseline_start.as_millis()
            && at.as_millis() < self.recent_start.as_millis()
    }

    /// Le due finestre, per esteso.
    ///
    /// Ogni numero di questo modulo si legge accanto a questa frase: senza le
    /// date, «compare 14 volte» non dice nulla.
    #[must_use]
    ///
    /// Le due date del periodo recente, e il periodo di confronto detto per la
    /// sua durata (UX-EXCELLENCE-02, SIM3-12): erano quattro istanti e una
    /// giustificazione, un paragrafo di quattro righe nel Cruscotto. Le due
    /// finestre hanno la stessa durata e sono contigue per costruzione: il
    /// confronto comincia dove la durata finisce, e la frase lo dice.
    pub fn as_sentence(&self) -> String {
        let durata = durata_in_parole(self.duration_ms);
        let confronto = match durata.as_str() {
            "un giorno" => String::from("il giorno precedente"),
            "un'ora" => String::from("l'ora precedente"),
            altra => format!("i {altra} precedenti"),
        };
        format!(
            "Periodo recente: dal {} al {}. Periodo di confronto: {confronto}.",
            self.recent_start.to_readable_local(),
            self.recent_end.to_readable_local(),
        )
    }
}

/// La durata, in parole.
fn durata_in_parole(millis: i64) -> String {
    let ore = millis / (60 * 60 * 1_000);
    if ore % 24 == 0 && ore >= 24 {
        let giorni = ore / 24;
        return match giorni {
            1 => String::from("un giorno"),
            altri => format!("{altri} giorni"),
        };
    }
    match ore {
        1 => String::from("un'ora"),
        0 => format!("{} minuti", millis / (60 * 1_000)),
        altre => format!("{altre} ore"),
    }
}

/// Perché il confronto non è stato possibile.
///
/// Ognuna di queste è una **ragione dichiarata**, non un elenco vuoto: un
/// elenco vuoto si leggerebbe come «non sta emergendo nulla», che è una cosa
/// diversa da «non è stato possibile guardare».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrendGap {
    /// L'archivio non contiene alcun contenuto.
    EmptyArchive,
    /// Il periodo di confronto comincia prima del primo contenuto archiviato.
    ///
    /// È il caso di ogni archivio giovane, ed è la trappola principale di questa
    /// milestone: senza questo rifiuto, il giorno dopo il primo monitoraggio
    /// **tutto** risulterebbe emergente.
    BaselinePrecedesArchive {
        /// Il primo istante di cui l'archivio sappia qualcosa.
        archive_since: Timestamp,
    },
    /// Il periodo di confronto non contiene alcuna osservazione.
    ///
    /// Può succedere anche su un archivio vecchio: una settimana di fermo
    /// produce una linea di partenza vuota, e su una linea vuota qualunque cosa
    /// sembra un aumento.
    EmptyBaseline,
    /// Le osservazioni del periodo superano il limite di lettura.
    ///
    /// **Non si tronca**: un conteggio su un insieme troncato è un numero
    /// sbagliato, non una vista parziale. Un elenco tagliato mostra meno righe;
    /// un conteggio tagliato mostra numeri falsi.
    TooManyObservations {
        /// Il limite oltre il quale la lettura si ferma.
        limit: u32,
    },
}

impl TrendGap {
    /// Che cosa manca, detto a chi legge.
    #[must_use]
    pub fn as_sentence(self) -> String {
        match self {
            Self::EmptyArchive => String::from(
                "L'archivio non contiene alcun contenuto: non c'\u{e8} nulla da confrontare. \
                 Non significa che non stia emergendo nulla \u{2014} significa che non \
                 \u{e8} stato ancora acquisito niente.",
            ),
            // Una riga di Cruscotto, non un ragionamento (UX-EXCELLENCE-02,
            // SIM3-12): il perché resta, in mezza riga — un periodo in cui NEXUM
            // non guardava farebbe sembrare nuova ogni cosa.
            Self::BaselinePrecedesArchive { archive_since } => format!(
                "Confronto non ancora possibile: il periodo di confronto comincerebbe prima del \
                 primo contenuto archiviato ({}), quando NEXUM non guardava.",
                archive_since.to_readable_local()
            ),
            Self::EmptyBaseline => String::from(
                "Il periodo di confronto non contiene alcuna osservazione. Su una linea di \
                 partenza vuota qualunque cosa sembra un aumento, e nessun numero \
                 significherebbe qualcosa.",
            ),
            Self::TooManyObservations { limit } => format!(
                "Il periodo contiene pi\u{f9} di {limit} osservazioni. Il confronto non viene \
                 eseguito su una parte: un conteggio su un insieme troncato \u{e8} un numero \
                 sbagliato, non una vista parziale."
            ),
        }
    }
}

/// Qualcosa che compare nel periodo recente più che in quello di confronto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergingObservation {
    /// Che genere di cosa.
    pub kind: ObservationKind,
    /// Il valore.
    pub key: String,
    /// Quante volte nel periodo recente.
    pub recent: u32,
    /// Quante volte nel periodo di confronto.
    pub baseline: u32,
}

impl EmergingObservation {
    /// Di quante occorrenze è aumentato.
    ///
    /// È una **sottrazione fra due conteggi**, entrambi visibili accanto. Non è
    /// un punteggio, e non è una proporzione: quanto valga quell'aumento lo
    /// giudica chi legge.
    #[must_use]
    pub const fn increase(&self) -> u32 {
        self.recent.saturating_sub(self.baseline)
    }

    /// Se nel periodo di confronto non compariva affatto.
    #[must_use]
    pub const fn is_new(&self) -> bool {
        self.baseline == 0
    }

    /// Che cosa è stato contato, e come.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let prima = if self.is_new() {
            String::from("non compariva affatto")
        } else {
            match self.baseline {
                1 => String::from("compariva una volta"),
                altre => format!("compariva {altre} volte"),
            }
        };
        let adesso = match self.recent {
            1 => String::from("una volta"),
            altre => format!("{altre} volte"),
        };

        format!(
            "{} \u{ab}{}\u{bb}: {adesso} nel periodo recente, e nel periodo di confronto {prima}. \
             Differenza: {}.",
            self.kind.label(),
            self.key,
            self.increase(),
        )
    }
}

/// L'esito del confronto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrendOutcome {
    /// Il confronto è stato eseguito.
    Compared {
        /// Ciò che compare più di prima, dal maggiore aumento.
        findings: Vec<EmergingObservation>,
        /// Osservazioni totali nel periodo recente.
        recent_total: u32,
        /// Osservazioni totali nel periodo di confronto.
        baseline_total: u32,
        /// Quanti valori distinti sono stati confrontati.
        distinct_keys: usize,
    },
    /// Il confronto non è stato possibile, e si dice perché.
    NotComparable(TrendGap),
}

/// Che cosa compare adesso e prima non compariva.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrendReport {
    /// Le due finestre, che si dichiarano anche quando il confronto non si fa.
    pub windows: ComparisonWindows,
    /// L'esito.
    pub outcome: TrendOutcome,
}

impl TrendReport {
    /// Quante cose compaiono più di prima, quando il confronto è stato fatto.
    ///
    /// `None` quando non è stato possibile confrontare: **zero e «non misurato»
    /// non sono la stessa cosa**, e restituire zero qui le confonderebbe nella
    /// prima schermata che chiama questo metodo.
    #[must_use]
    pub fn emerging_count(&self) -> Option<usize> {
        match &self.outcome {
            TrendOutcome::Compared { findings, .. } => Some(findings.len()),
            TrendOutcome::NotComparable(_) => None,
        }
    }

    /// Ciò che compare più di prima; vuoto quando non si è potuto confrontare.
    #[must_use]
    pub fn findings(&self) -> &[EmergingObservation] {
        match &self.outcome {
            TrendOutcome::Compared { findings, .. } => findings,
            TrendOutcome::NotComparable(_) => &[],
        }
    }

    /// L'esito, con le finestre sempre accanto.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match &self.outcome {
            TrendOutcome::NotComparable(gap) => {
                format!("{} {}", gap.as_sentence(), self.windows.as_sentence())
            }
            TrendOutcome::Compared {
                findings,
                recent_total,
                baseline_total,
                distinct_keys,
            } => {
                let quante = if findings.is_empty() {
                    format!(
                        "Nulla compare almeno {MINIMUM_OCCURRENCES} volte nel periodo recente \
                         pi\u{f9} che nel periodo di confronto."
                    )
                } else {
                    match findings.len() {
                        1 => {
                            String::from("Una cosa compare pi\u{f9} che nel periodo di confronto.")
                        }
                        altre => {
                            format!("{altre} cose compaiono pi\u{f9} che nel periodo di confronto.")
                        }
                    }
                };

                format!(
                    "{quante} Confrontate {distinct_keys} voci distinte su {recent_total} \
                     osservazioni recenti e {baseline_total} di confronto; \u{e8} un confronto \
                     fra due periodi, non una tendenza \u{2014} due finestre non sono una serie. \
                     {}",
                    self.windows.as_sentence()
                )
            }
        }
    }
}

/// Confronta due periodi della stessa durata.
///
/// # Che cosa entra
///
/// Le osservazioni di **entrambe** le finestre, già lette, e il primo istante di
/// cui l'archivio sappia qualcosa. Quest'ultimo non è una comodità: è ciò che
/// impedisce di confrontare con un periodo in cui NEXUM non guardava.
///
/// # La regola, per intero
///
/// Una voce compare nell'esito quando, nel periodo recente, ha almeno
/// [`MINIMUM_OCCURRENCES`] occorrenze **e** ne ha più che nel periodo di
/// confronto. Nient'altro: nessuna soglia proporzionale, nessun punteggio.
///
/// # Non scrive nulla
///
/// Non può: non conosce l'archivio.
#[must_use]
pub fn analyse(
    observations: &[Observation],
    windows: ComparisonWindows,
    archive_since: Option<Timestamp>,
) -> TrendReport {
    let Some(archive_since) = archive_since else {
        return TrendReport {
            windows,
            outcome: TrendOutcome::NotComparable(TrendGap::EmptyArchive),
        };
    };

    if windows.baseline_start().as_millis() < archive_since.as_millis() {
        return TrendReport {
            windows,
            outcome: TrendOutcome::NotComparable(TrendGap::BaselinePrecedesArchive {
                archive_since,
            }),
        };
    }

    let mut conteggi: BTreeMap<(ObservationKind, String), (u32, u32)> = BTreeMap::new();
    let mut recent_total = 0_u32;
    let mut baseline_total = 0_u32;

    for observation in observations {
        let chiave = (observation.kind, observation.key.clone());
        if windows.is_recent(observation.at) {
            conteggi.entry(chiave).or_default().0 += 1;
            recent_total += 1;
        } else if windows.is_baseline(observation.at) {
            conteggi.entry(chiave).or_default().1 += 1;
            baseline_total += 1;
        }
        // Le osservazioni fuori da entrambe le finestre non si contano. Non è
        // una svista: sono state lette perché la lettura prende un intervallo
        // solo, e contarle allargherebbe in silenzio una delle due finestre.
    }

    if baseline_total == 0 {
        return TrendReport {
            windows,
            outcome: TrendOutcome::NotComparable(TrendGap::EmptyBaseline),
        };
    }

    let mut findings: Vec<EmergingObservation> = conteggi
        .iter()
        .filter(|(_, (recent, baseline))| *recent >= MINIMUM_OCCURRENCES && recent > baseline)
        .map(|((kind, key), (recent, baseline))| EmergingObservation {
            kind: *kind,
            key: key.clone(),
            recent: *recent,
            baseline: *baseline,
        })
        .collect();

    // L'ordine è la differenza fra i due conteggi, che è il fatto stesso di cui
    // la riga riferisce, e ogni riga porta accanto i numeri che l'hanno
    // collocata (WQ-01). A parità, il genere e poi il valore: così due
    // esecuzioni sugli stessi fatti danno lo stesso elenco.
    findings.sort_by(|left, right| {
        right
            .increase()
            .cmp(&left.increase())
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.key.cmp(&right.key))
    });

    TrendReport {
        windows,
        outcome: TrendOutcome::Compared {
            findings,
            recent_total,
            baseline_total,
            distinct_keys: conteggi.len(),
        },
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;

    use super::{
        ComparisonWindows, DEFAULT_WINDOW_MS, MINIMUM_OCCURRENCES, Observation, ObservationKind,
        TrendGap, TrendOutcome, analyse,
    };

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("trend.rs");

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

    const GIORNO: i64 = 24 * 60 * 60 * 1_000;
    const ORA_ZERO: i64 = 1_700_000_000_000;

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    /// Le due finestre standard: recente [-7g, 0), confronto [-14g, -7g).
    fn finestre() -> ComparisonWindows {
        let Some(finestre) = ComparisonWindows::ending_at(istante(ORA_ZERO), DEFAULT_WINDOW_MS)
        else {
            panic!("le finestre di prova devono potersi costruire");
        };
        finestre
    }

    /// Un'osservazione a `giorni_fa` giorni prima dell'ora zero.
    fn osservazione(chiave: &str, giorni_fa: i64) -> Observation {
        Observation {
            kind: ObservationKind::Term,
            key: chiave.to_owned(),
            at: istante(ORA_ZERO - giorni_fa * GIORNO),
        }
    }

    /// Ripete la stessa osservazione a giorni consecutivi, dal più lontano.
    fn ripetuta(chiave: &str, quante: i64, primo_giorno_fa: i64) -> Vec<Observation> {
        (0..quante)
            .map(|i| osservazione(chiave, primo_giorno_fa - i))
            .collect()
    }

    /// L'archivio comincia quindici giorni fa: copre entrambe le finestre.
    fn archivio_vecchio() -> Option<Timestamp> {
        Some(istante(ORA_ZERO - 15 * GIORNO))
    }

    /// **Non esiste una finestra sbilanciata.**
    ///
    /// I campi sono privati e il solo costruttore ricava le due finestre da una
    /// durata sola. Confrontare sette giorni con trenta è la bugia più facile di
    /// questa milestone, e qui non si può nemmeno scrivere.
    #[test]
    fn non_esiste_un_modo_di_costruire_una_finestra_sbilanciata() {
        let blocco = blocco_di("pub struct ComparisonWindows {");
        for riga in blocco.lines().filter(|riga| riga.contains(':')) {
            assert!(
                !riga.trim_start().starts_with("pub "),
                "i campi delle finestre devono restare privati: «{}»",
                riga.trim()
            );
        }

        let produzione = codice_senza_commenti();
        assert_eq!(
            produzione.matches("-> Option<Self>").count(),
            1,
            "le finestre devono avere un solo costruttore"
        );

        // E la forma costruita è davvero simmetrica.
        let finestre = finestre();
        assert_eq!(
            finestre.recent_end().as_millis() - finestre.recent_start().as_millis(),
            finestre.duration_ms()
        );
        assert_eq!(
            finestre.recent_start().as_millis() - finestre.baseline_start().as_millis(),
            finestre.duration_ms()
        );
    }

    /// Una durata non positiva non è una finestra.
    #[test]
    fn una_durata_non_positiva_non_produce_finestre() {
        assert!(ComparisonWindows::ending_at(istante(ORA_ZERO), 0).is_none());
        assert!(ComparisonWindows::ending_at(istante(ORA_ZERO), -1).is_none());
    }

    /// **Questo modulo non conosce l'archivio.**
    #[test]
    fn il_confronto_non_ha_alcun_modo_di_scrivere() {
        let produzione = codice_senza_commenti();
        assert!(!produzione.contains("lisi_storage"));
        assert!(!produzione.contains("Database"));
    }

    /// **Nessun punteggio dell'emergenza.**
    ///
    /// «Questo termine è emergente al 78%» sarebbe una valutazione appresa
    /// travestita da statistica. Ci sono due conteggi interi e la loro
    /// differenza.
    #[test]
    fn nessun_punteggio_dell_emergenza_puo_entrare_in_questo_modulo() {
        let produzione = codice_senza_commenti();
        for vietato in ["f32", "f64", "as f", "percent", "punteggio", "score"] {
            assert!(
                !produzione.contains(vietato),
                "«{vietato}» apre la strada a un punteggio dell'emergenza"
            );
        }
    }

    /// **Un periodo di confronto anteriore all'archivio non è un confronto.**
    ///
    /// È la trappola principale: senza questo rifiuto, il giorno dopo il primo
    /// monitoraggio ogni cosa risulterebbe emergente.
    #[test]
    fn con_l_archivio_piu_giovane_del_confronto_non_si_confronta() {
        let osservazioni = ripetuta("assalto", 5, 6);
        let esito = analyse(
            &osservazioni,
            finestre(),
            // L'archivio comincia dentro il periodo recente.
            Some(istante(ORA_ZERO - 3 * GIORNO)),
        );

        assert!(matches!(
            esito.outcome,
            TrendOutcome::NotComparable(TrendGap::BaselinePrecedesArchive { .. })
        ));
        assert!(esito.emerging_count().is_none());
        assert!(
            esito.as_sentence().contains("non guardava"),
            "{}",
            esito.as_sentence()
        );
    }

    /// Un archivio vuoto non dice che non stia emergendo nulla.
    #[test]
    fn senza_archivio_non_si_dice_che_non_emerge_nulla() {
        let esito = analyse(&[], finestre(), None);

        assert!(matches!(
            esito.outcome,
            TrendOutcome::NotComparable(TrendGap::EmptyArchive)
        ));
        assert!(
            esito
                .as_sentence()
                .contains("non \u{e8} stato ancora acquisito niente"),
            "{}",
            esito.as_sentence()
        );
    }

    /// **Su una linea di partenza vuota non si confronta.**
    ///
    /// Qualunque cosa sembrerebbe un aumento.
    #[test]
    fn con_il_periodo_di_confronto_vuoto_non_si_confronta() {
        // Cinque occorrenze, tutte nel periodo recente; nessuna prima.
        let esito = analyse(&ripetuta("assalto", 5, 6), finestre(), archivio_vecchio());

        assert!(matches!(
            esito.outcome,
            TrendOutcome::NotComparable(TrendGap::EmptyBaseline)
        ));
        assert!(
            esito.as_sentence().contains("linea di"),
            "{}",
            esito.as_sentence()
        );
    }

    /// Ciò che compare più di prima compare nell'esito, con entrambi i numeri.
    #[test]
    fn cio_che_compare_piu_di_prima_porta_con_se_i_due_conteggi() {
        let mut osservazioni = ripetuta("assalto", 6, 6);
        osservazioni.extend(ripetuta("assalto", 2, 13));
        osservazioni.extend(ripetuta("corteo", 4, 13));

        let esito = analyse(&osservazioni, finestre(), archivio_vecchio());

        let TrendOutcome::Compared { findings, .. } = &esito.outcome else {
            panic!("il confronto doveva eseguirsi");
        };
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].key, "assalto");
        assert_eq!(findings[0].recent, 6);
        assert_eq!(findings[0].baseline, 2);
        assert_eq!(findings[0].increase(), 4);

        let frase = findings[0].as_sentence();
        assert!(frase.contains("6 volte nel periodo recente"), "{frase}");
        assert!(frase.contains("compariva 2 volte"), "{frase}");
    }

    /// Sotto la soglia non si dice niente.
    #[test]
    fn sotto_la_soglia_di_occorrenze_non_si_dice_niente() {
        let quante = i64::from(MINIMUM_OCCURRENCES) - 1;
        let mut osservazioni = ripetuta("assalto", quante, 6);
        osservazioni.extend(ripetuta("corteo", 3, 13));

        let esito = analyse(&osservazioni, finestre(), archivio_vecchio());

        let TrendOutcome::Compared { findings, .. } = &esito.outcome else {
            panic!("il confronto doveva eseguirsi");
        };
        assert!(
            findings.is_empty(),
            "due occorrenze non sono un segnale: sono due occorrenze"
        );
    }

    /// **Zero cose emergenti si dice soltanto dopo aver guardato.**
    ///
    /// Ed è diverso da «non misurato»: `emerging_count` restituisce `Some(0)`
    /// nel primo caso e `None` nel secondo.
    #[test]
    fn zero_dopo_aver_guardato_non_e_la_stessa_cosa_di_non_misurato() {
        let misurato = analyse(&ripetuta("corteo", 4, 13), finestre(), archivio_vecchio());
        assert_eq!(misurato.emerging_count(), Some(0));

        let non_misurato = analyse(&[], finestre(), None);
        assert_eq!(non_misurato.emerging_count(), None);
    }

    /// **L'esito nega di essere una tendenza.**
    ///
    /// Due finestre non sono una serie: dicono che cosa è cambiato fra due
    /// periodi, non che cosa stia crescendo.
    #[test]
    fn l_esito_dichiara_di_non_essere_una_tendenza() {
        let mut osservazioni = ripetuta("assalto", 6, 6);
        osservazioni.extend(ripetuta("assalto", 2, 13));

        let frase = analyse(&osservazioni, finestre(), archivio_vecchio()).as_sentence();

        assert!(frase.contains("non una tendenza"), "{frase}");
        assert!(frase.contains("due finestre non sono una serie"), "{frase}");
    }

    /// Ogni frase porta con sé le due finestre e la loro durata.
    #[test]
    fn ogni_esito_dichiara_le_finestre_su_cui_e_stato_calcolato() {
        let con_esito = analyse(&ripetuta("corteo", 4, 13), finestre(), archivio_vecchio());
        let senza_esito = analyse(&[], finestre(), None);

        for frase in [con_esito.as_sentence(), senza_esito.as_sentence()] {
            assert!(frase.contains("Periodo recente:"), "{frase}");
            assert!(frase.contains("Periodo di confronto:"), "{frase}");
            assert!(frase.contains("7 giorni"), "{frase}");
        }
    }

    /// **Il confine appartiene al periodo recente, e a quello soltanto.**
    ///
    /// Le due finestre sono semiaperte — inizio compreso, fine esclusa — così
    /// che si affianchino senza sovrapporsi né lasciare un istante scoperto.
    ///
    /// # Perché questa prova dice così e non «non si conta due volte»
    ///
    /// Perché il doppio conteggio è già impossibile: i due rami sono un `else
    /// if`, e nessuna occorrenza può entrare in entrambi qualunque cosa dicano
    /// i due confronti. Una prova che dichiarasse **quello** dichiarerebbe una
    /// proprietà garantita dalla struttura, e resterebbe verde davanti a un
    /// confine spostato.
    ///
    /// Ciò che un errore plausibile rompe è **a quale delle due** finestre il
    /// confine appartenga: basta un `>` al posto di un `>=` perché l'istante di
    /// confine non cada in nessuna delle due, e le occorrenze di quel momento
    /// spariscano da entrambi i conteggi.
    #[test]
    fn il_confine_appartiene_al_periodo_recente_e_a_quello_soltanto() {
        let finestre = finestre();
        // Esattamente sul confine fra le due finestre.
        let confine = finestre.recent_start();
        let osservazioni = vec![
            Observation {
                kind: ObservationKind::Term,
                key: String::from("confine"),
                at: confine,
            },
            osservazione("altro", 10),
        ];

        let esito = analyse(&osservazioni, finestre, archivio_vecchio());

        let TrendOutcome::Compared {
            recent_total,
            baseline_total,
            ..
        } = &esito.outcome
        else {
            panic!("il confronto doveva eseguirsi");
        };
        assert_eq!(*recent_total, 1);
        assert_eq!(*baseline_total, 1);
    }

    /// Generi diversi con lo stesso valore non si confondono.
    #[test]
    fn due_generi_con_lo_stesso_valore_restano_due_voci() {
        let mut osservazioni: Vec<Observation> = ripetuta("nexum.example", 4, 6);
        osservazioni.extend((0..4).map(|i| Observation {
            kind: ObservationKind::Domain,
            key: String::from("nexum.example"),
            at: istante(ORA_ZERO - (6 - i) * GIORNO),
        }));
        osservazioni.extend(ripetuta("altro", 2, 13));

        let esito = analyse(&osservazioni, finestre(), archivio_vecchio());

        let TrendOutcome::Compared { distinct_keys, .. } = &esito.outcome else {
            panic!("il confronto doveva eseguirsi");
        };
        assert_eq!(*distinct_keys, 3, "termine, dominio e la voce di confronto");
    }

    /// Due esecuzioni sugli stessi fatti danno lo stesso esito.
    #[test]
    fn due_esecuzioni_danno_lo_stesso_esito() {
        let mut osservazioni = ripetuta("assalto", 6, 6);
        osservazioni.extend(ripetuta("corteo", 5, 6));
        osservazioni.extend(ripetuta("assalto", 2, 13));
        osservazioni.extend(ripetuta("corteo", 1, 13));

        assert_eq!(
            analyse(&osservazioni, finestre(), archivio_vecchio()),
            analyse(&osservazioni, finestre(), archivio_vecchio())
        );
    }

    /// Ogni genere ha un'etichetta propria e una forma d'archivio propria.
    #[test]
    fn ogni_genere_ha_un_nome_distinto() {
        let etichette: Vec<&str> = ObservationKind::all().iter().map(|k| k.label()).collect();
        let forme: Vec<&str> = ObservationKind::all().iter().map(|k| k.as_str()).collect();

        for elenco in [&etichette, &forme] {
            for voce in elenco {
                assert_eq!(
                    elenco.iter().filter(|altra| *altra == voce).count(),
                    1,
                    "nome ripetuto: {voce}"
                );
            }
        }
    }
}

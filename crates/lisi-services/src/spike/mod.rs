//! Aumenti anomali delle occorrenze, con metodo e soglie dichiarati.
//!
//! # La frase che questo modulo può dire, e quella che non può
//!
//! Può dire: **«le occorrenze di questa voce sono aumentate oltre la soglia
//! dichiarata»**. È un fatto aritmetico su conteggi registrati, e ogni numero
//! che lo compone è visibile.
//!
//! Non può dire che ci sia un attacco, una campagna, una minaccia o un
//! responsabile. Il congelamento lo scrive alla lettera — «aumento anomalo
//! delle occorrenze», non «attacco confermato» — e una prova impone che nel
//! sorgente di questo modulo e del metodo **non compaia** alcuna parola che
//! attribuisca un'intenzione.
//!
//! Non è pedanteria linguistica. Un conteggio che cresce e una parola che dice
//! «attacco» sono due cose diverse, e il salto fra le due è precisamente
//! l'attribuzione automatica di responsabilità che il confine della decisione
//! umana vieta.
//!
//! # Metodo e soglie: documentati **e versionati**
//!
//! Il piano chiede entrambe le cose. Il metodo sta in [`method`], che è un file
//! solo, e [`SPIKE_METHOD_VERSION`] lo numera. [`SPIKE_METHOD_FINGERPRINT`] è
//! l'impronta del suo sorgente, e una prova la ricalcola.
//!
//! Chi cambia la formula vede diventare rossa una prova che dice, per esteso,
//! di alzare la versione e aggiornare l'impronta. **Non può cambiarla di
//! nascosto**: un metodo che cambia senza cambiare numero rende incomparabili
//! due esiti a distanza di mesi, ed è peggio di non avere alcun numero, perché
//! ora c'è qualcosa che sembra affidabile. È la lezione di ENGINE-01.
//!
//! # La garanzia strutturale: gli intervalli sono tutti uguali, e l'osservato
//! non è fra quelli di confronto
//!
//! [`BucketedWindow`] ha i campi **privati** e **un solo costruttore**, che
//! ricava intervalli adiacenti e della stessa durata da una durata sola.
//! Intervalli disuguali confronterebbero durate invece di frequenze.
//!
//! E l'intervallo **osservato non entra nella mediana**: se ci entrasse, un
//! aumento alzerebbe la soglia che deve superare, nascondendosi in parte da
//! solo. La forma dei dati lo impedisce — la mediana riceve una fetta che
//! l'osservato non tocca — e una prova lo verifica.
//!
//! # Su che cosa il metodo si rifiuta di pronunciarsi
//!
//! Sulle stesse cose di TREND-01, per le stesse ragioni: archivio vuoto,
//! archivio più giovane del periodo, troppe osservazioni per contarle tutte. E
//! su una in più, propria di qui: **troppo pochi intervalli di confronto**. Una
//! mediana su tre valori non descrive un comportamento abituale, e chiamarla
//! così sarebbe la parte falsa del metodo.

pub mod method;

use std::collections::BTreeMap;

use lisi_core::Timestamp;
use lisi_core::digest::Sha256Digest;

use crate::trend::{Observation, ObservationKind};

pub use method::{
    DEVIATION_MULTIPLIER, MINIMUM_BASELINE_BUCKETS, MINIMUM_DEVIATION, MINIMUM_OBSERVED,
    SpikeMeasurement,
};

/// Versione del metodo di rilevazione.
///
/// # Che cosa numera
///
/// Numera **la formula**: come i conteggi diventano una soglia, e quando un
/// conteggio la supera. Non numera il prodotto, che ha una versione propria, né
/// il motore di analisi, che ha la sua.
///
/// **1** è il metodo com'è oggi. Il primo che lo modifichi porterà il 2, e la
/// prova dell'impronta glielo ricorderà.
pub const SPIKE_METHOD_VERSION: u32 = 1;

/// Il sorgente del metodo.
///
/// Uno solo, ed è tutto il metodo: bucket, mediana, scarto, soglia, decisione.
/// Questo modulo compone e nomina, e non decide.
const SPIKE_METHOD_SOURCES: &[&str] = &[include_str!("method.rs")];

/// Impronta del metodo alla versione [`SPIKE_METHOD_VERSION`].
///
/// Si aggiorna **soltanto** insieme alla versione, e la prova
/// `l_impronta_del_metodo_corrisponde_al_codice` impedisce di aggiornare l'una
/// senza l'altra.
pub const SPIKE_METHOD_FINGERPRINT: &str =
    "3d4856512b4898a9dce60ed7fc8de031b27a26f384ba2d51a5501ab8b202e440";

/// Calcola l'impronta del metodo dal proprio codice.
///
/// # Perché si ferma prima delle prove
///
/// Perché l'impronta deve coprire **il metodo**, non ciò che lo verifica.
/// Includendo il blocco di prova, correggere il nome di una prova alzerebbe la
/// versione del metodo — e una versione che si alza per motivi che non
/// riguardano la formula insegna ad alzarla senza pensarci, che è il modo più
/// veloce di togliere significato al numero.
///
/// È una differenza rispetto a `ENGINE_FINGERPRINT`, che include anche le
/// proprie prove. Quella milestone è chiusa e resta com'è: qui la scelta è
/// dichiarata, non silenziosa.
#[must_use]
pub fn spike_method_fingerprint() -> String {
    let produzione: Vec<&str> = SPIKE_METHOD_SOURCES
        .iter()
        .map(|sorgente| {
            sorgente
                .split_once("#[cfg(test)]")
                .map_or(*sorgente, |(prima, _)| prima)
        })
        .collect();

    Sha256Digest::of_text(&produzione.join("\n"))
        .as_str()
        .to_owned()
}

/// Come il metodo si nomina in una schermata e in un documento.
#[must_use]
pub fn spike_method_label() -> String {
    format!(
        "metodo v{SPIKE_METHOD_VERSION}: mediana + {DEVIATION_MULTIPLIER} \u{d7} scarto tipico, \
         scarto minimo {MINIMUM_DEVIATION}, almeno {MINIMUM_OBSERVED} occorrenze"
    )
}

/// Il periodo, diviso in intervalli uguali.
///
/// # Perché i campi sono privati
///
/// Perché il solo costruttore garantisce che gli intervalli siano **adiacenti e
/// della stessa durata**. Intervalli disuguali confronterebbero durate invece
/// di frequenze, ed è la stessa bugia che `ComparisonWindows` rende
/// inscrivibile in TREND-01.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketedWindow {
    /// Fine dell'intervallo osservato, esclusa.
    end: Timestamp,
    /// Durata di **ciascun** intervallo.
    bucket_ms: i64,
    /// Quanti intervalli in tutto, compreso l'osservato.
    bucket_count: usize,
}

impl BucketedWindow {
    /// L'unico modo di costruire un periodo diviso in intervalli.
    ///
    /// L'ultimo intervallo finisce a `end` e dura `bucket_ms`; i precedenti lo
    /// precedono, **tutti della stessa durata**.
    ///
    /// Restituisce `None` per una durata non positiva o per meno di due
    /// intervalli: con un intervallo solo non c'è nulla con cui confrontarlo.
    #[must_use]
    pub const fn ending_at(end: Timestamp, bucket_ms: i64, bucket_count: usize) -> Option<Self> {
        if bucket_ms <= 0 || bucket_count < 2 {
            return None;
        }
        Some(Self {
            end,
            bucket_ms,
            bucket_count,
        })
    }

    /// Inizio del primo intervallo di confronto.
    #[must_use]
    pub const fn start(&self) -> Timestamp {
        Timestamp::from_millis(self.end.as_millis() - self.bucket_ms * self.bucket_count as i64)
    }

    /// Fine dell'intervallo osservato, esclusa.
    #[must_use]
    pub const fn end(&self) -> Timestamp {
        self.end
    }

    /// Inizio dell'intervallo **osservato**.
    #[must_use]
    pub const fn observed_start(&self) -> Timestamp {
        Timestamp::from_millis(self.end.as_millis() - self.bucket_ms)
    }

    /// Durata di ciascun intervallo.
    #[must_use]
    pub const fn bucket_ms(&self) -> i64 {
        self.bucket_ms
    }

    /// Quanti intervalli di confronto: tutti tranne l'osservato.
    #[must_use]
    pub const fn baseline_buckets(&self) -> usize {
        self.bucket_count - 1
    }

    /// In quale intervallo cade un istante, se ci cade.
    ///
    /// Zero è il più vecchio; l'ultimo indice è quello osservato. Gli intervalli
    /// sono semiaperti — inizio compreso, fine esclusa — così si affiancano
    /// senza sovrapporsi.
    #[must_use]
    fn bucket_of(&self, at: Timestamp) -> Option<usize> {
        let dall_inizio = at.as_millis() - self.start().as_millis();
        if dall_inizio < 0 || at.as_millis() >= self.end.as_millis() {
            return None;
        }
        usize::try_from(dall_inizio / self.bucket_ms).ok()
    }

    /// Il periodo, per esteso.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        format!(
            "Intervallo osservato: dal {} al {}. Confronto: i {} intervalli precedenti, ciascuno \
             della stessa durata, dal {}.",
            self.observed_start().to_readable_local(),
            self.end.to_readable_local(),
            self.baseline_buckets(),
            self.start().to_readable_local(),
        )
    }
}

/// Perché il metodo non si è potuto applicare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpikeGap {
    /// L'archivio non contiene alcun contenuto.
    EmptyArchive,
    /// Il periodo comincia prima del primo contenuto archiviato.
    ArchiveTooYoung {
        /// Il primo istante di cui l'archivio sappia qualcosa.
        archive_since: Timestamp,
    },
    /// Gli intervalli di confronto sono troppo pochi per una mediana.
    NotEnoughBaseline {
        /// Quanti ce ne sono.
        have: usize,
        /// Quanti ne servono.
        need: usize,
    },
    /// Le osservazioni del periodo superano il limite di lettura.
    TooManyObservations {
        /// Il limite oltre il quale la lettura si ferma.
        limit: u32,
    },
}

impl SpikeGap {
    /// Che cosa manca, detto a chi legge.
    #[must_use]
    pub fn as_sentence(self) -> String {
        match self {
            Self::EmptyArchive => String::from(
                "L'archivio non contiene alcun contenuto: non c'\u{e8} nulla da misurare. Non \
                 significa che non ci siano aumenti \u{2014} significa che non \u{e8} stato \
                 ancora acquisito niente.",
            ),
            Self::ArchiveTooYoung { archive_since } => format!(
                "Il periodo comincia prima del primo contenuto archiviato ({}). Gli intervalli \
                 in cui NEXUM non guardava conterebbero zero, e ogni voce risulterebbe \
                 aumentata: il metodo non viene applicato.",
                archive_since.to_readable_local()
            ),
            Self::NotEnoughBaseline { have, need } => format!(
                "Gli intervalli di confronto sono {have}, e ne servono almeno {need}. Una \
                 mediana su pochi valori non descrive un comportamento abituale, e chiamarla \
                 cos\u{ec} sarebbe la parte falsa del metodo."
            ),
            Self::TooManyObservations { limit } => format!(
                "Il periodo contiene pi\u{f9} di {limit} osservazioni. Il metodo non viene \
                 applicato su una parte: una mediana calcolata su un insieme troncato \u{e8} un \
                 numero sbagliato, non una vista parziale."
            ),
        }
    }
}

/// Una voce le cui occorrenze sono aumentate oltre la soglia.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpikeFinding {
    /// Che genere di cosa.
    pub kind: ObservationKind,
    /// Il valore.
    pub key: String,
    /// La misura, con tutti i numeri che l'hanno prodotta.
    pub measurement: SpikeMeasurement,
}

impl SpikeFinding {
    /// Che cosa è stato misurato, e con quale metodo.
    ///
    /// # Perché la frase è lunga
    ///
    /// Perché il piano chiede che il metodo sia **spiegabile**, e una frase che
    /// dicesse «aumento anomalo» senza i numeri sarebbe un verdetto. Qui ci
    /// sono l'osservato, la mediana, lo scarto, la soglia e il conto che li
    /// lega: chi legge può rifarlo.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let misura = &self.measurement;

        let scarto = if misura.used_the_declared_floor() {
            format!(
                "lo scarto tipico misurato era 0 \u{2014} in quegli intervalli il conteggio non \
                 variava \u{2014} e si \u{e8} usato lo scarto minimo dichiarato, {}",
                misura.deviation_used
            )
        } else {
            format!("lo scarto tipico era {}", misura.deviation_used)
        };

        format!(
            "{} \u{ab}{}\u{bb}: {} occorrenze nell'intervallo osservato. Nei {} intervalli di \
             confronto la mediana era {} e {scarto}; la soglia dichiarata \u{e8} mediana + \
             {DEVIATION_MULTIPLIER} \u{d7} scarto = {}. \u{c8} un aumento delle occorrenze, e \
             nient'altro: non dice da chi, non dice perch\u{e9}, e non conferma alcun evento.",
            self.kind.label(),
            self.key,
            misura.observed,
            misura.baseline_buckets,
            misura.median,
            misura.threshold,
        )
    }
}

/// L'esito della misura.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpikeOutcome {
    /// Il metodo è stato applicato.
    Measured {
        /// Le voci sopra soglia, dal maggiore superamento.
        findings: Vec<SpikeFinding>,
        /// Quante voci distinte sono state misurate.
        examined_keys: usize,
    },
    /// Il metodo non si è potuto applicare, e si dice perché.
    NotMeasurable(SpikeGap),
}

/// Che cosa è aumentato oltre la soglia dichiarata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpikeReport {
    /// Il periodo e i suoi intervalli, che si dichiarano sempre.
    pub window: BucketedWindow,
    /// L'esito.
    pub outcome: SpikeOutcome,
}

impl SpikeReport {
    /// Quante voci sono sopra soglia, quando il metodo è stato applicato.
    ///
    /// `None` quando non si è potuto applicare: **zero e «non misurato» non
    /// sono la stessa cosa**.
    #[must_use]
    pub fn anomalous_count(&self) -> Option<usize> {
        match &self.outcome {
            SpikeOutcome::Measured { findings, .. } => Some(findings.len()),
            SpikeOutcome::NotMeasurable(_) => None,
        }
    }

    /// Le voci sopra soglia; vuoto quando il metodo non si è potuto applicare.
    #[must_use]
    pub fn findings(&self) -> &[SpikeFinding] {
        match &self.outcome {
            SpikeOutcome::Measured { findings, .. } => findings,
            SpikeOutcome::NotMeasurable(_) => &[],
        }
    }

    /// L'esito, con il periodo e il metodo sempre accanto.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match &self.outcome {
            SpikeOutcome::NotMeasurable(gap) => {
                format!("{} {}", gap.as_sentence(), self.window.as_sentence())
            }
            SpikeOutcome::Measured {
                findings,
                examined_keys,
            } => {
                let quante = match findings.len() {
                    0 => String::from(
                        "Nessuna voce supera la soglia dichiarata nell'intervallo osservato.",
                    ),
                    1 => String::from(
                        "Una voce supera la soglia dichiarata nell'intervallo osservato.",
                    ),
                    altre => format!(
                        "{altre} voci superano la soglia dichiarata nell'intervallo osservato."
                    ),
                };

                format!(
                    "{quante} Misurate {examined_keys} voci distinte con il {}. {} Un \
                     superamento della soglia \u{e8} un aumento delle occorrenze: non \u{e8} la \
                     conferma di alcun evento, e che cosa significhi lo stabilisce una persona.",
                    spike_method_label(),
                    self.window.as_sentence(),
                )
            }
        }
    }
}

/// Applica il metodo alle osservazioni di un periodo.
///
/// # Che cosa entra
///
/// Le osservazioni dell'intero periodo, già lette, e il primo istante di cui
/// l'archivio sappia qualcosa — che è ciò che impedisce di contare zero negli
/// intervalli in cui NEXUM non guardava.
///
/// # Non scrive nulla
///
/// Non può: questo modulo non conosce l'archivio.
#[must_use]
pub fn detect(
    observations: &[Observation],
    window: BucketedWindow,
    archive_since: Option<Timestamp>,
) -> SpikeReport {
    let Some(archive_since) = archive_since else {
        return SpikeReport {
            window,
            outcome: SpikeOutcome::NotMeasurable(SpikeGap::EmptyArchive),
        };
    };

    if window.start().as_millis() < archive_since.as_millis() {
        return SpikeReport {
            window,
            outcome: SpikeOutcome::NotMeasurable(SpikeGap::ArchiveTooYoung { archive_since }),
        };
    }

    if window.baseline_buckets() < MINIMUM_BASELINE_BUCKETS {
        return SpikeReport {
            window,
            outcome: SpikeOutcome::NotMeasurable(SpikeGap::NotEnoughBaseline {
                have: window.baseline_buckets(),
                need: MINIMUM_BASELINE_BUCKETS,
            }),
        };
    }

    let totali = window.baseline_buckets() + 1;
    let mut serie: BTreeMap<(ObservationKind, String), Vec<u32>> = BTreeMap::new();

    for observation in observations {
        let Some(intervallo) = window.bucket_of(observation.at) else {
            // Fuori dal periodo. Non è una svista: la lettura prende un
            // intervallo solo, e contare ciò che ne esce allargherebbe in
            // silenzio uno degli intervalli.
            continue;
        };
        let conteggi = serie
            .entry((observation.kind, observation.key.clone()))
            .or_insert_with(|| vec![0; totali]);
        if let Some(cella) = conteggi.get_mut(intervallo) {
            *cella += 1;
        }
    }

    let mut findings: Vec<SpikeFinding> = serie
        .iter()
        .filter_map(|((kind, key), conteggi)| {
            // L'ULTIMO intervallo è l'osservato, e non entra nella mediana: se
            // ci entrasse, un aumento alzerebbe la soglia che deve superare.
            let (baseline, osservato) = conteggi.split_at(conteggi.len() - 1);
            let measurement = method::measure(baseline, *osservato.first()?)?;
            measurement.is_anomalous().then(|| SpikeFinding {
                kind: *kind,
                key: key.clone(),
                measurement,
            })
        })
        .collect();

    // L'ordine è di quanto la soglia è stata superata: è il fatto stesso di cui
    // la riga riferisce, e ogni riga porta accanto i numeri che l'hanno
    // collocata (WQ-01, come in TREND-01).
    findings.sort_by(|left, right| {
        let sinistra = left.measurement.observed - left.measurement.threshold;
        let destra = right.measurement.observed - right.measurement.threshold;
        destra
            .cmp(&sinistra)
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.key.cmp(&right.key))
    });

    SpikeReport {
        window,
        outcome: SpikeOutcome::Measured {
            findings,
            examined_keys: serie.len(),
        },
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;

    use super::{
        BucketedWindow, DEVIATION_MULTIPLIER, MINIMUM_BASELINE_BUCKETS, MINIMUM_OBSERVED,
        SPIKE_METHOD_FINGERPRINT, SPIKE_METHOD_VERSION, SpikeGap, SpikeOutcome, detect,
        spike_method_fingerprint, spike_method_label,
    };
    use crate::trend::{Observation, ObservationKind};

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("mod.rs");

    /// Il metodo, per la guardia sul linguaggio.
    const METHOD_MODULE: &str = include_str!("method.rs");

    const GIORNO: i64 = 24 * 60 * 60 * 1_000;
    const ORA_ZERO: i64 = 1_700_000_000_000;

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    /// Il codice di produzione di un modulo, senza i commenti.
    fn senza_commenti(sorgente: &str) -> String {
        let produzione = sorgente
            .split_once("#[cfg(test)]\nmod tests {")
            .map_or(sorgente, |(prima, _)| prima);
        produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Il blocco di una dichiarazione, dal nome alla graffa che la chiude.
    fn blocco_di(nome: &str) -> String {
        let produzione = senza_commenti(THIS_MODULE);
        let Some(inizio) = produzione.find(nome) else {
            panic!("il modulo deve dichiarare {nome}");
        };
        let resto = &produzione[inizio..];
        let Some(fine) = resto.find("\n}\n") else {
            panic!("la dichiarazione {nome} deve chiudersi");
        };
        resto[..fine].to_owned()
    }

    /// Il periodo standard: otto intervalli da un giorno.
    fn periodo(intervalli: usize) -> BucketedWindow {
        let Some(periodo) = BucketedWindow::ending_at(istante(ORA_ZERO), GIORNO, intervalli) else {
            panic!("il periodo di prova deve potersi costruire");
        };
        periodo
    }

    /// Osservazioni di una voce, con i conteggi indicati intervallo per
    /// intervallo, dal più vecchio.
    fn serie(chiave: &str, conteggi: &[u32], intervalli: usize) -> Vec<Observation> {
        let mut osservazioni = Vec::new();
        for (indice, quante) in conteggi.iter().enumerate() {
            // L'intervallo `indice` va da start + indice giorni a + 1 giorno;
            // si mette l'osservazione a meta' dell'intervallo.
            let inizio = ORA_ZERO - (intervalli as i64 - indice as i64) * GIORNO;
            for _ in 0..*quante {
                osservazioni.push(Observation {
                    kind: ObservationKind::Term,
                    key: chiave.to_owned(),
                    at: istante(inizio + GIORNO / 2),
                });
            }
        }
        osservazioni
    }

    /// L'archivio comincia prima del periodo.
    fn archivio_vecchio(intervalli: usize) -> Option<Timestamp> {
        Some(istante(ORA_ZERO - (intervalli as i64 + 1) * GIORNO))
    }

    /// **L'impronta del metodo corrisponde al codice del metodo.**
    ///
    /// # Che cosa fare quando questa prova diventa rossa
    ///
    /// Vuol dire che il metodo di rilevazione è cambiato. Due gesti, in
    /// quest'ordine:
    ///
    /// 1. **alzare `SPIKE_METHOD_VERSION`** di uno;
    /// 2. sostituire `SPIKE_METHOD_FINGERPRINT` con il valore che questa prova
    ///    stampa.
    ///
    /// Il secondo senza il primo è il difetto che questa prova esiste per
    /// impedire: due metodi diversi che dichiarano lo stesso numero rendono
    /// incomparabili due esiti a distanza di mesi, ed è peggio di non avere
    /// alcun numero — perché ora c'è qualcosa che sembra affidabile.
    ///
    /// Se il cambiamento era **solo** un commento, si alza comunque la
    /// versione: distinguere «un commento» da «una formula» è il giudizio che
    /// una guardia non può dare.
    #[test]
    fn l_impronta_del_metodo_corrisponde_al_codice() {
        let calcolata = spike_method_fingerprint();

        assert_eq!(
            calcolata, SPIKE_METHOD_FINGERPRINT,
            "\n\nIL METODO DI RILEVAZIONE E' CAMBIATO.\n\n\
             Alzare SPIKE_METHOD_VERSION (oggi {SPIKE_METHOD_VERSION}) e sostituire\n\
             SPIKE_METHOD_FINGERPRINT con:\n\n  \"{calcolata}\"\n\n\
             Aggiornare l'impronta SENZA alzare la versione e' il difetto che\n\
             questa prova esiste per impedire: due metodi diversi che\n\
             dichiarano lo stesso numero.\n"
        );
    }

    /// L'impronta è stabile.
    #[test]
    fn l_impronta_e_stabile() {
        assert_eq!(spike_method_fingerprint(), spike_method_fingerprint());
        assert_eq!(spike_method_fingerprint().len(), 64);
    }

    /// **Il metodo si nomina con le proprie soglie.**
    ///
    /// Il piano chiede che metodo e soglie siano documentati: una frase che
    /// dicesse soltanto «metodo v1» documenterebbe il numero e non il metodo.
    #[test]
    fn il_metodo_si_nomina_con_le_proprie_soglie() {
        let etichetta = spike_method_label();

        assert!(
            etichetta.contains(&SPIKE_METHOD_VERSION.to_string()),
            "{etichetta}"
        );
        assert!(etichetta.contains("mediana"), "{etichetta}");
        assert!(
            etichetta.contains(&DEVIATION_MULTIPLIER.to_string()),
            "{etichetta}"
        );
        assert!(
            etichetta.contains(&MINIMUM_OBSERVED.to_string()),
            "{etichetta}"
        );
    }

    /// **Nessuna parola attribuisce un'intenzione.**
    ///
    /// Il congelamento lo scrive alla lettera: «aumento anomalo delle
    /// occorrenze», non «attacco confermato». Un conteggio che cresce e una
    /// parola che dice «attacco» sono due cose diverse, e il salto fra le due è
    /// l'attribuzione automatica di responsabilità che il confine della
    /// decisione umana vieta.
    #[test]
    fn nessuna_parola_di_questo_modulo_attribuisce_un_intenzione() {
        for (nome, sorgente) in [("mod.rs", THIS_MODULE), ("method.rs", METHOD_MODULE)] {
            let codice = senza_commenti(sorgente).to_lowercase();
            for vietata in [
                "attacco",
                "attacchi",
                "minaccia",
                "campagna",
                "colpevole",
                "responsabil",
                "pericolos",
                "sospett",
                "malevol",
                "criminal",
                "estremis",
            ] {
                assert!(
                    !codice.contains(vietata),
                    "in {nome} compare «{vietata}»: un aumento delle occorrenze non attribuisce \
                     un'intenzione a nessuno"
                );
            }
        }
    }

    /// **Ogni riga dichiara di essere un aumento e nient'altro.**
    #[test]
    fn ogni_riga_dichiara_di_non_confermare_alcun_evento() {
        let osservazioni = serie("assalto", &[0, 0, 0, 0, 5, 5, 5, 30], 8);
        let esito = detect(&osservazioni, periodo(8), archivio_vecchio(8));

        let SpikeOutcome::Measured { findings, .. } = &esito.outcome else {
            panic!("il metodo doveva applicarsi: {:?}", esito.outcome);
        };
        assert_eq!(findings.len(), 1, "{findings:?}");

        let frase = findings[0].as_sentence();
        assert!(frase.contains("non conferma alcun evento"), "{frase}");
        assert!(frase.contains("30 occorrenze"), "{frase}");
        assert!(frase.contains("la mediana era"), "{frase}");
        assert!(frase.contains("soglia dichiarata"), "{frase}");
    }

    /// **Non esiste un modo di costruire intervalli disuguali.**
    #[test]
    fn non_esiste_un_modo_di_costruire_intervalli_disuguali() {
        let blocco = blocco_di("pub struct BucketedWindow {");
        for riga in blocco.lines().filter(|riga| riga.contains(':')) {
            assert!(
                !riga.trim_start().starts_with("pub "),
                "i campi del periodo devono restare privati: «{}»",
                riga.trim()
            );
        }

        assert_eq!(
            senza_commenti(THIS_MODULE)
                .matches("-> Option<Self>")
                .count(),
            1,
            "il periodo deve avere un solo costruttore"
        );
    }

    /// Con meno di due intervalli non c'è nulla da confrontare.
    #[test]
    fn con_meno_di_due_intervalli_non_si_costruisce_un_periodo() {
        assert!(BucketedWindow::ending_at(istante(ORA_ZERO), GIORNO, 1).is_none());
        assert!(BucketedWindow::ending_at(istante(ORA_ZERO), 0, 8).is_none());
    }

    /// **Questo modulo non conosce l'archivio.**
    #[test]
    fn il_metodo_non_ha_alcun_modo_di_scrivere() {
        for sorgente in [THIS_MODULE, METHOD_MODULE] {
            let codice = senza_commenti(sorgente);
            assert!(!codice.contains("lisi_storage"));
            assert!(!codice.contains("Database"));
        }
    }

    /// **Nessun punteggio dell'anomalia.**
    #[test]
    fn nessun_punteggio_dell_anomalia_puo_entrare() {
        for sorgente in [THIS_MODULE, METHOD_MODULE] {
            let codice = senza_commenti(sorgente);
            for vietato in ["f32", "f64", "as f", "percent", "score"] {
                assert!(
                    !codice.contains(vietato),
                    "«{vietato}» apre la strada a un punteggio dell'anomalia"
                );
            }
        }
    }

    /// **L'intervallo osservato non entra nella mediana.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Se l'osservato entrasse fra i valori di confronto, un aumento alzerebbe
    /// la soglia che deve superare, nascondendosi in parte da solo.
    ///
    /// I conteggi sono scelti perché la differenza si veda: con i sette
    /// intervalli di confronto `0 0 0 0 5 5 5` la mediana è 0 e la soglia 3, e
    /// 6 la supera. Includendo l'osservato la mediana salirebbe a 2, lo scarto
    /// a 2 e la soglia a 8: **lo stesso aumento non risulterebbe**.
    #[test]
    fn l_intervallo_osservato_non_entra_nella_mediana() {
        let osservazioni = serie("assalto", &[0, 0, 0, 0, 5, 5, 5, 6], 8);
        let esito = detect(&osservazioni, periodo(8), archivio_vecchio(8));

        let SpikeOutcome::Measured { findings, .. } = &esito.outcome else {
            panic!("il metodo doveva applicarsi");
        };
        assert_eq!(findings.len(), 1, "{findings:?}");

        let misura = findings[0].measurement;
        assert_eq!(misura.observed, 6);
        assert_eq!(misura.baseline_buckets, 7);
        assert_eq!(misura.median, 0, "la mediana e' quella dei soli confronti");
        assert_eq!(misura.threshold, DEVIATION_MULTIPLIER);
    }

    /// Sotto il minimo assoluto di occorrenze non compare nulla.
    #[test]
    fn sotto_il_minimo_di_occorrenze_non_compare_nulla() {
        let sotto = MINIMUM_OBSERVED - 1;
        let osservazioni = serie("raro", &[0, 0, 0, 0, 0, 0, 0, sotto], 8);
        let esito = detect(&osservazioni, periodo(8), archivio_vecchio(8));

        let SpikeOutcome::Measured { findings, .. } = &esito.outcome else {
            panic!("il metodo doveva applicarsi");
        };
        assert!(findings.is_empty(), "{findings:?}");
    }

    /// **Con troppo pochi intervalli di confronto non si misura.**
    #[test]
    fn con_pochi_intervalli_di_confronto_non_si_misura() {
        let intervalli = MINIMUM_BASELINE_BUCKETS;
        let osservazioni = serie("assalto", &[0, 0, 0, 0, 5, 5, 30], intervalli);
        let esito = detect(
            &osservazioni,
            periodo(intervalli),
            archivio_vecchio(intervalli),
        );

        assert!(
            matches!(
                esito.outcome,
                SpikeOutcome::NotMeasurable(SpikeGap::NotEnoughBaseline { .. })
            ),
            "{:?}",
            esito.outcome
        );
        assert_eq!(esito.anomalous_count(), None);
        assert!(
            esito
                .as_sentence()
                .contains("non descrive un comportamento")
        );
    }

    /// **Su un archivio più giovane del periodo non si misura.**
    ///
    /// Gli intervalli in cui NEXUM non guardava conterebbero zero, e ogni voce
    /// risulterebbe aumentata.
    #[test]
    fn su_un_archivio_piu_giovane_del_periodo_non_si_misura() {
        let osservazioni = serie("assalto", &[0, 0, 0, 0, 5, 5, 5, 30], 8);
        let esito = detect(
            &osservazioni,
            periodo(8),
            Some(istante(ORA_ZERO - 3 * GIORNO)),
        );

        assert!(matches!(
            esito.outcome,
            SpikeOutcome::NotMeasurable(SpikeGap::ArchiveTooYoung { .. })
        ));
        assert!(esito.as_sentence().contains("non guardava"));
    }

    /// Un archivio vuoto non dice che non ci siano aumenti.
    #[test]
    fn senza_archivio_non_si_dice_che_non_ci_sono_aumenti() {
        let esito = detect(&[], periodo(8), None);

        assert!(matches!(
            esito.outcome,
            SpikeOutcome::NotMeasurable(SpikeGap::EmptyArchive)
        ));
        assert_eq!(esito.anomalous_count(), None);
        assert!(
            esito
                .as_sentence()
                .contains("non \u{e8} stato ancora acquisito niente")
        );
    }

    /// **Quando lo scarto misurato è zero, la frase lo dichiara.**
    ///
    /// Tacere la sostituzione presenterebbe come misurata una soglia che è
    /// stata scelta.
    #[test]
    fn quando_lo_scarto_e_zero_la_frase_dichiara_la_sostituzione() {
        // Sette intervalli di confronto tutti a zero: scarto misurato zero.
        let osservazioni = serie("assalto", &[0, 0, 0, 0, 0, 0, 0, 20], 8);
        let esito = detect(&osservazioni, periodo(8), archivio_vecchio(8));

        let SpikeOutcome::Measured { findings, .. } = &esito.outcome else {
            panic!("il metodo doveva applicarsi");
        };
        assert_eq!(findings.len(), 1);
        assert!(findings[0].measurement.used_the_declared_floor());

        let frase = findings[0].as_sentence();
        assert!(frase.contains("scarto minimo dichiarato"), "{frase}");
        assert!(frase.contains("il conteggio non variava"), "{frase}");
    }

    /// **Zero voci sopra soglia si dice solo dopo aver misurato.**
    #[test]
    fn zero_dopo_aver_misurato_non_e_la_stessa_cosa_di_non_misurato() {
        let stabile = serie("assalto", &[5, 5, 5, 5, 5, 5, 5, 5], 8);
        let misurato = detect(&stabile, periodo(8), archivio_vecchio(8));
        assert_eq!(misurato.anomalous_count(), Some(0));

        let non_misurato = detect(&[], periodo(8), None);
        assert_eq!(non_misurato.anomalous_count(), None);
    }

    /// L'esito dichiara sempre il metodo e il periodo su cui è stato calcolato.
    #[test]
    fn ogni_esito_dichiara_metodo_e_periodo() {
        let stabile = serie("assalto", &[5, 5, 5, 5, 5, 5, 5, 5], 8);
        let esito = detect(&stabile, periodo(8), archivio_vecchio(8));

        let frase = esito.as_sentence();
        assert!(frase.contains("Intervallo osservato:"), "{frase}");
        assert!(frase.contains(&spike_method_label()), "{frase}");
        assert!(
            frase.contains("non \u{e8} la conferma di alcun evento"),
            "{frase}"
        );
    }

    /// Due esecuzioni sugli stessi fatti danno lo stesso esito.
    #[test]
    fn due_esecuzioni_danno_lo_stesso_esito() {
        let mut osservazioni = serie("assalto", &[0, 0, 0, 0, 5, 5, 5, 30], 8);
        osservazioni.extend(serie("corteo", &[2, 2, 2, 2, 2, 2, 2, 40], 8));

        assert_eq!(
            detect(&osservazioni, periodo(8), archivio_vecchio(8)),
            detect(&osservazioni, periodo(8), archivio_vecchio(8))
        );
    }
}

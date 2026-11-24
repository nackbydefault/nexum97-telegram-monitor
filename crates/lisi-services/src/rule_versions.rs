//! Le versioni delle regole che mettono un elemento sullo schermo (PR-02,
//! ADR-0119).
//!
//! # Perché una versione per ogni regola
//!
//! Perché «che cosa lo ha fatto comparire» si dice con il nome della regola
//! **e la sua versione**. Chi rilegge un atto fra sei mesi deve sapere se la
//! regola di allora è quella di oggi, e il nome da solo non lo dice.
//!
//! # Perché ogni versione ha un'impronta
//!
//! Perché una versione che nessuno aggiorna è un numero che mente. Ogni versione
//! qui sotto ha l'impronta SHA-256 **del codice delle funzioni che decidono la
//! regola** — non del file intero: le prove e il codice di servizio non la
//! muovono. Chi cambia una di quelle funzioni vede fallire
//! `ogni_impronta_corrisponde_al_codice`, che dice per esteso di alzare la
//! versione e aggiornare l'impronta. È la disciplina di ENGINE-01 (motore di
//! analisi) e di SPIKE-01 (aumenti), che avevano già la loro, applicata al
//! resto.
//!
//! # Perché tutte partono da 1
//!
//! Perché 1 è il codice di oggi, ed è anche il codice che ha prodotto ciò che
//! c'è già sullo schermo. Il primo che modifichi una regola porterà il 2.

use lisi_core::analysis::ENGINE_VERSION;
use lisi_core::model::explanation::{Explained, RuleVersion};

use crate::spike::SPIKE_METHOD_VERSION;

/// Una regola con la sua versione e l'impronta del codice che la decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionedRule {
    /// Il genere di elemento che la regola mette sullo schermo.
    pub explained: Explained,
    /// La versione.
    pub version: u32,
    /// L'impronta del codice alla versione [`Self::version`].
    pub fingerprint: &'static str,
}

/// Le regole versionate qui. Il motore di analisi e gli aumenti hanno la loro
/// versione nei rispettivi moduli.
pub const RULES: [VersionedRule; 12] = [
    VersionedRule {
        explained: Explained::Content,
        version: 2,
        fingerprint: "1bad49e46c0c5173f7ca7d4a9b3d8f458a6041f305b11b47cd115d1ef28a1f4e",
    },
    VersionedRule {
        explained: Explained::Alert,
        version: 1,
        fingerprint: "48ad5bb419862f389d3fbc693c24a944fd7c7d366b0e7aa007c4cbada8142819",
    },
    VersionedRule {
        explained: Explained::CyberEvent,
        version: 1,
        fingerprint: "124ea3a2a3b20bc97a8b7875b14809706ce40994c3b56bace671026829e4eeaa",
    },
    VersionedRule {
        explained: Explained::CyberWatchRow { by_a_person: false },
        version: 1,
        fingerprint: "6ae10d0e44bee2214f3b485a6fa6ac3f657c0cae9035e4382378226b5c50284d",
    },
    VersionedRule {
        explained: Explained::SourceSuggestion,
        version: 1,
        fingerprint: "05618f5c8d465e462c4ff0d8cf4a02e00548cc5bcc912f1d1d76aad58cb1528c",
    },
    VersionedRule {
        explained: Explained::DiscoveryResult,
        version: 1,
        fingerprint: "21a219daf859a4c3bfda4d9e132a3c8b21bf64e8b80fccea695ec082c28eef66",
    },
    VersionedRule {
        explained: Explained::WorkQueueItem,
        // Impronta rifatta senza alzare la versione, due volte.
        //
        // La prima (OPERATOR-UX-REMEDIATION-01, OS-10): `into_item` porta
        // anche il testo del contenuto, da mostrare nella riga.
        //
        // La seconda (FINAL-FPR-ALL-16, DEC-387 punto 6): `why_here` nomina
        // una schermata, e quella schermata ha cambiato nome — «Segnali
        // cyber» invece di «Cyber Watch».
        //
        // In entrambi i casi l'ordine e i fatti che lo decidono non sono
        // cambiati: lo stesso archivio mette sullo schermo gli stessi
        // elementi, nello stesso ordine. E' il punto 3 della prova.
        version: 1,
        fingerprint: "27f8eb93ab37e792742f9eda64e06255ae548595306ac13c5b8ba01517cf7e9b",
    },
    VersionedRule {
        explained: Explained::GraphNode { by_a_person: false },
        version: 1,
        fingerprint: "25347973b2431894fd9da507434b3958e3dd8eb83de045db65a69249e5c7765a",
    },
    VersionedRule {
        explained: Explained::Trend,
        version: 1,
        fingerprint: "a6c6da0f8b4c1a4b7bce9eaeed4a16d7606847b2202dbd7e3160f22a1a39f8ea",
    },
    VersionedRule {
        explained: Explained::Resemblance,
        version: 1,
        fingerprint: "d921c0d495e735116e27194e2a43d3c46bb7507f53e3a192372efcd55ff0310f",
    },
    VersionedRule {
        explained: Explained::PersonAssociation,
        version: 1,
        fingerprint: "64b923c36b0ac13c34caa8a122e21c6d7fc977cd887a07ee1ca76568688e22e0",
    },
    VersionedRule {
        explained: Explained::CoverageGap,
        version: 2,
        fingerprint: "b24ab18e4965a7b75c96fd1e8e678bbea8d66e117811ca06339db0e428aeeefa",
    },
];

/// La versione di una regola in [`RULES`].
///
/// Le varianti che dipendono da chi ha agito condividono la regola: il grafo
/// mostra con la stessa regola un collegamento osservato e uno deciso.
const fn registered(explained: Explained) -> u32 {
    let mut indice = 0;
    while indice < RULES.len() {
        if same_rule(RULES[indice].explained, explained) {
            return RULES[indice].version;
        }
        indice += 1;
    }
    // Irraggiungibile: `current_version` chiama questa funzione soltanto per i
    // generi in `RULES`, e la prova `ogni_genere_ha_una_versione` lo verifica.
    0
}

/// Se due generi sono messi sullo schermo dalla stessa regola.
const fn same_rule(uno: Explained, altro: Explained) -> bool {
    matches!(
        (uno, altro),
        (Explained::Content, Explained::Content)
            | (Explained::Alert, Explained::Alert)
            | (Explained::CyberEvent, Explained::CyberEvent)
            | (
                Explained::CyberWatchRow { .. },
                Explained::CyberWatchRow { .. }
            )
            | (Explained::SourceSuggestion, Explained::SourceSuggestion)
            | (Explained::DiscoveryResult, Explained::DiscoveryResult)
            | (Explained::WorkQueueItem, Explained::WorkQueueItem)
            | (Explained::GraphNode { .. }, Explained::GraphNode { .. })
            | (Explained::Trend, Explained::Trend)
            | (Explained::Resemblance, Explained::Resemblance)
            | (Explained::PersonAssociation, Explained::PersonAssociation)
            | (Explained::CoverageGap, Explained::CoverageGap)
    )
}

/// La versione **di oggi** della regola che mette sullo schermo un elemento di
/// quel genere.
///
/// Per un livello e un riscontro già registrati la versione giusta è quella
/// **registrata** con il contenuto, non questa: la sceglie
/// [`crate::why::explain_level`].
#[must_use]
pub const fn current_version(explained: Explained) -> RuleVersion {
    match explained {
        Explained::Level | Explained::Match => RuleVersion::Known(ENGINE_VERSION),
        Explained::Spike => RuleVersion::Known(SPIKE_METHOD_VERSION),
        Explained::Content
        | Explained::Alert
        | Explained::CyberEvent
        | Explained::CyberWatchRow { .. }
        | Explained::SourceSuggestion
        | Explained::DiscoveryResult
        | Explained::WorkQueueItem
        | Explained::GraphNode { .. }
        | Explained::Trend
        | Explained::Resemblance
        | Explained::PersonAssociation
        | Explained::CoverageGap => RuleVersion::Known(registered(explained)),
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::digest::Sha256Digest;
    use lisi_core::model::explanation::{Explained, RuleVersion};

    use super::{RULES, current_version};

    /// I punti del codice che decidono ciascuna regola.
    ///
    /// # Quando si aggiorna questa tabella
    ///
    /// Quando una regola **si sposta**: se una decisione finisce in una
    /// funzione nuova, la funzione va aggiunta qui, altrimenti l'impronta non
    /// la vede (ADR-0119, rischio residuo).
    fn punti_di_decisione(genere: Explained) -> Vec<(&'static str, &'static [&'static str])> {
        const STORICO: &str = include_str!("history.rs");
        const ANALISI: &str = include_str!("../../lisi-core/src/model/analysis.rs");
        const CYBER: &str = include_str!("cyber_watch.rs");
        const ORDINE: &str = include_str!("../../lisi-core/src/model/discovery_rank.rs");
        const SCOPERTA: &str = include_str!("discovery.rs");
        const CODA: &str = include_str!("work_queue.rs");
        const GRAFO: &str = include_str!("evidence_graph.rs");
        const TENDENZA: &str = include_str!("trend.rs");
        const SOMIGLIANZA: &str = include_str!("similarity.rs");
        const ASSOCIAZIONI: &str = include_str!("association.rs");
        const PERIODI: &str = include_str!("gap.rs");

        match genere {
            Explained::Content => vec![(
                STORICO,
                &[
                    "pub fn entries(",
                    "pub fn matching(",
                    "fn accepts(",
                    "fn matches_query(",
                    "pub fn alerts_only(",
                ],
            )],
            Explained::Alert => vec![(ANALISI, &["pub const fn raises_alert(self)"])],
            Explained::CyberEvent => {
                vec![(CYBER, &["pub const MEMBERS_PER_EVENT", "pub fn events_of("])]
            }
            Explained::CyberWatchRow { .. } => vec![(CYBER, &["pub fn timeline_of("])],
            Explained::SourceSuggestion => vec![(
                ORDINE,
                &[
                    "fn confronta(",
                    "fn distingue(",
                    "pub fn rank(",
                    "pub fn rank_with<T>(",
                ],
            )],
            Explained::DiscoveryResult => vec![(
                SCOPERTA,
                &["pub fn runs(", "pub fn run_detail(", "fn candidati_da("],
            )],
            Explained::WorkQueueItem => vec![(
                CODA,
                &[
                    "pub fn why_here(",
                    "fn queue_order(",
                    "pub fn compose(",
                    "fn into_item(",
                ],
            )],
            Explained::GraphNode { .. } => vec![(
                GRAFO,
                &[
                    "pub const EDGES_PER_NODE",
                    "pub fn edges_of_session_on(",
                    "pub fn edges_of_events_on(",
                    "pub fn edges_of_subject_on(",
                    "pub fn neighbourhood_of_session(",
                ],
            )],
            Explained::Trend => vec![(
                TENDENZA,
                &[
                    "pub const DEFAULT_WINDOW_MS",
                    "pub const MINIMUM_OCCURRENCES",
                    "pub fn analyse(",
                ],
            )],
            Explained::Resemblance => vec![(
                SOMIGLIANZA,
                &[
                    "pub const SHINGLE_WORDS",
                    "pub const MINIMUM_SHARED_PERCENT",
                    "pub fn shingles(",
                    "const fn percentuale(",
                    "pub fn compare_against(",
                ],
            )],
            Explained::PersonAssociation => vec![(
                ASSOCIAZIONI,
                &["pub fn for_session(", "pub fn for_identity("],
            )],
            Explained::CoverageGap => vec![(
                PERIODI,
                &[
                    "pub const OBSERVATION_DAYS",
                    "pub const MIN_ARRIVALS",
                    "pub const HIGH_FACTOR",
                    "pub fn mean_interval_ms(",
                    "pub const fn priority_of(",
                    "pub fn observed_rhythm(",
                    "pub fn assess_source(",
                    "pub fn order(",
                    "pub fn assess(",
                    "fn arrivals_by_source(",
                ],
            )],
            // Versionati altrove, con la loro impronta: ENGINE-01 e SPIKE-01.
            Explained::Level | Explained::Match | Explained::Spike => Vec::new(),
        }
    }

    /// Il testo di un elemento del sorgente: una funzione fino alla graffa che
    /// la chiude, una costante fino al punto e virgola.
    ///
    /// Salta commenti, stringhe e caratteri, perché una graffa dentro una
    /// stringa di formato non chiude niente.
    fn elemento(sorgente: &str, firma: &str) -> String {
        let produzione = sorgente
            .split_once("#[cfg(test)]\nmod tests {")
            .map_or(sorgente, |(codice, _)| codice);
        assert_eq!(
            produzione.matches(firma).count(),
            1,
            "la firma «{firma}» deve comparire una volta sola nel codice di produzione"
        );
        let Some(inizio) = produzione.find(firma) else {
            panic!("la firma «{firma}» non è nel codice di produzione");
        };
        let costante = !firma.contains("fn ");
        let byte = produzione.as_bytes();
        let mut i = inizio;
        let mut profondita = 0_i32;
        let mut aperta = false;

        while i < byte.len() {
            match byte[i] {
                b'/' if byte.get(i + 1) == Some(&b'/') => {
                    while i < byte.len() && byte[i] != b'\n' {
                        i += 1;
                    }
                }
                b'/' if byte.get(i + 1) == Some(&b'*') => {
                    i += 2;
                    while i + 1 < byte.len() && !(byte[i] == b'*' && byte[i + 1] == b'/') {
                        i += 1;
                    }
                    i += 1;
                }
                b'r' if i > 0
                    && !(byte[i - 1].is_ascii_alphanumeric() || byte[i - 1] == b'_')
                    && matches!(byte.get(i + 1), Some(b'"' | b'#')) =>
                {
                    let mut cancelletti = 0;
                    let mut j = i + 1;
                    while byte.get(j) == Some(&b'#') {
                        cancelletti += 1;
                        j += 1;
                    }
                    if byte.get(j) == Some(&b'"') {
                        let chiusura = format!("\"{}", "#".repeat(cancelletti));
                        let Some(fine) = produzione[j + 1..].find(&chiusura) else {
                            panic!("stringa grezza non chiusa dopo «{firma}»");
                        };
                        i = j + 1 + fine + chiusura.len() - 1;
                    }
                }
                b'"' => {
                    i += 1;
                    while i < byte.len() && byte[i] != b'"' {
                        if byte[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                }
                b'\'' => {
                    let resto = &produzione[i + 1..];
                    let mut caratteri = resto.chars();
                    match caratteri.next() {
                        // Un carattere con la barra: la chiusura viene dopo il
                        // carattere che la barra protegge, anche se è un apice.
                        Some('\\') => {
                            if let Some(fine) = resto.get(2..).and_then(|coda| coda.find('\'')) {
                                i += 1 + 2 + fine;
                            }
                        }
                        Some(carattere) if resto[carattere.len_utf8()..].starts_with('\'') => {
                            i += carattere.len_utf8() + 1;
                        }
                        // Una durata, come `'a`: non apre niente.
                        _ => {}
                    }
                }
                b'{' => {
                    profondita += 1;
                    aperta = true;
                }
                b'}' => {
                    profondita -= 1;
                    if aperta && profondita == 0 {
                        return produzione[inizio..=i].to_owned();
                    }
                }
                b';' if costante && profondita == 0 => {
                    return produzione[inizio..=i].to_owned();
                }
                _ => {}
            }
            i += 1;
        }
        panic!("l'elemento «{firma}» non si chiude");
    }

    fn impronta(genere: Explained) -> String {
        let mut parti = Vec::new();
        for (sorgente, firme) in punti_di_decisione(genere) {
            for firma in firme {
                parti.push(elemento(sorgente, firma));
            }
        }
        Sha256Digest::of_text(&parti.join("\n")).as_str().to_owned()
    }

    /// **Una regola non cambia senza cambiare versione.**
    ///
    /// Se questa prova fallisce, una delle funzioni che decidono la regola è
    /// cambiata. Si fa così:
    ///
    /// 1. se la regola è cambiata davvero — cioè lo stesso archivio metterebbe
    ///    sullo schermo elementi diversi, o in un ordine diverso — si alza
    ///    `version` di uno;
    /// 2. si sostituisce `fingerprint` con il valore che questa prova stampa;
    /// 3. se è cambiato solo un commento, si aggiorna l'impronta e **non** la
    ///    versione, e lo si scrive nel messaggio del commit.
    #[test]
    fn ogni_impronta_corrisponde_al_codice() {
        let mut sbagliate = Vec::new();
        for regola in RULES {
            let calcolata = impronta(regola.explained);
            if calcolata != regola.fingerprint {
                sbagliate.push(format!(
                    "«{}» v{}: l'impronta registrata è {}, quella del codice è\n  \"{calcolata}\"",
                    regola.explained.rule_name(),
                    regola.version,
                    regola.fingerprint
                ));
            }
        }
        assert!(
            sbagliate.is_empty(),
            "il codice di una regola è cambiato senza che la sua versione cambiasse.\n\
             Se la regola è cambiata, alzarne la versione; poi aggiornare l'impronta:\n\n{}",
            sbagliate.join("\n")
        );
    }

    /// **Ogni genere ha una versione nota**, e nessuna è zero.
    #[test]
    fn ogni_genere_ha_una_versione() {
        for genere in Explained::ALL {
            let RuleVersion::Known(versione) = current_version(genere) else {
                panic!("{genere:?}: la versione di oggi deve essere nota");
            };
            assert!(versione >= 1, "{genere:?}: versione {versione}");
        }
    }

    /// **Ogni regola registrata ha dei punti di decisione**, e ognuno esiste.
    ///
    /// Una regola senza punti avrebbe l'impronta del testo vuoto, che non
    /// cambia mai: una guardia che passa a vuoto (ADR-0111).
    #[test]
    fn nessuna_regola_ha_l_impronta_del_vuoto() {
        let vuota = Sha256Digest::of_text("").as_str().to_owned();
        for regola in RULES {
            assert!(
                !punti_di_decisione(regola.explained).is_empty(),
                "{:?} non ha punti di decisione",
                regola.explained
            );
            assert_ne!(impronta(regola.explained), vuota);
        }
    }

    /// **L'estrattore sa dove finisce una funzione**, anche con graffe nelle
    /// stringhe, nei caratteri e nei commenti.
    #[test]
    fn l_estrattore_salta_stringhe_caratteri_e_commenti() {
        let sorgente = "fn prima() {\n    let a = \"}\";\n    let b = '}';\n    let e = '\\'';\n    // }\n    \
                        let c = r#\"}\"#;\n    let d: &'static str = \"x\";\n    if a.is_empty() { \
                        return; }\n}\nfn dopo() {}\npub const X: u32 = 3;\n";
        let prima = elemento(sorgente, "fn prima(");
        assert!(prima.ends_with("return; }\n}"), "{prima}");
        assert_eq!(elemento(sorgente, "pub const X"), "pub const X: u32 = 3;");
    }
}

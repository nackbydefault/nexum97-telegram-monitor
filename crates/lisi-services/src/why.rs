//! «Perché sto vedendo questo?» sui soggetti che non sono un contenuto (PROV-02).
//!
//! # Che cosa fa questo modulo
//!
//! Raccoglie. Ogni cosa spiega già sé stessa — un grappolo dice perché i suoi
//! contenuti stanno insieme, un arco per quale fatto esiste, un'associazione
//! porta la propria provenienza — e qui quelle frasi vengono **prese**, non
//! rifatte.
//!
//! Due composizioni della stessa spiegazione divergono alla prima modifica, e
//! quella nella schermata direbbe una cosa e quella nel documento un'altra.
//!
//! # Il metodo di un calcolo si dichiara qui, e non si inventa
//!
//! [`Origin::Computed`] pretende un metodo, e il metodo di una
//! tendenza o di una somiglianza **è fatto di costanti che stanno nel loro
//! modulo**: la durata delle finestre, il numero minimo di occorrenze, la
//! lunghezza degli n-grammi, la percentuale minima condivisa.
//!
//! Si leggono da lì. Scriverle a mano qui significherebbe che il giorno in cui
//! qualcuno cambia una soglia, la spiegazione continuerebbe a dichiarare quella
//! vecchia — e chi legge crederebbe di sapere come è stato calcolato un numero
//! che è stato calcolato in un altro modo.
//!
//! # Il sesto soggetto non c'è
//!
//! Il congelamento elenca anche il **suggerimento di fonte**. Public Discovery
//! dal vivo non esiste (HVQ-03), e il pannello di PROV-02 non lo copre.
//!
//! # «Perché vedo questo?» (PR-02, ADR-0119)
//!
//! Le funzioni in fondo al modulo compongono la risposta breve in tre parti su
//! **ogni** elemento che il programma ha selezionato, compreso un candidato
//! della ricerca pubblica quando una ricerca registrata ne ha prodotti. Il
//! pannello di PROV-02 resta com'era: ci porta la porta «Vedi tutta la
//! provenienza».

use lisi_core::model::explanation::{Explained, Explanation, RuleVersion};
use lisi_core::model::why::{Origin, WhyAnswer, WhySubject};

use crate::provenance::ResultProvenance;

/// Il metodo con cui si dichiara una tendenza, letto dalle costanti che lo
/// producono.
///
/// # Perché si compone dalle costanti invece di essere scritto
///
/// Perché una soglia cambiata lascerebbe indietro una frase che dichiara quella
/// vecchia, e chi legge crederebbe di sapere come è stato calcolato un numero
/// che è stato calcolato in un altro modo.
#[must_use]
pub fn trend_method() -> String {
    format!(
        "Due finestre di uguale durata ({}), confrontate per conteggio. Una voce compare \
         nell'elenco solo se nel periodo recente raggiunge almeno {} occorrenze. L'aumento \u{e8} \
         una sottrazione fra i due conteggi, entrambi visibili: non \u{e8} un punteggio, e quanto \
         valga lo giudica chi legge.",
        durata_in_parole(crate::trend::DEFAULT_WINDOW_MS),
        crate::trend::MINIMUM_OCCURRENCES
    )
}

/// Il metodo con cui si dichiara una somiglianza, letto dalle costanti che lo
/// producono.
#[must_use]
pub fn resemblance_method() -> String {
    format!(
        "Si contano i gruppi di {} parole che i due testi hanno in comune, sul totale del \
         testo pi\u{f9} corto. Due contenuti compaiono come somiglianti a partire dal {}% in \
         comune. Nessun modello di intelligenza artificiale, e nessun modello appreso: la \
         stessa coppia d\u{e0} sempre lo stesso numero.",
        crate::similarity::SHINGLE_WORDS,
        crate::similarity::MINIMUM_SHARED_PERCENT
    )
}

/// Il dettaglio tecnico del metodo di una somiglianza (PR-01, ADR-0117).
///
/// # Perché non dice più «Jaccard»
///
/// La frase precedente cominciava con «Jaccard esatto su n-grammi». Il
/// coefficiente di Jaccard divide per l'**unione** dei due insiemi; la
/// percentuale che il prodotto mostra divide per le sequenze del testo **più
/// corto** (`similarity.rs`, «calcolarla sull'unione lo…»). Il nome era quello
/// della famiglia scelta in ADR-0055, non quello del numero sullo schermo. Il
/// dettaglio ora nomina il numero che c'è.
#[must_use]
pub fn resemblance_method_technical_detail() -> String {
    format!(
        "Sequenze di {} parole normalizzate (n-grammi), confrontate in modo esatto. La \
         percentuale è il coefficiente di contenimento: sequenze in comune diviso sequenze del \
         testo più corto. Nessun embedding e nessun MinHash (ADR-0048, ADR-0055).",
        crate::similarity::SHINGLE_WORDS
    )
}

/// Il dettaglio tecnico del metodo di un soggetto, quando ne ha uno.
///
/// Oggi lo ha la sola somiglianza: la tendenza e il grappolo si spiegano per
/// intero con parole comuni.
#[must_use]
pub fn method_technical_detail(subject: &WhySubject) -> Option<String> {
    match subject {
        WhySubject::Resemblance { .. } => Some(resemblance_method_technical_detail()),
        _ => None,
    }
}

/// Il metodo con cui si forma un grappolo di segnali.
#[must_use]
pub fn cyber_event_method() -> String {
    format!(
        "I contenuti di un solo monitoraggio che nominano lo stesso indicatore tecnico, \
         raccolti quando sono pi\u{f9} d'uno. Un contenuto che nomina una CVE resta un \
         contenuto che nomina una CVE: il valore della correlazione sta nel ripetersi. Se ne \
         caricano al massimo {}. Fonti distinte non sono conferme indipendenti: possono \
         riprendere la stessa origine.",
        crate::cyber_watch::MEMBERS_PER_EVENT
    )
}

/// La durata, in parole.
///
/// # Perché una copia e non la funzione del modulo delle tendenze
///
/// Perché quella è privata, ed esporla per una frase significherebbe allargare
/// la superficie di un modulo per comodità di un altro. Questa versione tratta
/// **soltanto** i multipli di un giorno, che è ciò che le finestre sono, e
/// dichiara il resto invece di arrotondarlo.
fn durata_in_parole(millis: i64) -> String {
    let giorno = 24 * 60 * 60 * 1_000;
    if millis > 0 && millis % giorno == 0 {
        let giorni = millis / giorno;
        if giorni == 1 {
            return String::from("un giorno");
        }
        return format!("{giorni} giorni");
    }
    format!("{millis} millisecondi")
}

/// La risposta su un soggetto, con la spiegazione che gli appartiene.
///
/// # Perché prende la spiegazione invece di ricavarla
///
/// Perché ricavarla qui significherebbe rileggere l'archivio una seconda volta,
/// e comporre una seconda verità accanto a quella che la schermata sta già
/// mostrando. Chi chiede il perché ha la cosa davanti: la sua frase ce l'ha già.
///
/// # Errori
///
/// Restituisce `None` quando la spiegazione è vuota — una risposta senza
/// spiegazione direbbe che non c'è una ragione, e una ragione c'è sempre,
/// altrimenti quel soggetto non sarebbe sullo schermo.
#[must_use]
pub fn answer_for(subject: WhySubject, explanation: &str) -> Option<WhyAnswer> {
    let explanation = explanation.trim();
    if explanation.is_empty() {
        return None;
    }

    match subject.nature() {
        Origin::Computed => {
            let metodo = match &subject {
                WhySubject::CyberEvent { .. } => cyber_event_method(),
                WhySubject::Trend { .. } => trend_method(),
                WhySubject::Resemblance { .. } => resemblance_method(),
                // Le altre varianti non sono elaborazioni: il `match` sulla
                // natura le ha gia' escluse, e questo braccio esiste perche' il
                // compilatore non puo' saperlo.
                WhySubject::GraphEdge { .. }
                | WhySubject::PersonAssociation { .. }
                | WhySubject::ContentFromSource { .. } => return None,
            };
            WhyAnswer::elaborated(subject, explanation.to_owned(), metodo)
        }
        Origin::Observed | Origin::Operator => {
            WhyAnswer::observed_or_decided(subject, explanation.to_owned())
        }
    }
}

// ------------------------------------------- «Perché vedo questo?» (PR-02)
//
// Le funzioni qui sotto compongono la risposta in tre parti di ADR-0119. Il
// nome della regola, l'origine e la frase su che cosa non significa vengono
// dal genere dell'elemento; qui si sceglie soltanto **quale versione** e
// **quali fatti**. Nessuna legge l'orologio: stesso elemento, stesso stato,
// stessa frase.

/// La risposta su un elemento, con la versione di oggi della sua regola.
///
/// I fatti sono quelli che la schermata sta già mostrando: chi chiede il
/// perché ha la cosa davanti (PROV-02).
///
/// # Errori
///
/// Restituisce `None` quando i fatti sono vuoti.
#[must_use]
pub fn explain(explained: Explained, facts: &str) -> Option<Explanation> {
    Explanation::compose(
        explained,
        crate::rule_versions::current_version(explained),
        facts,
    )
}

/// La versione del motore **registrata** con il contenuto.
///
/// Un contenuto analizzato prima che il motore avesse un numero dice «versione
/// non registrata», non la versione di oggi (ENGINE-01).
fn recorded_engine(percorso: &ResultProvenance) -> RuleVersion {
    percorso
        .engine_version
        .map_or(RuleVersion::NotRecorded, RuleVersion::Known)
}

/// Perché un contenuto è nell'elenco dello Storico: da dove viene e quando è
/// stato acquisito.
#[must_use]
pub fn explain_content(percorso: &ResultProvenance) -> Option<Explanation> {
    explain(Explained::Content, &percorso.origin.as_sentence())
}

/// Perché quel livello: come si è arrivati al numero, con il motore registrato.
#[must_use]
pub fn explain_level(percorso: &ResultProvenance) -> Option<Explanation> {
    Explanation::compose(
        Explained::Level,
        recorded_engine(percorso),
        &format!(
            "Livello {}. {}",
            percorso.stored_level,
            percorso.scoring.explanation.as_sentence()
        ),
    )
}

/// Perché un avviso: quando fu emesso, e con quale motivazione.
///
/// Restituisce `None` quando sul contenuto non è stato emesso alcun avviso:
/// non c'è niente da spiegare, e una risposta inventata direbbe il contrario.
#[must_use]
pub fn explain_alert(percorso: &ResultProvenance) -> Option<Explanation> {
    let avviso = percorso.alert.as_ref()?;
    let motivazione = avviso.reason.trim();
    let fatti = if motivazione.is_empty() {
        avviso.as_sentence()
    } else {
        format!(
            "{} Motivazione scritta allora: «{motivazione}».",
            avviso.as_sentence()
        )
    };
    explain(Explained::Alert, &fatti)
}

/// Perché un termine è stato trovato, nel percorso di un contenuto già
/// analizzato: con il motore registrato.
#[must_use]
pub fn explain_recorded_match(percorso: &ResultProvenance, facts: &str) -> Option<Explanation> {
    Explanation::compose(Explained::Match, recorded_engine(percorso), facts)
}

/// La risposta su un elemento che ha composto l'Hub.
///
/// La versione della regola è quella dell'Hub, e il protocollo non la
/// trasmette: scrivere quella della postazione sarebbe un'affermazione che
/// nessuno ha verificato (ADR-0119, decisione 3).
#[must_use]
pub fn explain_from_hub(explained: Explained, facts: &str) -> Option<Explanation> {
    Explanation::compose(explained, RuleVersion::NotTransmitted, facts)
}

#[cfg(test)]
mod tests {
    use lisi_core::ContentId;
    use lisi_core::model::indicator::IndicatorKind;
    use lisi_core::model::why::{Origin, WhySubject};

    use super::{answer_for, cyber_event_method, resemblance_method, trend_method};

    /// Il testo di questo modulo, per la guardia che guarda la forma del codice.
    const THIS_MODULE: &str = include_str!("why.rs");

    /// **Il metodo di un calcolo si legge dalle costanti che lo producono.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che il giorno in cui qualcuno cambia una soglia, la spiegazione continui
    /// a dichiarare quella vecchia. Chi legge crederebbe di sapere come e' stato
    /// calcolato un numero che e' stato calcolato in un altro modo — ed e'
    /// peggio di non saperlo, perche' non ha modo di accorgersene.
    ///
    /// # Il controllo negativo
    ///
    /// Scrivendo a mano una delle soglie invece di leggerla dalla costante,
    /// questa prova diventa rossa.
    #[test]
    fn il_metodo_si_legge_dalle_costanti_che_lo_producono() {
        assert!(
            trend_method().contains(&crate::trend::MINIMUM_OCCURRENCES.to_string()),
            "il metodo della tendenza deve nominare il minimo di occorrenze: {}",
            trend_method()
        );
        assert!(
            resemblance_method().contains(&crate::similarity::MINIMUM_SHARED_PERCENT.to_string()),
            "il metodo della somiglianza deve nominare la percentuale minima: {}",
            resemblance_method()
        );
        assert!(
            resemblance_method().contains(&crate::similarity::SHINGLE_WORDS.to_string()),
            "il metodo della somiglianza deve nominare la lunghezza degli n-grammi: {}",
            resemblance_method()
        );
        assert!(
            cyber_event_method().contains(&crate::cyber_watch::MEMBERS_PER_EVENT.to_string()),
            "il metodo del grappolo deve nominare il tetto dei membri: {}",
            cyber_event_method()
        );

        // E le costanti si LEGGONO, non si copiano: il testo del modulo le
        // nomina invece di portarne il valore.
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        for costante in [
            "crate::trend::MINIMUM_OCCURRENCES",
            "crate::similarity::MINIMUM_SHARED_PERCENT",
            "crate::similarity::SHINGLE_WORDS",
            "crate::cyber_watch::MEMBERS_PER_EVENT",
        ] {
            assert!(
                produzione.contains(costante),
                "il metodo deve leggere «{costante}» invece di scriverne il valore"
            );
        }
    }

    /// **Ogni calcolo arriva con il proprio metodo.**
    #[test]
    fn ogni_calcolo_arriva_con_il_proprio_metodo() {
        let calcoli = [
            WhySubject::CyberEvent {
                kind: IndicatorKind::Cve,
                value: String::from("CVE-2026-1234"),
            },
            WhySubject::Trend {
                key: String::from("molotov"),
            },
            WhySubject::Resemblance {
                first: ContentId::new(1),
                second: ContentId::new(2),
            },
        ];

        for soggetto in calcoli {
            let Some(risposta) = answer_for(soggetto.clone(), "una spiegazione qualsiasi") else {
                panic!("un calcolo deve poter ricevere una risposta: {soggetto:?}");
            };
            assert_eq!(risposta.nature(), Origin::Computed);
            assert!(
                !risposta.method().is_empty(),
                "il metodo non puo' essere vuoto: {soggetto:?}"
            );
            assert!(
                risposta
                    .as_sentence()
                    .contains("Come \u{e8} stato calcolato"),
                "la frase deve dire come e' stato calcolato: {soggetto:?}"
            );
        }
    }

    /// **Un fatto osservato non porta un metodo, e lo dichiara come tale.**
    #[test]
    fn un_fatto_osservato_arriva_senza_metodo() {
        let Some(risposta) = answer_for(
            WhySubject::PersonAssociation {
                identifier: String::from("111"),
            },
            "Ha scritto questo contenuto. Osservato nel contenuto #1.",
        ) else {
            panic!("un fatto osservato deve poter ricevere una risposta");
        };

        assert_eq!(risposta.nature(), Origin::Observed);
        assert!(risposta.method().is_empty());
        assert!(
            !risposta
                .as_sentence()
                .contains("Come \u{e8} stato calcolato")
        );
    }

    /// **Un arco deciso da una persona non si presenta come un'osservazione.**
    #[test]
    fn un_arco_deciso_da_una_persona_lo_dichiara() {
        let Some(risposta) = answer_for(
            WhySubject::GraphEdge {
                decided_by_a_person: true,
            },
            "Una persona ha collegato questa identita' a questo fascicolo.",
        ) else {
            panic!("un arco deciso deve poter ricevere una risposta");
        };

        assert_eq!(risposta.nature(), Origin::Operator);
        assert!(
            risposta
                .as_sentence()
                .contains("L'ha scritto o deciso una persona"),
            "{}",
            risposta.as_sentence()
        );
    }

    /// **Una risposta senza spiegazione non si costruisce.**
    ///
    /// Direbbe che non c'e' una ragione, e una ragione c'e' sempre: altrimenti
    /// quel soggetto non sarebbe sullo schermo.
    #[test]
    fn una_risposta_senza_spiegazione_non_si_costruisce() {
        for vuota in ["", "   ", "\n\t "] {
            assert!(
                answer_for(
                    WhySubject::Trend {
                        key: String::from("molotov")
                    },
                    vuota
                )
                .is_none(),
                "una spiegazione vuota non produce una risposta"
            );
        }
    }

    /// **Il metodo di una somiglianza dichiara che non c'è alcun modello.**
    ///
    /// E' il vincolo permanente di prodotto (ADR-0048), e il posto in cui
    /// qualcuno potrebbe dubitarne e' proprio la spiegazione di un numero che
    /// somiglia a un punteggio.
    #[test]
    fn il_metodo_della_somiglianza_dichiara_che_non_c_e_alcun_modello() {
        let metodo = resemblance_method();
        // Da PR-01 la frase semplice dice «nessun modello» in parole comuni, e
        // il dettaglio tecnico nomina ciò che esclude: nessuna delle due metà
        // può perdere la propria negazione.
        assert!(
            metodo.contains("Nessun modello di intelligenza artificiale"),
            "{metodo}"
        );
        assert!(metodo.contains("nessun modello appreso"), "{metodo}");
        let dettaglio = super::resemblance_method_technical_detail();
        assert!(dettaglio.contains("Nessun embedding"), "{dettaglio}");
        assert!(dettaglio.contains("contenimento"), "{dettaglio}");
        assert!(
            metodo.contains("la stessa coppia d\u{e0} sempre lo stesso numero"),
            "{metodo}"
        );
    }

    /// **Il metodo di un grappolo ripete che le fonti distinte non sono
    /// conferme.**
    ///
    /// E' l'errore piu' probabile di chi legge, e una spiegazione che lo
    /// omettesse lo lascerebbe fare proprio nel momento in cui qualcuno sta
    /// cercando di capire.
    #[test]
    fn il_metodo_del_grappolo_ripete_che_le_fonti_distinte_non_sono_conferme() {
        let metodo = cyber_event_method();
        assert!(
            metodo.contains("non sono conferme indipendenti"),
            "{metodo}"
        );
    }

    /// **Le finestre si dicono in giorni, non in millisecondi.**
    ///
    /// «604800000 millisecondi» e' un numero che nessuno converte mentre legge.
    #[test]
    fn le_finestre_si_dicono_in_giorni() {
        let metodo = trend_method();
        assert!(metodo.contains("7 giorni"), "{metodo}");
        assert!(!metodo.contains("millisecondi"), "{metodo}");
    }
}

#[cfg(test)]
mod perche_vedo_questo {
    use lisi_core::ContentId;
    use lisi_core::Timestamp;
    use lisi_core::model::content_history::ContentHistorySummary;
    use lisi_core::model::explanation::Explained;
    use lisi_core::model::origin::Origin;
    use lisi_core::model::provenance::{ExplanationGap, ScoringExplanation, ScoringProvenance};
    use lisi_core::text::DisplayName;

    use super::{
        explain, explain_alert, explain_content, explain_from_hub, explain_level,
        explain_recorded_match,
    };
    use crate::provenance::{AlertProvenance, ContentOrigin, ResultProvenance};

    /// Il sorgente del modulo e del registro, per la prova sull'orologio.
    const QUESTO: &str = include_str!("why.rs");
    const REGISTRO: &str = include_str!("rule_versions.rs");

    fn percorso(engine_version: Option<u32>, avviso: Option<&str>) -> ResultProvenance {
        let Ok(nome) = DisplayName::try_new("Canale di prova") else {
            panic!("il nome di prova deve essere valido");
        };
        ResultProvenance {
            content_id: ContentId::new(7),
            origin: ContentOrigin {
                source_name: nome,
                remote_message_id: String::from("m-7"),
                author: None,
                author_username: None,
                author_identifier: None,
                url: None,
                published_at: Timestamp::from_millis(1_700_000_000_000),
                acquired_at: Timestamp::from_millis(1_700_000_060_000),
                mode: String::from("Acquisito dal vivo."),
            },
            after_acquisition: ContentHistorySummary::default(),
            stored_level: 2,
            scoring: ScoringProvenance {
                contributions: Vec::new(),
                explanation: ScoringExplanation::Unavailable(ExplanationGap::NoMatches),
            },
            alert: avviso.map(|motivo| AlertProvenance {
                level: 2,
                reason: String::from(motivo),
                raised_at: Timestamp::from_millis(1_700_000_060_000),
                changed_after: None,
            }),
            decisions: Vec::new(),
            engine_version,
        }
    }

    /// **Ogni genere ha una risposta**, con le tre parti e la versione di oggi.
    #[test]
    fn ogni_genere_ha_una_risposta() {
        for genere in Explained::ALL {
            let Some(risposta) = explain(genere, "Un fatto registrato.") else {
                panic!("{genere:?}: nessuna risposta");
            };
            assert!(risposta.rule().contains("versione "), "{genere:?}");
            assert!(!risposta.does_not_mean().is_empty(), "{genere:?}");
            assert_eq!(risposta.certainty(), genere.origin());
        }
    }

    #[test]
    fn il_contenuto_si_spiega_con_la_sua_origine() {
        let Some(risposta) = explain_content(&percorso(Some(1), None)) else {
            panic!("un contenuto ha sempre un'origine");
        };
        assert_eq!(risposta.certainty(), Origin::Observed);
        assert!(
            risposta.facts().contains("Canale di prova"),
            "{}",
            risposta.facts()
        );
        assert!(risposta.rule().contains("Elenco dello Storico"));
    }

    /// **Il livello dice il motore registrato**, non quello di oggi.
    #[test]
    fn il_livello_dice_il_motore_registrato() {
        let Some(con) = explain_level(&percorso(Some(1), None)) else {
            panic!("un livello ha sempre una risposta");
        };
        assert!(con.rule().contains("versione 1"), "{}", con.rule());
        assert!(con.facts().starts_with("Livello 2."), "{}", con.facts());

        let Some(senza) = explain_level(&percorso(None, None)) else {
            panic!("un livello ha sempre una risposta");
        };
        assert!(
            senza.rule().contains("versione non registrata"),
            "{}",
            senza.rule()
        );
    }

    /// **Senza avviso non c'è una spiegazione dell'avviso**, e con l'avviso la
    /// motivazione è quella scritta allora.
    #[test]
    fn l_avviso_si_spiega_solo_se_c_e() {
        assert!(explain_alert(&percorso(Some(1), None)).is_none());
        let Some(risposta) = explain_alert(&percorso(Some(1), Some("Termine «corteo»."))) else {
            panic!("un avviso ha sempre una risposta");
        };
        assert!(
            risposta.facts().contains("Termine «corteo»."),
            "{}",
            risposta.facts()
        );
        assert_eq!(risposta.certainty(), Origin::Computed);
    }

    #[test]
    fn il_riscontro_nel_percorso_dice_il_motore_registrato() {
        let Some(risposta) = explain_recorded_match(&percorso(None, None), "«corteo», 1 volta.")
        else {
            panic!("un riscontro con fatti ha sempre una risposta");
        };
        assert!(risposta.rule().contains("versione non registrata"));
    }

    /// **La coda dell'ufficio non si attribuisce la versione della postazione.**
    #[test]
    fn cio_che_compone_l_hub_non_ha_la_versione_della_postazione() {
        let Some(risposta) = explain_from_hub(Explained::WorkQueueItem, "Mai esaminato.") else {
            panic!("fatti non vuoti devono comporre una risposta");
        };
        assert!(
            risposta.rule().contains("versione dell'Hub"),
            "{}",
            risposta.rule()
        );
        assert!(!risposta.rule().contains("versione 1"));
    }

    /// **Stesso elemento, stesso stato, stessa frase.**
    #[test]
    fn la_risposta_e_deterministica() {
        let uno = percorso(Some(1), Some("Motivo."));
        let due = percorso(Some(1), Some("Motivo."));
        assert_eq!(explain_content(&uno), explain_content(&due));
        assert_eq!(explain_level(&uno), explain_level(&due));
        assert_eq!(explain_alert(&uno), explain_alert(&due));
        for genere in Explained::ALL {
            assert_eq!(explain(genere, "Fatto."), explain(genere, "Fatto."));
        }
    }

    /// **Chi compone non legge l'orologio.**
    ///
    /// Una risposta che dipendesse dall'ora non sarebbe la stessa due volte, e
    /// nessuno potrebbe rileggerla com'era.
    #[test]
    fn chi_compone_non_legge_l_orologio() {
        for (nome, sorgente) in [("why.rs", QUESTO), ("rule_versions.rs", REGISTRO)] {
            let produzione = sorgente
                .split_once("#[cfg(test)]\nmod tests {")
                .map_or(sorgente, |(codice, _)| codice);
            for vietato in ["now(", "SystemTime", "Instant::", "rand::"] {
                assert!(
                    !produzione.contains(vietato),
                    "{nome}: «{vietato}» nel codice che compone le spiegazioni"
                );
            }
        }
    }
}

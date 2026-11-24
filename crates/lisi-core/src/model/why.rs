//! «Perché sto vedendo questo?», per ciò che non è un contenuto (PROV-02).
//!
//! # Che cosa aggiunge, visto che ogni cosa spiega già sé stessa
//!
//! Un grappolo dice perché i suoi contenuti stanno insieme. Un arco del grafo
//! dice per quale fatto esiste. Un'associazione porta la propria provenienza.
//! Una tendenza mostra le finestre da cui è ricavata. Una somiglianza dice quali
//! parole condivide.
//!
//! Tutte queste frasi esistono già, e questa milestone **non ne compone una
//! settima**: le raccoglie. Due composizioni della stessa spiegazione divergono
//! alla prima modifica, e quella nella schermata direbbe una cosa e quella nel
//! documento un'altra.
//!
//! # La cosa che nessuno vedrebbe da sé: una voce sola fa sembrare uguali cinque
//! certezze diverse
//!
//! Dietro un unico pulsante «Perché sto vedendo questo?», cinque risposte
//! arrivano **con la stessa faccia**.
//!
//! Ma non sono la stessa cosa. Che quel contenuto venga da quella fonte è un
//! **fatto osservato**: sta nell'archivio, e chiunque può riaprirlo. Che quel
//! termine sia «emergente» è un'**elaborazione**: dipende da due finestre che
//! qualcuno ha scelto e da una soglia che qualcuno ha fissato, e con finestre
//! diverse quel termine non emergerebbe. Che quell'identità sia collegata a quel
//! fascicolo è la **decisione di una persona**.
//!
//! Chi legge cinque risposte nella stessa voce ne ricava cinque fatti dello
//! stesso peso — e in una relazione scriverebbe le tre cose allo stesso modo. È
//! il difetto che ADR-0052 esisteva per chiudere sui contenuti, e che uno
//! sportello unico riaprirebbe su tutto il resto.
//!
//! # Come il tipo lo impedisce
//!
//! Ogni risposta **dichiara la propria natura**, e la dichiarazione non è un
//! campo che qualcuno compila: discende dal soggetto ([`WhySubject::nature`]).
//! Non esiste una risposta che possa sbagliarla, perché non esiste un posto dove
//! scriverla.
//!
//! È la stessa forma di garanzia dell'orologio di CYT-01.
//!
//! # Un'elaborazione automatica non si mostra senza il proprio metodo
//!
//! Una percentuale di somiglianza senza l'algoritmo che l'ha prodotta è un
//! numero che sembra oggettivo. Un aumento di occorrenze senza le due finestre
//! che lo misurano è un fatto che nessuno ha misurato così.
//!
//! [`WhyAnswer`] ha i campi privati e due costruttori: quello per
//! un'elaborazione **vuole il metodo**, e non c'è modo di ottenerne una senza.
//! È la garanzia di PERS-03 applicata a un'altra cosa.
//!
//! # Il sesto soggetto non c'è, ed è scritto
//!
//! Il congelamento elenca anche il **suggerimento di fonte**. Public Discovery
//! dal vivo non esiste: il suo percorso di produzione dichiara che l'ambiente non
//! è stato validato e non parte, e le misure dal vivo aspettano credenziali reali
//! (HVQ-03). Non c'è alcun suggerimento da spiegare.
//!
//! Costruirne la spiegazione adesso significherebbe scrivere che cosa dirà un
//! sottosistema che nessuno ha ancora visto funzionare.

use crate::model::indicator::IndicatorKind;
use crate::{ContentId, SourceId};

/// Di che genere è la certezza di una risposta: la sua **origine**.
///
/// Fino a PR-03 era un tipo a sé, `WhyNature`, con tre nomi propri — «Fatto
/// osservato», «Elaborazione automatica», «Decisione di una persona» — mentre
/// lo Storico ne usava altri tre. Una cosa sola chiamata in due modi insegna
/// che le parole non contano (ADR-0117, L3). Ora è [`Origin`], la stessa di
/// ogni altra schermata (ADR-0118): le tre nature di ADR-0052, con un nome solo.
pub use crate::model::origin::Origin;

/// Di che cosa si sta chiedendo il perché.
///
/// # Perché un'enumerazione chiusa
///
/// Perché l'insieme delle cose su cui questo prodotto risponde «perché sto
/// vedendo questo?» deve essere **leggibile per intero**, e ogni aggiunta è una
/// decisione: passa da qui, e con essa passa la scelta della sua natura.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhySubject {
    /// Un grappolo di segnali, identificato dalla ragione che lo tiene insieme.
    CyberEvent {
        /// Il genere dell'indicatore.
        kind: IndicatorKind,
        /// Il valore normalizzato.
        value: String,
    },
    /// Un arco del grafo delle prove, fra due nodi.
    ///
    /// # Perché la natura non è una sola
    ///
    /// Perché un arco osservato e un arco che una persona ha deciso sono due
    /// cose diverse, e GRAPH-01 le tiene separate. Qui il soggetto porta quale
    /// delle due sia, e la natura ne discende.
    GraphEdge {
        /// Se quell'arco lo ha stabilito una persona.
        decided_by_a_person: bool,
    },
    /// Un'associazione di un'identità osservata.
    PersonAssociation {
        /// L'identificativo osservato.
        identifier: String,
    },
    /// Un termine, un indicatore o un volume dichiarato emergente.
    Trend {
        /// Il valore osservato.
        key: String,
    },
    /// Due contenuti che si somigliano.
    Resemblance {
        /// Il primo contenuto.
        first: ContentId,
        /// Il secondo.
        second: ContentId,
    },
    /// Da dove viene un contenuto: la fonte che lo ha portato.
    ContentFromSource {
        /// Il contenuto.
        content: ContentId,
        /// La fonte.
        source: SourceId,
    },
}

impl WhySubject {
    /// Di che genere è la certezza della risposta su questo soggetto.
    ///
    /// # Perché è una funzione e non un campo
    ///
    /// Perché un campo si compila, e ciò che si compila si può sbagliare. Qui la
    /// natura **discende dal soggetto**: una tendenza è un calcolo perché è un
    /// calcolo, non perché qualcuno lo ha scritto in una riga. Il giorno in cui
    /// si aggiunge un soggetto, il `match` costringe a decidere, sotto gli occhi
    /// di chi rivede.
    #[must_use]
    pub const fn nature(&self) -> Origin {
        match self {
            // Un grappolo e' l'esito di una regola deterministica sui contenuti:
            // e' un calcolo, e con un tetto diverso raccoglierebbe altro.
            Self::CyberEvent { .. } | Self::Trend { .. } | Self::Resemblance { .. } => {
                Origin::Computed
            }
            // Un'associazione nasce da un fatto gia' nell'archivio: quel
            // contenuto, quella fonte, quell'istante (PERS-03).
            Self::PersonAssociation { .. } | Self::ContentFromSource { .. } => Origin::Observed,
            Self::GraphEdge {
                decided_by_a_person,
            } => {
                if *decided_by_a_person {
                    Origin::Operator
                } else {
                    Origin::Observed
                }
            }
        }
    }

    /// Come si nomina il soggetto a chi legge.
    #[must_use]
    pub fn as_label(&self) -> String {
        match self {
            Self::CyberEvent { kind, value } => {
                format!("Gruppo di segnali che nominano {} «{value}»", kind.label())
            }
            Self::GraphEdge {
                decided_by_a_person,
            } => {
                if *decided_by_a_person {
                    String::from("Collegamento del grafo, stabilito da una persona")
                } else {
                    String::from("Collegamento del grafo, osservato nell'archivio")
                }
            }
            Self::PersonAssociation { identifier } => {
                format!("Cosa associata all'identità osservata {identifier}")
            }
            Self::Trend { key } => format!("«{key}», dichiarato emergente"),
            Self::Resemblance { first, second } => format!(
                "Somiglianza fra il contenuto #{} e il contenuto #{}",
                first.get(),
                second.get()
            ),
            Self::ContentFromSource { content, source } => format!(
                "Il contenuto #{} proviene dalla fonte #{}",
                content.get(),
                source.get()
            ),
        }
    }
}

/// La risposta a «perché sto vedendo questo?».
///
/// # Perché i campi sono privati e i costruttori sono due
///
/// Perché un'elaborazione automatica **non si mostra senza il proprio metodo**:
/// una percentuale senza l'algoritmo che l'ha prodotta è un numero che sembra
/// oggettivo, e un aumento senza le due finestre che lo misurano è un fatto che
/// nessuno ha misurato così.
///
/// [`Self::observed_or_decided`] rifiuta i soggetti che sono un calcolo;
/// [`Self::elaborated`] vuole il metodo e rifiuta quelli che non lo sono. Non c'è
/// un terzo costruttore, non c'è `Default`, e non c'è un `Option` da lasciare
/// vuoto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhyAnswer {
    /// Di che cosa.
    subject: WhySubject,
    /// La spiegazione, **presa da chi la possiede** e non ricomposta.
    explanation: String,
    /// I parametri del calcolo, quando la natura è un'elaborazione.
    ///
    /// Vuoto per le altre nature: un metodo accanto a un fatto osservato
    /// suggerirebbe che sia stato calcolato anche quello.
    method: String,
}

impl WhyAnswer {
    /// La risposta su un fatto osservato o su una decisione di una persona.
    ///
    /// Restituisce `None` se il soggetto è invece un'elaborazione automatica:
    /// quella richiede il proprio metodo, e [`Self::elaborated`] lo vuole.
    #[must_use]
    pub fn observed_or_decided(subject: WhySubject, explanation: String) -> Option<Self> {
        if subject.nature().requires_a_method() {
            return None;
        }
        Some(Self {
            subject,
            explanation,
            method: String::new(),
        })
    }

    /// La risposta su un'elaborazione automatica, **con il suo metodo**.
    ///
    /// Restituisce `None` se il soggetto non è un'elaborazione — un metodo
    /// accanto a un fatto osservato direbbe che è stato calcolato — oppure se il
    /// metodo è vuoto, che è il modo in cui la garanzia si aggirerebbe restando
    /// dentro il tipo.
    #[must_use]
    pub fn elaborated(subject: WhySubject, explanation: String, method: String) -> Option<Self> {
        if !subject.nature().requires_a_method() || method.trim().is_empty() {
            return None;
        }
        Some(Self {
            subject,
            explanation,
            method,
        })
    }

    /// Di che cosa.
    #[must_use]
    pub const fn subject(&self) -> &WhySubject {
        &self.subject
    }

    /// Di che genere è la certezza.
    #[must_use]
    pub const fn nature(&self) -> Origin {
        self.subject.nature()
    }

    /// La spiegazione, come chi la possiede l'ha composta.
    #[must_use]
    pub fn explanation(&self) -> &str {
        &self.explanation
    }

    /// I parametri del calcolo, vuoti quando non è un calcolo.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// La risposta intera, detta a chi legge.
    ///
    /// # Perché la natura viene prima della spiegazione
    ///
    /// Perché chi legge deve sapere **che genere di cosa** sta per leggere prima
    /// di leggerla: una spiegazione convincente letta senza sapere che è un
    /// calcolo si ricorda come un fatto.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let mut testo = format!(
            "{}\n{} — {}\n{}",
            self.subject.as_label(),
            self.nature().label(),
            self.nature().as_sentence(),
            self.explanation
        );

        if !self.method.is_empty() {
            testo.push_str(&format!("\nCome è stato calcolato: {}", self.method));
        }

        testo
    }
}

#[cfg(test)]
mod tests {
    use super::{Origin, WhyAnswer, WhySubject};
    use crate::model::indicator::IndicatorKind;
    use crate::{ContentId, SourceId};

    /// Il testo di questo modulo, per le guardie che guardano la forma del
    /// codice e non il suo esito.
    const THIS_MODULE: &str = include_str!("why.rs");

    /// La parte di produzione di questo modulo, senza le prove.
    fn produzione() -> &'static str {
        let Some((codice, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        codice
    }

    fn tendenza() -> WhySubject {
        WhySubject::Trend {
            key: String::from("molotov"),
        }
    }

    fn fatto_osservato() -> WhySubject {
        WhySubject::ContentFromSource {
            content: ContentId::new(1),
            source: SourceId::new(7),
        }
    }

    /// **Ogni soggetto dichiara la natura della propria certezza.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che cinque risposte diverse arrivino con la stessa faccia. Che quel
    /// contenuto venga da quella fonte e' un fatto che sta nell'archivio; che
    /// quel termine sia emergente e' un calcolo che dipende da due finestre
    /// scelte da qualcuno. Chi legge le due cose nella stessa voce ne ricava due
    /// fatti dello stesso peso, e in una relazione le scrive allo stesso modo.
    ///
    /// # Il controllo negativo
    ///
    /// Portando `Trend` fra i fatti osservati — o `PersonAssociation` fra le
    /// elaborazioni — questa prova diventa rossa.
    #[test]
    fn la_natura_discende_dal_soggetto() {
        let calcoli = [
            WhySubject::CyberEvent {
                kind: IndicatorKind::Cve,
                value: String::from("CVE-2026-1234"),
            },
            tendenza(),
            WhySubject::Resemblance {
                first: ContentId::new(1),
                second: ContentId::new(2),
            },
        ];
        for soggetto in &calcoli {
            assert_eq!(
                soggetto.nature(),
                Origin::Computed,
                "{soggetto:?} e' un calcolo del programma"
            );
            assert!(soggetto.nature().requires_a_method());
        }

        let osservati = [
            fatto_osservato(),
            WhySubject::PersonAssociation {
                identifier: String::from("111"),
            },
            WhySubject::GraphEdge {
                decided_by_a_person: false,
            },
        ];
        for soggetto in &osservati {
            assert_eq!(
                soggetto.nature(),
                Origin::Observed,
                "{soggetto:?} sta nell'archivio"
            );
            assert!(!soggetto.nature().requires_a_method());
        }

        assert_eq!(
            WhySubject::GraphEdge {
                decided_by_a_person: true
            }
            .nature(),
            Origin::Operator,
            "un arco che una persona ha deciso non e' un'osservazione"
        );
    }

    /// **La natura non è un campo che qualcuno compila.**
    ///
    /// Finche' discende dal soggetto, un soggetto nuovo costringe a decidere
    /// dentro il `match`, sotto gli occhi di chi rivede.
    #[test]
    fn la_natura_non_e_un_campo() {
        let codice = produzione();
        let Some(inizio) = codice.find("pub enum WhySubject {") else {
            panic!("l'enumerazione dei soggetti deve esistere");
        };
        let Some(lunghezza) = codice[inizio..].find("\n}\n") else {
            panic!("l'enumerazione dei soggetti deve chiudersi");
        };
        let enumerazione = &codice[inizio..inizio + lunghezza];

        assert!(
            !enumerazione.contains("Origin"),
            "nessuna variante deve poter dichiarare la propria natura: {enumerazione}"
        );
        assert!(
            codice.contains("pub const fn nature(&self) -> Origin {"),
            "la natura deve discendere dal soggetto"
        );
    }

    /// **Un'elaborazione automatica non si mostra senza il proprio metodo.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che una percentuale di somiglianza compaia senza l'algoritmo che l'ha
    /// prodotta, o un aumento di occorrenze senza le due finestre che lo
    /// misurano. Un numero senza il proprio metodo sembra oggettivo, ed e'
    /// esattamente cio' che TREND-01 ha stabilito che non deve succedere: «ogni
    /// numero espone come e' stato calcolato».
    ///
    /// # Il controllo negativo
    ///
    /// Togliendo dal costruttore il rifiuto del metodo vuoto, questa prova
    /// diventa rossa.
    #[test]
    fn un_calcolo_non_si_mostra_senza_il_proprio_metodo() {
        // Il costruttore dei fatti osservati RIFIUTA un calcolo.
        assert!(
            WhyAnswer::observed_or_decided(tendenza(), String::from("compare piu' di prima"))
                .is_none(),
            "una tendenza non puo' passare per un fatto osservato"
        );

        // E quello dei calcoli rifiuta un metodo vuoto.
        assert!(
            WhyAnswer::elaborated(
                tendenza(),
                String::from("compare piu' di prima"),
                String::new()
            )
            .is_none(),
            "un calcolo senza metodo non si costruisce"
        );
        assert!(
            WhyAnswer::elaborated(
                tendenza(),
                String::from("compare piu' di prima"),
                String::from("   ")
            )
            .is_none(),
            "uno spazio non e' un metodo"
        );

        // Con il metodo, si costruisce.
        let Some(risposta) = WhyAnswer::elaborated(
            tendenza(),
            String::from("compare piu' di prima"),
            String::from("due finestre di sette giorni, confronto per conteggio"),
        ) else {
            panic!("un calcolo con il proprio metodo deve potersi costruire");
        };
        assert!(
            risposta
                .as_sentence()
                .contains("Come \u{e8} stato calcolato")
        );
    }

    /// **Un metodo non compare accanto a un fatto osservato.**
    ///
    /// Direbbe che e' stato calcolato anche quello.
    #[test]
    fn un_fatto_osservato_non_porta_un_metodo() {
        assert!(
            WhyAnswer::elaborated(
                fatto_osservato(),
                String::from("sta nell'archivio"),
                String::from("un metodo qualsiasi")
            )
            .is_none(),
            "un fatto osservato non si costruisce come un calcolo"
        );

        let Some(risposta) =
            WhyAnswer::observed_or_decided(fatto_osservato(), String::from("sta nell'archivio"))
        else {
            panic!("un fatto osservato deve potersi costruire");
        };
        assert!(risposta.method().is_empty());
        assert!(
            !risposta
                .as_sentence()
                .contains("Come \u{e8} stato calcolato")
        );
    }

    /// **La risposta non è costruibile senza passare da un costruttore.**
    ///
    /// # Il controllo negativo
    ///
    /// Rendendo pubblici i campi di `WhyAnswer`, questa prova diventa rossa.
    #[test]
    fn una_risposta_non_si_costruisce_a_mano() {
        let codice = produzione();
        let Some(inizio) = codice.find("pub struct WhyAnswer {") else {
            panic!("la risposta deve esistere");
        };
        let Some(lunghezza) = codice[inizio..].find("\n}\n") else {
            panic!("la risposta deve chiudersi");
        };
        let campi = &codice[inizio..inizio + lunghezza];

        assert!(
            !campi.contains("pub subject:")
                && !campi.contains("pub explanation:")
                && !campi.contains("pub method:"),
            "i campi di una risposta restano privati: {campi}"
        );
        assert!(
            !codice.contains("impl Default for WhyAnswer"),
            "nessun valore predefinito puo' aggirare i costruttori"
        );
    }

    /// **La natura viene prima della spiegazione.**
    ///
    /// Una spiegazione convincente letta senza sapere che e' un calcolo si
    /// ricorda come un fatto.
    #[test]
    fn la_natura_precede_la_spiegazione() {
        let Some(risposta) = WhyAnswer::elaborated(
            tendenza(),
            String::from("SPIEGAZIONE-DI-PROVA"),
            String::from("METODO-DI-PROVA"),
        ) else {
            panic!("la risposta deve potersi costruire");
        };
        let frase = risposta.as_sentence();

        let Some(natura) = frase.find("Calcolato") else {
            panic!("la natura deve comparire: {frase}");
        };
        let Some(spiegazione) = frase.find("SPIEGAZIONE-DI-PROVA") else {
            panic!("la spiegazione deve comparire: {frase}");
        };
        assert!(
            natura < spiegazione,
            "la natura arriva DOPO la spiegazione: {frase}"
        );
    }

    /// **Ogni natura dice anche il proprio limite.**
    ///
    /// E' l'unica cosa che impedisce di leggere cinque risposte come cinque
    /// fatti dello stesso peso.
    #[test]
    fn ogni_natura_dice_il_proprio_limite() {
        assert!(
            Origin::Computed
                .as_sentence()
                .contains("Con parametri diversi il risultato sarebbe diverso"),
            "{}",
            Origin::Computed.as_sentence()
        );
        assert!(
            Origin::Operator
                .as_sentence()
                .contains("L'ha scritto o deciso una persona"),
            "{}",
            Origin::Operator.as_sentence()
        );
        assert!(
            Origin::Observed
                .as_sentence()
                .contains("non l'ha calcolato"),
            "{}",
            Origin::Observed.as_sentence()
        );
    }

    /// **La spiegazione non si ricompone: arriva da chi la possiede.**
    ///
    /// Due composizioni della stessa spiegazione divergono alla prima modifica,
    /// e quella nella schermata direbbe una cosa e quella nel documento
    /// un'altra.
    #[test]
    fn la_spiegazione_non_si_ricompone_qui() {
        let codice = produzione();

        // LA GUARDIA GUARDA GLI IMPORT, non le parole.
        //
        // Cercare i nomi dei tipi nel testo inciamperebbe sui nomi delle
        // varianti di questo modulo — `Resemblance` e' anche il nome di un
        // soggetto — e una guardia che si accende dove non deve e' una guardia
        // che qualcuno allenta. Se questo modulo non **importa** nulla da chi
        // possiede le spiegazioni, non puo' ricomporle.
        let importati: Vec<&str> = codice
            .lines()
            .filter(|riga| riga.starts_with("use "))
            .collect();

        for riga in &importati {
            for proprietario in [
                "cyber_event",
                "association",
                "evidence_graph",
                "provenance",
                "trend",
                "similarity",
            ] {
                assert!(
                    !riga.contains(proprietario),
                    "il dominio della risposta importa da «{proprietario}»: la spiegazione si \
                     riceve, non si ricompone \u{2014} {riga}"
                );
            }
        }

        assert!(
            !importati.is_empty(),
            "la guardia deve avere qualcosa da guardare: se gli import sono spariti, \
             e' cambiata la forma del modulo e questa prova va rifatta"
        );
    }

    /// **Il sesto soggetto non c'è, ed è scritto.**
    ///
    /// Public Discovery dal vivo non esiste: non c'e' alcun suggerimento di
    /// fonte da spiegare, e costruirne la spiegazione significherebbe scrivere
    /// che cosa dira' un sottosistema che nessuno ha visto funzionare.
    #[test]
    fn il_suggerimento_di_fonte_e_dichiarato_assente() {
        let codice = produzione();
        assert!(
            codice.contains("suggerimento di fonte"),
            "l'assenza del sesto soggetto va dichiarata a chi legge il codice"
        );
        assert!(
            codice.contains("HVQ-03"),
            "la dichiarazione deve dire da che cosa dipende"
        );
    }
}

//! «Perché vedo questo?» (PR-02, ADR-0119).
//!
//! # Tre parti, sempre le stesse, sempre in quest'ordine
//!
//! 1. **che cosa lo ha fatto comparire**: la regola, con nome e versione, e i
//!    fatti registrati che l'hanno fatta scattare;
//! 2. **che genere di certezza è**: l'[`Origin`] di PR-03;
//! 3. **che cosa non significa**: la salvaguardia interpretativa.
//!
//! # Che cosa il tipo impedisce
//!
//! [`Explanation`] ha i campi privati e un costruttore solo. Il **nome della
//! regola**, l'**origine** e la **parte 3** non si passano: discendono dal
//! genere dell'elemento ([`Explained`]), con un `match` esaustivo. Chi aggiunge
//! un genere deve scriverne la frase; chi compone una spiegazione non può
//! dimenticarla, né spiegare una coda di lavoro con il nome della regola di un
//! avviso.
//!
//! Si passano soltanto la **versione** della regola — che la conosce chi
//! possiede la regola, non il dominio — e i **fatti**, che la conosce chi ha
//! l'elemento davanti.
//!
//! # Che cosa il tipo non fa
//!
//! Non legge l'orologio: stesso elemento, stesso stato, stessa frase. Non
//! genera testo: ogni frase è un fatto registrato o un testo fisso del prodotto
//! (ADR-0048).

use crate::model::origin::Origin;

/// Il genere dell'elemento di cui si chiede il perché.
///
/// # Perché un'enumerazione chiusa
///
/// Perché l'insieme delle cose su cui il prodotto risponde deve essere
/// leggibile per intero, e ogni aggiunta è una decisione: con il genere
/// arrivano il nome della regola, l'origine e la frase su che cosa non
/// significa. Una prova verifica che [`Explained::ALL`] li elenchi tutti.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Explained {
    /// Un contenuto in un elenco dello Storico.
    Content,
    /// Un avviso emesso su un contenuto.
    Alert,
    /// Il livello di un contenuto.
    Level,
    /// Un termine trovato nel testo.
    Match,
    /// Un gruppo di segnali che nominano lo stesso indicatore.
    CyberEvent,
    /// Una riga della cronologia di un gruppo di segnali.
    CyberWatchRow {
        /// Se la riga è l'atto di una persona.
        by_a_person: bool,
    },
    /// Un candidato della ricerca pubblica.
    SourceSuggestion,
    /// Una ricerca pubblica registrata.
    DiscoveryResult,
    /// Una voce della coda di lavoro.
    WorkQueueItem,
    /// Un vicino nel grafo delle prove.
    GraphNode {
        /// Se il collegamento lo ha stabilito una persona.
        by_a_person: bool,
    },
    /// Un valore dichiarato emergente.
    Trend,
    /// Un aumento oltre la soglia.
    Spike,
    /// Due contenuti che si somigliano.
    Resemblance,
    /// Una cosa associata a un'identità osservata.
    PersonAssociation,
    /// Un periodo non coperto prioritario (PR-06).
    CoverageGap,
}

impl Explained {
    /// Tutti i generi, con entrambi i valori dove l'origine dipende da chi ha
    /// agito.
    pub const ALL: [Self; 17] = [
        Self::Content,
        Self::Alert,
        Self::Level,
        Self::Match,
        Self::CyberEvent,
        Self::CyberWatchRow { by_a_person: false },
        Self::CyberWatchRow { by_a_person: true },
        Self::SourceSuggestion,
        Self::DiscoveryResult,
        Self::WorkQueueItem,
        Self::GraphNode { by_a_person: false },
        Self::GraphNode { by_a_person: true },
        Self::Trend,
        Self::Spike,
        Self::Resemblance,
        Self::PersonAssociation,
        Self::CoverageGap,
    ];

    /// Come si nomina l'elemento a chi legge.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Content => "Contenuto in elenco",
            Self::Alert => "Avviso",
            Self::Level => "Livello",
            Self::Match => "Riscontro",
            Self::CyberEvent => "Gruppo di segnali",
            Self::CyberWatchRow { .. } => "Riga della cronologia cyber",
            Self::SourceSuggestion => "Suggerimento di fonte",
            Self::DiscoveryResult => "Ricerca pubblica registrata",
            Self::WorkQueueItem => "Voce della coda di lavoro",
            Self::GraphNode { .. } => "Vicino nel grafo",
            Self::Trend => "Valore emergente",
            Self::Spike => "Aumento oltre la soglia",
            Self::Resemblance => "Somiglianza fra contenuti",
            Self::PersonAssociation => "Associazione di un'identità osservata",
            Self::CoverageGap => "Periodo non coperto prioritario",
        }
    }

    /// Il nome della regola che mette l'elemento sullo schermo.
    ///
    /// La **versione** non sta qui: la conosce chi possiede la regola.
    #[must_use]
    pub const fn rule_name(self) -> &'static str {
        match self {
            Self::Content => "Elenco dello Storico",
            Self::Alert => "Regola dell'avviso",
            Self::Level => "Motore di analisi",
            Self::Match => "Ricerca dei termini del motore di analisi",
            Self::CyberEvent => "Raggruppamento per indicatore",
            Self::CyberWatchRow { .. } => "Cronologia del gruppo di segnali",
            Self::SourceSuggestion => "Ordine dei candidati",
            Self::DiscoveryResult => "Registro delle ricerche pubbliche",
            Self::WorkQueueItem => "Ordine della coda di lavoro",
            Self::GraphNode { .. } => "Vicinato del grafo",
            Self::Trend => "Valori emergenti",
            Self::Spike => "Aumenti oltre la soglia",
            Self::Resemblance => "Somiglianza fra testi",
            Self::PersonAssociation => "Associazioni dell'identità osservata",
            Self::CoverageGap => "Priorità dei periodi non coperti",
        }
    }

    /// Chi afferma la cosa (PR-03).
    ///
    /// # Perché è una funzione e non un campo
    ///
    /// Perché un campo si compila, e ciò che si compila si può sbagliare: un
    /// livello è un calcolo perché è un calcolo.
    #[must_use]
    pub const fn origin(self) -> Origin {
        match self {
            Self::Content | Self::PersonAssociation => Origin::Observed,
            Self::CyberWatchRow { by_a_person } | Self::GraphNode { by_a_person } => {
                if by_a_person {
                    Origin::Operator
                } else {
                    Origin::Observed
                }
            }
            Self::Alert
            | Self::Level
            | Self::Match
            | Self::CyberEvent
            | Self::SourceSuggestion
            | Self::DiscoveryResult
            | Self::WorkQueueItem
            | Self::Trend
            | Self::Spike
            | Self::Resemblance
            | Self::CoverageGap => Origin::Computed,
        }
    }

    /// **Che cosa non significa.** La parte 3, obbligatoria.
    ///
    /// # Perché sta nel dominio e non nella schermata
    ///
    /// Perché è la salvaguardia interpretativa messa dove una persona la
    /// incontra, e una salvaguardia che la schermata può omettere è una
    /// salvaguardia che una schermata ometterà.
    #[must_use]
    pub const fn does_not_mean(self) -> &'static str {
        match self {
            Self::Content => {
                "Essere in elenco non è un giudizio: vuol dire che la fonte lo ha pubblicato \
                 mentre il monitoraggio la seguiva. Non dice che sia vero, né che sia importante."
            }
            Self::Alert => {
                "Un avviso non è un accertamento: dice che una regola è scattata sul testo. Non \
                 dice che un fatto sia avvenuto, né chi ne sia responsabile."
            }
            Self::Level => {
                "Un livello non è un giudizio su chi scrive, né una probabilità. Con altri termini \
                 o con un altro motore il livello sarebbe diverso."
            }
            Self::Match => {
                "Un riscontro non è un accertamento: il termine compare nel testo, e basta. Non \
                 dice con quale intenzione è stato scritto."
            }
            Self::CyberEvent => {
                "Un gruppo di segnali non dice che un attacco sia avvenuto. Fonti diverse non sono \
                 conferme indipendenti: possono riprendere la stessa origine."
            }
            Self::CyberWatchRow { .. } => {
                "Una riga della cronologia dice che qualcosa è stato pubblicato o fatto a quell'ora. \
                 Non dice che sia vero, né che sia collegato al resto."
            }
            Self::SourceSuggestion => {
                "Un suggerimento non è una fonte, né un giudizio su chi la gestisce. La posizione \
                 in elenco non è un voto: dice quali ragioni ha, non quanto vale."
            }
            Self::DiscoveryResult => {
                "Una ricerca registrata dice che cosa è stato chiesto e che cosa è tornato. Ciò che \
                 non è tornato non vuol dire che non esista."
            }
            Self::WorkQueueItem => {
                "Una posizione in coda non è un giudizio: dice in che ordine guardare, non che cosa \
                 sia più grave. Una riga in fondo non è meno importante."
            }
            Self::GraphNode { .. } => {
                "Un collegamento nel grafo non è una relazione fra persone, né una prova di \
                 complicità. Dice che due cose compaiono nello stesso fatto registrato."
            }
            Self::Trend => {
                "Emergente non vuol dire pericoloso: vuol dire che compare più spesso che nel \
                 periodo di confronto. Con altri periodi il risultato sarebbe diverso."
            }
            Self::Spike => {
                "Un aumento oltre la soglia non vuol dire che stia succedendo qualcosa. Dice che il \
                 conteggio del giorno supera quello abituale, secondo una regola fissa."
            }
            Self::Resemblance => {
                "Due testi simili non hanno per forza lo stesso autore, né la stessa intenzione. \
                 Possono citare la stessa fonte, o riprendersi a vicenda."
            }
            Self::PersonAssociation => {
                "Un'associazione dice che l'identità compare in quel fatto registrato. Non dice \
                 chi sia la persona dietro l'identità, né che abbia fatto qualcosa."
            }
            Self::CoverageGap => {
                "La priorità è tecnica: non dice che nel periodo la fonte abbia pubblicato \
                 qualcosa, né quanto. Dice soltanto dove guardare per primo."
            }
        }
    }
}

/// La versione della regola, com'è nota a chi compone la risposta.
///
/// # Perché non basta un numero
///
/// Perché a volte il numero **non c'è**, e scriverne uno sarebbe
/// un'affermazione che nessuno ha verificato. Anche allora la risposta dice
/// qualcosa sulla versione: dice che non si sa, e perché.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleVersion {
    /// La versione è nota.
    Known(u32),
    /// L'elemento è stato prodotto prima che la regola avesse un numero.
    NotRecorded,
    /// La regola l'ha applicata l'Hub, e il protocollo non ne trasmette la
    /// versione.
    NotTransmitted,
}

impl RuleVersion {
    /// Come si dice la versione a chi legge.
    #[must_use]
    pub fn as_words(self) -> String {
        match self {
            Self::Known(numero) => format!("versione {numero}"),
            Self::NotRecorded => String::from(
                "versione non registrata: l'elemento è stato prodotto prima che la regola avesse \
                 un numero",
            ),
            Self::NotTransmitted => String::from(
                "versione dell'Hub: il protocollo non la trasmette a questa postazione",
            ),
        }
    }
}

/// La risposta a «perché vedo questo?», in tre parti.
///
/// # Perché i campi sono privati
///
/// Perché la parte 3 non deve potersi togliere, e il nome della regola non deve
/// potersi scambiare. L'unico costruttore è [`Explanation::compose`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explanation {
    /// Di che cosa.
    explained: Explained,
    /// La versione della regola.
    version: RuleVersion,
    /// I fatti registrati che l'hanno fatta scattare.
    facts: String,
}

impl Explanation {
    /// Compone la risposta.
    ///
    /// Restituisce `None` se i fatti sono vuoti: una risposta senza fatti
    /// direbbe che non c'è una ragione, e una ragione c'è sempre, altrimenti
    /// l'elemento non sarebbe sullo schermo.
    #[must_use]
    pub fn compose(explained: Explained, version: RuleVersion, facts: &str) -> Option<Self> {
        let facts = facts.trim();
        if facts.is_empty() {
            return None;
        }
        Some(Self {
            explained,
            version,
            facts: facts.to_owned(),
        })
    }

    /// Di che cosa.
    #[must_use]
    pub const fn explained(&self) -> Explained {
        self.explained
    }

    /// Di che cosa, a parole.
    #[must_use]
    pub const fn subject(&self) -> &'static str {
        self.explained.label()
    }

    /// Parte 1, la regola: il nome e la versione, sempre insieme.
    #[must_use]
    pub fn rule(&self) -> String {
        format!(
            "Regola «{}», {}.",
            self.explained.rule_name(),
            self.version.as_words()
        )
    }

    /// La versione della regola.
    #[must_use]
    pub const fn version(&self) -> RuleVersion {
        self.version
    }

    /// Parte 1, i fatti.
    #[must_use]
    pub fn facts(&self) -> &str {
        &self.facts
    }

    /// Parte 2: che genere di certezza è.
    #[must_use]
    pub const fn certainty(&self) -> Origin {
        self.explained.origin()
    }

    /// Parte 3: che cosa non significa.
    #[must_use]
    pub const fn does_not_mean(&self) -> &'static str {
        self.explained.does_not_mean()
    }

    /// La risposta intera, nelle tre parti e in quest'ordine.
    #[must_use]
    pub fn as_text(&self) -> String {
        format!(
            "{}\n\n{}\n{}\n{}\n\n{}\n{} — {}\n\n{}\n{}",
            self.subject(),
            PART_CAUSE,
            self.rule(),
            self.facts,
            PART_CERTAINTY,
            self.certainty().label(),
            self.certainty().as_sentence(),
            PART_NOT_MEANING,
            self.does_not_mean()
        )
    }
}

/// Il titolo della parte 1.
pub const PART_CAUSE: &str = "Che cosa lo ha fatto comparire";
/// Il titolo della parte 2.
pub const PART_CERTAINTY: &str = "Che genere di certezza è";
/// Il titolo della parte 3.
pub const PART_NOT_MEANING: &str = "Che cosa non significa";

/// L'esito di una richiesta: la risposta, oppure la dichiarazione che non la si
/// può dare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplanationOutcome {
    /// La risposta, composta.
    Composed(Explanation),
    /// L'elemento non è fra quelli che questa postazione può vedere.
    NotAvailable,
}

impl ExplanationOutcome {
    /// La frase che dice che la risposta non è disponibile.
    ///
    /// Non dice perché l'elemento non si vede: dirlo sarebbe già dire
    /// qualcosa dell'elemento.
    pub const NOT_AVAILABLE: &'static str = "La spiegazione non è disponibile: questo elemento non \
                                             è fra quelli che l'Hub mostra a questa postazione.";
}

#[cfg(test)]
mod tests {
    use super::{Explained, Explanation, ExplanationOutcome, RuleVersion};
    use crate::model::origin::Origin;

    /// Il sorgente di questo modulo, per le prove sulla forma.
    const THIS_MODULE: &str = include_str!("explanation.rs");

    fn produzione() -> &'static str {
        THIS_MODULE
            .split_once("#[cfg(test)]\nmod tests {")
            .map_or(THIS_MODULE, |(codice, _)| codice)
    }

    fn una(genere: Explained) -> Explanation {
        let Some(risposta) = Explanation::compose(genere, RuleVersion::Known(1), "Un fatto.")
        else {
            panic!("fatti non vuoti devono comporre una risposta");
        };
        risposta
    }

    /// **Ogni genere ha le tre parti, e nessuna è vuota.**
    #[test]
    fn ogni_genere_ha_le_tre_parti() {
        for genere in Explained::ALL {
            let risposta = una(genere);
            assert!(!risposta.rule().is_empty(), "{genere:?}: regola vuota");
            assert!(!risposta.facts().is_empty(), "{genere:?}: fatti vuoti");
            assert!(
                !risposta.certainty().label().is_empty(),
                "{genere:?}: certezza vuota"
            );
            assert!(
                !risposta.does_not_mean().trim().is_empty(),
                "{genere:?}: manca la parte 3, «che cosa non significa»"
            );
        }
    }

    /// **La parte 3 nega qualcosa.** Una frase che non contiene una negazione
    /// non dice che cosa l'elemento non significa.
    #[test]
    fn la_parte_3_dice_che_cosa_non_significa() {
        for genere in Explained::ALL {
            let frase = genere.does_not_mean();
            assert!(
                frase.contains("non ") || frase.contains("Non ") || frase.contains(" né "),
                "{genere:?}: la parte 3 deve dire che cosa NON significa: «{frase}»"
            );
        }
    }

    /// **La regola si nomina con la versione, mai da sola.**
    #[test]
    fn la_regola_si_nomina_con_la_versione() {
        for versione in [
            RuleVersion::Known(3),
            RuleVersion::NotRecorded,
            RuleVersion::NotTransmitted,
        ] {
            for genere in Explained::ALL {
                let Some(risposta) = Explanation::compose(genere, versione, "Un fatto.") else {
                    panic!("fatti non vuoti devono comporre una risposta");
                };
                let regola = risposta.rule();
                assert!(regola.contains(genere.rule_name()), "{regola}");
                assert!(regola.contains("versione"), "{regola}");
            }
        }
        assert!(una(Explained::Alert).rule().contains("versione 1"));
    }

    /// **Le tre parti compaiono sempre, nello stesso ordine.**
    #[test]
    fn le_tre_parti_sono_in_quest_ordine() {
        for genere in Explained::ALL {
            let testo = una(genere).as_text();
            let (Some(uno), Some(due), Some(tre)) = (
                testo.find(super::PART_CAUSE),
                testo.find(super::PART_CERTAINTY),
                testo.find(super::PART_NOT_MEANING),
            ) else {
                panic!("{genere:?}: una delle tre parti manca:\n{testo}");
            };
            assert!(uno < due && due < tre, "{genere:?}: ordine sbagliato");
            assert!(testo.contains(genere.does_not_mean()));
        }
    }

    /// **Senza fatti non c'è risposta.**
    #[test]
    fn senza_fatti_non_si_compone() {
        assert!(Explanation::compose(Explained::Trend, RuleVersion::Known(1), "   ").is_none());
    }

    /// **Stesso elemento, stesso stato, stessa frase.**
    #[test]
    fn la_risposta_e_deterministica() {
        for genere in Explained::ALL {
            assert_eq!(una(genere).as_text(), una(genere).as_text());
        }
    }

    /// **L'origine è quella di PR-03**, e dipende da chi ha agito dove una
    /// persona può averlo fatto.
    #[test]
    fn l_origine_discende_dal_genere() {
        assert_eq!(Explained::Content.origin(), Origin::Observed);
        assert_eq!(Explained::Level.origin(), Origin::Computed);
        assert_eq!(Explained::WorkQueueItem.origin(), Origin::Computed);
        assert_eq!(
            Explained::GraphNode { by_a_person: true }.origin(),
            Origin::Operator
        );
        assert_eq!(
            Explained::GraphNode { by_a_person: false }.origin(),
            Origin::Observed
        );
        assert_eq!(
            Explained::CyberWatchRow { by_a_person: true }.origin(),
            Origin::Operator
        );
    }

    /// **Nessun genere dimenticato in `ALL`.** Ogni variante dichiarata
    /// nell'enumerazione compare nell'elenco.
    #[test]
    fn all_elenca_ogni_genere() {
        let codice = produzione();
        let Some((_, dopo)) = codice.split_once("pub enum Explained {") else {
            panic!("l'enumerazione deve essere riconoscibile");
        };
        let Some((corpo, _)) = dopo.split_once("\n}\n") else {
            panic!("l'enumerazione deve chiudersi");
        };
        let varianti: Vec<&str> = corpo
            .lines()
            .map(str::trim)
            .filter(|riga| !riga.starts_with("//") && !riga.is_empty())
            .filter_map(|riga| {
                let nome = riga.split([',', ' ', '{']).next()?;
                nome.chars()
                    .next()
                    .filter(char::is_ascii_uppercase)
                    .map(|_| nome)
            })
            .collect();
        assert!(varianti.len() >= 14, "{varianti:?}");
        for variante in varianti {
            assert!(
                Explained::ALL
                    .iter()
                    .any(|genere| format!("{genere:?}").starts_with(variante)),
                "il genere «{variante}» non è in Explained::ALL"
            );
        }
    }

    /// **Nessuna lettura dell'orologio** nel codice che compone.
    #[test]
    fn il_modulo_non_legge_l_orologio() {
        let codice = produzione();
        for vietato in ["now(", "SystemTime", "Instant", "Timestamp", "rand"] {
            assert!(
                !codice.contains(vietato),
                "«{vietato}» nel modulo delle spiegazioni: la risposta dipenderebbe dall'orologio"
            );
        }
    }

    #[test]
    fn non_disponibile_non_dice_che_cosa_sia_l_elemento() {
        let frase = ExplanationOutcome::NOT_AVAILABLE;
        assert!(frase.contains("non è disponibile"));
        assert!(!frase.contains('#'));
    }
}

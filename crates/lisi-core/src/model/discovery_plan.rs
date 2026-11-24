//! Che cosa si chiederebbe, deciso prima di chiedere.
//!
//! # Perché un pianificatore esiste
//!
//! Un dizionario dell'ufficio può avere mille termini. Mille termini che
//! diventano mille interrogazioni sono **un modo per farsi bloccare l'account
//! d'ufficio** (ADR-0035, decisione 12), e l'account d'ufficio è uno solo.
//!
//! # La regola che governa questo modulo
//!
//! **Un piano che taglia in silenzio è un piano che mente.**
//!
//! Il tetto taglia, ed è giusto: su mille termini e dieci interrogazioni
//! disponibili, novecentonovanta restano fuori. Ciò che non è giusto è tacerlo —
//! un piano che taglia in silenzio fa credere di aver cercato tutto, e il
//! rapporto che ne esce dice «non trovato» di cose che **nessuno ha cercato**.
//!
//! È la stessa forma del difetto che questo prodotto chiude da ADR-0064 in poi:
//! **un'assenza che non dichiara di essere un'assenza**.
//!
//! # Che cosa questo modulo NON fa
//!
//! Non parla con Telegram: non ha un client, non fa richieste, non attende
//! risposte. Non è purismo — un pianificatore che esce in rete **non si può
//! provare**, e le sue proprietà interessanti diventerebbero verificabili solo
//! con un account vero, cioè mai.
//!
//! La decisione completa sta in
//! `docs/adr/ADR-0075-UN-PIANO-CHE-TAGLIA-IN-SILENZIO-E-UN-PIANO-CHE-MENTE.md`.

use crate::model::discovery::{DiscoveryQuery, SearchScope, ValidatedDiscoveryPolicy};

/// Quante pagine al massimo si leggono di una stessa interrogazione.
///
/// # Perché è un tetto NOSTRO, e si chiama così
///
/// Telegram non lo dichiara: lo scegliamo noi, e serve a non restare a leggere
/// per sempre — **non** a non spendere, perché paginare non consuma quota nuova
/// (ADR-0035, decisione 4).
///
/// Mescolarlo ai limiti misurati renderebbe di nuovo indistinguibile ciò che è
/// stato osservato da ciò che è stato deciso (ADR-0075, decisione 6).
pub const NOSTRO_TETTO_PAGINE: u32 = 5;

/// Quanto si aspetta una risposta, in secondi.
///
/// Tetto **nostro**: vedere [`NOSTRO_TETTO_PAGINE`].
pub const NOSTRA_ATTESA_MASSIMA_SECONDI: u32 = 30;

/// Quanti errori di fila prima di fermarsi.
///
/// Tetto **nostro**: vedere [`NOSTRO_TETTO_PAGINE`]. Fermarsi dopo pochi errori
/// consecutivi è ciò che distingue un programma che incontra un problema da uno
/// che insiste contro un limite.
pub const NOSTRI_ERRORI_CONSECUTIVI: u32 = 3;

/// Perché un termine non è entrato nel piano.
///
/// Sono pochi e distinti apposta: «tagliato» senza dire perché manderebbe chi
/// legge a indovinare, e le tre cause portano a tre azioni diverse — correggere
/// il termine, non preoccuparsi, oppure alzare il tetto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Omission {
    /// Non era un'interrogazione: vuoto, o fatto di soli spazi.
    NotAQuery,
    /// Produceva la stessa interrogazione di un termine già entrato.
    ///
    /// **Non è una perdita**: la domanda verrà comunque posta, una volta sola.
    AlreadyAsked,
    /// Il tetto delle interrogazioni era finito.
    ///
    /// È l'unica omissione che **toglie una domanda**: quella parola non verrà
    /// chiesta a nessuno.
    BudgetSpent,
}

impl Omission {
    /// Se questa omissione **toglie davvero una domanda**.
    ///
    /// Serve a chi deve dire all'operatore quanto è stato lasciato fuori senza
    /// gonfiare il numero con i duplicati, che una domanda ce l'hanno.
    #[must_use]
    pub const fn toglie_una_domanda(self) -> bool {
        matches!(self, Self::BudgetSpent)
    }

    /// Nome stabile, per l'archivio e per l'audit.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAQuery => "non_e_un_interrogazione",
            Self::AlreadyAsked => "gia_chiesta",
            Self::BudgetSpent => "tetto_esaurito",
        }
    }

    /// Il motivo, in una frase che una persona legge.
    #[must_use]
    pub const fn sentence(self) -> &'static str {
        match self {
            Self::NotAQuery => "non è una domanda: è vuoto",
            Self::AlreadyAsked => {
                "la stessa domanda è già nell'elenco, e verrà posta una volta sola"
            }
            Self::BudgetSpent => "il numero di domande disponibili era finito",
        }
    }
}

/// Un termine che non è entrato, e perché.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmittedTerm {
    /// Il termine, come era stato scritto.
    pub term: String,
    /// Perché non è entrato.
    pub reason: Omission,
}

/// I tetti che valgono durante l'esecuzione.
///
/// # Perché due specie di numeri stanno in due posti
///
/// Il tetto sulle **interrogazioni** viene dalla politica, che è validata contro
/// limiti **osservati**: quello non lo inventiamo. Gli altri li scegliamo noi, e
/// portano un nome che lo dice (ADR-0075, decisione 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryBudget {
    /// Quante interrogazioni distinte, dalla politica validata.
    pub distinct_queries: u32,
    /// Quanti risultati per interrogazione, dalla politica validata.
    pub results_per_query: u32,
    /// Quante pagine per interrogazione. **Tetto nostro.**
    pub our_page_cap: u32,
    /// Quanto si aspetta una risposta, in secondi. **Tetto nostro.**
    pub our_wait_seconds: u32,
    /// Quanti errori di fila prima di fermarsi. **Tetto nostro.**
    pub our_consecutive_errors: u32,
    /// Fra quanti secondi Telegram dice che si potrà riprovare.
    ///
    /// **Non è un tetto nostro**: è il ritardo che Telegram dichiara, e si
    /// aspetta quello — non un intervallo scelto da noi (ADR-0035, decisione 4).
    pub declared_backoff_seconds: u32,
}

/// Che cosa si chiederebbe, e che cosa resta fuori.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryPlan {
    /// Dove si guarderebbe.
    pub scope: SearchScope,
    /// Le interrogazioni, nell'ordine in cui verrebbero poste.
    pub queries: Vec<DiscoveryQuery>,
    /// I tetti che valgono durante l'esecuzione.
    pub budget: DiscoveryBudget,
    /// Che cosa non è entrato, e perché.
    ///
    /// **Non è un dettaglio diagnostico**: è la differenza fra «non trovato» e
    /// «non cercato», e chi legge un rapporto ha diritto di saperla.
    pub omitted: Vec<OmittedTerm>,
}

impl DiscoveryPlan {
    /// Quante domande sono state **tolte** dal tetto.
    ///
    /// Non conta i duplicati, che una domanda ce l'hanno.
    #[must_use]
    pub fn domande_tolte(&self) -> usize {
        self.omitted
            .iter()
            .filter(|omesso| omesso.reason.toglie_una_domanda())
            .count()
    }

    /// Che cosa dire di ciò che è rimasto fuori.
    ///
    /// `None` quando non è rimasto fuori niente che tolga una domanda: una frase
    /// che dicesse «zero termini esclusi» insegnerebbe a non leggerla.
    #[must_use]
    pub fn omissions_sentence(&self) -> Option<String> {
        let tolte = self.domande_tolte();
        if tolte == 0 {
            return None;
        }

        Some(format!(
            "{tolte} termini non sono stati chiesti: il numero di domande \
             disponibili era finito. Di quei termini questa ricerca non dice \
             nulla — né che ci siano riscontri, né che non ce ne siano."
        ))
    }
}

/// Compone il piano da una politica validata e dai termini da chiedere.
///
/// # Deterministico, e che cosa significa
///
/// Due esecuzioni sulla stessa base danno **lo stesso piano, nello stesso
/// ordine**. Ne segue che cosa è vietato qui dentro: nessun orologio, nessun
/// numero casuale, nessun ordine che venga dall'iterazione di una tabella hash.
///
/// L'ordine è quello in cui i termini arrivano: chi chiama lo ha già deciso, e
/// due riordini diversi dello stesso insieme sono due decisioni diverse — non
/// spetta al pianificatore sceglierne una.
///
/// # Che cosa fa la deduplica
///
/// Due termini che producono la stessa interrogazione consumano **una** quota, e
/// **resta il primo**: anche la deduplica deve essere ripetibile.
#[must_use]
pub fn plan(policy: &ValidatedDiscoveryPolicy, terms: &[String]) -> DiscoveryPlan {
    let budget = DiscoveryBudget {
        distinct_queries: policy.policy().max_distinct_queries,
        results_per_query: policy.policy().max_results_per_query,
        our_page_cap: NOSTRO_TETTO_PAGINE,
        our_wait_seconds: NOSTRA_ATTESA_MASSIMA_SECONDI,
        our_consecutive_errors: NOSTRI_ERRORI_CONSECUTIVI,
        declared_backoff_seconds: policy.limits().next_free_in_seconds(),
    };

    let mut queries: Vec<DiscoveryQuery> = Vec::new();
    let mut omitted: Vec<OmittedTerm> = Vec::new();

    for term in terms {
        let Some(query) = DiscoveryQuery::try_new(term) else {
            omitted.push(OmittedTerm {
                term: term.clone(),
                reason: Omission::NotAQuery,
            });
            continue;
        };

        // La deduplica guarda la forma normalizzata, non il testo originale:
        // due termini scritti in modo diverso che producono la stessa domanda
        // sono una domanda sola.
        if queries
            .iter()
            .any(|esistente| stessa_domanda(esistente, &query))
        {
            omitted.push(OmittedTerm {
                term: term.clone(),
                reason: Omission::AlreadyAsked,
            });
            continue;
        }

        // IL TETTO VIENE DALLA POLITICA, che è validata contro limiti osservati.
        if u32::try_from(queries.len()).unwrap_or(u32::MAX) >= budget.distinct_queries {
            omitted.push(OmittedTerm {
                term: term.clone(),
                reason: Omission::BudgetSpent,
            });
            continue;
        }

        queries.push(query);
    }

    DiscoveryPlan {
        scope: policy.scope(),
        queries,
        budget,
        omitted,
    }
}

/// Se due interrogazioni sono la stessa domanda.
///
/// Il confronto ignora maiuscole e minuscole. **Non promette** che Telegram le
/// tratterebbe allo stesso modo: la deduplica risparmia quota, non afferma che le
/// risposte sarebbero state identiche (ADR-0075, rischio residuo).
fn stessa_domanda(uno: &DiscoveryQuery, altro: &DiscoveryQuery) -> bool {
    uno.as_str().to_lowercase() == altro.as_str().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{DiscoveryBudget, Omission, plan};
    use crate::model::discovery::{DiscoveryPolicy, ObservedLimits, SearchScope};
    use crate::time::Timestamp;

    fn politica(
        interrogazioni: u32,
        attesa: u32,
    ) -> crate::model::discovery::ValidatedDiscoveryPolicy {
        let Some(limiti) = ObservedLimits::observed(
            100,
            100,
            attesa,
            Timestamp::from_millis(1_700_000_000_000),
            "misura dal vivo di prova",
        ) else {
            panic!("i limiti di prova devono potersi costruire");
        };
        let Some(validata) = (DiscoveryPolicy {
            scope: SearchScope::PublicChannelPosts,
            max_distinct_queries: interrogazioni,
            max_results_per_query: 20,
        })
        .validate(&limiti) else {
            panic!("la politica di prova deve potersi validare");
        };
        validata
    }

    fn termini(elenco: &[&str]) -> Vec<String> {
        elenco.iter().map(|testo| (*testo).to_owned()).collect()
    }

    /// **Stessi termini, stessa politica, stesso piano.**
    ///
    /// Un piano che cambia da solo produce scoperte che nessuno puo' ripetere:
    /// chi rileggesse un rapporto fra un anno non potrebbe rifare la stessa
    /// domanda e vedere se la risposta e' cambiata.
    #[test]
    fn lo_stesso_piano_si_ottiene_due_volte() {
        let politica = politica(5, 0);
        let elenco = termini(&["ransomware", "phishing", "ransomware", "", "cve-2026-1"]);

        let primo = plan(&politica, &elenco);
        let secondo = plan(&politica, &elenco);

        assert_eq!(primo, secondo, "due esecuzioni devono dare lo stesso piano");
    }

    /// **Cio' che non entra nel piano si dichiara, con il suo motivo.**
    ///
    /// Un piano che taglia in silenzio fa credere di aver cercato tutto, e il
    /// rapporto che ne esce dice «non trovato» di cose che nessuno ha cercato.
    #[test]
    fn cio_che_resta_fuori_porta_il_motivo() {
        let politica = politica(2, 0);
        let elenco = termini(&["uno", "  ", "UNO", "due", "tre"]);

        let piano = plan(&politica, &elenco);

        assert_eq!(piano.queries.len(), 2);
        assert_eq!(piano.queries[0].as_str(), "uno");
        assert_eq!(piano.queries[1].as_str(), "due");

        let motivi: Vec<Omission> = piano.omitted.iter().map(|omesso| omesso.reason).collect();
        assert_eq!(
            motivi,
            vec![
                Omission::NotAQuery,
                Omission::AlreadyAsked,
                Omission::BudgetSpent
            ],
            "ogni termine escluso deve portare il proprio motivo"
        );
    }

    /// **Un duplicato non e' una domanda tolta.**
    ///
    /// Contarlo fra le esclusioni gonfierebbe il numero che l'operatore legge, e
    /// un numero gonfiato e' un numero che si impara a ignorare.
    #[test]
    fn un_duplicato_non_conta_come_domanda_tolta() {
        let politica = politica(10, 0);
        let piano = plan(&politica, &termini(&["uno", "UNO", "Uno"]));

        assert_eq!(piano.queries.len(), 1);
        assert_eq!(piano.omitted.len(), 2);
        assert_eq!(piano.domande_tolte(), 0);
        assert!(
            piano.omissions_sentence().is_none(),
            "senza domande tolte non c'e' niente da dire"
        );
    }

    /// **La frase sulle esclusioni dice che di quei termini non si sa nulla.**
    ///
    /// Non «non trovato»: NON CERCATO. Sono due cose diverse, e la seconda non ha
    /// il diritto di somigliare alla prima.
    #[test]
    fn la_frase_distingue_non_cercato_da_non_trovato() {
        let politica = politica(1, 0);
        let piano = plan(&politica, &termini(&["uno", "due", "tre"]));

        assert_eq!(piano.domande_tolte(), 2);
        let Some(frase) = piano.omissions_sentence() else {
            panic!("con delle domande tolte ci deve essere una frase");
        };
        assert!(
            frase.contains("non dice nulla"),
            "la frase deve dire che di quei termini non si sa nulla: «{frase}»"
        );
        assert!(
            frase.contains("né che non ce ne siano"),
            "la frase deve escludere la lettura «non trovato»: «{frase}»"
        );
    }

    /// **I tetti nostri e i limiti osservati non si mescolano.**
    ///
    /// Il tetto sulle interrogazioni viene dalla politica, che e' validata contro
    /// limiti misurati; gli altri li scegliamo noi, e il nome lo dice. E il
    /// backoff e' quello che Telegram dichiara, non un intervallo scelto.
    #[test]
    fn i_tetti_nostri_si_distinguono_dai_limiti_osservati() {
        let politica = politica(7, 42);
        let piano = plan(&politica, &termini(&["uno"]));

        let DiscoveryBudget {
            distinct_queries,
            our_page_cap,
            declared_backoff_seconds,
            ..
        } = piano.budget;

        assert_eq!(
            distinct_queries, 7,
            "il tetto delle interrogazioni viene dalla politica validata"
        );
        assert_eq!(our_page_cap, super::NOSTRO_TETTO_PAGINE);
        assert_eq!(
            declared_backoff_seconds, 42,
            "il backoff e' quello che Telegram dichiara, non uno scelto da noi"
        );
    }

    /// **Il pianificatore non parla con nessuno.**
    ///
    /// Un pianificatore che esce in rete non si puo' provare: le sue proprieta'
    /// interessanti diventerebbero verificabili solo con un account vero.
    #[test]
    fn il_pianificatore_non_esce_in_rete_e_non_guarda_l_orologio() {
        const QUESTO_MODULO: &str = include_str!("discovery_plan.rs");

        let Some((produzione, _)) = QUESTO_MODULO.split_once("\n#[cfg(test)]\nmod tests {") else {
            panic!("il blocco delle prove non si delimita");
        };
        let codice: String = produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<&str>>()
            .join("\n");

        for vietato in [
            "https::",
            "fetch(",
            "reqwest",
            "Timestamp::now",
            "SystemTime",
            "rand",
            "HashMap",
            "HashSet",
        ] {
            assert!(
                !codice.contains(vietato),
                "«{vietato}» nel pianificatore: deve restare deterministico e \
                 non parlare con nessuno (ADR-0075)"
            );
        }
    }

    /// **Il piano guarda dove dice la politica.**
    #[test]
    fn il_piano_porta_l_ambito_della_politica() {
        let politica = politica(3, 0);
        let piano = plan(&politica, &termini(&["uno"]));
        assert_eq!(piano.scope, SearchScope::PublicChannelPosts);
    }
}

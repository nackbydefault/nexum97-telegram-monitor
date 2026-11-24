//! Il live condiviso: che cosa l'Hub pubblica di una tornata, e quanto una
//! postazione ne conserva (TEAM-LIVE-01, ADR-0093).
//!
//! # Si aggrega, e si dichiara ciò che si taglia
//!
//! Un evento per messaggio moltiplicherebbe per il traffico una sequenza
//! pensata per fatti amministrativi, e riempirebbe la coda di ADR-0088 in una
//! manciata di secondi. Si pubblica quindi **un evento per fonte per tornata**,
//! con un tetto; oltre il tetto si pubblica **un** evento che dice quante
//! fonti e quanti contenuti restano fuori.
//!
//! Un taglio che si dichiara, non un silenzio: è la regola di ADR-0075, dove
//! un piano che taglia senza dirlo fa leggere «non trovato» dove la verità è
//! «non cercato».
//!
//! # L'ordine del taglio è alfabetico, e non è un giudizio
//!
//! Le fonti si ordinano per nome, e il tetto prende le prime. Ordinare per
//! numero di contenuti sembrerebbe più utile e sarebbe una **classifica**: il
//! prodotto non ne produce (ADR-0078). Ciò che resta fuori è comunque
//! dichiarato, quindi nessuno legge un elenco parziale come completo.

use std::collections::BTreeMap;

/// Eventi al più pubblicati per una tornata di acquisizione.
///
/// Valore scelto da noi, **non misurato**: trentadue fonti in una tornata sono
/// già un ufficio che sorveglia molto, e oltre il tetto la riga che dichiara il
/// taglio dice più di trenta righe che nessuno legge.
pub const MAX_LIVE_EVENTS_PER_ROUND: usize = 32;

/// Righe che una postazione conserva del live condiviso.
///
/// La proiezione **non è l'archivio dell'Hub**: è ciò che si vede sullo
/// schermo. Il punto raggiunto vive nel cursore (ADR-0087), quindi potare non
/// perde nulla.
pub const LIVE_FEED_MAX_ROWS: usize = 500;

/// Che cosa pubblicare di una tornata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundPlan {
    /// Le fonti pubblicate, in ordine di nome, con quanti contenuti ciascuna.
    pub published: Vec<(String, usize)>,
    /// Quante fonti restano fuori dal tetto.
    pub omitted_sources: usize,
    /// Quanti contenuti restano fuori dal tetto.
    pub omitted_contents: usize,
}

impl RoundPlan {
    /// Se qualcosa è stato tagliato, e quindi va dichiarato.
    #[must_use]
    pub const fn has_omissions(&self) -> bool {
        self.omitted_sources > 0
    }

    /// Quante fonti sono state contate in tutto.
    #[must_use]
    pub const fn counted_sources(&self) -> usize {
        self.published.len() + self.omitted_sources
    }
}

/// Decide che cosa pubblicare di una tornata, dato il tetto.
///
/// `counts` associa a ciascuna fonte quanti contenuti ha prodotto nella
/// tornata. Le fonti senza contenuti non si pubblicano: un evento «zero
/// contenuti» direbbe che non è successo nulla, che è esattamente ciò che
/// l'assenza di evento dice già.
#[must_use]
pub fn plan_round(counts: &BTreeMap<String, usize>, cap: usize) -> RoundPlan {
    let mut published = Vec::new();
    let mut omitted_sources = 0_usize;
    let mut omitted_contents = 0_usize;

    for (fonte, quanti) in counts {
        if *quanti == 0 {
            continue;
        }
        if published.len() < cap {
            published.push((fonte.clone(), *quanti));
        } else {
            omitted_sources += 1;
            omitted_contents += *quanti;
        }
    }

    RoundPlan {
        published,
        omitted_sources,
        omitted_contents,
    }
}

/// Quante righe della proiezione vanno potate, dato quante ce ne sono.
///
/// La potatura è **sul numero**, non sull'età: una postazione ferma una
/// settimana deve trovare le ultime righe, non una schermata vuota perché il
/// tempo è passato.
#[must_use]
pub const fn rows_to_prune(rows: usize, cap: usize) -> usize {
    rows.saturating_sub(cap)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{LIVE_FEED_MAX_ROWS, MAX_LIVE_EVENTS_PER_ROUND, plan_round, rows_to_prune};

    fn conteggi(voci: &[(&str, usize)]) -> BTreeMap<String, usize> {
        let mut mappa = BTreeMap::new();
        for (fonte, quanti) in voci {
            mappa.insert(String::from(*fonte), *quanti);
        }
        mappa
    }

    #[test]
    fn a_round_publishes_one_entry_per_source_with_content() {
        let piano = plan_round(&conteggi(&[("alfa", 3), ("beta", 1)]), 32);
        assert_eq!(
            piano.published,
            vec![(String::from("alfa"), 3), (String::from("beta"), 1)]
        );
        assert!(!piano.has_omissions());
        assert_eq!(piano.counted_sources(), 2);
    }

    #[test]
    fn a_source_without_content_is_not_published() {
        let piano = plan_round(&conteggi(&[("alfa", 0), ("beta", 2)]), 32);
        assert_eq!(piano.published, vec![(String::from("beta"), 2)]);
        assert!(!piano.has_omissions());
    }

    #[test]
    fn beyond_the_cap_what_is_left_out_is_declared() {
        let piano = plan_round(&conteggi(&[("alfa", 1), ("beta", 2), ("gamma", 4)]), 1);
        assert_eq!(piano.published, vec![(String::from("alfa"), 1)]);
        assert_eq!(piano.omitted_sources, 2);
        assert_eq!(
            piano.omitted_contents, 6,
            "ciò che resta fuori si dichiara anche nel numero dei contenuti"
        );
        assert!(piano.has_omissions());
        assert_eq!(piano.counted_sources(), 3);
    }

    #[test]
    fn an_empty_round_publishes_nothing() {
        let piano = plan_round(&conteggi(&[]), MAX_LIVE_EVENTS_PER_ROUND);
        assert!(piano.published.is_empty());
        assert!(!piano.has_omissions());
    }

    #[test]
    fn pruning_counts_rows_and_not_days() {
        assert_eq!(rows_to_prune(10, LIVE_FEED_MAX_ROWS), 0);
        assert_eq!(rows_to_prune(LIVE_FEED_MAX_ROWS, LIVE_FEED_MAX_ROWS), 0);
        assert_eq!(rows_to_prune(LIVE_FEED_MAX_ROWS + 7, LIVE_FEED_MAX_ROWS), 7);
    }
}

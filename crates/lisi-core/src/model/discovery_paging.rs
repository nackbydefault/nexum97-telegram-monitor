//! Quando si legge un'altra pagina, quando ci si ferma, e che cosa si può dire
//! di ciò che si è letto.
//!
//! # La frase che governa questo modulo
//!
//! **L'assenza di risultati non è l'assenza di contenuto.**
//!
//! ADR-0035 l'aveva già scritta, e aggiungeva che chi legge deve poter sapere
//! **quale ambito**, **quali limiti**, **se c'era paginazione** e **se qualcosa è
//! stato troncato**. Tutte e quattro si sanno **solo mentre si pagina**: se il
//! motore non le raccoglie, nessuna schermata potrà dirle dopo — e una ricerca
//! che non ha trovato nulla avrà lo stesso aspetto di una che si è fermata al
//! primo tetto.
//!
//! # Che cosa questo modulo NON fa
//!
//! Non chiede pagine: **decide se continuare**. Non ha un client, non attende,
//! non riprova da sé. Un motore che chiede da sé non si può provare, ed è la
//! stessa ragione per cui il pianificatore non parla con Telegram (ADR-0075).
//!
//! La decisione completa sta in
//! `docs/adr/ADR-0077-L-ASSENZA-DI-RISULTATI-NON-E-L-ASSENZA-DI-CONTENUTO.md`.

use crate::model::discovery::SearchScope;
use crate::model::discovery_plan::DiscoveryBudget;

/// Se una superficie sa paginare.
///
/// # Perché è una domanda e non un dettaglio
///
/// `searchPublicChats` restituisce «un numero significativo di risultati» **con
/// criterio ignoto e senza paginazione** (ADR-0035). Per quella superficie
/// «finito» non si può dire: la risposta è **parziale per costruzione**, e un
/// elenco parziale che si presenta come completo è la bugia più facile da
/// scrivere, perché non richiede di dire niente di falso — basta tacere.
#[must_use]
pub const fn la_superficie_pagina(scope: SearchScope) -> bool {
    !matches!(scope, SearchScope::DiscoveredPublicChats)
}

/// Perché si è smesso di leggere.
///
/// Cinque motivi, distinti perché portano a cinque letture diverse. Appiattirli
/// in «finito» renderebbe indistinguibile una risposta completa da una troncata,
/// e la prima autorizza a concludere mentre la seconda no.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StopReason {
    /// Il servizio ha detto di non avere altro.
    ///
    /// È **l'unico** motivo che permette di dire «questo è tutto», e anche
    /// allora solo **nell'ambito eseguito**.
    ServiceExhausted,
    /// Il tetto delle pagine, che è **nostro**.
    OurPageCap,
    /// Il tetto dei risultati, che viene dalla politica validata.
    ResultsCap,
    /// Troppi errori di fila.
    ConsecutiveErrors,
    /// La superficie non pagina: ciò che è arrivato è parziale per costruzione.
    SurfaceDoesNotPaginate,
}

impl StopReason {
    /// Se, fermandosi così, si può dire di aver visto tutto l'ambito.
    #[must_use]
    pub const fn si_e_visto_tutto_l_ambito(self) -> bool {
        matches!(self, Self::ServiceExhausted)
    }

    /// Nome stabile, per l'archivio e per l'audit.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServiceExhausted => "servizio_esaurito",
            Self::OurPageCap => "nostro_tetto_pagine",
            Self::ResultsCap => "tetto_risultati",
            Self::ConsecutiveErrors => "troppi_errori",
            Self::SurfaceDoesNotPaginate => "superficie_senza_paginazione",
        }
    }
}

/// Che cosa è arrivato con l'ultima pagina.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageReceived {
    /// Una pagina è arrivata, con questi risultati.
    Results {
        /// Quanti risultati portava.
        count: u32,
        /// Se il servizio dichiara che ce n'è ancora.
        more_available: bool,
    },
    /// La richiesta non è andata a buon fine.
    Failed,
}

/// Che cosa fare dopo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PagingStep {
    /// Leggere un'altra pagina.
    ReadAnother,
    /// Smettere, per questo motivo.
    Stop(StopReason),
}

/// Che cosa si è letto finora, e che cosa se ne può dire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Reading {
    /// Quante pagine sono state lette.
    pub pages: u32,
    /// Quanti risultati sono arrivati.
    pub results: u32,
    /// Quanti errori **di fila**.
    ///
    /// Si azzera appena una pagina arriva: un contatore che non si azzerasse
    /// fermerebbe una ricerca per errori sparsi nell'arco di un'ora, cioè per una
    /// rete che funziona male ma funziona.
    pub consecutive_errors: u32,
}

impl Reading {
    /// Registra che cosa è arrivato.
    #[must_use]
    pub const fn con(self, page: PageReceived) -> Self {
        match page {
            PageReceived::Results { count, .. } => Self {
                pages: self.pages + 1,
                results: self.results + count,
                // UNA PAGINA ARRIVATA AZZERA IL CONTO: e' cio' che distingue un
                // servizio che non risponde da uno che risponde a fatica.
                consecutive_errors: 0,
            },
            PageReceived::Failed => Self {
                consecutive_errors: self.consecutive_errors + 1,
                ..self
            },
        }
    }
}

/// Che cosa dire di una lettura finita.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadingReport {
    /// Dove si è guardato.
    pub scope: SearchScope,
    /// Che cosa si è letto.
    pub reading: Reading,
    /// Perché si è smesso.
    pub stopped: StopReason,
}

impl ReadingReport {
    /// Se ciò che è stato letto è **troncato**.
    #[must_use]
    pub const fn troncato(&self) -> bool {
        !self.stopped.si_e_visto_tutto_l_ambito()
    }

    /// Che cosa dire a chi legge.
    ///
    /// # Perché zero risultati e zero pagine sono due frasi diverse
    ///
    /// «Non ho trovato nulla» e «non ho potuto guardare» si somigliano solo in
    /// una schermata mal scritta. Con zero pagine lette non si afferma niente
    /// sul contenuto: si afferma qualcosa **sulla ricerca**.
    #[must_use]
    pub fn sentence(&self) -> String {
        let dove = self.scope.label();

        if self.reading.pages == 0 {
            return format!(
                "Non è stata letta nessuna pagina in «{dove}». Di quell'ambito \
                 questa ricerca non dice nulla: né che ci siano riscontri, né \
                 che non ce ne siano."
            );
        }

        let quante = self.reading.pages;
        let quanti = self.reading.results;

        if self.troncato() {
            let perche = match self.stopped {
                StopReason::OurPageCap => {
                    "ci si è fermati al numero di pagine che questo programma legge"
                }
                StopReason::ResultsCap => "è stato raggiunto il numero di risultati previsto",
                StopReason::ConsecutiveErrors => "le richieste hanno smesso di funzionare",
                StopReason::SurfaceDoesNotPaginate => {
                    "questa superficie non si sfoglia: Telegram restituisce una parte \
                     dei risultati, con un criterio che non dichiara"
                }
                StopReason::ServiceExhausted => "",
            };
            return format!(
                "In «{dove}» sono state lette {quante} pagine, con {quanti} \
                 risultati, e {perche}. Quello che c'era oltre non è stato \
                 guardato: di quella parte questa ricerca non dice nulla."
            );
        }

        format!(
            "In «{dove}» sono state lette {quante} pagine, con {quanti} risultati, \
             e Telegram ha dichiarato di non avere altro. Vale per l'ambito \
             cercato: altre superfici possono contenere cose che qui non \
             compaiono."
        )
    }
}

/// Decide se leggere un'altra pagina.
///
/// # Che cosa guarda, in quest'ordine
///
/// Prima la superficie — se non pagina, si smette comunque e lo si dice — poi gli
/// errori di fila, poi ciò che il servizio ha dichiarato, poi i due tetti.
///
/// L'ordine non è estetico: una superficie che non pagina **non è troncata dai
/// nostri tetti**, e attribuirle il nostro tetto direbbe una cosa falsa su di
/// essa.
#[must_use]
pub fn next_step(
    scope: SearchScope,
    budget: &DiscoveryBudget,
    reading: Reading,
    page: PageReceived,
) -> PagingStep {
    if !la_superficie_pagina(scope) {
        return PagingStep::Stop(StopReason::SurfaceDoesNotPaginate);
    }

    if reading.consecutive_errors >= budget.our_consecutive_errors {
        return PagingStep::Stop(StopReason::ConsecutiveErrors);
    }

    if let PageReceived::Results {
        more_available: false,
        ..
    } = page
    {
        return PagingStep::Stop(StopReason::ServiceExhausted);
    }

    if reading.results >= budget.results_per_query {
        return PagingStep::Stop(StopReason::ResultsCap);
    }

    if reading.pages >= budget.our_page_cap {
        return PagingStep::Stop(StopReason::OurPageCap);
    }

    PagingStep::ReadAnother
}

#[cfg(test)]
mod tests {
    use super::{
        PageReceived, PagingStep, Reading, ReadingReport, StopReason, la_superficie_pagina,
        next_step,
    };
    use crate::model::discovery::SearchScope;
    use crate::model::discovery_plan::DiscoveryBudget;

    fn budget() -> DiscoveryBudget {
        DiscoveryBudget {
            distinct_queries: 5,
            results_per_query: 20,
            our_page_cap: 3,
            our_wait_seconds: 30,
            our_consecutive_errors: 3,
            declared_backoff_seconds: 0,
        }
    }

    fn pagina(count: u32, more_available: bool) -> PageReceived {
        PageReceived::Results {
            count,
            more_available,
        }
    }

    /// **Una superficie che non pagina non si dichiara completa.**
    ///
    /// Un elenco parziale che si presenta come completo e' la bugia piu' facile
    /// da scrivere: non richiede di dire niente di falso, basta tacere.
    #[test]
    fn una_superficie_che_non_pagina_si_dichiara_parziale() {
        assert!(!la_superficie_pagina(SearchScope::DiscoveredPublicChats));

        let passo = next_step(
            SearchScope::DiscoveredPublicChats,
            &budget(),
            Reading::default(),
            pagina(50, true),
        );
        assert_eq!(
            passo,
            PagingStep::Stop(StopReason::SurfaceDoesNotPaginate),
            "per una superficie senza paginazione non si chiede un'altra pagina"
        );
        assert!(
            !StopReason::SurfaceDoesNotPaginate.si_e_visto_tutto_l_ambito(),
            "di una superficie che non pagina non si puo' dire di aver visto tutto"
        );
    }

    /// **Solo «il servizio non aveva altro» permette di dire di aver visto tutto.**
    #[test]
    fn solo_il_servizio_esaurito_permette_di_dire_di_aver_visto_tutto() {
        assert!(StopReason::ServiceExhausted.si_e_visto_tutto_l_ambito());

        for motivo in [
            StopReason::OurPageCap,
            StopReason::ResultsCap,
            StopReason::ConsecutiveErrors,
            StopReason::SurfaceDoesNotPaginate,
        ] {
            assert!(
                !motivo.si_e_visto_tutto_l_ambito(),
                "«{}» non permette di dire di aver visto tutto",
                motivo.as_str()
            );
        }
    }

    /// **Una pagina arrivata azzera il conto degli errori.**
    ///
    /// Un contatore che non si azzerasse fermerebbe una ricerca per errori
    /// sparsi nell'arco di un'ora, cioe' per una rete che funziona male ma
    /// funziona.
    #[test]
    fn una_pagina_arrivata_azzera_gli_errori_di_fila() {
        let lettura = Reading::default()
            .con(PageReceived::Failed)
            .con(PageReceived::Failed);
        assert_eq!(lettura.consecutive_errors, 2);

        let lettura = lettura.con(pagina(3, true));
        assert_eq!(
            lettura.consecutive_errors, 0,
            "una pagina arrivata distingue un servizio che non risponde da uno \
             che risponde a fatica"
        );
        assert_eq!(lettura.pages, 1);
        assert_eq!(lettura.results, 3);
    }

    /// **Troppi errori di fila fermano la lettura.**
    #[test]
    fn troppi_errori_di_fila_fermano_la_lettura() {
        let mut lettura = Reading::default();
        for _ in 0..3 {
            lettura = lettura.con(PageReceived::Failed);
        }

        assert_eq!(
            next_step(
                SearchScope::PublicChannelPosts,
                &budget(),
                lettura,
                PageReceived::Failed
            ),
            PagingStep::Stop(StopReason::ConsecutiveErrors)
        );
    }

    /// **I due tetti si distinguono, e nessuno dei due dice «finito».**
    #[test]
    fn i_due_tetti_fermano_la_lettura_e_si_distinguono() {
        // Il tetto dei risultati, che viene dalla politica validata.
        let lettura = Reading {
            pages: 1,
            results: 20,
            consecutive_errors: 0,
        };
        assert_eq!(
            next_step(
                SearchScope::PublicChannelPosts,
                &budget(),
                lettura,
                pagina(20, true)
            ),
            PagingStep::Stop(StopReason::ResultsCap)
        );

        // Il tetto delle pagine, che e' nostro.
        let lettura = Reading {
            pages: 3,
            results: 3,
            consecutive_errors: 0,
        };
        assert_eq!(
            next_step(
                SearchScope::PublicChannelPosts,
                &budget(),
                lettura,
                pagina(1, true)
            ),
            PagingStep::Stop(StopReason::OurPageCap)
        );
    }

    /// **Si continua finche' il servizio dice che c'e' altro e i tetti reggono.**
    #[test]
    fn si_continua_finche_c_e_altro_e_i_tetti_reggono() {
        let lettura = Reading {
            pages: 1,
            results: 5,
            consecutive_errors: 0,
        };
        assert_eq!(
            next_step(
                SearchScope::PublicChannelPosts,
                &budget(),
                lettura,
                pagina(5, true)
            ),
            PagingStep::ReadAnother
        );
    }

    /// **Zero pagine lette non dice niente sul contenuto.**
    ///
    /// «Non ho trovato nulla» e «non ho potuto guardare» si somigliano solo in
    /// una schermata mal scritta.
    #[test]
    fn zero_pagine_lette_non_affermano_niente_sul_contenuto() {
        let resoconto = ReadingReport {
            scope: SearchScope::PublicChannelPosts,
            reading: Reading::default(),
            stopped: StopReason::ConsecutiveErrors,
        };

        let frase = resoconto.sentence();
        assert!(
            frase.contains("non dice nulla"),
            "senza pagine lette non si afferma niente sul contenuto: «{frase}»"
        );
        assert!(
            frase.contains("né che non ce ne siano"),
            "la frase deve escludere la lettura «non c'e' niente»: «{frase}»"
        );
    }

    /// **Una lettura troncata lo dice, e una completa dice fin dove vale.**
    #[test]
    fn una_lettura_troncata_lo_dice_e_una_completa_dice_fin_dove_vale() {
        let troncata = ReadingReport {
            scope: SearchScope::PublicChannelPosts,
            reading: Reading {
                pages: 3,
                results: 30,
                consecutive_errors: 0,
            },
            stopped: StopReason::OurPageCap,
        };
        assert!(troncata.troncato());
        let frase = troncata.sentence();
        assert!(
            frase.contains("non è stato guardato"),
            "una lettura troncata deve dirlo: «{frase}»"
        );

        let completa = ReadingReport {
            scope: SearchScope::PublicChannelPosts,
            reading: Reading {
                pages: 2,
                results: 7,
                consecutive_errors: 0,
            },
            stopped: StopReason::ServiceExhausted,
        };
        assert!(!completa.troncato());
        let frase = completa.sentence();
        assert!(
            frase.contains("Vale per l'ambito cercato"),
            "anche una lettura completa vale solo per il suo ambito: «{frase}»"
        );
        assert!(
            frase.contains("altre superfici"),
            "le tre superfici sono disgiunte, e nessuna somma «tutto»: «{frase}»"
        );
    }

    /// **Il motore non parla con nessuno e non guarda l'orologio.**
    #[test]
    fn il_motore_non_esce_in_rete() {
        const QUESTO_MODULO: &str = include_str!("discovery_paging.rs");

        let Some((produzione, _)) = QUESTO_MODULO.split_once("\n#[cfg(test)]\nmod tests {") else {
            panic!("il blocco delle prove non si delimita");
        };
        let codice: String = produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<&str>>()
            .join("\n");

        for vietato in ["https::", "fetch(", "Timestamp::now", "SystemTime", "sleep"] {
            assert!(
                !codice.contains(vietato),
                "«{vietato}» nel motore di paginazione: decide se continuare, non \
                 chiede e non attende (ADR-0077)"
            );
        }
    }
}

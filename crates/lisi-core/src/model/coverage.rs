//! Che cosa stavamo guardando (PR-05, ADR-0121).
//!
//! # Tre stati, e nessun quarto
//!
//! [`CoverageState::Covered`] — si guardava; [`CoverageState::NotCovered`] — si
//! sa che non si guardava; [`CoverageState::Undetermined`] — i fatti non bastano
//! a decidere. **«Non determinabile» è un risultato**, come «origine non
//! registrata» in PR-03: dire «non lo so» si può, inventare no.
//!
//! # Perché gli intervalli sono privati
//!
//! [`Coverage`] garantisce per costruzione che i tratti siano **in ordine,
//! contigui e non vuoti**: una copertura con un buco fra due tratti direbbe
//! qualcosa — o niente — di un periodo che nessuno ha classificato.

use crate::time::Timestamp;

/// Perché un tratto non era coperto: si sa che non si guardava.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotCoveredReason {
    /// La fonte non era ancora configurata nel prodotto.
    NotYetConfigured,
    /// Nessun monitoraggio seguiva la fonte.
    NoMonitoring,
    /// L'acquisizione era in pausa per decisione dell'operatore (PAUSE-01,
    /// ADR-0172).
    Paused,
}

/// Perché un tratto non è determinabile: i fatti non bastano a decidere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UndeterminedReason {
    /// Dall'avvio al primo fatto, quando il primo fatto è un ritorno in linea;
    /// oppure un monitoraggio senza alcun fatto.
    NoFactYet,
    /// Il collegamento è tornato: subito prima non c'era, e da quando non si sa.
    ConnectionRestored,
    /// Il programma si è fermato — chiuso o caduto — e non si sa quando.
    ProgramStopped,
    /// Il collegamento si era perso.
    ConnectionLost,
    /// Il connettore si era fermato per un errore.
    ConnectorFailed,
    /// Dopo l'ultimo fatto registrato non si sa se il collegamento sia rimasto.
    AfterLastFact,
    /// Una verifica ha trovato la fonte non accessibile.
    SourceNotAccessible,
}

/// Lo stato di un tratto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoverageState {
    /// Si guardava: ciò che è stato pubblicato è arrivato.
    Covered,
    /// Si sa che non si guardava.
    NotCovered(NotCoveredReason),
    /// I fatti non bastano a decidere.
    Undetermined(UndeterminedReason),
}

impl CoverageState {
    /// La parola che l'operatore legge.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Covered => "coperto",
            Self::NotCovered(_) => "non coperto",
            Self::Undetermined(_) => "non determinabile",
        }
    }

    /// Perché, in una frase: vuota per un tratto coperto.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Covered => "",
            Self::NotCovered(NotCoveredReason::NotYetConfigured) => {
                "la fonte non era ancora configurata"
            }
            Self::NotCovered(NotCoveredReason::NoMonitoring) => "nessun monitoraggio la seguiva",
            Self::NotCovered(NotCoveredReason::Paused) => {
                "l'acquisizione era in pausa per decisione dell'operatore"
            }
            Self::Undetermined(UndeterminedReason::NoFactYet) => {
                "nessun fatto registrato dice che il collegamento ci fosse"
            }
            Self::Undetermined(UndeterminedReason::ConnectionRestored) => {
                "il collegamento è tornato dopo una pausa, e da quando mancava non si sa"
            }
            Self::Undetermined(UndeterminedReason::ProgramStopped) => {
                "il programma si è fermato, chiuso o caduto, e non si sa quando"
            }
            Self::Undetermined(UndeterminedReason::ConnectionLost) => {
                "il collegamento si era perso: Telegram può consegnare dopo, ma non è garantito"
            }
            Self::Undetermined(UndeterminedReason::ConnectorFailed) => {
                "il collegamento a Telegram si era fermato per un errore"
            }
            Self::Undetermined(UndeterminedReason::AfterLastFact) => {
                "dopo l'ultimo fatto registrato non si sa se il collegamento sia rimasto"
            }
            Self::Undetermined(UndeterminedReason::SourceNotAccessible) => {
                "una verifica ha trovato la fonte non accessibile"
            }
        }
    }

    /// Il nome stabile dello stato e della sua ragione, per il protocollo
    /// dell'Hub (HUB-COVERAGE-01, ADR-0199, decisione 3). Non cambia con le
    /// parole dello schermo.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Covered => "coperto",
            Self::NotCovered(NotCoveredReason::NotYetConfigured) => "non_coperto.non_configurata",
            Self::NotCovered(NotCoveredReason::NoMonitoring) => "non_coperto.nessun_monitoraggio",
            Self::NotCovered(NotCoveredReason::Paused) => "non_coperto.in_pausa",
            Self::Undetermined(UndeterminedReason::NoFactYet) => "non_determinabile.nessun_fatto",
            Self::Undetermined(UndeterminedReason::ConnectionRestored) => {
                "non_determinabile.collegamento_tornato"
            }
            Self::Undetermined(UndeterminedReason::ProgramStopped) => {
                "non_determinabile.programma_fermo"
            }
            Self::Undetermined(UndeterminedReason::ConnectionLost) => {
                "non_determinabile.collegamento_perso"
            }
            Self::Undetermined(UndeterminedReason::ConnectorFailed) => {
                "non_determinabile.connettore_guasto"
            }
            Self::Undetermined(UndeterminedReason::AfterLastFact) => {
                "non_determinabile.dopo_ultimo_fatto"
            }
            Self::Undetermined(UndeterminedReason::SourceNotAccessible) => {
                "non_determinabile.fonte_non_accessibile"
            }
        }
    }

    /// Tutti gli stati, con le loro ragioni.
    pub const ALL: [Self; 11] = [
        Self::Covered,
        Self::NotCovered(NotCoveredReason::NotYetConfigured),
        Self::NotCovered(NotCoveredReason::NoMonitoring),
        Self::NotCovered(NotCoveredReason::Paused),
        Self::Undetermined(UndeterminedReason::NoFactYet),
        Self::Undetermined(UndeterminedReason::ConnectionRestored),
        Self::Undetermined(UndeterminedReason::ProgramStopped),
        Self::Undetermined(UndeterminedReason::ConnectionLost),
        Self::Undetermined(UndeterminedReason::ConnectorFailed),
        Self::Undetermined(UndeterminedReason::AfterLastFact),
        Self::Undetermined(UndeterminedReason::SourceNotAccessible),
    ];

    /// Riconosce uno stato dal suo nome stabile. Un nome sconosciuto non è
    /// uno stato: non diventa «coperto».
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|stato| stato.token() == token)
    }

    /// Chi lo dice (PR-03): la copertura è **calcolata** da fatti registrati.
    #[must_use]
    pub const fn origin() -> crate::model::origin::Origin {
        crate::model::origin::Origin::Computed
    }
}

/// Un tratto: da un istante a un altro, con il suo stato.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageInterval {
    /// Da quando, compreso.
    pub from: Timestamp,
    /// Fino a quando, escluso.
    pub to: Timestamp,
    /// Lo stato.
    pub state: CoverageState,
}

/// La copertura di una fonte o di un monitoraggio su una finestra di tempo.
///
/// # Che cosa il tipo garantisce
///
/// I tratti sono **in ordine, contigui e non vuoti**, e due tratti vicini con
/// lo stesso stato sono uniti. Si costruisce soltanto con [`Coverage::build`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    intervals: Vec<CoverageInterval>,
}

impl Coverage {
    /// Costruisce la copertura dai tratti, **rifiutando** una sequenza con
    /// buchi, sovrapposizioni o tratti rovesciati.
    ///
    /// I tratti vuoti si tolgono; i vicini con lo stesso stato si uniscono.
    #[must_use]
    pub fn build(tratti: Vec<CoverageInterval>) -> Option<Self> {
        let mut intervals: Vec<CoverageInterval> = Vec::with_capacity(tratti.len());
        for tratto in tratti {
            if tratto.to < tratto.from {
                return None;
            }
            if tratto.to == tratto.from {
                continue;
            }
            match intervals.last_mut() {
                Some(ultimo) if ultimo.to != tratto.from => return None,
                Some(ultimo) if ultimo.state == tratto.state => ultimo.to = tratto.to,
                _ => intervals.push(tratto),
            }
        }
        Some(Self { intervals })
    }

    /// Una copertura senza tratti: una finestra vuota.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            intervals: Vec::new(),
        }
    }

    /// Un tratto solo; vuota se il tratto è vuoto o rovesciato.
    #[must_use]
    pub fn single(from: Timestamp, to: Timestamp, state: CoverageState) -> Self {
        if to <= from {
            return Self::empty();
        }
        Self {
            intervals: vec![CoverageInterval { from, to, state }],
        }
    }

    /// I tratti, in ordine.
    #[must_use]
    pub fn intervals(&self) -> &[CoverageInterval] {
        &self.intervals
    }

    /// I tratti che non sono coperti: quelli che vanno detti.
    pub fn gaps(&self) -> impl Iterator<Item = &CoverageInterval> {
        self.intervals
            .iter()
            .filter(|tratto| tratto.state != CoverageState::Covered)
    }

    /// Da dove comincia, se ha almeno un tratto.
    #[must_use]
    pub fn start(&self) -> Option<Timestamp> {
        self.intervals.first().map(|tratto| tratto.from)
    }

    /// Dove finisce, se ha almeno un tratto.
    #[must_use]
    pub fn end(&self) -> Option<Timestamp> {
        self.intervals.last().map(|tratto| tratto.to)
    }

    /// Quanti millisecondi di ciascuno stato: coperti, non coperti, non
    /// determinabili.
    #[must_use]
    pub fn totals(&self) -> (i64, i64, i64) {
        let mut totali = (0, 0, 0);
        for tratto in &self.intervals {
            let durata = tratto.to.as_millis() - tratto.from.as_millis();
            match tratto.state {
                CoverageState::Covered => totali.0 += durata,
                CoverageState::NotCovered(_) => totali.1 += durata,
                CoverageState::Undetermined(_) => totali.2 += durata,
            }
        }
        totali
    }
}

/// La frase che fissa il senso della copertura, nei documenti e sullo schermo.
pub const COVERAGE_MEANING: &str = "Un tratto non coperto o non determinabile non è un periodo \
                                    senza messaggi. È un periodo in cui NEXUM non stava \
                                    guardando, o non sa dire se guardasse.";

#[cfg(test)]
mod tests {
    use super::{
        COVERAGE_MEANING, Coverage, CoverageInterval, CoverageState, NotCoveredReason,
        UndeterminedReason,
    };
    use crate::time::Timestamp;

    #[test]
    fn ogni_stato_ha_un_nome_stabile_che_si_rilegge() {
        let mut visti = std::collections::BTreeSet::new();
        for stato in CoverageState::ALL {
            assert!(
                visti.insert(stato.token()),
                "nome ripetuto: {}",
                stato.token()
            );
            assert_eq!(CoverageState::from_token(stato.token()), Some(stato));
        }
        assert_eq!(CoverageState::from_token("coperto_forse"), None);
    }

    fn tratto(da: i64, a: i64, stato: CoverageState) -> CoverageInterval {
        CoverageInterval {
            from: Timestamp::from_millis(da),
            to: Timestamp::from_millis(a),
            state: stato,
        }
    }

    const NON_SI_SA: CoverageState = CoverageState::Undetermined(UndeterminedReason::NoFactYet);

    #[test]
    fn i_tratti_vicini_con_lo_stesso_stato_si_uniscono_e_i_vuoti_spariscono() {
        let Some(copertura) = Coverage::build(vec![
            tratto(0, 10, CoverageState::Covered),
            tratto(10, 10, NON_SI_SA),
            tratto(10, 20, CoverageState::Covered),
            tratto(20, 30, NON_SI_SA),
        ]) else {
            panic!("tratti contigui devono costruire una copertura");
        };
        assert_eq!(copertura.intervals().len(), 2);
        assert_eq!(copertura.totals(), (20, 0, 10));
        assert_eq!(copertura.gaps().count(), 1);
    }

    /// **Un buco o una sovrapposizione non costruiscono una copertura**: un
    /// periodo che nessuno ha classificato non si mostra come se lo fosse.
    #[test]
    fn un_buco_o_una_sovrapposizione_si_rifiutano() {
        assert!(
            Coverage::build(vec![
                tratto(0, 10, CoverageState::Covered),
                tratto(12, 20, NON_SI_SA),
            ])
            .is_none()
        );
        assert!(
            Coverage::build(vec![
                tratto(0, 10, CoverageState::Covered),
                tratto(8, 20, NON_SI_SA),
            ])
            .is_none()
        );
        assert!(Coverage::build(vec![tratto(10, 0, CoverageState::Covered)]).is_none());
        assert!(
            Coverage::single(
                Timestamp::from_millis(5),
                Timestamp::from_millis(5),
                CoverageState::Covered
            )
            .intervals()
            .is_empty()
        );
    }

    /// **Ogni tratto non coperto dice perché**, e un tratto coperto no.
    #[test]
    fn ogni_tratto_non_coperto_dice_perche() {
        assert_eq!(CoverageState::Covered.reason(), "");
        let stati = [
            CoverageState::NotCovered(NotCoveredReason::NotYetConfigured),
            CoverageState::NotCovered(NotCoveredReason::NoMonitoring),
            CoverageState::Undetermined(UndeterminedReason::NoFactYet),
            CoverageState::Undetermined(UndeterminedReason::ConnectionRestored),
            CoverageState::Undetermined(UndeterminedReason::ProgramStopped),
            CoverageState::Undetermined(UndeterminedReason::ConnectionLost),
            CoverageState::Undetermined(UndeterminedReason::ConnectorFailed),
            CoverageState::Undetermined(UndeterminedReason::AfterLastFact),
            CoverageState::Undetermined(UndeterminedReason::SourceNotAccessible),
        ];
        for stato in stati {
            assert!(!stato.reason().is_empty(), "{stato:?}");
            assert_ne!(stato.label(), "coperto");
        }
    }

    #[test]
    fn la_frase_del_senso_dice_che_un_vuoto_non_e_un_silenzio() {
        assert!(COVERAGE_MEANING.contains("non è un periodo senza messaggi"));
        assert_eq!(
            CoverageState::origin(),
            crate::model::origin::Origin::Computed
        );
    }
}

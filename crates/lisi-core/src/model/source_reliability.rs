//! L'affidabilità di una fonte, come l'ufficio la valuta **a mano**
//! (SOURCE-RELIABILITY-01, ADR-0167; ADR-0035, decisione 9).
//!
//! # Un giudizio di una persona
//!
//! È ciò che l'ufficio ha riscontrato su una fonte, detto da chi lo dice, con
//! il motivo e l'istante. **Il programma non lo calcola**: non c'è una
//! funzione che lo ricavi dal numero di iscritti, dall'orientamento, dai
//! contenuti o dagli avvisi. Il numero di iscritti non è una misura di verità.
//!
//! # Separato dal contenuto
//!
//! Un giudizio sulla fonte non rende vero o falso un contenuto: ogni contenuto
//! si valuta comunque, e le frasi di ciascun livello lo dicono.

use crate::SourceId;
use crate::model::reason::OperationalReason;
use crate::text::Actor;
use crate::time::Timestamp;

/// Che cosa l'ufficio dice di una fonte. **Parole, non numeri.**
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReliabilityLevel {
    /// Affidabile per l'esperienza dell'ufficio.
    Reliable,
    /// Da verificare caso per caso.
    CaseByCase,
    /// Poco affidabile per l'esperienza dell'ufficio.
    Unreliable,
}

impl ReliabilityLevel {
    /// Etichetta stabile, quella che finisce nell'archivio.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reliable => "affidabile",
            Self::CaseByCase => "da_verificare",
            Self::Unreliable => "poco_affidabile",
        }
    }

    /// Come si nomina a chi legge.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Reliable => "AFFIDABILE PER L'ESPERIENZA DELL'UFFICIO",
            Self::CaseByCase => "DA VERIFICARE CASO PER CASO",
            Self::Unreliable => "POCO AFFIDABILE PER L'ESPERIENZA DELL'UFFICIO",
        }
    }

    /// Che cosa il livello significa, e che cosa **non** significa.
    #[must_use]
    pub const fn as_sentence(self) -> &'static str {
        match self {
            Self::Reliable => {
                "\u{c8} ci\u{f2} che l'ufficio ha riscontrato finora. Non rende vero un \
                 contenuto: ogni contenuto si valuta comunque."
            }
            Self::CaseByCase => {
                "L'ufficio non ha un'esperienza che basti. Ogni contenuto si verifica da s\u{e9}."
            }
            Self::Unreliable => {
                "\u{c8} ci\u{f2} che l'ufficio ha riscontrato finora. Non rende falso un \
                 contenuto: ogni contenuto si valuta comunque."
            }
        }
    }

    /// Tutti i livelli, nell'ordine in cui si mostrano.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Reliable, Self::CaseByCase, Self::Unreliable]
    }
}

/// Che cosa un operatore ha fatto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReliabilityAct {
    /// Ha dato una valutazione.
    Assess(ReliabilityLevel),
    /// L'ha ritirata: la fonte torna **NON VALUTATA**.
    Withdraw,
}

impl ReliabilityAct {
    /// Etichetta stabile.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Assess(livello) => livello.as_str(),
            Self::Withdraw => "ritirata",
        }
    }

    /// Come si nomina a chi legge.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Assess(livello) => livello.as_label(),
            Self::Withdraw => "NON VALUTATA",
        }
    }
}

impl core::str::FromStr for ReliabilityAct {
    type Err = crate::error::DomainError;

    /// # Errori
    ///
    /// Rifiuta ogni testo che non sia uno dei quattro atti.
    fn from_str(raw: &str) -> crate::error::DomainResult<Self> {
        match raw {
            "affidabile" => Ok(Self::Assess(ReliabilityLevel::Reliable)),
            "da_verificare" => Ok(Self::Assess(ReliabilityLevel::CaseByCase)),
            "poco_affidabile" => Ok(Self::Assess(ReliabilityLevel::Unreliable)),
            "ritirata" => Ok(Self::Withdraw),
            altro => Err(crate::error::unknown_variant(
                "valutazione dell'affidabilit\u{e0}",
                altro,
            )),
        }
    }
}

/// Un atto sull'affidabilità di una fonte: chi, quando, perché.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewReliability {
    /// Quale fonte.
    pub source: SourceId,
    /// Che cosa si è fatto.
    pub act: ReliabilityAct,
    /// Perché, **anche per ritirare**.
    pub reason: OperationalReason,
    /// Chi.
    pub by: Actor,
    /// Quando.
    pub at: Timestamp,
}

/// La valutazione in vigore, se c'è: l'atto più recente, se è una
/// valutazione. Dopo un ritiro la fonte è non valutata.
#[must_use]
pub fn current_reliability(atti: &[NewReliability]) -> Option<&NewReliability> {
    atti.iter()
        .max_by_key(|atto| atto.at)
        .filter(|atto| matches!(atto.act, ReliabilityAct::Assess(_)))
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::{NewReliability, ReliabilityAct, ReliabilityLevel, current_reliability};
    use crate::SourceId;
    use crate::model::reason::OperationalReason;
    use crate::text::Actor;
    use crate::time::Timestamp;

    const THIS_MODULE: &str = include_str!("source_reliability.rs");

    fn atto(act: ReliabilityAct, quando: i64) -> NewReliability {
        let (Ok(reason), Ok(by)) = (
            OperationalReason::try_new("riscontri dell'ufficio sugli ultimi tre mesi"),
            Actor::try_new("operatore.prova"),
        ) else {
            panic!("valori di prova validi");
        };
        NewReliability {
            source: SourceId::new(1),
            act,
            reason,
            by,
            at: Timestamp::from_millis(quando),
        }
    }

    /// **Ogni atto si conserva e si rilegge con la stessa parola, e un testo
    /// sconosciuto non è un atto** (SOURCE-RELIABILITY-01, criterio 1).
    #[test]
    fn ogni_atto_si_rilegge_con_la_stessa_parola() {
        for livello in ReliabilityLevel::all() {
            let act = ReliabilityAct::Assess(*livello);
            assert_eq!(ReliabilityAct::from_str(act.as_str()).ok(), Some(act));
            assert!(
                livello.as_sentence().contains("contenuto"),
                "ogni livello dice che cosa non dice dei contenuti"
            );
        }
        assert_eq!(
            ReliabilityAct::from_str("ritirata").ok(),
            Some(ReliabilityAct::Withdraw)
        );
        assert!(ReliabilityAct::from_str("90%").is_err());
        assert!(ReliabilityAct::from_str("non_valutata").is_err());
    }

    /// **Vale l'atto più recente, e dopo un ritiro la fonte è non valutata**
    /// (criterio 2).
    #[test]
    fn vale_l_atto_piu_recente_e_il_ritiro_toglie() {
        assert!(current_reliability(&[]).is_none());
        let atti = vec![
            atto(ReliabilityAct::Assess(ReliabilityLevel::Reliable), 10),
            atto(ReliabilityAct::Assess(ReliabilityLevel::Unreliable), 30),
            atto(ReliabilityAct::Assess(ReliabilityLevel::CaseByCase), 20),
        ];
        assert_eq!(
            current_reliability(&atti).map(|atto| atto.act),
            Some(ReliabilityAct::Assess(ReliabilityLevel::Unreliable))
        );
        let mut ritirata = atti;
        ritirata.push(atto(ReliabilityAct::Withdraw, 40));
        assert!(current_reliability(&ritirata).is_none());
    }

    /// **Il modulo non ricava un giudizio da un dato**: nessun numero di
    /// iscritti, nessun contenuto, nessun avviso (criterio 3).
    #[test]
    fn il_modulo_non_ricava_un_giudizio_da_un_dato() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        for dato in [
            "member",
            "subscriber",
            "Content",
            "Alert",
            "level: u8",
            "score",
            "f64",
        ] {
            assert!(
                !produzione.contains(dato),
                "il modulo nomina «{dato}»: l'affidabilità non si ricava"
            );
        }
    }
}

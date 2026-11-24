//! Il monitoraggio in background, mentre l'utente di Windows è uscito
//! (SERVICE-01, ADR-0203).
//!
//! # Due custodi, uno alla volta
//!
//! L'acquisizione la tiene **la finestra** quando la persona è collegata a
//! Windows, e **il servizio** quando è uscita. Mai entrambi: decide il file
//! dell'istanza (`lisi_services::instance`), che Windows dà a un processo solo.
//!
//! # Il passaggio non è un'interruzione, se è breve e fra custodi diversi
//!
//! Chi tiene l'acquisizione scrive a intervalli un segno di vita. Chi la
//! prende dopo legge l'ultimo: se l'ha scritto **l'altro** custode, e da non
//! più di [`HANDOVER_TOLERANCE_MS`], è un passaggio di mano, e si registra con
//! i due istanti. Altrimenti è un'interruzione, come prima (ADR-0064). Lo
//! stesso custode che riparte non passa la mano a sé stesso: un riavvio della
//! finestra resta un'interruzione.

use crate::time::Timestamp;

/// Il nome del servizio di Windows.
pub const SERVICE_NAME: &str = "Nexum97Background";

/// L'argomento con cui Windows avvia il programma come servizio.
pub const SERVICE_ARGUMENT: &str = "--servizio";

/// Ogni quanto il custode scrive il segno di vita.
pub const HEARTBEAT_INTERVAL_MS: i64 = 10_000;

/// Il tempo più lungo fra l'ultimo segno di vita di un custode e la presa
/// dell'altro perché sia un passaggio di mano e non un'interruzione.
pub const HANDOVER_TOLERANCE_MS: i64 = 120_000;

/// Chi tiene l'acquisizione.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keeper {
    /// Il programma con la sua finestra, con la persona collegata.
    Window,
    /// Il servizio di Windows, con la persona uscita.
    Service,
}

impl Keeper {
    /// Il nome stabile, nell'archivio.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Window => "finestra",
            Self::Service => "servizio",
        }
    }

    /// Dal nome stabile.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "finestra" => Some(Self::Window),
            "servizio" => Some(Self::Service),
            _ => None,
        }
    }
}

/// L'ultimo segno di vita letto all'avvio di un custode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastSign {
    /// Chi l'ha scritto.
    pub keeper: Keeper,
    /// Quando.
    pub at: Timestamp,
    /// Gli account che la persona aveva collegato, da riprendere.
    pub linked_accounts: Vec<i64>,
}

/// Se chi prende l'acquisizione adesso continua quella dell'altro custode.
#[must_use]
pub fn continues(last: &LastSign, taker: Keeper, now: Timestamp) -> bool {
    let trascorso = now.as_millis() - last.at.as_millis();
    last.keeper != taker && (0..=HANDOVER_TOLERANCE_MS).contains(&trascorso)
}

/// Gli account da riprendere, scritti nell'archivio: identificativi separati
/// da virgole.
#[must_use]
pub fn accounts_to_text(accounts: &[i64]) -> String {
    accounts
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Gli account da riprendere, letti dall'archivio. Ciò che non è un numero si
/// scarta.
#[must_use]
pub fn accounts_from_text(text: &str) -> Vec<i64> {
    text.split(',')
        .filter_map(|pezzo| pezzo.trim().parse().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segno(keeper: Keeper, at: i64) -> LastSign {
        LastSign {
            keeper,
            at: Timestamp::from_millis(at),
            linked_accounts: vec![3],
        }
    }

    /// **Il servizio continua la finestra, se arriva in tempo.**
    #[test]
    fn il_passaggio_fra_custodi_diversi_in_tempo_continua() {
        let ultimo = segno(Keeper::Window, 1_000_000);
        assert!(continues(
            &ultimo,
            Keeper::Service,
            Timestamp::from_millis(1_000_000 + HANDOVER_TOLERANCE_MS)
        ));
    }

    /// **Oltre la tolleranza è un'interruzione.**
    #[test]
    fn oltre_la_tolleranza_non_continua() {
        let ultimo = segno(Keeper::Window, 1_000_000);
        assert!(!continues(
            &ultimo,
            Keeper::Service,
            Timestamp::from_millis(1_000_001 + HANDOVER_TOLERANCE_MS)
        ));
    }

    /// **Lo stesso custode non passa la mano a sé stesso**, e un segno di vita
    /// nel futuro non vale.
    #[test]
    fn lo_stesso_custode_e_il_tempo_all_indietro_non_continuano() {
        let ultimo = segno(Keeper::Window, 1_000_000);
        assert!(!continues(
            &ultimo,
            Keeper::Window,
            Timestamp::from_millis(1_000_500)
        ));
        assert!(!continues(
            &ultimo,
            Keeper::Service,
            Timestamp::from_millis(999_000)
        ));
    }

    /// **Gli account si scrivono e si rileggono uguali.**
    #[test]
    fn gli_account_vanno_e_tornano() {
        assert_eq!(accounts_from_text(&accounts_to_text(&[3, 41])), vec![3, 41]);
        assert!(accounts_from_text("").is_empty());
        assert_eq!(
            Keeper::parse(Keeper::Service.as_str()),
            Some(Keeper::Service)
        );
    }
}

//! L'account d'ufficio di un monitoraggio (MULTI-ACCOUNT-02, ADR-0173,
//! DEC-439).
//!
//! # Che cosa decide questo modulo
//!
//! - **Quanti account** possono essere attivi insieme: tre al più
//!   ([`MAX_ACTIVE_ACCOUNTS`]).
//! - **A quale monitoraggio** va un aggiornamento arrivato a un account
//!   ([`attributes_to`]): a quello legato a quell'account, mai a un altro,
//!   anche quando la chat è la stessa.
//! - **Se un monitoraggio è pronto a partire** all'ora programmata
//!   ([`OpenAccounts::is_ready_for`]): se lo è il **suo** account.
//!
//! # Il monitoraggio senza account
//!
//! I monitoraggi nati prima della migrazione 0072, e quelli dimostrativi, non
//! hanno un account registrato. Non si indovina quale fosse: un tale
//! monitoraggio riceve aggiornamenti soltanto quando è aperto **un solo**
//! account, cioè nella situazione in cui è nato. Con due account aperti non
//! riceve niente, perché attribuirgli l'aggiornamento di uno dei due sarebbe
//! scegliere a caso.
//!
//! # Che cosa non fa
//!
//! Non sceglie mai un account al posto di un altro: nessuna funzione di questo
//! modulo riceve un limite, un errore o uno stato di collegamento per decidere
//! **quale** account usare (ADR-0173, decisione 4).

use crate::id::SessionId;
use crate::model::telegram_account::AccountUuid;
use crate::text::DisplayName;
use crate::time::Timestamp;

/// Quanti account d'ufficio possono essere attivi insieme (ADR-0173,
/// decisione 2).
///
/// Un tetto dichiarato, non un limite di TDLib: ogni account in più è un
/// collegamento, una cartella e una chiave in più da sorvegliare.
pub const MAX_ACTIVE_ACCOUNTS: usize = 3;

/// L'account con cui un monitoraggio lavora, registrato quando nasce.
///
/// Il nome è quello che l'account aveva allora: un documento che nomina
/// l'account deve leggere lo stesso nome anche se più tardi l'ufficio lo
/// rinomina o lo rimuove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitoringAccount {
    /// Il monitoraggio.
    pub session_id: SessionId,
    /// L'identità stabile dell'account.
    pub account_uuid: AccountUuid,
    /// Il nome dell'account quando il monitoraggio è nato.
    pub account_label: DisplayName,
    /// Quando il legame è stato registrato.
    pub bound_at: Timestamp,
}

/// Un account con cui una fonte è stata seguita (MULTI-ACCOUNT-02 parte 2,
/// DEC-441).
///
/// Non è scritto sulla fonte: si ricava dai monitoraggi che la includono e
/// dall'account a cui ciascuno è legato. Una chat seguita da due account è
/// **una** fonte con **due** account, e una colonna sola sulla fonte non
/// saprebbe dirlo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceAccount {
    /// L'identità stabile dell'account.
    pub account_uuid: AccountUuid,
    /// Il nome dell'account nel monitoraggio più recente che lo lega alla
    /// fonte.
    pub account_label: DisplayName,
    /// L'ultima volta che un monitoraggio di questo account ha incluso la
    /// fonte.
    pub last_bound_at: Timestamp,
}

/// Se un aggiornamento arrivato all'account `origin` appartiene a un
/// monitoraggio legato a `bound`, mentre gli account aperti sono `open`.
///
/// Legato: soltanto se l'account è lo stesso. Senza account: soltanto se è
/// aperto un account solo (vedere la documentazione del modulo).
#[must_use]
pub fn attributes_to(bound: Option<&AccountUuid>, origin: &AccountUuid, open: usize) -> bool {
    match bound {
        Some(account) => account == origin,
        None => open == 1,
    }
}

/// Gli account aperti in questo giro, e quali sono collegati e pronti.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenAccounts {
    /// Quanti account hanno un runtime aperto.
    open: usize,
    /// Quelli fra loro collegati e pronti.
    ready: Vec<AccountUuid>,
}

impl OpenAccounts {
    /// Nessun account aperto.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            open: 0,
            ready: Vec::new(),
        }
    }

    /// Registra un account aperto, pronto o no.
    pub fn add(&mut self, account: AccountUuid, ready: bool) {
        self.open += 1;
        if ready {
            self.ready.push(account);
        }
    }

    /// Quanti account sono aperti.
    #[must_use]
    pub const fn open(&self) -> usize {
        self.open
    }

    /// Se il monitoraggio legato a `bound` ha il suo account collegato e
    /// pronto.
    ///
    /// Un monitoraggio senza account è pronto quando è aperto un account solo
    /// e quello è pronto: la stessa regola di [`attributes_to`].
    #[must_use]
    pub fn is_ready_for(&self, bound: Option<&AccountUuid>) -> bool {
        match bound {
            Some(account) => self.ready.contains(account),
            None => self.open == 1 && self.ready.len() == 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_ACTIVE_ACCOUNTS, OpenAccounts, attributes_to};
    use crate::model::telegram_account::AccountUuid;

    fn account(byte: u8) -> AccountUuid {
        AccountUuid::from_bytes([byte; 16])
    }

    /// **Un aggiornamento va soltanto al monitoraggio del suo account**
    /// (MULTI-ACCOUNT-02 parte 2, criterio 3; prova negativa: l'account del
    /// monitoraggio ignorato → rossa).
    #[test]
    fn un_aggiornamento_va_soltanto_al_suo_account() {
        let (primo, secondo) = (account(0xa1), account(0xb2));
        assert!(attributes_to(Some(&primo), &primo, 2));
        assert!(!attributes_to(Some(&primo), &secondo, 2));
        assert!(
            !attributes_to(Some(&primo), &secondo, 1),
            "anche con un solo account aperto, un altro account non è il suo"
        );
    }

    /// **Un monitoraggio senza account riceve soltanto con un account solo
    /// aperto** (criterio 4).
    #[test]
    fn senza_account_soltanto_con_un_account_aperto() {
        let primo = account(0xa1);
        assert!(attributes_to(None, &primo, 1));
        assert!(!attributes_to(None, &primo, 2));
        assert!(!attributes_to(None, &primo, MAX_ACTIVE_ACCOUNTS));
    }

    /// **All'ora programmata conta il suo account, non un altro** (criterio
    /// 5; prova negativa: «un account qualunque pronto» → rossa).
    #[test]
    fn all_ora_conta_il_suo_account() {
        let (primo, secondo) = (account(0xa1), account(0xb2));
        let mut aperti = OpenAccounts::none();
        aperti.add(primo.clone(), false);
        aperti.add(secondo.clone(), true);
        assert_eq!(aperti.open(), 2);
        assert!(
            !aperti.is_ready_for(Some(&primo)),
            "il suo account non è collegato"
        );
        assert!(aperti.is_ready_for(Some(&secondo)));
        assert!(
            !aperti.is_ready_for(None),
            "senza account, con due aperti, non si sceglie"
        );

        let mut uno = OpenAccounts::none();
        uno.add(primo.clone(), true);
        assert!(uno.is_ready_for(None));
        assert!(!OpenAccounts::none().is_ready_for(None));
        assert!(!OpenAccounts::none().is_ready_for(Some(&primo)));
    }

    /// **Il tetto è tre** (ADR-0173, decisione 2).
    #[test]
    fn il_tetto_e_tre() {
        assert_eq!(MAX_ACTIVE_ACCOUNTS, 3);
    }
}

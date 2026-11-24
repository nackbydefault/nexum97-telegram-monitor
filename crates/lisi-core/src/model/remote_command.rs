//! I comandi a distanza di un monitoraggio dell'Hub (HUB-REMOTE-01, ADR-0200).
//!
//! # Tre atti, e nessun altro
//!
//! Da una postazione che segue l'Hub una persona entrata con la propria frase
//! mette in pausa l'acquisizione di un monitoraggio, la riprende, o arresta il
//! monitoraggio. Avviare un monitoraggio o cambiarne le fonti chiede di
//! guardare l'Hub, e a distanza non si fa (decisione 1).
//!
//! # L'arresto non si annulla
//!
//! Per questo lo comanda soltanto una persona con il ruolo di amministratore
//! presso l'Hub (decisione 3): [`RemoteAction::needs_administrator`].

use crate::error::{DomainError, DomainResult};
use crate::model::hub_access::HubRole;

/// Che cosa si comanda a distanza.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteAction {
    /// Mettere in pausa l'acquisizione (ADR-0172).
    Pause,
    /// Riprendere l'acquisizione messa in pausa.
    Resume,
    /// Arrestare il monitoraggio: non si annulla.
    Stop,
}

impl RemoteAction {
    /// Tutti gli atti.
    pub const ALL: [Self; 3] = [Self::Pause, Self::Resume, Self::Stop];

    /// Il nome stabile, sul filo e nel registro.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pause => "pausa",
            Self::Resume => "ripresa",
            Self::Stop => "arresto",
        }
    }

    /// Che cosa vuol dire, in parole.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pause => "mettere in pausa l'acquisizione",
            Self::Resume => "riprendere l'acquisizione",
            Self::Stop => "arrestare il monitoraggio",
        }
    }

    /// Riconosce un atto dal suo nome stabile.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::UnknownVariant`] su un nome sconosciuto: un
    /// atto che non si riconosce non diventa un altro.
    pub fn parse(raw: &str) -> DomainResult<Self> {
        Self::ALL
            .into_iter()
            .find(|atto| atto.as_str() == raw)
            .ok_or_else(|| DomainError::UnknownVariant {
                kind: "comando_a_distanza",
                value: raw.chars().take(64).collect(),
            })
    }

    /// Se l'atto chiede il ruolo di amministratore presso l'Hub.
    #[must_use]
    pub const fn needs_administrator(self) -> bool {
        matches!(self, Self::Stop)
    }

    /// Se una persona con questo ruolo può comandarlo.
    #[must_use]
    pub const fn allowed_to(self, role: HubRole) -> bool {
        !self.needs_administrator() || matches!(role, HubRole::Administrator)
    }
}

/// Com'è andato un comando, nel registro dell'Hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteOutcome {
    /// L'Hub lo ha eseguito.
    Executed,
    /// L'Hub lo ha rifiutato, e ha detto perché.
    Refused,
}

impl RemoteOutcome {
    /// Il nome stabile nel registro.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Executed => "eseguito",
            Self::Refused => "rifiutato",
        }
    }

    /// Riconosce un esito dal suo nome stabile.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::UnknownVariant`] su un nome sconosciuto.
    pub fn parse(raw: &str) -> DomainResult<Self> {
        match raw {
            "eseguito" => Ok(Self::Executed),
            "rifiutato" => Ok(Self::Refused),
            altro => Err(DomainError::UnknownVariant {
                kind: "esito_comando_a_distanza",
                value: altro.chars().take(64).collect(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RemoteAction, RemoteOutcome};
    use crate::model::hub_access::HubRole;

    /// **Ogni atto ha un nome stabile che si rilegge**, e un nome sconosciuto
    /// non diventa un altro atto.
    #[test]
    fn ogni_atto_si_rilegge_e_uno_sconosciuto_no() {
        for atto in RemoteAction::ALL {
            assert_eq!(RemoteAction::parse(atto.as_str()), Ok(atto));
        }
        for estraneo in ["", "avvio", "Pausa", "configura"] {
            assert!(RemoteAction::parse(estraneo).is_err());
        }
        for esito in [RemoteOutcome::Executed, RemoteOutcome::Refused] {
            assert_eq!(RemoteOutcome::parse(esito.as_str()), Ok(esito));
        }
    }

    /// **L'arresto, che non si annulla, chiede il ruolo di amministratore**
    /// (ADR-0200, decisione 3); pausa e ripresa no.
    #[test]
    fn soltanto_chi_amministra_arresta_a_distanza() {
        assert!(RemoteAction::Pause.allowed_to(HubRole::Operator));
        assert!(RemoteAction::Resume.allowed_to(HubRole::Operator));
        assert!(!RemoteAction::Stop.allowed_to(HubRole::Operator));
        for atto in RemoteAction::ALL {
            assert!(atto.allowed_to(HubRole::Administrator));
        }
    }
}

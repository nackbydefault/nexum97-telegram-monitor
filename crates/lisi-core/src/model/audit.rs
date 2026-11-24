//! Registro di audit.
//!
//! L'audit annota chi ha fatto che cosa e quando. È append-only: il vincolo è
//! realizzato nello schema con dei trigger, non con una convenzione di codice,
//! perché una convenzione viene aggirata dal primo percorso che la dimentica.

use crate::id::AuditId;
use crate::role::OperatingMode;
use crate::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use crate::time::Timestamp;

/// Voce di audit che si intende registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAuditEntry {
    /// Soggetto che ha compiuto l'azione.
    pub actor: Actor,
    /// Azione compiuta.
    pub action: AuditAction,
    /// Entità interessata.
    pub entity: AuditEntity,
    /// Identificatore dell'entità interessata, quando applicabile.
    ///
    /// È un intero grezzo e non un identificatore tipizzato perché l'audit
    /// attraversa tutte le entità: il tipo è indicato da `entity`.
    pub entity_id: Option<i64>,
    /// Modalità operativa con cui l'azione è stata compiuta.
    ///
    /// Assente quando il servizio che scrive non conosce la modalità: `None`
    /// significa «non registrata», e attribuire una modalità dove non se ne
    /// conosce alcuna sarebbe inventare un fatto.
    pub actor_mode: Option<OperatingMode>,
    /// Dettaglio facoltativo.
    ///
    /// Non deve contenere segreti, credenziali o contenuti integrali: l'audit
    /// documenta le azioni, non i dati su cui esse insistono.
    pub detail: Option<AuditDetail>,
    /// Istante dell'azione.
    pub recorded_at: Timestamp,
}

/// Voce di audit registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// Identificatore assegnato dalla persistenza.
    pub id: AuditId,
    /// Soggetto che ha compiuto l'azione.
    pub actor: Actor,
    /// Azione compiuta.
    pub action: AuditAction,
    /// Entità interessata.
    pub entity: AuditEntity,
    /// Identificatore dell'entità interessata.
    pub entity_id: Option<i64>,
    /// Modalità operativa con cui l'azione è stata compiuta.
    pub actor_mode: Option<OperatingMode>,
    /// Dettaglio facoltativo.
    pub detail: Option<AuditDetail>,
    /// Istante dell'azione.
    pub recorded_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::NewAuditEntry;
    use crate::text::{Actor, AuditAction, AuditEntity};
    use crate::time::Timestamp;

    #[test]
    fn an_entry_keeps_the_actor_the_action_and_the_entity() {
        let (Ok(actor), Ok(action), Ok(entity)) = (
            Actor::try_new("operatore.prova"),
            AuditAction::try_new("sessione_avviata"),
            AuditEntity::try_new("session"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };

        let entry = NewAuditEntry {
            actor,
            action,
            entity,
            entity_id: Some(7),
            actor_mode: Some(crate::role::OperatingMode::Administrator),
            detail: None,
            recorded_at: Timestamp::from_millis(1_700_000_000_000),
        };

        assert_eq!(entry.actor.as_str(), "operatore.prova");
        assert_eq!(entry.action.as_str(), "sessione_avviata");
        assert_eq!(entry.entity.as_str(), "session");
        assert_eq!(entry.entity_id, Some(7));
        assert_eq!(
            entry.actor_mode,
            Some(crate::role::OperatingMode::Administrator)
        );
    }
}

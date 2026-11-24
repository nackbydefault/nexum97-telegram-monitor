//! Le decisioni sui periodi non coperti prioritari (PR-06, ADR-0122).
//!
//! In sola aggiunta: una riga non si modifica e non si cancella, e due trigger
//! lo impongono. La decisione e la sua riga d'audit si scrivono **nella stessa
//! transazione**: un atto di una persona senza traccia, o una traccia senza
//! l'atto, non devono poter esistere.

use lisi_core::model::NewAuditEntry;
use lisi_core::{SourceId, Timestamp};

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// Una decisione da registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewGapDecision {
    /// La fonte.
    pub source_id: SourceId,
    /// Da quando il periodo.
    pub gap_from: Timestamp,
    /// Fino a quando.
    pub gap_to: Timestamp,
    /// La priorità tecnica, com'era quando si è deciso.
    pub priority: String,
    /// La versione del criterio che l'ha data.
    pub criterion_version: u32,
    /// Che cosa si è deciso.
    pub decision: String,
    /// Il motivo, scritto da chi decide.
    pub reason: String,
    /// Chi decide, e quando.
    pub decided_by: String,
    /// Quando.
    pub decided_at: Timestamp,
}

/// Una decisione registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredGapDecision {
    /// Identificativo.
    pub id: i64,
    /// La fonte.
    pub source_id: SourceId,
    /// Da quando il periodo.
    pub gap_from: Timestamp,
    /// Fino a quando.
    pub gap_to: Timestamp,
    /// La priorità tecnica di allora.
    pub priority: String,
    /// La versione del criterio di allora.
    pub criterion_version: u32,
    /// Che cosa si è deciso.
    pub decision: String,
    /// Il motivo.
    pub reason: String,
    /// Chi.
    pub decided_by: String,
    /// Quando.
    pub decided_at: Timestamp,
}

impl Database {
    /// Registra una decisione **e** la sua riga d'audit, insieme.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce; in quel caso non
    /// resta né la decisione né la riga d'audit.
    pub fn insert_gap_decision(
        &mut self,
        decisione: &NewGapDecision,
        audit: &NewAuditEntry,
    ) -> StorageResult<i64> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO coverage_gap_decisions (
                 source_id, gap_from, gap_to, priority, criterion_version, decision,
                 reason, decided_by, decided_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                decisione.source_id.get(),
                millis(decisione.gap_from),
                millis(decisione.gap_to),
                decisione.priority,
                decisione.criterion_version,
                decisione.decision,
                decisione.reason,
                decisione.decided_by,
                millis(decisione.decided_at),
            ],
        )?;
        let id = transazione.last_insert_rowid();
        transazione.execute(
            "INSERT INTO audit (actor, action, entity, entity_id, detail, recorded_at, actor_mode)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                audit.actor.as_str(),
                audit.action.as_str(),
                audit.entity.as_str(),
                Some(id),
                audit
                    .detail
                    .as_ref()
                    .map(|dettaglio| dettaglio.as_str().to_owned()),
                millis(audit.recorded_at),
                audit.actor_mode.map(|modo| modo.as_str()),
            ],
        )?;
        transazione.commit()?;
        Ok(id)
    }

    /// Tutte le decisioni, dalla più vecchia.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn gap_decisions(&self) -> StorageResult<Vec<StoredGapDecision>> {
        let mut statement = self.connection.prepare(
            "SELECT id, source_id, gap_from, gap_to, priority, criterion_version, decision,
                    reason, decided_by, decided_at
             FROM coverage_gap_decisions
             ORDER BY decided_at, id",
        )?;
        let righe = statement.query_map([], |row| {
            Ok(StoredGapDecision {
                id: row.get(0)?,
                source_id: SourceId::new(row.get(1)?),
                gap_from: instant(row.get(2)?),
                gap_to: instant(row.get(3)?),
                priority: row.get(4)?,
                criterion_version: row.get(5)?,
                decision: row.get(6)?,
                reason: row.get(7)?,
                decided_by: row.get(8)?,
                decided_at: instant(row.get(9)?),
            })
        })?;
        let mut decisioni = Vec::new();
        for riga in righe {
            decisioni.push(riga?);
        }
        Ok(decisioni)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::SourceId;
    use lisi_core::model::NewAuditEntry;
    use lisi_core::text::{AuditAction, AuditDetail, AuditEntity};

    use super::NewGapDecision;
    use crate::test_support::{actor, database, later};

    fn decisione() -> NewGapDecision {
        NewGapDecision {
            source_id: SourceId::new(7),
            gap_from: later(10),
            gap_to: later(20),
            priority: String::from("alta"),
            criterion_version: 1,
            decision: String::from("da_valutare_per_recupero"),
            reason: String::from("Fonte seguita dall'ufficio nel turno di notte."),
            decided_by: String::from("operatore.prova"),
            decided_at: later(30),
        }
    }

    fn audit() -> NewAuditEntry {
        let (Ok(azione), Ok(entita), Ok(dettaglio)) = (
            AuditAction::try_new("periodo_non_coperto_deciso"),
            AuditEntity::try_new("periodo_non_coperto"),
            AuditDetail::try_new("Da valutare per un recupero"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        NewAuditEntry {
            actor: actor("operatore.prova"),
            action: azione,
            entity: entita,
            entity_id: None,
            actor_mode: None,
            detail: Some(dettaglio),
            recorded_at: later(30),
        }
    }

    /// **La decisione e la sua traccia si scrivono insieme**, e si rileggono
    /// com'erano.
    #[test]
    fn la_decisione_e_la_traccia_si_scrivono_insieme() {
        let mut archivio = database();
        let Ok(id) = archivio.insert_gap_decision(&decisione(), &audit()) else {
            panic!("la decisione deve registrarsi");
        };
        let Ok(decisioni) = archivio.gap_decisions() else {
            panic!("le decisioni devono rileggersi");
        };
        assert_eq!(decisioni.len(), 1);
        assert_eq!(decisioni[0].id, id);
        assert_eq!(
            decisioni[0].reason,
            "Fonte seguita dall'ufficio nel turno di notte."
        );

        let Ok(voci) = archivio.audit_entries() else {
            panic!("l'audit deve rileggersi");
        };
        let Some(voce) = voci
            .iter()
            .find(|voce| voce.action.as_str() == "periodo_non_coperto_deciso")
        else {
            panic!("la traccia deve esserci");
        };
        assert_eq!(voce.entity_id, Some(id));
    }

    /// **In sola aggiunta**: una decisione non si modifica e non si cancella, e
    /// un motivo vuoto non entra.
    #[test]
    fn una_decisione_non_si_modifica_ne_si_cancella() {
        let mut archivio = database();
        let Ok(_) = archivio.insert_gap_decision(&decisione(), &audit()) else {
            panic!("la decisione deve registrarsi");
        };
        assert!(
            archivio
                .connection
                .execute("UPDATE coverage_gap_decisions SET reason = 'altro'", [])
                .is_err()
        );
        assert!(
            archivio
                .connection
                .execute("DELETE FROM coverage_gap_decisions", [])
                .is_err()
        );

        let mut senza_motivo = decisione();
        senza_motivo.reason = String::from("   ");
        assert!(
            archivio
                .insert_gap_decision(&senza_motivo, &audit())
                .is_err()
        );
        // E la transazione non lascia una traccia orfana.
        let Ok(voci) = archivio.audit_entries() else {
            panic!("l'audit deve rileggersi");
        };
        assert_eq!(
            voci.iter()
                .filter(|voce| voce.action.as_str() == "periodo_non_coperto_deciso")
                .count(),
            1
        );
    }
}

//! Gli atti sull'affidabilità di una fonte, in sola aggiunta
//! (SOURCE-RELIABILITY-01, ADR-0167).
//!
//! Ogni atto porta chi, quando e perché, e la sua riga d'audit nella stessa
//! transazione. La valutazione in vigore si ricava dagli atti
//! (`lisi_core::model::source_reliability::current_reliability`).

use core::str::FromStr;

use lisi_core::SourceId;
use lisi_core::model::NewAuditEntry;
use lisi_core::model::reason::OperationalReason;
use lisi_core::model::source_reliability::{NewReliability, ReliabilityAct};
use lisi_core::text::Actor;

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

impl Database {
    /// Registra un atto sull'affidabilità di una fonte **e** la sua riga
    /// d'audit, insieme.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo schema lo rifiuta o la scrittura non riesce;
    /// allora non resta né l'atto né l'audit.
    pub fn insert_source_reliability(
        &mut self,
        atto: &NewReliability,
        audit: &NewAuditEntry,
    ) -> StorageResult<i64> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO source_reliability_entries (source_id, act, reason, actor, acted_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                atto.source.get(),
                atto.act.as_str(),
                atto.reason.as_str(),
                atto.by.as_str(),
                millis(atto.at),
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

    /// Gli atti sull'affidabilità di una fonte, dal più antico. Un atto che
    /// l'archivio conserva con una parola sconosciuta si salta: non si
    /// indovina.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn source_reliability_history(
        &self,
        source: SourceId,
    ) -> StorageResult<Vec<NewReliability>> {
        let mut statement = self.connection.prepare(
            "SELECT act, reason, actor, acted_at FROM source_reliability_entries
             WHERE source_id = ?1
             ORDER BY acted_at, id",
        )?;
        let righe = statement.query_map([source.get()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        let mut atti = Vec::new();
        for riga in righe {
            let (act, reason, actor, at) = riga?;
            let (Ok(act), Ok(reason), Ok(by)) = (
                ReliabilityAct::from_str(&act),
                OperationalReason::try_new(&reason),
                Actor::try_new(&actor),
            ) else {
                continue;
            };
            atti.push(NewReliability {
                source,
                act,
                reason,
                by,
                at: instant(at),
            });
        }
        Ok(atti)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::SourceId;
    use lisi_core::model::NewAuditEntry;
    use lisi_core::model::reason::OperationalReason;
    use lisi_core::model::source_reliability::{NewReliability, ReliabilityAct, ReliabilityLevel};
    use lisi_core::text::{AuditAction, AuditEntity};

    use crate::test_support::{actor, database, later};

    fn audit() -> NewAuditEntry {
        let (Ok(azione), Ok(entita)) = (
            AuditAction::try_new("affidabilita_fonte"),
            AuditEntity::try_new("fonte"),
        ) else {
            panic!("valori d'audit validi");
        };
        NewAuditEntry {
            actor: actor("operatore.prova"),
            action: azione,
            entity: entita,
            entity_id: None,
            actor_mode: None,
            detail: None,
            recorded_at: later(0),
        }
    }

    fn atto(act: ReliabilityAct, secondi: i64) -> NewReliability {
        let Ok(reason) = OperationalReason::try_new("riscontri dell'ufficio sugli ultimi tre mesi")
        else {
            panic!("ragione valida");
        };
        NewReliability {
            source: SourceId::new(7),
            act,
            reason,
            by: actor("operatore.prova"),
            at: later(secondi),
        }
    }

    /// **Gli atti si registrano con l'audit, si rileggono in ordine e non si
    /// riscrivono** (SOURCE-RELIABILITY-01, criterio 4).
    #[test]
    fn gli_atti_si_registrano_e_si_rileggono_in_ordine() {
        let mut archivio = database();
        for (act, quando) in [
            (ReliabilityAct::Assess(ReliabilityLevel::Reliable), 1),
            (ReliabilityAct::Withdraw, 2),
        ] {
            let Ok(_) = archivio.insert_source_reliability(&atto(act, quando), &audit()) else {
                panic!("l'atto deve registrarsi");
            };
        }
        let Ok(storia) = archivio.source_reliability_history(SourceId::new(7)) else {
            panic!("la storia deve leggersi");
        };
        assert_eq!(
            storia.iter().map(|a| a.act).collect::<Vec<_>>(),
            [
                ReliabilityAct::Assess(ReliabilityLevel::Reliable),
                ReliabilityAct::Withdraw
            ]
        );
        assert!(
            archivio
                .source_reliability_history(SourceId::new(8))
                .is_ok_and(|altra| altra.is_empty())
        );
        for comando in [
            "UPDATE source_reliability_entries SET act = 'affidabile'",
            "DELETE FROM source_reliability_entries",
            "INSERT INTO source_reliability_entries (source_id, act, reason, actor, acted_at)
             VALUES (7, 'sicura_al_90', 'riscontri dell''ufficio sugli ultimi tre mesi', 'x', 1)",
        ] {
            assert!(
                archivio.connection.execute(comando, []).is_err(),
                "«{comando}»"
            );
        }
    }
}

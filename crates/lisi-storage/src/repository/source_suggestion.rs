//! Le decisioni sui suggerimenti di fonti, in sola aggiunta (SOURCE-SUGGEST-01,
//! ADR-0164).
//!
//! Il suggerimento non si conserva: si ricalcola dai contenuti acquisiti. Si
//! conserva **che cosa una persona ne ha deciso**, con il motivo, e la riga
//! d'audit nella stessa transazione.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// Una decisione da registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSuggestionDecision {
    /// L'indirizzo pubblico, in minuscolo.
    pub address: String,
    /// `ignorato` o `aggiunto`.
    pub decision: &'static str,
    /// Chi.
    pub actor: String,
    /// Perché.
    pub reason: String,
    /// Quando.
    pub decided_at: Timestamp,
    /// La fonte nata dall'aggiunta.
    pub source_id: Option<i64>,
}

/// Una decisione registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSuggestionDecision {
    /// L'indirizzo pubblico, in minuscolo.
    pub address: String,
    /// `ignorato` o `aggiunto`.
    pub decision: String,
    /// Chi.
    pub actor: String,
    /// Perché.
    pub reason: String,
    /// Quando.
    pub decided_at: Timestamp,
}

impl Database {
    /// Registra una decisione **e** la sua riga d'audit, insieme.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo schema la rifiuta o la scrittura non riesce;
    /// allora non resta né la decisione né l'audit.
    pub fn insert_suggestion_decision(
        &mut self,
        decisione: &NewSuggestionDecision,
        audit: &NewAuditEntry,
    ) -> StorageResult<i64> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO source_suggestion_decisions (address, decision, actor, reason,
                 decided_at, source_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                decisione.address,
                decisione.decision,
                decisione.actor,
                decisione.reason,
                millis(decisione.decided_at),
                decisione.source_id,
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

    /// Le decisioni prese, nell'ordine in cui sono state prese.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn suggestion_decisions(&self) -> StorageResult<Vec<StoredSuggestionDecision>> {
        let mut statement = self.connection.prepare(
            "SELECT address, decision, actor, reason, decided_at
             FROM source_suggestion_decisions
             ORDER BY id",
        )?;
        let righe = statement.query_map([], |row| {
            Ok(StoredSuggestionDecision {
                address: row.get(0)?,
                decision: row.get(1)?,
                actor: row.get(2)?,
                reason: row.get(3)?,
                decided_at: instant(row.get(4)?),
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
    use lisi_core::model::NewAuditEntry;
    use lisi_core::text::{AuditAction, AuditEntity};

    use super::NewSuggestionDecision;
    use crate::test_support::{actor, database, later};

    fn audit() -> NewAuditEntry {
        let (Ok(azione), Ok(entita)) = (
            AuditAction::try_new("suggerimento_ignorato"),
            AuditEntity::try_new("suggerimento_fonte"),
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

    fn decisione(
        indirizzo: &str,
        esito: &'static str,
        fonte: Option<i64>,
    ) -> NewSuggestionDecision {
        NewSuggestionDecision {
            address: indirizzo.to_owned(),
            decision: esito,
            actor: String::from("operatore.prova"),
            reason: String::from("non pertinente all'indagine"),
            decided_at: later(1),
            source_id: fonte,
        }
    }

    /// **Una decisione si registra con il suo audit, resta, e lo schema rifiuta
    /// ciò che non è una decisione** (SOURCE-SUGGEST-01, criterio 4).
    #[test]
    fn una_decisione_si_registra_e_resta() {
        let mut archivio = database();
        let Ok(_) = archivio
            .insert_suggestion_decision(&decisione("canale_cyber", "ignorato", None), &audit())
        else {
            panic!("la decisione deve registrarsi");
        };
        let Ok(decisioni) = archivio.suggestion_decisions() else {
            panic!("le decisioni devono leggersi");
        };
        assert_eq!(decisioni.len(), 1);
        assert_eq!(decisioni[0].address, "canale_cyber");
        for (descrizione, sbagliata) in [
            ("maiuscole", decisione("Canale_Cyber", "ignorato", None)),
            ("troppo corto", decisione("abc", "ignorato", None)),
            (
                "aggiunto senza fonte",
                decisione("canale_cyber", "aggiunto", None),
            ),
            (
                "ignorato con fonte",
                decisione("canale_cyber", "ignorato", Some(3)),
            ),
            (
                "decisione sconosciuta",
                decisione("canale_cyber", "aperto", None),
            ),
        ] {
            assert!(
                archivio
                    .insert_suggestion_decision(&sbagliata, &audit())
                    .is_err(),
                "lo schema deve rifiutare: {descrizione}"
            );
        }
        for comando in [
            "UPDATE source_suggestion_decisions SET reason = 'altro'",
            "DELETE FROM source_suggestion_decisions",
        ] {
            assert!(
                archivio.connection.execute(comando, []).is_err(),
                "«{comando}»"
            );
        }
        let Ok(audit_scritti) = archivio.connection.query_row(
            "SELECT COUNT(*) FROM audit WHERE entity = 'suggerimento_fonte'",
            [],
            |row| row.get::<_, i64>(0),
        ) else {
            panic!("l'audit deve leggersi");
        };
        assert_eq!(
            audit_scritti, 1,
            "soltanto la decisione registrata ha l'audit"
        );
    }
}

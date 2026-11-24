//! Il registro delle consultazioni (AUDIT-VIEW-01, ADR-0193, migrazione 0088).
//!
//! Separato dall'audit: qui stanno le letture, là le azioni (ADR-0051,
//! decisione 5). La scelta della conservazione è un'azione e porta la sua
//! riga d'audit nella stessa transazione; le consultazioni no.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::text::Actor;
use rusqlite::OptionalExtension;

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// Una consultazione registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredConsultation {
    /// Chi.
    pub actor: String,
    /// `contenuto` o `soggetto`.
    pub kind: String,
    /// Quale.
    pub entity_id: i64,
    /// Quando.
    pub viewed_at: Timestamp,
}

impl Database {
    /// La conservazione in giorni; `None` se il registro è spento.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn consultation_retention(&self) -> StorageResult<Option<u32>> {
        let giorni: Option<i64> = self.connection.query_row(
            "SELECT retention_days FROM consultation_settings WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(giorni.and_then(|valore| u32::try_from(valore).ok()))
    }

    /// Accende, cambia o spegne il registro, con la sua riga d'audit.
    /// Spegnerlo toglie tutte le righe; restituisce quante ne ha tolte.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il valore non rispetta lo schema o la
    /// scrittura non riesce: in quel caso non cambia niente.
    pub fn save_consultation_retention(
        &mut self,
        retention_days: Option<u32>,
        actor: &Actor,
        audit: &NewAuditEntry,
    ) -> StorageResult<usize> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "UPDATE consultation_settings
             SET retention_days = ?1, updated_at = ?2, updated_by = ?3
             WHERE id = 1",
            rusqlite::params![
                retention_days.map(i64::from),
                millis(audit.recorded_at),
                actor.as_str(),
            ],
        )?;
        let tolte = if retention_days.is_none() {
            transazione.execute("DELETE FROM consultations", [])?
        } else {
            0
        };
        transazione.execute(
            "INSERT INTO audit (actor, action, entity, entity_id, detail, recorded_at, actor_mode)
             VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?6)",
            rusqlite::params![
                audit.actor.as_str(),
                audit.action.as_str(),
                audit.entity.as_str(),
                audit
                    .detail
                    .as_ref()
                    .map(|dettaglio| dettaglio.as_str().to_owned()),
                millis(audit.recorded_at),
                audit.actor_mode.map(|modo| modo.as_str()),
            ],
        )?;
        transazione.commit()?;
        Ok(tolte)
    }

    /// L'ultima consultazione della stessa persona sulla stessa cosa, se c'è.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn last_consultation_of(
        &self,
        actor: &str,
        kind: &str,
        entity_id: i64,
    ) -> StorageResult<Option<Timestamp>> {
        Ok(self
            .connection
            .query_row(
                "SELECT MAX(viewed_at) FROM consultations
                 WHERE actor = ?1 AND kind = ?2 AND entity_id = ?3",
                rusqlite::params![actor, kind, entity_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten()
            .map(instant))
    }

    /// Registra una consultazione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la riga non rispetta lo schema o la scrittura
    /// non riesce.
    pub fn insert_consultation(&self, consultation: &StoredConsultation) -> StorageResult<()> {
        self.connection.execute(
            "INSERT INTO consultations (actor, kind, entity_id, viewed_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                consultation.actor,
                consultation.kind,
                consultation.entity_id,
                millis(consultation.viewed_at),
            ],
        )?;
        Ok(())
    }

    /// Toglie le consultazioni registrate prima di `before`; restituisce quante.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn prune_consultations(&self, before: Timestamp) -> StorageResult<usize> {
        Ok(self.connection.execute(
            "DELETE FROM consultations WHERE viewed_at < ?1",
            [millis(before)],
        )?)
    }

    /// Le consultazioni, le più recenti prima, al più `limit`.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn consultations(&self, limit: usize) -> StorageResult<Vec<StoredConsultation>> {
        let mut richiesta = self.connection.prepare(
            "SELECT actor, kind, entity_id, viewed_at FROM consultations
             ORDER BY viewed_at DESC, id DESC LIMIT ?1",
        )?;
        let righe = richiesta.query_map([i64::try_from(limit).unwrap_or(i64::MAX)], |row| {
            Ok(StoredConsultation {
                actor: row.get(0)?,
                kind: row.get(1)?,
                entity_id: row.get(2)?,
                viewed_at: instant(row.get(3)?),
            })
        })?;
        let mut tutte = Vec::new();
        for riga in righe {
            tutte.push(riga?);
        }
        Ok(tutte)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::NewAuditEntry;
    use lisi_core::text::{AuditAction, AuditDetail, AuditEntity};

    use super::StoredConsultation;
    use crate::test_support::{actor, database, later, now};

    fn audit() -> NewAuditEntry {
        let (Ok(azione), Ok(entita), Ok(dettaglio)) = (
            AuditAction::try_new("registro_consultazioni_scelto"),
            AuditEntity::try_new("postazione"),
            AuditDetail::try_new("prova"),
        ) else {
            panic!("i valori dell'audit di prova devono essere validi");
        };
        NewAuditEntry {
            actor: actor("amministratore.prova"),
            action: azione,
            entity: entita,
            entity_id: None,
            actor_mode: None,
            detail: Some(dettaglio),
            recorded_at: now(),
        }
    }

    fn consultazione(chi: &str, secondi: i64) -> StoredConsultation {
        StoredConsultation {
            actor: chi.to_owned(),
            kind: String::from("contenuto"),
            entity_id: 7,
            viewed_at: later(secondi),
        }
    }

    #[test]
    fn il_registro_e_spento_di_fabbrica_e_spegnerlo_lo_svuota() {
        let mut database = database();
        assert_eq!(database.consultation_retention().ok(), Some(None));
        let Ok(0) = database.save_consultation_retention(
            Some(90),
            &actor("amministratore.prova"),
            &audit(),
        ) else {
            panic!("il registro si deve accendere");
        };
        assert_eq!(database.consultation_retention().ok(), Some(Some(90)));
        assert!(
            database
                .save_consultation_retention(Some(10), &actor("a"), &audit())
                .is_err(),
            "meno di 30 giorni non si sceglie"
        );
        for secondi in [1, 2, 3] {
            let Ok(()) = database.insert_consultation(&consultazione("operatore.uno", secondi))
            else {
                panic!("la consultazione si deve registrare");
            };
        }
        assert_eq!(
            database
                .last_consultation_of("operatore.uno", "contenuto", 7)
                .ok(),
            Some(Some(later(3)))
        );
        assert_eq!(database.prune_consultations(later(2)).ok(), Some(1));
        assert!(
            database
                .connection
                .execute("UPDATE consultations SET actor = 'altro'", [])
                .is_err()
        );
        let Ok(tolte) =
            database.save_consultation_retention(None, &actor("amministratore.prova"), &audit())
        else {
            panic!("il registro si deve spegnere");
        };
        assert_eq!(tolte, 2);
        assert_eq!(database.consultations(10).map(|v| v.len()).ok(), Some(0));
    }
}

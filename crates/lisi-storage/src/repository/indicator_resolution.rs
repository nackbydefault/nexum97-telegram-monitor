//! La risoluzione degli indicatori dal PC (IOC-RESOLVE-01, ADR-0202,
//! migrazione 0093).
//!
//! La scelta di abilitarla è un'azione e porta la sua riga d'audit nella
//! stessa transazione. Una richiesta si scrive una volta, con la sua riga
//! d'audit, e non cambia più.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::text::Actor;

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// Una richiesta da registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewIndicatorResolution {
    /// Il genere dell'indicatore, nell'etichetta stabile.
    pub indicator_kind: &'static str,
    /// Il valore dell'indicatore, come è conservato.
    pub indicator_value: String,
    /// Il nome chiesto davvero al risolutore.
    pub queried_name: String,
    /// Chi.
    pub requested_by: String,
    /// Quando.
    pub requested_at: Timestamp,
    /// `trovato`, `nessun_record`, `inesistente` o `non_riuscito`.
    pub outcome: &'static str,
    /// Il codice di Windows, quando non è riuscita.
    pub error_code: Option<i64>,
    /// Le risposte, una per riga.
    pub answers: String,
}

/// Una richiesta registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredIndicatorResolution {
    /// L'identificativo.
    pub id: i64,
    /// Il genere dell'indicatore.
    pub indicator_kind: String,
    /// Il valore dell'indicatore.
    pub indicator_value: String,
    /// Il nome chiesto al risolutore.
    pub queried_name: String,
    /// Chi.
    pub requested_by: String,
    /// Quando.
    pub requested_at: Timestamp,
    /// L'esito, nel nome stabile.
    pub outcome: String,
    /// Il codice di Windows, quando non è riuscita.
    pub error_code: Option<i64>,
    /// Le risposte, una per riga.
    pub answers: String,
}

impl Database {
    /// Se la risoluzione degli indicatori è abilitata.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn indicator_resolution_enabled(&self) -> StorageResult<bool> {
        let abilitata: i64 = self.connection.query_row(
            "SELECT enabled FROM indicator_resolution_settings WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(abilitata == 1)
    }

    /// Abilita o spegne la risoluzione, con la sua riga d'audit.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce: in quel caso non
    /// cambia niente.
    pub fn save_indicator_resolution_enabled(
        &mut self,
        enabled: bool,
        actor: &Actor,
        audit: &NewAuditEntry,
    ) -> StorageResult<()> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "UPDATE indicator_resolution_settings
             SET enabled = ?1, updated_at = ?2, updated_by = ?3
             WHERE id = 1",
            rusqlite::params![
                i64::from(enabled),
                millis(audit.recorded_at),
                actor.as_str()
            ],
        )?;
        inserisci_audit(&transazione, audit, None)?;
        transazione.commit()?;
        Ok(())
    }

    /// Registra una richiesta e la sua riga d'audit, insieme.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo schema rifiuta qualcosa o la scrittura non
    /// riesce: allora non resta niente.
    pub fn insert_indicator_resolution(
        &mut self,
        richiesta: &NewIndicatorResolution,
        audit: &NewAuditEntry,
    ) -> StorageResult<i64> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO indicator_resolutions (indicator_kind, indicator_value, queried_name,
                 requested_by, requested_at, outcome, error_code, answers)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                richiesta.indicator_kind,
                richiesta.indicator_value,
                richiesta.queried_name,
                richiesta.requested_by,
                millis(richiesta.requested_at),
                richiesta.outcome,
                richiesta.error_code,
                richiesta.answers,
            ],
        )?;
        let id = transazione.last_insert_rowid();
        inserisci_audit(&transazione, audit, Some(id))?;
        transazione.commit()?;
        Ok(id)
    }

    /// Le richieste per un indicatore, dalla più nuova, al più `limite`.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn indicator_resolutions(
        &self,
        kind: &str,
        value: &str,
        limite: u32,
    ) -> StorageResult<Vec<StoredIndicatorResolution>> {
        let mut statement = self.connection.prepare(
            "SELECT id, indicator_kind, indicator_value, queried_name, requested_by, requested_at,
                    outcome, error_code, answers
             FROM indicator_resolutions
             WHERE indicator_kind = ?1 AND indicator_value = ?2
             ORDER BY requested_at DESC, id DESC
             LIMIT ?3",
        )?;
        let righe = statement.query_map(rusqlite::params![kind, value, limite], |row| {
            Ok(StoredIndicatorResolution {
                id: row.get(0)?,
                indicator_kind: row.get(1)?,
                indicator_value: row.get(2)?,
                queried_name: row.get(3)?,
                requested_by: row.get(4)?,
                requested_at: instant(row.get(5)?),
                outcome: row.get(6)?,
                error_code: row.get(7)?,
                answers: row.get(8)?,
            })
        })?;
        let mut richieste = Vec::new();
        for riga in righe {
            richieste.push(riga?);
        }
        Ok(richieste)
    }
}

fn inserisci_audit(
    transazione: &rusqlite::Transaction<'_>,
    audit: &NewAuditEntry,
    entity_id: Option<i64>,
) -> StorageResult<()> {
    transazione.execute(
        "INSERT INTO audit (actor, action, entity, entity_id, detail, recorded_at, actor_mode)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            audit.actor.as_str(),
            audit.action.as_str(),
            audit.entity.as_str(),
            entity_id.or(audit.entity_id),
            audit
                .detail
                .as_ref()
                .map(|dettaglio| dettaglio.as_str().to_owned()),
            millis(audit.recorded_at),
            audit.actor_mode.map(|modo| modo.as_str()),
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::NewAuditEntry;
    use lisi_core::text::{Actor, AuditAction, AuditEntity};

    use super::NewIndicatorResolution;
    use crate::Database;

    fn attore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn audit() -> NewAuditEntry {
        let (Ok(action), Ok(entity)) = (
            AuditAction::try_new("indicatore_risolto"),
            AuditEntity::try_new("indicatore"),
        ) else {
            panic!("l'audit di prova deve essere valido");
        };
        NewAuditEntry {
            actor: attore(),
            action,
            entity,
            entity_id: None,
            actor_mode: None,
            detail: None,
            recorded_at: Timestamp::from_millis(1_700_000_000_000),
        }
    }

    fn archivio() -> Database {
        let Ok(archivio) = Database::open_in_memory() else {
            panic!("l'archivio in memoria deve aprirsi");
        };
        archivio
    }

    fn richiesta(kind: &'static str, outcome: &'static str) -> NewIndicatorResolution {
        NewIndicatorResolution {
            indicator_kind: kind,
            indicator_value: String::from("esempio.invalid"),
            queried_name: String::from("esempio.invalid"),
            requested_by: String::from("operatore.prova"),
            requested_at: Timestamp::from_millis(1_700_000_000_000),
            outcome,
            error_code: None,
            answers: String::from("192.0.2.10"),
        }
    }

    #[test]
    fn la_risoluzione_e_spenta_di_fabbrica_e_si_accende_con_l_audit() {
        let mut archivio = archivio();
        assert_eq!(archivio.indicator_resolution_enabled().ok(), Some(false));
        let Ok(()) = archivio.save_indicator_resolution_enabled(true, &attore(), &audit()) else {
            panic!("la scelta deve salvarsi");
        };
        assert_eq!(archivio.indicator_resolution_enabled().ok(), Some(true));
    }

    #[test]
    fn una_risoluzione_si_registra_e_non_cambia() {
        let mut archivio = archivio();
        let Ok(_) =
            archivio.insert_indicator_resolution(&richiesta("dominio", "trovato"), &audit())
        else {
            panic!("la richiesta deve registrarsi");
        };
        let Ok(richieste) = archivio.indicator_resolutions("dominio", "esempio.invalid", 10) else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(richieste.len(), 1);
        assert_eq!(richieste[0].answers, "192.0.2.10");
        assert_eq!(
            archivio
                .indicator_resolutions("ipv4", "esempio.invalid", 10)
                .map(|r| r.len())
                .ok(),
            Some(0)
        );
        assert!(
            archivio
                .connection
                .execute("UPDATE indicator_resolutions SET answers = ''", [])
                .is_err(),
            "una risoluzione registrata non cambia"
        );
        assert!(
            archivio
                .connection
                .execute("DELETE FROM indicator_resolutions", [])
                .is_err(),
            "una risoluzione registrata non si toglie"
        );
    }

    #[test]
    fn lo_schema_rifiuta_un_genere_che_non_si_risolve() {
        let mut archivio = archivio();
        assert!(
            archivio
                .insert_indicator_resolution(&richiesta("sha256", "trovato"), &audit())
                .is_err(),
            "un'impronta non si risolve"
        );
        assert!(
            archivio
                .insert_indicator_resolution(&richiesta("dominio", "forse"), &audit())
                .is_err(),
            "un esito sconosciuto non entra"
        );
    }
}

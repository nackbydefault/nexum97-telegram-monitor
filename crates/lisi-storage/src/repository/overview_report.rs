//! Il registro dei rapporti complessivi su più monitoraggi (REPORT-MULTI-01,
//! ADR-0192, migrazione 0087).
//!
//! Una riga per rapporto prodotto, con l'audit nella stessa transazione; le
//! righe non cambiano e non si cancellano.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// Un rapporto complessivo da registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewOverviewReport {
    /// L'anno dell'identificativo.
    pub year: i32,
    /// Il progressivo nell'anno.
    pub sequence: u32,
    /// Chi l'ha chiesto.
    pub requested_by: String,
    /// Quando.
    pub requested_at: Timestamp,
    /// Il responsabile del documento.
    pub responsible_name: String,
    /// La sua qualifica.
    pub responsible_role: String,
    /// I monitoraggi, in ordine.
    pub session_ids: Vec<i64>,
    /// L'impronta dell'elenco delle impronte.
    pub manifest_sha256: String,
}

/// Un rapporto complessivo registrato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredOverviewReport {
    /// L'identificativo della riga.
    pub id: i64,
    /// Il rapporto, come è stato registrato.
    pub report: NewOverviewReport,
}

impl Database {
    /// Il prossimo progressivo libero dell'anno.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn next_overview_sequence(&self, year: i32) -> StorageResult<u32> {
        let massimo: Option<i64> = self.connection.query_row(
            "SELECT MAX(sequence) FROM overview_reports WHERE year = ?1",
            [i64::from(year)],
            |row| row.get(0),
        )?;
        Ok(massimo
            .and_then(|valore| u32::try_from(valore).ok())
            .unwrap_or(0)
            .saturating_add(1))
    }

    /// Registra un rapporto complessivo, con la sua riga d'audit.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la riga non rispetta lo schema (anche un
    /// progressivo già preso) o la scrittura non riesce: in quel caso non
    /// resta né la riga né l'audit.
    pub fn insert_overview_report(
        &mut self,
        report: &NewOverviewReport,
        audit: &NewAuditEntry,
    ) -> StorageResult<i64> {
        let monitoraggi = report
            .session_ids
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO overview_reports (
                 year, sequence, requested_by, requested_at, responsible_name,
                 responsible_role, session_ids, manifest_sha256
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                i64::from(report.year),
                i64::from(report.sequence),
                report.requested_by,
                millis(report.requested_at),
                report.responsible_name,
                report.responsible_role,
                monitoraggi,
                report.manifest_sha256,
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
                id,
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

    /// I rapporti complessivi registrati, i più recenti prima, al più `limit`.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o una riga è corrotta.
    pub fn overview_reports(&self, limit: usize) -> StorageResult<Vec<StoredOverviewReport>> {
        let mut richiesta = self.connection.prepare(
            "SELECT id, year, sequence, requested_by, requested_at, responsible_name,
                    responsible_role, session_ids, manifest_sha256
             FROM overview_reports ORDER BY requested_at DESC, id DESC LIMIT ?1",
        )?;
        let righe = richiesta.query_map([i64::try_from(limit).unwrap_or(i64::MAX)], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
            ))
        })?;
        let mut rapporti = Vec::new();
        for riga in righe {
            let (id, anno, progressivo, chi, quando, nome, qualifica, monitoraggi, impronta) =
                riga?;
            let session_ids = monitoraggi
                .split(',')
                .map(str::parse::<i64>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| crate::error::StorageError::CorruptedRow {
                    detail: "monitoraggi illeggibili in overview_reports",
                })?;
            rapporti.push(StoredOverviewReport {
                id,
                report: NewOverviewReport {
                    year: i32::try_from(anno).unwrap_or_default(),
                    sequence: u32::try_from(progressivo).unwrap_or_default(),
                    requested_by: chi,
                    requested_at: instant(quando),
                    responsible_name: nome,
                    responsible_role: qualifica,
                    session_ids,
                    manifest_sha256: impronta,
                },
            });
        }
        Ok(rapporti)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::NewAuditEntry;
    use lisi_core::text::{AuditAction, AuditDetail, AuditEntity};

    use super::NewOverviewReport;
    use crate::test_support::{actor, database, now};

    fn audit() -> NewAuditEntry {
        let (Ok(azione), Ok(entita), Ok(dettaglio)) = (
            AuditAction::try_new("rapporto_complessivo_prodotto"),
            AuditEntity::try_new("rapporto"),
            AuditDetail::try_new("prova"),
        ) else {
            panic!("i valori dell'audit di prova devono essere validi");
        };
        NewAuditEntry {
            actor: actor("operatore.prova"),
            action: azione,
            entity: entita,
            entity_id: None,
            actor_mode: None,
            detail: Some(dettaglio),
            recorded_at: now(),
        }
    }

    fn rapporto(progressivo: u32, monitoraggi: Vec<i64>) -> NewOverviewReport {
        NewOverviewReport {
            year: 2026,
            sequence: progressivo,
            requested_by: String::from("operatore.prova"),
            requested_at: now(),
            responsible_name: String::from("Mario Rossi"),
            responsible_role: String::from("Responsabile dell'ufficio"),
            session_ids: monitoraggi,
            manifest_sha256: "d".repeat(64),
        }
    }

    #[test]
    fn un_rapporto_si_registra_e_il_progressivo_avanza() {
        let mut database = database();
        assert_eq!(database.next_overview_sequence(2026).ok(), Some(1));
        let Ok(_) = database.insert_overview_report(&rapporto(1, vec![3, 1]), &audit()) else {
            panic!("il rapporto si deve registrare");
        };
        assert_eq!(database.next_overview_sequence(2026).ok(), Some(2));
        assert_eq!(database.next_overview_sequence(2027).ok(), Some(1));
        assert!(
            database
                .insert_overview_report(&rapporto(1, vec![1, 2]), &audit())
                .is_err(),
            "lo stesso progressivo non si prende due volte"
        );
        assert!(
            database
                .insert_overview_report(&rapporto(2, vec![1]), &audit())
                .is_err(),
            "un monitoraggio solo non fa un rapporto complessivo"
        );
        let Ok(letti) = database.overview_reports(10) else {
            panic!("il registro si deve leggere");
        };
        assert_eq!(letti.len(), 1);
        assert_eq!(letti[0].report, rapporto(1, vec![3, 1]));
        assert!(
            database
                .connection
                .execute("DELETE FROM overview_reports", [])
                .is_err()
        );
    }
}

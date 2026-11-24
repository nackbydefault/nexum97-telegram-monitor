//! Il registro dei pacchetti di evidenze (PR-11, ADR-0127).
//!
//! In sola aggiunta: una riga per pacchetto prodotto. La riga e la sua voce
//! d'audit si scrivono **nella stessa transazione**.

use lisi_core::model::NewAuditEntry;
use lisi_core::{Timestamp, WorkspaceId};

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// Un pacchetto da registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEvidencePackage {
    /// L'identificativo, che è anche il nome della cartella.
    pub package_ref: String,
    /// Da quale workspace.
    pub workspace_id: WorkspaceId,
    /// Chi.
    pub produced_by: String,
    /// Perché.
    pub reason: String,
    /// Quando.
    pub produced_at: Timestamp,
    /// Quanti contenuti.
    pub contents_count: u32,
    /// L'impronta del manifest.
    pub manifest_sha256: String,
}

impl Database {
    /// Registra un pacchetto **e** la sua riga d'audit, insieme.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce; in quel caso non resta
    /// nulla.
    pub fn insert_evidence_package(
        &mut self,
        pacchetto: &NewEvidencePackage,
        audit: &NewAuditEntry,
    ) -> StorageResult<i64> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO evidence_packages (
                 package_ref, workspace_id, produced_by, reason, produced_at, contents_count,
                 manifest_sha256
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                pacchetto.package_ref,
                pacchetto.workspace_id.get(),
                pacchetto.produced_by,
                pacchetto.reason,
                millis(pacchetto.produced_at),
                pacchetto.contents_count,
                pacchetto.manifest_sha256,
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

    /// I pacchetti prodotti da un workspace, dal più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn workspace_evidence_packages(
        &self,
        workspace_id: WorkspaceId,
    ) -> StorageResult<Vec<NewEvidencePackage>> {
        let mut statement = self.connection.prepare(
            "SELECT package_ref, workspace_id, produced_by, reason, produced_at, contents_count,
                    manifest_sha256
             FROM evidence_packages
             WHERE workspace_id = ?1
             ORDER BY produced_at DESC, id DESC",
        )?;
        let righe = statement.query_map([workspace_id.get()], |row| {
            Ok(NewEvidencePackage {
                package_ref: row.get(0)?,
                workspace_id: WorkspaceId::new(row.get(1)?),
                produced_by: row.get(2)?,
                reason: row.get(3)?,
                produced_at: instant(row.get(4)?),
                contents_count: row.get(5)?,
                manifest_sha256: row.get(6)?,
            })
        })?;
        let mut pacchetti = Vec::new();
        for riga in righe {
            pacchetti.push(riga?);
        }
        Ok(pacchetti)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::NewAuditEntry;
    use lisi_core::model::workspace::NewWorkspace;
    use lisi_core::text::{AuditAction, AuditEntity, DisplayName};

    use super::NewEvidencePackage;
    use crate::test_support::{actor, database, later};

    fn audit() -> NewAuditEntry {
        let (Ok(azione), Ok(entita)) = (
            AuditAction::try_new("pacchetto_di_evidenze_prodotto"),
            AuditEntity::try_new("pacchetto"),
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
            recorded_at: later(1),
        }
    }

    /// **Un pacchetto si registra e resta com'è**; un identificativo di altra
    /// forma, o un numero di contenuti fuori misura, non entrano.
    #[test]
    fn un_pacchetto_si_registra_e_resta() {
        let mut archivio = database();
        let Ok(nome) = DisplayName::try_new("Filone di prova") else {
            panic!("nome valido");
        };
        let Ok(workspace) = archivio.insert_workspace(
            &NewWorkspace {
                name: nome,
                description: None,
                created_by: actor("operatore.prova"),
            },
            later(0),
        ) else {
            panic!("il workspace deve aprirsi");
        };
        let pacchetto = NewEvidencePackage {
            package_ref: String::from("PE-20261001-120000"),
            workspace_id: workspace,
            produced_by: String::from("operatore.prova"),
            reason: String::from("richiesta dell'autorità procedente"),
            produced_at: later(1),
            contents_count: 3,
            manifest_sha256: "a".repeat(64),
        };
        let Ok(_) = archivio.insert_evidence_package(&pacchetto, &audit()) else {
            panic!("il pacchetto deve registrarsi");
        };
        let Ok(righe) = archivio.workspace_evidence_packages(workspace) else {
            panic!("il registro deve leggersi");
        };
        assert_eq!(righe, vec![pacchetto.clone()]);
        for comando in [
            "UPDATE evidence_packages SET contents_count = 1",
            "DELETE FROM evidence_packages",
        ] {
            assert!(
                archivio.connection.execute(comando, []).is_err(),
                "{comando}"
            );
        }
        for sbagliato in [
            NewEvidencePackage {
                package_ref: String::from("../../fuori"),
                ..pacchetto.clone()
            },
            NewEvidencePackage {
                package_ref: String::from("PE-20261001-120001"),
                contents_count: 501,
                ..pacchetto.clone()
            },
        ] {
            assert!(
                archivio
                    .insert_evidence_package(&sbagliato, &audit())
                    .is_err()
            );
        }
    }
}

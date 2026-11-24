//! Mitigazioni e rilevazioni di ATT&CK (ATTACK-03, ADR-0185, migrazione
//! 0082). Questo modulo scrive e legge, e basta.

use lisi_core::AttackSnapshotId;
use lisi_core::model::attack::AttackTechniqueId;
use lisi_core::model::attack_guidance::{AttackGuidance, GuidanceKind};

use crate::Database;
use crate::error::{StorageError, StorageResult};

impl Database {
    /// Scrive le mitigazioni e le rilevazioni di una fotografia, con i loro
    /// legami, in una transazione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn insert_attack_guidance(
        &mut self,
        snapshot_id: AttackSnapshotId,
        guidance: &[AttackGuidance],
    ) -> StorageResult<usize> {
        let transazione = self.connection.transaction()?;
        {
            let mut voce = transazione.prepare(
                "INSERT INTO attack_guidance (snapshot_id, guidance_id, kind, name, description)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            let mut legame = transazione.prepare(
                "INSERT OR IGNORE INTO attack_guidance_techniques
                     (snapshot_id, guidance_id, technique_id)
                 VALUES (?1, ?2, ?3)",
            )?;
            for elemento in guidance {
                voce.execute(rusqlite::params![
                    snapshot_id.get(),
                    elemento.id(),
                    elemento.kind().as_str(),
                    elemento.name(),
                    elemento.description(),
                ])?;
                for tecnica in elemento.techniques() {
                    legame.execute(rusqlite::params![
                        snapshot_id.get(),
                        elemento.id(),
                        tecnica.as_str()
                    ])?;
                }
            }
        }
        transazione.commit()?;
        Ok(guidance.len())
    }

    /// Le mitigazioni e le rilevazioni legate a una tecnica, ordinate per
    /// genere e identificativo. Le tecniche a cui si riferiscono non si
    /// rileggono: la scheda è di una tecnica.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga non si
    /// interpreta.
    pub fn attack_guidance_for(
        &self,
        snapshot_id: AttackSnapshotId,
        technique: &AttackTechniqueId,
    ) -> StorageResult<Vec<AttackGuidance>> {
        let mut richiesta = self.connection.prepare(
            "SELECT g.kind, g.guidance_id, g.name, g.description
             FROM attack_guidance_techniques AS l
             JOIN attack_guidance AS g
               ON g.snapshot_id = l.snapshot_id AND g.guidance_id = l.guidance_id
             WHERE l.snapshot_id = ?1 AND l.technique_id = ?2
             ORDER BY g.kind, g.guidance_id",
        )?;
        let righe = richiesta.query_map(
            rusqlite::params![snapshot_id.get(), technique.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )?;
        let mut trovate = Vec::new();
        for riga in righe {
            let (genere, id, nome, descrizione) = riga?;
            let voce = GuidanceKind::from_stored(&genere)
                .and_then(|genere| {
                    AttackGuidance::new(genere, &id, &nome, &descrizione, Vec::new())
                })
                .ok_or(StorageError::CorruptedRow {
                    detail: "una mitigazione o una rilevazione ATT&CK che non si interpreta",
                })?;
            trovate.push(voce);
        }
        Ok(trovate)
    }

    /// Se la fotografia porta mitigazioni e rilevazioni: quelle importate
    /// prima di ATTACK-03 non le hanno (ADR-0185, decisione 4).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn attack_snapshot_has_guidance(
        &self,
        snapshot_id: AttackSnapshotId,
    ) -> StorageResult<bool> {
        Ok(self.connection.query_row(
            "SELECT EXISTS (SELECT 1 FROM attack_guidance WHERE snapshot_id = ?1)",
            [snapshot_id.get()],
            |row| row.get(0),
        )?)
    }
}

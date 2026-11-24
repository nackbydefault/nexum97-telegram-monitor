//! Il punteggio CVSS delle CVE (CVSS-01, ADR-0184, migrazione 0081).
//!
//! Accanto alle voci della fotografia, non dentro: il record della CVE non
//! porta punteggi. Questo modulo scrive e legge, e basta.

use lisi_core::CveSnapshotId;
use lisi_core::model::cve::CveId;
use lisi_core::model::cvss::{CvssScore, CvssVersion};

use crate::Database;
use crate::error::{StorageError, StorageResult};

impl Database {
    /// Scrive i punteggi di una fotografia, in una transazione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn insert_cve_scores(
        &mut self,
        snapshot_id: CveSnapshotId,
        scores: &[(CveId, CvssScore)],
    ) -> StorageResult<usize> {
        if scores.is_empty() {
            return Ok(0);
        }
        let transazione = self.connection.transaction()?;
        let mut scritte = 0_usize;
        {
            let mut richiesta = transazione.prepare(
                "INSERT OR IGNORE INTO cve_scores (
                     snapshot_id, cve_id, version, vector, base_tenths, severity, source
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for (id, punteggio) in scores {
                scritte += richiesta.execute(rusqlite::params![
                    snapshot_id.get(),
                    id.as_str(),
                    punteggio.version().as_str(),
                    punteggio.vector(),
                    punteggio.base_tenths(),
                    punteggio.severity(),
                    punteggio.source(),
                ])?;
            }
        }
        transazione.commit()?;
        Ok(scritte)
    }

    /// Il punteggio di una CVE in una fotografia, se c'è.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se la riga non si
    /// interpreta.
    pub fn cve_score(
        &self,
        snapshot_id: CveSnapshotId,
        id: &CveId,
    ) -> StorageResult<Option<CvssScore>> {
        let riga = self.connection.query_row(
            "SELECT version, vector, base_tenths, severity, source
             FROM cve_scores WHERE snapshot_id = ?1 AND cve_id = ?2",
            rusqlite::params![snapshot_id.get(), id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u8>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        );
        let (versione, vettore, decimi, severita, fonte) = match riga {
            Ok(riga) => riga,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(errore) => return Err(errore.into()),
        };
        let versione = CvssVersion::from_stored(&versione).ok_or(StorageError::CorruptedRow {
            detail: "una versione di CVSS che lo schema non ammette",
        })?;
        CvssScore::try_new(versione, &vettore, decimi, &severita, &fonte)
            .map(Some)
            .map_err(|_| StorageError::CorruptedRow {
                detail: "un punteggio CVSS che non si interpreta",
            })
    }

    /// Se la fotografia porta i punteggi: le fotografie importate prima di
    /// CVSS-01 non li hanno (ADR-0184, decisione 5).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn cve_snapshot_has_scores(&self, snapshot_id: CveSnapshotId) -> StorageResult<bool> {
        Ok(self.connection.query_row(
            "SELECT EXISTS (SELECT 1 FROM cve_scores WHERE snapshot_id = ?1)",
            [snapshot_id.get()],
            |row| row.get(0),
        )?)
    }
}

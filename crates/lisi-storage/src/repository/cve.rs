//! La fotografia locale del catalogo CVE.
//!
//! # La domanda per cui queste tabelle esistono
//!
//! «Che cos'è questo identificativo», chiesto **offline** di un `CVE-…` comparso
//! in un contenuto monitorato.
//!
//! E la risposta ha **tre esiti, non due**: trovata, fuori dalla copertura di
//! questa fotografia, oppure dentro la copertura e assente dal catalogo. La
//! copertura sta in una tabella proprio perché quella distinzione possa
//! esistere (ADR-0060).
//!
//! # Che cosa non si fa, mai
//!
//! Non si contatta nulla. I file arrivano da `scripts/fetch-cve.ps1`, che li
//! scarica e ne verifica l'impronta contro quella che **NVD stessa** dichiara.

use lisi_core::model::cve::{CveCoverage, CveId, CveRecord, CveResolution, CveStatus};
use lisi_core::text::Actor;
use lisi_core::{CveSnapshotId, Timestamp};

use crate::Database;
use crate::error::{StorageError, StorageResult};

/// Un anno acquisito, con l'identità di ciò che è stato preso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquiredYear {
    /// L'anno.
    pub year: i32,
    /// L'impronta che NVD dichiarava per quell'anno, in esadecimale.
    pub source_sha256: String,
    /// L'istante che NVD dichiarava come ultima modifica, nella sua forma.
    pub source_last_modified: String,
}

/// Una fotografia come sta in archivio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCveSnapshot {
    /// Identificatore di riga.
    pub id: CveSnapshotId,
    /// Lo schema della fonte.
    pub source: String,
    /// La designazione di copyright che ogni copia deve riprodurre.
    pub attribution: String,
    /// Chi l'ha importata.
    pub imported_by: Actor,
    /// Quando.
    pub imported_at: Timestamp,
    /// Che cosa copre.
    pub coverage: CveCoverage,
    /// Gli anni acquisiti, con la loro identità.
    pub years: Vec<AcquiredYear>,
    /// Quante voci contiene.
    pub record_count: u64,
}

impl Database {
    /// Apre una fotografia, dichiarandone la copertura.
    ///
    /// # Perché la riga si scrive prima delle voci
    ///
    /// Perché le voci la riferiscono. E perché la riga **non porta conteggi**:
    /// un conteggio andrebbe aggiornato dopo, e una fotografia che si aggiorna
    /// non è immutabile. I conteggi si contano.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn open_cve_snapshot(
        &mut self,
        source: &str,
        attribution: &str,
        years: &[AcquiredYear],
        imported_by: &Actor,
        now: Timestamp,
    ) -> StorageResult<CveSnapshotId> {
        let transaction = self.connection.transaction()?;

        let id: i64 = transaction.query_row(
            "INSERT INTO cve_snapshots (source, attribution, imported_by, imported_at)
             VALUES (?1, ?2, ?3, ?4)
             RETURNING id",
            rusqlite::params![source, attribution, imported_by.as_str(), now.as_millis()],
            |row| row.get(0),
        )?;

        {
            let mut statement = transaction.prepare(
                "INSERT INTO cve_snapshot_years (
                     snapshot_id, year, source_sha256, source_last_modified
                 ) VALUES (?1, ?2, ?3, ?4)",
            )?;
            for anno in years {
                statement.execute(rusqlite::params![
                    id,
                    anno.year,
                    anno.source_sha256.as_str(),
                    anno.source_last_modified.as_str(),
                ])?;
            }
        }

        transaction.commit()?;
        Ok(CveSnapshotId::new(id))
    }

    /// Registra un blocco di voci dentro una fotografia.
    ///
    /// # Perché a blocchi e non tutte insieme
    ///
    /// Perché una fotografia di tre anni ha più di centomila voci, e tenerle
    /// tutte in memoria prima di scriverle costerebbe centinaia di megabyte
    /// senza guadagnare nulla. Ogni blocco è una transazione: un'interruzione
    /// lascia una fotografia incompleta, che si riconosce dal conteggio e si
    /// rifà.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn insert_cve_records(
        &mut self,
        snapshot_id: CveSnapshotId,
        records: &[CveRecord],
    ) -> StorageResult<usize> {
        if records.is_empty() {
            return Ok(0);
        }

        let transaction = self.connection.transaction()?;
        let mut scritte = 0_usize;
        {
            let mut statement = transaction.prepare(
                "INSERT OR IGNORE INTO cve_records (
                     snapshot_id, cve_id, description, published, last_modified, status
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for record in records {
                scritte += statement.execute(rusqlite::params![
                    snapshot_id.get(),
                    record.id().as_str(),
                    record.description(),
                    record.published(),
                    record.last_modified(),
                    record.status().as_str(),
                ])?;
            }
        }
        transaction.commit()?;
        Ok(scritte)
    }

    /// Le fotografie in archivio, dalla più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga non è più
    /// interpretabile.
    pub fn cve_snapshots(&self) -> StorageResult<Vec<StoredCveSnapshot>> {
        let mut statement = self.connection.prepare(
            "SELECT id, source, attribution, imported_by, imported_at
             FROM cve_snapshots
             ORDER BY imported_at DESC, id DESC",
        )?;
        let righe = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;

        let mut trovate = Vec::new();
        for riga in righe {
            let (id, source, attribution, imported_by, imported_at) = riga?;
            let Ok(imported_by) = Actor::try_new(&imported_by) else {
                return Err(StorageError::CorruptedRow {
                    detail: "operatore della fotografia CVE non interpretabile",
                });
            };
            let id = CveSnapshotId::new(id);
            let years = self.cve_snapshot_years(id)?;
            let Ok(coverage) = CveCoverage::new(years.iter().map(|anno| anno.year).collect())
            else {
                return Err(StorageError::CorruptedRow {
                    detail: "una fotografia CVE senza copertura non è interpretabile",
                });
            };

            trovate.push(StoredCveSnapshot {
                id,
                source,
                attribution,
                imported_by,
                imported_at: Timestamp::from_millis(imported_at),
                coverage,
                years,
                record_count: self.cve_record_count(id)?,
            });
        }
        Ok(trovate)
    }

    /// Gli anni acquisiti da una fotografia, in ordine.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn cve_snapshot_years(
        &self,
        snapshot_id: CveSnapshotId,
    ) -> StorageResult<Vec<AcquiredYear>> {
        let mut statement = self.connection.prepare(
            "SELECT year, source_sha256, source_last_modified
             FROM cve_snapshot_years
             WHERE snapshot_id = ?1
             ORDER BY year",
        )?;
        let righe = statement.query_map(rusqlite::params![snapshot_id.get()], |row| {
            Ok(AcquiredYear {
                year: row.get::<_, i64>(0)?.try_into().unwrap_or(0),
                source_sha256: row.get(1)?,
                source_last_modified: row.get(2)?,
            })
        })?;

        let mut trovati = Vec::new();
        for riga in righe {
            trovati.push(riga?);
        }
        Ok(trovati)
    }

    /// Quante voci contiene una fotografia.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il conteggio non riesce.
    pub fn cve_record_count(&self, snapshot_id: CveSnapshotId) -> StorageResult<u64> {
        let quante: i64 = self.connection.query_row(
            "SELECT count(*) FROM cve_records WHERE snapshot_id = ?1",
            rusqlite::params![snapshot_id.get()],
            |row| row.get(0),
        )?;
        Ok(u64::try_from(quante).unwrap_or(0))
    }

    /// Risolve un identificativo dentro una fotografia.
    ///
    /// # Perché la copertura si legge prima del catalogo
    ///
    /// Perché è la copertura a decidere **quale delle due assenze** sia vera.
    /// Cercare prima nel catalogo e dedurre l'esito dal fallimento produrrebbe
    /// un solo «non trovata», che è esattamente ciò che questa milestone esiste
    /// per non dire.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga non è più
    /// interpretabile.
    pub fn resolve_cve(
        &self,
        snapshot_id: CveSnapshotId,
        id: &CveId,
    ) -> StorageResult<CveResolution> {
        let years = self.cve_snapshot_years(snapshot_id)?;
        let Ok(coverage) = CveCoverage::new(years.iter().map(|anno| anno.year).collect()) else {
            return Err(StorageError::CorruptedRow {
                detail: "una fotografia CVE senza copertura non è interpretabile",
            });
        };

        if !coverage.covers(id) {
            return Ok(CveResolution::OutsideCoverage { coverage });
        }

        let trovata = self
            .connection
            .query_row(
                "SELECT description, published, last_modified, status
                 FROM cve_records
                 WHERE snapshot_id = ?1 AND cve_id = ?2",
                rusqlite::params![snapshot_id.get(), id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;

        let Some((description, published, last_modified, status)) = trovata else {
            return Ok(CveResolution::AbsentFromCatalogue { coverage });
        };

        let (Ok(status), Ok(record_id)) =
            (CveStatus::try_new(&status), CveId::try_new(id.as_str()))
        else {
            return Err(StorageError::CorruptedRow {
                detail: "voce di una fotografia CVE non interpretabile",
            });
        };
        let Ok(record) =
            CveRecord::new(record_id, &description, &published, &last_modified, status)
        else {
            return Err(StorageError::CorruptedRow {
                detail: "voce di una fotografia CVE non ricomponibile",
            });
        };

        Ok(CveResolution::Found(Box::new(record)))
    }
}

use rusqlite::OptionalExtension as _;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::database;

    fn attore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn identificativo(raw: &str) -> CveId {
        let Ok(id) = CveId::try_new(raw) else {
            panic!("l'identificativo di prova deve essere valido");
        };
        id
    }

    fn record(id: &str, stato: &str) -> CveRecord {
        let Ok(status) = CveStatus::try_new(stato) else {
            panic!("lo stato di prova deve essere valido");
        };
        let Ok(record) = CveRecord::new(
            identificativo(id),
            "una descrizione intera, come NVD la pubblica",
            "2026-01-11T05:00:00.000",
            "2026-06-16T22:01:26.443",
            status,
        ) else {
            panic!("il record di prova deve essere valido");
        };
        record
    }

    fn anno(year: i32) -> AcquiredYear {
        AcquiredYear {
            year,
            source_sha256: String::from(
                "1eb592ab51a51f6a0d08b672b66c0f4d13d5f97e86bd233c0f3d22071cfa2c8e",
            ),
            source_last_modified: String::from("2026-09-10T03:00:15-04:00"),
        }
    }

    /// Archivio con una fotografia che copre 2025 e 2026 e contiene due voci.
    fn archivio() -> (Database, CveSnapshotId) {
        let mut database = database();
        let Ok(id) = database.open_cve_snapshot(
            "NVD_CVE 2.0",
            "© 2026 The MITRE Corporation.",
            &[anno(2025), anno(2026)],
            &attore(),
            Timestamp::from_millis(1_757_000_000_000),
        ) else {
            panic!("la fotografia deve potersi aprire");
        };
        let Ok(scritte) = database.insert_cve_records(
            id,
            &[
                record("CVE-2026-1234", "Analyzed"),
                record("CVE-2026-5678", CveStatus::REJECTED),
            ],
        ) else {
            panic!("le voci devono potersi registrare");
        };
        assert_eq!(scritte, 2);
        (database, id)
    }

    #[test]
    fn una_fotografia_si_apre_e_si_rilegge() {
        let (database, id) = archivio();
        let Ok(fotografie) = database.cve_snapshots() else {
            panic!("le fotografie devono potersi rileggere");
        };
        assert_eq!(fotografie.len(), 1);
        assert_eq!(fotografie[0].id, id);
        assert_eq!(fotografie[0].record_count, 2);
        assert_eq!(fotografie[0].coverage.years(), &[2025, 2026]);
        assert!(fotografie[0].attribution.contains("MITRE"));
        assert_eq!(fotografie[0].years.len(), 2);
    }

    /// **Trovata.**
    #[test]
    fn un_identificativo_presente_si_trova() {
        let (database, id) = archivio();
        let Ok(esito) = database.resolve_cve(id, &identificativo("CVE-2026-1234")) else {
            panic!("la risoluzione deve riuscire");
        };
        let CveResolution::Found(record) = esito else {
            panic!("la voce doveva essere trovata");
        };
        assert_eq!(
            record.description(),
            "una descrizione intera, come NVD la pubblica"
        );
        assert!(!record.status().is_rejected());
    }

    /// **Fuori copertura: non lo so.**
    #[test]
    fn un_identificativo_di_un_anno_non_coperto_e_fuori_copertura() {
        let (database, id) = archivio();
        let Ok(esito) = database.resolve_cve(id, &identificativo("CVE-2019-1234")) else {
            panic!("la risoluzione deve riuscire");
        };
        let CveResolution::OutsideCoverage { coverage } = esito else {
            panic!("l'esito doveva essere «fuori copertura»");
        };
        assert_eq!(coverage.years(), &[2025, 2026]);
    }

    /// **Assente dal catalogo: NVD non ha una CVE con questo numero.**
    ///
    /// È l'esito che si perderebbe se ce ne fosse uno solo, ed è quello che
    /// permette di riconoscere un identificativo inventato.
    #[test]
    fn un_identificativo_coperto_e_assente_e_assente_dal_catalogo() {
        let (database, id) = archivio();
        let Ok(esito) = database.resolve_cve(id, &identificativo("CVE-2026-9999")) else {
            panic!("la risoluzione deve riuscire");
        };
        let CveResolution::AbsentFromCatalogue { coverage } = esito else {
            panic!("l'esito doveva essere «assente dal catalogo»");
        };
        assert_eq!(coverage.years(), &[2025, 2026]);
    }

    /// Una voce ritirata si trova, e porta il proprio stato.
    #[test]
    fn una_voce_ritirata_si_trova_e_dichiara_lo_stato() {
        let (database, id) = archivio();
        let Ok(esito) = database.resolve_cve(id, &identificativo("CVE-2026-5678")) else {
            panic!("la risoluzione deve riuscire");
        };
        let CveResolution::Found(record) = esito else {
            panic!("la voce ritirata doveva comunque essere trovata");
        };
        assert!(record.status().is_rejected());
    }

    /// Registrare due volte non duplica.
    #[test]
    fn registrare_due_volte_non_duplica() {
        let (mut database, id) = archivio();
        let Ok(seconde) = database.insert_cve_records(id, &[record("CVE-2026-1234", "Analyzed")])
        else {
            panic!("la seconda registrazione deve riuscire");
        };
        assert_eq!(seconde, 0);
        let Ok(quante) = database.cve_record_count(id) else {
            panic!("il conteggio deve riuscire");
        };
        assert_eq!(quante, 2);
    }

    /// **Una fotografia non si modifica e non si cancella.**
    #[test]
    fn una_fotografia_non_si_modifica_ne_si_cancella() {
        let (database, _) = archivio();
        for sql in [
            "UPDATE cve_snapshots SET attribution = 'nessuna'",
            "DELETE FROM cve_snapshots",
            "UPDATE cve_snapshot_years SET year = 1999",
            "DELETE FROM cve_snapshot_years",
            "UPDATE cve_records SET description = 'altro'",
            "DELETE FROM cve_records",
        ] {
            assert!(
                database.connection.execute(sql, []).is_err(),
                "«{sql}» non doveva essere ammesso"
            );
        }
    }

    /// **Lo schema rifiuta una fotografia senza attribuzione.**
    #[test]
    fn lo_schema_rifiuta_una_fotografia_senza_attribuzione() {
        let database = database();
        assert!(
            database
                .connection
                .execute(
                    "INSERT INTO cve_snapshots (source, attribution, imported_by, imported_at)
                     VALUES ('NVD_CVE 2.0', '   ', 'operatore', 1)",
                    [],
                )
                .is_err(),
            "l'attribuzione vuota non doveva essere ammessa"
        );
    }
}

//! La fotografia locale di MITRE ATT&CK.
//!
//! # Che cosa si conserva, e che cosa no
//!
//! Le **tecniche** e le **tattiche**. Non i gruppi di attaccanti, non le
//! campagne, non i malware, non gli strumenti: sono attori, e questo prodotto
//! non attribuisce (ADR-0058). Non esiste una tabella in cui metterli, ed è la
//! forma più forte della garanzia — ciò che non entra non può essere mostrato
//! per errore.
//!
//! # Che cosa non si fa, mai
//!
//! Non si contatta nulla. Il pacchetto arriva da un file che qualcun altro ha
//! scaricato e verificato (`scripts/fetch-attack.ps1`): questo modulo legge e
//! scrive righe, e non ha accesso alla rete.

use lisi_core::model::attack::{
    AttackSnapshot, AttackTactic, AttackTacticId, AttackTechnique, AttackTechniqueId,
    NewAttackTechnique,
};
use lisi_core::text::Actor;
use lisi_core::{AttackSnapshotId, Sha256Digest, Timestamp};

use crate::Database;
use crate::error::{ConstraintKind, StorageError, StorageResult, constraint_kind};

/// Una fotografia come sta in archivio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAttackSnapshot {
    /// Identificatore di riga.
    pub id: AttackSnapshotId,
    /// Il dominio ATT&CK.
    pub domain: String,
    /// La versione di ATT&CK, per esempio `19.2`.
    pub attack_version: String,
    /// La versione della specifica ATT&CK.
    pub spec_version: String,
    /// L'impronta del file da cui è stata importata.
    pub source_sha256: Sha256Digest,
    /// La designazione di copyright che ogni copia deve riprodurre.
    pub attribution: String,
    /// Chi l'ha importata.
    pub imported_by: Actor,
    /// Quando.
    pub imported_at: Timestamp,
    /// Quante tecniche contiene.
    pub technique_count: u32,
    /// Quante tattiche contiene.
    pub tactic_count: u32,
}

impl Database {
    /// Registra una fotografia, con le sue tattiche e le sue tecniche.
    ///
    /// # Perché tutto in una transazione
    ///
    /// Perché una fotografia con metà delle proprie tecniche risponderebbe
    /// «quella tecnica non c'è» a una domanda a cui ATT&CK risponde di sì, e
    /// nulla lo segnalerebbe. O entra intera o non entra.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::DuplicateAttackSnapshot`] se una fotografia
    /// della stessa versione è già in archivio, o un errore se la scrittura non
    /// riesce.
    pub fn insert_attack_snapshot(
        &mut self,
        snapshot: &AttackSnapshot,
        source_sha256: &Sha256Digest,
        imported_by: &Actor,
        now: Timestamp,
    ) -> StorageResult<AttackSnapshotId> {
        let technique_count = i64::try_from(snapshot.techniques().len()).unwrap_or(i64::MAX);
        let tactic_count = i64::try_from(snapshot.tactics().len()).unwrap_or(i64::MAX);

        let transaction = self.connection.transaction()?;

        let snapshot_id: i64 = transaction
            .query_row(
                "INSERT INTO attack_snapshots (
                     domain, attack_version, spec_version, source_sha256,
                     attribution, license_text, imported_by, imported_at,
                     technique_count, tactic_count
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 RETURNING id",
                rusqlite::params![
                    snapshot.domain(),
                    snapshot.attack_version(),
                    snapshot.spec_version(),
                    source_sha256.as_str(),
                    snapshot.attribution(),
                    snapshot.license_text(),
                    imported_by.as_str(),
                    now.as_millis(),
                    technique_count,
                    tactic_count,
                ],
                |row| row.get(0),
            )
            .map_err(|error| match constraint_kind(&error) {
                Some(ConstraintKind::Unique) => StorageError::DuplicateAttackSnapshot,
                _ => StorageError::Sqlite(error),
            })?;

        {
            let mut tattica = transaction.prepare(
                "INSERT INTO attack_tactics (
                     snapshot_id, tactic_id, shortname, name, description
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for tactic in snapshot.tactics() {
                tattica.execute(rusqlite::params![
                    snapshot_id,
                    tactic.id().as_str(),
                    tactic.shortname(),
                    tactic.name(),
                    tactic.description(),
                ])?;
            }

            let mut tecnica = transaction.prepare(
                "INSERT INTO attack_techniques (
                     snapshot_id, technique_id, name, description,
                     is_subtechnique, deprecated, revoked, object_version, url
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;
            let mut legame = transaction.prepare(
                "INSERT INTO attack_technique_tactics (
                     snapshot_id, technique_id, tactic_shortname
                 ) VALUES (?1, ?2, ?3)",
            )?;

            for technique in snapshot.techniques() {
                tecnica.execute(rusqlite::params![
                    snapshot_id,
                    technique.id().as_str(),
                    technique.name(),
                    technique.description(),
                    i64::from(technique.id().is_subtechnique()),
                    i64::from(technique.is_deprecated()),
                    i64::from(technique.is_revoked()),
                    technique.object_version(),
                    technique.url(),
                ])?;

                for tactic in technique.tactics() {
                    legame.execute(rusqlite::params![
                        snapshot_id,
                        technique.id().as_str(),
                        tactic,
                    ])?;
                }
            }
        }

        transaction.commit()?;
        Ok(AttackSnapshotId::new(snapshot_id))
    }

    /// Le fotografie in archivio, dalla più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga non è
    /// interpretabile.
    pub fn attack_snapshots(&self) -> StorageResult<Vec<StoredAttackSnapshot>> {
        let mut statement = self.connection.prepare(
            "SELECT id, domain, attack_version, spec_version, source_sha256,
                    attribution, imported_by, imported_at,
                    technique_count, tactic_count
             FROM attack_snapshots
             ORDER BY imported_at DESC, id DESC",
        )?;
        let righe = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
            ))
        })?;

        let mut trovate = Vec::new();
        for riga in righe {
            let (
                id,
                domain,
                attack_version,
                spec_version,
                sha256,
                attribution,
                imported_by,
                imported_at,
                technique_count,
                tactic_count,
            ) = riga?;

            let Ok(source_sha256) = Sha256Digest::from_hex(&sha256) else {
                return Err(StorageError::CorruptedRow {
                    detail: "impronta della fotografia ATT&CK non interpretabile",
                });
            };
            let Ok(imported_by) = Actor::try_new(&imported_by) else {
                return Err(StorageError::CorruptedRow {
                    detail: "operatore della fotografia ATT&CK non interpretabile",
                });
            };

            trovate.push(StoredAttackSnapshot {
                id: AttackSnapshotId::new(id),
                domain,
                attack_version,
                spec_version,
                source_sha256,
                attribution,
                imported_by,
                imported_at: Timestamp::from_millis(imported_at),
                technique_count: u32::try_from(technique_count).unwrap_or(0),
                tactic_count: u32::try_from(tactic_count).unwrap_or(0),
            });
        }
        Ok(trovate)
    }

    /// Le tecniche di una fotografia, in ordine stabile.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga porta un
    /// identificativo che il dominio non riconosce più.
    pub fn attack_techniques(
        &self,
        snapshot_id: AttackSnapshotId,
    ) -> StorageResult<Vec<AttackTechnique>> {
        let mut statement = self.connection.prepare(
            "SELECT t.technique_id, t.name, t.description, t.deprecated,
                    t.revoked, t.object_version, t.url,
                    (SELECT group_concat(l.tactic_shortname, char(31))
                     FROM attack_technique_tactics AS l
                     WHERE l.snapshot_id = t.snapshot_id
                       AND l.technique_id = t.technique_id)
             FROM attack_techniques AS t
             WHERE t.snapshot_id = ?1
             ORDER BY t.technique_id",
        )?;
        let righe = statement.query_map(rusqlite::params![snapshot_id.get()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
            ))
        })?;

        let mut trovate = Vec::new();
        for riga in righe {
            let (id, name, description, deprecated, revoked, object_version, url, tactics) = riga?;

            let Ok(id) = AttackTechniqueId::try_new(&id) else {
                return Err(StorageError::CorruptedRow {
                    detail: "identificativo di tecnica ATT&CK non interpretabile",
                });
            };
            // Il separatore e' l'unita' di informazione US (0x1F), che non
            // compare in un nome breve di tattica: una virgola invece si',
            // e un giorno spezzerebbe un nome a meta' senza che nulla lo dica.
            let tactics: Vec<String> = tactics
                .unwrap_or_default()
                .split('\u{1f}')
                .filter(|tactic| !tactic.is_empty())
                .map(String::from)
                .collect();

            let Ok(technique) = AttackTechnique::new(NewAttackTechnique {
                id,
                name: &name,
                description: &description,
                tactics,
                deprecated: deprecated != 0,
                revoked: revoked != 0,
                object_version: &object_version,
                url: &url,
            }) else {
                return Err(StorageError::CorruptedRow {
                    detail: "tecnica ATT&CK non interpretabile",
                });
            };
            trovate.push(technique);
        }
        Ok(trovate)
    }

    /// Le tattiche di una fotografia, in ordine stabile.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga non è
    /// interpretabile.
    pub fn attack_tactics(
        &self,
        snapshot_id: AttackSnapshotId,
    ) -> StorageResult<Vec<AttackTactic>> {
        let mut statement = self.connection.prepare(
            "SELECT tactic_id, shortname, name, description
             FROM attack_tactics
             WHERE snapshot_id = ?1
             ORDER BY tactic_id",
        )?;
        let righe = statement.query_map(rusqlite::params![snapshot_id.get()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;

        let mut trovate = Vec::new();
        for riga in righe {
            let (id, shortname, name, description) = riga?;
            let Ok(id) = AttackTacticId::try_new(&id) else {
                return Err(StorageError::CorruptedRow {
                    detail: "identificativo di tattica ATT&CK non interpretabile",
                });
            };
            let Ok(tactic) = AttackTactic::new(id, &shortname, &name, &description) else {
                return Err(StorageError::CorruptedRow {
                    detail: "tattica ATT&CK non interpretabile",
                });
            };
            trovate.push(tactic);
        }
        Ok(trovate)
    }
}

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

    fn fotografia(versione: &str) -> AttackSnapshot {
        let Ok(tactic_id) = AttackTacticId::try_new("TA0002") else {
            panic!("l'identificativo di prova deve essere valido");
        };
        let Ok(tactic) = AttackTactic::new(tactic_id, "execution", "Execution", "descrizione")
        else {
            panic!("la tattica di prova deve essere valida");
        };
        let Ok(technique_id) = AttackTechniqueId::try_new("T1059.001") else {
            panic!("l'identificativo di prova deve essere valido");
        };
        let Ok(technique) = AttackTechnique::new(NewAttackTechnique {
            id: technique_id,
            name: "PowerShell",
            description: "descrizione della tecnica",
            tactics: vec![String::from("execution")],
            deprecated: false,
            revoked: false,
            object_version: "2.0",
            url: "https://attack.mitre.org/techniques/T1059/001",
        }) else {
            panic!("la tecnica di prova deve essere valida");
        };
        let Ok(snapshot) = AttackSnapshot::new(
            "enterprise-attack",
            versione,
            "3.3.0",
            "License\n-------\n…",
            vec![tactic],
            vec![technique],
        ) else {
            panic!("la fotografia di prova deve essere valida");
        };
        snapshot
    }

    fn impronta() -> Sha256Digest {
        Sha256Digest::of_text("pacchetto di prova")
    }

    #[test]
    fn una_fotografia_si_scrive_e_si_rilegge() {
        let mut database = database();
        let Ok(id) = database.insert_attack_snapshot(
            &fotografia("19.2"),
            &impronta(),
            &attore(),
            Timestamp::from_millis(1_757_000_000_000),
        ) else {
            panic!("la fotografia deve potersi registrare");
        };

        let Ok(fotografie) = database.attack_snapshots() else {
            panic!("le fotografie devono potersi rileggere");
        };
        assert_eq!(fotografie.len(), 1);
        assert_eq!(fotografie[0].attack_version, "19.2");
        assert_eq!(fotografie[0].technique_count, 1);
        assert!(fotografie[0].attribution.contains("MITRE"));

        let Ok(tecniche) = database.attack_techniques(id) else {
            panic!("le tecniche devono potersi rileggere");
        };
        assert_eq!(tecniche.len(), 1);
        assert_eq!(tecniche[0].id().as_str(), "T1059.001");
        assert_eq!(tecniche[0].tactics(), &[String::from("execution")]);

        let Ok(tattiche) = database.attack_tactics(id) else {
            panic!("le tattiche devono potersi rileggere");
        };
        assert_eq!(tattiche.len(), 1);
        assert_eq!(tattiche[0].shortname(), "execution");
    }

    /// **La stessa versione non si importa due volte.**
    #[test]
    fn la_stessa_versione_non_si_importa_due_volte() {
        let mut database = database();
        let ora = Timestamp::from_millis(1_757_000_000_000);
        let Ok(_) =
            database.insert_attack_snapshot(&fotografia("19.2"), &impronta(), &attore(), ora)
        else {
            panic!("la prima importazione deve riuscire");
        };

        assert!(matches!(
            database.insert_attack_snapshot(&fotografia("19.2"), &impronta(), &attore(), ora),
            Err(StorageError::DuplicateAttackSnapshot)
        ));
    }

    /// **Due versioni convivono**: importare la nuova non toglie la vecchia.
    ///
    /// Un atto prodotto sei mesi fa cita una tecnica come la conosceva quella
    /// versione, e cancellarla renderebbe illeggibile ciò che fu scritto.
    #[test]
    fn due_versioni_convivono() {
        let mut database = database();
        let ora = Timestamp::from_millis(1_757_000_000_000);
        let Ok(_) =
            database.insert_attack_snapshot(&fotografia("19.2"), &impronta(), &attore(), ora)
        else {
            panic!("la prima importazione deve riuscire");
        };
        let Ok(_) = database.insert_attack_snapshot(
            &fotografia("20.0"),
            &impronta(),
            &attore(),
            ora.plus_seconds(60),
        ) else {
            panic!("la seconda importazione deve riuscire");
        };

        let Ok(fotografie) = database.attack_snapshots() else {
            panic!("le fotografie devono potersi rileggere");
        };
        assert_eq!(fotografie.len(), 2);
        assert_eq!(fotografie[0].attack_version, "20.0");
        assert_eq!(fotografie[1].attack_version, "19.2");
    }

    /// **Una fotografia non si modifica e non si cancella.**
    #[test]
    fn una_fotografia_non_si_modifica_ne_si_cancella() {
        let mut database = database();
        let Ok(_) = database.insert_attack_snapshot(
            &fotografia("19.2"),
            &impronta(),
            &attore(),
            Timestamp::from_millis(1_757_000_000_000),
        ) else {
            panic!("la fotografia deve potersi registrare");
        };

        for sql in [
            "UPDATE attack_snapshots SET attribution = 'nessuna'",
            "DELETE FROM attack_snapshots",
            "UPDATE attack_techniques SET name = 'altro'",
            "DELETE FROM attack_techniques",
            "UPDATE attack_tactics SET name = 'altro'",
            "DELETE FROM attack_tactics",
            "UPDATE attack_technique_tactics SET tactic_shortname = 'altro'",
            "DELETE FROM attack_technique_tactics",
        ] {
            assert!(
                database.connection.execute(sql, []).is_err(),
                "«{sql}» non doveva essere ammesso"
            );
        }
    }

    /// **Una fotografia senza attribuzione non entra nemmeno per via diretta.**
    ///
    /// Il dominio la rifiuta prima; questa guardia sta nello schema, e vale
    /// anche per chi scrivesse in archivio senza passare dal dominio.
    #[test]
    fn lo_schema_rifiuta_una_fotografia_senza_attribuzione() {
        let database = database();
        assert!(
            database
                .connection
                .execute(
                    "INSERT INTO attack_snapshots (
                         domain, attack_version, spec_version, source_sha256,
                         attribution, license_text, imported_by, imported_at,
                         technique_count, tactic_count
                     ) VALUES ('enterprise-attack', '19.2', '3.3.0',
                               'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                               '   ', 'licenza', 'operatore', 1, 1, 1)",
                    [],
                )
                .is_err(),
            "l'attribuzione vuota non doveva essere ammessa"
        );
    }
}

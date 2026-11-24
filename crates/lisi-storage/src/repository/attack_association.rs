//! Le associazioni fra un termine e una tecnica ATT&CK.
//!
//! # Che cosa questo modulo fa, e che cosa non fa
//!
//! Registra **atti**: una dichiarazione, un ritiro. Non cerca tecniche, non ne
//! propone, non ne ordina per verosimiglianza: l'identificativo lo scrive una
//! persona (ADR-0059).
//!
//! # La domanda per cui la tabella esiste
//!
//! «Quali tecniche riguardano **questo contenuto**». Si risponde partendo dai
//! riscontri, che registrano il termine normalizzato e la sua categoria — e
//! l'associazione usa **quella stessa coppia**, così che le due cose combacino
//! senza che nessuno debba indovinare.

use lisi_core::model::attack::AttackTechniqueId;
use lisi_core::model::attack_association::{
    AssociatedTerm, AttackAssociationWithdrawal, NewAttackAssociation, StandingAssociation,
    StandingAssociationParts,
};
use lisi_core::text::Actor;
use lisi_core::{AttackAssociationId, AttackSnapshotId, ContentId};

use crate::Database;
use crate::error::{ConstraintKind, StorageError, StorageResult, constraint_kind};

impl Database {
    /// Registra la dichiarazione di un'associazione.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::DuplicateAttackAssociation`] se lo stesso
    /// legame è già dichiarato **e in piedi**, [`StorageError::NotFound`] se la
    /// tecnica non esiste dentro quella fotografia, o un errore se la scrittura
    /// non riesce.
    pub fn declare_attack_association(
        &mut self,
        snapshot_id: AttackSnapshotId,
        association: &NewAttackAssociation,
    ) -> StorageResult<AttackAssociationId> {
        // DUE DICHIARAZIONI CONTEMPORANEE DELLO STESSO LEGAME NON AGGIUNGONO
        // NULLA, e rendono ambiguo quale motivo valga. Ridichiarare DOPO un
        // ritiro invece si puo': sono due atti, in due momenti, con due motivi.
        if self.standing_association_exists(snapshot_id, association)? {
            return Err(StorageError::DuplicateAttackAssociation);
        }

        let id: i64 = self
            .connection
            .query_row(
                "INSERT INTO attack_term_associations (
                     term_normalised, term_category, snapshot_id, technique_id,
                     reason, declared_by, declared_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 RETURNING id",
                rusqlite::params![
                    association.term.normalised(),
                    association.term.category(),
                    snapshot_id.get(),
                    association.technique.as_str(),
                    association.reason.as_str(),
                    association.declared_by.as_str(),
                    association.declared_at.as_millis(),
                ],
                |row| row.get(0),
            )
            .map_err(|error| match constraint_kind(&error) {
                Some(ConstraintKind::ForeignKey) => StorageError::NotFound {
                    entity: "tecnica ATT&CK in questa fotografia",
                    id: snapshot_id.get(),
                },
                _ => StorageError::Sqlite(error),
            })?;

        Ok(AttackAssociationId::new(id))
    }

    /// Se lo stesso legame è già dichiarato e non ritirato.
    fn standing_association_exists(
        &self,
        snapshot_id: AttackSnapshotId,
        association: &NewAttackAssociation,
    ) -> StorageResult<bool> {
        let quante: i64 = self.connection.query_row(
            "SELECT count(*)
             FROM attack_term_associations AS a
             WHERE a.term_normalised = ?1
               AND a.term_category = ?2
               AND a.snapshot_id = ?3
               AND a.technique_id = ?4
               AND NOT EXISTS (
                   SELECT 1 FROM attack_association_withdrawals AS w
                   WHERE w.association_id = a.id
               )",
            rusqlite::params![
                association.term.normalised(),
                association.term.category(),
                snapshot_id.get(),
                association.technique.as_str(),
            ],
            |row| row.get(0),
        )?;
        Ok(quante > 0)
    }

    /// Registra il ritiro di un'associazione.
    ///
    /// # Perché un ritiro non è una cancellazione
    ///
    /// Perché un legame sciolto in silenzio non dice se fosse sbagliato o
    /// scomodo, e cancellarlo renderebbe illeggibili i rapporti che lo
    /// citavano.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se l'associazione non esiste,
    /// e un errore se era già ritirata o se la scrittura non riesce.
    pub fn withdraw_attack_association(
        &mut self,
        association_id: AttackAssociationId,
        withdrawal: &AttackAssociationWithdrawal,
    ) -> StorageResult<()> {
        let scritte = self
            .connection
            .execute(
                "INSERT INTO attack_association_withdrawals (
                     association_id, reason, withdrawn_by, withdrawn_at
                 ) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    association_id.get(),
                    withdrawal.reason.as_str(),
                    withdrawal.withdrawn_by.as_str(),
                    withdrawal.withdrawn_at.as_millis(),
                ],
            )
            .map_err(|error| match constraint_kind(&error) {
                Some(ConstraintKind::ForeignKey) => StorageError::NotFound {
                    entity: "associazione con una tecnica",
                    id: association_id.get(),
                },
                // La chiave primaria impone che si ritiri una volta sola.
                Some(ConstraintKind::Unique) => StorageError::DuplicateAttackAssociation,
                _ => StorageError::Sqlite(error),
            })?;

        if scritte == 0 {
            return Err(StorageError::NotFound {
                entity: "associazione con una tecnica",
                id: association_id.get(),
            });
        }
        Ok(())
    }

    /// Le associazioni in piedi di un termine, in ordine stabile.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga non è più
    /// interpretabile.
    pub fn standing_associations_for_term(
        &self,
        term: &AssociatedTerm,
    ) -> StorageResult<Vec<StandingAssociation>> {
        self.read_standing(
            "WHERE a.term_normalised = ?1 AND a.term_category = ?2",
            rusqlite::params![term.normalised(), term.category()],
        )
    }

    /// Le associazioni in piedi dei termini che un contenuto ha riscontrato.
    ///
    /// # Perché si parte dai riscontri
    ///
    /// Perché è ciò che il contenuto **ha davvero**: un riscontro registra il
    /// termine normalizzato e la sua categoria, e l'associazione usa la stessa
    /// coppia. Nessun passaggio intermedio, nessuna ricostruzione, niente da
    /// indovinare.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga non è più
    /// interpretabile.
    pub fn standing_associations_for_content(
        &self,
        content_id: ContentId,
    ) -> StorageResult<Vec<StandingAssociation>> {
        self.read_standing(
            "WHERE EXISTS (
                 SELECT 1 FROM matches AS m
                 WHERE m.content_id = ?1
                   AND m.rule_id = a.term_normalised
                   AND m.rule_category = a.term_category
             )",
            rusqlite::params![content_id.get()],
        )
    }

    /// Legge le associazioni in piedi che soddisfano il filtro indicato.
    ///
    /// Il filtro è una **costante del sorgente**, mai un dato d'ingresso: i
    /// valori passano dai parametri.
    fn read_standing(
        &self,
        filtro: &str,
        parametri: &[&dyn rusqlite::ToSql],
    ) -> StorageResult<Vec<StandingAssociation>> {
        let sql = format!(
            "SELECT a.id, a.term_normalised, a.term_category, a.technique_id,
                    t.name, s.attack_version, t.deprecated, t.revoked,
                    a.reason, a.declared_by, a.declared_at
             FROM attack_term_associations AS a
             JOIN attack_snapshots AS s ON s.id = a.snapshot_id
             JOIN attack_techniques AS t
               ON t.snapshot_id = a.snapshot_id AND t.technique_id = a.technique_id
             {filtro}
               AND NOT EXISTS (
                   SELECT 1 FROM attack_association_withdrawals AS w
                   WHERE w.association_id = a.id
               )
             ORDER BY a.term_normalised, a.technique_id, a.declared_at"
        );

        let mut statement = self.connection.prepare(&sql)?;
        let righe = statement.query_map(parametri, |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, i64>(10)?,
            ))
        })?;

        let mut trovate = Vec::new();
        for riga in righe {
            let (
                id,
                normalised,
                category,
                technique_id,
                technique_name,
                attack_version,
                deprecated,
                revoked,
                reason,
                declared_by,
                declared_at,
            ) = riga?;

            let (Ok(term), Ok(technique), Ok(declared_by)) = (
                AssociatedTerm::new(&normalised, &category),
                AttackTechniqueId::try_new(&technique_id),
                Actor::try_new(&declared_by),
            ) else {
                return Err(StorageError::CorruptedRow {
                    detail: "associazione con una tecnica ATT&CK non interpretabile",
                });
            };

            let Ok(association) = StandingAssociation::new(StandingAssociationParts {
                id: AttackAssociationId::new(id),
                term,
                technique,
                technique_name,
                attack_version,
                deprecated: deprecated != 0,
                revoked: revoked != 0,
                reason,
                declared_by,
                declared_at: lisi_core::Timestamp::from_millis(declared_at),
            }) else {
                return Err(StorageError::CorruptedRow {
                    detail: "associazione con una tecnica ATT&CK non leggibile",
                });
            };
            trovate.push(association);
        }
        Ok(trovate)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::attack::{
        AttackSnapshot, AttackTactic, AttackTacticId, AttackTechnique, NewAttackTechnique,
    };
    use lisi_core::{AttackSnapshotId, Sha256Digest};

    use super::*;
    use crate::test_support::database;

    fn attore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn termine() -> AssociatedTerm {
        let Ok(termine) = AssociatedTerm::new("molotov", "oggetto") else {
            panic!("il termine di prova deve essere valido");
        };
        termine
    }

    fn tecnica_id(raw: &str) -> AttackTechniqueId {
        let Ok(id) = AttackTechniqueId::try_new(raw) else {
            panic!("l'identificativo di prova deve essere valido");
        };
        id
    }

    /// Archivio con una fotografia che contiene due tecniche.
    fn archivio_con_fotografia() -> (Database, AttackSnapshotId) {
        let mut database = database();

        let Ok(tactic_id) = AttackTacticId::try_new("TA0002") else {
            panic!("l'identificativo di prova deve essere valido");
        };
        let Ok(tactic) = AttackTactic::new(tactic_id, "execution", "Execution", "descrizione")
        else {
            panic!("la tattica di prova deve essere valida");
        };

        let tecnica = |id: &str, deprecated: bool| {
            let Ok(tecnica) = AttackTechnique::new(NewAttackTechnique {
                id: tecnica_id(id),
                name: "Nome della tecnica",
                description: "descrizione",
                tactics: vec![String::from("execution")],
                deprecated,
                revoked: false,
                object_version: "1.0",
                url: "https://attack.mitre.org/techniques/",
            }) else {
                panic!("la tecnica di prova deve essere valida");
            };
            tecnica
        };

        let Ok(snapshot) = AttackSnapshot::new(
            "enterprise-attack",
            "19.2",
            "3.3.0",
            "License\n-------\n…",
            vec![tactic],
            vec![tecnica("T1234", false), tecnica("T5678", true)],
        ) else {
            panic!("la fotografia di prova deve essere valida");
        };

        let Ok(id) = database.insert_attack_snapshot(
            &snapshot,
            &Sha256Digest::of_text("pacchetto"),
            &attore(),
            Timestamp::from_millis(1_757_000_000_000),
        ) else {
            panic!("la fotografia deve potersi registrare");
        };

        (database, id)
    }

    fn atto(technique: &str) -> NewAttackAssociation {
        let Ok(atto) = (NewAttackAssociation {
            term: termine(),
            technique: tecnica_id(technique),
            reason: String::from("il termine ricorre nei materiali che descrivono la tecnica"),
            declared_by: attore(),
            declared_at: Timestamp::from_millis(1_757_000_000_000),
        })
        .validated() else {
            panic!("l'atto di prova deve essere valido");
        };
        atto
    }

    #[test]
    fn un_associazione_si_dichiara_e_si_rilegge() {
        let (mut database, snapshot_id) = archivio_con_fotografia();
        let Ok(_) = database.declare_attack_association(snapshot_id, &atto("T1234")) else {
            panic!("la dichiarazione deve riuscire");
        };

        let Ok(trovate) = database.standing_associations_for_term(&termine()) else {
            panic!("le associazioni devono potersi rileggere");
        };
        assert_eq!(trovate.len(), 1);
        assert_eq!(trovate[0].technique().as_str(), "T1234");
        assert_eq!(trovate[0].attack_version(), "19.2");
        assert!(trovate[0].reason().contains("ricorre"));
    }

    /// **Lo stesso legame non si dichiara due volte mentre è in piedi.**
    #[test]
    fn lo_stesso_legame_non_si_dichiara_due_volte() {
        let (mut database, snapshot_id) = archivio_con_fotografia();
        let Ok(_) = database.declare_attack_association(snapshot_id, &atto("T1234")) else {
            panic!("la prima dichiarazione deve riuscire");
        };
        assert!(matches!(
            database.declare_attack_association(snapshot_id, &atto("T1234")),
            Err(StorageError::DuplicateAttackAssociation)
        ));
    }

    /// **Una tecnica che la fotografia non contiene non è associabile.**
    #[test]
    fn una_tecnica_assente_dalla_fotografia_non_e_associabile() {
        let (mut database, snapshot_id) = archivio_con_fotografia();
        assert!(matches!(
            database.declare_attack_association(snapshot_id, &atto("T9999")),
            Err(StorageError::NotFound { .. })
        ));
    }

    /// **Ritirare toglie dalle associazioni in piedi, e non cancella l'atto.**
    #[test]
    fn ritirare_toglie_dalle_associazioni_in_piedi() {
        let (mut database, snapshot_id) = archivio_con_fotografia();
        let Ok(id) = database.declare_attack_association(snapshot_id, &atto("T1234")) else {
            panic!("la dichiarazione deve riuscire");
        };

        let Ok(ritiro) = (AttackAssociationWithdrawal {
            reason: String::from("l'associazione era sbagliata"),
            withdrawn_by: attore(),
            withdrawn_at: Timestamp::from_millis(1_757_000_100_000),
        })
        .validated() else {
            panic!("il ritiro di prova deve essere valido");
        };
        let Ok(()) = database.withdraw_attack_association(id, &ritiro) else {
            panic!("il ritiro deve riuscire");
        };

        let Ok(trovate) = database.standing_associations_for_term(&termine()) else {
            panic!("le associazioni devono potersi rileggere");
        };
        assert!(trovate.is_empty());

        // L'atto resta: la riga non e' stata cancellata.
        let quante: i64 = {
            let Ok(quante) = database.connection.query_row(
                "SELECT count(*) FROM attack_term_associations",
                [],
                |row| row.get(0),
            ) else {
                panic!("il conteggio deve riuscire");
            };
            quante
        };
        assert_eq!(quante, 1, "l'atto non deve essere stato cancellato");
    }

    /// **Dopo un ritiro si può ridichiarare**: sono due atti, con due motivi.
    #[test]
    fn dopo_un_ritiro_si_puo_ridichiarare() {
        let (mut database, snapshot_id) = archivio_con_fotografia();
        let Ok(id) = database.declare_attack_association(snapshot_id, &atto("T1234")) else {
            panic!("la dichiarazione deve riuscire");
        };
        let Ok(ritiro) = (AttackAssociationWithdrawal {
            reason: String::from("sbagliata"),
            withdrawn_by: attore(),
            withdrawn_at: Timestamp::from_millis(1_757_000_100_000),
        })
        .validated() else {
            panic!("il ritiro di prova deve essere valido");
        };
        let Ok(()) = database.withdraw_attack_association(id, &ritiro) else {
            panic!("il ritiro deve riuscire");
        };

        let Ok(_) = database.declare_attack_association(snapshot_id, &atto("T1234")) else {
            panic!("la ridichiarazione deve riuscire");
        };
        let Ok(trovate) = database.standing_associations_for_term(&termine()) else {
            panic!("le associazioni devono potersi rileggere");
        };
        assert_eq!(trovate.len(), 1);
    }

    /// Una tecnica deprecata resta associabile, e la lettura lo dichiara.
    #[test]
    fn una_tecnica_deprecata_si_legge_come_tale() {
        let (mut database, snapshot_id) = archivio_con_fotografia();
        let Ok(_) = database.declare_attack_association(snapshot_id, &atto("T5678")) else {
            panic!("la dichiarazione deve riuscire");
        };

        let Ok(trovate) = database.standing_associations_for_term(&termine()) else {
            panic!("le associazioni devono potersi rileggere");
        };
        assert_eq!(trovate.len(), 1);
        assert!(trovate[0].is_deprecated());
        assert!(trovate[0].as_sentence().contains("deprecata"));
    }

    /// **Un atto non si modifica e non si cancella.**
    #[test]
    fn un_atto_non_si_modifica_ne_si_cancella() {
        let (mut database, snapshot_id) = archivio_con_fotografia();
        let Ok(_) = database.declare_attack_association(snapshot_id, &atto("T1234")) else {
            panic!("la dichiarazione deve riuscire");
        };

        for sql in [
            "UPDATE attack_term_associations SET reason = 'altro'",
            "DELETE FROM attack_term_associations",
        ] {
            assert!(
                database.connection.execute(sql, []).is_err(),
                "«{sql}» non doveva essere ammesso"
            );
        }
    }
}

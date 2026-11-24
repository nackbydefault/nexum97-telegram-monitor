//! Il registro delle copie cifrate per il destinatario (ENCRYPT-02, ADR-0190,
//! migrazione 0085).
//!
//! Una riga per tentativo, riuscito o no, con l'audit nella stessa
//! transazione. Il registro dice i nomi, mai le cartelle; le righe non
//! cambiano e non si cancellano.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use rusqlite::Row;

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// Una copia da registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRecipientCopy {
    /// Chi l'ha chiesta.
    pub requested_by: String,
    /// Quando.
    pub requested_at: Timestamp,
    /// Il nome della cartella del pacchetto.
    pub package_name: String,
    /// L'impronta del manifest del pacchetto.
    pub manifest_sha256: String,
    /// Il titolare del certificato di chi riceve.
    pub recipient_subject: String,
    /// L'impronta del certificato di chi riceve.
    pub recipient_sha256: String,
    /// Il nome della copia scritta; `None` per un rifiuto.
    pub copy_name: Option<String>,
    /// L'impronta della copia scritta; `None` per un rifiuto.
    pub copy_sha256: Option<String>,
    /// `cifrata` o `non_cifrata`.
    pub outcome: String,
    /// Perché no, per un rifiuto.
    pub outcome_detail: Option<String>,
}

/// Una copia registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecipientCopy {
    /// L'identificativo della riga.
    pub id: i64,
    /// La copia, come è stata registrata.
    pub copy: NewRecipientCopy,
}

impl StoredRecipientCopy {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            copy: NewRecipientCopy {
                requested_by: row.get(1)?,
                requested_at: instant(row.get(2)?),
                package_name: row.get(3)?,
                manifest_sha256: row.get(4)?,
                recipient_subject: row.get(5)?,
                recipient_sha256: row.get(6)?,
                copy_name: row.get(7)?,
                copy_sha256: row.get(8)?,
                outcome: row.get(9)?,
                outcome_detail: row.get(10)?,
            },
        })
    }
}

impl Database {
    /// Registra una copia, o un tentativo non riuscito, con la sua riga
    /// d'audit nella stessa transazione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la riga non rispetta lo schema o la scrittura
    /// non riesce: in quel caso non resta né la riga né l'audit.
    pub fn insert_recipient_copy(
        &mut self,
        copia: &NewRecipientCopy,
        audit: &NewAuditEntry,
    ) -> StorageResult<i64> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO recipient_copies (
                 requested_by, requested_at, package_name, manifest_sha256,
                 recipient_subject, recipient_sha256, copy_name, copy_sha256,
                 outcome, outcome_detail
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                copia.requested_by,
                millis(copia.requested_at),
                copia.package_name,
                copia.manifest_sha256,
                copia.recipient_subject,
                copia.recipient_sha256,
                copia.copy_name,
                copia.copy_sha256,
                copia.outcome,
                copia.outcome_detail,
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

    /// Le copie registrate, le più recenti prima, al più `limit`.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn recipient_copies(&self, limit: usize) -> StorageResult<Vec<StoredRecipientCopy>> {
        let mut richiesta = self.connection.prepare(
            "SELECT id, requested_by, requested_at, package_name, manifest_sha256,
                    recipient_subject, recipient_sha256, copy_name, copy_sha256,
                    outcome, outcome_detail
             FROM recipient_copies ORDER BY requested_at DESC, id DESC LIMIT ?1",
        )?;
        let righe = richiesta.query_map(
            [i64::try_from(limit).unwrap_or(i64::MAX)],
            StoredRecipientCopy::read,
        )?;
        let mut copie = Vec::new();
        for riga in righe {
            copie.push(riga?);
        }
        Ok(copie)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::NewAuditEntry;
    use lisi_core::text::{AuditAction, AuditDetail, AuditEntity};

    use super::NewRecipientCopy;
    use crate::test_support::{actor, database, now};

    fn audit() -> NewAuditEntry {
        let (Ok(azione), Ok(entita), Ok(dettaglio)) = (
            AuditAction::try_new("copia_per_destinatario"),
            AuditEntity::try_new("pacchetto"),
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

    fn riga(esito: &str) -> NewRecipientCopy {
        let scritta = esito == "cifrata";
        NewRecipientCopy {
            requested_by: String::from("operatore.prova"),
            requested_at: now(),
            package_name: String::from("pacchetto-1"),
            manifest_sha256: "a".repeat(64),
            recipient_subject: String::from("Ufficio destinatario"),
            recipient_sha256: "b".repeat(64),
            copy_name: scritta.then(|| String::from("pacchetto-1.zip.p7m")),
            copy_sha256: scritta.then(|| "c".repeat(64)),
            outcome: esito.to_owned(),
            outcome_detail: (!scritta).then(|| String::from("certificato scaduto")),
        }
    }

    #[test]
    fn una_copia_si_registra_con_il_suo_audit_e_si_rilegge() {
        let mut database = database();
        let (Ok(prima), Ok(seconda)) = (
            database.insert_recipient_copy(&riga("cifrata"), &audit()),
            database.insert_recipient_copy(&riga("non_cifrata"), &audit()),
        ) else {
            panic!("le copie devono potersi registrare");
        };
        assert!(seconda > prima);
        let Ok(copie) = database.recipient_copies(10) else {
            panic!("il registro si deve leggere");
        };
        assert_eq!(copie.len(), 2);
        assert_eq!(copie[0].copy, riga("non_cifrata"));
        let Ok(quanti) = database.connection.query_row(
            "SELECT count(*) FROM audit WHERE action = 'copia_per_destinatario'",
            [],
            |row| row.get::<_, i64>(0),
        ) else {
            panic!("l'audit si deve leggere");
        };
        assert_eq!(quanti, 2);

        // Una riga che non rispetta lo schema non lascia nemmeno l'audit.
        let mut sbagliata = riga("non_cifrata");
        sbagliata.outcome_detail = None;
        assert!(
            database
                .insert_recipient_copy(&sbagliata, &audit())
                .is_err()
        );
        let Ok(dopo) = database.connection.query_row(
            "SELECT count(*) FROM audit WHERE action = 'copia_per_destinatario'",
            [],
            |row| row.get::<_, i64>(0),
        ) else {
            panic!("l'audit si deve leggere");
        };
        assert_eq!(dopo, 2);
    }
}

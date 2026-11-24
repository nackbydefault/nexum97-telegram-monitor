//! I firmatari degli aggiornamenti (UPDATE-SIGN-01 parte 1, ADR-0183,
//! migrazione 0080).
//!
//! Le impronte dei certificati con cui il produttore firma il manifesto degli
//! aggiornamenti. Questo modulo scrive e legge, e basta: chi può ammetterli lo
//! decide il servizio, e lo schema ricontrolla ciò che conta anche se il
//! servizio sbagliasse. Un firmatario non si cancella: si ritira.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::text::Actor;
use rusqlite::Row;

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// Un firmatario degli aggiornamenti.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredUpdateSigner {
    /// L'impronta SHA-256 del certificato, in esadecimale minuscolo.
    pub sha256: String,
    /// Il nome con cui l'amministratore lo riconosce.
    pub name: String,
    /// Quando è stato ammesso.
    pub added_at: Timestamp,
    /// Chi l'ha ammesso.
    pub added_by: String,
    /// Quando è stato ritirato, se lo è.
    pub retired_at: Option<Timestamp>,
    /// Chi l'ha ritirato.
    pub retired_by: Option<String>,
}

impl StoredUpdateSigner {
    /// Se una firma sua si accetta ancora.
    #[must_use]
    pub const fn is_admitted(&self) -> bool {
        self.retired_at.is_none()
    }

    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            sha256: row.get(0)?,
            name: row.get(1)?,
            added_at: instant(row.get(2)?),
            added_by: row.get(3)?,
            retired_at: row.get::<_, Option<i64>>(4)?.map(instant),
            retired_by: row.get(5)?,
        })
    }
}

/// Scrive la riga d'audit dentro una transazione già aperta.
fn scrivi_audit(
    transazione: &rusqlite::Transaction<'_>,
    audit: &NewAuditEntry,
) -> rusqlite::Result<usize> {
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
    )
}

impl Database {
    /// I firmatari degli aggiornamenti, ammessi e ritirati, dal più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn update_signers(&self) -> StorageResult<Vec<StoredUpdateSigner>> {
        let mut richiesta = self.connection.prepare(
            "SELECT fingerprint, name, added_at, added_by, retired_at, retired_by
             FROM update_signers ORDER BY added_at DESC, fingerprint",
        )?;
        let righe = richiesta.query_map([], StoredUpdateSigner::read)?;
        Ok(righe.collect::<Result<Vec<_>, _>>()?)
    }

    /// Ammette un firmatario, con la riga d'audit nella stessa transazione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce: un'impronta già
    /// presente, ammessa o ritirata, o il nono ammesso li rifiuta lo schema.
    pub fn admit_update_signer(
        &mut self,
        sha256: &str,
        name: &str,
        actor: &Actor,
        audit: &NewAuditEntry,
    ) -> StorageResult<()> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO update_signers (fingerprint, name, added_at, added_by)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![sha256, name, millis(audit.recorded_at), actor.as_str()],
        )?;
        scrivi_audit(&transazione, audit)?;
        transazione.commit()?;
        Ok(())
    }

    /// Ritira un firmatario ammesso, con la riga d'audit nella stessa
    /// transazione. Restituisce `false` se non c'era un firmatario ammesso con
    /// quell'impronta: niente è stato scritto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn retire_update_signer(
        &mut self,
        sha256: &str,
        actor: &Actor,
        audit: &NewAuditEntry,
    ) -> StorageResult<bool> {
        let transazione = self.connection.transaction()?;
        let cambiate = transazione.execute(
            "UPDATE update_signers SET retired_at = ?2, retired_by = ?3
             WHERE fingerprint = ?1 AND retired_at IS NULL",
            rusqlite::params![sha256, millis(audit.recorded_at), actor.as_str()],
        )?;
        if cambiate == 0 {
            return Ok(false);
        }
        scrivi_audit(&transazione, audit)?;
        transazione.commit()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::NewAuditEntry;
    use lisi_core::text::{Actor, AuditAction, AuditEntity};

    use crate::Database;

    fn archivio() -> Database {
        let Ok(database) = Database::open_in_memory() else {
            panic!("l'archivio in memoria deve aprirsi");
        };
        database
    }

    fn attore() -> Actor {
        let Ok(attore) = Actor::try_new("amministratore.prova") else {
            panic!("attore valido");
        };
        attore
    }

    fn audit(azione: &str, quando: i64) -> NewAuditEntry {
        let (Ok(action), Ok(entity)) = (
            AuditAction::try_new(azione),
            AuditEntity::try_new("aggiornamento"),
        ) else {
            panic!("audit valido");
        };
        NewAuditEntry {
            actor: attore(),
            action,
            entity,
            entity_id: None,
            actor_mode: None,
            detail: None,
            recorded_at: Timestamp::from_millis(quando),
        }
    }

    fn righe_d_audit(database: &Database) -> i64 {
        let Ok(righe) = database.connection.query_row(
            "SELECT count(*) FROM audit WHERE entity = 'aggiornamento'",
            [],
            |row| row.get(0),
        ) else {
            panic!("l'audit si legge");
        };
        righe
    }

    /// **Un firmatario si ammette e si ritira, e resta** (ADR-0183,
    /// decisione 3): il ritiro dice chi e quando; un secondo ritiro e
    /// un'impronta già vista non scrivono niente, nemmeno l'audit.
    #[test]
    fn un_firmatario_si_ammette_si_ritira_e_resta() {
        let mut database = archivio();
        let a = "a".repeat(64);
        let Ok(()) =
            database.admit_update_signer(&a, "Produttore, chiave 2026", &attore(), &audit("x", 1))
        else {
            panic!("il firmatario si ammette");
        };
        let Ok(firmatari) = database.update_signers() else {
            panic!("i firmatari si leggono");
        };
        assert_eq!(firmatari.len(), 1);
        assert!(firmatari[0].is_admitted());

        assert!(
            database
                .admit_update_signer(&a, "di nuovo", &attore(), &audit("x", 2))
                .is_err(),
            "la stessa impronta non si ammette due volte"
        );
        assert_eq!(righe_d_audit(&database), 1, "il rifiuto non lascia audit");

        assert_eq!(
            database
                .retire_update_signer(&a, &attore(), &audit("x", 3))
                .ok(),
            Some(true)
        );
        assert_eq!(
            database
                .retire_update_signer(&a, &attore(), &audit("x", 4))
                .ok(),
            Some(false),
            "un ritirato non si ritira due volte"
        );
        assert_eq!(righe_d_audit(&database), 2);

        let Ok(firmatari) = database.update_signers() else {
            panic!("i firmatari si leggono");
        };
        assert_eq!(firmatari.len(), 1, "il ritirato resta");
        assert!(!firmatari[0].is_admitted());
        assert_eq!(
            firmatari[0].retired_by.as_deref(),
            Some("amministratore.prova")
        );
        assert_eq!(firmatari[0].retired_at, Some(Timestamp::from_millis(3)));
    }
}

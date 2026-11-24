//! La firma dell'ufficio (SIGN-01 parte 2, ADR-0181, migrazione 0079).
//!
//! Il certificato scelto e il registro delle firme. Questo modulo scrive e
//! legge, e basta: che cosa è ammesso lo decide il servizio, e lo schema
//! ricontrolla ciò che conta anche se il servizio sbagliasse. Il certificato e
//! la sua chiave non passano di qui: stanno nell'archivio di Windows.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::text::Actor;
use rusqlite::Row;

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// Il certificato scelto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSigningCertificate {
    /// L'impronta SHA-256, in esadecimale minuscolo.
    pub sha256: String,
    /// Il nome del titolare, come Windows lo mostrava quando è stato scelto.
    pub subject: String,
}

/// Una firma da registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDocumentSignature {
    /// Chi l'ha chiesta.
    pub requested_by: String,
    /// Quando.
    pub requested_at: Timestamp,
    /// `manifest` o `dizionario`.
    pub kind: String,
    /// Il nome del file, senza la cartella.
    pub file_name: String,
    /// L'impronta SHA-256 del file.
    pub file_sha256: String,
    /// L'impronta SHA-256 del certificato.
    pub certificate_sha256: String,
    /// `non_revocato` o `non_saputo`, per una firma fatta.
    pub revocation: Option<String>,
    /// `firmato` o `non_firmato`.
    pub outcome: String,
    /// Il perché di un rifiuto.
    pub outcome_detail: Option<String>,
}

/// Una firma registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDocumentSignature {
    /// La riga.
    pub id: i64,
    /// Chi l'ha chiesta.
    pub requested_by: String,
    /// Quando.
    pub requested_at: Timestamp,
    /// `manifest` o `dizionario`.
    pub kind: String,
    /// Il nome del file.
    pub file_name: String,
    /// L'impronta del file.
    pub file_sha256: String,
    /// L'impronta del certificato.
    pub certificate_sha256: String,
    /// Che cosa si sapeva della revoca.
    pub revocation: Option<String>,
    /// L'esito.
    pub outcome: String,
    /// Il perché.
    pub outcome_detail: Option<String>,
}

impl StoredDocumentSignature {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            requested_by: row.get(1)?,
            requested_at: instant(row.get(2)?),
            kind: row.get(3)?,
            file_name: row.get(4)?,
            file_sha256: row.get(5)?,
            certificate_sha256: row.get(6)?,
            revocation: row.get(7)?,
            outcome: row.get(8)?,
            outcome_detail: row.get(9)?,
        })
    }
}

/// Scrive la riga d'audit dentro una transazione già aperta.
fn scrivi_audit(
    transazione: &rusqlite::Transaction<'_>,
    audit: &NewAuditEntry,
    entity_id: Option<i64>,
) -> rusqlite::Result<usize> {
    transazione.execute(
        "INSERT INTO audit (actor, action, entity, entity_id, detail, recorded_at, actor_mode)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            audit.actor.as_str(),
            audit.action.as_str(),
            audit.entity.as_str(),
            entity_id,
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
    /// Il certificato scelto, se c'è.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn signing_certificate(&self) -> StorageResult<Option<StoredSigningCertificate>> {
        let (impronta, titolare) = self.connection.query_row(
            "SELECT sha256, subject FROM signing_certificate WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            },
        )?;
        Ok(impronta
            .zip(titolare)
            .map(|(sha256, subject)| StoredSigningCertificate { sha256, subject }))
    }

    /// Salva il certificato scelto, o lo toglie passando `None`, con la riga
    /// d'audit nella stessa transazione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce, compreso il caso di
    /// un valore che lo schema rifiuta.
    pub fn save_signing_certificate(
        &mut self,
        certificate: Option<&StoredSigningCertificate>,
        actor: &Actor,
        audit: &NewAuditEntry,
    ) -> StorageResult<()> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "UPDATE signing_certificate
             SET sha256 = ?1, subject = ?2, updated_at = ?3, updated_by = ?4
             WHERE id = 1",
            rusqlite::params![
                certificate.map(|c| c.sha256.as_str()),
                certificate.map(|c| c.subject.as_str()),
                millis(audit.recorded_at),
                actor.as_str(),
            ],
        )?;
        scrivi_audit(&transazione, audit, None)?;
        transazione.commit()?;
        Ok(())
    }

    /// Registra una firma, o un tentativo, con la sua riga d'audit, nella
    /// stessa transazione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo schema rifiuta la riga o se la scrittura
    /// non riesce.
    pub fn insert_document_signature(
        &mut self,
        firma: &NewDocumentSignature,
        audit: &NewAuditEntry,
    ) -> StorageResult<i64> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO document_signatures (
                 requested_by, requested_at, kind, file_name, file_sha256,
                 certificate_sha256, revocation, outcome, outcome_detail
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                firma.requested_by,
                millis(firma.requested_at),
                firma.kind,
                firma.file_name,
                firma.file_sha256,
                firma.certificate_sha256,
                firma.revocation,
                firma.outcome,
                firma.outcome_detail,
            ],
        )?;
        let id = transazione.last_insert_rowid();
        scrivi_audit(&transazione, audit, Some(id))?;
        transazione.commit()?;
        Ok(id)
    }

    /// Le firme, dalla più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn document_signatures(&self) -> StorageResult<Vec<StoredDocumentSignature>> {
        let mut statement = self.connection.prepare(
            "SELECT id, requested_by, requested_at, kind, file_name, file_sha256,
                    certificate_sha256, revocation, outcome, outcome_detail
             FROM document_signatures ORDER BY requested_at DESC, id DESC",
        )?;
        let righe = statement.query_map([], StoredDocumentSignature::read)?;
        let mut firme = Vec::new();
        for riga in righe {
            firme.push(riga?);
        }
        Ok(firme)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::NewAuditEntry;
    use lisi_core::text::{Actor, AuditAction, AuditEntity};

    use super::{NewDocumentSignature, StoredSigningCertificate};
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

    fn audit(azione: &str) -> NewAuditEntry {
        let (Ok(action), Ok(entity)) =
            (AuditAction::try_new(azione), AuditEntity::try_new("firma"))
        else {
            panic!("audit valido");
        };
        NewAuditEntry {
            actor: attore(),
            action,
            entity,
            entity_id: None,
            actor_mode: None,
            detail: None,
            recorded_at: Timestamp::from_millis(1_000),
        }
    }

    fn firma(esito: &str, revoca: Option<&str>, motivo: Option<&str>) -> NewDocumentSignature {
        NewDocumentSignature {
            requested_by: String::from("operatore.prova"),
            requested_at: Timestamp::from_millis(2_000),
            kind: String::from("manifest"),
            file_name: String::from("manifest.txt"),
            file_sha256: "c".repeat(64),
            certificate_sha256: "d".repeat(64),
            revocation: revoca.map(str::to_owned),
            outcome: esito.to_owned(),
            outcome_detail: motivo.map(str::to_owned),
        }
    }

    /// **Il certificato si sceglie, si rilegge e si toglie.**
    #[test]
    fn il_certificato_si_sceglie_e_si_toglie() {
        let mut database = archivio();
        assert_eq!(database.signing_certificate().ok(), Some(None));

        let scelto = StoredSigningCertificate {
            sha256: "e".repeat(64),
            subject: String::from("Ufficio di prova"),
        };
        let Ok(()) = database.save_signing_certificate(
            Some(&scelto),
            &attore(),
            &audit("certificato_firma_scelto"),
        ) else {
            panic!("il certificato deve scriversi");
        };
        assert_eq!(database.signing_certificate().ok(), Some(Some(scelto)));

        let Ok(()) =
            database.save_signing_certificate(None, &attore(), &audit("certificato_firma_scelto"))
        else {
            panic!("il certificato deve togliersi");
        };
        assert_eq!(database.signing_certificate().ok(), Some(None));
    }

    /// **Una firma si registra, e una che lo schema rifiuta non lascia
    /// niente: né la riga né l'audit.**
    #[test]
    fn una_firma_si_registra_e_una_rifiutata_non_lascia_niente() {
        let mut database = archivio();
        let Ok(_) = database.insert_document_signature(
            &firma("firmato", Some("non_saputo"), None),
            &audit("documento_firmato"),
        ) else {
            panic!("una firma fatta si registra");
        };
        assert!(
            database
                .insert_document_signature(
                    &firma("non_firmato", None, None),
                    &audit("documento_non_firmato")
                )
                .is_err(),
            "un rifiuto senza motivo si rifiuta"
        );

        let Ok(firme) = database.document_signatures() else {
            panic!("il registro deve leggersi");
        };
        assert_eq!(firme.len(), 1);
        assert_eq!(firme[0].revocation.as_deref(), Some("non_saputo"));
        let Ok(righe) = database.connection.query_row(
            "SELECT count(*) FROM audit WHERE entity = 'firma'",
            [],
            |row| row.get::<_, i64>(0),
        ) else {
            panic!("l'audit deve leggersi");
        };
        assert_eq!(righe, 1, "il rifiuto non deve lasciare una riga d'audit");
    }
}

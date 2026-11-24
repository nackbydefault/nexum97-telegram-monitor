//! Lo scambio TAXII (TAXII-01 parte 2, ADR-0179, migrazione 0078).
//!
//! La destinazione e il registro degli invii. Questo modulo scrive e legge, e
//! basta: che cosa è ammesso lo decide il servizio, e lo schema ricontrolla
//! ciò che conta anche se il servizio sbagliasse. La parola d'ordine non passa
//! di qui: non sta nell'archivio.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::text::Actor;
use rusqlite::Row;

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// La destinazione conservata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTaxiiDestination {
    /// La radice dell'API, `https://`.
    pub api_root: String,
    /// L'identificativo della collezione.
    pub collection_id: String,
    /// Il nome utente, se scritto.
    pub username: Option<String>,
}

/// Un invio da registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTaxiiSubmission {
    /// Chi ha premuto.
    pub requested_by: String,
    /// Quando.
    pub requested_at: Timestamp,
    /// L'indirizzo a cui si è mandato.
    pub url: String,
    /// Il monitoraggio da cui vengono gli oggetti.
    pub session_id: i64,
    /// Quanti oggetti.
    pub objects: u32,
    /// L'impronta SHA-256 del corpo mandato.
    pub body_sha256: String,
    /// Lo stato HTTP, se il server ha risposto.
    pub http_status: Option<u32>,
    /// `consegnato` o `non_consegnato`.
    pub outcome: String,
    /// Il perché dell'esito.
    pub outcome_detail: Option<String>,
    /// L'identificativo dello stato TAXII.
    pub status_id: Option<String>,
    /// Gli oggetti presi dal server.
    pub success_count: Option<u64>,
    /// Gli oggetti rifiutati dal server.
    pub failure_count: Option<u64>,
    /// Gli oggetti ancora in attesa.
    pub pending_count: Option<u64>,
}

/// Un invio registrato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTaxiiSubmission {
    /// La riga.
    pub id: i64,
    /// Chi ha premuto.
    pub requested_by: String,
    /// Quando.
    pub requested_at: Timestamp,
    /// L'indirizzo.
    pub url: String,
    /// Il monitoraggio.
    pub session_id: i64,
    /// Quanti oggetti.
    pub objects: u32,
    /// L'impronta del corpo.
    pub body_sha256: String,
    /// Lo stato HTTP.
    pub http_status: Option<u32>,
    /// L'esito.
    pub outcome: String,
    /// Il perché.
    pub outcome_detail: Option<String>,
    /// L'identificativo dello stato TAXII.
    pub status_id: Option<String>,
    /// Gli oggetti presi.
    pub success_count: Option<u64>,
    /// Gli oggetti rifiutati.
    pub failure_count: Option<u64>,
    /// Gli oggetti in attesa.
    pub pending_count: Option<u64>,
}

/// Un numero dell'archivio come conteggio, se lo è.
fn conteggio(valore: Option<i64>) -> Option<u64> {
    valore.and_then(|numero| u64::try_from(numero).ok())
}

impl StoredTaxiiSubmission {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            requested_by: row.get(1)?,
            requested_at: instant(row.get(2)?),
            url: row.get(3)?,
            session_id: row.get(4)?,
            objects: u32::try_from(row.get::<_, i64>(5)?).unwrap_or(0),
            body_sha256: row.get(6)?,
            http_status: row
                .get::<_, Option<i64>>(7)?
                .and_then(|stato| u32::try_from(stato).ok()),
            outcome: row.get(8)?,
            outcome_detail: row.get(9)?,
            status_id: row.get(10)?,
            success_count: conteggio(row.get(11)?),
            failure_count: conteggio(row.get(12)?),
            pending_count: conteggio(row.get(13)?),
        })
    }
}

const COLONNE: &str = "id, requested_by, requested_at, url, session_id, objects, body_sha256,
     http_status, outcome, outcome_detail, status_id, success_count, failure_count,
     pending_count";

/// Un conteggio per l'archivio: oltre `i64` non ci arriva un server vero, e
/// se ci arrivasse il numero non si scrive.
fn per_archivio(valore: Option<u64>) -> Option<i64> {
    valore.and_then(|numero| i64::try_from(numero).ok())
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
    /// La destinazione TAXII, se configurata.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn taxii_destination(&self) -> StorageResult<Option<StoredTaxiiDestination>> {
        let (radice, collezione, nome) = self.connection.query_row(
            "SELECT api_root, collection_id, username FROM taxii_destination WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )?;
        Ok(radice
            .zip(collezione)
            .map(|(api_root, collection_id)| StoredTaxiiDestination {
                api_root,
                collection_id,
                username: nome,
            }))
    }

    /// Salva la destinazione, o la svuota passando `None`, con la riga d'audit
    /// nella stessa transazione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce, compreso il caso di
    /// una destinazione che lo schema rifiuta.
    pub fn save_taxii_destination(
        &mut self,
        destination: Option<&StoredTaxiiDestination>,
        actor: &Actor,
        audit: &NewAuditEntry,
    ) -> StorageResult<()> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "UPDATE taxii_destination
             SET api_root = ?1, collection_id = ?2, username = ?3,
                 updated_at = ?4, updated_by = ?5
             WHERE id = 1",
            rusqlite::params![
                destination.map(|d| d.api_root.as_str()),
                destination.map(|d| d.collection_id.as_str()),
                destination.and_then(|d| d.username.as_deref()),
                millis(audit.recorded_at),
                actor.as_str(),
            ],
        )?;
        scrivi_audit(&transazione, audit, None)?;
        transazione.commit()?;
        Ok(())
    }

    /// Registra un invio con la sua riga d'audit, nella stessa transazione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo schema rifiuta la riga o se la scrittura
    /// non riesce.
    pub fn insert_taxii_submission(
        &mut self,
        invio: &NewTaxiiSubmission,
        audit: &NewAuditEntry,
    ) -> StorageResult<i64> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO taxii_submissions (
                 requested_by, requested_at, url, session_id, objects, body_sha256,
                 http_status, outcome, outcome_detail, status_id, success_count,
                 failure_count, pending_count
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            rusqlite::params![
                invio.requested_by,
                millis(invio.requested_at),
                invio.url,
                invio.session_id,
                invio.objects,
                invio.body_sha256,
                invio.http_status,
                invio.outcome,
                invio.outcome_detail,
                invio.status_id,
                per_archivio(invio.success_count),
                per_archivio(invio.failure_count),
                per_archivio(invio.pending_count),
            ],
        )?;
        let id = transazione.last_insert_rowid();
        scrivi_audit(&transazione, audit, Some(id))?;
        transazione.commit()?;
        Ok(id)
    }

    /// Gli invii, dal più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn taxii_submissions(&self) -> StorageResult<Vec<StoredTaxiiSubmission>> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT {COLONNE} FROM taxii_submissions ORDER BY requested_at DESC, id DESC"
        ))?;
        let righe = statement.query_map([], StoredTaxiiSubmission::read)?;
        let mut invii = Vec::new();
        for riga in righe {
            invii.push(riga?);
        }
        Ok(invii)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::NewAuditEntry;
    use lisi_core::text::{Actor, AuditAction, AuditEntity};

    use super::{NewTaxiiSubmission, StoredTaxiiDestination};
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
            (AuditAction::try_new(azione), AuditEntity::try_new("taxii"))
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

    fn invio(esito: &str, stato: Option<u32>) -> NewTaxiiSubmission {
        NewTaxiiSubmission {
            requested_by: String::from("operatore.prova"),
            requested_at: Timestamp::from_millis(2_000),
            url: String::from("https://esempio.test/api/collections/c1/objects/"),
            session_id: 7,
            objects: 3,
            body_sha256: "c".repeat(64),
            http_status: stato,
            outcome: esito.to_owned(),
            outcome_detail: None,
            status_id: None,
            success_count: None,
            failure_count: None,
            pending_count: None,
        }
    }

    /// **La destinazione si scrive, si rilegge e si svuota.**
    #[test]
    fn la_destinazione_si_scrive_e_si_svuota() {
        let mut database = archivio();
        assert_eq!(database.taxii_destination().ok(), Some(None));

        let destinazione = StoredTaxiiDestination {
            api_root: String::from("https://esempio.test/api/"),
            collection_id: String::from("c1"),
            username: Some(String::from("ufficio.prova")),
        };
        let Ok(()) = database.save_taxii_destination(
            Some(&destinazione),
            &attore(),
            &audit("destinazione_taxii_impostata"),
        ) else {
            panic!("la destinazione deve scriversi");
        };
        assert_eq!(database.taxii_destination().ok(), Some(Some(destinazione)));

        let Ok(()) = database.save_taxii_destination(
            None,
            &attore(),
            &audit("destinazione_taxii_impostata"),
        ) else {
            panic!("la destinazione deve svuotarsi");
        };
        assert_eq!(database.taxii_destination().ok(), Some(None));
    }

    /// **Un invio si registra, e uno che lo schema rifiuta non lascia niente:
    /// né la riga né l'audit.**
    #[test]
    fn un_invio_si_registra_e_uno_rifiutato_non_lascia_niente() {
        let mut database = archivio();
        let Ok(_) = database.insert_taxii_submission(
            &invio("non_consegnato", Some(401)),
            &audit("taxii_non_consegnato"),
        ) else {
            panic!("un mancato invio si registra");
        };
        assert!(
            database
                .insert_taxii_submission(
                    &invio("consegnato", Some(200)),
                    &audit("taxii_consegnato")
                )
                .is_err(),
            "una consegna senza 202 si rifiuta"
        );

        let Ok(invii) = database.taxii_submissions() else {
            panic!("il registro deve leggersi");
        };
        assert_eq!(invii.len(), 1);
        assert_eq!(invii[0].http_status, Some(401));
        assert_eq!(invii[0].objects, 3);
        let Ok(righe) = database.connection.query_row(
            "SELECT count(*) FROM audit WHERE entity = 'taxii'",
            [],
            |row| row.get::<_, i64>(0),
        ) else {
            panic!("l'audit deve leggersi");
        };
        assert_eq!(righe, 1, "il rifiuto non deve lasciare una riga d'audit");
    }
}

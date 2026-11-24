//! Gli allegati conservati su richiesta (ATTACH-01 parte 2, ADR-0177,
//! migrazione 0076).
//!
//! Una riga per richiesta, con la riga d'audit nella stessa transazione. Lo
//! schema impedisce di riscriverla, di cancellarla, di conservare due volte lo
//! stesso allegato e di superare il tetto complessivo. L'impronta la calcola
//! questo modulo dai byte che riceve: chi scrive non può dichiararne una
//! diversa.
//!
//! I byte non si aprono: questo modulo li scrive e li rilegge, e basta
//! (ADR-0177, decisione 7).

use lisi_core::model::NewAuditEntry;
use lisi_core::{ContentId, Sha256Digest, Timestamp};
use rusqlite::{OptionalExtension, Row};

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// Una richiesta da registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAttachmentKeeping {
    /// Il contenuto che porta l'allegato.
    pub content_id: ContentId,
    /// L'account d'ufficio che ha letto, se il monitoraggio ne ha uno.
    pub account_uuid: Option<String>,
    /// Chi ha chiesto.
    pub requested_by: String,
    /// Perché.
    pub reason: String,
    /// Quando.
    pub requested_at: Timestamp,
    /// `conservato`, `fermato`, `rifiutato` o `non_riuscito`.
    pub outcome: String,
    /// Il perché di un esito che non è una conservazione, o ciò che resta da
    /// sapere di una riuscita.
    pub outcome_detail: Option<String>,
    /// I byte, non aperti: soltanto per l'esito `conservato`.
    pub bytes: Option<Vec<u8>>,
}

/// Una richiesta registrata, **senza i byte**: per elencare non serve
/// leggerli. Si leggono con [`Database::kept_attachment_bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAttachmentKeeping {
    /// La riga.
    pub id: i64,
    /// Il contenuto.
    pub content_id: ContentId,
    /// L'account d'ufficio che ha letto.
    pub account_uuid: Option<String>,
    /// Chi ha chiesto.
    pub requested_by: String,
    /// Perché.
    pub reason: String,
    /// Quando.
    pub requested_at: Timestamp,
    /// L'esito.
    pub outcome: String,
    /// Il perché dell'esito.
    pub outcome_detail: Option<String>,
    /// Quanti byte si sono conservati.
    pub size: Option<u64>,
    /// L'impronta SHA-256, in esadecimale.
    pub sha256: Option<String>,
}

impl StoredAttachmentKeeping {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            content_id: ContentId::new(row.get(1)?),
            account_uuid: row.get(2)?,
            requested_by: row.get(3)?,
            reason: row.get(4)?,
            requested_at: instant(row.get(5)?),
            outcome: row.get(6)?,
            outcome_detail: row.get(7)?,
            size: row
                .get::<_, Option<i64>>(8)?
                .and_then(|n| u64::try_from(n).ok()),
            sha256: row.get(9)?,
        })
    }
}

const COLONNE: &str = "id, content_id, account_uuid, requested_by, reason, requested_at, outcome,
     outcome_detail, length(bytes), sha256";

impl Database {
    /// Registra una richiesta con la sua riga d'audit, nella stessa
    /// transazione: o entrambe, o nessuna.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo schema rifiuta la riga (un secondo
    /// allegato conservato per lo stesso contenuto, il tetto superato, …) o se
    /// la scrittura non riesce.
    pub fn insert_attachment_keeping(
        &mut self,
        richiesta: &NewAttachmentKeeping,
        audit: &NewAuditEntry,
    ) -> StorageResult<i64> {
        let impronta = richiesta
            .bytes
            .as_deref()
            .map(|byte| Sha256Digest::of_bytes(byte).as_str().to_owned());
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO attachment_keepings (
                 content_id, account_uuid, requested_by, reason, requested_at, outcome,
                 outcome_detail, bytes, sha256
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                richiesta.content_id.get(),
                richiesta.account_uuid,
                richiesta.requested_by,
                richiesta.reason,
                millis(richiesta.requested_at),
                richiesta.outcome,
                richiesta.outcome_detail,
                richiesta.bytes,
                impronta,
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

    /// Le richieste per l'allegato di un contenuto, dalla più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn attachment_keepings(
        &self,
        content_id: ContentId,
    ) -> StorageResult<Vec<StoredAttachmentKeeping>> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT {COLONNE} FROM attachment_keepings WHERE content_id = ?1
             ORDER BY requested_at DESC, id DESC"
        ))?;
        let righe = statement.query_map([content_id.get()], StoredAttachmentKeeping::read)?;
        let mut richieste = Vec::new();
        for riga in righe {
            richieste.push(riga?);
        }
        Ok(richieste)
    }

    /// La conservazione riuscita dell'allegato di un contenuto, se c'è.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn kept_attachment(
        &self,
        content_id: ContentId,
    ) -> StorageResult<Option<StoredAttachmentKeeping>> {
        Ok(self
            .connection
            .query_row(
                &format!(
                    "SELECT {COLONNE} FROM attachment_keepings
                     WHERE content_id = ?1 AND outcome = 'conservato'"
                ),
                [content_id.get()],
                StoredAttachmentKeeping::read,
            )
            .optional()?)
    }

    /// I byte di una conservazione riuscita, non aperti.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn kept_attachment_bytes(&self, keeping_id: i64) -> StorageResult<Option<Vec<u8>>> {
        Ok(self
            .connection
            .query_row(
                "SELECT bytes FROM attachment_keepings
                 WHERE id = ?1 AND outcome = 'conservato'",
                [keeping_id],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Quanti byte di allegati l'archivio conserva, in tutto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn kept_attachments_total_bytes(&self) -> StorageResult<u64> {
        let totale: i64 = self.connection.query_row(
            "SELECT coalesce(sum(length(bytes)), 0) FROM attachment_keepings",
            [],
            |row| row.get(0),
        )?;
        Ok(u64::try_from(totale).unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::NewAuditEntry;
    use lisi_core::text::{AuditAction, AuditDetail, AuditEntity};
    use lisi_core::{ContentId, Sha256Digest};

    use super::NewAttachmentKeeping;
    use crate::test_support::{actor, database_with_session, later, new_content};

    fn audit(quando: i64) -> NewAuditEntry {
        let (Ok(action), Ok(entity), Ok(detail)) = (
            AuditAction::try_new("allegato_conservato"),
            AuditEntity::try_new("allegato"),
            AuditDetail::try_new("prova"),
        ) else {
            panic!("valori d'audit validi");
        };
        NewAuditEntry {
            actor: actor("operatore.prova"),
            action,
            entity,
            entity_id: None,
            detail: Some(detail),
            recorded_at: later(quando),
            actor_mode: None,
        }
    }

    fn richiesta(
        content_id: ContentId,
        quando: i64,
        esito: &str,
        byte: Option<Vec<u8>>,
    ) -> NewAttachmentKeeping {
        NewAttachmentKeeping {
            content_id,
            account_uuid: None,
            requested_by: String::from("operatore.prova"),
            reason: String::from("Il documento allegato alla minaccia"),
            requested_at: later(quando),
            outcome: String::from(esito),
            outcome_detail: None,
            bytes: byte,
        }
    }

    fn un_contenuto() -> (crate::Database, ContentId) {
        let (mut database, fonte, sessione) = database_with_session();
        let Ok(inserito) = database.insert_content(&new_content(sessione, fonte, "1", "un pdf"))
        else {
            panic!("il contenuto di prova si registra");
        };
        (database, inserito.content_id())
    }

    /// **Un allegato si conserva una volta, con l'impronta calcolata qui e
    /// l'audit nella stessa transazione; le richieste non riuscite restano
    /// accanto** (ADR-0177, decisioni 3 e 8). Prova negativa: una seconda
    /// conservazione dello stesso allegato lo schema la rifiuta.
    #[test]
    fn un_allegato_si_conserva_una_volta_e_le_richieste_restano() {
        let (mut database, contenuto) = un_contenuto();
        let byte = b"%PDF-1.7 sintetico".to_vec();
        let Ok(_) = database
            .insert_attachment_keeping(&richiesta(contenuto, 1, "rifiutato", None), &audit(1))
        else {
            panic!("una richiesta rifiutata si registra");
        };
        let Ok(riuscita) = database.insert_attachment_keeping(
            &richiesta(contenuto, 2, "conservato", Some(byte.clone())),
            &audit(2),
        ) else {
            panic!("la conservazione si registra");
        };
        assert!(
            database
                .insert_attachment_keeping(
                    &richiesta(contenuto, 3, "conservato", Some(byte.clone())),
                    &audit(3),
                )
                .is_err(),
            "lo stesso allegato non si conserva due volte"
        );
        let Ok(Some(conservato)) = database.kept_attachment(contenuto) else {
            panic!("la conservazione si rilegge");
        };
        assert_eq!(conservato.id, riuscita);
        assert_eq!(
            conservato.sha256.as_deref(),
            Some(Sha256Digest::of_bytes(&byte).as_str())
        );
        assert_eq!(conservato.size, Some(byte.len() as u64));
        assert_eq!(
            database.kept_attachment_bytes(riuscita).ok(),
            Some(Some(byte.clone()))
        );
        assert_eq!(
            database
                .attachment_keepings(contenuto)
                .map(|righe| righe.len())
                .ok(),
            Some(2),
            "la riuscita e il rifiuto; la seconda conservazione non c'è"
        );
        assert_eq!(
            database.kept_attachments_total_bytes().ok(),
            Some(byte.len() as u64)
        );
        let Ok(voci) = database.audit_entries() else {
            panic!("l'audit si legge");
        };
        assert_eq!(
            voci.iter()
                .filter(|voce| voce.action.as_str() == "allegato_conservato")
                .count(),
            2,
            "la seconda conservazione rifiutata non lascia una riga d'audit a metà"
        );
    }

    /// **Lo schema vuole i byte soltanto per una conservazione, e li vuole
    /// sotto il tetto; le righe non cambiano, non si cancellano, e il
    /// contenuto resta** (ADR-0177, decisioni 5 e 8).
    #[test]
    fn lo_schema_custodisce_le_conservazioni() {
        let (mut database, contenuto) = un_contenuto();
        assert!(
            database
                .insert_attachment_keeping(
                    &richiesta(contenuto, 1, "rifiutato", Some(vec![1])),
                    &audit(1)
                )
                .is_err(),
            "un rifiuto non porta byte"
        );
        assert!(
            database
                .insert_attachment_keeping(&richiesta(contenuto, 1, "conservato", None), &audit(1))
                .is_err(),
            "una conservazione senza byte non esiste"
        );
        assert!(
            database
                .insert_attachment_keeping(
                    &richiesta(
                        contenuto,
                        1,
                        "conservato",
                        Some(vec![0; 25 * 1024 * 1024 + 1])
                    ),
                    &audit(1)
                )
                .is_err(),
            "oltre 25 MiB non si scrive"
        );
        let Ok(id) = database.insert_attachment_keeping(
            &richiesta(contenuto, 2, "conservato", Some(vec![7; 16])),
            &audit(2),
        ) else {
            panic!("la conservazione si registra");
        };
        for istruzione in [
            "UPDATE attachment_keepings SET reason = 'altro' WHERE id = ?1",
            "DELETE FROM attachment_keepings WHERE id = ?1",
        ] {
            assert!(
                database.connection.execute(istruzione, [id]).is_err(),
                "«{istruzione}» non passa"
            );
        }
        assert!(
            database
                .connection
                .execute("DELETE FROM contents WHERE id = ?1", [contenuto.get()])
                .is_err(),
            "il contenuto con un allegato conservato non si toglie"
        );
    }

    /// **Il tetto complessivo lo ricontrolla lo schema** (ADR-0177,
    /// decisione 5). Riempire un GiB per provarlo costerebbe un GiB di
    /// memoria: la prova legge il trigger com'è nell'archivio; il servizio
    /// prova il rifiuto con il suo conto.
    #[test]
    fn il_tetto_complessivo_lo_ricontrolla_lo_schema() {
        let (database, _) = un_contenuto();
        let Ok(corpo) = database.connection.query_row(
            "SELECT sql FROM sqlite_master
             WHERE name = 'attachment_keepings_stay_under_the_total'",
            [],
            |row| row.get::<_, String>(0),
        ) else {
            panic!("il trigger del tetto esiste");
        };
        assert!(corpo.contains("1073741824"), "il tetto è 1 GiB: {corpo}");
        assert!(
            corpo.contains("sum(length(bytes))"),
            "somma i byte: {corpo}"
        );
    }
}

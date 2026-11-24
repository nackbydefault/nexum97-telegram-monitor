//! I dizionari dalla rete (DICT-NET-01 parte 2, ADR-0178, migrazione 0077).
//!
//! La fonte, i firmatari ammessi e il registro degli scaricamenti. Questo
//! modulo scrive e legge, e basta: che cosa è ammesso lo decide il servizio,
//! e lo schema ricontrolla ciò che conta anche se il servizio sbagliasse.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::text::Actor;
use rusqlite::Row;

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// Un tentativo da registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDictionaryDownload {
    /// Chi ha premuto.
    pub requested_by: String,
    /// Quando.
    pub requested_at: Timestamp,
    /// L'indirizzo del dizionario.
    pub url: String,
    /// L'impronta SHA-256 dei byte arrivati, se sono arrivati.
    pub content_sha256: Option<String>,
    /// L'impronta SHA-256 del certificato di chi ha firmato, se la firma l'ha
    /// detto.
    pub signer_sha256: Option<String>,
    /// Il nome dichiarato dal dizionario, se è stato letto.
    pub declared_name: Option<String>,
    /// Il numero di versione dichiarato, se è stato letto.
    pub declared_version: Option<u32>,
    /// `importato`, `rifiutato` o `non_riuscito`.
    pub outcome: String,
    /// Il perché dell'esito.
    pub outcome_detail: Option<String>,
    /// Il dizionario scritto, per un ingresso.
    pub dictionary_id: Option<i64>,
    /// La versione scritta, per un ingresso.
    pub version_id: Option<i64>,
}

/// Un tentativo registrato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDictionaryDownload {
    /// La riga.
    pub id: i64,
    /// Chi ha premuto.
    pub requested_by: String,
    /// Quando.
    pub requested_at: Timestamp,
    /// L'indirizzo.
    pub url: String,
    /// L'impronta dei byte.
    pub content_sha256: Option<String>,
    /// L'impronta del firmatario.
    pub signer_sha256: Option<String>,
    /// Il nome dichiarato.
    pub declared_name: Option<String>,
    /// Il numero dichiarato.
    pub declared_version: Option<u32>,
    /// L'esito.
    pub outcome: String,
    /// Il perché.
    pub outcome_detail: Option<String>,
    /// Il dizionario scritto.
    pub dictionary_id: Option<i64>,
    /// La versione scritta.
    pub version_id: Option<i64>,
}

impl StoredDictionaryDownload {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            requested_by: row.get(1)?,
            requested_at: instant(row.get(2)?),
            url: row.get(3)?,
            content_sha256: row.get(4)?,
            signer_sha256: row.get(5)?,
            declared_name: row.get(6)?,
            declared_version: row
                .get::<_, Option<i64>>(7)?
                .and_then(|n| u32::try_from(n).ok()),
            outcome: row.get(8)?,
            outcome_detail: row.get(9)?,
            dictionary_id: row.get(10)?,
            version_id: row.get(11)?,
        })
    }
}

const COLONNE: &str = "id, requested_by, requested_at, url, content_sha256, signer_sha256,
     declared_name, declared_version, outcome, outcome_detail, dictionary_id, version_id";

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
    /// L'indirizzo da cui si scaricano i dizionari, se configurato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn dictionary_network_source(&self) -> StorageResult<Option<String>> {
        Ok(self.connection.query_row(
            "SELECT url FROM dictionary_network_source WHERE id = 1",
            [],
            |row| row.get(0),
        )?)
    }

    /// Salva l'indirizzo, o lo svuota passando `None`, con la riga d'audit
    /// nella stessa transazione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce, compreso il caso di
    /// un indirizzo che lo schema rifiuta.
    pub fn save_dictionary_network_source(
        &mut self,
        url: Option<&str>,
        actor: &Actor,
        audit: &NewAuditEntry,
    ) -> StorageResult<()> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "UPDATE dictionary_network_source
             SET url = ?1, updated_at = ?2, updated_by = ?3
             WHERE id = 1",
            rusqlite::params![url, millis(audit.recorded_at), actor.as_str()],
        )?;
        scrivi_audit(&transazione, audit, None)?;
        transazione.commit()?;
        Ok(())
    }

    /// Le impronte dei firmatari ammessi, in ordine.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn dictionary_signers(&self) -> StorageResult<Vec<String>> {
        let mut statement = self
            .connection
            .prepare("SELECT fingerprint FROM dictionary_signers ORDER BY fingerprint")?;
        let righe = statement.query_map([], |row| row.get(0))?;
        let mut impronte = Vec::new();
        for riga in righe {
            impronte.push(riga?);
        }
        Ok(impronte)
    }

    /// Sostituisce l'elenco dei firmatari ammessi, con la riga d'audit: o
    /// tutto, o niente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo schema rifiuta un'impronta, o più di otto,
    /// o se la scrittura non riesce.
    pub fn replace_dictionary_signers(
        &mut self,
        fingerprints: &[String],
        actor: &Actor,
        audit: &NewAuditEntry,
    ) -> StorageResult<()> {
        let transazione = self.connection.transaction()?;
        transazione.execute("DELETE FROM dictionary_signers", [])?;
        for impronta in fingerprints {
            transazione.execute(
                "INSERT INTO dictionary_signers (fingerprint, added_at, added_by)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![impronta, millis(audit.recorded_at), actor.as_str()],
            )?;
        }
        scrivi_audit(&transazione, audit, None)?;
        transazione.commit()?;
        Ok(())
    }

    /// Registra un tentativo con la sua riga d'audit, nella stessa
    /// transazione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo schema rifiuta la riga o se la scrittura
    /// non riesce.
    pub fn insert_dictionary_download(
        &mut self,
        tentativo: &NewDictionaryDownload,
        audit: &NewAuditEntry,
    ) -> StorageResult<i64> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO dictionary_downloads (
                 requested_by, requested_at, url, content_sha256, signer_sha256,
                 declared_name, declared_version, outcome, outcome_detail,
                 dictionary_id, version_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                tentativo.requested_by,
                millis(tentativo.requested_at),
                tentativo.url,
                tentativo.content_sha256,
                tentativo.signer_sha256,
                tentativo.declared_name,
                tentativo.declared_version,
                tentativo.outcome,
                tentativo.outcome_detail,
                tentativo.dictionary_id,
                tentativo.version_id,
            ],
        )?;
        let id = transazione.last_insert_rowid();
        scrivi_audit(&transazione, audit, Some(id))?;
        transazione.commit()?;
        Ok(id)
    }

    /// I tentativi, dal più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn dictionary_downloads(&self) -> StorageResult<Vec<StoredDictionaryDownload>> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT {COLONNE} FROM dictionary_downloads ORDER BY requested_at DESC, id DESC"
        ))?;
        let righe = statement.query_map([], StoredDictionaryDownload::read)?;
        let mut tentativi = Vec::new();
        for riga in righe {
            tentativi.push(riga?);
        }
        Ok(tentativi)
    }

    /// L'ultimo ingresso riuscito di un dizionario con questo nome, se c'è.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn latest_dictionary_download_named(
        &self,
        name: &str,
    ) -> StorageResult<Option<StoredDictionaryDownload>> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT {COLONNE} FROM dictionary_downloads
             WHERE declared_name = ?1 AND outcome = 'importato'
             ORDER BY declared_version DESC, id DESC
             LIMIT 1"
        ))?;
        let mut righe = statement.query_map([name], StoredDictionaryDownload::read)?;
        Ok(righe.next().transpose()?)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::NewAuditEntry;
    use lisi_core::text::{AuditAction, AuditDetail, AuditEntity};

    use super::NewDictionaryDownload;
    use crate::test_support::{actor, database, later};

    fn audit(quando: i64) -> NewAuditEntry {
        let (Ok(action), Ok(entity), Ok(detail)) = (
            AuditAction::try_new("dizionario_scaricato"),
            AuditEntity::try_new("dizionario"),
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

    fn tentativo(versione: u32, esito: &str) -> NewDictionaryDownload {
        let ingresso = esito == "importato";
        NewDictionaryDownload {
            requested_by: String::from("operatore.prova"),
            requested_at: later(i64::from(versione)),
            url: String::from("https://esempio.test/d.json"),
            content_sha256: Some("a".repeat(64)),
            signer_sha256: Some("b".repeat(64)),
            declared_name: Some(String::from("Prova")),
            declared_version: Some(versione),
            outcome: String::from(esito),
            outcome_detail: None,
            dictionary_id: ingresso.then_some(1),
            version_id: ingresso.then_some(i64::from(versione)),
        }
    }

    /// **La fonte e i firmatari si scrivono con l'audit, e l'elenco si
    /// sostituisce per intero o per niente.**
    #[test]
    fn la_fonte_e_i_firmatari_si_scrivono_con_l_audit() {
        let mut database = database();
        assert_eq!(database.dictionary_network_source().ok(), Some(None));
        assert_eq!(database.dictionary_signers().ok(), Some(Vec::new()));

        let chi = actor("amministratore.prova");
        let Ok(()) = database.save_dictionary_network_source(
            Some("https://esempio.test/d.json"),
            &chi,
            &audit(1),
        ) else {
            panic!("una fonte https si salva");
        };
        assert_eq!(
            database
                .dictionary_network_source()
                .ok()
                .flatten()
                .as_deref(),
            Some("https://esempio.test/d.json")
        );

        let due = vec!["1".repeat(64), "2".repeat(64)];
        let Ok(()) = database.replace_dictionary_signers(&due, &chi, &audit(2)) else {
            panic!("due firmatari si ammettono");
        };
        // Un elenco con un'impronta sbagliata non tocca quello di prima.
        let sbagliato = vec!["3".repeat(64), String::from("non-esadecimale")];
        assert!(
            database
                .replace_dictionary_signers(&sbagliato, &chi, &audit(3))
                .is_err()
        );
        assert_eq!(database.dictionary_signers().ok(), Some(due));

        let Ok(righe) = database.audit_entries() else {
            panic!("l'audit si legge");
        };
        assert_eq!(
            righe
                .iter()
                .filter(|riga| riga.action.as_str() == "dizionario_scaricato")
                .count(),
            2,
            "due scritture riuscite, due righe d'audit; il rifiuto non ne lascia"
        );
    }

    /// **Il registro tiene ogni tentativo, e dice l'ultimo ingresso per nome.**
    #[test]
    fn il_registro_tiene_ogni_tentativo_e_l_ultimo_ingresso_per_nome() {
        let mut database = database();
        for (versione, esito) in [(2, "importato"), (5, "rifiutato"), (3, "importato")] {
            let Ok(_) = database.insert_dictionary_download(&tentativo(versione, esito), &audit(1))
            else {
                panic!("il tentativo {versione} si registra");
            };
        }
        let Ok(tutti) = database.dictionary_downloads() else {
            panic!("il registro si legge");
        };
        assert_eq!(tutti.len(), 3);
        let Ok(Some(ultimo)) = database.latest_dictionary_download_named("Prova") else {
            panic!("l'ultimo ingresso si trova");
        };
        assert_eq!(
            ultimo.declared_version,
            Some(3),
            "conta il numero più alto entrato, non un rifiuto più alto"
        );
        assert_eq!(
            database.latest_dictionary_download_named("Altro").ok(),
            Some(None)
        );
    }
}

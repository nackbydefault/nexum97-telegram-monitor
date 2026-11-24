//! Il registro delle ricerche puntuali (PR-09, ADR-0125).
//!
//! In sola aggiunta: una riga per ricerca, con l'esito per quello che è. La
//! ricerca e la sua riga d'audit si scrivono **nella stessa transazione**.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// Il profilo restituito da Telegram: soltanto per un esito «trovato».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundProfile {
    /// Il genere, nella parola dell'operatore.
    pub kind: String,
    /// L'identificativo Telegram.
    pub telegram_id: i64,
    /// Il nome mostrato.
    pub name: String,
    /// Il nome utente, se restituito.
    pub username: Option<String>,
    /// Nome, cognome, username attivi e telefono mascherato (ADR-0153).
    ///
    /// `None` per le ricerche registrate prima della migrazione 0059: allora non
    /// si registravano, e `None` lo dice — non è «Telegram non li ha dati».
    pub details: Option<FoundDetails>,
}

/// Ciò che la migrazione 0059 aggiunge a un profilo trovato.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FoundDetails {
    /// Il nome proprio, com'è arrivato; può essere vuoto.
    pub first_name: String,
    /// Il cognome, com'è arrivato; può essere vuoto.
    pub last_name: String,
    /// Tutti gli username attivi, nell'ordine di Telegram.
    pub usernames: Vec<String>,
    /// Il telefono **mascherato**, se Telegram lo ha restituito. Lo schema
    /// rifiuta una forma con più di due cifre in chiaro.
    pub phone_masked: Option<String>,
}

impl FoundDetails {
    /// Gli username come li conserva la colonna: separati da uno spazio.
    fn usernames_column(&self) -> String {
        self.usernames.join(" ")
    }

    /// Gli username dalla colonna.
    fn usernames_from(colonna: &str) -> Vec<String> {
        colonna.split_whitespace().map(str::to_owned).collect()
    }
}

/// Una ricerca da registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewIdentityResolution {
    /// Chi.
    pub requested_by: String,
    /// Perché.
    pub reason: String,
    /// Il genere dell'ingresso, nel nome stabile.
    pub input_kind: String,
    /// L'ingresso, com'è stato scritto.
    pub input_value: String,
    /// Quando.
    pub requested_at: Timestamp,
    /// Se la richiesta è partita verso Telegram.
    pub executed: bool,
    /// L'esito, nel nome stabile.
    pub outcome: String,
    /// Il motivo, o per un «trovato» ciò che è arrivato.
    pub outcome_reason: String,
    /// L'attesa indicata da Telegram, per un errore temporaneo.
    pub wait_seconds: Option<u32>,
    /// Codice e messaggio di Telegram, per la diagnostica.
    pub technical_detail: Option<String>,
    /// Il profilo, soltanto per un «trovato».
    pub found: Option<FoundProfile>,
    /// La versione della tabella degli esiti che l'ha classificata.
    pub table_version: u32,
}

/// Una ricerca registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredIdentityResolution {
    /// L'identificativo della riga.
    pub id: i64,
    /// Ciò che è stato registrato.
    pub resolution: NewIdentityResolution,
}

impl Database {
    /// Registra una ricerca **e** la sua riga d'audit, insieme.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce; in quel caso non resta
    /// né la ricerca né la riga d'audit.
    pub fn insert_identity_resolution(
        &mut self,
        ricerca: &NewIdentityResolution,
        audit: &NewAuditEntry,
    ) -> StorageResult<i64> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO identity_resolutions (
                 requested_by, reason, input_kind, input_value, requested_at, executed,
                 outcome, outcome_reason, wait_seconds, technical_detail, found_kind,
                 found_telegram_id, found_name, found_username, table_version,
                 found_first_name, found_last_name, found_usernames, found_phone_masked
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                       ?16, ?17, ?18, ?19)",
            rusqlite::params![
                ricerca.requested_by,
                ricerca.reason,
                ricerca.input_kind,
                ricerca.input_value,
                millis(ricerca.requested_at),
                i64::from(ricerca.executed),
                ricerca.outcome,
                ricerca.outcome_reason,
                ricerca.wait_seconds,
                ricerca.technical_detail,
                ricerca.found.as_ref().map(|profilo| profilo.kind.clone()),
                ricerca.found.as_ref().map(|profilo| profilo.telegram_id),
                ricerca.found.as_ref().map(|profilo| profilo.name.clone()),
                ricerca
                    .found
                    .as_ref()
                    .and_then(|profilo| profilo.username.clone()),
                ricerca.table_version,
                dettagli(ricerca).map(|d| d.first_name.clone()),
                dettagli(ricerca).map(|d| d.last_name.clone()),
                dettagli(ricerca).map(FoundDetails::usernames_column),
                dettagli(ricerca).and_then(|d| d.phone_masked.clone()),
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

    /// Le ricerche più recenti, dalla più nuova, al più `limite`.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn recent_identity_resolutions(
        &self,
        limite: u32,
    ) -> StorageResult<Vec<StoredIdentityResolution>> {
        let mut statement = self.connection.prepare(
            "SELECT id, requested_by, reason, input_kind, input_value, requested_at, executed,
                    outcome, outcome_reason, wait_seconds, technical_detail, found_kind,
                    found_telegram_id, found_name, found_username, table_version,
                    found_first_name, found_last_name, found_usernames, found_phone_masked
             FROM identity_resolutions
             ORDER BY requested_at DESC, id DESC
             LIMIT ?1",
        )?;
        let righe = statement.query_map([limite], read_row)?;
        let mut ricerche = Vec::new();
        for riga in righe {
            ricerche.push(riga?);
        }
        Ok(ricerche)
    }

    /// Una ricerca, per identificativo, se esiste.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn identity_resolution(&self, id: i64) -> StorageResult<Option<StoredIdentityResolution>> {
        let mut statement = self.connection.prepare(
            "SELECT id, requested_by, reason, input_kind, input_value, requested_at, executed,
                    outcome, outcome_reason, wait_seconds, technical_detail, found_kind,
                    found_telegram_id, found_name, found_username, table_version,
                    found_first_name, found_last_name, found_usernames, found_phone_masked
             FROM identity_resolutions
             WHERE id = ?1",
        )?;
        let mut righe = statement.query_map([id], read_row)?;
        Ok(righe.next().transpose()?)
    }

    /// Quante ricerche sono **partite verso Telegram** da `dal` in poi.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn executed_identity_resolutions_since(&self, dal: Timestamp) -> StorageResult<u32> {
        let quante: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM identity_resolutions WHERE executed = 1 AND requested_at >= ?1",
            [millis(dal)],
            |row| row.get(0),
        )?;
        Ok(u32::try_from(quante).unwrap_or(u32::MAX))
    }

    /// L'ultima ricerca partita verso Telegram: quando, e l'attesa che
    /// Telegram ha indicato, se ne ha indicata una.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn latest_executed_identity_resolution(
        &self,
    ) -> StorageResult<Option<(Timestamp, Option<u32>)>> {
        let mut statement = self.connection.prepare(
            "SELECT requested_at, wait_seconds FROM identity_resolutions
             WHERE executed = 1
             ORDER BY requested_at DESC, id DESC
             LIMIT 1",
        )?;
        let mut righe = statement.query([])?;
        match righe.next()? {
            Some(riga) => Ok(Some((instant(riga.get(0)?), riga.get(1)?))),
            None => Ok(None),
        }
    }
}

/// I dettagli di una ricerca da registrare, se ne porta.
fn dettagli(ricerca: &NewIdentityResolution) -> Option<&FoundDetails> {
    ricerca
        .found
        .as_ref()
        .and_then(|profilo| profilo.details.as_ref())
}

/// Una riga del registro, dalla SELECT comune.
fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredIdentityResolution> {
    let genere: Option<String> = row.get(11)?;
    let identificativo: Option<i64> = row.get(12)?;
    let nome: Option<String> = row.get(13)?;
    let nome_utente: Option<String> = row.get(14)?;
    let nome_proprio: Option<String> = row.get(16)?;
    let cognome: Option<String> = row.get(17)?;
    let nomi_utente: Option<String> = row.get(18)?;
    let telefono: Option<String> = row.get(19)?;
    // I DETTAGLI ESISTONO DALLA 0059: una riga di prima ha le quattro colonne
    // vuote, e resta senza dettagli invece di riceverne di inventati.
    let details = nomi_utente.map(|nomi| FoundDetails {
        first_name: nome_proprio.unwrap_or_default(),
        last_name: cognome.unwrap_or_default(),
        usernames: FoundDetails::usernames_from(&nomi),
        phone_masked: telefono,
    });
    // Il profilo c'è tutto, o non c'è: lo schema lo garantisce, e qui si
    // rilegge com'è.
    let found = genere
        .zip(identificativo)
        .map(|(kind, telegram_id)| FoundProfile {
            kind,
            telegram_id,
            name: nome.unwrap_or_default(),
            username: nome_utente,
            details,
        });
    Ok(StoredIdentityResolution {
        id: row.get(0)?,
        resolution: NewIdentityResolution {
            requested_by: row.get(1)?,
            reason: row.get(2)?,
            input_kind: row.get(3)?,
            input_value: row.get(4)?,
            requested_at: instant(row.get(5)?),
            executed: row.get::<_, i64>(6)? != 0,
            outcome: row.get(7)?,
            outcome_reason: row.get(8)?,
            wait_seconds: row.get(9)?,
            technical_detail: row.get(10)?,
            found,
            table_version: row.get(15)?,
        },
    })
}

#[cfg(test)]
mod tests {
    use lisi_core::model::NewAuditEntry;
    use lisi_core::text::{AuditAction, AuditEntity};

    use super::{FoundProfile, NewIdentityResolution};
    use crate::test_support::{actor, database, later};

    fn audit() -> NewAuditEntry {
        let (Ok(azione), Ok(entita)) = (
            AuditAction::try_new("ricerca_puntuale"),
            AuditEntity::try_new("ricerca"),
        ) else {
            panic!("valori d'audit validi");
        };
        NewAuditEntry {
            actor: actor("operatore.prova"),
            action: azione,
            entity: entita,
            entity_id: None,
            actor_mode: None,
            detail: None,
            recorded_at: later(1),
        }
    }

    fn ricerca(esito: &str, trovato: Option<FoundProfile>) -> NewIdentityResolution {
        NewIdentityResolution {
            requested_by: String::from("operatore.prova"),
            reason: String::from("fascicolo 12/2026"),
            input_kind: String::from("nome_utente"),
            input_value: String::from("canale_prova"),
            requested_at: later(1),
            executed: true,
            outcome: String::from(esito),
            outcome_reason: String::from("motivo"),
            wait_seconds: None,
            technical_detail: None,
            found: trovato,
            table_version: 1,
        }
    }

    /// **Una ricerca si registra, si rilegge e resta com'è.**
    #[test]
    fn una_ricerca_si_registra_e_resta() {
        let mut archivio = database();
        let profilo = FoundProfile {
            kind: String::from("canale"),
            telegram_id: -1_001,
            name: String::from("Canale"),
            username: Some(String::from("canale_prova")),
            details: None,
        };
        let Ok(_) = archivio
            .insert_identity_resolution(&ricerca("trovato", Some(profilo.clone())), &audit())
        else {
            panic!("la ricerca deve registrarsi");
        };
        let Ok(righe) = archivio.recent_identity_resolutions(10) else {
            panic!("il registro deve leggersi");
        };
        assert_eq!(righe.len(), 1);
        assert_eq!(righe[0].resolution.found, Some(profilo));
        for comando in [
            "UPDATE identity_resolutions SET outcome = 'dato_non_disponibile'",
            "DELETE FROM identity_resolutions",
        ] {
            assert!(
                archivio.connection.execute(comando, []).is_err(),
                "«{comando}» deve essere rifiutato"
            );
        }
        let Ok(quante) = archivio.executed_identity_resolutions_since(later(0)) else {
            panic!("il conteggio deve riuscire");
        };
        assert_eq!(quante, 1);
    }

    /// **Un profilo senza «trovato», o un «trovato» senza profilo, non
    /// entrano**: il registro non conserva ipotesi (controllo negativo 5).
    #[test]
    fn nessun_profilo_fuori_da_un_trovato() {
        let mut archivio = database();
        let profilo = FoundProfile {
            kind: String::from("persona"),
            telegram_id: 42,
            name: String::from("Nome ipotizzato"),
            username: None,
            details: None,
        };
        assert!(
            archivio
                .insert_identity_resolution(
                    &ricerca("dato_non_disponibile", Some(profilo)),
                    &audit()
                )
                .is_err()
        );
        assert!(
            archivio
                .insert_identity_resolution(&ricerca("trovato", None), &audit())
                .is_err()
        );
        let mut con_attesa = ricerca("dato_non_disponibile", None);
        con_attesa.wait_seconds = Some(30);
        assert!(
            archivio
                .insert_identity_resolution(&con_attesa, &audit())
                .is_err()
        );
        let Ok(righe) = archivio.recent_identity_resolutions(10) else {
            panic!("il registro deve leggersi");
        };
        assert!(righe.is_empty(), "nessuna riga orfana");
        let Ok(voci) = archivio.audit_entries() else {
            panic!("l'audit deve leggersi");
        };
        assert!(
            voci.iter()
                .all(|voce| voce.action.as_str() != "ricerca_puntuale")
        );
    }
}

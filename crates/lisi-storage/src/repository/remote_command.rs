//! I comandi a distanza dei monitoraggi dell'Hub (HUB-REMOTE-01, ADR-0200,
//! migrazione 0091).
//!
//! La scelta di accettarli è un'azione e porta la sua riga d'audit nella stessa
//! transazione. Un comando ricevuto si scrive una volta, con la sua riga
//! d'audit, e non cambia più.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::text::Actor;
use rusqlite::OptionalExtension;

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// Un comando a distanza registrato sull'Hub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRemoteCommand {
    /// L'identificativo che la postazione ha dato al comando.
    pub command_id: String,
    /// Da quale postazione.
    pub device: String,
    /// Chi, come è entrato presso l'Hub.
    pub person: String,
    /// Su quale monitoraggio.
    pub session_id: i64,
    /// `pausa`, `ripresa` o `arresto`.
    pub action: String,
    /// Il motivo, come è stato scritto.
    pub reason: String,
    /// `eseguito` o `rifiutato`.
    pub outcome: String,
    /// Che cosa l'Hub ha risposto.
    pub detail: String,
    /// Quando l'Hub l'ha ricevuto.
    pub received_at: Timestamp,
}

impl Database {
    /// Se l'Hub accetta comandi a distanza.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn remote_commands_accepted(&self) -> StorageResult<bool> {
        let accettati: i64 = self.connection.query_row(
            "SELECT accepted FROM remote_command_settings WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(accettati == 1)
    }

    /// Accende o spegne i comandi a distanza, con la sua riga d'audit.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce: in quel caso non
    /// cambia niente.
    pub fn save_remote_commands_accepted(
        &mut self,
        accepted: bool,
        actor: &Actor,
        audit: &NewAuditEntry,
    ) -> StorageResult<()> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "UPDATE remote_command_settings
             SET accepted = ?1, updated_at = ?2, updated_by = ?3
             WHERE id = 1",
            rusqlite::params![
                i64::from(accepted),
                millis(audit.recorded_at),
                actor.as_str()
            ],
        )?;
        inserisci_audit(&transazione, audit)?;
        transazione.commit()?;
        Ok(())
    }

    /// Il comando già registrato con questo identificativo, se c'è.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn remote_command(&self, command_id: &str) -> StorageResult<Option<StoredRemoteCommand>> {
        Ok(self
            .connection
            .query_row(
                &format!("{SELEZIONE} WHERE command_id = ?1"),
                [command_id],
                riga,
            )
            .optional()?)
    }

    /// Registra un comando ricevuto, con la sua riga d'audit.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la riga non rispetta lo schema — compreso un
    /// identificativo già registrato — o la scrittura non riesce.
    pub fn insert_remote_command(
        &mut self,
        command: &StoredRemoteCommand,
        audit: &NewAuditEntry,
    ) -> StorageResult<()> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO remote_commands (command_id, device, person, session_id, action,
                 reason, outcome, detail, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                command.command_id,
                command.device,
                command.person,
                command.session_id,
                command.action,
                command.reason,
                command.outcome,
                command.detail,
                millis(command.received_at),
            ],
        )?;
        inserisci_audit(&transazione, audit)?;
        transazione.commit()?;
        Ok(())
    }

    /// I comandi ricevuti, i più recenti prima, al più `limit`.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn remote_commands(&self, limit: usize) -> StorageResult<Vec<StoredRemoteCommand>> {
        let mut istruzione = self.connection.prepare(&format!(
            "{SELEZIONE} ORDER BY received_at DESC, id DESC LIMIT ?1"
        ))?;
        let righe = istruzione
            .query_map([i64::try_from(limit).unwrap_or(i64::MAX)], riga)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(righe)
    }
}

const SELEZIONE: &str = "SELECT command_id, device, person, session_id, action, reason, outcome,
     detail, received_at FROM remote_commands";

fn riga(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredRemoteCommand> {
    Ok(StoredRemoteCommand {
        command_id: row.get(0)?,
        device: row.get(1)?,
        person: row.get(2)?,
        session_id: row.get(3)?,
        action: row.get(4)?,
        reason: row.get(5)?,
        outcome: row.get(6)?,
        detail: row.get(7)?,
        received_at: instant(row.get(8)?),
    })
}

fn inserisci_audit(
    transazione: &rusqlite::Transaction<'_>,
    audit: &NewAuditEntry,
) -> StorageResult<()> {
    transazione.execute(
        "INSERT INTO audit (actor, action, entity, entity_id, detail, recorded_at, actor_mode)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            audit.actor.as_str(),
            audit.action.as_str(),
            audit.entity.as_str(),
            audit.entity_id,
            audit
                .detail
                .as_ref()
                .map(|dettaglio| dettaglio.as_str().to_owned()),
            millis(audit.recorded_at),
            audit.actor_mode.map(|modo| modo.as_str()),
        ],
    )?;
    Ok(())
}

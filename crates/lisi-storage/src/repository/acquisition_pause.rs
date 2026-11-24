//! Le pause dell'acquisizione (PAUSE-01, ADR-0172, migrazione 0071).
//!
//! Una riga per pausa, con la sua riga d'audit nella stessa transazione. Una
//! sola pausa aperta per monitoraggio; la ripresa la completa una volta; le
//! righe non si cancellano. Lo schema lo impone.

use lisi_core::SessionId;
use lisi_core::model::NewAuditEntry;
use lisi_core::model::acquisition_pause::AcquisitionPause;
use lisi_core::model::reason::OperationalReason;
use lisi_core::text::Actor;
use lisi_core::time::Timestamp;

use crate::Database;
use crate::error::{StorageError, StorageResult};
use crate::repository::{instant, millis};

/// Le colonne di una riga, nell'ordine delle letture.
const COLONNE: &str = "session_id, paused_at, paused_by, reason, resumed_at, resumed_by";

/// Una riga letta, prima di diventare dominio.
type Riga = (i64, i64, String, String, Option<i64>, Option<String>);

fn leggi(row: &rusqlite::Row<'_>) -> rusqlite::Result<Riga> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

/// La riga nel dominio. Un attore o un motivo che l'archivio conserva in una
/// forma che il dominio non accetta non si indovinano: la riga si salta.
fn dominio((session_id, at, by, reason, resumed_at, resumed_by): Riga) -> Option<AcquisitionPause> {
    let resumed_by = match resumed_by {
        Some(chi) => Some(Actor::try_new(&chi).ok()?),
        None => None,
    };
    Some(AcquisitionPause {
        session_id: SessionId::new(session_id),
        paused_at: instant(at),
        paused_by: Actor::try_new(&by).ok()?,
        reason: OperationalReason::try_new(&reason).ok()?,
        resumed_at: resumed_at.map(instant),
        resumed_by,
    })
}

/// Scrive la riga d'audit dentro una transazione aperta.
fn audit_in(
    transazione: &rusqlite::Transaction<'_>,
    audit: &NewAuditEntry,
    entity_id: i64,
) -> StorageResult<()> {
    transazione.execute(
        "INSERT INTO audit (actor, action, entity, entity_id, detail, recorded_at, actor_mode)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            audit.actor.as_str(),
            audit.action.as_str(),
            audit.entity.as_str(),
            Some(entity_id),
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

impl Database {
    /// Apre una pausa **e** registra la sua riga d'audit, insieme.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se una pausa è già aperta, se lo schema rifiuta i
    /// valori, o se la scrittura non riesce; allora non resta niente.
    pub fn insert_acquisition_pause(
        &mut self,
        session_id: SessionId,
        at: Timestamp,
        by: &Actor,
        reason: &OperationalReason,
        audit: &NewAuditEntry,
    ) -> StorageResult<()> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO acquisition_pauses (session_id, paused_at, paused_by, reason)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![session_id.get(), millis(at), by.as_str(), reason.as_str()],
        )?;
        audit_in(&transazione, audit, session_id.get())?;
        transazione.commit()?;
        Ok(())
    }

    /// Chiude la pausa aperta di un monitoraggio **e** registra la sua riga
    /// d'audit, insieme.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se non c'è una pausa aperta, e un
    /// errore se la scrittura non riesce; allora non resta niente.
    pub fn resume_acquisition_pause(
        &mut self,
        session_id: SessionId,
        at: Timestamp,
        by: &Actor,
        audit: &NewAuditEntry,
    ) -> StorageResult<()> {
        let transazione = self.connection.transaction()?;
        let quante = transazione.execute(
            "UPDATE acquisition_pauses SET resumed_at = max(?2, paused_at), resumed_by = ?3
             WHERE session_id = ?1 AND resumed_at IS NULL",
            rusqlite::params![session_id.get(), millis(at), by.as_str()],
        )?;
        if quante == 0 {
            return Err(StorageError::NotFound {
                entity: "acquisition_pause",
                id: session_id.get(),
            });
        }
        audit_in(&transazione, audit, session_id.get())?;
        transazione.commit()?;
        Ok(())
    }

    /// Le pause di un monitoraggio, dalla più vecchia.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn acquisition_pauses(
        &self,
        session_id: SessionId,
    ) -> StorageResult<Vec<AcquisitionPause>> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT {COLONNE} FROM acquisition_pauses WHERE session_id = ?1
             ORDER BY paused_at, id"
        ))?;
        let righe = statement.query_map([session_id.get()], leggi)?;
        let mut pause = Vec::new();
        for riga in righe {
            if let Some(pausa) = dominio(riga?) {
                pause.push(pausa);
            }
        }
        Ok(pause)
    }

    /// **Quanti** dei monitoraggi che ricevono hanno l'acquisizione in pausa
    /// (COLLAUDO-FIX-01, CU01-004, DEC-509): la condizione di
    /// [`Database::receiving_session_count`], più una pausa aperta.
    ///
    /// Il Cruscotto li confronta con quelli che ricevono: se sono tutti in
    /// pausa non si acquisisce nulla, e non si dice «in corso».
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il conteggio non riesce.
    pub fn paused_receiving_session_count(&self) -> StorageResult<usize> {
        let quanti: i64 = self.connection.query_row(
            "SELECT count(*) FROM sessions AS s
             WHERE s.state IN ('running', 'paused')
               AND NOT EXISTS (
                   SELECT 1 FROM session_interruptions AS i
                   WHERE i.session_id = s.id AND i.acknowledged_at IS NULL
               )
               AND EXISTS (
                   SELECT 1 FROM acquisition_pauses AS p
                   WHERE p.session_id = s.id AND p.resumed_at IS NULL
               )",
            [],
            |row| row.get(0),
        )?;
        Ok(usize::try_from(quanti).unwrap_or(0))
    }

    /// I monitoraggi con una pausa aperta.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn paused_session_ids(&self) -> StorageResult<Vec<SessionId>> {
        let mut statement = self.connection.prepare(
            "SELECT session_id FROM acquisition_pauses WHERE resumed_at IS NULL
             ORDER BY session_id",
        )?;
        let righe = statement.query_map([], |row| row.get::<_, i64>(0))?;
        let mut sessioni = Vec::new();
        for riga in righe {
            sessioni.push(SessionId::new(riga?));
        }
        Ok(sessioni)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::NewAuditEntry;
    use lisi_core::model::reason::OperationalReason;
    use lisi_core::text::{AuditAction, AuditEntity};

    use crate::test_support::{actor, database_with_session, later};

    fn audit(azione: &str) -> NewAuditEntry {
        let (Ok(azione), Ok(entita)) = (
            AuditAction::try_new(azione),
            AuditEntity::try_new("session"),
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
            recorded_at: later(0),
        }
    }

    fn motivo() -> OperationalReason {
        let Ok(motivo) = OperationalReason::try_new("Riunione d'ufficio, riprendo dopo pranzo")
        else {
            panic!("il motivo di prova deve essere valido");
        };
        motivo
    }

    /// **Si contano quelli che ricevono e hanno l'acquisizione in pausa**
    /// (COLLAUDO-FIX-01, CU01-004, DEC-509).
    #[test]
    fn si_contano_quelli_che_ricevono_in_pausa() {
        use lisi_core::model::session::SessionState;

        let (mut database, _, session_id) = database_with_session();
        let Ok(()) = database.update_session_state(session_id, SessionState::Running, later(5))
        else {
            panic!("la sessione di prova deve potersi avviare");
        };
        assert_eq!(database.receiving_session_count().ok(), Some(1));
        assert_eq!(database.paused_receiving_session_count().ok(), Some(0));

        let chi = actor("operatore.prova");
        let Ok(()) = database.insert_acquisition_pause(
            session_id,
            later(10),
            &chi,
            &motivo(),
            &audit("acquisizione_in_pausa"),
        ) else {
            panic!("la pausa deve aprirsi");
        };
        assert_eq!(database.paused_receiving_session_count().ok(), Some(1));
        // Riceve ancora, nell'archivio: la veglia non cambia (DEC-509).
        assert_eq!(database.receiving_session_count().ok(), Some(1));

        let Ok(()) = database.resume_acquisition_pause(
            session_id,
            later(70),
            &chi,
            &audit("acquisizione_ripresa"),
        ) else {
            panic!("la pausa deve riprendersi");
        };
        assert_eq!(database.paused_receiving_session_count().ok(), Some(0));
    }

    /// **Una pausa aperta per volta, completata una volta, mai cancellata, con
    /// l'audit nella stessa transazione** (PAUSE-01, ADR-0172, criterio 3;
    /// prova negativa: il divieto di riscrivere tolto → rossa).
    #[test]
    fn una_pausa_si_apre_una_volta_e_si_completa_una_volta() {
        let (mut database, _, session_id) = database_with_session();
        let chi = actor("operatore.prova");
        let Ok(()) = database.insert_acquisition_pause(
            session_id,
            later(10),
            &chi,
            &motivo(),
            &audit("acquisizione_in_pausa"),
        ) else {
            panic!("la pausa deve aprirsi");
        };
        assert!(
            database
                .insert_acquisition_pause(
                    session_id,
                    later(11),
                    &chi,
                    &motivo(),
                    &audit("acquisizione_in_pausa"),
                )
                .is_err(),
            "una seconda pausa aperta"
        );
        assert_eq!(database.paused_session_ids().ok(), Some(vec![session_id]));

        let Ok(()) = database.resume_acquisition_pause(
            session_id,
            later(70),
            &chi,
            &audit("acquisizione_ripresa"),
        ) else {
            panic!("la pausa deve riprendersi");
        };
        assert!(
            database
                .resume_acquisition_pause(
                    session_id,
                    later(80),
                    &chi,
                    &audit("acquisizione_ripresa")
                )
                .is_err(),
            "nessuna pausa aperta da riprendere"
        );
        assert_eq!(database.paused_session_ids().ok(), Some(Vec::new()));

        let Ok(pause) = database.acquisition_pauses(session_id) else {
            panic!("le pause devono rileggersi");
        };
        assert_eq!(pause.len(), 1);
        assert_eq!(pause[0].span(later(999)), (later(10), later(70)));
        assert!(!pause[0].is_open());

        // Una pausa chiusa non si riscrive e non si cancella. I valori nuovi
        // sono validi per ogni altro vincolo: a rifiutarli dev'essere il
        // divieto, non un controllo sulla forma (la prima stesura usava un
        // istante prima della pausa, e la prova restava verde senza divieto).
        assert!(
            database
                .connection
                .execute(
                    "UPDATE acquisition_pauses SET resumed_at = resumed_at + 1000",
                    []
                )
                .is_err(),
            "la ripresa di una pausa chiusa si riscrive"
        );
        assert!(
            database
                .connection
                .execute(
                    "UPDATE acquisition_pauses SET reason = 'un altro motivo lungo abbastanza'",
                    []
                )
                .is_err(),
            "il motivo di una pausa si riscrive"
        );
        assert!(
            database
                .connection
                .execute("DELETE FROM acquisition_pauses", [])
                .is_err()
        );
        // Due righe d'audit, una per atto.
        let Ok(voci) = database.audit_entries() else {
            panic!("l'audit deve leggersi");
        };
        assert_eq!(
            voci.iter()
                .filter(|voce| voce.action.as_str().starts_with("acquisizione_"))
                .count(),
            2
        );
    }
}

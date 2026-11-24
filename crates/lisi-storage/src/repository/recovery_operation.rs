//! Il registro delle operazioni di recupero (PR-07, ADR-0123).
//!
//! In sola aggiunta: un'operazione non si modifica e non si cancella, e un
//! legame fra un contenuto e la sua operazione non si modifica. L'operazione, i
//! legami e la riga d'audit si scrivono **nella stessa transazione**: un
//! recupero senza chi lo ha chiesto, o una traccia di un recupero mai
//! registrato, non devono poter esistere.

use std::collections::BTreeMap;

use lisi_core::model::NewAuditEntry;
use lisi_core::{ContentId, SessionId, SourceId, Timestamp};

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// Un'operazione da registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRecoveryOperation {
    /// Il monitoraggio a cui i contenuti appartengono.
    pub session_id: SessionId,
    /// La fonte letta.
    pub source_id: SourceId,
    /// L'intervallo richiesto; `None` per il recupero fino all'inizio del
    /// monitoraggio.
    pub interval: Option<(Timestamp, Timestamp)>,
    /// Chi lo ha chiesto.
    pub requested_by: String,
    /// Quando.
    pub performed_at: Timestamp,
    /// Quanti messaggi mancanti la ricognizione ha trovato.
    pub found: u32,
    /// I contenuti archiviati da questa operazione.
    pub archived: Vec<ContentId>,
}

/// Un'operazione registrata, come la vede chi dichiara un modo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecovery {
    /// L'operazione.
    pub operation_id: i64,
    /// L'intervallo, se registrato.
    pub interval: Option<(Timestamp, Timestamp)>,
    /// Chi lo ha chiesto.
    pub requested_by: String,
    /// Quando.
    pub performed_at: Timestamp,
}

impl Database {
    /// Registra un'operazione, i legami con i contenuti archiviati e la riga
    /// d'audit, **insieme**.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce; in quel caso non resta
    /// nulla.
    pub fn insert_recovery_operation(
        &mut self,
        operazione: &NewRecoveryOperation,
        audit: &NewAuditEntry,
    ) -> StorageResult<i64> {
        let archiviati = i64::try_from(operazione.archived.len()).unwrap_or(i64::MAX);
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO recovery_operations (
                 session_id, source_id, interval_from, interval_to, requested_by,
                 performed_at, found, archived
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                operazione.session_id.get(),
                operazione.source_id.get(),
                operazione.interval.map(|(da, _)| millis(da)),
                operazione.interval.map(|(_, a)| millis(a)),
                operazione.requested_by,
                millis(operazione.performed_at),
                operazione.found,
                archiviati,
            ],
        )?;
        let id = transazione.last_insert_rowid();
        for contenuto in &operazione.archived {
            transazione.execute(
                "INSERT INTO content_recoveries (content_id, operation_id) VALUES (?1, ?2)",
                rusqlite::params![contenuto.get(), id],
            )?;
        }
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

    /// I contenuti recuperati di un monitoraggio e di una fonte che non sono
    /// ancora legati a un'operazione: identificativo e identificativo remoto.
    ///
    /// Sono quelli appena archiviati da un recupero, e quelli dei recuperi
    /// anteriori a PR-07, che restano senza operazione: a chi chiama il compito
    /// di scegliere soltanto i primi, per identificativo remoto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn unlinked_recovered_contents(
        &self,
        session_id: SessionId,
        source_id: SourceId,
    ) -> StorageResult<Vec<(ContentId, String)>> {
        let mut statement = self.connection.prepare(
            "SELECT contents.id, contents.remote_message_id
             FROM contents
             LEFT JOIN content_recoveries ON content_recoveries.content_id = contents.id
             WHERE contents.session_id = ?1
               AND contents.source_id = ?2
               AND contents.acquisition_origin = 'recuperato'
               AND content_recoveries.content_id IS NULL
             ORDER BY contents.id",
        )?;
        let righe = statement.query_map(
            rusqlite::params![session_id.get(), source_id.get()],
            |row| Ok((ContentId::new(row.get(0)?), row.get::<_, String>(1)?)),
        )?;
        let mut trovati = Vec::new();
        for riga in righe {
            trovati.push(riga?);
        }
        Ok(trovati)
    }

    /// Per ogni contenuto recuperato di un monitoraggio, l'operazione che lo ha
    /// portato in archivio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn session_recoveries(
        &self,
        session_id: SessionId,
    ) -> StorageResult<BTreeMap<i64, StoredRecovery>> {
        let mut statement = self.connection.prepare(
            "SELECT content_recoveries.content_id, recovery_operations.id,
                    recovery_operations.interval_from, recovery_operations.interval_to,
                    recovery_operations.requested_by, recovery_operations.performed_at
             FROM content_recoveries
             JOIN recovery_operations ON recovery_operations.id = content_recoveries.operation_id
             WHERE recovery_operations.session_id = ?1",
        )?;
        let righe = statement.query_map([session_id.get()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?;
        let mut legami = BTreeMap::new();
        for riga in righe {
            let (contenuto, operazione, da, a, chi, quando) = riga?;
            legami.insert(
                contenuto,
                StoredRecovery {
                    operation_id: operazione,
                    interval: da.zip(a).map(|(da, a)| (instant(da), instant(a))),
                    requested_by: chi,
                    performed_at: instant(quando),
                },
            );
        }
        Ok(legami)
    }

    /// Le operazioni di recupero registrate per una fonte, dalla più vecchia.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn source_recovery_operations(
        &self,
        source_id: SourceId,
    ) -> StorageResult<Vec<RecordedRecovery>> {
        let mut statement = self.connection.prepare(
            "SELECT session_id, interval_from, interval_to, requested_by, performed_at,
                    found, archived
             FROM recovery_operations
             WHERE source_id = ?1
             ORDER BY performed_at, id",
        )?;
        let righe = statement.query_map([source_id.get()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?;
        let mut operazioni = Vec::new();
        for riga in righe {
            let (sessione, da, a, chi, quando, trovati, archiviati) = riga?;
            operazioni.push(RecordedRecovery {
                session_id: SessionId::new(sessione),
                interval: da.zip(a).map(|(da, a)| (instant(da), instant(a))),
                requested_by: chi,
                performed_at: instant(quando),
                found: u32::try_from(trovati).unwrap_or(u32::MAX),
                archived: u32::try_from(archiviati).unwrap_or(u32::MAX),
            });
        }
        Ok(operazioni)
    }
}

/// Un'operazione registrata, con i suoi conteggi: ciò che la schermata del
/// recupero mostra accanto a un periodo già recuperato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedRecovery {
    /// Il monitoraggio.
    pub session_id: SessionId,
    /// L'intervallo, se registrato.
    pub interval: Option<(Timestamp, Timestamp)>,
    /// Chi lo ha chiesto.
    pub requested_by: String,
    /// Quando.
    pub performed_at: Timestamp,
    /// Quanti messaggi mancanti la ricognizione aveva trovato.
    pub found: u32,
    /// Quanti ne sono entrati in archivio.
    pub archived: u32,
}

#[cfg(test)]
mod tests {
    use lisi_core::model::NewAuditEntry;
    use lisi_core::text::{AuditAction, AuditEntity};
    use lisi_core::{ContentId, SessionId, SourceId};

    use super::NewRecoveryOperation;
    use crate::test_support::{actor, database_with_session, later};

    fn audit() -> NewAuditEntry {
        let (Ok(azione), Ok(entita)) = (
            AuditAction::try_new("recupero_archiviato"),
            AuditEntity::try_new("recupero"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        NewAuditEntry {
            actor: actor("operatore.prova"),
            action: azione,
            entity: entita,
            entity_id: None,
            actor_mode: None,
            detail: None,
            recorded_at: later(40),
        }
    }

    fn operazione(sessione: SessionId, fonte: SourceId) -> NewRecoveryOperation {
        NewRecoveryOperation {
            session_id: sessione,
            source_id: fonte,
            interval: Some((later(10), later(20))),
            requested_by: String::from("operatore.prova"),
            performed_at: later(40),
            found: 0,
            archived: Vec::new(),
        }
    }

    /// **L'operazione si registra e non si tocca più.**
    #[test]
    fn un_operazione_si_registra_e_resta_com_e() {
        let (mut archivio, fonte, sessione) = database_with_session();
        let Ok(_) = archivio.insert_recovery_operation(&operazione(sessione, fonte), &audit())
        else {
            panic!("l'operazione deve registrarsi");
        };
        assert!(
            archivio
                .connection
                .execute("UPDATE recovery_operations SET requested_by = 'altri'", [])
                .is_err()
        );
        assert!(
            archivio
                .connection
                .execute("DELETE FROM recovery_operations", [])
                .is_err()
        );
    }

    /// **Un intervallo a metà, un operatore vuoto o più archiviati che trovati
    /// non entrano**, e la transazione non lascia tracce.
    #[test]
    fn un_operazione_incoerente_non_entra() {
        let (mut archivio, fonte, sessione) = database_with_session();
        let mut senza_operatore = operazione(sessione, fonte);
        senza_operatore.requested_by = String::from("  ");
        assert!(
            archivio
                .insert_recovery_operation(&senza_operatore, &audit())
                .is_err()
        );

        let mut troppi = operazione(sessione, fonte);
        troppi.archived = vec![ContentId::new(1)];
        assert!(
            archivio
                .insert_recovery_operation(&troppi, &audit())
                .is_err()
        );

        let Ok(voci) = archivio.audit_entries() else {
            panic!("l'audit deve leggersi");
        };
        assert!(
            voci.iter()
                .all(|voce| voce.action.as_str() != "recupero_archiviato"),
            "una transazione rifiutata non lascia la sua traccia"
        );
        let Ok(legami) = archivio.session_recoveries(sessione) else {
            panic!("i legami devono leggersi");
        };
        assert!(legami.is_empty());
    }
}

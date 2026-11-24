//! Gli elenchi degli iscritti delle fonti (MEMBERS-01, ADR-0201, migrazione
//! 0092).
//!
//! La scelta di abilitarli è un'azione e porta la sua riga d'audit nella
//! stessa transazione. Una richiesta si scrive una volta, con le sue righe e
//! la sua riga d'audit, e non cambia più.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::text::Actor;

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// Una richiesta da registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewMembersListing {
    /// La fonte.
    pub source_id: i64,
    /// La chat della fonte presso Telegram.
    pub chat_id: i64,
    /// L'account d'ufficio che ha chiesto, se noto.
    pub account_uuid: Option<String>,
    /// Chi.
    pub requested_by: String,
    /// Perché.
    pub reason: String,
    /// Quando.
    pub requested_at: Timestamp,
    /// `ottenuto`, `rifiutato`, `non_riuscito` o `non_gruppo`.
    pub outcome: &'static str,
    /// Il perché dell'esito, quando non è ottenuto.
    pub outcome_detail: Option<String>,
    /// Quanti iscritti dichiarava Telegram.
    pub declared_total: Option<i64>,
    /// Vero se la richiesta si è fermata al tetto.
    pub stopped_at_cap: bool,
}

/// Un iscritto da registrare. Il telefono è **già** mascherato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewMemberRow {
    /// L'identificativo numerico.
    pub user_id: i64,
    /// Nome e cognome.
    pub display_name: Option<String>,
    /// Lo username.
    pub username: Option<String>,
    /// Il telefono mascherato.
    pub masked_phone: Option<String>,
    /// La chiave dello stato.
    pub status: &'static str,
    /// Da quando è iscritto.
    pub joined_at: Option<Timestamp>,
}

/// Una richiesta registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMembersListing {
    /// L'identificativo.
    pub id: i64,
    /// La fonte.
    pub source_id: i64,
    /// Chi.
    pub requested_by: String,
    /// Perché.
    pub reason: String,
    /// Quando.
    pub requested_at: Timestamp,
    /// L'esito, nel nome stabile.
    pub outcome: String,
    /// Il perché dell'esito.
    pub outcome_detail: Option<String>,
    /// Quanti iscritti dichiarava Telegram.
    pub declared_total: Option<i64>,
    /// Quanti ne sono arrivati.
    pub received: i64,
    /// Vero se la richiesta si è fermata al tetto.
    pub stopped_at_cap: bool,
}

/// Un iscritto registrato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMemberRow {
    /// L'identificativo numerico.
    pub user_id: i64,
    /// Nome e cognome.
    pub display_name: Option<String>,
    /// Lo username.
    pub username: Option<String>,
    /// Il telefono mascherato.
    pub masked_phone: Option<String>,
    /// La chiave dello stato.
    pub status: String,
    /// Da quando è iscritto.
    pub joined_at: Option<Timestamp>,
}

impl Database {
    /// Se l'elenco degli iscritti è abilitato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn members_listing_enabled(&self) -> StorageResult<bool> {
        let abilitato: i64 = self.connection.query_row(
            "SELECT enabled FROM members_listing_settings WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(abilitato == 1)
    }

    /// Abilita o spegne l'elenco degli iscritti, con la sua riga d'audit.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce: in quel caso non
    /// cambia niente.
    pub fn save_members_listing_enabled(
        &mut self,
        enabled: bool,
        actor: &Actor,
        audit: &NewAuditEntry,
    ) -> StorageResult<()> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "UPDATE members_listing_settings
             SET enabled = ?1, updated_at = ?2, updated_by = ?3
             WHERE id = 1",
            rusqlite::params![
                i64::from(enabled),
                millis(audit.recorded_at),
                actor.as_str()
            ],
        )?;
        inserisci_audit(&transazione, audit, None)?;
        transazione.commit()?;
        Ok(())
    }

    /// Registra una richiesta, i suoi iscritti e la riga d'audit, insieme.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo schema rifiuta qualcosa o la scrittura non
    /// riesce: allora non resta niente.
    pub fn insert_members_listing(
        &mut self,
        richiesta: &NewMembersListing,
        righe: &[NewMemberRow],
        audit: &NewAuditEntry,
    ) -> StorageResult<i64> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO members_listings (source_id, chat_id, account_uuid, requested_by, reason,
                 requested_at, outcome, outcome_detail, declared_total, received, stopped_at_cap)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                richiesta.source_id,
                richiesta.chat_id,
                richiesta.account_uuid,
                richiesta.requested_by,
                richiesta.reason,
                millis(richiesta.requested_at),
                richiesta.outcome,
                richiesta.outcome_detail,
                richiesta.declared_total,
                i64::try_from(righe.len()).unwrap_or(i64::MAX),
                i64::from(richiesta.stopped_at_cap),
            ],
        )?;
        let id = transazione.last_insert_rowid();
        for (posizione, riga) in righe.iter().enumerate() {
            transazione.execute(
                "INSERT INTO members_listing_rows (listing_id, position, user_id, display_name,
                     username, masked_phone, status, joined_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    id,
                    i64::try_from(posizione).unwrap_or(i64::MAX),
                    riga.user_id,
                    riga.display_name,
                    riga.username,
                    riga.masked_phone,
                    riga.status,
                    riga.joined_at.map(millis),
                ],
            )?;
        }
        inserisci_audit(&transazione, audit, Some(id))?;
        transazione.commit()?;
        Ok(id)
    }

    /// Quando è partita l'ultima richiesta, se ce n'è una.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn last_members_listing_at(&self) -> StorageResult<Option<Timestamp>> {
        let ultima: Option<i64> = self.connection.query_row(
            "SELECT MAX(requested_at) FROM members_listings",
            [],
            |row| row.get(0),
        )?;
        Ok(ultima.map(instant))
    }

    /// Le richieste più recenti, dalla più nuova, al più `limite`.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn members_listings(&self, limite: u32) -> StorageResult<Vec<StoredMembersListing>> {
        let mut statement = self.connection.prepare(
            "SELECT id, source_id, requested_by, reason, requested_at, outcome, outcome_detail,
                    declared_total, received, stopped_at_cap
             FROM members_listings
             ORDER BY requested_at DESC, id DESC
             LIMIT ?1",
        )?;
        let righe = statement.query_map([limite], |row| {
            Ok(StoredMembersListing {
                id: row.get(0)?,
                source_id: row.get(1)?,
                requested_by: row.get(2)?,
                reason: row.get(3)?,
                requested_at: instant(row.get(4)?),
                outcome: row.get(5)?,
                outcome_detail: row.get(6)?,
                declared_total: row.get(7)?,
                received: row.get(8)?,
                stopped_at_cap: row.get::<_, i64>(9)? == 1,
            })
        })?;
        let mut elenchi = Vec::new();
        for riga in righe {
            elenchi.push(riga?);
        }
        Ok(elenchi)
    }

    /// Gli iscritti di una richiesta, nell'ordine in cui sono arrivati.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn members_listing_rows(&self, listing_id: i64) -> StorageResult<Vec<StoredMemberRow>> {
        let mut statement = self.connection.prepare(
            "SELECT user_id, display_name, username, masked_phone, status, joined_at
             FROM members_listing_rows
             WHERE listing_id = ?1
             ORDER BY position",
        )?;
        let righe = statement.query_map([listing_id], |row| {
            Ok(StoredMemberRow {
                user_id: row.get(0)?,
                display_name: row.get(1)?,
                username: row.get(2)?,
                masked_phone: row.get(3)?,
                status: row.get(4)?,
                joined_at: row.get::<_, Option<i64>>(5)?.map(instant),
            })
        })?;
        let mut iscritti = Vec::new();
        for riga in righe {
            iscritti.push(riga?);
        }
        Ok(iscritti)
    }
}

fn inserisci_audit(
    transazione: &rusqlite::Transaction<'_>,
    audit: &NewAuditEntry,
    entity_id: Option<i64>,
) -> StorageResult<()> {
    transazione.execute(
        "INSERT INTO audit (actor, action, entity, entity_id, detail, recorded_at, actor_mode)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            audit.actor.as_str(),
            audit.action.as_str(),
            audit.entity.as_str(),
            entity_id.or(audit.entity_id),
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

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::NewAuditEntry;
    use lisi_core::text::{Actor, AuditAction, AuditEntity};

    use super::{NewMemberRow, NewMembersListing};
    use crate::Database;

    fn attore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn audit() -> NewAuditEntry {
        let (Ok(action), Ok(entity)) = (
            AuditAction::try_new("elenco_iscritti_chiesto"),
            AuditEntity::try_new("fonte"),
        ) else {
            panic!("l'audit di prova deve essere valido");
        };
        NewAuditEntry {
            actor: attore(),
            action,
            entity,
            entity_id: None,
            actor_mode: None,
            detail: None,
            recorded_at: Timestamp::from_millis(1_700_000_000_000),
        }
    }

    fn archivio_con_fonte() -> (Database, i64) {
        let Ok(archivio) = Database::open_in_memory() else {
            panic!("l'archivio in memoria deve aprirsi");
        };
        let Ok(_) = archivio.connection.execute(
            "INSERT INTO sources (kind, identifier, display_name, authorized_by, active,
                 created_at, updated_at)
             VALUES ('group', '-1001', 'Gruppo di prova', 'amministratore', 1, 0, 0)",
            [],
        ) else {
            panic!("la fonte di prova deve inserirsi");
        };
        let id = archivio.connection.last_insert_rowid();
        (archivio, id)
    }

    fn richiesta(fonte: i64) -> NewMembersListing {
        NewMembersListing {
            source_id: fonte,
            chat_id: -1001,
            account_uuid: None,
            requested_by: String::from("operatore.prova"),
            reason: String::from("Verifica dei partecipanti a una truffa"),
            requested_at: Timestamp::from_millis(1_700_000_000_000),
            outcome: "ottenuto",
            outcome_detail: None,
            declared_total: Some(2),
            stopped_at_cap: false,
        }
    }

    fn iscritto(id: i64, telefono: Option<&str>) -> NewMemberRow {
        NewMemberRow {
            user_id: id,
            display_name: Some(String::from("Ada")),
            username: None,
            masked_phone: telefono.map(str::to_owned),
            status: "iscritto",
            joined_at: None,
        }
    }

    #[test]
    fn l_elenco_e_spento_di_fabbrica_e_si_accende_con_l_audit() {
        let (mut archivio, _) = archivio_con_fonte();
        assert_eq!(archivio.members_listing_enabled().ok(), Some(false));
        let Ok(()) = archivio.save_members_listing_enabled(true, &attore(), &audit()) else {
            panic!("la scelta deve salvarsi");
        };
        assert_eq!(archivio.members_listing_enabled().ok(), Some(true));
    }

    #[test]
    fn una_richiesta_si_registra_con_i_suoi_iscritti_e_non_cambia() {
        let (mut archivio, fonte) = archivio_con_fonte();
        let righe = [iscritto(11, Some("+••••••••••67")), iscritto(12, None)];
        let Ok(id) = archivio.insert_members_listing(&richiesta(fonte), &righe, &audit()) else {
            panic!("la richiesta deve registrarsi");
        };
        let Ok(elenchi) = archivio.members_listings(10) else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(elenchi.len(), 1);
        assert_eq!(elenchi[0].received, 2);
        let Ok(iscritti) = archivio.members_listing_rows(id) else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(iscritti.len(), 2);
        assert_eq!(iscritti[0].masked_phone.as_deref(), Some("+••••••••••67"));

        assert!(
            archivio
                .connection
                .execute("UPDATE members_listings SET reason = 'altro'", [])
                .is_err(),
            "una richiesta registrata non cambia"
        );
        assert!(
            archivio
                .connection
                .execute("DELETE FROM members_listing_rows", [])
                .is_err(),
            "un iscritto registrato non si toglie"
        );
    }

    #[test]
    fn lo_schema_rifiuta_un_telefono_intero() {
        let (mut archivio, fonte) = archivio_con_fonte();
        let righe = [iscritto(11, Some("+393331234567"))];
        assert!(
            archivio
                .insert_members_listing(&richiesta(fonte), &righe, &audit())
                .is_err(),
            "un telefono con tre cifre di fila non entra"
        );
        assert_eq!(archivio.members_listings(10).map(|e| e.len()).ok(), Some(0));
    }
}

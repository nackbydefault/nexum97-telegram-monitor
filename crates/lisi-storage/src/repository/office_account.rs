//! Le letture dell'account d'ufficio (`getMe`), in sola aggiunta
//! (NEXUM97-IDENTITY-02, ADR-0153, DG-07).
//!
//! Una riga per lettura chiesta, riuscita o no, con chi e quando. La lettura e
//! la sua riga d'audit si scrivono **nella stessa transazione**. Il telefono
//! entra soltanto mascherato: lo schema rifiuta una forma con più di due cifre
//! in chiaro.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// Ciò che Telegram ha detto dell'account d'ufficio, per una lettura riuscita.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfficeAccountProfile {
    /// L'identificativo Telegram dell'account.
    pub telegram_id: i64,
    /// Il nome proprio, com'è arrivato.
    pub first_name: String,
    /// Il cognome, com'è arrivato.
    pub last_name: String,
    /// Tutti gli username attivi, nell'ordine di Telegram.
    pub usernames: Vec<String>,
    /// Il telefono **mascherato**, se Telegram lo ha restituito.
    pub phone_masked: Option<String>,
}

/// Una lettura da registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewOfficeAccountRead {
    /// Chi l'ha chiesta.
    pub read_by: String,
    /// Quando.
    pub read_at: Timestamp,
    /// Il profilo, se Telegram ha risposto; altrimenti `None`.
    pub profile: Option<OfficeAccountProfile>,
    /// Che cosa è successo, in una frase.
    pub outcome_reason: String,
}

/// Una lettura registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredOfficeAccountRead {
    /// L'identificativo della riga.
    pub id: i64,
    /// Ciò che è stato registrato.
    pub read: NewOfficeAccountRead,
}

impl Database {
    /// Registra una lettura **e** la sua riga d'audit, insieme.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce, compreso il rifiuto
    /// dello schema per un telefono non mascherato; in quel caso non resta né la
    /// lettura né la riga d'audit.
    pub fn insert_office_account_read(
        &mut self,
        lettura: &NewOfficeAccountRead,
        audit: &NewAuditEntry,
    ) -> StorageResult<i64> {
        let transazione = self.connection.transaction()?;
        let profilo = lettura.profile.as_ref();
        transazione.execute(
            "INSERT INTO office_account_reads (
                 read_by, read_at, outcome, outcome_reason, telegram_id, first_name,
                 last_name, usernames, phone_masked
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                lettura.read_by,
                millis(lettura.read_at),
                if profilo.is_some() {
                    "letto"
                } else {
                    "non_letto"
                },
                lettura.outcome_reason,
                profilo.map(|p| p.telegram_id),
                profilo.map(|p| p.first_name.clone()),
                profilo.map(|p| p.last_name.clone()),
                profilo.map(|p| p.usernames.join(" ")),
                profilo.and_then(|p| p.phone_masked.clone()),
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

    /// L'ultima lettura registrata, riuscita o no.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn latest_office_account_read(&self) -> StorageResult<Option<StoredOfficeAccountRead>> {
        let mut statement = self.connection.prepare(
            "SELECT id, read_by, read_at, outcome_reason, telegram_id, first_name, last_name,
                    usernames, phone_masked
             FROM office_account_reads
             ORDER BY read_at DESC, id DESC
             LIMIT 1",
        )?;
        let mut righe = statement.query_map([], |row| {
            let telegram_id: Option<i64> = row.get(4)?;
            let profile = match telegram_id {
                Some(telegram_id) => Some(OfficeAccountProfile {
                    telegram_id,
                    first_name: row.get::<_, Option<String>>(5)?.unwrap_or_default(),
                    last_name: row.get::<_, Option<String>>(6)?.unwrap_or_default(),
                    usernames: row
                        .get::<_, Option<String>>(7)?
                        .unwrap_or_default()
                        .split_whitespace()
                        .map(str::to_owned)
                        .collect(),
                    phone_masked: row.get(8)?,
                }),
                None => None,
            };
            Ok(StoredOfficeAccountRead {
                id: row.get(0)?,
                read: NewOfficeAccountRead {
                    read_by: row.get(1)?,
                    read_at: instant(row.get(2)?),
                    profile,
                    outcome_reason: row.get(3)?,
                },
            })
        })?;
        Ok(righe.next().transpose()?)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::NewAuditEntry;
    use lisi_core::text::{AuditAction, AuditEntity};

    use super::{NewOfficeAccountRead, OfficeAccountProfile};
    use crate::test_support::{actor, database, later};

    fn audit() -> NewAuditEntry {
        let (Ok(azione), Ok(entita)) = (
            AuditAction::try_new("lettura_account_ufficio"),
            AuditEntity::try_new("account_ufficio"),
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

    fn lettura(telefono: Option<&str>) -> NewOfficeAccountRead {
        NewOfficeAccountRead {
            read_by: String::from("operatore.prova"),
            read_at: later(1),
            profile: Some(OfficeAccountProfile {
                telegram_id: 777,
                first_name: String::from("Ufficio"),
                last_name: String::from("Prova"),
                usernames: vec![String::from("ufficio_prova"), String::from("ufficio_2")],
                phone_masked: telefono.map(str::to_owned),
            }),
            outcome_reason: String::from("Telegram ha risposto."),
        }
    }

    /// **Una lettura si registra con il suo audit, si rilegge, e resta com'è.**
    #[test]
    fn una_lettura_si_registra_e_resta() {
        let mut archivio = database();
        let attesa = lettura(Some("+**********99"));
        let Ok(_) = archivio.insert_office_account_read(&attesa, &audit()) else {
            panic!("la lettura deve registrarsi");
        };
        let Ok(Some(letta)) = archivio.latest_office_account_read() else {
            panic!("la lettura deve rileggersi");
        };
        assert_eq!(letta.read, attesa);
        for comando in [
            "UPDATE office_account_reads SET first_name = 'Altro'",
            "DELETE FROM office_account_reads",
        ] {
            assert!(
                archivio.connection.execute(comando, []).is_err(),
                "«{comando}» deve essere rifiutato"
            );
        }
        let Ok(audit) = archivio.connection.query_row(
            "SELECT COUNT(*) FROM audit WHERE action = 'lettura_account_ufficio'",
            [],
            |row| row.get::<_, i64>(0),
        ) else {
            panic!("l'audit deve leggersi");
        };
        assert_eq!(audit, 1, "la lettura porta la sua riga d'audit");
    }

    /// **Il telefono pieno non entra** (A3): lo schema lo rifiuta, e con lui
    /// la riga d'audit.
    #[test]
    fn il_telefono_pieno_non_entra() {
        let mut archivio = database();
        assert!(
            archivio
                .insert_office_account_read(&lettura(Some("+390600000099")), &audit())
                .is_err(),
            "un numero con tutte le cifre in chiaro deve essere rifiutato"
        );
        let Ok(audit) = archivio
            .connection
            .query_row("SELECT COUNT(*) FROM audit", [], |row| row.get::<_, i64>(0))
        else {
            panic!("l'audit deve leggersi");
        };
        assert_eq!(audit, 0, "nessuna riga d'audit senza la lettura");
    }

    /// **Una lettura non riuscita non porta dati.**
    #[test]
    fn una_lettura_non_riuscita_non_porta_dati() {
        let mut archivio = database();
        let senza = NewOfficeAccountRead {
            profile: None,
            outcome_reason: String::from("Telegram non ha risposto entro il tempo massimo."),
            ..lettura(None)
        };
        let Ok(_) = archivio.insert_office_account_read(&senza, &audit()) else {
            panic!("una lettura non riuscita si registra");
        };
        assert!(
            archivio
                .connection
                .execute(
                    "INSERT INTO office_account_reads (read_by, read_at, outcome, outcome_reason, \
                     first_name) VALUES ('x', 1, 'non_letto', 'r', 'Nome inventato')",
                    [],
                )
                .is_err(),
            "una lettura non riuscita con un nome e' un'ipotesi, e lo schema la rifiuta"
        );
    }
}

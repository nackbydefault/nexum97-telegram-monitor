//! Chi ha registrato un nome o un indirizzo, chiesto dal PC (WHOIS-01,
//! ADR-0205, migrazione 0095).
//!
//! La scelta di abilitarlo è un'azione e porta la sua riga d'audit nella
//! stessa transazione. Una richiesta si scrive una volta, con la sua riga
//! d'audit, e non cambia più.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::text::Actor;

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// Una richiesta da registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRegistrationLookup {
    /// Il genere dell'indicatore, nell'etichetta stabile.
    pub indicator_kind: &'static str,
    /// Il valore dell'indicatore, come è conservato.
    pub indicator_value: String,
    /// Il nome o l'indirizzo chiesto davvero.
    pub queried_name: String,
    /// `rdap`, `whois` o `nessuno`.
    pub service: &'static str,
    /// Il registro interrogato: l'indirizzo RDAP o il nome del server WHOIS.
    pub server: String,
    /// Chi.
    pub requested_by: String,
    /// Quando.
    pub requested_at: Timestamp,
    /// `trovato`, `inesistente`, `nessun_servizio` o `non_riuscito`.
    pub outcome: &'static str,
    /// Il motivo, quando non è riuscita.
    pub detail: String,
    /// Il riassunto della risposta, una voce per riga.
    pub summary: String,
}

/// Una richiesta registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRegistrationLookup {
    /// L'identificativo.
    pub id: i64,
    /// Il genere dell'indicatore.
    pub indicator_kind: String,
    /// Il valore dell'indicatore.
    pub indicator_value: String,
    /// Il nome o l'indirizzo chiesto.
    pub queried_name: String,
    /// Il servizio, nel nome stabile.
    pub service: String,
    /// Il registro interrogato.
    pub server: String,
    /// Chi.
    pub requested_by: String,
    /// Quando.
    pub requested_at: Timestamp,
    /// L'esito, nel nome stabile.
    pub outcome: String,
    /// Il motivo, quando non è riuscita.
    pub detail: String,
    /// Il riassunto della risposta.
    pub summary: String,
}

impl Database {
    /// Se il WHOIS è abilitato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn registration_lookup_enabled(&self) -> StorageResult<bool> {
        let abilitato: i64 = self.connection.query_row(
            "SELECT enabled FROM registration_lookup_settings WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(abilitato == 1)
    }

    /// Abilita o spegne il WHOIS, con la sua riga d'audit.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce: in quel caso non
    /// cambia niente.
    pub fn save_registration_lookup_enabled(
        &mut self,
        enabled: bool,
        actor: &Actor,
        audit: &NewAuditEntry,
    ) -> StorageResult<()> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "UPDATE registration_lookup_settings
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

    /// Registra una richiesta e la sua riga d'audit, insieme.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo schema rifiuta qualcosa o la scrittura non
    /// riesce: allora non resta niente.
    pub fn insert_registration_lookup(
        &mut self,
        richiesta: &NewRegistrationLookup,
        audit: &NewAuditEntry,
    ) -> StorageResult<i64> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO registration_lookups (indicator_kind, indicator_value, queried_name,
                 service, server, requested_by, requested_at, outcome, detail, summary)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                richiesta.indicator_kind,
                richiesta.indicator_value,
                richiesta.queried_name,
                richiesta.service,
                richiesta.server,
                richiesta.requested_by,
                millis(richiesta.requested_at),
                richiesta.outcome,
                richiesta.detail,
                richiesta.summary,
            ],
        )?;
        let id = transazione.last_insert_rowid();
        inserisci_audit(&transazione, audit, Some(id))?;
        transazione.commit()?;
        Ok(id)
    }

    /// Le richieste per un indicatore, dalla più nuova, al più `limite`.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn registration_lookups(
        &self,
        kind: &str,
        value: &str,
        limite: u32,
    ) -> StorageResult<Vec<StoredRegistrationLookup>> {
        let mut statement = self.connection.prepare(
            "SELECT id, indicator_kind, indicator_value, queried_name, service, server,
                    requested_by, requested_at, outcome, detail, summary
             FROM registration_lookups
             WHERE indicator_kind = ?1 AND indicator_value = ?2
             ORDER BY requested_at DESC, id DESC
             LIMIT ?3",
        )?;
        let righe = statement.query_map(rusqlite::params![kind, value, limite], |row| {
            Ok(StoredRegistrationLookup {
                id: row.get(0)?,
                indicator_kind: row.get(1)?,
                indicator_value: row.get(2)?,
                queried_name: row.get(3)?,
                service: row.get(4)?,
                server: row.get(5)?,
                requested_by: row.get(6)?,
                requested_at: instant(row.get(7)?),
                outcome: row.get(8)?,
                detail: row.get(9)?,
                summary: row.get(10)?,
            })
        })?;
        let mut richieste = Vec::new();
        for riga in righe {
            richieste.push(riga?);
        }
        Ok(richieste)
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

    use super::NewRegistrationLookup;
    use crate::Database;

    fn attore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn audit() -> NewAuditEntry {
        let (Ok(action), Ok(entity)) = (
            AuditAction::try_new("registrazione_chiesta"),
            AuditEntity::try_new("indicatore"),
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

    fn archivio() -> Database {
        let Ok(archivio) = Database::open_in_memory() else {
            panic!("l'archivio in memoria deve aprirsi");
        };
        archivio
    }

    fn richiesta(
        kind: &'static str,
        service: &'static str,
        outcome: &'static str,
    ) -> NewRegistrationLookup {
        NewRegistrationLookup {
            indicator_kind: kind,
            indicator_value: String::from("esempio.invalid"),
            queried_name: String::from("esempio.invalid"),
            service,
            server: String::from("whois.esempio.invalid"),
            requested_by: String::from("operatore.prova"),
            requested_at: Timestamp::from_millis(1_700_000_000_000),
            outcome,
            detail: String::new(),
            summary: String::from("Registrar: Esempio"),
        }
    }

    #[test]
    fn il_whois_e_spento_di_fabbrica_e_si_accende_con_l_audit() {
        let mut archivio = archivio();
        assert_eq!(archivio.registration_lookup_enabled().ok(), Some(false));
        let Ok(()) = archivio.save_registration_lookup_enabled(true, &attore(), &audit()) else {
            panic!("la scelta deve salvarsi");
        };
        assert_eq!(archivio.registration_lookup_enabled().ok(), Some(true));
    }

    #[test]
    fn una_richiesta_si_registra_e_non_cambia() {
        let mut archivio = archivio();
        let Ok(_) = archivio
            .insert_registration_lookup(&richiesta("dominio", "whois", "trovato"), &audit())
        else {
            panic!("la richiesta deve registrarsi");
        };
        let Ok(richieste) = archivio.registration_lookups("dominio", "esempio.invalid", 10) else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(richieste.len(), 1);
        assert_eq!(richieste[0].summary, "Registrar: Esempio");
        assert_eq!(richieste[0].service, "whois");
        assert!(
            archivio
                .connection
                .execute("UPDATE registration_lookups SET summary = ''", [])
                .is_err(),
            "una richiesta registrata non cambia"
        );
        assert!(
            archivio
                .connection
                .execute("DELETE FROM registration_lookups", [])
                .is_err(),
            "una richiesta registrata non si toglie"
        );
    }

    #[test]
    fn lo_schema_rifiuta_generi_servizi_ed_esiti_sconosciuti() {
        let mut archivio = archivio();
        for (kind, service, outcome) in [
            ("sha256", "rdap", "trovato"),
            ("dominio", "ftp", "trovato"),
            ("dominio", "rdap", "forse"),
        ] {
            assert!(
                archivio
                    .insert_registration_lookup(&richiesta(kind, service, outcome), &audit())
                    .is_err(),
                "{kind} {service} {outcome} non entra"
            );
        }
    }
}

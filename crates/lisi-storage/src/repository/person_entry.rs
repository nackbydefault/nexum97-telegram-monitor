//! Note e riferimenti del soggetto, in sola aggiunta (NEXUM97-IDENTITY-02,
//! ADR-0153, DG-08).
//!
//! Ogni scrittura — una voce, un ritiro — porta la sua riga d'audit **nella
//! stessa transazione**: o ci sono entrambe, o nessuna. Lo schema rifiuta una
//! riscrittura del testo, una cancellazione, un ritiro senza ragione o ripetuto.

use lisi_core::model::NewAuditEntry;
use lisi_core::{PersonId, Timestamp};

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// A che cosa si riferisce un riferimento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryTarget {
    /// Un contenuto dell'archivio, per numero.
    Content(i64),
    /// Una fonte dell'archivio, per numero.
    Source(i64),
    /// Un rapporto dell'archivio, per numero.
    Report(i64),
    /// Un documento esterno, per la sua indicazione: un protocollo, un atto.
    Document(String),
}

impl EntryTarget {
    /// Il genere, nella parola che l'archivio conserva.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Content(_) => "contenuto",
            Self::Source(_) => "fonte",
            Self::Report(_) => "rapporto",
            Self::Document(_) => "documento",
        }
    }

    fn target_id(&self) -> Option<i64> {
        match self {
            Self::Content(id) | Self::Source(id) | Self::Report(id) => Some(*id),
            Self::Document(_) => None,
        }
    }

    fn document(&self) -> Option<&str> {
        match self {
            Self::Document(testo) => Some(testo.as_str()),
            _ => None,
        }
    }

    fn from_columns(kind: &str, id: Option<i64>, document: Option<String>) -> Option<Self> {
        match (kind, id, document) {
            ("contenuto", Some(id), None) => Some(Self::Content(id)),
            ("fonte", Some(id), None) => Some(Self::Source(id)),
            ("rapporto", Some(id), None) => Some(Self::Report(id)),
            ("documento", None, Some(testo)) => Some(Self::Document(testo)),
            _ => None,
        }
    }
}

/// Una voce da scrivere: una nota, o un riferimento con la sua ragione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPersonEntry {
    /// Su quale soggetto.
    pub person_id: PersonId,
    /// La nota, o la ragione del riferimento.
    pub body: String,
    /// Il riferimento; `None` per una nota.
    pub target: Option<EntryTarget>,
    /// Chi.
    pub written_by: String,
    /// Quando.
    pub written_at: Timestamp,
}

/// Il ritiro di una voce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryWithdrawal {
    /// Chi.
    pub by: String,
    /// Quando.
    pub at: Timestamp,
    /// Perché.
    pub reason: String,
}

/// Una voce registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPersonEntry {
    /// L'identificativo della voce.
    pub id: i64,
    /// Ciò che è stato scritto.
    pub entry: NewPersonEntry,
    /// Il ritiro, se c'è.
    pub withdrawal: Option<EntryWithdrawal>,
}

impl Database {
    /// Scrive una voce **e** la sua riga d'audit, insieme.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo schema la rifiuta o la scrittura non riesce;
    /// allora non resta né la voce né l'audit.
    pub fn insert_person_entry(
        &mut self,
        voce: &NewPersonEntry,
        audit: &NewAuditEntry,
    ) -> StorageResult<i64> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO person_entries (person_id, entry_kind, body, ref_kind, ref_target_id,
                 ref_document, written_by, written_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                voce.person_id.get(),
                if voce.target.is_some() {
                    "riferimento"
                } else {
                    "nota"
                },
                voce.body,
                voce.target.as_ref().map(EntryTarget::kind),
                voce.target.as_ref().and_then(EntryTarget::target_id),
                voce.target.as_ref().and_then(EntryTarget::document),
                voce.written_by,
                millis(voce.written_at),
            ],
        )?;
        let id = transazione.last_insert_rowid();
        insert_audit(&transazione, audit, id)?;
        transazione.commit()?;
        Ok(id)
    }

    /// Ritira una voce **e** registra la riga d'audit, insieme.
    ///
    /// Restituisce `false` se la voce non esiste: nulla è stato scritto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo schema rifiuta il ritiro — già ritirata,
    /// ragione troppo corta — o la scrittura non riesce.
    pub fn withdraw_person_entry(
        &mut self,
        id: i64,
        ritiro: &EntryWithdrawal,
        audit: &NewAuditEntry,
    ) -> StorageResult<bool> {
        let transazione = self.connection.transaction()?;
        let cambiate = transazione.execute(
            "UPDATE person_entries SET withdrawn_by = ?1, withdrawn_at = ?2,
                 withdrawal_reason = ?3
             WHERE id = ?4",
            rusqlite::params![ritiro.by, millis(ritiro.at), ritiro.reason, id],
        )?;
        if cambiate == 0 {
            return Ok(false);
        }
        insert_audit(&transazione, audit, id)?;
        transazione.commit()?;
        Ok(true)
    }

    /// Le voci di un soggetto, dalla più antica.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn person_entries(&self, person: PersonId) -> StorageResult<Vec<StoredPersonEntry>> {
        let mut statement = self.connection.prepare(
            "SELECT id, person_id, body, ref_kind, ref_target_id, ref_document, written_by,
                    written_at, withdrawn_by, withdrawn_at, withdrawal_reason
             FROM person_entries
             WHERE person_id = ?1
             ORDER BY written_at, id",
        )?;
        let righe = statement.query_map([person.get()], |row| {
            let genere: Option<String> = row.get(3)?;
            let target = genere.and_then(|genere| {
                EntryTarget::from_columns(
                    &genere,
                    row.get(4).ok().flatten(),
                    row.get(5).ok().flatten(),
                )
            });
            let ritirata_da: Option<String> = row.get(8)?;
            let ritirata_il: Option<i64> = row.get(9)?;
            let ragione: Option<String> = row.get(10)?;
            Ok(StoredPersonEntry {
                id: row.get(0)?,
                entry: NewPersonEntry {
                    person_id: PersonId::new(row.get(1)?),
                    body: row.get(2)?,
                    target,
                    written_by: row.get(6)?,
                    written_at: instant(row.get(7)?),
                },
                withdrawal: match (ritirata_da, ritirata_il, ragione) {
                    (Some(by), Some(at), Some(reason)) => Some(EntryWithdrawal {
                        by,
                        at: instant(at),
                        reason,
                    }),
                    _ => None,
                },
            })
        })?;
        let mut voci = Vec::new();
        for riga in righe {
            voci.push(riga?);
        }
        Ok(voci)
    }
}

/// La riga d'audit, dentro la transazione della scrittura.
fn insert_audit(
    transazione: &rusqlite::Transaction<'_>,
    audit: &NewAuditEntry,
    id: i64,
) -> StorageResult<()> {
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use lisi_core::PersonId;
    use lisi_core::model::NewAuditEntry;
    use lisi_core::text::{AuditAction, AuditEntity};

    use super::{EntryTarget, EntryWithdrawal, NewPersonEntry};
    use crate::Database;
    use crate::test_support::{actor, database, later};

    fn audit(azione: &str) -> NewAuditEntry {
        let (Ok(azione), Ok(entita)) = (
            AuditAction::try_new(azione),
            AuditEntity::try_new("soggetto"),
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

    fn con_soggetto() -> (Database, PersonId) {
        let archivio = database();
        let Ok(_) = archivio.connection.execute(
            "INSERT INTO persons (label, reason, opened_by, opened_at)
             VALUES ('Soggetto', 'richiesta dell''autorita'' procedente', 'operatore.prova', 1)",
            [],
        ) else {
            panic!("il soggetto di prova deve aprirsi");
        };
        let id = archivio.connection.last_insert_rowid();
        (archivio, PersonId::new(id))
    }

    fn voce(soggetto: PersonId, corpo: &str, target: Option<EntryTarget>) -> NewPersonEntry {
        NewPersonEntry {
            person_id: soggetto,
            body: corpo.to_owned(),
            target,
            written_by: String::from("operatore.prova"),
            written_at: later(2),
        }
    }

    /// **Note e riferimenti si scrivono, si rileggono, si ritirano e restano**
    /// (B2, B3).
    #[test]
    fn note_e_riferimenti_si_scrivono_e_restano() {
        let (mut archivio, soggetto) = con_soggetto();
        let nota = voce(soggetto, "Ha cambiato nome due volte in un mese.", None);
        let riferimento = voce(
            soggetto,
            "Il messaggio con cui ha annunciato il presidio.",
            Some(EntryTarget::Content(7)),
        );
        let documento = voce(
            soggetto,
            "Segnalazione ricevuta dall'ufficio territoriale.",
            Some(EntryTarget::Document(String::from("prot. 1234/2026"))),
        );
        let mut ids = Vec::new();
        for v in [&nota, &riferimento, &documento] {
            let Ok(id) = archivio.insert_person_entry(v, &audit("voce_soggetto")) else {
                panic!("la voce deve scriversi");
            };
            ids.push(id);
        }
        let ritiro = EntryWithdrawal {
            by: String::from("operatore.prova"),
            at: later(3),
            reason: String::from("Il riferimento era a un messaggio sbagliato."),
        };
        let Ok(true) =
            archivio.withdraw_person_entry(ids[1], &ritiro, &audit("ritiro_voce_soggetto"))
        else {
            panic!("il ritiro deve riuscire");
        };
        let Ok(voci) = archivio.person_entries(soggetto) else {
            panic!("le voci devono leggersi");
        };
        assert_eq!(voci.len(), 3, "un ritiro non toglie la voce");
        assert_eq!(voci[0].entry, nota);
        assert_eq!(voci[1].entry, riferimento);
        assert_eq!(voci[1].withdrawal, Some(ritiro.clone()));
        assert_eq!(voci[2].entry, documento);

        // Il ritiro non si ripete e non si annulla.
        assert!(
            archivio
                .withdraw_person_entry(ids[1], &ritiro, &audit("ritiro_voce_soggetto"))
                .is_err()
        );
        for comando in [
            "UPDATE person_entries SET body = 'altro testo'",
            "UPDATE person_entries SET withdrawn_by = NULL, withdrawn_at = NULL, withdrawal_reason = NULL",
            "DELETE FROM person_entries",
        ] {
            assert!(
                archivio.connection.execute(comando, []).is_err(),
                "«{comando}» deve essere rifiutato"
            );
        }
        let Ok(audit) = archivio
            .connection
            .query_row("SELECT COUNT(*) FROM audit", [], |row| row.get::<_, i64>(0))
        else {
            panic!("l'audit deve leggersi");
        };
        assert_eq!(audit, 4, "tre voci e un ritiro, ciascuno con la sua riga");
    }

    /// **Lo schema rifiuta ciò che non è una voce** (B2, B3): riferimento con
    /// ragione corta, documento con un numero, nota con un riferimento, genere
    /// sconosciuto, ritiro senza ragione.
    #[test]
    fn lo_schema_rifiuta_cio_che_non_e_una_voce() {
        let (mut archivio, soggetto) = con_soggetto();
        assert!(
            archivio
                .insert_person_entry(
                    &voce(soggetto, "corta", Some(EntryTarget::Content(1))),
                    &audit("voce_soggetto")
                )
                .is_err(),
            "un riferimento vuole una ragione di venti caratteri"
        );
        for sql in [
            "INSERT INTO person_entries (person_id, entry_kind, body, ref_kind, ref_target_id, \
             written_by, written_at) VALUES (1, 'riferimento', 'una ragione abbastanza lunga', \
             'documento', 3, 'o', 1)",
            "INSERT INTO person_entries (person_id, entry_kind, body, ref_kind, ref_target_id, \
             written_by, written_at) VALUES (1, 'nota', 'testo', 'contenuto', 3, 'o', 1)",
            "INSERT INTO person_entries (person_id, entry_kind, body, written_by, written_at) \
             VALUES (1, 'alias', 'Mario', 'o', 1)",
            "INSERT INTO person_entries (person_id, entry_kind, body, ref_kind, ref_target_id, \
             written_by, written_at) VALUES (1, 'riferimento', 'una ragione abbastanza lunga', \
             'persona', 3, 'o', 1)",
            "INSERT INTO person_entries (person_id, entry_kind, body, written_by, written_at, \
             withdrawn_by, withdrawn_at) VALUES (1, 'nota', 'testo', 'o', 1, 'o', 2)",
            "INSERT INTO person_entries (person_id, entry_kind, body, written_by, written_at) \
             VALUES (999, 'nota', 'testo', 'o', 1)",
        ] {
            assert!(
                archivio.connection.execute(sql, []).is_err(),
                "lo schema deve rifiutare: {sql}"
            );
        }
        let Ok(voci) = archivio.person_entries(soggetto) else {
            panic!("le voci devono leggersi");
        };
        assert!(voci.is_empty());
    }
}

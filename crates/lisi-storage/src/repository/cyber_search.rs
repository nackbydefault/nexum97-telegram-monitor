//! Il registro delle ricerche cyber B, C e D, in sola aggiunta
//! (NEXUM97-CYBER-SEARCH-01, ADR-0154; CYBER-SEARCH-02, ADR-0161).
//!
//! Una riga per pagina chiesta, con la sua riga d'audit **nella stessa
//! transazione**. Nessun testo di messaggio: si registra la ricerca, non ciò
//! che ha trovato.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// Una ricerca da registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCyberSearch {
    /// Chi.
    pub searched_by: String,
    /// Quando.
    pub searched_at: Timestamp,
    /// «B», «C» o «D».
    pub branch: &'static str,
    /// Le parole.
    pub query: String,
    /// Il perimetro, in una frase.
    pub scope: String,
    /// La chat, per la C.
    pub chat_id: Option<i64>,
    /// Quale pagina, da 1.
    pub page: u32,
    /// L'esito, nel nome stabile.
    pub outcome: &'static str,
    /// Quanti risultati.
    pub results: u32,
    /// Il perché, in una frase.
    pub outcome_reason: String,
}

/// Una ricerca registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCyberSearch {
    /// L'identificativo.
    pub id: i64,
    /// Chi.
    pub searched_by: String,
    /// Quando.
    pub searched_at: Timestamp,
    /// «B», «C» o «D».
    pub branch: String,
    /// Le parole.
    pub query: String,
    /// Quanti risultati.
    pub results: u32,
    /// Il perché.
    pub outcome_reason: String,
}

impl Database {
    /// Registra una ricerca **e** la sua riga d'audit, insieme.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo schema la rifiuta o la scrittura non riesce;
    /// allora non resta né la ricerca né l'audit.
    pub fn insert_cyber_search(
        &mut self,
        ricerca: &NewCyberSearch,
        audit: &NewAuditEntry,
    ) -> StorageResult<i64> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO cyber_searches (searched_by, searched_at, branch, query, scope, chat_id,
                 page, outcome, results, outcome_reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                ricerca.searched_by,
                millis(ricerca.searched_at),
                ricerca.branch,
                ricerca.query,
                ricerca.scope,
                ricerca.chat_id,
                ricerca.page,
                ricerca.outcome,
                ricerca.results,
                ricerca.outcome_reason,
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

    /// Quante pagine di ricerca sono state chieste da `dal` in poi.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn cyber_searches_since(&self, dal: Timestamp) -> StorageResult<u32> {
        let quante: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM cyber_searches WHERE searched_at >= ?1",
            [millis(dal)],
            |row| row.get(0),
        )?;
        Ok(u32::try_from(quante).unwrap_or(u32::MAX))
    }

    /// Le ricerche più recenti, dalla più nuova, al più `limite`.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn recent_cyber_searches(&self, limite: u32) -> StorageResult<Vec<StoredCyberSearch>> {
        let mut statement = self.connection.prepare(
            "SELECT id, searched_by, searched_at, branch, query, results, outcome_reason
             FROM cyber_searches
             ORDER BY searched_at DESC, id DESC
             LIMIT ?1",
        )?;
        let righe = statement.query_map([limite], |row| {
            Ok(StoredCyberSearch {
                id: row.get(0)?,
                searched_by: row.get(1)?,
                searched_at: instant(row.get(2)?),
                branch: row.get(3)?,
                query: row.get(4)?,
                results: row.get(5)?,
                outcome_reason: row.get(6)?,
            })
        })?;
        let mut ricerche = Vec::new();
        for riga in righe {
            ricerche.push(riga?);
        }
        Ok(ricerche)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::NewAuditEntry;
    use lisi_core::text::{AuditAction, AuditEntity};

    use super::NewCyberSearch;
    use crate::test_support::{actor, database, later};

    fn audit() -> NewAuditEntry {
        let (Ok(azione), Ok(entita)) = (
            AuditAction::try_new("ricerca_cyber"),
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

    fn ricerca(
        branch: &'static str,
        chat: Option<i64>,
        esito: &'static str,
        n: u32,
    ) -> NewCyberSearch {
        NewCyberSearch {
            searched_by: String::from("operatore.prova"),
            searched_at: later(1),
            branch,
            query: String::from("ransomware"),
            scope: String::from("Nelle chat dell'account."),
            chat_id: chat,
            page: 1,
            outcome: esito,
            results: n,
            outcome_reason: String::from("motivo"),
        }
    }

    /// **Una ricerca si registra con il suo audit e resta** (criterio 5).
    #[test]
    fn una_ricerca_si_registra_e_resta() {
        let mut archivio = database();
        let Ok(_) = archivio.insert_cyber_search(&ricerca("B", None, "trovati", 3), &audit())
        else {
            panic!("la ricerca deve registrarsi");
        };
        let Ok(_) = archivio.insert_cyber_search(&ricerca("D", None, "rifiutata", 0), &audit())
        else {
            panic!("la ricerca D deve registrarsi (ADR-0161)");
        };
        let Ok(righe) = archivio.recent_cyber_searches(10) else {
            panic!("il registro deve leggersi");
        };
        assert_eq!(righe.len(), 2);
        assert!(righe.iter().any(|riga| riga.results == 3));
        let Ok(quante) = archivio.cyber_searches_since(later(0)) else {
            panic!("il conteggio deve riuscire");
        };
        assert_eq!(quante, 2);
        for comando in [
            "UPDATE cyber_searches SET query = 'altro'",
            "DELETE FROM cyber_searches",
        ] {
            assert!(
                archivio.connection.execute(comando, []).is_err(),
                "«{comando}»"
            );
        }
    }

    /// **Lo schema rifiuta ciò che non è una ricerca registrabile** (criterio 5).
    #[test]
    fn lo_schema_rifiuta_cio_che_non_e_una_ricerca() {
        let mut archivio = database();
        for (descrizione, sbagliata) in [
            ("C senza chat", ricerca("C", None, "trovati", 1)),
            ("B con chat", ricerca("B", Some(-1001), "trovati", 1)),
            ("trovati senza risultati", ricerca("B", None, "trovati", 0)),
            (
                "nessun risultato con risultati",
                ricerca("B", None, "nessun_risultato", 2),
            ),
            // La D si ammette dalla 0063 (ADR-0161): si rifiuta una D con una
            // chat, e un ramo che non esiste.
            ("D con chat", ricerca("D", Some(-1001), "trovati", 1)),
            ("ramo E", ricerca("E", None, "trovati", 1)),
            (
                "parola di un carattere",
                NewCyberSearch {
                    query: String::from("x"),
                    ..ricerca("B", None, "trovati", 1)
                },
            ),
        ] {
            assert!(
                archivio.insert_cyber_search(&sbagliata, &audit()).is_err(),
                "lo schema deve rifiutare: {descrizione}"
            );
        }
    }
}

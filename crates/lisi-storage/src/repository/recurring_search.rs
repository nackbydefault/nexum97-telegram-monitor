//! Le ricerche ricorrenti E e le loro esecuzioni (CYBER-WATCH-02, ADR-0162).
//!
//! Si conserva la **domanda** che si ripete e, per ogni esecuzione, l'esito, le
//! novità contate, se la pagina era piena e la data del messaggio più recente
//! letto. **Nessun testo di messaggio.**
//!
//! # Che cosa non si può fare, e chi lo impedisce
//!
//! Riscrivere la definizione, riprendere una ricorrente ritirata, cancellare
//! una ricorrente o un'esecuzione: lo rifiutano i trigger della migrazione
//! 0064. Qui non c'è una funzione che ci provi.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// Una ricerca ricorrente da salvare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRecurringSearch {
    /// «B», «C» o «D».
    pub branch: &'static str,
    /// Le parole.
    pub query: String,
    /// La chat, per la C.
    pub chat_id: Option<i64>,
    /// Ogni quanti minuti, da 60 a 1440.
    pub interval_minutes: u32,
    /// Chi la salva.
    pub created_by: String,
    /// Quando.
    pub created_at: Timestamp,
}

/// Una ricerca ricorrente salvata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecurringSearch {
    /// L'identificativo.
    pub id: i64,
    /// «B», «C» o «D».
    pub branch: String,
    /// Le parole.
    pub query: String,
    /// La chat, per la C.
    pub chat_id: Option<i64>,
    /// Ogni quanti minuti.
    pub interval_minutes: u32,
    /// Chi l'ha salvata.
    pub created_by: String,
    /// Quando.
    pub created_at: Timestamp,
    /// Se è sospesa.
    pub suspended: bool,
}

/// Un'esecuzione da registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRecurringRun {
    /// Quale ricorrente.
    pub recurring_id: i64,
    /// Quando.
    pub ran_at: Timestamp,
    /// La pagina registrata fra le ricerche, se una richiesta c'è stata.
    pub search_id: Option<i64>,
    /// `novita`, `nessuna_novita`, `rifiutata`, `non_riuscita` o `saltata`.
    pub outcome: &'static str,
    /// Quanti messaggi nuovi.
    pub new_results: u32,
    /// Se la pagina era piena.
    pub page_full: bool,
    /// La data del messaggio più recente letto, se ce n'era uno.
    pub newest_published_at: Option<Timestamp>,
    /// Il perché, in una frase.
    pub reason: String,
}

/// Un'esecuzione registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecurringRun {
    /// Quando.
    pub ran_at: Timestamp,
    /// L'esito.
    pub outcome: String,
    /// Quanti messaggi nuovi.
    pub new_results: u32,
    /// Se la pagina era piena.
    pub page_full: bool,
    /// Il perché.
    pub reason: String,
}

impl Database {
    /// Salva una ricerca ricorrente **e** la sua riga d'audit, insieme.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo schema la rifiuta o la scrittura non riesce;
    /// allora non resta né la ricorrente né l'audit.
    pub fn insert_recurring_search(
        &mut self,
        ricorrente: &NewRecurringSearch,
        audit: &NewAuditEntry,
    ) -> StorageResult<i64> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO recurring_searches (branch, query, chat_id, interval_minutes, created_by,
                 created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                ricorrente.branch,
                ricorrente.query,
                ricorrente.chat_id,
                ricorrente.interval_minutes,
                ricorrente.created_by,
                millis(ricorrente.created_at),
            ],
        )?;
        let id = transazione.last_insert_rowid();
        insert_audit(&transazione, audit, id)?;
        transazione.commit()?;
        Ok(id)
    }

    /// Sospende o riprende una ricorrente non ritirata, con l'audit. `false` se
    /// non c'è una ricorrente non ritirata con quel numero.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn set_recurring_search_suspended(
        &mut self,
        id: i64,
        sospesa: bool,
        audit: &NewAuditEntry,
    ) -> StorageResult<bool> {
        let transazione = self.connection.transaction()?;
        let cambiate = transazione.execute(
            "UPDATE recurring_searches SET suspended = ?2
             WHERE id = ?1 AND withdrawn_at IS NULL",
            rusqlite::params![id, i64::from(sospesa)],
        )?;
        if cambiate == 0 {
            return Ok(false);
        }
        insert_audit(&transazione, audit, id)?;
        transazione.commit()?;
        Ok(true)
    }

    /// Ritira una ricorrente, con l'audit. `false` se non c'è una ricorrente
    /// non ritirata con quel numero.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn withdraw_recurring_search(
        &mut self,
        id: i64,
        da: &str,
        quando: Timestamp,
        audit: &NewAuditEntry,
    ) -> StorageResult<bool> {
        let transazione = self.connection.transaction()?;
        let cambiate = transazione.execute(
            "UPDATE recurring_searches SET withdrawn_by = ?2, withdrawn_at = ?3
             WHERE id = ?1 AND withdrawn_at IS NULL",
            rusqlite::params![id, da, millis(quando)],
        )?;
        if cambiate == 0 {
            return Ok(false);
        }
        insert_audit(&transazione, audit, id)?;
        transazione.commit()?;
        Ok(true)
    }

    /// Le ricorrenti non ritirate, nell'ordine in cui sono state salvate.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn recurring_searches(&self) -> StorageResult<Vec<StoredRecurringSearch>> {
        let mut statement = self.connection.prepare(
            "SELECT id, branch, query, chat_id, interval_minutes, created_by, created_at,
                 suspended
             FROM recurring_searches
             WHERE withdrawn_at IS NULL
             ORDER BY id",
        )?;
        let righe = statement.query_map([], |row| {
            Ok(StoredRecurringSearch {
                id: row.get(0)?,
                branch: row.get(1)?,
                query: row.get(2)?,
                chat_id: row.get(3)?,
                interval_minutes: row.get(4)?,
                created_by: row.get(5)?,
                created_at: instant(row.get(6)?),
                suspended: row.get::<_, i64>(7)? != 0,
            })
        })?;
        let mut ricorrenti = Vec::new();
        for riga in righe {
            ricorrenti.push(riga?);
        }
        Ok(ricorrenti)
    }

    /// Registra un'esecuzione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo schema la rifiuta o la scrittura non riesce.
    pub fn insert_recurring_run(&mut self, esecuzione: &NewRecurringRun) -> StorageResult<i64> {
        self.connection.execute(
            "INSERT INTO recurring_search_runs (recurring_id, ran_at, search_id, outcome,
                 new_results, page_full, newest_published_at, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                esecuzione.recurring_id,
                millis(esecuzione.ran_at),
                esecuzione.search_id,
                esecuzione.outcome,
                esecuzione.new_results,
                i64::from(esecuzione.page_full),
                esecuzione.newest_published_at.map(millis),
                esecuzione.reason,
            ],
        )?;
        Ok(self.connection.last_insert_rowid())
    }

    /// Le esecuzioni più recenti di una ricorrente, dalla più nuova, al più
    /// `limite`.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn recurring_runs(&self, id: i64, limite: u32) -> StorageResult<Vec<StoredRecurringRun>> {
        let mut statement = self.connection.prepare(
            "SELECT ran_at, outcome, new_results, page_full, reason
             FROM recurring_search_runs
             WHERE recurring_id = ?1
             ORDER BY ran_at DESC, id DESC
             LIMIT ?2",
        )?;
        let righe = statement.query_map(rusqlite::params![id, limite], |row| {
            Ok(StoredRecurringRun {
                ran_at: instant(row.get(0)?),
                outcome: row.get(1)?,
                new_results: row.get(2)?,
                page_full: row.get::<_, i64>(3)? != 0,
                reason: row.get(4)?,
            })
        })?;
        let mut esecuzioni = Vec::new();
        for riga in righe {
            esecuzioni.push(riga?);
        }
        Ok(esecuzioni)
    }

    /// La data del messaggio più recente letto da una ricorrente, se ne ha
    /// letto uno: le novità sono i messaggi pubblicati dopo.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn recurring_newest_seen(&self, id: i64) -> StorageResult<Option<Timestamp>> {
        let piu_recente: Option<i64> = self.connection.query_row(
            "SELECT MAX(newest_published_at) FROM recurring_search_runs WHERE recurring_id = ?1",
            [id],
            |row| row.get(0),
        )?;
        Ok(piu_recente.map(instant))
    }

    /// Quante pagine hanno chiesto le ricorrenti da `dal` in poi.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn recurring_pages_since(&self, dal: Timestamp) -> StorageResult<u32> {
        let quante: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM recurring_search_runs
             WHERE ran_at >= ?1 AND search_id IS NOT NULL",
            [millis(dal)],
            |row| row.get(0),
        )?;
        Ok(u32::try_from(quante).unwrap_or(u32::MAX))
    }
}

/// La riga d'audit di un gesto su una ricorrente, nella stessa transazione.
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
    use lisi_core::model::NewAuditEntry;
    use lisi_core::text::{AuditAction, AuditEntity};

    use super::{NewRecurringRun, NewRecurringSearch};
    use crate::repository::cyber_search::NewCyberSearch;
    use crate::test_support::{actor, database, later};

    fn audit() -> NewAuditEntry {
        let (Ok(azione), Ok(entita)) = (
            AuditAction::try_new("ricerca_ricorrente_salvata"),
            AuditEntity::try_new("ricerca_ricorrente"),
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

    fn ricorrente(ramo: &'static str, chat: Option<i64>, minuti: u32) -> NewRecurringSearch {
        NewRecurringSearch {
            branch: ramo,
            query: String::from("ransomware"),
            chat_id: chat,
            interval_minutes: minuti,
            created_by: String::from("operatore.prova"),
            created_at: later(0),
        }
    }

    fn esecuzione(
        id: i64,
        secondi: i64,
        ricerca: Option<i64>,
        esito: &'static str,
        nuove: u32,
        piu_recente: Option<i64>,
    ) -> NewRecurringRun {
        NewRecurringRun {
            recurring_id: id,
            ran_at: later(secondi),
            search_id: ricerca,
            outcome: esito,
            new_results: nuove,
            page_full: false,
            newest_published_at: piu_recente.map(later),
            reason: String::from("motivo"),
        }
    }

    /// **Una ricorrente si salva, si sospende, si ritira, e la sua definizione
    /// non si riscrive** (CYBER-WATCH-02, criterio 1).
    #[test]
    fn una_ricorrente_si_salva_si_sospende_e_si_ritira() {
        let mut archivio = database();
        let Ok(id) = archivio.insert_recurring_search(&ricorrente("D", None, 60), &audit()) else {
            panic!("la ricorrente deve salvarsi");
        };
        assert_eq!(
            archivio
                .set_recurring_search_suspended(id, true, &audit())
                .ok(),
            Some(true)
        );
        let Ok(elenco) = archivio.recurring_searches() else {
            panic!("l'elenco deve leggersi");
        };
        assert_eq!(elenco.len(), 1);
        assert!(elenco[0].suspended);
        assert_eq!(
            archivio
                .withdraw_recurring_search(id, "operatore.prova", later(5), &audit())
                .ok(),
            Some(true)
        );
        assert_eq!(archivio.recurring_searches().map(|e| e.len()).ok(), Some(0));
        assert_eq!(
            archivio
                .set_recurring_search_suspended(id, false, &audit())
                .ok(),
            Some(false),
            "una ritirata non si riprende"
        );
        assert_eq!(
            archivio
                .withdraw_recurring_search(id, "operatore.prova", later(6), &audit())
                .ok(),
            Some(false)
        );
        for comando in [
            "UPDATE recurring_searches SET query = 'altro'",
            "UPDATE recurring_searches SET suspended = 0",
            "DELETE FROM recurring_searches",
        ] {
            assert!(
                archivio.connection.execute(comando, []).is_err(),
                "«{comando}»"
            );
        }
        let Ok(audit_scritti) = archivio.connection.query_row(
            "SELECT COUNT(*) FROM audit WHERE entity = 'ricerca_ricorrente'",
            [],
            |row| row.get::<_, i64>(0),
        ) else {
            panic!("l'audit deve leggersi");
        };
        assert_eq!(audit_scritti, 3, "salvata, sospesa, ritirata");
    }

    /// **Lo schema rifiuta una ricorrente fuori misura** (criterio 1).
    #[test]
    fn lo_schema_rifiuta_una_ricorrente_fuori_misura() {
        let mut archivio = database();
        for (descrizione, sbagliata) in [
            ("C senza chat", ricorrente("C", None, 60)),
            ("B con chat", ricorrente("B", Some(-1001), 60)),
            ("ramo E", ricorrente("E", None, 60)),
            ("meno di un'ora", ricorrente("B", None, 59)),
            ("più di un giorno", ricorrente("B", None, 1_441)),
            (
                "parola di un carattere",
                NewRecurringSearch {
                    query: String::from("x"),
                    ..ricorrente("B", None, 60)
                },
            ),
        ] {
            assert!(
                archivio
                    .insert_recurring_search(&sbagliata, &audit())
                    .is_err(),
                "lo schema deve rifiutare: {descrizione}"
            );
        }
    }

    /// **Le esecuzioni si registrano, danno la soglia delle novità e il conto
    /// delle pagine, e non si riscrivono** (criteri 3, 4, 5).
    #[test]
    fn le_esecuzioni_danno_la_soglia_e_il_conto_delle_pagine() {
        let mut archivio = database();
        let Ok(id) = archivio.insert_recurring_search(&ricorrente("B", None, 60), &audit()) else {
            panic!("la ricorrente deve salvarsi");
        };
        let Ok(pagina) = archivio.insert_cyber_search(
            &NewCyberSearch {
                searched_by: String::from("operatore.prova"),
                searched_at: later(10),
                branch: "B",
                query: String::from("ransomware"),
                scope: String::from("perimetro"),
                chat_id: None,
                page: 1,
                outcome: "trovati",
                results: 2,
                outcome_reason: String::from("motivo"),
            },
            &audit(),
        ) else {
            panic!("la pagina deve registrarsi");
        };
        assert_eq!(archivio.recurring_newest_seen(id).ok(), Some(None));
        for riga in [
            esecuzione(id, 5, None, "saltata", 0, None),
            esecuzione(id, 10, Some(pagina), "novita", 2, Some(8)),
        ] {
            let Ok(_) = archivio.insert_recurring_run(&riga) else {
                panic!("l'esecuzione deve registrarsi");
            };
        }
        assert_eq!(
            archivio.recurring_newest_seen(id).ok(),
            Some(Some(later(8)))
        );
        assert_eq!(
            archivio.recurring_pages_since(later(0)).ok(),
            Some(1),
            "una saltata non è una pagina"
        );
        let Ok(esecuzioni) = archivio.recurring_runs(id, 10) else {
            panic!("le esecuzioni devono leggersi");
        };
        assert_eq!(esecuzioni.len(), 2);
        assert_eq!(esecuzioni[0].outcome, "novita", "dalla più nuova");

        for (descrizione, sbagliata) in [
            (
                "saltata con una pagina",
                esecuzione(id, 20, Some(pagina), "saltata", 0, None),
            ),
            (
                "novità senza novità",
                esecuzione(id, 20, Some(pagina), "novita", 0, None),
            ),
            (
                "nessuna novità con novità",
                esecuzione(id, 20, Some(pagina), "nessuna_novita", 3, None),
            ),
            (
                "fatta senza pagina",
                esecuzione(id, 20, None, "nessuna_novita", 0, None),
            ),
        ] {
            assert!(
                archivio.insert_recurring_run(&sbagliata).is_err(),
                "lo schema deve rifiutare: {descrizione}"
            );
        }
        for comando in [
            "UPDATE recurring_search_runs SET reason = 'altro'",
            "DELETE FROM recurring_search_runs",
        ] {
            assert!(
                archivio.connection.execute(comando, []).is_err(),
                "«{comando}»"
            );
        }
    }
}

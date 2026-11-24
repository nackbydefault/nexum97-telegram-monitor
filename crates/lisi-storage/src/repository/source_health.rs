//! Verifiche di salute di una fonte.
//!
//! # Che cosa questo modulo scrive, e che cosa non scrive
//!
//! Scrive **osservazioni**: a un istante, una fonte risultava in un certo modo
//! a un certo account. Non scrive stati: lo stato si deriva, ed è
//! `lisi_core::model::source_health::derive` a farlo.
//!
//! La distinzione è la stessa di PROV-01: si conservano i fatti, e la
//! conclusione si ricalcola da essi. Conservare lo stato significherebbe avere
//! una seconda copia che può divergere dai fatti che la producono.

use std::collections::BTreeMap;

use lisi_core::model::source_health::HealthCheckOutcome;
use lisi_core::{SourceId, Timestamp};
use rusqlite::Row;

use crate::database::Database;
use crate::error::{StorageError, StorageResult};
use crate::repository::{instant, millis};

/// Verifica che si intende registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewHealthCheck {
    /// Fonte osservata.
    pub source_id: SourceId,
    /// Account che ha osservato, quando la fonte ne ha uno.
    pub account_id: Option<i64>,
    /// Che cosa la verifica ha appreso.
    pub outcome: HealthCheckOutcome,
    /// Classe dell'errore o precisazione dell'esito.
    ///
    /// **Costante del prodotto, mai il testo di un errore remoto.**
    pub detail: Option<String>,
}

/// Verifica registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthCheck {
    /// Identificatore assegnato dalla persistenza.
    pub id: i64,
    /// Fonte osservata.
    pub source_id: SourceId,
    /// Account che ha osservato.
    pub account_id: Option<i64>,
    /// Che cosa la verifica ha appreso.
    pub outcome: HealthCheckOutcome,
    /// Classe dell'errore o precisazione dell'esito.
    pub detail: Option<String>,
    /// Istante dell'osservazione.
    pub observed_at: Timestamp,
}

/// Quel che serve a derivare lo stato di una fonte, letto dall'archivio.
///
/// Non contiene lo stato: contiene i **fatti**, e chi legge li passa a
/// `derive`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoredHealthFacts {
    /// L'ultima osservazione conclusiva, con il suo istante.
    pub last_conclusive: Option<(HealthCheckOutcome, Timestamp)>,
    /// L'istante dell'ultimo tentativo, riuscito o no.
    pub last_attempt_at: Option<Timestamp>,
    /// Tentativi non riusciti dopo l'ultima osservazione conclusiva.
    pub failed_attempts_since: u32,
}

impl Database {
    /// Registra una verifica.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce, in particolare se la
    /// fonte non esiste.
    pub fn insert_health_check(
        &self,
        check: &NewHealthCheck,
        now: Timestamp,
    ) -> StorageResult<i64> {
        self.connection.execute(
            "INSERT INTO source_health_checks
                 (source_id, account_id, outcome, detail, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                check.source_id.get(),
                check.account_id,
                check.outcome.as_str(),
                check.detail.as_deref(),
                millis(now),
            ],
        )?;
        Ok(self.connection.last_insert_rowid())
    }

    /// Le ultime verifiche di una fonte, dalla più recente.
    ///
    /// `limit` è il numero massimo di righe restituite: la storia di una fonte
    /// può essere lunga, e il pannello ne mostra le ultime.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// esito che il dominio non riconosce.
    pub fn source_health_checks(
        &self,
        source_id: SourceId,
        limit: u32,
    ) -> StorageResult<Vec<HealthCheck>> {
        let mut statement = self.connection.prepare(
            "SELECT id, source_id, account_id, outcome, detail, observed_at
             FROM source_health_checks
             WHERE source_id = ?1
             ORDER BY observed_at DESC, id DESC
             LIMIT ?2",
        )?;

        let rows = statement.query_map(rusqlite::params![source_id.get(), limit], read_check)?;

        let mut checks = Vec::new();
        for row in rows {
            checks.push(row??);
        }
        Ok(checks)
    }

    /// I fatti di salute di **tutte** le fonti, in una lettura sola.
    ///
    /// # Perché in blocco
    ///
    /// Perché l'elenco delle fonti mostra lo stato di ciascuna: chiedere la
    /// storia fonte per fonte sarebbe un'interrogazione per riga. È la stessa
    /// scelta di CTX-01 e di PROV-01, e la stessa ragione.
    ///
    /// Le fonti senza alcuna verifica **non compaiono**: l'assenza della chiave
    /// significa «mai verificata», che è esattamente ciò che il chiamante deve
    /// sapere.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// esito che il dominio non riconosce.
    pub fn health_facts(&self) -> StorageResult<BTreeMap<i64, StoredHealthFacts>> {
        // Si legge in ordine cronologico CRESCENTE e si ricostruisce in avanti:
        // cosi' "tentativi non riusciti DOPO l'ultima osservazione conclusiva"
        // e' un conteggio che si azzera ogni volta che arriva un'osservazione
        // conclusiva, senza una seconda interrogazione.
        let mut statement = self.connection.prepare(
            "SELECT source_id, outcome, observed_at
             FROM source_health_checks
             ORDER BY source_id, observed_at, id",
        )?;

        let rows = statement.query_map([], |row| {
            let source_id: i64 = row.get(0)?;
            let outcome: String = row.get(1)?;
            let observed_at: i64 = row.get(2)?;
            Ok((source_id, outcome, observed_at))
        })?;

        let mut per_fonte: BTreeMap<i64, StoredHealthFacts> = BTreeMap::new();
        for row in rows {
            let (source_id, outcome, observed_at) = row?;
            let Some(outcome) = HealthCheckOutcome::from_stored(&outcome) else {
                return Err(StorageError::CorruptedRow {
                    detail: "esito di una verifica di salute non riconosciuto",
                });
            };
            let observed_at = instant(observed_at);

            let facts = per_fonte.entry(source_id).or_default();
            facts.last_attempt_at = Some(observed_at);
            if outcome.is_conclusive() {
                facts.last_conclusive = Some((outcome, observed_at));
                facts.failed_attempts_since = 0;
            } else {
                facts.failed_attempts_since = facts.failed_attempts_since.saturating_add(1);
            }
        }
        Ok(per_fonte)
    }

    /// Quanti guasti sono attribuiti a ciascuna fonte dopo un certo istante.
    ///
    /// Le fonti senza guasti non compaiono. Una chiave assente significa zero.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn faults_per_source_since(&self) -> StorageResult<BTreeMap<i64, Vec<Timestamp>>> {
        let mut statement = self.connection.prepare(
            "SELECT source_id, occurred_at
             FROM faults
             WHERE source_id IS NOT NULL
             ORDER BY source_id, occurred_at",
        )?;

        let rows = statement.query_map([], |row| {
            let source_id: i64 = row.get(0)?;
            let occurred_at: i64 = row.get(1)?;
            Ok((source_id, occurred_at))
        })?;

        let mut per_fonte: BTreeMap<i64, Vec<Timestamp>> = BTreeMap::new();
        for row in rows {
            let (source_id, occurred_at) = row?;
            per_fonte
                .entry(source_id)
                .or_default()
                .push(instant(occurred_at));
        }
        Ok(per_fonte)
    }

    /// Istante dell'ultimo contenuto acquisito, per ciascuna fonte.
    ///
    /// **Informativo.** Non concorre allo stato di salute: serve a mostrarlo
    /// accanto, perché l'operatore vuole sapere anche quello.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn last_content_per_source(&self) -> StorageResult<BTreeMap<i64, Timestamp>> {
        let mut statement = self
            .connection
            .prepare("SELECT source_id, MAX(acquired_at) FROM contents GROUP BY source_id")?;

        let rows = statement.query_map([], |row| {
            let source_id: i64 = row.get(0)?;
            let acquired_at: i64 = row.get(1)?;
            Ok((source_id, acquired_at))
        })?;

        let mut per_fonte = BTreeMap::new();
        for row in rows {
            let (source_id, acquired_at) = row?;
            per_fonte.insert(source_id, instant(acquired_at));
        }
        Ok(per_fonte)
    }
}

/// Legge una riga di verifica, validando l'esito contro il dominio.
fn read_check(row: &Row<'_>) -> rusqlite::Result<StorageResult<HealthCheck>> {
    let id: i64 = row.get(0)?;
    let source_id: i64 = row.get(1)?;
    let account_id: Option<i64> = row.get(2)?;
    let outcome: String = row.get(3)?;
    let detail: Option<String> = row.get(4)?;
    let observed_at: i64 = row.get(5)?;

    Ok(HealthCheckOutcome::from_stored(&outcome).map_or_else(
        || {
            Err(StorageError::CorruptedRow {
                detail: "esito di una verifica di salute non riconosciuto",
            })
        },
        |outcome| {
            Ok(HealthCheck {
                id,
                source_id: SourceId::new(source_id),
                account_id,
                outcome,
                detail: detail.clone(),
                observed_at: instant(observed_at),
            })
        },
    ))
}

#[cfg(test)]
mod tests {
    use lisi_core::model::source_health::HealthCheckOutcome;
    use lisi_core::{SourceId, Timestamp};

    use super::NewHealthCheck;
    use crate::test_support::{database_with_session, now};

    fn check(source_id: SourceId, outcome: HealthCheckOutcome) -> NewHealthCheck {
        NewHealthCheck {
            source_id,
            account_id: None,
            outcome,
            detail: None,
        }
    }

    #[test]
    fn una_verifica_si_scrive_e_si_rilegge_immutata() {
        let (database, source_id, _) = database_with_session();

        let Ok(id) = database.insert_health_check(
            &NewHealthCheck {
                source_id,
                account_id: None,
                outcome: HealthCheckOutcome::Reachable,
                detail: Some(String::from("storico leggibile")),
            },
            now(),
        ) else {
            panic!("la verifica deve potersi registrare");
        };
        assert!(id > 0);

        let Ok(checks) = database.source_health_checks(source_id, 10) else {
            panic!("le verifiche devono potersi leggere");
        };
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].outcome, HealthCheckOutcome::Reachable);
        assert_eq!(checks[0].detail.as_deref(), Some("storico leggibile"));
        assert_eq!(checks[0].source_id, source_id);
    }

    #[test]
    fn una_fonte_mai_verificata_non_compare_fra_i_fatti() {
        let (database, _, _) = database_with_session();

        let Ok(fatti) = database.health_facts() else {
            panic!("i fatti devono potersi leggere");
        };
        assert!(
            fatti.is_empty(),
            "l'assenza della chiave significa «mai verificata»"
        );
    }

    #[test]
    fn i_tentativi_non_riusciti_si_contano_dopo_l_ultima_osservazione_conclusiva() {
        let (database, source_id, _) = database_with_session();

        // Conclusiva, poi due tentativi non riusciti.
        for (millis, outcome) in [
            (1_700_000_000_000_i64, HealthCheckOutcome::Reachable),
            (1_700_000_100_000, HealthCheckOutcome::CheckFailed),
            (1_700_000_200_000, HealthCheckOutcome::CheckFailed),
        ] {
            let Ok(_) = database
                .insert_health_check(&check(source_id, outcome), Timestamp::from_millis(millis))
            else {
                panic!("la verifica deve potersi registrare");
            };
        }

        let Ok(fatti) = database.health_facts() else {
            panic!("i fatti devono potersi leggere");
        };
        let fonte = &fatti[&source_id.get()];
        assert_eq!(
            fonte.last_conclusive.map(|(outcome, _)| outcome),
            Some(HealthCheckOutcome::Reachable)
        );
        assert_eq!(fonte.failed_attempts_since, 2);
        // L'ultimo TENTATIVO e' piu' recente dell'ultima OSSERVAZIONE.
        assert_eq!(
            fonte.last_attempt_at,
            Some(Timestamp::from_millis(1_700_000_200_000))
        );
        assert_eq!(
            fonte.last_conclusive.map(|(_, istante)| istante),
            Some(Timestamp::from_millis(1_700_000_000_000))
        );
    }

    #[test]
    fn una_nuova_osservazione_conclusiva_azzera_i_tentativi_non_riusciti() {
        let (database, source_id, _) = database_with_session();

        for (millis, outcome) in [
            (1_700_000_000_000_i64, HealthCheckOutcome::Reachable),
            (1_700_000_100_000, HealthCheckOutcome::CheckFailed),
            (1_700_000_200_000, HealthCheckOutcome::CheckFailed),
            (1_700_000_300_000, HealthCheckOutcome::Reachable),
        ] {
            let Ok(_) = database
                .insert_health_check(&check(source_id, outcome), Timestamp::from_millis(millis))
            else {
                panic!("la verifica deve potersi registrare");
            };
        }

        let Ok(fatti) = database.health_facts() else {
            panic!("i fatti devono potersi leggere");
        };
        assert_eq!(fatti[&source_id.get()].failed_attempts_since, 0);
    }

    #[test]
    fn la_lettura_in_blocco_e_quella_per_fonte_concordano() {
        let (database, source_id, _) = database_with_session();

        for (millis, outcome) in [
            (1_700_000_000_000_i64, HealthCheckOutcome::Reachable),
            (1_700_000_100_000, HealthCheckOutcome::NotAccessible),
        ] {
            let Ok(_) = database
                .insert_health_check(&check(source_id, outcome), Timestamp::from_millis(millis))
            else {
                panic!("la verifica deve potersi registrare");
            };
        }

        let (Ok(fatti), Ok(storia)) = (
            database.health_facts(),
            database.source_health_checks(source_id, 10),
        ) else {
            panic!("le due letture devono riuscire");
        };

        // La piu' recente della storia e' l'ultima osservazione conclusiva dei
        // fatti: due percorsi verso lo stesso dato.
        assert_eq!(storia[0].outcome, HealthCheckOutcome::NotAccessible);
        assert_eq!(
            fatti[&source_id.get()].last_conclusive.map(|(o, _)| o),
            Some(HealthCheckOutcome::NotAccessible)
        );
    }
}

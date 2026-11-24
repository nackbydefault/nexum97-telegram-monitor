//! Le scoperte pubbliche in archivio: che cosa è stato chiesto, che cosa **non**
//! è stato chiesto, e su quali limiti poggiava.
//!
//! # La regola che governa questo modulo
//!
//! **Una scoperta si scrive tutta insieme, o non si scrive.**
//!
//! Domande, omissioni, risultati e motivi entrano in **una sola transazione**.
//! Una scoperta registrata a metà è peggio di una non registrata: dichiara meno
//! di quanto ha chiesto, e chi la rilegge conta le domande e ne trova meno di
//! quante ne erano state poste, **senza sapere che ne mancano**.
//!
//! È la stessa lezione della fotografia KEV: *una fotografia si scrive intera o
//! per niente* (ADR-0061, ADR-0076).
//!
//! # Perché `contents` non compare qui
//!
//! «Come è stato acquisito un contenuto» e «come è stata scoperta una fonte»
//! sono due storie diverse, e **un candidato non è un contenuto** (ADR-0035,
//! decisione 13).

use lisi_core::model::discovery::{CandidateDecision, DiscoveryQuery, PublicAddress, SearchScope};
use lisi_core::model::discovery_plan::{DiscoveryBudget, Omission};
use lisi_core::model::source::NewSource;
use lisi_core::{SourceId, Timestamp};

use crate::Database;
use crate::error::{StorageError, StorageResult};

/// Un risultato da registrare, con i motivi che lo rendono un candidato.
///
/// Senza motivi è **solo un risultato**: la regola del dominio — un candidato
/// non si costruisce senza un motivo — qui diventa «nessuna riga, nessun
/// candidato».
#[derive(Debug, Clone)]
pub struct NewDiscoveryResult<'a> {
    /// La domanda che lo ha restituito.
    pub query: &'a str,
    /// La superficie da cui viene.
    pub scope: SearchScope,
    /// Il nome pubblico, **così come è arrivato**.
    pub public_name: &'a str,
    /// L'indirizzo pubblico, quando la chat ne ha uno.
    pub public_address: Option<&'a PublicAddress>,
    /// Perché è stato suggerito. Vuoto significa: non è un candidato.
    pub reasons: &'a [String],
}

/// Una scoperta da registrare, intera.
#[derive(Debug, Clone)]
pub struct NewDiscoveryRun<'a> {
    /// Quando è cominciata.
    pub started_at: i64,
    /// Dove si è guardato.
    pub scope: SearchScope,
    /// I tetti che valevano.
    pub budget: DiscoveryBudget,
    /// Quante interrogazioni gratuite al giorno dichiarava la misura.
    pub limits_free_per_day: u32,
    /// Quante ne restavano al momento della misura.
    pub limits_remaining_free: u32,
    /// Quando è stata fatta la misura.
    pub limits_observed_at: i64,
    /// Da quale misura vengono quei numeri.
    pub limits_origin: &'a str,
    /// Le domande poste, nell'ordine.
    pub queries: &'a [DiscoveryQuery],
    /// Ciò che **non** è stato chiesto, con il motivo.
    pub omissions: &'a [(String, Omission)],
    /// Ciò che è stato restituito.
    pub results: &'a [NewDiscoveryResult<'a>],
}

/// Una scoperta come sta in archivio, con la misura su cui poggiava.
///
/// # Perché i limiti tornano indietro interi
///
/// Un numero senza provenienza non si distingue da uno inventato, e sei mesi
/// dopo la **data** della misura è ciò che dice se quella scoperta valga ancora
/// qualcosa (ADR-0074, ADR-0079).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedDiscoveryRun {
    /// Identificativo interno dell'esecuzione.
    pub id: i64,
    /// Quando è cominciata.
    pub started_at: i64,
    /// Dove si è guardato.
    pub scope: SearchScope,
    /// I tetti che valevano.
    pub budget: DiscoveryBudget,
    /// Quante interrogazioni gratuite al giorno dichiarava la misura.
    pub limits_free_per_day: u32,
    /// Quante ne restavano al momento della misura.
    pub limits_remaining_free: u32,
    /// Quando è stata fatta la misura.
    pub limits_observed_at: i64,
    /// Da quale misura vengono quei numeri.
    pub limits_origin: String,
}

/// Un risultato come sta in archivio, con i motivi che lo rendono un candidato.
///
/// Senza motivi è **solo un risultato**, e si rilegge così: l'elenco vuoto è il
/// fatto, non un dato mancante.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedDiscoveryResult {
    /// La domanda che lo ha restituito.
    pub query: String,
    /// La superficie da cui viene.
    pub scope: SearchScope,
    /// Il nome pubblico, **così come era arrivato**.
    ///
    /// È testo di provenienza ostile: chi lo mostra non lo interpreta.
    pub public_name: String,
    /// L'indirizzo pubblico, quando la chat ne ha uno.
    ///
    /// Senza, il risultato **non si può né aprire né aggiungere**: non c'è
    /// niente da aprire e niente da sorvegliare (ADR-0080).
    pub public_address: Option<PublicAddress>,
    /// Identificativo interno della riga, per decidere su di essa.
    pub id: i64,
    /// Perché è stato suggerito.
    pub reasons: Vec<String>,
}

/// Una decisione presa su un candidato.
///
/// **È un fatto, non uno stato**: non si modifica e non si cancella. Cambiare
/// idea si fa decidendo di nuovo, e le due decisioni restano entrambe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedCandidateDecision {
    /// Su quale risultato.
    pub result_id: i64,
    /// Che cosa è stato deciso.
    pub decision: CandidateDecision,
    /// Chi l'ha deciso.
    pub actor: String,
    /// Perché.
    pub reason: String,
    /// Quando.
    pub decided_at: i64,
    /// La fonte nata da questa decisione, quando ne è nata una.
    pub source_id: Option<i64>,
}

/// Una decisione da registrare.
#[derive(Debug, Clone)]
pub struct NewCandidateDecision<'a> {
    /// Su quale risultato.
    pub result_id: i64,
    /// Che cosa si è deciso.
    pub decision: CandidateDecision,
    /// Chi lo ha deciso.
    pub actor: &'a str,
    /// Perché. **Obbligatorio**: un motivo per candidato è la difesa più
    /// semplice contro il gesto.
    pub reason: &'a str,
    /// Quando.
    pub decided_at: Timestamp,
    /// La fonte da far nascere, se e solo se la decisione è «aggiunto».
    pub source: Option<&'a NewSource>,
}

impl Database {
    /// Registra una scoperta, **intera**.
    ///
    /// # Perché una transazione sola
    ///
    /// Vedere la nota del modulo: una scoperta registrata a metà dichiara meno
    /// di quanto ha chiesto, e chi la rilegge non sa che ne mancano.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce. **Nulla resta scritto**:
    /// la transazione non viene confermata.
    pub fn record_discovery_run(&mut self, run: &NewDiscoveryRun<'_>) -> StorageResult<i64> {
        let transaction = self.connection.transaction()?;

        transaction.execute(
            "INSERT INTO discovery_runs (
                 started_at, scope,
                 max_distinct_queries, max_results_per_query,
                 our_page_cap, our_wait_seconds, our_consecutive_errors,
                 declared_backoff_seconds,
                 limits_free_per_day, limits_remaining_free,
                 limits_observed_at, limits_origin
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                run.started_at,
                run.scope.as_str(),
                run.budget.distinct_queries,
                run.budget.results_per_query,
                run.budget.our_page_cap,
                run.budget.our_wait_seconds,
                run.budget.our_consecutive_errors,
                run.budget.declared_backoff_seconds,
                run.limits_free_per_day,
                run.limits_remaining_free,
                run.limits_observed_at,
                run.limits_origin,
            ],
        )?;
        let run_id = transaction.last_insert_rowid();

        for (posizione, domanda) in run.queries.iter().enumerate() {
            transaction.execute(
                "INSERT INTO discovery_queries (run_id, position, query)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![
                    run_id,
                    i64::try_from(posizione).unwrap_or(0),
                    domanda.as_str()
                ],
            )?;
        }

        // CIO' CHE NON E' STATO CHIESTO SI SCRIVE QUI, nella stessa transazione
        // delle domande: sono la differenza fra «non cercato» e «non trovato», e
        // separarle sarebbe separare una frase dalla sua negazione.
        for (posizione, (termine, motivo)) in run.omissions.iter().enumerate() {
            transaction.execute(
                "INSERT INTO discovery_omissions (run_id, position, term, reason)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    run_id,
                    i64::try_from(posizione).unwrap_or(0),
                    termine,
                    motivo.as_str()
                ],
            )?;
        }

        for risultato in run.results {
            transaction.execute(
                "INSERT INTO discovery_results (run_id, query, scope, public_name, public_address)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    run_id,
                    risultato.query,
                    risultato.scope.as_str(),
                    risultato.public_name,
                    risultato
                        .public_address
                        .map(lisi_core::model::discovery::PublicAddress::as_str)
                ],
            )?;
            let result_id = transaction.last_insert_rowid();

            for (posizione, motivo) in risultato.reasons.iter().enumerate() {
                transaction.execute(
                    "INSERT INTO discovery_result_reasons (result_id, position, reason)
                     VALUES (?1, ?2, ?3)",
                    rusqlite::params![result_id, i64::try_from(posizione).unwrap_or(0), motivo],
                )?;
            }
        }

        transaction.commit()?;
        Ok(run_id)
    }

    /// Le domande poste da una scoperta, nell'ordine.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn discovery_queries(&self, run_id: i64) -> StorageResult<Vec<String>> {
        let mut statement = self
            .connection
            .prepare("SELECT query FROM discovery_queries WHERE run_id = ?1 ORDER BY position")?;
        let righe = statement.query_map([run_id], |row| row.get::<_, String>(0))?;

        let mut domande = Vec::new();
        for riga in righe {
            domande.push(riga?);
        }
        Ok(domande)
    }

    /// Ciò che **non** è stato chiesto, con il motivo, nell'ordine.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn discovery_omissions(&self, run_id: i64) -> StorageResult<Vec<(String, String)>> {
        let mut statement = self.connection.prepare(
            "SELECT term, reason FROM discovery_omissions WHERE run_id = ?1 ORDER BY position",
        )?;
        let righe = statement.query_map([run_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut omissioni = Vec::new();
        for riga in righe {
            omissioni.push(riga?);
        }
        Ok(omissioni)
    }

    /// Le scoperte registrate, **la più recente per prima**.
    ///
    /// # Perché l'ambito torna come tipo e non come testo
    ///
    /// Perché un nome che l'archivio non ha mai scritto non si interpreta: il
    /// vincolo di schema lo esclude, e questa lettura lo esclude una seconda
    /// volta invece di far passare una provenienza che nessuno può leggere.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce, o se l'ambito scritto in
    /// archivio non è uno di quelli che questo prodotto conosce.
    pub fn discovery_runs(&self) -> StorageResult<Vec<RecordedDiscoveryRun>> {
        let mut statement = self.connection.prepare(
            "SELECT id, started_at, scope,
                    max_distinct_queries, max_results_per_query,
                    our_page_cap, our_wait_seconds, our_consecutive_errors,
                    declared_backoff_seconds,
                    limits_free_per_day, limits_remaining_free,
                    limits_observed_at, limits_origin
               FROM discovery_runs
              ORDER BY started_at DESC, id DESC",
        )?;
        let righe = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                DiscoveryBudget {
                    distinct_queries: row.get::<_, u32>(3)?,
                    results_per_query: row.get::<_, u32>(4)?,
                    our_page_cap: row.get::<_, u32>(5)?,
                    our_wait_seconds: row.get::<_, u32>(6)?,
                    our_consecutive_errors: row.get::<_, u32>(7)?,
                    declared_backoff_seconds: row.get::<_, u32>(8)?,
                },
                row.get::<_, u32>(9)?,
                row.get::<_, u32>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, String>(12)?,
            ))
        })?;

        let mut scoperte = Vec::new();
        for riga in righe {
            let (id, started_at, ambito, budget, per_day, remaining, observed_at, origin) = riga?;
            let Some(scope) = SearchScope::dal_nome(&ambito) else {
                return Err(StorageError::UnknownSearchScope(ambito));
            };
            scoperte.push(RecordedDiscoveryRun {
                id,
                started_at,
                scope,
                budget,
                limits_free_per_day: per_day,
                limits_remaining_free: remaining,
                limits_observed_at: observed_at,
                limits_origin: origin,
            });
        }
        Ok(scoperte)
    }

    /// Ciò che una scoperta ha restituito, con i motivi di ciascun risultato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce, o se l'ambito scritto in
    /// archivio non è uno di quelli che questo prodotto conosce.
    pub fn discovery_results(&self, run_id: i64) -> StorageResult<Vec<RecordedDiscoveryResult>> {
        let mut statement = self.connection.prepare(
            "SELECT id, query, scope, public_name, public_address
               FROM discovery_results
              WHERE run_id = ?1
              ORDER BY id",
        )?;
        let righe = statement.query_map([run_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })?;

        let mut grezzi = Vec::new();
        for riga in righe {
            grezzi.push(riga?);
        }

        let mut risultati = Vec::with_capacity(grezzi.len());
        for (id, query, ambito, public_name, indirizzo) in grezzi {
            let Some(scope) = SearchScope::dal_nome(&ambito) else {
                return Err(StorageError::UnknownSearchScope(ambito));
            };
            // UN INDIRIZZO MAL FORMATO NON SI CORREGGE. Torna indietro come
            // assente, che e' la stessa cosa che significa per chi decide: non
            // c'e' niente da aprire e niente da sorvegliare.
            let public_address = indirizzo
                .as_deref()
                .and_then(lisi_core::model::discovery::PublicAddress::try_new);
            risultati.push(RecordedDiscoveryResult {
                query,
                scope,
                public_name,
                public_address,
                id,
                reasons: self.discovery_result_reasons(id)?,
            });
        }
        Ok(risultati)
    }

    /// Registra una decisione presa su un candidato, **e la fonte che ne nasce**.
    ///
    /// # Perché in una transazione sola
    ///
    /// Una fonte senza la decisione che l'ha creata è una fonte comparsa dal
    /// nulla; una decisione che dichiara una fonte che non esiste è una bugia in
    /// archivio. O entrambe, o niente (ADR-0080).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce. **Nulla resta
    /// scritto**: la transazione non viene confermata.
    pub fn record_candidate_decision(
        &mut self,
        decisione: &NewCandidateDecision<'_>,
    ) -> StorageResult<Option<SourceId>> {
        let transaction = self.connection.transaction()?;

        let fonte = match decisione.source {
            Some(nuova) => {
                transaction.execute(
                    "INSERT INTO sources (
                         kind, identifier, display_name, authorized_by, active, created_at, updated_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                    rusqlite::params![
                        nuova.kind.as_str(),
                        nuova.identifier.as_str(),
                        nuova.display_name.as_str(),
                        nuova.authorized_by.as_str(),
                        i64::from(nuova.active),
                        decisione.decided_at.as_millis()
                    ],
                )?;
                Some(SourceId::new(transaction.last_insert_rowid()))
            }
            None => None,
        };

        transaction.execute(
            "INSERT INTO discovery_decisions
                 (result_id, decision, actor, reason, decided_at, source_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                decisione.result_id,
                decisione.decision.as_str(),
                decisione.actor,
                decisione.reason,
                decisione.decided_at.as_millis(),
                fonte.map(SourceId::get)
            ],
        )?;

        transaction.commit()?;
        Ok(fonte)
    }

    /// Le decisioni prese sui risultati di una scoperta, nell'ordine in cui sono
    /// state prese.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce, o se una decisione scritta
    /// in archivio non è una di quelle che questo prodotto conosce.
    pub fn candidate_decisions(
        &self,
        run_id: i64,
    ) -> StorageResult<Vec<RecordedCandidateDecision>> {
        let mut statement = self.connection.prepare(
            "SELECT d.result_id, d.decision, d.actor, d.reason, d.decided_at, d.source_id
               FROM discovery_decisions d
               JOIN discovery_results r ON r.id = d.result_id
              WHERE r.run_id = ?1
              ORDER BY d.id",
        )?;
        let righe = statement.query_map([run_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<i64>>(5)?,
            ))
        })?;

        let mut decisioni = Vec::new();
        for riga in righe {
            let (result_id, nome, actor, reason, decided_at, source_id) = riga?;
            let Some(decision) = CandidateDecision::dal_nome(&nome) else {
                return Err(StorageError::UnknownCandidateDecision(nome));
            };
            decisioni.push(RecordedCandidateDecision {
                result_id,
                decision,
                actor,
                reason,
                decided_at,
                source_id,
            });
        }
        Ok(decisioni)
    }

    /// I motivi di un risultato, nell'ordine in cui erano stati scritti.
    fn discovery_result_reasons(&self, result_id: i64) -> StorageResult<Vec<String>> {
        let mut statement = self.connection.prepare(
            "SELECT reason FROM discovery_result_reasons WHERE result_id = ?1 ORDER BY position",
        )?;
        let righe = statement.query_map([result_id], |row| row.get::<_, String>(0))?;

        let mut motivi = Vec::new();
        for riga in righe {
            motivi.push(riga?);
        }
        Ok(motivi)
    }

    /// Da quale misura poggiava una scoperta.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn discovery_limits_origin(&self, run_id: i64) -> StorageResult<String> {
        let origine: String = self.connection.query_row(
            "SELECT limits_origin FROM discovery_runs WHERE id = ?1",
            [run_id],
            |row| row.get(0),
        )?;
        Ok(origine)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::discovery::{
        CandidateDecision, DiscoveryQuery, PublicAddress, SearchScope,
    };
    use lisi_core::model::discovery_plan::{DiscoveryBudget, Omission};
    use lisi_core::model::source::{NewSource, SourceKind};
    use lisi_core::text::{Actor, DisplayName, SourceIdentifier};

    use super::{NewCandidateDecision, NewDiscoveryResult, NewDiscoveryRun};
    use crate::test_support::database;

    fn budget() -> DiscoveryBudget {
        DiscoveryBudget {
            distinct_queries: 5,
            results_per_query: 20,
            our_page_cap: 5,
            our_wait_seconds: 30,
            our_consecutive_errors: 3,
            declared_backoff_seconds: 0,
        }
    }

    fn domande(elenco: &[&str]) -> Vec<DiscoveryQuery> {
        elenco
            .iter()
            .filter_map(|testo| DiscoveryQuery::try_new(testo))
            .collect()
    }

    fn fonte_di_prova() -> NewSource {
        let Ok(identifier) = SourceIdentifier::try_new("canale_uno") else {
            panic!("l'identificativo di prova e' valido");
        };
        let Ok(display_name) = DisplayName::try_new("Canale Uno") else {
            panic!("il nome di prova e' valido");
        };
        let Ok(authorized_by) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova e' valido");
        };
        NewSource {
            kind: SourceKind::Channel,
            identifier,
            display_name,
            authorized_by,
            active: true,
        }
    }

    fn scoperta_con_un_candidato(database: &mut crate::Database) -> i64 {
        let poste = domande(&["ransomware"]);
        let motivi = vec![String::from("18 riscontri Cyber Core")];
        let Some(indirizzo) = PublicAddress::try_new("canale_uno") else {
            panic!("l'indirizzo di prova e' valido");
        };

        let Ok(run_id) = database.record_discovery_run(&NewDiscoveryRun {
            started_at: 1,
            scope: SearchScope::PublicChannelPosts,
            budget: budget(),
            limits_free_per_day: 100,
            limits_remaining_free: 100,
            limits_observed_at: 1,
            limits_origin: "una misura con un nome",
            queries: &poste,
            omissions: &[],
            results: &[NewDiscoveryResult {
                query: "ransomware",
                scope: SearchScope::PublicChannelPosts,
                public_name: "Canale Uno",
                public_address: Some(&indirizzo),
                reasons: &motivi,
            }],
        }) else {
            panic!("la scoperta di prova deve potersi registrare");
        };
        run_id
    }

    /// **L'indirizzo pubblico torna indietro com'era.**
    ///
    /// Senza, un candidato non si puo' ne' aprire ne' aggiungere.
    #[test]
    fn l_indirizzo_pubblico_si_rilegge() {
        let mut database = database();
        let run_id = scoperta_con_un_candidato(&mut database);

        let Ok(risultati) = database.discovery_results(run_id) else {
            panic!("i risultati devono potersi rileggere");
        };
        assert_eq!(risultati.len(), 1);
        assert_eq!(
            risultati[0]
                .public_address
                .as_ref()
                .map(PublicAddress::as_str),
            Some("canale_uno")
        );
    }

    /// **Una decisione che aggiunge una fonte si scrive tutta insieme.**
    ///
    /// Una fonte senza la decisione che l'ha creata e' una fonte comparsa dal
    /// nulla; una decisione che dichiara una fonte inesistente e' una bugia.
    #[test]
    fn aggiungere_scrive_la_decisione_e_la_fonte_insieme() {
        let mut database = database();
        let run_id = scoperta_con_un_candidato(&mut database);
        let Ok(risultati) = database.discovery_results(run_id) else {
            panic!("i risultati devono potersi rileggere");
        };
        let result_id = risultati[0].id;
        let fonte = fonte_di_prova();

        let Ok(Some(source_id)) = database.record_candidate_decision(&NewCandidateDecision {
            result_id,
            decision: CandidateDecision::Added,
            actor: "operatore.prova",
            reason: "canale pubblico gia' raggiungibile dall'account d'ufficio",
            decided_at: Timestamp::from_millis(10),
            source: Some(&fonte),
        }) else {
            panic!("la decisione deve potersi registrare insieme alla fonte");
        };

        assert!(
            database.source(source_id).is_ok(),
            "la fonte dichiarata dalla decisione esiste davvero"
        );

        let Ok(decisioni) = database.candidate_decisions(run_id) else {
            panic!("le decisioni devono potersi rileggere");
        };
        assert_eq!(decisioni.len(), 1);
        assert_eq!(decisioni[0].decision, CandidateDecision::Added);
        assert_eq!(decisioni[0].source_id, Some(source_id.get()));
        assert_eq!(decisioni[0].actor, "operatore.prova");
    }

    /// **Ignorare non cancella, e non fa nascere niente.**
    ///
    /// Se cancellasse, si perderebbe il fatto che qualcuno ha guardato e ha
    /// detto di no - e la stessa chat tornerebbe come se fosse nuova.
    #[test]
    fn ignorare_non_cancella_e_non_fa_nascere_una_fonte() {
        let mut database = database();
        let run_id = scoperta_con_un_candidato(&mut database);
        let Ok(risultati) = database.discovery_results(run_id) else {
            panic!("i risultati devono potersi rileggere");
        };
        let result_id = risultati[0].id;

        let Ok(nessuna_fonte) = database.record_candidate_decision(&NewCandidateDecision {
            result_id,
            decision: CandidateDecision::Ignored,
            actor: "operatore.prova",
            reason: "fuori ambito per questo monitoraggio",
            decided_at: Timestamp::from_millis(10),
            source: None,
        }) else {
            panic!("la decisione deve potersi registrare");
        };
        assert_eq!(nessuna_fonte, None);

        let Ok(dopo) = database.discovery_results(run_id) else {
            panic!("i risultati devono restare");
        };
        assert_eq!(dopo.len(), 1, "ignorare non cancella il candidato");
        assert_eq!(database.sources().map(|f| f.len()).ok(), Some(0));
    }

    /// **Cambiare idea aggiunge una decisione: non ne riscrive una.**
    #[test]
    fn cambiare_idea_lascia_vere_entrambe_le_decisioni() {
        let mut database = database();
        let run_id = scoperta_con_un_candidato(&mut database);
        let Ok(risultati) = database.discovery_results(run_id) else {
            panic!("i risultati devono potersi rileggere");
        };
        let result_id = risultati[0].id;

        let Ok(_) = database.record_candidate_decision(&NewCandidateDecision {
            result_id,
            decision: CandidateDecision::Ignored,
            actor: "operatore.prova",
            reason: "fuori ambito oggi",
            decided_at: Timestamp::from_millis(10),
            source: None,
        }) else {
            panic!("la prima decisione deve potersi registrare");
        };

        let fonte = fonte_di_prova();
        let Ok(_) = database.record_candidate_decision(&NewCandidateDecision {
            result_id,
            decision: CandidateDecision::Added,
            actor: "operatore.prova",
            reason: "diventato pertinente per un'indagine aperta",
            decided_at: Timestamp::from_millis(20),
            source: Some(&fonte),
        }) else {
            panic!("la seconda decisione deve potersi registrare");
        };

        let Ok(decisioni) = database.candidate_decisions(run_id) else {
            panic!("le decisioni devono potersi rileggere");
        };
        assert_eq!(decisioni.len(), 2, "restano vere entrambe");
        assert_eq!(decisioni[0].decision, CandidateDecision::Ignored);
        assert_eq!(decisioni[1].decision, CandidateDecision::Added);
    }

    /// **Una decisione presa non si modifica e non si cancella.**
    #[test]
    fn una_decisione_presa_non_si_riscrive() {
        let mut database = database();
        let run_id = scoperta_con_un_candidato(&mut database);
        let Ok(risultati) = database.discovery_results(run_id) else {
            panic!("i risultati devono potersi rileggere");
        };

        let Ok(_) = database.record_candidate_decision(&NewCandidateDecision {
            result_id: risultati[0].id,
            decision: CandidateDecision::Opened,
            actor: "operatore.prova",
            reason: "guardato per capire di che cosa si tratta",
            decided_at: Timestamp::from_millis(10),
            source: None,
        }) else {
            panic!("la decisione deve potersi registrare");
        };

        assert!(
            database
                .connection
                .execute("UPDATE discovery_decisions SET reason = 'altro'", [])
                .is_err(),
            "una decisione presa non si modifica: si decide di nuovo"
        );
        assert!(
            database
                .connection
                .execute("DELETE FROM discovery_decisions", [])
                .is_err(),
            "una decisione presa non si cancella"
        );
    }

    /// **Un motivo vuoto non entra**, e il vincolo sta nello schema.
    ///
    /// Un motivo per candidato e' la difesa piu' semplice contro il gesto: non
    /// si scrive un motivo dieci volte per distrazione.
    #[test]
    fn una_decisione_senza_motivo_non_entra() {
        let mut database = database();
        let run_id = scoperta_con_un_candidato(&mut database);
        let Ok(risultati) = database.discovery_results(run_id) else {
            panic!("i risultati devono potersi rileggere");
        };

        assert!(
            database
                .record_candidate_decision(&NewCandidateDecision {
                    result_id: risultati[0].id,
                    decision: CandidateDecision::Ignored,
                    actor: "operatore.prova",
                    reason: "   ",
                    decided_at: Timestamp::from_millis(10),
                    source: None,
                })
                .is_err(),
            "una decisione senza motivo non e' una decisione"
        );
    }

    /// **Una scoperta si rilegge per intero, misura compresa.**
    ///
    /// Un numero senza provenienza non si distingue da uno inventato, e sei mesi
    /// dopo la data della misura e' cio' che dice se quella scoperta valga
    /// ancora qualcosa.
    #[test]
    fn una_scoperta_si_rilegge_con_la_misura_su_cui_poggiava() {
        let mut database = database();
        let poste = domande(&["ransomware"]);

        let Ok(_) = database.record_discovery_run(&NewDiscoveryRun {
            started_at: 1_700_000_000_000,
            scope: SearchScope::PublicChannelPosts,
            budget: budget(),
            limits_free_per_day: 100,
            limits_remaining_free: 98,
            limits_observed_at: 1_699_000_000_000,
            limits_origin: "misura dal vivo del 2026-09-13",
            queries: &poste,
            omissions: &[],
            results: &[],
        }) else {
            panic!("la scoperta di prova deve potersi registrare");
        };

        let Ok(scoperte) = database.discovery_runs() else {
            panic!("le scoperte devono potersi rileggere");
        };
        assert_eq!(scoperte.len(), 1);
        let scoperta = &scoperte[0];
        assert_eq!(scoperta.scope, SearchScope::PublicChannelPosts);
        assert_eq!(scoperta.budget, budget());
        assert_eq!(scoperta.limits_free_per_day, 100);
        assert_eq!(scoperta.limits_remaining_free, 98);
        assert_eq!(scoperta.limits_observed_at, 1_699_000_000_000);
        assert_eq!(scoperta.limits_origin, "misura dal vivo del 2026-09-13");
    }

    /// **La piu' recente sta davanti.**
    ///
    /// Chi apre la schermata cerca l'ultima, non la prima: un elenco in ordine
    /// di scrittura la seppellirebbe sotto tutte le altre.
    #[test]
    fn le_scoperte_si_rileggono_dalla_piu_recente() {
        let mut database = database();
        let poste = domande(&["uno"]);

        for istante in [10_i64, 30, 20] {
            let Ok(_) = database.record_discovery_run(&NewDiscoveryRun {
                started_at: istante,
                scope: SearchScope::AccountChats,
                budget: budget(),
                limits_free_per_day: 100,
                limits_remaining_free: 100,
                limits_observed_at: 1,
                limits_origin: "una misura con un nome",
                queries: &poste,
                omissions: &[],
                results: &[],
            }) else {
                panic!("la scoperta di prova deve potersi registrare");
            };
        }

        let Ok(scoperte) = database.discovery_runs() else {
            panic!("le scoperte devono potersi rileggere");
        };
        let istanti: Vec<i64> = scoperte.iter().map(|run| run.started_at).collect();
        assert_eq!(istanti, vec![30, 20, 10]);
    }

    /// **Un risultato torna indietro con i propri motivi, e uno senza torna
    /// senza.**
    ///
    /// Motivi = candidato; nessun motivo = solo un risultato. L'elenco vuoto e'
    /// il fatto, non un dato mancante.
    #[test]
    fn i_motivi_tornano_con_il_risultato_a_cui_appartengono() {
        let mut database = database();
        let poste = domande(&["ransomware"]);
        let motivi = vec![
            String::from("18 riscontri Cyber Core"),
            String::from("4 CVE in comune"),
        ];

        let Ok(run_id) = database.record_discovery_run(&NewDiscoveryRun {
            started_at: 1,
            scope: SearchScope::Extended,
            budget: budget(),
            limits_free_per_day: 100,
            limits_remaining_free: 100,
            limits_observed_at: 1,
            limits_origin: "una misura con un nome",
            queries: &poste,
            omissions: &[],
            results: &[
                NewDiscoveryResult {
                    query: "ransomware",
                    scope: SearchScope::PublicChannelPosts,
                    public_name: "Canale con motivi",
                    public_address: None,
                    reasons: &motivi,
                },
                NewDiscoveryResult {
                    query: "ransomware",
                    scope: SearchScope::AccountChats,
                    public_name: "Chat senza motivi",
                    public_address: None,
                    reasons: &[],
                },
            ],
        }) else {
            panic!("la scoperta di prova deve potersi registrare");
        };

        let Ok(risultati) = database.discovery_results(run_id) else {
            panic!("i risultati devono potersi rileggere");
        };
        assert_eq!(risultati.len(), 2);

        let Some(con_motivi) = risultati
            .iter()
            .find(|risultato| risultato.public_name == "Canale con motivi")
        else {
            panic!("il risultato con motivi deve tornare indietro");
        };
        assert_eq!(con_motivi.reasons, motivi);
        assert_eq!(
            con_motivi.scope,
            SearchScope::PublicChannelPosts,
            "l'ambito e' del risultato, non dell'esecuzione"
        );

        let Some(senza_motivi) = risultati
            .iter()
            .find(|risultato| risultato.public_name == "Chat senza motivi")
        else {
            panic!("anche il risultato senza motivi deve tornare indietro");
        };
        assert!(
            senza_motivi.reasons.is_empty(),
            "nessun motivo significa: e' solo un risultato, non un candidato"
        );
    }

    /// **Cio' che non e' stato chiesto si rilegge insieme a cio' che e' stato
    /// chiesto.**
    ///
    /// Se l'archivio conservasse solo le domande poste, ogni «non cercato»
    /// diventerebbe un «non trovato» nel momento esatto in cui qualcuno rilegge.
    #[test]
    fn cio_che_non_e_stato_chiesto_si_rilegge() {
        let mut database = database();
        let poste = domande(&["ransomware", "phishing"]);
        let omesse = vec![
            (String::from("   "), Omission::NotAQuery),
            (String::from("RANSOMWARE"), Omission::AlreadyAsked),
            (String::from("cve-2026-1"), Omission::BudgetSpent),
        ];

        let Ok(run_id) = database.record_discovery_run(&NewDiscoveryRun {
            started_at: 1_700_000_000_000,
            scope: SearchScope::PublicChannelPosts,
            budget: budget(),
            limits_free_per_day: 100,
            limits_remaining_free: 98,
            limits_observed_at: 1_699_000_000_000,
            limits_origin: "misura dal vivo del 2026-09-13",
            queries: &poste,
            omissions: &omesse,
            results: &[],
        }) else {
            panic!("la scoperta di prova deve potersi registrare");
        };

        assert_eq!(
            database.discovery_queries(run_id).ok(),
            Some(vec![String::from("ransomware"), String::from("phishing")])
        );

        let Ok(omissioni) = database.discovery_omissions(run_id) else {
            panic!("le omissioni devono potersi rileggere");
        };
        assert_eq!(omissioni.len(), 3);
        assert_eq!(omissioni[2].0, "cve-2026-1");
        assert_eq!(omissioni[2].1, "tetto_esaurito");
    }

    /// **La misura su cui la scoperta poggiava resta con la scoperta.**
    ///
    /// Una scoperta senza la misura e' una scoperta di cui, fra sei mesi, non si
    /// puo' dire niente - e i limiti cambiano, che e' l'unica cosa certa di un
    /// servizio di qualcun altro.
    #[test]
    fn la_misura_resta_con_la_scoperta() {
        let mut database = database();
        let poste = domande(&["uno"]);

        let Ok(run_id) = database.record_discovery_run(&NewDiscoveryRun {
            started_at: 1,
            scope: SearchScope::AccountChats,
            budget: budget(),
            limits_free_per_day: 100,
            limits_remaining_free: 100,
            limits_observed_at: 2,
            limits_origin: "una misura con un nome",
            queries: &poste,
            omissions: &[],
            results: &[],
        }) else {
            panic!("la scoperta di prova deve potersi registrare");
        };

        assert_eq!(
            database.discovery_limits_origin(run_id).ok().as_deref(),
            Some("una misura con un nome")
        );
    }

    /// **Una misura senza origine non entra**, e il vincolo sta nello schema.
    ///
    /// Un numero senza provenienza non si distingue da uno inventato: il dominio
    /// lo vieta, e l'archivio non si fida del dominio.
    #[test]
    fn una_scoperta_senza_origine_della_misura_non_entra() {
        let mut database = database();
        let poste = domande(&["uno"]);

        assert!(
            database
                .record_discovery_run(&NewDiscoveryRun {
                    started_at: 1,
                    scope: SearchScope::AccountChats,
                    budget: budget(),
                    limits_free_per_day: 100,
                    limits_remaining_free: 100,
                    limits_observed_at: 2,
                    limits_origin: "   ",
                    queries: &poste,
                    omissions: &[],
                    results: &[],
                })
                .is_err(),
            "una misura senza origine non deve poter entrare in archivio"
        );
    }

    /// **Un risultato con dei motivi e' un candidato; uno senza e' un risultato.**
    #[test]
    fn i_motivi_distinguono_un_candidato_da_un_risultato() {
        let mut database = database();
        let poste = domande(&["ransomware"]);
        let motivi = vec![String::from("18 riscontri Cyber Core")];
        let risultati = vec![
            NewDiscoveryResult {
                query: "ransomware",
                scope: SearchScope::PublicChannelPosts,
                public_name: "un canale suggerito",
                public_address: None,
                reasons: &motivi,
            },
            NewDiscoveryResult {
                query: "ransomware",
                scope: SearchScope::PublicChannelPosts,
                public_name: "un canale qualunque",
                public_address: None,
                reasons: &[],
            },
        ];

        let Ok(run_id) = database.record_discovery_run(&NewDiscoveryRun {
            started_at: 1,
            scope: SearchScope::PublicChannelPosts,
            budget: budget(),
            limits_free_per_day: 100,
            limits_remaining_free: 100,
            limits_observed_at: 2,
            limits_origin: "misura",
            queries: &poste,
            omissions: &[],
            results: &risultati,
        }) else {
            panic!("la scoperta di prova deve potersi registrare");
        };

        let Ok(con_motivi) = database.connection.query_row(
            "SELECT COUNT(*) FROM discovery_result_reasons r
             JOIN discovery_results s ON s.id = r.result_id
             WHERE s.run_id = ?1",
            [run_id],
            |row| row.get::<_, i64>(0),
        ) else {
            panic!("il conteggio deve potersi leggere");
        };
        assert_eq!(con_motivi, 1, "solo il candidato porta un motivo");
    }

    /// **Una scoperta e' un fatto avvenuto, e non si riscrive.**
    #[test]
    fn una_scoperta_registrata_non_si_modifica_ne_si_cancella() {
        let mut database = database();
        let poste = domande(&["uno"]);

        let Ok(run_id) = database.record_discovery_run(&NewDiscoveryRun {
            started_at: 1,
            scope: SearchScope::SelectedSources,
            budget: budget(),
            limits_free_per_day: 100,
            limits_remaining_free: 100,
            limits_observed_at: 2,
            limits_origin: "misura",
            queries: &poste,
            omissions: &[(String::from("due"), Omission::BudgetSpent)],
            results: &[],
        }) else {
            panic!("la scoperta di prova deve potersi registrare");
        };

        assert!(
            database
                .connection
                .execute(
                    "UPDATE discovery_runs SET scope = 'esteso' WHERE id = ?1",
                    [run_id]
                )
                .is_err(),
            "una scoperta registrata non deve potersi modificare"
        );
        assert!(
            database
                .connection
                .execute("DELETE FROM discovery_runs WHERE id = ?1", [run_id])
                .is_err(),
            "una scoperta registrata non deve potersi cancellare"
        );
        assert!(
            database
                .connection
                .execute(
                    "DELETE FROM discovery_omissions WHERE run_id = ?1",
                    [run_id]
                )
                .is_err(),
            "cio' che non e' stato chiesto non deve potersi cancellare: e' la \
             parte che qualcuno sarebbe tentato di togliere perche' sembra rumore"
        );
    }

    /// **O tutta, o niente.**
    ///
    /// Una scoperta registrata a meta' dichiara meno di quanto ha chiesto, e chi
    /// la rilegge non sa che ne mancano.
    #[test]
    fn una_scoperta_che_non_si_scrive_per_intero_non_lascia_niente() {
        let mut database = database();
        let poste = domande(&["uno", "due"]);

        // Un ambito inventato fa fallire l'inserimento dell'ESECUZIONE: nulla
        // deve restare scritto, nemmeno le domande.
        let esito = database.record_discovery_run(&NewDiscoveryRun {
            started_at: 1,
            scope: SearchScope::SelectedSources,
            budget: DiscoveryBudget {
                distinct_queries: 0,
                ..budget()
            },
            limits_free_per_day: 100,
            limits_remaining_free: 100,
            limits_observed_at: 2,
            limits_origin: "misura",
            queries: &poste,
            omissions: &[],
            results: &[],
        });
        assert!(esito.is_err(), "un tetto di zero domande non deve entrare");

        let Ok(quante) =
            database
                .connection
                .query_row("SELECT COUNT(*) FROM discovery_queries", [], |row| {
                    row.get::<_, i64>(0)
                })
        else {
            panic!("il conteggio deve potersi leggere");
        };
        assert_eq!(
            quante, 0,
            "una scoperta che non si e' scritta per intero non deve lasciare \
             domande orfane"
        );
    }
}

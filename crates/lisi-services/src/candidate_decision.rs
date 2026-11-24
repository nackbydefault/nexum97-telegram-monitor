//! Che cosa una persona decide di un candidato: aprirlo, aggiungerlo, ignorarlo.
//!
//! # La regola che governa questo modulo
//!
//! **«Legittimamente accessibile» lo dice una persona.**
//!
//! Il piano chiede «Aggiungi *se legittimamente accessibile*». Il prodotto non
//! può verificarlo: per saperlo dovrebbe **provare ad accedervi**, e provare è
//! esattamente la cosa che non fa — nessun ingresso in gruppi, nessuna richiesta
//! di adesione, nessuna partecipazione.
//!
//! Quindi non lo verifica: lo fa **dichiarare**, con un motivo, e la
//! dichiarazione porta il nome di chi l'ha firmata. È la stessa regola per cui
//! una fonte ha da sempre un `authorized_by` (ADR-0080).
//!
//! # Perché questo servizio è separato da quello che rilegge
//!
//! PD-UI-01 ha costruito un servizio di **sola lettura**, con una guardia che
//! verifica che non scriva. Qui si scrive: audit, decisione, e — per
//! «Aggiungi» — una fonte nuova. Aggiungere la scrittura dove c'era la lettura
//! avrebbe reso quella guardia falsa senza che nessuna prova lo dicesse.
//!
//! # Che cosa questo servizio NON fa
//!
//! Decidere. Ogni metodo pretende **chi** decide e **perché**, e non esiste un
//! metodo che agisca su più di un candidato per volta: una decisione presa su
//! dieci cose insieme non è dieci decisioni, è **un gesto** — e il gesto è ciò
//! che «mai adesione automatica» vieta.

use lisi_core::model::NewAuditEntry;
use lisi_core::model::discovery::{CandidateDecision, PublicAddress};
use lisi_core::model::source::{NewSource, SourceKind};
use lisi_core::text::{
    Actor, AuditAction, AuditDetail, AuditEntity, DisplayName, SourceIdentifier,
};
use lisi_core::{SourceId, Timestamp};
use lisi_storage::Database;
use lisi_storage::repository::discovery::NewCandidateDecision;

use crate::error::{ServiceError, ServiceResult};

/// Che cosa dire a chi sta per aggiungere una fonte.
///
/// **Non è una formalità.** Chi firma si assume la responsabilità di una cosa
/// che il prodotto non può verificare, e deve saperlo prima di firmare.
pub const COSA_SI_DICHIARA_AGGIUNGENDO: &str = "Aggiungendo questa chat dichiari che è legittimamente accessibile \
     all'account d'ufficio e che il monitoraggio è autorizzato. Il programma non \
     può verificarlo: per saperlo dovrebbe provare ad accedervi, e non lo fa mai. \
     La dichiarazione resta in archivio con il tuo nome, il motivo e l'istante.";

/// Che cosa succede ignorando.
pub const COSA_SUCCEDE_IGNORANDO: &str = "Ignorare non cancella nulla: registra che qualcuno ha guardato e ha detto \
     di no, con il motivo. Serve perché la stessa chat, in una ricerca futura, \
     non torni come se non fosse mai stata esaminata.";

/// L'esito di una decisione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionOutcome {
    /// Che cosa è stato deciso.
    pub decision: CandidateDecision,
    /// La fonte nata dalla decisione, quando ne è nata una.
    pub source: Option<SourceId>,
    /// L'indirizzo da aprire, quando la decisione è «apri».
    ///
    /// Il servizio **non apre**: restituisce l'indirizzo, e l'apertura passa da
    /// dove passano tutte le aperture di questo prodotto (ADR-0018).
    pub open: Option<String>,
}

/// Registra le decisioni prese sui candidati.
pub struct CandidateDecisionService {
    database: Database,
}

impl CandidateDecisionService {
    /// Crea il servizio attorno al database indicato.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Database sottostante, per i test e la diagnostica.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Database sottostante in scrittura, per la preparazione dei test.
    #[must_use]
    pub const fn database_mut(&mut self) -> &mut Database {
        &mut self.database
    }

    /// Restituisce il database, per riusarlo altrove.
    #[must_use]
    pub fn into_database(self) -> Database {
        self.database
    }

    /// Registra che un candidato è stato aperto per guardarlo.
    ///
    /// **Aprire non aggiunge.** Restituisce l'indirizzo da aprire; aprirlo è di
    /// chi ha una porta verso il sistema, e passa dalla validazione di ADR-0018.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::CandidateWithoutAddress`] se il candidato non
    /// ha un indirizzo pubblico, e un errore se la scrittura non riesce.
    pub fn open(
        &mut self,
        result_id: i64,
        reason: &str,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<DecisionOutcome> {
        let indirizzo = self.indirizzo_di(result_id)?;
        self.registra(
            result_id,
            CandidateDecision::Opened,
            reason,
            actor,
            now,
            None,
        )?;
        Ok(DecisionOutcome {
            decision: CandidateDecision::Opened,
            source: None,
            open: Some(indirizzo.public_url()),
        })
    }

    /// Registra che qualcuno ha guardato il candidato e ha detto di no.
    ///
    /// **Non cancella niente.**
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn ignore(
        &mut self,
        result_id: i64,
        reason: &str,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<DecisionOutcome> {
        self.registra(
            result_id,
            CandidateDecision::Ignored,
            reason,
            actor,
            now,
            None,
        )?;
        Ok(DecisionOutcome {
            decision: CandidateDecision::Ignored,
            source: None,
            open: None,
        })
    }

    /// Aggiunge il candidato come fonte, sotto la responsabilità di chi lo fa.
    ///
    /// La fonte nasce **inattiva**: aggiungerla è dichiararla accessibile, non
    /// metterla subito sotto sorveglianza. Chi la vuole in una sessione la
    /// sceglie, e quello è un altro gesto con un altro significato.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::CandidateWithoutAddress`] se il candidato non
    /// ha un indirizzo pubblico, un errore di dominio se il nome non è valido, e
    /// un errore se la scrittura non riesce. **Nulla resta scritto** se la
    /// transazione non va a buon fine: né la decisione né la fonte.
    pub fn add_as_source(
        &mut self,
        result_id: i64,
        reason: &str,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<DecisionOutcome> {
        let indirizzo = self.indirizzo_di(result_id)?;
        let nome = self.nome_di(result_id)?;

        let identifier = SourceIdentifier::try_new(indirizzo.as_str())?;
        let display_name = DisplayName::try_new(&nome)?;
        let fonte = NewSource {
            kind: SourceKind::Channel,
            identifier,
            display_name,
            // CHI FIRMA E' CHI DECIDE. Non c'e' un valore predefinito e non c'e'
            // un attore di sistema: una fonte che nasce da un suggerimento nasce
            // con la stessa firma di tutte le altre (ADR-0080).
            authorized_by: actor.clone(),
            active: false,
        };

        let source = self.registra(
            result_id,
            CandidateDecision::Added,
            reason,
            actor,
            now,
            Some(&fonte),
        )?;

        Ok(DecisionOutcome {
            decision: CandidateDecision::Added,
            source,
            open: None,
        })
    }

    /// Le decisioni prese sui risultati di una scoperta.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn decisions(
        &self,
        run_id: i64,
    ) -> ServiceResult<Vec<lisi_storage::repository::discovery::RecordedCandidateDecision>> {
        Ok(self.database.candidate_decisions(run_id)?)
    }

    /// Scrive la decisione, l'eventuale fonte e la riga d'audit.
    ///
    /// L'audit si scrive **dopo** la decisione: se la decisione non entra, non
    /// c'è niente da verbalizzare.
    fn registra(
        &mut self,
        result_id: i64,
        decision: CandidateDecision,
        reason: &str,
        actor: &Actor,
        now: Timestamp,
        source: Option<&NewSource>,
    ) -> ServiceResult<Option<SourceId>> {
        if reason.trim().is_empty() {
            return Err(ServiceError::CandidateDecisionWithoutReason);
        }

        let nata = self
            .database
            .record_candidate_decision(&NewCandidateDecision {
                result_id,
                decision,
                actor: actor.as_str(),
                reason,
                decided_at: now,
                source,
            })?;

        let dettaglio = AuditDetail::try_new(&format!(
            "candidato {result_id}: {} — {reason}",
            decision.as_str()
        ))?;
        let _ = self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("decisione_candidato")?,
            entity: AuditEntity::try_new("scoperta_pubblica")?,
            entity_id: Some(result_id),
            actor_mode: None,
            detail: Some(dettaglio),
            recorded_at: now,
        })?;

        Ok(nata)
    }

    /// L'indirizzo pubblico di un risultato, o il rifiuto che ne segue.
    fn indirizzo_di(&self, result_id: i64) -> ServiceResult<PublicAddress> {
        let Some(risultato) = self.risultato(result_id)? else {
            return Err(ServiceError::CandidateNotFound);
        };
        risultato
            .public_address
            .ok_or(ServiceError::CandidateWithoutAddress)
    }

    /// Il nome pubblico di un risultato.
    fn nome_di(&self, result_id: i64) -> ServiceResult<String> {
        let Some(risultato) = self.risultato(result_id)? else {
            return Err(ServiceError::CandidateNotFound);
        };
        Ok(risultato.public_name)
    }

    /// Il risultato, cercato fra le scoperte registrate.
    fn risultato(
        &self,
        result_id: i64,
    ) -> ServiceResult<Option<lisi_storage::repository::discovery::RecordedDiscoveryResult>> {
        for scoperta in self.database.discovery_runs()? {
            if let Some(trovato) = self
                .database
                .discovery_results(scoperta.id)?
                .into_iter()
                .find(|risultato| risultato.id == result_id)
            {
                return Ok(Some(trovato));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::discovery::{CandidateDecision, PublicAddress, SearchScope};
    use lisi_core::model::discovery_plan::DiscoveryBudget;
    use lisi_core::text::Actor;
    use lisi_storage::repository::discovery::{NewDiscoveryResult, NewDiscoveryRun};

    use super::{COSA_SI_DICHIARA_AGGIUNGENDO, CandidateDecisionService};
    use crate::error::ServiceError;
    use crate::sources::open_in_memory_database;

    fn operatore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova e' valido");
        };
        attore
    }

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    /// Un servizio con una scoperta che porta due risultati: uno con indirizzo
    /// pubblico, uno senza.
    fn servizio() -> (CandidateDecisionService, i64, i64) {
        let Ok(mut archivio) = open_in_memory_database() else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        let Some(domanda) = lisi_core::model::discovery::DiscoveryQuery::try_new("ransomware")
        else {
            panic!("l'interrogazione di prova non e' vuota");
        };
        let Some(indirizzo) = PublicAddress::try_new("canale_uno") else {
            panic!("l'indirizzo di prova e' valido");
        };
        let motivi = vec![String::from("18 riscontri Cyber Core")];

        let Ok(run_id) = archivio.record_discovery_run(&NewDiscoveryRun {
            started_at: 1,
            scope: SearchScope::PublicChannelPosts,
            budget: DiscoveryBudget {
                distinct_queries: 5,
                results_per_query: 20,
                our_page_cap: 5,
                our_wait_seconds: 30,
                our_consecutive_errors: 3,
                declared_backoff_seconds: 0,
            },
            limits_free_per_day: 100,
            limits_remaining_free: 100,
            limits_observed_at: 1,
            limits_origin: "una misura con un nome",
            queries: &[domanda],
            omissions: &[],
            results: &[
                NewDiscoveryResult {
                    query: "ransomware",
                    scope: SearchScope::PublicChannelPosts,
                    public_name: "Canale Uno",
                    public_address: Some(&indirizzo),
                    reasons: &motivi,
                },
                NewDiscoveryResult {
                    query: "ransomware",
                    scope: SearchScope::PublicChannelPosts,
                    public_name: "Senza indirizzo",
                    public_address: None,
                    reasons: &motivi,
                },
            ],
        }) else {
            panic!("la scoperta di prova deve potersi registrare");
        };

        let Ok(risultati) = archivio.discovery_results(run_id) else {
            panic!("i risultati devono potersi rileggere");
        };
        let con_indirizzo = risultati[0].id;
        let senza_indirizzo = risultati[1].id;

        (
            CandidateDecisionService::new(archivio),
            con_indirizzo,
            senza_indirizzo,
        )
    }

    /// **Aprire non aggiunge.**
    ///
    /// Aprire e' guardare, aggiungere e' cominciare a sorvegliare: confonderle
    /// e' il modo in cui un candidato diventa una fonte per sbaglio.
    #[test]
    fn aprire_non_aggiunge() {
        let (mut servizio, result_id, _) = servizio();

        let Ok(esito) = servizio.open(
            result_id,
            "guardato per capire che cos'e'",
            &operatore(),
            now(),
        ) else {
            panic!("l'apertura deve potersi registrare");
        };

        assert_eq!(esito.decision, CandidateDecision::Opened);
        assert_eq!(esito.source, None, "aprire non fa nascere una fonte");
        assert_eq!(esito.open.as_deref(), Some("https://t.me/canale_uno"));
        assert_eq!(
            servizio.database().sources().map(|f| f.len()).ok(),
            Some(0),
            "nessuna fonte nasce guardando"
        );
    }

    /// **Aggiungere firma una dichiarazione, e la fonte nasce inattiva.**
    ///
    /// Dichiararla accessibile non e' metterla subito sotto sorveglianza.
    #[test]
    fn aggiungere_fa_nascere_una_fonte_firmata_e_inattiva() {
        let (mut servizio, result_id, _) = servizio();

        let Ok(esito) = servizio.add_as_source(
            result_id,
            "canale pubblico gia' raggiungibile dall'account d'ufficio",
            &operatore(),
            now(),
        ) else {
            panic!("l'aggiunta deve potersi registrare");
        };

        let Some(source_id) = esito.source else {
            panic!("aggiungere fa nascere una fonte");
        };
        let Ok(fonte) = servizio.database().source(source_id) else {
            panic!("la fonte dichiarata esiste");
        };
        assert_eq!(fonte.authorized_by.as_str(), "operatore.prova");
        assert!(!fonte.active, "una fonte aggiunta nasce inattiva");
        assert_eq!(fonte.identifier.as_str(), "canale_uno");
    }

    /// **Senza indirizzo non c'e' niente da aprire e niente da sorvegliare.**
    #[test]
    fn un_candidato_senza_indirizzo_non_si_apre_e_non_si_aggiunge() {
        let (mut servizio, _, senza) = servizio();

        assert!(matches!(
            servizio.open(senza, "motivo", &operatore(), now()),
            Err(ServiceError::CandidateWithoutAddress)
        ));
        assert!(matches!(
            servizio.add_as_source(senza, "motivo", &operatore(), now()),
            Err(ServiceError::CandidateWithoutAddress)
        ));
    }

    /// **Nessuna decisione senza motivo.**
    ///
    /// Un motivo per candidato e' la difesa piu' semplice contro il gesto: non
    /// si scrive un motivo dieci volte per distrazione.
    #[test]
    fn nessuna_decisione_si_prende_senza_un_motivo() {
        let (mut servizio, result_id, _) = servizio();

        for esito in [
            servizio.open(result_id, "   ", &operatore(), now()),
            servizio.ignore(result_id, "", &operatore(), now()),
            servizio.add_as_source(result_id, "  \t ", &operatore(), now()),
        ] {
            assert!(matches!(
                esito,
                Err(ServiceError::CandidateDecisionWithoutReason)
            ));
        }
    }

    /// **Ignorare registra un no, e non cancella niente.**
    #[test]
    fn ignorare_registra_un_no_e_non_cancella() {
        let (mut servizio, result_id, _) = servizio();

        let Ok(esito) = servizio.ignore(result_id, "fuori ambito", &operatore(), now()) else {
            panic!("ignorare deve potersi registrare");
        };
        assert_eq!(esito.decision, CandidateDecision::Ignored);
        assert_eq!(esito.source, None);

        let Ok(scoperte) = servizio.database().discovery_runs() else {
            panic!("le scoperte devono restare");
        };
        let Ok(risultati) = servizio.database().discovery_results(scoperte[0].id) else {
            panic!("i risultati devono restare");
        };
        assert_eq!(risultati.len(), 2, "ignorare non toglie niente");
    }

    /// **Che cosa si dichiara aggiungendo si dice prima, non dopo.**
    #[test]
    fn cio_che_si_dichiara_aggiungendo_e_scritto() {
        assert!(COSA_SI_DICHIARA_AGGIUNGENDO.contains("legittimamente accessibile"));
        assert!(
            COSA_SI_DICHIARA_AGGIUNGENDO.contains("non può verificarlo"),
            "chi firma deve sapere che il programma non lo verifica"
        );
        assert!(COSA_SI_DICHIARA_AGGIUNGENDO.contains("con il tuo nome"));
    }

    /// **Non esiste un modo di decidere su piu' di un candidato per volta.**
    ///
    /// Una decisione presa su dieci cose insieme non e' dieci decisioni: e' un
    /// gesto, ed e' cio' che «mai adesione automatica» vieta.
    #[test]
    fn non_esiste_una_decisione_cumulativa() {
        const QUESTO_MODULO: &str = include_str!("candidate_decision.rs");

        let Some((produzione, _)) = QUESTO_MODULO.split_once("\n#[cfg(test)]\nmod tests {") else {
            panic!("il blocco delle prove non si delimita");
        };
        let codice: String = produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<&str>>()
            .join("\n");

        for vietato in ["result_ids", "&[i64]", "Vec<i64>", "add_all", "ignore_all"] {
            assert!(
                !codice.contains(vietato),
                "«{vietato}»: una decisione su molti candidati e' un gesto, non \
                 dieci decisioni (ADR-0080)"
            );
        }
    }
}

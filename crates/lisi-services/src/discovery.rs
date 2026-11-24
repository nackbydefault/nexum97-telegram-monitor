//! Che cosa una scoperta pubblica ha chiesto, che cosa **non** ha chiesto, e su
//! quale misura poggiava.
//!
//! # La regola che governa questo modulo
//!
//! **Conservare e non mostrare è come non conservare.**
//!
//! PD-STORAGE-01 scrive le omissioni con il loro motivo perché la dichiarazione
//! del pianificatore non muoia con la schermata. Se poi nessuno le rileggesse,
//! il silenzio tornerebbe al suo posto: l'archivio le ha, nessuno le vede, e chi
//! rilegge conclude «non trovato» di termini che nessuno ha cercato.
//!
//! Questo servizio compone la scoperta **intera**: le domande poste **e** quelle
//! omesse con il motivo, la misura su cui poggiava, e i candidati nell'ordine di
//! PD-RANK-01 con la frase che dice perché sono in quell'ordine.
//!
//! # Consultare non scrive
//!
//! Non ha metodi di scrittura, non registra nulla nell'audit, non tocca niente.
//! Vale la ragione di ADR-0051 decisione 5: l'audit documenta le **azioni**, e
//! rileggere una scoperta non è un'azione di cui qualcuno risponda.
//!
//! # Che cosa questo servizio NON fa
//!
//! Eseguire una scoperta. Non può: serve una politica validata, che si ottiene
//! solo da limiti osservati, che nessuno ha ancora misurato (ADR-0074, HVQ-03).
//!
//! La decisione completa sta in
//! `docs/adr/ADR-0079-CONSERVARE-E-NON-MOSTRARE-E-COME-NON-CONSERVARE.md`.

use lisi_core::Timestamp;
use lisi_core::model::discovery::{
    CandidateReason, DiscoveryQuery, DiscoveryResult, SearchScope, SourceCandidate,
};
use lisi_core::model::discovery_plan::Omission;
use lisi_core::model::discovery_rank::{Placement, RankedCandidate, rank_with};
use lisi_storage::Database;
use lisi_storage::repository::discovery::{RecordedDiscoveryResult, RecordedDiscoveryRun};

use crate::error::ServiceResult;

/// Perché da questa schermata non si cerca.
///
/// Non è un divieto: è un'impossibilità, e si dichiara invece di tacerla — la
/// stessa forma con cui il canale degli aggiornamenti dichiara di essere senza
/// effetto finché manca il certificato (ADR-0066).
pub const PERCHE_NON_SI_CERCA: &str = "Da questa schermata non si avvia una ricerca, e non è una scelta \
     prudenziale. Una ricerca pubblica richiede una politica validata. Una politica \
     si convalida solo davanti ai limiti che Telegram dichiara davvero. Quei limiti \
     non sono ancora stati misurati su un account reale, quindi nessuna politica \
     validata può esistere. Non c'è un comando da premere, perché non ci sarebbe \
     niente da eseguire. Un comando che non fa ciò che dice è una promessa.";

/// Che cosa dire quando nessuna scoperta è mai stata eseguita.
///
/// **Non è «non è stato trovato nulla».** Le due frasi si somigliano solo in una
/// schermata mal scritta: la prima non dice niente sul contenuto di Telegram, la
/// seconda dice qualcosa, e solo nell'ambito eseguito (ADR-0035, ADR-0077).
pub const NESSUNA_SCOPERTA_ESEGUITA: &str = "Nessuna scoperta è mai stata eseguita. Questa non è l'assenza di \
     riscontri: è l'assenza di ricerche — di Telegram, qui dentro, non è stato \
     ancora chiesto niente.";

/// Un termine che non è stato chiesto, e perché.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmittedTermView {
    /// Il termine come era stato scritto: è ciò che l'operatore riconosce.
    pub term: String,
    /// Il motivo, in ciò che una persona legge.
    pub reason: String,
    /// Che cosa si può fare, se si può fare qualcosa.
    pub consequence: String,
}

/// La misura su cui una scoperta poggiava.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedLimitsView {
    /// Quante interrogazioni gratuite al giorno dichiarava la misura.
    pub free_per_day: u32,
    /// Quante ne restavano al momento della misura.
    pub remaining_free: u32,
    /// Quando è stata fatta la misura.
    pub observed_at: Timestamp,
    /// Da dove viene la misura.
    pub origin: String,
}

/// Una scoperta registrata, nell'elenco.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryRunView {
    /// Identificativo interno, per chiedere il dettaglio.
    pub id: i64,
    /// Quando è cominciata.
    pub started_at: Timestamp,
    /// Dove si è guardato.
    pub scope: SearchScope,
    /// Quante domande sono state poste.
    pub asked: usize,
    /// Quanti termini **non** sono stati chiesti.
    pub omitted: usize,
    /// Quanti risultati sono tornati.
    pub results: usize,
    /// Quanti di quei risultati sono candidati, cioè hanno almeno un motivo.
    pub candidates: usize,
}

/// Una scoperta registrata, per intero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryRunDetail {
    /// La riga d'elenco a cui appartiene.
    pub run: DiscoveryRunView,
    /// Le domande poste, nell'ordine.
    pub asked: Vec<String>,
    /// Ciò che **non** è stato chiesto, con il motivo.
    pub omitted: Vec<OmittedTermView>,
    /// La misura su cui poggiava.
    pub limits: ObservedLimitsView,
    /// I candidati, nell'ordine di PD-RANK-01, con la frase che lo spiega e con
    /// **la riga d'archivio da cui vengono**.
    ///
    /// La riga serve a chi decide: una decisione si prende su una riga, non su
    /// un valore. Due candidati possono essere indistinguibili in tutto tranne
    /// che nella riga, e riassociarli dopo farebbe finire una decisione sulla
    /// riga sbagliata pur sembrando giusta (ADR-0080).
    pub candidates: Vec<(i64, RankedCandidate)>,
    /// I risultati **senza** motivi: non sono candidati, e restano contati.
    pub results_without_reasons: usize,
}

impl DiscoveryRunDetail {
    /// La frase che dice che cosa si è guardato e che cosa se ne è ricavato.
    #[must_use]
    pub fn sentence(&self) -> String {
        let dove = self.run.scope.label();
        let poste = self.asked.len();
        let omesse = self.omitted.len();
        let candidati = self.candidates.len();

        format!(
            "In «{dove}» sono state poste {poste} domande e {omesse} termini non \
             sono stati chiesti. Ne sono tornati {} risultati, di cui \
             {candidati} con almeno un motivo. Ciò che non è stato chiesto non è \
             stato trovato assente: non è stato cercato.",
            self.run.results
        )
    }
}

/// Rilegge le scoperte pubbliche registrate.
pub struct DiscoveryReviewService {
    database: Database,
}

impl DiscoveryReviewService {
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

    /// Le scoperte registrate, la più recente per prima.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura dell'archivio non riesce.
    pub fn runs(&self) -> ServiceResult<Vec<DiscoveryRunView>> {
        let scoperte = self.database.discovery_runs()?;
        let mut elenco = Vec::with_capacity(scoperte.len());
        for scoperta in scoperte {
            elenco.push(self.riga(&scoperta)?);
        }
        Ok(elenco)
    }

    /// Una scoperta per intero.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura dell'archivio non riesce.
    pub fn run_detail(&self, run_id: i64) -> ServiceResult<Option<DiscoveryRunDetail>> {
        let Some(scoperta) = self
            .database
            .discovery_runs()?
            .into_iter()
            .find(|scoperta| scoperta.id == run_id)
        else {
            return Ok(None);
        };

        let risultati = self.database.discovery_results(run_id)?;
        let candidati = rank_with(candidati_da(&risultati));
        let senza_motivi = risultati
            .iter()
            .filter(|risultato| risultato.reasons.is_empty())
            .count();

        Ok(Some(DiscoveryRunDetail {
            run: self.riga(&scoperta)?,
            asked: self.database.discovery_queries(run_id)?,
            omitted: omissioni_da(self.database.discovery_omissions(run_id)?),
            limits: ObservedLimitsView {
                free_per_day: scoperta.limits_free_per_day,
                remaining_free: scoperta.limits_remaining_free,
                observed_at: Timestamp::from_millis(scoperta.limits_observed_at),
                origin: scoperta.limits_origin,
            },
            candidates: candidati,
            results_without_reasons: senza_motivi,
        }))
    }

    /// La riga d'elenco di una scoperta, con i conteggi.
    fn riga(&self, scoperta: &RecordedDiscoveryRun) -> ServiceResult<DiscoveryRunView> {
        let risultati = self.database.discovery_results(scoperta.id)?;
        let candidati = risultati
            .iter()
            .filter(|risultato| !risultato.reasons.is_empty())
            .count();

        Ok(DiscoveryRunView {
            id: scoperta.id,
            started_at: Timestamp::from_millis(scoperta.started_at),
            scope: scoperta.scope,
            asked: self.database.discovery_queries(scoperta.id)?.len(),
            omitted: self.database.discovery_omissions(scoperta.id)?.len(),
            results: risultati.len(),
            candidates: candidati,
        })
    }
}

/// I candidati fra i risultati: quelli con almeno un motivo.
///
/// Un risultato senza motivi **non diventa** un candidato con un motivo
/// inventato: resta fuori, e viene contato a parte.
fn candidati_da(risultati: &[RecordedDiscoveryResult]) -> Vec<(i64, SourceCandidate)> {
    let mut candidati = Vec::new();
    for risultato in risultati {
        let motivi: Vec<CandidateReason> = risultato
            .reasons
            .iter()
            .filter_map(|testo| CandidateReason::try_new(testo))
            .collect();

        let Some(query) = DiscoveryQuery::try_new(&risultato.query) else {
            continue;
        };
        let esito = DiscoveryResult {
            query,
            scope: risultato.scope,
            public_name: risultato.public_name.clone(),
            public_address: risultato.public_address.clone(),
        };
        if let Some(candidato) = SourceCandidate::try_new(esito, motivi) {
            candidati.push((risultato.id, candidato));
        }
    }
    candidati
}

/// Le omissioni, con il motivo in ciò che una persona legge.
///
/// I tre motivi restano **distinti** perché portano a tre azioni diverse:
/// correggere il termine, non preoccuparsi, oppure alzare il tetto.
fn omissioni_da(righe: Vec<(String, String)>) -> Vec<OmittedTermView> {
    righe
        .into_iter()
        .map(|(termine, motivo)| {
            let (spiegazione, conseguenza) = match motivo.as_str() {
                nome if nome == Omission::NotAQuery.as_str() => (
                    "non era una domanda",
                    "Era vuoto o fatto di soli spazi: interrogare il vuoto consumerebbe \
                     una quota vera per una domanda che nessuno ha posto.",
                ),
                nome if nome == Omission::AlreadyAsked.as_str() => (
                    "era già stato chiesto",
                    "Un'altra domanda dello stesso piano copre lo stesso termine: \
                     ripeterla non avrebbe aggiunto niente.",
                ),
                nome if nome == Omission::BudgetSpent.as_str() => (
                    "il tetto delle domande era esaurito",
                    "Questo termine non è stato cercato. Se serve, va cercato in \
                     un'altra esecuzione: non è stato trovato assente.",
                ),
                altro => (
                    altro,
                    "Motivo scritto da una versione che questo programma non conosce: \
                     non si interpreta.",
                ),
            };
            OmittedTermView {
                term: termine,
                reason: spiegazione.to_owned(),
                consequence: conseguenza.to_owned(),
            }
        })
        .collect()
}

/// Che cosa dire di un candidato, in una riga.
///
/// La posizione **non compare da sola**: arriva sempre con la ragione che l'ha
/// decisa, perché un ordine che non si può discutere è ciò che questo prodotto
/// non produce (ADR-0078).
#[must_use]
pub fn candidate_sentence(candidato: &RankedCandidate) -> String {
    let frase = candidato.sentence();
    let motivi = candidato.candidate.reasons().len();
    let parola = if motivi == 1 { "motivo" } else { "motivi" };
    format!("{frase} {motivi} {parola}.")
}

/// Se questo posto è stato deciso da un criterio, o da niente.
#[must_use]
pub const fn placement_is_arbitrary(candidato: &RankedCandidate) -> bool {
    matches!(candidato.placement, Placement::IdenticalToPrevious)
}

#[cfg(test)]
mod tests {
    use lisi_core::model::discovery::SearchScope;
    use lisi_core::model::discovery_plan::{DiscoveryBudget, Omission};
    use lisi_storage::repository::discovery::{NewDiscoveryResult, NewDiscoveryRun};

    use super::{
        DiscoveryReviewService, NESSUNA_SCOPERTA_ESEGUITA, PERCHE_NON_SI_CERCA, candidate_sentence,
    };
    use crate::sources::open_in_memory_database;

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

    fn servizio_con_una_scoperta() -> (DiscoveryReviewService, i64) {
        let Ok(mut archivio) = open_in_memory_database() else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        let Some(prima) = lisi_core::model::discovery::DiscoveryQuery::try_new("ransomware") else {
            panic!("l'interrogazione di prova non e' vuota");
        };
        let Some(seconda) = lisi_core::model::discovery::DiscoveryQuery::try_new("phishing") else {
            panic!("l'interrogazione di prova non e' vuota");
        };
        let motivi_molti = vec![
            String::from("18 riscontri Cyber Core"),
            String::from("4 CVE in comune"),
        ];
        let motivi_pochi = vec![String::from("citata da 3 fonti monitorate")];

        let Ok(run_id) = archivio.record_discovery_run(&NewDiscoveryRun {
            started_at: 1_700_000_000_000,
            scope: SearchScope::Extended,
            budget: budget(),
            limits_free_per_day: 100,
            limits_remaining_free: 98,
            limits_observed_at: 1_699_000_000_000,
            limits_origin: "misura dal vivo del 2026-09-13",
            queries: &[prima, seconda],
            omissions: &[
                (String::from("   "), Omission::NotAQuery),
                (String::from("RANSOMWARE"), Omission::AlreadyAsked),
                (String::from("cve-2026-1"), Omission::BudgetSpent),
            ],
            results: &[
                NewDiscoveryResult {
                    query: "ransomware",
                    scope: SearchScope::PublicChannelPosts,
                    public_name: "Uno",
                    public_address: None,
                    reasons: &motivi_pochi,
                },
                NewDiscoveryResult {
                    query: "ransomware",
                    scope: SearchScope::PublicChannelPosts,
                    public_name: "Due",
                    public_address: None,
                    reasons: &motivi_molti,
                },
                NewDiscoveryResult {
                    query: "phishing",
                    scope: SearchScope::AccountChats,
                    public_name: "Solo un risultato",
                    public_address: None,
                    reasons: &[],
                },
            ],
        }) else {
            panic!("la scoperta di prova deve potersi registrare");
        };

        (DiscoveryReviewService::new(archivio), run_id)
    }

    /// **Senza scoperte si dice che non ce ne sono state, non che non c'e' nulla.**
    ///
    /// «Non e' mai stata eseguita una scoperta» e «una scoperta non ha trovato
    /// nulla» si somigliano solo in una schermata mal scritta.
    #[test]
    fn senza_scoperte_non_si_afferma_niente_sul_contenuto() {
        let Ok(archivio) = open_in_memory_database() else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        let servizio = DiscoveryReviewService::new(archivio);

        let Ok(scoperte) = servizio.runs() else {
            panic!("l'elenco deve potersi leggere anche vuoto");
        };
        assert!(scoperte.is_empty());

        assert!(
            NESSUNA_SCOPERTA_ESEGUITA.contains("assenza di ricerche"),
            "il vuoto deve dire quale vuoto e'"
        );
        assert!(
            !NESSUNA_SCOPERTA_ESEGUITA.contains("nessun riscontro"),
            "non si afferma niente sul contenuto di Telegram"
        );
    }

    /// **Cio' che non e' stato chiesto si mostra accanto a cio' che e' stato
    /// chiesto.**
    ///
    /// Conservarlo e non mostrarlo riporterebbe il silenzio al suo posto:
    /// l'archivio le ha, nessuno le vede.
    #[test]
    fn le_omissioni_arrivano_con_le_domande() {
        let (servizio, run_id) = servizio_con_una_scoperta();

        let Ok(Some(dettaglio)) = servizio.run_detail(run_id) else {
            panic!("la scoperta registrata deve potersi rileggere");
        };

        assert_eq!(dettaglio.asked.len(), 2);
        assert_eq!(dettaglio.omitted.len(), 3);

        let motivi: Vec<&str> = dettaglio
            .omitted
            .iter()
            .map(|omesso| omesso.reason.as_str())
            .collect();
        assert!(motivi.contains(&"il tetto delle domande era esaurito"));
        assert!(motivi.contains(&"era già stato chiesto"));

        let Some(tagliato) = dettaglio
            .omitted
            .iter()
            .find(|omesso| omesso.term == "cve-2026-1")
        else {
            panic!("il termine tagliato dal tetto deve comparire");
        };
        assert!(
            tagliato.consequence.contains("non è stato trovato assente"),
            "la differenza fra «non cercato» e «non trovato» va detta: «{}»",
            tagliato.consequence
        );
    }

    /// **La misura su cui la scoperta poggiava si mostra con la sua origine.**
    #[test]
    fn la_misura_si_mostra_con_la_sua_provenienza() {
        let (servizio, run_id) = servizio_con_una_scoperta();

        let Ok(Some(dettaglio)) = servizio.run_detail(run_id) else {
            panic!("la scoperta registrata deve potersi rileggere");
        };

        assert_eq!(dettaglio.limits.free_per_day, 100);
        assert_eq!(dettaglio.limits.remaining_free, 98);
        assert_eq!(dettaglio.limits.origin, "misura dal vivo del 2026-09-13");
        assert_eq!(dettaglio.limits.observed_at.as_millis(), 1_699_000_000_000);
    }

    /// **I candidati arrivano ordinati, e un risultato senza motivi non lo
    /// diventa.**
    #[test]
    fn i_candidati_arrivano_ordinati_e_i_risultati_restano_risultati() {
        let (servizio, run_id) = servizio_con_una_scoperta();

        let Ok(Some(dettaglio)) = servizio.run_detail(run_id) else {
            panic!("la scoperta registrata deve potersi rileggere");
        };

        assert_eq!(dettaglio.candidates.len(), 2);
        assert_eq!(
            dettaglio.candidates[0].1.candidate.result.public_name, "Due",
            "chi ha piu' motivi si guarda prima"
        );
        assert_eq!(
            dettaglio.results_without_reasons, 1,
            "un risultato senza motivi resta contato, e non diventa un candidato"
        );
        assert_eq!(dettaglio.run.results, 3);
        assert_eq!(dettaglio.run.candidates, 2);
    }

    /// **La riga di un candidato non porta mai un numero da solo.**
    #[test]
    fn la_riga_di_un_candidato_porta_la_ragione_e_non_un_punteggio() {
        let (servizio, run_id) = servizio_con_una_scoperta();

        let Ok(Some(dettaglio)) = servizio.run_detail(run_id) else {
            panic!("la scoperta registrata deve potersi rileggere");
        };

        for (_, candidato) in &dettaglio.candidates {
            let frase = candidate_sentence(candidato);
            assert!(
                frase.contains("motivo") || frase.contains("motivi"),
                "la riga dice quanti motivi si possono leggere: «{frase}»"
            );
            assert!(
                !frase.to_lowercase().contains("punteggio"),
                "nessun punteggio compare in una riga: «{frase}»"
            );
        }
    }

    /// **La porta chiusa si dichiara, e dice che cosa manca.**
    #[test]
    fn la_porta_chiusa_dice_perche_e_chiusa() {
        assert!(
            PERCHE_NON_SI_CERCA.contains("politica validata"),
            "la ragione va nominata"
        );
        assert!(
            PERCHE_NON_SI_CERCA.contains("limiti"),
            "va detto che cosa manca"
        );
        assert!(
            PERCHE_NON_SI_CERCA.contains("promessa"),
            "un comando che non fa cio' che dice e' una promessa"
        );
    }

    /// **Il servizio non esegue una scoperta, e non ne ha il modo.**
    ///
    /// E' il punto da cui la tentazione entrerebbe: una funzione che «prova a
    /// cercare» renderebbe inutile il fatto che una politica validata non si
    /// possa costruire.
    #[test]
    fn il_servizio_non_esegue_e_non_scrive() {
        const QUESTO_MODULO: &str = include_str!("discovery.rs");

        let Some((produzione, _)) = QUESTO_MODULO.split_once("\n#[cfg(test)]\nmod tests {") else {
            panic!("il blocco delle prove non si delimita");
        };
        let codice: String = produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<&str>>()
            .join("\n");

        for vietato in [
            "record_discovery_run",
            "append_audit",
            "ValidatedDiscoveryPolicy",
            "plan(",
            "https::",
        ] {
            assert!(
                !codice.contains(vietato),
                "«{vietato}» in un servizio di sola rilettura: consultare non \
                 scrive e non esegue (ADR-0079)"
            );
        }
    }
}

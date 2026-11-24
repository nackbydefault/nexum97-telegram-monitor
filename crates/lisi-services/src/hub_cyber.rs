//! I grappoli cyber dell'ufficio, dal lato dell'Hub (TEAM-CYBER-01,
//! ADR-0102).
//!
//! # Si guarda, e non si rifà
//!
//! L'analisi cyber estrae gli indicatori **dai contenuti**, e i contenuti
//! stanno sull'Hub (ADR-0094). Una postazione che segue non ne ha, e quindi
//! non può rifare niente: qui non c'è un divieto da ricordarsi, c'è il fatto
//! che senza contenuti l'analisi non ha da dove partire.
//!
//! Questo modulo **legge** ciò che l'Hub ha già composto, e lo consegna in una
//! forma che una postazione può mostrare.
//!
//! # Che cosa non esce di qui
//!
//! Il testo dei messaggi. Escono gli **osservabili** — una CVE, un dominio, un
//! indirizzo — che sono vocabolario, e i fatti del grappolo. Una prova
//! verifica che questo modulo non nomini i contenuti.

use lisi_core::SessionId;
use lisi_core::model::hub_cyber::{
    MAX_INDICATORS_PER_EVENT, MAX_SHARED_CYBER_PAGE, SharedCyberEvent, SharedIndicator,
};

use crate::Database;
use crate::cyber_watch::{CyberWatchService, WatchEvent};
use crate::error::ServiceResult;

/// I grappoli dell'ufficio, serviti dall'Hub.
#[derive(Debug)]
pub struct HubCyberService {
    watch: CyberWatchService,
}

impl HubCyberService {
    /// Costruisce il servizio sull'archivio dell'Hub.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self {
            watch: CyberWatchService::new(database),
        }
    }

    /// L'archivio dell'Hub.
    #[must_use]
    pub const fn database(&self) -> &Database {
        self.watch.database()
    }

    /// I grappoli di una sessione, come una postazione li vede.
    ///
    /// # Errori
    ///
    /// Un errore di lettura.
    pub fn events(
        &self,
        session_id: SessionId,
        limit: usize,
    ) -> ServiceResult<Vec<SharedCyberEvent>> {
        let grappoli = self.watch.events(session_id)?;
        Ok(grappoli
            .iter()
            .take(limit.clamp(1, MAX_SHARED_CYBER_PAGE))
            .enumerate()
            .map(|(posto, grappolo)| sul_filo(posto, session_id, grappolo))
            .collect())
    }
}

/// Un grappolo, nella forma che attraversa il filo.
///
/// **Gli osservabili e i fatti, mai il testo** (ADR-0102, decisione 2).
fn sul_filo(position: usize, session_id: SessionId, grappolo: &WatchEvent) -> SharedCyberEvent {
    SharedCyberEvent {
        position,
        session_id,
        reason: grappolo.event.reason.as_sentence(),
        contents: grappolo.assessment.contents,
        distinct_sources: grappolo.assessment.distinct_sources,
        apparent_reposts: grappolo.assessment.apparent_reposts,
        italy: if grappolo.italy.is_empty() {
            String::new()
        } else {
            grappolo.italy.as_sentence()
        },
        sectors: if grappolo.sectors.is_empty() {
            String::new()
        } else {
            grappolo.sectors.as_sentence()
        },
        indicators: grappolo
            .indicators
            .iter()
            .take(MAX_INDICATORS_PER_EVENT)
            .map(|indicatore| SharedIndicator {
                kind: String::from(indicatore.kind.as_str()),
                value: indicatore.value.clone(),
            })
            .collect(),
        decided: grappolo.review.decided,
        in_progress: grappolo.review.in_progress,
        untouched: grappolo.review.untouched,
        seen_between: grappolo.seen_between,
    }
}

#[cfg(test)]
mod guardie {
    /// Il sorgente di questo modulo, per la guardia.
    const QUESTO_MODULO: &str = include_str!("hub_cyber.rs");

    /// Il codice di produzione, senza i commenti.
    fn codice_senza_commenti() -> String {
        let Some((produzione, _)) = QUESTO_MODULO.split_once("#[cfg(test)]\nmod guardie {") else {
            panic!("il modulo deve avere un blocco di guardie riconoscibile");
        };
        produzione
            .lines()
            .filter(|riga| {
                let pulita = riga.trim_start();
                !pulita.starts_with("//") && !pulita.starts_with("///")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// **I grappoli condivisi non toccano i contenuti.**
    ///
    /// Escono gli osservabili, che sono vocabolario, e i fatti del grappolo.
    /// Il testo di un messaggio si chiede uno per volta, e passa da un'altra
    /// parte (ADR-0094).
    #[test]
    fn i_grappoli_condivisi_non_toccano_i_contenuti() {
        let codice = codice_senza_commenti();
        for vietato in ["contents(", "content_body", "body", "session_contents"] {
            assert!(
                !codice.contains(vietato),
                "il modulo dei grappoli condivisi nomina «{vietato}»: da qui escono gli \
                 osservabili, non i testi"
            );
        }
    }

    /// **Le due parole vietate non compaiono.**
    #[test]
    fn le_due_parole_vietate_non_compaiono() {
        let codice = codice_senza_commenti().to_lowercase();
        for vietata in ["confermato", "indipendenti"] {
            assert!(
                !codice.contains(vietata),
                "il modulo dice «{vietata}»: un grappolo è un evento candidato, e cinque copie \
                 non sono cinque testimoni"
            );
        }
    }
}

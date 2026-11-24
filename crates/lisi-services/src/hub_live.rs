//! Il live condiviso: chi lo pubblica, e chi lo mostra (TEAM-LIVE-01,
//! ADR-0093).
//!
//! # Due lati, due tipi
//!
//! [`HubLivePublisher`] vive **sull'Hub**: trasforma una tornata di
//! acquisizione in eventi della sequenza autorevole (ADR-0086). [`HubLiveFeed`]
//! vive **sulla postazione**: applica quegli eventi nella proiezione locale che
//! la schermata mostra.
//!
//! # Che cosa viaggia, e che cosa no
//!
//! Viaggiano i **fatti dell'attività**: quante cose sono arrivate, da quale
//! fonte, con quale livello, quale monitoraggio è partito o finito. **Non
//! viaggia il contenuto monitorato**: un flusso che portasse i messaggi sarebbe
//! la copia dell'archivio dell'Hub costruita un pezzo alla volta, che il
//! congelamento esclude (§7.10).
//!
//! Il nome della regola e il livello vengono dai dizionari **dell'ufficio**
//! (ADR-0038): dirli non racconta il contenuto che li ha attivati.
//!
//! # Si aggrega, e si dichiara ciò che si taglia
//!
//! Un evento per messaggio riempirebbe in pochi secondi la coda di ADR-0088.
//! Si pubblica un evento per fonte per tornata, con un tetto, e oltre il tetto
//! **una riga che dice quanto resta fuori** ([`lisi_core::model::hub_live`]).

use std::collections::BTreeMap;

use lisi_core::Timestamp;
use lisi_core::model::hub_event::{HubEvent, HubEventKind, NewHubEvent};
use lisi_core::model::hub_live::{LIVE_FEED_MAX_ROWS, MAX_LIVE_EVENTS_PER_ROUND, plan_round};
use lisi_core::text::{HubEventDetail, HubEventSubject};

use crate::Database;
use crate::error::ServiceResult;
use crate::hub_events::publish_event;

/// Il soggetto degli eventi che non riguardano una fonte sola.
const SOGGETTO_TORNATA: &str = "più fonti";

/// Il lato Hub: pubblica sulla sequenza autorevole ciò che accade.
#[derive(Debug)]
pub struct HubLivePublisher {
    database: Database,
}

impl HubLivePublisher {
    /// Costruisce il produttore sull'archivio dell'Hub.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Archivio sottostante.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Restituisce l'archivio al chiamante.
    #[must_use]
    pub fn into_database(self) -> Database {
        self.database
    }

    /// Pubblica una tornata di acquisizione.
    ///
    /// `counts` dice, per ciascuna fonte, quanti contenuti sono stati acquisiti
    /// **in questa tornata**. Una fonte senza contenuti non produce eventi: un
    /// «zero contenuti» direbbe che non è successo nulla, che è ciò che
    /// l'assenza di evento dice già.
    ///
    /// Restituisce quanti eventi sono stati pubblicati.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura di un evento non riesce.
    pub fn publish_round(
        &mut self,
        counts: &BTreeMap<String, usize>,
        now: Timestamp,
    ) -> ServiceResult<usize> {
        let piano = plan_round(counts, MAX_LIVE_EVENTS_PER_ROUND);
        let mut pubblicati = 0_usize;

        for (fonte, quanti) in &piano.published {
            self.publish(
                HubEventKind::ContentAcquired,
                fonte,
                &lisi_core::text::counted(*quanti, "contenuto acquisito", "contenuti acquisiti"),
                now,
            )?;
            pubblicati += 1;
        }

        // IL TAGLIO SI DICHIARA. Senza questa riga, un ufficio che sorveglia
        // più di trentadue fonti leggerebbe un live incompleto come completo.
        if piano.has_omissions() {
            self.publish(
                HubEventKind::ContentAcquired,
                SOGGETTO_TORNATA,
                &format!(
                    "{} {}, non {} in questa tornata",
                    if piano.omitted_sources == 1 {
                        String::from("un'altra fonte ha prodotto")
                    } else {
                        format!("altre {} fonti hanno prodotto", piano.omitted_sources)
                    },
                    lisi_core::text::counted(piano.omitted_contents, "contenuto", "contenuti"),
                    if piano.omitted_contents == 1 {
                        "elencato"
                    } else {
                        "elencati"
                    }
                ),
                now,
            )?;
            pubblicati += 1;
        }

        Ok(pubblicati)
    }

    /// Pubblica un avviso scattato.
    ///
    /// Gli avvisi **non si aggregano**: un avviso è il fatto che l'ufficio
    /// aspetta, e «tre avvisi» senza dire di che livello renderebbe il live
    /// inutile proprio dove serve.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il soggetto o il dettaglio non attraversano i
    /// tipi del dominio, o se la scrittura non riesce.
    pub fn publish_alert(
        &mut self,
        source: &str,
        level: &str,
        rule: &str,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.publish(
            HubEventKind::AlertRaised,
            source,
            &format!("livello {level}, regola «{rule}»"),
            now,
        )
    }

    /// Pubblica l'avvio di un monitoraggio.
    ///
    /// # Errori
    ///
    /// Come [`Self::publish_alert`].
    pub fn publish_monitoring_started(
        &mut self,
        source: &str,
        detail: &str,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.publish(HubEventKind::MonitoringStarted, source, detail, now)
    }

    /// Pubblica la conclusione di un monitoraggio.
    ///
    /// # Errori
    ///
    /// Come [`Self::publish_alert`].
    pub fn publish_monitoring_stopped(
        &mut self,
        source: &str,
        detail: &str,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.publish(HubEventKind::MonitoringStopped, source, detail, now)
    }

    fn publish(
        &mut self,
        kind: HubEventKind,
        subject: &str,
        detail: &str,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let evento = NewHubEvent {
            kind,
            subject: HubEventSubject::try_new(subject)?,
            detail: Some(HubEventDetail::try_new(detail)?),
        };
        publish_event(&mut self.database, &evento, now)?;
        Ok(())
    }
}

/// Il lato postazione: la proiezione che la schermata mostra.
#[derive(Debug)]
pub struct HubLiveFeed {
    database: Database,
    cap: usize,
}

impl HubLiveFeed {
    /// Costruisce la proiezione sull'archivio della postazione.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self {
            database,
            cap: LIVE_FEED_MAX_ROWS,
        }
    }

    /// Sostituisce il tetto delle righe conservate. Serve alle prove.
    #[must_use]
    pub const fn with_cap(mut self, cap: usize) -> Self {
        self.cap = cap;
        self
    }

    /// Applica un evento arrivato dall'Hub.
    ///
    /// Gli eventi che **non** sono del live — l'andirivieni dei dispositivi —
    /// non entrano nella proiezione: riguardano chi amministra, e la schermata
    /// del live non li elenca. Non è uno scarto silenzioso: l'evento è stato
    /// applicato lo stesso, e il cursore avanza.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn apply(&self, event: &HubEvent) -> ServiceResult<()> {
        if !event.kind.is_live() {
            return Ok(());
        }
        self.database.record_hub_live_event(event, self.cap)?;
        Ok(())
    }

    /// Le ultime righe, dalla più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn latest(&self, limit: usize) -> ServiceResult<Vec<HubEvent>> {
        Ok(self.database.hub_live_feed(limit.min(self.cap))?)
    }

    /// Quante righe conserva.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn len(&self) -> ServiceResult<usize> {
        Ok(self.database.hub_live_feed_len()?)
    }

    /// Se la proiezione è vuota.
    ///
    /// # Errori
    ///
    /// Come [`Self::len`].
    pub fn is_empty(&self) -> ServiceResult<bool> {
        Ok(self.len()? == 0)
    }

    /// Svuota la proiezione.
    ///
    /// Accompagna «dimentica il punto di lettura» (ADR-0087): dopo quell'atto
    /// le righe mostrate apparterrebbero a una storia che la postazione non
    /// segue più.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la cancellazione non riesce.
    pub fn forget(&self) -> ServiceResult<()> {
        self.database.clear_hub_live_feed()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use lisi_core::Timestamp;
    use lisi_core::model::hub_event::{HubEvent, HubEventKind};
    use lisi_core::text::HubEventSubject;

    use super::{HubLiveFeed, HubLivePublisher};

    fn adesso() -> Timestamp {
        Timestamp::from_millis(1_759_000_000_000)
    }

    fn archivio() -> crate::Database {
        match crate::sources::open_in_memory_database() {
            Ok(database) => database,
            Err(errore) => panic!("archivio di prova: {errore}"),
        }
    }

    fn conteggi(voci: &[(&str, usize)]) -> BTreeMap<String, usize> {
        let mut mappa = BTreeMap::new();
        for (fonte, quanti) in voci {
            mappa.insert(String::from(*fonte), *quanti);
        }
        mappa
    }

    fn evento(sequence: u64, kind: HubEventKind) -> HubEvent {
        let Ok(subject) = HubEventSubject::try_new("@fonte") else {
            panic!("soggetto");
        };
        HubEvent {
            sequence,
            kind,
            subject,
            detail: None,
            recorded_at: adesso(),
        }
    }

    #[test]
    fn a_round_publishes_one_event_per_source() {
        let mut produttore = HubLivePublisher::new(archivio());
        let Ok(quanti) =
            produttore.publish_round(&conteggi(&[("@alfa", 2), ("@beta", 5)]), adesso())
        else {
            panic!("la tornata deve potersi pubblicare");
        };
        assert_eq!(quanti, 2);

        let Ok(eventi) = produttore.database().hub_events_after(0, 10) else {
            panic!("gli eventi devono potersi leggere");
        };
        assert_eq!(eventi.len(), 2);
        assert!(eventi.iter().all(|evento| evento.kind.is_live()));
        let Some(dettaglio) = eventi[1].detail.as_ref() else {
            panic!("il dettaglio deve esserci");
        };
        assert!(
            dettaglio.as_str().contains('5'),
            "il numero dei contenuti deve comparire: «{}»",
            dettaglio.as_str()
        );
    }

    #[test]
    fn an_empty_round_publishes_nothing() {
        let mut produttore = HubLivePublisher::new(archivio());
        let Ok(quanti) = produttore.publish_round(&conteggi(&[("@alfa", 0)]), adesso()) else {
            panic!("la tornata deve potersi pubblicare");
        };
        assert_eq!(quanti, 0);
        assert_eq!(produttore.database().latest_hub_sequence().ok(), Some(0));
    }

    #[test]
    fn an_alert_says_the_level_and_the_rule() {
        let mut produttore = HubLivePublisher::new(archivio());
        let Ok(()) = produttore.publish_alert("@alfa", "alto", "armi", adesso()) else {
            panic!("l'avviso deve potersi pubblicare");
        };
        let Ok(eventi) = produttore.database().hub_events_after(0, 10) else {
            panic!("gli eventi devono potersi leggere");
        };
        assert_eq!(eventi.len(), 1);
        assert_eq!(eventi[0].kind, HubEventKind::AlertRaised);
        let Some(dettaglio) = eventi[0].detail.as_ref() else {
            panic!("il dettaglio deve esserci");
        };
        assert!(dettaglio.as_str().contains("alto"));
        assert!(dettaglio.as_str().contains("armi"));
    }

    #[test]
    fn only_the_live_events_enter_the_projection() {
        let proiezione = HubLiveFeed::new(archivio());
        let Ok(()) = proiezione.apply(&evento(1, HubEventKind::DeviceEnrolled)) else {
            panic!("l'applicazione deve riuscire");
        };
        assert_eq!(proiezione.len().ok(), Some(0));

        let Ok(()) = proiezione.apply(&evento(2, HubEventKind::ContentAcquired)) else {
            panic!("l'applicazione deve riuscire");
        };
        assert_eq!(proiezione.len().ok(), Some(1));
    }

    #[test]
    fn the_projection_is_bounded_and_can_be_forgotten() {
        let proiezione = HubLiveFeed::new(archivio()).with_cap(3);
        for numero in 1..=10 {
            let Ok(()) = proiezione.apply(&evento(numero, HubEventKind::ContentAcquired)) else {
                panic!("l'applicazione deve riuscire");
            };
        }
        assert_eq!(proiezione.len().ok(), Some(3));

        let Ok(righe) = proiezione.latest(10) else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(righe.first().map(|evento| evento.sequence), Some(10));

        let Ok(()) = proiezione.forget() else {
            panic!("lo svuotamento deve riuscire");
        };
        assert_eq!(proiezione.is_empty().ok(), Some(true));
    }
}

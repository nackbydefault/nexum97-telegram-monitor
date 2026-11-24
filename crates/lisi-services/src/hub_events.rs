//! Il servizio della sequenza degli eventi dell'Hub (HUB-EVENT-01, ADR-0086).
//!
//! # Chi scrive, e chi legge
//!
//! **Scrive l'Hub**, dentro gli atti che già compie: un dispositivo ammesso,
//! uno ritirato, un ruolo cambiato. Non esiste una via per cui un client
//! proponga un evento o il suo numero (ADR-0042 decisione 4: l'Hub distribuisce,
//! non raccoglie).
//!
//! **Legge chi torna**: dichiara il flusso che seguiva e l'ultimo numero
//! accettato, e riceve ciò che manca, a pezzi limitati. Il recupero vero e
//! proprio — quando chiederlo, come tornare in diretta — è di HUB-CATCHUP-01;
//! qui c'è la sequenza e il verdetto su che cosa consegnare.
//!
//! # Il caso che questo modulo esiste per impedire
//!
//! Un Hub reinstallato riparte dal numero uno. Senza il nome del flusso, un
//! client che aveva visto il cinquecento chiederebbe «dopo il cinquecento» e
//! riceverebbe **silenzio**, leggendolo come «non è successo nulla». Qui quel
//! silenzio ha un nome: [`EventDelivery::StreamChanged`].

use lisi_core::Timestamp;
use lisi_core::model::hub_event::{
    EventCursor, HUB_STREAM_ID_BYTES, HubEvent, HubEventStreamId, NewHubEvent, ResumeVerdict,
    resume_from,
};

use crate::Database;
use crate::error::{ServiceError, ServiceResult};

/// Che cosa l'Hub consegna a chi chiede di riprendere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventDelivery {
    /// Gli eventi che mancavano, in ordine di numero, al più il limite chiesto.
    Events {
        /// Gli eventi dopo il numero dichiarato.
        events: Vec<HubEvent>,
        /// L'ultimo numero che l'Hub ha emesso: dice se ne restano altri.
        latest: u64,
    },
    /// Il client seguiva un'altra storia. **Non è «nulla di nuovo».**
    StreamChanged {
        /// Il flusso vero di questo Hub.
        stream: HubEventStreamId,
        /// L'ultimo numero di questo flusso.
        latest: u64,
    },
    /// Il client dichiara un numero che questo Hub non ha mai emesso.
    AheadOfHub {
        /// L'ultimo numero emesso davvero.
        latest: u64,
    },
}

/// La sequenza degli eventi di questo Hub.
#[derive(Debug)]
pub struct HubEventService {
    database: Database,
}

impl HubEventService {
    /// Costruisce il servizio sull'archivio indicato.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Archivio sottostante.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Il nome del flusso di questo Hub, creato alla prima richiesta.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il generatore crittografico rifiuta o se la
    /// scrittura non riesce.
    pub fn stream_id(&self, now: Timestamp) -> ServiceResult<HubEventStreamId> {
        let mut byte = [0_u8; HUB_STREAM_ID_BYTES];
        lisi_security::random_bytes(&mut byte).map_err(|errore| ServiceError::DeviceIdentity {
            reason: String::from(errore.operator_message()),
        })?;
        Ok(self.database.hub_event_stream_id(byte, now)?)
    }

    /// L'ultimo numero emesso; zero se non è mai successo nulla.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn latest(&self) -> ServiceResult<u64> {
        Ok(self.database.latest_hub_sequence()?)
    }

    /// Scrive un evento e restituisce il numero che gli è stato dato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn publish(&mut self, event: &NewHubEvent, now: Timestamp) -> ServiceResult<u64> {
        publish_event(&mut self.database, event, now)
    }

    /// Decide che cosa consegnare a chi torna.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se una lettura non riesce o se il generatore
    /// rifiuta alla prima creazione del flusso.
    pub fn since(
        &self,
        cursor: EventCursor,
        limit: usize,
        now: Timestamp,
    ) -> ServiceResult<EventDelivery> {
        let stream = self.stream_id(now)?;
        let latest = self.latest()?;

        match resume_from(cursor, stream, latest) {
            ResumeVerdict::StreamChanged => Ok(EventDelivery::StreamChanged { stream, latest }),
            ResumeVerdict::AheadOfHub => Ok(EventDelivery::AheadOfHub { latest }),
            ResumeVerdict::Resume { after } => Ok(EventDelivery::Events {
                events: self.database.hub_events_after(after, limit)?,
                latest,
            }),
        }
    }
}

/// Scrive un evento nell'archivio indicato.
///
/// Esiste come funzione libera perché i produttori sono le autorità che già
/// compiono l'atto — l'arruolamento, l'accesso — e ciascuna possiede il proprio
/// archivio: un evento scritto altrove sarebbe un evento che racconta un atto
/// che non è ancora avvenuto.
///
/// # Errori
///
/// Restituisce un errore se la scrittura non riesce.
pub fn publish_event(
    database: &mut Database,
    event: &NewHubEvent,
    now: Timestamp,
) -> ServiceResult<u64> {
    Ok(database.append_hub_event(event, now)?)
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::hub_event::{
        EventCursor, HUB_STREAM_ID_BYTES, HubEventKind, HubEventStreamId, NewHubEvent,
    };
    use lisi_core::text::HubEventSubject;

    use super::{EventDelivery, HubEventService};

    fn adesso() -> Timestamp {
        Timestamp::from_millis(1_758_200_000_000)
    }

    fn servizio() -> HubEventService {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("archivio di prova");
        };
        HubEventService::new(database)
    }

    fn evento(soggetto: &str) -> NewHubEvent {
        let Ok(subject) = HubEventSubject::try_new(soggetto) else {
            panic!("soggetto");
        };
        NewHubEvent {
            kind: HubEventKind::DeviceEnrolled,
            subject,
            detail: None,
        }
    }

    #[test]
    fn a_client_of_the_same_stream_receives_only_what_it_missed() {
        let mut servizio = servizio();
        let Ok(flusso) = servizio.stream_id(adesso()) else {
            panic!("flusso");
        };
        for numero in 1..=3 {
            assert_eq!(
                servizio
                    .publish(&evento(&format!("dispositivo {numero}")), adesso())
                    .ok(),
                Some(numero)
            );
        }

        let Ok(EventDelivery::Events { events, latest }) = servizio.since(
            EventCursor {
                stream: flusso,
                last_sequence: 1,
            },
            100,
            adesso(),
        ) else {
            panic!("un client dello stesso flusso riceve ciò che manca");
        };
        assert_eq!(latest, 3);
        assert_eq!(
            events.iter().map(|e| e.sequence).collect::<Vec<u64>>(),
            vec![2, 3]
        );
    }

    #[test]
    fn a_stream_that_is_not_ours_is_said_and_not_answered_with_silence() {
        let mut servizio = servizio();
        let _ = servizio.publish(&evento("dispositivo"), adesso());
        let estraneo = HubEventStreamId::from_random_bytes([0xEE; HUB_STREAM_ID_BYTES]);

        let Ok(consegna) = servizio.since(
            EventCursor {
                stream: estraneo,
                last_sequence: 500,
            },
            100,
            adesso(),
        ) else {
            panic!("lettura");
        };
        let EventDelivery::StreamChanged { stream, latest } = consegna else {
            panic!("un flusso estraneo non è «nulla di nuovo»: {consegna:?}");
        };
        assert_eq!(latest, 1);
        assert_ne!(stream, estraneo);
    }

    #[test]
    fn a_number_never_issued_is_said_as_such() {
        let servizio = servizio();
        let Ok(flusso) = servizio.stream_id(adesso()) else {
            panic!("flusso");
        };
        assert_eq!(
            servizio
                .since(
                    EventCursor {
                        stream: flusso,
                        last_sequence: 7
                    },
                    10,
                    adesso()
                )
                .ok(),
            Some(EventDelivery::AheadOfHub { latest: 0 })
        );
    }

    #[test]
    fn the_stream_does_not_change_between_two_calls() {
        let servizio = servizio();
        let (Ok(primo), Ok(secondo)) = (servizio.stream_id(adesso()), servizio.stream_id(adesso()))
        else {
            panic!("flusso");
        };
        assert_eq!(primo, secondo);
    }
}

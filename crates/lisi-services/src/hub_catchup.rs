//! Il recupero dopo una riconnessione, lato postazione (HUB-CATCHUP-01,
//! ADR-0087).
//!
//! # Che cosa fa
//!
//! Tiene insieme tre cose che devono restare allineate: il **cursore
//! conservato** (dove la postazione era arrivata), la **macchina a stati** del
//! dominio ([`lisi_core::model::hub_catchup`]), e l'**applicazione** degli
//! eventi, che è di chi li riceve.
//!
//! # L'ordine è la garanzia
//!
//! Per ogni evento: si guarda **prima** di applicarlo, si applica, e **solo
//! dopo** si segna il cursore. Un arresto in mezzo lascia l'evento da
//! riapplicare — e riapplicarlo non deve fare danno — invece di lasciarlo
//! perso: un evento perso non si recupera, uno ripetuto sì.
//!
//! # Il recupero si ferma, e lo dice
//!
//! Se l'Hub risponde con un'altra storia, o non conosce il numero dichiarato,
//! **non si ricomincia da soli**: ricominciare significherebbe riscrivere la
//! copia della postazione senza che nessuno lo abbia deciso. Si registra il
//! fatto, si restituisce la frase per l'operatore, e si aspetta una persona.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::model::hub_catchup::{
    AcceptOutcome, CatchUpStop, CatchUpTracker, HubCursor, NextStep,
};
use lisi_core::model::hub_event::{HubEvent, HubEventStreamId};
use lisi_core::model::identity::OperatorId;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_storage::repository::hub_cursor::CursorRefusal;

use crate::Database;
use crate::error::{ServiceError, ServiceResult};

/// Entità dell'audit di questo modulo.
const AUDIT_ENTITY: &str = "recupero_hub";
/// Soggetto degli atti decisi dalla regola.
const AUDIT_AUTHORITY: &str = "hub.recupero";

const AUDIT_STOPPED: &str = "recupero_fermato";
const AUDIT_GAP: &str = "buco_nella_sequenza";
const AUDIT_FORGOTTEN: &str = "punto_di_lettura_dimenticato";

/// Che cosa è successo applicando una pagina.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageReport {
    /// Quanti eventi sono stati applicati.
    pub applied: usize,
    /// Quanti erano già stati applicati, e si sono scartati.
    pub duplicates: usize,
    /// Il buco incontrato, se la pagina non era contigua.
    pub gap: Option<Gap>,
    /// Che cosa fare adesso.
    pub next: NextStep,
}

/// Un buco nella sequenza: si chiede, non si assume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gap {
    /// Il numero atteso.
    pub expected: u64,
    /// Il numero arrivato.
    pub received: u64,
}

/// Il recupero della postazione.
#[derive(Debug)]
pub struct HubCatchUpService {
    database: Database,
}

impl HubCatchUpService {
    /// Costruisce il servizio sull'archivio della postazione.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Archivio sottostante.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Il punto conservato, se c'è.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn cursor(&self) -> ServiceResult<Option<HubCursor>> {
        Ok(self.database.hub_cursor()?)
    }

    /// La macchina a stati con cui cominciare, per la storia indicata.
    ///
    /// Se la postazione seguiva **un'altra** storia, il recupero **non
    /// comincia**: restituisce [`CatchUpStop::StreamChanged`], e dimenticare il
    /// vecchio punto resta un atto esplicito ([`Self::forget_position`]).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura o l'audit non riescono.
    pub fn begin(
        &self,
        stream: HubEventStreamId,
        now: Timestamp,
    ) -> ServiceResult<Result<CatchUpTracker, CatchUpStop>> {
        let conservato = self.cursor()?;
        match conservato {
            Some(cursore) if cursore.stream != stream => {
                self.registra(
                    AUDIT_STOPPED,
                    "l'Hub risponde con una storia diversa da quella seguita finora",
                    now,
                )?;
                Ok(Err(CatchUpStop::StreamChanged))
            }
            Some(cursore) => Ok(Ok(CatchUpTracker::resuming_from(cursore))),
            None => Ok(Ok(CatchUpTracker::resuming_from(HubCursor {
                stream,
                last_applied: 0,
            }))),
        }
    }

    /// Applica una pagina di eventi, in ordine.
    ///
    /// `applica` riceve un evento alla volta e deve **persistere** ciò che
    /// significa applicarlo; se fallisce, il recupero si ferma su quell'evento
    /// e il cursore non avanza.
    ///
    /// # Errori
    ///
    /// Restituisce l'errore di `applica`, o un errore d'archivio se il cursore
    /// non si può conservare.
    pub fn apply_page<A>(
        &self,
        tracker: &mut CatchUpTracker,
        events: &[HubEvent],
        hub_latest: u64,
        now: Timestamp,
        mut applica: A,
    ) -> ServiceResult<PageReport>
    where
        A: FnMut(&HubEvent) -> ServiceResult<()>,
    {
        let mut applicati = 0_usize;
        let mut duplicati = 0_usize;
        let mut buco = None;

        for evento in events {
            match tracker.inspect(evento.sequence) {
                AcceptOutcome::Duplicate => duplicati += 1,
                AcceptOutcome::Gap { expected, received } => {
                    // NON si applica, e non si prosegue: ciò che viene dopo un
                    // buco è altrettanto fuori posto.
                    self.registra(
                        AUDIT_GAP,
                        &format!("atteso il numero {expected}, arrivato il {received}"),
                        now,
                    )?;
                    buco = Some(Gap { expected, received });
                    break;
                }
                AcceptOutcome::Next => {
                    // PRIMA si applica...
                    applica(evento)?;
                    // ...e SOLO DOPO si segna.
                    let avanzato = tracker.applied(evento.sequence);
                    debug_assert!(avanzato, "inspect ha detto Next: applied non può rifiutare");
                    self.conserva(tracker.cursor(), now)?;
                    applicati += 1;
                }
            }
        }

        Ok(PageReport {
            applied: applicati,
            duplicates: duplicati,
            gap: buco,
            next: tracker.next_step(hub_latest),
        })
    }

    /// Registra che il recupero si è fermato, e restituisce la frase per
    /// l'operatore.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'audit non si scrive.
    pub fn stopped(&self, stop: CatchUpStop, now: Timestamp) -> ServiceResult<&'static str> {
        self.registra(AUDIT_STOPPED, stop.operator_message(), now)?;
        Ok(stop.operator_message())
    }

    /// Dimentica il punto raggiunto. **Atto di una persona**, e l'audit ne
    /// porta l'identificativo.
    ///
    /// Da qui la postazione ricomincerà a leggere dall'inizio della storia
    /// nuova: è il gesto che non deve accadere da solo.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura o l'audit non riescono.
    pub fn forget_position(&self, operator: &OperatorId, now: Timestamp) -> ServiceResult<()> {
        self.database.clear_hub_cursor()?;
        self.scrivi(
            operator.audit_actor()?,
            AUDIT_FORGOTTEN,
            "la postazione ricomincerà a leggere dall'inizio della storia dell'Hub",
            now,
        )
    }

    /// Conserva il punto raggiunto.
    fn conserva(&self, cursore: HubCursor, now: Timestamp) -> ServiceResult<()> {
        match self.database.advance_hub_cursor(cursore, now)? {
            Ok(()) | Err(CursorRefusal::NotForward) => Ok(()),
            // Non può accadere: `begin` rifiuta di cominciare su un'altra
            // storia. Se accade, qualcuno ha cambiato il cursore sotto i piedi
            // del recupero, e fermarsi è l'unica risposta onesta.
            Err(CursorRefusal::OtherStream) => Err(ServiceError::DeviceIdentity {
                reason: String::from(
                    "il punto di lettura conservato appartiene a un'altra storia: il recupero si ferma",
                ),
            }),
        }
    }

    fn registra(&self, azione: &str, dettaglio: &str, now: Timestamp) -> ServiceResult<()> {
        self.scrivi(Actor::try_new(AUDIT_AUTHORITY)?, azione, dettaglio, now)
    }

    fn scrivi(
        &self,
        actor: Actor,
        azione: &str,
        dettaglio: &str,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let entry = NewAuditEntry {
            actor,
            action: AuditAction::try_new(azione)?,
            entity: AuditEntity::try_new(AUDIT_ENTITY)?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(dettaglio)?),
            recorded_at: now,
        };
        self.database.append_audit(&entry)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use lisi_core::Timestamp;
    use lisi_core::model::hub_catchup::{CatchUpStop, NextStep};
    use lisi_core::model::hub_event::{
        HUB_STREAM_ID_BYTES, HubEvent, HubEventKind, HubEventStreamId,
    };
    use lisi_core::model::identity::OperatorId;
    use lisi_core::text::HubEventSubject;

    use super::{Gap, HubCatchUpService};
    use crate::error::ServiceError;

    fn adesso() -> Timestamp {
        Timestamp::from_millis(1_758_400_000_000)
    }

    fn flusso(seme: u8) -> HubEventStreamId {
        HubEventStreamId::from_random_bytes([seme; HUB_STREAM_ID_BYTES])
    }

    fn servizio() -> HubCatchUpService {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("archivio di prova");
        };
        HubCatchUpService::new(database)
    }

    fn evento(sequence: u64) -> HubEvent {
        let Ok(subject) = HubEventSubject::try_new("dispositivo") else {
            panic!("soggetto");
        };
        HubEvent {
            sequence,
            kind: HubEventKind::DeviceEnrolled,
            subject,
            detail: None,
            recorded_at: adesso(),
        }
    }

    fn azioni(servizio: &HubCatchUpService) -> Vec<String> {
        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("audit");
        };
        voci.iter()
            .filter(|voce| voce.entity.as_str() == "recupero_hub")
            .map(|voce| voce.action.as_str().to_owned())
            .collect()
    }

    #[test]
    fn a_new_station_applies_the_page_and_remembers_where_it_got_to() {
        let servizio = servizio();
        let Ok(Ok(mut tracker)) = servizio.begin(flusso(1), adesso()) else {
            panic!("un recupero nuovo deve poter cominciare");
        };
        let applicati = RefCell::new(Vec::new());

        let Ok(esito) = servizio.apply_page(
            &mut tracker,
            &[evento(1), evento(2), evento(3)],
            3,
            adesso(),
            |evento| {
                applicati.borrow_mut().push(evento.sequence);
                Ok(())
            },
        ) else {
            panic!("la pagina deve applicarsi");
        };
        assert_eq!(esito.applied, 3);
        assert_eq!(esito.next, NextStep::Live);
        assert_eq!(*applicati.borrow(), vec![1, 2, 3]);
        assert_eq!(
            servizio.cursor().ok().flatten().map(|c| c.last_applied),
            Some(3)
        );
    }

    #[test]
    fn what_was_already_applied_is_not_applied_again() {
        let servizio = servizio();
        let Ok(Ok(mut tracker)) = servizio.begin(flusso(1), adesso()) else {
            panic!("inizio");
        };
        let _ = servizio.apply_page(&mut tracker, &[evento(1), evento(2)], 2, adesso(), |_| {
            Ok(())
        });

        let riapplicati = RefCell::new(0_usize);
        let Ok(esito) = servizio.apply_page(
            &mut tracker,
            &[evento(1), evento(2), evento(3)],
            3,
            adesso(),
            |_| {
                *riapplicati.borrow_mut() += 1;
                Ok(())
            },
        ) else {
            panic!("la pagina deve applicarsi");
        };
        assert_eq!(esito.duplicates, 2);
        assert_eq!(esito.applied, 1);
        assert_eq!(*riapplicati.borrow(), 1, "solo il terzo si applica");
    }

    #[test]
    fn a_hole_stops_the_page_and_is_written_down() {
        let servizio = servizio();
        let Ok(Ok(mut tracker)) = servizio.begin(flusso(1), adesso()) else {
            panic!("inizio");
        };
        let applicati = RefCell::new(Vec::new());

        let Ok(esito) = servizio.apply_page(
            &mut tracker,
            &[evento(1), evento(3), evento(4)],
            4,
            adesso(),
            |evento| {
                applicati.borrow_mut().push(evento.sequence);
                Ok(())
            },
        ) else {
            panic!("la pagina deve produrre un esito");
        };
        assert_eq!(esito.applied, 1);
        assert_eq!(
            esito.gap,
            Some(Gap {
                expected: 2,
                received: 3
            })
        );
        assert_eq!(
            *applicati.borrow(),
            vec![1],
            "dopo un buco non si applica altro"
        );
        assert_eq!(
            esito.next,
            NextStep::RequestPage {
                after: 1,
                limit: lisi_core::model::hub_catchup::CATCH_UP_PAGE
            }
        );
        assert!(azioni(&servizio).contains(&String::from("buco_nella_sequenza")));
    }

    #[test]
    fn an_application_that_fails_does_not_advance_the_cursor() {
        let servizio = servizio();
        let Ok(Ok(mut tracker)) = servizio.begin(flusso(1), adesso()) else {
            panic!("inizio");
        };
        let esito = servizio.apply_page(&mut tracker, &[evento(1)], 1, adesso(), |_| {
            Err(ServiceError::DeviceIdentity {
                reason: String::from("l'applicazione non riesce"),
            })
        });
        assert!(esito.is_err());
        assert_eq!(tracker.cursor().last_applied, 0);
        assert_eq!(servizio.cursor().ok(), Some(None));
    }

    #[test]
    fn another_story_does_not_start_a_recovery_and_forgetting_is_a_persons_act() {
        let servizio = servizio();
        let Ok(Ok(mut tracker)) = servizio.begin(flusso(1), adesso()) else {
            panic!("inizio");
        };
        let _ = servizio.apply_page(&mut tracker, &[evento(1)], 1, adesso(), |_| Ok(()));

        // L'Hub risponde con un'altra storia.
        let Ok(Err(stop)) = servizio.begin(flusso(2), adesso()) else {
            panic!("un'altra storia non deve far cominciare un recupero");
        };
        assert_eq!(stop, CatchUpStop::StreamChanged);
        assert!(azioni(&servizio).contains(&String::from("recupero_fermato")));
        assert_eq!(
            servizio.cursor().ok().flatten().map(|c| c.last_applied),
            Some(1),
            "il punto vecchio resta finché qualcuno non lo dimentica"
        );

        let Ok(frase) = servizio.stopped(stop, adesso()) else {
            panic!("la frase per l'operatore");
        };
        assert!(frase.contains("si ferma qui"));

        // Dimenticare è un atto di una persona, e allora la storia nuova entra.
        assert!(
            servizio
                .forget_position(&OperatorId::local(), adesso())
                .is_ok()
        );
        assert_eq!(servizio.cursor().ok(), Some(None));
        assert!(azioni(&servizio).contains(&String::from("punto_di_lettura_dimenticato")));
        assert!(matches!(servizio.begin(flusso(2), adesso()), Ok(Ok(_))));
    }
}

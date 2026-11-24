//! La revisione condivisa, dal lato dell'Hub (TEAM-REVIEW-01, ADR-0094).
//!
//! # Tre atti, tre regole
//!
//! **Guardare la coda** non tocca nulla e porta soltanto metadati.
//! **Leggere un contenuto** è un atto: uno per volta, autorizzato, e l'audit
//! dice quale dispositivo lo ha chiesto. **Decidere** è un comando idempotente
//! con concorrenza ottimistica (ADR-0089): ripeterlo non raddoppia, e chi
//! scrive su una versione superata riceve un conflitto che dice contro che cosa
//! ha perso.
//!
//! # Chi ha rivisto è una postazione
//!
//! L'identità di **persona** autenticata non esiste (ADR-0082, decisione 6):
//! attribuire la decisione a un segnaposto locale scriverebbe nel registro un
//! nome che nessuno ha verificato. Si attribuisce quindi al **dispositivo**,
//! che è ciò che l'Hub autentica, e il registro lo dice.
//!
//! # Che cosa non c'è
//!
//! Nessuna copia dell'archivio verso il client, nessun elenco con i testi,
//! nessun «scrivi comunque» sul conflitto.

use lisi_core::ContentId;
use lisi_core::Timestamp;
use lisi_core::model::hub_access::HubAction;
use lisi_core::model::hub_command::{
    CommandId, CommandKey, CommandOutcome, CommandVerdict, Conflict,
};
use lisi_core::model::hub_event::{HubEventKind, NewHubEvent};
use lisi_core::model::hub_review::{ReviewContent, ReviewItem, ReviewQueueCursor};
use lisi_core::model::identity::DeviceId;
use lisi_core::model::review::ReviewState;
use lisi_core::model::{NewAuditEntry, NewReview};
use lisi_core::text::{
    Actor, AuditAction, AuditDetail, AuditEntity, HubEventDetail, HubEventSubject, Note,
};

use crate::Database;
use crate::error::{ServiceError, ServiceResult};
use crate::hub_access::AuthenticatedDevice;
use crate::hub_commands::HubCommandService;
use crate::hub_people::AuthenticatedOperator;

/// Entità dell'audit di questo modulo.
const AUDIT_ENTITY: &str = "revisione_condivisa";
/// Soggetto degli atti decisi dalla regola, non da una persona.
const AUDIT_AUTHORITY: &str = "hub.revisione";

const AUDIT_READ: &str = "contenuto_letto";
const AUDIT_REFUSED_READ: &str = "lettura_rifiutata";
const AUDIT_CONFLICT: &str = "revisione_in_conflitto";

/// La revisione condivisa servita dall'Hub.
#[derive(Debug)]
pub struct HubReviewService {
    commands: HubCommandService,
}

impl HubReviewService {
    /// Costruisce il servizio sull'archivio dell'Hub.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self {
            commands: HubCommandService::new(database),
        }
    }

    /// Archivio sottostante.
    #[must_use]
    pub const fn database(&self) -> &Database {
        self.commands.database()
    }

    /// La pagina della coda di revisione.
    ///
    /// **Non tocca nulla e non registra nulla**: guardare l'elenco non è un
    /// atto sul materiale sorvegliato, perché l'elenco non lo contiene.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il cursore non è utilizzabile o se la lettura
    /// non riesce.
    pub fn queue(&self, cursor: ReviewQueueCursor) -> ServiceResult<Vec<ReviewItem>> {
        Ok(self.database().hub_review_queue(cursor)?)
    }

    /// Consegna **un** contenuto da rivedere, e registra chi lo ha chiesto.
    ///
    /// Restituisce `None` quando il contenuto non esiste o non è stato
    /// segnalato: la revisione condivisa riguarda ciò che il motore ha
    /// segnalato, e consegnare un contenuto qualsiasi trasformerebbe la
    /// richiesta in una lettura libera dell'archivio.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::HubForbidden`] se il ruolo del dispositivo
    /// non consente la lettura, o un errore se la lettura o l'audit non
    /// riescono.
    pub fn content_for(
        &self,
        device: &AuthenticatedDevice,
        content_id: ContentId,
        now: Timestamp,
    ) -> ServiceResult<Option<ReviewContent>> {
        if !device.role().permits(HubAction::ReadContent) {
            self.registra(
                AUDIT_REFUSED_READ,
                &format!(
                    "dispositivo {}: lettura del contenuto {} non consentita al ruolo {}",
                    device.device(),
                    content_id.get(),
                    device.role().label()
                ),
                now,
            )?;
            return Err(ServiceError::HubForbidden {
                reason: format!(
                    "il dispositivo ha il ruolo {} e {}",
                    device.role().label(),
                    HubAction::ReadContent.reason()
                ),
            });
        }

        let contenuto = self.database().hub_review_content(content_id)?;

        // OGNI LETTURA E' UN ATTO. Si registra anche quando il contenuto non
        // c'e': aver chiesto è un fatto, e l'assenza della riga farebbe
        // sembrare che nessuno abbia chiesto.
        self.registra(
            AUDIT_READ,
            &format!(
                "dispositivo {}: contenuto {} {}",
                device.device(),
                content_id.get(),
                if contenuto.is_some() {
                    "consegnato per la revisione"
                } else {
                    "non trovato fra quelli segnalati"
                }
            ),
            now,
        )?;

        Ok(contenuto)
    }

    /// Registra una revisione decisa su una postazione.
    ///
    /// Il comando è idempotente sulla coppia *(dispositivo, identificativo)*;
    /// `expected_version` è quante revisioni la postazione aveva visto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura, l'evento o l'audit non riescono.
    ///
    // Otto parametri, e ciascuno dice una cosa che questa decisione non può
    // indovinare: chi, quale comando, quale contenuto, contro quale versione,
    // quale stato, con quale motivo, e quando. Raccoglierli in una struttura
    // li nasconderebbe dietro un nome senza toglierne nessuno.
    #[allow(clippy::too_many_arguments)]
    #[allow(
        clippy::too_many_arguments,
        reason = "decidere ha bisogno di chi, da dove, su che cosa, contro quale versione, \
                  con quale stato e con quale motivazione"
    )]
    pub fn submit(
        &mut self,
        device: &AuthenticatedDevice,
        operator: Option<&AuthenticatedOperator>,
        command_id: CommandId,
        content_id: ContentId,
        expected_version: u64,
        state: ReviewState,
        note: Option<Note>,
        now: Timestamp,
    ) -> ServiceResult<CommandVerdict> {
        // LA MEMORIA DEL COMANDO VIENE PRIMA DELLA VERSIONE.
        //
        // Una ripetizione nasce dal caso per cui l'idempotenza esiste: la
        // decisione è arrivata, l'Hub l'ha registrata, e la risposta si è persa
        // per strada. Chi riprova ha in mano la versione di **prima**, che nel
        // frattempo è avanzata **per effetto del suo stesso comando**:
        // controllare la versione per primo gli risponderebbe «conflitto» e lo
        // manderebbe a cercare chi ha scritto, che è lui.
        //
        // Trovato dalla prova della ripetizione, scrivendola.
        let chiave = CommandKey {
            device: device.device().clone(),
            command_id: command_id.clone(),
        };
        if let Some(esito) = self.commands.outcome(&chiave)? {
            return Ok(CommandVerdict::Replay(esito));
        }

        let versione_corrente = self.database().hub_review_version(content_id)?;
        let precedente = self.database().hub_latest_review(content_id)?;
        let esistente = self.database().hub_review_content(content_id)?;
        // IL NOME DI CHI E' ENTRATO, QUANDO QUALCUNO E' ENTRATO.
        //
        // ADR-0094 (decisione 3) attribuiva alla postazione **finché**
        // un'identità di persona autenticata non esisteva, e prometteva che
        // sarebbe diventata la persona «senza riscrivere il passato».
        // TEAM-ASSIGN-01 l'ha costruita (ADR-0097), e la promessa si mantiene
        // qui: chi è entrato firma con il proprio nome, chi non è entrato
        // continua a firmare con la postazione, e le due forme si distinguono
        // a colpo d'occhio.
        let revisore = match operator {
            Some(entrato) => Actor::try_new(&entrato.actor())?,
            None => attore_della_postazione(device.device())?,
        };

        // MAI «VINCE CHI SCRIVE PER ULTIMO» (ADR-0089): chi scrive su una
        // versione superata riceve il conflitto, con che cosa c'è adesso e chi
        // ce l'ha messo. Il conflitto si decide **prima** del comando: non è un
        // esito da ricordare, è un invito a rileggere e a decidere di nuovo.
        if expected_version != versione_corrente {
            let (stato, chi) = match &precedente {
                Some((stato, chi, _)) => (Some(*stato), Some(chi.clone())),
                None => (None, None),
            };
            let conflitto = Conflict {
                current_version: versione_corrente,
                expected_version,
                subject: HubEventSubject::try_new(&format!("contenuto {}", content_id.get()))?,
                current_value: stato
                    .map(|stato| HubEventDetail::try_new(stato.as_str()))
                    .transpose()?,
                written_by: chi.as_deref().and_then(dispositivo_dal_revisore),
            };
            self.registra(
                AUDIT_CONFLICT,
                &format!(
                    "dispositivo {}: contenuto {} è alla versione {} e la revisione ne \
                     dichiarava {}",
                    device.device(),
                    content_id.get(),
                    versione_corrente,
                    expected_version
                ),
                now,
            )?;
            return Ok(CommandVerdict::Conflict(conflitto));
        }

        self.commands.execute(
            device,
            command_id,
            HubAction::ReviewContent,
            now,
            |transaction| {
                // IL CONTENUTO DEVE ESISTERE ED ESSERE STATO SEGNALATO: una
                // decisione su qualcosa che l'Hub non ha segnalato sarebbe una
                // riga senza il fatto che la giustifica.
                if esistente.is_none() {
                    return Ok(CommandOutcome::Refused {
                        reason: HubEventDetail::try_new(
                            "il contenuto non risulta fra quelli segnalati da questo Hub",
                        )?,
                    });
                }

                lisi_storage::Database::insert_review_in(
                    transaction,
                    &NewReview {
                        content_id,
                        state,
                        reviewer: revisore.clone(),
                        note: note.clone(),
                        decided_at: now,
                    },
                )?;

                let evento = NewHubEvent {
                    kind: HubEventKind::ReviewRecorded,
                    subject: HubEventSubject::try_new(&format!("contenuto {}", content_id.get()))?,
                    detail: Some(HubEventDetail::try_new(&format!(
                        "{} da {}",
                        state.as_str(),
                        revisore.as_str()
                    ))?),
                };
                lisi_storage::repository::hub_event::append_hub_event_in(
                    transaction,
                    &evento,
                    now,
                )?;

                Ok(CommandOutcome::Done {
                    detail: Some(HubEventDetail::try_new(&format!(
                        "revisione registrata: {}",
                        state.as_str()
                    ))?),
                })
            },
        )
    }

    fn registra(&self, azione: &str, dettaglio: &str, now: Timestamp) -> ServiceResult<()> {
        let voce = NewAuditEntry {
            actor: Actor::try_new(AUDIT_AUTHORITY)?,
            action: AuditAction::try_new(azione)?,
            entity: AuditEntity::try_new(AUDIT_ENTITY)?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(dettaglio)?),
            recorded_at: now,
        };
        self.database().append_audit(&voce)?;
        Ok(())
    }
}

/// Il nome con cui una postazione compare nel registro delle revisioni.
///
/// **È il dispositivo, non una persona** (ADR-0094, decisione 3): finché
/// un'identità di operatore autenticata non esiste, scrivere un nome di persona
/// significherebbe scriverne uno che nessuno ha verificato.
pub fn attore_della_postazione(device: &DeviceId) -> ServiceResult<Actor> {
    Ok(Actor::try_new(&format!("postazione.{device}"))?)
}

/// Il dispositivo che si legge da un revisore conservato, se è una postazione.
fn dispositivo_dal_revisore(revisore: &str) -> Option<DeviceId> {
    let resto = revisore.strip_prefix("postazione.")?;
    DeviceId::parse(resto).ok()
}

#[cfg(test)]
mod tests {
    use super::attore_della_postazione;
    use lisi_core::model::identity::{DEVICE_ID_BYTES, DeviceId};

    #[test]
    fn the_reviewer_is_the_station_and_says_so() {
        let dispositivo = DeviceId::from_random_bytes(&[3; DEVICE_ID_BYTES]);
        let Ok(attore) = attore_della_postazione(&dispositivo) else {
            panic!("l'attore deve potersi costruire");
        };
        assert!(
            attore.as_str().starts_with("postazione."),
            "il registro deve dire che a rivedere e' stata una postazione: «{}»",
            attore.as_str()
        );
        assert!(attore.as_str().contains(dispositivo.as_str()));
    }

    #[test]
    fn a_reviewer_that_is_not_a_station_is_not_read_as_a_device() {
        assert!(super::dispositivo_dal_revisore("operatore.mario").is_none());
    }
}

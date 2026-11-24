//! A chi è il lavoro, dal lato dell'Hub (TEAM-ASSIGN-01, ADR-0098).
//!
//! # Un atto solo, tre verbi
//!
//! Prendere in carico, assegnare e revocare sono **lo stesso fatto**: questo
//! contenuto è di questa persona, oppure di nessuno. Due verbi per lo stesso
//! fatto darebbero due storie dello stesso contenuto, e nessuna delle due
//! sarebbe sbagliata in modo riconoscibile.
//!
//! # Il più restrittivo dei due vince
//!
//! L'atto lo compie una **persona** da una **postazione**, e devono consentirlo
//! tutte e due (ADR-0097, decisione 8). Il motore dei comandi controlla il
//! dispositivo; qui si controlla la persona, e il rifiuto è un **esito che si
//! ricorda**: ripeterlo non deve diventare un secondo tentativo.
//!
//! # La memoria del comando viene prima della versione
//!
//! È il difetto trovato costruendo TEAM-REVIEW-01, e non si ripete: chi
//! riprova dopo una risposta persa ha in mano la versione di prima, e
//! controllare la versione per primo gli risponderebbe «conflitto» contro sé
//! stesso.

use lisi_core::ContentId;
use lisi_core::Timestamp;
use lisi_core::model::hub_access::HubAction;
use lisi_core::model::hub_command::{
    CommandId, CommandKey, CommandOutcome, CommandVerdict, Conflict,
};
use lisi_core::model::hub_event::{HubEventKind, NewHubEvent};
use lisi_core::model::hub_person::PersonId;
use lisi_core::model::review::ReviewState;
use lisi_core::text::{HubEventDetail, HubEventSubject};

use crate::Database;
use crate::error::ServiceResult;
use crate::hub_access::AuthenticatedDevice;
use crate::hub_commands::HubCommandService;
use crate::hub_people::AuthenticatedOperator;

/// L'assegnazione del lavoro, servita dall'Hub.
#[derive(Debug)]
pub struct HubAssignmentService {
    commands: HubCommandService,
}

impl HubAssignmentService {
    /// Costruisce il servizio sull'archivio dell'Hub.
    #[must_use]
    pub fn new(database: Database) -> Self {
        Self {
            commands: HubCommandService::new(database),
        }
    }

    /// L'archivio dell'Hub.
    #[must_use]
    pub const fn database(&self) -> &Database {
        self.commands.database()
    }

    /// Quanti cambi di assegnazione ha avuto un contenuto.
    ///
    /// È la versione che chi scrive deve dichiarare.
    ///
    /// # Errori
    ///
    /// Un errore di lettura.
    pub fn version(&self, content_id: ContentId) -> ServiceResult<u64> {
        Ok(self.database().hub_assignment_version(content_id)?)
    }

    /// Scrive a chi è un contenuto, o lo rimette a nessuno.
    ///
    /// `to` vale `None` per la revoca. Prendere in carico è passare il proprio
    /// identificativo: non è un verbo diverso (ADR-0098, decisione 1).
    ///
    /// # Errori
    ///
    /// Un errore se una lettura o una scrittura non riescono. Un comando
    /// **rifiutato non è un errore**: è un esito, e si ricorda.
    #[allow(
        clippy::too_many_arguments,
        reason = "assegnare ha bisogno di chi, da dove, a chi, che cosa e contro quale versione; \n                  raggrupparlo in una struttura nasconderebbe che sono cose distinte"
    )]
    pub fn submit(
        &mut self,
        device: &AuthenticatedDevice,
        operator: &AuthenticatedOperator,
        command_id: CommandId,
        content_id: ContentId,
        expected_version: u64,
        to: Option<PersonId>,
        now: Timestamp,
    ) -> ServiceResult<CommandVerdict> {
        // LA MEMORIA DEL COMANDO VIENE PRIMA DELLA VERSIONE (ADR-0094).
        let chiave = CommandKey {
            device: device.device().clone(),
            command_id: command_id.clone(),
        };
        if let Some(esito) = self.commands.outcome(&chiave)? {
            return Ok(CommandVerdict::Replay(esito));
        }

        let versione_corrente = self.database().hub_assignment_version(content_id)?;
        let adesso_di = self.database().hub_assignment(content_id)?;

        if expected_version != versione_corrente {
            let conflitto = Conflict {
                current_version: versione_corrente,
                expected_version,
                subject: HubEventSubject::try_new(&format!("contenuto {}", content_id.get()))?,
                current_value: Some(HubEventDetail::try_new(&chi_ce_l_ha(
                    adesso_di
                        .as_ref()
                        .and_then(|riga| riga.assigned_to.as_ref()),
                ))?),
                // Il conflitto della revisione dice **quale postazione** ha
                // scritto; qui chi ha scritto è una persona, e il campo del
                // conflitto porta dispositivi. Il nome di chi ce l'ha adesso
                // sta nel valore corrente, che è ciò che serve a chi rilegge.
                written_by: None,
            };
            return Ok(CommandVerdict::Conflict(conflitto));
        }

        let azione = azione_richiesta(
            operator,
            adesso_di
                .as_ref()
                .and_then(|riga| riga.assigned_to.as_ref()),
            to.as_ref(),
        );
        let persona_consente = operator.permits(azione);
        let attore = operator.actor();
        let destinatario = to.as_ref().map(|persona| String::from(persona.as_str()));

        self.commands
            .execute(device, command_id, azione, now, |transaction| {
                // IL PIÙ RESTRITTIVO DEI DUE VINCE (ADR-0097, decisione 8).
                if !persona_consente {
                    return Ok(CommandOutcome::Refused {
                        reason: HubEventDetail::try_new(&format!(
                            "la persona ha il ruolo {} e l'azione è riservata: {}",
                            operator.role().label(),
                            azione.reason()
                        ))?,
                    });
                }

                // SI ASSEGNA SOLO A CHI ESISTE ED È ATTIVO, e si guarda
                // **dentro la transazione** che scrive: guardare prima
                // lascerebbe una finestra in cui la persona viene sospesa fra
                // il controllo e la scrittura (ADR-0098, decisione 4).
                if let Some(a_chi) = destinatario.as_deref()
                    && !lisi_storage::Database::hub_person_is_active_in(transaction, a_chi)?
                {
                    return Ok(CommandOutcome::Refused {
                        reason: HubEventDetail::try_new(
                            "la persona indicata non esiste o non è attiva",
                        )?,
                    });
                }

                // UN CONTENUTO GIÀ DECISO NON SI ASSEGNA: assegnare lavoro già
                // fatto è lavoro doppio con un nome sopra.
                if destinatario.is_some()
                    && let Some(stato) =
                        lisi_storage::Database::hub_review_state_in(transaction, content_id)?
                    && stato_deciso(stato)
                {
                    return Ok(CommandOutcome::Refused {
                        reason: HubEventDetail::try_new(
                            "il contenuto è già stato deciso: non c'è lavoro da assegnare",
                        )?,
                    });
                }

                lisi_storage::Database::set_hub_assignment_in(
                    transaction,
                    content_id,
                    destinatario.as_deref(),
                    &attore,
                    now,
                )?;

                let evento = NewHubEvent {
                    kind: HubEventKind::WorkAssigned,
                    subject: HubEventSubject::try_new(&format!("contenuto {}", content_id.get()))?,
                    detail: Some(HubEventDetail::try_new(&format!(
                        "{} da {attore}",
                        chi_ce_l_ha(to.as_ref())
                    ))?),
                };
                lisi_storage::repository::hub_event::append_hub_event_in(
                    transaction,
                    &evento,
                    now,
                )?;

                Ok(CommandOutcome::Done {
                    detail: Some(HubEventDetail::try_new(&chi_ce_l_ha(to.as_ref()))?),
                })
            })
    }
}

/// Che azione è, davvero.
///
/// Prendere in carico è assegnare a sé stessi; restituire il proprio lavoro è
/// la stessa cosa al contrario. Dare o togliere lavoro **a un altro** è una
/// decisione sull'ufficio.
fn azione_richiesta(
    operator: &AuthenticatedOperator,
    adesso_di: Option<&PersonId>,
    a_chi: Option<&PersonId>,
) -> HubAction {
    match (a_chi, adesso_di) {
        // «Lo prendo io.»
        (Some(destinatario), _) if destinatario == operator.person() => HubAction::TakeCharge,
        // «Lo restituisco»: revoca di ciò che si ha in mano.
        (None, Some(chi)) if chi == operator.person() => HubAction::TakeCharge,
        _ => HubAction::AssignWork,
    }
}

/// Come si dice, in una riga, di chi è il lavoro.
fn chi_ce_l_ha(a_chi: Option<&PersonId>) -> String {
    match a_chi {
        Some(persona) => format!("assegnato a {persona}"),
        None => String::from("assegnato a nessuno"),
    }
}

/// Se lo stato di una revisione chiude il lavoro.
///
/// «Nuovo» e «in esame» non lo chiudono: il lavoro è ancora da fare, e
/// assegnarlo ha senso.
const fn stato_deciso(state: ReviewState) -> bool {
    !matches!(state, ReviewState::New | ReviewState::InReview)
}

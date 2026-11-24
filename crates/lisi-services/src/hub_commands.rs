//! I comandi dell'Hub: autorizzati, eseguiti una volta sola, con riscontro
//! (HUB-CMD-01, ADR-0089).
//!
//! # Che cosa tiene insieme
//!
//! Un comando che modifica attraversa **quattro** cose che devono essere
//! atomiche o non esserlo affatto:
//!
//! 1. **l'autorizzazione** del dispositivo che lo manda (ADR-0085): non si può
//!    chiamare [`HubCommandService::execute`] senza dire **quale azione** è, e
//!    quindi non la si può dimenticare;
//! 2. **l'effetto** sull'archivio;
//! 3. **l'evento** nella sequenza autorevole (ADR-0086), se l'effetto ne
//!    produce uno;
//! 4. **la memoria del comando** (ADR-0042, decisione 8), che è ciò che una
//!    ripetizione riceve.
//!
//! Le ultime tre stanno nella **stessa transazione**. Separarle lascerebbe
//! istanti in cui una sola esiste, e ciascuno di quegli istanti è un modo di
//! raddoppiare o di perdere.
//!
//! # Che cosa non fa
//!
//! Non conosce i comandi: li esegue. Quali comandi esistano, che cosa scrivano
//! e quale versione controllino è delle milestone che li portano (TEAM-*).

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::model::hub_access::HubAction;
use lisi_core::model::hub_command::{CommandId, CommandKey, CommandOutcome, CommandVerdict};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity, HubEventDetail};
use lisi_storage::error::StorageResult;

use crate::Database;
use crate::error::ServiceResult;
use crate::hub_access::AuthenticatedDevice;

/// Entità dell'audit di questo modulo.
const AUDIT_ENTITY: &str = "comandi_hub";
/// Soggetto degli atti decisi dalla regola.
const AUDIT_AUTHORITY: &str = "hub.comandi";

const AUDIT_APPLIED: &str = "comando_eseguito";
const AUDIT_REPLAYED: &str = "comando_ripetuto";
const AUDIT_REFUSED: &str = "comando_rifiutato";

/// L'esecutore dei comandi dell'Hub.
#[derive(Debug)]
pub struct HubCommandService {
    database: Database,
}

impl HubCommandService {
    /// Costruisce l'esecutore sull'archivio dell'Hub.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Archivio sottostante.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Esegue un comando **una volta sola**, se il dispositivo può.
    ///
    /// - Se il ruolo non consente l'azione, il comando è **rifiutato**, e il
    ///   rifiuto si ricorda: ripeterlo restituisce lo stesso rifiuto, non un
    ///   secondo tentativo.
    /// - Se la coppia *(dispositivo, identificativo)* è già stata vista,
    ///   `effetto` **non viene chiamato**.
    /// - Altrimenti `effetto` scrive dentro la transazione del comando.
    ///
    /// # Errori
    ///
    /// L'errore dell'effetto, o un errore d'archivio o d'audit.
    pub fn execute<E>(
        &mut self,
        device: &AuthenticatedDevice,
        command_id: CommandId,
        action: HubAction,
        now: Timestamp,
        effetto: E,
    ) -> ServiceResult<CommandVerdict>
    where
        E: FnOnce(&lisi_storage::Transaction<'_>) -> StorageResult<CommandOutcome>,
    {
        let key = CommandKey {
            device: device.device().clone(),
            command_id,
        };
        let consentito = device.role().permits(action);

        let verdetto = self.database.apply_command_once(&key, now, |transaction| {
            if consentito {
                effetto(transaction)
            } else {
                // Il rifiuto per permesso è un esito, e si ricorda: ripetere
                // non deve diventare un secondo tentativo.
                Ok(CommandOutcome::Refused {
                    reason: HubEventDetail::try_new(&format!(
                        "il dispositivo ha il ruolo {} e l'azione è riservata: {}",
                        device.role().label(),
                        action.reason()
                    ))?,
                })
            }
        })?;

        let (azione, dettaglio) = match &verdetto {
            CommandVerdict::Applied(CommandOutcome::Done { .. }) => (
                AUDIT_APPLIED,
                format!(
                    "dispositivo {}: {} ({})",
                    key.device,
                    action.as_str(),
                    key.command_id.as_str()
                ),
            ),
            CommandVerdict::Applied(CommandOutcome::Refused { reason }) => (
                AUDIT_REFUSED,
                format!(
                    "dispositivo {}: {} ({}) — {}",
                    key.device,
                    action.as_str(),
                    key.command_id.as_str(),
                    reason.as_str()
                ),
            ),
            CommandVerdict::Replay(_) => (
                AUDIT_REPLAYED,
                format!(
                    "dispositivo {}: {} ({}) — già visto, nulla è stato rieseguito",
                    key.device,
                    action.as_str(),
                    key.command_id.as_str()
                ),
            ),
            CommandVerdict::Conflict(conflitto) => (
                AUDIT_REFUSED,
                format!(
                    "dispositivo {}: {} ({}) — conflitto sulla versione {}",
                    key.device,
                    action.as_str(),
                    key.command_id.as_str(),
                    conflitto.current_version
                ),
            ),
        };
        self.registra(azione, &dettaglio, now)?;
        Ok(verdetto)
    }

    /// L'esito di un comando già visto, se c'è.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn outcome(&self, key: &CommandKey) -> ServiceResult<Option<CommandOutcome>> {
        Ok(self.database.command_outcome(key)?)
    }

    fn registra(&self, azione: &str, dettaglio: &str, now: Timestamp) -> ServiceResult<()> {
        let entry = NewAuditEntry {
            actor: Actor::try_new(AUDIT_AUTHORITY)?,
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
    use lisi_core::Timestamp;
    use lisi_core::model::hub_access::HubAction;
    use lisi_core::model::hub_command::{CommandId, CommandKey, CommandOutcome, CommandVerdict};
    use lisi_core::model::hub_event::{HubEventKind, NewHubEvent};
    use lisi_core::model::identity::{DEVICE_ID_BYTES, DeviceId};
    use lisi_core::role::RestrictedAction;
    use lisi_core::text::{HubEventDetail, HubEventSubject};
    use lisi_storage::repository::hub_event::append_hub_event_in;

    use super::HubCommandService;
    use crate::hub_access::{AccessOutcome, HubAccessService};

    fn adesso() -> Timestamp {
        Timestamp::from_millis(1_758_800_000_000)
    }

    fn identificativo(testo: &str) -> CommandId {
        let Ok(valore) = CommandId::parse(testo) else {
            panic!("identificativo di prova");
        };
        valore
    }

    fn azione() -> HubAction {
        HubAction::Restricted(RestrictedAction::ConfigureSources)
    }

    /// Un Hub con un dispositivo autenticato, e il ruolo richiesto.
    fn hub_con_dispositivo(
        amministratore: bool,
    ) -> (HubCommandService, crate::hub_access::AuthenticatedDevice) {
        use lisi_core::model::enrollment::{DeviceToken, EnrollmentRequest, EnrollmentSalt};
        use lisi_core::model::hub_access::HubRole;
        use lisi_core::model::identity::{DeviceSecret, OperatorId};
        use lisi_core::text::DisplayName;

        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("archivio di prova");
        };
        let Ok(nome) = DisplayName::try_new("Hub di prova") else {
            panic!("nome");
        };
        let Ok(operatore) = OperatorId::try_new("amministratore.hub") else {
            panic!("operatore");
        };
        let mut arruolamento = crate::hub_enrollment::HubEnrollmentService::new(database, nome);
        let Ok(emesso) = arruolamento.issue_code(&operatore, adesso()) else {
            panic!("codice");
        };
        let salt = EnrollmentSalt::from_random_bytes(&[6; 16]);
        let token = DeviceToken::derive(&salt, &DeviceSecret::from_random_bytes([6; 32]));
        let dispositivo = DeviceId::from_random_bytes(&[6; DEVICE_ID_BYTES]);
        let Ok(etichetta) = DisplayName::try_new("Postazione 6") else {
            panic!("etichetta");
        };
        let richiesta = EnrollmentRequest {
            device_id: dispositivo.clone(),
            label: etichetta,
            code: emesso.code.clone(),
            salt,
            verifier: token.verifier(),
        };
        let Ok(esito) = arruolamento.admit(&richiesta, adesso()) else {
            panic!("ammissione");
        };
        assert!(esito.is_admitted());

        let mut accesso = HubAccessService::new(arruolamento.into_database());
        if amministratore {
            let Ok(true) =
                accesso.assign_role(&dispositivo, HubRole::Administrator, &operatore, adesso())
            else {
                panic!("assegnazione del ruolo");
            };
        }
        let Ok(AccessOutcome::Entered(entrato)) =
            accesso.authenticate(&dispositivo, &token.verifier(), "192.0.2.6", adesso())
        else {
            panic!("autenticazione");
        };
        // Il servizio dei comandi lavora sullo stesso archivio.
        (HubCommandService::new(accesso.into_database()), entrato)
    }

    fn evento_di_prova(
        transaction: &lisi_storage::Transaction<'_>,
    ) -> lisi_storage::error::StorageResult<()> {
        let Ok(subject) = HubEventSubject::try_new("perimetro di prova") else {
            panic!("soggetto");
        };
        let evento = NewHubEvent {
            kind: HubEventKind::DeviceRoleChanged,
            subject,
            detail: None,
        };
        append_hub_event_in(transaction, &evento, adesso())?;
        Ok(())
    }

    #[test]
    fn a_command_runs_once_and_its_event_is_written_in_the_same_transaction() {
        let (mut comandi, dispositivo) = hub_con_dispositivo(true);
        let id = identificativo("comando-abc");

        let Ok(CommandVerdict::Applied(CommandOutcome::Done { .. })) = comandi.execute(
            &dispositivo,
            id.clone(),
            azione(),
            adesso(),
            |transaction| {
                evento_di_prova(transaction)?;
                Ok(CommandOutcome::Done {
                    detail: HubEventDetail::try_new("fatto").ok(),
                })
            },
        ) else {
            panic!("il comando deve essere eseguito");
        };
        let Ok(prima) = comandi.database().latest_hub_sequence() else {
            panic!("sequenza");
        };

        // La ripetizione non riesegue, e non scrive un secondo evento.
        let Ok(CommandVerdict::Replay(CommandOutcome::Done { detail })) =
            comandi.execute(&dispositivo, id, azione(), adesso(), |_| {
                panic!("un comando già visto non si riesegue")
            })
        else {
            panic!("la ripetizione deve restituire l'esito di allora");
        };
        assert_eq!(
            detail.map(|d| d.as_str().to_owned()),
            Some(String::from("fatto"))
        );
        assert_eq!(comandi.database().latest_hub_sequence().ok(), Some(prima));
    }

    #[test]
    fn a_role_that_does_not_allow_the_action_refuses_and_the_refusal_is_remembered() {
        let (mut comandi, operatore) = hub_con_dispositivo(false);
        let id = identificativo("comando-negato");

        let Ok(CommandVerdict::Applied(CommandOutcome::Refused { reason })) =
            comandi.execute(&operatore, id.clone(), azione(), adesso(), |_| {
                panic!("l'effetto non deve essere eseguito senza permesso")
            })
        else {
            panic!("un operatore non configura le fonti dell'Hub");
        };
        assert!(reason.as_str().contains("Operatore"));

        let Ok(CommandVerdict::Replay(CommandOutcome::Refused { .. })) =
            comandi.execute(&operatore, id, azione(), adesso(), |_| {
                panic!("nemmeno la ripetizione esegue")
            })
        else {
            panic!("ripetere un comando rifiutato restituisce lo stesso rifiuto");
        };
    }

    #[test]
    fn the_outcome_of_a_seen_command_can_be_asked_again() {
        let (mut comandi, dispositivo) = hub_con_dispositivo(true);
        let id = identificativo("comando-xyz");
        let _ = comandi.execute(&dispositivo, id.clone(), azione(), adesso(), |_| {
            Ok(CommandOutcome::Done { detail: None })
        });
        let chiave = CommandKey {
            device: dispositivo.device().clone(),
            command_id: id,
        };
        assert!(matches!(
            comandi.outcome(&chiave).ok().flatten(),
            Some(CommandOutcome::Done { .. })
        ));
    }

    #[test]
    fn every_command_leaves_a_line_that_says_which_and_how_it_ended() {
        let (mut comandi, dispositivo) = hub_con_dispositivo(true);
        let id = identificativo("comando-audit");
        let _ = comandi.execute(&dispositivo, id.clone(), azione(), adesso(), |_| {
            Ok(CommandOutcome::Done { detail: None })
        });
        let _ = comandi.execute(&dispositivo, id, azione(), adesso(), |_| {
            Ok(CommandOutcome::Done { detail: None })
        });

        let Ok(voci) = comandi.database().audit_entries() else {
            panic!("audit");
        };
        let azioni: Vec<String> = voci
            .iter()
            .filter(|voce| voce.entity.as_str() == "comandi_hub")
            .map(|voce| voce.action.as_str().to_owned())
            .collect();
        assert_eq!(azioni, vec!["comando_eseguito", "comando_ripetuto"]);
    }
}

//! I comandi a distanza dei monitoraggi dell'Hub (HUB-REMOTE-01, ADR-0200,
//! DEC-492).
//!
//! # Chi decide
//!
//! L'Hub accetta comandi a distanza soltanto se chi lo amministra lo ha
//! scelto: è la nona azione riservata, e di fabbrica è spenta ([`choose`]).
//!
//! # Le stesse regole di chi è davanti all'Hub
//!
//! [`execute`] passa dalle funzioni del servizio dei monitoraggi: la pausa, la
//! ripresa, l'arresto. Un monitoraggio che non lo ammette rifiuta con la
//! stessa frase che leggerebbe chi è davanti all'Hub (decisione 4).
//!
//! # Tutto si scrive
//!
//! Ogni comando ricevuto, eseguito o rifiutato, resta nel registro dell'Hub con
//! la sua riga d'audit (decisione 5); la postazione che lo ha dato lo scrive
//! nel proprio audit con [`record_sent`] (decisione 6). Lo stesso
//! identificativo non esegue due volte (decisione 7).

use std::path::Path;

use lisi_core::model::NewAuditEntry;
use lisi_core::model::hub_access::HubRole;
use lisi_core::model::hub_command::CommandId;
use lisi_core::model::hub_person::PersonId;
use lisi_core::model::reason::OperationalReason;
use lisi_core::model::remote_command::{RemoteAction, RemoteOutcome};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{OperatingMode, RestrictedAction, SessionId, Timestamp};
use lisi_storage::Database;
pub use lisi_storage::repository::remote_command::StoredRemoteCommand;

use crate::error::{ServiceError, ServiceResult};
use crate::monitoring::{MonitoringAction, MonitoringService};

/// L'azione d'audit della scelta.
pub const CHOICE_AUDIT_ACTION: &str = "comandi_a_distanza_scelti";
/// Quanti comandi ricevuti l'Hub mostra.
pub const SHOWN: usize = 20;
/// Il tetto del dettaglio d'audit che si scrive per un comando.
const DETTAGLIO_MASSIMO: usize = 1_000;

/// Che cosa l'Hub ha deciso di un comando.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteVerdict {
    /// Eseguito, con la frase che lo dice.
    Executed(String),
    /// Rifiutato, con la ragione.
    Refused(String),
    /// Lo stesso comando era già arrivato: l'esito di allora, senza rieseguire.
    Replay(RemoteOutcome, String),
}

/// Un comando come l'Hub lo riceve, da una persona già entrata.
#[derive(Debug, Clone, Copy)]
pub struct RemoteCommandRequest<'a> {
    /// L'identificativo che la postazione gli ha dato.
    pub command_id: &'a str,
    /// Da quale postazione.
    pub device: &'a str,
    /// Chi: la persona entrata presso l'Hub con la propria frase.
    pub person: &'a PersonId,
    /// Il suo ruolo presso l'Hub.
    pub role: HubRole,
    /// Su quale monitoraggio.
    pub session_id: SessionId,
    /// Il nome stabile dell'atto.
    pub action: &'a str,
    /// Il motivo, come è stato scritto.
    pub reason: &'a str,
}

/// Se l'Hub accetta comandi a distanza.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn accepted(database: &Database) -> ServiceResult<bool> {
    Ok(database.remote_commands_accepted()?)
}

/// Che cosa vale, in una frase.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn status_sentence(database: &Database) -> ServiceResult<String> {
    Ok(if accepted(database)? {
        String::from(
            "Questo Hub accetta comandi a distanza: una persona entrata da un'altra postazione può \
             mettere in pausa, riprendere o arrestare un monitoraggio, con un motivo.",
        )
    } else {
        String::from("Questo Hub non accetta comandi a distanza.")
    })
}

/// Accende o spegne i comandi a distanza. Soltanto l'amministratore.
///
/// # Errori
///
/// [`ServiceError::ActionReservedToAdministrator`] in modalità operatore; un
/// errore se la scrittura non riesce.
pub fn choose(
    database: &mut Database,
    accept: bool,
    mode: OperatingMode,
    actor: &Actor,
    now: Timestamp,
) -> ServiceResult<String> {
    if !mode.allows(RestrictedAction::ChooseRemoteCommands) {
        return Err(ServiceError::ActionReservedToAdministrator {
            action: RestrictedAction::ChooseRemoteCommands,
        });
    }
    let audit = NewAuditEntry {
        actor: actor.clone(),
        action: AuditAction::try_new(CHOICE_AUDIT_ACTION)?,
        entity: AuditEntity::try_new("postazione")?,
        entity_id: None,
        actor_mode: Some(mode),
        detail: Some(AuditDetail::try_new(if accept {
            "accettati"
        } else {
            "non accettati"
        })?),
        recorded_at: now,
    };
    database.save_remote_commands_accepted(accept, actor, &audit)?;
    Ok(String::from(if accept {
        "L'Hub accetta comandi a distanza. Ogni comando resta nel registro, con chi lo ha dato e \
         perché."
    } else {
        "L'Hub non accetta più comandi a distanza."
    }))
}

/// I comandi ricevuti, i più recenti prima.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn recent(database: &Database) -> ServiceResult<Vec<StoredRemoteCommand>> {
    Ok(database.remote_commands(SHOWN)?)
}

/// Un comando ricevuto, in una frase per chi è davanti all'Hub.
#[must_use]
pub fn as_sentence(riga: &StoredRemoteCommand) -> String {
    let atto = RemoteAction::parse(&riga.action).map_or("un atto sconosciuto", RemoteAction::label);
    let esito = if riga.outcome == RemoteOutcome::Executed.as_str() {
        "eseguito"
    } else {
        "rifiutato"
    };
    format!(
        "{}: {} dalla postazione {} chiede di {atto} sul monitoraggio n. {}, perché «{}». \
         {esito}: {}.",
        riga.received_at.to_readable_local(),
        riga.person,
        riga.device,
        riga.session_id,
        riga.reason,
        riga.detail
    )
}

/// Esegue o rifiuta un comando ricevuto, e lo scrive (ADR-0200).
///
/// `archive` è l'archivio dell'Hub: il comando passa dal servizio dei
/// monitoraggi su quello stesso archivio.
///
/// # Errori
///
/// Restituisce un errore se l'archivio non si apre o la scrittura del registro
/// non riesce. Un comando che l'Hub non esegue **non** è un errore: è un
/// [`RemoteVerdict::Refused`] con la ragione.
pub fn execute(
    archive: &Path,
    request: &RemoteCommandRequest<'_>,
    now: Timestamp,
) -> ServiceResult<RemoteVerdict> {
    let mut registro = Database::open(archive)?;
    // UN IDENTIFICATIVO CHE NON SI SCRIVE NON SI REGISTRA: il protocollo lo ha
    // già controllato, e qui si rifiuta senza scrivere una riga che lo schema
    // non accetterebbe.
    if CommandId::parse(request.command_id).is_err() {
        return Ok(RemoteVerdict::Refused(String::from(
            "il comando non porta un identificativo utilizzabile",
        )));
    }
    if let Some(gia) = registro.remote_command(request.command_id)? {
        if gia.device != request.device || gia.person != request.person.as_str() {
            return Ok(RemoteVerdict::Refused(String::from(
                "questo identificativo appartiene già a un altro comando",
            )));
        }
        let esito = RemoteOutcome::parse(&gia.outcome)?;
        return Ok(RemoteVerdict::Replay(esito, gia.detail));
    }
    let Ok(atto) = RemoteAction::parse(request.action) else {
        return Ok(RemoteVerdict::Refused(String::from(
            "l'Hub non riconosce questo comando",
        )));
    };

    let attore = attore(request)?;
    let esito = decidi(archive, &registro, request, atto, &attore, now);
    let (verdetto, esito_registro, dettaglio) = match esito {
        Ok(frase) => (
            RemoteVerdict::Executed(frase.clone()),
            RemoteOutcome::Executed,
            frase,
        ),
        Err(ragione) => (
            RemoteVerdict::Refused(ragione.clone()),
            RemoteOutcome::Refused,
            ragione,
        ),
    };
    let riga = StoredRemoteCommand {
        command_id: String::from(request.command_id),
        device: String::from(request.device),
        person: String::from(request.person.as_str()),
        session_id: request.session_id.get(),
        action: String::from(atto.as_str()),
        reason: request.reason.trim().chars().take(500).collect(),
        outcome: String::from(esito_registro.as_str()),
        detail: dettaglio.clone(),
        received_at: now,
    };
    let audit = NewAuditEntry {
        actor: attore,
        action: AuditAction::try_new(match esito_registro {
            RemoteOutcome::Executed => "comando_a_distanza_eseguito",
            RemoteOutcome::Refused => "comando_a_distanza_rifiutato",
        })?,
        entity: AuditEntity::try_new("monitoraggio")?,
        entity_id: Some(request.session_id.get()),
        actor_mode: None,
        detail: Some(AuditDetail::try_new(&tagliato(&format!(
            "{}: {}; motivo: {}",
            atto.as_str(),
            dettaglio,
            riga.reason
        )))?),
        recorded_at: now,
    };
    registro.insert_remote_command(&riga, &audit)?;
    Ok(verdetto)
}

/// Le regole, in ordine; `Err` è la ragione del rifiuto.
fn decidi(
    archive: &Path,
    registro: &Database,
    request: &RemoteCommandRequest<'_>,
    atto: RemoteAction,
    attore: &Actor,
    now: Timestamp,
) -> Result<String, String> {
    let rifiuto = |frase: &str| String::from(frase);
    match registro.remote_commands_accepted() {
        Ok(true) => {}
        Ok(false) => {
            return Err(rifiuto(
                "questo Hub non accetta comandi a distanza: lo decide chi lo amministra",
            ));
        }
        Err(_) => {
            return Err(rifiuto(
                "la scelta dell'Hub sui comandi a distanza non si legge",
            ));
        }
    }
    if !atto.allowed_to(request.role) {
        return Err(rifiuto(
            "arrestare un monitoraggio a distanza è riservato a chi amministra l'Hub",
        ));
    }
    let Ok(motivo) = OperationalReason::try_new(request.reason) else {
        return Err(rifiuto(
            "un comando a distanza porta un motivo di almeno venti caratteri",
        ));
    };
    match registro.sessions() {
        Ok(sessioni) if sessioni.iter().any(|riga| riga.id == request.session_id) => {}
        Ok(_) => return Err(rifiuto("questo monitoraggio non è nell'archivio dell'Hub")),
        Err(_) => return Err(rifiuto("i monitoraggi dell'Hub non si leggono")),
    }
    let mut monitoraggi = match Database::open(archive) {
        Ok(archivio) => MonitoringService::new(archivio),
        Err(_) => return Err(rifiuto("l'archivio dell'Hub non si apre")),
    };
    let eseguito = match atto {
        RemoteAction::Pause => {
            monitoraggi.pause_acquisition(request.session_id, attore, &motivo, now)
        }
        RemoteAction::Resume => monitoraggi.resume_acquisition(request.session_id, attore, now),
        RemoteAction::Stop => {
            monitoraggi.perform(request.session_id, MonitoringAction::Stop, attore, now)
        }
    };
    match eseguito {
        Ok(()) => Ok(String::from(match atto {
            RemoteAction::Pause => "acquisizione messa in pausa a distanza",
            RemoteAction::Resume => "acquisizione ripresa a distanza",
            RemoteAction::Stop => "monitoraggio arrestato a distanza",
        })),
        Err(errore) => Err(errore.operator_message()),
    }
}

/// Chi compare nell'audit: la persona e la postazione da cui ha comandato.
fn attore(request: &RemoteCommandRequest<'_>) -> ServiceResult<Actor> {
    let nome: String = format!("{}@{}", request.person.as_str(), request.device)
        .chars()
        .take(128)
        .collect();
    Ok(Actor::try_new(&nome)?)
}

fn tagliato(testo: &str) -> String {
    testo.chars().take(DETTAGLIO_MASSIMO).collect()
}

/// Scrive nell'audit della postazione il comando dato e la risposta dell'Hub
/// (ADR-0200, decisione 6).
///
/// # Errori
///
/// Restituisce un errore se la scrittura non riesce.
pub fn record_sent(
    database: &Database,
    actor: &Actor,
    session_id: SessionId,
    action: RemoteAction,
    reason: &str,
    answer: &str,
    now: Timestamp,
) -> ServiceResult<()> {
    database.append_audit(&NewAuditEntry {
        actor: actor.clone(),
        action: AuditAction::try_new("comando_a_distanza_dato")?,
        entity: AuditEntity::try_new("monitoraggio_hub")?,
        entity_id: Some(session_id.get()),
        actor_mode: None,
        detail: Some(AuditDetail::try_new(&tagliato(&format!(
            "{}; motivo: {}; risposta dell'Hub: {answer}",
            action.as_str(),
            reason.trim()
        )))?),
        recorded_at: now,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use lisi_core::model::hub_access::HubRole;
    use lisi_core::model::hub_person::PersonId;
    use lisi_core::model::{NewSession, NewSource, SessionDuration, SessionState, SourceKind};
    use lisi_core::text::{Actor, DisplayName, SourceIdentifier};
    use lisi_core::{OperatingMode, SessionId, Timestamp};
    use lisi_storage::Database;

    use super::{RemoteCommandRequest, RemoteVerdict, choose, execute, recent};
    use crate::error::ServiceError;

    const MOTIVO: &str = "la fonte pubblica dati di una persona per errore";

    fn al(minuti: i64) -> Timestamp {
        Timestamp::from_millis(1_800_000_000_000 + minuti * 60_000)
    }

    /// Un archivio dell'Hub con un monitoraggio in corso.
    fn hub() -> (tempfile::TempDir, std::path::PathBuf, SessionId) {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        let percorso = cartella.path().join("hub.sqlite");
        let Ok(mut archivio) = Database::open(&percorso) else {
            panic!("archivio di prova");
        };
        let (Ok(attore), Ok(identificativo), Ok(nome), Ok(etichetta)) = (
            Actor::try_new("operatore.hub"),
            SourceIdentifier::try_new("canale_sintetico"),
            DisplayName::try_new("Canale sintetico"),
            DisplayName::try_new("Monitoraggio sintetico"),
        ) else {
            panic!("valori di prova");
        };
        let Ok(fonte) = archivio.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier: identificativo,
                display_name: nome,
                authorized_by: attore.clone(),
                active: true,
            },
            al(0),
        ) else {
            panic!("fonte di prova");
        };
        let Ok(sessione) = archivio.insert_session(
            &NewSession {
                label: etichetta,
                started_by: attore,
                duration: SessionDuration::Preset { seconds: 36_000 },
                source_ids: vec![fonte],
            },
            al(1),
        ) else {
            panic!("monitoraggio di prova");
        };
        let Ok(()) = archivio.update_session_state(sessione, SessionState::Running, al(1)) else {
            panic!("il monitoraggio deve avviarsi");
        };
        (cartella, percorso, sessione)
    }

    fn persona(nome: &str) -> PersonId {
        let Ok(persona) = PersonId::parse(nome) else {
            panic!("persona di prova");
        };
        persona
    }

    fn accetta(percorso: &std::path::Path) {
        let (Ok(mut archivio), Ok(amministratore)) =
            (Database::open(percorso), Actor::try_new("amministratore"))
        else {
            panic!("archivio di prova");
        };
        let Ok(_) = choose(
            &mut archivio,
            true,
            OperatingMode::Administrator,
            &amministratore,
            al(2),
        ) else {
            panic!("l'amministratore accende i comandi a distanza");
        };
    }

    /// **Di fabbrica l'Hub non ascolta, e soltanto l'amministratore lo accende**
    /// (ADR-0200, decisione 3); il rifiuto resta nel registro.
    #[test]
    fn di_fabbrica_l_hub_non_accetta_e_lo_scrive() {
        let (_cartella, percorso, sessione) = hub();
        let chi = persona("mrossi");
        let richiesta = RemoteCommandRequest {
            command_id: "cmd-0001-pausa",
            device: "ABCD-EFGH",
            person: &chi,
            role: HubRole::Administrator,
            session_id: sessione,
            action: "pausa",
            reason: MOTIVO,
        };
        assert!(matches!(
            execute(&percorso, &richiesta, al(3)),
            Ok(RemoteVerdict::Refused(frase)) if frase.contains("non accetta")
        ));
        let (Ok(mut archivio), Ok(operatore)) =
            (Database::open(&percorso), Actor::try_new("operatore"))
        else {
            panic!("archivio di prova");
        };
        assert!(matches!(
            choose(
                &mut archivio,
                true,
                OperatingMode::Operator,
                &operatore,
                al(3)
            ),
            Err(ServiceError::ActionReservedToAdministrator { .. })
        ));
        let Ok(registro) = recent(&archivio) else {
            panic!("il registro si legge");
        };
        assert_eq!(registro.len(), 1);
        assert_eq!(registro[0].outcome, "rifiutato");
        assert_eq!(registro[0].person, "mrossi");
    }

    /// **Una pausa a distanza è la pausa di sempre, con nome e motivo; lo
    /// stesso comando ripetuto non esegue due volte** (decisioni 4, 5 e 7).
    #[test]
    fn la_pausa_a_distanza_e_quella_di_sempre_e_non_si_ripete() {
        let (_cartella, percorso, sessione) = hub();
        accetta(&percorso);
        let chi = persona("mrossi");
        let richiesta = RemoteCommandRequest {
            command_id: "cmd-0002-pausa",
            device: "ABCD-EFGH",
            person: &chi,
            role: HubRole::Operator,
            session_id: sessione,
            action: "pausa",
            reason: MOTIVO,
        };
        assert!(matches!(
            execute(&percorso, &richiesta, al(3)),
            Ok(RemoteVerdict::Executed(_))
        ));
        assert!(matches!(
            execute(&percorso, &richiesta, al(4)),
            Ok(RemoteVerdict::Replay(
                lisi_core::model::remote_command::RemoteOutcome::Executed,
                _
            ))
        ));
        let Ok(archivio) = Database::open(&percorso) else {
            panic!("archivio di prova");
        };
        assert_eq!(
            archivio.paused_session_ids().ok(),
            Some(vec![sessione]),
            "il monitoraggio è in pausa, una volta sola"
        );
        // Una seconda pausa, con un altro identificativo: la stessa frase di
        // chi è davanti all'Hub.
        let ancora = RemoteCommandRequest {
            command_id: "cmd-0003-pausa",
            ..richiesta
        };
        assert!(matches!(
            execute(&percorso, &ancora, al(5)),
            Ok(RemoteVerdict::Refused(_))
        ));
        let Ok(registro) = recent(&archivio) else {
            panic!("il registro si legge");
        };
        assert_eq!(
            registro.len(),
            2,
            "il comando ripetuto non fa una riga nuova"
        );
    }

    /// **Nessun comando senza motivo, e l'arresto soltanto da chi amministra**
    /// (decisioni 2 e 3).
    #[test]
    fn senza_motivo_o_senza_ruolo_non_si_arresta() {
        let (_cartella, percorso, sessione) = hub();
        accetta(&percorso);
        let chi = persona("mrossi");
        let senza_motivo = RemoteCommandRequest {
            command_id: "cmd-0004-pausa",
            device: "ABCD-EFGH",
            person: &chi,
            role: HubRole::Administrator,
            session_id: sessione,
            action: "pausa",
            reason: "ok",
        };
        assert!(matches!(
            execute(&percorso, &senza_motivo, al(3)),
            Ok(RemoteVerdict::Refused(frase)) if frase.contains("motivo")
        ));
        let arresto = RemoteCommandRequest {
            command_id: "cmd-0005-arresto",
            role: HubRole::Operator,
            action: "arresto",
            reason: MOTIVO,
            ..senza_motivo
        };
        assert!(matches!(
            execute(&percorso, &arresto, al(4)),
            Ok(RemoteVerdict::Refused(frase)) if frase.contains("riservato")
        ));
        let da_chi_amministra = RemoteCommandRequest {
            command_id: "cmd-0006-arresto",
            role: HubRole::Administrator,
            ..arresto
        };
        assert!(matches!(
            execute(&percorso, &da_chi_amministra, al(5)),
            Ok(RemoteVerdict::Executed(_))
        ));
        let Ok(archivio) = Database::open(&percorso) else {
            panic!("archivio di prova");
        };
        assert!(
            archivio
                .session(sessione)
                .is_ok_and(|riga| riga.state.is_final()),
            "il monitoraggio è arrestato"
        );
    }
}

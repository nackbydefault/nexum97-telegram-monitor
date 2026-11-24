//! L'elenco degli iscritti di una fonte, su richiesta motivata (MEMBERS-01,
//! ADR-0201).
//!
//! # Chi decide
//!
//! L'elenco si chiede soltanto se l'amministratore lo ha abilitato: è la
//! decima azione riservata, e di fabbrica è spento ([`choose`]).
//!
//! # Che cosa fa
//!
//! Per **una** fonte configurata, chiede a Telegram i suoi iscritti con le
//! richieste ufficiali, al più [`lisi_telegram::members::MAX_MEMBERS`].
//! Registra la richiesta, il motivo, l'esito e gli iscritti arrivati, con la
//! riga d'audit nella stessa transazione. Il telefono arriva già mascherato
//! dal connettore.
//!
//! # Che cosa non fa
//!
//! - Non parte senza l'autorità di acquisire né senza un motivo: la richiesta
//!   non si costruisce.
//! - Non parte se l'elenco non è abilitato, né per una fonte che non ha un
//!   identificativo di Telegram.
//! - Non ripete: una richiesta per gesto, e mai due troppo vicine.
//!
//! # Senza autorità, non compila
//!
//! ```compile_fail
//! use lisi_core::model::reason::OperationalReason;
//! use lisi_core::text::Actor;
//! use lisi_core::SourceId;
//! use lisi_services::members_listing::MembersListingRequest;
//!
//! fn da_un_client(operatore: Actor, ragione: OperationalReason) -> MembersListingRequest {
//!     MembersListingRequest::new(SourceId::new(1), operatore, ragione)
//! }
//! ```

use lisi_core::model::NewAuditEntry;
use lisi_core::model::reason::OperationalReason;
use lisi_core::model::telegram_account::AccountUuid;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{OperatingMode, RestrictedAction, SourceId, Timestamp};
use lisi_storage::Database;
use lisi_storage::repository::members_listing::{NewMemberRow, NewMembersListing};
pub use lisi_storage::repository::members_listing::{StoredMemberRow, StoredMembersListing};
use lisi_telegram::TelegramConnector;
use lisi_telegram::members::{MAX_MEMBERS, MembersReply};

use crate::acquisition_authority::AcquisitionAuthority;
use crate::error::{ServiceError, ServiceResult};

/// L'azione d'audit della scelta.
pub const CHOICE_AUDIT_ACTION: &str = "elenco_iscritti_scelto";
/// L'azione d'audit di una richiesta.
pub const REQUEST_AUDIT_ACTION: &str = "elenco_iscritti_chiesto";
/// Secondi, almeno, fra una richiesta e la successiva sulla postazione.
pub const MIN_SECONDS_BETWEEN: i64 = 60;
/// Quante richieste la schermata mostra.
pub const SHOWN: u32 = 20;

/// Una richiesta. **Vuole l'autorità di acquisizione e un motivo**: senza,
/// non esiste.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembersListingRequest {
    source_id: SourceId,
    operator: Actor,
    reason: OperationalReason,
}

impl MembersListingRequest {
    /// Costruisce la richiesta.
    #[must_use]
    pub const fn new(
        _autorita: &AcquisitionAuthority,
        source_id: SourceId,
        operator: Actor,
        reason: OperationalReason,
    ) -> Self {
        Self {
            source_id,
            operator,
            reason,
        }
    }
}

/// Com'è andata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembersListingAttempt {
    /// La richiesta è registrata, con il suo esito.
    Recorded {
        /// La riga della richiesta.
        id: i64,
        /// `ottenuto`, `rifiutato`, `non_riuscito` o `non_gruppo`.
        outcome: &'static str,
        /// La frase che lo dice.
        sentence: String,
    },
    /// Il prodotto ha rifiutato di chiedere: il perché. Nessuna richiesta.
    Refused(String),
}

/// Se l'elenco degli iscritti è abilitato.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn enabled(database: &Database) -> ServiceResult<bool> {
    Ok(database.members_listing_enabled()?)
}

/// Abilita o spegne l'elenco degli iscritti. Soltanto l'amministratore.
///
/// # Errori
///
/// [`ServiceError::ActionReservedToAdministrator`] in modalità operatore; un
/// errore se la scrittura non riesce.
pub fn choose(
    database: &mut Database,
    enable: bool,
    mode: OperatingMode,
    actor: &Actor,
    now: Timestamp,
) -> ServiceResult<String> {
    if !mode.allows(RestrictedAction::ChooseMembersListing) {
        return Err(ServiceError::ActionReservedToAdministrator {
            action: RestrictedAction::ChooseMembersListing,
        });
    }
    let audit = NewAuditEntry {
        actor: actor.clone(),
        action: AuditAction::try_new(CHOICE_AUDIT_ACTION)?,
        entity: AuditEntity::try_new("postazione")?,
        entity_id: None,
        actor_mode: Some(mode),
        detail: Some(AuditDetail::try_new(if enable {
            "abilitato"
        } else {
            "spento"
        })?),
        recorded_at: now,
    };
    database.save_members_listing_enabled(enable, actor, &audit)?;
    Ok(String::from(if enable {
        "Gli iscritti delle fonti si possono chiedere. Ogni richiesta vuole un motivo, e resta nel \
         registro."
    } else {
        "Gli iscritti delle fonti non si possono più chiedere."
    }))
}

/// La richiesta: i rifiuti prima di chiedere, poi **una** lettura, poi il
/// registro.
///
/// # Errori
///
/// Restituisce un errore se l'archivio non si legge o non si scrive.
pub fn request_members(
    connector: &mut dyn TelegramConnector,
    account: Option<&AccountUuid>,
    database: &mut Database,
    richiesta: &MembersListingRequest,
    now: Timestamp,
) -> ServiceResult<MembersListingAttempt> {
    if !database.members_listing_enabled()? {
        return Ok(MembersListingAttempt::Refused(String::from(
            "L'elenco degli iscritti non è abilitato: lo abilita l'amministratore, nelle \
             Impostazioni.",
        )));
    }
    let fonte = database.source(richiesta.source_id)?;
    let Ok(chat_id) = fonte.identifier.as_str().parse::<i64>() else {
        return Ok(MembersListingAttempt::Refused(String::from(
            "La fonte non ha un identificativo numerico di Telegram: gli iscritti si chiedono \
             soltanto per un gruppo collegato.",
        )));
    };
    if let Some(ultima) = database.last_members_listing_at()?
        && now.millis_since(ultima) < MIN_SECONDS_BETWEEN * 1_000
    {
        return Ok(MembersListingAttempt::Refused(format!(
            "Un'altra richiesta è partita da meno di {MIN_SECONDS_BETWEEN} secondi: riprovare fra \
             poco."
        )));
    }

    let mut registro = NewMembersListing {
        source_id: richiesta.source_id.get(),
        chat_id,
        account_uuid: account.map(|account| account.as_str().to_owned()),
        requested_by: richiesta.operator.as_str().to_owned(),
        reason: richiesta.reason.as_str().to_owned(),
        requested_at: now,
        outcome: "non_riuscito",
        outcome_detail: None,
        declared_total: None,
        stopped_at_cap: false,
    };
    let mut righe = Vec::new();
    // UNA lettura, e una sola. Nessuna ripetizione, qualunque sia l'esito.
    match connector.members_reader() {
        None => {
            registro.outcome_detail = Some(String::from(
                "Questo collegamento non offre l'elenco degli iscritti.",
            ));
        }
        Some(lettore) => match lettore.read_members(chat_id, MAX_MEMBERS) {
            Ok(MembersReply::Found(elenco)) => {
                registro.outcome = "ottenuto";
                registro.declared_total = elenco.declared_total;
                registro.stopped_at_cap = elenco.stopped_at_cap;
                righe = elenco
                    .members
                    .into_iter()
                    .map(|iscritto| NewMemberRow {
                        user_id: iscritto.user_id,
                        display_name: iscritto.display_name,
                        username: iscritto.username,
                        masked_phone: iscritto.masked_phone,
                        status: iscritto.status.as_str(),
                        joined_at: iscritto.joined_at_millis.map(Timestamp::from_millis),
                    })
                    .collect();
            }
            Ok(MembersReply::Refused { code, message }) => {
                registro.outcome = "rifiutato";
                registro.outcome_detail =
                    Some(format!("Telegram ha rifiutato ({code}): {message}"));
            }
            Ok(MembersReply::NotAGroup(frase)) => {
                registro.outcome = "non_gruppo";
                registro.outcome_detail = Some(frase);
            }
            Err(errore) => {
                registro.outcome_detail = Some(format!(
                    "La richiesta non è arrivata a una risposta: {}.",
                    crate::identity_resolver::connector_fault(&errore)
                ));
            }
        },
    }
    let sentence = outcome_sentence(
        registro.outcome,
        registro.outcome_detail.as_deref(),
        registro.declared_total,
        righe.len(),
        registro.stopped_at_cap,
    );
    let audit = NewAuditEntry {
        actor: richiesta.operator.clone(),
        action: AuditAction::try_new(REQUEST_AUDIT_ACTION)?,
        entity: AuditEntity::try_new("fonte")?,
        entity_id: None,
        actor_mode: None,
        detail: Some(AuditDetail::try_new(&format!(
            "fonte {}, motivo: «{}»: {}, {} iscritti",
            richiesta.source_id.get(),
            richiesta.reason.as_str(),
            registro.outcome,
            righe.len()
        ))?),
        recorded_at: now,
    };
    let outcome = registro.outcome;
    let id = database.insert_members_listing(&registro, &righe, &audit)?;
    Ok(MembersListingAttempt::Recorded {
        id,
        outcome,
        sentence,
    })
}

/// L'esito in una frase: quanti iscritti sono arrivati, su quanti dichiarati.
/// Un elenco parziale lo dice.
#[must_use]
pub fn outcome_sentence(
    outcome: &str,
    detail: Option<&str>,
    declared_total: Option<i64>,
    received: usize,
    stopped_at_cap: bool,
) -> String {
    if outcome != "ottenuto" {
        return detail.map_or_else(
            || String::from("La richiesta non ha dato un elenco."),
            str::to_owned,
        );
    }
    let arrivati = i64::try_from(received).unwrap_or(i64::MAX);
    let mut frase = match declared_total {
        Some(totale) if totale > arrivati => {
            format!(
                "Arrivati {arrivati} iscritti su {totale} dichiarati da Telegram: l'elenco è parziale."
            )
        }
        Some(totale) => format!("Arrivati {arrivati} iscritti su {totale} dichiarati da Telegram."),
        None => format!("Arrivati {arrivati} iscritti; Telegram non dichiara il totale."),
    };
    if stopped_at_cap {
        frase.push_str(&format!(
            " La richiesta si è fermata al tetto di {MAX_MEMBERS}: per gli altri serve un'altra \
             richiesta, con un altro motivo."
        ));
    }
    frase
}

/// Le richieste più recenti, dalla più nuova.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn recent(database: &Database) -> ServiceResult<Vec<StoredMembersListing>> {
    Ok(database.members_listings(SHOWN)?)
}

/// Gli iscritti di una richiesta.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn rows(database: &Database, listing_id: i64) -> ServiceResult<Vec<StoredMemberRow>> {
    Ok(database.members_listing_rows(listing_id)?)
}

#[cfg(test)]
mod tests {
    use lisi_core::model::reason::OperationalReason;
    use lisi_core::model::{NewSource, SourceKind};
    use lisi_core::text::{Actor, DisplayName, SourceIdentifier};
    use lisi_core::{OperatingMode, SourceId, Timestamp};
    use lisi_storage::Database;
    use lisi_telegram::members::{Member, MemberList, MemberStatus, MembersReply};
    use lisi_telegram::{
        ClientParameters, LoginCode, MockTelegramConnector, PhoneNumber, TelegramConnector,
    };

    use super::{
        MembersListingAttempt, MembersListingRequest, choose, outcome_sentence, request_members,
        rows,
    };
    use crate::acquisition_authority::{AcquisitionAuthority, StationAuthorityService};
    use crate::error::ServiceError;
    use crate::hub_client::HubConnectionStore;

    const CHAT: i64 = -1_001;

    fn adesso(secondi: i64) -> Timestamp {
        Timestamp::from_millis(1_800_000_000_000 + secondi * 1_000)
    }

    fn chi() -> Actor {
        let Ok(chi) = Actor::try_new("operatore.prova") else {
            panic!("valori di prova validi");
        };
        chi
    }

    fn archivio(identificativo: &str) -> (Database, SourceId) {
        let Ok(database) = Database::open_in_memory() else {
            panic!("l'archivio di prova si apre");
        };
        let (Ok(identificativo), Ok(nome)) = (
            SourceIdentifier::try_new(identificativo),
            DisplayName::try_new("Gruppo"),
        ) else {
            panic!("valori di prova validi");
        };
        let Ok(fonte) = database.insert_source(
            &NewSource {
                kind: SourceKind::Group,
                identifier: identificativo,
                display_name: nome,
                authorized_by: chi(),
                active: true,
            },
            adesso(0),
        ) else {
            panic!("la fonte si registra");
        };
        (database, fonte)
    }

    fn collegato() -> MockTelegramConnector {
        let mut mock = MockTelegramConnector::new();
        let (Ok(api_id), Ok(api_hash), Ok(telefono), Ok(codice)) = (
            lisi_telegram::ApiId::try_new(1),
            lisi_telegram::ApiHash::try_new("00000000000000000000000000000000"),
            PhoneNumber::try_new("+390000000000"),
            LoginCode::try_new("12345"),
        ) else {
            panic!("valori di prova validi");
        };
        let parametri = ClientParameters {
            api_id,
            api_hash,
            database_directory: std::path::PathBuf::from("sessione-di-prova"),
            use_test_datacenter: true,
            application_version: String::from("0.0.0-test"),
            system_language_code: String::from("it"),
        };
        assert!(mock.start(&parametri).is_ok());
        assert!(mock.submit_phone_number(&telefono).is_ok());
        assert!(mock.submit_code(&codice).is_ok());
        mock
    }

    fn autorita(cartella: &std::path::Path) -> AcquisitionAuthority {
        let servizio = StationAuthorityService::new(HubConnectionStore::at(
            lisi_security::ProtectedStore::at(cartella.join("hub-client.protetto")),
        ));
        let Ok(esito) = servizio.acquisition_authority(&crate::run_mode::operational_for_tests())
        else {
            panic!("l'esito dell'autorità c'è");
        };
        let Some(autorita) = esito.into_granted() else {
            panic!("una postazione senza Hub acquisisce");
        };
        autorita
    }

    fn richiesta(fonte: SourceId) -> MembersListingRequest {
        let Ok(perche) = OperationalReason::try_new("Verifica dei partecipanti a una truffa")
        else {
            panic!("valori di prova validi");
        };
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        MembersListingRequest::new(&autorita(cartella.path()), fonte, chi(), perche)
    }

    fn abilitato(database: &mut Database) {
        let Ok(_) = choose(
            database,
            true,
            OperatingMode::Administrator,
            &chi(),
            adesso(0),
        ) else {
            panic!("l'amministratore abilita");
        };
    }

    fn elenco(n: i64, totale: Option<i64>) -> MembersReply {
        MembersReply::Found(MemberList {
            declared_total: totale,
            members: (1..=n)
                .map(|id| Member {
                    user_id: id,
                    display_name: Some(format!("Persona {id}")),
                    username: None,
                    masked_phone: (id == 1).then(|| String::from("+••••••••••67")),
                    status: MemberStatus::Member,
                    joined_at_millis: None,
                })
                .collect(),
            stopped_at_cap: false,
        })
    }

    #[test]
    fn l_operatore_non_abilita_e_spento_non_si_chiede() {
        let (mut database, fonte) = archivio(&CHAT.to_string());
        assert!(matches!(
            choose(
                &mut database,
                true,
                OperatingMode::Operator,
                &chi(),
                adesso(0)
            ),
            Err(ServiceError::ActionReservedToAdministrator { .. })
        ));
        let mut mock = collegato();
        mock.set_members_reply(CHAT, Ok(elenco(2, Some(2))));
        let Ok(esito) = request_members(
            &mut mock,
            None,
            &mut database,
            &richiesta(fonte),
            adesso(10),
        ) else {
            panic!("la richiesta si valuta");
        };
        assert!(matches!(esito, MembersListingAttempt::Refused(_)));
        assert_eq!(mock.members_calls(), 0, "spento, Telegram non si interroga");
    }

    #[test]
    fn abilitato_l_elenco_arriva_e_resta_con_il_motivo() {
        let (mut database, fonte) = archivio(&CHAT.to_string());
        abilitato(&mut database);
        let mut mock = collegato();
        mock.set_members_reply(CHAT, Ok(elenco(3, Some(5))));
        let Ok(MembersListingAttempt::Recorded {
            id,
            outcome,
            sentence,
        }) = request_members(
            &mut mock,
            None,
            &mut database,
            &richiesta(fonte),
            adesso(10),
        )
        else {
            panic!("la richiesta si registra");
        };
        assert_eq!(outcome, "ottenuto");
        assert!(sentence.contains("parziale"), "{sentence}");
        assert_eq!(mock.members_calls(), 1);
        let Ok(iscritti) = rows(&database, id) else {
            panic!("gli iscritti si leggono");
        };
        assert_eq!(iscritti.len(), 3);
        assert_eq!(iscritti[0].masked_phone.as_deref(), Some("+••••••••••67"));
        let Ok(elenchi) = super::recent(&database) else {
            panic!("le richieste si leggono");
        };
        assert_eq!(elenchi[0].reason, "Verifica dei partecipanti a una truffa");
    }

    #[test]
    fn due_richieste_troppo_vicine_non_partono_e_un_rifiuto_si_registra() {
        let (mut database, fonte) = archivio(&CHAT.to_string());
        abilitato(&mut database);
        let mut mock = collegato();
        mock.set_members_reply(
            CHAT,
            Ok(MembersReply::Refused {
                code: 400,
                message: String::from("CHAT_ADMIN_REQUIRED"),
            }),
        );
        let Ok(MembersListingAttempt::Recorded { outcome, .. }) = request_members(
            &mut mock,
            None,
            &mut database,
            &richiesta(fonte),
            adesso(10),
        ) else {
            panic!("il rifiuto si registra");
        };
        assert_eq!(outcome, "rifiutato");
        let Ok(seconda) = request_members(
            &mut mock,
            None,
            &mut database,
            &richiesta(fonte),
            adesso(20),
        ) else {
            panic!("la seconda si valuta");
        };
        assert!(matches!(seconda, MembersListingAttempt::Refused(_)));
        assert_eq!(mock.members_calls(), 1);
    }

    #[test]
    fn una_fonte_senza_identificativo_numerico_non_parte() {
        let (mut database, fonte) = archivio("canale_uno");
        abilitato(&mut database);
        let mut mock = collegato();
        let Ok(esito) = request_members(
            &mut mock,
            None,
            &mut database,
            &richiesta(fonte),
            adesso(10),
        ) else {
            panic!("la richiesta si valuta");
        };
        assert!(matches!(esito, MembersListingAttempt::Refused(_)));
        assert_eq!(mock.members_calls(), 0);
    }

    #[test]
    fn la_frase_dice_il_tetto_e_il_totale() {
        let frase = outcome_sentence("ottenuto", None, Some(5_000), 1_000, true);
        assert!(
            frase.contains("parziale") && frase.contains("tetto"),
            "{frase}"
        );
        let intero = outcome_sentence("ottenuto", None, Some(3), 3, false);
        assert!(!intero.contains("parziale"), "{intero}");
    }
}

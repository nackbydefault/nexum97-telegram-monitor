//! Foto, biografia e stato di un autore, su richiesta motivata
//! (PERSON-MEDIA-01, ADR-0174).
//!
//! # Che cosa fa
//!
//! Per **un** autore che ha scritto in un monitoraggio, chiede a Telegram, con
//! l'account d'ufficio di quel monitoraggio, ciò che rende visibile: biografia,
//! stato e immagine piccola del profilo. Registra l'esito come un'osservazione
//! datata, con chi, quando e perché, e la riga d'audit nella stessa
//! transazione.
//!
//! # Che cosa non fa
//!
//! - Non parte senza l'autorità di acquisire né senza una ragione: la richiesta
//!   non si costruisce.
//! - Non parte per un autore che non ha scritto nel monitoraggio, né con un
//!   account diverso da quello del monitoraggio (ADR-0173).
//! - Non ripete: una lettura per gesto, e mai due troppo vicine.
//! - Non guarda la foto e non la confronta con nulla: ne conserva i byte e
//!   l'impronta (ADR-0174, decisione 5).
//! - Non collega l'autore a un soggetto, non cerca recapiti nella biografia.
//!
//! # Senza autorità, non compila
//!
//! ```compile_fail
//! use lisi_core::SessionId;
//! use lisi_core::model::reason::OperationalReason;
//! use lisi_core::text::Actor;
//! use lisi_services::profile_media::ProfileMediaRequest;
//!
//! fn da_un_client(operatore: Actor, ragione: OperationalReason) -> ProfileMediaRequest {
//!     ProfileMediaRequest::new(SessionId::new(1), "42", operatore, ragione)
//! }
//! ```

use lisi_core::model::NewAuditEntry;
use lisi_core::model::reason::OperationalReason;
use lisi_core::model::telegram_account::AccountUuid;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{SessionId, Timestamp};
use lisi_storage::Database;
use lisi_storage::repository::profile_media::NewProfileMediaObservation;
pub use lisi_storage::repository::profile_media::StoredProfileMediaObservation;
use lisi_telegram::TelegramConnector;
use lisi_telegram::profile::{ProfileMediaReply, ProfileStatus};

use crate::acquisition_authority::AcquisitionAuthority;
use crate::error::ServiceResult;

/// L'azione d'audit di una richiesta di foto, biografia e stato.
pub const PROFILE_MEDIA_AUDIT_ACTION: &str = "profilo_chiesto";

/// Secondi, almeno, fra una richiesta e la successiva sulla postazione.
pub const MIN_SECONDS_BETWEEN: i64 = 15;

/// Una richiesta. **Vuole l'autorità di acquisizione e una ragione
/// operativa**: senza, non esiste.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileMediaRequest {
    session_id: SessionId,
    author_identifier: String,
    operator: Actor,
    reason: OperationalReason,
}

impl ProfileMediaRequest {
    /// Costruisce la richiesta.
    #[must_use]
    pub fn new(
        _autorita: &AcquisitionAuthority,
        session_id: SessionId,
        author_identifier: &str,
        operator: Actor,
        reason: OperationalReason,
    ) -> Self {
        Self {
            session_id,
            author_identifier: author_identifier.trim().to_owned(),
            operator,
            reason,
        }
    }
}

/// Com'è andata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileMediaAttempt {
    /// La richiesta è registrata, con il suo esito.
    Recorded {
        /// La riga dell'osservazione.
        id: i64,
        /// `osservato`, `rifiutato` o `non_riuscito`.
        outcome: &'static str,
    },
    /// Il prodotto ha rifiutato di chiedere: il perché. Nessuna richiesta.
    Refused(String),
}

/// La richiesta: i rifiuti prima di chiedere, poi **una** lettura, poi il
/// registro.
///
/// `account` è l'account d'ufficio del connettore: deve essere quello del
/// monitoraggio, se il monitoraggio ne ha uno.
///
/// # Errori
///
/// Restituisce un errore se l'archivio non si legge o non si scrive.
pub fn request_profile_media(
    connector: &mut dyn TelegramConnector,
    account: &AccountUuid,
    database: &mut Database,
    richiesta: &ProfileMediaRequest,
    now: Timestamp,
) -> ServiceResult<ProfileMediaAttempt> {
    let Some(user_id) = richiesta
        .author_identifier
        .parse::<i64>()
        .ok()
        .filter(|id| *id > 0)
    else {
        return Ok(ProfileMediaAttempt::Refused(String::from(
            "L'autore non ha un identificativo di Telegram: foto, biografia e stato si chiedono \
             soltanto per una persona che ha scritto con il suo account.",
        )));
    };
    if !database.author_observed_in_session(richiesta.session_id, &richiesta.author_identifier)? {
        return Ok(ProfileMediaAttempt::Refused(String::from(
            "Questo autore non ha scritto in questo monitoraggio: la richiesta parte soltanto per \
             chi è già stato osservato.",
        )));
    }
    let legame = database.session_account(richiesta.session_id)?;
    if let Some(legame) = &legame
        && legame.account_uuid != *account
    {
        return Ok(ProfileMediaAttempt::Refused(format!(
            "Il monitoraggio lavora con l'account «{}»: selezionarlo per chiedere. Nessun account \
             chiede al posto di un altro.",
            legame.account_label.as_str()
        )));
    }
    if let Some(ultima) = database.last_profile_media_request_at()?
        && now.millis_since(ultima) < MIN_SECONDS_BETWEEN * 1_000
    {
        return Ok(ProfileMediaAttempt::Refused(format!(
            "Un'altra richiesta è partita da meno di {MIN_SECONDS_BETWEEN} secondi: riprovare fra \
             poco."
        )));
    }

    let mut osservazione = NewProfileMediaObservation {
        session_id: richiesta.session_id,
        author_identifier: richiesta.author_identifier.clone(),
        account_uuid: legame.map(|legame| legame.account_uuid.as_str().to_owned()),
        requested_by: richiesta.operator.as_str().to_owned(),
        reason: richiesta.reason.as_str().to_owned(),
        requested_at: now,
        outcome: String::new(),
        outcome_detail: None,
        bio: None,
        status: None,
        status_was_online: None,
        photo: None,
        photo_not_read: None,
    };
    // UNA lettura, e una sola. Nessuna ripetizione, qualunque sia l'esito.
    let esito: &'static str = match connector.profile_media() {
        None => {
            osservazione.outcome_detail = Some(String::from(
                "Questo collegamento non offre la lettura del profilo.",
            ));
            "non_riuscito"
        }
        Some(lettore) => match lettore.read_profile_media(user_id) {
            Ok(ProfileMediaReply::Found(profilo)) => {
                osservazione.bio = profilo.bio;
                osservazione.status = Some(profilo.status.as_str().to_owned());
                if let ProfileStatus::Offline { was_online_millis } = profilo.status {
                    osservazione.status_was_online =
                        Some(Timestamp::from_millis(was_online_millis));
                }
                osservazione.photo = profilo.photo;
                osservazione.photo_not_read = profilo.photo_not_read;
                "osservato"
            }
            Ok(ProfileMediaReply::Refused { code, message }) => {
                osservazione.outcome_detail =
                    Some(format!("Telegram ha rifiutato ({code}): {message}"));
                "rifiutato"
            }
            Err(errore) => {
                osservazione.outcome_detail = Some(format!(
                    "La richiesta non è arrivata a una risposta: {}. Non vuol dire che il dato \
                     manchi.",
                    crate::identity_resolver::connector_fault(&errore)
                ));
                "non_riuscito"
            }
        },
    };
    osservazione.outcome = String::from(esito);
    let audit = NewAuditEntry {
        actor: richiesta.operator.clone(),
        action: AuditAction::try_new(PROFILE_MEDIA_AUDIT_ACTION)?,
        entity: AuditEntity::try_new("profilo")?,
        entity_id: None,
        actor_mode: None,
        detail: Some(AuditDetail::try_new(&format!(
            "autore {}, monitoraggio {}, motivo: «{}»: {esito}",
            richiesta.author_identifier,
            richiesta.session_id.get(),
            richiesta.reason.as_str()
        ))?),
        recorded_at: now,
    };
    let id = database.insert_profile_media_observation(&osservazione, &audit)?;
    Ok(ProfileMediaAttempt::Recorded { id, outcome: esito })
}

/// Le osservazioni di un autore in un monitoraggio, dalla più recente.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn observations(
    database: &Database,
    session_id: SessionId,
    author_identifier: &str,
) -> ServiceResult<Vec<StoredProfileMediaObservation>> {
    Ok(database.profile_media_observations(session_id, author_identifier)?)
}

/// L'azione d'audit di una scelta per i documenti.
pub const REPORT_MARK_AUDIT_ACTION: &str = "profilo_per_i_documenti";

/// Lo stato nella parola dell'operatore: la stessa frase nella scheda e nei
/// documenti. «Non mostrato» non è «non attivo».
#[must_use]
pub fn status_in_words(chiave: &str, ultimo_accesso: Option<Timestamp>) -> String {
    match chiave {
        "in_linea" => String::from("in linea"),
        "non_in_linea" => ultimo_accesso.map_or_else(
            || String::from("non in linea"),
            |quando| {
                format!(
                    "non in linea, ultimo accesso {}",
                    quando.to_readable_local()
                )
            },
        ),
        "di_recente" => String::from("visto di recente"),
        "ultima_settimana" => String::from("visto nell'ultima settimana"),
        "ultimo_mese" => String::from("visto nell'ultimo mese"),
        _ => String::from("non mostrato da Telegram (non vuol dire non attivo)"),
    }
}

/// Sceglie un'osservazione per i documenti, o la toglie (PERSON-MEDIA-01
/// parte 3, ADR-0174, decisione 7). Restituisce la frase per l'operatore, o
/// il perché del rifiuto.
///
/// Si sceglie soltanto un'osservazione riuscita del monitoraggio indicato: un
/// rifiuto di Telegram non ha niente da riportare. Togliere si può sempre.
///
/// # Errori
///
/// Restituisce un errore se l'archivio non si legge o non si scrive.
pub fn mark_for_documents(
    database: &mut Database,
    session_id: SessionId,
    observation_id: i64,
    chosen: bool,
    operator: &Actor,
    now: Timestamp,
) -> ServiceResult<Result<&'static str, String>> {
    let Some(osservazione) = database.profile_media_observation(observation_id)? else {
        return Ok(Err(String::from(
            "Questa osservazione non c'è più nell'archivio.",
        )));
    };
    if osservazione.session_id != session_id {
        return Ok(Err(String::from(
            "Questa osservazione è di un altro monitoraggio: si sceglie dal suo.",
        )));
    }
    if chosen && osservazione.outcome != "osservato" {
        return Ok(Err(String::from(
            "Una richiesta a cui Telegram non ha risposto con un profilo non ha niente da riportare.",
        )));
    }
    let audit = NewAuditEntry {
        actor: operator.clone(),
        action: AuditAction::try_new(REPORT_MARK_AUDIT_ACTION)?,
        entity: AuditEntity::try_new("profilo")?,
        entity_id: None,
        actor_mode: None,
        detail: Some(AuditDetail::try_new(&format!(
            "osservazione {observation_id} dell'autore {}: {}",
            osservazione.author_identifier,
            if chosen {
                "scelta per i documenti"
            } else {
                "tolta dai documenti"
            }
        ))?),
        recorded_at: now,
    };
    database.insert_profile_media_mark(observation_id, chosen, operator.as_str(), now, &audit)?;
    Ok(Ok(if chosen {
        "L'osservazione entrerà nei documenti di questo monitoraggio; la foto resta nell'archivio."
    } else {
        "L'osservazione non entrerà nei documenti."
    }))
}

/// Se l'osservazione è scelta per i documenti.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn is_chosen(database: &Database, observation_id: i64) -> ServiceResult<bool> {
    Ok(database.profile_media_chosen(observation_id)?)
}

/// Le osservazioni di un monitoraggio scelte per i documenti.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn chosen_for_documents(
    database: &Database,
    session_id: SessionId,
) -> ServiceResult<Vec<StoredProfileMediaObservation>> {
    Ok(database.chosen_profile_media_for_session(session_id)?)
}
#[cfg(test)]
mod tests {
    use lisi_core::model::reason::OperationalReason;
    use lisi_core::model::telegram_account::AccountUuid;
    use lisi_core::model::{NewContent, NewSession, NewSource, SessionDuration, SourceKind};
    use lisi_core::text::{Actor, DisplayName, SourceIdentifier};
    use lisi_core::{SessionId, Timestamp};
    use lisi_storage::Database;
    use lisi_telegram::profile::{ProfileMedia, ProfileMediaReply, ProfileStatus};
    use lisi_telegram::{
        ClientParameters, LoginCode, MockTelegramConnector, PhoneNumber, TelegramConnector,
    };

    use super::{ProfileMediaAttempt, ProfileMediaRequest, request_profile_media};
    use crate::acquisition_authority::{AcquisitionAuthority, StationAuthorityService};
    use crate::hub_client::HubConnectionStore;

    fn adesso(secondi: i64) -> Timestamp {
        Timestamp::from_millis(1_800_000_000_000 + secondi * 1_000)
    }

    /// Un archivio con un monitoraggio in cui l'autore 42 ha scritto.
    fn archivio() -> (Database, SessionId) {
        let Ok(mut database) = Database::open_in_memory() else {
            panic!("l'archivio di prova si apre");
        };
        let (Ok(identificativo), Ok(nome), Ok(chi), Ok(etichetta)) = (
            SourceIdentifier::try_new("-1001"),
            DisplayName::try_new("Canale"),
            Actor::try_new("operatore.prova"),
            DisplayName::try_new("Monitoraggio"),
        ) else {
            panic!("valori di prova validi");
        };
        let Ok(fonte) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier: identificativo,
                display_name: nome,
                authorized_by: chi.clone(),
                active: true,
            },
            adesso(0),
        ) else {
            panic!("la fonte si registra");
        };
        let Ok(sessione) = database.insert_session(
            &NewSession {
                label: etichetta,
                started_by: chi,
                duration: SessionDuration::Preset { seconds: 3_600 },
                source_ids: vec![fonte],
            },
            adesso(0),
        ) else {
            panic!("il monitoraggio nasce");
        };
        let (Ok(remoto), Ok(corpo)) = (
            lisi_core::text::RemoteMessageId::try_new("7"),
            lisi_core::text::ContentBody::try_new("un messaggio"),
        ) else {
            panic!("valori di prova validi");
        };
        let Ok(_) = database.insert_content(&NewContent {
            session_id: sessione,
            source_id: fonte,
            remote_message_id: remoto,
            author: None,
            author_identifier: Some(String::from("42")),
            author_username: None,
            body: corpo,
            url: None,
            published_at: adesso(0),
            acquired_at: adesso(1),
            origin: lisi_core::model::AcquisitionOrigin::Observed,
            analysis_level: lisi_core::model::AnalysisLevel::NOT_RELEVANT,
        }) else {
            panic!("il contenuto si registra");
        };
        (database, sessione)
    }

    fn collegato(mock: &mut MockTelegramConnector) {
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
    }

    fn richiesta(sessione: SessionId, autore: &str) -> ProfileMediaRequest {
        let (Ok(chi), Ok(perche)) = (
            Actor::try_new("operatore.prova"),
            OperationalReason::try_new("Verifica dell'autore di un messaggio di minaccia"),
        ) else {
            panic!("valori di prova validi");
        };
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        ProfileMediaRequest::new(&autorita(cartella.path()), sessione, autore, chi, perche)
    }

    /// L'autorità di una postazione che acquisisce, dal percorso vero (come in
    /// `discovery_gate`).
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

    fn account() -> AccountUuid {
        AccountUuid::from_bytes([0xa1; 16])
    }

    /// **Una richiesta motivata legge una volta e registra l'osservazione con
    /// la sua riga d'audit** (PERSON-MEDIA-01, criteri 1 e 2).
    #[test]
    fn una_richiesta_motivata_legge_una_volta_e_registra() {
        let (mut database, sessione) = archivio();
        let mut mock = MockTelegramConnector::new();
        collegato(&mut mock);
        mock.set_profile_media_reply(
            42,
            Ok(ProfileMediaReply::Found(ProfileMedia {
                user_id: 42,
                bio: Some(String::from("Cronista")),
                status: ProfileStatus::Recently,
                photo: Some(vec![0xff, 0xd8, 0xff]),
                photo_not_read: None,
            })),
        );
        let Ok(ProfileMediaAttempt::Recorded { outcome, .. }) = request_profile_media(
            &mut mock,
            &account(),
            &mut database,
            &richiesta(sessione, "42"),
            adesso(10),
        ) else {
            panic!("la richiesta si registra");
        };
        assert_eq!(outcome, "osservato");
        assert_eq!(mock.profile_media_calls(), 1, "una lettura, una sola");
        let Ok(lette) = super::observations(&database, sessione, "42") else {
            panic!("le osservazioni si leggono");
        };
        let Some(prima) = lette.first() else {
            panic!("c'è un'osservazione");
        };
        assert_eq!(prima.bio.as_deref(), Some("Cronista"));
        assert_eq!(prima.status.as_deref(), Some("di_recente"));
        assert!(prima.photo_sha256.is_some(), "la foto ha la sua impronta");
        assert!(prima.reason.contains("minaccia"), "il perché resta");
        let Ok(audit) = database.audit_entries() else {
            panic!("l'audit si legge");
        };
        assert!(audit.iter().any(|voce| {
            voce.action.as_str() == super::PROFILE_MEDIA_AUDIT_ACTION
                && voce
                    .detail
                    .as_ref()
                    .is_some_and(|d| d.as_str().contains("autore 42"))
        }));
    }

    /// **Nessuna richiesta per chi non ha scritto, per un autore che non è un
    /// numero, con un account diverso da quello del monitoraggio, o troppo
    /// presto dopo un'altra** (prove negative: Telegram non viene chiamato).
    #[test]
    fn i_rifiuti_prima_di_chiedere_non_chiamano_telegram() {
        let (mut database, sessione) = archivio();
        let mut mock = MockTelegramConnector::new();
        collegato(&mut mock);
        for autore in ["43", "abc", "-5"] {
            let Ok(ProfileMediaAttempt::Refused(_)) = request_profile_media(
                &mut mock,
                &account(),
                &mut database,
                &richiesta(sessione, autore),
                adesso(10),
            ) else {
                panic!("«{autore}» va rifiutato prima di chiedere");
            };
        }
        let Ok(nome) = DisplayName::try_new("Ufficio B") else {
            panic!("nome valido");
        };
        let Ok(()) = database.insert_session_account(
            sessione,
            &AccountUuid::from_bytes([0xb2; 16]),
            &nome,
            adesso(0),
        ) else {
            panic!("il legame si registra");
        };
        let Ok(ProfileMediaAttempt::Refused(perche)) = request_profile_media(
            &mut mock,
            &account(),
            &mut database,
            &richiesta(sessione, "42"),
            adesso(10),
        ) else {
            panic!("un altro account non chiede per il monitoraggio di B");
        };
        assert!(perche.contains("Ufficio B"), "{perche}");
        assert_eq!(mock.profile_media_calls(), 0, "nessuna lettura partita");
        let Ok(lette) = super::observations(&database, sessione, "42") else {
            panic!("le osservazioni si leggono");
        };
        assert!(
            lette.is_empty(),
            "un rifiuto prima di chiedere non è un'osservazione"
        );
    }

    /// **Un rifiuto di Telegram si registra com'è, senza dati, e una seconda
    /// richiesta troppo vicina non parte.**
    #[test]
    fn un_rifiuto_si_registra_e_una_richiesta_troppo_vicina_non_parte() {
        let (mut database, sessione) = archivio();
        let mut mock = MockTelegramConnector::new();
        collegato(&mut mock);
        let Ok(ProfileMediaAttempt::Recorded { outcome, .. }) = request_profile_media(
            &mut mock,
            &account(),
            &mut database,
            &richiesta(sessione, "42"),
            adesso(10),
        ) else {
            panic!("il rifiuto si registra");
        };
        assert_eq!(outcome, "rifiutato", "il simulatore non inventa profili");
        let Ok(ProfileMediaAttempt::Refused(_)) = request_profile_media(
            &mut mock,
            &account(),
            &mut database,
            &richiesta(sessione, "42"),
            adesso(12),
        ) else {
            panic!("troppo presto");
        };
        assert_eq!(mock.profile_media_calls(), 1);
        let Ok(ProfileMediaAttempt::Recorded { .. }) = request_profile_media(
            &mut mock,
            &account(),
            &mut database,
            &richiesta(sessione, "42"),
            adesso(10 + super::MIN_SECONDS_BETWEEN),
        ) else {
            panic!("dopo l'attesa si può chiedere di nuovo");
        };
        let Ok(lette) = super::observations(&database, sessione, "42") else {
            panic!("le osservazioni si leggono");
        };
        assert_eq!(lette.len(), 2, "due richieste, due righe");
        assert!(lette.iter().all(|o| o.bio.is_none() && o.photo.is_none()));
    }

    /// **Si sceglie per i documenti soltanto un'osservazione riuscita del suo
    /// monitoraggio; togliere si può sempre** (PERSON-MEDIA-01 parte 3). Prova
    /// negativa: un rifiuto di Telegram, o un altro monitoraggio → rifiutati.
    #[test]
    fn si_sceglie_soltanto_un_osservazione_riuscita_del_suo_monitoraggio() {
        let (mut database, sessione) = archivio();
        let mut mock = MockTelegramConnector::new();
        collegato(&mut mock);
        let Ok(ProfileMediaAttempt::Recorded { id: rifiutata, .. }) = request_profile_media(
            &mut mock,
            &account(),
            &mut database,
            &richiesta(sessione, "42"),
            adesso(10),
        ) else {
            panic!("il rifiuto si registra");
        };
        mock.set_profile_media_reply(
            42,
            Ok(ProfileMediaReply::Found(ProfileMedia {
                user_id: 42,
                bio: None,
                status: ProfileStatus::LastWeek,
                photo: None,
                photo_not_read: None,
            })),
        );
        let Ok(ProfileMediaAttempt::Recorded { id: riuscita, .. }) = request_profile_media(
            &mut mock,
            &account(),
            &mut database,
            &richiesta(sessione, "42"),
            adesso(10 + super::MIN_SECONDS_BETWEEN),
        ) else {
            panic!("l'osservazione si registra");
        };
        let Ok(chi) = Actor::try_new("operatore.prova") else {
            panic!("attore valido");
        };
        let scegli = |database: &mut Database, sessione: SessionId, id: i64, scelta: bool| {
            super::mark_for_documents(database, sessione, id, scelta, &chi, adesso(60))
        };
        assert!(
            matches!(scegli(&mut database, sessione, rifiutata, true), Ok(Err(_))),
            "un rifiuto non ha niente da riportare"
        );
        assert!(
            matches!(
                scegli(&mut database, SessionId::new(999), riuscita, true),
                Ok(Err(_))
            ),
            "un altro monitoraggio non sceglie"
        );
        assert!(matches!(
            scegli(&mut database, sessione, riuscita, true),
            Ok(Ok(_))
        ));
        assert_eq!(super::is_chosen(&database, riuscita).ok(), Some(true));
        let Ok(scelte) = super::chosen_for_documents(&database, sessione) else {
            panic!("le scelte si leggono");
        };
        assert_eq!(
            scelte.iter().map(|o| o.id).collect::<Vec<_>>(),
            vec![riuscita]
        );
        assert!(matches!(
            scegli(&mut database, sessione, riuscita, false),
            Ok(Ok(_))
        ));
        assert_eq!(super::is_chosen(&database, riuscita).ok(), Some(false));
        let Ok(audit) = database.audit_entries() else {
            panic!("l'audit si legge");
        };
        assert_eq!(
            audit
                .iter()
                .filter(|voce| voce.action.as_str() == super::REPORT_MARK_AUDIT_ACTION)
                .count(),
            2,
            "scelta e ritiro, ciascuno con la sua riga"
        );
    }

    /// **La foto non si analizza** (ADR-0174, decisione 5). Nei moduli che
    /// toccano la foto nessuna decodifica, ridimensionamento, confronto o
    /// distanza; e nessuna crate di analisi delle immagini o dei volti nei
    /// manifesti del progetto. Prova negativa: un `decode` nel modulo, o
    /// `imageproc` in un manifesto → rossa.
    #[test]
    fn la_foto_non_si_analizza_ne_si_confronta() {
        let radice = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let produzione = |percorso: &str| -> String {
            let Ok(testo) = std::fs::read_to_string(radice.join(percorso)) else {
                panic!("{percorso} si legge");
            };
            testo
                .split_once("#[cfg(test)]")
                .map_or(testo.as_str(), |(prima, _)| prima)
                .lines()
                .filter(|riga| !riga.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join(
                    "
",
                )
                .to_lowercase()
        };
        for modulo in [
            "crates/lisi-services/src/profile_media.rs",
            "crates/lisi-storage/src/repository/profile_media.rs",
            "crates/lisi-telegram/src/profile.rs",
        ] {
            let codice = produzione(modulo);
            for vietato in [
                "decode",
                "resize",
                "pixel",
                "thumbnail",
                "compare",
                "similar",
                "distance",
                "embedding",
                "face",
                "landmark",
            ] {
                assert!(
                    !codice.contains(vietato),
                    "{modulo} non analizza la foto («{vietato}»)"
                );
            }
        }
        let Ok(manifesti) = std::fs::read_dir(radice.join("crates")) else {
            panic!("le crate si leggono");
        };
        for crate_ in manifesti.flatten() {
            let Ok(manifesto) = std::fs::read_to_string(crate_.path().join("Cargo.toml")) else {
                continue;
            };
            for vietata in [
                "imageproc",
                "img_hash",
                "image_hasher",
                "opencv",
                "dlib",
                "rustface",
                "face_detection",
                "tract-onnx",
                "ort",
            ] {
                assert!(
                    !manifesto
                        .lines()
                        .any(|riga| riga.trim_start().starts_with(&format!("{vietata} "))
                            || riga.trim_start().starts_with(&format!("{vietata}="))),
                    "{} non dipende da {vietata}",
                    crate_.path().display()
                );
            }
        }
    }
}

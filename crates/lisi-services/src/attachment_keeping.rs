//! Conservare l'allegato di un messaggio, su richiesta motivata (ATTACH-01
//! parte 2, ADR-0177).
//!
//! # Che cosa fa
//!
//! Per **un** contenuto acquisito in un monitoraggio, che all'acquisizione
//! aveva un allegato descritto, chiede a Telegram i byte con l'account
//! d'ufficio di quel monitoraggio, e li conserva nell'archivio con la loro
//! impronta. Registra la richiesta con chi, quando, perché e l'esito, e la riga
//! d'audit nella stessa transazione, anche quando un tetto la ferma o Telegram
//! la rifiuta.
//!
//! # Che cosa non fa
//!
//! - Non parte senza l'autorità di acquisire né senza una ragione: la richiesta
//!   non si costruisce.
//! - Non parte per un contenuto senza allegato descritto, con un account
//!   diverso da quello del monitoraggio (ADR-0173), né per un allegato già
//!   conservato (ADR-0177, decisione 8).
//! - Non supera i tetti: 25 MiB per allegato, 1 GiB in tutto, controllati
//!   prima di chiedere e ricontrollati sui byte (decisione 5).
//! - Non ripete: una lettura per gesto, qualunque sia l'esito.
//! - **Non apre i byte**: non li decodifica, non li mostra, non li passa a un
//!   altro programma, e il nome dichiarato non diventa un file (decisione 7).
//!   Una guardia lo sorveglia.
//!
//! # Senza autorità, non compila
//!
//! ```compile_fail
//! use lisi_core::ContentId;
//! use lisi_core::model::reason::OperationalReason;
//! use lisi_core::text::Actor;
//! use lisi_services::attachment_keeping::AttachmentKeepRequest;
//!
//! fn da_un_client(operatore: Actor, ragione: OperationalReason) -> AttachmentKeepRequest {
//!     AttachmentKeepRequest::new(ContentId::new(1), operatore, ragione)
//! }
//! ```

use lisi_core::model::NewAuditEntry;
use lisi_core::model::reason::OperationalReason;
use lisi_core::model::telegram_account::AccountUuid;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{ContentId, Timestamp};
use lisi_storage::Database;
use lisi_storage::repository::attachment_keeping::NewAttachmentKeeping;
pub use lisi_storage::repository::attachment_keeping::StoredAttachmentKeeping;
use lisi_telegram::TelegramConnector;
use lisi_telegram::attachment::{
    AttachmentKind, AttachmentReply, MAX_ATTACHMENT_BYTES, MAX_KEPT_TOTAL_BYTES,
};

use crate::acquisition_authority::AcquisitionAuthority;
use crate::error::ServiceResult;

/// L'azione d'audit di una richiesta di conservare un allegato.
pub const KEEP_AUDIT_ACTION: &str = "allegato_chiesto";

/// Una richiesta. **Vuole l'autorità di acquisizione e una ragione
/// operativa**: senza, non esiste.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentKeepRequest {
    content_id: ContentId,
    operator: Actor,
    reason: OperationalReason,
}

impl AttachmentKeepRequest {
    /// Costruisce la richiesta.
    #[must_use]
    pub const fn new(
        _autorita: &AcquisitionAuthority,
        content_id: ContentId,
        operator: Actor,
        reason: OperationalReason,
    ) -> Self {
        Self {
            content_id,
            operator,
            reason,
        }
    }
}

/// Com'è andata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeepAttempt {
    /// La richiesta è registrata, con il suo esito.
    Recorded {
        /// La riga della richiesta.
        id: i64,
        /// `conservato`, `fermato`, `rifiutato` o `non_riuscito`.
        outcome: &'static str,
    },
    /// Il prodotto ha rifiutato di chiedere: il perché. Nessuna richiesta,
    /// nessuna riga.
    Refused(String),
}

/// La richiesta: i rifiuti prima di chiedere, i tetti, poi **una** lettura,
/// poi il registro.
///
/// `account` è l'account d'ufficio del connettore: deve essere quello del
/// monitoraggio, se il monitoraggio ne ha uno.
///
/// # Errori
///
/// Restituisce un errore se l'archivio non si legge o non si scrive.
pub fn keep_attachment(
    connector: &mut dyn TelegramConnector,
    account: &AccountUuid,
    database: &mut Database,
    richiesta: &AttachmentKeepRequest,
    now: Timestamp,
) -> ServiceResult<KeepAttempt> {
    let Some(descrizione) = database.content_attachment(richiesta.content_id)? else {
        return Ok(KeepAttempt::Refused(String::from(
            "Questo contenuto non ha un allegato descritto: si conserva soltanto un allegato che \
             il monitoraggio ha visto arrivare.",
        )));
    };
    if let Some(gia) = database.kept_attachment(richiesta.content_id)? {
        return Ok(KeepAttempt::Refused(format!(
            "L'allegato è già conservato, con l'impronta {}: non si conserva due volte.",
            gia.sha256.as_deref().unwrap_or("-")
        )));
    }
    let contenuto = database.content(richiesta.content_id)?;
    let legame = database.session_account(contenuto.session_id)?;
    if let Some(legame) = &legame
        && legame.account_uuid != *account
    {
        return Ok(KeepAttempt::Refused(format!(
            "Il monitoraggio lavora con l'account «{}»: selezionarlo per chiedere. Nessun account \
             chiede al posto di un altro.",
            legame.account_label.as_str()
        )));
    }
    let fonte = database.source(contenuto.source_id)?;
    let (Ok(chat_id), Ok(message_id)) = (
        fonte.identifier.as_str().parse::<i64>(),
        contenuto.remote_message_id.as_str().parse::<i64>(),
    ) else {
        return Ok(KeepAttempt::Refused(String::from(
            "Questo contenuto non porta gli identificativi di Telegram che servono per chiedere \
             l'allegato.",
        )));
    };

    let mut registro = NewAttachmentKeeping {
        content_id: richiesta.content_id,
        account_uuid: legame.map(|legame| legame.account_uuid.as_str().to_owned()),
        requested_by: richiesta.operator.as_str().to_owned(),
        reason: richiesta.reason.as_str().to_owned(),
        requested_at: now,
        outcome: String::new(),
        outcome_detail: None,
        bytes: None,
    };
    let totale = database.kept_attachments_total_bytes()?;
    let spazio = MAX_KEPT_TOTAL_BYTES.saturating_sub(totale);
    let fermo_prima = match descrizione.declared_size {
        Some(dichiarata) if dichiarata > MAX_ATTACHMENT_BYTES => Some(format!(
            "L'allegato dichiara {dichiarata} byte: oltre il tetto di 25 MiB non si scarica."
        )),
        Some(dichiarata) if dichiarata > spazio => Some(tetto_complessivo(totale)),
        _ if spazio == 0 => Some(tetto_complessivo(totale)),
        _ => None,
    };

    let esito: &'static str = if let Some(perche) = fermo_prima {
        // FERMATO PRIMA DI CHIEDERE: Telegram non viene chiamato, ma la
        // richiesta resta (ADR-0177, decisione 3).
        registro.outcome_detail = Some(perche);
        "fermato"
    } else {
        let limite = MAX_ATTACHMENT_BYTES.min(spazio);
        // UNA lettura, e una sola. Nessuna ripetizione, qualunque sia l'esito.
        match connector.attachment_reader() {
            None => {
                registro.outcome_detail = Some(String::from(
                    "Questo collegamento non offre la lettura degli allegati.",
                ));
                "non_riuscito"
            }
            Some(lettore) => match lettore.fetch_attachment(chat_id, message_id, limite) {
                Ok(AttachmentReply::Fetched { bytes, leftover }) => {
                    let quanti = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                    if bytes.is_empty() {
                        registro.outcome_detail =
                            Some(String::from("Telegram ha dato un file vuoto."));
                        "non_riuscito"
                    } else if quanti > limite {
                        // RICONTROLLATO SUI BYTE (decisione 5): la dimensione
                        // dichiarata non basta.
                        registro.outcome_detail = Some(format!(
                            "I byte arrivati sono {quanti}, oltre il tetto: non si conservano."
                        ));
                        "fermato"
                    } else {
                        registro.bytes = Some(bytes);
                        registro.outcome_detail = leftover;
                        "conservato"
                    }
                }
                Ok(AttachmentReply::TooLarge { size }) => {
                    registro.outcome_detail = Some(format!(
                        "Telegram dice che l'allegato è di {size} byte: oltre il tetto non si \
                         scarica."
                    ));
                    "fermato"
                }
                Ok(AttachmentReply::NotRead(perche)) => {
                    registro.outcome_detail = Some(perche);
                    "non_riuscito"
                }
                Ok(AttachmentReply::Refused { code, message }) => {
                    registro.outcome_detail =
                        Some(format!("Telegram ha rifiutato ({code}): {message}"));
                    "rifiutato"
                }
                Err(errore) => {
                    registro.outcome_detail = Some(format!(
                        "La richiesta non è arrivata a una risposta: {}. Non vuol dire che \
                         l'allegato manchi.",
                        crate::identity_resolver::connector_fault(&errore)
                    ));
                    "non_riuscito"
                }
            },
        }
    };
    registro.outcome = String::from(esito);
    let audit = NewAuditEntry {
        actor: richiesta.operator.clone(),
        action: AuditAction::try_new(KEEP_AUDIT_ACTION)?,
        entity: AuditEntity::try_new("allegato")?,
        entity_id: None,
        actor_mode: None,
        detail: Some(AuditDetail::try_new(&format!(
            "contenuto {}, {}, motivo: «{}»: {esito}",
            richiesta.content_id.get(),
            descrizione.kind,
            richiesta.reason.as_str()
        ))?),
        recorded_at: now,
    };
    let id = database.insert_attachment_keeping(&registro, &audit)?;
    Ok(KeepAttempt::Recorded { id, outcome: esito })
}

fn tetto_complessivo(totale: u64) -> String {
    format!(
        "L'archivio conserva già {totale} byte di allegati: oltre 1 GiB in tutto non se ne \
         conservano altri."
    )
}

/// L'allegato di un contenuto detto a parole: il genere e ciò che il mittente
/// dichiara, e, se è conservato, l'impronta. `None` se il contenuto non ha un
/// allegato descritto. La stessa frase va nella schermata e nei documenti
/// (ADR-0177, decisione 9): mai i byte.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn describe(database: &Database, content_id: ContentId) -> ServiceResult<Option<String>> {
    let Some(descrizione) = database.content_attachment(content_id)? else {
        return Ok(None);
    };
    let genere: &str = match AttachmentKind::from_key(&descrizione.kind) {
        Some(genere) => genere.label(),
        None => &descrizione.kind,
    };
    let mut frase = format!("Allegato: {genere}");
    if let Some(nome) = &descrizione.declared_name {
        frase.push_str(&format!(", nome dichiarato «{nome}»"));
    }
    if let Some(byte) = descrizione.declared_size {
        frase.push_str(&format!(", {byte} byte dichiarati"));
    }
    if let Some(tipo) = &descrizione.declared_mime {
        frase.push_str(&format!(", tipo dichiarato {tipo}"));
    }
    frase.push('.');
    match database.kept_attachment(content_id)? {
        Some(conservato) => frase.push_str(&format!(
            " Conservato nell'archivio, {} byte, impronta {}.",
            conservato.size.unwrap_or_default(),
            conservato.sha256.as_deref().unwrap_or("-")
        )),
        None => frase.push_str(" Non conservato."),
    }
    Ok(Some(frase))
}

/// Le richieste per l'allegato di un contenuto, dalla più recente.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn keepings(
    database: &Database,
    content_id: ContentId,
) -> ServiceResult<Vec<StoredAttachmentKeeping>> {
    Ok(database.attachment_keepings(content_id)?)
}

#[cfg(test)]
mod tests {
    use lisi_core::model::reason::OperationalReason;
    use lisi_core::model::telegram_account::AccountUuid;
    use lisi_core::model::{NewContent, NewSession, NewSource, SessionDuration, SourceKind};
    use lisi_core::text::{Actor, DisplayName, SourceIdentifier};
    use lisi_core::{ContentId, Timestamp};
    use lisi_storage::Database;
    use lisi_storage::repository::attachment::ContentAttachment;
    use lisi_telegram::attachment::{AttachmentReply, MAX_ATTACHMENT_BYTES};
    use lisi_telegram::{
        ClientParameters, LoginCode, MockTelegramConnector, PhoneNumber, TelegramConnector,
        TelegramError,
    };

    use super::{AttachmentKeepRequest, KEEP_AUDIT_ACTION, KeepAttempt, keep_attachment};
    use crate::acquisition_authority::{AcquisitionAuthority, StationAuthorityService};
    use crate::hub_client::HubConnectionStore;

    const CHAT: i64 = -1_001;
    const MESSAGGIO: i64 = 7_340_032;

    fn adesso(secondi: i64) -> Timestamp {
        Timestamp::from_millis(1_800_000_000_000 + secondi * 1_000)
    }

    /// Un archivio con un monitoraggio e un contenuto; con `dimensione`, il
    /// contenuto ha un documento descritto che dichiara quella dimensione.
    fn archivio(descritto: Option<Option<u64>>) -> (Database, ContentId) {
        let Ok(mut database) = Database::open_in_memory() else {
            panic!("l'archivio di prova si apre");
        };
        let (Ok(identificativo), Ok(nome), Ok(chi), Ok(etichetta)) = (
            SourceIdentifier::try_new(&CHAT.to_string()),
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
            lisi_core::text::RemoteMessageId::try_new(&MESSAGGIO.to_string()),
            lisi_core::text::ContentBody::try_new("ecco il documento"),
        ) else {
            panic!("valori di prova validi");
        };
        let Ok(inserito) = database.insert_content(&NewContent {
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
        let contenuto = inserito.content_id();
        if let Some(dimensione) = descritto {
            let Ok(()) = database.record_content_attachment(
                contenuto,
                &ContentAttachment {
                    kind: String::from("documento"),
                    declared_name: Some(String::from("fattura.pdf")),
                    declared_size: dimensione,
                    declared_mime: Some(String::from("application/pdf")),
                },
            ) else {
                panic!("la descrizione si registra");
            };
        }
        (database, contenuto)
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

    /// L'autorità di una postazione che acquisisce, dal percorso vero (come in
    /// `profile_media`).
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

    fn richiesta(contenuto: ContentId) -> AttachmentKeepRequest {
        let (Ok(chi), Ok(perche)) = (
            Actor::try_new("operatore.prova"),
            OperationalReason::try_new("Il documento allegato al messaggio di minaccia"),
        ) else {
            panic!("valori di prova validi");
        };
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        AttachmentKeepRequest::new(&autorita(cartella.path()), contenuto, chi, perche)
    }

    fn account() -> AccountUuid {
        AccountUuid::from_bytes([0xa1; 16])
    }

    fn chiedi(
        mock: &mut MockTelegramConnector,
        database: &mut Database,
        contenuto: ContentId,
        secondi: i64,
    ) -> KeepAttempt {
        let Ok(tentativo) = keep_attachment(
            mock,
            &account(),
            database,
            &richiesta(contenuto),
            adesso(secondi),
        ) else {
            panic!("la richiesta arriva a un esito");
        };
        tentativo
    }

    /// **Una richiesta motivata legge una volta, con gli identificativi del
    /// messaggio, e conserva i byte con l'impronta e la riga d'audit**
    /// (ATTACH-01 parte 2, ADR-0177, decisioni 3, 4 e 6).
    #[test]
    fn una_richiesta_motivata_conserva_una_volta() {
        let (mut database, contenuto) = archivio(Some(Some(18)));
        let mut mock = MockTelegramConnector::new();
        collegato(&mut mock);
        let byte = b"%PDF-1.7 sintetico".to_vec();
        mock.set_attachment_reply(
            CHAT,
            MESSAGGIO,
            Ok(AttachmentReply::Fetched {
                bytes: byte.clone(),
                leftover: None,
            }),
        );
        let KeepAttempt::Recorded { outcome, .. } = chiedi(&mut mock, &mut database, contenuto, 10)
        else {
            panic!("la richiesta si registra");
        };
        assert_eq!(outcome, "conservato");
        assert_eq!(mock.attachment_calls(), 1, "una lettura, una sola");
        let Ok(Some(conservato)) = database.kept_attachment(contenuto) else {
            panic!("l'allegato è conservato");
        };
        assert_eq!(
            conservato.sha256.as_deref(),
            Some(lisi_core::Sha256Digest::of_bytes(&byte).as_str())
        );
        assert!(conservato.reason.contains("minaccia"), "il perché resta");
        let Ok(audit) = database.audit_entries() else {
            panic!("l'audit si legge");
        };
        assert!(audit.iter().any(|voce| {
            voce.action.as_str() == KEEP_AUDIT_ACTION
                && voce.detail.as_ref().is_some_and(|d| {
                    d.as_str()
                        .contains(&format!("contenuto {}, documento", contenuto.get()))
                })
        }));

        // UNA VOLTA (decisione 8): la seconda richiesta non chiama Telegram.
        let KeepAttempt::Refused(perche) = chiedi(&mut mock, &mut database, contenuto, 20) else {
            panic!("un allegato conservato non si richiede");
        };
        assert!(perche.contains("già conservato"), "{perche}");
        assert_eq!(mock.attachment_calls(), 1);
    }

    /// **L'allegato si dice con ciò che è dichiarato e, se conservato, con
    /// l'impronta; mai con i byte** (ATTACH-01 parte 3, decisione 9). Prova
    /// negativa: un contenuto senza allegato non ha frase.
    #[test]
    fn l_allegato_si_dice_con_la_descrizione_e_l_impronta() {
        let (senza, contenuto_senza) = archivio(None);
        let Ok(nessuna) = super::describe(&senza, contenuto_senza) else {
            panic!("la descrizione si legge");
        };
        assert_eq!(nessuna, None, "nessun allegato, nessuna frase");

        let (mut database, contenuto) = archivio(Some(Some(18)));
        let Ok(Some(prima)) = super::describe(&database, contenuto) else {
            panic!("la frase c'è");
        };
        assert_eq!(
            prima,
            "Allegato: documento, nome dichiarato «fattura.pdf», 18 byte dichiarati, tipo \
             dichiarato application/pdf. Non conservato."
        );

        let mut mock = MockTelegramConnector::new();
        collegato(&mut mock);
        let byte = b"%PDF-1.7 sintetico".to_vec();
        mock.set_attachment_reply(
            CHAT,
            MESSAGGIO,
            Ok(AttachmentReply::Fetched {
                bytes: byte.clone(),
                leftover: None,
            }),
        );
        let KeepAttempt::Recorded { .. } = chiedi(&mut mock, &mut database, contenuto, 10) else {
            panic!("la richiesta si registra");
        };
        let Ok(Some(dopo)) = super::describe(&database, contenuto) else {
            panic!("la frase c'è");
        };
        let impronta = lisi_core::Sha256Digest::of_bytes(&byte);
        assert!(
            dopo.ends_with(&format!(
                "Conservato nell'archivio, 18 byte, impronta {}.",
                impronta.as_str()
            )),
            "{dopo}"
        );
        assert!(!dopo.contains("PDF-1.7"), "i byte non entrano nella frase");
    }

    /// **Nessuna richiesta per un contenuto senza allegato descritto, né con
    /// un account diverso da quello del monitoraggio** (prove negative:
    /// Telegram non viene chiamato e non resta una riga).
    #[test]
    fn i_rifiuti_prima_di_chiedere_non_chiamano_telegram() {
        let (mut database, contenuto) = archivio(None);
        let mut mock = MockTelegramConnector::new();
        collegato(&mut mock);
        let KeepAttempt::Refused(perche) = chiedi(&mut mock, &mut database, contenuto, 10) else {
            panic!("senza allegato descritto non si chiede");
        };
        assert!(perche.contains("non ha un allegato"), "{perche}");

        let (mut database, contenuto) = archivio(Some(Some(18)));
        let Ok(sessione) = database.content(contenuto).map(|c| c.session_id) else {
            panic!("il contenuto si legge");
        };
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
        let KeepAttempt::Refused(perche) = chiedi(&mut mock, &mut database, contenuto, 10) else {
            panic!("un altro account non chiede per il monitoraggio di B");
        };
        assert!(perche.contains("Ufficio B"), "{perche}");
        assert_eq!(mock.attachment_calls(), 0, "Telegram non è stato chiamato");
        assert_eq!(
            database
                .attachment_keepings(contenuto)
                .map(|righe| righe.len())
                .ok(),
            Some(0)
        );
    }

    /// **Il tetto per allegato ferma prima di chiedere quando la dimensione
    /// dichiarata lo supera, e ferma dopo quando lo superano i byte; in
    /// entrambi i casi la richiesta resta, senza byte** (ADR-0177,
    /// decisioni 3 e 5).
    #[test]
    fn il_tetto_ferma_prima_e_dopo_e_lascia_traccia() {
        let (mut database, contenuto) = archivio(Some(Some(MAX_ATTACHMENT_BYTES + 1)));
        let mut mock = MockTelegramConnector::new();
        collegato(&mut mock);
        let KeepAttempt::Recorded { outcome, .. } = chiedi(&mut mock, &mut database, contenuto, 10)
        else {
            panic!("la richiesta fermata si registra");
        };
        assert_eq!(outcome, "fermato");
        assert_eq!(mock.attachment_calls(), 0, "fermato prima di chiedere");

        // La dimensione non dichiarata: si chiede, e i byte oltre il tetto
        // si fermano.
        let (mut database, contenuto) = archivio(Some(None));
        let Ok(troppi) = usize::try_from(MAX_ATTACHMENT_BYTES + 1) else {
            panic!("il tetto sta in un usize");
        };
        mock.set_attachment_reply(
            CHAT,
            MESSAGGIO,
            Ok(AttachmentReply::Fetched {
                bytes: vec![0; troppi],
                leftover: None,
            }),
        );
        let KeepAttempt::Recorded { outcome, .. } = chiedi(&mut mock, &mut database, contenuto, 10)
        else {
            panic!("la richiesta fermata si registra");
        };
        assert_eq!(outcome, "fermato");
        assert_eq!(mock.attachment_calls(), 1);
        assert_eq!(database.kept_attachment(contenuto).ok(), Some(None));
        let Ok(righe) = database.attachment_keepings(contenuto) else {
            panic!("le richieste si leggono");
        };
        assert!(
            righe
                .iter()
                .all(|riga| riga.size.is_none() && riga.outcome_detail.is_some()),
            "nessun byte, e il perché"
        );
    }

    /// **Un rifiuto di Telegram e una richiesta senza risposta restano, ognuna
    /// con il suo esito, e non impediscono di riprovare con un altro gesto**
    /// (ADR-0177, decisioni 3 e 4).
    #[test]
    fn rifiuti_e_silenzi_restano_e_si_puo_riprovare() {
        let (mut database, contenuto) = archivio(Some(Some(18)));
        let mut mock = MockTelegramConnector::new();
        collegato(&mut mock);
        mock.set_attachment_reply(
            CHAT,
            MESSAGGIO,
            Ok(AttachmentReply::Refused {
                code: 400,
                message: String::from("MESSAGE_ID_INVALID"),
            }),
        );
        let KeepAttempt::Recorded { outcome, .. } = chiedi(&mut mock, &mut database, contenuto, 10)
        else {
            panic!("il rifiuto si registra");
        };
        assert_eq!(outcome, "rifiutato");
        mock.set_attachment_reply(
            CHAT,
            MESSAGGIO,
            Err(TelegramError::Timeout { millis: 60_000 }),
        );
        let KeepAttempt::Recorded { outcome, .. } = chiedi(&mut mock, &mut database, contenuto, 20)
        else {
            panic!("il silenzio si registra");
        };
        assert_eq!(outcome, "non_riuscito");
        mock.set_attachment_reply(
            CHAT,
            MESSAGGIO,
            Ok(AttachmentReply::Fetched {
                bytes: vec![1, 2, 3],
                leftover: Some(String::from("La copia di Telegram non si è cancellata.")),
            }),
        );
        let KeepAttempt::Recorded { outcome, .. } = chiedi(&mut mock, &mut database, contenuto, 30)
        else {
            panic!("la conservazione si registra");
        };
        assert_eq!(outcome, "conservato");
        let Ok(righe) = super::keepings(&database, contenuto) else {
            panic!("le richieste si leggono");
        };
        assert_eq!(
            righe.iter().map(|r| r.outcome.as_str()).collect::<Vec<_>>(),
            vec!["conservato", "non_riuscito", "rifiutato"]
        );
        assert_eq!(
            righe.first().and_then(|r| r.outcome_detail.as_deref()),
            Some("La copia di Telegram non si è cancellata."),
            "ciò che resta sul disco si dice"
        );
        assert_eq!(mock.attachment_calls(), 3, "una lettura per gesto");
    }

    /// **Un allegato non si apre** (ADR-0177, decisione 7). La guardia legge
    /// il codice di produzione dei moduli che toccano gli allegati: nessuno
    /// avvia un programma, apre la shell, decodifica, scompatta o scrive un
    /// file; la lettura dal connettore non usa il nome dichiarato e fa
    /// cancellare la copia di TDLib. Prova negativa: uno di questi nomi in uno
    /// di quei moduli → rossa.
    #[test]
    fn un_allegato_non_si_apre() {
        fn produzione(testo: &str) -> String {
            testo
                .split_once("#[cfg(test)]")
                .map_or(testo, |(prima, _)| prima)
                .lines()
                .filter(|riga| !riga.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n")
        }
        let moduli = [
            (
                "attachment_keeping.rs",
                include_str!("attachment_keeping.rs"),
            ),
            (
                "lisi-telegram/src/attachment.rs",
                include_str!("../../lisi-telegram/src/attachment.rs"),
            ),
            (
                "lisi-storage/src/repository/attachment.rs",
                include_str!("../../lisi-storage/src/repository/attachment.rs"),
            ),
            (
                "lisi-storage/src/repository/attachment_keeping.rs",
                include_str!("../../lisi-storage/src/repository/attachment_keeping.rs"),
            ),
            (
                "lisi-app/src/attachment.rs",
                include_str!("../../lisi-app/src/attachment.rs"),
            ),
        ];
        // LA SCHEDA NON LEGGE I BYTE (parte 3): mostra la descrizione e
        // l'impronta, mai il contenuto.
        assert!(
            !produzione(include_str!("../../lisi-app/src/attachment.rs"))
                .contains("kept_attachment_bytes"),
            "la scheda dell'allegato non legge i byte"
        );
        for (nome, testo) in moduli {
            let codice = produzione(testo);
            assert!(codice.len() > 500, "{nome}: la guardia non ha letto nulla");
            for vietato in [
                "std::process",
                "Command::new",
                "ShellExecute",
                "open::",
                "opener",
                "std::fs",
                "File::create",
                "image::",
                "zip::",
                "flate",
                "decode",
                "PathBuf",
            ] {
                assert!(
                    !codice.contains(vietato),
                    "{nome} usa «{vietato}»: un allegato non si apre"
                );
            }
        }
        let connettore = include_str!("../../lisi-telegram/src/tdlib/live.rs");
        let Some((_, lettura)) = connettore.split_once("fn fetch_attachment(") else {
            panic!("la lettura degli allegati del connettore deve esistere");
        };
        let lettura = lettura
            .split_once("\nimpl")
            .map_or(lettura, |(corpo, _)| corpo);
        for vietato in ["file_name", "declared_name", "std::process", "Command::new"] {
            assert!(
                !lettura.contains(vietato),
                "la lettura degli allegati usa «{vietato}»"
            );
        }
        assert!(
            lettura.contains("\"deleteFile\""),
            "la copia di TDLib si fa cancellare"
        );
    }
}

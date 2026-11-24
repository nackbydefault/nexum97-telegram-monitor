//! Il collegamento ufficiale a un messaggio, **chiesto a Telegram al momento**.
//!
//! # Perché esiste (CAPABILITY-AUDIT-02, CA02-14; ADR-0144, DG-02)
//!
//! LINK-01 ha tolto l'indirizzo composto dal prodotto: un collegamento si
//! chiede a Telegram (`getMessageLink`) e non si fabbrica. Il connettore sapeva
//! chiederlo, ma **nessuno lo chiamava**: l'acquisizione scrive `url: None` per
//! scelta, e «Apri collegamento» compariva soltanto sui contenuti archiviati
//! prima di LINK-01. Il primo passo di HVQ-38 — «chiedere il collegamento» —
//! non si poteva eseguire dalla schermata.
//!
//! # Chiedere non scrive niente
//!
//! Come il contesto (`crate::context`), questo servizio **legge** il
//! contenuto dall'archivio e **chiede** a Telegram. Non scrive nell'archivio né
//! nell'audit: il collegamento è una risposta di adesso, non un fatto
//! acquisito, e conservarlo accanto al testo lo farebbe sembrare una prova
//! (DG-02: «mai conservato come prova»). Una prova lo verifica sul sorgente.
//!
//! # Che cosa si dichiara
//!
//! L'istante della richiesta, se Telegram ha fornito un collegamento, se è
//! **pubblico** o si apre solo per i membri della conversazione, e, se manca,
//! perché manca. Le frasi le compone `lisi_telegram::link`, in un posto solo.

use lisi_core::{ContentId, Timestamp};
use lisi_storage::Database;
use lisi_telegram::{ChatId, LinkGap, LinkOutcome, MessageId, TelegramConnector};

use crate::error::{ServiceError, ServiceResult};

/// L'esito di una richiesta del collegamento a un messaggio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRequest {
    /// Il contenuto per cui si è chiesto.
    pub content_id: ContentId,
    /// Quando si è chiesto: il collegamento vale per quel momento.
    pub asked_at: Timestamp,
    outcome: LinkOutcome,
}

impl LinkRequest {
    /// L'indirizzo fornito da Telegram, se c'è.
    #[must_use]
    pub fn url(&self) -> Option<&str> {
        self.outcome.link().map(lisi_telegram::MessageLink::as_str)
    }

    /// Se Telegram lo dichiara utilizzabile da chiunque. `false` anche quando
    /// non c'è.
    #[must_use]
    pub fn is_public(&self) -> bool {
        self.outcome
            .link()
            .is_some_and(lisi_telegram::MessageLink::is_public)
    }

    /// Che cosa è successo, con l'istante della richiesta.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        format!(
            "Chiesto a Telegram il {}. {} Il collegamento non viene conservato: vale per il \
             momento in cui è stato chiesto.",
            self.asked_at.to_readable_local(),
            self.outcome.as_sentence()
        )
    }
}

/// Che cosa un documento scrive al posto del collegamento che non conserva
/// (ADR-0152, DG-02).
///
/// # Perché una frase e non «non disponibile»
///
/// Perché «non disponibile» non dice perché, e chi legge una relazione può
/// capire che Telegram non abbia un indirizzo per quel messaggio, o che il
/// programma l'abbia perso. Il collegamento non si conserva per scelta: si
/// chiede a Telegram al momento, e il documento non lo ha chiesto.
pub const IN_DOCUMENTS_NOT_KEPT: &str =
    "non conservato: si chiede a Telegram al momento, e questo documento non lo ha chiesto";

/// Da dove viene un indirizzo conservato nell'archivio, detto come lo legge
/// chi apre un documento o la conversazione (DEC-416).
///
/// Prima di LINK-01 il programma **componeva** l'indirizzo dai due
/// identificativi; dopo, non ne conserva più. Nessun indirizzo dell'archivio è
/// quindi stato fornito da Telegram, e la frase non lo dice.
pub const ARCHIVED_PROVENANCE: &str =
    "composto dal programma all'acquisizione, non fornito da Telegram";

/// Il collegamento di un contenuto come lo scrive un documento.
///
/// Un indirizzo conservato all'acquisizione (prima di LINK-01) si riporta
/// dicendo che il programma lo ha composto; altrimenti la frase dice perché
/// manca. **Nessun indirizzo si compone.**
#[must_use]
pub fn in_documents(archived: Option<&str>) -> String {
    archived.filter(|url| !url.trim().is_empty()).map_or_else(
        || String::from(IN_DOCUMENTS_NOT_KEPT),
        |url| format!("{url} ({ARCHIVED_PROVENANCE})"),
    )
}

/// Chiede a Telegram il collegamento ufficiale al messaggio di un contenuto.
///
/// Senza connettore — nessun account collegato — l'esito è
/// [`LinkGap::ConnectorUnavailable`], non un errore: è il caso normale di chi
/// lavora senza Telegram, e la frase lo dice.
///
/// # Errori
///
/// Restituisce un errore se il contenuto o la sua fonte non si leggono, o se la
/// richiesta non si può nemmeno inviare.
pub fn request(
    database: &Database,
    connector: Option<&mut dyn TelegramConnector>,
    content_id: ContentId,
    now: Timestamp,
) -> ServiceResult<LinkRequest> {
    let content = database.content(content_id)?;
    let source = database.source(content.source_id)?;

    let risposta = |outcome| LinkRequest {
        content_id,
        asked_at: now,
        outcome,
    };

    let Some(connector) = connector else {
        return Ok(risposta(LinkOutcome::NotProvided(
            LinkGap::ConnectorUnavailable,
        )));
    };

    // Gli identificativi remoti sono numeri conservati come testo. Uno che non
    // si legge è un messaggio che non si può chiedere: Telegram non ne darebbe
    // il collegamento, e lo si dice con la stessa frase.
    let identificativi = source
        .identifier
        .as_str()
        .parse::<i64>()
        .ok()
        .and_then(|chat| ChatId::try_new(chat).ok())
        .zip(
            content
                .remote_message_id
                .as_str()
                .parse::<i64>()
                .ok()
                .and_then(|message| MessageId::try_new(message).ok()),
        );
    let Some((chat_id, message_id)) = identificativi else {
        return Ok(risposta(LinkOutcome::NotProvided(
            LinkGap::NotOfferedByTelegram,
        )));
    };

    let outcome = connector
        .message_link(chat_id, message_id)
        .map_err(ServiceError::Connector)?;
    Ok(risposta(outcome))
}

/// Quanti collegamenti, al più, si chiedono per una relazione (ADR-0165).
pub const MAX_DOCUMENT_LINKS: usize = 20;

/// I collegamenti chiesti a Telegram **per un documento**, già in frase, per
/// numero di contenuto (CONTEXT-02, ADR-0165). Vivono nel documento prodotto:
/// non entrano nell'archivio.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkBook {
    frasi: std::collections::BTreeMap<i64, String>,
}

impl LinkBook {
    /// La frase del collegamento di un contenuto, se è stato chiesto o se si
    /// dice perché non è stato chiesto.
    #[must_use]
    pub fn sentence_for(&self, content_id: ContentId) -> Option<&str> {
        self.frasi.get(&content_id.get()).map(String::as_str)
    }

    /// Quanti contenuti ha una frase.
    #[must_use]
    pub fn len(&self) -> usize {
        self.frasi.len()
    }

    /// Se non ha frasi.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frasi.is_empty()
    }

    /// Scrive la frase del collegamento di un contenuto.
    pub(crate) fn insert(&mut self, content_id: ContentId, frase: String) {
        self.frasi.insert(content_id.get(), frase);
    }
}

/// Chiede a Telegram il collegamento dei contenuti indicati, per un documento:
/// al più [`MAX_DOCUMENT_LINKS`], uno per volta, fermandosi al primo errore.
/// Ogni contenuto ha la sua frase: fornito, mancante con il perché, oppure non
/// chiesto con il perché.
///
/// # Errori
///
/// Restituisce un errore se un contenuto o la sua fonte non si leggono.
pub fn ask_for_documents(
    database: &Database,
    connector: &mut dyn TelegramConnector,
    contents: &[ContentId],
    now: Timestamp,
) -> ServiceResult<LinkBook> {
    let mut libro = LinkBook::default();
    let mut fermato: Option<String> = None;
    for (indice, &content_id) in contents.iter().enumerate() {
        if let Some(perche) = fermato.as_ref() {
            libro.insert(content_id, perche.clone());
            continue;
        }
        if indice >= MAX_DOCUMENT_LINKS {
            libro.insert(
                content_id,
                format!(
                    "non chiesto: questo documento chiede a Telegram al pi\u{f9} \
                     {MAX_DOCUMENT_LINKS} collegamenti"
                ),
            );
            continue;
        }
        match request(database, Some(&mut *connector), content_id, now) {
            Ok(risposta) => {
                libro.insert(content_id, document_sentence(&risposta));
            }
            Err(ServiceError::Connector(_)) => {
                let perche = String::from(
                    "non chiesto: Telegram non ha risposto a una richiesta precedente, e il \
                     documento ha smesso di chiedere",
                );
                libro.insert(content_id, perche.clone());
                fermato = Some(perche);
            }
            Err(altro) => return Err(altro),
        }
    }
    Ok(libro)
}

/// La frase del collegamento chiesto, come la scrive un documento.
fn document_sentence(risposta: &LinkRequest) -> String {
    let quando = risposta.asked_at.to_readable_utc();
    match risposta.url() {
        Some(url) => format!(
            "{url} (fornito da Telegram il {quando}, {})",
            if risposta.is_public() {
                "pubblico"
            } else {
                "soltanto per chi fa parte della conversazione"
            }
        ),
        None => format!(
            "chiesto a Telegram il {quando}: {}",
            risposta.outcome.as_sentence()
        ),
    }
}

/// Il collegamento di un contenuto come lo scrive un documento: quello
/// chiesto per il documento, se c'è, altrimenti [`in_documents`].
#[must_use]
pub fn in_documents_with(asked: Option<&str>, archived: Option<&str>) -> String {
    asked.map_or_else(|| in_documents(archived), str::to_owned)
}

/// La pagina pubblica della fonte di un contenuto, per «Apri la fonte»
/// (ADR-0165): l'indirizzo e la frase che dice che si apre la fonte, non il
/// messaggio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcePage {
    /// L'indirizzo da aprire.
    pub url: String,
    /// Che cosa si apre, in una frase.
    pub sentence: String,
}

/// La pagina pubblica della fonte di un contenuto, se la fonte ha un indirizzo
/// pubblico visto.
///
/// # Errori
///
/// Restituisce un errore se il contenuto o l'indirizzo non si leggono.
pub fn source_page(
    database: &Database,
    content_id: ContentId,
) -> ServiceResult<Option<SourcePage>> {
    let content = database.content(content_id)?;
    let Some(visto) = database.source_address(content.source_id)? else {
        return Ok(None);
    };
    let Some(indirizzo) = lisi_core::model::discovery::PublicAddress::try_new(&visto.address)
    else {
        return Ok(None);
    };
    Ok(Some(SourcePage {
        url: indirizzo.public_url(),
        sentence: format!(
            "Si apre la pagina pubblica della fonte, @{}, non il messaggio. Il nome era questo il \
             {}, e un nome utente pu\u{f2} passare a un'altra chat.",
            indirizzo.as_str(),
            visto.observed_at.to_readable_local()
        ),
    }))
}

#[cfg(test)]
mod tests {
    use lisi_core::model::{AcquisitionOrigin, NewSession, NewSource, SessionDuration, SourceKind};
    use lisi_core::text::{Actor, ContentBody, DisplayName, RemoteMessageId, SourceIdentifier};
    use lisi_core::{ContentId, Timestamp};
    use lisi_storage::Database;
    use lisi_telegram::{
        AccessibleChat, AuthorizationState, ChatId, ClientParameters, ConnectionState,
        ConnectorEvent, ContextMessage, IncomingMessage, LinkGap, LinkOutcome, LoginCode,
        MessageId, MessageLink, PhoneNumber, TelegramConnector, TelegramResult, TwoFactorPassword,
    };

    use super::request;
    use crate::analysis::{AnalysisService, NewContentDraft};

    const ORA: i64 = 1_760_000_000_000;

    /// Un connettore che risponde alla richiesta del collegamento con l'esito
    /// indicato, e ricorda che cosa gli è stato chiesto.
    #[derive(Debug)]
    struct CollegamentoFinto {
        risposta: LinkOutcome,
        chiesto: Option<(i64, i64)>,
        /// Se Telegram non risponde: il documento deve smettere di chiedere.
        fallisce: bool,
    }

    impl TelegramConnector for CollegamentoFinto {
        fn start(&mut self, _parameters: &ClientParameters) -> TelegramResult<()> {
            Ok(())
        }
        fn submit_phone_number(&mut self, _phone: &PhoneNumber) -> TelegramResult<()> {
            Ok(())
        }
        fn submit_code(&mut self, _code: &LoginCode) -> TelegramResult<()> {
            Ok(())
        }
        fn submit_password(&mut self, _password: &TwoFactorPassword) -> TelegramResult<()> {
            Ok(())
        }
        fn poll_event(
            &mut self,
            _timeout: std::time::Duration,
        ) -> TelegramResult<Option<ConnectorEvent>> {
            Ok(None)
        }
        fn accessible_chats(&mut self) -> TelegramResult<Vec<AccessibleChat>> {
            Ok(Vec::new())
        }
        fn fetch_history(
            &mut self,
            _chat_id: ChatId,
            _from_message_id: i64,
            _limit: u32,
        ) -> TelegramResult<Vec<IncomingMessage>> {
            Ok(Vec::new())
        }
        fn fetch_context(
            &mut self,
            _chat_id: ChatId,
            _around: MessageId,
            _before: u32,
            _after: u32,
        ) -> TelegramResult<Vec<ContextMessage>> {
            Ok(Vec::new())
        }
        fn message_link(
            &mut self,
            chat_id: ChatId,
            message_id: MessageId,
        ) -> TelegramResult<LinkOutcome> {
            self.chiesto = Some((chat_id.get(), message_id.get()));
            if self.fallisce {
                return Err(lisi_telegram::TelegramError::Timeout { millis: 10 });
            }
            Ok(self.risposta.clone())
        }
        fn authorization_state(&self) -> AuthorizationState {
            AuthorizationState::Ready
        }
        fn connection_state(&self) -> ConnectionState {
            ConnectionState::Online
        }
        fn shutdown(&mut self) -> TelegramResult<()> {
            Ok(())
        }
    }

    /// Un archivio con un contenuto di una fonte con identificativo numerico.
    fn archivio_con_contenuto() -> (Database, ContentId) {
        let Ok(mut database) = crate::sources::open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        let (Ok(identifier), Ok(title), Ok(label), Ok(attore)) = (
            SourceIdentifier::try_new("-1001"),
            DisplayName::try_new("Canale di prova"),
            DisplayName::try_new("Sessione di prova"),
            Actor::try_new("operatore.prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(source_id) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier,
                display_name: title,
                authorized_by: attore.clone(),
                active: true,
            },
            Timestamp::from_millis(ORA),
        ) else {
            panic!("la fonte deve potersi registrare");
        };
        let Ok(session_id) = database.insert_session(
            &NewSession {
                label,
                started_by: attore.clone(),
                duration: SessionDuration::Preset { seconds: 3_600 },
                source_ids: vec![source_id],
            },
            Timestamp::from_millis(ORA),
        ) else {
            panic!("la sessione deve potersi creare");
        };
        let (Ok(remote), Ok(body)) = (
            RemoteMessageId::try_new("500"),
            ContentBody::try_new("il testo acquisito"),
        ) else {
            panic!("i valori del contenuto devono essere validi");
        };
        let mut analysis = AnalysisService::new(database);
        let Ok(record) = analysis.analyse_and_record(
            &NewContentDraft {
                session_id,
                source_id,
                remote_message_id: remote,
                author: None,
                author_identifier: None,
                author_username: None,
                body,
                url: None,
                published_at: Timestamp::from_millis(ORA),
                acquired_at: Timestamp::from_millis(ORA),
                origin: AcquisitionOrigin::Observed,
            },
            &lisi_core::model::dictionary::ResolvedDictionaryConfiguration::from_terms(Vec::new()),
            &attore,
            Timestamp::from_millis(ORA),
        ) else {
            panic!("l'analisi deve riuscire");
        };
        let Some(content_id) = record.content_id else {
            panic!("il contenuto doveva essere registrato");
        };
        (analysis.into_database(), content_id)
    }

    /// Quante righe ha l'audit: chiedere non deve aggiungerne.
    fn righe_di_audit(database: &Database) -> usize {
        database.audit_entries().map_or(0, |righe| righe.len())
    }

    /// **Il collegamento si chiede a Telegram, con i due identificativi del
    /// contenuto, e si dichiara pubblico o no** (CA02-14, DG-02).
    #[test]
    fn il_collegamento_si_chiede_e_si_dichiara() {
        let (database, id) = archivio_con_contenuto();
        let Some(link) = MessageLink::from_telegram("https://t.me/canale/500", true) else {
            panic!("l'indirizzo di prova deve essere valido");
        };
        let mut connettore = CollegamentoFinto {
            risposta: LinkOutcome::Provided(link),
            chiesto: None,
            fallisce: false,
        };
        let prima = righe_di_audit(&database);

        let Ok(esito) = request(
            &database,
            Some(&mut connettore),
            id,
            Timestamp::from_millis(ORA + 60_000),
        ) else {
            panic!("la richiesta deve riuscire");
        };
        assert_eq!(connettore.chiesto, Some((-1001, 500)));
        assert_eq!(esito.url(), Some("https://t.me/canale/500"));
        assert!(esito.is_public());
        let frase = esito.as_sentence();
        assert!(frase.contains("Chiesto a Telegram il"), "{frase}");
        assert!(frase.contains("pubblico"), "{frase}");
        assert!(frase.contains("non viene conservato"), "{frase}");

        assert_eq!(
            righe_di_audit(&database),
            prima,
            "chiedere non scrive l'audit"
        );
        let Ok(contenuto) = database.content(id) else {
            panic!("il contenuto deve rileggersi");
        };
        assert!(contenuto.url.is_none(), "chiedere non scrive nell'archivio");
    }

    /// **Senza account collegato non si inventa nulla**: nessun indirizzo, e
    /// la frase dice perché.
    #[test]
    fn senza_collegamento_non_c_e_un_indirizzo() {
        let (database, id) = archivio_con_contenuto();
        let Ok(esito) = request(&database, None, id, Timestamp::from_millis(ORA)) else {
            panic!("senza connettore l'esito c'è comunque");
        };
        assert_eq!(esito.url(), None);
        assert!(!esito.is_public());
        assert!(esito.as_sentence().contains("Non c'"));

        let mut rifiuta = CollegamentoFinto {
            risposta: LinkOutcome::NotProvided(LinkGap::NotOfferedByTelegram),
            chiesto: None,
            fallisce: false,
        };
        let Ok(esito) = request(
            &database,
            Some(&mut rifiuta),
            id,
            Timestamp::from_millis(ORA),
        ) else {
            panic!("un rifiuto è un esito, non un errore");
        };
        assert_eq!(esito.url(), None);
        assert!(esito.as_sentence().contains("Resta la fonte"));
    }

    /// Il servizio non ha modo di scrivere: nessuna chiamata che inserisca,
    /// aggiorni o registri, nel codice di produzione.
    #[test]
    fn chiedere_non_ha_modo_di_scrivere() {
        let sorgente = include_str!("message_link.rs");
        let Some((produzione, _)) = sorgente.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        for vietata in ["insert_", "update_", "record_", "&mut Database", "audit"] {
            let usata = produzione
                .lines()
                .filter(|riga| !riga.trim_start().starts_with("//"))
                .any(|riga| riga.contains(vietata));
            assert!(
                !usata,
                "il servizio del collegamento non deve usare «{vietata}»"
            );
        }
    }

    /// **Nei documenti il collegamento c'è, o si dice perché manca**
    /// (ADR-0152, criteri 1 e 2).
    #[test]
    fn nei_documenti_il_collegamento_c_e_o_si_dice_perche_manca() {
        assert_eq!(
            super::in_documents(None),
            super::IN_DOCUMENTS_NOT_KEPT,
            "senza indirizzo, la frase che dice perche'"
        );
        assert_eq!(
            super::in_documents(Some("  ")),
            super::IN_DOCUMENTS_NOT_KEPT
        );
        // Fino al 2026-10-19 questa prova pretendeva «fornito da Telegram
        // all'acquisizione», cioè la provenienza sbagliata (DEC-416).
        assert_eq!(
            super::in_documents(Some("https://t.me/canale/7")),
            "https://t.me/canale/7 (composto dal programma all'acquisizione, non fornito da \
             Telegram)"
        );
    }

    /// **Un indirizzo conservato non si attribuisce a Telegram**
    /// (DEC-416, NEXUM97-FULL-OPERATIONAL-VALIDATION-01).
    ///
    /// Prima di LINK-01 il programma componeva l'indirizzo dai due
    /// identificativi: in una relazione vera del 2026-10-19 un contenuto del
    /// 20 agosto risultava «fornito da Telegram all'acquisizione», cioè una
    /// deduzione del programma presentata come un fatto di Telegram.
    #[test]
    fn un_indirizzo_conservato_non_si_attribuisce_a_telegram() {
        let frase = super::in_documents(Some("https://t.me/c/1234567890/302419"));
        assert!(
            frase.starts_with("https://t.me/c/1234567890/302419 "),
            "l'indirizzo conservato resta: è un dato dell'archivio ({frase})"
        );
        assert!(
            !frase.contains("fornito da Telegram all"),
            "un indirizzo composto dal programma non è fornito da Telegram: {frase}"
        );
        assert!(frase.contains("composto dal programma"), "{frase}");
    }

    /// **Ogni documento usa la stessa frase, e nessuno la riscrive**
    /// (criteri 1, 3 e 4).
    ///
    /// Una riga «Collegamento» che stampasse l'indirizzo da se', o «non
    /// disponibile», tornerebbe a non dire perche'.
    #[test]
    fn ogni_documento_usa_la_stessa_frase() {
        for (nome, sorgente) in [
            ("report_narrative.rs", include_str!("report_narrative.rs")),
            ("report_annex.rs", include_str!("report_annex.rs")),
            ("report_ledger.rs", include_str!("report_ledger.rs")),
            ("export.rs", include_str!("export.rs")),
        ] {
            let Some((produzione, _)) = sorgente.split_once("#[cfg(test)]") else {
                panic!("{nome} deve avere un blocco di prove");
            };
            // Le due strade comuni: `in_documents_with` per i documenti che
            // possono portare il collegamento chiesto (ADR-0165), e che senza
            // richiesta ricade su `in_documents`.
            assert!(
                produzione.contains("message_link::in_documents(")
                    || produzione.contains("message_link::in_documents_with("),
                "{nome} deve scrivere il collegamento con la frase di message_link"
            );
            for vecchia in [
                "url.as_deref().unwrap_or(NOT_AVAILABLE)",
                "Cell::optional(content.url",
                "optional(finding.url",
                "Collegamento: {}\n\", url.as_str()",
                "non conservato: si chiede",
            ] {
                assert!(
                    !produzione.contains(vecchia),
                    "{nome} scrive il collegamento a modo suo: «{vecchia}»"
                );
            }
        }
    }

    /// **Per un documento si chiedono i collegamenti dei contenuti scelti,
    /// al più venti; oltre il tetto lo si dice, e il collegamento si dichiara
    /// fornito da Telegram** (CONTEXT-02, criterio 1; prova negativa: tetto
    /// tolto → rossa).
    #[test]
    fn i_collegamenti_di_un_documento_si_chiedono_fino_al_tetto() {
        let (database, id) = archivio_con_contenuto();
        let Some(link) = MessageLink::from_telegram("https://t.me/canale/500", false) else {
            panic!("l'indirizzo di prova deve essere valido");
        };
        let mut connettore = CollegamentoFinto {
            risposta: LinkOutcome::Provided(link),
            chiesto: None,
            fallisce: false,
        };
        let mut scelti = vec![id; super::MAX_DOCUMENT_LINKS];
        scelti.push(ContentId::new(999));
        let Ok(libro) = super::ask_for_documents(
            &database,
            &mut connettore,
            &scelti,
            Timestamp::from_millis(ORA),
        ) else {
            panic!("le richieste devono riuscire");
        };
        let Some(frase) = libro.sentence_for(id) else {
            panic!("il contenuto chiesto ha la sua frase");
        };
        assert!(
            frase.starts_with("https://t.me/canale/500 (fornito da Telegram il"),
            "{frase}"
        );
        assert!(
            frase.contains("soltanto per chi fa parte della conversazione"),
            "{frase}"
        );
        let Some(oltre) = libro.sentence_for(ContentId::new(999)) else {
            panic!("anche il contenuto oltre il tetto ha la sua frase");
        };
        assert!(oltre.contains("al pi\u{f9} 20 collegamenti"), "{oltre}");
        assert_eq!(
            super::in_documents_with(Some(frase), None),
            frase,
            "il documento scrive la frase chiesta"
        );
        assert_eq!(
            super::in_documents_with(None, None),
            super::IN_DOCUMENTS_NOT_KEPT,
            "senza richiesta resta la frase di sempre"
        );
    }

    /// **Al primo errore di Telegram il documento smette di chiedere, e lo
    /// dice** (criterio 1).
    #[test]
    fn al_primo_errore_il_documento_smette_di_chiedere() {
        let (database, id) = archivio_con_contenuto();
        let mut connettore = CollegamentoFinto {
            risposta: LinkOutcome::NotProvided(LinkGap::NotOfferedByTelegram),
            chiesto: None,
            fallisce: true,
        };
        let Ok(libro) = super::ask_for_documents(
            &database,
            &mut connettore,
            &[id, ContentId::new(999)],
            Timestamp::from_millis(ORA),
        ) else {
            panic!("un errore di Telegram non ferma il documento");
        };
        for numero in [id, ContentId::new(999)] {
            let Some(frase) = libro.sentence_for(numero) else {
                panic!("ogni contenuto ha la sua frase");
            };
            assert!(frase.contains("ha smesso di chiedere"), "{frase}");
        }
    }

    /// **«Apri la fonte» apre la pagina pubblica della fonte e lo dice; senza
    /// indirizzo visto non c'è** (criterio 4).
    #[test]
    fn apri_la_fonte_si_offre_soltanto_con_un_indirizzo_visto() {
        let (database, id) = archivio_con_contenuto();
        assert_eq!(super::source_page(&database, id).ok(), Some(None));
        let Ok(contenuto) = database.content(id) else {
            panic!("il contenuto deve leggersi");
        };
        let Ok(()) = database.record_source_address(
            contenuto.source_id,
            "canale_cyber",
            Timestamp::from_millis(ORA),
        ) else {
            panic!("l'indirizzo deve registrarsi");
        };
        let Ok(Some(pagina)) = super::source_page(&database, id) else {
            panic!("con un indirizzo visto la fonte si apre");
        };
        assert_eq!(pagina.url, "https://t.me/canale_cyber");
        assert!(
            pagina.sentence.contains("non il messaggio"),
            "{}",
            pagina.sentence
        );
        assert!(
            pagina.sentence.contains("un'altra chat"),
            "{}",
            pagina.sentence
        );
    }
}

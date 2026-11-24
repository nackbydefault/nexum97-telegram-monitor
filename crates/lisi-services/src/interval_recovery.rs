//! Il recupero per intervallo (PR-07, ADR-0123).
//!
//! # Da un periodo deciso, per una fonte, per un intervallo
//!
//! Un periodo non coperto che una persona ha deciso «da valutare per un
//! recupero» (PR-06) si guarda qui: si legge la cronologia di **quella fonte**,
//! **per quell'intervallo**, e si dice quanti messaggi dell'intervallo non sono
//! in archivio. Poi, **solo dopo la conferma**, si archiviano come recuperati,
//! e l'operazione si registra: chi, quando, per quale intervallo.
//!
//! # Che cosa non fa
//!
//! - **Non parte da solo.** Ricognizione e archiviazione sono due comandi di
//!   una persona.
//! - **Non riscrive.** Un messaggio già in archivio non diventa recuperato; se
//!   la cronologia lo mostra con un testo diverso, si aggiunge una **versione**.
//! - **Non esce dal monitoraggio.** Un contenuto appartiene a un monitoraggio;
//!   ciò che ne sta fuori è lo storico aggiuntivo di PR-08.
//! - **Non usa altro che la lettura della cronologia esistente** (MP-16.1), con
//!   il tetto di pagine del recupero esistente. Nessun nuovo punto di chiamata,
//!   Stars a zero.
//!
//! # Perché la richiesta vuole l'autorità di acquisizione
//!
//! [`IntervalRecoveryRequest`] si costruisce soltanto con
//! un'[`AcquisitionAuthority`], che una postazione Team non ottiene: su un
//! client, la richiesta **non si compila**. È una capacità, non un controllo, e
//! la prova che non si fabbrica è nel modulo che la concede
//! ([`crate::acquisition_authority`]).

use std::collections::BTreeMap;

use lisi_core::model::NewAuditEntry;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{ContentId, SessionId, SourceId, Timestamp};
use lisi_storage::Database;
use lisi_storage::repository::recovery_operation::NewRecoveryOperation;
use lisi_telegram::identifier::ChatId;
use lisi_telegram::{IncomingMessage, TelegramConnector};

use crate::acquisition::{AcquisitionService, SessionContext};
use crate::acquisition_authority::AcquisitionAuthority;
use crate::error::{ServiceError, ServiceResult};

/// Messaggi per pagina di cronologia, come il recupero esistente.
const PAGE_SIZE: u32 = 100;

/// Pagine lette al più, come il recupero esistente.
const MAX_PAGES: usize = 1_000;

/// L'azione d'audit di un recupero per intervallo archiviato.
pub const INTERVAL_RECOVERY_AUDIT_ACTION: &str = "recupero_per_intervallo_archiviato";

/// Una richiesta di recupero per intervallo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntervalRecoveryRequest {
    session_id: SessionId,
    source_id: SourceId,
    chat_id: ChatId,
    from: Timestamp,
    to: Timestamp,
    operator: Actor,
}

impl IntervalRecoveryRequest {
    /// Costruisce la richiesta. **Vuole l'autorità di acquisizione**: senza, non
    /// esiste.
    ///
    /// Restituisce `None` per un intervallo vuoto o rovesciato.
    #[must_use]
    pub fn new(
        _autorita: &AcquisitionAuthority,
        session_id: SessionId,
        source_id: SourceId,
        chat_id: ChatId,
        (from, to): (Timestamp, Timestamp),
        operator: Actor,
    ) -> Option<Self> {
        if to <= from {
            return None;
        }
        Some(Self {
            session_id,
            source_id,
            chat_id,
            from,
            to,
            operator,
        })
    }

    /// L'intervallo richiesto.
    #[must_use]
    pub const fn interval(&self) -> (Timestamp, Timestamp) {
        (self.from, self.to)
    }
}

/// Che cosa la ricognizione di un intervallo ha trovato.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IntervalSurvey {
    /// I messaggi dell'intervallo che non sono in archivio.
    pub missing: Vec<IncomingMessage>,
    /// I messaggi già in archivio con un testo diverso da quello conservato.
    pub changed: Vec<IncomingMessage>,
    /// Quanti messaggi dell'intervallo erano già in archivio, uguali.
    pub already_present: usize,
    /// Se la lettura è arrivata all'inizio dell'intervallo.
    pub reached_start: bool,
    /// Il motivo per cui l'intervallo non è recuperabile, quando non lo è.
    pub not_recoverable: Option<String>,
    /// L'istante del messaggio più vecchio letto, in millisecondi: dice fin dove
    /// la lettura è arrivata quando non ha raggiunto l'inizio (FR-010).
    pub oldest_seen_millis: Option<i64>,
}

impl IntervalSurvey {
    /// L'intervallo davvero letto: tutto quello chiesto se la lettura ne ha
    /// raggiunto l'inizio, altrimenti dal messaggio più vecchio letto.
    ///
    /// FINAL-REVIEW-01, FR-010: fino al 2026-10-03 si registrava sempre
    /// l'intervallo chiesto, e dopo il tetto di pagine la copertura mostrava
    /// «recuperato» per un tratto mai letto. È la stessa regola dello storico
    /// precedente (`source_history`).
    #[must_use]
    pub fn read_interval(&self, from: Timestamp, to: Timestamp) -> Option<(Timestamp, Timestamp)> {
        if self.reached_start {
            return Some((from, to));
        }
        self.oldest_seen_millis
            .map(|piu_vecchio| {
                (
                    Timestamp::from_millis(piu_vecchio.max(from.as_millis())),
                    to,
                )
            })
            .filter(|(da, a)| da < a)
    }

    /// La frase per l'operatore.
    #[must_use]
    pub fn operator_message(&self) -> String {
        if let Some(motivo) = &self.not_recoverable {
            return format!("Non recuperabile: {motivo}");
        }
        let mut frase = match self.missing.len() {
            0 => String::from("Nell'intervallo non manca nessun messaggio letto nella cronologia."),
            1 => String::from("Nell'intervallo manca 1 messaggio letto nella cronologia."),
            quanti => format!("Nell'intervallo mancano {quanti} messaggi letti nella cronologia."),
        };
        if !self.changed.is_empty() {
            frase.push_str(&format!(
                " {} messaggi già in archivio hanno oggi un testo diverso: si aggiunge una \
                 versione, e quella conservata resta.",
                self.changed.len()
            ));
        }
        if !self.reached_start {
            frase.push_str(
                " La lettura si è fermata prima dell'inizio dell'intervallo: potrebbero \
                 essercene altri.",
            );
        }
        frase.push(' ');
        frase.push_str(lisi_core::model::RECOVERY_LIMITS);
        frase
    }
}

/// Legge la cronologia della fonte per l'intervallo richiesto. **Non scrive.**
#[must_use]
pub fn survey(
    connector: &mut dyn TelegramConnector,
    database: &Database,
    richiesta: &IntervalRecoveryRequest,
) -> IntervalSurvey {
    let conosciuti = match conosciuti(database, richiesta) {
        Ok(conosciuti) => conosciuti,
        Err(errore) => {
            return IntervalSurvey {
                not_recoverable: Some(format!(
                    "l'archivio non si è potuto leggere ({})",
                    errore.kind()
                )),
                ..IntervalSurvey::default()
            };
        }
    };

    let mut trovato = IntervalSurvey::default();
    let mut da_messaggio = 0_i64;
    for _ in 0..MAX_PAGES {
        let pagina = match connector.fetch_history(richiesta.chat_id, da_messaggio, PAGE_SIZE) {
            Ok(pagina) => pagina,
            Err(errore) => {
                return IntervalSurvey {
                    not_recoverable: Some(crate::source_history::history_read_failure(&errore)),
                    ..IntervalSurvey::default()
                };
            }
        };
        if pagina.is_empty() {
            trovato.reached_start = true;
            break;
        }
        if let Some(ultimo) = pagina.last() {
            da_messaggio = ultimo.message_id.get();
        }

        let mut oltre_l_inizio = false;
        for messaggio in pagina {
            trovato.oldest_seen_millis = Some(
                trovato
                    .oldest_seen_millis
                    .map_or(messaggio.published_at_millis, |prima| {
                        prima.min(messaggio.published_at_millis)
                    }),
            );
            if messaggio.published_at_millis >= richiesta.to.as_millis() {
                continue;
            }
            if messaggio.published_at_millis < richiesta.from.as_millis() {
                oltre_l_inizio = true;
                continue;
            }
            match conosciuti.get(&messaggio.message_id.get().to_string()) {
                None => trovato.missing.push(messaggio),
                Some(testo) if *testo != messaggio.text => trovato.changed.push(messaggio),
                Some(_) => trovato.already_present += 1,
            }
        }
        if oltre_l_inizio {
            trovato.reached_start = true;
            break;
        }
    }
    trovato
}

/// I messaggi della fonte già in archivio nel monitoraggio, con il testo più
/// recente che l'archivio conserva.
fn conosciuti(
    database: &Database,
    richiesta: &IntervalRecoveryRequest,
) -> ServiceResult<BTreeMap<String, String>> {
    let mut testi = BTreeMap::new();
    for contenuto in database.session_contents(richiesta.session_id)? {
        if contenuto.source_id != richiesta.source_id {
            continue;
        }
        let ultimo = database
            .content_versions(contenuto.id)?
            .into_iter()
            .max_by_key(|versione| versione.version_number)
            .map_or_else(
                || contenuto.body.as_str().to_owned(),
                |versione| versione.body.as_str().to_owned(),
            );
        testi.insert(contenuto.remote_message_id.as_str().to_owned(), ultimo);
    }
    Ok(testi)
}

/// Che cosa l'archiviazione ha fatto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntervalOutcome {
    /// Quanti contenuti recuperati sono entrati in archivio.
    pub archived: usize,
    /// Quante versioni si sono aggiunte a contenuti già in archivio.
    pub new_versions: usize,
}

/// Archivia ciò che la ricognizione ha trovato, e registra l'operazione.
///
/// # Errori
///
/// Restituisce un errore se l'intervallo non era recuperabile, o se una
/// scrittura non riesce.
pub fn archive(
    richiesta: &IntervalRecoveryRequest,
    trovato: &IntervalSurvey,
    acquisizione: &mut AcquisitionService,
    contesto: &SessionContext,
    now: Timestamp,
) -> ServiceResult<IntervalOutcome> {
    if let Some(motivo) = &trovato.not_recoverable {
        return Err(ServiceError::SessionUnavailable {
            reason: format!("l'intervallo non è recuperabile: {motivo}"),
        });
    }
    acquisizione.ingest_recovered(&trovato.missing, contesto, now)?;
    let versioni = acquisizione.ingest_recovered_edits(&trovato.changed, contesto, now)?;

    let archiviati = legati(
        acquisizione.database(),
        richiesta.session_id,
        richiesta.source_id,
        &trovato.missing,
    )?;
    let audit = NewAuditEntry {
        actor: richiesta.operator.clone(),
        action: AuditAction::try_new(INTERVAL_RECOVERY_AUDIT_ACTION)?,
        entity: AuditEntity::try_new("recupero")?,
        entity_id: None,
        actor_mode: None,
        detail: Some(AuditDetail::try_new(&format!(
            "fonte {}, dal {} al {}: {} trovati, {} archiviati",
            richiesta.source_id.get(),
            richiesta.from.to_readable_utc(),
            richiesta.to.to_readable_utc(),
            trovato.missing.len(),
            archiviati.len()
        ))?),
        recorded_at: now,
    };
    acquisizione.database_mut().insert_recovery_operation(
        &NewRecoveryOperation {
            session_id: richiesta.session_id,
            source_id: richiesta.source_id,
            interval: trovato.read_interval(richiesta.from, richiesta.to),
            requested_by: String::from(richiesta.operator.as_str()),
            performed_at: now,
            found: u32::try_from(trovato.missing.len()).unwrap_or(u32::MAX),
            archived: archiviati.clone(),
        },
        &audit,
    )?;
    Ok(IntervalOutcome {
        archived: archiviati.len(),
        new_versions: versioni.enqueued,
    })
}

/// Un periodo che una persona ha deciso «da valutare per un recupero», con il
/// monitoraggio dentro cui si può recuperarlo — o il motivo per cui qui no.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCandidate {
    /// La fonte.
    pub source_id: SourceId,
    /// Il suo nome, com'è mostrato.
    pub source_name: String,
    /// Il periodo deciso.
    pub gap: (Timestamp, Timestamp),
    /// Chi ha deciso, e quando.
    pub decided_by: String,
    /// Quando.
    pub decided_at: Timestamp,
    /// Dove recuperarlo: la chat, il monitoraggio in corso e l'intervallo
    /// ristretto a quel monitoraggio. `Err` con la frase quando non si può.
    pub target: Result<CandidateTarget, &'static str>,
    /// Le operazioni già eseguite su quell'intervallo.
    pub done: Vec<lisi_storage::repository::recovery_operation::RecordedRecovery>,
}

/// Dove un periodo si può recuperare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateTarget {
    /// La chat della fonte.
    pub chat_id: ChatId,
    /// Il monitoraggio in corso che la comprende.
    pub session_id: SessionId,
    /// Il suo nome.
    pub session_label: String,
    /// L'intervallo, ristretto al monitoraggio.
    pub interval: (Timestamp, Timestamp),
}

/// Perché un periodo non si recupera dentro un monitoraggio.
pub const OUTSIDE_ANY_MONITORING: &str = "Il periodo non sta dentro un monitoraggio in corso \
     della fonte. Un recupero porta contenuti in un monitoraggio aperto: un monitoraggio \
     concluso non ne riceve dopo la chiusura.";

/// Perché una fonte senza identificativo numerico non si recupera.
pub const NO_CHAT_IDENTIFIER: &str =
    "La fonte non ha un identificativo di chat numerico: la sua cronologia non si può chiedere.";

impl RecoveryCandidate {
    /// La chiave con cui la schermata indica il periodo: fonte, inizio, fine.
    #[must_use]
    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.source_id.get(),
            self.gap.0.as_millis(),
            self.gap.1.as_millis()
        )
    }

    /// La frase della riga: il periodo, chi lo ha deciso, dove si recupera e
    /// che cosa è già stato fatto.
    #[must_use]
    pub fn sentence(&self) -> String {
        let mut frase = format!(
            "Dal {} al {}. Deciso da {} il {}.",
            self.gap.0.to_readable_local(),
            self.gap.1.to_readable_local(),
            self.decided_by,
            self.decided_at.to_readable_local()
        );
        match &self.target {
            Ok(dove) => frase.push_str(&format!(
                " Si recupera nel monitoraggio «{}», dal {} al {}.",
                dove.session_label,
                dove.interval.0.to_readable_local(),
                dove.interval.1.to_readable_local()
            )),
            Err(motivo) => {
                frase.push(' ');
                frase.push_str(motivo);
            }
        }
        for operazione in &self.done {
            frase.push_str(&format!(
                " Recuperato il {} da {}: trovati {}, archiviati {}.",
                operazione.performed_at.to_readable_local(),
                operazione.requested_by,
                operazione.found,
                operazione.archived
            ));
        }
        frase
    }
}

/// I periodi decisi «da valutare per un recupero», con dove recuperarli.
///
/// **Legge soltanto.** Il monitoraggio è quello **in corso** (avviato e non
/// concluso) che comprende la fonte e si sovrappone di più al periodo; a parità,
/// il più vecchio. L'intervallo si restringe al monitoraggio: prima del suo
/// avvio nessuno aveva deciso di sorvegliare.
///
/// # Errori
///
/// Restituisce un errore se una lettura non riesce.
pub fn candidates(database: &Database, now: Timestamp) -> ServiceResult<Vec<RecoveryCandidate>> {
    let decisioni = database.gap_decisions()?;
    // Dal più vecchio: a parità di sovrapposizione vince il primo, e la scelta
    // non dipende dall'ordine in cui l'archivio restituisce le righe.
    let mut sessioni = database.sessions()?;
    sessioni.sort_by_key(|sessione| sessione.id.get());
    let mut candidati = Vec::new();
    for decisione in decisioni {
        if decisione.decision != crate::gap::GapDecision::EvaluateRecovery.as_str() {
            continue;
        }
        let fonte = database.source(decisione.source_id)?;
        let chat = fonte
            .identifier
            .as_str()
            .parse::<i64>()
            .ok()
            .and_then(|grezzo| ChatId::try_new(grezzo).ok());

        let mut scelta: Option<(i64, CandidateTarget)> = None;
        for sessione in &sessioni {
            let (Some(avvio), false) = (sessione.started_at, sessione.state.is_final()) else {
                continue;
            };
            if !database
                .session_source_ids(sessione.id)?
                .contains(&decisione.source_id)
            {
                continue;
            }
            let fine = sessione.ended_at.unwrap_or(now);
            let da = decisione.gap_from.max(avvio);
            let a = decisione.gap_to.min(fine);
            if a <= da {
                continue;
            }
            let sovrapposizione = a.as_millis() - da.as_millis();
            if scelta
                .as_ref()
                .is_some_and(|(migliore, _)| *migliore >= sovrapposizione)
            {
                continue;
            }
            if let Some(chat_id) = chat {
                scelta = Some((
                    sovrapposizione,
                    CandidateTarget {
                        chat_id,
                        session_id: sessione.id,
                        session_label: sessione.label.as_str().to_owned(),
                        interval: (da, a),
                    },
                ));
            }
        }
        let target = match (chat, scelta) {
            (None, _) => Err(NO_CHAT_IDENTIFIER),
            (Some(_), None) => Err(OUTSIDE_ANY_MONITORING),
            (Some(_), Some((_, dove))) => Ok(dove),
        };
        let done = database
            .source_recovery_operations(decisione.source_id)?
            .into_iter()
            .filter(|operazione| {
                operazione
                    .interval
                    .is_some_and(|(da, a)| da >= decisione.gap_from && a <= decisione.gap_to)
            })
            .collect();
        candidati.push(RecoveryCandidate {
            source_id: decisione.source_id,
            source_name: fonte.display_name.as_str().to_owned(),
            gap: (decisione.gap_from, decisione.gap_to),
            decided_by: decisione.decided_by,
            decided_at: decisione.decided_at,
            target,
            done,
        });
    }
    Ok(candidati)
}

impl IntervalRecoveryRequest {
    /// La richiesta per un periodo candidato, quando lo si può recuperare.
    #[must_use]
    pub fn for_candidate(
        autorita: &AcquisitionAuthority,
        candidato: &RecoveryCandidate,
        operator: Actor,
    ) -> Option<Self> {
        let dove = candidato.target.as_ref().ok()?;
        Self::new(
            autorita,
            dove.session_id,
            candidato.source_id,
            dove.chat_id,
            dove.interval,
            operator,
        )
    }

    /// Il monitoraggio in cui i contenuti entrano.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }
}

/// I contenuti appena archiviati da questo recupero: recuperati, non ancora
/// legati a un'operazione, e fra quelli trovati.
pub(crate) fn legati(
    database: &Database,
    session_id: SessionId,
    source_id: SourceId,
    trovati: &[IncomingMessage],
) -> ServiceResult<Vec<ContentId>> {
    let cercati: std::collections::BTreeSet<String> = trovati
        .iter()
        .map(|messaggio| messaggio.message_id.get().to_string())
        .collect();
    Ok(database
        .unlinked_recovered_contents(session_id, source_id)?
        .into_iter()
        .filter(|(_, remoto)| cercati.contains(remoto))
        .map(|(contenuto, _)| contenuto)
        .collect())
}

#[cfg(test)]
mod tests {
    use lisi_core::model::dictionary::ConfigurationResolver;
    use lisi_core::model::{
        AcquisitionMode, AcquisitionOrigin, NewSession, NewSource, SessionDuration, SourceKind,
    };
    use lisi_core::text::{Actor, DisplayName, SourceIdentifier};
    use lisi_core::{SessionId, SourceId, Timestamp};
    use lisi_telegram::{
        ChatId, ConnectorEvent, IncomingMessage, MessageId, MockTelegramConnector,
    };

    use super::{IntervalRecoveryRequest, archive, survey};
    use crate::acquisition::{AcquisitionService, SessionContext};
    use crate::acquisition_authority::StationAuthorityService;

    const CHAT: i64 = -1_001_000_000_001;

    fn t(ore: i64) -> Timestamp {
        Timestamp::from_millis(1_790_294_400_000 + ore * 3_600_000)
    }

    fn operatore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn chat() -> ChatId {
        let Ok(chat) = ChatId::try_new(CHAT) else {
            panic!("l'identificativo di prova deve essere valido");
        };
        chat
    }

    /// Connettore autorizzato, pronto a rispondere sulla cronologia.
    fn pronto() -> MockTelegramConnector {
        use lisi_telegram::TelegramConnector;
        use lisi_telegram::connector::ClientParameters;
        use lisi_telegram::secret::{ApiHash, ApiId, LoginCode, PhoneNumber};

        let mut connettore = MockTelegramConnector::new();
        let (Ok(api_id), Ok(api_hash)) = (ApiId::try_new(1), ApiHash::try_new(&"a".repeat(32)))
        else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(()) = connettore.start(&ClientParameters {
            api_id,
            api_hash,
            database_directory: std::path::PathBuf::from("."),
            use_test_datacenter: true,
            application_version: String::from("prova"),
            system_language_code: String::from("it"),
        }) else {
            panic!("l'avvio simulato deve riuscire");
        };
        let (Ok(telefono), Ok(codice)) = (
            PhoneNumber::try_new("+390000000000"),
            LoginCode::try_new("12345"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let (Ok(()), Ok(())) = (
            connettore.submit_phone_number(&telefono),
            connettore.submit_code(&codice),
        ) else {
            panic!("l'accesso simulato deve riuscire");
        };
        connettore
    }

    /// Un monitoraggio su una fonte, con l'acquisizione pronta.
    fn monitoraggio() -> (AcquisitionService, SessionContext, SourceId) {
        let Ok(mut database) = crate::sources::open_in_memory_database() else {
            panic!("l'archivio in memoria deve potersi aprire");
        };
        let (Ok(identificativo), Ok(nome), Ok(etichetta)) = (
            SourceIdentifier::try_new(&CHAT.to_string()),
            DisplayName::try_new("Canale di prova"),
            DisplayName::try_new("Monitoraggio di prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(fonte) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier: identificativo,
                display_name: nome,
                authorized_by: operatore(),
                active: true,
            },
            t(-1),
        ) else {
            panic!("la fonte deve potersi registrare");
        };
        let Ok(sessione) = database.insert_session(
            &NewSession {
                label: etichetta,
                started_by: operatore(),
                duration: SessionDuration::Preset { seconds: 360_000 },
                source_ids: vec![fonte],
            },
            t(0),
        ) else {
            panic!("la sessione deve potersi creare");
        };
        let Ok(()) =
            database.save_resolved_configuration(sessione, &ConfigurationResolver::new().finish())
        else {
            panic!("la configurazione deve potersi salvare");
        };
        let acquisizione = AcquisitionService::new(database);
        let Ok(contesto) = acquisizione.load_context(sessione, operatore()) else {
            panic!("il contesto deve potersi costruire");
        };
        (acquisizione, contesto, fonte)
    }

    fn richiesta(sessione: SessionId, fonte: SourceId) -> IntervalRecoveryRequest {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let Ok(esito) = StationAuthorityService::in_directory(cartella.path())
            .acquisition_authority(&crate::run_mode::operational_for_tests())
        else {
            panic!("la domanda di autorità deve avere una risposta");
        };
        let Some(autorita) = esito.into_granted() else {
            panic!("una postazione senza Hub è autorità di sé stessa");
        };
        let Some(richiesta) = IntervalRecoveryRequest::new(
            &autorita,
            sessione,
            fonte,
            chat(),
            (t(2), t(5)),
            operatore(),
        ) else {
            panic!("un intervallo valido costruisce la richiesta");
        };
        richiesta
    }

    /// **Un intervallo vuoto o rovesciato non costruisce una richiesta.**
    #[test]
    fn un_intervallo_rovesciato_non_e_una_richiesta() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let Ok(esito) = StationAuthorityService::in_directory(cartella.path())
            .acquisition_authority(&crate::run_mode::operational_for_tests())
        else {
            panic!("la domanda di autorità deve avere una risposta");
        };
        let Some(autorita) = esito.granted() else {
            panic!("una postazione senza Hub è autorità di sé stessa");
        };
        for intervallo in [(t(5), t(2)), (t(3), t(3))] {
            assert!(
                IntervalRecoveryRequest::new(
                    autorita,
                    SessionId::new(1),
                    SourceId::new(1),
                    chat(),
                    intervallo,
                    operatore(),
                )
                .is_none()
            );
        }
    }

    /// **Si recupera soltanto l'intervallo**, i messaggi entrano come
    /// recuperati con chi, quando e per quale intervallo, e il modo dichiarato
    /// lo dice.
    #[test]
    fn si_recupera_l_intervallo_e_lo_si_dichiara() {
        let (mut acquisizione, contesto, fonte) = monitoraggio();
        let mut connettore = pronto();
        for (id, ora) in [(40, 6), (30, 4), (20, 3), (10, 1)] {
            let Ok(()) =
                connettore.push_history(CHAT, id, &format!("messaggio {id}"), t(ora).as_millis())
            else {
                panic!("la cronologia sintetica deve potersi scrivere");
            };
        }
        let richiesta = richiesta(contesto.session_id, fonte);
        let trovato = survey(&mut connettore, acquisizione.database(), &richiesta);
        assert_eq!(trovato.missing.len(), 2, "solo le ore 3 e 4");
        assert!(trovato.reached_start);
        assert!(
            trovato
                .operator_message()
                .contains(lisi_core::model::RECOVERY_LIMITS),
            "la frase dice che cosa un recupero non vede"
        );

        let Ok(esito) = archive(&richiesta, &trovato, &mut acquisizione, &contesto, t(10)) else {
            panic!("l'archiviazione deve riuscire");
        };
        assert_eq!(esito.archived, 2);

        let Ok(operazioni) = acquisizione
            .database()
            .session_recoveries(contesto.session_id)
        else {
            panic!("le operazioni devono potersi leggere");
        };
        assert_eq!(operazioni.len(), 2, "un legame per contenuto recuperato");

        let Ok(modi) = crate::acquisition_mode::for_session(
            acquisizione.database(),
            contesto.session_id,
            t(11),
        ) else {
            panic!("i modi devono potersi ricavare");
        };
        assert_eq!(modi.len(), 2);
        for modo in modi.values() {
            let AcquisitionMode::Recovered {
                at,
                interval,
                operator,
            } = modo
            else {
                panic!("un recuperato resta recuperato, mai dal vivo: {modo:?}");
            };
            assert_eq!(*at, t(10));
            assert_eq!(*interval, Some((t(2), t(5))));
            assert_eq!(operator.as_deref(), Some("operatore.prova"));
        }

        // La marcatura vive nell'archivio, e sopravvive alla copia di
        // sicurezza e al ripristino: la copia riaperta dice le stesse cose.
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let copia = cartella.path().join("copia.sqlite3");
        let Ok(_) = acquisizione.database().backup_to(&copia) else {
            panic!("la copia deve potersi scrivere");
        };
        let Ok(ripristinato) = lisi_storage::Database::open(&copia) else {
            panic!("la copia deve potersi riaprire");
        };
        let Ok(dopo) =
            crate::acquisition_mode::for_session(&ripristinato, contesto.session_id, t(11))
        else {
            panic!("i modi devono potersi ricavare dalla copia");
        };
        assert_eq!(
            dopo, modi,
            "la copia dichiara gli stessi modi dell'originale"
        );
    }

    /// **Il recupero non sostituisce**: un messaggio già in archivio con un
    /// testo diverso riceve una versione in più, e resta dal percorso da cui
    /// era entrato.
    #[test]
    fn il_recupero_non_sostituisce_un_contenuto() {
        let (mut acquisizione, contesto, fonte) = monitoraggio();
        let Ok(id) = MessageId::try_new(20) else {
            panic!("l'identificativo di prova deve essere valido");
        };
        let dal_vivo = ConnectorEvent::MessageReceived(IncomingMessage {
            chat_id: chat(),
            message_id: id,
            author: None,
            author_identifier: None,
            author_username: None,
            text: String::from("testo di allora"),
            published_at_millis: t(3).as_millis(),
            url: None,
            attachment: None,
        });
        let Ok(_) = acquisizione.ingest(&dal_vivo, &contesto, t(3)) else {
            panic!("il messaggio dal vivo deve entrare");
        };
        let mut connettore = pronto();
        let Ok(()) = connettore.push_history(CHAT, 20, "testo di oggi", t(3).as_millis()) else {
            panic!("la cronologia sintetica deve potersi scrivere");
        };

        let richiesta = richiesta(contesto.session_id, fonte);
        let trovato = survey(&mut connettore, acquisizione.database(), &richiesta);
        assert!(trovato.missing.is_empty());
        assert_eq!(trovato.changed.len(), 1);
        let Ok(esito) = archive(&richiesta, &trovato, &mut acquisizione, &contesto, t(10)) else {
            panic!("l'archiviazione deve riuscire");
        };
        assert_eq!(esito.archived, 0);
        assert_eq!(esito.new_versions, 1);

        let Ok(contenuti) = acquisizione
            .database()
            .session_contents(contesto.session_id)
        else {
            panic!("i contenuti devono potersi leggere");
        };
        assert_eq!(contenuti.len(), 1);
        assert_eq!(
            contenuti[0].body.as_str(),
            "testo di allora",
            "il testo osservato allora resta"
        );
        assert_eq!(
            contenuti[0].origin,
            AcquisitionOrigin::Observed,
            "il percorso non cambia"
        );
        let Ok(versioni) = acquisizione.database().content_versions(contenuti[0].id) else {
            panic!("le versioni devono potersi leggere");
        };
        assert!(
            versioni
                .iter()
                .any(|versione| versione.body.as_str() == "testo di oggi"),
            "il testo di oggi è una versione in più"
        );
        let Some(ritrovata) = versioni
            .iter()
            .find(|versione| versione.body.as_str() == "testo di oggi")
        else {
            panic!("la versione ritrovata deve esserci");
        };
        assert_eq!(
            ritrovata.remote_edit_timestamp, None,
            "la cronologia non dice quando il testo è cambiato: nessuna ora inventata"
        );
        assert_eq!(
            ritrovata.observed_at,
            t(10),
            "si sa soltanto quando lo si è visto"
        );

        // Una seconda ricognizione trova il testo di oggi già conservato.
        let di_nuovo = survey(&mut connettore, acquisizione.database(), &richiesta);
        assert!(di_nuovo.changed.is_empty());
        assert_eq!(di_nuovo.already_present, 1);

        // Nemmeno un recuperato che arrivasse come messaggio nuovo, con lo
        // stesso identificativo, sostituisce l'osservato (controllo negativo 2).
        let doppione = IncomingMessage {
            chat_id: chat(),
            message_id: id,
            author: None,
            author_identifier: None,
            author_username: None,
            text: String::from("testo sostituito"),
            published_at_millis: t(3).as_millis(),
            url: None,
            attachment: None,
        };
        let Ok(_) = acquisizione.ingest_recovered(&[doppione], &contesto, t(12)) else {
            panic!("un doppione non è un errore");
        };
        let Ok(dopo) = acquisizione
            .database()
            .session_contents(contesto.session_id)
        else {
            panic!("i contenuti devono potersi leggere");
        };
        assert_eq!(dopo.len(), 1);
        assert_eq!(dopo[0].body.as_str(), "testo di allora");
        assert_eq!(dopo[0].origin, AcquisitionOrigin::Observed);
    }

    /// **Un intervallo che Telegram non lascia leggere è «Non recuperabile»**,
    /// con il motivo, e non si archivia nulla.
    #[test]
    fn un_intervallo_illeggibile_non_e_recuperabile() {
        let (mut acquisizione, contesto, fonte) = monitoraggio();
        // Un connettore mai autorizzato: la cronologia non si legge.
        let mut connettore = MockTelegramConnector::new();
        let richiesta = richiesta(contesto.session_id, fonte);
        let trovato = survey(&mut connettore, acquisizione.database(), &richiesta);
        assert!(trovato.operator_message().starts_with("Non recuperabile:"));
        assert!(archive(&richiesta, &trovato, &mut acquisizione, &contesto, t(10)).is_err());
        let Ok(operazioni) = acquisizione
            .database()
            .session_recoveries(contesto.session_id)
        else {
            panic!("le operazioni devono potersi leggere");
        };
        assert!(operazioni.is_empty(), "nulla di registrato");
    }

    fn decidi(acquisizione: &mut AcquisitionService, fonte: SourceId, da: i64, a: i64) {
        use lisi_core::model::NewAuditEntry;
        use lisi_core::text::{AuditAction, AuditEntity};
        use lisi_storage::repository::gap_decision::NewGapDecision;

        let (Ok(azione), Ok(entita)) = (
            AuditAction::try_new("decisione_periodo"),
            AuditEntity::try_new("periodo"),
        ) else {
            panic!("valori d'audit validi");
        };
        let Ok(_) = acquisizione.database_mut().insert_gap_decision(
            &NewGapDecision {
                source_id: fonte,
                gap_from: t(da),
                gap_to: t(a),
                priority: String::from("alta"),
                criterion_version: 2,
                decision: String::from("da_valutare_per_recupero"),
                reason: String::from("motivo di prova"),
                decided_by: String::from("operatore.prova"),
                decided_at: t(20),
            },
            &NewAuditEntry {
                actor: operatore(),
                action: azione,
                entity: entita,
                entity_id: None,
                actor_mode: None,
                detail: None,
                recorded_at: t(20),
            },
        ) else {
            panic!("la decisione deve registrarsi");
        };
    }

    /// **Un periodo deciso si recupera soltanto dentro un monitoraggio in
    /// corso**, ristretto al suo intervallo; fuori, o in un monitoraggio
    /// concluso, la riga dice perché no.
    #[test]
    fn un_periodo_si_recupera_solo_in_un_monitoraggio_in_corso() {
        use lisi_core::model::SessionState;

        let (mut acquisizione, contesto, fonte) = monitoraggio();
        let Ok(()) = acquisizione.database_mut().update_session_state(
            contesto.session_id,
            SessionState::Running,
            t(1),
        ) else {
            panic!("il monitoraggio deve avviarsi");
        };
        // Un periodo che comincia prima dell'avvio: si restringe al monitoraggio.
        decidi(&mut acquisizione, fonte, -5, 4);

        let Ok(candidati) = super::candidates(acquisizione.database(), t(30)) else {
            panic!("i candidati devono potersi comporre");
        };
        assert_eq!(candidati.len(), 1);
        let Ok(dove) = &candidati[0].target else {
            panic!("dentro un monitoraggio in corso si recupera");
        };
        assert_eq!(dove.session_id, contesto.session_id);
        assert_eq!(dove.interval, (t(1), t(4)), "non prima dell'avvio");

        // Concluso il monitoraggio, lo stesso periodo non si recupera più qui.
        let Ok(()) = acquisizione.database_mut().update_session_state(
            contesto.session_id,
            SessionState::Stopped,
            t(25),
        ) else {
            panic!("il monitoraggio deve concludersi");
        };
        let Ok(candidati) = super::candidates(acquisizione.database(), t(30)) else {
            panic!("i candidati devono potersi comporre");
        };
        assert_eq!(candidati[0].target, Err(super::OUTSIDE_ANY_MONITORING));
        assert!(
            candidati[0]
                .sentence()
                .contains("non sta dentro un monitoraggio in corso")
        );
    }

    /// **Un recupero eseguito resta scritto sulla riga del periodo**: chi,
    /// quando, quanti trovati e quanti archiviati.
    #[test]
    fn la_riga_del_periodo_dice_che_cosa_e_stato_fatto() {
        use lisi_core::model::SessionState;

        let (mut acquisizione, contesto, fonte) = monitoraggio();
        let Ok(()) = acquisizione.database_mut().update_session_state(
            contesto.session_id,
            SessionState::Running,
            t(0),
        ) else {
            panic!("il monitoraggio deve avviarsi");
        };
        decidi(&mut acquisizione, fonte, 2, 5);
        let mut connettore = pronto();
        let Ok(()) = connettore.push_history(CHAT, 30, "ritrovato", t(3).as_millis()) else {
            panic!("la cronologia sintetica deve potersi scrivere");
        };

        let Ok(candidati) = super::candidates(acquisizione.database(), t(30)) else {
            panic!("i candidati devono potersi comporre");
        };
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let Ok(esito) = StationAuthorityService::in_directory(cartella.path())
            .acquisition_authority(&crate::run_mode::operational_for_tests())
        else {
            panic!("la domanda di autorità deve avere una risposta");
        };
        let Some(autorita) = esito.granted() else {
            panic!("una postazione senza Hub è autorità di sé stessa");
        };
        let Some(richiesta) =
            IntervalRecoveryRequest::for_candidate(autorita, &candidati[0], operatore())
        else {
            panic!("il periodo si recupera");
        };
        let trovato = survey(&mut connettore, acquisizione.database(), &richiesta);
        let Ok(_) = archive(&richiesta, &trovato, &mut acquisizione, &contesto, t(31)) else {
            panic!("l'archiviazione deve riuscire");
        };

        let Ok(candidati) = super::candidates(acquisizione.database(), t(32)) else {
            panic!("i candidati devono potersi comporre");
        };
        assert_eq!(candidati[0].done.len(), 1);
        let frase = candidati[0].sentence();
        assert!(
            frase.contains("da operatore.prova: trovati 1, archiviati 1."),
            "{frase}"
        );
    }
}

#[cfg(test)]
mod read_interval_tests {
    use lisi_core::Timestamp;

    use super::IntervalSurvey;

    /// **Si registra l'intervallo davvero letto** (FINAL-REVIEW-01, FR-010).
    #[test]
    fn a_survey_that_stopped_early_records_only_what_it_read() {
        let da = Timestamp::from_millis(1_000);
        let a = Timestamp::from_millis(9_000);

        let intero = IntervalSurvey {
            reached_start: true,
            oldest_seen_millis: Some(5_000),
            ..IntervalSurvey::default()
        };
        assert_eq!(intero.read_interval(da, a), Some((da, a)));

        let fermato = IntervalSurvey {
            reached_start: false,
            oldest_seen_millis: Some(5_000),
            ..IntervalSurvey::default()
        };
        assert_eq!(
            fermato.read_interval(da, a),
            Some((Timestamp::from_millis(5_000), a)),
            "una lettura fermata prima dell'inizio non dichiara letto ciò che non ha letto"
        );

        let vuoto = IntervalSurvey::default();
        assert_eq!(vuoto.read_interval(da, a), None);
    }
}

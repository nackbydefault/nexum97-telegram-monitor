//! Lo storico precedente all'avvio (PR-08, ADR-0124).
//!
//! # Un limite dell'ufficio, e perché qui si va oltre
//!
//! Il recupero di MP-16.3 risale fino all'inizio del monitoraggio **e non
//! oltre** (risposta 8.a), e quel limite resta. Lo storico anteriore è
//! un'operazione **diversa e distinta**: la chiede una persona, con una
//! **ragione operativa** scritta, nel mandato della risposta 9.a.
//!
//! # Una sola semantica di «recuperato»
//!
//! Lo storico entra come recuperato, con la stessa marcatura di PR-07: istante,
//! intervallo, operatore. Il registro è quello della 0053; nessun tipo nuovo e
//! nessuna migrazione.
//!
//! # Volume
//!
//! Una pagina per passo, un tetto dichiarato prima di cominciare, e
//! l'interruzione in qualsiasi momento: ciò che è stato trovato resta, e si
//! decide se archiviarlo. La lettura parte **dal messaggio più vecchio già in
//! archivio** per quella fonte: la cronologia si legge a ritroso, e rileggere
//! ciò che è già stato acquisito sarebbe traffico inutile.
//!
//! # Che cosa non fa
//!
//! Non parte da solo, non legge fonti che l'account non vede, non ricostruisce
//! cancellazioni o modifiche anteriori, e non va oltre l'avvio del monitoraggio:
//! dopo l'avvio vale il recupero di sempre.

use std::collections::BTreeSet;

use lisi_core::model::NewAuditEntry;
use lisi_core::model::reason::OperationalReason;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{SessionId, SourceId, Timestamp};
use lisi_storage::Database;
use lisi_storage::repository::recovery_operation::{NewRecoveryOperation, RecordedRecovery};
use lisi_telegram::identifier::ChatId;
use lisi_telegram::{IncomingMessage, TelegramConnector};

use crate::acquisition::{AcquisitionService, SessionContext};
use crate::acquisition_authority::AcquisitionAuthority;
use crate::error::{ServiceError, ServiceResult};

/// Le durate che si possono chiedere, in giorni prima dell'avvio.
pub const HISTORY_SPANS_DAYS: [i64; 3] = [7, 30, 90];

/// Messaggi per pagina di cronologia.
const PAGE_SIZE: u32 = 100;

/// Pagine lette al più in una lettura dello storico: il tetto dichiarato.
pub const HISTORY_MAX_PAGES: usize = 200;

/// Il limite dello storico, detto **prima** di cominciare.
pub const HISTORY_LIMITS: &str = "Lo storico è ciò che la fonte mostra oggi. Ciò che è stato \
     cancellato o modificato prima di oggi non c'è, e il programma non lo ricostruisce.";

/// Che cosa dire quando una pagina di cronologia non arriva.
///
/// # Perché non è sempre «Telegram non consente» (FINAL-REVIEW-01, FR-009)
///
/// Fino al 2026-10-03 ogni errore della lettura diventava «Telegram non
/// consente di leggere la cronologia di questa fonte»: anche un'attesa scaduta
/// e un limite di frequenza. Un'attesa non è un divieto, e dire il contrario
/// manda l'operatore a cercare un permesso che c'è. Le due letture —
/// recupero di un intervallo e storico precedente — usano questa frase sola.
#[must_use]
pub fn history_read_failure(errore: &lisi_telegram::TelegramError) -> String {
    let testo = errore.to_string();
    if matches!(errore, lisi_telegram::TelegramError::Timeout { .. }) {
        return format!(
            "La lettura della cronologia non ha avuto risposta entro l'attesa ({testo}). Non è un \
             rifiuto di Telegram: si può riprovare più tardi."
        );
    }
    if e_un_limite_di_frequenza(&testo) {
        return format!(
            "Telegram ha chiesto di attendere prima di altre letture ({testo}). Non è un rifiuto: \
             si riprova dopo l'attesa indicata, non prima."
        );
    }
    if matches!(errore, lisi_telegram::TelegramError::Tdlib { .. }) {
        return format!(
            "Telegram non consente di leggere la cronologia di questa fonte ({testo})."
        );
    }
    format!("La lettura della cronologia non è riuscita ({testo}).")
}

/// Se l'errore di TDLib è un limite di frequenza: le forme sono quelle,
/// inglesi, del protocollo, e si confrontano per testo. Il codice `429` conta
/// solo come numero a sé: dentro un identificativo o un numero più lungo
/// («14290») non è un limite di frequenza.
fn e_un_limite_di_frequenza(testo: &str) -> bool {
    let codice_a_se = testo.match_indices("429").any(|(inizio, _)| {
        let prima = testo[..inizio].chars().next_back();
        let dopo = testo[inizio + 3..].chars().next();
        !prima.is_some_and(|c| c.is_ascii_digit()) && !dopo.is_some_and(|c| c.is_ascii_digit())
    });
    codice_a_se || testo.contains("FLOOD_WAIT") || testo.contains("Too Many Requests")
}

/// L'azione d'audit di uno storico archiviato.
pub const HISTORY_AUDIT_ACTION: &str = "storico_precedente_archiviato";

/// Perché una fonte senza identificativo numerico non si legge.
pub const NO_CHAT_IDENTIFIER: &str = crate::interval_recovery::NO_CHAT_IDENTIFIER;

const GIORNO: i64 = 24 * 60 * 60 * 1_000;

/// Una fonte di un monitoraggio in corso, di cui si può chiedere lo storico.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryTarget {
    /// Il monitoraggio in corso.
    pub session_id: SessionId,
    /// Il suo nome.
    pub session_label: String,
    /// La fonte.
    pub source_id: SourceId,
    /// Il suo nome, com'è mostrato.
    pub source_name: String,
    /// La chat, quando l'identificativo è numerico.
    pub chat_id: Option<ChatId>,
    /// L'avvio del monitoraggio: lo storico si ferma qui.
    pub started_at: Timestamp,
    /// Gli storici già archiviati per questa fonte in questo monitoraggio.
    pub done: Vec<RecordedRecovery>,
}

impl HistoryTarget {
    /// La chiave con cui la schermata indica la riga: monitoraggio e fonte.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}:{}", self.session_id.get(), self.source_id.get())
    }

    /// La frase della riga: il monitoraggio, e che cosa è già stato fatto.
    #[must_use]
    pub fn sentence(&self) -> String {
        let mut frase = format!(
            "Monitoraggio «{}», avviato il {}.",
            self.session_label,
            self.started_at.to_readable_local()
        );
        if self.chat_id.is_none() {
            frase.push(' ');
            frase.push_str(NO_CHAT_IDENTIFIER);
        }
        for operazione in &self.done {
            if let Some((da, a)) = operazione.interval {
                frase.push_str(&format!(
                    " Storico dal {} al {} recuperato il {} da {}: trovati {}, archiviati {}.",
                    da.to_readable_local(),
                    a.to_readable_local(),
                    operazione.performed_at.to_readable_local(),
                    operazione.requested_by,
                    operazione.found,
                    operazione.archived
                ));
            }
        }
        frase
    }
}

/// Le fonti dei monitoraggi in corso, di cui si può chiedere lo storico.
///
/// **Legge soltanto.** In corso vuol dire avviato e non concluso: un
/// monitoraggio concluso non riceve contenuti dopo la chiusura (ADR-0123).
///
/// # Errori
///
/// Restituisce un errore se una lettura non riesce.
pub fn targets(database: &Database) -> ServiceResult<Vec<HistoryTarget>> {
    let mut sessioni = database.sessions()?;
    sessioni.sort_by_key(|sessione| sessione.id.get());
    let mut righe = Vec::new();
    for sessione in sessioni {
        let (Some(avvio), false) = (sessione.started_at, sessione.state.is_final()) else {
            continue;
        };
        for fonte_id in database.session_source_ids(sessione.id)? {
            let fonte = database.source(fonte_id)?;
            let chat_id = fonte
                .identifier
                .as_str()
                .parse::<i64>()
                .ok()
                .and_then(|grezzo| ChatId::try_new(grezzo).ok());
            let done = database
                .source_recovery_operations(fonte_id)?
                .into_iter()
                .filter(|operazione| {
                    operazione.session_id == sessione.id
                        && operazione.interval.is_some_and(|(_, a)| a <= avvio)
                })
                .collect();
            righe.push(HistoryTarget {
                session_id: sessione.id,
                session_label: sessione.label.as_str().to_owned(),
                source_id: fonte_id,
                source_name: fonte.display_name.as_str().to_owned(),
                chat_id,
                started_at: avvio,
                done,
            });
        }
    }
    Ok(righe)
}

/// Una richiesta di storico.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryRequest {
    session_id: SessionId,
    source_id: SourceId,
    chat_id: ChatId,
    from: Timestamp,
    to: Timestamp,
    operator: Actor,
    reason: OperationalReason,
}

impl HistoryRequest {
    /// Costruisce la richiesta. **Vuole l'autorità di acquisizione e una
    /// ragione operativa**: senza, non esiste.
    ///
    /// Restituisce `None` per una durata che non è fra quelle dichiarate, o per
    /// una fonte senza chat numerica.
    #[must_use]
    pub fn new(
        _autorita: &AcquisitionAuthority,
        target: &HistoryTarget,
        days: i64,
        operator: Actor,
        reason: OperationalReason,
    ) -> Option<Self> {
        if !HISTORY_SPANS_DAYS.contains(&days) {
            return None;
        }
        let chat_id = target.chat_id?;
        let to = target.started_at;
        Some(Self {
            session_id: target.session_id,
            source_id: target.source_id,
            chat_id,
            from: Timestamp::from_millis(to.as_millis() - days * GIORNO),
            to,
            operator,
            reason,
        })
    }

    /// L'intervallo chiesto: dall'inizio scelto fino all'avvio.
    #[must_use]
    pub const fn interval(&self) -> (Timestamp, Timestamp) {
        (self.from, self.to)
    }

    /// Il monitoraggio in cui i contenuti entrano.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }
}

/// Una lettura dello storico, **una pagina per passo**.
#[derive(Debug)]
pub struct HistoryRun {
    request: HistoryRequest,
    /// I messaggi di questa fonte già in archivio nel monitoraggio.
    known: BTreeSet<String>,
    /// Quelli recuperati e rimasti senza operazione: un'interruzione fra
    /// l'archiviazione e la registrazione. Si legano alla prima operazione che
    /// li ritrova.
    unlinked: BTreeSet<String>,
    /// Da dove riprende la pagina successiva.
    next_from: i64,
    pages: usize,
    missing: Vec<IncomingMessage>,
    relink: Vec<IncomingMessage>,
    already_present: usize,
    /// Il messaggio più vecchio letto dentro l'intervallo.
    oldest_seen: Option<i64>,
    reached_start: bool,
    finished: bool,
    stopped: bool,
    error: Option<String>,
}

impl HistoryRun {
    /// Prepara la lettura. **Non legge nulla da Telegram.**
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'archivio non si legge.
    pub fn new(database: &Database, request: HistoryRequest) -> ServiceResult<Self> {
        let mut known = BTreeSet::new();
        let mut piu_vecchio: Option<i64> = None;
        for contenuto in database.session_contents(request.session_id)? {
            if contenuto.source_id != request.source_id {
                continue;
            }
            let remoto = contenuto.remote_message_id.as_str();
            if let Ok(numero) = remoto.parse::<i64>() {
                piu_vecchio = Some(piu_vecchio.map_or(numero, |finora| finora.min(numero)));
            }
            known.insert(remoto.to_owned());
        }
        let unlinked = database
            .unlinked_recovered_contents(request.session_id, request.source_id)?
            .into_iter()
            .map(|(_, remoto)| remoto)
            .collect();
        Ok(Self {
            request,
            known,
            unlinked,
            // Sotto il più vecchio già in archivio: ciò che sta sopra è già
            // stato acquisito. Zero, se non c'è nulla, vuol dire «dal più
            // recente».
            next_from: piu_vecchio.unwrap_or(0),
            pages: 0,
            missing: Vec::new(),
            relink: Vec::new(),
            already_present: 0,
            oldest_seen: None,
            reached_start: false,
            finished: false,
            stopped: false,
            error: None,
        })
    }

    /// Legge **una** pagina.
    pub fn step(&mut self, connector: &mut dyn TelegramConnector) {
        if self.finished {
            return;
        }
        let pagina = match connector.fetch_history(self.request.chat_id, self.next_from, PAGE_SIZE)
        {
            Ok(pagina) => pagina,
            Err(errore) => {
                // Non si riprova da qui: un'attesa chiesta da Telegram si
                // rispetta, e la lettura si chiude dicendo perché.
                self.error = Some(history_read_failure(&errore));
                self.finished = true;
                return;
            }
        };
        self.pages += 1;
        if pagina.is_empty() {
            self.reached_start = true;
            self.finished = true;
            return;
        }
        if let Some(ultimo) = pagina.last() {
            self.next_from = ultimo.message_id.get();
        }

        let (da, a) = (self.request.from.as_millis(), self.request.to.as_millis());
        let mut oltre = false;
        for messaggio in pagina {
            // Dopo l'avvio: è il periodo del monitoraggio, non lo storico.
            if messaggio.published_at_millis >= a {
                continue;
            }
            if messaggio.published_at_millis < da {
                oltre = true;
                continue;
            }
            self.oldest_seen = Some(
                self.oldest_seen
                    .map_or(messaggio.published_at_millis, |finora| {
                        finora.min(messaggio.published_at_millis)
                    }),
            );
            let remoto = messaggio.message_id.get().to_string();
            // UN MESSAGGIO SI CONTA UNA VOLTA (E2E01-08). Due pagine che si
            // toccano possono riportare lo stesso messaggio: senza questo
            // «mancano» lo conterebbe due volte, e l'archiviazione ne
            // registrerebbe uno, lasciando una differenza senza spiegazione.
            if self.unlinked.remove(&remoto) {
                self.known.insert(remoto);
                self.relink.push(messaggio);
            } else if self.known.contains(&remoto) {
                self.already_present += 1;
            } else {
                self.known.insert(remoto);
                self.missing.push(messaggio);
            }
        }
        if oltre {
            self.reached_start = true;
            self.finished = true;
        } else if self.pages >= HISTORY_MAX_PAGES {
            self.finished = true;
        }
    }

    /// Interrompe la lettura, **conservando** ciò che ha trovato.
    pub fn stop(&mut self) {
        self.stopped = !self.finished;
        self.finished = true;
    }

    /// Se non c'è più nulla da leggere.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    /// Se c'è qualcosa da archiviare.
    #[must_use]
    pub fn has_something(&self) -> bool {
        !self.missing.is_empty() || !self.relink.is_empty()
    }

    /// I messaggi che non sono in archivio.
    #[must_use]
    pub fn missing(&self) -> &[IncomingMessage] {
        &self.missing
    }

    /// La richiesta.
    #[must_use]
    pub const fn request(&self) -> &HistoryRequest {
        &self.request
    }

    /// La frase di avanzamento.
    #[must_use]
    pub fn progress_message(&self) -> String {
        format!(
            "Lettura dello storico: {} pagine lette su al più {HISTORY_MAX_PAGES}, {} messaggi \
             trovati finora.",
            self.pages,
            self.missing.len()
        )
    }

    /// La frase finale, con il limite dello storico.
    #[must_use]
    pub fn operator_message(&self) -> String {
        if let (Some(motivo), false) = (&self.error, self.has_something()) {
            return format!("Non recuperabile: {motivo} {HISTORY_LIMITS}");
        }
        let mut frase = match self.missing.len() {
            0 => String::from(
                "Nello storico scelto non manca nessun messaggio letto nella cronologia.",
            ),
            1 => String::from("Nello storico scelto manca 1 messaggio letto nella cronologia."),
            quanti => {
                format!("Nello storico scelto mancano {quanti} messaggi letti nella cronologia.")
            }
        };
        if !self.reached_start {
            let perche = if let Some(motivo) = &self.error {
                format!(" La lettura si è interrotta: {motivo}")
            } else if self.stopped {
                String::from(" La lettura è stata interrotta prima dell'inizio scelto.")
            } else {
                format!(" La lettura si è fermata al tetto di {HISTORY_MAX_PAGES} pagine.")
            };
            frase.push_str(&perche);
            frase.push_str(
                " Potrebbero essercene altri; ciò che è stato trovato si può archiviare.",
            );
        }
        frase.push(' ');
        frase.push_str(HISTORY_LIMITS);
        frase
    }

    /// L'intervallo davvero letto: tutto quello chiesto se la lettura ne ha
    /// raggiunto l'inizio, altrimenti dal messaggio più vecchio letto.
    fn read_interval(&self) -> Option<(Timestamp, Timestamp)> {
        if self.reached_start {
            return Some((self.request.from, self.request.to));
        }
        self.oldest_seen
            .map(|piu_vecchio| (Timestamp::from_millis(piu_vecchio), self.request.to))
            .filter(|(da, a)| da < a)
    }
}

/// Che cosa l'archiviazione ha fatto.
///
/// I quattro numeri esistono perché la differenza fra «trovati» e
/// «archiviati» si deve poter spiegare (INSTALLED-APP-E2E-01, E2E01-08): 725
/// trovati e 717 archiviati, senza una parola sugli altri otto, è un buco che
/// chi rilegge l'atto non sa riempire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryOutcome {
    /// Quanti messaggi la lettura ha trovato e proposto.
    pub found: usize,
    /// Quanti contenuti sono entrati, o sono stati legati all'operazione.
    pub archived: usize,
    /// Quanti erano già nell'archivio, o comparivano due volte nella lettura:
    /// la chiave di idempotenza li ha riconosciuti e non li ha ripetuti.
    pub already_present: usize,
    /// Quanti sono stati messi in quarantena perché non validi (corpo oltre
    /// misura o con caratteri non ammessi, istante mancante).
    pub quarantined: usize,
}

impl HistoryOutcome {
    /// Quelli che non sono entrati, per nessuna delle due ragioni note.
    #[must_use]
    pub const fn unexplained(&self) -> usize {
        self.found
            .saturating_sub(self.archived)
            .saturating_sub(self.already_present)
            .saturating_sub(self.quarantined)
    }

    /// La frase che spiega la differenza fra trovati e archiviati, o `None`
    /// se non c'è differenza.
    #[must_use]
    pub fn difference_sentence(&self) -> Option<String> {
        let mancanti = self.found.saturating_sub(self.archived);
        if mancanti == 0 {
            return None;
        }
        let mut parti = Vec::new();
        if self.already_present > 0 {
            parti.push(format!(
                "{} erano già nell'archivio o comparivano due volte nella lettura",
                self.already_present
            ));
        }
        if self.quarantined > 0 {
            parti.push(format!(
                "{} sono stati messi in quarantena perché non validi",
                self.quarantined
            ));
        }
        if self.unexplained() > 0 {
            parti.push(format!(
                "{} non sono stati legati all'operazione per una ragione che il programma non sa dire",
                self.unexplained()
            ));
        }
        Some(format!(
            "Trovati {}, archiviati {}: degli altri {mancanti}, {}.",
            self.found,
            self.archived,
            parti.join("; ")
        ))
    }
}

/// Archivia ciò che la lettura ha trovato, e registra l'operazione con la sua
/// ragione.
///
/// # Errori
///
/// Restituisce un errore se la lettura non è finita, se non c'è nulla da
/// archiviare, o se una scrittura non riesce.
pub fn archive(
    lettura: &HistoryRun,
    acquisizione: &mut AcquisitionService,
    contesto: &SessionContext,
    now: Timestamp,
) -> ServiceResult<HistoryOutcome> {
    if !lettura.is_finished() {
        return Err(ServiceError::SessionUnavailable {
            reason: String::from("la lettura dello storico non è finita"),
        });
    }
    let (Some((da, a)), true) = (lettura.read_interval(), lettura.has_something()) else {
        return Err(ServiceError::SessionUnavailable {
            reason: String::from("non c'è nulla da archiviare"),
        });
    };
    let richiesta = &lettura.request;
    let ingestione = acquisizione.ingest_recovered(&lettura.missing, contesto, now)?;

    let mut trovati = lettura.missing.clone();
    trovati.extend(lettura.relink.iter().cloned());
    let archiviati = crate::interval_recovery::legati(
        acquisizione.database(),
        richiesta.session_id,
        richiesta.source_id,
        &trovati,
    )?;
    let audit = NewAuditEntry {
        actor: richiesta.operator.clone(),
        action: AuditAction::try_new(HISTORY_AUDIT_ACTION)?,
        entity: AuditEntity::try_new("recupero")?,
        entity_id: None,
        actor_mode: None,
        detail: Some(AuditDetail::try_new(&format!(
            "fonte {}, storico dal {} al {}, motivo: «{}»: {} trovati, {} archiviati, {} già presenti, {} in quarantena",
            richiesta.source_id.get(),
            da.to_readable_utc(),
            a.to_readable_utc(),
            richiesta.reason.as_str(),
            trovati.len(),
            archiviati.len(),
            ingestione.duplicates,
            ingestione.discarded
        ))?),
        recorded_at: now,
    };
    acquisizione.database_mut().insert_recovery_operation(
        &NewRecoveryOperation {
            session_id: richiesta.session_id,
            source_id: richiesta.source_id,
            interval: Some((da, a)),
            requested_by: String::from(richiesta.operator.as_str()),
            performed_at: now,
            found: u32::try_from(trovati.len()).unwrap_or(u32::MAX),
            archived: archiviati.clone(),
        },
        &audit,
    )?;
    Ok(HistoryOutcome {
        found: trovati.len(),
        archived: archiviati.len(),
        already_present: ingestione.duplicates,
        quarantined: ingestione.discarded,
    })
}

#[cfg(test)]
mod tests {
    use lisi_core::model::dictionary::ConfigurationResolver;
    use lisi_core::model::reason::OperationalReason;
    use lisi_core::model::{
        AcquisitionMode, NewSession, NewSource, SessionDuration, SessionState, SourceKind,
    };
    use lisi_core::text::{Actor, DisplayName, SourceIdentifier};
    use lisi_core::{SourceId, Timestamp};
    use lisi_telegram::MockTelegramConnector;

    use super::{HistoryRequest, HistoryRun, HistoryTarget, archive, targets};
    use crate::acquisition::{AcquisitionService, SessionContext};
    use crate::acquisition_authority::StationAuthorityService;

    const CHAT: i64 = -1_001_000_000_002;

    /// L'avvio del monitoraggio è `t(0)`; un'unità è un minuto.
    fn t(minuti: i64) -> Timestamp {
        Timestamp::from_millis(1_790_294_400_000 + minuti * 60_000)
    }

    fn operatore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn ragione() -> OperationalReason {
        let Ok(ragione) = OperationalReason::try_new("fonte nuova del fascicolo 12/2026") else {
            panic!("la ragione di prova deve essere valida");
        };
        ragione
    }

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

    /// Un monitoraggio avviato a `t(0)` su una fonte.
    fn monitoraggio() -> (AcquisitionService, SessionContext, SourceId) {
        let Ok(mut database) = crate::sources::open_in_memory_database() else {
            panic!("l'archivio in memoria deve potersi aprire");
        };
        let (Ok(identificativo), Ok(nome), Ok(etichetta)) = (
            SourceIdentifier::try_new(&CHAT.to_string()),
            DisplayName::try_new("Canale nuovo"),
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
            t(-1),
        ) else {
            panic!("la sessione deve potersi creare");
        };
        let Ok(()) =
            database.save_resolved_configuration(sessione, &ConfigurationResolver::new().finish())
        else {
            panic!("la configurazione deve potersi salvare");
        };
        let Ok(()) = database.update_session_state(sessione, SessionState::Running, t(0)) else {
            panic!("il monitoraggio deve avviarsi");
        };
        let acquisizione = AcquisitionService::new(database);
        let Ok(contesto) = acquisizione.load_context(sessione, operatore()) else {
            panic!("il contesto deve potersi costruire");
        };
        (acquisizione, contesto, fonte)
    }

    fn bersaglio(acquisizione: &AcquisitionService) -> HistoryTarget {
        let Ok(mut righe) = targets(acquisizione.database()) else {
            panic!("i bersagli devono potersi comporre");
        };
        assert_eq!(righe.len(), 1);
        righe.remove(0)
    }

    fn richiesta(bersaglio: &HistoryTarget, giorni: i64) -> HistoryRequest {
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
        let Some(richiesta) =
            HistoryRequest::new(&autorita, bersaglio, giorni, operatore(), ragione())
        else {
            panic!("una durata dichiarata costruisce la richiesta");
        };
        richiesta
    }

    fn fino_in_fondo(lettura: &mut HistoryRun, connettore: &mut MockTelegramConnector) {
        for _ in 0..=super::HISTORY_MAX_PAGES {
            if lettura.is_finished() {
                return;
            }
            lettura.step(connettore);
        }
    }

    /// **Lo storico entra recuperato, con intervallo e operatore, e mai «dal
    /// vivo» né «non determinabile»** (PR-08, controllo negativo 5). Si legge
    /// soltanto fra l'inizio scelto e l'avvio.
    #[test]
    fn lo_storico_entra_recuperato_e_mai_dal_vivo() {
        let (mut acquisizione, contesto, _) = monitoraggio();
        let mut connettore = pronto();
        // Dal più recente: dopo l'avvio, dentro i sette giorni, oltre.
        for (id, minuti) in [(90, 5), (50, -60), (40, -3_000), (30, -20_000)] {
            let Ok(()) = connettore.push_history(
                CHAT,
                id,
                &format!("messaggio {id}"),
                t(minuti).as_millis(),
            ) else {
                panic!("la cronologia sintetica deve potersi scrivere");
            };
        }
        let bersaglio = bersaglio(&acquisizione);
        let Ok(mut lettura) = HistoryRun::new(acquisizione.database(), richiesta(&bersaglio, 7))
        else {
            panic!("la lettura deve potersi preparare");
        };
        fino_in_fondo(&mut lettura, &mut connettore);
        assert_eq!(lettura.missing().len(), 2, "solo i due dei sette giorni");
        assert!(lettura.operator_message().contains(super::HISTORY_LIMITS));

        let Ok(esito) = archive(&lettura, &mut acquisizione, &contesto, t(100)) else {
            panic!("l'archiviazione deve riuscire");
        };
        assert_eq!(esito.archived, 2);

        let Ok(modi) = crate::acquisition_mode::for_session(
            acquisizione.database(),
            contesto.session_id,
            t(101),
        ) else {
            panic!("i modi devono potersi ricavare");
        };
        assert_eq!(modi.len(), 2);
        for modo in modi.values() {
            let AcquisitionMode::Recovered {
                interval, operator, ..
            } = modo
            else {
                panic!("lo storico è sempre recuperato: {modo:?}");
            };
            assert_eq!(*interval, Some((t(-7 * 24 * 60), t(0))));
            assert_eq!(operator.as_deref(), Some("operatore.prova"));
        }
    }

    /// **La differenza fra trovati e archiviati si spiega** (E2E01-08): un
    /// messaggio con un carattere non ammesso va in quarantena, e l'esito lo
    /// dice con il numero invece di lasciare il buco.
    #[test]
    fn la_differenza_fra_trovati_e_archiviati_si_spiega() {
        let (mut acquisizione, contesto, _) = monitoraggio();
        let mut connettore = pronto();
        for (id, testo) in [
            (50, "messaggio valido"),
            (45, "campanello\u{7}nel testo"),
            (40, "altro messaggio valido"),
        ] {
            let Ok(()) = connettore.push_history(CHAT, id, testo, t(-60 - id).as_millis()) else {
                panic!("la cronologia sintetica deve potersi scrivere");
            };
        }
        let bersaglio = bersaglio(&acquisizione);
        let Ok(mut lettura) = HistoryRun::new(acquisizione.database(), richiesta(&bersaglio, 7))
        else {
            panic!("la lettura deve potersi preparare");
        };
        fino_in_fondo(&mut lettura, &mut connettore);
        assert_eq!(lettura.missing().len(), 3);

        let Ok(esito) = archive(&lettura, &mut acquisizione, &contesto, t(100)) else {
            panic!("l'archiviazione deve riuscire");
        };
        assert_eq!(esito.found, 3);
        assert_eq!(esito.archived, 2);
        assert_eq!(esito.quarantined, 1);
        assert_eq!(esito.unexplained(), 0, "nessun buco senza nome");
        let Some(frase) = esito.difference_sentence() else {
            panic!("una differenza c'è, e va detta");
        };
        assert!(frase.contains("Trovati 3, archiviati 2"), "{frase}");
        assert!(
            frase.contains("1 sono stati messi in quarantena"),
            "{frase}"
        );
    }

    /// **Un messaggio letto due volte si conta una volta** (E2E01-08): se due
    /// pagine riportano lo stesso messaggio, «mancano» non lo raddoppia.
    #[test]
    fn un_messaggio_letto_due_volte_si_conta_una_volta() {
        let (acquisizione, _, _) = monitoraggio();
        let mut connettore = pronto();
        for (id, minuti) in [(50, -60), (50, -60), (40, -90)] {
            let Ok(()) = connettore.push_history(CHAT, id, "lo stesso", t(minuti).as_millis())
            else {
                panic!("la cronologia sintetica deve potersi scrivere");
            };
        }
        let bersaglio = bersaglio(&acquisizione);
        let Ok(mut lettura) = HistoryRun::new(acquisizione.database(), richiesta(&bersaglio, 7))
        else {
            panic!("la lettura deve potersi preparare");
        };
        fino_in_fondo(&mut lettura, &mut connettore);
        let identificativi: Vec<i64> = lettura
            .missing()
            .iter()
            .map(|messaggio| messaggio.message_id.get())
            .collect();
        assert_eq!(identificativi, vec![50, 40], "il 50 una volta sola");
    }

    /// Senza differenza non c'è frase, e una differenza senza ragione nota
    /// si dichiara come tale invece di essere taciuta.
    #[test]
    fn la_frase_della_differenza_non_inventa_ragioni() {
        let pari = super::HistoryOutcome {
            found: 4,
            archived: 4,
            already_present: 0,
            quarantined: 0,
        };
        assert_eq!(pari.difference_sentence(), None);

        let ignota = super::HistoryOutcome {
            found: 725,
            archived: 717,
            already_present: 3,
            quarantined: 0,
        };
        assert_eq!(ignota.unexplained(), 5);
        let Some(frase) = ignota.difference_sentence() else {
            panic!("la differenza va detta");
        };
        assert!(frase.contains("degli altri 8"), "{frase}");
        assert!(frase.contains("3 erano già nell'archivio"), "{frase}");
        assert!(frase.contains("5 non sono stati legati"), "{frase}");
        assert!(
            !frase.contains("quarantena"),
            "nessuna ragione che non c'è: {frase}"
        );
    }

    /// **La ripresa non duplica, e parte dal più vecchio già in archivio**
    /// (controllo negativo 2): interrotta dopo una pagina, la lettura archivia
    /// ciò che ha trovato; la seconda trova soltanto il resto.
    #[test]
    fn la_ripresa_non_duplica() {
        let (mut acquisizione, contesto, _) = monitoraggio();
        let mut connettore = pronto();
        for id in (1..=250_i64).rev() {
            let Ok(()) = connettore.push_history(
                CHAT,
                id,
                &format!("messaggio {id}"),
                t(-(251 - id)).as_millis(),
            ) else {
                panic!("la cronologia sintetica deve potersi scrivere");
            };
        }
        let bersaglio = bersaglio(&acquisizione);
        let Ok(mut prima) = HistoryRun::new(acquisizione.database(), richiesta(&bersaglio, 7))
        else {
            panic!("la lettura deve potersi preparare");
        };
        prima.step(&mut connettore);
        prima.stop();
        assert_eq!(prima.missing().len(), 100);
        assert!(
            prima
                .operator_message()
                .contains("interrotta prima dell'inizio scelto")
        );
        let Ok(_) = archive(&prima, &mut acquisizione, &contesto, t(10)) else {
            panic!("ciò che è stato trovato si archivia");
        };
        // L'operazione dice l'intervallo davvero letto, non quello chiesto.
        let Ok(operazioni) = acquisizione
            .database()
            .source_recovery_operations(bersaglio.source_id)
        else {
            panic!("le operazioni devono potersi leggere");
        };
        assert_eq!(operazioni[0].interval, Some((t(-100), t(0))));

        let Ok(mut seconda) = HistoryRun::new(acquisizione.database(), richiesta(&bersaglio, 7))
        else {
            panic!("la lettura deve potersi preparare");
        };
        assert_eq!(
            seconda.next_from, 151,
            "si riparte sotto il più vecchio già in archivio"
        );
        fino_in_fondo(&mut seconda, &mut connettore);
        assert_eq!(seconda.missing().len(), 150, "soltanto il resto");
        let Ok(_) = archive(&seconda, &mut acquisizione, &contesto, t(20)) else {
            panic!("il resto si archivia");
        };
        let Ok(contenuti) = acquisizione
            .database()
            .session_contents(contesto.session_id)
        else {
            panic!("i contenuti devono potersi leggere");
        };
        assert_eq!(contenuti.len(), 250, "nessun doppione");
    }

    /// **La ragione operativa resta, con l'operazione** (controllo negativo 3).
    #[test]
    fn la_ragione_resta_nell_audit() {
        let (mut acquisizione, contesto, _) = monitoraggio();
        let mut connettore = pronto();
        let Ok(()) = connettore.push_history(CHAT, 10, "prima dell'avvio", t(-30).as_millis())
        else {
            panic!("la cronologia sintetica deve potersi scrivere");
        };
        let bersaglio = bersaglio(&acquisizione);
        let Ok(mut lettura) = HistoryRun::new(acquisizione.database(), richiesta(&bersaglio, 30))
        else {
            panic!("la lettura deve potersi preparare");
        };
        fino_in_fondo(&mut lettura, &mut connettore);
        let Ok(_) = archive(&lettura, &mut acquisizione, &contesto, t(5)) else {
            panic!("l'archiviazione deve riuscire");
        };
        let Ok(voci) = acquisizione.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let Some(voce) = voci
            .iter()
            .find(|voce| voce.action.as_str() == super::HISTORY_AUDIT_ACTION)
        else {
            panic!("l'operazione deve essere nell'audit");
        };
        let dettaglio = voce
            .detail
            .as_ref()
            .map_or("", |dettaglio| dettaglio.as_str());
        assert!(
            dettaglio.contains("motivo: «fonte nuova del fascicolo 12/2026»"),
            "{dettaglio}"
        );
        assert_eq!(voce.actor.as_str(), "operatore.prova");
    }

    /// **Una fonte che Telegram non lascia leggere è «Non recuperabile»**, e
    /// non si archivia nulla.
    #[test]
    fn una_fonte_illeggibile_non_e_recuperabile() {
        let (mut acquisizione, contesto, _) = monitoraggio();
        let mut connettore = MockTelegramConnector::new();
        let bersaglio = bersaglio(&acquisizione);
        let Ok(mut lettura) = HistoryRun::new(acquisizione.database(), richiesta(&bersaglio, 7))
        else {
            panic!("la lettura deve potersi preparare");
        };
        lettura.step(&mut connettore);
        assert!(lettura.is_finished());
        assert!(lettura.operator_message().starts_with("Non recuperabile:"));
        assert!(archive(&lettura, &mut acquisizione, &contesto, t(5)).is_err());
    }

    /// **Soltanto le durate dichiarate, e soltanto i monitoraggi in corso.**
    #[test]
    fn solo_durate_dichiarate_e_monitoraggi_in_corso() {
        let (mut acquisizione, contesto, _) = monitoraggio();
        let bersaglio = bersaglio(&acquisizione);
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
        for giorni in [0, 10, 365] {
            assert!(
                HistoryRequest::new(autorita, &bersaglio, giorni, operatore(), ragione()).is_none(),
                "{giorni} giorni non è una durata dichiarata"
            );
        }
        let Some(richiesta) = HistoryRequest::new(autorita, &bersaglio, 30, operatore(), ragione())
        else {
            panic!("trenta giorni è una durata dichiarata");
        };
        assert_eq!(
            richiesta.interval(),
            (t(-30 * 24 * 60), t(0)),
            "fino all'avvio"
        );

        let Ok(()) = acquisizione.database_mut().update_session_state(
            contesto.session_id,
            SessionState::Stopped,
            t(50),
        ) else {
            panic!("il monitoraggio deve concludersi");
        };
        let Ok(righe) = targets(acquisizione.database()) else {
            panic!("i bersagli devono potersi comporre");
        };
        assert!(
            righe.is_empty(),
            "un monitoraggio concluso non riceve storico"
        );
    }

    /// **Lo storico si vede come uno strato a parte, non come copertura**
    /// (controllo negativo 1): nel periodo letto dopo, la copertura resta quella
    /// di allora, e l'intervallo compare fra i recuperati.
    #[test]
    fn lo_storico_e_uno_strato_non_copertura() {
        use lisi_core::model::coverage::CoverageState;

        let (mut acquisizione, contesto, fonte) = monitoraggio();
        let mut connettore = pronto();
        let Ok(()) = connettore.push_history(CHAT, 10, "prima dell'avvio", t(-600).as_millis())
        else {
            panic!("la cronologia sintetica deve potersi scrivere");
        };
        let bersaglio = bersaglio(&acquisizione);
        let Ok(mut lettura) = HistoryRun::new(acquisizione.database(), richiesta(&bersaglio, 7))
        else {
            panic!("la lettura deve potersi preparare");
        };
        fino_in_fondo(&mut lettura, &mut connettore);
        let Ok(_) = archive(&lettura, &mut acquisizione, &contesto, t(5)) else {
            panic!("l'archiviazione deve riuscire");
        };

        let (dal, al) = (t(-8 * 24 * 60), t(10));
        let Ok(strato) = crate::coverage::recovered_spans(acquisizione.database(), fonte, dal, al)
        else {
            panic!("lo strato deve potersi leggere");
        };
        assert_eq!(strato, vec![(t(-7 * 24 * 60), t(0))]);

        let Ok(coperture) = crate::coverage::for_sources(acquisizione.database(), dal, al) else {
            panic!("la copertura deve potersi comporre");
        };
        let Some(della_fonte) = coperture.iter().find(|voce| voce.source_id == fonte) else {
            panic!("la fonte deve avere la sua copertura");
        };
        for tratto in della_fonte.coverage.intervals() {
            if tratto.from < t(0) {
                assert_ne!(
                    tratto.state,
                    CoverageState::Covered,
                    "prima dell'avvio nessuno guardava, anche se dopo si è letto"
                );
            }
        }
    }
}

#[cfg(test)]
mod read_failure_tests {
    use lisi_telegram::TelegramError;

    use super::history_read_failure;

    /// **Un'attesa non è un divieto** (FINAL-REVIEW-01, FR-009).
    #[test]
    fn a_timeout_or_a_rate_limit_is_not_a_refusal() {
        let scaduta = history_read_failure(&TelegramError::Timeout { millis: 10_000 });
        assert!(!scaduta.contains("non consente"), "{scaduta}");
        assert!(scaduta.contains("Non è un rifiuto"), "{scaduta}");

        let frequenza = history_read_failure(&TelegramError::Tdlib {
            reason: String::from(
                "errore del componente per Telegram 429: Too Many Requests: retry after 30",
            ),
        });
        assert!(!frequenza.contains("non consente"), "{frequenza}");
        assert!(frequenza.contains("attendere"), "{frequenza}");

        let rifiuto = history_read_failure(&TelegramError::Tdlib {
            reason: String::from("errore del componente per Telegram 400: CHANNEL_PRIVATE"),
        });
        assert!(rifiuto.contains("non consente"), "{rifiuto}");
    }

    /// **«429» dentro un numero più lungo non è un limite di frequenza**
    /// (FINAL-REVIEW-01, revisione finale del diff).
    #[test]
    fn a_429_inside_a_longer_number_is_not_a_rate_limit() {
        let rifiuto = history_read_failure(&TelegramError::Tdlib {
            reason: String::from("errore del componente per Telegram 400: chat 14290 privata"),
        });
        assert!(rifiuto.contains("non consente"), "{rifiuto}");
    }
}

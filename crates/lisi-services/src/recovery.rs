//! Recupero della cronologia di una fonte.
//!
//! # Due atti distinti, e la distinzione conta
//!
//! **Guardare** e **archiviare** sono due cose diverse, e questo modulo le tiene
//! separate perché lo sono anche per chi risponde di ciò che l'archivio
//! contiene.
//!
//! [`survey`] legge la cronologia già pubblicata e dice **quanti messaggi
//! mancano**, senza scrivere nulla. Leggere è ciò che l'account fa comunque:
//! scorrere all'indietro una conversazione a cui si ha accesso non lascia
//! traccia in archivio. [`apply`] è l'atto che archivia, e avviene solo dopo che
//! l'operatore ha visto il numero e ha confermato.
//!
//! È la scelta dell'ufficio: *«dire quanti ne mancano e chiedere conferma prima
//! di partire»*. Un recupero silenzioso su un canale attivo lasciato un fine
//! settimana porterebbe in archivio migliaia di messaggi che nessuno ha deciso
//! di acquisire.
//!
//! # Fin dove si risale
//!
//! Fino all'**inizio del monitoraggio in corso**, che è la risposta data
//! dall'ufficio. Non oltre: prima di quell'istante il monitoraggio non era
//! stato deciso, e l'archivio non deve contenere ciò che nessuno ha chiesto di
//! sorvegliare.
//!
//! # Il tetto, e perché il numero può essere una stima per difetto
//!
//! La lettura procede a pagine, all'indietro, e si ferma a un tetto di pagine.
//! Senza tetto un canale molto attivo produrrebbe un'attesa che sembra un
//! blocco. Quando il tetto scatta prima dell'inizio del monitoraggio, il
//! risultato dichiara di essere **incompleto**: dire «mancano 500 messaggi»
//! quando sono 500 *finora contati* sarebbe un numero preciso e falso.

use std::collections::BTreeSet;

use lisi_core::{SessionId, SourceId, Timestamp};
use lisi_storage::Database;
use lisi_telegram::identifier::ChatId;
use lisi_telegram::{IncomingMessage, TelegramConnector};

use crate::acquisition::{AcquisitionService, IngestReport, SessionContext};
use crate::error::{ServiceError, ServiceResult};

/// Messaggi chiesti in una sola pagina.
///
/// Coincide con il tetto che TDLib accetta per `getChatHistory`.
const PAGE_SIZE: u32 = 100;

/// Pagine massime lette in una ricognizione.
///
/// Centomila messaggi sono ampiamente oltre ciò che un fine settimana produce
/// su una fonte reale; il tetto esiste perché *esista*, non perché ci si arrivi.
/// Quando scatta, il risultato lo dichiara invece di far credere di aver
/// guardato tutto.
const MAX_PAGES: usize = 1_000;

/// Che cosa la ricognizione ha trovato, senza aver scritto nulla.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoverySurvey {
    /// Messaggi pubblicati dopo l'inizio del monitoraggio che **non** sono in
    /// archivio, dal più recente al più vecchio.
    pub missing: Vec<IncomingMessage>,
    /// Quanti dei messaggi letti erano già in archivio.
    ///
    /// Non è un dettaglio tecnico: è la differenza fra «il monitoraggio non ha
    /// visto nulla» e «il monitoraggio ha visto quasi tutto», e chi decide se
    /// avviare un recupero deve poterla vedere.
    pub already_present: usize,
    /// Se la lettura ha raggiunto l'inizio del monitoraggio.
    ///
    /// Falso quando il tetto di pagine è scattato prima: in quel caso il numero
    /// dei mancanti è una **stima per difetto**, e va detto.
    pub reached_session_start: bool,
}

impl RecoverySurvey {
    /// Quanti messaggi verrebbero archiviati confermando.
    #[must_use]
    pub const fn missing_count(&self) -> usize {
        self.missing.len()
    }

    /// Se non c'è nulla da recuperare.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.missing.is_empty()
    }

    /// Frase per l'operatore, da mostrare **prima** di chiedere conferma.
    ///
    /// Dice il numero, dice che cosa era già stato osservato, e dichiara quando
    /// il numero è una stima per difetto. Non promette completezza che non ha.
    #[must_use]
    pub fn operator_message(&self) -> String {
        if self.is_empty() {
            return if self.reached_session_start {
                String::from(
                    "Non manca nulla: ogni messaggio pubblicato da questa fonte \
                     dall'inizio del monitoraggio è già in archivio.",
                )
            } else {
                String::from(
                    "Fra i messaggi più recenti non manca nulla, ma la lettura si è fermata \
                     prima di raggiungere l'inizio del monitoraggio: potrebbero essercene \
                     altri più indietro.",
                )
            };
        }

        let quanti = if self.missing_count() == 1 {
            String::from("Manca 1 messaggio")
        } else {
            format!("Mancano {} messaggi", self.missing_count())
        };

        let precisione = if self.reached_session_start {
            String::from(" dall'inizio del monitoraggio.")
        } else {
            String::from(
                " e potrebbero essercene altri: la lettura si è fermata prima di \
                 raggiungere l'inizio del monitoraggio.",
            )
        };

        let osservati = if self.already_present == 0 {
            String::new()
        } else if self.already_present == 1 {
            String::from(" Un altro messaggio era già stato acquisito.")
        } else {
            format!(
                " Altri {} messaggi erano già stati acquisiti.",
                self.already_present
            )
        };

        format!(
            "{quanti}{precisione}{osservati} \
             Verranno registrati come recuperati dalla cronologia, non come osservati."
        )
    }
}

/// Legge la cronologia di una fonte **senza archiviare nulla**.
///
/// Risale all'indietro fino a `session_started_at`, saltando i messaggi già in
/// archivio per quella sessione e quella fonte.
///
/// # Errori
///
/// Restituisce un errore se la lettura dalla piattaforma o dall'archivio non
/// riesce.
pub fn survey(
    connector: &mut dyn TelegramConnector,
    database: &Database,
    session_id: SessionId,
    source_id: SourceId,
    chat_id: ChatId,
    session_started_at: Timestamp,
) -> ServiceResult<RecoverySurvey> {
    let known = known_remote_ids(database, session_id, source_id)?;

    let mut missing = Vec::new();
    let mut already_present = 0_usize;
    let mut from_message_id = 0_i64;
    let mut reached_session_start = false;

    for _ in 0..MAX_PAGES {
        let page = connector
            .fetch_history(chat_id, from_message_id, PAGE_SIZE)
            .map_err(|error| ServiceError::SessionUnavailable {
                reason: format!("cronologia non leggibile: {error}"),
            })?;

        if page.is_empty() {
            // La fonte non ha altro da mostrare: si è visto tutto ciò che
            // esiste, quindi anche l'inizio del monitoraggio è alle spalle.
            reached_session_start = true;
            break;
        }

        // L'identificativo da cui ripartire è quello dell'ultimo messaggio
        // letto, che essendo la pagina ordinata dal più recente è anche il più
        // vecchio. Si aggiorna **prima** dei filtri: saltare un messaggio non
        // deve far ripartire la pagina successiva dallo stesso punto, che è il
        // modo in cui una paginazione gira in tondo.
        if let Some(last) = page.last() {
            from_message_id = last.message_id.get();
        }

        let mut crossed_the_start = false;
        for message in page {
            if message.published_at_millis < session_started_at.as_millis() {
                // Prima dell'inizio del monitoraggio: nessuno ha chiesto di
                // sorvegliare quel periodo, e l'archivio non deve contenerlo.
                crossed_the_start = true;
                continue;
            }

            let remote_id = message.message_id.get().to_string();
            if known.contains(&remote_id) {
                already_present += 1;
            } else {
                missing.push(message);
            }
        }

        if crossed_the_start {
            reached_session_start = true;
            break;
        }
    }

    Ok(RecoverySurvey {
        missing,
        already_present,
        reached_session_start,
    })
}

/// Percorre **tutte le fonti** della sessione in corso.
///
/// Il ciclo sta qui e non nell'interfaccia perché è logica — quali fonti, in
/// quale ordine, che cosa fare quando una non risponde — e la logica
/// nell'interfaccia è logica che nessun test esercita.
///
/// **Una fonte che non risponde non ferma le altre.** L'errore viene registrato
/// e la ricognizione prosegue: perdere il recupero di cinque fonti perché la
/// sesta è irraggiungibile sarebbe un danno maggiore del guasto. Il risultato
/// però lo dichiara — `reached_session_start` diventa falso — perché un numero
/// che tace di essere parziale è un numero falso.
///
/// # Errori
///
/// Restituisce un errore se l'archivio non è leggibile. I guasti della singola
/// fonte non sono errori di questa funzione.
pub fn survey_session(
    connector: &mut dyn TelegramConnector,
    database: &Database,
    context: &SessionContext,
    session_started_at: Timestamp,
) -> ServiceResult<RecoverySurvey> {
    let mut total = RecoverySurvey {
        reached_session_start: true,
        ..RecoverySurvey::default()
    };

    // L'ordine è quello degli identificativi di chat, e non quello della mappa:
    // una `HashMap` non ha ordine, e un recupero che leggesse le fonti in
    // sequenza diversa a ogni esecuzione renderebbe irriproducibile ciò che
    // l'operatore vede.
    let mut chats: Vec<(i64, SourceId)> = context.monitored_chats().collect();
    chats.sort_unstable();

    for (raw_chat, source_id) in chats {
        let Ok(chat_id) = ChatId::try_new(raw_chat) else {
            tracing::warn!(chat = raw_chat, "identificativo di chat non valido");
            total.reached_session_start = false;
            continue;
        };

        match survey(
            connector,
            database,
            context.session_id,
            source_id,
            chat_id,
            session_started_at,
        ) {
            Ok(one) => {
                total.missing.extend(one.missing);
                total.already_present = total.already_present.saturating_add(one.already_present);
                if !one.reached_session_start {
                    total.reached_session_start = false;
                }
            }
            Err(error) => {
                tracing::warn!(
                    kind = error.kind(),
                    "cronologia di una fonte non leggibile: le altre proseguono"
                );
                total.reached_session_start = false;
            }
        }
    }

    Ok(total)
}

/// Ricognizione **riprendibile**, una fonte per volta.
///
/// Esiste perché una ricognizione su più fonti attive può durare parecchio, e
/// un'applicazione che sembra bloccata senza spiegazione è il difetto che
/// questo progetto ha già incontrato più volte. Chi la guida — il ciclo
/// periodico dell'interfaccia — la fa avanzare di un passo alla volta e fra un
/// passo e l'altro può ridisegnare, dire a che punto è, e **fermarsi**.
///
/// La fermata non è un annullamento: ciò che è già stato trovato resta, e
/// l'operatore decide se archiviarlo. Buttare via il lavoro fatto perché
/// qualcuno ha premuto «basta» sarebbe punire chi si è accorto che stava
/// durando troppo.
#[derive(Debug)]
pub struct SurveyRun {
    /// Fonti ancora da leggere, in ordine.
    remaining: Vec<(i64, SourceId)>,
    /// Quante fonti la sessione ha in tutto, per dire «N di M».
    total_sources: usize,
    /// Ciò che è stato trovato finora.
    found: RecoverySurvey,
    session_id: SessionId,
    session_started_at: Timestamp,
}

impl SurveyRun {
    /// Prepara una ricognizione su tutte le fonti della sessione.
    #[must_use]
    pub fn new(context: &SessionContext, session_started_at: Timestamp) -> Self {
        // Ordinate, e non nell'ordine della mappa: una `HashMap` non ha ordine,
        // e leggere le fonti in sequenza diversa a ogni esecuzione renderebbe
        // irriproducibile ciò che l'operatore vede.
        let mut remaining: Vec<(i64, SourceId)> = context.monitored_chats().collect();
        remaining.sort_unstable();
        // Si consuma dal fondo, quindi si inverte per leggere nell'ordine
        // crescente che l'operatore si aspetta.
        remaining.reverse();

        Self {
            total_sources: remaining.len(),
            remaining,
            found: RecoverySurvey {
                reached_session_start: true,
                ..RecoverySurvey::default()
            },
            session_id: context.session_id,
            session_started_at,
        }
    }

    /// Se non c'è più nulla da leggere.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.remaining.is_empty()
    }

    /// Quante fonti sono già state lette.
    #[must_use]
    pub const fn sources_done(&self) -> usize {
        self.total_sources.saturating_sub(self.remaining.len())
    }

    /// Quante fonti in tutto.
    #[must_use]
    pub const fn total_sources(&self) -> usize {
        self.total_sources
    }

    /// Ciò che è stato trovato finora.
    #[must_use]
    pub const fn found(&self) -> &RecoverySurvey {
        &self.found
    }

    /// Consegna ciò che è stato trovato, consumando la ricognizione.
    #[must_use]
    pub fn into_found(self) -> RecoverySurvey {
        self.found
    }

    /// Frase di avanzamento per l'operatore.
    #[must_use]
    pub fn progress_message(&self) -> String {
        format!(
            "Lettura in corso: {} su {}, {} finora.",
            lisi_core::text::counted(self.sources_done(), "fonte", "fonti"),
            self.total_sources,
            lisi_core::text::counted(
                self.found.missing_count(),
                "messaggio trovato",
                "messaggi trovati"
            )
        )
    }

    /// Interrompe la ricognizione, **conservando** ciò che ha già trovato.
    ///
    /// Il risultato viene marcato come incompleto: chi si ferma a metà non deve
    /// poi leggere un numero che si presenta come definitivo.
    pub fn stop(&mut self) {
        self.remaining.clear();
        self.found.reached_session_start = false;
    }

    /// Legge **una** fonte.
    ///
    /// # Errori
    ///
    /// Restituisce un errore solo se l'archivio non è leggibile. Il guasto di
    /// una singola fonte non ferma le altre: viene registrato e la ricognizione
    /// prosegue, dichiarandosi incompleta.
    pub fn step(
        &mut self,
        connector: &mut dyn TelegramConnector,
        database: &Database,
    ) -> ServiceResult<()> {
        let Some((raw_chat, source_id)) = self.remaining.pop() else {
            return Ok(());
        };

        let Ok(chat_id) = ChatId::try_new(raw_chat) else {
            tracing::warn!(chat = raw_chat, "identificativo di chat non valido");
            self.found.reached_session_start = false;
            return Ok(());
        };

        match survey(
            connector,
            database,
            self.session_id,
            source_id,
            chat_id,
            self.session_started_at,
        ) {
            Ok(one) => {
                self.found.missing.extend(one.missing);
                self.found.already_present = self
                    .found
                    .already_present
                    .saturating_add(one.already_present);
                if !one.reached_session_start {
                    self.found.reached_session_start = false;
                }
            }
            Err(error) => {
                tracing::warn!(
                    kind = error.kind(),
                    "cronologia di una fonte non leggibile: le altre proseguono"
                );
                self.found.reached_session_start = false;
            }
        }

        Ok(())
    }
}

/// Archivia i messaggi trovati dalla ricognizione.
///
/// Va chiamata **solo dopo** che l'operatore ha visto
/// [`RecoverySurvey::operator_message`] e ha confermato: è l'atto che scrive.
///
/// # Errori
///
/// Restituisce un errore se la scrittura non riesce.
pub fn apply(
    survey: &RecoverySurvey,
    acquisition: &mut AcquisitionService,
    context: &SessionContext,
    operator: &lisi_core::text::Actor,
    now: Timestamp,
) -> ServiceResult<IngestReport> {
    let report = acquisition.ingest_recovered(&survey.missing, context, now)?;

    // IL REGISTRO DEI RECUPERI (PR-07, ADR-0123): un'operazione per fonte, con
    // chi l'ha chiesta e quando. L'intervallo è quello implicito di questo
    // recupero — dall'inizio del monitoraggio — e il registro lo dice lasciando
    // l'intervallo vuoto, invece di scriverne uno.
    let mut per_fonte: std::collections::BTreeMap<i64, Vec<IncomingMessage>> =
        std::collections::BTreeMap::new();
    for messaggio in &survey.missing {
        if let Some((_, fonte)) = context
            .monitored_chats()
            .find(|(chat, _)| *chat == messaggio.chat_id.get())
        {
            per_fonte
                .entry(fonte.get())
                .or_default()
                .push(messaggio.clone());
        }
    }
    for (fonte, messaggi) in per_fonte {
        let fonte = SourceId::new(fonte);
        let archiviati = crate::interval_recovery::legati(
            acquisition.database(),
            context.session_id,
            fonte,
            &messaggi,
        )?;
        let audit = lisi_core::model::NewAuditEntry {
            actor: operator.clone(),
            action: lisi_core::text::AuditAction::try_new("recupero_archiviato")?,
            entity: lisi_core::text::AuditEntity::try_new("recupero")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(lisi_core::text::AuditDetail::try_new(&format!(
                "fonte {}, dall'inizio del monitoraggio: {} trovati, {} archiviati",
                fonte.get(),
                messaggi.len(),
                archiviati.len()
            ))?),
            recorded_at: now,
        };
        acquisition.database_mut().insert_recovery_operation(
            &lisi_storage::repository::recovery_operation::NewRecoveryOperation {
                session_id: context.session_id,
                source_id: fonte,
                interval: None,
                requested_by: String::from(operator.as_str()),
                performed_at: now,
                found: u32::try_from(messaggi.len()).unwrap_or(u32::MAX),
                archived: archiviati,
            },
            &audit,
        )?;
    }
    Ok(report)
}

/// Identificativi remoti già in archivio per quella sessione e quella fonte.
fn known_remote_ids(
    database: &Database,
    session_id: SessionId,
    source_id: SourceId,
) -> ServiceResult<BTreeSet<String>> {
    Ok(database
        .session_contents(session_id)?
        .into_iter()
        .filter(|content| content.source_id == source_id)
        .map(|content| content.remote_message_id.as_str().to_owned())
        .collect())
}

#[cfg(test)]
mod tests {
    use lisi_core::{SessionId, SourceId, Timestamp};
    use lisi_telegram::identifier::ChatId;
    use lisi_telegram::mock::MockTelegramConnector;

    use super::{RecoverySurvey, survey};
    use crate::sources::open_in_memory_database;

    const CHAT: i64 = -1_001_000_000_001;

    /// Istante d'avvio del monitoraggio nei test.
    fn started_at() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn chat() -> ChatId {
        let Ok(chat) = ChatId::try_new(CHAT) else {
            panic!("l'identificativo di prova deve essere valido");
        };
        chat
    }

    /// Connettore autorizzato, pronto a rispondere sulla cronologia.
    fn ready_connector() -> MockTelegramConnector {
        use lisi_telegram::TelegramConnector;
        use lisi_telegram::connector::ClientParameters;
        use lisi_telegram::secret::{ApiHash, ApiId, LoginCode, PhoneNumber};

        let mut connector = MockTelegramConnector::new();
        let (Ok(api_id), Ok(api_hash)) = (ApiId::try_new(1), ApiHash::try_new(&"a".repeat(32)))
        else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(()) = connector.start(&ClientParameters {
            api_id,
            api_hash,
            database_directory: std::path::PathBuf::from("."),
            use_test_datacenter: true,
            application_version: String::from("prova"),
            system_language_code: String::from("it"),
        }) else {
            panic!("l'avvio simulato deve riuscire");
        };
        let (Ok(phone), Ok(code)) = (
            PhoneNumber::try_new("+390000000000"),
            LoginCode::try_new("12345"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let (Ok(()), Ok(())) = (
            connector.submit_phone_number(&phone),
            connector.submit_code(&code),
        ) else {
            panic!("l'accesso simulato deve riuscire");
        };
        connector
    }

    fn run(connector: &mut MockTelegramConnector) -> RecoverySurvey {
        let Ok(database) = open_in_memory_database() else {
            panic!("l'archivio in memoria deve potersi aprire");
        };
        let Ok(outcome) = survey(
            connector,
            &database,
            SessionId::new(1),
            SourceId::new(1),
            chat(),
            started_at(),
        ) else {
            panic!("la ricognizione deve riuscire");
        };
        outcome
    }

    #[test]
    fn a_source_with_nothing_published_has_nothing_to_recover() {
        let mut connector = ready_connector();
        let outcome = run(&mut connector);

        assert!(outcome.is_empty());
        assert!(outcome.reached_session_start);
        assert!(outcome.operator_message().contains("Non manca nulla"));
    }

    #[test]
    fn messages_published_after_the_session_started_are_reported_as_missing() {
        let mut connector = ready_connector();
        // Dal piu' recente al piu' vecchio, come li restituisce la piattaforma.
        let (Ok(()), Ok(())) = (
            connector.push_history(CHAT, 3 << 20, "terzo", started_at().as_millis() + 3_000),
            connector.push_history(CHAT, 2 << 20, "secondo", started_at().as_millis() + 2_000),
        ) else {
            panic!("la cronologia di prova deve potersi comporre");
        };

        let outcome = run(&mut connector);
        assert_eq!(outcome.missing_count(), 2);
        assert_eq!(outcome.already_present, 0);

        let message = outcome.operator_message();
        assert!(message.contains("Mancano 2 messaggi"));
        // La frase deve dire **come** verranno registrati: chi conferma sta
        // decidendo che cosa l'archivio affermera'.
        assert!(message.contains("recuperati dalla cronologia"));
    }

    #[test]
    fn what_was_published_before_the_session_started_is_left_alone() {
        // Prima di quell'istante il monitoraggio non era stato deciso, e
        // l'archivio non deve contenere cio' che nessuno ha chiesto di
        // sorvegliare.
        let mut connector = ready_connector();
        let (Ok(()), Ok(())) = (
            connector.push_history(CHAT, 2 << 20, "dopo", started_at().as_millis() + 1_000),
            connector.push_history(CHAT, 1 << 20, "prima", started_at().as_millis() - 1_000),
        ) else {
            panic!("la cronologia di prova deve potersi comporre");
        };

        let outcome = run(&mut connector);
        assert_eq!(outcome.missing_count(), 1);
        assert_eq!(outcome.missing[0].text, "dopo");
        assert!(outcome.reached_session_start);
    }

    #[test]
    fn a_message_exactly_at_the_session_start_is_included() {
        // Il confine e' incluso: un messaggio pubblicato nell'istante in cui il
        // monitoraggio e' iniziato appartiene al monitoraggio. Escluderlo
        // sarebbe una perdita silenziosa proprio sul bordo.
        let mut connector = ready_connector();
        let Ok(()) = connector.push_history(CHAT, 1 << 20, "sul bordo", started_at().as_millis())
        else {
            panic!("la cronologia di prova deve potersi comporre");
        };

        let outcome = run(&mut connector);
        assert_eq!(outcome.missing_count(), 1);
    }

    #[test]
    fn the_survey_writes_nothing() {
        // E' la separazione per cui questo modulo esiste: guardare non e'
        // archiviare, e chi guarda per decidere non deve trovarsi con
        // l'archivio gia' cambiato.
        let mut connector = ready_connector();
        let Ok(()) = connector.push_history(CHAT, 1 << 20, "messaggio", started_at().as_millis())
        else {
            panic!("la cronologia di prova deve potersi comporre");
        };

        let Ok(database) = open_in_memory_database() else {
            panic!("l'archivio in memoria deve potersi aprire");
        };
        let Ok(_) = survey(
            &mut connector,
            &database,
            SessionId::new(1),
            SourceId::new(1),
            chat(),
            started_at(),
        ) else {
            panic!("la ricognizione deve riuscire");
        };

        let Ok(contents) = database.session_contents(SessionId::new(1)) else {
            panic!("l'archivio deve potersi leggere");
        };
        assert!(
            contents.is_empty(),
            "la ricognizione non deve scrivere alcun contenuto"
        );
    }

    #[test]
    fn what_is_already_in_the_archive_is_counted_apart_and_not_offered_again() {
        // È il numero che distingue «il monitoraggio non ha visto nulla» da «ha
        // visto quasi tutto», e chi decide se avviare un recupero lo legge.
        // Contare come mancante ciò che c'è già gonfierebbe quel numero.
        use lisi_core::model::{
            AcquisitionOrigin, AnalysisLevel, NewContent, NewSession, NewSource, SessionDuration,
            SourceKind,
        };
        use lisi_core::text::{ContentBody, DisplayName, RemoteMessageId, SourceIdentifier};

        let Ok(mut database) = open_in_memory_database() else {
            panic!("l'archivio in memoria deve potersi aprire");
        };
        let (Ok(identifier), Ok(title), Ok(label), Ok(actor)) = (
            SourceIdentifier::try_new("canale_uno"),
            DisplayName::try_new("Canale di prova"),
            DisplayName::try_new("Monitoraggio di prova"),
            lisi_core::text::Actor::try_new("operatore.prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(source_id) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier,
                display_name: title,
                authorized_by: actor.clone(),
                active: true,
            },
            started_at(),
        ) else {
            panic!("la fonte deve potersi registrare");
        };
        let Ok(session_id) = database.insert_session(
            &NewSession {
                label,
                started_by: actor,
                duration: SessionDuration::Preset { seconds: 3_600 },
                source_ids: vec![source_id],
            },
            started_at(),
        ) else {
            panic!("la sessione deve potersi creare");
        };

        // Il messaggio 2 è già stato osservato dal vivo.
        let (Ok(remote), Ok(body)) = (
            RemoteMessageId::try_new(&(2_i64 << 20).to_string()),
            ContentBody::try_new("gia' visto"),
        ) else {
            panic!("i valori del contenuto devono essere validi");
        };
        let Ok(_) = database.insert_content(&NewContent {
            session_id,
            source_id,
            remote_message_id: remote,
            author: None,
            author_identifier: None,
            author_username: None,
            body,
            url: None,
            published_at: Timestamp::from_millis(started_at().as_millis() + 2_000),
            acquired_at: Timestamp::from_millis(started_at().as_millis() + 2_100),
            origin: AcquisitionOrigin::Observed,
            analysis_level: AnalysisLevel::NOT_RELEVANT,
        }) else {
            panic!("il contenuto deve potersi registrare");
        };

        let mut connector = ready_connector();
        let (Ok(()), Ok(())) = (
            connector.push_history(CHAT, 3 << 20, "nuovo", started_at().as_millis() + 3_000),
            connector.push_history(
                CHAT,
                2 << 20,
                "gia' visto",
                started_at().as_millis() + 2_000,
            ),
        ) else {
            panic!("la cronologia di prova deve potersi comporre");
        };

        let Ok(outcome) = survey(
            &mut connector,
            &database,
            session_id,
            source_id,
            chat(),
            started_at(),
        ) else {
            panic!("la ricognizione deve riuscire");
        };

        assert_eq!(outcome.missing_count(), 1, "solo quello che manca davvero");
        assert_eq!(outcome.missing[0].text, "nuovo");
        assert_eq!(outcome.already_present, 1);
        assert!(
            outcome
                .operator_message()
                .contains("era già stato acquisito")
        );
    }

    #[test]
    fn an_empty_survey_that_never_reached_the_start_says_it_is_uncertain() {
        // Un numero preciso e falso e' peggio di un numero dichiarato incerto.
        let outcome = RecoverySurvey {
            missing: Vec::new(),
            already_present: 0,
            reached_session_start: false,
        };
        assert!(outcome.operator_message().contains("potrebbero essercene"));
    }

    #[test]
    fn a_partial_survey_declares_that_the_number_may_grow() {
        let outcome = RecoverySurvey {
            missing: Vec::new(),
            already_present: 0,
            reached_session_start: true,
        };
        assert!(outcome.operator_message().contains("Non manca nulla"));
    }
}

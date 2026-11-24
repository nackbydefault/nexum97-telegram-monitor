//! Storico dei contenuti acquisiti e analizzati.
//!
//! È la vista che il requisito chiama «storico di ogni contenuto effettivamente
//! acquisito e analizzato». La parola importante è **ogni**: comprende anche i
//! contenuti di livello 0, che non hanno prodotto alcun alert. Mostrare soltanto
//! ciò che ha fatto scattare qualcosa darebbe l'impressione che il monitoraggio
//! abbia osservato solo quello.
//!
//! # Che cosa questo modulo fa e che cosa non fa
//!
//! Assembla, non decide. Il livello viene dal motore, la motivazione dall'alert,
//! lo stato dalla revisione: qui si mettono accanto perché una riga sia
//! leggibile senza aprire quattro tabelle. Nessun valore mostrato è ricalcolato,
//! perché un ricalcolo che diverge dal registro racconterebbe una storia diversa
//! da quella che è stata scritta al momento dell'analisi.
//!
//! # Gli avvisi sono lo stesso storico, filtrato
//!
//! La schermata «Alert» non ha un archivio proprio: è questo, con la soglia
//! sul livello. Due elenchi separati sarebbero due verità, e la seconda
//! invecchierebbe.

use lisi_core::model::analysis::ContentMatch;
use lisi_core::model::content_history::{ContentHistory, ContentHistorySummary};
use lisi_core::model::{AcquisitionMode, Alert, Content, Review, ReviewState, Session};
use lisi_core::text::DisplayName;
use lisi_core::{SessionId, SourceId};
use lisi_storage::Database;

use crate::error::ServiceResult;

/// Riga dello storico: un contenuto con ciò che serve a giudicarlo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// Contenuto registrato, con corpo, URL e istanti.
    pub content: Content,
    /// Nome della fonte da cui proviene, come mostrato all'operatore.
    pub source_name: DisplayName,
    /// Riscontri del dizionario, in ordine di posizione nel testo.
    pub matches: Vec<ContentMatch>,
    /// Alert, presente solo dai livelli 1 in su.
    pub alert: Option<Alert>,
    /// Ultima decisione umana, se qualcuno lo ha esaminato.
    pub last_decision: Option<Review>,
    /// Che cosa è successo al messaggio dopo l'acquisizione, in forma breve.
    ///
    /// # Perché la forma breve e non la storia intera
    ///
    /// Lo Storico mostra centinaia di righe. La forma breve dice se il
    /// messaggio è stato modificato o non è più esposto dalla fonte, e costa
    /// **due letture per sessione** invece di due per riga. I corpi delle
    /// versioni si leggono quando l'operatore apre il contenuto — con
    /// [`HistoryService::content_history`] — perché è l'unico momento in cui
    /// servono davvero.
    pub history: ContentHistorySummary,
    /// Come il contenuto è entrato: dal vivo, recuperato o non determinabile
    /// (PR-07, ADR-0123). Ricavato dai fatti con il criterio «Modo di
    /// acquisizione», mai con un valore predefinito.
    pub mode: AcquisitionMode,
}

impl HistoryEntry {
    /// Livello attribuito dall'analisi, da 0 a 4.
    #[must_use]
    pub const fn level(&self) -> u8 {
        self.content.analysis_level.get()
    }

    /// Se il contenuto ha prodotto un alert.
    #[must_use]
    pub const fn raised_alert(&self) -> bool {
        self.alert.is_some()
    }

    /// Stato corrente della revisione.
    ///
    /// Un contenuto che nessuno ha aperto è `New`: l'assenza di decisione è
    /// essa stessa uno stato, e non va confusa con un contenuto archiviato.
    #[must_use]
    pub fn review_state(&self) -> ReviewState {
        self.last_decision
            .as_ref()
            .map_or(ReviewState::New, |review| review.state)
    }

    /// Se attende ancora una decisione umana.
    #[must_use]
    pub fn awaits_a_decision(&self) -> bool {
        !self.review_state().is_decided()
    }

    /// Motivazione del livello, come è stata scritta al momento dell'analisi.
    ///
    /// Per i contenuti di livello 0 l'alert non esiste, e con esso la frase:
    /// il limite è dichiarato in `analysis.rs`. Qui si restituisce la stringa
    /// vuota invece di ricostruirla, perché una frase ricostruita oggi
    /// spiegherebbe la formula di oggi su un'analisi di ieri.
    #[must_use]
    pub fn reason(&self) -> &str {
        self.alert
            .as_ref()
            .map_or("", |alert| alert.reason.as_str())
    }

    /// Termini riscontrati, senza ripetizioni e nell'ordine di comparsa.
    #[must_use]
    pub fn matched_terms(&self) -> Vec<&str> {
        let mut terms: Vec<&str> = Vec::new();
        for entry in &self.matches {
            let term = entry.matched_text.as_str();
            if !terms.contains(&term) {
                terms.push(term);
            }
        }
        terms
    }

    /// Se la riga soddisfa la ricerca testuale indicata.
    ///
    /// Cerca nel corpo, nel nome della fonte e nei termini riscontrati: sono i
    /// tre modi in cui un operatore ricorda un contenuto che ha già visto.
    fn matches_query(&self, needle: &str) -> bool {
        let needle = needle.trim().to_lowercase();
        if needle.is_empty() {
            return true;
        }

        self.content.body.as_str().to_lowercase().contains(&needle)
            || self.source_name.as_str().to_lowercase().contains(&needle)
            || self
                .matched_terms()
                .iter()
                .any(|term| term.to_lowercase().contains(&needle))
    }
}

/// Filtro applicato allo storico.
///
/// Il filtro sta nel servizio e non nell'interfaccia: è coperto da test, e due
/// ricerche scritte in due posti divergono il giorno in cui una delle due
/// cambia.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryFilter {
    /// Testo cercato nel corpo, nella fonte o nei termini.
    pub query: String,
    /// Livello minimo mostrato; `0` non esclude nulla.
    pub minimum_level: u8,
    /// Solo i contenuti che attendono una decisione umana.
    pub only_pending: bool,
}

impl HistoryFilter {
    /// Filtro della schermata degli avvisi: i soli contenuti con un alert.
    #[must_use]
    pub fn alerts_only() -> Self {
        Self {
            minimum_level: 1,
            ..Self::default()
        }
    }

    /// Se la riga passa il filtro.
    fn accepts(&self, entry: &HistoryEntry) -> bool {
        if entry.level() < self.minimum_level {
            return false;
        }
        if self.only_pending && !entry.awaits_a_decision() {
            return false;
        }
        entry.matches_query(&self.query)
    }
}

/// Conteggi dello storico, per la testata della schermata.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HistorySummary {
    /// Contenuti acquisiti e analizzati.
    pub total: usize,
    /// Contenuti con un alert, dal livello 1 in su.
    pub alerted: usize,
    /// Contenuti che attendono una decisione umana.
    pub pending: usize,
    /// Quanti per ciascun livello, dall'indice 0 al 4.
    pub by_level: [usize; 5],
}

/// Insieme di contenuti su cui lo storico è calcolato.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryScope {
    /// Tutte le sessioni condotte sulla postazione.
    Everything,
    /// Una sola sessione.
    Session(SessionId),
}

/// Sessione condotta, con quanto ha prodotto.
///
/// Serve a scegliere una sessione senza doverla aprire: l'etichetta da sola non
/// dice se quel monitoraggio abbia osservato tre contenuti o tremila.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    /// Sessione, con etichetta, stato e istanti.
    pub session: Session,
    /// Conteggi dei contenuti acquisiti durante la sessione.
    pub counts: HistorySummary,
}

impl SessionSummary {
    /// Riga di scelta: etichetta, istante e quanto ha prodotto.
    ///
    /// L'istante in ora locale con l'UTC accanto (ADR-0136), e i conteggi
    /// concordati: «1 avvisi» era sullo schermo (SIM3-17).
    #[must_use]
    pub fn label(&self) -> String {
        let contenuti = if self.counts.total == 1 {
            String::from("1 contenuto")
        } else {
            format!("{} contenuti", self.counts.total)
        };
        let avvisi = if self.counts.alerted == 1 {
            String::from("1 avviso")
        } else {
            format!("{} avvisi", self.counts.alerted)
        };
        // L'ISTANTE HA IL SUO NOME (CAPABILITY-AUDIT-02, CA02-02): i menu
        // mostravano la creazione senza dirlo, mentre Monitoraggio, Report e
        // Storico dicono l'avvio, e lo stesso monitoraggio aveva due orari.
        let quando = self.session.started_at.map_or_else(
            || {
                format!(
                    "creato il {}, non avviato",
                    self.session.created_at.to_readable_local()
                )
            },
            |avvio| format!("avviato il {}", avvio.to_readable_local()),
        );
        format!(
            "{} \u{2014} {quando} \u{2014} {contenuti}, {avvisi}",
            self.session.label.as_str(),
        )
    }
}

/// Servizio dello storico.
#[derive(Debug)]
pub struct HistoryService {
    database: Database,
}

impl HistoryService {
    /// Crea il servizio attorno al database indicato.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Database sottostante, per i test e la diagnostica.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Database sottostante in scrittura, per i servizi che lo prendono in
    /// prestito (i riferimenti informatici, PR-14).
    #[must_use]
    pub const fn database_mut(&mut self) -> &mut Database {
        &mut self.database
    }

    /// Le fonti dell'archivio: la ricerca trasversale ne ricava da quale chat
    /// viene un contenuto (CYBER-SEARCH-03, ADR-0163).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn sources(&self) -> ServiceResult<Vec<lisi_core::model::Source>> {
        Ok(self.database.sources()?)
    }

    /// Restituisce il database, consumando il servizio.
    #[must_use]
    pub fn into_database(self) -> Database {
        self.database
    }

    /// Storico completo dell'insieme indicato, dal più recente.
    ///
    /// L'ordine è per istante di acquisizione decrescente, con
    /// l'identificatore a decidere le parità: due contenuti acquisiti nello
    /// stesso millisecondo devono comunque comparire sempre nello stesso
    /// ordine, altrimenti la stessa schermata riletta cambia da sola.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se una delle letture non riesce.
    pub fn entries(&self, scope: HistoryScope) -> ServiceResult<Vec<HistoryEntry>> {
        let sessions = match scope {
            HistoryScope::Session(id) => vec![id],
            HistoryScope::Everything => self
                .database
                .sessions()?
                .into_iter()
                .map(|session| session.id)
                .collect(),
        };

        let mut entries = Vec::new();
        for session_id in sessions {
            // La storia si legge **una volta per sessione**, non per riga:
            // due interrogazioni in tutto invece di due per contenuto. I
            // contenuti a cui non e' successo nulla non compaiono nella mappa,
            // e restano con il riepilogo vuoto che `assemble` ha gia' messo.
            let storia = self.database.session_content_history(session_id)?;
            // Il modo si ricava una volta per monitoraggio, con la copertura di
            // adesso: un orologio illeggibile lascia la copertura vuota, e i
            // contenuti osservati restano «non determinabile», non «dal vivo».
            let adesso = lisi_core::Timestamp::now()
                .unwrap_or_else(|_| lisi_core::Timestamp::from_millis(0));
            let modi = crate::acquisition_mode::for_session(&self.database, session_id, adesso)?;

            for content in self.database.session_contents(session_id)? {
                let mut entry = self.assemble(content)?;
                if let Some(riepilogo) = storia.get(&entry.content.id.get()) {
                    entry.history = *riepilogo;
                }
                if let Some(modo) = modi.get(&entry.content.id.get()) {
                    entry.mode = modo.clone();
                }
                entries.push(entry);
            }
        }

        entries.sort_by(|left, right| {
            right
                .content
                .acquired_at
                .cmp(&left.content.acquired_at)
                .then_with(|| right.content.id.cmp(&left.content.id))
        });
        Ok(entries)
    }

    /// Sessioni condotte, dalla più recente, con quanto ciascuna ha prodotto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se una delle letture non riesce.
    pub fn sessions(&self) -> ServiceResult<Vec<SessionSummary>> {
        let mut sessions = self.database.sessions()?;
        sessions.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right.id.cmp(&left.id))
        });

        let mut summaries = Vec::with_capacity(sessions.len());
        for session in sessions {
            let counts = self.summary(HistoryScope::Session(session.id))?;
            summaries.push(SessionSummary { session, counts });
        }
        Ok(summaries)
    }

    /// Storico filtrato.
    ///
    /// # Errori
    ///
    /// Come [`Self::entries`].
    pub fn matching(
        &self,
        scope: HistoryScope,
        filter: &HistoryFilter,
    ) -> ServiceResult<Vec<HistoryEntry>> {
        let mut entries = self.entries(scope)?;
        entries.retain(|entry| filter.accepts(entry));
        Ok(entries)
    }

    /// Tutto ciò che si sa di un contenuto dopo l'acquisizione, corpi compresi.
    ///
    /// # Perché è separata dall'elenco
    ///
    /// Le versioni portano i corpi, che in un elenco di centinaia di righe
    /// sarebbero centinaia di testi caricati per mostrarne uno. Si chiama
    /// quando l'operatore **apre** un contenuto.
    ///
    /// # La consultazione non tocca la storia
    ///
    /// È una lettura, e nient'altro: nessuna riga viene scritta, e le versioni
    /// sono comunque immutabili per costruzione — due trigger abortiscono
    /// modifica e cancellazione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn content_history(
        &self,
        content_id: lisi_core::ContentId,
    ) -> ServiceResult<ContentHistory> {
        Ok(self.database.content_history(content_id)?)
    }

    /// Conteggi dell'insieme indicato, calcolati sullo storico non filtrato.
    ///
    /// Non filtrato di proposito: la testata dice quanto è stato osservato in
    /// tutto, e un totale che cambia con la ricerca non è più un totale.
    ///
    /// # Errori
    ///
    /// Come [`Self::entries`].
    pub fn summary(&self, scope: HistoryScope) -> ServiceResult<HistorySummary> {
        let entries = self.entries(scope)?;

        let mut summary = HistorySummary {
            total: entries.len(),
            ..HistorySummary::default()
        };
        for entry in &entries {
            if let Some(slot) = summary.by_level.get_mut(usize::from(entry.level())) {
                *slot += 1;
            }
            if entry.raised_alert() {
                summary.alerted += 1;
            }
            if entry.awaits_a_decision() {
                summary.pending += 1;
            }
        }
        Ok(summary)
    }

    /// Mette accanto a un contenuto la fonte, i riscontri, l'alert e l'esame.
    fn assemble(&self, content: Content) -> ServiceResult<HistoryEntry> {
        let source_name = self.source_name(content.source_id)?;
        let matches = self.database.content_matches(content.id)?;
        let alert = self.database.content_alert(content.id)?;
        let last_decision = self.database.latest_review(content.id)?;

        Ok(HistoryEntry {
            content,
            source_name,
            matches,
            alert,
            last_decision,
            history: ContentHistorySummary::default(),
            // Il modo lo scrive `entries`, che lo ricava per l'intero
            // monitoraggio; fino ad allora non è determinato, mai «dal vivo».
            mode: AcquisitionMode::Undetermined,
        })
    }

    /// Nome della fonte, o un segnaposto se la fonte non è più leggibile.
    ///
    /// Una fonte rimossa non deve far sparire dallo storico ciò che era stato
    /// acquisito attraverso di essa: il contenuto è un fatto avvenuto, e
    /// nasconderlo perché manca un nome sarebbe la perdita più grave delle due.
    fn source_name(&self, source_id: SourceId) -> ServiceResult<DisplayName> {
        match self.database.source(source_id) {
            Ok(source) => Ok(source.display_name),
            Err(error) => {
                tracing::warn!(
                    fonte = source_id.get(),
                    errore = %error,
                    "nome della fonte non leggibile per una riga dello storico"
                );
                Ok(DisplayName::try_new("Fonte non più disponibile")?)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::AcquisitionOrigin;
    use lisi_core::model::dictionary::{
        ConfigurationResolver, MatchMode, ResolvedDictionaryConfiguration, TermProvenance,
    };
    use lisi_core::model::{NewSession, NewSource, ReviewState, SessionDuration, SourceKind};
    use lisi_core::text::{
        Actor, ContentBody, DisplayName, LanguageTag, RemoteMessageId, SourceIdentifier,
        TermCategory, TermText,
    };
    use lisi_core::{SessionId, SourceId, Timestamp};
    use lisi_storage::Database;

    /// **Il menu dice l'avvio, con la parola** (CA02-02): la creazione si dice
    /// solo per un monitoraggio mai avviato, e anche lei con la sua parola.
    #[test]
    fn il_menu_dei_monitoraggi_dice_l_avvio() {
        use lisi_core::model::{Session, SessionState};

        let (Ok(nome), Ok(chi)) = (
            DisplayName::try_new("Prova"),
            Actor::try_new("operatore.prova"),
        ) else {
            panic!("valori validi");
        };
        let creato = Timestamp::from_millis(1_700_000_000_000);
        let avviato = Timestamp::from_millis(1_700_001_800_000);
        let mut riga = super::SessionSummary {
            session: Session {
                id: SessionId::new(1),
                label: nome,
                started_by: chi,
                duration: SessionDuration::Manual,
                state: SessionState::Running,
                created_at: creato,
                started_at: Some(avviato),
                ended_at: None,
            },
            counts: super::HistorySummary::default(),
        };
        let frase = riga.label();
        assert!(
            frase.contains(&format!("avviato il {}", avviato.to_readable_local())),
            "{frase}"
        );
        assert!(!frase.contains(&creato.to_readable_local()), "{frase}");

        riga.session.started_at = None;
        let frase = riga.label();
        assert!(frase.contains("creato il"), "{frase}");
        assert!(frase.contains("non avviato"), "{frase}");
    }

    use super::{HistoryFilter, HistoryScope, HistoryService};
    use crate::analysis::{AnalysisService, NewContentDraft};
    use crate::review::ReviewService;
    use crate::sources::open_in_memory_database;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn later(seconds: i64) -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000 + seconds * 1_000)
    }

    fn operator() -> Actor {
        let Ok(value) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        value
    }

    /// Configurazione con un termine di livello 3 e uno negativo.
    fn configuration() -> ResolvedDictionaryConfiguration {
        let mut resolver = ConfigurationResolver::new();
        for (text, level) in [("molotov", 3_i8), ("film", -2_i8)] {
            let (Ok(text), Ok(category), Ok(language)) = (
                TermText::try_new(text),
                TermCategory::try_new("prova"),
                LanguageTag::try_new("it"),
            ) else {
                panic!("i valori del termine devono essere validi");
            };
            let Ok(()) = resolver.add(
                text,
                category,
                language,
                MatchMode::NormalizedWord,
                level,
                TermProvenance::ad_hoc(),
            ) else {
                panic!("il termine doveva essere accettato");
            };
        }
        resolver.finish()
    }

    /// Archivio con una sessione e i contenuti indicati, già analizzati.
    fn archive_with(bodies: &[&str]) -> (Database, SessionId, SourceId) {
        let Ok(mut database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };

        let (Ok(identifier), Ok(title), Ok(label)) = (
            SourceIdentifier::try_new("canale_uno"),
            DisplayName::try_new("Canale di prova"),
            DisplayName::try_new("Sessione di prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(source_id) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier,
                display_name: title,
                authorized_by: operator(),
                active: true,
            },
            now(),
        ) else {
            panic!("la fonte deve potersi registrare");
        };
        let Ok(session_id) = database.insert_session(
            &NewSession {
                label,
                started_by: operator(),
                duration: SessionDuration::Preset { seconds: 3_600 },
                source_ids: vec![source_id],
            },
            now(),
        ) else {
            panic!("la sessione deve potersi creare");
        };

        let configuration = configuration();
        let mut analysis = AnalysisService::new(database);
        for (index, body) in bodies.iter().enumerate() {
            let Ok(index) = i64::try_from(index) else {
                panic!("l'indice di prova deve stare in un intero");
            };
            let (Ok(remote), Ok(body)) = (
                RemoteMessageId::try_new(&format!("m{index}")),
                ContentBody::try_new(body),
            ) else {
                panic!("i valori del contenuto devono essere validi");
            };
            let Ok(_) = analysis.analyse_and_record(
                &NewContentDraft {
                    session_id,
                    source_id,
                    remote_message_id: remote,
                    author: None,
                    author_identifier: None,
                    author_username: None,
                    body,
                    url: None,
                    published_at: now(),
                    acquired_at: later(index),
                    origin: AcquisitionOrigin::Observed,
                },
                &configuration,
                &operator(),
                later(index),
            ) else {
                panic!("l'analisi deve riuscire");
            };
        }

        (analysis.into_database(), session_id, source_id)
    }

    #[test]
    fn the_history_holds_everything_acquired_not_only_what_alarmed() {
        // E' il punto del requisito: mostrare solo cio' che ha fatto scattare
        // qualcosa direbbe che il monitoraggio ha osservato solo quello.
        let (database, session, _) = archive_with(&["una molotov", "buongiorno a tutti"]);
        let service = HistoryService::new(database);

        let Ok(entries) = service.entries(HistoryScope::Session(session)) else {
            panic!("lo storico deve potersi leggere");
        };
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries.iter().filter(|entry| entry.raised_alert()).count(),
            1
        );
        assert!(
            entries.iter().any(|entry| entry.level() == 0),
            "il contenuto non rilevante resta nello storico"
        );
    }

    #[test]
    fn the_most_recent_comes_first() {
        let (database, session, _) = archive_with(&["primo", "una molotov"]);
        let service = HistoryService::new(database);

        let Ok(entries) = service.entries(HistoryScope::Session(session)) else {
            panic!("lo storico deve potersi leggere");
        };
        assert!(entries[0].content.body.as_str().contains("molotov"));
    }

    #[test]
    fn a_row_carries_the_reason_written_at_the_time_of_the_analysis() {
        let (database, session, _) = archive_with(&["una molotov"]);
        let service = HistoryService::new(database);

        let Ok(entries) = service.entries(HistoryScope::Session(session)) else {
            panic!("lo storico deve potersi leggere");
        };
        assert_eq!(entries[0].level(), 3);
        assert!(!entries[0].reason().is_empty());
        assert_eq!(entries[0].matched_terms(), vec!["molotov"]);
        assert_eq!(entries[0].source_name.as_str(), "Canale di prova");
    }

    #[test]
    fn a_content_of_level_zero_has_no_reason_and_this_is_declared() {
        // Il limite e' dichiarato: la frase vive nell'alert, che dal livello 0
        // non esiste. Ricostruirla oggi racconterebbe la formula di oggi.
        let (database, session, _) = archive_with(&["buongiorno a tutti"]);
        let service = HistoryService::new(database);

        let Ok(entries) = service.entries(HistoryScope::Session(session)) else {
            panic!("lo storico deve potersi leggere");
        };
        assert_eq!(entries[0].level(), 0);
        assert!(entries[0].reason().is_empty());
        assert!(!entries[0].raised_alert());
    }

    #[test]
    fn the_alert_screen_is_the_same_history_with_a_threshold() {
        // Due elenchi separati sarebbero due verita', e la seconda invecchia.
        let (database, session, _) = archive_with(&["una molotov", "buongiorno"]);
        let service = HistoryService::new(database);

        let Ok(alerts) = service.matching(
            HistoryScope::Session(session),
            &HistoryFilter::alerts_only(),
        ) else {
            panic!("gli avvisi devono potersi leggere");
        };
        assert_eq!(alerts.len(), 1);
        assert!(alerts.iter().all(super::HistoryEntry::raised_alert));
    }

    #[test]
    fn the_search_looks_in_the_body_in_the_source_and_in_the_terms() {
        let (database, session, _) = archive_with(&["una molotov", "buongiorno a tutti"]);
        let service = HistoryService::new(database);

        let find = |query: &str| {
            let filter = HistoryFilter {
                query: String::from(query),
                ..HistoryFilter::default()
            };
            match service.matching(HistoryScope::Session(session), &filter) {
                Ok(entries) => entries.len(),
                Err(_) => panic!("la ricerca deve riuscire"),
            }
        };

        assert_eq!(find("buongiorno"), 1, "cerca nel corpo");
        assert_eq!(
            find("MOLOTOV"),
            1,
            "cerca nei termini, senza distinguere il caso"
        );
        assert_eq!(find("Canale di prova"), 2, "cerca nel nome della fonte");
        assert_eq!(find("   "), 2, "una ricerca vuota non esclude nulla");
        assert_eq!(find("inesistente"), 0);
    }

    #[test]
    fn a_decided_content_leaves_the_pending_filter() {
        let (database, session, _) = archive_with(&["una molotov"]);
        let service = HistoryService::new(database);

        let Ok(entries) = service.entries(HistoryScope::Session(session)) else {
            panic!("lo storico deve potersi leggere");
        };
        assert!(entries[0].awaits_a_decision());
        assert_eq!(entries[0].review_state(), ReviewState::New);

        let content = entries[0].content.id;
        let review = ReviewService::new(service.into_database());
        let Ok(()) = review.record(content, ReviewState::Relevant, &operator(), None, later(60))
        else {
            panic!("la decisione deve riuscire");
        };

        let service = HistoryService::new(review.into_database());
        let filter = HistoryFilter {
            only_pending: true,
            ..HistoryFilter::default()
        };
        let Ok(pending) = service.matching(HistoryScope::Session(session), &filter) else {
            panic!("la coda deve potersi leggere");
        };
        assert!(pending.is_empty());

        let Ok(all) = service.entries(HistoryScope::Session(session)) else {
            panic!("lo storico deve potersi leggere");
        };
        assert_eq!(all[0].review_state(), ReviewState::Relevant);
    }

    #[test]
    fn the_summary_counts_by_level_and_does_not_follow_the_search() {
        // Un totale che cambia con la ricerca non e' piu' un totale.
        let (database, session, _) = archive_with(&["una molotov", "buongiorno", "un film"]);
        let service = HistoryService::new(database);

        let Ok(summary) = service.summary(HistoryScope::Session(session)) else {
            panic!("i conteggi devono potersi leggere");
        };
        assert_eq!(summary.total, 3);
        assert_eq!(summary.alerted, 1);
        assert_eq!(summary.pending, 3);
        assert_eq!(summary.by_level[0], 2);
        assert_eq!(summary.by_level[3], 1);
    }

    #[test]
    fn a_session_can_be_chosen_knowing_what_it_produced() {
        // L'etichetta da sola non dice se quel monitoraggio abbia osservato
        // tre contenuti o tremila.
        let (database, _, _) = archive_with(&["una molotov", "buongiorno"]);
        let service = HistoryService::new(database);

        let Ok(sessions) = service.sessions() else {
            panic!("le sessioni devono potersi leggere");
        };
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].counts.total, 2);
        assert_eq!(sessions[0].counts.alerted, 1);

        let label = sessions[0].label();
        assert!(label.contains("Sessione di prova"));
        assert!(label.contains("2 contenuti"));
        // Uno al singolare (SIM3-17): la prova chiedeva «1 avvisi», cioè
        // l'errore di concordanza che OPERATOR-SIM-03 ha letto sullo schermo.
        assert!(label.contains("1 avviso"));
        assert!(!label.contains("1 avvisi"));
        assert!(label.contains("UTC"));
    }

    #[test]
    fn everything_covers_all_the_sessions() {
        let (database, session, _) = archive_with(&["una molotov"]);
        let service = HistoryService::new(database);

        let Ok(all) = service.entries(HistoryScope::Everything) else {
            panic!("lo storico complessivo deve potersi leggere");
        };
        let Ok(one) = service.entries(HistoryScope::Session(session)) else {
            panic!("lo storico della sessione deve potersi leggere");
        };
        assert_eq!(all, one, "con una sola sessione i due insiemi coincidono");
    }
}

//! «Perché sto vedendo questo?», composto da ciò che l'archivio conserva.
//!
//! # Che cosa mette insieme, e da dove
//!
//! Nulla qui dentro è nuovo. Ogni pezzo esisteva, in un archivio diverso, e
//! nessuna schermata li aveva mai messi in fila:
//!
//! | Anello | Da dove viene |
//! |---|---|
//! | il contenuto e la sua origine | `contents`, `sources` |
//! | che cosa gli è successo dopo | `content_versions`, `content_deletions` (CTX-01) |
//! | quali termini sono stati trovati, e dove | `matches`, una riga per occorrenza |
//! | da quale dizionario e versione venivano | `session_resolved_terms`, la fotografia della sessione |
//! | come il livello è stato calcolato | ricalcolo dell'aritmetica sui due precedenti |
//! | l'avviso, e quando | `alerts` |
//! | le decisioni delle persone | `reviews`, che è uno storico e non uno stato |
//!
//! # Il costo
//!
//! Sei letture per contenuto, tutte per chiave primaria o per indice, e
//! **soltanto quando l'operatore apre il pannello**. Nessuna entra
//! nell'elenco: lo Storico continua a costare quello che costava.
//!
//! Il pannello non si apre da solo e non si apre per tutte le righe. È la
//! stessa scelta di CTX-01 (ADR-0051 Decisione 4): il costo della lettura sta
//! dove la lettura serve.
//!
//! # Consultare non scrive
//!
//! Questo servizio non ha metodi di scrittura, non registra nulla nell'audit e
//! non tocca la revisione. Vale la ragione di ADR-0051 Decisione 5: l'audit
//! documenta le **azioni**, e leggere perché un risultato esiste non è un'azione
//! di cui qualcuno risponda.

use lisi_core::model::content_history::ContentHistorySummary;
use lisi_core::model::provenance::{ScoringProvenance, explain_scoring};
use lisi_core::model::{Alert, Content, ContentMatch, Review};
use lisi_core::text::DisplayName;
use lisi_core::{ContentId, SourceId, Timestamp};
use lisi_storage::Database;

use crate::error::ServiceResult;

/// Da dove viene il contenuto, in ciò che l'operatore riconosce.
///
/// Gli identificativi tecnici ci sono — un fascicolo può doverli citare — ma
/// non sono ciò che si legge per primo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentOrigin {
    /// Nome della fonte come l'operatore la conosce.
    pub source_name: DisplayName,
    /// Identificativo del messaggio presso la piattaforma.
    pub remote_message_id: String,
    /// Autore dichiarato dalla fonte, quando c'è.
    pub author: Option<String>,
    /// Lo username pubblico dell'autore, quando la fonte lo dichiara.
    pub author_username: Option<String>,
    /// L'identificativo Telegram dell'autore, quando la fonte lo dichiara.
    ///
    /// Lo Storico lo mostra accanto al messaggio: la Provenienza non può dire
    /// «autore non dichiarato» per lo stesso contenuto (E2E01-07).
    pub author_identifier: Option<String>,
    /// Collegamento al messaggio, quando la piattaforma ne espone uno.
    pub url: Option<String>,
    /// Istante dichiarato dalla fonte.
    pub published_at: Timestamp,
    /// Istante in cui NEXUM/97 lo ha acquisito.
    pub acquired_at: Timestamp,
    /// Il modo di acquisizione dichiarato (PR-07, ADR-0123), con la stessa
    /// frase dell'atto e della schermata.
    pub mode: String,
}

impl ContentOrigin {
    /// Frase che dice da dove viene, senza numeri interni.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let autore = author_in_words(
            self.author.as_deref(),
            self.author_username.as_deref(),
            self.author_identifier.as_deref(),
        );

        format!(
            "Acquisito il {} dalla fonte \u{ab}{}\u{bb}, pubblicato il {} \u{2014} {autore}. {}",
            self.acquired_at.to_readable_local(),
            self.source_name.as_str(),
            self.published_at.to_readable_local(),
            self.mode
        )
    }
}

/// L'autore come la fonte l'ha dichiarato, con ciò che c'è.
///
/// Il nome se c'è; altrimenti lo username e l'identificativo che lo Storico
/// mostra accanto al messaggio, dicendo che il nome manca. «Autore non
/// dichiarato» soltanto quando la fonte non ha dichiarato nulla: un canale, che
/// non ha un autore individuale (E2E01-07). Nulla è dedotto: si riporta ciò che
/// Telegram ha mostrato all'account.
fn author_in_words(
    nome: Option<&str>,
    username: Option<&str>,
    identificativo: Option<&str>,
) -> String {
    if let Some(nome) = nome {
        return nome.to_owned();
    }
    let mut parti = Vec::new();
    if let Some(username) = username {
        parti.push(format!("@{username}"));
    }
    if let Some(identificativo) = identificativo {
        parti.push(format!("identificativo Telegram {identificativo}"));
    }
    if parti.is_empty() {
        String::from("autore non dichiarato")
    } else {
        format!("autore senza nome dichiarato, {}", parti.join(", "))
    }
}

/// L'avviso, con ciò che serve a sapere su che cosa fu emesso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertProvenance {
    /// Livello con cui l'avviso fu emesso.
    pub level: u8,
    /// Frase conservata **allora**, non ricalcolata.
    pub reason: String,
    /// Istante dell'emissione.
    pub raised_at: Timestamp,
    /// Se il messaggio è stato modificato o rimosso **dopo** l'emissione.
    ///
    /// # Perché sta qui e non solo sul contenuto
    ///
    /// Perché è la cosa che cambia il modo di leggere l'avviso. Un avviso
    /// emesso su un testo poi riscritto resta un fatto avvenuto, e la sua
    /// motivazione riguarda il testo di allora: PROV-01 non la riscrive, la
    /// data.
    pub changed_after: Option<String>,
}

impl AlertProvenance {
    /// Frase che dice quando fu emesso e su che cosa.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let mut frase = format!(
            "Avviso di livello {} emesso il {}.",
            self.level,
            self.raised_at.to_readable_local()
        );

        if let Some(dopo) = &self.changed_after {
            frase.push_str(&format!(
                " Il messaggio risulta {dopo} DOPO l'emissione: la motivazione qui sopra \
                 riguarda il testo con cui l'avviso fu emesso, e non è stata rifatta."
            ));
        }

        frase
    }
}

/// Una decisione umana, con lo stato automatico che la precedeva.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionStep {
    /// Esito scelto dalla persona.
    pub state: String,
    /// Chi ha deciso.
    pub reviewer: String,
    /// Annotazione, quando ne ha lasciata una.
    pub note: Option<String>,
    /// Quando.
    pub decided_at: Timestamp,
    /// Livello che il motore aveva proposto, invariato da questa decisione.
    pub automatic_level: u8,
}

impl DecisionStep {
    /// Frase che tiene separata la macchina dalla persona.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        format!(
            "Il {} {} ha deciso \u{ab}{}\u{bb}. Il livello proposto dal motore resta {}: una \
             decisione dell'operatore non lo cambia.",
            self.decided_at.to_readable_local(),
            self.reviewer,
            self.state,
            self.automatic_level
        )
    }
}

/// Il percorso completo, dall'osservazione alla decisione.
///
/// Le tre nature restano distinte e in quest'ordine: **fatto osservato**
/// (origine e versione), **elaborazione automatica** (termini, livello,
/// avviso), **decisione umana** (le revisioni). Mescolarle produrrebbe
/// esattamente la confusione che questo prodotto rifiuta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultProvenance {
    /// Contenuto a cui il percorso appartiene.
    pub content_id: ContentId,
    /// Fatto osservato: da dove viene.
    pub origin: ContentOrigin,
    /// Fatto osservato: che cosa gli è successo dopo l'acquisizione.
    pub after_acquisition: ContentHistorySummary,
    /// Elaborazione automatica: livello registrato, che resta quello valido.
    pub stored_level: u8,
    /// Elaborazione automatica: termini trovati e spiegazione del livello.
    pub scoring: ScoringProvenance,
    /// Elaborazione automatica: l'avviso, quando c'è stato.
    pub alert: Option<AlertProvenance>,
    /// Decisioni umane, dalla più antica alla più recente.
    pub decisions: Vec<DecisionStep>,
    /// Versione del motore che ha prodotto il livello registrato.
    ///
    /// `None` per i contenuti analizzati prima che il motore avesse un numero
    /// (ENGINE-01): quale formula li abbia prodotti **non risulta**.
    pub engine_version: Option<u32>,
}

impl ResultProvenance {
    /// Se la spiegazione del livello può essere mostrata come tale.
    #[must_use]
    pub const fn scoring_is_trustworthy(&self) -> bool {
        self.scoring.explanation.is_trustworthy()
    }

    /// Se il messaggio è cambiato dopo essere stato analizzato.
    #[must_use]
    pub fn changed_after_analysis(&self) -> bool {
        self.after_acquisition.short_label().is_some()
    }

    /// Chi ha prodotto il livello: il motore, con la propria versione.
    ///
    /// # Perché sta accanto al dizionario e non al posto suo
    ///
    /// Perché un livello è il prodotto di **due** cose: quali termini si
    /// cercavano — il dizionario, con la sua versione — e come i riscontri
    /// diventano un numero — il motore, con la sua. Fino a ENGINE-01 la seconda
    /// metà non era scritta da nessuna parte, e chi rileggeva un atto poteva
    /// sapere quali termini erano stati usati ma non quale formula li avesse
    /// pesati.
    ///
    /// # Perché «non risulta» non è «v1»
    ///
    /// Perché i contenuti di prima furono analizzati da un motore di cui non si
    /// sa quale fosse, e scrivere la versione corrente direbbe che qualcuno lo
    /// sa.
    #[must_use]
    pub fn engine_sentence(&self) -> String {
        self.engine_version.map_or_else(
            || String::from(lisi_core::analysis::unknown_engine_label()),
            |versione| format!("Livello prodotto dal motore di analisi v{versione}."),
        )
    }

    /// Frase che avverte quando l'analisi riguarda un testo non più attuale.
    ///
    /// Restituisce `None` quando non c'è nulla da avvertire: una riga che dice
    /// «tutto regolare» accanto a ogni risultato insegnerebbe a saltarla.
    #[must_use]
    pub fn version_warning(&self) -> Option<String> {
        let dopo = self.after_acquisition.short_label()?;
        Some(format!(
            "Il messaggio risulta {dopo}. Tutto ciò che segue \u{2014} termini, livello e \
             avviso \u{2014} riguarda la versione acquisita: l'analisi non viene rifatta sulle \
             versioni successive."
        ))
    }
}

/// Ricostruisce il percorso di un risultato.
#[derive(Debug)]
pub struct ProvenanceService {
    database: Database,
}

impl ProvenanceService {
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

    /// Database sottostante in scrittura, per la preparazione dei test.
    #[must_use]
    pub const fn database_mut(&mut self) -> &mut Database {
        &mut self.database
    }

    /// Restituisce il database, per riusarlo altrove.
    #[must_use]
    pub fn into_database(self) -> Database {
        self.database
    }

    /// Perché questo contenuto è come l'operatore lo vede.
    ///
    /// **Non scrive nulla.** Nessuna riga di audit, nessuna revisione toccata,
    /// nessun contatore: aprire una spiegazione è una lettura.
    ///
    /// # La fotografia dei termini, e perché un errore non fa fallire tutto
    ///
    /// La configurazione della sessione viene letta verificandone l'impronta.
    /// Se manca, o se la verifica fallisce, il resto del percorso **resta
    /// leggibile** e la sola spiegazione del livello dichiara la lacuna: un
    /// contenuto storico deve restare consultabile anche quando non tutto di
    /// lui è ricostruibile.
    ///
    /// # Errori
    ///
    /// Restituisce l'errore della persistenza se il contenuto non esiste o se
    /// una riga necessaria è illeggibile.
    pub fn explain(&self, content_id: ContentId) -> ServiceResult<ResultProvenance> {
        let content = self.database.content(content_id)?;
        let source_name = self.source_name(content.source_id)?;

        let matches = self.database.content_matches(content_id)?;
        let alert = self.database.content_alert(content_id)?;
        let reviews = self.database.content_reviews(content_id)?;
        let after_acquisition = self.database.content_history(content_id)?.summary();

        // La configurazione con cui la sessione fu condotta, non i dizionari di
        // oggi. Un errore di lettura non e' fatale: diventa una lacuna
        // dichiarata dentro la spiegazione.
        let configuration = self
            .database
            .session_resolved_configuration(content.session_id)
            .unwrap_or(None);

        let scoring = explain_scoring(&matches, configuration.as_ref(), content.analysis_level);

        // Il modo di acquisizione, ricavato per il suo monitoraggio con la
        // copertura di adesso (PR-07).
        //
        // L'istante viene dall'ancora dell'avvio quando l'orologio non si
        // legge più (FINAL-FPR-ALL-16, FPR-10): prima era l'epoca, e una
        // copertura confrontata con il 1970 lasciava il modo «non
        // determinabile» per una ragione che non c'entrava nulla con la
        // copertura.
        let adesso = lisi_core::time::anchored_now();
        let modo =
            crate::acquisition_mode::for_session(&self.database, content.session_id, adesso)?
                .remove(&content_id.get())
                .unwrap_or(lisi_core::model::AcquisitionMode::Undetermined);

        Ok(ResultProvenance {
            content_id,
            // La versione del motore viene dal CONTENUTO, non da questo
            // binario: dice chi ha prodotto quel livello allora, non chi lo
            // produrrebbe adesso.
            engine_version: content.engine_version,
            origin: origin_of(
                &content,
                source_name,
                crate::acquisition_mode::declared(&modo),
            ),
            stored_level: content.analysis_level.get(),
            alert: alert.map(|alert| alert_provenance(&alert, &after_acquisition)),
            decisions: decisions_of(&reviews, content.analysis_level.get()),
            after_acquisition,
            scoring,
        })
    }

    /// Nome della fonte, o un segnaposto se la fonte non è più leggibile.
    ///
    /// Una fonte rimossa non deve far sparire la spiegazione di ciò che era
    /// stato osservato quando c'era: è la stessa scelta dello Storico.
    fn source_name(&self, source_id: SourceId) -> ServiceResult<DisplayName> {
        match self.database.source(source_id) {
            Ok(source) => Ok(source.display_name),
            Err(error) => {
                tracing::warn!(
                    fonte = source_id.get(),
                    errore = %error,
                    "nome della fonte non leggibile per una spiegazione"
                );
                Ok(DisplayName::try_new("Fonte non più disponibile")?)
            }
        }
    }

    /// Riesegue l'analisi di un contenuto con il motore di **adesso**.
    ///
    /// # Perché sta qui e non nel replay
    ///
    /// Perché `crate::replay` **non conosce l'archivio**, e non deve
    /// conoscerlo: è la garanzia che non possa riscrivere il livello storico.
    /// Qualcuno deve pur leggere il corpo e la fotografia della sessione, e
    /// quel qualcuno è questo servizio, che legge già entrambi per rispondere
    /// a «perché sto vedendo questo».
    ///
    /// # Perché restituisce `None` senza la fotografia della sessione
    ///
    /// Perché il replay ha senso **solo** con la configurazione di allora.
    /// Rieseguire con i dizionari di oggi misurerebbe insieme il cambio di
    /// motore e il cambio di dizionari, e il numero che ne uscirebbe non
    /// direbbe niente di nessuno dei due. Meglio non dire nulla che dire una
    /// cosa che sembra una risposta.
    ///
    /// # Non scrive nulla
    ///
    /// Come tutto questo servizio: rieseguire un'analisi non è un'azione di cui
    /// qualcuno risponda, e il livello registrato resta quello che era.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn replay_of(
        &self,
        content_id: ContentId,
    ) -> ServiceResult<Option<crate::replay::ReplayFinding>> {
        let content = self.database.content(content_id)?;

        let Some(configuration) = self
            .database
            .session_resolved_configuration(content.session_id)?
        else {
            return Ok(None);
        };

        let esito = crate::replay::replay(
            &[crate::replay::ReplayInput {
                content_id,
                body: content.body.as_str().to_owned(),
                stored_level: content.analysis_level,
                recorded_engine: content.engine_version,
            }],
            &configuration,
        );

        Ok(esito.findings.into_iter().next())
    }
    /// I soli riscontri, per chi deve mostrarli senza il resto del percorso.
    ///
    /// # Errori
    ///
    /// Come [`Self::explain`].
    pub fn content_matches(&self, content_id: ContentId) -> ServiceResult<Vec<ContentMatch>> {
        Ok(self.database.content_matches(content_id)?)
    }

    /// I contenuti della stessa sessione che somigliano a questo (SIM-01).
    ///
    /// # Perché la lettura sta qui e il confronto no
    ///
    /// Perché [`crate::similarity`] **non conosce l'archivio**, come il Rule
    /// Lab, il replay e le analisi temporali. Qualcuno deve pur leggere i
    /// corpi, gli istanti e gli indicatori, e quel qualcuno è il servizio che
    /// risponde a «perché sto vedendo questo»: la somiglianza è una delle cose
    /// che il congelamento gli chiede di spiegare.
    ///
    /// # Perché nella sessione e non nell'archivio intero
    ///
    /// Perché un quasi-duplicato che conta è quello che è passato **nello
    /// stesso monitoraggio**: lo stesso messaggio inoltrato in dieci canali
    /// osservati insieme. Confrontare con l'archivio intero costerebbe con la
    /// storia dell'ufficio invece che con ciò che è successo, e la milestone
    /// che lo faccia dovrà dire quanto costa prima di cominciare.
    ///
    /// # Non scrive nulla
    ///
    /// Chiedersi a che cosa un contenuto somigli non è un atto di cui qualcuno
    /// risponda.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn resembling_to(
        &self,
        content_id: ContentId,
        limit: u32,
    ) -> ServiceResult<crate::similarity::SimilarityReport> {
        let content = self.database.content(content_id)?;
        let righe = self
            .database
            .session_comparable_contents(content.session_id, limit)?;

        if righe.len() > limit as usize {
            return Ok(crate::similarity::SimilarityReport {
                outcome: crate::similarity::SimilarityOutcome::NotComparable(
                    crate::similarity::SimilarityGap::TooManyContents {
                        limit: limit as usize,
                    },
                ),
            });
        }

        let indicatori = self.database.session_indicators(content.session_id)?;

        let contenuti: Vec<crate::similarity::ComparableContent> = righe
            .into_iter()
            .map(|riga| crate::similarity::ComparableContent {
                indicators: indicatori
                    .get(&riga.content_id.get())
                    .cloned()
                    .unwrap_or_default(),
                content_id: riga.content_id,
                body: riga.body,
                published_at: riga.published_at,
            })
            .collect();

        Ok(crate::similarity::compare_against(
            content_id,
            &contenuti,
            limit as usize,
        ))
    }
}

/// Origine leggibile di un contenuto.
fn origin_of(content: &Content, source_name: DisplayName, mode: String) -> ContentOrigin {
    ContentOrigin {
        mode,
        source_name,
        remote_message_id: content.remote_message_id.as_str().to_owned(),
        author: content
            .author
            .as_ref()
            .map(|author| author.as_str().to_owned()),
        author_username: content.author_username.clone(),
        author_identifier: content.author_identifier.clone(),
        url: content.url.as_ref().map(|url| url.as_str().to_owned()),
        published_at: content.published_at,
        acquired_at: content.acquired_at,
    }
}

/// Avviso con l'avvertenza sulla versione, quando serve.
fn alert_provenance(alert: &Alert, after: &ContentHistorySummary) -> AlertProvenance {
    AlertProvenance {
        level: alert.level.get(),
        reason: alert.reason.as_str().to_owned(),
        raised_at: alert.raised_at,
        changed_after: after.short_label(),
    }
}

/// Decisioni umane in ordine cronologico, con il livello automatico accanto.
fn decisions_of(reviews: &[Review], automatic_level: u8) -> Vec<DecisionStep> {
    let mut decisions: Vec<DecisionStep> = reviews
        .iter()
        .map(|review| DecisionStep {
            state: review.state.label().to_owned(),
            reviewer: review.reviewer.as_str().to_owned(),
            note: review.note.as_ref().map(|note| note.as_str().to_owned()),
            decided_at: review.decided_at,
            automatic_level,
        })
        .collect();

    // Dalla piu' antica alla piu' recente: il percorso si legge in avanti, e
    // l'ultima riga e' la decisione che vale oggi.
    decisions.sort_by_key(|decision| decision.decided_at);
    decisions
}

#[cfg(test)]
mod tests {
    use lisi_core::model::content_history::ContentHistorySummary;
    use lisi_core::model::dictionary::{
        ConfigurationResolver, MatchMode, ResolvedDictionaryConfiguration, TermProvenance,
    };
    use lisi_core::model::provenance::{ExplanationGap, ScoringExplanation};
    use lisi_core::model::{
        AcquisitionOrigin, Alert, AlertLevel, AnalysisLevel, NewReview, NewSession, NewSource,
        ReviewState, SessionDuration, SourceKind,
    };
    use lisi_core::text::{
        Actor, AlertReason, ContentBody, DisplayName, LanguageTag, RemoteMessageId,
        SourceIdentifier, TermCategory, TermText,
    };
    use lisi_core::{AlertId, ContentId, SessionId, SourceId, Timestamp};
    use lisi_storage::Database;

    use super::ProvenanceService;
    use crate::analysis::{AnalysisService, NewContentDraft};
    use crate::sources::open_in_memory_database;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn operator() -> Actor {
        let Ok(value) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        value
    }

    /// Configurazione risolta con i termini indicati.
    fn configuration(entries: &[(&str, &str, i8)]) -> ResolvedDictionaryConfiguration {
        let Ok(language) = LanguageTag::try_new("it") else {
            panic!("la lingua di prova deve essere valida");
        };

        let mut resolver = ConfigurationResolver::new();
        for (text, category, level) in entries {
            let (Ok(text), Ok(category)) =
                (TermText::try_new(text), TermCategory::try_new(category))
            else {
                panic!("il termine di prova deve essere valido");
            };
            let Ok(()) = resolver.add(
                text,
                category,
                language.clone(),
                MatchMode::NormalizedWord,
                *level,
                TermProvenance::ad_hoc(),
            ) else {
                panic!("il termine doveva essere accettato");
            };
        }
        resolver.finish()
    }

    /// Database con una sessione e una fonte pronte.
    fn database_with_session() -> (Database, SessionId, SourceId) {
        let Ok(database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        let mut database: Database = database;

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

        (database, session_id, source_id)
    }

    /// Contenuto di prova con il testo indicato.
    fn draft(session_id: SessionId, source_id: SourceId, body: &str) -> NewContentDraft {
        let (Ok(remote), Ok(body)) = (RemoteMessageId::try_new("m-1"), ContentBody::try_new(body))
        else {
            panic!("i valori di prova devono essere validi");
        };

        NewContentDraft {
            session_id,
            source_id,
            remote_message_id: remote,
            author: None,
            author_identifier: None,
            author_username: None,
            body,
            url: None,
            published_at: now(),
            acquired_at: now(),
            origin: AcquisitionOrigin::Observed,
        }
    }

    /// Analizza un contenuto e restituisce il servizio di provenienza.
    fn analysed(
        body: &str,
        terms: &[(&str, &str, i8)],
        salva_fotografia: bool,
    ) -> (ProvenanceService, ContentId) {
        let (database, session_id, source_id) = database_with_session();
        let configuration = configuration(terms);

        let mut service = AnalysisService::new(database);
        if salva_fotografia {
            let Ok(()) = service
                .database_mut()
                .save_resolved_configuration(session_id, &configuration)
            else {
                panic!("la fotografia deve potersi salvare");
            };
        }

        let Ok(record) = service.analyse_and_record(
            &draft(session_id, source_id, body),
            &configuration,
            &operator(),
            now(),
        ) else {
            panic!("l'analisi deve riuscire");
        };
        let Some(content_id) = record.content_id else {
            panic!("il contenuto doveva essere registrato");
        };

        (ProvenanceService::new(service.into_database()), content_id)
    }

    #[test]
    fn the_whole_chain_is_readable_from_what_the_archive_keeps() {
        let (service, content_id) = analysed(
            "hanno appiccato un incendio durante il corteo",
            &[("incendio", "violenza", 3), ("corteo", "ordine", 1)],
            true,
        );

        let Ok(provenance) = service.explain(content_id) else {
            panic!("la spiegazione deve potersi comporre");
        };

        // Fatto osservato.
        assert_eq!(provenance.origin.source_name.as_str(), "Canale di prova");
        assert_eq!(provenance.origin.remote_message_id, "m-1");
        // Elaborazione automatica: i due termini, con la loro provenienza.
        assert_eq!(provenance.scoring.contributions.len(), 2);
        assert!(!provenance.scoring.has_incomplete_origins());
        // E la spiegazione riproduce il livello registrato.
        assert!(provenance.scoring_is_trustworthy());
        assert!(provenance.stored_level > 0);
        // L'avviso c'e', con la frase conservata allora.
        let Some(alert) = &provenance.alert else {
            panic!("un livello maggiore di zero doveva produrre un avviso");
        };
        assert_eq!(alert.level, provenance.stored_level);
        assert!(!alert.reason.is_empty());
    }

    #[test]
    fn the_explanation_reproduces_the_level_that_the_engine_persisted() {
        // E' la prova che tiene insieme PROV-01: il ricalcolo NON e' una
        // narrazione accanto al risultato, e' la stessa aritmetica.
        let (service, content_id) = analysed(
            "incendio e corteo e assalto",
            &[
                ("incendio", "violenza", 3),
                ("corteo", "ordine", 1),
                ("assalto", "violenza", 2),
            ],
            true,
        );

        let Ok(provenance) = service.explain(content_id) else {
            panic!("la spiegazione deve potersi comporre");
        };

        let ScoringExplanation::Verified { level, rationale } = &provenance.scoring.explanation
        else {
            panic!("il ricalcolo doveva riprodurre il livello registrato");
        };
        assert_eq!(level.get(), provenance.stored_level);
        // La corroborazione ha davvero pesato: tre termini, due categorie.
        assert_eq!(rationale.corroboration, 1);
    }

    #[test]
    fn without_the_session_snapshot_the_chain_stays_readable() {
        // Un contenuto storico deve restare consultabile anche quando non
        // tutto di lui e' ricostruibile.
        let (service, content_id) = analysed(
            "hanno appiccato un incendio",
            &[("incendio", "violenza", 3)],
            false,
        );

        let Ok(provenance) = service.explain(content_id) else {
            panic!("la spiegazione deve comporsi anche senza fotografia");
        };

        assert_eq!(
            provenance.scoring.explanation,
            ScoringExplanation::Unavailable(ExplanationGap::NoSessionSnapshot)
        );
        // Il resto del percorso c'e' tutto.
        assert_eq!(provenance.origin.source_name.as_str(), "Canale di prova");
        assert_eq!(provenance.scoring.contributions.len(), 1);
        assert!(provenance.scoring.has_incomplete_origins());
        assert!(provenance.alert.is_some());
        assert!(provenance.stored_level > 0);
    }

    #[test]
    fn a_level_zero_content_says_why_it_is_level_zero() {
        let (service, content_id) = analysed(
            "una giornata tranquilla",
            &[("incendio", "violenza", 3)],
            true,
        );

        let Ok(provenance) = service.explain(content_id) else {
            panic!("la spiegazione deve potersi comporre");
        };

        assert_eq!(provenance.stored_level, 0);
        assert!(provenance.alert.is_none());
        assert_eq!(
            provenance.scoring.explanation,
            ScoringExplanation::Unavailable(ExplanationGap::NoMatches)
        );
    }

    #[test]
    fn a_human_decision_does_not_become_a_new_automatic_truth() {
        let (mut service, content_id) = analysed(
            "hanno appiccato un incendio",
            &[("incendio", "violenza", 3)],
            true,
        );

        let Ok(review_id) = service.database_mut().insert_review(&NewReview {
            content_id,
            state: ReviewState::NotRelevant,
            reviewer: operator(),
            note: None,
            decided_at: Timestamp::from_millis(1_700_000_100_000),
        }) else {
            panic!("la revisione deve potersi registrare");
        };
        assert!(review_id.get() > 0);

        let Ok(provenance) = service.explain(content_id) else {
            panic!("la spiegazione deve potersi comporre");
        };

        assert_eq!(provenance.decisions.len(), 1);
        // Il livello automatico NON e' stato toccato dalla decisione.
        assert_eq!(provenance.decisions[0].automatic_level, 3);
        assert_eq!(provenance.stored_level, 3);
        assert!(
            provenance.decisions[0]
                .as_sentence()
                .contains("una decisione dell'operatore non lo cambia")
        );
    }

    #[test]
    fn the_decisions_are_read_from_the_oldest_to_the_most_recent() {
        let (mut service, content_id) = analysed(
            "hanno appiccato un incendio",
            &[("incendio", "violenza", 3)],
            true,
        );

        // Scritte fuori ordine di proposito.
        for (millis, state) in [
            (1_700_000_300_000_i64, ReviewState::Relevant),
            (1_700_000_100_000_i64, ReviewState::InReview),
            (1_700_000_200_000_i64, ReviewState::NotRelevant),
        ] {
            let Ok(_) = service.database_mut().insert_review(&NewReview {
                content_id,
                state,
                reviewer: operator(),
                note: None,
                decided_at: Timestamp::from_millis(millis),
            }) else {
                panic!("la revisione deve potersi registrare");
            };
        }

        let Ok(provenance) = service.explain(content_id) else {
            panic!("la spiegazione deve potersi comporre");
        };

        assert_eq!(provenance.decisions.len(), 3);
        let istanti: Vec<i64> = provenance
            .decisions
            .iter()
            .map(|decision| decision.decided_at.as_millis())
            .collect();
        let mut ordinati = istanti.clone();
        ordinati.sort_unstable();
        assert_eq!(istanti, ordinati, "il percorso si legge in avanti");
    }

    #[test]
    fn consulting_a_provenance_writes_nothing() {
        let (service, content_id) = analysed(
            "hanno appiccato un incendio",
            &[("incendio", "violenza", 3)],
            true,
        );

        let Ok(prima) = service
            .database()
            .audit_entries()
            .map(|entries| entries.len())
        else {
            panic!("l'audit deve potersi leggere");
        };

        for _ in 0..3 {
            let Ok(_) = service.explain(content_id) else {
                panic!("la spiegazione deve potersi comporre");
            };
        }

        let Ok(dopo) = service
            .database()
            .audit_entries()
            .map(|entries| entries.len())
        else {
            panic!("l'audit deve potersi leggere");
        };
        assert_eq!(prima, dopo, "consultare non aggiunge righe all'audit");

        // E nemmeno una revisione.
        let Ok(reviews) = service.database().content_reviews(content_id) else {
            panic!("le revisioni devono potersi leggere");
        };
        assert!(reviews.is_empty());
    }

    #[test]
    fn a_message_never_changed_carries_no_warning() {
        let (service, content_id) = analysed(
            "hanno appiccato un incendio",
            &[("incendio", "violenza", 3)],
            true,
        );

        let Ok(provenance) = service.explain(content_id) else {
            panic!("la spiegazione deve potersi comporre");
        };

        assert!(!provenance.changed_after_analysis());
        assert!(provenance.version_warning().is_none());
        let Some(alert) = &provenance.alert else {
            panic!("l'avviso doveva esserci");
        };
        assert!(alert.changed_after.is_none());
    }

    #[test]
    fn a_mitigating_term_is_recognisable_only_thanks_to_the_snapshot() {
        let (service, content_id) = analysed(
            "un incendio in un film",
            &[("incendio", "violenza", 3), ("film", "contesto", -2)],
            true,
        );

        let Ok(provenance) = service.explain(content_id) else {
            panic!("la spiegazione deve potersi comporre");
        };

        let mitiganti = provenance
            .scoring
            .contributions
            .iter()
            .filter(|contribution| contribution.is_mitigating())
            .count();
        assert_eq!(mitiganti, 1, "il segno viene dalla fotografia");
        assert!(provenance.scoring_is_trustworthy());
    }

    /// Riepilogo di ciò che è successo dopo l'acquisizione.
    fn dopo(revisions: u32, eliminato: bool) -> ContentHistorySummary {
        ContentHistorySummary {
            revisions,
            last_revision_at: (revisions > 0).then(|| Timestamp::from_millis(1_700_000_500_000)),
            deleted_at: eliminato.then(|| Timestamp::from_millis(1_700_000_900_000)),
        }
    }

    /// Avviso di prova con la motivazione indicata.
    fn avviso(motivo: &str) -> Alert {
        let (Ok(analysis), Ok(reason)) = (AnalysisLevel::try_new(3), AlertReason::try_new(motivo))
        else {
            panic!("i valori dell'avviso di prova devono essere validi");
        };
        let Ok(level) = AlertLevel::try_new(analysis) else {
            panic!("i valori dell'avviso di prova devono essere validi");
        };
        Alert {
            id: AlertId::new(1),
            content_id: ContentId::new(1),
            level,
            reason,
            raised_at: Timestamp::from_millis(1_700_000_050_000),
        }
    }

    #[test]
    fn an_alert_on_a_message_changed_afterwards_keeps_its_own_reason() {
        // ADR-0051 Decisione 1 vale anche qui: la motivazione dell'avviso
        // riguarda il testo con cui fu emesso, e PROV-01 non la riscrive.
        let motivo = "Il termine più significativo trovato è \"incendio\".";

        let intatto = super::alert_provenance(&avviso(motivo), &dopo(0, false));
        let modificato = super::alert_provenance(&avviso(motivo), &dopo(2, false));

        // La stessa motivazione, parola per parola.
        assert_eq!(intatto.reason, modificato.reason);
        assert_eq!(modificato.reason, motivo);
        // Ma solo il secondo dichiara che il messaggio e' cambiato dopo.
        assert!(intatto.changed_after.is_none());
        assert_eq!(
            modificato.changed_after.as_deref(),
            Some("modificato 2 volte")
        );
        assert!(modificato.as_sentence().contains("non è stata rifatta"));
        assert!(!intatto.as_sentence().contains("non è stata rifatta"));
    }

    #[test]
    fn an_alert_on_a_deleted_message_never_says_that_nexum_deleted_it() {
        // ADR-0051 Decisione 3: che la fonte non esponga piu' un messaggio non
        // dice chi lo abbia rimosso.
        let provenance = super::alert_provenance(&avviso("motivazione di prova"), &dopo(0, true));

        let frase = provenance.as_sentence();
        assert!(frase.contains("eliminato su Telegram"));
        assert!(!frase.contains("NEXUM/97 ha eliminato"));
        assert!(!frase.contains("è stato eliminato da"));
    }

    /// **La Provenienza dice dell'autore ciò che lo Storico mostra** (E2E01-07):
    /// con l'identificativo e senza nome non è «autore non dichiarato».
    #[test]
    fn l_autore_senza_nome_non_e_un_autore_non_dichiarato() {
        use super::author_in_words;

        assert_eq!(
            author_in_words(Some("Mario"), Some("mario"), Some("42")),
            "Mario"
        );
        let senza_nome = author_in_words(None, None, Some("123456789"));
        assert_eq!(
            senza_nome,
            "autore senza nome dichiarato, identificativo Telegram 123456789"
        );
        assert!(!senza_nome.contains("autore non dichiarato"));
        assert_eq!(
            author_in_words(None, Some("fonte"), Some("7")),
            "autore senza nome dichiarato, @fonte, identificativo Telegram 7"
        );
        assert_eq!(author_in_words(None, None, None), "autore non dichiarato");
    }

    #[test]
    fn the_warning_is_absent_when_there_is_nothing_to_warn_about() {
        // Una riga «tutto regolare» accanto a ogni risultato insegnerebbe a
        // saltarla, e la renderebbe inutile dove conta.
        let intatto = super::ResultProvenance {
            content_id: ContentId::new(1),
            engine_version: Some(lisi_core::analysis::ENGINE_VERSION),
            origin: super::ContentOrigin {
                source_name: DisplayName::try_new("Canale").expect("nome valido"),
                remote_message_id: String::from("m-1"),
                author: None,
                author_username: None,
                author_identifier: None,
                url: None,
                published_at: now(),
                acquired_at: now(),
                mode: String::from("Acquisito dal vivo."),
            },
            after_acquisition: dopo(0, false),
            stored_level: 3,
            scoring: super::ScoringProvenance {
                contributions: Vec::new(),
                explanation: ScoringExplanation::Unavailable(ExplanationGap::NoMatches),
            },
            alert: None,
            decisions: Vec::new(),
        };

        assert!(intatto.version_warning().is_none());

        let cambiato = super::ResultProvenance {
            after_acquisition: dopo(1, false),
            ..intatto
        };
        let Some(avvertenza) = cambiato.version_warning() else {
            panic!("l'avvertenza doveva esserci");
        };
        assert!(avvertenza.contains("riguarda la versione acquisita"));
        assert!(avvertenza.contains("non viene rifatta"));
    }

    /// L'elenco dello Storico non compone il percorso di ogni riga.
    ///
    /// # Perché una guardia e non un commento
    ///
    /// Perché è l'invariante di costo su cui si regge tutta la scelta: sei
    /// letture per contenuto sono nulla quando l'operatore apre **un**
    /// pannello, e sono seicento letture quando l'elenco ne mostra cento.
    ///
    /// La verifica è testuale e lo dichiara: il servizio dello Storico non
    /// deve nominare questo modulo. Se un giorno servisse davvero, sarà una
    /// decisione da prendere guardando questa prova diventare rossa, non per
    /// distrazione.
    #[test]
    fn lo_storico_non_compone_il_percorso_per_ogni_riga() {
        const STORICO: &str = include_str!("history.rs");

        let Some((produzione, _)) = STORICO.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il servizio dello storico deve avere un blocco di prove riconoscibile");
        };

        for riferimento in ["ProvenanceService", "provenance::", "explain_scoring"] {
            assert!(
                !produzione.contains(riferimento),
                "il servizio dello Storico nomina «{riferimento}»: comporre il \
                 percorso per ogni riga costerebbe sei letture per riga"
            );
        }
    }
    /// Un servizio con i contenuti indicati nella stessa sessione.
    ///
    /// Ogni voce è `(identificativo remoto, corpo)`; gli istanti si
    /// distanziano di un minuto l'uno dall'altro.
    fn con_contenuti(corpi: &[&str]) -> (ProvenanceService, Vec<ContentId>) {
        let (database, session_id, source_id) = database_with_session();
        let configuration = configuration(&[("molotov", "oggetto", 3)]);

        let mut service = AnalysisService::new(database);
        let mut identificatori = Vec::new();

        for (indice, corpo) in corpi.iter().enumerate() {
            let mut bozza = draft(session_id, source_id, corpo);
            let Ok(remote) = RemoteMessageId::try_new(&format!("m-{indice}")) else {
                panic!("l'identificativo remoto deve essere valido");
            };
            bozza.remote_message_id = remote;
            bozza.published_at = Timestamp::from_millis(now().as_millis() + indice as i64 * 60_000);

            let Ok(record) =
                service.analyse_and_record(&bozza, &configuration, &operator(), bozza.published_at)
            else {
                panic!("l'analisi deve riuscire");
            };
            let Some(content_id) = record.content_id else {
                panic!("il contenuto doveva essere registrato");
            };
            identificatori.push(content_id);
        }

        (
            ProvenanceService::new(service.into_database()),
            identificatori,
        )
    }

    /// Due contenuti quasi identici della stessa sessione si somigliano, e la
    /// riga dice **perché**.
    #[test]
    fn due_contenuti_quasi_identici_si_somigliano_e_si_dice_perche() {
        let (service, contenuti) = con_contenuti(&[
            "il corteo si e' radunato davanti alla stazione centrale nel pomeriggio",
            "il corteo si e' radunato davanti alla stazione centrale nel tardo pomeriggio",
            "la partita di ieri sera si e' conclusa senza reti segnate da nessuno",
        ]);

        let Ok(esito) = service.resembling_to(contenuti[0], 100) else {
            panic!("il confronto deve riuscire");
        };

        assert_eq!(esito.resembling_count(), Some(1), "{}", esito.as_sentence());
        let somiglianza = &esito.resemblances()[0];
        assert!(
            !somiglianza.shared_shingles().is_empty(),
            "la riga deve portare le sequenze che la giustificano"
        );
        assert!(somiglianza.as_sentence().contains("sequenze di 3 parole"));
    }

    /// **Leggere le somiglianze non tocca nulla.**
    #[test]
    fn leggere_le_somiglianze_non_tocca_nulla() {
        let (service, contenuti) = con_contenuti(&[
            "il corteo si e' radunato davanti alla stazione centrale nel pomeriggio",
            "il corteo si e' radunato davanti alla stazione centrale nel tardo pomeriggio",
        ]);

        let Ok(voci_prima) = service.database().audit_entries() else {
            panic!("l'audit deve leggersi");
        };
        let Ok(_) = service.resembling_to(contenuti[0], 100) else {
            panic!("il confronto deve riuscire");
        };
        let Ok(voci_dopo) = service.database().audit_entries() else {
            panic!("l'audit deve leggersi ancora");
        };

        assert_eq!(voci_prima.len(), voci_dopo.len());
    }

    /// **Oltre il limite il confronto si rifiuta invece di troncare.**
    #[test]
    fn oltre_il_limite_il_confronto_delle_somiglianze_si_rifiuta() {
        let (service, contenuti) = con_contenuti(&[
            "il corteo si e' radunato davanti alla stazione centrale nel pomeriggio",
            "il corteo si e' radunato davanti alla stazione centrale nel tardo pomeriggio",
            "la partita di ieri sera si e' conclusa senza reti segnate da nessuno",
        ]);

        let Ok(esito) = service.resembling_to(contenuti[0], 2) else {
            panic!("la lettura deve riuscire");
        };

        assert_eq!(
            esito.resembling_count(),
            None,
            "un rifiuto non e' zero somiglianze: {}",
            esito.as_sentence()
        );
    }

    /// Un contenuto solo nella sessione non ha nulla con cui confrontarsi, e lo
    /// dichiara invece di dire «non somiglia a nulla».
    #[test]
    fn un_contenuto_solo_non_ha_nulla_con_cui_confrontarsi() {
        let (service, contenuti) =
            con_contenuti(&["il corteo si e' radunato davanti alla stazione centrale"]);

        let Ok(esito) = service.resembling_to(contenuti[0], 100) else {
            panic!("la lettura deve riuscire");
        };

        assert_eq!(esito.resembling_count(), None);
        assert!(
            esito
                .as_sentence()
                .contains("non si \u{e8} potuto guardare"),
            "{}",
            esito.as_sentence()
        );
    }
}

#[cfg(test)]
mod motore {
    use lisi_core::ContentId;
    use lisi_core::analysis::ENGINE_VERSION;

    /// Un percorso di prova con la versione di motore indicata.
    fn percorso(engine_version: Option<u32>) -> super::ResultProvenance {
        super::ResultProvenance {
            content_id: ContentId::new(1),
            engine_version,
            origin: super::ContentOrigin {
                source_name: lisi_core::text::DisplayName::try_new("Canale").expect("nome valido"),
                remote_message_id: String::from("m-1"),
                author: None,
                author_username: None,
                author_identifier: None,
                url: None,
                published_at: lisi_core::Timestamp::from_millis(1),
                acquired_at: lisi_core::Timestamp::from_millis(2),
                mode: String::from("Acquisito dal vivo."),
            },
            after_acquisition: lisi_core::model::content_history::ContentHistorySummary::default(),
            stored_level: 2,
            scoring: lisi_core::model::provenance::ScoringProvenance {
                contributions: Vec::new(),
                explanation: lisi_core::model::provenance::ScoringExplanation::Unavailable(
                    lisi_core::model::provenance::ExplanationGap::NoMatches,
                ),
            },
            alert: None,
            decisions: Vec::new(),
        }
    }

    /// Un contenuto analizzato adesso dichiara la versione del motore.
    #[test]
    fn un_contenuto_analizzato_adesso_dichiara_il_motore() {
        let frase = percorso(Some(ENGINE_VERSION)).engine_sentence();

        assert!(
            frase.contains(&format!("v{ENGINE_VERSION}")),
            "la versione va nominata: «{frase}»"
        );
    }

    /// **Un contenuto senza versione di motore non si spaccia per uno attuale.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// I contenuti analizzati prima di ENGINE-01 non portano alcun numero.
    /// Scrivere loro accanto la versione corrente direbbe che qualcuno sa quale
    /// formula li ha prodotti, e nessuno lo sa: è la stessa disciplina con cui
    /// una fonte mai verificata resta Sconosciuta invece di diventare
    /// Operativa.
    #[test]
    fn un_contenuto_senza_motore_registrato_lo_dichiara() {
        let frase = percorso(None).engine_sentence();

        assert!(
            frase.contains("non risulta"),
            "l'assenza va dichiarata: «{frase}»"
        );
        assert!(
            !frase.contains(&format!("v{ENGINE_VERSION}")),
            "«non registrato» non deve nominare la versione corrente: «{frase}»"
        );
        assert_ne!(frase, percorso(Some(ENGINE_VERSION)).engine_sentence());
    }
}

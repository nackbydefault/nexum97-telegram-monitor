//! Analisi di un contenuto e registrazione dell'esito.
//!
//! Il motore vive in `lisi-core` ed è una funzione pura; qui si decide **quando**
//! applicarlo e **che cosa** conservare.
//!
//! # L'ordine, che non è arbitrario
//!
//! Si analizza **prima** di scrivere, e si scrive **una volta sola**. Il livello
//! è una colonna del contenuto, fissata alla creazione: inserire prima e
//! aggiornare dopo lascerebbe, fra le due operazioni, un contenuto in archivio
//! con un livello che nessuno ha calcolato.
//!
//! # Che cosa viene conservato
//!
//! - il **livello**, sul contenuto;
//! - ogni **riscontro**, con il termine, la categoria, il livello suggerito e
//!   la posizione nel testo — anche per i contenuti di livello 0, perché sapere
//!   che un termine era presente e non ha fatto scattare nulla è
//!   un'informazione;
//! - l'**alert** con la frase che spiega il livello, per i livelli da 1 a 4.
//!
//! # Un limite dichiarato
//!
//! La frase è conservata nell'alert, quindi **esiste solo dai livelli 1 in su**.
//! Per un contenuto di livello 0 restano i riscontri, dai quali la spiegazione
//! è ricalcolabile finché la formula non cambia. Se la formula cambiasse, le
//! spiegazioni dei contenuti di livello 0 racconterebbero la regola nuova su
//! fatti vecchi: è il rischio residuo, e cambiare la formula è per questo una
//! decisione da ADR.

use lisi_core::analysis::{AnalysedContent, analyse};
use lisi_core::model::analysis::MatchRange;
use lisi_core::model::dictionary::ResolvedDictionaryConfiguration;
use lisi_core::model::indicator::extract;
use lisi_core::model::{
    AcquisitionOrigin, AlertLevel, NewAlert, NewAuditEntry, NewContent, NewMatch,
};
use lisi_core::text::{
    Actor, AlertReason, AuditAction, AuditEntity, MatchedText, RuleCategory, RuleId,
};
use lisi_core::{ContentId, SessionId, Timestamp};
use lisi_storage::Database;

use crate::error::ServiceResult;

/// Esito della registrazione di un contenuto analizzato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisRecord {
    /// Contenuto registrato, assente quando era già presente.
    pub content_id: Option<ContentId>,
    /// Se il contenuto era già stato acquisito per questa sessione e fonte.
    pub already_known: bool,
    /// Livello e motivazione, calcolati comunque.
    pub analysed: AnalysedContent,
}

impl AnalysisRecord {
    /// Se l'esito ha prodotto un alert.
    #[must_use]
    pub const fn raised_alert(&self) -> bool {
        self.analysed.outcome.raises_alert()
    }
}

/// Servizio che analizza i contenuti acquisiti e ne registra l'esito.
#[derive(Debug)]
pub struct AnalysisService {
    database: Database,
}

impl AnalysisService {
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

    /// Database sottostante in prestito mutabile, per le operazioni che aprono
    /// una transazione (come l'inserimento di un contenuto).
    #[must_use]
    pub const fn database_mut(&mut self) -> &mut Database {
        &mut self.database
    }

    /// Restituisce il database, consumando il servizio.
    ///
    /// I servizi possiedono il database invece di condividerlo: passarlo da uno
    /// all'altro è come si compone una sequenza — acquisire, analizzare,
    /// revisionare — senza introdurre una condivisione che nessuno ha ancora
    /// bisogno di gestire.
    #[must_use]
    pub fn into_database(self) -> Database {
        self.database
    }

    /// Analizza un contenuto e ne registra l'esito.
    ///
    /// Il contenuto **già acquisito** non viene rianalizzato né riscritto: la
    /// deduplicazione è quella dello schema, e riscrivere produrrebbe un
    /// secondo esito per lo stesso fatto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se un valore non rispetta le invarianti del
    /// dominio o se la scrittura non riesce.
    pub fn analyse_and_record(
        &mut self,
        content: &NewContentDraft,
        configuration: &ResolvedDictionaryConfiguration,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<AnalysisRecord> {
        let analysed = analyse(content.body.as_str(), configuration);

        let new_content = NewContent {
            session_id: content.session_id,
            source_id: content.source_id,
            remote_message_id: content.remote_message_id.clone(),
            author: content.author.clone(),
            author_identifier: content.author_identifier.clone(),
            author_username: content.author_username.clone(),
            body: content.body.clone(),
            url: content.url.clone(),
            published_at: content.published_at,
            acquired_at: content.acquired_at,
            origin: content.origin,
            // Il livello e' gia' quello definitivo: non esiste un istante in
            // cui il contenuto sta in archivio con un livello non calcolato.
            analysis_level: analysed.outcome.level,
        };

        let insertion = self.database.insert_content(&new_content)?;
        let content_id = insertion.content_id();
        let already_known = !insertion.is_new();

        // Riscontri e alert si registrano **solo se assenti**, non solo quando
        // il contenuto è nuovo. È ciò che rende l'operazione idempotente e
        // completa: se un crash è avvenuto fra l'inserimento del contenuto e i
        // suoi riscontri, la ripresa dell'evento — che qui ritrova il contenuto
        // «già acquisito» — deve **completarlo**, non saltarlo lasciandolo senza
        // riscontri e senza alert. I riscontri di un contenuto già completo non
        // si riscrivono, quindi non si duplicano.
        if self.database.content_matches(content_id)?.is_empty() {
            self.record_matches(content_id, &analysed, configuration, now)?;
        }

        // Gli indicatori tecnici — CVE, indirizzi, domini, URL, impronte.
        //
        // # Perche' qui e non altrove
        //
        // E' l'unico punto in cui il corpo di un contenuto e' gia' in memoria,
        // gia' validato dal dominio, e non e' ancora stato scartato. Estrarli
        // dopo significherebbe rileggere l'archivio; estrarli prima
        // significherebbe farlo anche per i contenuti che non vengono
        // registrati.
        //
        // # Perche' l'estrazione NON influenza il livello
        //
        // Un contenuto che nomina una CVE non e' per questo piu' grave. Il
        // livello lo decide il motore 0-4 sui dizionari; gli indicatori sono
        // materiale per la correlazione, che e' un'altra domanda e vuole una
        // decisione umana. Confonderli produrrebbe allarmi su chiunque citi un
        // bollettino di sicurezza.
        //
        // # Che cosa NON succede
        //
        // Nessuna risoluzione DNS, nessuna connessione, nessun prelievo:
        // l'indicatore si estrae e non si contatta (ADR-0035 Decisione 8).
        //
        // Registrati **solo se assenti**, come i riscontri: la ripresa di un
        // evento interrotto deve completare il contenuto, non saltarlo.
        if self.database.content_indicators(content_id)?.is_empty() {
            let estrazione = extract(content.body.as_str());
            if !estrazione.indicators.is_empty() {
                self.database
                    .insert_content_indicators(content_id, &estrazione.indicators)?;
            }
        }

        if let Ok(level) = AlertLevel::try_new(analysed.outcome.level)
            && self.database.content_alert(content_id)?.is_none()
        {
            let reason = AlertReason::try_new(&analysed.outcome.rationale.to_sentence())?;
            // L'ALERT E LA SUA RIGA D'AUDIT INSIEME (FINAL-REVIEW-01, FR-015).
            let riga = Self::audit_entry(actor, "alert_generato", content_id, level.get(), now)?;
            self.database.insert_alert_with_audit(
                &NewAlert {
                    content_id,
                    level,
                    reason,
                    raised_at: now,
                },
                &riga,
            )?;
        }

        Ok(AnalysisRecord {
            content_id: Some(content_id),
            already_known,
            analysed,
        })
    }

    /// Registra ogni occorrenza come riscontro del contenuto, in un'unica
    /// transazione.
    ///
    /// Il livello del **riscontro** è quello suggerito dal termine, non quello
    /// del contenuto: confonderli produrrebbe un alert per ogni parola. I
    /// riscontri di un contenuto sono un insieme atomico: o si scrivono tutti o
    /// nessuno, così che un crash non lasci un contenuto con riscontri parziali.
    fn record_matches(
        &mut self,
        content_id: ContentId,
        analysed: &AnalysedContent,
        configuration: &ResolvedDictionaryConfiguration,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let mut entries = Vec::with_capacity(analysed.occurrences.len());
        for occurrence in &analysed.occurrences {
            let Some(term) = configuration.terms.get(occurrence.term_index) else {
                continue;
            };

            // Il livello suggerito puo' essere negativo, mentre il livello di
            // analisi parte da zero: un termine mitigante si registra come
            // riscontro di livello 0, perche' e' stato trovato ma non alza
            // nulla.
            let level = u8::try_from(term.suggested_level.max(0)).unwrap_or(0);
            let Ok(level) = lisi_core::model::AnalysisLevel::try_new(level) else {
                continue;
            };

            entries.push(NewMatch {
                content_id,
                rule_id: RuleId::try_new(&term.normalised)?,
                rule_category: RuleCategory::try_new(term.category.as_str())?,
                matched_text: MatchedText::try_new(term.original.as_str())?,
                range: MatchRange::try_new(occurrence.start, occurrence.end)?,
                level,
            });
        }

        self.database.insert_matches(&entries, now)?;
        Ok(())
    }

    /// Registra nell'audit la generazione di un alert.
    fn audit_entry(
        actor: &Actor,
        action: &str,
        content_id: ContentId,
        level: u8,
        now: Timestamp,
    ) -> ServiceResult<NewAuditEntry> {
        Ok(NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new(action)?,
            entity: AuditEntity::try_new("content")?,
            entity_id: Some(content_id.get()),
            // L'analisi non dipende dalla modalita' operativa: non e' un'azione
            // che qualcuno compie, e attribuirle una modalita' sarebbe
            // inventarla.
            actor_mode: None,
            detail: Some(lisi_core::text::AuditDetail::try_new(&format!(
                "livello {level}"
            ))?),
            recorded_at: now,
        })
    }
}

/// Contenuto acquisito, prima che l'analisi ne fissi il livello.
///
/// È [`NewContent`] senza il livello: quel campo non è un'informazione
/// dell'acquisizione, e chiederlo a chi acquisisce lo obbligherebbe a inventarne
/// uno prima che l'analisi sia avvenuta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewContentDraft {
    /// Sessione in cui il contenuto è stato acquisito.
    pub session_id: SessionId,
    /// Fonte da cui proviene.
    pub source_id: lisi_core::SourceId,
    /// Identificativo del messaggio presso la fonte.
    pub remote_message_id: lisi_core::text::RemoteMessageId,
    /// Autore dichiarato, quando disponibile.
    pub author: Option<Actor>,
    /// Identificativo dell'autore presso la piattaforma, quando esiste.
    ///
    /// Regge nel tempo, a differenza del nome. Assente per i messaggi di
    /// canale, che non sono firmati da una persona.
    pub author_identifier: Option<String>,
    /// Username dell'autore, quando ne ha uno.
    ///
    /// Serve a ritrovare qualcuno oggi, non ad attribuirgli un messaggio
    /// domani: uno username può cambiare padrone.
    pub author_username: Option<String>,
    /// Corpo del messaggio.
    pub body: lisi_core::text::ContentBody,
    /// Collegamento al messaggio, quando disponibile.
    pub url: Option<lisi_core::text::ContentUrl>,
    /// Istante di pubblicazione dichiarato dalla fonte.
    pub published_at: Timestamp,
    /// Istante in cui il prodotto lo ha acquisito.
    pub acquired_at: Timestamp,
    /// Se il contenuto e' stato osservato dal vivo o recuperato dopo.
    ///
    /// Attraversa l'analisi **immutato**: il motore giudica il testo, non il
    /// modo in cui e' arrivato, e un'analisi che cambiasse a seconda
    /// dell'origine renderebbe i due percorsi non confrontabili.
    pub origin: AcquisitionOrigin,
}

#[cfg(test)]
mod tests {
    use lisi_core::model::AcquisitionOrigin;
    use lisi_core::model::dictionary::{
        ConfigurationResolver, MatchMode, ResolvedDictionaryConfiguration, TermProvenance,
    };
    use lisi_core::model::{NewSession, NewSource, SessionDuration, SourceKind};
    use lisi_core::text::{
        Actor, ContentBody, DisplayName, LanguageTag, RemoteMessageId, SourceIdentifier,
        TermCategory, TermText,
    };
    use lisi_core::{SessionId, SourceId, Timestamp};
    use lisi_storage::Database;

    use super::{AnalysisService, NewContentDraft};
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

    /// Servizio con una sessione e una fonte pronte.
    fn service_with_session() -> (AnalysisService, SessionId, SourceId) {
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

        (AnalysisService::new(database), session_id, source_id)
    }

    /// Contenuto di prova con il testo indicato.
    fn draft(
        session_id: SessionId,
        source_id: SourceId,
        remote: &str,
        body: &str,
    ) -> NewContentDraft {
        let (Ok(remote_message_id), Ok(body)) =
            (RemoteMessageId::try_new(remote), ContentBody::try_new(body))
        else {
            panic!("i valori del contenuto di prova devono essere validi");
        };

        NewContentDraft {
            session_id,
            source_id,
            remote_message_id,
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

    #[test]
    fn a_content_without_matches_is_recorded_at_level_zero_without_an_alert() {
        // Livello 0 non e' assenza di analisi: e' un contenuto analizzato e
        // risultato non rilevante, che resta nello storico.
        let (mut service, session, source) = service_with_session();
        let config = configuration(&[("incendio", "azione", 3)]);

        let Ok(record) = service.analyse_and_record(
            &draft(session, source, "m1", "ci vediamo domani"),
            &config,
            &operator(),
            now(),
        ) else {
            panic!("la registrazione deve riuscire");
        };

        assert!(!record.raised_alert());
        let Some(content_id) = record.content_id else {
            panic!("il contenuto doveva essere registrato");
        };
        assert_eq!(
            service
                .database()
                .content(content_id)
                .map(|c| c.analysis_level.get())
                .ok(),
            Some(0)
        );
        assert_eq!(
            service.database().content_alert(content_id).ok(),
            Some(None)
        );
    }

    #[test]
    fn a_matching_content_is_recorded_with_its_level_matches_and_alert() {
        let (mut service, session, source) = service_with_session();
        let config = configuration(&[("molotov", "oggetto", 4)]);

        let Ok(record) = service.analyse_and_record(
            &draft(session, source, "m1", "hanno preparato una molotov"),
            &config,
            &operator(),
            now(),
        ) else {
            panic!("la registrazione deve riuscire");
        };
        let Some(content_id) = record.content_id else {
            panic!("il contenuto doveva essere registrato");
        };

        assert!(record.raised_alert());
        assert_eq!(
            service
                .database()
                .content(content_id)
                .map(|c| c.analysis_level.get())
                .ok(),
            Some(4)
        );
        assert_eq!(
            service
                .database()
                .content_matches(content_id)
                .map(|m| m.len())
                .ok(),
            Some(1)
        );

        let Ok(Some(alert)) = service.database().content_alert(content_id) else {
            panic!("l'alert deve essere presente");
        };
        assert_eq!(alert.level.get(), 4);
        assert!(
            alert.reason.as_str().contains("molotov"),
            "la motivazione deve nominare il termine: {}",
            alert.reason.as_str()
        );
    }

    #[test]
    fn the_matches_of_a_level_zero_content_are_kept() {
        // Sapere che un termine era presente e non ha fatto scattare nulla e'
        // un'informazione: e' il caso del contesto riduttivo.
        let (mut service, session, source) = service_with_session();
        let config = configuration(&[("incendio", "azione", 3), ("nel film", "finzione", -3)]);

        let Ok(record) = service.analyse_and_record(
            &draft(
                session,
                source,
                "m1",
                "nel film c'e' un incendio spettacolare",
            ),
            &config,
            &operator(),
            now(),
        ) else {
            panic!("la registrazione deve riuscire");
        };
        let Some(content_id) = record.content_id else {
            panic!("il contenuto doveva essere registrato");
        };

        assert!(!record.raised_alert(), "mitigato a zero");
        assert_eq!(
            service
                .database()
                .content_matches(content_id)
                .map(|m| m.len())
                .ok(),
            Some(2),
            "entrambi i riscontri restano registrati"
        );
    }

    #[test]
    fn a_content_already_acquired_is_not_recorded_twice() {
        // Riscrivere produrrebbe un secondo esito per lo stesso fatto.
        let (mut service, session, source) = service_with_session();
        let config = configuration(&[("molotov", "oggetto", 3)]);
        let content = draft(session, source, "m1", "una molotov");

        let Ok(first) = service.analyse_and_record(&content, &config, &operator(), now()) else {
            panic!("la prima registrazione deve riuscire");
        };
        let Ok(second) = service.analyse_and_record(&content, &config, &operator(), now()) else {
            panic!("la seconda deve riuscire senza scrivere");
        };

        assert!(!first.already_known);
        assert!(second.already_known);
        // Il secondo esito riporta ora l'identificatore del contenuto esistente
        // — non `None` — così che una ripresa dopo un crash possa completarlo
        // (riscontri e alert) invece di ritrovarsi senza riferimento. Nulla
        // viene comunque riscritto: i riscontri restano uno solo.
        assert_eq!(second.content_id, first.content_id);

        let Some(content_id) = first.content_id else {
            panic!("il contenuto doveva essere registrato");
        };
        assert_eq!(
            service
                .database()
                .content_matches(content_id)
                .map(|m| m.len())
                .ok(),
            Some(1),
            "nessun riscontro duplicato"
        );
    }

    #[test]
    fn the_level_of_a_match_is_the_term_level_and_not_the_content_level() {
        // Confonderli produrrebbe un alert per ogni parola.
        let (mut service, session, source) = service_with_session();
        let config = configuration(&[
            ("appiccare", "azione", 2),
            ("molotov", "oggetto", 3),
            ("innesco", "oggetto", 1),
        ]);

        let Ok(record) = service.analyse_and_record(
            &draft(session, source, "m1", "appiccare con molotov e innesco"),
            &config,
            &operator(),
            now(),
        ) else {
            panic!("la registrazione deve riuscire");
        };
        let Some(content_id) = record.content_id else {
            panic!("il contenuto doveva essere registrato");
        };

        // Contenuto: base 3 + corroborazione 1 = 4.
        assert_eq!(record.analysed.outcome.level.get(), 4);

        let Ok(matches) = service.database().content_matches(content_id) else {
            panic!("i riscontri devono potersi leggere");
        };
        let levels: Vec<u8> = matches.iter().map(|entry| entry.level.get()).collect();
        assert!(
            levels.iter().all(|level| *level < 4),
            "nessun riscontro porta il livello del contenuto: {levels:?}"
        );
    }

    #[test]
    fn the_alert_generation_is_recorded_in_the_audit() {
        let (mut service, session, source) = service_with_session();
        let config = configuration(&[("molotov", "oggetto", 2)]);

        let Ok(_) = service.analyse_and_record(
            &draft(session, source, "m1", "una molotov"),
            &config,
            &operator(),
            now(),
        ) else {
            panic!("la registrazione deve riuscire");
        };

        let Ok(entries) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert!(
            entries
                .iter()
                .any(|entry| entry.action.as_str() == "alert_generato"),
            "la generazione dell'alert deve restare nel registro"
        );
    }

    #[test]
    fn a_level_zero_content_does_not_produce_an_audit_entry_for_an_alert() {
        let (mut service, session, source) = service_with_session();
        let config = configuration(&[("incendio", "azione", 3)]);

        let Ok(_) = service.analyse_and_record(
            &draft(session, source, "m1", "nulla di rilevante"),
            &config,
            &operator(),
            now(),
        ) else {
            panic!("la registrazione deve riuscire");
        };

        let Ok(entries) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert!(
            !entries
                .iter()
                .any(|entry| entry.action.as_str() == "alert_generato"),
            "nessun alert, nessuna voce"
        );
    }

    #[test]
    fn an_empty_configuration_records_the_content_at_level_zero() {
        // Una sessione senza termini non dovrebbe esistere, ma se esistesse il
        // contenuto va comunque conservato: lo storico documenta cio' che e'
        // stato osservato.
        let (mut service, session, source) = service_with_session();
        let empty = ResolvedDictionaryConfiguration::from_terms(vec![]);

        let Ok(record) = service.analyse_and_record(
            &draft(session, source, "m1", "un testo qualunque"),
            &empty,
            &operator(),
            now(),
        ) else {
            panic!("la registrazione deve riuscire");
        };

        assert!(record.content_id.is_some());
        assert!(!record.raised_alert());
    }

    /// **Gli indicatori vengono estratti e registrati durante l'analisi.**
    ///
    /// L'estrattore esisteva in `lisi-core`, era esportato, ed era chiamato da
    /// NESSUNO: costruito, collaudato e mai invocato. È la firma di un difetto
    /// che questo progetto ha già incontrato più volte, e questa prova è ciò
    /// che rende impossibile che torni a esserlo.
    #[test]
    fn analizzare_un_contenuto_ne_registra_gli_indicatori() {
        let (mut service, session, source) = service_with_session();
        let config = configuration(&[("molotov", "oggetto", 2)]);

        let Ok(record) = service.analyse_and_record(
            &draft(
                session,
                source,
                "m-ioc",
                "Bollettino: la CVE-2026-1234 riguarda esempio.test, host 203.0.113.7",
            ),
            &config,
            &operator(),
            now(),
        ) else {
            panic!("l'analisi deve riuscire");
        };
        let Some(content_id) = record.content_id else {
            panic!("il contenuto doveva essere registrato");
        };

        let Ok(indicatori) = service.database().content_indicators(content_id) else {
            panic!("gli indicatori devono potersi leggere");
        };

        let valori: Vec<&str> = indicatori.iter().map(|i| i.value.as_str()).collect();
        assert!(
            valori.iter().any(|v| v.contains("2026-1234")),
            "la CVE non e' stata estratta: {valori:?}"
        );
        assert!(
            valori.contains(&"203.0.113.7"),
            "l'indirizzo non e' stato estratto: {valori:?}"
        );
    }

    /// **Rianalizzare lo stesso contenuto non duplica gli indicatori.**
    ///
    /// La stessa regola dei riscontri: la ripresa di un evento interrotto deve
    /// completare il contenuto, non raddoppiarne le righe.
    #[test]
    fn rianalizzare_non_duplica_gli_indicatori() {
        let (mut service, session, source) = service_with_session();
        let config = configuration(&[("molotov", "oggetto", 2)]);

        let contenuto = draft(session, source, "m-ripetuto", "riferimento a CVE-2026-5555");

        let Ok(primo) = service.analyse_and_record(&contenuto, &config, &operator(), now()) else {
            panic!("la prima analisi deve riuscire");
        };
        let Ok(_) = service.analyse_and_record(&contenuto, &config, &operator(), now()) else {
            panic!("la seconda analisi deve riuscire");
        };

        let Some(content_id) = primo.content_id else {
            panic!("il contenuto doveva essere registrato");
        };
        let Ok(indicatori) = service.database().content_indicators(content_id) else {
            panic!("gli indicatori devono potersi leggere");
        };
        assert_eq!(indicatori.len(), 1, "gli indicatori sono stati duplicati");
    }

    /// **Un indicatore NON alza il livello.**
    ///
    /// Un contenuto che nomina una CVE non è per questo più grave. Il livello lo
    /// decide il motore 0-4 sui dizionari; gli indicatori sono materiale per la
    /// correlazione, che è un'altra domanda e vuole una decisione umana.
    ///
    /// Confonderli produrrebbe un allarme su chiunque citi un bollettino di
    /// sicurezza — cioè su chi fa esattamente il proprio lavoro.
    #[test]
    fn un_indicatore_non_alza_il_livello() {
        let (mut service, session, source) = service_with_session();
        let config = configuration(&[("molotov", "oggetto", 2)]);

        let Ok(record) = service.analyse_and_record(
            &draft(
                session,
                source,
                "m-innocuo",
                "CVE-2026-0001 esempio.test 198.51.100.4",
            ),
            &config,
            &operator(),
            now(),
        ) else {
            panic!("l'analisi deve riuscire");
        };

        assert_eq!(
            record.analysed.outcome.level.get(),
            0,
            "un contenuto senza riscontri di dizionario deve restare al livello 0 \
             anche se pieno di indicatori tecnici"
        );

        let Some(content_id) = record.content_id else {
            panic!("il contenuto doveva essere registrato");
        };
        let Ok(indicatori) = service.database().content_indicators(content_id) else {
            panic!("gli indicatori devono potersi leggere");
        };
        assert!(
            !indicatori.is_empty(),
            "gli indicatori devono comunque essere stati registrati"
        );
    }

    /// **Un contenuto senza indicatori non ne registra.**
    ///
    /// Il caso più frequente, e quello in cui un difetto passerebbe inosservato:
    /// se l'estrazione inventasse un indicatore da un testo qualunque, ogni
    /// correlazione futura partirebbe da rumore.
    #[test]
    fn un_testo_senza_indicatori_non_ne_produce() {
        let (mut service, session, source) = service_with_session();
        let config = configuration(&[("molotov", "oggetto", 2)]);

        let Ok(record) = service.analyse_and_record(
            &draft(
                session,
                source,
                "m-pulito",
                "un messaggio del tutto ordinario",
            ),
            &config,
            &operator(),
            now(),
        ) else {
            panic!("l'analisi deve riuscire");
        };
        let Some(content_id) = record.content_id else {
            panic!("il contenuto doveva essere registrato");
        };

        let Ok(indicatori) = service.database().content_indicators(content_id) else {
            panic!("gli indicatori devono potersi leggere");
        };
        assert!(
            indicatori.is_empty(),
            "sono stati inventati indicatori da un testo che non ne ha: {indicatori:?}"
        );
    }
}

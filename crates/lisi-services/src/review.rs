//! Revisione umana dei contenuti segnalati.
//!
//! Il motore propone, l'operatore decide. Questo modulo è il punto in cui una
//! valutazione automatica diventa **una valutazione assunta da una persona**.
//!
//! # Le decisioni non si correggono, si aggiungono
//!
//! Il registro delle revisioni è **append-only**: cambiare idea produce una
//! nuova voce, non la modifica della precedente. Chi legge lo storico deve
//! poter vedere che una valutazione è stata rivista, e da chi: sovrascriverla
//! cancellerebbe proprio il fatto che qualcuno abbia cambiato parere, che è
//! spesso l'informazione più utile.
//!
//! # Contraddire il motore richiede una ragione
//!
//! Se il motore ha segnalato un contenuto e l'operatore lo giudica non
//! rilevante, quella divergenza è il segnale con cui i dizionari si correggono.
//! Registrarla senza motivo la sprecherebbe: la nota diventa obbligatoria.
//!
//! Non è un attrito imposto per principio. Confermare non richiede nulla,
//! perché confermare non contraddice niente.

use lisi_core::model::{Alert, NewAuditEntry, NewReview, Review, ReviewState};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity, Note};
use lisi_core::{ContentId, SessionId, Timestamp};
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};
use crate::feedback::{DictionaryFeedback, ReviewedContent, aggregate};

/// Contenuto segnalato in attesa di una decisione umana.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingReview {
    /// Alert che ha portato il contenuto all'attenzione.
    pub alert: Alert,
    /// Stato corrente, se qualcuno ha già iniziato a esaminarlo.
    pub state: Option<ReviewState>,
}

impl PendingReview {
    /// Se nessuno lo ha ancora toccato.
    #[must_use]
    pub const fn is_untouched(&self) -> bool {
        self.state.is_none()
    }
}

/// Servizio della revisione umana.
#[derive(Debug)]
pub struct ReviewService {
    database: Database,
}

impl ReviewService {
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

    /// Restituisce il database, consumando il servizio.
    ///
    /// Come per gli altri servizi: l'archivio si passa da uno all'altro invece
    /// di condividerlo, ed è così che una sequenza — acquisire, analizzare,
    /// revisionare, rileggere — si compone.
    #[must_use]
    pub fn into_database(self) -> Database {
        self.database
    }

    /// Contenuti segnalati di una sessione che attendono una decisione.
    ///
    /// Comprende quelli già presi in carico ma non conclusi: sono in coda
    /// quanto quelli mai aperti, e nasconderli farebbe perdere di vista un
    /// esame lasciato a metà.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn pending(&self, session_id: SessionId) -> ServiceResult<Vec<PendingReview>> {
        let alerts = self.database.session_alerts(session_id)?;

        let mut pending = Vec::new();
        for alert in alerts {
            let state = self
                .database
                .latest_review(alert.content_id)?
                .map(|review| review.state);

            if state.is_some_and(ReviewState::is_decided) {
                continue;
            }
            pending.push(PendingReview { alert, state });
        }
        Ok(pending)
    }

    /// Stato corrente della revisione di un contenuto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn current_state(&self, content_id: ContentId) -> ServiceResult<ReviewState> {
        Ok(self
            .database
            .latest_review(content_id)?
            .map_or(ReviewState::New, |review| review.state))
    }

    /// Storico completo delle decisioni su un contenuto, dalla più antica.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn history(&self, content_id: ContentId) -> ServiceResult<Vec<Review>> {
        Ok(self.database.content_reviews(content_id)?)
    }

    /// Che cosa la revisione umana dice dei dizionari di una sessione.
    ///
    /// # Perché la lettura sta qui e l'aggregazione no
    ///
    /// Perché [`crate::feedback`] **non conosce l'archivio**, ed è la garanzia
    /// che non possa modificare un dizionario: non ha con che cosa. Qualcuno
    /// deve pur leggere i riscontri, le decisioni e la fotografia della
    /// sessione, e quel qualcuno è il servizio che le decisioni le registra.
    ///
    /// # Perché `None` senza la fotografia della sessione
    ///
    /// Perché la fotografia è l'unica cosa che sappia da quale dizionario, e in
    /// quale versione, un termine veniva **allora**. Senza, l'unica alternativa
    /// sarebbe attribuire le decisioni di ieri ai dizionari di oggi: le regole
    /// nel frattempo possono essere cambiate, e il quadro che ne uscirebbe
    /// accuserebbe una versione di ciò che aveva fatto un'altra.
    ///
    /// # Non scrive nulla
    ///
    /// Leggere che cosa le persone hanno deciso non è un atto di cui qualcuno
    /// risponda, e nessun dizionario viene toccato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn dictionary_feedback(
        &self,
        session_id: SessionId,
    ) -> ServiceResult<Option<DictionaryFeedback>> {
        let Some(configuration) = self.database.session_resolved_configuration(session_id)? else {
            return Ok(None);
        };

        let per_contenuto = self.database.session_matches(session_id)?;

        let mut contents = Vec::with_capacity(per_contenuto.len());
        for (raw, matches) in per_contenuto {
            let content_id = ContentId::new(raw);
            contents.push(ReviewedContent {
                content_id,
                decision: self
                    .database
                    .latest_review(content_id)?
                    .map(|review| review.state),
                rules: matches
                    .iter()
                    .map(|entry| entry.rule_id.as_str().to_owned())
                    .collect(),
            });
        }

        Ok(Some(aggregate(&contents, &configuration)))
    }

    /// Registra una decisione umana su un contenuto.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::ReviewNeedsReason`] quando la decisione
    /// contraddice il motore senza spiegare perché,
    /// [`ServiceError::ReviewStateUnchanged`] quando ripete lo stato corrente,
    /// e un errore se la scrittura non riesce.
    pub fn record(
        &self,
        content_id: ContentId,
        state: ReviewState,
        reviewer: &Actor,
        note: Option<&str>,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let current = self.current_state(content_id)?;
        if current == state {
            return Err(ServiceError::ReviewStateUnchanged {
                state: state.as_str(),
            });
        }

        let note = match note {
            Some(text) if !text.trim().is_empty() => Some(Note::try_new(text)?),
            _ => None,
        };

        if self.contradicts_the_engine(content_id, state)? && note.is_none() {
            return Err(ServiceError::ReviewNeedsReason {
                state: state.as_str(),
            });
        }
        if state == ReviewState::Reported && note.is_none() {
            return Err(ServiceError::ReviewNeedsReason {
                state: state.as_str(),
            });
        }

        self.database.insert_review(&NewReview {
            content_id,
            state,
            reviewer: reviewer.clone(),
            note,
            decided_at: now,
        })?;

        self.audit(reviewer, content_id, state, now)
    }

    /// Se la decisione smentisce una segnalazione del motore.
    ///
    /// Smentire significa dichiarare non rilevante, o duplicato, un contenuto
    /// che il motore aveva segnalato. È la divergenza da cui i dizionari si
    /// correggono, e va motivata perché serva a qualcosa.
    ///
    /// **Quali stati smentiscano lo dice [`ReviewState`]**, non questa
    /// funzione: la stessa definizione serve all'aggregazione del riscontro
    /// sui dizionari, e due copie divergerebbero alla prima aggiunta di uno
    /// stato.
    fn contradicts_the_engine(
        &self,
        content_id: ContentId,
        state: ReviewState,
    ) -> ServiceResult<bool> {
        if !state.contradicts_the_engine() {
            return Ok(false);
        }
        Ok(self.database.content_alert(content_id)?.is_some())
    }

    /// Registra la decisione nell'audit append-only.
    ///
    /// Il dettaglio riporta lo **stato**, non la nota: la nota può contenere
    /// osservazioni sul contenuto, e l'audit documenta le azioni, non i dati su
    /// cui esse insistono.
    fn audit(
        &self,
        reviewer: &Actor,
        content_id: ContentId,
        state: ReviewState,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let entry = NewAuditEntry {
            actor: reviewer.clone(),
            action: AuditAction::try_new("revisione_registrata")?,
            entity: AuditEntity::try_new("content")?,
            entity_id: Some(content_id.get()),
            // La revisione è un atto della persona, non della postazione: la
            // modalità operativa non la governa e attribuirgliene una sarebbe
            // inventarla.
            actor_mode: None,
            detail: Some(AuditDetail::try_new(state.as_str())?),
            recorded_at: now,
        };

        self.database.append_audit(&entry)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::id::{DictionaryId, DictionaryVersionId};
    use lisi_core::model::AcquisitionOrigin;
    use lisi_core::model::dictionary::{
        ConfigurationResolver, MatchMode, ResolvedDictionaryConfiguration, TermProvenance,
    };
    use lisi_core::model::{NewSession, NewSource, ReviewState, SessionDuration, SourceKind};
    use lisi_core::text::DictionaryName;
    use lisi_core::text::{
        Actor, ContentBody, DisplayName, LanguageTag, RemoteMessageId, SourceIdentifier,
        TermCategory, TermText,
    };
    use lisi_core::{ContentId, SessionId, Timestamp};

    use super::ReviewService;
    use crate::analysis::{AnalysisService, NewContentDraft};
    use crate::error::ServiceError;
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

    /// Servizio con un contenuto già analizzato e segnalato.
    ///
    /// `level` è il livello suggerito del termine, quindi quello del contenuto.
    fn with_alert(level: i8, body: &str) -> (ReviewService, SessionId, ContentId) {
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

        // Configurazione con un solo termine, del livello richiesto.
        let (Ok(text), Ok(category), Ok(language)) = (
            TermText::try_new("molotov"),
            TermCategory::try_new("oggetto"),
            LanguageTag::try_new("it"),
        ) else {
            panic!("i valori del termine devono essere validi");
        };
        let mut resolver = ConfigurationResolver::new();
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
        let configuration: ResolvedDictionaryConfiguration = resolver.finish();

        let (Ok(remote), Ok(body)) = (RemoteMessageId::try_new("m1"), ContentBody::try_new(body))
        else {
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
                published_at: now(),
                acquired_at: now(),
                origin: AcquisitionOrigin::Observed,
            },
            &configuration,
            &operator(),
            now(),
        ) else {
            panic!("l'analisi deve riuscire");
        };
        let Some(content_id) = record.content_id else {
            panic!("il contenuto doveva essere registrato");
        };

        (
            ReviewService::new(analysis.into_database()),
            session_id,
            content_id,
        )
    }

    /// Conserva con la sessione la fotografia dei termini, con la provenienza
    /// indicata.
    ///
    /// Serve al riscontro sui dizionari: senza la fotografia non si sa da quale
    /// dizionario, e in quale versione, il termine venisse **allora**.
    fn con_fotografia(
        service: ReviewService,
        session_id: SessionId,
        provenance: TermProvenance,
    ) -> ReviewService {
        let (Ok(text), Ok(category), Ok(language)) = (
            TermText::try_new("molotov"),
            TermCategory::try_new("oggetto"),
            LanguageTag::try_new("it"),
        ) else {
            panic!("i valori del termine devono essere validi");
        };
        let mut resolver = ConfigurationResolver::new();
        let Ok(()) = resolver.add(
            text,
            category,
            language,
            MatchMode::NormalizedWord,
            3,
            provenance,
        ) else {
            panic!("il termine doveva essere accettato");
        };
        let configuration = resolver.finish();

        let mut database = service.into_database();
        let Ok(()) = database.save_resolved_configuration(session_id, &configuration) else {
            panic!("la fotografia deve potersi conservare");
        };
        ReviewService::new(database)
    }

    fn dizionario() -> TermProvenance {
        let Ok(name) = DictionaryName::try_new("Ordine pubblico") else {
            panic!("il nome del dizionario deve essere valido");
        };
        TermProvenance::from_dictionary(DictionaryId::new(7), DictionaryVersionId::new(3), &name, 2)
    }

    /// **Senza la fotografia della sessione il riscontro non si esegue.**
    ///
    /// L'unica alternativa sarebbe attribuire le decisioni di ieri ai
    /// dizionari di oggi, che nel frattempo possono essere cambiati: il quadro
    /// accuserebbe una versione di ciò che aveva fatto un'altra.
    #[test]
    fn senza_la_fotografia_della_sessione_il_riscontro_non_si_esegue() {
        let (service, session, _) = with_alert(3, "una molotov");

        assert_eq!(service.dictionary_feedback(session).ok(), Some(None));
    }

    /// La decisione della persona si conta sulla regola che aveva trovato il
    /// contenuto, sotto il dizionario e la versione di allora.
    #[test]
    fn la_decisione_si_conta_sulla_regola_che_aveva_trovato_il_contenuto() {
        let (service, session, content) = with_alert(3, "una molotov");
        let service = con_fotografia(service, session, dizionario());

        let Ok(()) = service.record(
            content,
            ReviewState::NotRelevant,
            &operator(),
            Some("citazione giornalistica"),
            later(60),
        ) else {
            panic!("la revisione motivata deve riuscire");
        };

        let Ok(Some(esito)) = service.dictionary_feedback(session) else {
            panic!("con la fotografia il riscontro deve esserci");
        };

        assert_eq!(esito.rules.len(), 1);
        assert_eq!(esito.rules[0].rule, "molotov");
        assert_eq!(esito.rules[0].contradicting, 1);
        assert_eq!(esito.rules[0].confirming, 0);
        assert_eq!(esito.decided_contents, 1);
        assert!(esito.rules[0].origin.is_a_dictionary());
        assert_eq!(esito.rules[0].origin.label(), "Ordine pubblico v2");
        assert!(
            esito.suggestions().is_empty(),
            "una decisione sola non invita a rivedere nulla"
        );
    }

    /// **Leggere il riscontro non tocca alcun dizionario, e non è un atto.**
    ///
    /// La fotografia resta identica — impronta compresa — e l'audit non
    /// registra nulla: chiedersi che cosa dicano le persone non è una
    /// decisione di cui qualcuno risponda.
    #[test]
    fn leggere_il_riscontro_non_tocca_nulla() {
        let (service, session, content) = with_alert(3, "una molotov");
        let service = con_fotografia(service, session, dizionario());
        let Ok(()) = service.record(
            content,
            ReviewState::NotRelevant,
            &operator(),
            Some("citazione giornalistica"),
            later(60),
        ) else {
            panic!("la revisione motivata deve riuscire");
        };

        let prima = service.database().session_resolved_configuration(session);
        let Ok(Some(prima)) = prima else {
            panic!("la fotografia deve leggersi");
        };
        let Ok(voci_prima) = service.database().audit_entries() else {
            panic!("l'audit deve leggersi");
        };

        let Ok(Some(_)) = service.dictionary_feedback(session) else {
            panic!("il riscontro deve esserci");
        };

        let Ok(Some(dopo)) = service.database().session_resolved_configuration(session) else {
            panic!("la fotografia deve leggersi ancora");
        };
        let Ok(voci_dopo) = service.database().audit_entries() else {
            panic!("l'audit deve leggersi ancora");
        };

        assert_eq!(prima.digest, dopo.digest);
        assert_eq!(prima.terms, dopo.terms);
        assert_eq!(voci_prima.len(), voci_dopo.len());
        assert_eq!(
            service.current_state(content).ok(),
            Some(ReviewState::NotRelevant),
            "nemmeno la decisione viene toccata"
        );
    }

    #[test]
    fn a_content_never_examined_is_new_and_appears_in_the_queue() {
        let (service, session, content) = with_alert(3, "una molotov");

        assert_eq!(service.current_state(content).ok(), Some(ReviewState::New));
        let Ok(pending) = service.pending(session) else {
            panic!("la coda deve potersi leggere");
        };
        assert_eq!(pending.len(), 1);
        assert!(pending[0].is_untouched());
        assert_eq!(pending[0].alert.level.get(), 3);
    }

    #[test]
    fn confirming_the_engine_needs_no_reason() {
        // Confermare non contraddice niente.
        let (service, _, content) = with_alert(3, "una molotov");

        assert!(
            service
                .record(content, ReviewState::Relevant, &operator(), None, now())
                .is_ok()
        );
        assert_eq!(
            service.current_state(content).ok(),
            Some(ReviewState::Relevant)
        );
    }

    #[test]
    fn contradicting_the_engine_without_a_reason_is_refused() {
        // E' la divergenza da cui i dizionari si correggono: registrarla senza
        // motivo la sprecherebbe.
        let (service, _, content) = with_alert(4, "una molotov");

        let Err(error) =
            service.record(content, ReviewState::NotRelevant, &operator(), None, now())
        else {
            panic!("la smentita senza ragione doveva essere rifiutata");
        };
        assert!(matches!(error, ServiceError::ReviewNeedsReason { .. }));
        assert!(error.operator_message().contains("perché"));

        // E nulla e' stato registrato.
        assert_eq!(service.current_state(content).ok(), Some(ReviewState::New));
    }

    #[test]
    fn contradicting_the_engine_with_a_reason_is_accepted_and_kept() {
        let (service, _, content) = with_alert(4, "una molotov");

        let Ok(()) = service.record(
            content,
            ReviewState::NotRelevant,
            &operator(),
            Some("citazione da un articolo di cronaca"),
            now(),
        ) else {
            panic!("la smentita motivata deve essere accettata");
        };

        let Ok(history) = service.history(content) else {
            panic!("lo storico deve potersi leggere");
        };
        assert_eq!(history.len(), 1);
        let Some(note) = history[0].note.as_ref() else {
            panic!("la nota deve essere conservata");
        };
        assert!(note.as_str().contains("cronaca"));
    }

    #[test]
    fn a_content_without_an_alert_can_be_dismissed_without_a_reason() {
        // Non c'e' nulla da contraddire: il motore non aveva segnalato.
        let (service, _, content) = with_alert(0, "una molotov");

        assert!(
            service
                .database()
                .content_alert(content)
                .ok()
                .flatten()
                .is_none()
        );
        assert!(
            service
                .record(content, ReviewState::NotRelevant, &operator(), None, now())
                .is_ok()
        );
    }

    /// **«Segnalato» senza motivo non si sente dire che contraddice il motore**
    /// (OPERATOR-UX-REMEDIATION-01, OS-04): chi segnala conferma, e la frase
    /// sul disaccordo lo confondeva.
    #[test]
    fn reporting_without_a_reason_says_what_to_do_not_that_it_contradicts() {
        let (service, _, content) = with_alert(3, "una molotov");
        let Err(segnalato) =
            service.record(content, ReviewState::Reported, &operator(), None, now())
        else {
            panic!("la segnalazione senza motivo doveva essere rifiutata");
        };
        let frase = segnalato.operator_message();
        assert!(frase.contains("«Segnalato»"), "{frase}");
        assert!(frase.contains("«Motivo»"), "dice dove scrivere: {frase}");
        assert!(
            !frase.contains("contrario"),
            "non parla di disaccordo: {frase}"
        );

        let Err(smentita) =
            service.record(content, ReviewState::NotRelevant, &operator(), None, now())
        else {
            panic!("la smentita senza motivo doveva essere rifiutata");
        };
        let frase = smentita.operator_message();
        assert!(frase.contains("contrario"), "{frase}");
        assert!(frase.contains("«Motivo»"), "{frase}");
    }

    #[test]
    fn reporting_always_requires_a_reason() {
        // E' un atto rivolto all'esterno: che cosa sia stato trasmesso, e a chi,
        // non puo' restare implicito.
        let (service, _, content) = with_alert(3, "una molotov");

        assert!(matches!(
            service.record(content, ReviewState::Reported, &operator(), None, now()),
            Err(ServiceError::ReviewNeedsReason { .. })
        ));
        assert!(
            service
                .record(
                    content,
                    ReviewState::Reported,
                    &operator(),
                    Some("trasmesso all'ufficio competente"),
                    now()
                )
                .is_ok()
        );
    }

    #[test]
    fn a_decision_is_added_and_never_overwritten() {
        // Sovrascriverla cancellerebbe il fatto che qualcuno abbia cambiato
        // parere, che e' spesso l'informazione piu' utile.
        let (service, _, content) = with_alert(3, "una molotov");

        let Ok(()) = service.record(content, ReviewState::Relevant, &operator(), None, now())
        else {
            panic!("la prima decisione deve riuscire");
        };
        let Ok(()) = service.record(
            content,
            ReviewState::NotRelevant,
            &operator(),
            Some("rivista dopo un controllo"),
            later(60),
        ) else {
            panic!("il ripensamento deve riuscire");
        };

        let Ok(history) = service.history(content) else {
            panic!("lo storico deve potersi leggere");
        };
        assert_eq!(history.len(), 2, "entrambe le decisioni restano");
        assert_eq!(history[0].state, ReviewState::Relevant);
        assert_eq!(history[1].state, ReviewState::NotRelevant);
        assert_eq!(
            service.current_state(content).ok(),
            Some(ReviewState::NotRelevant)
        );
    }

    #[test]
    fn repeating_the_current_state_is_refused() {
        let (service, _, content) = with_alert(3, "una molotov");
        let Ok(()) = service.record(content, ReviewState::Relevant, &operator(), None, now())
        else {
            panic!("la prima decisione deve riuscire");
        };

        assert!(matches!(
            service.record(content, ReviewState::Relevant, &operator(), None, later(60)),
            Err(ServiceError::ReviewStateUnchanged { .. })
        ));
    }

    #[test]
    fn a_decided_content_leaves_the_queue_and_one_in_progress_stays() {
        // Un esame lasciato a meta' e' in coda quanto uno mai aperto:
        // nasconderlo lo farebbe perdere di vista.
        let (service, session, content) = with_alert(3, "una molotov");

        let Ok(()) = service.record(content, ReviewState::InReview, &operator(), None, now())
        else {
            panic!("la presa in carico deve riuscire");
        };
        let Ok(pending) = service.pending(session) else {
            panic!("la coda deve potersi leggere");
        };
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].state, Some(ReviewState::InReview));
        assert!(!pending[0].is_untouched());

        let Ok(()) = service.record(content, ReviewState::Relevant, &operator(), None, later(60))
        else {
            panic!("la conclusione deve riuscire");
        };
        assert_eq!(service.pending(session).map(|all| all.len()).ok(), Some(0));
    }

    #[test]
    fn every_decision_is_recorded_in_the_audit_without_the_note() {
        // La nota puo' contenere osservazioni sul contenuto: l'audit documenta
        // le azioni, non i dati su cui esse insistono.
        let (service, _, content) = with_alert(3, "una molotov");
        let Ok(()) = service.record(
            content,
            ReviewState::NotRelevant,
            &operator(),
            Some("osservazione riservata sul contenuto"),
            now(),
        ) else {
            panic!("la decisione deve riuscire");
        };

        let Ok(entries) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let Some(entry) = entries
            .iter()
            .find(|entry| entry.action.as_str() == "revisione_registrata")
        else {
            panic!("la voce deve essere presente");
        };
        let Some(detail) = entry.detail.as_ref() else {
            panic!("il dettaglio deve esserci");
        };
        assert_eq!(detail.as_str(), "not_relevant");
        assert!(
            !detail.as_str().contains("riservata"),
            "la nota non deve finire nell'audit"
        );
    }
}

//! Ciclo di vita del monitoraggio e stato di salute operativo.
//!
//! È la parte che l'operatore comanda: avviare un monitoraggio, sospendere gli
//! avvisi, riprenderli, arrestare. E la parte che l'operatore legge: in quale
//! stato è la sessione, se è operativa o ha anomalie, quanti contenuti ha
//! acquisito, quanti eventi attendono.
//!
//! # L'insieme dei comandi ammessi è calcolato qui
//!
//! Non nell'interfaccia. Un pulsante che avvia un monitoraggio già concluso è
//! una decisione di sicurezza, non un dettaglio grafico: dev'essere coperta da
//! un test. Il servizio restituisce le azioni **ammesse** e, per ciascuna
//! vietata, il **perché**; l'interfaccia si limita a mostrarle.
//!
//! # La semantica della pausa, dichiarata
//!
//! «Sospendi avvisi» **non** ferma l'acquisizione: la sessione continua a
//! ricevere e ad archiviare, e soltanto le notifiche tacciono. È la condizione
//! di chi rivede e non vuole essere interrotto. «Arresta» conclude la sessione
//! in modo ordinato. La distinzione è in ADR-0017 ed è ripetuta all'operatore
//! dove compie l'azione.

use lisi_core::model::NewAuditEntry;
use lisi_core::model::NewSession;
use lisi_core::model::acquisition_pause::{AcquisitionPause, may_pause, may_resume};
use lisi_core::model::dictionary::ResolvedDictionaryConfiguration;
use lisi_core::model::monitoring_account::{MonitoringAccount, OpenAccounts};
use lisi_core::model::reason::OperationalReason;
use lisi_core::model::schedule::{
    MissedStartReason, ScheduledStart, StartDecision, check_lead, decide,
};
use lisi_core::model::telegram_account::{AccountUuid, TelegramAccount};
use lisi_core::model::{SessionDuration, SessionState};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity, DisplayName};
use lisi_core::{SessionId, SourceId, Timestamp};
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};
use crate::wizard::WizardDuration;

/// Che cosa il wizard ha scelto, accanto ai termini risolti: le versioni dei
/// dizionari e le parole aggiunte a mano (FINAL-REVIEW-01, FR-049).
#[derive(Debug, Clone, Default)]
pub struct DictionaryChoice {
    /// Ogni dizionario con la versione che il monitoraggio userà.
    pub versions: Vec<(lisi_core::DictionaryId, lisi_core::DictionaryVersionId)>,
    /// Le parole aggiunte per questo monitoraggio.
    pub custom_terms: Vec<lisi_core::model::dictionary::SessionCustomTerm>,
}

/// L'account d'ufficio con cui un monitoraggio nasce (MULTI-ACCOUNT-02,
/// ADR-0173, decisione 3).
///
/// Si scrive una volta, accanto al monitoraggio, e non cambia: il monitoraggio
/// riceve soltanto ciò che arriva a quell'account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountBinding {
    /// L'identità stabile dell'account.
    pub uuid: AccountUuid,
    /// Il nome dell'account adesso, che resta con il monitoraggio.
    pub label: DisplayName,
}

impl AccountBinding {
    /// Il legame con l'account indicato.
    #[must_use]
    pub fn of(account: &TelegramAccount) -> Self {
        Self {
            uuid: account.uuid.clone(),
            label: account.label.clone(),
        }
    }
}

/// Le parole aggiunte, una sola volta per testo normalizzato e modalità.
///
/// Il wizard scarta un doppione solo se testo, modalità e livello coincidono:
/// «Bomba» e «bomba», o la stessa parola con due livelli, restano due voci.
/// Il risolutore le unisce in un termine solo con il livello più alto, e
/// l'archivio ne rifiuta la seconda (`UNIQUE (session_id, normalised,
/// match_mode)`): scriverle così com'erano faceva fallire l'avvio, e lasciava
/// una sessione pianificata senza configurazione (FINAL-REVIEW-01, revisione
/// finale del diff). Qui si fa ciò che fa il risolutore: resta la prima
/// grafia, con il livello più alto.
fn parole_distinte(
    parole: &[lisi_core::model::dictionary::SessionCustomTerm],
) -> Vec<lisi_core::model::dictionary::SessionCustomTerm> {
    let mut distinte: Vec<lisi_core::model::dictionary::SessionCustomTerm> = Vec::new();
    let mut chiavi: Vec<(String, lisi_core::model::dictionary::MatchMode)> = Vec::new();
    for parola in parole {
        let chiave = (
            lisi_core::model::dictionary::normalise_for_matching(parola.text.as_str()),
            parola.match_mode,
        );
        if let Some(posizione) = chiavi.iter().position(|nota| *nota == chiave) {
            if let Some(gia) = distinte.get_mut(posizione) {
                gia.suggested_level = gia.suggested_level.max(parola.suggested_level);
            }
        } else {
            chiavi.push(chiave);
            distinte.push(parola.clone());
        }
    }
    distinte
}

/// Azione del ciclo di vita di un monitoraggio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitoringAction {
    /// Avvia un monitoraggio pianificato.
    Start,
    /// Sospende gli avvisi: l'acquisizione continua, le notifiche no.
    SuspendAlerts,
    /// Riprende gli avvisi.
    Resume,
    /// Arresta il monitoraggio in modo ordinato.
    Stop,
}

impl MonitoringAction {
    /// Tutte le azioni, per l'interfaccia.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [Self::Start, Self::SuspendAlerts, Self::Resume, Self::Stop]
    }

    /// Stato verso cui l'azione porta la sessione.
    const fn target(self) -> SessionState {
        match self {
            Self::Start | Self::Resume => SessionState::Running,
            Self::SuspendAlerts => SessionState::Paused,
            Self::Stop => SessionState::Stopped,
        }
    }

    /// Se l'azione ha senso nello stato indicato.
    ///
    /// Non basta che la transizione verso `target` sia ammessa: «avvia» e
    /// «riprendi» portano entrambe a «in corso», ma la prima parte da un
    /// monitoraggio **pianificato** e la seconda da uno con gli **avvisi
    /// sospesi**. Distinguere lo stato di partenza è ciò che impedisce di
    /// offrire «riprendi avvisi» su una sessione mai avviata.
    const fn applies_to(self, state: SessionState) -> bool {
        match self {
            Self::Start => matches!(state, SessionState::Planned),
            Self::SuspendAlerts => matches!(state, SessionState::Running),
            Self::Resume => matches!(state, SessionState::Paused),
            Self::Stop => !state.is_final(),
        }
    }

    /// Identificatore stabile, usato dall'interfaccia nei comandi.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::SuspendAlerts => "suspend",
            Self::Resume => "resume",
            Self::Stop => "stop",
        }
    }

    /// Ricostruisce l'azione dal suo identificatore.
    #[must_use]
    pub fn from_identifier(raw: &str) -> Option<Self> {
        Self::all()
            .into_iter()
            .find(|action| action.as_str() == raw)
    }

    /// Etichetta mostrata sul comando.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Start => "Avvia",
            Self::SuspendAlerts => "Sospendi avvisi",
            Self::Resume => "Riprendi avvisi",
            Self::Stop => "Arresta",
        }
    }

    /// Azione registrata nell'audit.
    const fn audit_action(self) -> &'static str {
        match self {
            Self::Start => "monitoraggio_avviato",
            Self::SuspendAlerts => "avvisi_sospesi",
            Self::Resume => "monitoraggio_ripreso",
            Self::Stop => "monitoraggio_arrestato",
        }
    }
}

/// Stato di salute operativo di un monitoraggio.
///
/// Deriva da segnali reali — lo stato della sessione e le voci d'inbox fallite —
/// non è decorativo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    /// Pianificato, non ancora avviato.
    NotStarted,
    /// Operativo, senza anomalie.
    Operational,
    /// Operativo, ma con eventi falliti che richiedono attenzione.
    WithAnomalies,
    /// Avvisi sospesi: acquisizione in corso, notifiche tacitate.
    AlertsSuspended,
    /// Concluso perché la durata è trascorsa.
    Completed,
    /// Arrestato dall'operatore.
    Stopped,
}

impl HealthState {
    /// Descrizione mostrata all'operatore.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotStarted => "Pianificato",
            Self::Operational => "Operativo",
            Self::WithAnomalies => "Operativo con anomalie",
            Self::AlertsSuspended => "Avvisi sospesi",
            Self::Completed => "Concluso",
            Self::Stopped => "Arrestato",
        }
    }

    /// Se lo stato segnala una condizione da attenzionare.
    #[must_use]
    pub const fn is_attention(self) -> bool {
        matches!(self, Self::WithAnomalies)
    }

    fn derive(state: SessionState, inbox_failed: usize) -> Self {
        match state {
            SessionState::Planned => Self::NotStarted,
            SessionState::Running if inbox_failed > 0 => Self::WithAnomalies,
            SessionState::Running => Self::Operational,
            SessionState::Paused => Self::AlertsSuspended,
            SessionState::Completed => Self::Completed,
            SessionState::Stopped => Self::Stopped,
        }
    }
}

/// Un monitoraggio **in breve**: quel tanto che serve a elencarlo e a sceglierlo.
///
/// Con più monitoraggi (ADR-0065) la schermata deve poterli mostrare tutti e
/// lasciarne scegliere uno. Comporre una vista completa per ciascuno a ogni
/// ridisegno costerebbe, per ogni riga di elenco, le letture che servono a
/// mostrare **un** monitoraggio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitoringSummary {
    /// Sessione.
    pub session_id: SessionId,
    /// Nome del monitoraggio.
    pub label: String,
    /// Stato del ciclo di vita.
    pub state: SessionState,
}

/// Vista completa di un monitoraggio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitoringView {
    /// Sessione monitorata.
    pub session_id: SessionId,
    /// Nome del monitoraggio.
    pub label: String,
    /// Stato del ciclo di vita.
    pub state: SessionState,
    /// Stato di salute derivato.
    pub health: HealthState,
    /// Operatore che ha avviato la sessione.
    pub started_by: String,
    /// Istante di creazione.
    pub created_at: Timestamp,
    /// Istante del primo avvio, se avviata.
    pub started_at: Option<Timestamp>,
    /// Istante di conclusione, se conclusa.
    pub ended_at: Option<Timestamp>,
    /// Durata pianificata.
    pub duration: SessionDuration,
    /// Fonti configurate per la sessione.
    pub source_count: usize,
    /// Contenuti acquisiti e analizzati.
    pub contents_total: usize,
    /// Contenuti che hanno prodotto un alert.
    pub alerts_total: usize,
    /// Alert che attendono una decisione umana.
    pub pending_review: usize,
    /// Eventi in coda nell'inbox.
    pub inbox_pending: usize,
    /// Eventi falliti in modo permanente.
    pub inbox_failed: usize,
    /// Istante dell'ultimo checkpoint di ripresa.
    pub last_checkpoint: Option<Timestamp>,
    /// Azioni ammesse nello stato corrente.
    pub permitted: Vec<MonitoringAction>,
    /// L'inizio programmato, se il monitoraggio è stato programmato
    /// (SCHEDULE-01, ADR-0171).
    pub schedule: Option<ScheduledStart>,
    /// Le pause dell'acquisizione, dalla più vecchia (PAUSE-01, ADR-0172).
    pub pauses: Vec<AcquisitionPause>,
    /// Se adesso l'acquisizione si può mettere in pausa.
    pub can_pause_acquisition: bool,
    /// Se adesso l'acquisizione si può riprendere.
    pub can_resume_acquisition: bool,
}

impl MonitoringView {
    /// Lo stato da scrivere nella riga «Stato» della schermata.
    ///
    /// **La pausa dell'acquisizione viene prima dello stato** (COLLAUDO-FIX-01,
    /// CU01-004, DEC-509). Nell'archivio un monitoraggio in pausa resta «in
    /// corso», ma non acquisisce: la riga diceva «In corso» sopra la sezione
    /// che diceva la pausa, e chi guardava soltanto lo stato si sbagliava.
    #[must_use]
    pub fn state_label(&self) -> &'static str {
        if self.pauses.iter().any(AcquisitionPause::is_open) {
            "Acquisizione in pausa"
        } else {
            self.state.label()
        }
    }

    /// Se l'azione indicata è ammessa.
    #[must_use]
    pub fn allows(&self, action: MonitoringAction) -> bool {
        self.permitted.contains(&action)
    }

    /// Perché un'azione non è ammessa, quando non lo è.
    #[must_use]
    pub fn forbidden_reason(&self, action: MonitoringAction) -> Option<String> {
        if self.allows(action) {
            return None;
        }
        Some(String::from(match action {
            MonitoringAction::Start => "Il monitoraggio è già stato avviato o è concluso.",
            MonitoringAction::SuspendAlerts => {
                "Si possono sospendere gli avvisi solo di un monitoraggio in corso."
            }
            MonitoringAction::Resume => "Si riprende solo un monitoraggio con gli avvisi sospesi.",
            MonitoringAction::Stop => "Il monitoraggio è già concluso.",
        }))
    }
}

/// Un monitoraggio appena concluso perché la sua durata è trascorsa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConcludedMonitoring {
    /// Sessione conclusa.
    pub session_id: SessionId,
    /// Nome del monitoraggio, per l'annuncio sul live condiviso.
    pub label: String,
    /// La fine registrata: la scadenza pianificata, non l'istante del rilievo.
    pub ended_at: Timestamp,
}

/// Che cosa è successo a un inizio programmato giunto all'ora (SCHEDULE-01,
/// ADR-0171).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleOutcome {
    /// Partito all'istante detto.
    Started {
        /// Il monitoraggio.
        session_id: SessionId,
        /// Il suo nome, per l'annuncio sul live condiviso.
        label: String,
        /// L'inizio programmato.
        start_at: Timestamp,
        /// L'avvio vero.
        started_at: Timestamp,
    },
    /// Non partito: resta pianificato, con la ragione.
    Missed {
        /// Il monitoraggio.
        session_id: SessionId,
        /// Il suo nome.
        label: String,
        /// Perché.
        reason: MissedStartReason,
    },
}

/// Servizio del ciclo di vita del monitoraggio.
#[derive(Debug)]
pub struct MonitoringService {
    database: Database,
}

impl MonitoringService {
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
    #[must_use]
    pub fn into_database(self) -> Database {
        self.database
    }

    /// Crea e avvia un monitoraggio dalla composizione del wizard.
    ///
    /// La sessione nasce **pianificata** e viene subito avviata: un solo gesto
    /// dell'operatore la mette in corso. La configurazione risolta viene
    /// conservata come fotografia immutabile (ADR-0013).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se manca una fonte, se la scrittura non riesce, o
    /// se la configurazione non è coerente.
    #[allow(
        clippy::too_many_arguments,
        reason = "un avvio ha un nome, chi lo avvia, una durata, le fonti, i termini risolti, \
                  la scelta da cui vengono e l'istante; raggrupparli nasconderebbe che la \
                  scelta (FR-049) si scrive prima dei termini"
    )]
    pub fn begin(
        &mut self,
        label: DisplayName,
        actor: &Actor,
        duration: WizardDuration,
        source_ids: &[SourceId],
        configuration: Option<&ResolvedDictionaryConfiguration>,
        choice: &DictionaryChoice,
        now: Timestamp,
    ) -> ServiceResult<SessionId> {
        self.begin_on(
            None,
            label,
            actor,
            duration,
            source_ids,
            configuration,
            choice,
            now,
        )
    }

    /// Come [`Self::begin`], con l'account d'ufficio con cui il monitoraggio
    /// lavora (MULTI-ACCOUNT-02, ADR-0173, decisione 3).
    ///
    /// `None` è un monitoraggio senza account — dimostrativo, o avviato senza
    /// un account scelto —: riceve soltanto quando è aperto un account solo.
    ///
    /// # Errori
    ///
    /// Come [`Self::begin`], e un errore se il legame non si scrive.
    #[expect(
        clippy::too_many_arguments,
        reason = "gli argomenti dell'avvio, più l'account: raggrupparli \
                  nasconderebbe che l'account si sceglie come le fonti"
    )]
    pub fn begin_on(
        &mut self,
        account: Option<&AccountBinding>,
        label: DisplayName,
        actor: &Actor,
        duration: WizardDuration,
        source_ids: &[SourceId],
        configuration: Option<&ResolvedDictionaryConfiguration>,
        choice: &DictionaryChoice,
        now: Timestamp,
    ) -> ServiceResult<SessionId> {
        let session_id = self.create_planned(
            account,
            label,
            actor,
            duration,
            source_ids,
            configuration,
            choice,
            now,
        )?;

        // Dallo stato pianificato all'avvio: fissa `started_at`.
        self.database
            .update_session_state(session_id, SessionState::Running, now)?;
        self.audit(actor, MonitoringAction::Start, session_id, now)?;

        Ok(session_id)
    }

    /// Crea un monitoraggio **pianificato**, con la configurazione già
    /// fissata: la parte comune all'avvio di adesso e a quello programmato
    /// (SCHEDULE-01, ADR-0171).
    #[allow(
        clippy::too_many_arguments,
        reason = "gli argomenti dell'avvio, che questa funzione serve"
    )]
    fn create_planned(
        &mut self,
        account: Option<&AccountBinding>,
        label: DisplayName,
        actor: &Actor,
        duration: WizardDuration,
        source_ids: &[SourceId],
        configuration: Option<&ResolvedDictionaryConfiguration>,
        choice: &DictionaryChoice,
        now: Timestamp,
    ) -> ServiceResult<SessionId> {
        let session_id = self.database.insert_session(
            &NewSession {
                label,
                started_by: actor.clone(),
                duration: duration.to_session_duration(),
                source_ids: source_ids.to_vec(),
            },
            now,
        )?;

        // CHE COSA È STATO SCELTO, PRIMA DI CHE COSA NE È RISULTATO (FINAL-REVIEW-01,
        // FR-049). Le versioni dei dizionari e le parole aggiunte si scrivono
        // prima della configurazione risolta, perché dopo l'archivio le rifiuta:
        // fino al 2026-10-04 non si scrivevano affatto, e ogni relazione
        // dichiarava «Versioni di dizionario in vigore: nessuna.».
        if configuration.is_some() {
            self.database
                .set_session_dictionary_selection(session_id, &choice.versions, now)?;
            self.database.insert_session_custom_terms(
                session_id,
                &parole_distinte(&choice.custom_terms),
                now,
            )?;
        }
        if let Some(configuration) = configuration {
            self.database
                .save_resolved_configuration(session_id, configuration)?;
        }
        // L'ACCOUNT, UNA VOLTA (ADR-0173, decisione 3): prima che il
        // monitoraggio parta, così il primo aggiornamento lo trova già legato.
        // La riga d'audit lo nomina (F-019).
        if let Some(account) = account {
            self.database
                .insert_session_account(session_id, &account.uuid, &account.label, now)?;
            self.audit_schedule(
                actor,
                "monitoraggio_legato_all_account",
                session_id,
                &format!("account «{}»", account.label.as_str()),
                now,
            )?;
        }
        Ok(session_id)
    }

    /// L'account con cui un monitoraggio lavora, se registrato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn account_of(&self, session_id: SessionId) -> ServiceResult<Option<MonitoringAccount>> {
        Ok(self.database.session_account(session_id)?)
    }

    /// Programma un monitoraggio che parte più tardi (SCHEDULE-01, ADR-0171).
    ///
    /// Il monitoraggio nasce pianificato, con la configurazione già fissata
    /// come in [`Self::begin`], e con l'inizio scritto nella sua riga
    /// (migrazione 0070). Parte da sé con [`Self::start_due`].
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::ScheduleRefused`] se l'inizio è a meno di
    /// un minuto o a più di sette giorni, e un errore se una scrittura non
    /// riesce.
    #[expect(
        clippy::too_many_arguments,
        reason = "gli stessi argomenti dell'avvio, più l'inizio: raggrupparli \
                  nasconderebbe che un monitoraggio programmato è lo stesso \
                  monitoraggio, soltanto più tardi"
    )]
    pub fn schedule(
        &mut self,
        label: DisplayName,
        actor: &Actor,
        duration: WizardDuration,
        source_ids: &[SourceId],
        configuration: Option<&ResolvedDictionaryConfiguration>,
        choice: &DictionaryChoice,
        start_at: Timestamp,
        now: Timestamp,
    ) -> ServiceResult<SessionId> {
        self.schedule_on(
            None,
            label,
            actor,
            duration,
            source_ids,
            configuration,
            choice,
            start_at,
            now,
        )
    }

    /// Come [`Self::schedule`], con l'account d'ufficio del monitoraggio: è
    /// quello che dovrà essere collegato all'ora detta (ADR-0173).
    ///
    /// # Errori
    ///
    /// Come [`Self::schedule`], e un errore se il legame non si scrive.
    #[expect(
        clippy::too_many_arguments,
        reason = "gli argomenti della programmazione, più l'account"
    )]
    pub fn schedule_on(
        &mut self,
        account: Option<&AccountBinding>,
        label: DisplayName,
        actor: &Actor,
        duration: WizardDuration,
        source_ids: &[SourceId],
        configuration: Option<&ResolvedDictionaryConfiguration>,
        choice: &DictionaryChoice,
        start_at: Timestamp,
        now: Timestamp,
    ) -> ServiceResult<SessionId> {
        check_lead(start_at, now).map_err(|rifiuto| ServiceError::ScheduleRefused {
            reason: rifiuto.sentence(),
        })?;
        let session_id = self.create_planned(
            account,
            label,
            actor,
            duration,
            source_ids,
            configuration,
            choice,
            now,
        )?;
        self.database
            .insert_session_schedule(session_id, start_at, actor, now)?;
        self.audit_schedule(
            actor,
            "monitoraggio_programmato",
            session_id,
            &format!("inizio programmato {}", start_at.to_readable_utc()),
            now,
        )?;
        Ok(session_id)
    }

    /// Decide gli inizi programmati giunti all'ora (ADR-0171, decisioni 4 e
    /// 5): parte chi è in orario con l'account collegato, e chi non lo è
    /// riceve un avvio mancato con la sua ragione, una volta sola.
    ///
    /// Un inizio che non si riesce a scrivere si riprova al giro successivo,
    /// e la tolleranza decide se allora è ancora in orario.
    ///
    /// # Errori
    ///
    /// Restituisce un errore soltanto se l'elenco degli inizi non si legge.
    pub fn start_due(
        &mut self,
        actor: &Actor,
        now: Timestamp,
        accounts: &OpenAccounts,
    ) -> ServiceResult<Vec<ScheduleOutcome>> {
        let mut esiti = Vec::new();
        for inizio in self.database.due_schedules(now)? {
            // IL SUO ACCOUNT, NON UNO QUALUNQUE (ADR-0173): un monitoraggio
            // legato all'account A non parte perché è collegato B. Un legame
            // che non si legge non si indovina: si riprova al giro dopo.
            let legato = match self.database.session_account(inizio.session_id) {
                Ok(legato) => legato,
                Err(errore) => {
                    tracing::warn!(
                        errore = %errore,
                        sessione = inizio.session_id.get(),
                        "account del monitoraggio non leggibile: si riprova al giro successivo"
                    );
                    continue;
                }
            };
            let account_ready =
                accounts.is_ready_for(legato.as_ref().map(|legame| &legame.account_uuid));
            let decisione = decide(inizio.start_at, now, account_ready);
            let esito = match decisione {
                StartDecision::NotYet => continue,
                StartDecision::Start => self
                    .database
                    .update_session_state(inizio.session_id, SessionState::Running, now)
                    .map_err(ServiceError::from)
                    .and_then(|()| {
                        self.audit_schedule(
                            actor,
                            "monitoraggio_avviato_come_programmato",
                            inizio.session_id,
                            &format!(
                                "programmato {}; avviato {}",
                                inizio.start_at.to_readable_utc(),
                                now.to_readable_utc()
                            ),
                            now,
                        )
                    }),
                StartDecision::Missed(ragione) => self
                    .database
                    .record_missed_start(inizio.session_id, now, ragione)
                    .map_err(ServiceError::from)
                    .and_then(|()| {
                        self.audit_schedule(
                            actor,
                            "avvio_programmato_mancato",
                            inizio.session_id,
                            &format!(
                                "programmato {}; {}",
                                inizio.start_at.to_readable_utc(),
                                ragione.as_str()
                            ),
                            now,
                        )
                    }),
            };
            if let Err(errore) = esito {
                tracing::warn!(
                    errore = errore.kind(),
                    sessione = inizio.session_id.get(),
                    "inizio programmato non deciso: si riprova al giro successivo"
                );
                continue;
            }
            let label = self
                .database
                .session(inizio.session_id)
                .map(|sessione| sessione.label.as_str().to_owned())
                .unwrap_or_default();
            esiti.push(match decisione {
                StartDecision::Missed(reason) => ScheduleOutcome::Missed {
                    session_id: inizio.session_id,
                    label,
                    reason,
                },
                StartDecision::Start | StartDecision::NotYet => ScheduleOutcome::Started {
                    session_id: inizio.session_id,
                    label,
                    start_at: inizio.start_at,
                    started_at: now,
                },
            });
        }
        Ok(esiti)
    }

    /// Registra nell'audit un fatto dell'avvio programmato.
    fn audit_schedule(
        &self,
        actor: &Actor,
        action: &str,
        session_id: SessionId,
        detail: &str,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new(action)?,
            entity: AuditEntity::try_new("session")?,
            entity_id: Some(session_id.get()),
            actor_mode: None,
            detail: Some(AuditDetail::try_new(detail)?),
            recorded_at: now,
        })?;
        Ok(())
    }

    /// L'elenco dei monitoraggi, in breve, dal più recente.
    ///
    /// # Perché non sono viste complete
    ///
    /// Perché una vista completa conta contenuti, avvisi, revisioni in attesa e
    /// coda: sono letture che servono a **mostrare un monitoraggio**, non a
    /// **elencarli**. Comporne una per ciascuno a ogni ridisegno costerebbe
    /// tutte quelle letture per righe che mostrano un nome e uno stato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn summaries(&self) -> ServiceResult<Vec<MonitoringSummary>> {
        let mut sessions = self.database.sessions()?;
        sessions.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right.id.cmp(&left.id))
        });

        Ok(sessions
            .into_iter()
            .map(|session| MonitoringSummary {
                session_id: session.id,
                label: session.label.as_str().to_owned(),
                state: session.state,
            })
            .collect())
    }

    /// Vista del monitoraggio più recente, se ne esiste uno.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se una lettura non riesce.
    pub fn latest_view(&self) -> ServiceResult<Option<MonitoringView>> {
        let mut sessions = self.database.sessions()?;
        sessions.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right.id.cmp(&left.id))
        });

        match sessions.first() {
            Some(session) => Ok(Some(self.view(session.id)?)),
            None => Ok(None),
        }
    }

    /// Vista di un monitoraggio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la sessione non esiste o se una lettura non
    /// riesce.
    pub fn view(&self, session_id: SessionId) -> ServiceResult<MonitoringView> {
        let session = self.database.session(session_id)?;
        let source_count = self.database.session_source_ids(session_id)?.len();
        let contents = self.database.session_contents(session_id)?;
        let alerts = self.database.session_alerts(session_id)?;

        let mut pending_review = 0;
        for alert in &alerts {
            let decided = self
                .database
                .latest_review(alert.content_id)?
                .is_some_and(|review| review.state.is_decided());
            if !decided {
                pending_review += 1;
            }
        }

        let inbox_pending = self.database.inbox_pending(session_id)?.len();
        let inbox_failed = self.database.inbox_failed_count(session_id)?;
        let last_checkpoint = self
            .database
            .session_checkpoint(session_id)?
            .map(|(_, at)| at);

        let permitted = permitted_actions(session.state);
        let health = HealthState::derive(session.state, inbox_failed);
        let schedule = self.database.session_schedule(session_id)?;
        // LA PAUSA VERA (PAUSE-01, ADR-0172): le pause, e se si può mettere o
        // togliere adesso. Lo decide il servizio, non la schermata.
        let pauses = self.database.acquisition_pauses(session_id)?;
        let aperta = pauses.iter().any(AcquisitionPause::is_open);
        let in_attesa = self.awaiting_decision()?.contains(&session_id);
        let can_pause_acquisition = may_pause(session.state, in_attesa, aperta).is_ok();
        let can_resume_acquisition = may_resume(aperta).is_ok() && !session.state.is_final();

        Ok(MonitoringView {
            session_id,
            label: session.label.as_str().to_owned(),
            state: session.state,
            health,
            started_by: session.started_by.as_str().to_owned(),
            created_at: session.created_at,
            started_at: session.started_at,
            ended_at: session.ended_at,
            duration: session.duration,
            source_count,
            contents_total: contents.len(),
            alerts_total: alerts.len(),
            pending_review,
            inbox_pending,
            inbox_failed,
            last_checkpoint,
            permitted,
            schedule,
            pauses,
            can_pause_acquisition,
            can_resume_acquisition,
        })
    }

    /// Esegue un'azione del ciclo di vita, se ammessa.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::MonitoringActionNotAllowed`] se l'azione non
    /// è ammessa nello stato corrente, e un errore se la scrittura non riesce.
    pub fn perform(
        &mut self,
        session_id: SessionId,
        action: MonitoringAction,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let session = self.database.session(session_id)?;
        if !permitted_actions(session.state).contains(&action) {
            return Err(ServiceError::MonitoringActionNotAllowed {
                action: action.as_str(),
                state: session.state.as_str(),
            });
        }

        self.database
            .update_session_state(session_id, action.target(), now)?;
        self.audit(actor, action, session_id, now)?;
        // CHI ARRESTA UN MONITORAGGIO INTERROTTO HA DECISO (ADR-0146): l'avviso
        // non torna alla prossima apertura. Il fatto dell'interruzione resta.
        if action == MonitoringAction::Stop {
            self.database
                .acknowledge_open_interruption(session_id, now)?;
            // E UNA PAUSA APERTA SI CHIUDE CON IL MONITORAGGIO (ADR-0172).
            self.close_open_pause(session_id, now, actor)?;
        }
        Ok(())
    }

    /// Mette in pausa l'acquisizione di un monitoraggio (PAUSE-01, ADR-0172).
    ///
    /// Durante la pausa il monitoraggio non riceve eventi, e il periodo è «non
    /// coperto» per decisione dell'operatore. Non è la sospensione degli
    /// avvisi, che non ferma niente (ADR-0017).
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::PauseRefused`] se il monitoraggio non
    /// acquisisce, aspetta una decisione o è già in pausa, e un errore se la
    /// scrittura non riesce.
    pub fn pause_acquisition(
        &mut self,
        session_id: SessionId,
        actor: &Actor,
        reason: &OperationalReason,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let session = self.database.session(session_id)?;
        let aperta = self.open_pause(session_id)?.is_some();
        let in_attesa = self.awaiting_decision()?.contains(&session_id);
        may_pause(session.state, in_attesa, aperta).map_err(|rifiuto| {
            ServiceError::PauseRefused {
                reason: rifiuto.sentence(),
            }
        })?;
        let audit = pause_audit(
            actor,
            "acquisizione_in_pausa",
            session_id,
            reason.as_str(),
            now,
        )?;
        self.database
            .insert_acquisition_pause(session_id, now, actor, reason, &audit)?;
        Ok(())
    }

    /// Riprende l'acquisizione di un monitoraggio in pausa (ADR-0172,
    /// decisione 6): il periodo di pausa resta non coperto, e il programma non
    /// lo recupera da sé.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::PauseRefused`] se non è in pausa, e un errore
    /// se la scrittura non riesce.
    pub fn resume_acquisition(
        &mut self,
        session_id: SessionId,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let aperta = self.open_pause(session_id)?;
        may_resume(aperta.is_some()).map_err(|rifiuto| ServiceError::PauseRefused {
            reason: rifiuto.sentence(),
        })?;
        let dettaglio = aperta.map_or_else(String::new, |pausa| {
            format!(
                "periodo non coperto dal {} al {}",
                pausa.paused_at.to_readable_utc(),
                now.to_readable_utc()
            )
        });
        let audit = pause_audit(actor, "acquisizione_ripresa", session_id, &dettaglio, now)?;
        self.database
            .resume_acquisition_pause(session_id, now, actor, &audit)?;
        Ok(())
    }

    /// Chiude la pausa aperta alla fine del monitoraggio, se ce n'è una
    /// (ADR-0172, decisione 5).
    fn close_open_pause(
        &mut self,
        session_id: SessionId,
        at: Timestamp,
        actor: &Actor,
    ) -> ServiceResult<()> {
        if self.open_pause(session_id)?.is_none() {
            return Ok(());
        }
        let audit = pause_audit(
            actor,
            "pausa_chiusa_alla_fine",
            session_id,
            "il monitoraggio si è concluso in pausa",
            at,
        )?;
        self.database
            .resume_acquisition_pause(session_id, at, actor, &audit)?;
        Ok(())
    }

    /// La pausa aperta di un monitoraggio, se ce n'è una.
    fn open_pause(&self, session_id: SessionId) -> ServiceResult<Option<AcquisitionPause>> {
        Ok(self
            .database
            .acquisition_pauses(session_id)?
            .into_iter()
            .find(AcquisitionPause::is_open))
    }

    /// I monitoraggi con l'acquisizione in pausa, che quindi non ricevono
    /// eventi (ADR-0172, decisione 3).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn paused_sessions(&self) -> ServiceResult<Vec<SessionId>> {
        Ok(self.database.paused_session_ids()?)
    }

    /// I monitoraggi che **aspettano una decisione** dopo un'interruzione, e
    /// che quindi non acquisiscono (E2E01-02, ADR-0146).
    ///
    /// Un monitoraggio che risultava in corso alla riapertura resta «in corso»
    /// nell'archivio — portarlo ad «arrestato» attribuirebbe un atto a una
    /// persona (ADR-0064) — ma **non deve riprendere da solo** quando l'accesso
    /// a Telegram torna: ricevere contenuti senza che nessuno l'abbia deciso è
    /// ripartire, e ADR-0064 lo vieta. Riprende quando l'operatore prende in
    /// carico l'interruzione; si chiude con «Arresta».
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn awaiting_decision(&self) -> ServiceResult<Vec<SessionId>> {
        Ok(self
            .database
            .open_interruptions()?
            .into_iter()
            .map(|aperta| aperta.session_id)
            .collect())
    }

    /// Conclude ogni monitoraggio la cui durata pianificata è trascorsa
    /// (INSTALLED-APP-E2E-01, E2E01-01; ADR-0145).
    ///
    /// # Perché la fine è la scadenza e non `now`
    ///
    /// Perché il monitoraggio è durato quanto l'operatore ha deciso, non quanto
    /// il programma ha impiegato ad accorgersene: se la postazione era spenta,
    /// sospesa o il programma chiuso, `now` può essere ore dopo. La fine
    /// registrata è `avvio + durata`; l'audit registra **anche** quando la
    /// conclusione è stata rilevata, così le due cose restano distinte.
    ///
    /// # Perché va chiamata prima di ingerire
    ///
    /// Perché nulla deve essere attribuito a un monitoraggio dopo la sua
    /// scadenza: chi ingerisce all'istante `now` chiama prima questa funzione
    /// con lo stesso `now`, e la sessione scaduta non è più fra quelle che
    /// acquisiscono.
    ///
    /// Restituisce le sessioni concluse in questa chiamata, con la fine
    /// registrata. Una sessione che non si riesce a concludere non ferma le
    /// altre: l'errore si registra e si riprova al giro successivo.
    ///
    /// # Errori
    ///
    /// Restituisce un errore soltanto se l'elenco delle scadute non si legge.
    pub fn conclude_due(
        &mut self,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<Vec<ConcludedMonitoring>> {
        let mut concluse = Vec::new();
        for session in self.database.due_sessions(now)? {
            let Some(fine) = session.planned_end() else {
                continue;
            };
            // La fine non precede l'avvio e non segue `now`: un orologio
            // spostato indietro non deve scrivere una fine nel futuro.
            let fine = if fine.as_millis() > now.as_millis() {
                now
            } else {
                fine
            };
            let esito = self
                .database
                .update_session_state(session.id, SessionState::Completed, fine)
                .map_err(ServiceError::from)
                .and_then(|()| self.audit_conclusion(actor, session.id, fine, now))
                // La durata non si allunga in pausa: la pausa si chiude alla
                // fine prevista (ADR-0172, decisione 5).
                .and_then(|()| self.close_open_pause(session.id, fine, actor));
            match esito {
                Ok(()) => concluse.push(ConcludedMonitoring {
                    session_id: session.id,
                    label: session.label.as_str().to_owned(),
                    ended_at: fine,
                }),
                Err(errore) => tracing::warn!(
                    errore = errore.kind(),
                    sessione = session.id.get(),
                    "monitoraggio scaduto non concluso: si riprova al giro successivo"
                ),
            }
        }
        Ok(concluse)
    }

    /// Registra nell'audit la conclusione per durata, con la fine e l'istante
    /// in cui è stata rilevata.
    fn audit_conclusion(
        &self,
        actor: &Actor,
        session_id: SessionId,
        fine: Timestamp,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let dettaglio = format!(
            "conclusa; fine prevista {}; vista il {}",
            fine.to_readable_utc(),
            now.to_readable_utc()
        );
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("monitoraggio_concluso_per_durata")?,
            entity: AuditEntity::try_new("session")?,
            entity_id: Some(session_id.get()),
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&dettaglio)?),
            recorded_at: now,
        })?;
        Ok(())
    }

    /// Registra un'azione del ciclo di vita nell'audit.
    ///
    /// La modalità operativa non è registrata: il servizio non la conosce, e
    /// inventarla sarebbe peggio che dichiararla assente.
    fn audit(
        &self,
        actor: &Actor,
        action: MonitoringAction,
        session_id: SessionId,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new(action.audit_action())?,
            entity: AuditEntity::try_new("session")?,
            entity_id: Some(session_id.get()),
            actor_mode: None,
            detail: Some(AuditDetail::try_new(action.target().as_str())?),
            recorded_at: now,
        })?;
        Ok(())
    }
}

/// La riga d'audit di un atto sulla pausa dell'acquisizione (PAUSE-01).
fn pause_audit(
    actor: &Actor,
    action: &str,
    session_id: SessionId,
    detail: &str,
    now: Timestamp,
) -> ServiceResult<NewAuditEntry> {
    Ok(NewAuditEntry {
        actor: actor.clone(),
        action: AuditAction::try_new(action)?,
        entity: AuditEntity::try_new("session")?,
        entity_id: Some(session_id.get()),
        actor_mode: None,
        detail: if detail.is_empty() {
            None
        } else {
            Some(AuditDetail::try_new(detail)?)
        },
        recorded_at: now,
    })
}

/// Azioni ammesse in uno stato, dal ciclo di vita del dominio.///
/// Deriva da `SessionState::can_transition_to`: l'interfaccia non decide che
/// cosa sia ammesso, lo legge dal dominio.
fn permitted_actions(state: SessionState) -> Vec<MonitoringAction> {
    MonitoringAction::all()
        .into_iter()
        // Sia la precondizione sullo stato di partenza sia l'ammissibilità della
        // transizione: la prima distingue «avvia» da «riprendi», la seconda è la
        // garanzia del dominio.
        .filter(|action| action.applies_to(state) && state.can_transition_to(action.target()))
        .collect()
}

#[cfg(test)]
mod tests {
    use lisi_core::model::dictionary::{
        ConfigurationResolver, MatchMode, ResolvedDictionaryConfiguration, TermProvenance,
    };
    use lisi_core::model::schedule::MissedStartReason;
    use lisi_core::model::{NewSource, SessionState, SourceKind};
    use lisi_core::text::{
        Actor, DisplayName, LanguageTag, SourceIdentifier, TermCategory, TermText,
    };
    use lisi_core::{SessionId, SourceId, Timestamp};

    use super::{HealthState, MonitoringAction, MonitoringService};
    use crate::error::ServiceError;
    use crate::sources::open_in_memory_database;
    use crate::wizard::WizardDuration;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn later(seconds: i64) -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000 + seconds * 1_000)
    }

    fn operator() -> Actor {
        let Ok(actor) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        actor
    }

    fn label(text: &str) -> DisplayName {
        let Ok(value) = DisplayName::try_new(text) else {
            panic!("l'etichetta di prova deve essere valida");
        };
        value
    }

    fn configuration() -> ResolvedDictionaryConfiguration {
        let mut resolver = ConfigurationResolver::new();
        let (Ok(text), Ok(category), Ok(language)) = (
            TermText::try_new("molotov"),
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
            3,
            TermProvenance::ad_hoc(),
        ) else {
            panic!("il termine deve essere accettato");
        };
        resolver.finish()
    }

    /// Servizio con una fonte configurata, e il suo identificatore.
    fn fixture() -> (MonitoringService, SourceId) {
        let Ok(database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        let (Ok(identifier), Ok(title)) = (
            SourceIdentifier::try_new("-1001"),
            DisplayName::try_new("Canale di prova"),
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
        (MonitoringService::new(database), source_id)
    }

    /// Programma un monitoraggio di trenta minuti che parte fra due minuti.
    fn programmato(service: &mut MonitoringService, source_id: SourceId) -> SessionId {
        let Ok(session_id) = service.schedule(
            label("Programmato"),
            &operator(),
            WizardDuration::Preset(1_800),
            &[source_id],
            Some(&configuration()),
            &super::DictionaryChoice::default(),
            later(120),
            now(),
        ) else {
            panic!("la programmazione deve riuscire");
        };
        session_id
    }

    /// Un account solo aperto, collegato o no: la situazione d'un monitoraggio
    /// senza account.
    fn pronto(collegato: bool) -> lisi_core::model::monitoring_account::OpenAccounts {
        let mut aperti = lisi_core::model::monitoring_account::OpenAccounts::none();
        aperti.add(
            lisi_core::model::AccountUuid::from_bytes([0xc3; 16]),
            collegato,
        );
        aperti
    }

    /// **Un monitoraggio programmato su un account parte soltanto se è
    /// collegato quell'account, non un altro; il legame si scrive con la sua
    /// riga d'audit** (MULTI-ACCOUNT-02 parte 2, ADR-0173, criteri 2 e 5;
    /// prova negativa: lo stato di un account qualunque al posto del suo →
    /// rossa).
    #[test]
    fn un_programmato_parte_soltanto_con_il_suo_account() {
        use lisi_core::model::AccountUuid;
        use lisi_core::model::monitoring_account::OpenAccounts;

        let (mut service, source_id) = fixture();
        let (primo, secondo) = (
            AccountUuid::from_bytes([0xa1; 16]),
            AccountUuid::from_bytes([0xb2; 16]),
        );
        let legame = super::AccountBinding {
            uuid: primo.clone(),
            label: label("Ufficio A"),
        };
        let Ok(session_id) = service.schedule_on(
            Some(&legame),
            label("Programmato su A"),
            &operator(),
            WizardDuration::Preset(1_800),
            &[source_id],
            Some(&configuration()),
            &super::DictionaryChoice::default(),
            later(120),
            now(),
        ) else {
            panic!("la programmazione deve riuscire");
        };
        let Ok(Some(letto)) = service.account_of(session_id) else {
            panic!("il legame si rilegge");
        };
        assert_eq!(letto.account_uuid, primo);
        assert_eq!(voci(&service, "monitoraggio_legato_all_account"), 1);

        // All'ora detta è collegato soltanto B: per A l'avvio è mancato.
        let mut aperti = OpenAccounts::none();
        aperti.add(primo, false);
        aperti.add(secondo, true);
        let Ok(esiti) = service.start_due(&operator(), later(120), &aperti) else {
            panic!("la decisione deve riuscire");
        };
        assert!(
            matches!(
                esiti.as_slice(),
                [super::ScheduleOutcome::Missed {
                    reason: MissedStartReason::AccountNotConnected,
                    ..
                }]
            ),
            "un altro account collegato non fa partire il monitoraggio di A: {esiti:?}"
        );
    }

    /// Quante voci d'audit portano quell'azione.
    fn voci(service: &MonitoringService, azione: &str) -> usize {
        service.database().audit_entries().map_or(0, |voci| {
            voci.iter()
                .filter(|voce| voce.action.as_str() == azione)
                .count()
        })
    }

    fn motivo() -> lisi_core::model::reason::OperationalReason {
        let Ok(motivo) =
            lisi_core::model::reason::OperationalReason::try_new("Riunione d'ufficio fino alle 15")
        else {
            panic!("il motivo di prova deve essere valido");
        };
        motivo
    }

    /// **La pausa ferma l'acquisizione, si riprende, e il suo periodo è non
    /// coperto con il motivo** (PAUSE-01, ADR-0172, criteri 2 e 4; prova
    /// negativa: la pausa che non esclude il monitoraggio → rossa).
    #[test]
    fn la_pausa_ferma_l_acquisizione_e_si_riprende() {
        let (mut service, source_id) = fixture();
        let Ok(session_id) = service.begin(
            label("M"),
            &operator(),
            WizardDuration::Manual,
            &[source_id],
            None,
            &super::DictionaryChoice::default(),
            now(),
        ) else {
            panic!("l'avvio deve riuscire");
        };
        // Gli avvisi sospesi non sono una pausa, e si può mettere in pausa lo
        // stesso.
        let Ok(()) = service.perform(
            session_id,
            MonitoringAction::SuspendAlerts,
            &operator(),
            later(5),
        ) else {
            panic!("la sospensione deve riuscire");
        };
        let Ok(()) = service.pause_acquisition(session_id, &operator(), &motivo(), later(10))
        else {
            panic!("la pausa deve riuscire");
        };
        assert_eq!(service.paused_sessions().ok(), Some(vec![session_id]));
        let Ok(vista) = service.view(session_id) else {
            panic!("la vista deve leggersi");
        };
        assert!(!vista.can_pause_acquisition);
        assert!(vista.can_resume_acquisition);
        // LA RIGA «STATO» DICE LA PAUSA (COLLAUDO-FIX-01, CU01-004, DEC-509):
        // nel collaudo restava «In corso» sopra la sezione che diceva la pausa.
        assert_eq!(vista.state_label(), "Acquisizione in pausa");
        assert!(matches!(
            service.pause_acquisition(session_id, &operator(), &motivo(), later(11)),
            Err(ServiceError::PauseRefused { .. })
        ));

        let Ok(()) = service.resume_acquisition(session_id, &operator(), later(70)) else {
            panic!("la ripresa deve riuscire");
        };
        let Ok(ripresa) = service.view(session_id) else {
            panic!("la vista deve leggersi");
        };
        assert_eq!(ripresa.state_label(), ripresa.state.label());
        assert_eq!(service.paused_sessions().ok(), Some(Vec::new()));
        assert!(matches!(
            service.resume_acquisition(session_id, &operator(), later(71)),
            Err(ServiceError::PauseRefused { .. })
        ));
        assert_eq!(voci(&service, "acquisizione_in_pausa"), 1);
        assert_eq!(voci(&service, "acquisizione_ripresa"), 1);

        let Ok(copertura) =
            crate::coverage::for_monitoring(service.database(), session_id, later(100))
        else {
            panic!("la copertura deve leggersi");
        };
        let a_40 = copertura
            .overall
            .intervals()
            .iter()
            .find(|tratto| tratto.from <= later(40) && later(40) < tratto.to)
            .map(|tratto| tratto.state);
        assert_eq!(
            a_40,
            Some(lisi_core::model::coverage::CoverageState::NotCovered(
                lisi_core::model::coverage::NotCoveredReason::Paused
            ))
        );
    }

    /// **La pausa si chiude con il monitoraggio, all'arresto o alla fine
    /// prevista; un pianificato non si mette in pausa** (criteri 1 e 5; prova
    /// negativa: la pausa lasciata aperta alla fine → rossa).
    #[test]
    fn la_pausa_si_chiude_con_il_monitoraggio() {
        let (mut service, source_id) = fixture();
        let Ok(a_tempo) = service.begin(
            label("Trenta minuti"),
            &operator(),
            WizardDuration::Preset(1_800),
            &[source_id],
            None,
            &super::DictionaryChoice::default(),
            now(),
        ) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = service.pause_acquisition(a_tempo, &operator(), &motivo(), later(100)) else {
            panic!("la pausa deve riuscire");
        };
        let Ok(concluse) = service.conclude_due(&operator(), later(2_000)) else {
            panic!("la scadenza deve leggersi");
        };
        assert_eq!(concluse.len(), 1, "la pausa non allunga la durata");
        let Ok(pause) = service.database().acquisition_pauses(a_tempo) else {
            panic!("le pause devono leggersi");
        };
        assert_eq!(
            pause[0].resumed_at,
            Some(later(1_800)),
            "chiusa alla fine prevista"
        );

        let Ok(arrestato) = service.begin(
            label("Manuale"),
            &operator(),
            WizardDuration::Manual,
            &[source_id],
            None,
            &super::DictionaryChoice::default(),
            later(10),
        ) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = service.pause_acquisition(arrestato, &operator(), &motivo(), later(20)) else {
            panic!("la pausa deve riuscire");
        };
        let Ok(()) = service.perform(arrestato, MonitoringAction::Stop, &operator(), later(30))
        else {
            panic!("l'arresto deve riuscire");
        };
        assert_eq!(service.paused_sessions().ok(), Some(Vec::new()));
        let Ok(vista) = service.view(arrestato) else {
            panic!("la vista deve leggersi");
        };
        assert!(!vista.can_pause_acquisition && !vista.can_resume_acquisition);

        let pianificato = programmato(&mut service, source_id);
        assert!(matches!(
            service.pause_acquisition(pianificato, &operator(), &motivo(), later(40)),
            Err(ServiceError::PauseRefused { .. })
        ));
    }

    /// **Un monitoraggio programmato resta pianificato e parte all'istante
    /// detto, con la fine dall'avvio** (SCHEDULE-01, ADR-0171, criterio 3).
    #[test]
    fn un_monitoraggio_programmato_parte_all_istante_detto() {
        let (mut service, source_id) = fixture();
        let session_id = programmato(&mut service, source_id);
        let Ok(vista) = service.view(session_id) else {
            panic!("la vista deve leggersi");
        };
        assert_eq!(vista.state, SessionState::Planned);
        assert_eq!(
            vista.schedule.as_ref().map(|s| s.start_at),
            Some(later(120))
        );
        assert_eq!(voci(&service, "monitoraggio_programmato"), 1);

        assert_eq!(
            service
                .start_due(&operator(), later(119), &pronto(true))
                .ok(),
            Some(Vec::new()),
            "un secondo prima non parte"
        );
        let Ok(esiti) = service.start_due(&operator(), later(120), &pronto(true)) else {
            panic!("la decisione deve riuscire");
        };
        assert_eq!(
            esiti,
            vec![super::ScheduleOutcome::Started {
                session_id,
                label: String::from("Programmato"),
                start_at: later(120),
                started_at: later(120),
            }]
        );
        let Ok(vista) = service.view(session_id) else {
            panic!("la vista deve leggersi");
        };
        assert_eq!(vista.state, SessionState::Running);
        assert_eq!(vista.started_at, Some(later(120)));
        assert_eq!(voci(&service, "monitoraggio_avviato_come_programmato"), 1);
        assert_eq!(
            service
                .start_due(&operator(), later(121), &pronto(true))
                .ok(),
            Some(Vec::new())
        );

        // La fine è l'avvio più la durata.
        let Ok(concluse) = service.conclude_due(&operator(), later(120 + 1_800)) else {
            panic!("la scadenza deve leggersi");
        };
        assert_eq!(concluse.len(), 1);
        assert_eq!(concluse[0].ended_at, later(120 + 1_800));
    }

    /// **Un avvio mancato si dice con la ragione, una volta, e non si recupera
    /// da sé** (criterio 3; prova negativa: un avvio in ritardo che parte
    /// lo stesso → rossa).
    #[test]
    fn un_avvio_mancato_si_dice_e_non_si_recupera() {
        let (mut service, source_id) = fixture();
        let chiuso = programmato(&mut service, source_id);
        let Ok(esiti) = service.start_due(&operator(), later(120 + 61), &pronto(true)) else {
            panic!("la decisione deve riuscire");
        };
        assert_eq!(
            esiti,
            vec![super::ScheduleOutcome::Missed {
                session_id: chiuso,
                label: String::from("Programmato"),
                reason: MissedStartReason::ProgramClosed,
            }]
        );
        let Ok(vista) = service.view(chiuso) else {
            panic!("la vista deve leggersi");
        };
        assert_eq!(vista.state, SessionState::Planned, "resta pianificato");
        assert_eq!(
            vista.schedule.and_then(|s| s.missed).map(|m| m.reason),
            Some(MissedStartReason::ProgramClosed)
        );
        assert_eq!(
            service
                .start_due(&operator(), later(600), &pronto(true))
                .ok(),
            Some(Vec::new()),
            "il programma non lo avvia più da sé"
        );
        assert_eq!(voci(&service, "avvio_programmato_mancato"), 1);
        // A mano si avvia.
        let Ok(()) = service.perform(chiuso, MonitoringAction::Start, &operator(), later(700))
        else {
            panic!("l'avvio a mano deve riuscire");
        };

        // L'account non collegato all'istante detto.
        let senza_account = programmato(&mut service, source_id);
        let Ok(esiti) = service.start_due(&operator(), later(130), &pronto(false)) else {
            panic!("la decisione deve riuscire");
        };
        assert_eq!(
            esiti,
            vec![super::ScheduleOutcome::Missed {
                session_id: senza_account,
                label: String::from("Programmato"),
                reason: MissedStartReason::AccountNotConnected,
            }]
        );
    }

    /// **Un inizio troppo vicino o troppo lontano non crea nulla; un
    /// monitoraggio programmato si annulla** (criteri 2 e 3).
    #[test]
    fn un_inizio_fuori_misura_non_crea_nulla_e_uno_programmato_si_annulla() {
        let (mut service, source_id) = fixture();
        for inizio in [later(30), later(8 * 86_400)] {
            assert!(matches!(
                service.schedule(
                    label("Fuori misura"),
                    &operator(),
                    WizardDuration::Manual,
                    &[source_id],
                    None,
                    &super::DictionaryChoice::default(),
                    inizio,
                    now(),
                ),
                Err(ServiceError::ScheduleRefused { .. })
            ));
        }
        assert_eq!(service.summaries().map(|v| v.len()).ok(), Some(0));

        let annullato = programmato(&mut service, source_id);
        let Ok(()) = service.perform(annullato, MonitoringAction::Stop, &operator(), later(60))
        else {
            panic!("l'annullamento deve riuscire");
        };
        assert_eq!(
            service
                .start_due(&operator(), later(120), &pronto(true))
                .ok(),
            Some(Vec::new()),
            "un monitoraggio annullato non parte"
        );
    }

    #[test]
    fn beginning_a_monitoring_creates_a_running_session() {
        let (mut service, source_id) = fixture();
        let Ok(session_id) = service.begin(
            label("Monitoraggio di prova"),
            &operator(),
            WizardDuration::Preset(3_600),
            &[source_id],
            Some(&configuration()),
            &super::DictionaryChoice::default(),
            now(),
        ) else {
            panic!("l'avvio deve riuscire");
        };

        let Ok(view) = service.view(session_id) else {
            panic!("la vista deve potersi leggere");
        };
        assert_eq!(view.state, SessionState::Running);
        assert_eq!(view.health, HealthState::Operational);
        assert_eq!(view.source_count, 1);
        assert!(view.started_at.is_some());

        // L'avvio e' nell'audit.
        let Ok(audit) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert!(
            audit
                .iter()
                .any(|entry| entry.action.as_str() == "monitoraggio_avviato")
        );
    }

    #[test]
    fn the_permitted_actions_follow_the_lifecycle() {
        let (mut service, source_id) = fixture();
        let Ok(session_id) = service.begin(
            label("M"),
            &operator(),
            WizardDuration::Manual,
            &[source_id],
            None,
            &super::DictionaryChoice::default(),
            now(),
        ) else {
            panic!("l'avvio deve riuscire");
        };

        // In corso: si possono sospendere gli avvisi e arrestare, non avviare.
        let Ok(view) = service.view(session_id) else {
            panic!("la vista deve potersi leggere");
        };
        assert!(view.allows(MonitoringAction::SuspendAlerts));
        assert!(view.allows(MonitoringAction::Stop));
        assert!(!view.allows(MonitoringAction::Start));
        assert!(!view.allows(MonitoringAction::Resume));
        assert!(view.forbidden_reason(MonitoringAction::Start).is_some());

        // Sospesi gli avvisi: si riprende o si arresta.
        let Ok(()) = service.perform(
            session_id,
            MonitoringAction::SuspendAlerts,
            &operator(),
            later(1),
        ) else {
            panic!("la sospensione deve riuscire");
        };
        let Ok(view) = service.view(session_id) else {
            panic!("la vista deve potersi leggere");
        };
        assert_eq!(view.state, SessionState::Paused);
        assert_eq!(view.health, HealthState::AlertsSuspended);
        assert!(view.allows(MonitoringAction::Resume));
        assert!(!view.allows(MonitoringAction::SuspendAlerts));
    }

    #[test]
    fn a_forbidden_action_is_refused_with_its_reason() {
        let (mut service, source_id) = fixture();
        let Ok(session_id) = service.begin(
            label("M"),
            &operator(),
            WizardDuration::Manual,
            &[source_id],
            None,
            &super::DictionaryChoice::default(),
            now(),
        ) else {
            panic!("l'avvio deve riuscire");
        };

        // Arresta, poi tenta di sospendere: non ammesso su una sessione conclusa.
        let Ok(()) = service.perform(session_id, MonitoringAction::Stop, &operator(), later(1))
        else {
            panic!("l'arresto deve riuscire");
        };
        assert!(matches!(
            service.perform(
                session_id,
                MonitoringAction::SuspendAlerts,
                &operator(),
                later(2)
            ),
            Err(ServiceError::MonitoringActionNotAllowed { .. })
        ));

        let Ok(view) = service.view(session_id) else {
            panic!("la vista deve potersi leggere");
        };
        assert_eq!(view.state, SessionState::Stopped);
        assert_eq!(view.health, HealthState::Stopped);
        // Da uno stato terminale nessuna azione e' ammessa.
        assert!(view.permitted.is_empty());
    }

    #[test]
    fn a_planned_session_offers_start_and_stop_but_not_resume() {
        // La regressione della verifica a vista: «avvia» e «riprendi» portano
        // entrambe a «in corso», e per un attimo il monitoraggio pianificato
        // offriva «riprendi avvisi» — un comando che non ha senso su una
        // sessione mai avviata.
        use lisi_core::model::{NewSession, SessionDuration};

        let (service, source_id) = fixture();
        let mut database = service.into_database();
        let Ok(session_id) = database.insert_session(
            &NewSession {
                label: label("Pianificato"),
                started_by: operator(),
                duration: SessionDuration::Manual,
                source_ids: vec![source_id],
            },
            now(),
        ) else {
            panic!("la sessione deve potersi creare");
        };
        let service = MonitoringService::new(database);

        let Ok(view) = service.view(session_id) else {
            panic!("la vista deve potersi leggere");
        };
        assert_eq!(view.state, SessionState::Planned);
        assert_eq!(view.health, HealthState::NotStarted);
        assert!(view.allows(MonitoringAction::Start));
        assert!(view.allows(MonitoringAction::Stop));
        assert!(
            !view.allows(MonitoringAction::Resume),
            "non c'e' nulla da riprendere"
        );
        assert!(!view.allows(MonitoringAction::SuspendAlerts));
    }

    #[test]
    fn the_latest_view_is_the_most_recent_session() {
        let (mut service, source_id) = fixture();
        let Ok(_first) = service.begin(
            label("Primo"),
            &operator(),
            WizardDuration::Manual,
            &[source_id],
            None,
            &super::DictionaryChoice::default(),
            now(),
        ) else {
            panic!("il primo avvio deve riuscire");
        };
        let Ok(second) = service.begin(
            label("Secondo"),
            &operator(),
            WizardDuration::Manual,
            &[source_id],
            None,
            &super::DictionaryChoice::default(),
            later(10),
        ) else {
            panic!("il secondo avvio deve riuscire");
        };

        let Ok(Some(view)) = service.latest_view() else {
            panic!("la vista piu' recente deve esistere");
        };
        assert_eq!(view.session_id, second);
        assert_eq!(view.label, "Secondo");
    }

    #[test]
    fn without_any_session_there_is_nothing_to_show() {
        let (service, _) = fixture();
        assert!(
            service.latest_view().ok().flatten().is_none(),
            "senza sessioni la vista e' vuota, e la schermata lo dira'"
        );
    }

    /// **E2E01-01, con l'orologio in mano alla prova.** Un monitoraggio di 30
    /// minuti è ancora in corso a 29:59, è concluso a 30:00, e la fine
    /// registrata è la scadenza anche se il rilievo avviene 25 minuti dopo —
    /// la sessione 2 del collaudo, ancora «In corso» a 55 minuti.
    #[test]
    fn una_durata_personalizzata_si_conclude_alla_sua_fine_esatta() {
        // ADR-0150: 2 ore e 15 minuti, scelte a mano, con la regola di
        // ADR-0145. L'archivio la conserva come personalizzata.
        let (mut service, source_id) = fixture();
        let Some(durata) = WizardDuration::custom(2, 15) else {
            panic!("la durata di prova è nei limiti");
        };
        let Ok(session_id) = service.begin(
            label("Durata scelta"),
            &operator(),
            durata,
            &[source_id],
            None,
            &super::DictionaryChoice::default(),
            now(),
        ) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(vista) = service.view(session_id) else {
            panic!("la vista deve potersi leggere");
        };
        assert_eq!(
            vista.duration,
            lisi_core::model::SessionDuration::Custom { seconds: 8_100 }
        );

        assert!(
            service
                .conclude_due(&operator(), later(8_099))
                .is_ok_and(|v| v.is_empty()),
            "un secondo prima della fine è in corso"
        );
        let Ok(concluse) = service.conclude_due(&operator(), later(8_100)) else {
            panic!("il controllo della scadenza deve riuscire");
        };
        assert_eq!(concluse.len(), 1);
        assert_eq!(concluse[0].ended_at, later(8_100), "la fine è esatta");
    }

    #[test]
    fn un_monitoraggio_a_tempo_si_conclude_alla_scadenza() {
        let (mut service, source_id) = fixture();
        let Ok(session_id) = service.begin(
            label("Trenta minuti"),
            &operator(),
            WizardDuration::Preset(1_800),
            &[source_id],
            None,
            &super::DictionaryChoice::default(),
            now(),
        ) else {
            panic!("l'avvio deve riuscire");
        };

        let Ok(nessuna) = service.conclude_due(&operator(), later(1_799)) else {
            panic!("il controllo della scadenza deve riuscire");
        };
        assert!(nessuna.is_empty(), "a 29:59 il monitoraggio e' in corso");

        let Ok(concluse) = service.conclude_due(&operator(), later(3_300)) else {
            panic!("il controllo della scadenza deve riuscire");
        };
        assert_eq!(concluse.len(), 1);
        assert_eq!(concluse[0].session_id, session_id);
        assert_eq!(concluse[0].ended_at, later(1_800));

        let Ok(view) = service.view(session_id) else {
            panic!("la vista deve potersi leggere");
        };
        assert_eq!(view.state, SessionState::Completed);
        assert_eq!(view.health, HealthState::Completed);
        assert_eq!(view.ended_at, Some(later(1_800)), "la fine e' la scadenza");
        assert!(view.permitted.is_empty());

        // Una seconda chiamata non conclude di nuovo.
        assert!(
            service
                .conclude_due(&operator(), later(9_999))
                .is_ok_and(|v| v.is_empty())
        );

        // L'audit dice la fine e quando e' stata rilevata.
        let Ok(audit) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let Some(voce) = audit
            .iter()
            .find(|entry| entry.action.as_str() == "monitoraggio_concluso_per_durata")
        else {
            panic!("la conclusione deve essere nell'audit");
        };
        assert_eq!(voce.recorded_at, later(3_300));
        let dettaglio = voce.detail.as_ref().map_or("", |d| d.as_str());
        assert!(
            dettaglio.contains(&later(1_800).to_readable_utc()),
            "{dettaglio}"
        );
        assert!(
            dettaglio.contains(&later(3_300).to_readable_utc()),
            "{dettaglio}"
        );
    }

    /// Con gli avvisi sospesi l'acquisizione continua, e dunque la durata
    /// scade lo stesso (ADR-0017). Un monitoraggio manuale non scade mai.
    #[test]
    fn la_scadenza_vale_con_gli_avvisi_sospesi_e_non_per_il_manuale() {
        let (mut service, source_id) = fixture();
        let Ok(a_tempo) = service.begin(
            label("A tempo"),
            &operator(),
            WizardDuration::Preset(60),
            &[source_id],
            None,
            &super::DictionaryChoice::default(),
            now(),
        ) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(manuale) = service.begin(
            label("Manuale"),
            &operator(),
            WizardDuration::Manual,
            &[source_id],
            None,
            &super::DictionaryChoice::default(),
            now(),
        ) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(()) = service.perform(
            a_tempo,
            MonitoringAction::SuspendAlerts,
            &operator(),
            later(10),
        ) else {
            panic!("la sospensione deve riuscire");
        };

        let Ok(concluse) = service.conclude_due(&operator(), later(86_400)) else {
            panic!("il controllo della scadenza deve riuscire");
        };
        assert_eq!(
            concluse.iter().map(|c| c.session_id).collect::<Vec<_>>(),
            vec![a_tempo]
        );
        assert!(
            service
                .view(manuale)
                .is_ok_and(|v| v.state == SessionState::Running)
        );
    }

    /// Un orologio tornato indietro non scrive una fine nel futuro: se la
    /// scadenza calcolata segue `now`, la fine è `now`. Qui si simula con una
    /// sessione la cui scadenza coincide con `now`.
    #[test]
    fn la_fine_non_segue_mai_l_istante_del_rilievo() {
        let (mut service, source_id) = fixture();
        let Ok(session_id) = service.begin(
            label("Esatto"),
            &operator(),
            WizardDuration::Preset(60),
            &[source_id],
            None,
            &super::DictionaryChoice::default(),
            now(),
        ) else {
            panic!("l'avvio deve riuscire");
        };
        let Ok(concluse) = service.conclude_due(&operator(), later(60)) else {
            panic!("il controllo della scadenza deve riuscire");
        };
        assert_eq!(concluse.len(), 1);
        assert!(
            service
                .view(session_id)
                .is_ok_and(|v| v.ended_at == Some(later(60)))
        );
    }

    /// **Un monitoraggio interrotto aspetta una decisione, e l'arresto la
    /// prende** (E2E01-02, ADR-0146). Finché l'interruzione è aperta il
    /// monitoraggio è fra quelli in attesa — il ciclo non gli dà contenuti —;
    /// arrestato, non lo è più e l'avviso non torna.
    #[test]
    fn un_monitoraggio_interrotto_aspetta_una_decisione() {
        let (mut service, source_id) = fixture();
        let Ok(session_id) = service.begin(
            label("Interrotto"),
            &operator(),
            WizardDuration::Manual,
            &[source_id],
            None,
            &super::DictionaryChoice::default(),
            now(),
        ) else {
            panic!("l'avvio deve riuscire");
        };
        assert!(service.awaiting_decision().is_ok_and(|v| v.is_empty()));

        let mut database = service.into_database();
        let Ok(_) = crate::interruption::detect_all_on_startup(&mut database, later(100)) else {
            panic!("il rilevamento deve riuscire");
        };
        let mut service = MonitoringService::new(database);
        assert_eq!(service.awaiting_decision().ok(), Some(vec![session_id]));

        let Ok(()) = service.perform(session_id, MonitoringAction::Stop, &operator(), later(200))
        else {
            panic!("l'arresto deve riuscire");
        };
        assert!(service.awaiting_decision().is_ok_and(|v| v.is_empty()));
        assert!(
            service
                .database()
                .open_interruptions()
                .is_ok_and(|aperte| aperte.is_empty()),
            "l'arresto prende in carico l'avviso"
        );
    }

    #[test]
    fn every_action_round_trips_through_its_identifier() {
        for action in MonitoringAction::all() {
            assert_eq!(
                MonitoringAction::from_identifier(action.as_str()),
                Some(action)
            );
            assert!(!action.label().is_empty());
        }
        assert_eq!(MonitoringAction::from_identifier("inesistente"), None);
    }
}

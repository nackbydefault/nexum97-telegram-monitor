//! Motore decisionale delle notifiche.
//!
//! Decide **se** notificare una segnalazione e **che cosa** mostrare. Il come —
//! il toast di Windows vero — arriva dopo, con l'installer: qui c'è
//! l'interfaccia astratta e un notificatore che si può provare.
//!
//! # Che cosa decide, e perché
//!
//! - **la soglia:** sotto un livello scelto non si notifica. Notificare tutto
//!   equivale a non notificare nulla, perché l'operatore smette di guardare;
//! - **la riservatezza:** quanto la notifica rivela. Un contenuto sensibile che
//!   compare per intero su una schermata bloccata, visibile a chiunque passi, è
//!   una fuga che nessun controllo a valle recupera. Tre modalità: completa,
//!   ridotta, riservata;
//! - **la sospensione:** durante «avvisi sospesi» la notifica tace. La sessione
//!   continua ad acquisire; è la condizione di chi rivede e non vuole essere
//!   interrotto;
//! - **la deduplica:** una segnalazione si notifica una volta sola. La stessa a
//!   ogni riavvio sarebbe rumore, ed è imposta dal vincolo unico dello schema;
//! - **il tetto:** oltre un numero di notifiche per sessione, le nuove
//!   segnalazioni restano nello storico ma non producono altri toast.
//!
//! # Chi mostra l'avviso, e perché non è questo modulo
//!
//! Dal 2026-08-10 il riquadro di avviso di Windows esiste: lo emette
//! `lisi_app::toast`, sopra `lisi_platform::toast` (ADR-0025). Questo modulo
//! non lo conosce, e non deve: la **decisione** si prova per intero senza
//! mostrare una sola notifica, ed è ciò che ha permesso di costruirla e
//! collaudarla due milestone prima che esistesse un modo di renderla.
//!
//! [`LoggingNotifier`] resta come ripiego e per i test: scrive una riga
//! **redatta**, che non rivela più di quanto rivelerebbe la notifica stessa.

use lisi_core::branding::PRODUCT_NAME;
use lisi_core::model::{
    Alert, Content, NewAuditEntry, NewNotification, NotificationPrivacy, NotificationSettings,
    SessionState,
};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity, DisplayName};
use lisi_core::{ContentId, Timestamp};
use lisi_storage::Database;

use crate::error::ServiceResult;

/// Lunghezza massima dell'estratto mostrato in una notifica completa.
const EXCERPT_CHARS: usize = 140;

/// Quanti recuperati si annunciano al più con un avviso solo: un recupero più
/// grande si annuncia in più giri, uno per volta (NOTIFY-BACKFILL-01,
/// ADR-0188, decisione 3).
pub const MAX_RECOVERED_PER_NOTICE: usize = 500;

/// Notifica composta, pronta per essere mostrata.
///
/// **Solo `title`, `body` e `url` si mostrano.** `level`, `content_id` e
/// `privacy` sono metadati: servono a chi registra o instrada la notifica, non
/// a chi la vede. Chi mostra l'avviso **non deve derivare testo da `level`** —
/// altrimenti in modalità riservata il livello tornerebbe visibile su una
/// schermata bloccata, che è ciò che quella modalità esiste per impedire.
///
/// L'avvertenza era scritta qui prima che esistesse un consumatore, ed è stata
/// rispettata quando è arrivato: `lisi_app::toast` consegna a Windows soltanto
/// `title` e `body` (ADR-0025).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    /// Contenuto che l'ha generata, quando ce n'è **uno**.
    ///
    /// # Perché è facoltativo
    ///
    /// Una notifica ordinaria riguarda un contenuto, e lo porta. Un avviso su
    /// un **grappolo di segnali** riguarda una correlazione fra molti
    /// contenuti, e non ne ha uno solo: sceglierne uno a caso — il primo, il
    /// più recente — direbbe a chi legge il registro che l'avviso riguardava
    /// quel messaggio, e non è vero.
    ///
    /// `None` significa «non c'è un contenuto solo», che è un fatto, non un
    /// dato mancante.
    pub content_id: Option<ContentId>,
    /// Titolo del toast.
    pub title: String,
    /// Corpo del toast.
    pub body: String,
    /// URL, presente solo in modalità completa e se abilitato.
    pub url: Option<String>,
    /// Livello dell'allarme.
    pub level: u8,
    /// Riservatezza con cui è stata composta.
    pub privacy: NotificationPrivacy,
    /// Istante di emissione.
    pub emitted_at: Timestamp,
}

/// Motivo per cui una segnalazione non ha prodotto una notifica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressionReason {
    /// Il contenuto non ha un alert: non c'è nulla da notificare.
    NoAlert,
    /// Il livello è sotto la soglia scelta.
    BelowThreshold,
    /// Gli avvisi sono sospesi per questa sessione.
    AlertsSuspended,
    /// La segnalazione è già stata notificata.
    AlreadyNotified,
    /// È stato raggiunto il tetto di notifiche della sessione.
    RateLimited,
}

impl SuppressionReason {
    /// Etichetta stabile, per l'audit e i test.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoAlert => "nessun_alert",
            Self::BelowThreshold => "sotto_soglia",
            Self::AlertsSuspended => "avvisi_sospesi",
            Self::AlreadyNotified => "gia_notificato",
            Self::RateLimited => "tetto_raggiunto",
        }
    }
}

/// Esito della valutazione di una segnalazione.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationOutcome {
    /// Notifica emessa per il contenuto indicato.
    Emitted(ContentId),
    /// Nessuna notifica, con la ragione.
    Suppressed(SuppressionReason),
}

impl NotificationOutcome {
    /// Se ha prodotto una notifica.
    #[must_use]
    pub const fn is_emitted(self) -> bool {
        matches!(self, Self::Emitted(_))
    }
}

/// Destinatario di una notifica.
///
/// L'astrazione esiste perché il riquadro di avviso di Windows e la prova siano
/// intercambiabili: il motore decisionale non sa come la notifica viene
/// mostrata, ed è per questo che si è potuto costruirlo e collaudarlo due
/// milestone prima che esistesse un modo di renderla.
pub trait Notifier {
    /// Mostra una notifica.
    fn deliver(&mut self, notification: &Notification);
}

/// Notificatore di prova: conserva ciò che riceve, non mostra nulla.
#[derive(Debug, Default)]
pub struct RecordingNotifier {
    delivered: Vec<Notification>,
}

impl RecordingNotifier {
    /// Notifiche ricevute, nell'ordine.
    #[must_use]
    pub fn delivered(&self) -> &[Notification] {
        &self.delivered
    }
}

impl Notifier for RecordingNotifier {
    fn deliver(&mut self, notification: &Notification) {
        self.delivered.push(notification.clone());
    }
}

/// Notificatore che scrive e non mostra.
///
/// Era il predefinito dell'applicazione finché il riquadro di Windows non
/// esisteva; da ADR-0025 il predefinito è quello che lo mostra, e questo resta
/// come ripiego e per i test.
///
/// Scrive un log **redatto**: il titolo e il corpo dipendono già dalla
/// riservatezza scelta, quindi il log non rivela più di quanto rivelerebbe la
/// notifica stessa.
#[derive(Debug, Default)]
pub struct LoggingNotifier;

impl Notifier for LoggingNotifier {
    fn deliver(&mut self, notification: &Notification) {
        tracing::info!(
            contenuto = notification.content_id.map(lisi_core::ContentId::get),
            livello = notification.level,
            riservatezza = notification.privacy.as_str(),
            "notifica registrata senza riquadro di avviso"
        );
    }
}

/// Riga del centro notifiche: una notifica emessa, con ciò che la spiega.
///
/// È una revisione in-app (DEC-105): porta il contenuto per intero — fonte,
/// motivazione, estratto, URL — e **con quale** riservatezza la notifica era
/// apparsa. La riservatezza governa il toast sulla schermata bloccata, non ciò
/// che l'operatore, già dentro l'applicazione, rivede qui.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationEntry {
    /// Istante di emissione.
    pub emitted_at: Timestamp,
    /// Riservatezza con cui è stata mostrata.
    pub privacy: NotificationPrivacy,
    /// Livello dell'allarme, da 1 a 4.
    pub level: u8,
    /// Fonte da cui proviene il contenuto.
    pub source_name: DisplayName,
    /// Motivazione dell'allarme, come scritta al momento dell'analisi.
    pub reason: String,
    /// Estratto del contenuto.
    pub excerpt: String,
    /// URL del contenuto, se presente.
    pub url: Option<String>,
}

/// Servizio delle notifiche.
#[derive(Debug)]
pub struct NotificationService {
    database: Database,
}

impl NotificationService {
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

    /// Elenca le notifiche emesse, dalla più recente, con ciò che le spiega.
    ///
    /// È l'elenco del centro notifiche. Compone ogni riga dalle letture già
    /// esistenti (`content`, `source`, `content_alert`), come `HistoryService`:
    /// nessun nuovo join, nessuna nuova migrazione (DEC-105).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se una delle letture non riesce.
    pub fn history(&self) -> ServiceResult<Vec<NotificationEntry>> {
        let emitted = self.database.emitted_notifications()?;
        let mut entries = Vec::with_capacity(emitted.len());

        for notification in emitted {
            let content = self.database.content(notification.content_id)?;
            let source = self.database.source(content.source_id)?;
            // Una notifica è emessa solo per un contenuto con un alert, quindi
            // la motivazione c'è. Se mancasse — un archivio manomesso — si
            // mostra vuota invece di far cadere l'intero elenco.
            let reason = self
                .database
                .content_alert(notification.content_id)?
                .map(|alert| alert.reason.as_str().to_owned())
                .unwrap_or_default();

            entries.push(NotificationEntry {
                emitted_at: notification.emitted_at,
                privacy: notification.privacy,
                level: notification.level,
                source_name: source.display_name,
                reason,
                excerpt: excerpt(content.body.as_str()),
                url: content.url.map(|url| url.as_str().to_owned()),
            });
        }

        Ok(entries)
    }

    /// Valuta una segnalazione e, se del caso, la notifica.
    ///
    /// Prende l'attore per l'audit e il notificatore concreto: in esercizio il
    /// notificatore del toast, nei test uno che conserva ciò che riceve.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se una lettura o la registrazione non riescono.
    pub fn consider(
        &self,
        content_id: ContentId,
        settings: NotificationSettings,
        actor: &Actor,
        now: Timestamp,
        notifier: &mut dyn Notifier,
    ) -> ServiceResult<NotificationOutcome> {
        let Some(alert) = self.database.content_alert(content_id)? else {
            return Ok(NotificationOutcome::Suppressed(SuppressionReason::NoAlert));
        };

        let content = self.database.content(content_id)?;
        let session = self.database.session(content.session_id)?;

        // Avvisi sospesi: acquisizione in corso, notifiche no.
        if session.state == SessionState::Paused {
            return Ok(NotificationOutcome::Suppressed(
                SuppressionReason::AlertsSuspended,
            ));
        }
        if alert.level.get() < settings.minimum_level {
            return Ok(NotificationOutcome::Suppressed(
                SuppressionReason::BelowThreshold,
            ));
        }
        if self.database.notification_exists(content_id)? {
            return Ok(NotificationOutcome::Suppressed(
                SuppressionReason::AlreadyNotified,
            ));
        }
        if self
            .database
            .session_notification_count(content.session_id)?
            >= settings.max_per_session
        {
            return Ok(NotificationOutcome::Suppressed(
                SuppressionReason::RateLimited,
            ));
        }

        let source_name = self.database.source(content.source_id)?.display_name;
        let notification = compose(settings, &source_name, &content, &alert, now);

        // Si registra PRIMA di emettere: la registrazione è la deduplica, e un
        // toast mostrato ma non registrato tornerebbe a ogni riavvio.
        //
        // La deduplica si appoggia al **vincolo unico**, non alla sola lettura
        // di `notification_exists` fatta sopra: se un'altra valutazione avesse
        // inserito nel frattempo, qui l'inserimento non produrrebbe una riga, e
        // non si emette una seconda notifica. Il controllo precedente evita di
        // comporre inutilmente; questo è la garanzia.
        let inserted = self.database.insert_notification(&NewNotification {
            content_id,
            session_id: content.session_id,
            privacy: settings.privacy,
            level: alert.level.get(),
            emitted_at: now,
            recovered: false,
        })?;
        if inserted.is_none() {
            return Ok(NotificationOutcome::Suppressed(
                SuppressionReason::AlreadyNotified,
            ));
        }
        self.audit(actor, content_id, settings.privacy, now)?;

        notifier.deliver(&notification);
        Ok(NotificationOutcome::Emitted(content_id))
    }

    /// Annuncia i contenuti **recuperati dallo storico** con un avviso solo
    /// (NOTIFY-BACKFILL-01, ADR-0188).
    ///
    /// Cerca nell'archivio i recuperati con un avviso di almeno la soglia e
    /// nessuna notifica, al più [`MAX_RECOVERED_PER_NOTICE`] per volta; li
    /// registra uno per uno come notificati e recuperati, che non contano nel
    /// tetto per sessione; ed emette **un** avviso che dice quanti sono e che
    /// sono recuperati. Con gli avvisi sospesi in una sessione, i suoi restano
    /// per dopo.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se una lettura o la registrazione non riescono.
    pub fn consider_recovered(
        &self,
        settings: NotificationSettings,
        actor: &Actor,
        now: Timestamp,
        notifier: &mut dyn Notifier,
    ) -> ServiceResult<usize> {
        let candidati = self
            .database
            .recovered_contents_to_notify(settings.minimum_level, MAX_RECOVERED_PER_NOTICE)?;
        let mut registrati = 0_usize;
        let mut piu_alto: Option<(u8, ContentId)> = None;
        for content_id in candidati {
            let Some(alert) = self.database.content_alert(content_id)? else {
                continue;
            };
            let content = self.database.content(content_id)?;
            if self.database.session(content.session_id)?.state == SessionState::Paused {
                continue;
            }
            let inserito = self.database.insert_notification(&NewNotification {
                content_id,
                session_id: content.session_id,
                privacy: settings.privacy,
                level: alert.level.get(),
                emitted_at: now,
                recovered: true,
            })?;
            if inserito.is_none() {
                continue;
            }
            registrati += 1;
            if piu_alto.is_none_or(|(livello, _)| alert.level.get() > livello) {
                piu_alto = Some((alert.level.get(), content_id));
            }
        }
        let Some((livello, esempio)) = piu_alto else {
            return Ok(0);
        };
        let fonte = {
            let content = self.database.content(esempio)?;
            self.database.source(content.source_id)?.display_name
        };
        let quanti = if registrati == 1 {
            String::from("Un contenuto recuperato dallo storico")
        } else {
            format!("{registrati} contenuti recuperati dallo storico")
        };
        let (title, body) = match settings.privacy {
            NotificationPrivacy::Full => (
                format!("{quanti} da esaminare"),
                format!(
                    "Il più alto è di livello {livello}, da «{}». Erano già pubblicati: si \
                     leggono negli Avvisi.",
                    fonte.as_str()
                ),
            ),
            NotificationPrivacy::Reduced => (
                format!("{quanti} da esaminare"),
                String::from("Erano già pubblicati: si leggono negli Avvisi."),
            ),
            NotificationPrivacy::Confidential => (
                String::from(PRODUCT_NAME),
                String::from("Contenuti recuperati da esaminare."),
            ),
        };
        let notification = Notification {
            content_id: None,
            title,
            body,
            url: None,
            level: livello,
            privacy: settings.privacy,
            emitted_at: now,
        };
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("notifica_recuperati")?,
            entity: AuditEntity::try_new("content")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&format!(
                "{registrati} recuperati, {}",
                settings.privacy.as_str()
            ))?),
            recorded_at: now,
        })?;
        notifier.deliver(&notification);
        Ok(registrati)
    }

    /// Registra nell'audit l'emissione di una notifica.
    ///
    /// Il dettaglio è la **riservatezza**, non il testo: l'audit documenta che
    /// una notifica è stata mostrata e con quale grado di riservatezza, non il
    /// contenuto che mostrava.
    fn audit(
        &self,
        actor: &Actor,
        content_id: ContentId,
        privacy: NotificationPrivacy,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("notifica_emessa")?,
            entity: AuditEntity::try_new("content")?,
            entity_id: Some(content_id.get()),
            actor_mode: None,
            detail: Some(AuditDetail::try_new(privacy.as_str())?),
            recorded_at: now,
        })?;
        Ok(())
    }
}

/// Compone una notifica secondo la riservatezza scelta.
fn compose(
    settings: NotificationSettings,
    source_name: &DisplayName,
    content: &Content,
    alert: &Alert,
    now: Timestamp,
) -> Notification {
    let level = alert.level.get();
    let (title, body, url) = match settings.privacy {
        NotificationPrivacy::Full => {
            let body = format!(
                "{}\n{}\n{}",
                excerpt(content.body.as_str()),
                alert.reason.as_str(),
                content.acquired_at.to_readable_utc()
            );
            let url = if settings.include_url {
                content.url.as_ref().map(|url| url.as_str().to_owned())
            } else {
                None
            };
            (
                format!("{} \u{2014} livello {level}", source_name.as_str()),
                body,
                url,
            )
        }
        NotificationPrivacy::Reduced => (
            format!("{} \u{2014} livello {level}", source_name.as_str()),
            String::from("Nuovo contenuto da esaminare."),
            None,
        ),
        NotificationPrivacy::Confidential => (
            String::from(PRODUCT_NAME),
            String::from("Nuovo contenuto da esaminare."),
            None,
        ),
    };

    Notification {
        content_id: Some(content.id),
        title,
        body,
        url,
        level,
        privacy: settings.privacy,
        emitted_at: now,
    }
}

/// Estratto del corpo, su una riga e tagliato in caratteri.
fn excerpt(body: &str) -> String {
    let single_line: String = body
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    let trimmed = single_line.trim();

    if trimmed.chars().count() <= EXCERPT_CHARS {
        return String::from(trimmed);
    }
    let head: String = trimmed.chars().take(EXCERPT_CHARS).collect();
    format!("{head}\u{2026}")
}

#[cfg(test)]
mod tests {
    use lisi_core::model::AcquisitionOrigin;
    use lisi_core::model::dictionary::{
        ConfigurationResolver, MatchMode, ResolvedDictionaryConfiguration, TermProvenance,
    };
    use lisi_core::model::{
        NewSession, NewSource, NotificationPrivacy, SessionDuration, SessionState, SourceKind,
    };
    use lisi_core::text::{
        Actor, ContentBody, DisplayName, LanguageTag, RemoteMessageId, SourceIdentifier,
        TermCategory, TermText,
    };
    use lisi_core::{ContentId, SessionId, Timestamp};

    use super::{
        NotificationOutcome, NotificationService, NotificationSettings, RecordingNotifier,
        SuppressionReason,
    };
    use crate::analysis::{AnalysisService, NewContentDraft};
    use crate::sources::open_in_memory_database;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn operator() -> Actor {
        let Ok(actor) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        actor
    }

    fn configuration() -> ResolvedDictionaryConfiguration {
        let mut resolver = ConfigurationResolver::new();
        for (text, level) in [("molotov", 3_i8), ("gamma", 1_i8)] {
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
                panic!("il termine deve essere accettato");
            };
        }
        resolver.finish()
    }

    /// Servizio con una sessione e un contenuto già analizzato e segnalato.
    ///
    /// Restituisce il servizio, la sessione e il contenuto di livello `level`.
    fn with_alert(body: &str) -> (NotificationService, SessionId, ContentId) {
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
                duration: SessionDuration::Manual,
                source_ids: vec![source_id],
            },
            now(),
        ) else {
            panic!("la sessione deve potersi creare");
        };
        // La sessione e' in corso: le notifiche non sono sospese.
        let Ok(()) = database.update_session_state(session_id, SessionState::Running, now()) else {
            panic!("la sessione deve potersi avviare");
        };

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
            &configuration(),
            &operator(),
            now(),
        ) else {
            panic!("l'analisi deve riuscire");
        };
        let Some(content_id) = record.content_id else {
            panic!("il contenuto doveva essere registrato");
        };

        (
            NotificationService::new(analysis.into_database()),
            session_id,
            content_id,
        )
    }

    /// Servizio con una sessione in corso e i contenuti indicati, analizzati,
    /// ciascuno con la sua origine.
    fn with_contents(
        contents: &[(&str, AcquisitionOrigin)],
    ) -> (NotificationService, Vec<ContentId>) {
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
                duration: SessionDuration::Manual,
                source_ids: vec![source_id],
            },
            now(),
        ) else {
            panic!("la sessione deve potersi creare");
        };
        let Ok(()) = database.update_session_state(session_id, SessionState::Running, now()) else {
            panic!("la sessione deve potersi avviare");
        };
        let mut analysis = AnalysisService::new(database);
        let mut ids = Vec::new();
        for (indice, (testo, origine)) in contents.iter().enumerate() {
            let (Ok(remote), Ok(body)) = (
                RemoteMessageId::try_new(&format!("m{indice}")),
                ContentBody::try_new(testo),
            ) else {
                panic!("i valori del contenuto devono essere validi");
            };
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
                    origin: *origine,
                },
                &configuration(),
                &operator(),
                now(),
            ) else {
                panic!("l'analisi deve riuscire");
            };
            let Some(content_id) = record.content_id else {
                panic!("il contenuto doveva essere registrato");
            };
            ids.push(content_id);
        }
        (NotificationService::new(analysis.into_database()), ids)
    }

    /// **I recuperati si annunciano con un avviso solo, e una volta**
    /// (NOTIFY-BACKFILL-01, ADR-0188, decisioni 1 e 2): tre recuperati sopra la
    /// soglia, uno sotto e uno dal vivo; un avviso che dice tre e
    /// «recuperati»; un secondo giro non ripete niente.
    #[test]
    fn i_recuperati_si_annunciano_con_un_avviso_solo() {
        let (service, _) = with_contents(&[
            ("una molotov", AcquisitionOrigin::Recovered),
            ("un'altra molotov", AcquisitionOrigin::Recovered),
            ("la terza molotov", AcquisitionOrigin::Recovered),
            ("niente di che", AcquisitionOrigin::Recovered),
            ("una molotov dal vivo", AcquisitionOrigin::Observed),
        ]);
        let settings = NotificationSettings::default();
        let mut notifier = RecordingNotifier::default();
        let Ok(annunciati) =
            service.consider_recovered(settings, &operator(), now(), &mut notifier)
        else {
            panic!("la valutazione deve riuscire");
        };
        assert_eq!(annunciati, 3);
        assert_eq!(notifier.delivered().len(), 1, "un avviso solo");
        assert!(
            notifier.delivered()[0]
                .title
                .contains("3 contenuti recuperati")
        );
        assert_eq!(notifier.delivered()[0].content_id, None);

        let Ok(di_nuovo) = service.consider_recovered(settings, &operator(), now(), &mut notifier)
        else {
            panic!("la seconda valutazione deve riuscire");
        };
        assert_eq!(di_nuovo, 0);
        assert_eq!(notifier.delivered().len(), 1, "niente si ripete");
    }

    /// **I recuperati non tolgono posto agli avvisi dal vivo** (decisione 4):
    /// con un tetto di uno per sessione, dopo tre recuperati annunciati un
    /// contenuto dal vivo si notifica ancora.
    #[test]
    fn i_recuperati_non_tolgono_posto_al_vivo() {
        let (service, ids) = with_contents(&[
            ("una molotov", AcquisitionOrigin::Recovered),
            ("un'altra molotov", AcquisitionOrigin::Recovered),
            ("la terza molotov", AcquisitionOrigin::Recovered),
            ("una molotov dal vivo", AcquisitionOrigin::Observed),
        ]);
        let settings = NotificationSettings {
            max_per_session: 1,
            ..NotificationSettings::default()
        };
        let mut notifier = RecordingNotifier::default();
        let Ok(3) = service.consider_recovered(settings, &operator(), now(), &mut notifier) else {
            panic!("tre recuperati si annunciano");
        };
        let Ok(esito) = service.consider(ids[3], settings, &operator(), now(), &mut notifier)
        else {
            panic!("la valutazione del vivo deve riuscire");
        };
        assert_eq!(esito, NotificationOutcome::Emitted(ids[3]));
    }

    #[test]
    fn a_high_level_content_is_notified_once() {
        let (service, _, content_id) = with_alert("una molotov");
        let settings = NotificationSettings::default();
        let mut notifier = RecordingNotifier::default();

        let Ok(first) = service.consider(content_id, settings, &operator(), now(), &mut notifier)
        else {
            panic!("la valutazione deve riuscire");
        };
        assert_eq!(first, NotificationOutcome::Emitted(content_id));
        assert_eq!(notifier.delivered().len(), 1);

        // Una seconda valutazione non notifica di nuovo.
        let Ok(second) = service.consider(content_id, settings, &operator(), now(), &mut notifier)
        else {
            panic!("la seconda valutazione deve riuscire");
        };
        assert_eq!(
            second,
            NotificationOutcome::Suppressed(SuppressionReason::AlreadyNotified)
        );
        assert_eq!(notifier.delivered().len(), 1, "nessuna seconda notifica");
    }

    #[test]
    fn a_content_below_the_threshold_is_not_notified() {
        let (service, _, content_id) = with_alert("un gamma"); // livello 1
        let settings = NotificationSettings {
            minimum_level: 3,
            ..NotificationSettings::default()
        };
        let mut notifier = RecordingNotifier::default();

        let Ok(outcome) = service.consider(content_id, settings, &operator(), now(), &mut notifier)
        else {
            panic!("la valutazione deve riuscire");
        };
        assert_eq!(
            outcome,
            NotificationOutcome::Suppressed(SuppressionReason::BelowThreshold)
        );
        assert!(notifier.delivered().is_empty());
    }

    #[test]
    fn suspended_alerts_suppress_the_notification() {
        let (service, session_id, content_id) = with_alert("una molotov");
        // Sospendi gli avvisi: la sessione passa a «avvisi sospesi».
        let mut database = service.into_database();
        let Ok(()) = database.update_session_state(session_id, SessionState::Paused, now()) else {
            panic!("la sospensione deve riuscire");
        };
        let service = NotificationService::new(database);
        let mut notifier = RecordingNotifier::default();

        let Ok(outcome) = service.consider(
            content_id,
            NotificationSettings::default(),
            &operator(),
            now(),
            &mut notifier,
        ) else {
            panic!("la valutazione deve riuscire");
        };
        assert_eq!(
            outcome,
            NotificationOutcome::Suppressed(SuppressionReason::AlertsSuspended)
        );
        assert!(notifier.delivered().is_empty());
    }

    #[test]
    fn the_full_mode_shows_source_extract_and_reason() {
        let (service, _, content_id) = with_alert("una molotov");
        let settings = NotificationSettings {
            privacy: NotificationPrivacy::Full,
            ..NotificationSettings::default()
        };
        let mut notifier = RecordingNotifier::default();

        let Ok(_) = service.consider(content_id, settings, &operator(), now(), &mut notifier)
        else {
            panic!("la valutazione deve riuscire");
        };
        let shown = &notifier.delivered()[0];
        assert!(shown.title.contains("Canale di prova"));
        assert!(shown.title.contains("livello 3"));
        assert!(shown.body.contains("una molotov"), "l'estratto");
        assert!(
            shown.body.contains("molotov"),
            "la motivazione nomina il termine"
        );
    }

    #[test]
    fn the_reduced_mode_names_the_source_but_not_the_content() {
        let (service, _, content_id) = with_alert("una molotov");
        let settings = NotificationSettings {
            privacy: NotificationPrivacy::Reduced,
            ..NotificationSettings::default()
        };
        let mut notifier = RecordingNotifier::default();

        let Ok(_) = service.consider(content_id, settings, &operator(), now(), &mut notifier)
        else {
            panic!("la valutazione deve riuscire");
        };
        let shown = &notifier.delivered()[0];
        assert!(shown.title.contains("Canale di prova"));
        assert!(
            !shown.body.contains("molotov"),
            "la modalita' ridotta non mostra il testo del contenuto"
        );
    }

    #[test]
    fn the_confidential_mode_reveals_neither_source_nor_content() {
        let (service, _, content_id) = with_alert("una molotov");
        let settings = NotificationSettings {
            privacy: NotificationPrivacy::Confidential,
            ..NotificationSettings::default()
        };
        let mut notifier = RecordingNotifier::default();

        let Ok(_) = service.consider(content_id, settings, &operator(), now(), &mut notifier)
        else {
            panic!("la valutazione deve riuscire");
        };
        let shown = &notifier.delivered()[0];
        assert!(
            !shown.title.contains("Canale di prova"),
            "la modalita' riservata non nomina la fonte"
        );
        assert!(!shown.body.contains("molotov"));
        assert!(shown.url.is_none());
    }

    #[test]
    fn the_cap_stops_further_notifications_but_the_content_is_still_recorded() {
        let (service, _, content_id) = with_alert("una molotov");
        let settings = NotificationSettings {
            max_per_session: 0, // nessuna notifica ammessa
            ..NotificationSettings::default()
        };
        let mut notifier = RecordingNotifier::default();

        let Ok(outcome) = service.consider(content_id, settings, &operator(), now(), &mut notifier)
        else {
            panic!("la valutazione deve riuscire");
        };
        assert_eq!(
            outcome,
            NotificationOutcome::Suppressed(SuppressionReason::RateLimited)
        );
        // Il contenuto resta: solo il toast e' soppresso.
        assert!(service.database().content(content_id).is_ok());
    }

    #[test]
    fn the_logging_notifier_delivers_without_showing_a_toast() {
        // Il notificatore di ripiego: scrive un log redatto e non cade.
        use super::{LoggingNotifier, Notification, Notifier};

        let mut notifier = LoggingNotifier;
        notifier.deliver(&Notification {
            content_id: Some(ContentId::new(1)),
            title: String::from("t"),
            body: String::from("b"),
            url: None,
            level: 3,
            privacy: NotificationPrivacy::Reduced,
            emitted_at: now(),
        });
    }

    #[test]
    fn the_center_lists_an_emitted_notification_with_its_full_context() {
        // Anche se la notifica era ridotta, il centro mostra il contenuto per
        // intero: e' una revisione in-app, non il toast (DEC-105). Ricorda pero'
        // con quale riservatezza la notifica e' apparsa.
        let (service, _, content_id) = with_alert("una molotov"); // livello 3
        let settings = NotificationSettings {
            privacy: NotificationPrivacy::Reduced,
            ..NotificationSettings::default()
        };
        let mut notifier = RecordingNotifier::default();
        let Ok(_) = service.consider(content_id, settings, &operator(), now(), &mut notifier)
        else {
            panic!("la valutazione deve riuscire");
        };

        let Ok(history) = service.history() else {
            panic!("il centro deve potersi leggere");
        };
        assert_eq!(history.len(), 1);
        let entry = &history[0];
        assert_eq!(
            entry.privacy,
            NotificationPrivacy::Reduced,
            "si ricorda come e' apparsa"
        );
        assert_eq!(entry.level, 3);
        assert!(entry.source_name.as_str().contains("Canale di prova"));
        assert!(
            entry.reason.contains("molotov"),
            "ma il centro mostra la motivazione: {}",
            entry.reason
        );
        assert!(entry.excerpt.contains("molotov"), "e l'estratto");
    }

    #[test]
    fn the_center_lists_notifications_newest_first() {
        use crate::analysis::NewContentDraft;

        // Primo contenuto e alert dal solito aiutante; poi se ne aggiunge un
        // secondo allo stesso archivio, cosi' da poterne notificare due.
        let (service, session_id, first) = with_alert("una molotov");
        let database = service.into_database();
        let Ok(content) = database.content(first) else {
            panic!("il primo contenuto deve potersi leggere");
        };
        let source_id = content.source_id;

        let mut analysis = AnalysisService::new(database);
        let (Ok(remote), Ok(body)) = (
            RemoteMessageId::try_new("m2"),
            ContentBody::try_new("un gamma"),
        ) else {
            panic!("i valori del secondo contenuto devono essere validi");
        };
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
            &configuration(),
            &operator(),
            now(),
        ) else {
            panic!("l'analisi del secondo contenuto deve riuscire");
        };
        let Some(second) = record.content_id else {
            panic!("il secondo contenuto doveva essere registrato");
        };

        let service = NotificationService::new(analysis.into_database());
        let mut notifier = RecordingNotifier::default();
        let early = Timestamp::from_millis(1_700_000_000_000);
        let late = Timestamp::from_millis(1_700_000_100_000);

        // Il primo contenuto e' notificato prima, il secondo dopo.
        let Ok(_) = service.consider(
            first,
            NotificationSettings::default(),
            &operator(),
            early,
            &mut notifier,
        ) else {
            panic!("la prima notifica deve riuscire");
        };
        let Ok(_) = service.consider(
            second,
            NotificationSettings::default(),
            &operator(),
            late,
            &mut notifier,
        ) else {
            panic!("la seconda notifica deve riuscire");
        };

        let Ok(history) = service.history() else {
            panic!("il centro deve potersi leggere");
        };
        assert_eq!(history.len(), 2);
        // La piu' recente per prima: e' cio' che l'operatore vuole vedere in cima.
        assert_eq!(history[0].emitted_at, late);
        assert_eq!(history[1].emitted_at, early);
    }

    #[test]
    fn the_center_is_empty_when_nothing_was_notified() {
        // Finche' l'acquisizione dal vivo non emette notifiche, il centro e'
        // vuoto: lo stato che l'interfaccia dichiara.
        let (service, _, _) = with_alert("una molotov");
        let Ok(history) = service.history() else {
            panic!("il centro deve potersi leggere");
        };
        assert!(history.is_empty(), "senza consider() nessuna notifica");
    }

    #[test]
    fn a_content_without_an_alert_produces_nothing() {
        let (service, _, content_id) = with_alert("buongiorno a tutti"); // livello 0
        let mut notifier = RecordingNotifier::default();

        let Ok(outcome) = service.consider(
            content_id,
            NotificationSettings::default(),
            &operator(),
            now(),
            &mut notifier,
        ) else {
            panic!("la valutazione deve riuscire");
        };
        assert_eq!(
            outcome,
            NotificationOutcome::Suppressed(SuppressionReason::NoAlert)
        );
        assert!(notifier.delivered().is_empty());
    }

    #[test]
    fn an_emitted_notification_is_recorded_in_the_audit_with_its_privacy_not_its_text() {
        let (service, _, content_id) = with_alert("una molotov");
        let settings = NotificationSettings {
            privacy: NotificationPrivacy::Full,
            ..NotificationSettings::default()
        };
        let mut notifier = RecordingNotifier::default();
        let Ok(_) = service.consider(content_id, settings, &operator(), now(), &mut notifier)
        else {
            panic!("la valutazione deve riuscire");
        };

        let Ok(entries) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let Some(entry) = entries
            .iter()
            .find(|entry| entry.action.as_str() == "notifica_emessa")
        else {
            panic!("la notifica deve essere nell'audit");
        };
        assert_eq!(entry.detail.as_ref().map(|d| d.as_str()), Some("full"));
        assert!(
            !entry
                .detail
                .as_ref()
                .is_some_and(|d| d.as_str().contains("molotov")),
            "l'audit non porta il testo del contenuto"
        );
    }
}

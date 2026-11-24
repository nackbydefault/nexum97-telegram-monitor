//! Quando un grappolo di segnali merita di interrompere qualcuno.
//!
//! # La regola che questo modulo esiste per non violare
//!
//! **Un grappolo non produce un avviso per ogni segnale che lo compone.**
//!
//! Un indicatore che ricorre in venti messaggi produrrebbe venti valutazioni, e
//! se ciascuna emettesse un riquadro l'operatore riceverebbe venti avvisi per
//! **una** cosa da guardare. Dopo il terzo li chiude senza leggerli, e il
//! quarto — che poteva essere quello importante — è già perso.
//!
//! L'avviso è **dell'evento**, e l'evento si annuncia una volta sola.
//!
//! # Che cosa identifica un evento, visto che non è una riga
//!
//! I grappoli si ricalcolano a ogni lettura e non si conservano (DEC-221): non
//! esiste un identificativo da mettere in chiave esterna. Ciò che resta stabile
//! è la coppia **(genere dell'indicatore, valore)** dentro una sessione, e la
//! deduplica si appoggia a quella — imposta dal vincolo unico dello schema,
//! come per le notifiche ordinarie.
//!
//! # Due soglie, perché sono due domande
//!
//! **Quanti contenuti** dice quante volte la cosa è stata detta. **Quante fonti
//! distinte** dice da quante voci diverse. Un grappolo di venti messaggi da una
//! sola fonte e uno di tre messaggi da tre fonti sono due situazioni diverse, e
//! un ufficio può volerne sorvegliare una e non l'altra.
//!
//! Alzare la soglia sulle fonti rende più **raro** ciò che viene annunciato;
//! **non rende più attendibile ciò che passa**. Fonti distinte non sono
//! conferme indipendenti, e questo modulo non ha alcun modo di dire il
//! contrario.
//!
//! # Che cosa l'avviso non dice, mai
//!
//! Che un attacco sia avvenuto. Il testo che compone dice **quanti contenuti**,
//! **da quante fonti distinte** e **perché stanno insieme**, e nient'altro: una
//! notifica è ancora più esposta di una schermata a essere letta di sfuggita, e
//! su una schermata bloccata la legge chiunque passi.

use lisi_core::branding::PRODUCT_NAME;
use lisi_core::model::cyber_event::CorrelationReason;
use lisi_core::model::{NewAuditEntry, NotificationPrivacy, NotificationSettings, SessionState};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{SessionId, Timestamp};
use lisi_storage::{Database, NewCyberNotification};

use crate::cyber_watch::{CyberWatchService, WatchEvent};
use crate::error::ServiceResult;
use crate::notification::{Notification, Notifier};

/// Perché un grappolo non è stato annunciato.
///
/// Ogni ragione è una condizione **distinta** e verificabile: un solo
/// «soppresso» costringerebbe chi indaga a rileggere il codice per capire
/// quale delle sei condizioni sia scattata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CyberSuppressionReason {
    /// Gli avvisi sui grappoli sono spenti nelle impostazioni.
    Disabled,
    /// Gli avvisi sono sospesi per questa sessione.
    AlertsSuspended,
    /// Il grappolo non raggiunge la soglia sui contenuti.
    TooFewContents,
    /// Il grappolo non raggiunge la soglia sulle fonti distinte.
    TooFewSources,
    /// Quel grappolo è già stato annunciato in questa sessione.
    AlreadyNotified,
    /// I contenuti del grappolo sono già coperti da un avviso appena emesso.
    ///
    /// Due grappoli sugli stessi messaggi sono la stessa storia raccontata due
    /// volte: il secondo si vede in «Segnali cyber», ma non chiede di guardare una
    /// seconda volta le stesse righe.
    AlreadyCovered,
}

impl CyberSuppressionReason {
    /// Etichetta stabile, per l'audit e i test.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "avvisi_cyber_spenti",
            Self::AlertsSuspended => "avvisi_sospesi",
            Self::TooFewContents => "sotto_soglia_contenuti",
            Self::TooFewSources => "sotto_soglia_fonti",
            Self::AlreadyNotified => "gia_notificato",
            Self::AlreadyCovered => "gia_coperto_da_un_avviso",
        }
    }
}

/// Esito della valutazione di un grappolo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CyberNotificationOutcome {
    /// Avviso emesso per il grappolo indicato, con la sua chiave.
    Emitted {
        /// Genere dell'indicatore che tiene insieme il grappolo.
        kind: String,
        /// Valore normalizzato.
        value: String,
    },
    /// Nessun avviso, con la ragione.
    Suppressed(CyberSuppressionReason),
}

impl CyberNotificationOutcome {
    /// Se ha prodotto un avviso.
    #[must_use]
    pub const fn is_emitted(&self) -> bool {
        matches!(self, Self::Emitted { .. })
    }
}

/// Motore decisionale degli avvisi sui grappoli.
#[derive(Debug)]
pub struct CyberNotificationService {
    watch: CyberWatchService,
}

impl CyberNotificationService {
    /// Crea il servizio attorno alla sorveglianza dei grappoli.
    ///
    /// # Perché una connessione sola
    ///
    /// Gli altri servizi che leggono e scrivono ne tengono due, perché la
    /// scrittura vuole l'archivio **mutabile** e prestarlo a chi legge
    /// significherebbe prestarlo a tutti. Qui non serve: registrare un avviso e
    /// scrivere la voce d'audit passano entrambe da `&Database`, e la
    /// transazione la apre SQLite per la singola istruzione.
    ///
    /// Una seconda connessione avrebbe aggiunto una cosa da tenere allineata in
    /// cambio di niente.
    #[must_use]
    pub const fn new(watch: CyberWatchService) -> Self {
        Self { watch }
    }

    /// L'archivio, per le letture e le registrazioni.
    const fn database(&self) -> &Database {
        self.watch.database()
    }

    /// Valuta **tutti** i grappoli di una sessione e annuncia quelli nuovi che
    /// superano le soglie.
    ///
    /// # Perché tutti insieme e non uno per volta
    ///
    /// Un grappolo non nasce da un singolo contenuto: nasce dal **ripetersi**,
    /// e il contenuto che lo fa nascere è indistinguibile dagli altri finché
    /// non si guarda l'insieme. Valutare per contenuto, come fanno le notifiche
    /// ordinarie, chiederebbe «questo messaggio ha creato un grappolo?» — una
    /// domanda a cui si risponde comunque ricalcolando tutti i grappoli.
    ///
    /// Chiamarla dopo un ciclo di acquisizione, e non a ogni messaggio, è la
    /// scelta di chi la invoca; il costo è una lettura della correlazione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se una lettura o la registrazione non riescono.
    pub fn consider_session(
        &self,
        session_id: SessionId,
        settings: NotificationSettings,
        actor: &Actor,
        now: Timestamp,
        notifier: &mut dyn Notifier,
    ) -> ServiceResult<Vec<CyberNotificationOutcome>> {
        // Spenta: non si legge nemmeno la correlazione. Una capacita' spenta
        // non deve costare niente a chi non la usa.
        if !settings.cyber_enabled {
            return Ok(vec![CyberNotificationOutcome::Suppressed(
                CyberSuppressionReason::Disabled,
            )]);
        }

        // Avvisi sospesi: l'acquisizione continua, gli avvisi tacciono. E' la
        // stessa regola delle notifiche ordinarie, e vale qui per la stessa
        // ragione — chi sta rivedendo non vuole essere interrotto.
        let session = self.database().session(session_id)?;
        if session.state == SessionState::Paused {
            return Ok(vec![CyberNotificationOutcome::Suppressed(
                CyberSuppressionReason::AlertsSuspended,
            )]);
        }

        let mut events = self.watch.events(session_id)?;

        // Dal grappolo piu' grande al piu' piccolo.
        //
        // Non e' una preferenza estetica: serve all'aggregazione qui sotto, che
        // scarta un grappolo **contenuto** in uno gia' annunciato. Perche'
        // funzioni, il piu' grande deve essere valutato per primo.
        //
        // A parita' di dimensione l'ordine e' quello della correlazione, che e'
        // stabile: due esecuzioni sullo stesso archivio annunciano le stesse
        // cose.
        events.sort_by(|primo, secondo| {
            secondo
                .assessment
                .contents
                .cmp(&primo.assessment.contents)
                .then_with(|| key_of(primo).cmp(&key_of(secondo)))
        });

        let mut esiti = Vec::with_capacity(events.len());
        // I contenuti gia' coperti da un avviso emesso in QUESTO giro.
        let mut gia_coperti: Vec<Vec<i64>> = Vec::new();

        for event in &events {
            let membri = members_of(event);

            // AGGREGAZIONE: due grappoli sugli STESSI messaggi sono la stessa
            // storia raccontata due volte.
            //
            // Due messaggi che nominano insieme un dominio e una CVE formano
            // DUE grappoli — uno per indicatore — e sono correlazioni davvero
            // distinte. Ma per chi legge sono **gli stessi due messaggi**, e
            // due riquadri chiedono di guardare due volte la stessa cosa.
            //
            // Un grappolo i cui contenuti sono tutti gia' coperti da un avviso
            // appena emesso non ne produce un altro. Non e' un grappolo
            // nascosto: si vede in «Segnali cyber», dove i due compaiono separati
            // com'e' giusto. E' l'avviso a non ripetersi.
            if gia_coperti
                .iter()
                .any(|coperti| membri.iter().all(|id| coperti.contains(id)))
            {
                esiti.push(CyberNotificationOutcome::Suppressed(
                    CyberSuppressionReason::AlreadyCovered,
                ));
                continue;
            }

            let esito = self.consider(session_id, event, settings, actor, now, notifier)?;
            if esito.is_emitted() {
                gia_coperti.push(membri);
            }
            esiti.push(esito);
        }
        Ok(esiti)
    }

    /// Valuta un singolo grappolo.
    fn consider(
        &self,
        session_id: SessionId,
        event: &WatchEvent,
        settings: NotificationSettings,
        actor: &Actor,
        now: Timestamp,
        notifier: &mut dyn Notifier,
    ) -> ServiceResult<CyberNotificationOutcome> {
        let (kind, value) = key_of(event);

        // Le due soglie si controllano SEPARATAMENTE, e la ragione dice quale
        // non e' stata raggiunta: «sotto soglia» senza dire quale costringe chi
        // indaga a rileggere le impostazioni per indovinare.
        let contenuti = u32::try_from(event.assessment.contents).unwrap_or(u32::MAX);
        if contenuti < settings.cyber_minimum_contents {
            return Ok(CyberNotificationOutcome::Suppressed(
                CyberSuppressionReason::TooFewContents,
            ));
        }
        let fonti = u32::try_from(event.assessment.distinct_sources).unwrap_or(u32::MAX);
        if fonti < settings.cyber_minimum_sources {
            return Ok(CyberNotificationOutcome::Suppressed(
                CyberSuppressionReason::TooFewSources,
            ));
        }

        // Evita di comporre un avviso che verrebbe comunque scartato. NON e' la
        // garanzia: quella e' il vincolo unico, letto qui sotto.
        if self
            .database()
            .cyber_notification_exists(session_id, &kind, &value)?
        {
            return Ok(CyberNotificationOutcome::Suppressed(
                CyberSuppressionReason::AlreadyNotified,
            ));
        }

        // Si registra PRIMA di emettere: la registrazione e' la deduplica, e un
        // avviso mostrato ma non registrato tornerebbe a ogni ciclo.
        let inserted = self
            .database()
            .insert_cyber_notification(&NewCyberNotification {
                session_id,
                indicator_kind: kind.clone(),
                indicator_value: value.clone(),
                contents: event.assessment.contents,
                distinct_sources: event.assessment.distinct_sources,
                privacy: settings.privacy,
                emitted_at: now,
            })?;
        if inserted.is_none() {
            return Ok(CyberNotificationOutcome::Suppressed(
                CyberSuppressionReason::AlreadyNotified,
            ));
        }

        self.audit(actor, session_id, event, settings.privacy, now)?;
        notifier.deliver(&compose(settings.privacy, event, now));

        Ok(CyberNotificationOutcome::Emitted { kind, value })
    }

    /// Registra nell'audit l'emissione di un avviso cyber.
    ///
    /// # Che cosa entra nel dettaglio, e che cosa no
    ///
    /// Entrano la **ragione** del grappolo e le sue dimensioni al momento
    /// dell'avviso: sono ciò che permette di rileggere, mesi dopo, che cosa
    /// l'operatore aveva davanti quando il prodotto ha chiesto la sua
    /// attenzione.
    ///
    /// Non entra il testo dei contenuti. L'audit documenta che un avviso è
    /// stato emesso e su che cosa, non che cosa i messaggi dicevano.
    fn audit(
        &self,
        actor: &Actor,
        session_id: SessionId,
        event: &WatchEvent,
        privacy: NotificationPrivacy,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let dettaglio = format!(
            "{}; {} contenuti da {} fonti distinte; riservatezza {}",
            event.event.reason.as_sentence(),
            event.assessment.contents,
            event.assessment.distinct_sources,
            privacy.as_str()
        );

        self.database().append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("avviso_cyber_emesso")?,
            entity: AuditEntity::try_new("session")?,
            entity_id: Some(session_id.get()),
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&dettaglio)?),
            recorded_at: now,
        })?;
        Ok(())
    }
}

/// Gli identificativi dei contenuti del grappolo, ordinati.
///
/// Servono al confronto fra grappoli: due correlazioni distinte sugli **stessi
/// messaggi** sono la stessa storia raccontata due volte, e l'ordine stabile
/// rende il confronto ripetibile.
fn members_of(event: &WatchEvent) -> Vec<i64> {
    let mut ids: Vec<i64> = event
        .event
        .members
        .iter()
        .map(|member| member.content_id)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// La chiave che identifica un grappolo dentro una sessione.
fn key_of(event: &WatchEvent) -> (String, String) {
    match &event.event.reason {
        CorrelationReason::SameIndicator { kind, value } => {
            (String::from(kind.as_str()), value.clone())
        }
    }
}

/// Compone l'avviso secondo la riservatezza scelta.
///
/// # Perché la riservatezza conta qui più che altrove
///
/// Una notifica compare su una **schermata bloccata**, dove la legge chiunque
/// passi. Un indicatore tecnico non sembra sensibile — una CVE è pubblica — ma
/// un dominio o un indirizzo dicono **che cosa questo ufficio sta guardando**,
/// e quello non è pubblico.
///
/// In modalità ridotta e riservata l'indicatore **non compare**: l'avviso dice
/// che c'è qualcosa da guardare, e dove guardarlo.
fn compose(privacy: NotificationPrivacy, event: &WatchEvent, now: Timestamp) -> Notification {
    let (title, body) = match privacy {
        // # Perché il testo non contiene una negazione
        //
        // La prima stesura scriveva «**Non** è un attacco confermato: è un
        // invito a guardare». Sembrava prudente, e su una schermata bloccata è
        // il contrario: una notifica si legge di sfuggita, e una negazione
        // letta di sfuggita si ricorda al rovescio. Chi passa davanti legge
        // «attacco confermato» e va via.
        //
        // L'avviso dice **che cosa ha trovato**, e la spiegazione sta dove c'è
        // spazio per leggerla — la schermata «Segnali cyber», che la porta in cima
        // e per intero.
        //
        // La prova che rifiuta le formule vietate ha segnalato questa frase, e
        // aveva ragione: un controllo sul testo non distingue un'affermazione
        // da una negazione, e nemmeno chi legge in fretta.
        NotificationPrivacy::Full => (
            format!("{PRODUCT_NAME} \u{2014} segnali da guardare insieme"),
            format!(
                "{} contenuti che {}.\nDa {} fonti distinte. Aprire «Segnali cyber».",
                event.assessment.contents,
                event.event.reason.as_sentence(),
                event.assessment.distinct_sources
            ),
        ),
        NotificationPrivacy::Reduced => (
            format!("{PRODUCT_NAME} \u{2014} segnali da guardare insieme"),
            format!(
                "{} contenuti da {} fonti distinte nominano lo stesso indicatore tecnico. \
                 Aprire «Segnali cyber».",
                event.assessment.contents, event.assessment.distinct_sources
            ),
        ),
        // Riservata: nemmeno i conteggi. Su una schermata bloccata «14
        // contenuti da 6 fonti» dice a chi passa che cosa sta succedendo in
        // questo ufficio, e chi ha scelto questa modalita' ha chiesto che non
        // lo dica.
        NotificationPrivacy::Confidential => (
            String::from(PRODUCT_NAME),
            String::from("C'è qualcosa da guardare in «Segnali cyber»."),
        ),
    };

    Notification {
        title,
        body,
        url: None,
        // Il livello NON viene dal grappolo: un grappolo non ha un livello, e
        // attribuirgliene uno confonderebbe la correlazione con la gravita' —
        // che il motore 0-4 decide sui dizionari, e che ADR-0035 Decisione 10
        // tiene separata. Zero significa «nessun livello», e chi mostra
        // l'avviso non deve derivarne testo.
        level: 0,
        content_id: None,
        emitted_at: now,
        privacy,
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::indicator::extract;
    use lisi_core::model::{
        NewContent, NewSession, NewSource, NotificationPrivacy, NotificationSettings,
        SessionDuration, SessionState, SourceKind,
    };
    use lisi_core::text::{Actor, ContentBody, DisplayName, RemoteMessageId, SourceIdentifier};
    use lisi_core::{SessionId, Timestamp};

    use super::{CyberNotificationOutcome, CyberNotificationService, CyberSuppressionReason};
    use crate::cyber_watch::CyberWatchService;
    use crate::notification::RecordingNotifier;
    use crate::sources::open_in_memory_database;

    fn adesso() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn operatore() -> Actor {
        let Ok(value) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        value
    }

    /// Impostazioni con gli avvisi cyber **accesi** e soglie basse.
    ///
    /// Il predefinito li ha spenti, ed è giusto: qui si prova che cosa fanno
    /// quando qualcuno li accende.
    fn accesi() -> NotificationSettings {
        NotificationSettings {
            cyber_enabled: true,
            cyber_minimum_contents: 2,
            cyber_minimum_sources: 1,
            ..NotificationSettings::default()
        }
    }

    /// Archivio con i contenuti indicati, ciascuno con la propria fonte.
    ///
    /// Ogni testo arriva da una fonte **diversa**: serve a esercitare la soglia
    /// sulle fonti distinte, che con una fonte sola non si potrebbe provare.
    fn archivio(testi: &[&str]) -> (CyberNotificationService, SessionId) {
        archivio_con_stato(testi, None)
    }

    /// Come [`archivio`], ma con la sessione portata allo stato indicato.
    ///
    /// Lo stato si cambia mentre l'archivio e' ancora posseduto: il servizio lo
    /// tiene in lettura, e un archivio in memoria non si riapre.
    fn archivio_con_stato(
        testi: &[&str],
        stato: Option<SessionState>,
    ) -> (CyberNotificationService, SessionId) {
        let Ok(mut database) = open_in_memory_database() else {
            panic!("l'archivio di prova deve potersi aprire");
        };

        let Ok(attore) = Actor::try_new("responsabile.prova") else {
            panic!("l'attore deve essere valido");
        };

        let mut fonti = Vec::new();
        for numero in 0..testi.len().max(1) {
            let (Ok(identifier), Ok(nome)) = (
                SourceIdentifier::try_new(&format!("canale_{numero}")),
                DisplayName::try_new(&format!("Canale {numero}")),
            ) else {
                panic!("i valori della fonte devono essere validi");
            };
            let Ok(source_id) = database.insert_source(
                &NewSource {
                    kind: SourceKind::Channel,
                    identifier,
                    display_name: nome,
                    authorized_by: attore.clone(),
                    active: true,
                },
                adesso(),
            ) else {
                panic!("la fonte deve potersi registrare");
            };
            fonti.push(source_id);
        }

        let (Ok(etichetta), Ok(avviata_da)) = (
            DisplayName::try_new("Sessione di prova"),
            Actor::try_new("operatore.prova"),
        ) else {
            panic!("i valori della sessione devono essere validi");
        };
        let Ok(session_id) = database.insert_session(
            &NewSession {
                label: etichetta,
                started_by: avviata_da,
                duration: SessionDuration::Manual,
                source_ids: fonti.clone(),
            },
            adesso(),
        ) else {
            panic!("la sessione deve potersi creare");
        };

        for (numero, testo) in testi.iter().enumerate() {
            let (Ok(corpo), Ok(remote)) = (
                ContentBody::try_new(testo),
                RemoteMessageId::try_new(&format!("m-{numero}")),
            ) else {
                panic!("i valori del contenuto devono essere validi");
            };
            let Some(source_id) = fonti.get(numero).copied() else {
                panic!("ogni contenuto deve avere la propria fonte");
            };

            let Ok(inserimento) = database.insert_content(&NewContent {
                session_id,
                source_id,
                remote_message_id: remote,
                author: None,
                author_identifier: None,
                author_username: None,
                body: corpo,
                url: None,
                published_at: adesso(),
                acquired_at: adesso(),
                origin: lisi_core::model::AcquisitionOrigin::Observed,
                analysis_level: lisi_core::model::analysis::AnalysisLevel::NOT_RELEVANT,
            }) else {
                panic!("il contenuto deve potersi registrare");
            };
            let estrazione = extract(testo);
            let Ok(_) = database
                .insert_content_indicators(inserimento.content_id(), &estrazione.indicators)
            else {
                panic!("gli indicatori devono potersi registrare");
            };
        }

        // Una sessione nasce «pianificata» e non salta a «sospesa»: la macchina
        // a stati passa da «in corso», e la prova deve percorrere la stessa
        // strada del prodotto invece di forzare una riga.
        if let Some(voluto) = stato {
            let Ok(()) = database.update_session_state(session_id, SessionState::Running, adesso())
            else {
                panic!("la sessione deve potersi avviare");
            };
            if voluto != SessionState::Running {
                let Ok(()) = database.update_session_state(session_id, voluto, adesso()) else {
                    panic!("lo stato «{voluto:?}» deve essere raggiungibile da «in corso»");
                };
            }
        }

        // Una connessione sola basta: leggere e registrare passano entrambe
        // da `&Database`.
        let watch = CyberWatchService::new(database);
        (CyberNotificationService::new(watch), session_id)
    }

    /// **Un grappolo produce UN avviso, non uno per contenuto.**
    ///
    /// È la regola che questo modulo esiste per non violare. Sei messaggi che
    /// nominano la stessa CVE sono **una** cosa da guardare: sei riquadri
    /// insegnerebbero all'operatore a chiuderli senza leggerli.
    #[test]
    fn un_grappolo_produce_un_avviso_e_non_uno_per_contenuto() {
        let (servizio, session_id) = archivio(&[
            "allarme per la CVE-2026-1234",
            "anche noi vediamo la CVE-2026-1234",
            "sempre la CVE-2026-1234",
            "ancora CVE-2026-1234",
            "di nuovo CVE-2026-1234",
            "e infine CVE-2026-1234",
        ]);

        let mut notificatore = RecordingNotifier::default();
        let Ok(esiti) = servizio.consider_session(
            session_id,
            accesi(),
            &operatore(),
            adesso(),
            &mut notificatore,
        ) else {
            panic!("la valutazione deve riuscire");
        };

        let emessi = esiti.iter().filter(|esito| esito.is_emitted()).count();
        assert_eq!(emessi, 1, "un grappolo, un avviso: {esiti:?}");
        assert_eq!(
            notificatore.delivered().len(),
            1,
            "sei contenuti non devono produrre sei riquadri"
        );
    }

    /// **Il secondo giro non riannuncia lo stesso grappolo.**
    ///
    /// La deduplica è il vincolo unico dello schema, non un controllo
    /// applicativo: chiamare due volte deve restare innocuo anche se qualcosa è
    /// cambiato fra le due chiamate.
    #[test]
    fn lo_stesso_grappolo_non_si_annuncia_due_volte() {
        let (servizio, session_id) = archivio(&[
            "allarme per la CVE-2026-4321",
            "anche noi vediamo la CVE-2026-4321",
        ]);

        let mut notificatore = RecordingNotifier::default();
        let Ok(_) = servizio.consider_session(
            session_id,
            accesi(),
            &operatore(),
            adesso(),
            &mut notificatore,
        ) else {
            panic!("la prima valutazione deve riuscire");
        };
        assert_eq!(notificatore.delivered().len(), 1);

        let Ok(esiti) = servizio.consider_session(
            session_id,
            accesi(),
            &operatore(),
            adesso(),
            &mut notificatore,
        ) else {
            panic!("la seconda valutazione deve riuscire");
        };

        assert_eq!(
            notificatore.delivered().len(),
            1,
            "il secondo giro non deve aggiungere riquadri"
        );
        assert!(
            esiti.iter().any(|esito| matches!(
                esito,
                CyberNotificationOutcome::Suppressed(CyberSuppressionReason::AlreadyNotified)
            )),
            "e la ragione deve dirlo: {esiti:?}"
        );
    }

    /// **Spenti per difetto: niente avvisi, e nemmeno una lettura.**
    #[test]
    fn spenti_per_difetto_non_si_annuncia_nulla() {
        let (servizio, session_id) = archivio(&[
            "allarme per la CVE-2026-1111",
            "anche noi vediamo la CVE-2026-1111",
        ]);

        let mut notificatore = RecordingNotifier::default();
        let Ok(esiti) = servizio.consider_session(
            session_id,
            NotificationSettings::default(),
            &operatore(),
            adesso(),
            &mut notificatore,
        ) else {
            panic!("la valutazione deve riuscire");
        };

        assert!(notificatore.delivered().is_empty());
        assert_eq!(
            esiti,
            vec![CyberNotificationOutcome::Suppressed(
                CyberSuppressionReason::Disabled
            )],
            "spento significa spento, e la ragione lo dice"
        );
    }

    /// **Le due soglie sono distinte, e la ragione dice quale non è passata.**
    ///
    /// «Sotto soglia» senza dire quale costringe chi indaga a rileggere le
    /// impostazioni per indovinare.
    #[test]
    fn le_due_soglie_si_distinguono_nella_ragione() {
        let (servizio, session_id) = archivio(&[
            "allarme per la CVE-2026-2222",
            "anche noi vediamo la CVE-2026-2222",
        ]);
        let mut notificatore = RecordingNotifier::default();

        // Soglia sui contenuti troppo alta: due contenuti non bastano.
        let Ok(esiti) = servizio.consider_session(
            session_id,
            NotificationSettings {
                cyber_minimum_contents: 5,
                ..accesi()
            },
            &operatore(),
            adesso(),
            &mut notificatore,
        ) else {
            panic!("la valutazione deve riuscire");
        };
        assert!(
            esiti.iter().any(|esito| matches!(
                esito,
                CyberNotificationOutcome::Suppressed(CyberSuppressionReason::TooFewContents)
            )),
            "la ragione deve nominare i CONTENUTI: {esiti:?}"
        );
        assert!(notificatore.delivered().is_empty());

        // Soglia sulle fonti troppo alta: due fonti non bastano.
        let Ok(esiti) = servizio.consider_session(
            session_id,
            NotificationSettings {
                cyber_minimum_sources: 9,
                ..accesi()
            },
            &operatore(),
            adesso(),
            &mut notificatore,
        ) else {
            panic!("la valutazione deve riuscire");
        };
        assert!(
            esiti.iter().any(|esito| matches!(
                esito,
                CyberNotificationOutcome::Suppressed(CyberSuppressionReason::TooFewSources)
            )),
            "la ragione deve nominare le FONTI: {esiti:?}"
        );
        assert!(notificatore.delivered().is_empty());
    }

    /// **La riservatezza governa che cosa l'avviso rivela.**
    ///
    /// Una notifica compare su una schermata bloccata, dove la legge chiunque
    /// passi. Un dominio o un indirizzo dicono **che cosa questo ufficio sta
    /// guardando**, e quello non è pubblico.
    #[test]
    fn la_riservatezza_decide_che_cosa_l_avviso_rivela() {
        let testi = [
            "allarme su ministero.gov.it per la CVE-2026-3333",
            "anche noi vediamo ministero.gov.it, CVE-2026-3333",
        ];

        for (privacy, deve_contenere_indicatore) in [
            (NotificationPrivacy::Full, true),
            (NotificationPrivacy::Reduced, false),
            (NotificationPrivacy::Confidential, false),
        ] {
            let (servizio, session_id) = archivio(&testi);
            let mut notificatore = RecordingNotifier::default();

            let Ok(_) = servizio.consider_session(
                session_id,
                NotificationSettings {
                    privacy,
                    ..accesi()
                },
                &operatore(),
                adesso(),
                &mut notificatore,
            ) else {
                panic!("la valutazione deve riuscire");
            };

            let Some(avviso) = notificatore.delivered().first() else {
                panic!("l'avviso deve essere stato emesso con {privacy:?}");
            };
            let testo = format!("{} {}", avviso.title, avviso.body);

            // I due messaggi nominano un dominio E una CVE, quindi formano due
            // grappoli; l'aggregazione ne annuncia uno solo, e quale dei due sia
            // dipende dall'ordine stabile della correlazione. La prova non deve
            // dipendere da quello: controlla che NESSUNO dei due indicatori
            // compaia, o che ne compaia almeno uno.
            let indicatori = ["CVE-2026-3333", "ministero.gov.it"];
            let compare = indicatori.iter().any(|valore| testo.contains(valore));

            assert_eq!(
                compare,
                deve_contenere_indicatore,
                "con {privacy:?} un indicatore {} comparire: «{testo}»",
                if deve_contenere_indicatore {
                    "deve"
                } else {
                    "NON deve"
                }
            );

            // In modalita' riservata nemmeno i conteggi: «14 contenuti da 6
            // fonti» dice a chi passa che cosa sta succedendo in questo ufficio.
            if privacy == NotificationPrivacy::Confidential {
                assert!(
                    !testo.chars().any(|carattere| carattere.is_ascii_digit())
                        || testo.contains("NEXUM/97"),
                    "la modalita' riservata non deve portare conteggi: «{testo}»"
                );
            }

            // E in NESSUNA modalita' l'avviso dichiara un attacco.
            let minuscolo = testo.to_lowercase();
            for vietata in [
                "attacco confermato",
                "fonti indipendenti",
                "incidente confermato",
            ] {
                assert!(
                    !minuscolo.contains(vietata),
                    "con {privacy:?} l'avviso contiene «{vietata}»: «{testo}»"
                );
            }
        }
    }

    /// **L'avviso non porta un livello, perché un grappolo non ne ha uno.**
    ///
    /// Attribuirgliene uno confonderebbe la correlazione con la gravità, che il
    /// motore 0-4 decide sui dizionari e che ADR-0035 Decisione 10 tiene
    /// separata.
    #[test]
    fn l_avviso_non_attribuisce_un_livello_al_grappolo() {
        let (servizio, session_id) = archivio(&[
            "allarme per la CVE-2026-5151",
            "anche noi vediamo la CVE-2026-5151",
        ]);

        let mut notificatore = RecordingNotifier::default();
        let Ok(_) = servizio.consider_session(
            session_id,
            accesi(),
            &operatore(),
            adesso(),
            &mut notificatore,
        ) else {
            panic!("la valutazione deve riuscire");
        };

        let Some(avviso) = notificatore.delivered().first() else {
            panic!("l'avviso deve essere stato emesso");
        };
        assert_eq!(avviso.level, 0, "un grappolo non ha un livello");
        assert_eq!(
            avviso.content_id, None,
            "un grappolo non ha UN contenuto: sceglierne uno direbbe il falso"
        );
    }

    /// **L'emissione entra nell'audit con la ragione del grappolo.**
    ///
    /// È ciò che permette di rileggere, mesi dopo, che cosa l'operatore aveva
    /// davanti quando il prodotto ha chiesto la sua attenzione.
    #[test]
    fn l_avviso_entra_nell_audit_con_la_ragione() {
        let (servizio, session_id) = archivio(&[
            "allarme per la CVE-2026-6161",
            "anche noi vediamo la CVE-2026-6161",
        ]);

        let mut notificatore = RecordingNotifier::default();
        let Ok(_) = servizio.consider_session(
            session_id,
            accesi(),
            &operatore(),
            adesso(),
            &mut notificatore,
        ) else {
            panic!("la valutazione deve riuscire");
        };

        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let Some(voce) = voci
            .iter()
            .find(|voce| voce.action.as_str() == "avviso_cyber_emesso")
        else {
            panic!("la voce di audit deve esistere: {voci:?}");
        };
        let Some(dettaglio) = voce.detail.as_ref() else {
            panic!("la voce deve portare un dettaglio");
        };

        assert!(
            dettaglio.as_str().contains("2026-6161"),
            "l'audit deve dire PERCHE' il grappolo esisteva: «{}»",
            dettaglio.as_str()
        );
        assert!(
            dettaglio.as_str().contains("fonti distinte"),
            "e da quante fonti: «{}»",
            dettaglio.as_str()
        );
    }

    /// **Un grappolo che non c'è non produce nulla.**
    ///
    /// È la condizione ordinaria, e un avviso che comparisse comunque
    /// insegnerebbe a ignorarli tutti.
    #[test]
    fn senza_ricorrenze_non_si_annuncia_nulla() {
        let (servizio, session_id) = archivio(&[
            "una CVE-2026-7171 sola",
            "un dominio esempio.test solo",
            "niente di tecnico qui",
        ]);

        let mut notificatore = RecordingNotifier::default();
        let Ok(esiti) = servizio.consider_session(
            session_id,
            accesi(),
            &operatore(),
            adesso(),
            &mut notificatore,
        ) else {
            panic!("la valutazione deve riuscire");
        };

        assert!(notificatore.delivered().is_empty());
        assert!(esiti.is_empty(), "nessun grappolo, nessun esito: {esiti:?}");
    }

    /// **Due grappoli sugli stessi messaggi producono UN avviso.**
    ///
    /// # Il difetto che questa prova ha trovato scrivendone un'altra
    ///
    /// Due messaggi che nominano **insieme** un dominio e una CVE formano due
    /// grappoli — uno per indicatore — e sono correlazioni davvero distinte.
    /// Ma per chi legge sono **gli stessi due messaggi**, e due riquadri
    /// chiedono di guardare due volte la stessa cosa.
    ///
    /// Se ne è accorta la prova sulla riservatezza, che si aspettava un avviso
    /// e ne trovava due. È esattamente la tempesta che questo modulo esiste per
    /// evitare, in una forma che scrivendolo non era stata prevista.
    ///
    /// I due grappoli **restano** e si vedono in «Segnali cyber», dove è giusto che
    /// compaiano separati. È l'avviso a non ripetersi.
    #[test]
    fn due_grappoli_sugli_stessi_messaggi_producono_un_avviso_solo() {
        let (servizio, session_id) = archivio(&[
            "problema su ministero.gov.it per la CVE-2026-8888",
            "confermo su ministero.gov.it, CVE-2026-8888",
        ]);

        // Che i due grappoli esistano davvero: senza questo, la prova potrebbe
        // passare perche' ce n'e' uno solo, e non proverebbe nulla.
        let Ok(grappoli) = servizio.watch.events(session_id) else {
            panic!("i grappoli devono potersi leggere");
        };
        assert_eq!(
            grappoli.len(),
            2,
            "i due messaggi devono formare due grappoli: uno sul dominio, uno sulla CVE"
        );

        let mut notificatore = RecordingNotifier::default();
        let Ok(esiti) = servizio.consider_session(
            session_id,
            accesi(),
            &operatore(),
            adesso(),
            &mut notificatore,
        ) else {
            panic!("la valutazione deve riuscire");
        };

        assert_eq!(
            notificatore.delivered().len(),
            1,
            "gli stessi due messaggi non chiedono di essere guardati due volte"
        );
        assert!(
            esiti.iter().any(|esito| matches!(
                esito,
                CyberNotificationOutcome::Suppressed(CyberSuppressionReason::AlreadyCovered)
            )),
            "e la ragione deve dire che era gia' coperto: {esiti:?}"
        );
    }

    /// **Due grappoli su messaggi DIVERSI producono due avvisi.**
    ///
    /// È il rovescio della prova precedente, e senza di essa l'aggregazione
    /// potrebbe spegnere avvisi legittimi senza che nulla lo segnali. Un
    /// grappolo che non condivide i contenuti con un altro è un'altra storia, e
    /// merita di essere annunciata.
    #[test]
    fn due_grappoli_su_messaggi_diversi_producono_due_avvisi() {
        let (servizio, session_id) = archivio(&[
            "allarme per la CVE-2026-1010",
            "anche noi vediamo la CVE-2026-1010",
            "problema diverso: CVE-2026-2020",
            "confermo la CVE-2026-2020",
        ]);

        let mut notificatore = RecordingNotifier::default();
        let Ok(_) = servizio.consider_session(
            session_id,
            accesi(),
            &operatore(),
            adesso(),
            &mut notificatore,
        ) else {
            panic!("la valutazione deve riuscire");
        };

        assert_eq!(
            notificatore.delivered().len(),
            2,
            "due storie distinte meritano due avvisi"
        );
    }

    /// **Avvisi sospesi: la sessione acquisisce, i grappoli tacciono.**
    #[test]
    fn con_gli_avvisi_sospesi_nessun_grappolo_si_annuncia() {
        let (servizio, session_id) = archivio_con_stato(
            &[
                "allarme per la CVE-2026-3030",
                "anche noi vediamo la CVE-2026-3030",
            ],
            Some(SessionState::Paused),
        );

        let mut notificatore = RecordingNotifier::default();
        let Ok(esiti) = servizio.consider_session(
            session_id,
            accesi(),
            &operatore(),
            adesso(),
            &mut notificatore,
        ) else {
            panic!("la valutazione deve riuscire");
        };

        assert!(notificatore.delivered().is_empty());
        assert_eq!(
            esiti,
            vec![CyberNotificationOutcome::Suppressed(
                CyberSuppressionReason::AlertsSuspended
            )]
        );
    }
}

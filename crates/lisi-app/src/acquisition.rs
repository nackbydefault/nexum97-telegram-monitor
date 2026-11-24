//! Collegamento fra il connettore Telegram e il motore di acquisizione.
//!
//! Esiste per una ragione precisa, e vale la pena scriverla: fino al
//! 2026-07-30 `AcquisitionService` era completamente costruito e collaudato ma
//! **non chiamato da nessuna parte** — nessun riferimento fuori dal proprio
//! file. Il motore c'era, la schermata di monitoraggio pure, e non arrivava
//! mai un contenuto. È la stessa forma dell'incidente del 2026-07-26, in cui
//! `AuthenticationService::pump_events` era implementata, testata e mai
//! invocata.
//!
//! ## Perché il pompaggio dell'accesso e non un secondo consumatore
//!
//! `AcquisitionService::drain` sa leggere da sé dal connettore, e sarebbe
//! stata la strada ovvia. È però la strada sbagliata qui: il pompaggio
//! dell'accesso (`AuthenticationService::pump_events`) chiama già
//! `poll_event` ogni 200 ms, e i due consumatori sono ciascuno cieco a ciò che
//! interessa all'altro — `drain` scarta gli eventi di autorizzazione, il
//! pompaggio dell'accesso scartava i contenuti. Con entrambi attivi sulla
//! stessa coda vince chi arriva primo e gli eventi dell'altro spariscono, in
//! modo intermittente e senza alcun errore: per un prodotto di monitoraggio,
//! la perdita silenziosa di contenuti.
//!
//! Quindi: **un solo consumatore**, il pompaggio dell'accesso, che ora
//! conserva ciò che non lo riguarda; e una consegna esplicita a questo modulo,
//! che ingerisce evento per evento. La corsa non esiste per costruzione.

use std::collections::BTreeMap;

use lisi_core::model::monitoring_account::OpenAccounts;
use lisi_core::{ContentId, SessionId, SourceId, Timestamp};
use lisi_services::AccountRuntime;
use lisi_services::acquisition::{AcquisitionService, RaisedAlert, SessionContext};
use lisi_services::hub_live::HubLivePublisher;
use lisi_services::monitoring::{MonitoringService, ScheduleOutcome};
use lisi_services::notification::NotificationService;
use lisi_services::settings::SettingsService;

thread_local! {
    /// Contenuti recuperati dallo storico da annunciare al prossimo giro
    /// (NOTIFY-BACKFILL-01, ADR-0188).
    static RECUPERATI: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Segnala che un'archiviazione ha aggiunto contenuti recuperati: al prossimo
/// giro il ciclo li annuncia con un avviso solo.
pub fn mark_recovered() {
    RECUPERATI.with(|segnale| segnale.set(true));
}

/// Nome registrato nell'audit per le operazioni condotte dal ciclo automatico.
const AUDIT_ACTOR: &str = "acquisizione";

/// Sorgente di questo modulo, letta a tempo di compilazione.
///
/// Serve a una sola verifica, dichiaratamente strutturale e non funzionale:
/// che i due motori collegati da qui abbiano davvero un chiamante. Vedere
/// `tests::the_engines_this_module_exists_to_call_are_actually_called`.
#[cfg(test)]
const THIS_MODULE: &str = include_str!("acquisition.rs");

/// Quanti eventi al massimo si ingeriscono in una singola tornata.
///
/// Il pompaggio gira sul thread dell'interfaccia: una fonte molto attiva non
/// deve poter tenere la finestra ferma. Ciò che avanza resta in coda e viene
/// ingerito alla tornata successiva, 200 ms dopo: la coda ne cede al più
/// questo numero (`take_pending_events(INGEST_BUDGET)`), e non si svuota.
const INGEST_BUDGET: usize = 64;

/// Ogni quanto, al più, si scrive nell'audit che la coda ha scartato eventi.
const DROPPED_DECLARATION_INTERVAL_MS: i64 = 60_000;

/// Motore di acquisizione più ciò che serve a sapere **dove** ingerire.
pub struct AcquisitionPump {
    service: AcquisitionService,
    /// Connessione propria allo stesso archivio, usata solo per sapere quali
    /// monitoraggi siano in corso. Ogni servizio apre la sua: è l'idioma già
    /// usato dal resto dell'applicazione.
    monitoring: MonitoringService,
    /// Contesti dei monitoraggi in corso, tenuti da parte per non rileggerli
    /// dall'archivio a ogni tornata da 200 ms.
    ///
    /// Sono **piu' d'uno** perche' i monitoraggi possono esserlo (ADR-0065), e
    /// si rileggono solo quando l'insieme dei monitoraggi in corso cambia.
    contexts: Vec<(SessionId, SessionContext)>,
    /// Motore decisionale delle notifiche.
    ///
    /// Va chiamato **da qui**, sui contenuti appena ingeriti: è l'unico punto
    /// del prodotto che sappia quando un contenuto è appena arrivato. Fino al
    /// 2026-07-31 `NotificationService::consider` non era chiamata da nessuna
    /// parte fuori dal proprio file — il quarto motore costruito, collaudato e
    /// mai invocato di questa serie, dopo il pompaggio degli eventi,
    /// l'acquisizione e il registro delle chat.
    notifications: NotificationService,
    /// Impostazioni delle notifiche, rilette a ogni tornata **utile**.
    ///
    /// Non tenute da parte: l'operatore può cambiarle dalla schermata
    /// Impostazioni mentre il monitoraggio è in corso, e una copia stantia
    /// applicherebbe una soglia che l'operatore crede di aver cambiato. La
    /// lettura avviene solo quando c'è davvero un contenuto da valutare, non
    /// a ogni tick da 200 ms.
    settings: SettingsService,
    /// Chi mostra l'avviso di Windows.
    ///
    /// **Vive quanto il ciclo, e non quanto la singola tornata.** Ricrearlo a
    /// ogni gruppo di contenuti — com'era nella prima stesura — avrebbe
    /// azzerato ogni volta ciò che ha già imparato: su una postazione dove il
    /// sistema non mostra avvisi, la spiegazione sarebbe finita nel registro a
    /// ogni tornata invece che una volta sola, e chi lo rilegge cercherebbe un
    /// problema nuovo dentro la stessa riga ripetuta cento volte.
    notifier: crate::toast::WindowsToastNotifier,
    /// Chi pubblica il live condiviso, **quando questa postazione è l'Hub**.
    ///
    /// Assente su una postazione Standalone e su un client: il live lo produce
    /// l'autorità che acquisisce, una volta sola per tutto l'ufficio
    /// (TEAM-LIVE-01, ADR-0093).
    live: Option<HubLivePublisher>,
    /// Quanti eventi scartati dalla coda sono già stati dichiarati, e quando
    /// (FR-012): uno per account, per il suo identificativo.
    dropped: BTreeMap<i64, DroppedLedger>,
    /// Se un monitoraggio si è concluso per durata dall'ultima
    /// [`AcquisitionPump::take_concluded`].
    concluded: bool,
}

/// Il conto degli eventi scartati già dichiarati (FINAL-REVIEW-01, FR-012).
#[derive(Debug, Default)]
struct DroppedLedger {
    /// Il totale del runtime al momento dell'ultima dichiarazione.
    declared: u64,
    /// Quando è stata scritta l'ultima dichiarazione.
    declared_at: Option<Timestamp>,
}

impl DroppedLedger {
    /// Quanti eventi scartati vanno dichiarati adesso, se qualcuno.
    ///
    /// `total` è il conteggio del runtime: se è più basso di quello già
    /// dichiarato, il runtime è nuovo e il conto riparte da zero. Una
    /// dichiarazione si scrive al più ogni [`DROPPED_DECLARATION_INTERVAL_MS`];
    /// ciò che si perde nel frattempo non si dimentica, entra nella successiva.
    fn due(&mut self, total: u64, now: Timestamp) -> Option<u64> {
        if total < self.declared {
            self.declared = 0;
        }
        if total == self.declared {
            return None;
        }
        if self
            .declared_at
            .is_some_and(|prima| now.millis_since(prima) < DROPPED_DECLARATION_INTERVAL_MS)
        {
            return None;
        }
        let nuovi = total - self.declared;
        self.declared = total;
        self.declared_at = Some(now);
        Some(nuovi)
    }
}

/// Il nome con cui una fonte compare nel live condiviso.
///
/// È l'identificativo tecnico — `@nomecanale` — e non il nome dato
/// dall'ufficio: due uffici che si scambiano un fascicolo devono leggere la
/// stessa riga, e il nome locale può essere diverso su ogni postazione.
fn nome_della_fonte(database: &lisi_services::Database, source_id: i64) -> Option<String> {
    let fonte = database.source(SourceId::new(source_id)).ok()?;
    Some(String::from(fonte.identifier.as_str()))
}

/// Costruisce il ciclo di acquisizione, se tutti gli archivi sono apribili.
///
/// Ogni servizio apre la propria connessione allo stesso archivio: è l'idioma
/// già usato dal resto dell'applicazione.
pub fn create_service(
    acquisition_database: Option<lisi_services::Database>,
    monitoring_database: Option<lisi_services::Database>,
    notification_database: Option<lisi_services::Database>,
    settings_database: Option<lisi_services::Database>,
) -> Option<AcquisitionPump> {
    Some(AcquisitionPump {
        service: AcquisitionService::new(acquisition_database?),
        monitoring: MonitoringService::new(monitoring_database?),
        notifications: NotificationService::new(notification_database?),
        settings: SettingsService::new(settings_database?),
        contexts: Vec::new(),
        notifier: crate::toast::WindowsToastNotifier::default(),
        live: None,
        dropped: BTreeMap::new(),
        concluded: false,
    })
}

impl AcquisitionPump {
    /// Collega il produttore del live condiviso.
    ///
    /// Lo riceve già costruito: decidere **se** questa postazione è un Hub
    /// spetta a chi avvia l'applicazione, non al ciclo di acquisizione.
    #[must_use]
    pub fn with_hub_live(mut self, live: Option<HubLivePublisher>) -> Self {
        self.live = live;
        self
    }

    /// Un giro del ciclo: scadenze, inizi programmati, e gli eventi di ogni
    /// account aperto, ciascuno ai monitoraggi del suo account (ADR-0173).
    ///
    /// Prende i runtime e non un elenco di eventi per una ragione di confine,
    /// non di comodità: `lisi-app` dipende **solo** da `lisi-core` e
    /// `lisi-services` (ADR-0010, con un test che legge il manifest e rifiuta
    /// le dipendenze vietate), quindi non può nominare il tipo degli eventi,
    /// che vive in `lisi-telegram`. Ritirandoli qui il tipo resta inferito e il
    /// confine intatto.
    ///
    /// Si chiama a ogni giro **anche senza account aperti**: una durata scade
    /// con il tempo, e un inizio in orario senza il suo account è mancato.
    ///
    /// Restituisce quanti eventi sono stati davvero ingeriti. Zero non è un
    /// errore: è il caso normale di una fonte silenziosa o di un monitoraggio
    /// non in corso.
    pub fn ingest_all(&mut self, runtimes: &mut [&mut AccountRuntime], now: Timestamp) -> usize {
        // LA SCADENZA PRIMA DI TUTTO (E2E01-01, ADR-0145). Con lo stesso `now`
        // con cui si ingerisce: un monitoraggio scaduto esce dall'elenco di chi
        // acquisisce prima che un solo evento gli venga attribuito. Sta prima
        // del ritorno anticipato, perché una fonte silenziosa non deve tenere
        // aperto un monitoraggio finito.
        self.conclude_due(now);
        // L'INIZIO PROGRAMMATO NELLA STESSA TORNATA (SCHEDULE-01, ADR-0171):
        // un monitoraggio che parte adesso riceve gli eventi di questo giro.
        // Parte se è pronto il SUO account (ADR-0173), non uno qualunque.
        let mut aperti = OpenAccounts::none();
        for runtime in runtimes.iter() {
            aperti.add(runtime.account_uuid().clone(), runtime.is_ready());
        }
        self.start_due(now, &aperti);
        let mut ingeriti = 0_usize;
        for runtime in runtimes.iter_mut() {
            ingeriti += self.ingest_from(runtime, aperti.open(), now);
        }
        ingeriti
    }

    /// Ritira dal runtime di un account gli eventi che il pompaggio
    /// dell'accesso ha letto e non ha usato, e li ingerisce nei monitoraggi di
    /// quell'account soltanto.
    ///
    /// `open` è quanti account sono aperti in questo giro: un monitoraggio
    /// senza account riceve soltanto quando è uno solo.
    fn ingest_from(&mut self, runtime: &mut AccountRuntime, open: usize, now: Timestamp) -> usize {
        self.declare_dropped(runtime, now);
        if !runtime.has_pending_events() {
            // Nessuna lettura dall'archivio quando non c'è nulla da fare: il
            // caso di gran lunga più frequente, ed è su un timer da 200 ms.
            return 0;
        }

        // Un archivio che non risponde NON è «nessun monitoraggio in corso»:
        // gli eventi restano in coda e si riprovano alla tornata successiva
        // (la coda ha il suo tetto, e ciò che lo supera è contato).
        let Some(running) = self.acquiring_sessions() else {
            return 0;
        };
        if !running.is_empty() {
            self.ensure_contexts(&running);
            if self.contexts.is_empty() {
                // Contesti non leggibili: stessa ragione, gli eventi restano.
                return 0;
            }
        }

        // IL CONSUMATORE E' UNO, E DISTRIBUISCE (ADR-0065).
        //
        // Gli eventi si ritirano UNA VOLTA, qui, e si attribuiscono a ogni
        // monitoraggio in corso: dare a ciascun monitoraggio il proprio ritiro
        // perderebbe eventi in silenzio, perche' la coda si svuota leggendola.
        //
        // SI RITIRA SOLO CIO' CHE SI INGERISCE (FINAL-REVIEW-01, FR-001). Fino
        // al 2026-10-03 il ritiro svuotava la coda e il ciclo ne trattava
        // sessantaquattro: il resto usciva di scena con il vettore, senza
        // conteggio. Ora la coda cede al piu' `INGEST_BUDGET` eventi, e cio'
        // che avanza resta li' per la tornata successiva.
        //
        // Senza monitoraggi in corso gli eventi non appartengono ad alcuna
        // sessione e non vanno registrati: si ritirano tutti e si lasciano
        // andare. Non è una perdita di contenuti sorvegliati, è l'assenza di
        // sorveglianza.
        //
        // OGNI EVENTO AL SUO ACCOUNT (MULTI-ACCOUNT-02, ADR-0173, decisione
        // 3). Gli eventi di questo runtime appartengono ai soli monitoraggi
        // legati al suo account: se nessuno lo è, valgono come «nessun
        // monitoraggio in corso» per questo account, anche se altri account
        // ne hanno.
        let origine = runtime.account_uuid().clone();
        let nessuno = running.is_empty()
            || !self
                .contexts
                .iter()
                .any(|(_, context)| context.accepts_from(&origine, open));
        let quanti = if nessuno { usize::MAX } else { INGEST_BUDGET };
        let events = runtime.take_pending_events(quanti);
        if nessuno {
            return 0;
        }

        // I contesti escono da `self` per la durata del ciclo: `ingest` prende
        // `&mut self.service`, e tenerli prestati da `self.contexts` lo
        // impedirebbe. Vengono rimessi a posto subito dopo, cosi' la tornata
        // successiva non li rilegge dall'archivio.
        let contexts = std::mem::take(&mut self.contexts);

        let mut ingested = 0_usize;
        let mut fresh_content: Vec<ContentId> = Vec::new();
        let mut per_source: BTreeMap<i64, usize> = BTreeMap::new();
        let mut alerts: Vec<RaisedAlert> = Vec::new();
        for event in events.into_iter().take(INGEST_BUDGET) {
            let mut attribuito = false;
            for (session_id, context) in &contexts {
                // La stessa chat seguita da due account non basta: conta
                // l'account da cui l'evento è arrivato.
                if !context.accepts_from(&origine, open) {
                    continue;
                }
                match self.service.ingest(&event, context, now) {
                    Ok(report) => {
                        // IL LIVE CONTA UNA VOLTA SOLA, come il numero degli
                        // eventi (ADR-0065): lo stesso messaggio applicato a
                        // due monitoraggi è un fatto solo, e chi guarda il live
                        // non deve vederlo raddoppiare perché l'ufficio ha due
                        // monitoraggi aperti sulla stessa fonte.
                        if !attribuito {
                            for (fonte, quanti) in report.per_source {
                                *per_source.entry(fonte).or_insert(0) += quanti;
                            }
                            alerts.extend(report.alerts);
                        }
                        attribuito = true;
                        fresh_content.extend(report.content_ids);
                    }
                    Err(error) => {
                        // Un guasto su un singolo evento non deve fermare
                        // l'acquisizione degli altri, ma non deve nemmeno
                        // passare in silenzio: senza questa riga un archivio
                        // incompleto sarebbe indistinguibile da un archivio
                        // completo.
                        tracing::warn!(
                            errore = error.kind(),
                            sessione = session_id.get(),
                            "ingestione di un evento non riuscita: l'evento non e' stato registrato"
                        );
                    }
                }
            }
            // UN EVENTO CONTA UNA VOLTA, non una per monitoraggio: il numero
            // restituito dice quanti EVENTI sono stati trattati, e chi lo legge
            // non deve vederlo raddoppiare perche' i monitoraggi sono due
            // (ADR-0065: i conteggi non si sommano fra monitoraggi).
            if attribuito {
                ingested += 1;
            }
        }

        self.contexts = contexts;
        self.notify(&fresh_content, now);
        self.publish_live(&per_source, &alerts, now);
        ingested
    }

    /// Pubblica sul live condiviso ciò che la tornata ha prodotto.
    ///
    /// Non fa nulla quando questa postazione non è l'Hub. Un guasto qui **non
    /// ferma l'acquisizione**: il live è ciò che gli altri vedono, l'archivio è
    /// ciò che resta, e il secondo viene prima del primo.
    fn publish_live(
        &mut self,
        per_source: &BTreeMap<i64, usize>,
        alerts: &[RaisedAlert],
        now: Timestamp,
    ) {
        if per_source.is_empty() && alerts.is_empty() {
            return;
        }
        let Some(live) = self.live.as_mut() else {
            return;
        };

        // I nomi delle fonti si leggono ora: una copia tenuta da parte
        // mostrerebbe il nome che una fonte aveva prima che qualcuno lo
        // cambiasse.
        let mut conteggi = BTreeMap::new();
        for (source_id, quanti) in per_source {
            let Some(nome) = nome_della_fonte(live.database(), *source_id) else {
                continue;
            };
            conteggi.insert(nome, *quanti);
        }
        if let Err(error) = live.publish_round(&conteggi, now) {
            tracing::warn!(
                errore = error.kind(),
                "la tornata non e' stata pubblicata sul live condiviso"
            );
        }

        for alert in alerts {
            let Some(nome) = nome_della_fonte(live.database(), alert.source_id) else {
                continue;
            };
            let categoria = alert.category.as_ref().map_or_else(
                || String::from("nessuna categoria"),
                |categoria| String::from(categoria.as_str()),
            );
            if let Err(error) = live.publish_alert(&nome, &alert.level.label(), &categoria, now) {
                tracing::warn!(
                    errore = error.kind(),
                    "un avviso non e' stato pubblicato sul live condiviso"
                );
            }
        }
    }

    /// Sottopone al motore delle notifiche i contenuti appena ingeriti.
    ///
    /// Il motore decide da sé se e che cosa notificare: soglia di livello,
    /// avvisi sospesi, doppioni, tetto per sessione. Qui non si decide nulla,
    /// si chiede — e fino al 2026-07-31 **nessuno chiedeva**.
    fn notify(&mut self, content_ids: &[ContentId], now: Timestamp) {
        // I RECUPERATI DALLO STORICO si annunciano qui, con un avviso solo
        // (NOTIFY-BACKFILL-01, ADR-0188): le archiviazioni lo segnalano con
        // [`mark_recovered`], e il notificatore di Windows sta qui.
        let recuperati = RECUPERATI.with(|segnale| segnale.replace(false));
        if content_ids.is_empty() && !recuperati {
            return;
        }

        // Rilette ora e non tenute da parte: l'operatore può cambiarle mentre
        // il monitoraggio è in corso, e una copia stantia applicherebbe una
        // soglia che crede di aver cambiato.
        let mut settings = match self.settings.load() {
            Ok(settings) => settings,
            Err(error) => {
                tracing::warn!(
                    errore = error.kind(),
                    "impostazioni delle notifiche non leggibili: nessuna notifica in questa tornata"
                );
                return;
            }
        };
        // A POSTAZIONE BLOCCATA LA NOTIFICA E' SEMPRE RISERVATA
        // (OPERATOR-E2E-REMEDIATION-01, F-01). Il riquadro di Windows compare
        // sopra la schermata di blocco, che non mostra né fonte né motivazione:
        // con la riservatezza ridotta o completa il riquadro avrebbe detto a chi
        // passa davanti proprio ciò che il blocco nasconde. Il monitoraggio non
        // si ferma e la notifica parte comunque: cambia soltanto che cosa dice,
        // e l'audit registra la riservatezza davvero usata.
        if crate::lock::station_is_locked() {
            settings.privacy = lisi_core::model::NotificationPrivacy::Confidential;
            settings.include_url = false;
        }
        let Ok(actor) = lisi_core::text::Actor::try_new(AUDIT_ACTOR) else {
            tracing::error!("nome dell'attore di audit non valido");
            return;
        };

        // Il riquadro di avviso di Windows (ADR-0025). Se il sistema non lo
        // mostra, ripiega sulla riga **redatta** di prima: la decisione di
        // notificare avviene comunque, ed è quella che conta per l'audit e per
        // il centro notifiche. Il riquadro è la sua resa, non il fatto.
        //
        // Il notificatore è un campo e non una variabile locale: deve ricordare
        // fra una tornata e l'altra ciò che ha già imparato sul sistema.
        for content_id in content_ids {
            if let Err(error) =
                self.notifications
                    .consider(*content_id, settings, &actor, now, &mut self.notifier)
            {
                // Un guasto su un contenuto non deve impedire di valutare gli
                // altri, ma non deve nemmeno passare in silenzio.
                tracing::warn!(
                    errore = error.kind(),
                    "valutazione della notifica non riuscita per un contenuto"
                );
            }
        }
        if recuperati
            && let Err(error) =
                self.notifications
                    .consider_recovered(settings, &actor, now, &mut self.notifier)
        {
            tracing::warn!(
                errore = error.kind(),
                "avviso dei contenuti recuperati non riuscito"
            );
        }
    }

    /// Se la coda degli eventi ne ha scartati dall'ultima volta, lo dice: nel
    /// registro applicativo e nell'audit (FINAL-REVIEW-01, FR-012).
    ///
    /// Il conteggio è del runtime dell'account, e ricomincia da zero quando
    /// l'account si riapre: un valore più basso di quello già dichiarato è un
    /// runtime nuovo, non una perdita che si annulla.
    ///
    /// Una raffica che dura scarta qualcosa a ogni tornata: si dichiara al più
    /// una volta ogni [`DROPPED_DECLARATION_INTERVAL_MS`], con il totale di ciò
    /// che si è perso nel frattempo, perché l'audit non diventi esso stesso la
    /// raffica (cinque righe al secondo, senza fine).
    fn declare_dropped(&mut self, runtime: &AccountRuntime, now: Timestamp) {
        let scartati = runtime.dropped_event_count();
        // Un conto per account: i runtime sono più d'uno (ADR-0173), e il
        // totale di uno non è quello di un altro.
        let conto = self.dropped.entry(runtime.account_id().get()).or_default();
        let Some(nuovi) = conto.due(scartati, now) else {
            return;
        };
        tracing::warn!(
            nuovi,
            totale = scartati,
            "coda degli eventi piena: eventi scartati, non entrati in archivio"
        );
        if let Err(error) = self.service.declare_dropped_events(nuovi, scartati, now) {
            tracing::warn!(
                errore = error.kind(),
                "la perdita di eventi non e' stata scritta nell'audit"
            );
        }
    }

    /// Conclude i monitoraggi la cui durata è trascorsa (E2E01-01).
    ///
    /// Si chiama a ogni giro del ciclo da 200 ms, **anche senza account
    /// collegato**: una durata scade con il tempo, non con la connessione. Il
    /// controllo è una lettura d'archivio su un indice piccolo; chi lo chiama
    /// non deve aspettare la schermata Monitoraggio, che si ridisegna solo
    /// quando la si guarda.
    ///
    /// Restituisce quanti monitoraggi sono stati conclusi in questo giro, e
    /// annota che la schermata e la veglia della postazione vanno riallineate.
    pub fn conclude_due(&mut self, now: Timestamp) -> usize {
        let Ok(actor) = lisi_core::text::Actor::try_new(AUDIT_ACTOR) else {
            tracing::error!("nome dell'attore di audit non valido");
            return 0;
        };
        let concluse = match self.monitoring.conclude_due(&actor, now) {
            Ok(concluse) => concluse,
            Err(error) => {
                tracing::warn!(
                    errore = error.kind(),
                    "scadenze dei monitoraggi non leggibili: si riprova al giro successivo"
                );
                return 0;
            }
        };
        if concluse.is_empty() {
            return 0;
        }

        // Un contesto tenuto per un monitoraggio finito lo farebbe continuare
        // ad acquisire: esce subito, non al prossimo evento.
        self.contexts.retain(|(session_id, _)| {
            !concluse
                .iter()
                .any(|conclusa| conclusa.session_id == *session_id)
        });
        for conclusa in &concluse {
            tracing::info!(
                sessione = conclusa.session_id.get(),
                "monitoraggio concluso: durata pianificata trascorsa"
            );
            if let Some(live) = self.live.as_mut()
                && let Err(error) = live.publish_monitoring_stopped(
                    &conclusa.label,
                    "monitoraggio concluso per durata trascorsa",
                    conclusa.ended_at,
                )
            {
                tracing::warn!(
                    errore = error.kind(),
                    "la conclusione non e' stata annunciata sul live condiviso"
                );
            }
        }
        self.concluded = true;
        concluse.len()
    }

    /// Decide gli inizi programmati giunti all'ora (SCHEDULE-01, ADR-0171).
    ///
    /// Si chiama a ogni giro del ciclo da 200 ms, come [`Self::conclude_due`],
    /// anche senza account: allora un inizio in orario è **mancato** per
    /// l'account, e lo si dice. Un monitoraggio partito entra fra quelli che
    /// acquisiscono nella stessa tornata; uno mancato resta pianificato.
    ///
    /// Restituisce quanti inizi sono stati decisi, e annota che la schermata e
    /// la veglia della postazione vanno riallineate.
    pub fn start_due(&mut self, now: Timestamp, accounts: &OpenAccounts) -> usize {
        let Ok(actor) = lisi_core::text::Actor::try_new(AUDIT_ACTOR) else {
            tracing::error!("nome dell'attore di audit non valido");
            return 0;
        };
        let esiti = match self.monitoring.start_due(&actor, now, accounts) {
            Ok(esiti) => esiti,
            Err(error) => {
                tracing::warn!(
                    errore = error.kind(),
                    "inizi programmati non leggibili: si riprova al giro successivo"
                );
                return 0;
            }
        };
        for esito in &esiti {
            match esito {
                ScheduleOutcome::Started {
                    session_id,
                    label,
                    started_at,
                    ..
                } => {
                    tracing::info!(
                        sessione = session_id.get(),
                        "monitoraggio avviato come programmato"
                    );
                    if let Some(live) = self.live.as_mut()
                        && let Err(error) = live.publish_monitoring_started(
                            label,
                            "monitoraggio avviato come programmato",
                            *started_at,
                        )
                    {
                        tracing::warn!(
                            errore = error.kind(),
                            "l'avvio programmato non e' stato annunciato sul live condiviso"
                        );
                    }
                }
                ScheduleOutcome::Missed {
                    session_id, reason, ..
                } => tracing::warn!(
                    sessione = session_id.get(),
                    ragione = reason.as_str(),
                    "avvio programmato mancato"
                ),
            }
        }
        if !esiti.is_empty() {
            self.concluded = true;
        }
        esiti.len()
    }

    /// Se dall'ultima domanda qualche monitoraggio si è concluso per durata, o
    /// un inizio programmato è stato deciso.
    ///
    /// Chi la chiama riallinea la schermata Monitoraggio e la veglia della
    /// postazione: senza, una postazione resterebbe sveglia per un monitoraggio
    /// già finito (E2E01-22), o non si sveglierebbe per uno appena partito.
    pub fn take_concluded(&mut self) -> bool {
        std::mem::take(&mut self.concluded)
    }

    /// I monitoraggi che ricevono contenuti in questo giro: in corso o con gli
    /// avvisi sospesi, **e non in attesa di una decisione** dopo
    /// un'interruzione (ADR-0146). Un archivio che non risponde non è «nessun
    /// monitoraggio»: `None`, e gli eventi restano in coda.
    fn acquiring_sessions(&self) -> Option<Vec<SessionId>> {
        let in_attesa = match self.monitoring.awaiting_decision() {
            Ok(in_attesa) => in_attesa,
            Err(error) => {
                tracing::warn!(
                    errore = error.kind(),
                    "interruzioni aperte non leggibili: nessuna ingestione in questa tornata"
                );
                return None;
            }
        };
        // E NON IN PAUSA (PAUSE-01, ADR-0172): durante la pausa il monitoraggio
        // non riceve eventi, e il periodo è un buco dichiarato. Una pausa che
        // non si legge non è «nessuna pausa»: come sopra, nessuna ingestione.
        let in_pausa = match self.monitoring.paused_sessions() {
            Ok(in_pausa) => in_pausa,
            Err(error) => {
                tracing::warn!(
                    errore = error.kind(),
                    "pause dell'acquisizione non leggibili: nessuna ingestione in questa tornata"
                );
                return None;
            }
        };
        match self.monitoring.database().acquiring_sessions() {
            Ok(sessioni) => Some(
                sessioni
                    .into_iter()
                    .map(|(id, _)| id)
                    .filter(|id| !in_attesa.contains(id) && !in_pausa.contains(id))
                    .collect(),
            ),
            Err(error) => {
                tracing::warn!(
                    errore = %error,
                    "stato dei monitoraggi non leggibile: nessuna ingestione in questa tornata"
                );
                None
            }
        }
    }

    /// Assicura che i contesti tenuti da parte siano quelli dei monitoraggi in
    /// corso, rileggendo dall'archivio **solo ciò che è cambiato**.
    ///
    /// # Perché non si rileggono tutti a ogni tornata
    ///
    /// Perché è un ciclo da 200 ms, e il caso normale è che i monitoraggi in
    /// corso siano gli stessi della tornata precedente. Rileggerli tutti
    /// costerebbe una lettura per monitoraggio cinque volte al secondo.
    fn ensure_contexts(&mut self, running: &[SessionId]) {
        // Cio' che non e' piu' in corso esce: un contesto tenuto per un
        // monitoraggio finito lo farebbe continuare ad acquisire.
        self.contexts
            .retain(|(session_id, _)| running.contains(session_id));

        let mancanti: Vec<SessionId> = running
            .iter()
            .filter(|session_id| {
                !self
                    .contexts
                    .iter()
                    .any(|(cached, _)| cached == *session_id)
            })
            .copied()
            .collect();
        if mancanti.is_empty() {
            return;
        }

        let Ok(actor) = lisi_core::text::Actor::try_new(AUDIT_ACTOR) else {
            tracing::error!("nome dell'attore di audit non valido");
            return;
        };

        for session_id in mancanti {
            match self.service.load_context(session_id, actor.clone()) {
                Ok(context) => self.contexts.push((session_id, context)),
                Err(error) => {
                    // Un contesto non caricabile toglie QUEL monitoraggio dalla
                    // tornata, non tutti: gli altri continuano ad acquisire.
                    tracing::warn!(
                        errore = error.kind(),
                        sessione = session_id.get(),
                        "contesto del monitoraggio non caricabile: nessuna ingestione per questo"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    /// **Una raffica che dura non diventa una raffica nell'audit**, e nulla di
    /// ciò che si perde nel frattempo si dimentica (FINAL-REVIEW-01, revisione
    /// finale del diff).
    #[test]
    fn a_lasting_overflow_is_declared_at_intervals_with_the_full_count() {
        use lisi_core::Timestamp;
        let istante = |ms: i64| Timestamp::from_millis(1_700_000_000_000 + ms);
        let mut conto = super::DroppedLedger::default();

        assert_eq!(
            conto.due(0, istante(0)),
            None,
            "nulla scartato, nulla da dire"
        );
        assert_eq!(
            conto.due(10, istante(0)),
            Some(10),
            "la prima perdita si dice subito"
        );
        // Una tornata ogni 200 ms per un minuto meno un passo: nessuna riga.
        for passo in 1..300 {
            assert_eq!(
                conto.due(10 + passo, istante(i64::try_from(passo).unwrap_or(0) * 200)),
                None,
                "dentro l'intervallo non si scrive"
            );
        }
        assert_eq!(
            conto.due(400, istante(super::DROPPED_DECLARATION_INTERVAL_MS)),
            Some(390),
            "allo scadere si dichiara tutto ciò che si è perso nel frattempo"
        );
        assert_eq!(
            conto.due(3, istante(super::DROPPED_DECLARATION_INTERVAL_MS * 3)),
            Some(3),
            "un runtime nuovo ricomincia da zero"
        );
    }

    /// Guardia **strutturale**, non funzionale, contro il difetto che in questa
    /// serie si è ripetuto quattro volte: un motore costruito, collaudato e
    /// mai invocato — il pompaggio degli eventi (2026-07-26), l'acquisizione e
    /// il registro delle chat (2026-07-30), le notifiche (2026-07-31). Ogni
    /// volta il quality gate era verde, perché misura ciò che esiste e non ciò
    /// che nessuno chiama; ogni volta è servito un pilot con l'operatore alla
    /// tastiera per accorgersene.
    ///
    /// **Che cosa questo test prova e che cosa no.** Prova che il chiamante
    /// esiste in questo modulo, cioè esattamente ciò che mancava le quattro
    /// volte. **Non** prova che la chiamata sia corretta, né che venga
    /// raggiunta a runtime: quello richiederebbe un `AccountRuntime` completo e
    /// una scrittura diretta su SQLite dai test di `lisi-app`, che il confine
    /// architetturale del crate vieta (ADR-0010). La correttezza dei due
    /// motori è coperta dai loro test in `lisi-services`; ciò che qui restava
    /// scoperto era solo la loro invocazione.
    #[test]
    fn the_engines_this_module_exists_to_call_are_actually_called() {
        // Solo le righe di codice: un nome che comparisse in un commento - per
        // esempio in questa stessa spiegazione - soddisferebbe un controllo sul
        // testo grezzo, cioè fallirebbe proprio dove il codice è corretto. È lo
        // stesso accorgimento del controllo sul manifest in `main.rs`.
        // Si scarta tutto ciò che segue l'inizio di questo stesso modulo di
        // prova: le stringhe cercate compaiono qui sotto, nell'elenco, e senza
        // questo taglio il test **si soddisferebbe da solo** e passerebbe anche
        // dopo aver cancellato le chiamate vere. È esattamente il difetto che
        // rende inutile un test.
        let Some((production, _)) = super::THIS_MODULE.split_once("#[cfg(test)]\nmod tests {")
        else {
            panic!("il modulo di prova deve essere riconoscibile per poterlo escludere");
        };
        let code: String = production
            .lines()
            .map(str::trim_start)
            .filter(|line| !line.starts_with("//") && !line.starts_with("#!["))
            .collect::<Vec<_>>()
            .join("\n");

        for (engine, call) in [
            ("acquisizione", ".ingest("),
            ("notifiche", ".consider("),
            (
                "ritiro degli eventi dal connettore",
                ".take_pending_events(",
            ),
        ] {
            assert!(
                code.contains(call),
                "il motore delle {engine} non risulta chiamato da questo modulo: \
                 manca `{call}`. Un motore senza chiamanti passa ogni quality \
                 gate e non fa nulla."
            );
        }
    }

    /// **Il contesto non si rilegge per evento, e nemmeno per tornata.**
    ///
    /// # Che cosa questa guardia misura davvero
    ///
    /// ADR-0065 dice che il costo per evento **cresce linearmente** con i
    /// monitoraggi in corso. Quella frase è vera solo se per ciascun evento si
    /// paga **una ingestione per monitoraggio** — e non anche una **lettura del
    /// contesto**, che è una lettura d'archivio.
    ///
    /// Se `load_context` finisse dentro il ciclo degli eventi, il costo
    /// diventerebbe *eventi × monitoraggi* letture d'archivio su un ciclo da
    /// 200 ms, e **nulla fallirebbe**: l'applicazione funzionerebbe, più
    /// lentamente, e nessuno saprebbe perché.
    ///
    /// La guardia è **strutturale** e lo dichiara: legge il codice, non misura
    /// il tempo. Una misura a orologio su questa macchina non direbbe nulla di
    /// una postazione d'ufficio, e scriverla come se fosse una prova sarebbe
    /// peggio che non averla (HVQ-68).
    #[test]
    fn il_contesto_non_si_rilegge_per_evento() {
        // IL TAGLIO CADE SUL MODULO DI PROVA, NON SUL PRIMO `#[cfg(test)]`.
        //
        // La prima stesura tagliava al primo attributo, che in questo file sta
        // su `THIS_MODULE` a riga 43: il codice di produzione risultava vuoto e
        // la guardia falliva dicendo di non trovare il ciclo. E' lo stesso
        // difetto gia' corretto nel guardiano degli accenti, trovato questa
        // volta perche' la prova era rossa invece che verde.
        let Some((produzione, _)) = super::THIS_MODULE.split_once("#[cfg(test)]\nmod tests {")
        else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };

        const INIZIO: &str = "for event in events.into_iter().take(INGEST_BUDGET) {";
        let Some(inizio) = produzione.find(INIZIO) else {
            panic!(
                "il ciclo degli eventi non e' dove questa guardia lo cerca: \
                 se e' stato riscritto, va riscritta anche la guardia"
            );
        };
        let Some(fine) = produzione[inizio..].find("\n        }\n") else {
            panic!("il ciclo degli eventi deve avere una fine riconoscibile");
        };
        let ciclo = &produzione[inizio..inizio + fine];

        for vietato in [
            "load_context",
            "ensure_contexts",
            "running_sessions",
            "acquiring_sessions",
            "conclude_due",
            "start_due",
            "summaries(",
        ] {
            assert!(
                !ciclo.contains(vietato),
                "«{vietato}» sta dentro il ciclo degli eventi: il costo per evento \
                 diventerebbe una lettura d'archivio per monitoraggio, su un ciclo \
                 da 200 ms, e nulla fallirebbe"
            );
        }

        // E la lettura dei contesti deve avvenire UNA VOLTA, prima del ciclo.
        assert!(
            produzione.contains("self.ensure_contexts(&running);"),
            "i contesti si preparano prima del ciclo, non dentro"
        );
    }

    /// **La scadenza si controlla prima di qualunque ingestione, e prima del
    /// ritorno anticipato** (E2E01-01, ADR-0145).
    ///
    /// La guardia è strutturale, e lo dichiara: la conclusione stessa è
    /// provata con l'orologio in mano nel servizio
    /// (`un_monitoraggio_a_tempo_si_conclude_alla_scadenza`); qui si sorveglia
    /// che il ciclo la chiami **nel posto giusto**, perché chiamarla dopo
    /// `acquiring_sessions` attribuirebbe un giro di eventi a un monitoraggio
    /// già scaduto, e chiamarla dopo il ritorno anticipato lascerebbe aperto
    /// un monitoraggio su una fonte silenziosa — la sessione 2 del collaudo.
    #[test]
    fn la_scadenza_precede_ogni_ingestione() {
        let Some((produzione, _)) = super::THIS_MODULE.split_once("#[cfg(test)]\nmod tests {")
        else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        // Il giro comincia in `ingest_all` e prosegue, per ogni account, in
        // `ingest_from`, che nel file viene dopo.
        let Some(inizio) = produzione.find("pub fn ingest_all(") else {
            panic!("`ingest_all` non e' dove questa guardia lo cerca");
        };
        let corpo = &produzione[inizio..];
        let posizione = |testo: &str| {
            corpo
                .find(testo)
                .unwrap_or_else(|| panic!("«{testo}» manca dal giro del ciclo"))
        };
        let scadenza = posizione("self.conclude_due(now);");
        assert!(scadenza < posizione("self.ingest_from(runtime,"));
        assert!(scadenza < posizione("if !runtime.has_pending_events()"));
        assert!(scadenza < posizione("self.acquiring_sessions()"));
        assert!(scadenza < posizione("runtime.take_pending_events("));
    }

    /// **Un monitoraggio in pausa non acquisisce, e ripreso torna ad
    /// acquisire** (PAUSE-01, ADR-0172, criterio 2; prova negativa: il filtro
    /// della pausa tolto → rossa).
    #[test]
    fn un_monitoraggio_in_pausa_non_acquisisce() {
        let apri = || lisi_services::Database::open_shared_in_memory("pausa_acquisizione").ok();
        let (Some(primo), Some(secondo), Some(terzo), Some(quarto), Some(prova)) =
            (apri(), apri(), apri(), apri(), apri())
        else {
            panic!("l'archivio condiviso di prova deve aprirsi");
        };
        let Some(pompa) =
            super::create_service(Some(primo), Some(secondo), Some(terzo), Some(quarto))
        else {
            panic!("il ciclo di acquisizione deve nascere");
        };
        let mut pompa = pompa;
        let (Ok(identificativo), Ok(nome), Ok(etichetta), Ok(chi), Ok(motivo)) = (
            lisi_core::text::SourceIdentifier::try_new("-1001"),
            lisi_core::text::DisplayName::try_new("Canale"),
            lisi_core::text::DisplayName::try_new("Monitoraggio"),
            lisi_core::text::Actor::try_new("operatore.prova"),
            lisi_core::model::reason::OperationalReason::try_new("Riunione d'ufficio fino alle 15"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let adesso = lisi_core::Timestamp::from_millis(1_800_000_000_000);
        let Ok(fonte) = prova.insert_source(
            &lisi_core::model::NewSource {
                kind: lisi_core::model::SourceKind::Channel,
                identifier: identificativo,
                display_name: nome,
                authorized_by: chi.clone(),
                active: true,
            },
            adesso,
        ) else {
            panic!("la fonte deve registrarsi");
        };
        let Ok(sessione) = pompa.monitoring.begin(
            etichetta,
            &chi,
            lisi_services::wizard::WizardDuration::Manual,
            &[fonte],
            None,
            &lisi_services::monitoring::DictionaryChoice::default(),
            adesso,
        ) else {
            panic!("l'avvio deve riuscire");
        };
        assert_eq!(pompa.acquiring_sessions(), Some(vec![sessione]));
        let Ok(()) =
            pompa
                .monitoring
                .pause_acquisition(sessione, &chi, &motivo, adesso.plus_seconds(10))
        else {
            panic!("la pausa deve riuscire");
        };
        assert_eq!(
            pompa.acquiring_sessions(),
            Some(Vec::new()),
            "in pausa non acquisisce"
        );
        let Ok(()) = pompa
            .monitoring
            .resume_acquisition(sessione, &chi, adesso.plus_seconds(20))
        else {
            panic!("la ripresa deve riuscire");
        };
        assert_eq!(pompa.acquiring_sessions(), Some(vec![sessione]));
    }

    /// **L'inizio programmato si decide a ogni giro, prima di chi acquisisce,
    /// con e senza account** (SCHEDULE-01, ADR-0171, criterio 3; prova
    /// negativa: la decisione tolta dal giro senza account → rossa).
    ///
    /// Strutturale, come la guardia della scadenza: la decisione è provata
    /// con l'orologio in mano nel servizio
    /// (`un_monitoraggio_programmato_parte_all_istante_detto`); qui si
    /// sorveglia che il ciclo la chiami nel posto giusto. Dopo
    /// `acquiring_sessions`, un monitoraggio partito adesso perderebbe gli
    /// eventi di questo giro; senza la chiamata nel ramo senza account, un
    /// inizio mancato per l'account non si direbbe mai.
    #[test]
    fn l_inizio_programmato_si_decide_a_ogni_giro() {
        const MAIN: &str = include_str!("main.rs");
        let Some((produzione, _)) = super::THIS_MODULE.split_once("#[cfg(test)]\nmod tests {")
        else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let Some(inizio) = produzione.find("pub fn ingest_all(") else {
            panic!("`ingest_all` non e' dove questa guardia lo cerca");
        };
        let corpo = &produzione[inizio..];
        let posizione = |testo: &str| {
            corpo
                .find(testo)
                .unwrap_or_else(|| panic!("«{testo}» manca dal giro del ciclo"))
        };
        // La prontezza è quella di OGNI account aperto (ADR-0173): il
        // monitoraggio parte se è pronto il suo.
        let pronti = posizione("aperti.add(runtime.account_uuid().clone(), runtime.is_ready());");
        let decisione = posizione("self.start_due(now, &aperti);");
        assert!(pronti < decisione);
        assert!(decisione < posizione("self.ingest_from(runtime,"));
        assert!(decisione < posizione("self.acquiring_sessions()"));

        // E il giro si fa anche senza account: `main.rs` chiama sempre
        // `ingest_all`, con l'elenco vuoto quando non ce n'è nessuno aperto.
        let Some((_, giro)) = MAIN.split_once("if let Some(acquisition) = acquisition.as_mut() {")
        else {
            panic!("il giro del ciclo non e' dove questa guardia lo cerca");
        };
        let Some((giro, _)) = giro.split_once("if acquisition.take_concluded()") else {
            panic!("il giro del ciclo deve proseguire");
        };
        let codice: String = giro
            .lines()
            .map(str::trim_start)
            .filter(|riga| !riga.starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            codice.contains("let mut runtimes = session.runtimes_for_acquisition();")
                && codice.contains("acquisition.ingest_all(&mut runtimes, adesso)"),
            "senza account un inizio in orario e' mancato, e va detto: {codice}"
        );
        assert!(
            !codice.contains("match ") && !codice.contains("if let Some(runtime)"),
            "il giro non dipende dall'esserci di un account: {codice}"
        );
    }

    /// **Ogni evento ai soli monitoraggi del suo account, prima
    /// dell'ingestione** (MULTI-ACCOUNT-02 parte 2, ADR-0173, criterio 3;
    /// prova negativa: il filtro tolto dal ciclo → rossa).
    ///
    /// La regola è provata con eventi veri nel servizio
    /// (`la_stessa_chat_su_due_account_va_al_monitoraggio_del_suo_account`);
    /// qui si sorveglia che il ciclo la chieda per ogni monitoraggio, prima di
    /// `ingest`, con l'account del runtime da cui l'evento è stato ritirato.
    #[test]
    fn ogni_evento_va_ai_monitoraggi_del_suo_account() {
        let Some((produzione, _)) = super::THIS_MODULE.split_once("#[cfg(test)]\nmod tests {")
        else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let Some(inizio) = produzione.find("fn ingest_from(") else {
            panic!("`ingest_from` non e' dove questa guardia lo cerca");
        };
        let corpo = &produzione[inizio..];
        let posizione = |testo: &str| {
            corpo
                .find(testo)
                .unwrap_or_else(|| panic!("«{testo}» manca da `ingest_from`"))
        };
        let origine = posizione("let origine = runtime.account_uuid().clone();");
        let filtro = posizione(
            "if !context.accepts_from(&origine, open) {\n                    continue;\n                }\n                match self.service.ingest(&event, context, now) {",
        );
        assert!(origine < posizione("runtime.take_pending_events("));
        assert!(posizione("for event in events.into_iter()") < filtro);
    }

    /// **Un solo consumatore della coda degli eventi, in tutto il prodotto.**
    ///
    /// # Perché questa guardia esiste
    ///
    /// Perché `take_pending_events` **svuota**. Un secondo consumatore non
    /// riceve metà degli eventi: riceve quelli che il primo non ha ancora preso,
    /// in modo non riproducibile — e **nessuno se ne accorge**, perché un
    /// contenuto che non arriva non lascia traccia.
    ///
    /// È la prima decisione di ADR-0065: con più monitoraggi la scorciatoia
    /// ovvia è dare a ciascuno il proprio consumo, e la scorciatoia è vietata.
    /// Il consumatore è uno, e **distribuisce**.
    ///
    /// La guardia sorveglia ciò che la specifica dei monitoraggi multipli
    /// **afferma del codice di oggi**: una specifica che descrive male il codice
    /// è peggio di nessuna specifica.
    #[test]
    fn un_solo_consumatore_della_coda_degli_eventi() {
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(std::path::Path::to_path_buf);
        let Some(crates) = crates else {
            panic!("la cartella dei crate deve esistere sopra questo crate");
        };

        let mut chiamanti = Vec::new();
        let mut file_visti = 0_usize;
        for file in sorgenti(&crates) {
            let Ok(testo) = std::fs::read_to_string(&file) else {
                continue;
            };
            file_visti += 1;

            // Le prove possono ritirare eventi quanto vogliono: non sono il
            // prodotto, e non corrono contro nessuno.
            let produzione = testo
                .split_once("\n#[cfg(test)]")
                .map_or(testo.as_str(), |(prima, _)| prima);

            for riga in produzione.lines() {
                let riga = riga.trim_start();
                // La DEFINIZIONE non e' un consumo, e nemmeno un commento.
                if riga.starts_with("//") || riga.contains("fn take_pending_events") {
                    continue;
                }
                if riga.contains(".take_pending_events(") {
                    chiamanti.push(format!("{}: {riga}", file.display()));
                }
            }
        }

        assert!(
            file_visti > 50,
            "trovati solo {file_visti} sorgenti: la guardia non sta percorrendo il prodotto"
        );
        assert_eq!(
            chiamanti.len(),
            1,
            "la coda degli eventi deve avere UN SOLO consumatore, e ne ha {}: {chiamanti:#?}. \
             Due consumatori perdono eventi in silenzio (ADR-0065).",
            chiamanti.len()
        );
    }

    /// Tutti i file `.rs` sotto il percorso indicato.
    fn sorgenti(percorso: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut trovati = Vec::new();
        let Ok(voci) = std::fs::read_dir(percorso) else {
            return trovati;
        };
        for voce in voci.flatten() {
            let percorso = voce.path();
            if percorso.is_dir() {
                if percorso.file_name().is_some_and(|nome| nome == "target") {
                    continue;
                }
                trovati.extend(sorgenti(&percorso));
            } else if percorso
                .extension()
                .is_some_and(|estensione| estensione == "rs")
            {
                trovati.push(percorso);
            }
        }
        trovati
    }
}

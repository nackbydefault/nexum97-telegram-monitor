//! Collegamento fra la schermata Fonti e il servizio delle fonti.
//!
//! Come per la schermata Account, questo modulo non contiene logica: traduce i
//! comandi dell'operatore in chiamate al servizio e lo stato del servizio in
//! proprietà dell'interfaccia.
//!
//! L'elenco delle chat accessibili viene dal connettore attraverso il servizio:
//! l'interfaccia non conosce TDLib.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_services::ServiceError;
use lisi_services::source_health::{SourceHealth, SourceHealthService};
use lisi_services::sources::{AvailableSource, RemovalOutcome, SourceService};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::account::SharedSession;
use crate::{AppWindow, AvailableSourceEntry, ConfiguredSourceEntry, HealthCheckEntry};

/// Servizio delle fonti condiviso fra i gestori dei comandi.
pub type SharedSources = Rc<RefCell<SourceService>>;

/// Il servizio della salute, e le viste che l'elenco sta mostrando.
///
/// # Perché ricorda che cosa ha mostrato
///
/// Perché il pannello di dettaglio si apre **da una riga**, e la riga e il
/// pannello non devono poter dire due cose diverse della stessa fonte. Se il
/// pannello ricomponesse lo stato, fra il disegno dell'elenco e il clic
/// potrebbe essere stata registrata un'altra verifica: l'operatore leggerebbe
/// «Operativa» nella riga e «In errore» nel pannello, senza sapere quale delle
/// due valga.
///
/// Ciò che il pannello **aggiunge** — la storia e l'account — si legge invece
/// al momento dell'apertura, che è quando serve.
#[derive(Debug)]
pub struct HealthPresenter {
    service: SourceHealthService,
    shown: std::collections::BTreeMap<i64, lisi_services::source_health::SourceHealthView>,
}

impl HealthPresenter {
    /// Il servizio, per le letture che non passano dall'elenco.
    #[must_use]
    pub const fn service(&self) -> &SourceHealthService {
        &self.service
    }

    /// Compone l'elenco e **ricorda** che cosa ha mostrato.
    ///
    /// # Errori
    ///
    /// Restituisce l'errore della persistenza se la composizione non riesce;
    /// in quel caso le viste ricordate vengono svuotate, perché mostrare uno
    /// stato vecchio accanto a righe senza stato sarebbe peggio che non
    /// mostrarne alcuno.
    pub fn compose(
        &mut self,
    ) -> lisi_services::ServiceResult<
        std::collections::BTreeMap<i64, lisi_services::source_health::SourceHealthView>,
    > {
        match self.service.overview() {
            Ok(viste) => {
                self.shown = viste
                    .into_iter()
                    .map(|vista| (vista.source_id.get(), vista))
                    .collect();
                Ok(self.shown.clone())
            }
            Err(errore) => {
                self.shown.clear();
                Err(errore)
            }
        }
    }

    /// La vista che l'elenco sta mostrando per quella fonte.
    #[must_use]
    pub fn shown(&self, source_id: i64) -> Option<&lisi_services::source_health::SourceHealthView> {
        self.shown.get(&source_id)
    }
}

/// Servizio della salute delle fonti, condiviso fra i gestori dei comandi.
///
/// Sta accanto a [`SharedSources`] invece che dentro perché è un servizio
/// diverso su un archivio diverso: i servizi di questo prodotto non
/// condividono una connessione, e comporre la salute mentre l'elenco delle
/// fonti si aggiorna non deve contenderne una.
pub type SharedHealth = Rc<RefCell<HealthPresenter>>;

/// Crea il servizio della salute sull'archivio indicato.
#[must_use]
pub fn create_health_service(database: lisi_services::Database) -> Option<SharedHealth> {
    Some(Rc::new(RefCell::new(HealthPresenter {
        service: SourceHealthService::new(database),
        shown: std::collections::BTreeMap::new(),
    })))
}

/// Crea il servizio delle fonti sull'archivio indicato.
///
/// L'archivio arriva da fuori invece di essere aperto qui: così l'applicazione
/// gli passa quello di esercizio e i test uno in memoria. Aprirlo internamente
/// farebbe scrivere ai test nell'archivio dell'operatore, che è un difetto
/// prima ancora che una scomodità.
#[must_use]
pub fn create_service(database: lisi_services::Database) -> Option<SharedSources> {
    Some(Rc::new(RefCell::new(SourceService::new(database))))
}

/// Riporta nell'interfaccia lo stato delle fonti.
pub fn refresh(
    window: &AppWindow,
    sources: &SharedSources,
    health: Option<&SharedHealth>,
    session: &SharedSession,
    message: Option<&str>,
) {
    let authenticated = session.borrow().is_authenticated();
    window.set_sources_enabled(authenticated);
    // LE VALUTAZIONI SEGUONO L'ELENCO DELLE FONTI (ADR-0167): una fonte appena
    // aggiunta o tolta compare o sparisce anche lì.
    crate::source_reliability::show_rows(window, sources.borrow().database());

    if let Some(text) = message {
        window.set_sources_message(SharedString::from(text));
    }

    if !authenticated {
        window.set_available_sources(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        window.set_configured_sources(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        // Le fonti configurate restano sul disco anche senza account: il
        // conteggio della dashboard le mostra comunque, perche' azzerarlo
        // direbbe che non ce ne sono invece che «non sono raggiungibili ora».
        window.set_configured_source_count(configured_count(sources));
        return;
    }

    let filter = window.get_source_filter().to_string();

    let available = {
        // Il connettore resta dentro i servizi: qui passa solo il runtime
        // dell'account autorizzato, tramite la facade `available_for` (ADR-0010).
        let mut session_ref = session.borrow_mut();
        match session_ref.runtime_mut() {
            Some(runtime) => sources.borrow().available_for(runtime),
            None => Ok(Vec::new()),
        }
    };

    let rows: Vec<AvailableSourceEntry> = match available {
        Ok(list) => {
            let filtered = SourceService::search(&list, &filter);
            filtered.iter().map(to_available_entry).collect()
        }
        Err(error) => {
            tracing::warn!(kind = error.kind(), "elenco delle fonti non ottenibile");
            window.set_sources_message(crate::lingua::schermo(error.operator_message()));
            Vec::new()
        }
    };
    window.set_available_sources(ModelRc::from(Rc::new(VecModel::from(rows))));

    // La salute di ogni fonte, letta in blocco: quattro interrogazioni in
    // tutto, non quattro per riga. Se la lettura non riesce, le righe restano
    // e lo stato resta vuoto — un elenco di fonti senza salute e' meno utile
    // di uno con, ma e' molto piu' utile di nessun elenco.
    let salute: std::collections::BTreeMap<i64, lisi_services::source_health::SourceHealthView> =
        health.map_or_else(std::collections::BTreeMap::new, |health| {
            health.borrow_mut().compose().unwrap_or_else(|errore| {
                tracing::warn!(
                    kind = errore.kind(),
                    "salute delle fonti non leggibile: le righe restano senza stato"
                );
                std::collections::BTreeMap::new()
            })
        });

    // CHE COSA STAVAMO GUARDANDO negli ultimi sette giorni (PR-05): si legge
    // sull'archivio della salute, senza aprirne un altro, e una lettura che non
    // riesce lascia le barre vuote invece di mostrarne di inventate.
    let adesso = crate::account::now();
    let dal = crate::coverage::window_start(adesso);
    // Con la copertura, lo strato dei periodi RECUPERATI DOPO (PR-08): a parte,
    // perché nessuno guardava. Una lettura che non riesce lo lascia vuoto.
    type Recuperati = Vec<(lisi_core::Timestamp, lisi_core::Timestamp)>;
    let coperture: std::collections::BTreeMap<
        i64,
        (lisi_core::model::coverage::Coverage, Recuperati),
    > = health.map_or_else(std::collections::BTreeMap::new, |health| {
        let salute = health.borrow();
        let archivio = salute.service().database();
        match lisi_services::coverage::for_sources(archivio, dal, adesso) {
            Ok(elenco) => elenco
                .into_iter()
                .map(|fonte| {
                    let recuperati = lisi_services::coverage::recovered_spans(
                        archivio,
                        fonte.source_id,
                        dal,
                        adesso,
                    )
                    .unwrap_or_else(|errore| {
                        tracing::warn!(
                            kind = errore.kind(),
                            "periodi recuperati non leggibili: lo strato resta vuoto"
                        );
                        Vec::new()
                    });
                    (fonte.source_id.get(), (fonte.coverage, recuperati))
                })
                .collect(),
            Err(errore) => {
                tracing::warn!(
                    kind = errore.kind(),
                    "copertura delle fonti non leggibile: le barre restano vuote"
                );
                std::collections::BTreeMap::new()
            }
        }
    });
    window.set_coverage_meaning(SharedString::from(crate::coverage::meaning()));
    window.set_coverage_scope_note(SharedString::from(crate::coverage::scope_note(
        crate::coverage::in_team(),
    )));

    // Con quali account è stata seguita ogni fonte (MULTI-ACCOUNT-02, ADR-0173):
    // si ricava dai monitoraggi. Una lettura che non riesce lascia la riga
    // vuota, non inventa un account.
    let account_delle_fonti = sources
        .borrow()
        .accounts_of_sources()
        .unwrap_or_else(|errore| {
            tracing::warn!(kind = errore.kind(), "account delle fonti non leggibili");
            std::collections::BTreeMap::new()
        });
    let configured: Vec<ConfiguredSourceEntry> = match sources.borrow().configured() {
        Ok(list) => list
            .iter()
            .map(|source| {
                let vista = salute.get(&source.id.get());
                let copertura = coperture.get(&source.id.get());
                let (tratti, strato) = copertura.map_or_else(
                    || (Vec::new(), Vec::new()),
                    |(copertura, recuperati)| {
                        crate::coverage::bars(copertura, recuperati, dal, adesso)
                    },
                );
                ConfiguredSourceEntry {
                    source_id: i32::try_from(source.id.get()).unwrap_or(0),
                    title: SharedString::from(source.display_name.as_str()),
                    kind: SharedString::from(kind_label(source.kind)),
                    identifier: SharedString::from(source.identifier.as_str()),
                    authorized_by: SharedString::from(source.authorized_by.as_str()),
                    accounts: SharedString::from(accounts_line(
                        account_delle_fonti
                            .get(&source.id.get())
                            .map_or(&[][..], Vec::as_slice),
                    )),
                    active: source.active,
                    health: SharedString::from(vista.map_or("", |vista| vista.health.label())),
                    health_attention: vista.is_some_and(|vista| vista.needs_attention()),
                    health_unknown: vista
                        .is_some_and(|vista| vista.health == SourceHealth::Unknown),
                    health_stopped: vista
                        .is_some_and(|vista| vista.health == SourceHealth::Stopped),
                    last_check: SharedString::from(vista.map_or_else(String::new, last_check_line)),
                    last_content: SharedString::from(
                        vista.map_or_else(String::new, |vista| vista.silence()),
                    ),
                    coverage: ModelRc::from(Rc::new(VecModel::from(tratti))),
                    recovered: ModelRc::from(Rc::new(VecModel::from(strato))),
                    coverage_summary: SharedString::from(copertura.map_or_else(
                        || String::from("Copertura non leggibile."),
                        |(copertura, recuperati)| {
                            crate::coverage::in_words_with_recovered(copertura, recuperati)
                        },
                    )),
                }
            })
            .collect(),
        Err(error) => {
            tracing::warn!(kind = error.kind(), "fonti configurate non leggibili");
            Vec::new()
        }
    };

    // Il riepilogo, nella forma che il congelamento prescrive.
    if let Some(health) = health {
        match health.borrow().service().summary() {
            Ok(riepilogo) => {
                window.set_health_summary(crate::lingua::schermo(riepilogo.as_sentence()));
                window.set_health_needs_attention(riepilogo.needing_attention() > 0);
            }
            Err(errore) => {
                tracing::warn!(kind = errore.kind(), "riepilogo della salute non leggibile");
                window.set_health_summary(SharedString::default());
                window.set_health_needs_attention(false);
            }
        }
    }
    // Senza un account collegato l'elenco delle chat non si puo' leggere: il
    // comando si spegne invece di fallire dopo essere stato premuto.
    window.set_can_verify_sources(authenticated);
    window.set_configured_sources(ModelRc::from(Rc::new(VecModel::from(configured))));
    window.set_configured_source_count(configured_count(sources));

    // Il pannello aperto segue l'elenco: se i fatti sono cambiati — una
    // verifica appena eseguita — deve dire quelli nuovi. Se la fonte non c'è
    // più, si chiude: un pannello che descrive una fonte rimossa è un pannello
    // che mente.
    if window.get_source_health_open() {
        let aperta = i64::from(window.get_source_health_id());
        match health.filter(|_| salute.contains_key(&aperta)) {
            Some(health) => open_health(window, health, aperta),
            None => close_health(window),
        }
    }
}

/// Apre il pannello di dettaglio di una fonte.
///
/// # Che cosa NON fa
///
/// **Non ricompone lo stato.** Lo prende dalla vista che l'elenco sta
/// mostrando: la riga e il pannello devono dire la stessa cosa della stessa
/// fonte. E **non scrive**: aprire il pannello è una lettura, e se registrasse
/// un'osservazione la storia si riempirebbe di righe che nessuno ha chiesto
/// proprio nella schermata che quella storia mostra.
fn open_health(window: &AppWindow, health: &SharedHealth, source_id: i64) {
    let presenter = health.borrow();
    let Some(vista) = presenter.shown(source_id) else {
        // Nessuna vista per quella fonte: non si è in grado di dire nulla, e
        // aprire un pannello vuoto direbbe che non c'è nulla da dire.
        drop(presenter);
        close_health(window);
        return;
    };

    let Ok(dettaglio) = presenter.service().detail(vista) else {
        tracing::warn!("dettaglio della salute non leggibile");
        drop(presenter);
        close_health(window);
        return;
    };

    let righe: Vec<HealthCheckEntry> = dettaglio
        .checks
        .iter()
        .map(|check| HealthCheckEntry {
            headline: crate::lingua::schermo(check.headline()),
            meaning: SharedString::from(check.note()),
            conclusive: check.is_conclusive(),
            detail: check
                .detail
                .as_deref()
                .map_or_else(SharedString::default, SharedString::from),
            observer: SharedString::from(check.observer_note()),
        })
        .collect();

    window.set_source_health_id(i32::try_from(source_id).unwrap_or(-1));
    window.set_source_health_subject(SharedString::from(dettaglio.view.display_name.as_str()));
    window.set_source_health_state(crate::lingua::schermo(dettaglio.view.health.label()));
    window.set_source_health_attention(dettaglio.view.needs_attention());
    window.set_source_health_unknown(dettaglio.view.health == SourceHealth::Unknown);
    window.set_source_health_stopped(dettaglio.view.health == SourceHealth::Stopped);
    window.set_source_health_why(SharedString::from(dettaglio.view.why()));
    window.set_source_health_silence(SharedString::from(dettaglio.view.silence()));
    window.set_source_health_account(SharedString::from(dettaglio.account_note()));
    window.set_source_health_history_note(SharedString::from(dettaglio.history_note()));
    window.set_source_health_checks(ModelRc::from(Rc::new(VecModel::from(righe))));
    window.set_source_health_open(true);
}

/// Chiude il pannello e svuota ciò che mostrava.
///
/// Svuotarlo conta: un pannello chiuso che conserva i testi li rimostrerebbe
/// per un istante alla riapertura su un'altra fonte, e sarebbero i fatti di
/// una fonte diversa.
fn close_health(window: &AppWindow) {
    window.set_source_health_open(false);
    window.set_source_health_id(-1);
    window.set_source_health_subject(SharedString::default());
    window.set_source_health_state(SharedString::default());
    window.set_source_health_attention(false);
    window.set_source_health_unknown(false);
    window.set_source_health_stopped(false);
    window.set_source_health_why(SharedString::default());
    window.set_source_health_silence(SharedString::default());
    window.set_source_health_account(SharedString::default());
    window.set_source_health_history_note(SharedString::default());
    window.set_source_health_checks(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
}

/// Numero di fonti configurate, zero se l'elenco non è leggibile.
///
/// Zero è la risposta prudente quando la lettura fallisce: mostrare l'ultimo
/// valore noto farebbe credere aggiornato un numero che non lo è.
fn configured_count(sources: &SharedSources) -> i32 {
    sources
        .borrow()
        .configured()
        .ok()
        .and_then(|list| i32::try_from(list.len()).ok())
        .unwrap_or(0)
}

/// Traduce una chat disponibile in una riga dell'interfaccia.
fn to_available_entry(entry: &AvailableSource) -> AvailableSourceEntry {
    AvailableSourceEntry {
        chat_id: SharedString::from(entry.chat.chat_id.get().to_string()),
        title: SharedString::from(entry.chat.title.as_str()),
        kind: crate::lingua::schermo(entry.chat.kind.label()),
        username: entry
            .chat
            .username
            .as_deref()
            .map_or_else(SharedString::default, |username| {
                crate::lingua::schermo(format!("@{username}"))
            }),
        already_configured: entry.already_configured,
        selectable: entry.can_be_added(),
        reason: entry
            .unavailable_reason
            .map_or_else(SharedString::default, SharedString::from),
    }
}

/// Etichetta leggibile del tipo di fonte.
///
/// Viene dal dominio e non da un secondo elenco qui: la stessa parola deve
/// comparire nella schermata e nel registro che esce dall'ufficio, e due
/// elenchi della stessa cosa, il giorno in cui uno cambia, divergono
/// (FINAL-PRODUCT-REVIEW-01, FPR-02).
const fn kind_label(kind: lisi_services::sources::SourceKind) -> &'static str {
    kind.label()
}

/// Registra i gestori dei comandi della schermata Fonti.
pub fn wire(
    window: &AppWindow,
    sources: &SharedSources,
    health: Option<&SharedHealth>,
    session: &SharedSession,
) {
    {
        let weak = window.as_weak();
        let sources = Rc::clone(sources);
        let health = health.map(Rc::clone);
        let session = Rc::clone(session);
        window.on_filter_sources(move || {
            if crate::lock::refuse_while_locked("filter_sources") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            refresh(&window, &sources, health.as_ref(), &session, None);
        });
    }

    {
        // LA VERIFICA DELLE FONTI.
        //
        // Una sola richiesta a Telegram per tutte le fonti: si legge l'elenco
        // delle chat accessibili all'account, che e' l'operazione ufficiale
        // gia' usata quando una fonte si aggiunge. Non cerca nulla, non entra
        // in alcun gruppo, e la spesa in Stars resta zero.
        //
        // Se l'elenco non si legge, la funzione NON fallisce: registra un
        // tentativo non riuscito per ciascuna fonte attiva, e nessuno stato
        // cambia. Non aver potuto guardare non e' aver visto un guasto.
        let weak = window.as_weak();
        let sources = Rc::clone(sources);
        let health = health.map(Rc::clone);
        let session = Rc::clone(session);
        window.on_verify_sources(move || {
            if crate::lock::refuse_while_locked("verify_sources") {
                return;
            }
            // Un prerequisito della fascia di prontezza puo' essere cambiato (F-08).
            crate::preflight::mark_stale();
            let Some(window) = weak.upgrade() else { return };
            let Some(health) = health.as_ref() else {
                refresh(
                    &window,
                    &sources,
                    None,
                    &session,
                    Some("La salute delle fonti non è disponibile in questa esecuzione."),
                );
                return;
            };

            let esito = {
                let mut session_ref = session.borrow_mut();
                let Some(runtime) = session_ref.runtime_mut() else {
                    refresh(
                        &window,
                        &sources,
                        Some(health),
                        &session,
                        Some("Per verificare le fonti serve un account collegato."),
                    );
                    return;
                };
                let Ok(attore) = lisi_core::text::Actor::try_new(crate::operator::NAME) else {
                    return;
                };
                let account_id = Some(runtime.account_id());
                health.borrow().service().verify_all(
                    runtime.connector_mut(),
                    account_id,
                    &attore,
                    adesso(),
                )
            };

            let messaggio = match esito {
                Ok(report) => report.as_sentence(),
                Err(errore) => {
                    tracing::warn!(kind = errore.kind(), "verifica delle fonti non registrata");
                    errore.operator_message().to_owned()
                }
            };
            refresh(&window, &sources, Some(health), &session, Some(&messaggio));
        });
    }

    {
        // IL PANNELLO «PERCHÉ QUESTO STATO».
        //
        // Due letture, e solo qui: la storia delle verifiche e gli account.
        // Nessuna richiesta a Telegram, nessuna scrittura: consultare non
        // osserva.
        let weak = window.as_weak();
        let health = health.map(Rc::clone);
        window.on_open_source_health(move |source_id| {
            if crate::lock::refuse_while_locked("open_source_health") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            let Some(health) = health.as_ref() else {
                close_health(&window);
                return;
            };
            open_health(&window, health, i64::from(source_id));
        });
    }

    {
        let weak = window.as_weak();
        window.on_close_source_health(move || {
            if crate::lock::refuse_while_locked("close_source_health") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            close_health(&window);
        });
    }

    {
        // All'ingresso nella schermata l'elenco va riletto: lo stato
        // dell'accesso puo' essere cambiato nel frattempo, e mostrare un elenco
        // vecchio sarebbe peggio che non mostrarne nessuno.
        let weak = window.as_weak();
        let sources = Rc::clone(sources);
        let health = health.map(Rc::clone);
        let session = Rc::clone(session);
        window.on_page_shown(move || {
            let Some(window) = weak.upgrade() else { return };
            refresh(&window, &sources, health.as_ref(), &session, None);
        });
    }

    {
        let weak = window.as_weak();
        let sources = Rc::clone(sources);
        let health = health.map(Rc::clone);
        let session = Rc::clone(session);
        window.on_add_source(move |chat_identifier| {
            if crate::lock::refuse_while_locked("add_source") {
                return;
            }
            // Un prerequisito della fascia di prontezza puo' essere cambiato (F-08).
            crate::preflight::mark_stale();
            let Some(window) = weak.upgrade() else { return };
            let Ok(identifier) = chat_identifier.to_string().parse::<i64>() else {
                refresh(
                    &window,
                    &sources,
                    health.as_ref(),
                    &session,
                    Some("Identificativo della chat non valido."),
                );
                return;
            };

            // Il connettore resta nei servizi: si passa il runtime dell'account
            // autorizzato attraverso la facade `add_with_default_actor_for`.
            let message = {
                let mut session_ref = session.borrow_mut();
                match session_ref.runtime_mut() {
                    Some(runtime) => {
                        let outcome = lisi_services::sources::add_with_default_actor_for(
                            &sources.borrow(),
                            runtime,
                            identifier,
                            crate::operator::NAME,
                        );
                        describe(outcome.map(|_| "Fonte aggiunta all'elenco."))
                    }
                    None => String::from(
                        "Accedere con l'account d'ufficio prima di aggiungere una fonte.",
                    ),
                }
            };
            refresh(&window, &sources, health.as_ref(), &session, Some(&message));
        });
    }

    {
        let weak = window.as_weak();
        let sources = Rc::clone(sources);
        let health = health.map(Rc::clone);
        let session = Rc::clone(session);
        window.on_toggle_source(move |source_id, active| {
            if crate::lock::refuse_while_locked("toggle_source") {
                return;
            }
            // Un prerequisito della fascia di prontezza puo' essere cambiato (F-08).
            crate::preflight::mark_stale();
            let Some(window) = weak.upgrade() else { return };
            let outcome = lisi_services::sources::set_active_with_default_actor(
                &sources.borrow(),
                i64::from(source_id),
                active,
                crate::operator::NAME,
            );

            let message = describe(outcome.map(|()| {
                if active {
                    "Fonte attivata."
                } else {
                    "Fonte disattivata: non sarà usata in nuove sessioni."
                }
            }));
            refresh(&window, &sources, health.as_ref(), &session, Some(&message));
        });
    }

    {
        let weak = window.as_weak();
        let sources = Rc::clone(sources);
        let health = health.map(Rc::clone);
        let session = Rc::clone(session);
        window.on_remove_source(move |source_id| {
            if crate::lock::refuse_while_locked("remove_source") {
                return;
            }
            // Un prerequisito della fascia di prontezza puo' essere cambiato (F-08).
            crate::preflight::mark_stale();
            let Some(window) = weak.upgrade() else { return };
            let outcome = lisi_services::sources::remove_with_default_actor(
                &sources.borrow(),
                i64::from(source_id),
                crate::operator::NAME,
            );

            let message = match outcome {
                Ok(RemovalOutcome::Deleted) => {
                    String::from(RemovalOutcome::Deleted.operator_message())
                }
                Ok(RemovalOutcome::Deactivated) => {
                    String::from(RemovalOutcome::Deactivated.operator_message())
                }
                Err(error) => error.operator_message(),
            };
            refresh(&window, &sources, health.as_ref(), &session, Some(&message));
        });
    }
}

/// Traduce l'esito di un comando in un messaggio per l'operatore.
fn describe(outcome: Result<&'static str, ServiceError>) -> String {
    match outcome {
        Ok(message) => String::from(message),
        Err(error) => {
            tracing::warn!(kind = error.kind(), "comando sulle fonti non riuscito");
            error.operator_message()
        }
    }
}

/// La riga degli account con cui una fonte è stata seguita (MULTI-ACCOUNT-02,
/// ADR-0173). Vuota quando nessun monitoraggio legato a un account l'ha
/// inclusa: non si indovina.
fn accounts_line(account: &[lisi_core::model::monitoring_account::SourceAccount]) -> String {
    let nomi: Vec<&str> = account
        .iter()
        .map(|voce| voce.account_label.as_str())
        .collect();
    match nomi.as_slice() {
        [] => String::new(),
        [solo] => format!("Seguita con l'account {solo}."),
        [prima @ .., ultimo] => format!("Seguita con gli account {} e {ultimo}.", prima.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::kind_label;
    use lisi_services::sources::SourceKind;

    #[test]
    fn every_kind_has_a_readable_label() {
        assert_eq!(kind_label(SourceKind::Channel), "Canale");
        assert_eq!(kind_label(SourceKind::Group), "Gruppo");
        assert_eq!(kind_label(SourceKind::Supergroup), "Supergruppo");
    }

    /// **La fonte dice con quali account è stata seguita, e niente se nessuno**
    /// (MULTI-ACCOUNT-02 parte 3).
    #[test]
    fn la_fonte_dice_con_quali_account_e_stata_seguita() {
        use lisi_core::model::monitoring_account::SourceAccount;
        use lisi_core::model::telegram_account::AccountUuid;

        let voce = |byte: u8, nome: &str| {
            let Ok(account_label) = lisi_core::text::DisplayName::try_new(nome) else {
                panic!("nome valido");
            };
            SourceAccount {
                account_uuid: AccountUuid::from_bytes([byte; 16]),
                account_label,
                last_bound_at: lisi_core::Timestamp::from_millis(0),
            }
        };
        assert_eq!(super::accounts_line(&[]), "");
        assert_eq!(
            super::accounts_line(&[voce(1, "Ufficio A")]),
            "Seguita con l'account Ufficio A."
        );
        assert_eq!(
            super::accounts_line(&[voce(1, "A"), voce(2, "B"), voce(3, "C")]),
            "Seguita con gli account A, B e C."
        );
    }
}

/// La riga «ultima verifica», che non è la riga «ultimo messaggio».
///
/// # Perché sono due righe e non una
///
/// Perché sono le due cose che HEALTH-01 esiste per non far confondere. Su una
/// riga sola si leggerebbero come una sola informazione, e un canale silenzioso
/// sembrerebbe non verificato — che è esattamente l'errore da evitare.
fn last_check_line(vista: &lisi_services::source_health::SourceHealthView) -> String {
    vista.evidence.last_conclusive_at().map_or_else(
        || String::from("Mai verificata in modo conclusivo."),
        |istante| format!("Verificata il {}.", istante.to_readable_local()),
    )
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn adesso() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

#[cfg(test)]
mod salute_delle_fonti {
    /// Il file dell'interfaccia, per le guardie testuali.
    const UI: &str = include_str!("../ui/app-window.slint");

    /// Questo modulo, per verificare che cosa il codice di produzione fa.
    const THIS_MODULE: &str = include_str!("sources.rs");

    /// Una fonte mai verificata non si dipinge come un guasto.
    ///
    /// È la regola che protegge il rosso: se «Sconosciuta» fosse rossa, un
    /// operatore che apre l'elenco il primo giorno vedrebbe tutto rosso e
    /// imparerebbe a ignorarlo.
    #[test]
    fn una_fonte_sconosciuta_non_si_dipinge_come_un_guasto() {
        let Some(inizio) = UI.find("text: source.health;") else {
            panic!("l'etichetta dello stato deve esistere");
        };
        let Some(fine) = UI[inizio..].find("font-weight: 600;") else {
            panic!("il blocco dell'etichetta deve avere una fine riconoscibile");
        };
        let blocco = &UI[inizio..inizio + fine];

        assert!(
            blocco.contains("source.health-unknown"),
            "lo stato sconosciuto deve avere un colore proprio"
        );
        // Il ramo dello sconosciuto porta al grigio, non al corallo.
        let Some(ramo) = blocco.find("source.health-unknown") else {
            panic!("il ramo dello sconosciuto deve esistere");
        };
        let dopo = &blocco[ramo..];
        let Some(scelta) = dopo.find("Palette.") else {
            panic!("il ramo deve scegliere un colore");
        };
        assert!(
            dopo[scelta..].starts_with("Palette.text-muted"),
            "una fonte mai verificata non deve essere colorata come un guasto"
        );
    }

    /// Il colore dipende dalla salute tecnica, non dal numero di contenuti.
    ///
    /// Una fonte che non pubblica da venti giorni ma risulta verificata resta
    /// verde: l'espressione del colore non deve nemmeno nominare il contenuto.
    #[test]
    fn il_colore_dello_stato_non_dipende_dai_contenuti() {
        let Some(inizio) = UI.find("text: source.health;") else {
            panic!("l'etichetta dello stato deve esistere");
        };
        let Some(fine) = UI[inizio..].find("font-weight: 600;") else {
            panic!("il blocco dell'etichetta deve avere una fine riconoscibile");
        };
        let blocco = &UI[inizio..inizio + fine];

        for vietato in ["last-content", "contents", "contenuti"] {
            assert!(
                !blocco.contains(vietato),
                "il colore dello stato nomina «{vietato}»: la severità deve \
                 dipendere dalla salute tecnica, non da quanti contenuti ci sono"
            );
        }
    }

    /// L'ultima verifica e l'ultimo contenuto restano due righe distinte.
    ///
    /// Sono la coppia che questa milestone esiste per non far confondere. Su
    /// una riga sola si leggerebbero come una cosa sola, e un canale
    /// silenzioso sembrerebbe non verificato.
    #[test]
    fn l_ultima_verifica_e_l_ultimo_contenuto_sono_due_righe() {
        let Some(verifica) = UI.find("text: source.last-check;") else {
            panic!("la riga dell'ultima verifica deve esistere");
        };
        let Some(contenuto) = UI.find("text: source.last-content;") else {
            panic!("la riga dell'ultimo contenuto deve esistere");
        };

        assert!(
            verifica < contenuto,
            "l'ultima verifica va detta prima dell'ultimo contenuto: dice se la \
             fonte è raggiungibile, che è la domanda"
        );
        // E non sono la stessa riga concatenata.
        assert!(
            !UI.contains("source.last-check + source.last-content"),
            "le due informazioni non vanno unite in una riga sola"
        );
    }

    /// Il riepilogo non dichiara mai una copertura.
    ///
    /// Il congelamento di prodotto lo prescrive: si dice «14/15 fonti
    /// configurate operative», **mai** «copertura Telegram al 100%».
    /// # Perché guarda solo il testo mostrato
    ///
    /// Una prima versione cercava le parole vietate in **tutto** il file, e
    /// diventava rossa su `width: 100%` — una dimensione di impaginazione, che
    /// non è un'affermazione sulle fonti. La prova era sbagliata, non il
    /// codice: cercare «100%» ovunque non verifica ciò che dichiara di
    /// verificare.
    ///
    /// Ora guarda le righe `text:`, che sono ciò che un operatore legge.
    #[test]
    fn il_riepilogo_non_dichiara_una_copertura() {
        let mostrate: Vec<&str> = UI
            .lines()
            .map(str::trim)
            .filter(|riga| riga.starts_with("text:") || riga.starts_with("+ \""))
            .collect();

        for vietato in ["copertura", "100%", "tutte le fonti attive"] {
            for riga in &mostrate {
                assert!(
                    !riga.contains(vietato),
                    "il testo mostrato contiene «{vietato}»: il riepilogo della \
                     salute dice quante fonti su quante, non una copertura \
                     — «{riga}»"
                );
            }
        }
    }

    /// Il comando della verifica dichiara che cosa costa, prima di essere
    /// premuto.
    ///
    /// Una richiesta a Telegram per tutte le fonti, non una per fonte: chi
    /// preme deve saperlo, perché è ciò che rende la verifica ripetibile senza
    /// rischi per l'account.
    #[test]
    fn il_comando_della_verifica_dichiara_che_cosa_costa() {
        assert!(
            UI.contains("una richiesta per tutte le "),
            "il comando deve dire che la verifica costa una sola richiesta"
        );
        assert!(
            UI.contains("Non entra in alcun gruppo e non cerca nulla."),
            "il comando deve dire che cosa NON fa"
        );
    }

    /// Senza un account collegato il comando è spento, non fallace.
    #[test]
    fn senza_account_il_comando_della_verifica_e_spento() {
        assert!(
            UI.contains("enabled: root.can-verify-sources;"),
            "il comando deve spegnersi senza un account collegato"
        );
    }

    /// Comporre l'elenco non scrive verifiche.
    ///
    /// Aprire la schermata è una lettura: se `refresh` registrasse una
    /// verifica, ogni apertura interrogherebbe Telegram e la storia della
    /// fonte si riempirebbe di righe che nessuno ha chiesto.
    #[test]
    fn comporre_l_elenco_non_registra_verifiche() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };

        let Some(inizio) = produzione.find("pub fn refresh(") else {
            panic!("la funzione che compone l'elenco deve esistere");
        };
        let Some(fine) = produzione[inizio..].find("\n}\n") else {
            panic!("la funzione deve avere una fine riconoscibile");
        };
        let corpo = &produzione[inizio..inizio + fine];

        for scrittura in ["verify_all", "insert_health_check", "accessible_chats"] {
            assert!(
                !corpo.contains(scrittura),
                "comporre l'elenco chiama «{scrittura}»: aprire la schermata \
                 non deve interrogare Telegram né scrivere osservazioni"
            );
        }
    }

    // ------------------------------------------------------------------
    // HEALTH-02 — il pannello «Perché questo stato»
    // ------------------------------------------------------------------

    /// Il corpo di una funzione del codice di produzione.
    fn corpo_di(nome: &str) -> &'static str {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let Some(inizio) = produzione.find(nome) else {
            panic!("la funzione «{nome}» deve esistere");
        };
        let Some(fine) = produzione[inizio..].find("\n}\n") else {
            panic!("la funzione «{nome}» deve avere una fine riconoscibile");
        };
        &produzione[inizio..inizio + fine]
    }

    /// La domanda «perché questo stato» è raggiungibile da ogni riga.
    ///
    /// # Perché è una prova e non un dettaglio
    ///
    /// Perché `why()` e `history()` esistevano, erano provati, ed erano
    /// **irraggiungibili**: nessuna riga di interfaccia li chiamava. Una
    /// capacità che nessuno può usare non è una capacità.
    #[test]
    fn ogni_riga_puo_chiedere_perche_e_in_quello_stato() {
        assert!(
            UI.contains("root.open-source-health(source.source-id);"),
            "ogni fonte configurata deve poter aprire il proprio dettaglio"
        );
        assert!(
            UI.contains("if root.source-health-open: Rectangle {"),
            "il pannello deve esistere e aprirsi su richiesta"
        );
        assert!(
            UI.contains("root.close-source-health();"),
            "il pannello deve potersi chiudere"
        );
    }

    /// Un tentativo non riuscito non si colora come un guasto.
    ///
    /// È la regola di ADR-0053 portata dove è più facile violarla: in un
    /// elenco di venti righe, dove il colore è la prima cosa che si legge.
    #[test]
    fn un_tentativo_non_riuscito_non_si_colora_come_un_guasto() {
        let Some(inizio) = UI.find("text: check.headline;") else {
            panic!("la riga della verifica deve esistere");
        };
        let Some(fine) = UI[inizio..].find("wrap: word-wrap;") else {
            panic!("il blocco della riga deve avere una fine riconoscibile");
        };
        let blocco = &UI[inizio..inizio + fine];

        assert!(
            blocco.contains("check.conclusive"),
            "il colore della riga deve dipendere dal fatto che abbia concluso"
        );
        for allarme in ["Palette.coral", "Palette.amber"] {
            assert!(
                !blocco.contains(allarme),
                "la riga di una verifica usa «{allarme}»: un tentativo non \
                 riuscito non è un guasto, e colorarlo come tale è la falsa \
                 attribuzione che questa milestone esiste per impedire"
            );
        }
    }

    /// Ogni riga della storia porta due frasi, e in quest'ordine.
    ///
    /// La prima dice come è andato il tentativo, la seconda che cosa se ne è
    /// appreso della fonte. Con la sola prima, quattro tentativi non riusciti
    /// si leggono come quattro guasti.
    #[test]
    fn ogni_riga_della_storia_porta_due_frasi() {
        let (Some(esito), Some(significato)) = (
            UI.find("text: check.headline;"),
            UI.find("text: check.meaning;"),
        ) else {
            panic!("la riga deve portare l'esito e il suo significato");
        };
        assert!(
            esito < significato,
            "l'esito va detto prima di che cosa significhi per la fonte"
        );
        assert!(
            !UI.contains("check.headline + check.meaning"),
            "le due frasi non vanno unite in una riga sola"
        );
    }

    /// Il pannello dichiara la condizione dell'account, separatamente.
    ///
    /// ADR-0053 Decisione 7: un account non autorizzato non cambia ciò che fu
    /// osservato della chat; cambia se il monitoraggio possa funzionare
    /// **adesso**. Le due cose vanno dette, e vanno dette separate.
    #[test]
    fn il_pannello_dichiara_la_condizione_dell_account() {
        assert!(
            UI.contains("CONDIZIONE DELL'ACCOUNT"),
            "la condizione dell'account deve avere una sezione propria"
        );
        assert!(
            UI.contains("text: root.source-health-account;"),
            "la dichiarazione deve essere mostrata"
        );
    }

    /// Il pannello non ricompone lo stato che la riga mostra.
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Se `open_health` ricomponesse l'elenco, fra il disegno della riga e il
    /// clic potrebbe essere stata registrata un'altra verifica: la riga
    /// direbbe «Operativa» e il pannello «In errore», e nessuno saprebbe quale
    /// delle due valga.
    #[test]
    fn il_pannello_non_ricompone_lo_stato_della_riga() {
        let corpo = corpo_di("fn open_health(");

        assert!(
            corpo.contains("presenter.shown(source_id)"),
            "il pannello deve prendere lo stato dalla vista che l'elenco mostra"
        );
        for ricomposizione in ["overview()", ".compose()"] {
            assert!(
                !corpo.contains(ricomposizione),
                "aprire il pannello chiama «{ricomposizione}»: ricomporre lo \
                 stato farebbe dire al pannello una cosa diversa dalla riga"
            );
        }
    }

    /// Aprire il pannello non interroga Telegram e non scrive.
    #[test]
    fn aprire_il_pannello_e_una_lettura() {
        let corpo = corpo_di("fn open_health(");

        for scrittura in [
            "verify_all",
            "insert_health_check",
            "accessible_chats",
            "append_audit",
        ] {
            assert!(
                !corpo.contains(scrittura),
                "aprire il pannello chiama «{scrittura}»: consultare non osserva, \
                 e la storia non deve riempirsi di righe che nessuno ha chiesto"
            );
        }
    }

    /// Chiudere il pannello svuota tutto ciò che mostrava.
    ///
    /// # Perché è una prova strutturale
    ///
    /// Perché il difetto si presenta aggiungendo una proprietà al pannello e
    /// dimenticandola nella chiusura: alla riapertura su un'altra fonte
    /// resterebbe visibile, per un istante, un fatto di una fonte diversa.
    #[test]
    fn chiudere_il_pannello_svuota_cio_che_mostrava() {
        let apre = corpo_di("fn open_health(");
        let chiude = corpo_di("fn close_health(");

        for riga in apre.lines() {
            let riga = riga.trim();
            let Some(resto) = riga.strip_prefix("window.set_source_health_") else {
                continue;
            };
            let Some(nome) = resto.split('(').next() else {
                continue;
            };
            assert!(
                chiude.contains(&format!("window.set_source_health_{nome}(")),
                "il pannello scrive «source_health_{nome}» e la chiusura non lo \
                 svuota: alla riapertura mostrerebbe il fatto di un'altra fonte"
            );
        }
    }
}

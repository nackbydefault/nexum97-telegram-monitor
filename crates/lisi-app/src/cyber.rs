//! Collegamento fra la schermata Cyber Watch e la sorveglianza dei segnali.
//!
//! # Perché questa schermata esiste
//!
//! CY-01 estrae gli indicatori, CY-02 li raggruppa, CY-05 dice dove ricade ciò
//! che nominano, CY-06 li compone. Fino al 2026-08-25 tutto questo si
//! affacciava all'operatore in **una frase** in coda alla descrizione della
//! schermata Alert.
//!
//! Il dominio c'era, la composizione pure, e chi doveva guardare i grappoli non
//! aveva un posto in cui farlo. È la stessa forma di difetto che CY-01 esisteva
//! per chiudere — una capacità costruita, collaudata e mai raggiungibile — e
//! questa volta il pezzo mancante era la schermata.
//!
//! # Che cosa questa schermata non dice, mai
//!
//! Che un attacco sia avvenuto. Che una fonte sia attendibile. Che qualcuno
//! abbia fatto qualcosa. Un grappolo è **un invito a guardare**, e la
//! conclusione la trae una persona (ADR-0035 Decisione 6).
//!
//! Due parole sono vietate per costruzione e sorvegliate da una prova:
//! «confermato» su un evento, e «indipendenti» sulle fonti. La seconda è la più
//! insidiosa — cinque canali che ripubblicano lo stesso messaggio sono cinque
//! copie, non cinque testimoni.

use std::rc::Rc;

use lisi_core::SessionId;
use lisi_core::model::cyber_event::CorrelationReason;
use lisi_core::model::cyber_timeline::CyberTimeline;
use lisi_core::model::indicator::IndicatorKind;
use lisi_services::cyber_watch::WatchEvent;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use lisi_core::model::hub_cyber::SharedCyberEvent;
use lisi_services::acquisition_authority::StationAuthorityService;
use lisi_services::device_identity::DeviceIdentityService;
use lisi_services::hub_catchup::HubCatchUpService;
use lisi_services::hub_client::{HubClientService, HubConnectionStore, ReviewSessionOutcome};

use crate::history::SharedHistory;

/// Monitoraggi dell'ufficio che questa schermata chiede.
const MONITORAGGI_A_SCHERMO: usize = 50;

/// Grappoli dell'ufficio che questa schermata chiede.
const GRAPPOLI_A_SCHERMO: usize = 25;
use crate::{
    AppWindow, CyberCandidateEntry, CyberEventEntry, CyberIndicatorEntry, CyberTimelineEntry,
};

/// Collega i comandi della schermata ai servizi.
pub fn wire(window: &AppWindow, screens: &SharedHistory) {
    {
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        window.on_cyber_shown(move || {
            if let Some(window) = handle.upgrade() {
                refresh(&window, &screens);
            }
        });
    }

    {
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        window.on_cyber_session_chosen(move |index| {
            if crate::lock::refuse_while_locked("cyber_session_chosen") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            window.set_cyber_session_index(index);
            refresh(&window, &screens);
        });
    }

    {
        // Dal grappolo ai contenuti che lo compongono.
        //
        // Porta allo Storico con la ricerca gia' impostata sul valore
        // dell'indicatore, che e' esattamente cio' che tiene insieme quei
        // contenuti. Non filtra per sessione: chi arriva qui da un grappolo
        // puo' volere sapere se quello stesso indicatore compare anche altrove,
        // e restringere di nascosto gli toglierebbe la risposta.
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        window.on_cyber_open_in_history(move |chiave| {
            if crate::lock::refuse_while_locked("cyber_open_in_history") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            window.set_history_filter(chiave);
            window.set_current_page(PAGINA_STORICO);
            crate::history::refresh(&window, &screens, Some(""));
        });
    }

    {
        // La cronologia di un gruppo: in che ordine e' arrivato.
        //
        // Si chiede per genere e valore dell'indicatore, che insieme sono la
        // ragione del gruppo. Il valore da solo non basta: «esempio.it» puo'
        // essere un dominio e non un URL, e chiedere la cronologia del genere
        // sbagliato restituirebbe un elenco vuoto senza dire perche'.
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        window.on_cyber_timeline_requested(move |genere, valore| {
            if crate::lock::refuse_while_locked("cyber_timeline_requested") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            open_timeline(&window, &screens, &genere, &valore);
        });
    }

    {
        let handle = window.as_weak();
        window.on_cyber_timeline_closed(move || {
            if crate::lock::refuse_while_locked("cyber_timeline_closed") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                close_timeline(&window);
            }
        });
    }
}

/// Chiude la cronologia, svuotando ogni riga che la riguarda.
///
/// # Perché si svuota tutto e non solo l'elenco
///
/// Perché un titolo o un'avvertenza rimasti dietro a un pannello chiuso
/// tornerebbero a comparire alla prossima apertura, riferiti a un gruppo
/// diverso — e una frase che parla di un altro gruppo è peggio di nessuna
/// frase.
fn close_timeline(window: &AppWindow) {
    window.set_cyber_timeline_open(false);
    window.set_cyber_timeline_title(SharedString::new());
    window.set_cyber_timeline_window(SharedString::new());
    window.set_cyber_timeline_caveat(SharedString::new());
    window.set_cyber_timeline_message(SharedString::new());
    window.set_cyber_timeline(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
    crate::ioc_resolve::hide(window);
    crate::registrazione::hide(window);
}

/// Apre la cronologia del gruppo indicato dalla sua ragione.
fn open_timeline(window: &AppWindow, screens: &SharedHistory, kind: &str, value: &str) {
    close_timeline(window);

    // UN GENERE CHE IL DOMINIO NON CONOSCE non si indovina: significherebbe
    // mostrare la cronologia di un altro indicatore, e chi legge non avrebbe
    // modo di accorgersene.
    let Some(kind) = IndicatorKind::parse(kind) else {
        window.set_cyber_timeline_open(true);
        window.set_cyber_timeline_message(crate::lingua::schermo(
            "Il genere dell'indicatore non è riconoscibile: la cronologia non viene mostrata \
             perché mostrarne una di un altro indicatore sarebbe peggio.",
        ));
        return;
    };

    let borrowed = screens.borrow();
    let Some(session_id) = borrowed.session_at(window.get_cyber_session_index()) else {
        return;
    };

    let reason = CorrelationReason::SameIndicator {
        kind,
        value: value.to_owned(),
    };

    window.set_cyber_timeline_open(true);
    // La risoluzione dal PC (IOC-RESOLVE-01, ADR-0202), per lo stesso
    // indicatore.
    crate::ioc_resolve::show_for(window, kind.as_str(), value);
    // Il WHOIS dal PC (WHOIS-01, ADR-0205), per lo stesso indicatore.
    crate::registrazione::show_for(window, kind.as_str(), value);
    window.set_cyber_timeline_title(crate::lingua::schermo(format!(
        "Cronologia del gruppo: contenuti che {}",
        reason.as_sentence()
    )));

    match borrowed.cyber_timeline(session_id, &reason) {
        Ok(timeline) => {
            window
                .set_cyber_timeline_window(crate::lingua::schermo(timeline.window().as_sentence()));
            window.set_cyber_timeline_caveat(SharedString::from(timeline.caveat()));
            window.set_cyber_timeline(timeline_model(&timeline));
        }
        Err(error) => {
            tracing::warn!(kind = error.kind(), "cronologia del gruppo non leggibile");
            window.set_cyber_timeline_message(crate::lingua::schermo(error.operator_message()));
        }
    }
}

/// Le righe della cronologia, come la schermata le mostra.
///
/// # Perché ogni riga porta il proprio orologio
///
/// Perché una riga copiata in una relazione viaggia da sola, e senza quella
/// parola sembrerebbe un istante come un altro. Gli istanti dei contenuti li
/// dichiara la fonte, quelli delle revisioni li ha misurati questa postazione,
/// e nessuno li ha sincronizzati.
fn timeline_model(timeline: &CyberTimeline) -> ModelRc<CyberTimelineEntry> {
    let entries: Vec<CyberTimelineEntry> = timeline
        .entries()
        .iter()
        .map(|riga| CyberTimelineEntry {
            when: SharedString::from(riga.at().to_readable_local()),
            clock: crate::lingua::schermo(riga.clock().as_label()),
            what: crate::lingua::schermo(riga.moment().as_sentence()),
            reference: crate::lingua::schermo(riga.reference().as_sentence()),
            is_human_act: riga.moment().is_human_act(),
        })
        .collect();

    ModelRc::from(Rc::new(VecModel::from(entries)))
}

/// La pagina dello Storico, dove la navigazione porta.
///
/// Il numero è quello dell'interfaccia. Sta qui come costante con un nome
/// perché un `8` nudo dentro una chiamata non dice a nessuno dove si sta
/// andando.
const PAGINA_STORICO: i32 = 8;

/// Quanti indicatori si mostrano per ogni grappolo.
///
/// # Perché un tetto, e perché si dichiara
///
/// Un grappolo di cinquanta contenuti può nominare centinaia di domini, e un
/// elenco così lungo smette di essere leggibile molto prima di finire. Il
/// taglio è dichiarato nella riga che lo segue: un elenco troncato in silenzio
/// farebbe credere completo ciò che non lo è, ed è il difetto che l'assaggio
/// dei termini nel wizard ha già insegnato a non ripetere.
const INDICATORS_PER_EVENT: usize = 12;

/// Riporta nell'interfaccia i grappoli della sessione scelta.
/// I grappoli dell'ufficio, quando questa postazione **segue** un Hub.
///
/// # Perché qui e non in una schermata a parte
///
/// Perché è la stessa domanda: «che cosa hanno in comune i contenuti che
/// abbiamo raccolto». Cambia **dove** si guarda, non che cosa si guarda, e due
/// schermate farebbero chiedere quale delle due dice il vero.
///
/// Su una postazione che ha i fatti questa funzione non fa niente: lì i
/// grappoli sono quelli di casa (TEAM-CYBER-01, ADR-0102).
fn grappoli_dell_ufficio(window: &AppWindow) -> bool {
    let Some(radice) = crate::account::data_root() else {
        return false;
    };
    if StationAuthorityService::in_directory(&radice)
        .role()
        .may_acquire()
    {
        return false;
    }

    let (Ok(identita), Ok(configurazione)) = (
        DeviceIdentityService::default_location(),
        HubConnectionStore::default_location(),
    ) else {
        return false;
    };
    let Ok(archivio) = lisi_services::sources::open_application_database() else {
        return false;
    };
    let client = HubClientService::new(HubCatchUpService::new(archivio), identita, configurazione)
        .with_default_office_networks()
        .with_screen_limits();

    let mut sessione = match client.open_review_session(crate::account::now()) {
        Ok(ReviewSessionOutcome::Ready(sessione)) => *sessione,
        Ok(altro) => {
            mostra_solo_un_messaggio(
                window,
                &altro
                    .refusal_message()
                    .unwrap_or_else(|| String::from("Il collegamento all'Hub non si è aperto.")),
            );
            return true;
        }
        Err(errore) => {
            mostra_solo_un_messaggio(window, &errore.operator_message());
            return true;
        }
    };

    // I MONITORAGGI VENGONO PRIMA: senza sapere quali ne ha l'ufficio, questa
    // postazione non sa come nominarne uno.
    let monitoraggi = match sessione.shared_sessions(MONITORAGGI_A_SCHERMO) {
        Ok(Some(monitoraggi)) => monitoraggi,
        Ok(None) => {
            sessione.close();
            mostra_solo_un_messaggio(
                window,
                "Questo Hub non dice quali monitoraggi ha l'ufficio: i grappoli non si possono \
                 chiedere.",
            );
            return true;
        }
        Err(errore) => {
            sessione.close();
            mostra_solo_un_messaggio(window, &errore.operator_message());
            return true;
        }
    };

    let mut etichette = vec![crate::lingua::schermo("Nessun monitoraggio scelto")];
    etichette.extend(
        monitoraggi
            .iter()
            .map(|riga| SharedString::from(riga.label.as_str())),
    );
    let scelto = window.get_cyber_session_index();
    let scelto = if usize::try_from(scelto).is_ok_and(|valore| valore < etichette.len()) {
        scelto
    } else {
        0
    };
    window.set_cyber_session_index(scelto);
    window.set_cyber_sessions(ModelRc::from(Rc::new(VecModel::from(etichette))));

    let scelta = usize::try_from(scelto)
        .ok()
        .filter(|indice| *indice > 0)
        .and_then(|indice| monitoraggi.get(indice - 1));
    let Some(monitoraggio) = scelta else {
        sessione.close();
        window.set_cyber_has_session(false);
        window.set_cyber_message(crate::lingua::schermo(
            "I grappoli sono quelli dell'ufficio, e li compone l'Hub: scegliere un monitoraggio.",
        ));
        window.set_cyber_events(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        return true;
    };

    let esito = sessione.shared_cyber_events(monitoraggio.id, GRAPPOLI_A_SCHERMO);
    sessione.close();

    window.set_cyber_has_session(true);
    match esito {
        Ok(Some(grappoli)) => {
            let righe: Vec<CyberEventEntry> = grappoli.iter().map(riga_dell_ufficio).collect();
            window.set_cyber_message(crate::lingua::schermo(
                "Grappoli dell'ufficio, composti dall'Hub. Il testo dei messaggi non arriva qui: \
                 si apre un contenuto per volta dalla Revisione condivisa.",
            ));
            window.set_cyber_events(ModelRc::from(Rc::new(VecModel::from(righe))));
        }
        Ok(None) => {
            mostra_solo_un_messaggio(window, "Questo Hub non tiene i grappoli dell'ufficio.")
        }
        Err(errore) => mostra_solo_un_messaggio(window, &errore.operator_message()),
    }
    true
}

/// Mostra un messaggio e nient'altro.
///
/// «Non c'è nulla da guardare» e «non sono riuscito a guardare» sono due cose
/// diverse: qui si dice la seconda, e l'elenco resta vuoto **con** la frase.
fn mostra_solo_un_messaggio(window: &AppWindow, frase: &str) {
    window.set_cyber_has_session(false);
    window.set_cyber_message(crate::lingua::schermo(frase));
    window.set_cyber_events(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
}

/// Un grappolo dell'ufficio, come la schermata lo mostra.
///
/// Gli stessi campi di uno di casa: cambia **dove** è stato composto.
fn riga_dell_ufficio(grappolo: &SharedCyberEvent) -> CyberEventEntry {
    let (primo, ultimo) = grappolo.seen_between.map_or_else(
        || (String::from("\u{2014}"), String::from("\u{2014}")),
        |(primo, ultimo)| (primo.to_readable_local(), ultimo.to_readable_local()),
    );

    CyberEventEntry {
        reason: crate::lingua::schermo(format!(
            "{} contenuti che {}",
            grappolo.contents, grappolo.reason
        )),
        assessment: crate::lingua::schermo(format!(
            "{}, {}.",
            lisi_core::text::counted(
                grappolo.distinct_sources,
                "fonte distinta",
                "fonti distinte"
            ),
            if grappolo.apparent_reposts == 1 {
                String::from("1 sembra una ripubblicazione")
            } else {
                format!("{} sembrano ripubblicazioni", grappolo.apparent_reposts)
            }
        )),
        contents: i32::try_from(grappolo.contents).unwrap_or(i32::MAX),
        distinct_sources: i32::try_from(grappolo.distinct_sources).unwrap_or(i32::MAX),
        apparent_reposts: i32::try_from(grappolo.apparent_reposts).unwrap_or(i32::MAX),
        first_seen: SharedString::from(primo),
        last_seen: SharedString::from(ultimo),
        italy: SharedString::from(grappolo.italy.as_str()),
        has_italy_signal: !grappolo.italy.is_empty(),
        sectors: SharedString::from(grappolo.sectors.as_str()),
        has_sector: !grappolo.sectors.is_empty(),
        sector_labels: SharedString::from(grappolo.sectors.as_str()),
        indicators: ModelRc::from(Rc::new(VecModel::from(
            grappolo
                .indicators
                .iter()
                .map(|indicatore| CyberIndicatorEntry {
                    // La stessa parola che l'elenco dei grappoli di casa usa
                    // per lo stesso indicatore, poche righe sotto
                    // (`indicator_model`): «nome di dominio», non `domain`
                    // (FINAL-FPR-ALL-16, FPR-02).
                    kind: SharedString::from(genere_indicatore(&indicatore.kind)),
                    value: SharedString::from(indicatore.value.as_str()),
                })
                .collect::<Vec<_>>(),
        ))),
        review: crate::lingua::schermo(grappolo.review_sentence()),
        search_key: SharedString::from(String::new()),
        reason_kind: SharedString::from(String::new()),
        // I contenuti stanno sull'Hub: qui non c'e' una conversazione da aprire.
        first_content_id: -1,
    }
}

pub fn refresh(window: &AppWindow, screens: &SharedHistory) {
    // I GRAPPOLI SONO DI CHI HA I CONTENUTI. Su una postazione che segue un
    // Hub li compone l'Hub, e questa schermata li guarda invece di rifarli
    // (TEAM-CYBER-01, ADR-0102, decisione 1).
    if grappoli_dell_ufficio(window) {
        return;
    }

    let borrowed = screens.borrow();

    // Il selettore ripete la prima voce «tutte» dello Storico, perche' e' lo
    // stesso elenco di sessioni — ma qui «tutte» NON e' una scelta valida: i
    // grappoli si costruiscono dentro una sessione, e mescolarne due
    // produrrebbe un gruppo che non appartiene a nessuna delle due (DEC-221).
    // La voce resta, e la schermata dice che cosa scegliere.
    let mut labels = vec![crate::lingua::schermo("Nessun monitoraggio scelto")];
    let mut nomi: Vec<(i64, String)> = Vec::new();
    match borrowed.sessions() {
        Ok(sessions) => {
            labels.extend(
                sessions
                    .iter()
                    .map(|summary| crate::lingua::schermo(summary.label())),
            );
            nomi.extend(
                sessions
                    .iter()
                    .map(|summary| (summary.session.id.get(), summary.label())),
            );
        }
        Err(error) => {
            tracing::warn!(kind = error.kind(), "elenco delle sessioni non leggibile");
        }
    }

    // Un indice rimasto oltre la fine — perche' l'elenco si e' accorciato —
    // punterebbe a una sessione diversa da quella scelta.
    let chosen = window.get_cyber_session_index();
    let chosen = if usize::try_from(chosen).is_ok_and(|value| value < labels.len()) {
        chosen
    } else {
        0
    };
    window.set_cyber_session_index(chosen);
    window.set_cyber_sessions(ModelRc::from(Rc::new(VecModel::from(labels))));

    let Some(session_id) = borrowed.session_at(chosen) else {
        window.set_cyber_has_session(false);
        window.set_cyber_message(SharedString::new());
        window.set_cyber_events(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        load_candidates(window, &borrowed, &nomi);
        return;
    };
    window.set_cyber_candidates(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));

    window.set_cyber_has_session(true);
    load_events(window, &borrowed, session_id);
}

/// Legge i grappoli e li porta nell'interfaccia.
///
/// # Perché un errore non diventa un elenco vuoto
///
/// «Non c'è nulla da guardare» e «non sono riuscito a guardare» sono due cose
/// diverse, e solo una delle due significa che l'archivio va controllato.
/// Ridurle entrambe a un elenco vuoto direbbe la prima quando è vera la
/// seconda.
fn load_events(window: &AppWindow, screens: &crate::history::HistoryScreens, session: SessionId) {
    match screens.cyber_events(session) {
        Ok(events) => {
            window.set_cyber_message(SharedString::new());
            window.set_cyber_events(event_model(&events));
        }
        Err(error) => {
            tracing::warn!(kind = error.kind(), "grappoli non leggibili");
            window.set_cyber_message(crate::lingua::schermo(error.operator_message()));
            window.set_cyber_events(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        }
    }
}

/// Legge gli eventi candidati di tutto l'archivio (CYBER-EVENTS-02, ADR-0189).
///
/// Un errore si dice, come per i grappoli: un elenco vuoto direbbe che non c'è
/// nulla da guardare.
fn load_candidates(
    window: &AppWindow,
    screens: &crate::history::HistoryScreens,
    nomi: &[(i64, String)],
) {
    match screens.cyber_candidates(crate::account::now()) {
        Ok(candidati) => {
            let righe: Vec<CyberCandidateEntry> = candidati
                .iter()
                .map(|candidato| candidate_entry(candidato, nomi))
                .collect();
            window.set_cyber_candidates(ModelRc::from(Rc::new(VecModel::from(righe))));
        }
        Err(error) => {
            tracing::warn!(kind = error.kind(), "eventi candidati non leggibili");
            window.set_cyber_message(crate::lingua::schermo(error.operator_message()));
            window.set_cyber_candidates(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        }
    }
}

/// Un evento candidato, come la schermata lo mostra.
fn candidate_entry(
    candidato: &lisi_core::model::cyber_candidate::CandidateEvent,
    nomi: &[(i64, String)],
) -> CyberCandidateEntry {
    let (primo, ultimo) = candidato.seen_between().map_or_else(
        || (String::from("—"), String::from("—")),
        |(primo, ultimo)| (primo.to_readable_local(), ultimo.to_readable_local()),
    );
    // Un monitoraggio senza nome nell'elenco si dice col suo numero: un nome
    // inventato direbbe dove guardare e porterebbe altrove.
    let monitoraggi = candidato
        .sessions()
        .iter()
        .map(|id| {
            nomi.iter()
                .find(|(chiave, _)| chiave == id)
                .map_or_else(|| format!("n. {id}"), |(_, nome)| nome.clone())
        })
        .collect::<Vec<String>>()
        .join(", ");

    CyberCandidateEntry {
        sentence: crate::lingua::schermo(candidato.as_sentence()),
        first_seen: SharedString::from(primo),
        last_seen: SharedString::from(ultimo),
        sessions: SharedString::from(monitoraggi),
        review: crate::lingua::schermo(candidato.review_summary().as_sentence()),
        first_content_id: candidato
            .first_content_id()
            .and_then(|id| i32::try_from(id).ok())
            .unwrap_or(-1),
    }
}

/// I grappoli, come la schermata li mostra.
fn event_model(events: &[WatchEvent]) -> ModelRc<CyberEventEntry> {
    let entries: Vec<CyberEventEntry> = events.iter().map(entry_of).collect();
    ModelRc::from(Rc::new(VecModel::from(entries)))
}

/// Un grappolo, come la schermata lo mostra.
fn entry_of(event: &WatchEvent) -> CyberEventEntry {
    // Un grappolo senza date non dovrebbe esistere — un grappolo ha membri, e
    // ogni membro ha un istante — ma il tipo lo consente, e un trattino dice
    // «non lo so» meglio di una data inventata.
    let (first, last) = event.seen_between.map_or_else(
        || (String::from("\u{2014}"), String::from("\u{2014}")),
        |(primo, ultimo)| (primo.to_readable_local(), ultimo.to_readable_local()),
    );

    CyberEventEntry {
        // La ragione porta gia' il conteggio: «6 contenuti che nominano la CVE
        // …». E' la frase che chi legge puo' verificare aprendo i contenuti.
        reason: crate::lingua::schermo(format!(
            "{} contenuti che {}",
            event.assessment.contents,
            event.event.reason.as_sentence()
        )),
        assessment: crate::lingua::schermo(event.assessment.as_sentence()),
        contents: i32::try_from(event.assessment.contents).unwrap_or(i32::MAX),
        distinct_sources: i32::try_from(event.assessment.distinct_sources).unwrap_or(i32::MAX),
        apparent_reposts: i32::try_from(event.assessment.apparent_reposts).unwrap_or(i32::MAX),
        first_seen: SharedString::from(first),
        last_seen: SharedString::from(last),
        italy: crate::lingua::schermo(event.italy.as_sentence()),
        has_italy_signal: !event.italy.is_empty(),
        sectors: crate::lingua::schermo(event.sectors.as_sentence()),
        has_sector: !event.sectors.is_empty(),
        sector_labels: SharedString::from(sector_labels(event)),
        indicators: indicator_model(event),
        review: crate::lingua::schermo(event.review.as_sentence()),
        search_key: SharedString::from(search_key(event)),
        reason_kind: SharedString::from(reason_kind(event)),
        // IL PRIMO PER PUBBLICAZIONE (ADR-0165): l'ingresso alla conversazione.
        first_content_id: event
            .event
            .members
            .iter()
            .min_by_key(|membro| (membro.published_at, membro.content_id))
            .and_then(|membro| i32::try_from(membro.content_id).ok())
            .unwrap_or(-1),
    }
}

/// Le etichette dei settori toccati, separate da virgola.
///
/// # Perché i settori distinti e non le attribuzioni
///
/// Due organizzazioni della sanità toccano **un** settore, non due: ripeterlo
/// due volte farebbe sembrare più esteso ciò che il grappolo dice. Le singole
/// attribuzioni, con la loro provenienza, restano leggibili nella frase estesa.
fn sector_labels(event: &WatchEvent) -> String {
    event
        .sectors
        .sectors()
        .iter()
        .map(|settore| settore.label())
        .collect::<Vec<&str>>()
        .join(", ")
}

/// Il genere di un indicatore **arrivato dall'Hub**, nella parola
/// dell'operatore.
///
/// # Perché una conversione e non una `label()`
///
/// Perché dall'Hub il genere arriva nella **forma conservata**, e deve: un
/// protocollo fra due versioni del prodotto porta chiavi, non parole, e una
/// parola che cambia romperebbe la compatibilità fra una postazione aggiornata
/// e una che non lo è ancora. La traduzione si fa qui, dove si mostra.
///
/// # Il genere che questa versione non conosce
///
/// Si mostra **come è arrivato**, invece di sparire o di diventare «altro»: un
/// Hub più recente può nominare un genere che questa postazione non ha ancora,
/// e far sparire una riga dall'elenco sarebbe peggio che mostrarla con una
/// parola tecnica.
fn genere_indicatore(conservato: &str) -> String {
    lisi_core::model::indicator::IndicatorKind::parse(conservato)
        .map_or_else(|| conservato.to_owned(), |genere| genere.label().to_owned())
}

/// Gli indicatori del grappolo, entro il tetto e con il taglio dichiarato.
fn indicator_model(event: &WatchEvent) -> ModelRc<CyberIndicatorEntry> {
    let mut entries: Vec<CyberIndicatorEntry> = event
        .indicators
        .iter()
        .take(INDICATORS_PER_EVENT)
        .map(|indicator| CyberIndicatorEntry {
            kind: crate::lingua::schermo(indicator.kind.label()),
            value: SharedString::from(indicator.value.as_str()),
        })
        .collect();

    // Il taglio si dichiara, e occupa una riga dell'elenco perche' e' li' che
    // chi legge lo cerca.
    if event.indicators.len() > entries.len() {
        entries.push(CyberIndicatorEntry {
            kind: crate::lingua::schermo("e altri"),
            value: crate::lingua::schermo(format!(
                "{} indicatori non elencati: si vedono aprendo i contenuti",
                event.indicators.len() - entries.len()
            )),
        });
    }

    ModelRc::from(Rc::new(VecModel::from(entries)))
}

/// Il genere dell'indicatore che tiene insieme il grappolo.
///
/// Nella forma dell'archivio, non nell'etichetta: l'etichetta è per chi legge e
/// cambia con le parole, il genere è ciò con cui si torna a interrogare
/// l'archivio.
fn reason_kind(event: &WatchEvent) -> &'static str {
    match &event.event.reason {
        lisi_core::model::cyber_event::CorrelationReason::SameIndicator { kind, .. } => {
            kind.as_str()
        }
    }
}

/// Il valore su cui cercare per ritrovare i contenuti del grappolo.
///
/// È **l'indicatore che li tiene insieme**: cercarlo nello Storico riporta
/// esattamente i contenuti che hanno formato il grappolo, e non altro.
fn search_key(event: &WatchEvent) -> String {
    match &event.event.reason {
        lisi_core::model::cyber_event::CorrelationReason::SameIndicator { value, .. } => {
            value.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn il_genere_di_un_indicatore_dell_hub_si_legge_in_italiano() {
        // Dall'Hub il genere arriva nella forma conservata, perché un
        // protocollo porta chiavi; sullo schermo ci andava così com'era, dove
        // l'elenco dei grappoli di casa, nella stessa pagina, scrive «nome di
        // dominio» (FINAL-FPR-ALL-16, FPR-02).
        assert_eq!(super::genere_indicatore("dominio"), "nome di dominio");
        assert_eq!(super::genere_indicatore("cve"), "vulnerabilità dichiarata");
        for genere in lisi_core::model::indicator::IndicatorKind::ALL {
            assert_eq!(
                super::genere_indicatore(genere.as_str()),
                genere.label(),
                "il genere «{}» non si traduce",
                genere.as_str()
            );
        }
    }

    #[test]
    fn un_genere_che_questa_versione_non_conosce_si_mostra_come_e_arrivato() {
        // La prova del valore sconosciuto: un Hub più recente può nominare un
        // genere che questa postazione non ha. Far sparire la riga, o
        // chiamarla «altro», nasconderebbe un indicatore che qualcuno ha
        // nominato.
        assert_eq!(super::genere_indicatore("genere_futuro"), "genere_futuro");
        assert_eq!(super::genere_indicatore(""), "");
    }

    /// Interfaccia principale, letta a tempo di compilazione.
    /// Il blocco della schermata Cyber Watch, dal suo marcatore alla fine.
    fn schermata() -> String {
        // L'ESTRATTORE E' UNO SOLO, E DIMOSTRA DI AVER LETTO QUALCOSA.
        //
        // Prima di HARDEN-02 ogni modulo ritagliava il corpo della propria
        // pagina per conto proprio, e un ritaglio che coglieva troppo poco
        // non faceva fallire niente: ogni divieto restava vero perche' non
        // c'era niente da vietare (ADR-0111).
        crate::page_guard::corpo_della_pagina(16)
    }

    /// **La schermata non può dire che un attacco sia confermato.**
    ///
    /// # Perché una guardia sul testo e non solo una convenzione
    ///
    /// Non esiste uno stato «confermato» che il programma possa assegnare da
    /// sé: quella è una conclusione, e la trae una persona (ADR-0035 Decisione
    /// 6). La regola è chiara e sta scritta in tre documenti — e una regola che
    /// vive solo nei documenti dura fino al primo che ha fretta di rendere
    /// l'elenco «più utile».
    ///
    /// La parola più insidiosa non è «attacco»: è **«indipendenti»**. Cinque
    /// canali che ripubblicano lo stesso messaggio sono cinque copie, non
    /// cinque testimoni, e chiamarli fonti indipendenti trasformerebbe un
    /// rilancio in una conferma.
    #[test]
    fn la_schermata_non_dichiara_un_attacco_ne_fonti_indipendenti() {
        let testo = schermata().to_lowercase();

        for vietata in [
            "attacco confermato",
            "incidente confermato",
            "fonti indipendenti",
            "conferme indipendenti:",
            "attacco in corso",
            "minaccia confermata",
        ] {
            assert!(
                !testo.contains(vietata),
                "la schermata Cyber Watch contiene «{vietata}»: un grappolo non e' \
                 un incidente confermato, e nessuna schermata puo' dichiararlo"
            );
        }
    }

    /// **La schermata dice che cosa NON è, prima di elencare.**
    ///
    /// Chi legge deve sapere che cosa ha davanti prima di leggerlo. Una
    /// dichiarazione in fondo alla pagina arriva dopo che l'impressione si è
    /// formata.
    #[test]
    fn la_schermata_dichiara_che_cosa_non_e_prima_dell_elenco() {
        let testo = schermata();

        let Some(avvertenza) = testo.find("non è un attacco") else {
            panic!("la schermata deve dichiarare che un gruppo non e' un attacco");
        };
        let Some(elenco) = testo.find("for entry in root.cyber-events") else {
            panic!("la schermata deve elencare i grappoli");
        };

        assert!(
            avvertenza < elenco,
            "la dichiarazione arriva DOPO l'elenco: chi legge si e' gia' fatto \
             un'idea di cio' che sta guardando"
        );
    }

    /// **Le fonti si chiamano «distinte», e la schermata spiega perché.**
    #[test]
    fn le_fonti_si_chiamano_distinte() {
        let testo = schermata();
        assert!(
            testo.contains("fonti distinte"),
            "il conteggio delle fonti deve dirsi «distinte»"
        );
    }

    /// **I quattro stati della schermata esistono tutti.**
    ///
    /// Nessuna sessione scelta, nessun gruppo, errore di lettura, elenco. I
    /// primi tre si somigliano a chi scrive il codice e sono tre cose diverse
    /// per chi legge lo schermo: «scegli un monitoraggio», «non c'è nulla» e
    /// «non sono riuscito a guardare» hanno tre risposte diverse.
    #[test]
    fn gli_stati_della_schermata_esistono() {
        let testo = schermata();

        for (marcatore, che_cosa) in [
            (
                "if !root.cyber-has-session && root.cyber-candidates.length == 0:",
                "nessuna sessione scelta",
            ),
            // CYBER-EVENTS-02 (ADR-0189): senza sessione, gli eventi
            // candidati dell'archivio quando ce ne sono.
            (
                "for candidato in root.cyber-candidates:",
                "eventi candidati dell'archivio",
            ),
            ("Nessun gruppo di segnali", "nessun grappolo"),
            (
                "if root.cyber-message != \"\": ErrorBanner",
                "errore di lettura",
            ),
            ("for entry in root.cyber-events:", "elenco dei grappoli"),
        ] {
            assert!(
                testo.contains(marcatore),
                "manca lo stato «{che_cosa}»: si riconosce da «{marcatore}»"
            );
        }
    }

    /// **La schermata mostra il settore, e dice da dove viene.**
    ///
    /// Fino a CYBER-SECTOR questa prova verificava il contrario: che la
    /// schermata dichiarasse **perché** il settore non compariva. Ora compare, e
    /// ciò che va sorvegliato è cambiato di conseguenza — un settore mostrato
    /// senza la sua provenienza sarebbe un'attribuzione che nessuno può
    /// contestare, che è esattamente ciò che DEC-235 esisteva per impedire.
    #[test]
    fn la_schermata_mostra_il_settore_con_la_sua_provenienza() {
        let testo = schermata();

        assert!(
            testo.contains("entry.sector-labels"),
            "la voce deve mostrare i settori toccati"
        );
        assert!(
            testo.contains("entry.sectors"),
            "la voce deve mostrare la provenienza per esteso: quale organizzazione, \
             che cosa ha riscontrato, e chi ha dichiarato il settore"
        );
        assert!(
            testo.contains("if entry.has-sector:"),
            "un grappolo senza settore non deve mostrare un riquadro vuoto: \
             suggerirebbe un dato mancante dove non c'e' nulla da mostrare"
        );
    }

    /// **La schermata dice dove il limite si è spostato.**
    ///
    /// Il settore ora compare, ma **solo per le organizzazioni dichiarate**: il
    /// prodotto continua a non dedurlo dal testo. Un contenuto senza settore non
    /// è un contenuto che non ne riguarda uno, ed è una differenza che chi legge
    /// non può indovinare.
    #[test]
    fn la_schermata_dichiara_da_che_cosa_dipende_il_settore() {
        let testo = schermata();
        assert!(
            testo.contains("organizzazioni")
                && testo.contains("dichiarate in Impostazioni")
                && testo.contains("sarebbe inventarlo"),
            "la schermata deve dire che il settore dipende da cio' che qualcuno ha \
             dichiarato, e che il prodotto non lo deduce dal testo"
        );
    }

    /// **Il taglio dell'elenco si dichiara, e non avviene in silenzio.**
    ///
    /// Un elenco troncato senza dirlo fa credere completo ciò che non lo è. È
    /// lo stesso difetto che l'assaggio dei termini nel wizard ha già insegnato
    /// a non ripetere, e il rimedio è lo stesso: la riga che manca occupa una
    /// riga dell'elenco.
    #[test]
    fn il_taglio_dell_elenco_degli_indicatori_si_dichiara() {
        let sorgente = include_str!("cyber.rs");
        let Some(inizio) = sorgente.find("fn indicator_model(") else {
            panic!("la funzione che costruisce l'elenco deve esistere");
        };
        let corpo = &sorgente[inizio..];

        assert!(
            corpo.contains("INDICATORS_PER_EVENT"),
            "l'elenco deve avere un tetto"
        );
        assert!(
            corpo.contains("indicatori non elencati"),
            "il taglio deve comparire NELL'elenco, non solo nel commento"
        );
    }

    // ------------------------------------------------------------------
    // La cronologia del gruppo (CYT-01).
    // ------------------------------------------------------------------

    /// **Ogni riga della cronologia dice di quale orologio è il suo istante.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che una riga copiata in una relazione perda l'unica parola che dice se
    /// quell'istante lo ha dichiarato Telegram o misurato questa postazione.
    /// Senza, due righe una sotto l'altra affermano una successione che nessuno
    /// ha osservato.
    ///
    /// # Il controllo negativo
    ///
    /// Togliendo dalla riga il campo `clock`, questa prova diventa rossa.
    #[test]
    fn ogni_riga_della_cronologia_nomina_il_proprio_orologio() {
        let testo = schermata();

        let Some(elenco) = testo.find("for row in root.cyber-timeline:") else {
            panic!("la schermata deve elencare le righe della cronologia");
        };
        let blocco = &testo[elenco..];
        let Some(fine) = blocco.find("cyber-timeline-caveat") else {
            panic!("l'elenco della cronologia deve chiudersi con l'avvertenza");
        };

        assert!(
            blocco[..fine].contains("text: row.clock;"),
            "ogni riga deve mostrare di quale orologio e' il proprio istante"
        );
        assert!(
            blocco[..fine].contains("text: row.reference;"),
            "ogni riga deve mostrare i propri rimandi"
        );
    }

    /// **Il periodo di osservazione arriva prima delle righe.**
    ///
    /// Un vuoto fra due righe si legge come «qui non è successo niente». La
    /// finestra è l'unica cosa che lo smentisce, e serve **prima** che
    /// l'impressione si formi.
    #[test]
    fn il_periodo_di_osservazione_precede_le_righe() {
        let testo = schermata();

        let Some(finestra) = testo.find("root.cyber-timeline-window") else {
            panic!("la schermata deve mostrare il periodo di osservazione");
        };
        let Some(righe) = testo.find("for row in root.cyber-timeline:") else {
            panic!("la schermata deve elencare le righe della cronologia");
        };

        assert!(
            finestra < righe,
            "il periodo in cui si e' osservato arriva DOPO le righe: chi legge \
             si e' gia' fatto un'idea dei vuoti"
        );
    }

    /// **L'atto di una persona non si rende come un'osservazione.**
    ///
    /// Sono due cose diverse, e chi legge deve poterlo vedere senza leggere la
    /// frase: un giudizio scritto da qualcuno e un fatto registrato dal
    /// programma non hanno lo stesso peso in un fascicolo.
    #[test]
    fn un_atto_di_una_persona_si_distingue_da_un_osservazione() {
        let testo = schermata();
        assert!(
            testo.contains("row.is-human-act"),
            "la schermata deve distinguere l'atto di una persona"
        );
        assert!(
            testo.contains("row.is-human-act ? Origine.operatore : Origine.osservato"),
            "la schermata deve segnare l'origine di ogni riga con le parole di ADR-0118"
        );
    }

    /// **La cronologia non porta un punteggio, e nemmeno un totale.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che un conteggio accanto a un gruppo diventi un punteggio. È il confine
    /// che il prodotto rifiuta, e una fase successiva non è un permesso.
    #[test]
    fn la_cronologia_non_mostra_alcun_punteggio() {
        let testo = schermata().to_lowercase();

        let Some(inizio) = testo.find("if root.cyber-timeline-open:") else {
            panic!("il pannello della cronologia deve esistere");
        };
        let pannello = &testo[inizio..];
        let Some(fine) = pannello.find("codice: \"sic-14\"") else {
            panic!("il pannello deve chiudersi prima del limite dichiarato");
        };
        let pannello = &pannello[..fine];

        for vietata in ["punteggio", "gravità", "rischio", "livello di"] {
            assert!(
                !pannello.contains(vietata),
                "il pannello della cronologia contiene «{vietata}»: una linea del \
                 tempo con accanto un giudizio non e' piu' una linea del tempo"
            );
        }
    }
}

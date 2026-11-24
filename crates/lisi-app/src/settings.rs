//! Collegamento fra la schermata Impostazioni e il servizio delle impostazioni.
//!
//! Come gli altri moduli di collegamento, non contiene logica: traduce le
//! impostazioni conservate in proprietà dell'interfaccia e le scelte
//! dell'operatore in una chiamata al servizio.
//!
//! Le opzioni di riservatezza e il loro ordine vengono dal dominio
//! (`NotificationPrivacy::all()`): l'interfaccia riceve le etichette già pronte
//! e non ripete l'elenco delle modalità.

use std::rc::Rc;

use lisi_core::model::language::InterfaceLanguage;
use lisi_core::model::motion::MotionPreference;
use lisi_core::model::{NotificationPrivacy, NotificationSettings};
use lisi_platform::AutostartState;
use lisi_services::settings::SettingsService;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::{AppWindow, Appearance, CapabilityRow};

/// Servizio delle impostazioni condiviso fra i gestori.
pub type SharedSettings = Rc<SettingsService>;

/// Indice della pagina Impostazioni nell'interfaccia.
///
/// Usato solo dal test che lo lega al file `.slint`: la navigazione avviene
/// nella voce di menu, non da Rust, quindi la costante non serve a runtime.
#[cfg(test)]
const SETTINGS_PAGE: i32 = 11;

/// Crea il servizio delle impostazioni sull'archivio indicato.
#[must_use]
pub fn create_service(database: lisi_services::Database) -> Option<SharedSettings> {
    Some(Rc::new(SettingsService::new(database)))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// Attore dell'audit.
fn actor() -> lisi_services::ServiceResult<lisi_core::text::Actor> {
    crate::operator::audit_actor()
}

/// Etichette delle modalità di riservatezza, nell'ordine del dominio.
fn privacy_options() -> ModelRc<SharedString> {
    let labels: Vec<SharedString> = NotificationPrivacy::all()
        .iter()
        .map(|mode| crate::lingua::schermo(mode.label()))
        .collect();
    ModelRc::from(Rc::new(VecModel::from(labels)))
}

/// Modalità corrispondente all'indice scelto nell'interfaccia.
fn privacy_from_index(index: i32) -> NotificationPrivacy {
    usize::try_from(index)
        .ok()
        .and_then(|position| NotificationPrivacy::all().get(position).copied())
        .unwrap_or(NotificationPrivacy::Reduced)
}

/// Indice dell'interfaccia corrispondente a una modalità.
fn index_of_privacy(privacy: NotificationPrivacy) -> i32 {
    NotificationPrivacy::all()
        .iter()
        .position(|mode| *mode == privacy)
        .and_then(|position| i32::try_from(position).ok())
        .unwrap_or(1)
}

/// Scrive nell'interfaccia le impostazioni indicate.
fn show(window: &AppWindow, settings: NotificationSettings) {
    window.set_settings_privacy_index(index_of_privacy(settings.privacy));
    window.set_settings_min_level(i32::from(settings.minimum_level));
    window.set_settings_max(i32::try_from(settings.max_per_session).unwrap_or(i32::MAX));
    window.set_settings_include_url(settings.include_url);
    window.set_settings_cyber_enabled(settings.cyber_enabled);
    window.set_settings_cyber_contents(i32::try_from(settings.cyber_minimum_contents).unwrap_or(3));
    window.set_settings_cyber_sources(i32::try_from(settings.cyber_minimum_sources).unwrap_or(2));
}

/// Riporta nell'interfaccia ciò che il registro dice dell'avvio automatico.
///
/// Si **rilegge** invece di ricordare ciò che si è appena scritto: il registro
/// è l'unica fonte, e chiunque può averlo cambiato da fuori con `msconfig` o il
/// Gestione attività. Ricordare produrrebbe una schermata che afferma uno stato
/// che il sistema non ha più.
fn show_autostart(window: &AppWindow) -> Option<AutostartState> {
    match lisi_platform::autostart::state() {
        Ok(state) => {
            window.set_autostart_registered(state.is_registered());
            window.set_autostart_effective(state.is_effective());
            window.set_autostart_message(crate::lingua::schermo(state.operator_message()));
            Some(state)
        }
        Err(error) => {
            tracing::warn!(errore = %error, "stato dell'avvio automatico non leggibile");
            // Non leggibile non è «spento»: dirlo spento inviterebbe a
            // riattivarlo, e la riattivazione fallirebbe per la stessa ragione.
            window.set_autostart_registered(false);
            window.set_autostart_effective(false);
            window.set_autostart_message(crate::lingua::schermo(
                "Non è stato possibile leggere l'avvio automatico dal registro di Windows: \
                 lo stato mostrato qui sopra potrebbe non essere quello reale.",
            ));
            None
        }
    }
}

/// Riporta nell'interfaccia l'idoneita' della postazione.
///
/// # Perche' si interroga a ogni apertura
///
/// Ogni capacita' qui dentro puo' cambiare mentre il prodotto e' aperto: un
/// criterio di dominio applicato, un certificato scaduto, un'impostazione
/// cambiata in un'altra finestra. Una fotografia scattata all'avvio
/// invecchierebbe senza dirlo.
fn show_capabilities(window: &AppWindow) {
    let stato = lisi_services::capability::station_capabilities();

    let righe: Vec<CapabilityRow> = stato
        .capabilities
        .iter()
        .map(|capacita| CapabilityRow {
            name: SharedString::from(capacita.name),
            requirement: crate::lingua::schermo(capacita.requirement.label()),
            status: crate::lingua::schermo(capacita.availability.label()),
            detail: SharedString::from(capacita.detail.as_str()),
            usable: capacita.availability.is_usable(),
            blocking: capacita.blocks_work(),
        })
        .collect();

    window.set_station_capabilities(ModelRc::from(Rc::new(VecModel::from(righe))));
    window.set_station_verdict(crate::lingua::schermo(stato.operator_message()));
    window.set_station_fit(stato.is_fit());
}

/// Riporta nell'interfaccia la preferenza sul movimento.
///
/// # Perche' il sistema si interroga a ogni apertura
///
/// La preferenza di accessibilita' di Windows puo' cambiare mentre il prodotto
/// e' aperto, e chi ha scelto «come Windows» deve vederla cambiare. Ricordarla
/// al primo avvio la congelerebbe per tutta la sessione.
fn show_motion(window: &AppWindow, settings: &SharedSettings) {
    let scelte = MotionPreference::all();
    let etichette: Vec<SharedString> = scelte
        .iter()
        .map(|scelta| crate::lingua::schermo(scelta.label()))
        .collect();
    window.set_motion_options(ModelRc::from(Rc::new(VecModel::from(etichette))));

    let scelta = settings
        .database()
        .motion_preference()
        .unwrap_or_else(|error| {
            tracing::warn!(errore = %error, "preferenza sul movimento non leggibile");
            MotionPreference::default()
        });
    let indice = scelte
        .iter()
        .position(|candidata| *candidata == scelta)
        .and_then(|posizione| i32::try_from(posizione).ok())
        .unwrap_or(0);
    window.set_motion_index(indice);
    window.set_motion_consequence(crate::lingua::schermo(scelta.consequence()));

    let sistema = lisi_platform::motion::system_motion();
    window.set_motion_system_message(crate::lingua::schermo(sistema.operator_message()));
    apply_motion(window, scelta, sistema);
}

/// Riporta nell'interfaccia la lingua scelta (I18N-01, ADR-0197).
///
/// I nomi delle lingue non si traducono: ciascuno è scritto nella lingua
/// stessa, perché chi non legge l'italiano riconosca la propria.
fn show_language(window: &AppWindow, settings: &SharedSettings) {
    let scelte = InterfaceLanguage::all();
    let etichette: Vec<SharedString> = scelte
        .iter()
        .map(|scelta| crate::lingua::schermo(scelta.label()))
        .collect();
    window.set_language_options(ModelRc::from(Rc::new(VecModel::from(etichette))));

    let scelta = settings
        .database()
        .interface_language()
        .unwrap_or_else(|error| {
            tracing::warn!(errore = %error, "lingua dell'interfaccia non leggibile");
            InterfaceLanguage::default()
        });
    let indice = scelte
        .iter()
        .position(|candidata| *candidata == scelta)
        .and_then(|posizione| i32::try_from(posizione).ok())
        .unwrap_or(0);
    window.set_language_index(indice);
    window.set_language_consequence(SharedString::from(crate::lingua::tr(scelta.consequence())));
}

/// Applica la scelta all'interfaccia.
///
/// E' l'unico punto in cui il movimento si accende o si spegne: `Appearance` e'
/// un `global` di Slint, e radar, transizioni ed entrate lo leggono da li'.
fn apply_motion(
    window: &AppWindow,
    scelta: MotionPreference,
    sistema: lisi_platform::SystemMotion,
) {
    let ridurre = scelta.reduces(sistema.asks_for_reduction());
    window.global::<Appearance>().set_motion_enabled(!ridurre);
}

/// Riporta nell'interfaccia che cosa Windows dice degli avvisi.
///
/// # Perche' si chiede a ogni apertura della schermata
///
/// L'operatore puo' aver appena cambiato le impostazioni di Windows, in un'altra
/// finestra, proprio perche' non vedeva gli avvisi. Ricordare la risposta del
/// primo avvio significherebbe mostrargliela per tutta la sessione dopo che ha
/// smesso di valere.
fn show_toast_state(window: &AppWindow) {
    let stato = lisi_platform::toast::notification_state();
    window.set_toast_state_enabled(stato.is_enabled());
    window.set_toast_state_message(crate::lingua::schermo(stato.operator_message()));
}

/// Riporta nell'interfaccia che cosa Windows dice della firma di questa copia.
///
/// # Perche' si chiede a ogni apertura della schermata
///
/// Non e' costoso — riguarda un file solo — e la risposta puo' cambiare senza
/// che il programma se ne accorga: un certificato scade, un'autorita' viene
/// revocata, qualcuno sostituisce l'eseguibile. Ricordare la risposta del primo
/// avvio significherebbe mostrarla per mesi dopo che ha smesso di valere.
fn show_signature(window: &AppWindow) {
    let stato = lisi_platform::signature::verify_self();
    window.set_signature_trusted(stato.is_trusted());
    window.set_signature_message(crate::lingua::schermo(stato.operator_message()));
}

/// Riporta nell'interfaccia le impostazioni conservate.
pub fn refresh(window: &AppWindow, settings: &SharedSettings, message: Option<&str>) {
    if let Some(text) = message {
        window.set_settings_message(SharedString::from(text));
    }
    window.set_settings_privacy_options(privacy_options());
    let _ = show_autostart(window);
    show_signature(window);
    show_toast_state(window);
    show_motion(window, settings);
    show_language(window, settings);
    show_capabilities(window);

    match settings.load() {
        Ok(loaded) => show(window, loaded),
        Err(error) => {
            tracing::warn!(kind = error.kind(), "impostazioni non leggibili");
            window.set_settings_message(crate::lingua::schermo(error.operator_message()));
            // Senza impostazioni leggibili si mostra il valore prudente di
            // fabbrica: la schermata non resta in uno stato indeterminato.
            show(window, NotificationSettings::default());
        }
    }
}

/// Legge dall'interfaccia le impostazioni scelte dall'operatore.
fn chosen(window: &AppWindow) -> NotificationSettings {
    NotificationSettings {
        privacy: privacy_from_index(window.get_settings_privacy_index()),
        minimum_level: u8::try_from(window.get_settings_min_level()).unwrap_or(1),
        max_per_session: usize::try_from(window.get_settings_max()).unwrap_or(0),
        include_url: window.get_settings_include_url(),
        cyber_enabled: window.get_settings_cyber_enabled(),
        cyber_minimum_contents: u32::try_from(window.get_settings_cyber_contents()).unwrap_or(3),
        cyber_minimum_sources: u32::try_from(window.get_settings_cyber_sources()).unwrap_or(2),
    }
}

/// Salva le impostazioni scelte e riporta l'esito.
fn save(window: &AppWindow, settings: &SharedSettings) -> String {
    let chosen = chosen(window);
    let outcome = actor().and_then(|actor| settings.save(chosen, &actor, now()));

    match outcome {
        Ok(saved) => {
            // Si rimostra cio' che e' stato davvero conservato: se un valore
            // era fuori scala, l'operatore vede quello ricondotto.
            show(window, saved);
            String::from("Impostazioni salvate.")
        }
        Err(error) => {
            tracing::warn!(kind = error.kind(), "impostazioni non salvate");
            error.operator_message()
        }
    }
}

/// Attiva o disattiva l'avvio automatico, e ne registra il fatto nell'audit.
///
/// L'esito riportato non è quello del comando ma quello della **rilettura**:
/// «attivato» va detto solo se il registro poi lo conferma.
fn set_autostart(window: &AppWindow, settings: &SharedSettings, wanted: bool) -> String {
    // Da una chiavetta il registro non si tocca, né per scrivere né per
    // togliere (ADR-0176, decisione 6): prima di ogni altra cosa.
    if let Some(rifiuto) = lisi_platform::launch_volume::of_current_executable().autostart_refusal()
    {
        tracing::info!(
            voluto = wanted,
            "avvio automatico rifiutato: programma fuori dalla postazione"
        );
        let _ = show_autostart(window);
        return String::from(rifiuto);
    }

    let outcome = if wanted {
        lisi_platform::autostart::enable()
    } else {
        lisi_platform::autostart::disable()
    };

    if let Err(error) = outcome {
        tracing::warn!(errore = %error, voluto = wanted, "avvio automatico non modificato");
        let _ = show_autostart(window);
        return String::from(
            "Windows non ha accettato la modifica dell'avvio automatico. \
             L'applicazione funziona lo stesso; semplicemente non si avvierà da sola.",
        );
    }

    // Che il computer avvii o non avvii da solo un programma di monitoraggio è
    // un fatto della postazione, non una preferenza estetica: resta scritto.
    // Un audit non riuscito non annulla la modifica, che è già avvenuta nel
    // registro: si segnala e si prosegue, invece di riferire un guasto per
    // qualcosa che ha funzionato.
    let recorded =
        actor().and_then(|actor| settings.record_autostart_change(wanted, &actor, now()));
    if let Err(error) = recorded {
        tracing::warn!(
            kind = error.kind(),
            "cambio di avvio automatico non registrato in audit"
        );
    }

    // Il messaggio viene da ciò che il registro dice **adesso**, non da ciò che
    // è stato chiesto: un comando che riesce e uno stato che non cambia sono
    // due cose diverse, e riferire l'intenzione invece del fatto è il modo in
    // cui un'interfaccia finisce per mentire con le migliori intenzioni.
    match show_autostart(window) {
        Some(AutostartState::Enabled) => {
            String::from("Avvio automatico attivato per questo profilo Windows.")
        }
        Some(AutostartState::Disabled) => String::from("Avvio automatico disattivato."),
        Some(AutostartState::EnabledElsewhere) => String::from(
            "La voce di avvio automatico esiste ma punta a un'altra copia del programma: \
             non partirebbe questa.",
        ),
        None => String::from(
            "La modifica è stata inviata a Windows, ma il registro non è rileggibile: \
             lo stato mostrato potrebbe non essere quello reale.",
        ),
    }
}

/// Collega i comandi della schermata al servizio.
pub fn wire(window: &AppWindow, settings: &SharedSettings) {
    {
        let handle = window.as_weak();
        let settings = Rc::clone(settings);
        window.on_motion_chosen(move |index| {
            if crate::lock::refuse_while_locked("motion_chosen") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let scelta = usize::try_from(index)
                .ok()
                .and_then(|posizione| MotionPreference::all().get(posizione).copied())
                .unwrap_or_default();

            // Si applica SUBITO, poi si salva.
            //
            // Chi sceglie «ridotto» perche' il movimento gli da' fastidio non
            // deve continuare a vederlo mentre l'archivio scrive, e non deve
            // restare col movimento acceso se la scrittura fallisce.
            let sistema = lisi_platform::motion::system_motion();
            apply_motion(&window, scelta, sistema);
            window.set_motion_consequence(crate::lingua::schermo(scelta.consequence()));

            let esito = actor().map_err(|_| ()).and_then(|actor| {
                settings
                    .database()
                    .save_motion_preference(scelta, &actor, now().as_millis())
                    .map_err(|_| ())
            });
            if esito.is_err() {
                tracing::warn!("preferenza sul movimento non salvata");
                window.set_settings_message(crate::lingua::schermo(
                    "La scelta vale per questa sessione ma non è stata conservata: \
                     al prossimo avvio tornerà quella precedente.",
                ));
            }
        });
    }

    {
        let handle = window.as_weak();
        let settings = Rc::clone(settings);
        window.on_language_chosen(move |index| {
            if crate::lock::refuse_while_locked("language_chosen") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let scelta = usize::try_from(index)
                .ok()
                .and_then(|posizione| InterfaceLanguage::all().get(posizione).copied())
                .unwrap_or_default();

            // Si applica SUBITO, poi si salva, come il movimento: chi ha
            // scelto una lingua che legge non deve aspettare l'archivio.
            crate::lingua::applica(scelta);
            window.set_language_consequence(SharedString::from(crate::lingua::tr(
                scelta.consequence(),
            )));

            let esito = actor().map_err(|_| ()).and_then(|actor| {
                settings
                    .database()
                    .save_interface_language(scelta, &actor, now().as_millis())
                    .map_err(|_| ())
            });
            if esito.is_err() {
                tracing::warn!("lingua dell'interfaccia non salvata");
                window.set_settings_message(SharedString::from(crate::lingua::tr(
                    "La lingua vale per questa sessione ma non è stata conservata: al prossimo \
                     avvio tornerà quella precedente.",
                )));
            }
        });
    }

    {
        let handle = window.as_weak();
        let settings = Rc::clone(settings);
        window.on_settings_shown(move || {
            if let Some(window) = handle.upgrade() {
                refresh(&window, &settings, Some(""));
                crate::signing::refresh(&window);
                crate::servizio_stato::refresh(&window);
            }
        });
    }

    {
        let handle = window.as_weak();
        let settings = Rc::clone(settings);
        window.on_save_settings(move || {
            if crate::lock::refuse_while_locked("save_settings") {
                return;
            }
            // Un prerequisito della fascia di prontezza puo' essere cambiato (F-08).
            crate::preflight::mark_stale();
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = save(&window, &settings);
            refresh(&window, &settings, Some(&message));
        });
    }

    {
        let handle = window.as_weak();
        let settings = Rc::clone(settings);
        window.on_set_autostart(move |wanted| {
            if crate::lock::refuse_while_locked("set_autostart") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = set_autostart(&window, &settings, wanted);
            window.set_settings_message(crate::lingua::schermo(message));
        });
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::NotificationPrivacy;

    use super::{SETTINGS_PAGE, index_of_privacy, privacy_from_index};

    /// Interfaccia, letta a tempo di compilazione per il controllo qui sotto.
    const UI: &str = include_str!("../ui/app-window.slint");

    #[test]
    fn the_settings_page_index_matches_the_interface() {
        // L'indice e' condiviso con il file .slint: se cambia in un posto solo,
        // la voce di menu «Impostazioni» porterebbe alla pagina sbagliata.
        assert_eq!(SETTINGS_PAGE, 11);

        assert!(
            UI.contains(&format!("current-page == {SETTINGS_PAGE}: Rectangle")),
            "la pagina Impostazioni con indice {SETTINGS_PAGE} non e' nell'interfaccia"
        );
        assert!(
            UI.contains(&format!("root.open-page({SETTINGS_PAGE});")),
            "la voce di menu Impostazioni non naviga all'indice {SETTINGS_PAGE}"
        );
    }

    /// **La schermata deve dire la verita' anche quando e' scomoda.**
    ///
    /// Finche' non esiste un certificato (HVQ-07) questa copia non e' firmata,
    /// e la sezione deve dirlo. Una schermata che tacesse sarebbe piu' comoda e
    /// meno vera.
    ///
    /// La prova NON asserisce quale sia l'esito: pretendere «non firmato»
    /// diventerebbe rossa il giorno in cui il prodotto viene firmato, cioe'
    /// esattamente al contrario di cio' che serve.
    #[test]
    fn l_origine_del_programma_viene_sempre_dichiarata() {
        let messaggio = lisi_platform::signature::verify_self().operator_message();
        assert!(
            !messaggio.is_empty(),
            "la schermata deve dire qualcosa dell'origine del programma"
        );
        // Attendibile o no, il messaggio deve nominare la firma: chi legge deve
        // capire DI CHE COSA si parla senza il titolo della sezione.
        assert!(
            messaggio.contains("firma") || messaggio.contains("firmato"),
            "il messaggio non nomina cio' di cui parla: «{messaggio}»"
        );
    }

    /// **La schermata deve dire se Windows sopprime gli avvisi.**
    ///
    /// Il pilot del 20 agosto ha lasciato una domanda aperta — perche' gli
    /// avvisi arrivavano nel centro notifiche ma non comparivano — e la
    /// risposta piu' economica richiedeva che una persona aprisse le
    /// impostazioni di Windows. Adesso il prodotto la chiede da se'.
    ///
    /// La prova NON asserisce quale sia l'esito: dipende dalla macchina.
    #[test]
    fn il_consenso_di_windows_viene_sempre_dichiarato() {
        let stato = lisi_platform::toast::notification_state();
        let messaggio = stato.operator_message();
        assert!(
            !messaggio.is_empty(),
            "la schermata deve dire qualcosa del consenso di Windows"
        );
        assert!(
            messaggio.contains("avvisi") || messaggio.contains("notific"),
            "il messaggio non nomina cio' di cui parla: «{messaggio}»"
        );
    }

    /// La sezione deve esistere nell'interfaccia, non solo nel codice Rust.
    #[test]
    fn la_sezione_del_consenso_e_nell_interfaccia() {
        assert!(
            UI.contains("CONSENSO DI WINDOWS"),
            "la sezione non compare nella schermata Impostazioni"
        );
        assert!(
            UI.contains("toast-state-message"),
            "la schermata non lega il messaggio alla proprieta'"
        );
    }

    /// **L'idoneita' della postazione deve essere leggibile in una schermata.**
    ///
    /// ADR-0039 Decisione 5: un amministratore che installa il prodotto su una
    /// postazione nuova deve poter leggere che cosa funziona e che cosa no,
    /// senza aprire un registro ne' interpretare un errore.
    #[test]
    fn l_idoneita_della_postazione_e_nell_interfaccia() {
        assert!(
            UI.contains("IDONEITÀ DELLA POSTAZIONE"),
            "la sezione non compare nella schermata Impostazioni"
        );
        assert!(
            UI.contains("station-capabilities"),
            "la schermata non lega l'elenco alla proprieta'"
        );
    }

    /// **Lo stato di ogni capacita' e' SCRITTO, non solo colorato.**
    ///
    /// Il colore da solo non basta a chi non lo distingue, ed e' la stessa
    /// regola che il progetto applica ai livelli 0-4.
    #[test]
    fn lo_stato_di_ogni_capacita_e_scritto_e_non_solo_colorato() {
        assert!(
            UI.contains("capacita.status"),
            "lo stato non compare come testo: chi non distingue i colori non \
             saprebbe leggerlo"
        );
        assert!(
            UI.contains("capacita.requirement"),
            "la schermata non dice se una capacita' e' necessaria o facoltativa, \
             che e' cio' che distingue una postazione inutilizzabile da una \
             che lavora con meno"
        );
    }

    #[test]
    fn the_privacy_index_round_trips_through_every_mode() {
        // L'indice dell'interfaccia e la modalita' del dominio devono restare in
        // corrispondenza in entrambi i versi, per ogni modalita'.
        for mode in NotificationPrivacy::all() {
            assert_eq!(privacy_from_index(index_of_privacy(*mode)), *mode);
        }
    }

    #[test]
    fn an_out_of_range_index_falls_back_to_a_prudent_mode() {
        assert_eq!(privacy_from_index(-1), NotificationPrivacy::Reduced);
        assert_eq!(privacy_from_index(99), NotificationPrivacy::Reduced);
    }
}

//! La striscia «Pronto per lavorare» (PR-04, ADR-0120).
//!
//! # Che cosa fa
//!
//! Raccoglie i fatti, chiede l'esito a `lisi_services::preflight::assess`,
//! lascia la riga d'audit e mostra **una riga**. All'avvio, dopo che la finestra
//! è comparsa; poi ogni volta che l'operatore preme «Ricontrolla».
//!
//! # Che cosa non fa
//!
//! **Non ripara.** Il pulsante della striscia cambia pagina e basta: porta alla
//! schermata dove il gesto si compie, con i controlli che quella schermata ha
//! già. Non avvia il monitoraggio, non produce copie, non prende in carico
//! un'interruzione, non cambia modalità. Una prova lo verifica sul codice.
//!
//! # Il controllo dell'Hub
//!
//! Apre il canale cifrato, verifica la chiave dell'Hub e chiude, **senza
//! presentarsi**: nessuna sessione e nessuna presenza. Con i tetti delle
//! schermate, che sono i più stretti: se l'Hub non risponde, la finestra
//! aspetta al più quei secondi.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use lisi_services::diagnostics::StationFacts;
use lisi_services::hub_client::HubClientService;
use lisi_services::preflight::{
    HubReachability, Preflight, PreflightFacts, PreflightPlace, PreflightService, assess,
};
use lisi_services::source_health::HealthSummary;
use slint::{ComponentHandle, SharedString};

use crate::AppWindow;
use crate::diagnostics::SharedDiagnostics;
use crate::sources::SharedHealth;

/// Lo stato della striscia.
pub struct PreflightScreen {
    service: PreflightService,
    /// Il collegamento all'Hub, quando la postazione ne ha la configurazione.
    hub: Option<HubClientService>,
    diagnostics: SharedDiagnostics,
    health: Option<SharedHealth>,
}

/// La striscia, condivisa fra l'avvio e il comando «Ricontrolla».
pub type SharedPreflight = Rc<RefCell<PreflightScreen>>;

/// La pagina dove si compie il gesto, oppure nessuna quando il gesto sta fuori
/// dal prodotto.
#[must_use]
pub const fn page_of(place: PreflightPlace) -> Option<i32> {
    match place {
        PreflightPlace::Accounts => Some(2),
        PreflightPlace::Sources => Some(3),
        PreflightPlace::Monitoring => Some(9),
        PreflightPlace::Settings => Some(11),
        PreflightPlace::TeamLive => Some(27),
        PreflightPlace::OutsideTheProduct => None,
    }
}

/// Il nome del pulsante che porta alla pagina.
#[must_use]
pub const fn go_label(place: PreflightPlace) -> &'static str {
    match place {
        PreflightPlace::Accounts => "Apri Account",
        PreflightPlace::Sources => "Apri Fonti",
        PreflightPlace::Monitoring => "Apri Monitoraggio",
        PreflightPlace::Settings => "Apri Impostazioni",
        PreflightPlace::TeamLive => "Apri Live condiviso",
        PreflightPlace::OutsideTheProduct => "",
    }
}

/// Costruisce la striscia, se l'archivio del controllo si apre.
///
/// Il collegamento all'Hub si costruisce soltanto se la postazione ha dove
/// cercarne la configurazione; se non ce l'ha, il controllo dell'Hub dice «non
/// in Team», che è vero.
#[must_use]
pub fn create(
    database: Option<lisi_services::Database>,
    hub_database: Option<lisi_services::Database>,
    diagnostics: Option<&SharedDiagnostics>,
    health: Option<&SharedHealth>,
) -> Option<SharedPreflight> {
    let service = PreflightService::new(database?);
    let hub = hub_database.and_then(|archivio| {
        let identita =
            lisi_services::device_identity::DeviceIdentityService::default_location().ok()?;
        let configurazione =
            lisi_services::hub_client::HubConnectionStore::default_location().ok()?;
        Some(
            HubClientService::new(
                lisi_services::hub_catchup::HubCatchUpService::new(archivio),
                identita,
                configurazione,
            )
            .with_default_office_networks()
            .with_screen_limits(),
        )
    });
    Some(Rc::new(RefCell::new(PreflightScreen {
        service,
        hub,
        diagnostics: Rc::clone(diagnostics?),
        health: health.map(Rc::clone),
    })))
}

thread_local! {
    /// Se un prerequisito è cambiato dall'ultimo controllo
    /// (OPERATOR-E2E-REMEDIATION-01, F-08).
    ///
    /// Il controllo girava all'avvio e a «Ricontrolla», e basta: dopo l'accesso
    /// la fascia diceva ancora «Nessun account», dopo quattro fonti «Nessuna
    /// fonte», dopo la copia «Nessuna copia». Ora chi cambia un prerequisito lo
    /// segna qui, e il ciclo periodico ricontrolla **una volta** — non a ogni
    /// giro: il controllo scrive una riga d'audit, e un controllo continuo
    /// riempirebbe l'audit di righe uguali.
    static STALE: Cell<bool> = const { Cell::new(false) };
}

/// Segna che un prerequisito del controllo è cambiato.
pub fn mark_stale() {
    STALE.with(|stale| stale.set(true));
}

/// Ricontrolla se qualcosa è cambiato dall'ultima volta, e solo allora.
pub fn run_if_stale(window: &AppWindow, preflight: &SharedPreflight) {
    if STALE.with(|stale| stale.replace(false)) {
        run(window, preflight);
    }
}

/// Esegue il controllo e ne mostra la riga.
pub fn run(window: &AppWindow, preflight: &SharedPreflight) {
    let schermata = preflight.borrow();
    let now = crate::account::now();

    let sources = schermata
        .health
        .as_ref()
        .map_or_else(HealthSummary::default, |health| {
            health
                .borrow()
                .service()
                .summary()
                .unwrap_or_else(|errore| {
                    tracing::warn!(
                        kind = errore.kind(),
                        "riepilogo delle fonti non leggibile: il controllo lo dirà vuoto"
                    );
                    HealthSummary::default()
                })
        });
    let mode = lisi_services::station::persisted_mode_or_restricted();

    let station = StationFacts {
        mode,
        telegram_runtime_started: crate::account::telegram_live_connected(window),
        sources,
    };
    let Ok(rapporto) = schermata.diagnostics.borrow().compose(&station, now) else {
        mostra_non_eseguito(window);
        return;
    };

    let (Ok(open_interruptions), Ok(latest_recorded)) = (
        schermata.service.open_interruptions(),
        schermata.service.latest_recorded(),
    ) else {
        mostra_non_eseguito(window);
        return;
    };

    let hub = schermata
        .hub
        .as_ref()
        .map_or(HubReachability::NotConfigured, HubClientService::probe);

    let facts = PreflightFacts {
        mode,
        sources,
        open_interruptions,
        hub,
        latest_recorded,
        exercise: lisi_services::run_mode::is_exercise(),
        // Letto dal registro di Windows, senza rete (CLOCK-01, ADR-0168).
        time_sync: lisi_platform::time_sync::time_sync_state(),
    };
    let esito = assess(&rapporto, &facts, now);

    // L'UNICA SCRITTURA del controllo: la sua riga d'audit, con l'esito e il
    // titolo del controllo. Se non si scrive, la riga si mostra lo stesso: il
    // controllo informa, e l'informazione non dipende dall'audit.
    if let Ok(attore) = crate::operator::audit_actor()
        && let Err(errore) = schermata.service.record(&esito, &attore, now)
    {
        tracing::warn!(
            kind = errore.kind(),
            "controllo di avvio non registrato nell'audit"
        );
    }

    mostra(window, &esito);
}

/// Le frasi tradotte una per una e unite da uno spazio (CU01-010).
fn per_lo_schermo(frasi: &[String]) -> SharedString {
    SharedString::from(
        frasi
            .iter()
            .filter(|frase| !frase.is_empty())
            .map(|frase| crate::lingua::schermo(frase).to_string())
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// Mostra la riga.
fn mostra(window: &AppWindow, esito: &Preflight) {
    window.set_preflight_ready(esito.is_ready());
    // Una frase per volta al confine con lo schermo: la riga intera non è nel
    // catalogo, e nell'interfaccia inglese restava italiana (CU01-010).
    window.set_preflight_line(per_lo_schermo(&esito.line_sentences()));
    window.set_preflight_what_to_do(crate::lingua::schermo(
        esito.what_to_do().unwrap_or_default(),
    ));

    let luogo = match &esito.outcome {
        lisi_services::preflight::PreflightOutcome::NotYet { fix, .. } => Some(fix.place),
        lisi_services::preflight::PreflightOutcome::Ready { .. } => None,
    };
    window.set_preflight_go_page(luogo.and_then(page_of).unwrap_or(-1));
    window.set_preflight_go_label(crate::lingua::schermo(luogo.map_or("", go_label)));
    let controllo = match &esito.outcome {
        lisi_services::preflight::PreflightOutcome::NotYet { check, .. } => Some(*check),
        lisi_services::preflight::PreflightOutcome::Ready { .. } => None,
    };
    window.set_preflight_go_section(controllo.map_or(0, settings_section_of));
    window.set_preflight_shown(true);
}

/// La sezione delle Impostazioni che la frase nomina, quando la nomina.
///
/// «Apri Impostazioni» apriva la pagina in cima, e la sezione indicata stava
/// una dozzina di sezioni più in basso (FULL-OPERATIONAL-VALIDATION-01). I
/// numeri sono quelli di `settings-jump-section` nell'interfaccia: 1 lo stato
/// dell'archivio, 2 la copia di sicurezza, 0 nessuna sezione.
#[must_use]
pub const fn settings_section_of(check: lisi_services::preflight::PreflightCheck) -> i32 {
    match check {
        lisi_services::preflight::PreflightCheck::Archive => 1,
        lisi_services::preflight::PreflightCheck::Backup => 2,
        _ => 0,
    }
}

/// Dice che il controllo non si è potuto eseguire: **non** «pronto».
fn mostra_non_eseguito(window: &AppWindow) {
    window.set_preflight_ready(false);
    window.set_preflight_line(crate::lingua::schermo(
        "Il controllo di avvio non si è potuto eseguire: non si sa se si possa cominciare. La \
         Diagnostica dice che cosa non risponde.",
    ));
    window.set_preflight_what_to_do(SharedString::default());
    window.set_preflight_go_page(-1);
    window.set_preflight_go_label(SharedString::default());
    window.set_preflight_go_section(0);
    window.set_preflight_shown(true);
}

/// Collega «Ricontrolla».
pub fn wire(window: &AppWindow, preflight: &SharedPreflight) {
    let handle = window.as_weak();
    let preflight = Rc::clone(preflight);
    window.on_preflight_rerun(move || {
        if crate::lock::refuse_while_locked("preflight_rerun") {
            return;
        }
        if let Some(window) = handle.upgrade() {
            run(&window, &preflight);
        }
    });
}

#[cfg(test)]
mod tests {
    use lisi_services::preflight::PreflightPlace;

    use super::{go_label, page_of};

    /// **Nell'interfaccia inglese la riga «Pronto per lavorare…» è tutta
    /// tradotta**: ogni sua frase ha la voce nel catalogo, in ogni stato
    /// dell'ora di Windows e anche in Esercitazione (COLLAUDO-FIX-01, CU01-010).
    ///
    /// Vista rossa con la riga intera, com'era nella 0.2.2: la frase composta
    /// non è nel catalogo, e restava italiana.
    #[test]
    fn la_riga_di_prontezza_si_traduce_frase_per_frase() {
        use lisi_core::model::language::InterfaceLanguage;
        use lisi_core::role::OperatingMode;
        use lisi_platform::time_sync::TimeSyncState;
        use lisi_services::preflight::{Preflight, PreflightOutcome};

        let ore = [
            TimeSyncState::FromServer,
            TimeSyncState::FromDomain,
            TimeSyncState::FromBoth,
            TimeSyncState::NotSynchronized,
            TimeSyncState::ServiceDisabled,
            TimeSyncState::Undeterminable,
        ];
        let mut lette = 0;
        for time_sync in ore {
            for exercise in [false, true] {
                let esito = Preflight {
                    outcome: PreflightOutcome::Ready {
                        not_verified: Vec::new(),
                    },
                    mode: OperatingMode::Administrator,
                    exercise,
                    time_sync,
                };
                assert_eq!(esito.line_sentences().join(" "), esito.line());
                for frase in esito.line_sentences() {
                    lette += 1;
                    assert_ne!(
                        crate::lingua::tr_in(InterfaceLanguage::English, &frase),
                        frase,
                        "senza traduzione inglese: «{frase}»"
                    );
                }
            }
        }
        assert!(lette >= 30, "frasi lette: {lette}");
    }

    const UI: &str = include_str!("../ui/app-window.slint");
    const THIS_MODULE: &str = include_str!("preflight.rs");

    const LUOGHI: [PreflightPlace; 6] = [
        PreflightPlace::Accounts,
        PreflightPlace::Sources,
        PreflightPlace::Monitoring,
        PreflightPlace::Settings,
        PreflightPlace::TeamLive,
        PreflightPlace::OutsideTheProduct,
    ];

    /// **Ogni pagina è quella della voce di menu con lo stesso nome.**
    ///
    /// Un numero di pagina scritto a mano diverge il giorno in cui qualcuno
    /// inserisce una pagina: il pulsante porterebbe altrove, in silenzio.
    #[test]
    fn ogni_pulsante_porta_alla_pagina_del_suo_nome() {
        let righe: Vec<&str> = UI.lines().collect();
        for luogo in LUOGHI {
            let Some(pagina) = page_of(luogo) else {
                assert_eq!(
                    go_label(luogo),
                    "",
                    "fuori dal prodotto non c'è un pulsante"
                );
                continue;
            };
            let nome = go_label(luogo).trim_start_matches("Apri ");
            // La voce si scrive anche tradotta, con `@tr` (I18N-01).
            let voce = format!("label: \"{nome}\";");
            let tradotta = format!("label: @tr(\"{nome}\");");
            let comando = format!("root.open-page({pagina});");
            let trovata = righe.iter().enumerate().any(|(indice, riga)| {
                riga.contains(&comando)
                    && righe[indice.saturating_sub(6)..indice]
                        .iter()
                        .any(|prima| prima.contains(&voce) || prima.contains(&tradotta))
            });
            assert!(
                trovata,
                "«{nome}» non è la voce di menu della pagina {pagina}"
            );
        }
    }

    /// **Il pulsante della striscia cambia pagina, e basta** (PR-04, controllo
    /// negativo 2 per la schermata).
    ///
    /// Un pulsante che eseguisse il comando della pagina — aggiungere un
    /// account, riprendere un monitoraggio — salterebbe i controlli che la
    /// pagina ha, compresa l'autorizzazione dell'amministratore.
    /// **«Apri Impostazioni» porta alla sezione che la frase nomina**
    /// (FULL-OPERATIONAL-VALIDATION-01): apriva la pagina in cima.
    #[test]
    fn apri_impostazioni_porta_alla_sezione_nominata() {
        use lisi_services::preflight::PreflightCheck;
        assert_eq!(super::settings_section_of(PreflightCheck::Archive), 1);
        assert_eq!(super::settings_section_of(PreflightCheck::Backup), 2);
        assert_eq!(super::settings_section_of(PreflightCheck::Sources), 0);
        for (numero, sezione) in [(1, "sez-archivio"), (2, "sez-copia")] {
            assert!(
                UI.contains(&format!("if (root.settings-jump-section == {numero}) {{"))
                    || UI.contains(&format!(
                        "else if (root.settings-jump-section == {numero}) {{"
                    )),
                "la sezione {numero} deve avere il suo ramo"
            );
            assert!(
                UI.contains(&format!(
                    "root.settings-scroll-target({sezione}.absolute-position.y"
                )),
                "«{sezione}» deve essere raggiungibile"
            );
        }
    }

    #[test]
    fn la_striscia_cambia_soltanto_pagina() {
        let Some(inizio) = UI.find("if root.preflight-shown: Rectangle {") else {
            panic!("la striscia deve esistere");
        };
        let Some(fine) = UI[inizio..].find("accessible-label: root.preflight-line;") else {
            panic!("la striscia deve chiudersi");
        };
        let striscia = &UI[inizio..inizio + fine];
        let comandi: Vec<&str> = striscia
            .lines()
            .map(str::trim)
            .filter(|riga| riga.starts_with("root.") && riga.ends_with(';'))
            .collect();
        assert_eq!(
            comandi,
            // La sezione da raggiungere non è un comando: dice soltanto fin dove
            // scorrere la pagina che si apre.
            vec![
                "root.settings-jump-section = root.preflight-go-section;",
                "root.open-page(root.preflight-go-page);",
                "root.preflight-rerun();"
            ],
            "la striscia può soltanto cambiare pagina e ricontrollare"
        );

        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        assert!(
            !produzione.contains("invoke_"),
            "il controllo di avvio non esegue comandi di altre schermate"
        );
    }
}

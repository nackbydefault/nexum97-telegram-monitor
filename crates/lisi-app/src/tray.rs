//! Collegamento fra l'area di notifica e il resto dell'applicazione.
//!
//! # Questo modulo non decide nulla
//!
//! Le decisioni stanno in `lisi_services::tray`, dove si provano senza una
//! finestra; il disegno sta in `lisi_platform::tray`, che non sa che cosa sia un
//! monitoraggio. Qui in mezzo c'è soltanto il collegamento: leggere lo stato,
//! chiedere che cosa mostrare, e instradare il comando scelto.
//!
//! # Perché l'aggiornamento passa dal ciclo che c'è già
//!
//! Perché un secondo timer avrebbe una propria cadenza da tenere allineata a
//! questa, ed è la stessa ragione per cui il blocco automatico non ne ha uno.
//!
//! # Perché si aggiorna solo quando cambia
//!
//! Perché `Shell_NotifyIconW` con `NIM_MODIFY` cinque volte al secondo è
//! traffico verso Windows per un suggerimento che non è cambiato — e, su una
//! postazione lenta, un lampeggio dell'icona.
//!
//! La decisione completa sta in
//! `docs/adr/ADR-0063-IL-VASSOIO-NON-E-UNA-FINESTRA-SUL-BLOCCO.md`.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_platform::tray::{MenuEntry, TrayEvent, TrayIcon, bring_window_to_front};
use lisi_services::tray::{
    LockAvailability, MonitoringVisibility, StationFact, TrayCommand, TrayView, compose,
};

use crate::AppWindow;
use crate::lock::SharedLock;

/// Stato del vassoio, condiviso fra i gestori.
pub struct TrayState {
    /// L'icona, che si toglie quando questo stato cade.
    icon: TrayIcon,
    /// Connessione propria, per sapere QUANTI monitoraggi siano in corso.
    ///
    /// Ogni servizio apre la sua: e' l'idioma gia' usato dal resto
    /// dell'applicazione, e tiene fuori dal ciclo periodico una lettura che
    /// riguarda solo il vassoio.
    archive: Option<lisi_services::Database>,
    /// L'handle della finestra, per portarla davanti.
    window_handle: isize,
    /// L'ultima vista consegnata a Windows.
    ///
    /// Serve a non riconsegnare la stessa: vedere la nota del modulo.
    last: Option<TrayView>,
}

/// Stato condiviso.
pub type SharedTray = Rc<RefCell<TrayState>>;

/// Installa l'icona, se la piattaforma la offre.
///
/// Restituisce `None` quando il vassoio non è disponibile: **non è un guasto**,
/// e l'applicazione prosegue senza. Un'icona in meno non impedisce nulla; ogni
/// funzione che il vassoio raggiunge si raggiunge anche dalla finestra.
#[must_use]
pub fn create_state(
    window_handle: isize,
    archive: Option<lisi_services::Database>,
) -> Option<SharedTray> {
    let vista = compose(
        lisi_core::PRODUCT_NAME,
        &StationFact {
            monitoring: monitoring_visibility("", 0),
            pending_alerts: 0,
            locked: false,
        },
        LockAvailability::NoActiveAccount,
    );

    let icon = TrayIcon::install(&vista.tooltip, &entries(&vista))
        .map_err(|error| {
            tracing::info!(
                errore = %error,
                "area di notifica non disponibile in questa esecuzione"
            );
        })
        .ok()?;

    tracing::info!("icona dell'area di notifica installata");

    Some(Rc::new(RefCell::new(TrayState {
        icon,
        archive,
        window_handle,
        last: Some(vista),
    })))
}

/// Traduce le voci decise nelle voci che Windows disegna.
///
/// **Il comando non attraversa il confine**: di là serve solo sapere se una voce
/// si preme, e torna indietro un indice.
fn entries(view: &TrayView) -> Vec<MenuEntry> {
    view.items
        .iter()
        .map(|voce| MenuEntry {
            label: voce.label.clone(),
            enabled: voce.is_enabled(),
        })
        .collect()
}

/// Che cosa il vassoio può dire del monitoraggio.
///
/// **«Non disponibile» non è «fermo»**: un binario compilato senza TDLib non può
/// monitorare, e dire «fermo» sarebbe una bugia piccola e permanente (DEC-203).
///
/// Negli altri casi si porta **ciò che la schermata mostra**, senza
/// ricalcolarlo: la stessa regola della schermata di blocco.
///
/// E con **più di un monitoraggio in corso** si dice **quanti**, mai quali: un
/// elenco di etichette è più vicino al contenuto che al fatto, e il vassoio è
/// visibile a postazione bloccata (ADR-0065).
fn monitoring_visibility(shown: &str, running: u32) -> MonitoringVisibility {
    if !lisi_services::TELEGRAM_RUNTIME_AVAILABLE {
        return MonitoringVisibility::Unavailable;
    }
    if running > 1 {
        return MonitoringVisibility::Several(running);
    }
    MonitoringVisibility::AsShown(String::from(shown))
}

/// **Quanti** monitoraggi risultano in corso.
///
/// Zero quando l'archivio non è disponibile o la lettura non riesce: il vassoio
/// ricade su ciò che la schermata mostra, che con un monitoraggio solo è esatto.
fn running_count(tray: &SharedTray) -> u32 {
    let state = tray.borrow();
    let Some(archive) = state.archive.as_ref() else {
        return 0;
    };
    match archive.running_session_count() {
        Ok(quanti) => u32::try_from(quanti).unwrap_or(0),
        Err(error) => {
            tracing::debug!(
                errore = %error,
                "numero dei monitoraggi in corso non leggibile per il vassoio"
            );
            0
        }
    }
}

/// Che cosa si può fare con il blocco, adesso.
fn lock_availability(lock: Option<&SharedLock>) -> LockAvailability {
    let Some(lock) = lock else {
        return LockAvailability::NoActiveAccount;
    };
    let lock = lock.borrow();
    if lock.is_locked() {
        return LockAvailability::AlreadyLocked;
    }
    if !lock.has_account() {
        return LockAvailability::NoActiveAccount;
    }
    if !lock.has_unlock_word() {
        return LockAvailability::NoUnlockWord;
    }
    LockAvailability::Available
}

/// Aggiorna l'icona e consegna i comandi scelti.
///
/// Chiamata dal ciclo periodico che già esiste.
pub fn refresh(window: &AppWindow, tray: &SharedTray, lock: Option<&SharedLock>) {
    let running = running_count(tray);
    let vista = compose(
        lisi_core::PRODUCT_NAME,
        &StationFact {
            monitoring: monitoring_visibility(&window.get_monitoring_state(), running),
            pending_alerts: u32::try_from(window.get_alert_pending()).unwrap_or(0),
            locked: lock.is_some_and(|lock| lock.borrow().is_locked()),
        },
        lock_availability(lock),
    );

    // SI AGGIORNA SOLO QUANDO CAMBIA.
    let cambiata = {
        let state = tray.borrow();
        state.last.as_ref() != Some(&vista)
    };
    if cambiata {
        let esito = {
            let state = tray.borrow();
            state.icon.update(&vista.tooltip, &entries(&vista))
        };
        match esito {
            Ok(()) => tray.borrow_mut().last = Some(vista.clone()),
            // Un aggiornamento non riuscito non e' fatale: l'icona resta con il
            // suggerimento precedente. NON si registra `last`, cosi' il giro
            // successivo riprova.
            Err(error) => tracing::debug!(
                errore = %error,
                "suggerimento dell'area di notifica non aggiornato"
            ),
        }
    }

    let eventi = tray.borrow().icon.take_events();
    for evento in eventi {
        let comando = match evento {
            // Il clic sinistro fa la cosa più innocua che il menu offra:
            // aprire la finestra. NON blocca, perché un clic per sbaglio non
            // deve chiudere fuori nessuno.
            TrayEvent::Activated => Some(TrayCommand::OpenWindow),
            TrayEvent::Chosen(indice) => vista.items.get(indice).and_then(|voce| voce.command),
        };
        if let Some(comando) = comando {
            perform(window, tray, lock, comando);
        }
    }
}

/// Esegue un comando del vassoio.
///
/// **I comandi sono due**, e l'enumerazione è chiusa: nessuna azione riservata è
/// raggiungibile da qui, e nessuno sblocco.
fn perform(window: &AppWindow, tray: &SharedTray, lock: Option<&SharedLock>, command: TrayCommand) {
    tracing::info!(comando = command.as_str(), "comando dall'area di notifica");

    match command {
        TrayCommand::OpenWindow => {
            let handle = tray.borrow().window_handle;
            if let Err(error) = bring_window_to_front(handle) {
                tracing::info!(
                    errore = %error,
                    "finestra non portata davanti dall'area di notifica"
                );
            }
        }
        TrayCommand::LockStation => {
            // Si passa dalla STESSA funzione che blocca dalla schermata: una
            // seconda strada per bloccare sarebbe una seconda strada da
            // sorvegliare, e la voce del menu e' gia' spenta quando non si puo'.
            if let Some(lock) = lock {
                crate::lock::engage(window, lock);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Il codice di produzione del modulo, senza commenti e senza le prove.
    fn codice_di_produzione() -> String {
        let sorgente = include_str!("tray.rs");
        let produzione = sorgente
            .split_once("\n#[cfg(test)]")
            .map_or(sorgente, |(prima, _)| prima);
        produzione
            .lines()
            .filter(|riga| {
                let trimmed = riga.trim_start();
                !trimmed.starts_with("//") && !trimmed.starts_with("///")
            })
            .collect::<Vec<&str>>()
            .join("\n")
    }

    /// **Il collegamento non sblocca, e non compone frasi proprie.**
    ///
    /// È la guardia che tiene questo modulo un collegamento: se un giorno
    /// qualcuno gli facesse comporre una frase o togliere un blocco, sarebbe la
    /// seconda porta — e la seconda frase.
    ///
    /// # Perché vieta le CHIAMATE e non le parole
    ///
    /// Perché la prima stesura vietava `unlock` ed è diventata rossa su
    /// `has_unlock_word`, che è una **lettura** — «esiste una parola di
    /// sblocco?» — e non uno sblocco. Vietare una parola dentro il nome di una
    /// lettura avrebbe costretto a chiamare peggio la lettura.
    #[test]
    fn il_collegamento_non_sblocca_e_non_compone_frasi_proprie() {
        let codice = codice_di_produzione();
        for vietato in [
            ".unlock(",
            "::unlock(",
            ".release(",
            "return_to_administrator",
            "enter_operator_mode",
            "RestrictedAction",
            "Monitoraggio:",
            "avvisi da esaminare",
        ] {
            assert!(
                !codice.contains(vietato),
                "il collegamento del vassoio non deve nominare «{vietato}»"
            );
        }
    }

    /// **Senza blocco disponibile, il vassoio non promette di bloccare.**
    #[test]
    fn senza_blocco_non_si_promette_di_bloccare() {
        assert_eq!(lock_availability(None), LockAvailability::NoActiveAccount);
    }

    /// **Un binario senza TDLib non dice «fermo».**
    #[test]
    fn un_binario_senza_tdlib_non_dice_fermo() {
        let visibilita = monitoring_visibility("", 0);
        if lisi_services::TELEGRAM_RUNTIME_AVAILABLE {
            assert_eq!(visibilita, MonitoringVisibility::AsShown(String::new()));
        } else {
            assert_eq!(visibilita, MonitoringVisibility::Unavailable);
        }
    }

    /// Le voci che attraversano il confine portano il testo e se si premono,
    /// **e nient'altro**.
    #[test]
    fn al_confine_passano_solo_testo_e_premibilita() {
        let vista = compose(
            "NEXUM/97",
            &StationFact {
                monitoring: MonitoringVisibility::AsShown(String::new()),
                pending_alerts: 0,
                locked: false,
            },
            LockAvailability::NoUnlockWord,
        );
        let voci = entries(&vista);
        assert_eq!(voci.len(), vista.items.len());
        assert!(!voci[0].enabled, "la riga di stato non si preme");
        assert!(voci[1].enabled, "«Apri» si preme sempre");
        assert!(
            !voci[2].enabled,
            "senza parola di sblocco, «Blocca» non si preme"
        );
    }
}

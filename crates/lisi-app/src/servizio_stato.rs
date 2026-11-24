//! Il monitoraggio con Windows chiuso, in Impostazioni (SERVICE-01 parte 2,
//! ADR-0203 decisione 9).
//!
//! Lo stato lo dice Windows, e si rilegge a ogni apertura della schermata,
//! come l'avvio automatico: nessuna seconda copia in archivio. I passaggi di
//! mano vengono dall'archivio, dove nessuno li cambia.
//!
//! I due pulsanti avviano questo stesso programma con il comando
//! dell'installazione (`servizio_installazione`): i permessi
//! dell'amministratore e la password li chiede Windows, con le sue finestre.
//! La schermata non li vede mai.

use std::cell::RefCell;

use lisi_core::model::background::{Keeper, SERVICE_NAME};
use lisi_platform::background_service::{ServiceState, state};
use lisi_services::Database;
use lisi_services::background::StoredHandover;
use slint::{ComponentHandle, SharedString};

use crate::AppWindow;
use crate::servizio_installazione::{RIFIUTATO, RIUSCITO};

thread_local! {
    /// L'archivio della sezione, aperto all'avvio.
    static ARCHIVIO: RefCell<Option<Database>> = const { RefCell::new(None) };
}

/// Mette a disposizione l'archivio.
pub fn install(database: Option<Database>) {
    ARCHIVIO.with(|cella| *cella.borrow_mut() = database);
}

/// Lo stato del servizio, in una frase.
fn frase_dello_stato(stato: Option<ServiceState>) -> &'static str {
    match stato {
        Some(ServiceState::NotInstalled) => {
            "Non attivo: quando si esce da Windows il monitoraggio si interrompe."
        }
        Some(ServiceState::Running) => {
            "Attivo: quando si esce da Windows il monitoraggio continua con gli account collegati."
        }
        Some(ServiceState::Stopped) => {
            "Installato ma fermo. Se la password di Windows è cambiata, va scritta di nuovo con il pulsante qui sotto."
        }
        Some(ServiceState::Changing) => "Sta partendo o si sta fermando.",
        None => "Windows non ha detto lo stato del servizio.",
    }
}

/// Chi tiene l'acquisizione, in parole.
fn custode(keeper: Keeper) -> &'static str {
    match keeper {
        Keeper::Window => "il programma",
        Keeper::Service => "il servizio di Windows",
    }
}

/// Un passaggio di mano, in una frase.
fn passaggio(voce: &StoredHandover) -> String {
    let secondi = (voce.taken_at.as_millis() - voce.released_at.as_millis()) / 1000;
    format!(
        "{}: ha lasciato {}, ha preso {}, dopo {} secondi, con {} account.",
        voce.taken_at.to_readable_local(),
        crate::lingua::tr(custode(voce.released_by)),
        crate::lingua::tr(custode(voce.taken_by)),
        secondi,
        voce.accounts.len()
    )
}

/// Riporta in schermata lo stato e gli ultimi passaggi.
pub fn refresh(window: &AppWindow) {
    window.set_background_service_state(crate::lingua::schermo(frase_dello_stato(
        state(SERVICE_NAME).ok(),
    )));
    let passaggi = ARCHIVIO
        .with(|cella| {
            cella
                .borrow()
                .as_ref()
                .map(lisi_services::background::recent)
        })
        .and_then(Result::ok)
        .unwrap_or_default();
    let righe: Vec<String> = passaggi
        .iter()
        .map(|voce| crate::lingua::schermo(passaggio(voce)).to_string())
        .collect();
    window.set_background_service_handovers(SharedString::from(if righe.is_empty() {
        crate::lingua::tr("Nessun passaggio di mano registrato.").to_owned()
    } else {
        righe.join("\n")
    }));
}

/// L'esito del comando, in una frase.
fn frase_dell_esito(codice: Option<i32>) -> &'static str {
    match codice {
        Some(RIUSCITO) => "Fatto. Lo stato qui sopra è quello che dice Windows.",
        Some(RIFIUTATO) => "Nulla è cambiato: una finestra di Windows è stata chiusa.",
        _ => "Non è riuscito: i permessi o la password non sono stati accettati da Windows.",
    }
}

/// Avvia questo programma con `argomento` e, quando finisce, aggiorna la
/// schermata. Non aspetta: le finestre di Windows restano davanti.
fn avvia(window: &AppWindow, argomento: &'static str) {
    let Ok(programma) = std::env::current_exe() else {
        window.set_background_service_message(crate::lingua::schermo(frase_dell_esito(None)));
        return;
    };
    window.set_background_service_message(crate::lingua::schermo(
        "Windows chiede i permessi in una sua finestra.",
    ));
    let handle = window.as_weak();
    std::thread::spawn(move || {
        let codice = std::process::Command::new(programma)
            .arg(argomento)
            .status()
            .ok()
            .and_then(|esito| esito.code());
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(window) = handle.upgrade() {
                refresh(&window);
                window.set_background_service_message(crate::lingua::schermo(frase_dell_esito(
                    codice,
                )));
            }
        });
    });
}

/// Collega i due pulsanti.
pub fn wire(window: &AppWindow) {
    {
        let handle = window.as_weak();
        window.on_background_service_install(move || {
            if crate::lock::refuse_while_locked("background_service_install") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                avvia(&window, "--installa-servizio");
            }
        });
    }
    {
        let handle = window.as_weak();
        window.on_background_service_remove(move || {
            if crate::lock::refuse_while_locked("background_service_remove") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                avvia(&window, "--rimuovi-servizio");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Ogni stato ha la sua frase**, e quello che manca non si dice
    /// installato.
    #[test]
    fn ogni_stato_ha_la_sua_frase() {
        let frasi = [
            frase_dello_stato(Some(ServiceState::NotInstalled)),
            frase_dello_stato(Some(ServiceState::Running)),
            frase_dello_stato(Some(ServiceState::Stopped)),
            frase_dello_stato(Some(ServiceState::Changing)),
            frase_dello_stato(None),
        ];
        for (i, frase) in frasi.iter().enumerate() {
            assert!(frasi[i + 1..].iter().all(|altra| altra != frase), "{frase}");
        }
        assert!(frasi[0].starts_with("Non attivo"));
        assert!(frasi[4].contains("non ha detto"));
    }

    /// **Un passaggio dice chi, dopo quanto e con quanti account.**
    #[test]
    fn un_passaggio_dice_chi_e_dopo_quanto() {
        let voce = StoredHandover {
            id: 1,
            released_by: Keeper::Window,
            released_at: lisi_core::Timestamp::from_millis(1_000),
            taken_by: Keeper::Service,
            taken_at: lisi_core::Timestamp::from_millis(16_000),
            accounts: vec![3, 4],
        };
        let frase = passaggio(&voce);
        assert!(
            frase.contains(": ha lasciato il programma, ha preso il servizio di Windows, dopo 15 secondi, con 2 account."),
            "{frase}"
        );
    }

    /// **I pulsanti chiedono a Windows, non al programma**: i due comandi
    /// sono quelli che `servizio_installazione` riconosce.
    #[test]
    fn i_pulsanti_usano_i_comandi_dell_installazione() {
        for argomento in ["--installa-servizio", "--rimuovi-servizio"] {
            let argomenti = vec!["programma.exe".to_owned(), argomento.to_owned()];
            assert!(crate::servizio_installazione::comando(&argomenti).is_some());
        }
    }
}

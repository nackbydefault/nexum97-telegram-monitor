//! «Copie pianificate» in Impostazioni › «Copia di sicurezza», e il controllo
//! periodico che le fa partire (BACKUP-SCHEDULE-01, ADR-0191, DEC-477).
//!
//! L'amministratore sceglie la cartella con una finestra di sistema, ogni
//! quanti giorni e quante copie tenere; chiunque legge la pianificazione e
//! l'esito dell'ultimo tentativo. Il controllo periodico chiede al servizio
//! se una copia è dovuta: questo modulo non decide niente di suo.
//!
//! L'archivio sta in un `thread_local`, come quello della firma: le copie
//! pianificate scrivono il loro registro e l'audit.

use std::cell::RefCell;
use std::path::PathBuf;

use lisi_core::OperatingMode;
use lisi_services::backup_schedule::{BackupSchedule, BackupScheduleService};
use lisi_services::{Database, station};
use slint::{ComponentHandle, SharedString};

use crate::AppWindow;

/// Ogni quanto il controllo periodico chiede se una copia è dovuta.
pub const CHECK_EVERY: std::time::Duration = std::time::Duration::from_secs(10 * 60);

thread_local! {
    /// Il servizio delle copie pianificate, aperto all'avvio.
    static SERVIZIO: RefCell<Option<BackupScheduleService>> = const { RefCell::new(None) };
}

/// Mette a disposizione l'archivio delle copie pianificate.
pub fn install(database: Option<Database>) {
    SERVIZIO.with(|servizio| *servizio.borrow_mut() = database.map(BackupScheduleService::new));
}

fn con_il_servizio<R>(lavoro: impl FnOnce(&mut BackupScheduleService) -> R) -> Option<R> {
    SERVIZIO.with(|servizio| servizio.borrow_mut().as_mut().map(lavoro))
}

/// Un numero scritto in un campo, entro i limiti.
fn numero(testo: &str) -> Option<u32> {
    testo.trim().parse::<u32>().ok()
}

/// Riporta in schermata la pianificazione e l'ultimo tentativo.
pub fn refresh(window: &AppWindow) {
    window.set_backup_schedule_administrator(
        station::persisted_mode_or_restricted() == OperatingMode::Administrator,
    );
    let stato = con_il_servizio(|servizio| (servizio.schedule(), servizio.attempts(1)));
    let Some((scelta, tentativi)) = stato else {
        window.set_backup_schedule_active(false);
        window.set_backup_schedule_state(crate::lingua::schermo(
            "L'archivio non è aperto: nessuna copia pianificata parte.",
        ));
        return;
    };
    let mut frase = match scelta {
        Ok(Some(scelta)) => {
            window.set_backup_schedule_active(true);
            window.set_backup_schedule_days(SharedString::from(scelta.interval_days.to_string()));
            window.set_backup_schedule_keep(SharedString::from(scelta.keep.to_string()));
            format!(
                "{} Parte mentre il programma è aperto; un intervallo scaduto a programma \
                 chiuso si recupera dopo l'avvio.",
                scelta.as_sentence()
            )
        }
        Ok(None) => {
            window.set_backup_schedule_active(false);
            String::from("Nessuna copia pianificata: le copie si fanno soltanto a mano.")
        }
        Err(errore) => {
            window.set_backup_schedule_active(false);
            errore.operator_message()
        }
    };
    if let Ok(tentativi) = tentativi
        && let Some(ultimo) = tentativi.first()
    {
        frase.push_str(&format!(
            " Ultimo tentativo: {}, {}.",
            ultimo.attempt.attempted_at.to_readable_local(),
            if ultimo.attempt.outcome == "riuscita" {
                String::from("riuscito")
            } else {
                format!(
                    "NON riuscito ({})",
                    ultimo.attempt.detail.clone().unwrap_or_default()
                )
            }
        ));
    }
    window.set_backup_schedule_state(crate::lingua::schermo(frase));
}

/// Sceglie o spegne la pianificazione.
fn scegli(scelta: Option<BackupSchedule>) -> String {
    let attore = match crate::operator::audit_actor() {
        Ok(attore) => attore,
        Err(_) => return String::from(crate::account::NON_SI_SA_CHI_OPERA),
    };
    let modalita = station::persisted_mode_or_restricted();
    con_il_servizio(|servizio| {
        match servizio.choose(scelta.as_ref(), modalita, &attore, crate::account::now()) {
            Ok(()) if scelta.is_some() => String::from(
                "Copie pianificate. La prima parte al prossimo controllo, entro pochi minuti.",
            ),
            Ok(()) => String::from("Copie pianificate spente: le copie si fanno a mano."),
            Err(errore) => errore.operator_message(),
        }
    })
    .unwrap_or_else(|| String::from("L'archivio non è aperto: niente è cambiato."))
}

/// Il controllo periodico: fa la copia se è dovuta, e la dice.
pub fn tick(window: &AppWindow) {
    let Ok(attore) = crate::operator::audit_actor() else {
        return;
    };
    let esito = con_il_servizio(|servizio| servizio.run_if_due(&attore, crate::account::now()));
    match esito {
        Some(Ok(Some(esito))) => {
            window.set_backup_schedule_message(crate::lingua::schermo(esito.operator_message()));
            refresh(window);
            // Un fallimento resta nella fascia di prontezza (ADR-0191).
            crate::preflight::mark_stale();
        }
        Some(Err(errore)) => {
            tracing::warn!(kind = errore.kind(), "copia pianificata non controllabile");
        }
        _ => {}
    }
}

/// Collega i comandi della sezione.
pub fn wire(window: &AppWindow) {
    {
        let handle = window.as_weak();
        window.on_backup_schedule_choose(move || {
            if crate::lock::refuse_while_locked("backup_schedule_choose") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let (Some(giorni), Some(quante)) = (
                numero(window.get_backup_schedule_days().as_str()),
                numero(window.get_backup_schedule_keep().as_str()),
            ) else {
                window.set_backup_schedule_message(crate::lingua::schermo(
                    "Scrivere ogni quanti giorni (da 1 a 30) e quante copie tenere (da 1 a 30).",
                ));
                return;
            };
            crate::dialogs::ask(
                &window,
                rfd::AsyncFileDialog::new()
                    .set_title("Scegliere la cartella delle copie pianificate"),
                crate::dialogs::Pick::Folder,
                "backup_schedule_choose",
                move |window, cartella: PathBuf| {
                    let frase = scegli(Some(BackupSchedule {
                        destination: cartella,
                        interval_days: giorni,
                        keep: quante,
                    }));
                    refresh(window);
                    window.set_backup_schedule_message(crate::lingua::schermo(frase));
                },
            );
        });
    }
    {
        let handle = window.as_weak();
        window.on_backup_schedule_off(move || {
            if crate::lock::refuse_while_locked("backup_schedule_off") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let frase = scegli(None);
            refresh(&window);
            window.set_backup_schedule_message(crate::lingua::schermo(frase));
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{numero, scegli};

    #[test]
    fn i_numeri_si_leggono_e_senza_archivio_niente_cambia() {
        assert_eq!(numero(" 7 "), Some(7));
        assert_eq!(numero("sette"), None);
        assert_eq!(numero("-1"), None);
        let frase = scegli(None);
        assert!(!frase.is_empty());
    }
}

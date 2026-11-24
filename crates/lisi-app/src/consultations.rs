//! «Registro delle consultazioni» in Impostazioni, e i due ingressi che lo
//! scrivono (AUDIT-VIEW-01, ADR-0193, DEC-481).
//!
//! Chiunque legge se il registro è acceso e per quanto si conserva;
//! l'amministratore lo accende, lo regola, lo spegne e ne legge le righe. Le
//! aperture si registrano dalla conversazione di un contenuto e dalla scheda
//! di un soggetto; questo modulo non decide niente di suo.

use std::cell::RefCell;

use lisi_core::OperatingMode;
use lisi_services::consultation_log::{ConsultationLogService, Consulted, as_sentence};
use lisi_services::{Database, station};
use slint::{ComponentHandle, SharedString};

use crate::AppWindow;

thread_local! {
    /// Il servizio del registro, aperto all'avvio.
    static SERVIZIO: RefCell<Option<ConsultationLogService>> = const { RefCell::new(None) };
}

/// Mette a disposizione l'archivio del registro, e toglie le righe più
/// vecchie della conservazione (ADR-0193, decisione 5).
pub fn install(database: Option<Database>) {
    let servizio = database.map(ConsultationLogService::new);
    if let Some(servizio) = servizio.as_ref()
        && let Err(errore) = servizio.prune(crate::account::now())
    {
        tracing::warn!(
            kind = errore.kind(),
            "conservazione del registro non applicata"
        );
    }
    SERVIZIO.with(|cella| *cella.borrow_mut() = servizio);
}

fn con_il_servizio<R>(lavoro: impl FnOnce(&mut ConsultationLogService) -> R) -> Option<R> {
    SERVIZIO.with(|cella| cella.borrow_mut().as_mut().map(lavoro))
}

/// Registra un'apertura: lo decide il servizio, se il registro è acceso.
fn registra(che_cosa: Consulted) {
    let Ok(attore) = crate::operator::audit_actor() else {
        return;
    };
    if let Some(Err(errore)) =
        con_il_servizio(|servizio| servizio.record(che_cosa, &attore, crate::account::now()))
    {
        tracing::warn!(kind = errore.kind(), "consultazione non registrata");
    }
}

/// La conversazione di un contenuto è stata aperta.
pub fn content_opened(content_id: i64) {
    registra(Consulted::Content(content_id));
}

/// La scheda di un soggetto è stata aperta.
pub fn subject_opened(subject_id: i64) {
    registra(Consulted::Subject(subject_id));
}

/// Riporta in schermata lo stato e, all'amministratore, le righe.
pub fn refresh(window: &AppWindow) {
    let modalita = station::persisted_mode_or_restricted();
    window.set_consultations_administrator(modalita == OperatingMode::Administrator);
    let stato = con_il_servizio(|servizio| {
        let frase = servizio
            .status_sentence()
            .unwrap_or_else(|errore| errore.operator_message());
        let acceso = servizio.retention().ok().flatten();
        let righe = if modalita == OperatingMode::Administrator {
            servizio.entries(modalita).map_or_else(
                |errore| errore.operator_message(),
                |righe| {
                    if righe.is_empty() {
                        String::from("Nessuna consultazione registrata.")
                    } else {
                        righe.iter().map(as_sentence).collect::<Vec<_>>().join("\n")
                    }
                },
            )
        } else {
            String::new()
        };
        (frase, acceso, righe)
    });
    let Some((frase, acceso, righe)) = stato else {
        window.set_consultations_state(crate::lingua::schermo(
            "L'archivio non è aperto: il registro delle consultazioni non si legge.",
        ));
        return;
    };
    window.set_consultations_state(crate::lingua::schermo(frase));
    window.set_consultations_active(acceso.is_some());
    if let Some(giorni) = acceso {
        window.set_consultations_days(SharedString::from(giorni.to_string()));
    }
    window.set_consultations_entries(SharedString::from(righe));
}

/// Accende o regola (con i giorni scritti) o spegne il registro.
fn scegli(giorni: Option<u32>) -> String {
    let attore = match crate::operator::audit_actor() {
        Ok(attore) => attore,
        Err(_) => return String::from(crate::account::NON_SI_SA_CHI_OPERA),
    };
    let modalita = station::persisted_mode_or_restricted();
    con_il_servizio(|servizio| {
        servizio
            .choose(giorni, modalita, &attore, crate::account::now())
            .unwrap_or_else(|errore| errore.operator_message())
    })
    .unwrap_or_else(|| String::from("L'archivio non è aperto: niente è cambiato."))
}

/// Collega i comandi della sezione.
pub fn wire(window: &AppWindow) {
    {
        let handle = window.as_weak();
        window.on_consultations_turn_on(move || {
            if crate::lock::refuse_while_locked("consultations_turn_on") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let frase = match window.get_consultations_days().trim().parse::<u32>() {
                Ok(giorni) => scegli(Some(giorni)),
                Err(_) => String::from("Scrivere per quanti giorni si conserva, da 30 a 365."),
            };
            refresh(&window);
            window.set_consultations_message(crate::lingua::schermo(frase));
        });
    }
    {
        let handle = window.as_weak();
        window.on_consultations_turn_off(move || {
            if crate::lock::refuse_while_locked("consultations_turn_off") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let frase = scegli(None);
            refresh(&window);
            window.set_consultations_message(crate::lingua::schermo(frase));
        });
    }
}

#[cfg(test)]
mod tests {
    use super::scegli;

    #[test]
    fn senza_archivio_niente_cambia_e_lo_si_dice() {
        let frase = scegli(Some(90));
        assert!(!frase.is_empty());
        // Senza archivio un'apertura non registra niente, e non si ferma.
        super::content_opened(1);
        super::subject_opened(1);
    }
}

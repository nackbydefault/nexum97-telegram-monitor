//! La veglia della postazione: segue i monitoraggi che ricevono contenuti.
//!
//! Stava in `monitoring.rs`. Si è separata quando la presa in carico di
//! un'interruzione ha dovuto riallinearla (E2E01-22): quel collegamento non
//! deve nominare il Monitoraggio, perché accorgersi di un'interruzione non è
//! ripartire, e una guardia lo sorveglia. La veglia non riprende nulla: dice
//! soltanto a Windows se la postazione può sospendersi.

use std::cell::Cell;

use crate::AppWindow;

/// Riallinea veglia e «in corso» a chi riceve adesso, senza ridisegnare la
/// schermata.
///
/// Serve a chi cambia il numero fuori dalla schermata Monitoraggio: la presa in
/// carico di un'interruzione fa riprendere l'acquisizione (ADR-0146), e la
/// postazione deve tornare sveglia subito, non alla prossima apertura della
/// pagina (E2E01-22).
pub fn follow_receiving(window: &AppWindow, database: &lisi_services::Database) {
    match database.receiving_session_count() {
        Ok(quanti) => {
            window.set_monitoring_active(quanti > 0);
            follow_wakefulness(quanti > 0);
        }
        Err(error) => tracing::warn!(
            errore = %error,
            "numero dei monitoraggi che ricevono non leggibile: veglia invariata"
        ),
    }
    follow_pause(window, database);
}

/// Se **tutti** i monitoraggi che ricevono hanno l'acquisizione in pausa
/// (COLLAUDO-FIX-01, CU01-004, DEC-509).
///
/// Allora la postazione non acquisisce nulla: il marchio non pulsa, il radar
/// si ferma e dice «IN PAUSA». **La veglia non cambia**: la pausa si riprende
/// in ogni momento, e una postazione addormentata nel frattempo non
/// riprenderebbe.
pub fn follow_pause(window: &AppWindow, database: &lisi_services::Database) {
    match (
        database.receiving_session_count(),
        database.paused_receiving_session_count(),
    ) {
        (Ok(ricevono), Ok(in_pausa)) => {
            window.set_acquisition_paused(ricevono > 0 && in_pausa >= ricevono);
        }
        (Err(error), _) | (_, Err(error)) => tracing::warn!(
            errore = %error,
            "monitoraggi in pausa non leggibili: stato della pausa invariato"
        ),
    }
}

/// Allinea lo stato di sospensione della postazione a quello della sessione.
///
/// Non è un comando dell'operatore ed è deliberato: una casella «non far
/// dormire il computer» sarebbe una cosa in più da ricordarsi, e chi se la
/// dimentica scopre il monitoraggio interrotto il giorno dopo. La veglia segue
/// lo stato reale, e si spegne da sé quando la sessione finisce.
///
/// **Vale anche per una sessione con gli avvisi sospesi:** «sospendi avvisi»
/// tacita le notifiche, non l'acquisizione (DEC-098). Lasciar dormire la
/// postazione in quello stato fermerebbe proprio ciò che l'operatore ha scelto
/// di lasciare acceso.
///
/// L'esito non è fatale e si registra una volta sola per transizione: se il
/// sistema rifiuta, la postazione potrà sospendersi e il recupero della
/// cronologia colmerà il vuoto al risveglio.
pub fn follow_wakefulness(acquiring: bool) {
    thread_local! {
        /// Ultimo stato richiesto, per non ripetere la chiamata a ogni
        /// aggiornamento della schermata — che avviene a ogni comando e a ogni
        /// ingresso nella pagina.
        static REQUESTED: Cell<bool> = const { Cell::new(false) };
    }

    REQUESTED.with(|requested| {
        if requested.get() == acquiring {
            return;
        }
        requested.set(acquiring);

        let outcome = if acquiring {
            lisi_platform::keep_system_awake()
        } else {
            lisi_platform::allow_system_sleep()
        };

        match outcome {
            Ok(()) if acquiring => {
                tracing::info!("la postazione resta sveglia: monitoraggio in corso");
            }
            Ok(()) => tracing::info!("la postazione puo' sospendersi: nessun monitoraggio attivo"),
            Err(error) => tracing::info!(
                errore = %error,
                "stato di sospensione della postazione invariato"
            ),
        }
    });
}

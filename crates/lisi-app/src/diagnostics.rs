//! Collegamento fra la schermata «Diagnostica» e il servizio che la compone.
//!
//! Come gli altri moduli dell'interfaccia, non contiene logica: traduce la
//! fotografia composta dai servizi in righe, e il comando «Aggiorna» in una
//! nuova composizione.
//!
//! # Che cosa questo modulo non fa
//!
//! **Non compie alcun rimedio.** Non verifica l'archivio, non produce copie di
//! sicurezza, non interroga Telegram. Le voci che indicano un rimedio dicono
//! **dove** si compie, e il rimedio resta dove è sempre stato: un secondo
//! pannello di comandi accanto a quello vero è due pannelli che divergono, e il
//! giorno in cui uno cambia l'altro mente.
//!
//! # L'unica cosa che scrive, ed è la propria
//!
//! Il **pacchetto diagnostico** (DIAG-02): il file che si manda a chi assiste.
//! Non è il rimedio di un'altra schermata — nessun'altra pagina lo produce — e
//! per questo non contraddice la regola qui sopra: la regola vieta di duplicare
//! i rimedi altrui, non di avere un mestiere.
//!
//! Che cosa il file conterrà è scritto **nella schermata, prima** che il file
//! esista: chi legge la promessa dopo aver spedito la legge troppo tardi.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_services::diagnostics::{CheckOutcome, DiagnosticsService, StationFacts};
use lisi_services::source_health::HealthSummary;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::sources::SharedHealth;
use crate::{AppWindow, DiagnosticRow};

/// Servizio della diagnostica, condiviso fra i gestori dei comandi.
pub type SharedDiagnostics = Rc<RefCell<DiagnosticsService>>;

/// Crea il servizio della diagnostica sull'archivio indicato.
#[must_use]
pub fn create_service(database: lisi_services::Database) -> Option<SharedDiagnostics> {
    Some(Rc::new(RefCell::new(DiagnosticsService::new(database))))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn adesso() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// Prende la fotografia e la riporta nell'interfaccia.
///
/// # Perché le fonti arrivano da fuori
///
/// Perché la salute delle fonti la compone il servizio della salute, ed è già
/// composta: ricomporla qui creerebbe una seconda derivazione, e la
/// diagnostica potrebbe dire delle fonti una cosa diversa da quella che la
/// schermata Fonti dice nello stesso momento. È la ragione di DEC-252,
/// applicata a una seconda superficie.
pub fn refresh(window: &AppWindow, diagnostics: &SharedDiagnostics, health: Option<&SharedHealth>) {
    let sources = health.map_or_else(HealthSummary::default, |health| {
        health
            .borrow()
            .service()
            .summary()
            .unwrap_or_else(|errore| {
                tracing::warn!(
                    kind = errore.kind(),
                    "riepilogo delle fonti non leggibile: la diagnostica lo dirà vuoto"
                );
                HealthSummary::default()
            })
    });

    let facts = StationFacts {
        // La modalità in vigore, letta dove la leggono le altre schermate.
        mode: lisi_services::station::persisted_mode_or_restricted(),
        // «Autenticato» in questa esecuzione: è ciò che l'interfaccia sa, e
        // non è la stessa cosa dell'autorizzazione registrata nell'archivio —
        // che la diagnostica legge da sé.
        telegram_runtime_started: crate::account::telegram_live_connected(window),
        sources,
    };

    let now = adesso();
    let Ok(rapporto) = diagnostics.borrow().compose(&facts, now) else {
        tracing::warn!("diagnostica non componibile: la schermata resta vuota");
        window.set_diagnostics(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        window.set_diagnostics_summary(crate::lingua::schermo(
            "Non è stato possibile comporre la diagnostica di questa postazione.",
        ));
        window.set_diagnostics_taken_at(SharedString::default());
        window.set_diagnostics_attention(true);
        return;
    };

    let righe: Vec<DiagnosticRow> = rapporto
        .checks
        .iter()
        .map(|check| DiagnosticRow {
            area: crate::lingua::schermo(check.area.title()),
            outcome: crate::lingua::schermo(check.outcome.label()),
            detail: SharedString::from(check.detail.as_str()),
            action: check
                .action
                .as_deref()
                .map_or_else(SharedString::default, SharedString::from),
            attention: check.outcome == CheckOutcome::Attention,
            problem: check.outcome == CheckOutcome::Problem,
            unmeasured: check.outcome == CheckOutcome::Unmeasured,
        })
        .collect();

    window.set_diagnostics_summary(crate::lingua::schermo(rapporto.as_sentence()));
    window.set_diagnostics_attention(rapporto.needing_attention() > 0);
    window.set_diagnostics_taken_at(crate::lingua::schermo(format!(
        "Fotografia presa il {}.",
        rapporto.taken_at.to_readable_local()
    )));
    window.set_diagnostics(ModelRc::from(Rc::new(VecModel::from(righe))));
}

/// Registra i gestori dei comandi della schermata.
pub fn wire(window: &AppWindow, diagnostics: &SharedDiagnostics, health: Option<&SharedHealth>) {
    {
        // All'ingresso nella schermata la fotografia si riprende: mostrarne una
        // vecchia in una schermata che esiste per dire come stanno le cose
        // adesso sarebbe il difetto peggiore che potesse avere.
        let weak = window.as_weak();
        let diagnostics = Rc::clone(diagnostics);
        let health = health.map(Rc::clone);
        window.on_diagnostics_shown(move || {
            let Some(window) = weak.upgrade() else { return };
            refresh(&window, &diagnostics, health.as_ref());
        });
    }

    {
        let weak = window.as_weak();
        let diagnostics = Rc::clone(diagnostics);
        let health = health.map(Rc::clone);
        window.on_refresh_diagnostics(move || {
            if crate::lock::refuse_while_locked("refresh_diagnostics") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            refresh(&window, &diagnostics, health.as_ref());
        });
    }

    {
        // L'ESPORTAZIONE (DIAG-02).
        //
        // È l'unica cosa che questa schermata scrive, ed è la propria: produce
        // il file che si manda a chi assiste. Non è il rimedio di un'altra
        // schermata, ed è la ragione per cui non contraddice la regola
        // «il centro guarda e non tocca».
        let weak = window.as_weak();
        let diagnostics = Rc::clone(diagnostics);
        let health = health.map(Rc::clone);
        window.on_export_diagnostics(move || {
            if crate::lock::refuse_while_locked("export_diagnostics") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };

            // La cartella si SCEGLIE e non si digita: una cartella scelta da
            // una finestra di sistema esiste per costruzione, e non c'è un
            // testo da convalidare che possa contenere qualcosa di inatteso
            // (DEC-113).
            let diagnostics = Rc::clone(&diagnostics);
            let health = health.as_ref().map(Rc::clone);
            crate::dialogs::ask_or_cancel(
                &window,
                rfd::AsyncFileDialog::new().set_title("Dove salvare il pacchetto diagnostico"),
                crate::dialogs::Pick::Folder,
                "export_diagnostics",
                move |window, cartella| {
                    let sources = health
                        .as_ref()
                        .map_or_else(HealthSummary::default, |health| {
                            health
                                .borrow()
                                .service()
                                .summary()
                                .unwrap_or_else(|_| HealthSummary::default())
                        });
                    let facts = StationFacts {
                        mode: lisi_services::station::persisted_mode_or_restricted(),
                        telegram_runtime_started: crate::account::telegram_live_connected(window),
                        sources,
                    };

                    let Ok(attore) = crate::operator::audit_actor() else {
                        return;
                    };
                    let messaggio = match diagnostics.borrow().export_to(
                        &cartella,
                        &facts,
                        &attore,
                        adesso(),
                    ) {
                        Ok(percorso) => {
                            // Il NOME del file, non il percorso: chi ha scelto la
                            // cartella sa dove sta, e la schermata non ripete un
                            // percorso che nel resto di questa pagina non compare mai.
                            let nome = percorso
                                .file_name()
                                .and_then(|nome| nome.to_str())
                                .unwrap_or("(nome non leggibile)")
                                .to_owned();
                            format!(
                                "Pacchetto scritto: «{nome}», nella cartella scelta. Contiene le \
                         righe qui sopra e nulla d'altro."
                            )
                        }
                        Err(errore) => {
                            tracing::warn!(
                                kind = errore.kind(),
                                "pacchetto diagnostico non scritto"
                            );
                            errore.operator_message()
                        }
                    };
                    window.set_diagnostics_export_message(crate::lingua::schermo(messaggio));
                },
                |window| {
                    window.set_diagnostics_export_message(crate::lingua::schermo(
                        "Esportazione annullata: nessun file è stato scritto.",
                    ));
                },
            );
        });
    }
}

#[cfg(test)]
mod guardie {
    /// Il file dell'interfaccia, per le guardie testuali.
    const UI: &str = include_str!("../ui/app-window.slint");

    /// Questo modulo, per verificare che cosa il codice di produzione fa.
    const THIS_MODULE: &str = include_str!("diagnostics.rs");

    /// Il corpo del codice di produzione, senza le prove.
    fn produzione() -> &'static str {
        let Some((codice, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod guardie {") else {
            panic!("il modulo deve avere un blocco di guardie riconoscibile");
        };
        codice
    }

    /// «Non misurato» non si dipinge né come guasto né come in ordine.
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Su questa postazione almeno due aree non sono misurabili — la cifratura
    /// del disco e lo stato dell'aggiornamento. Dipingerle di rosso
    /// insegnerebbe a ignorare il rosso; dipingerle di verde direbbe che il
    /// prodotto ha guardato quando non ha guardato.
    #[test]
    fn cio_che_non_si_e_misurato_ha_un_colore_proprio() {
        let Some(inizio) = UI.find("text: voce.outcome;") else {
            panic!("l'etichetta dell'esito deve esistere");
        };
        let Some(fine) = UI[inizio..].find("horizontal-stretch: 0;") else {
            panic!("il blocco dell'etichetta deve avere una fine riconoscibile");
        };
        let blocco = &UI[inizio..inizio + fine];

        assert!(
            blocco.contains("voce.unmeasured"),
            "l'esito non misurato deve avere un ramo proprio"
        );

        let Some(ramo) = blocco.find("voce.unmeasured") else {
            panic!("il ramo del non misurato deve esistere");
        };
        let dopo = &blocco[ramo..];
        let Some(scelta) = dopo.find("Palette.") else {
            panic!("il ramo deve scegliere un colore");
        };
        assert!(
            dopo[scelta..].starts_with("Palette.text-muted"),
            "un'area non misurata non va colorata né come guasto né come in ordine"
        );
    }

    /// Lo stato è scritto oltre che colorato.
    ///
    /// Il colore da solo non basta a chi non lo distingue, ed è la regola già
    /// in vigore nell'idoneità della postazione.
    #[test]
    fn l_esito_si_legge_oltre_che_vedersi() {
        assert!(
            UI.contains("text: voce.outcome;"),
            "l'esito va scritto, non solo colorato"
        );
    }

    /// La schermata non compie alcun **rimedio**.
    ///
    /// # Perché è una prova e non una convenzione
    ///
    /// Perché la tentazione è forte e sembra un miglioramento: un pulsante
    /// «Verifica l'archivio» qui accanto. Sarebbe un secondo pannello di
    /// comandi accanto a quello vero, e il giorno in cui uno dei due cambia
    /// l'altro mente.
    ///
    /// # L'esportazione non è un'eccezione a questa regola
    ///
    /// Il pacchetto diagnostico (DIAG-02) è **il gesto proprio di questa
    /// schermata**, non il rimedio di un'altra: nessun'altra pagina lo
    /// produce, e non c'è alcun secondo pannello con cui divergere. La regola
    /// vieta di duplicare i rimedi altrui, non di avere un mestiere.
    #[test]
    fn la_schermata_indica_il_gesto_e_non_lo_compie() {
        let codice = produzione();

        for rimedio_altrui in [
            "verify_integrity",
            "write_to",
            "verify_all",
            "accessible_chats",
            "append_audit",
        ] {
            assert!(
                !codice.contains(rimedio_altrui),
                "la schermata della diagnostica chiama «{rimedio_altrui}»: il centro \
                 guarda, e il rimedio resta dove è sempre stato"
            );
        }

        // E il proprio mestiere invece ce l'ha: se sparisse, il pacchetto
        // diagnostico non sarebbe raggiungibile da alcuna schermata — che è il
        // difetto già trovato cinque volte in questo progetto.
        assert!(
            codice.contains("export_to("),
            "il pacchetto diagnostico deve essere raggiungibile da questa schermata"
        );
    }

    /// La schermata dice che cosa uscirà **prima** che esca.
    ///
    /// Chi legge la promessa dopo aver spedito il file la legge troppo tardi.
    #[test]
    fn la_schermata_dichiara_che_cosa_esce_prima_di_produrlo() {
        let Some(avvertenza) = UI.find("Il file esportato contiene queste stesse righe") else {
            panic!("l'avvertenza sull'esportazione deve esistere");
        };
        let Some(riscontro) = UI.find("root.diagnostics-export-message") else {
            panic!("il riscontro dell'esportazione deve esistere");
        };

        assert!(
            avvertenza < riscontro,
            "che cosa il file conterrà va detto prima dell'esito, non dopo"
        );
        for promessa in ["nessun testo di messaggio", "nessun percorso di cartella"] {
            assert!(
                UI.contains(promessa),
                "l'avvertenza deve nominare «{promessa}»: è ciò che rende il file \
                 inviabile senza doversi fidare"
            );
        }
    }

    /// La cartella si sceglie, non si digita.
    ///
    /// Una cartella scelta da una finestra di sistema esiste per costruzione, e
    /// non c'è un testo da convalidare che possa contenere qualcosa di
    /// inatteso (DEC-113).
    #[test]
    fn la_cartella_del_pacchetto_si_sceglie_e_non_si_digita() {
        let codice = produzione();

        assert!(
            codice.contains("crate::dialogs::Pick::Folder"),
            "la destinazione deve venire da una finestra di sistema"
        );
        assert!(
            !UI.contains("diagnostics-export-path"),
            "non deve esistere un campo di testo in cui digitare la destinazione"
        );
    }

    /// La schermata dichiara che una voce non misurata non è una voce a posto.
    #[test]
    fn la_schermata_dichiara_che_cosa_non_ha_guardato() {
        assert!(
            UI.contains("non è un'area a posto"),
            "il limite va dichiarato nella schermata, non solo nel codice"
        );
    }
}

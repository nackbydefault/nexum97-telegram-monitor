//! Collegamento fra la schermata «Verifica» e il servizio di esportazione.
//!
//! La verifica dei manifest (DEC-102) produce già un `Verification` per rapporto
//! (`ExportService::verify_directory`); questo modulo li traduce in righe
//! dell'interfaccia. Non contiene logica di verifica: mostra ciò che il motore
//! ha constatato.
//!
//! La scansione è **esplicita** — un clic su «Verifica ora», oppure la
//! scorciatoia dalla schermata Storico — e non automatica all'apertura: ogni
//! scansione lascia una traccia d'audit, e ripeterla a ogni navigazione la
//! trasformerebbe in rumore (DEC-104).

use std::rc::Rc;

use lisi_services::export::{ExportService, Verification, VerificationStatus};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::{AppWindow, VerificationRow};

/// Servizio di esportazione usato per la verifica, condiviso fra i gestori.
pub type SharedVerification = Rc<ExportService>;

/// Indice della pagina Verifica nell'interfaccia.
const VERIFICATION_PAGE: i32 = 12;

/// Crea il servizio di verifica sull'archivio indicato.
#[must_use]
pub fn create_service(database: lisi_services::Database) -> Option<SharedVerification> {
    Some(Rc::new(ExportService::new(database)))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// Attore dell'audit.
fn actor() -> lisi_services::ServiceResult<lisi_core::text::Actor> {
    crate::operator::audit_actor()
}

/// Etichetta mostrabile del verdetto.
fn status_label(status: &VerificationStatus) -> &'static str {
    match status {
        VerificationStatus::Intact => "Integro",
        VerificationStatus::Altered { .. } => "Alterato",
        VerificationStatus::ReportMissing => "Rapporto mancante",
        VerificationStatus::ManifestUnreadable => "Elenco delle impronte illeggibile",
    }
}

/// Frase riassuntiva in testa all'elenco.
fn summary(verifications: &[Verification]) -> String {
    if verifications.is_empty() {
        return String::from("Nessun rapporto esportato da verificare.");
    }

    let doubtful = verifications
        .iter()
        .filter(|verification| !verification.status.is_intact())
        .count();

    if doubtful == 0 {
        format!(
            "Verificati {}: tutti integri, corrispondono al loro elenco delle impronte.",
            lisi_core::text::counted(verifications.len(), "rapporto", "rapporti")
        )
    } else {
        format!(
            "ATTENZIONE: su {}, {doubtful} non {} al loro elenco delle impronte.",
            lisi_core::text::counted(verifications.len(), "rapporto", "rapporti"),
            if doubtful == 1 {
                "corrisponde"
            } else {
                "corrispondono"
            }
        )
    }
}

/// Traduce le verifiche in righe dell'interfaccia.
fn rows(verifications: &[Verification]) -> ModelRc<VerificationRow> {
    let rows: Vec<VerificationRow> = verifications
        .iter()
        .map(|verification| VerificationRow {
            report: SharedString::from(verification.report_name.as_str()),
            status: SharedString::from(status_label(&verification.status)),
            ok: verification.status.is_intact(),
        })
        .collect();
    ModelRc::from(Rc::new(VecModel::from(rows)))
}

/// Esegue la scansione e riporta l'esito nell'interfaccia.
/// Chiede all'operatore quale cartella esaminare.
///
/// Non tocca la destinazione configurata: e' una domanda su un pacchetto, non
/// una decisione sull'ufficio. Le due cose si somigliano abbastanza da essere
/// confuse, e confonderle significherebbe cambiare dove i documenti nascono
/// per aver chiesto di controllarne uno.
fn folder_dialog(current: Option<&std::path::PathBuf>) -> rfd::AsyncFileDialog {
    let mut dialog = rfd::AsyncFileDialog::new().set_title("Scegliere la cartella da verificare");
    if let Some(path) = current {
        dialog = dialog.set_directory(path);
    }
    dialog
}

fn scan(window: &AppWindow, service: &SharedVerification, altrove: Option<std::path::PathBuf>) {
    // Da questo momento la schermata mostra un esito, non lo stato iniziale.
    window.set_verification_checked(true);

    // La stessa cartella in cui l'esportazione scrive. Chiederla al servizio
    // invece di ricalcolarla e' cio' che impedisce a questa schermata di
    // dichiarare «nessun rapporto» guardando dove i rapporti non sono.
    //
    // Quando l'operatore ne indica una, e' quella: la sua scelta batte la
    // configurazione, perche' e' una risposta a «guarda QUI» e non una nuova
    // impostazione.
    let scelta = altrove.map(Ok);
    let Ok(directory) = scelta.unwrap_or_else(|| service.destination()) else {
        window.set_verification_rows(rows(&[]));
        window.set_verification_summary(crate::lingua::schermo(
            "Cartella dei documenti non determinabile su questa postazione.",
        ));
        return;
    };

    let outcome = actor().and_then(|actor| service.verify_directory(&directory, &actor, now()));

    match outcome {
        Ok(verifications) => {
            window.set_verification_rows(rows(&verifications));
            // **UN «NON HO TROVATO NULLA» DEVE DIRE DOVE HA GUARDATO.**
            //
            // Il 2026-08-20 la schermata rispondeva «nessun rapporto da
            // verificare» a chi aveva appena prodotto un pacchetto. Il
            // messaggio era vero e inutile: non diceva in quale cartella
            // avesse cercato, e senza quella riga non c'e' modo di capire se
            // il difetto sia nella ricerca o nella cartella.
            //
            // Il percorso compare solo quando non si e' trovato nulla: quando
            // l'elenco c'e', il percorso e' rumore.
            let testo = if verifications.is_empty() {
                format!(
                    "{} Cartella esaminata: {}",
                    summary(&verifications),
                    directory.display()
                )
            } else {
                summary(&verifications)
            };
            window.set_verification_summary(SharedString::from(testo));
        }
        Err(error) => {
            tracing::warn!(kind = error.kind(), "verifica dei rapporti non riuscita");
            window.set_verification_rows(rows(&[]));
            window.set_verification_summary(crate::lingua::schermo(error.operator_message()));
        }
    }
}

/// Collega i comandi della schermata al servizio.
pub fn wire(window: &AppWindow, service: &SharedVerification) {
    {
        // RIAPRIRE LA SCHERMATA NON RIPROPONE UN ESITO VECCHIO (FINAL-REVIEW-01,
        // FR-052). Il callback era invocato all'apertura e nessuno lo
        // gestiva: si tornava sulla Verifica e si leggeva l'esito di una
        // scansione di prima come se fosse di adesso. Un verdetto su file che
        // nel frattempo possono essere cambiati non si conserva (ADR-0069):
        // la schermata torna allo stato iniziale, e la verifica si rifà.
        let handle = window.as_weak();
        window.on_verification_shown(move || {
            if let Some(window) = handle.upgrade() {
                window.set_verification_checked(false);
                window.set_verification_rows(rows(&[]));
                window.set_verification_summary(SharedString::default());
            }
        });
    }

    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_verify_now(move || {
            if crate::lock::refuse_while_locked("verify_now") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                scan(&window, &service, None);
            }
        });
    }

    {
        // Verifica una cartella indicata sul momento.
        //
        // Il selettore si apre sulla destinazione configurata quando c'e':
        // e' il punto da cui si parte a cercare, non quello dove si finisce.
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_verify_elsewhere(move || {
            if crate::lock::refuse_while_locked("verify_elsewhere") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let partenza = service.destination().ok();
            // Annullare non e' un errore e non cambia nulla: la schermata
            // resta con l'esito che aveva.
            let service = Rc::clone(&service);
            crate::dialogs::ask(
                &window,
                folder_dialog(partenza.as_ref()),
                crate::dialogs::Pick::Folder,
                "verify_elsewhere",
                move |window, scelta| scan(window, &service, Some(scelta)),
            );
        });
    }

    {
        // Scorciatoia dalla schermata Storico: porta alla schermata Verifica e
        // vi avvia subito la scansione, perché chi ha appena esportato vuole
        // vedere l'esito, non un'altra schermata da comandare.
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_verify_exports(move || {
            if crate::lock::refuse_while_locked("verify_exports") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            window.set_current_page(VERIFICATION_PAGE);
            scan(&window, &service, None);
        });
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Sha256Digest;
    use lisi_services::export::{Verification, VerificationStatus};

    use super::{VERIFICATION_PAGE, status_label, summary};

    /// Interfaccia, letta a tempo di compilazione per il controllo qui sotto.
    const UI: &str = include_str!("../ui/app-window.slint");

    #[test]
    fn the_verification_page_index_matches_the_interface() {
        assert_eq!(VERIFICATION_PAGE, 12);
        assert!(
            UI.contains(&format!("current-page == {VERIFICATION_PAGE}: Rectangle")),
            "la pagina Verifica con indice {VERIFICATION_PAGE} non e' nell'interfaccia"
        );
        assert!(
            UI.contains(&format!("root.open-page({VERIFICATION_PAGE});")),
            "la voce di menu Verifica non naviga all'indice {VERIFICATION_PAGE}"
        );
    }

    #[test]
    fn every_status_has_a_readable_label() {
        let altered = VerificationStatus::Altered {
            declared: Sha256Digest::of_bytes(b"a"),
            actual: Sha256Digest::of_bytes(b"b"),
        };
        assert_eq!(status_label(&VerificationStatus::Intact), "Integro");
        assert_eq!(status_label(&altered), "Alterato");
        assert_eq!(
            status_label(&VerificationStatus::ReportMissing),
            "Rapporto mancante"
        );
        assert_eq!(
            status_label(&VerificationStatus::ManifestUnreadable),
            "Elenco delle impronte illeggibile"
        );
    }

    fn verification(name: &str, status: VerificationStatus) -> Verification {
        Verification {
            report_name: String::from(name),
            status,
        }
    }

    #[test]
    fn the_summary_distinguishes_empty_all_intact_and_some_doubtful() {
        assert!(summary(&[]).contains("Nessun rapporto"));

        let all_intact = [
            verification("a.txt", VerificationStatus::Intact),
            verification("b.txt", VerificationStatus::Intact),
        ];
        assert!(summary(&all_intact).contains("tutti integri"));

        let some_doubtful = [
            verification("a.txt", VerificationStatus::Intact),
            verification("b.txt", VerificationStatus::ReportMissing),
        ];
        let text = summary(&some_doubtful);
        assert!(text.contains("ATTENZIONE"));
        assert!(text.contains("1 non corrispond"), "{text}");
    }
}

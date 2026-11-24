//! Collegamento fra la sezione «Configurazione condivisa» e il servizio del
//! fascicolo.
//!
//! # I tre gesti, e perché sono tre
//!
//! **Esportare** produce un file. **Scegliere** ne apre uno e mostra che cosa
//! cambierebbe. **Importare** applica.
//!
//! Scegliere e importare sono separati di proposito: l'anteprima esiste perché
//! chi riceve un fascicolo possa vedere che cosa gli sostituirebbe la firma in
//! calce ai propri atti **prima** che gliela sostituisca. Unirli in un comando
//! solo trasformerebbe l'anteprima in un messaggio che si legge dopo.

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;

use lisi_services::team::{MAX_FASCICOLO_BYTES, TeamService};
use slint::{ComponentHandle, SharedString};

use crate::AppWindow;

/// Servizio del fascicolo condiviso fra i gestori.
pub type SharedTeam = Rc<RefCell<TeamService>>;

/// Estensione del fascicolo.
const EXTENSION: &str = "nexum97.json";

/// Crea il servizio sul dato archivio.
#[must_use]
pub fn create_service(database: lisi_services::Database) -> Option<SharedTeam> {
    Some(Rc::new(RefCell::new(TeamService::new(database))))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// Attore dell'audit.
fn actor() -> lisi_services::ServiceResult<lisi_core::text::Actor> {
    crate::operator::audit_actor()
}

/// Il nome con cui questa postazione si presenta nel fascicolo.
///
/// # Perché il nome del computer e non un identificativo inventato
///
/// Chi riceve un fascicolo deve poter risalire a **chi glielo ha mandato**, e
/// in un ufficio il nome della macchina è ciò che le persone riconoscono. Un
/// identificativo generato sarebbe più stabile e non direbbe nulla a nessuno.
fn station_name() -> String {
    std::env::var("COMPUTERNAME")
        .ok()
        .filter(|nome| !nome.trim().is_empty())
        .unwrap_or_else(|| String::from("postazione sconosciuta"))
}

/// Chiede dove salvare il fascicolo.
fn save_dialog() -> rfd::AsyncFileDialog {
    rfd::AsyncFileDialog::new()
        .set_title("Salvare la configurazione condivisibile")
        .add_filter("Fascicolo NEXUM/97", &[EXTENSION])
        .set_file_name(format!("configurazione.{EXTENSION}"))
}

/// Chiede quale fascicolo aprire.
fn open_dialog() -> rfd::AsyncFileDialog {
    rfd::AsyncFileDialog::new()
        .set_title("Scegliere il fascicolo da importare")
        .add_filter("Fascicolo NEXUM/97", &[EXTENSION, "json"])
}

/// Legge un fascicolo dal disco, con il limite applicato **prima** della
/// lettura.
///
/// # Perché si guarda la dimensione del file e non del contenuto
///
/// Il servizio limita la lunghezza del testo che riceve, ma a quel punto il
/// testo è già in memoria. Qui si interroga il filesystem: un file da un
/// gigabyte viene rifiutato senza che un solo byte venga letto.
fn read_fascicolo(path: &Path) -> Result<String, String> {
    let dati = std::fs::metadata(path)
        .map_err(|errore| format!("«{}» non è leggibile: {errore}", path.display()))?;

    let limite = u64::try_from(MAX_FASCICOLO_BYTES).unwrap_or(u64::MAX);
    if dati.len() > limite {
        return Err(format!(
            "Il file occupa {} byte e supera il limite di {MAX_FASCICOLO_BYTES}: \
             non è stato nemmeno letto.",
            dati.len()
        ));
    }

    std::fs::read_to_string(path)
        .map_err(|errore| format!("«{}» non è leggibile: {errore}", path.display()))
}

/// Azzera l'anteprima e il comando che importa.
///
/// Si chiama dopo ogni operazione: un'anteprima che sopravvive al proprio
/// fascicolo descriverebbe un file che non è più quello scelto.
fn clear_preview(window: &AppWindow) {
    window.set_team_preview(crate::lingua::schermo(""));
    window.set_team_can_import(false);
}

/// Il fascicolo scelto, conservato fra la scelta e l'importazione.
type Chosen = Rc<RefCell<Option<String>>>;

/// Collega i comandi della sezione al servizio.
pub fn wire(window: &AppWindow, team: &SharedTeam) {
    let scelto: Chosen = Rc::new(RefCell::new(None));

    {
        let handle = window.as_weak();
        let team = Rc::clone(team);
        window.on_export_fascicolo(move || {
            if crate::lock::refuse_while_locked("export_fascicolo") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let team = Rc::clone(&team);
            crate::dialogs::ask(
                &window,
                save_dialog(),
                crate::dialogs::Pick::Save,
                "export_fascicolo",
                move |window, destinazione| {
                    // Il file lo scrive il servizio, del solo utente (SEC-02):
                    // l'interfaccia non tocca il disco, e un rifiuto per i
                    // permessi arriva con la sua frase.
                    let esito = {
                        let servizio = team.borrow();
                        actor().and_then(|actor| {
                            servizio.export_to_file(&destinazione, &station_name(), &actor, now())
                        })
                    };

                    let messaggio = match esito {
                        Err(errore) => errore.operator_message(),
                        Ok(consegnati) => format!(
                            "Configurazione esportata in «{}». Non contiene contenuti acquisiti \
                             né credenziali. Si apre soltanto con l'utente Windows «{}».",
                            destinazione.display(),
                            consegnati.owner.name
                        ),
                    };
                    window.set_team_message(crate::lingua::schermo(messaggio));
                },
            );
        });
    }

    {
        let handle = window.as_weak();
        let team = Rc::clone(team);
        let scelto = Rc::clone(&scelto);
        window.on_choose_fascicolo(move || {
            if crate::lock::refuse_while_locked("choose_fascicolo") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let team = Rc::clone(&team);
            let scelto = Rc::clone(&scelto);
            crate::dialogs::ask(
                &window,
                open_dialog(),
                crate::dialogs::Pick::File,
                "choose_fascicolo",
                move |window, percorso| {
                    window.set_team_path(SharedString::from(percorso.display().to_string()));
                    clear_preview(window);
                    *scelto.borrow_mut() = None;

                    let documento = match read_fascicolo(&percorso) {
                        Ok(testo) => testo,
                        Err(motivo) => {
                            window.set_team_message(SharedString::from(motivo));
                            return;
                        }
                    };

                    let esito = team.borrow().preview_import(&documento);
                    match esito {
                        Ok((_, anteprima)) => {
                            window.set_team_preview(crate::lingua::schermo(
                                anteprima.operator_message(),
                            ));
                            // Un fascicolo che non cambierebbe nulla non offre il
                            // comando che importa: un pulsante che non fa nulla insegna
                            // a non fidarsi dei pulsanti.
                            window.set_team_can_import(!anteprima.is_empty());
                            *scelto.borrow_mut() = Some(documento);
                            window.set_team_message(crate::lingua::schermo(
                                "Nulla è stato ancora importato. Leggere l'anteprima qui sopra.",
                            ));
                        }
                        Err(errore) => {
                            window.set_team_message(crate::lingua::schermo(
                                errore.operator_message(),
                            ));
                        }
                    }
                },
            );
        });
    }

    {
        let handle = window.as_weak();
        let team = Rc::clone(team);
        let scelto = Rc::clone(&scelto);
        window.on_import_fascicolo(move || {
            if crate::lock::refuse_while_locked("import_fascicolo") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let Some(documento) = scelto.borrow().clone() else {
                window.set_team_message(crate::lingua::schermo(
                    "Nessun fascicolo scelto: usare prima «Scegli un fascicolo...».",
                ));
                return;
            };

            let esito = {
                let mut servizio = team.borrow_mut();
                actor().and_then(|actor| servizio.import(&documento, &actor, now()))
            };

            let messaggio = match esito {
                Ok(risultato) => risultato.operator_message(),
                Err(errore) => errore.operator_message(),
            };

            // Il fascicolo si consuma: importarlo due volte per un doppio clic
            // non farebbe danni — le fonti già presenti si saltano — ma il
            // secondo esito direbbe «zero fonti aggiunte» e sembrerebbe un
            // guasto.
            *scelto.borrow_mut() = None;
            clear_preview(&window);
            window.set_team_message(crate::lingua::schermo(messaggio));
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{EXTENSION, read_fascicolo, station_name};

    #[test]
    fn una_postazione_si_presenta_sempre_con_un_nome() {
        // Chi riceve un fascicolo deve poter risalire a chi glielo ha mandato.
        // Se la variabile mancasse, un nome vuoto renderebbe la traccia d'audit
        // inutile proprio nel punto in cui serve.
        let nome = station_name();
        assert!(!nome.trim().is_empty());
    }

    #[test]
    fn un_file_troppo_grande_non_viene_letto() {
        // Il limite si applica al FILE e non al contenuto: a contenuto letto
        // sarebbe gia' tardi.
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let percorso = cartella.path().join("enorme.json");
        let Ok(()) = std::fs::write(&percorso, vec![b'x'; super::MAX_FASCICOLO_BYTES + 1]) else {
            panic!("il file di prova deve potersi scrivere");
        };

        let Err(motivo) = read_fascicolo(&percorso) else {
            panic!("un file oltre il limite non deve essere letto");
        };
        assert!(
            motivo.contains("non è stato nemmeno letto"),
            "il rifiuto deve dire che il file non e' stato toccato: «{motivo}»"
        );
    }

    #[test]
    fn un_file_che_non_esiste_dice_quale() {
        let Err(motivo) = read_fascicolo(std::path::Path::new("C:/non/esiste.json")) else {
            panic!("un file inesistente non deve essere letto");
        };
        assert!(
            motivo.contains("esiste.json"),
            "il rifiuto deve nominare il file: «{motivo}»"
        );
    }

    #[test]
    fn l_estensione_e_riconoscibile_e_non_generica() {
        // «.json» da solo confonderebbe il fascicolo con un dizionario o con
        // qualunque altro file di configurazione della macchina.
        assert!(EXTENSION.starts_with("nexum97"));
    }
}

//! Collegamento fra la schermata Dizionari e il servizio della libreria.
//!
//! Come per Account e Fonti, questo modulo non contiene logica: traduce i
//! comandi dell'operatore in chiamate al servizio e lo stato del servizio in
//! proprietà dell'interfaccia.
//!
//! In particolare **non decide** se un dizionario sia utilizzabile né perché
//! non lo sia: quelle risposte arrivano già calcolate da `LibraryEntry`, dove
//! sono coperte da test. Ripeterle qui vorrebbe dire avere due risposte che un
//! giorno divergeranno.

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;

use lisi_core::OperatingMode;
use lisi_core::model::dictionary::MAX_IMPORT_BYTES;
use lisi_services::dictionaries::{
    DictionaryRemoval, DictionaryService, LibraryEntry, LibraryFilter,
};
use lisi_services::dictionary_download::StoredDictionaryDownload;
use lisi_services::{ServiceError, ServiceResult, station};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::{AppWindow, DictionaryEntry, TermEntry};

/// Servizio dei dizionari condiviso fra i gestori dei comandi.
pub type SharedDictionaries = Rc<RefCell<DictionaryService>>;

/// Crea il servizio sull'archivio indicato e vi installa i dizionari forniti.
///
/// L'installazione è idempotente: eseguirla a ogni avvio non duplica nulla.
///
/// L'archivio arriva da fuori invece di essere aperto qui: così l'applicazione
/// gli passa quello di esercizio e i test uno in memoria, senza che il codice
/// debba sapere quale dei due sia. Aprirlo internamente farebbe scrivere ai
/// test nell'archivio dell'operatore.
#[must_use]
pub fn create_service(database: lisi_services::Database) -> Option<SharedDictionaries> {
    let mode = station::persisted_mode_or_restricted();
    tracing::info!(
        modalita = mode.as_str(),
        "modalità operativa della postazione"
    );
    let mut service = DictionaryService::with_mode(database, mode);

    if let Err(error) = service.install_seed_dictionaries(now()) {
        // Un seed illeggibile e' un difetto del prodotto, non della postazione:
        // i file sono inclusi nel binario. La schermata resta raggiungibile e
        // dira' che la libreria e' vuota, invece di non aprirsi affatto.
        tracing::error!(
            errore = %error.kind(),
            "installazione dei dizionari forniti con il prodotto non riuscita"
        );
    }

    Some(Rc::new(RefCell::new(service)))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// Attore dell'audit.
fn actor() -> ServiceResult<lisi_core::text::Actor> {
    crate::operator::audit_actor()
}

/// Traduce una voce di libreria nella riga attesa dall'interfaccia.
fn row(entry: &LibraryEntry) -> DictionaryEntry {
    DictionaryEntry {
        dictionary_id: i32::try_from(entry.dictionary.id.get()).unwrap_or(0),
        name: SharedString::from(entry.dictionary.name.as_str()),
        description: SharedString::from(entry.dictionary.description.as_str()),
        scope: crate::lingua::schermo(entry.dictionary.scope.label()),
        origin: crate::lingua::schermo(entry.dictionary.origin.label()),
        visibility: crate::lingua::schermo(entry.dictionary.visibility.label()),
        status: crate::lingua::schermo(entry.dictionary.status.label()),
        published_version: entry
            .published
            .as_ref()
            .and_then(|version| i32::try_from(version.number).ok())
            .unwrap_or(0),
        published_terms: i32::try_from(entry.published_terms).unwrap_or(i32::MAX),
        has_open_draft: entry.has_open_draft,
        built_in: !entry.dictionary.is_editable(),
        usable: entry.is_usable(),
        unusable_reason: SharedString::from(entry.unusable_reason().unwrap_or_default()),
    }
}

/// Riporta nell'interfaccia lo stato della libreria.
pub fn refresh(window: &AppWindow, dictionaries: &SharedDictionaries, message: Option<&str>) {
    if let Some(text) = message {
        window.set_dictionaries_message(SharedString::from(text));
    }

    let mode = dictionaries.borrow().mode();
    window.set_operating_mode_label(crate::lingua::schermo(mode.label()));
    window.set_operating_mode_description(crate::lingua::schermo(mode.description()));
    window.set_administrator_mode(mode == OperatingMode::Administrator);

    // Il filtro viene dall'interfaccia ma è applicato dal servizio, dove è
    // coperto da test: ripeterlo qui vorrebbe dire due ricerche che un giorno
    // divergono.
    let filter = LibraryFilter {
        query: window.get_dictionary_filter().to_string(),
        only_usable: window.get_only_usable(),
        only_editable: window.get_only_editable(),
    };

    let entries = match dictionaries.borrow().library_matching(&filter) {
        Ok(entries) => entries,
        Err(error) => {
            window.set_dictionaries_message(crate::lingua::schermo(error.operator_message()));
            window.set_dictionaries(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
            window.set_dictionaries_usable_count(0);
            return;
        }
    };

    let usable = entries.iter().filter(|entry| entry.is_usable()).count();
    let rows: Vec<DictionaryEntry> = entries.iter().map(row).collect();

    window.set_dictionaries(ModelRc::from(Rc::new(VecModel::from(rows))));
    window.set_dictionaries_usable_count(i32::try_from(usable).unwrap_or(i32::MAX));
}

/// Collega i comandi della schermata al servizio.
pub fn wire(window: &AppWindow, dictionaries: &SharedDictionaries) {
    {
        let handle = window.as_weak();
        let service = Rc::clone(dictionaries);
        window.on_dictionaries_shown(move || {
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service, Some(""));
                window.set_dictionary_download_message(SharedString::new());
                refresh_network(&window, &service);
            }
        });
    }

    // La fonte e i firmatari (DICT-NET-01, ADR-0178). Il servizio decide chi
    // può scriverli: in modalità operatore il pulsante non c'è, e se ci fosse
    // il rifiuto verrebbe comunque dal servizio.
    {
        let handle = window.as_weak();
        let service = Rc::clone(dictionaries);
        window.on_save_dictionary_source(move || {
            if crate::lock::refuse_while_locked("save_dictionary_source") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let fonte = window.get_dictionary_source().to_string();
            let firmatari = window.get_dictionary_signers().to_string();
            let esito = save_source(&service, &fonte, &firmatari);
            refresh_network(&window, &service);
            match esito {
                Ok(()) => window.set_dictionary_source_note(crate::lingua::schermo(format!(
                    "Fonte e firmatari salvati.\n\n{}",
                    window.get_dictionary_source_note()
                ))),
                // Rifiutati, i valori scritti restano nei campi, da correggere.
                Err(message) => {
                    window.set_dictionary_source(SharedString::from(fonte));
                    window.set_dictionary_signers(SharedString::from(firmatari));
                    window.set_dictionary_source_note(crate::lingua::schermo(message));
                }
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(dictionaries);
        window.on_download_dictionary(move || {
            if crate::lock::refuse_while_locked("download_dictionary") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = download(&service);
            refresh(&window, &service, None);
            refresh_network(&window, &service);
            window.set_dictionary_download_message(crate::lingua::schermo(message));
        });
    }

    // Import da disco. Fino al 2026-07-31 `DictionaryService::import` non era
    // chiamata da alcun punto dell'interfaccia: il formato di scambio esisteva,
    // era collaudato, ed era usato soltanto dai dizionari che il prodotto
    // stesso spedisce. Il quinto motore costruito e mai invocato di questa
    // serie.
    {
        let handle = window.as_weak();
        let service = Rc::clone(dictionaries);
        window.on_dictionaries_import(move || {
            if crate::lock::refuse_while_locked("dictionaries_import") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = import_from_path(&service, window.get_dictionary_import_path().as_str());
            window.set_dictionary_import_path(SharedString::new());
            refresh(&window, &service, Some(&message));
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(dictionaries);
        window.on_dictionaries_choose_file(move || {
            if crate::lock::refuse_while_locked("dictionaries_choose_file") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            // Annullare non e' un errore e non produce messaggi: la schermata
            // resta com'era.
            let service = Rc::clone(&service);
            crate::dialogs::ask(
                &window,
                dictionary_file_dialog(),
                crate::dialogs::Pick::File,
                "dictionaries_choose_file",
                move |window, path| {
                    let message = import_from_path(&service, &path.to_string_lossy());
                    window.set_dictionary_import_path(SharedString::new());
                    refresh(window, &service, Some(&message));
                },
            );
        });
    }

    {
        let handle = window.as_weak();
        let service = Rc::clone(dictionaries);
        window.on_duplicate_dictionary(move |dictionary_id| {
            if crate::lock::refuse_while_locked("duplicate_dictionary") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = duplicate(&service, i64::from(dictionary_id));
            refresh(&window, &service, Some(&message));
        });
    }

    // ESPORTARE DALLA SCHERMATA (NEXUM97-MINOR-FIX-01, GAP-19).
    {
        let handle = window.as_weak();
        let service = Rc::clone(dictionaries);
        window.on_export_dictionary(move |dictionary_id| {
            if crate::lock::refuse_while_locked("export_dictionary") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let service = Rc::clone(&service);
            crate::dialogs::ask(
                &window,
                export_file_dialog(),
                crate::dialogs::Pick::Save,
                "export_dictionary",
                move |window, path| {
                    let message = export_to_path(&service, i64::from(dictionary_id), &path, false);
                    refresh(window, &service, Some(&message));
                },
            );
        });
    }

    // ESPORTARE E FIRMARE (SIGN-01 parte 4, DEC-465): soltanto con un
    // certificato scelto, e la firma si chiede dopo che il file è scritto.
    {
        let handle = window.as_weak();
        let service = Rc::clone(dictionaries);
        window.on_export_dictionary_signed(move |dictionary_id| {
            if crate::lock::refuse_while_locked("export_dictionary_signed") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let service = Rc::clone(&service);
            crate::dialogs::ask(
                &window,
                export_file_dialog(),
                crate::dialogs::Pick::Save,
                "export_dictionary_signed",
                move |window, path| {
                    let message = export_to_path(&service, i64::from(dictionary_id), &path, true);
                    refresh(window, &service, Some(&message));
                },
            );
        });
    }

    {
        let handle = window.as_weak();
        let service = Rc::clone(dictionaries);
        window.on_archive_dictionary(move |dictionary_id| {
            if crate::lock::refuse_while_locked("archive_dictionary") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = archive(&service, i64::from(dictionary_id));
            refresh(&window, &service, Some(&message));
        });
    }

    {
        let handle = window.as_weak();
        let service = Rc::clone(dictionaries);
        window.on_filter_dictionaries(move || {
            if crate::lock::refuse_while_locked("filter_dictionaries") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                // Cambiare la ricerca invalida l'anteprima: mostrarla accanto a
                // un elenco che non contiene piu' quel dizionario confonderebbe.
                clear_preview(&window);
                refresh(&window, &service, None);
            }
        });
    }

    {
        let handle = window.as_weak();
        let service = Rc::clone(dictionaries);
        window.on_preview_dictionary(move |dictionary_id| {
            if crate::lock::refuse_while_locked("preview_dictionary") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                show_preview(&window, &service, i64::from(dictionary_id));
            }
        });
    }

    // Modifica della bozza: i tre comandi che chiudono il percorso duplicare →
    // adattare → pubblicare, che fino al 2026-08-01 si fermava al primo passo.
    {
        let handle = window.as_weak();
        let service = Rc::clone(dictionaries);
        window.on_add_draft_term(move || {
            if crate::lock::refuse_while_locked("add_draft_term") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = add_draft_term(&window, &service);
            show_preview(
                &window,
                &service,
                i64::from(window.get_selected_dictionary()),
            );
            refresh(&window, &service, Some(&message));
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(dictionaries);
        window.on_remove_draft_term(move |term_id| {
            if crate::lock::refuse_while_locked("remove_draft_term") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let dictionary_id = i64::from(window.get_selected_dictionary());
            let message = remove_draft_term(&service, dictionary_id, i64::from(term_id));
            show_preview(&window, &service, dictionary_id);
            refresh(&window, &service, Some(&message));
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(dictionaries);
        window.on_publish_draft(move || {
            if crate::lock::refuse_while_locked("publish_draft") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let dictionary_id = i64::from(window.get_selected_dictionary());
            let message = publish_draft(&service, dictionary_id);
            show_preview(&window, &service, dictionary_id);
            refresh(&window, &service, Some(&message));
        });
    }

    {
        let handle = window.as_weak();
        let service = Rc::clone(dictionaries);
        window.on_start_new_version(move |dictionary_id| {
            if crate::lock::refuse_while_locked("start_new_version") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = start_new_version(&service, i64::from(dictionary_id));
            // La bozza appena aperta si mostra subito: e' quella su cui si lavora.
            show_preview(&window, &service, i64::from(dictionary_id));
            refresh(&window, &service, Some(&message));
        });
    }

    {
        let handle = window.as_weak();
        let service = Rc::clone(dictionaries);
        window.on_switch_to_operator(move || {
            if crate::lock::refuse_while_locked("switch_to_operator") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = switch_mode(&service, &window, true);
            // La parola viene svuotata **sempre**, anche quando il passaggio
            // fallisce: un valore riservato non resta nel widget dopo l'uso.
            window.set_unlock_input(SharedString::new());
            window.set_station_message(crate::lingua::schermo(message));
            refresh(&window, &service, None);
        });
    }

    {
        let handle = window.as_weak();
        let service = Rc::clone(dictionaries);
        window.on_switch_to_administrator(move || {
            if crate::lock::refuse_while_locked("switch_to_administrator") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = switch_mode(&service, &window, false);
            window.set_unlock_input(SharedString::new());
            window.set_station_message(crate::lingua::schermo(message));
            refresh(&window, &service, None);
        });
    }
}

/// Quanti tentativi mostra il registro sulla schermata.
const SHOWN_DOWNLOADS: usize = 10;

/// Riporta nella schermata la fonte, i firmatari e il registro.
///
/// È separata da [`refresh`]: quella corre a ogni filtro, e riscrivere i campi
/// a ogni filtro cancellerebbe ciò che l'amministratore sta scrivendo.
fn refresh_network(window: &AppWindow, dictionaries: &SharedDictionaries) {
    let servizio = dictionaries.borrow();
    let amministratore = servizio.mode() == OperatingMode::Administrator;

    // Un errore di lettura non diventa «non indicata»: come per l'origine
    // degli aggiornamenti, un campo vuoto inviterebbe a riscrivere ciò che
    // forse c'è già.
    let letti = servizio
        .dictionary_source()
        .and_then(|fonte| Ok((fonte, servizio.dictionary_signers()?)));
    match letti {
        Ok((fonte, firmatari)) => {
            window.set_dictionary_source(SharedString::from(fonte.clone().unwrap_or_default()));
            window.set_dictionary_signers(SharedString::from(firmatari.join(", ")));
            window.set_dictionary_source_note(SharedString::from(source_note(
                fonte.is_some(),
                firmatari.len(),
                amministratore,
            )));
        }
        Err(error) => {
            tracing::warn!(kind = error.kind(), "fonte dei dizionari non letta");
            window.set_dictionary_source(SharedString::new());
            window.set_dictionary_signers(SharedString::new());
            window.set_dictionary_source_note(crate::lingua::schermo(error.operator_message()));
        }
    }

    let registro = match servizio.dictionary_downloads() {
        Ok(righe) => downloads_text(&righe),
        Err(error) => error.operator_message(),
    };
    window.set_dictionary_downloads_text(SharedString::from(registro));
}

/// La frase sotto i campi: che cosa succede premendo, con ciò che c'è scritto.
fn source_note(has_source: bool, signers: usize, administrator: bool) -> String {
    let stato = if !has_source || signers == 0 {
        String::from(
            "Senza indirizzo o senza firmatari ammessi il programma non va in rete per i dizionari.",
        )
    } else if signers == 1 {
        String::from("Fonte indicata, un firmatario ammesso.")
    } else {
        format!("Fonte indicata, {signers} firmatari ammessi.")
    };
    if administrator {
        stato
    } else {
        format!("{stato} La fonte e i firmatari si scrivono in modalità amministratore.")
    }
}

/// Divide l'elenco dei firmatari scritto nel campo.
///
/// Le virgole e i punti e virgola separano; gli spazi no, perché Windows
/// mostra un'impronta a gruppi separati da spazi.
fn split_signers(written: &str) -> Vec<&str> {
    written
        .split([',', ';', '\n'])
        .map(str::trim)
        .filter(|impronta| !impronta.is_empty())
        .collect()
}

/// Scrive la fonte e poi i firmatari; il primo rifiuto ferma il secondo.
fn save_source(
    dictionaries: &SharedDictionaries,
    source: &str,
    signers: &str,
) -> Result<(), String> {
    let Ok(attore) = actor() else {
        return Err(String::from(crate::account::NON_SI_SA_CHI_OPERA));
    };
    let fonte = source.trim();
    let fonte = if fonte.is_empty() { None } else { Some(fonte) };
    let mut servizio = dictionaries.borrow_mut();
    servizio
        .set_dictionary_source(fonte, &attore, now())
        .and_then(|()| servizio.set_dictionary_signers(&split_signers(signers), &attore, now()))
        .map_err(|error| {
            tracing::warn!(kind = error.kind(), "fonte dei dizionari non cambiata");
            error.operator_message()
        })
}

/// Scarica il dizionario dalla fonte e restituisce la frase dell'esito.
fn download(dictionaries: &SharedDictionaries) -> String {
    let Ok(attore) = actor() else {
        return String::from(crate::account::NON_SI_SA_CHI_OPERA);
    };
    let esito = dictionaries
        .borrow_mut()
        .download_dictionary(&attore, now());
    match esito {
        Ok(esito) => esito.operator_message(),
        Err(error) => error.operator_message(),
    }
}

/// Il registro dei tentativi, dal più recente, in righe da leggere.
fn downloads_text(rows: &[StoredDictionaryDownload]) -> String {
    if rows.is_empty() {
        return String::from("Nessun tentativo di scaricamento finora.");
    }
    let mut righe = vec![String::from("Ultimi tentativi:")];
    for riga in rows.iter().take(SHOWN_DOWNLOADS) {
        let esito = match riga.outcome.as_str() {
            "importato" => "entrato in bozza",
            "rifiutato" => "rifiutato",
            _ => "non scaricato",
        };
        let mut testo = format!(
            "{} — {}: {esito}",
            riga.requested_at.to_readable_local(),
            riga.requested_by
        );
        if let (Some(nome), Some(numero)) = (&riga.declared_name, riga.declared_version) {
            testo.push_str(&format!(", «{nome}» versione {numero}"));
        }
        if let Some(perche) = &riga.outcome_detail {
            testo.push_str(&format!(" ({perche})"));
        }
        righe.push(testo);
    }
    righe.join("\n")
}

/// Legge un file di dizionario dal disco, rifiutandolo se e' troppo grande.
///
/// Il tetto si applica **prima** di leggere il contenuto, non dopo: la
/// documentazione di `DictionaryService::import` lo dichiara esplicitamente
/// come compito di chi collega un selettore di file, perche' il servizio
/// riceve i byte e a quel punto il file e' gia' interamente in memoria. Leggere
/// prima e verificare poi significherebbe far scegliere a un file estraneo
/// quanta memoria occupare.
///
/// Non segue collegamenti simbolici in modo speciale ne' interpreta il
/// percorso: si limita a chiedere al sistema operativo la dimensione e, se
/// accettabile, il contenuto.
fn read_dictionary_file(path: &str) -> Result<Vec<u8>, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(String::from("Indicare il percorso del file da importare."));
    }

    // Il messaggio riporta **il percorso davvero tentato**. Dire solo "non
    // esiste" lascia chi legge senza modo di capire se abbia sbagliato a
    // scrivere, se manchi un pezzo o se il file sia altrove: e' lo stesso
    // difetto - una diagnosi che non localizza nulla - inseguito per tutta la
    // sessione del 2026-07-30. Un percorso non e' un segreto: il prodotto
    // registra gia' la cartella dei log all'avvio.
    let metadata = std::fs::metadata(trimmed).map_err(|_| {
        format!("Il file non esiste o non è leggibile. Percorso provato: «{trimmed}»")
    })?;
    if !metadata.is_file() {
        return Err(format!("Il percorso indicato non è un file: «{trimmed}»"));
    }
    if metadata.len() > MAX_IMPORT_BYTES as u64 {
        return Err(format!(
            "Il file supera il limite di {} MB previsto per un dizionario.",
            MAX_IMPORT_BYTES / (1024 * 1024)
        ));
    }

    std::fs::read(trimmed).map_err(|_| String::from("Il file non è stato letto per intero."))
}

/// Chiede all'operatore quale file importare, con la finestra di sistema.
///
/// Far digitare un percorso a mano a un operatore non tecnico è una cattiva
/// interfaccia: un carattere sbagliato produce un rifiuto che sembra un guasto,
/// ed è successo al primo tentativo reale (2026-08-04). La finestra di sistema
/// toglie il problema alla radice, perché un file scelto esiste per costruzione.
///
/// Il campo di testo resta, e non per ripiego: serve a chi lavora da remoto o
/// con un percorso già negli appunti, e permette di provare l'import senza
/// toccare il mouse.
///
fn dictionary_file_dialog() -> rfd::AsyncFileDialog {
    rfd::AsyncFileDialog::new()
        .set_title("Scegliere il dizionario da importare")
        .add_filter("Dizionario NEXUM/97", &["json"])
}

/// Importa un dizionario dal percorso indicato e restituisce il messaggio.
///
/// Il dizionario entra **personale e in bozza**: non viene pubblicato, perche'
/// un file che entrasse gia' pubblicato scavalcherebbe la sola verifica umana
/// prevista dal percorso.
fn import_from_path(dictionaries: &SharedDictionaries, path: &str) -> String {
    let bytes = match read_dictionary_file(path) {
        Ok(bytes) => bytes,
        Err(message) => return message,
    };

    let Ok(actor) = actor() else {
        return String::from(crate::account::NON_SI_SA_CHI_OPERA);
    };
    let imported = dictionaries.borrow_mut().import(&bytes, &actor, now());
    match imported {
        Ok((_, version_id)) => {
            // L'IMPRONTA DEI TERMINI (GAP-19): la stessa che l'esportazione
            // ha detto sull'altra postazione, da confrontare a vista.
            let impronta = dictionaries
                .borrow()
                .terms_fingerprint(version_id)
                .unwrap_or_else(|_| String::from("non calcolabile"));
            format!(
                "Dizionario importato come personale e in bozza. Controllarne i termini \
                 e pubblicarlo quando è corretto. Impronta dei termini: {impronta}."
            )
        }
        Err(error) => error.operator_message(),
    }
}

/// La finestra di sistema per scegliere dove scrivere il dizionario (GAP-19).
fn export_file_dialog() -> rfd::AsyncFileDialog {
    rfd::AsyncFileDialog::new()
        .set_title("Scegliere dove scrivere il dizionario")
        .add_filter("Dizionario NEXUM/97", &["json"])
        .set_file_name("dizionario.json")
}

/// Esporta la versione pubblicata del dizionario nel file scelto (GAP-19).
///
/// Senza firma la frase lo dice: l'impronta dei termini serve a chi lo
/// riceve per confrontarla con chi lo ha mandato. Con `firma`, il file
/// scritto si firma con il certificato dell'ufficio (SIGN-01, DEC-465).
fn export_to_path(
    dictionaries: &SharedDictionaries,
    dictionary_id: i64,
    path: &Path,
    firma: bool,
) -> String {
    let Ok(actor) = actor() else {
        return String::from(crate::account::NON_SI_SA_CHI_OPERA);
    };
    let service = dictionaries.borrow();
    let version = match service
        .database()
        .latest_published_version(lisi_core::DictionaryId::new(dictionary_id))
    {
        Ok(Some(version)) => version,
        Ok(None) => {
            return String::from(
                "Il dizionario non ha una versione pubblicata: si esporta solo ciò che è pubblicato.",
            );
        }
        Err(error) => return ServiceError::Storage(error).operator_message(),
    };
    match service.export_published(version.id, path, &actor, now()) {
        Ok(impronta) if firma => {
            format!(
                "Dizionario esportato in «{}». Impronta dei termini: {impronta}. {}",
                path.display(),
                crate::signing::sign_dictionary(path)
            )
        }
        Ok(impronta) => format!(
            "Dizionario esportato in «{}». Impronta dei termini: {impronta}. Il file non è \
             firmato: chi lo riceve confronta l'impronta con chi lo ha mandato.",
            path.display()
        ),
        Err(error) => error.operator_message(),
    }
}

/// Livelli offerti dall'elenco a discesa della bozza, nell'ordine mostrato.
///
/// Comprende i valori negativi: un dizionario che non potesse contenerli non
/// saprebbe riconoscere il proprio errore, e segnalerebbe una recensione
/// cinematografica con la stessa forza di una minaccia.
const DRAFT_LEVELS: [i8; 7] = [1, 2, 3, 4, -1, -2, -3];

/// Livello scelto nell'elenco, dall'indice della voce.
///
/// Un indice fuori intervallo ricade sul primo livello utile invece che su
/// zero: zero e' "nessun avviso", e un termine che qualcuno ha scritto in un
/// dizionario non deve finire in uno stato che non segnala nulla.
fn draft_level_from_index(index: i32) -> i8 {
    usize::try_from(index)
        .ok()
        .and_then(|position| DRAFT_LEVELS.get(position).copied())
        .unwrap_or(DRAFT_LEVELS[0])
}

/// Aggiunge un termine alla bozza del dizionario selezionato.
fn add_draft_term(window: &AppWindow, dictionaries: &SharedDictionaries) -> String {
    let dictionary_id = lisi_core::DictionaryId::new(i64::from(window.get_selected_dictionary()));
    let Ok(Some(draft)) = dictionaries.borrow().open_draft(dictionary_id) else {
        return String::from("Nessuna bozza aperta per questo dizionario.");
    };
    let Ok(actor) = actor() else {
        return String::from(crate::account::NON_SI_SA_CHI_OPERA);
    };

    let level = draft_level_from_index(window.get_draft_level_index());
    let (Ok(text), Ok(category), Ok(language), Ok(suggested_level), Ok(note)) = (
        lisi_core::text::TermText::try_new(window.get_draft_term_input().as_str()),
        lisi_core::text::TermCategory::try_new(window.get_draft_category_input().as_str()),
        lisi_core::text::LanguageTag::try_new("it"),
        lisi_core::model::dictionary::SuggestedLevel::try_new(level),
        lisi_core::text::TermNote::try_new(""),
    ) else {
        return String::from("Termine o categoria non validi: correggere e riprovare.");
    };

    // Una frase si riconosce dallo spazio, come nel wizard: chiederlo per ogni
    // termine aggiungerebbe un passo a un'operazione che deve restare rapida.
    // Un termine di sole cifre è un codice numerico (DICT-CODES-01,
    // ADR-0170): conta soltanto insieme a un altro termine, e il servizio lo
    // accetta soltanto con il livello 1.
    let scritto = window.get_draft_term_input();
    // UN'ESPRESSIONE SI SCRIVE FRA DUE BARRE, «/vend[eo] armi/» (DICT-REGEX-01,
    // ADR-0187): il testo del termine è quello fra le barre.
    let fra_barre = scritto
        .trim()
        .strip_prefix('/')
        .and_then(|resto| resto.strip_suffix('/'))
        .filter(|dentro| !dentro.trim().is_empty())
        .map(str::to_owned);
    let match_mode = if fra_barre.is_some() {
        lisi_core::model::dictionary::MatchMode::Expression
    } else if lisi_core::model::dictionary::is_digits_only(scritto.as_str()) {
        lisi_core::model::dictionary::MatchMode::NumericCode
    } else if scritto.trim().contains(' ') {
        lisi_core::model::dictionary::MatchMode::Phrase
    } else {
        lisi_core::model::dictionary::MatchMode::NormalizedWord
    };
    let codice = match_mode == lisi_core::model::dictionary::MatchMode::NumericCode;
    let text = match &fra_barre {
        Some(dentro) => match lisi_core::text::TermText::try_new(dentro) {
            Ok(espressione) => espressione,
            Err(_) => return String::from("Espressione non valida: correggere e riprovare."),
        },
        None => text,
    };

    let term = lisi_core::model::dictionary::NewDictionaryTerm {
        version_id: draft.id,
        text,
        category,
        language,
        match_mode,
        suggested_level,
        note,
    };
    match dictionaries
        .borrow_mut()
        .add_terms(draft.id, &[term], &actor, now())
    {
        Ok(_) => {
            window.set_draft_term_input(SharedString::new());
            if codice {
                String::from(
                    "Codice numerico aggiunto alla bozza: conta soltanto insieme a un altro \
                     termine.",
                )
            } else {
                String::from("Termine aggiunto alla bozza.")
            }
        }
        Err(error) => error.operator_message(),
    }
}

/// Toglie un termine dalla bozza.
fn remove_draft_term(
    dictionaries: &SharedDictionaries,
    dictionary_id: i64,
    term_id: i64,
) -> String {
    let Ok(actor) = actor() else {
        return String::from(crate::account::NON_SI_SA_CHI_OPERA);
    };
    match dictionaries.borrow().remove_term(
        lisi_core::DictionaryId::new(dictionary_id),
        lisi_core::DictionaryTermId::new(term_id),
        &actor,
        now(),
    ) {
        Ok(()) => String::from("Termine tolto dalla bozza."),
        Err(error) => error.operator_message(),
    }
}

/// Pubblica la bozza del dizionario selezionato.
///
/// La frase dice **quale** versione è nata e dove la si ritrova: «pubblicata»
/// da sola non diceva che cosa fosse cambiato nell'elenco (F-07).
fn publish_draft(dictionaries: &SharedDictionaries, dictionary_id: i64) -> String {
    let identifier = lisi_core::DictionaryId::new(dictionary_id);
    let Ok(Some(draft)) = dictionaries.borrow().open_draft(identifier) else {
        return String::from("Nessuna bozza aperta per questo dizionario.");
    };
    let Ok(actor) = actor() else {
        return String::from(crate::account::NON_SI_SA_CHI_OPERA);
    };
    let nome = dictionaries
        .borrow()
        .database()
        .dictionary(identifier)
        .map(|d| d.name.as_str().to_owned())
        .unwrap_or_default();
    match dictionaries.borrow().publish(draft.id, &actor, now()) {
        Ok(()) => format!(
            "«{nome}» versione {} pubblicata. Da ora è immutabile; nell'elenco qui sotto \
             compare come «Versione {}», e si sceglie in Nuovo monitoraggio.",
            draft.number, draft.number
        ),
        Err(error) => error.operator_message(),
    }
}

/// Apre una nuova bozza a partire dalla versione pubblicata (F-07).
fn start_new_version(dictionaries: &SharedDictionaries, dictionary_id: i64) -> String {
    let identifier = lisi_core::DictionaryId::new(dictionary_id);
    let Ok(actor) = actor() else {
        return String::from(crate::account::NON_SI_SA_CHI_OPERA);
    };
    let Ok(nota) = lisi_core::text::DictionaryDescription::try_new(
        "Nuova versione aperta dalla schermata Dizionari",
    ) else {
        return String::from("La nota della nuova versione non è valida.");
    };
    let esito = dictionaries
        .borrow_mut()
        .start_new_version(identifier, &nota, &actor, now());
    match esito {
        Ok(_) => {
            let servizio = dictionaries.borrow();
            let numero = servizio
                .open_draft(identifier)
                .ok()
                .flatten()
                .map_or(0, |bozza| bozza.number);
            format!(
                "Bozza della versione {numero} aperta, con i termini della versione pubblicata, \
                 che resta com'è. Si modifica qui sotto; «Prova nel Laboratorio» mostra che cosa \
                 cambia prima di pubblicarla."
            )
        }
        Err(error) => error.operator_message(),
    }
}

/// Svuota l'anteprima.
fn clear_preview(window: &AppWindow) {
    window.set_preview_title(SharedString::new());
    window.set_preview_note(SharedString::new());
    window.set_preview_terms(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
}

/// Mostra i termini della versione pubblicata del dizionario indicato.
fn show_preview(window: &AppWindow, dictionaries: &SharedDictionaries, dictionary_id: i64) {
    let identifier = lisi_core::DictionaryId::new(dictionary_id);
    let service = dictionaries.borrow();
    // La domanda «Pubblicare?» appartiene alla bozza per cui era stata aperta:
    // mostrata accanto a un'altra, pubblicherebbe quella sbagliata.
    window.set_publish_armed(false);

    let Ok(dictionary) = service.database().dictionary(identifier) else {
        clear_preview(window);
        window.set_dictionaries_message(crate::lingua::schermo(
            "Il contenuto di questo dizionario non è leggibile.",
        ));
        return;
    };

    // Con una bozza aperta si mostrano i **suoi** termini, non quelli
    // pubblicati: sono ciò che l'operatore sta modificando, e mostrare la
    // versione pubblicata mentre si lavora sulla bozza farebbe credere che le
    // aggiunte non abbiano avuto effetto.
    let draft = service.open_draft(identifier).ok().flatten();
    let terms = match draft.as_ref() {
        Some(version) => service.terms(version.id),
        None => service.published_terms(identifier),
    };
    let Ok(terms) = terms else {
        clear_preview(window);
        window.set_dictionaries_message(crate::lingua::schermo(
            "Il contenuto di questo dizionario non è leggibile.",
        ));
        return;
    };

    window.set_draft_open(draft.is_some());
    window.set_draft_title(SharedString::from(match draft.as_ref() {
        Some(version) => format!("{} v{}", dictionary.name.as_str(), version.number),
        None => String::new(),
    }));

    let rows: Vec<TermEntry> = terms
        .iter()
        .map(|term| TermEntry {
            // Zero per una versione pubblicata: da lì non si toglie nulla, ed è
            // il modo in cui l'interfaccia distingue i due casi senza doverne
            // sapere di più.
            term_id: draft
                .as_ref()
                .and_then(|_| i32::try_from(term.id.get()).ok())
                .unwrap_or(0),
            text: SharedString::from(term.text.as_str()),
            category: SharedString::from(term.category.as_str()),
            match_mode: crate::lingua::schermo(term.match_mode.label()),
            // Il livello è reso in testo con il segno: letto come numero da un
            // widget, il meno di un termine mitigante potrebbe perdersi.
            suggested_level: crate::lingua::schermo(format!("{:+}", term.suggested_level.get())),
            mitigating: term.suggested_level.is_mitigating(),
            note: SharedString::from(term.note.as_str()),
        })
        .collect();

    window.set_preview_title(crate::lingua::schermo(format!(
        "{} \u{00b7} {} termini",
        dictionary.name.as_str(),
        rows.len()
    )));
    window.set_preview_note(crate::lingua::schermo(
        "Il livello è il suggerimento di chi ha compilato il dizionario, non l'esito \
         di un'analisi. I valori negativi abbassano il peso di un riscontro.",
    ));
    // Riscontro immediato nella fascia dei messaggi, che sta **in alto** ed e'
    // sempre visibile. Il pannello dell'anteprima e' dichiarato dopo l'elenco
    // dei dizionari: con l'elenco lungo compare sotto il bordo della finestra,
    // e l'operatore vede un pulsante che non fa nulla mentre in realta' ha
    // funzionato (rilevato dall'operatore il 2026-08-01). Una riga in alto
    // dice che e' successo qualcosa e dove guardare.
    window.set_dictionaries_message(crate::lingua::schermo(format!(
        "Termini di «{}» mostrati in fondo alla schermata: {} voci.",
        dictionary.name.as_str(),
        terms.len()
    )));
    window.set_preview_terms(ModelRc::from(Rc::new(VecModel::from(rows))));
}

/// Esegue un passaggio di modalità e produce il messaggio per l'operatore.
fn switch_mode(dictionaries: &SharedDictionaries, window: &AppWindow, to_operator: bool) -> String {
    let word = window.get_unlock_input().to_string();

    let Ok(actor) = actor() else {
        return String::from(crate::account::NON_SI_SA_CHI_OPERA);
    };

    let outcome = if to_operator {
        dictionaries
            .borrow_mut()
            .switch_to_operator_mode(&word, &actor, now())
    } else {
        dictionaries
            .borrow_mut()
            .switch_to_administrator_mode(&word, &actor, now())
    };

    match outcome {
        Ok(()) if to_operator => String::from(
            "La postazione è ora in modalità operatore. La parola fissata è l'unico modo \
             per tornare amministratore conservando questa configurazione.",
        ),
        Ok(()) => String::from("La postazione è tornata in modalità amministratore."),
        Err(error) => error.operator_message(),
    }
}

/// Duplica un dizionario, dandogli un nome libero.
///
/// Il nome della copia porta un suffisso progressivo invece di chiedere subito
/// all'operatore: un dialogo modale prima ancora di sapere se la copia serva
/// interromperebbe il lavoro per una decisione che si può cambiare dopo.
fn duplicate(dictionaries: &SharedDictionaries, dictionary_id: i64) -> String {
    let identifier = lisi_core::DictionaryId::new(dictionary_id);

    let Ok(actor) = actor() else {
        return String::from(crate::account::NON_SI_SA_CHI_OPERA);
    };

    let original = match dictionaries.borrow().database().dictionary(identifier) {
        Ok(dictionary) => dictionary,
        Err(error) => return ServiceError::Storage(error).operator_message(),
    };

    // Si cerca il primo nome libero. Il limite evita che un errore ripetuto
    // diventi un ciclo lungo quanto la pazienza dell'operatore.
    for attempt in 1..=32_u32 {
        let candidate = format!("{} (copia {attempt})", original.name.as_str());
        let Ok(name) = lisi_core::text::DictionaryName::try_new(&candidate) else {
            return String::from("Il nome della copia non è valido.");
        };

        match dictionaries
            .borrow_mut()
            .duplicate(identifier, &name, &actor, now())
        {
            Ok(_) => return format!("Creata la copia \"{candidate}\", modificabile liberamente."),
            Err(ServiceError::DictionaryNameAlreadyUsed) => continue,
            Err(error) => return error.operator_message(),
        }
    }

    String::from("Esistono già troppe copie di questo dizionario: rinominarne o rimuoverne una.")
}

/// Archivia un dizionario, togliendolo dalla scelta senza cancellarlo.
fn archive(dictionaries: &SharedDictionaries, dictionary_id: i64) -> String {
    let Ok(actor) = actor() else {
        return String::from(crate::account::NON_SI_SA_CHI_OPERA);
    };

    match dictionaries
        .borrow()
        .remove(lisi_core::DictionaryId::new(dictionary_id), &actor, now())
    {
        Ok(DictionaryRemoval::Deleted) => {
            String::from(DictionaryRemoval::Deleted.operator_message())
        }
        Ok(DictionaryRemoval::Archived) => {
            String::from(DictionaryRemoval::Archived.operator_message())
        }
        Err(error) => error.operator_message(),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use lisi_core::OperatingMode;
    use lisi_services::ServiceError;
    use lisi_services::dictionaries::DictionaryService;
    use lisi_services::dictionary_download::StoredDictionaryDownload;

    use super::{
        DRAFT_LEVELS, MAX_IMPORT_BYTES, SharedDictionaries, archive, create_service, download,
        downloads_text, draft_level_from_index, duplicate, read_dictionary_file, row, save_source,
        source_note, split_signers,
    };

    /// Servizio su un archivio privato del test.
    ///
    /// I test **non devono toccare l'archivio di esercizio**: scriverci
    /// significherebbe alterare le fonti e i dizionari dell'operatore, e far
    /// dipendere l'esito di un test da quello che c'e' gia' sulla postazione.
    fn test_service() -> Option<SharedDictionaries> {
        let database = lisi_services::sources::open_in_memory_database().ok()?;
        create_service(database)
    }

    #[test]
    fn the_shipped_dictionaries_are_installed_at_startup() {
        let Some(service) = test_service() else {
            panic!("il servizio deve potersi creare");
        };
        let Ok(entries) = service.borrow().library() else {
            panic!("la libreria deve potersi leggere");
        };

        assert!(!entries.is_empty(), "l'elenco non deve essere vuoto");
        for entry in &entries {
            assert!(entry.is_usable(), "un seed installato deve essere usabile");
            assert!(entry.published_terms > 0);
        }
    }

    #[test]
    fn a_row_says_why_a_dictionary_is_not_usable() {
        // La riga porta la ragione gia' calcolata: se fosse vuota, l'operatore
        // vedrebbe un dizionario inerte senza sapere che cosa manca.
        let Some(service) = test_service() else {
            panic!("il servizio deve potersi creare");
        };
        let Ok(entries) = service.borrow().library() else {
            panic!("la libreria deve potersi leggere");
        };

        let usable = row(&entries[0]);
        assert!(usable.usable);
        assert_eq!(usable.unusable_reason.as_str(), "");
        assert!(usable.built_in, "i seed sono di sistema");
        assert!(usable.published_version > 0);
    }

    #[test]
    fn duplicating_a_system_dictionary_gives_a_copy_that_can_be_changed() {
        let Some(service) = test_service() else {
            panic!("il servizio deve potersi creare");
        };
        let identifier = {
            let Ok(entries) = service.borrow().library() else {
                panic!("la libreria deve potersi leggere");
            };
            entries[0].dictionary.id.get()
        };

        let message = duplicate(&service, identifier);
        assert!(message.contains("copia"), "messaggio inatteso: {message}");

        let Ok(entries) = service.borrow().library() else {
            panic!("la libreria deve potersi leggere");
        };
        let Some(copy) = entries
            .iter()
            .find(|entry| entry.dictionary.derived_from.is_some())
        else {
            panic!("la copia deve essere presente");
        };
        assert!(copy.dictionary.is_editable());
        assert!(!copy.is_usable(), "una copia nasce in bozza");
    }

    #[test]
    fn duplicating_twice_does_not_collide_on_the_name() {
        let Some(service) = test_service() else {
            panic!("il servizio deve potersi creare");
        };
        let identifier = {
            let Ok(entries) = service.borrow().library() else {
                panic!("la libreria deve potersi leggere");
            };
            entries[0].dictionary.id.get()
        };

        let (first, second) = (
            duplicate(&service, identifier),
            duplicate(&service, identifier),
        );
        assert!(first.contains("copia 1"), "primo messaggio: {first}");
        assert!(second.contains("copia 2"), "secondo messaggio: {second}");
    }

    #[test]
    fn a_system_dictionary_cannot_be_archived_from_the_screen() {
        // Il pulsante e' disabilitato nell'interfaccia, ma il comando deve
        // rifiutare comunque: un pulsante disabilitato non e' un controllo.
        let Some(service) = test_service() else {
            panic!("il servizio deve potersi creare");
        };
        let identifier = {
            let Ok(entries) = service.borrow().library() else {
                panic!("la libreria deve potersi leggere");
            };
            entries[0].dictionary.id.get()
        };

        let message = archive(&service, identifier);
        assert!(message.contains("Duplica"), "messaggio inatteso: {message}");
    }

    #[test]
    fn archiving_a_personal_copy_takes_it_out_of_the_choice() {
        let Some(service) = test_service() else {
            panic!("il servizio deve potersi creare");
        };
        let identifier = {
            let Ok(entries) = service.borrow().library() else {
                panic!("la libreria deve potersi leggere");
            };
            entries[0].dictionary.id.get()
        };
        let _ = duplicate(&service, identifier);

        let copy = {
            let Ok(entries) = service.borrow().library() else {
                panic!("la libreria deve potersi leggere");
            };
            let Some(copy) = entries
                .iter()
                .find(|entry| entry.dictionary.derived_from.is_some())
            else {
                panic!("la copia deve essere presente");
            };
            copy.dictionary.id.get()
        };

        let message = archive(&service, copy);
        assert!(!message.is_empty());
        let Ok(entries) = service.borrow().library() else {
            panic!("la libreria deve potersi leggere");
        };
        assert!(
            entries
                .iter()
                .all(|entry| entry.dictionary.id.get() != copy)
                || entries
                    .iter()
                    .any(|entry| entry.dictionary.id.get() == copy && !entry.is_usable()),
            "la copia non deve piu' essere proposta"
        );
    }

    #[test]
    fn the_screen_never_borrows_the_service_twice_at_once() {
        // `RefCell` scopre i prestiti sovrapposti solo a runtime: questo test
        // esercita di seguito i percorsi che prendono un prestito mutabile,
        // che e' il modo in cui un errore del genere si manifesterebbe.
        let Some(service) = test_service() else {
            panic!("il servizio deve potersi creare");
        };
        let identifier = {
            let Ok(entries) = service.borrow().library() else {
                panic!("la libreria deve potersi leggere");
            };
            entries[0].dictionary.id.get()
        };

        let _ = duplicate(&service, identifier);
        let _ = archive(&service, identifier);
        let _ = duplicate(&service, identifier);

        assert!(service.borrow().library().is_ok());
        let _: &DictionaryService = &service.borrow();
    }

    /// Il tetto di dimensione agisce **prima** di leggere il contenuto.
    ///
    /// Il servizio riceve i byte, quindi a quel punto il file e' gia'
    /// interamente in memoria: verificare dopo significherebbe far scegliere a
    /// un file estraneo quanta memoria occupare. La documentazione di
    /// `DictionaryService::import` lo dichiara come compito di chi collega il
    /// percorso da disco, ed e' questo.
    #[test]
    fn a_file_over_the_limit_is_refused_without_being_read() {
        let directory = std::env::temp_dir().join(format!(
            "nexum-import-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos())
        ));
        let Ok(()) = std::fs::create_dir_all(&directory) else {
            panic!("la cartella di prova deve potersi creare");
        };
        let oversized = directory.join("troppo-grande.json");
        // Un byte oltre il tetto basta: il contenuto non viene mai guardato.
        let Ok(()) = std::fs::write(&oversized, vec![b'{'; MAX_IMPORT_BYTES + 1]) else {
            panic!("il file di prova deve potersi scrivere");
        };

        let Err(message) = read_dictionary_file(&oversized.to_string_lossy()) else {
            panic!("un file oltre il tetto deve essere rifiutato");
        };
        assert!(
            message.contains("limite"),
            "il rifiuto deve dire all'operatore qual e' il limite: {message}"
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    /// Un percorso che non esiste, o che non e' un file, va rifiutato con un
    /// messaggio che dice che cosa non va — non con un errore tecnico.
    #[test]
    fn a_missing_path_and_a_directory_are_both_refused_with_a_readable_reason() {
        let Err(empty) = read_dictionary_file("   ") else {
            panic!("un percorso vuoto deve essere rifiutato");
        };
        assert!(empty.contains("percorso"));

        let Err(missing) = read_dictionary_file("C:\\percorso\\che\\non\\esiste\\x.json") else {
            panic!("un percorso inesistente deve essere rifiutato");
        };
        assert!(missing.contains("non esiste") || missing.contains("leggibile"));

        let directory = std::env::temp_dir();
        let Err(not_a_file) = read_dictionary_file(&directory.to_string_lossy()) else {
            panic!("una cartella non e' un file da importare");
        };
        assert!(not_a_file.contains("non è un file"));
    }

    /// L'elenco a discesa della bozza offre anche i livelli **negativi**.
    ///
    /// Un dizionario che non potesse contenerli non saprebbe riconoscere il
    /// proprio errore, e segnalerebbe una recensione cinematografica con la
    /// stessa forza di una minaccia: è la ragione per cui il dizionario
    /// «Contesto riduttivo» esiste.
    #[test]
    fn the_draft_levels_include_the_mitigating_ones() {
        assert!(
            DRAFT_LEVELS.iter().any(|level| *level < 0),
            "senza livelli negativi un dizionario non puo' correggersi: {DRAFT_LEVELS:?}"
        );
        assert!(DRAFT_LEVELS.iter().any(|level| *level > 0));
        assert!(
            !DRAFT_LEVELS.contains(&0),
            "zero non segnala nulla: non va offerto come scelta"
        );
    }

    /// Ogni voce dell'elenco vale il proprio livello, e nessun indice — nemmeno
    /// assurdo — produce zero.
    #[test]
    fn every_index_maps_to_a_level_that_does_something() {
        for (index, expected) in DRAFT_LEVELS.iter().enumerate() {
            let Ok(position) = i32::try_from(index) else {
                panic!("l'indice di prova deve essere rappresentabile");
            };
            assert_eq!(draft_level_from_index(position), *expected);
        }

        for absurd in [-1, i32::MIN, 99, i32::MAX] {
            assert_ne!(
                draft_level_from_index(absurd),
                0,
                "l'indice {absurd} non deve produrre un livello che non segnala"
            );
        }
    }

    /// Un servizio su un archivio privato, nella modalità chiesta.
    fn service_in(mode: OperatingMode) -> SharedDictionaries {
        let Ok(database) = lisi_services::sources::open_in_memory_database() else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        Rc::new(RefCell::new(DictionaryService::with_mode(database, mode)))
    }

    /// Un'impronta di prova: 64 cifre, nessun certificato vero.
    const IMPRONTA: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn the_note_says_that_without_source_or_signers_nothing_goes_out() {
        for (fonte, firmatari) in [(false, 0), (false, 2), (true, 0)] {
            assert!(
                source_note(fonte, firmatari, true).contains("non va in rete"),
                "fonte {fonte}, firmatari {firmatari}"
            );
        }
        assert_eq!(
            source_note(true, 1, true),
            "Fonte indicata, un firmatario ammesso."
        );
        assert!(source_note(true, 3, true).contains("3 firmatari"));
        // L'operatore sa perché i campi sono spenti.
        assert!(source_note(true, 3, false).contains("modalità amministratore"));
        assert!(!source_note(true, 3, true).contains("modalità amministratore"));
    }

    #[test]
    fn signers_split_on_commas_and_not_on_spaces() {
        assert_eq!(
            split_signers(" ab cd , ef:01;\n, 23 "),
            vec!["ab cd", "ef:01", "23"]
        );
        assert!(split_signers("  ,; ").is_empty());
    }

    #[test]
    fn the_administrator_saves_source_and_signers_and_the_operator_does_not() {
        let amministratore = service_in(OperatingMode::Administrator);
        let firmatari = format!("{}, {IMPRONTA}", IMPRONTA.to_uppercase());
        assert_eq!(
            save_source(
                &amministratore,
                " https://ufficio.example/dizionario.json ",
                &firmatari
            ),
            Ok(())
        );
        let servizio = amministratore.borrow();
        assert_eq!(
            servizio.dictionary_source().ok().flatten().as_deref(),
            Some("https://ufficio.example/dizionario.json")
        );
        assert_eq!(
            servizio.dictionary_signers().ok(),
            Some(vec![IMPRONTA.to_owned()])
        );
        drop(servizio);

        // Un indirizzo in chiaro si rifiuta e i firmatari non si toccano.
        assert!(save_source(&amministratore, "http://ufficio.example/d.json", "").is_err());
        assert_eq!(
            amministratore
                .borrow()
                .dictionary_signers()
                .ok()
                .map(|elenco| elenco.len()),
            Some(1)
        );

        let operatore = service_in(OperatingMode::Operator);
        assert!(save_source(&operatore, "https://ufficio.example/d.json", IMPRONTA).is_err());
        assert_eq!(operatore.borrow().dictionary_source().ok(), Some(None));
    }

    #[test]
    fn without_a_source_the_download_says_so_and_writes_nothing() {
        let servizio = service_in(OperatingMode::Operator);
        assert_eq!(
            download(&servizio),
            ServiceError::DictionarySourceMissing.operator_message()
        );
        let Ok(righe) = servizio.borrow().dictionary_downloads() else {
            panic!("il registro deve potersi leggere");
        };
        assert!(righe.is_empty(), "senza rete non c'è tentativo da scrivere");
        assert_eq!(
            downloads_text(&righe),
            "Nessun tentativo di scaricamento finora."
        );
    }

    #[test]
    fn the_register_reads_each_attempt_with_its_outcome() {
        let riga = |outcome: &str, detail: Option<&str>, nome: Option<(&str, u32)>| {
            StoredDictionaryDownload {
                id: 1,
                requested_by: String::from("operatore di prova"),
                requested_at: lisi_core::Timestamp::from_millis(0),
                url: String::from("https://ufficio.example/d.json"),
                content_sha256: None,
                signer_sha256: None,
                declared_name: nome.map(|(nome, _)| nome.to_owned()),
                declared_version: nome.map(|(_, numero)| numero),
                outcome: outcome.to_owned(),
                outcome_detail: detail.map(str::to_owned),
                dictionary_id: None,
                version_id: None,
            }
        };
        let testo = downloads_text(&[
            riga("importato", None, Some(("Termini d'ufficio", 3))),
            riga("rifiutato", Some("firmatario non ammesso"), None),
            riga("non_riuscito", Some("la fonte non risponde"), None),
        ]);
        let righe: Vec<&str> = testo.lines().collect();
        assert_eq!(righe.len(), 4);
        assert!(
            righe[1]
                .ends_with("operatore di prova: entrato in bozza, «Termini d'ufficio» versione 3")
        );
        assert!(righe[2].ends_with(": rifiutato (firmatario non ammesso)"));
        assert!(righe[3].ends_with(": non scaricato (la fonte non risponde)"));

        let molte: Vec<StoredDictionaryDownload> =
            (0..15).map(|_| riga("rifiutato", None, None)).collect();
        assert_eq!(
            downloads_text(&molte).lines().count(),
            1 + super::SHOWN_DOWNLOADS
        );
    }
}

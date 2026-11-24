//! La schermata dei workspace operativi (WS-02).
//!
//! # Che cosa questa schermata mostra, e che cosa non tiene
//!
//! Mostra i contenitori di lavoro e ciò che hanno raccolto. **Non tiene una
//! copia del materiale**: ogni riga porta l'etichetta che il servizio ha
//! risolto **al momento del disegno**, e la si rilegge a ogni apertura.
//!
//! Non è una precauzione di questo modulo: `ArchiveRef` è `Copy` e non può
//! portare un testo, e la tabella non ha una colonna in cui una copia possa
//! stare (WS-01). Qui c'è la conseguenza — si rilegge invece di ricordare.
//!
//! # Un riferimento che non arriva più a nulla si vede
//!
//! Il riferimento è polimorfico e non ha una chiave esterna: ciò a cui punta
//! può essere stato cancellato. Quella riga **non si filtra via**. Comparirebbe
//! altrimenti un elenco che dice «questo workspace non ha mai raccolto quella
//! cosa», che è falso.
//!
//! # Non esiste un comando che riapre
//!
//! L'archivio rifiuta la riapertura con un trigger, e un comando che fallisce
//! sempre è peggio di un comando assente: insegna che il programma non
//! funziona. Su un workspace chiuso i comandi **non compaiono**.
//!
//! # Da dove si raccoglie
//!
//! Non da qui. Si raccoglie **dove il materiale è** — dallo Storico, davanti al
//! contenuto — perché chiedere a una persona di trascrivere un identificativo
//! sarebbe chiederle di fare il lavoro che il programma dovrebbe fare.
//!
//! Il workspace in cui si raccoglie è **quello selezionato qui**, e il comando
//! dello Storico lo dice per nome: se non ce n'è uno selezionato, lo dichiara
//! invece di indovinare.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_core::model::workspace::{ArchiveRef, ArchiveRefKind, NewWorkspace};
use lisi_core::text::{DisplayName, Note};
use lisi_core::{Timestamp, WorkspaceId};
use lisi_services::workspace::WorkspaceService;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::{AppWindow, WorkspaceEntryRow, WorkspaceRow};

/// Servizio dei workspace, condiviso fra i gestori dei comandi.
pub type SharedWorkspaces = Rc<RefCell<WorkspaceService>>;

/// Costruisce il servizio sull'archivio indicato.
///
/// # Perché un archivio proprio
///
/// Perché aprire, raccogliere e chiudere **scrivono**, e scrivere vuole
/// l'archivio mutabile: condividerlo con i servizi in sola lettura
/// significherebbe prestarlo mutabile a tutti.
#[must_use]
pub fn create_service(database: lisi_services::Database) -> Option<SharedWorkspaces> {
    Some(Rc::new(RefCell::new(WorkspaceService::new(database))))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> Timestamp {
    lisi_core::time::anchored_now()
}

/// Rilegge l'elenco dei workspace e ciò che il selezionato contiene.
///
/// # Perché si rilegge invece di ricordare
///
/// Perché un workspace **riferisce senza copiare**: ciò che mostra deve essere
/// ciò che l'archivio dice adesso. Tenere le righe fra un disegno e l'altro
/// sarebbe la seconda copia che WS-01 esiste per impedire, ricostruita qui.
pub fn refresh(window: &AppWindow, workspaces: &SharedWorkspaces) {
    let servizio = workspaces.borrow();

    let Ok(elenco) = servizio.all() else {
        window.set_workspace_message(crate::lingua::schermo(
            "L'elenco dei raccoglitori non \u{e8} leggibile in questo momento: quello qui sotto non \
             dice che non ce ne siano.",
        ));
        window.set_workspace_rows(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        window.set_workspace_entries(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        return;
    };

    let righe: Vec<WorkspaceRow> = elenco
        .iter()
        .map(|workspace| WorkspaceRow {
            id: i32::try_from(workspace.id.get()).unwrap_or(i32::MAX),
            name: SharedString::from(workspace.name.as_str()),
            // LA FRASE LA COMPONE IL MODELLO (DEC-252): dice chi lo ha aperto,
            // quando, e che non conserva copie.
            // La descrizione scritta aprendolo si legge qui (F-29): prima
            // l'archivio la conservava e nessuna schermata la mostrava.
            sentence: SharedString::from(match &workspace.description {
                Some(descrizione) => format!(
                    "{} A che cosa serve: {}",
                    workspace.as_sentence(),
                    descrizione.as_str()
                ),
                None => workspace.as_sentence(),
            }),
            open: workspace.accepts_items(),
        })
        .collect();
    window.set_workspace_rows(ModelRc::from(Rc::new(VecModel::from(righe))));

    // IL SELEZIONATO, e cio' che ha raccolto.
    let selezionato = window.get_workspace_selected();
    if selezionato <= 0 {
        window.set_workspace_entries(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        window.set_workspace_selected_name(SharedString::default());
        window.set_workspace_selected_open(false);
        return;
    }

    let id = WorkspaceId::new(i64::from(selezionato));
    let Ok((workspace, elementi)) = servizio.contents(id) else {
        // Il workspace selezionato non c'e' piu', o non e' leggibile: la
        // selezione si svuota invece di mostrare le righe di un altro.
        window.set_workspace_selected(0);
        window.set_workspace_selected_name(SharedString::default());
        window.set_workspace_selected_open(false);
        window.set_workspace_entries(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        return;
    };

    window.set_workspace_selected_name(SharedString::from(workspace.name.as_str()));
    window.set_workspace_selected_open(workspace.accepts_items());

    // OGNI RIGA COMPARE, COMPRESA QUELLA CHE NON ARRIVA PIU' A NULLA.
    //
    // Filtrarla produrrebbe un elenco che dice «questo workspace non ha mai
    // raccolto quella cosa», che e' falso.
    let voci: Vec<WorkspaceEntryRow> = elementi
        .iter()
        .map(|elemento| WorkspaceEntryRow {
            kind: SharedString::from(elemento.entry.item.kind().as_str()),
            target_id: i32::try_from(elemento.entry.item.target_id()).unwrap_or(i32::MAX),
            // LA FRASE LA COMPONE IL REPOSITORY, e dice o l'etichetta di adesso
            // o che la cosa non e' piu' nell'archivio.
            sentence: SharedString::from(elemento.target.as_sentence(elemento.entry.item.kind())),
            present: elemento.target.is_present(),
            added: crate::lingua::schermo(format!(
                "raccolto da {} il {}",
                elemento.entry.added_by.as_str(),
                elemento.entry.added_at.to_readable_local()
            )),
        })
        .collect();
    window.set_workspace_entries(ModelRc::from(Rc::new(VecModel::from(voci))));
}

/// Apre un workspace.
fn open_workspace(window: &AppWindow, workspaces: &SharedWorkspaces, name: &str, note: &str) {
    let Ok(nome) = DisplayName::try_new(name) else {
        window.set_workspace_message(crate::lingua::schermo(
            "Un raccoglitore ha bisogno di un nome: \u{e8} quello con cui lo si chiamer\u{e0}.",
        ));
        return;
    };

    // LA DESCRIZIONE E' FACOLTATIVA.
    //
    // Obbligarla produrrebbe descrizioni finte, che e' peggio di nessuna
    // descrizione: farebbero credere che qualcuno abbia detto a che cosa serve.
    let descrizione = if note.trim().is_empty() {
        None
    } else {
        match Note::try_new(note) {
            Ok(nota) => Some(nota),
            Err(_) => {
                window.set_workspace_message(crate::lingua::schermo(
                    "La descrizione contiene qualcosa che non si pu\u{f2} conservare.",
                ));
                return;
            }
        }
    };

    let Ok(attore) = crate::operator::audit_actor() else {
        window.set_workspace_message(crate::lingua::schermo(
            "Non si riesce a stabilire chi stia agendo su questa postazione.",
        ));
        return;
    };

    let esito = workspaces.borrow().open(
        &NewWorkspace {
            name: nome,
            description: descrizione,
            created_by: attore,
        },
        now(),
    );

    match esito {
        Ok(id) => {
            window.set_workspace_new_name(SharedString::default());
            window.set_workspace_new_description(SharedString::default());
            window.set_workspace_selected(i32::try_from(id.get()).unwrap_or(i32::MAX));
            window.set_workspace_message(crate::lingua::schermo(
                "Raccoglitore aperto. Raccoglie riferimenti al materiale dell'archivio, e non ne \
                 conserva copie.",
            ));
        }
        Err(errore) => {
            window.set_workspace_message(crate::lingua::schermo(errore.operator_message()));
        }
    }

    refresh(window, workspaces);
}

/// Chiude un workspace.
fn close_workspace(window: &AppWindow, workspaces: &SharedWorkspaces, id: i32) {
    if id <= 0 {
        return;
    }
    let Ok(attore) = crate::operator::audit_actor() else {
        window.set_workspace_message(crate::lingua::schermo(
            "Non si riesce a stabilire chi stia agendo su questa postazione.",
        ));
        return;
    };

    let esito = workspaces
        .borrow()
        .close(WorkspaceId::new(i64::from(id)), &attore, now());

    match esito {
        Ok(()) => window.set_workspace_message(crate::lingua::schermo(
            "Raccoglitore chiuso. Non accetta n\u{e9} perde elementi, e non si riapre: se il lavoro \
             continua, conviene aprirne un altro.",
        )),
        Err(errore) => {
            window.set_workspace_message(crate::lingua::schermo(errore.operator_message()));
        }
    }

    refresh(window, workspaces);
}

/// Toglie un riferimento dal workspace selezionato.
fn remove_entry(window: &AppWindow, workspaces: &SharedWorkspaces, kind: &str, target_id: i32) {
    let selezionato = window.get_workspace_selected();
    if selezionato <= 0 {
        return;
    }

    let (Ok(genere), Ok(item)) = (
        kind.parse::<ArchiveRefKind>(),
        kind.parse::<ArchiveRefKind>()
            .and_then(|genere| ArchiveRef::to(genere, i64::from(target_id))),
    ) else {
        window.set_workspace_message(crate::lingua::schermo(
            "Questo riferimento non \u{e8} interpretabile: non \u{e8} stato tolto.",
        ));
        return;
    };
    let _ = genere;

    let Ok(attore) = crate::operator::audit_actor() else {
        window.set_workspace_message(crate::lingua::schermo(
            "Non si riesce a stabilire chi stia agendo su questa postazione.",
        ));
        return;
    };

    let esito = workspaces.borrow().remove(
        WorkspaceId::new(i64::from(selezionato)),
        item,
        &attore,
        now(),
    );

    match esito {
        Ok(()) => window.set_workspace_message(crate::lingua::schermo(
            "Riferimento tolto. La cosa referenziata resta dov'era: un raccoglitore raccoglie \
             riferimenti, e toglierne uno non cancella nulla.",
        )),
        Err(errore) => {
            window.set_workspace_message(crate::lingua::schermo(errore.operator_message()));
        }
    }

    refresh(window, workspaces);
}

/// Raccoglie un contenuto nel workspace selezionato.
///
/// # Perché il comando vive nello Storico e la funzione qui
///
/// Perché si raccoglie **dove il materiale è**, e la regola su *quale*
/// workspace è di questo modulo. Se non ce n'è uno selezionato, lo dichiara
/// invece di indovinare.
pub fn collect_content(window: &AppWindow, workspaces: &SharedWorkspaces, content_id: i32) {
    let selezionato = window.get_workspace_selected();
    if selezionato <= 0 || content_id <= 0 {
        window.set_history_message(crate::lingua::schermo(
            "Nessun raccoglitore selezionato: aprire la schermata «Raccoglitori», sceglierne uno \
             o crearlo, poi tornare qui.",
        ));
        return;
    }

    let Ok(item) = ArchiveRef::to(ArchiveRefKind::Content, i64::from(content_id)) else {
        return;
    };
    let Ok(attore) = crate::operator::audit_actor() else {
        return;
    };

    let esito = workspaces.borrow().add(
        WorkspaceId::new(i64::from(selezionato)),
        item,
        &attore,
        now(),
    );

    // LA FRASE DICE IN QUALE WORKSPACE, per nome.
    //
    // «Aggiunto» senza dire dove lascerebbe chi legge a indovinare, e chi
    // indovina sbaglia il giorno in cui ne ha aperti due.
    let nome = window.get_workspace_selected_name();
    match esito {
        Ok(()) => window.set_history_message(crate::lingua::schermo(format!(
            "Raccolto nel raccoglitore «{nome}». \u{c8} un riferimento: il contenuto resta \
             nell'archivio, e il raccoglitore non ne conserva una copia."
        ))),
        Err(errore) => {
            window.set_history_message(crate::lingua::schermo(errore.operator_message()));
        }
    }

    refresh(window, workspaces);
}

/// Collega i comandi della schermata.
pub fn wire(window: &AppWindow, workspaces: &SharedWorkspaces) {
    {
        let handle = window.as_weak();
        let workspaces = Rc::clone(workspaces);
        window.on_workspaces_shown(move || {
            if let Some(window) = handle.upgrade() {
                refresh(&window, &workspaces);
            }
        });
    }

    {
        let handle = window.as_weak();
        let workspaces = Rc::clone(workspaces);
        window.on_workspace_open(move |name, note| {
            if crate::lock::refuse_while_locked("workspace_open") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                open_workspace(&window, &workspaces, name.as_str(), note.as_str());
            }
        });
    }

    {
        let handle = window.as_weak();
        let workspaces = Rc::clone(workspaces);
        window.on_workspace_close(move |id| {
            if crate::lock::refuse_while_locked("workspace_close") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                close_workspace(&window, &workspaces, id);
            }
        });
    }

    {
        let handle = window.as_weak();
        let workspaces = Rc::clone(workspaces);
        window.on_workspace_select(move |id| {
            if crate::lock::refuse_while_locked("workspace_select") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            // SELEZIONARE NON SCRIVE NIENTE: cambia che cosa si guarda, e
            // rilegge.
            window.set_workspace_selected(id);
            window.set_workspace_message(SharedString::default());
            refresh(&window, &workspaces);
        });
    }

    {
        let handle = window.as_weak();
        let workspaces = Rc::clone(workspaces);
        window.on_workspace_remove(move |kind, target_id| {
            if crate::lock::refuse_while_locked("workspace_remove") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                remove_entry(&window, &workspaces, kind.as_str(), target_id);
            }
        });
    }

    {
        let handle = window.as_weak();
        let workspaces = Rc::clone(workspaces);
        window.on_history_collect_in_workspace(move |content_id| {
            if crate::lock::refuse_while_locked("history_collect_in_workspace") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                collect_content(&window, &workspaces, content_id);
            }
        });
    }
}

/// Quante righe l'elenco mostra: serve alle prove.
#[cfg(test)]
fn conta_righe(window: &AppWindow) -> usize {
    use slint::Model as _;
    window.get_workspace_rows().iter().count()
}

#[cfg(test)]
mod tests {
    use super::conta_righe;

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("workspace.rs");

    /// Il file dell'interfaccia.
    const UI: &str = include_str!("../ui/app-window.slint");

    /// Il codice di produzione senza i commenti.
    fn codice_senza_commenti() -> String {
        let Some((produzione, prove)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        for riga in prove.lines() {
            let e_codice = ["impl ", "fn ", "struct ", "enum ", "const ", "use ", "pub "]
                .iter()
                .any(|inizio| riga.starts_with(inizio));
            assert!(
                !e_codice,
                "c'e' del codice dopo il blocco di prove, invisibile a ogni guardia: «{riga}»"
            );
        }
        produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Il blocco che disegna la schermata dei workspace.
    ///
    /// Estrattore senza ripiego: se non trova la fine, si ferma invece di
    /// restituire il resto del file (la lezione di SIM-01 e LINK-01).
    fn schermata() -> String {
        // L'ESTRATTORE E' UNO SOLO, E DIMOSTRA DI AVER LETTO QUALCOSA.
        //
        // Prima di HARDEN-02 ogni modulo ritagliava il corpo della propria
        // pagina per conto proprio, e un ritaglio che coglieva troppo poco
        // non faceva fallire niente: ogni divieto restava vero perche' non
        // c'era niente da vietare (ADR-0111).
        crate::page_guard::corpo_della_pagina(20)
    }

    /// **Un riferimento che non arriva più a nulla non si filtra via.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un elenco che nasconde le righe non risolte. Direbbe «questo workspace
    /// non ha mai raccolto quella cosa», che è falso — e chi lo rilegge non
    /// avrebbe modo di accorgersene.
    #[test]
    fn un_riferimento_appeso_non_si_filtra_via() {
        let codice = codice_senza_commenti();
        let Some(inizio) = codice.find("let voci: Vec<WorkspaceEntryRow> = elementi") else {
            panic!("la composizione delle righe deve esistere");
        };
        let Some(fine) = codice[inizio..].find(".collect();") else {
            panic!("la composizione deve chiudersi");
        };
        let blocco = &codice[inizio..inizio + fine];
        for filtro in [".filter(", ".retain(", "if elemento.target ==", "continue"] {
            assert!(
                !blocco.contains(filtro),
                "le righe si filtrano con «{filtro}»: una riga nascosta direbbe che quella cosa \
                 non e' mai stata raccolta"
            );
        }
    }

    /// **Non esiste alcun comando che riapre un workspace chiuso.**
    ///
    /// L'archivio lo rifiuta con un trigger, e un comando che fallisce sempre è
    /// peggio di un comando assente: insegna che il programma non funziona.
    #[test]
    fn non_esiste_un_comando_che_riapre() {
        let codice = codice_senza_commenti();
        for riapertura in ["reopen", "riapri", "riapre(", "set_state", "Open)"] {
            assert!(
                !codice.contains(riapertura),
                "il modulo nomina «{riapertura}»: un workspace chiuso non si riapre"
            );
        }
        assert!(
            !schermata().contains("Riapri"),
            "la schermata non deve offrire un comando che riapre"
        );
    }

    /// **Su un workspace chiuso i comandi che scrivono non compaiono.**
    #[test]
    fn su_uno_chiuso_i_comandi_che_scrivono_non_compaiono() {
        let vista = schermata();
        assert!(
            vista.contains("if root.workspace-selected-open:"),
            "i comandi che scrivono devono dipendere dallo stato del ciclo di vita"
        );
    }

    /// **La schermata non tiene copie: rilegge.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una mappa da identificativo a testo, tenuta fra un disegno e l'altro
    /// «per non rileggere». Sarebbe la seconda copia che WS-01 esiste per
    /// impedire, ricostruita nell'interfaccia.
    #[test]
    fn la_schermata_non_tiene_copie() {
        let codice = codice_senza_commenti();
        for memoria in [
            "BTreeMap",
            "HashMap",
            "static mut",
            "OnceCell",
            "lazy_static",
        ] {
            assert!(
                !codice.contains(memoria),
                "il modulo tiene «{memoria}»: sarebbe un posto dove una copia puo' stare"
            );
        }
        // E ogni comando che scrive rilegge prima di ridisegnare.
        for comando in [
            "fn open_workspace(",
            "fn close_workspace(",
            "fn remove_entry(",
        ] {
            let Some(inizio) = codice.find(comando) else {
                panic!("la funzione «{comando}» deve esistere");
            };
            let Some(fine) = codice[inizio..].find("\n}\n") else {
                panic!("la funzione «{comando}» deve chiudersi");
            };
            assert!(
                codice[inizio..inizio + fine].contains("refresh(window, workspaces)"),
                "«{comando}» deve rileggere: cio' che si mostra e' cio' che l'archivio dice adesso"
            );
        }
    }

    /// **Raccogliere dice in quale workspace, per nome.**
    ///
    /// «Aggiunto» senza dire dove lascerebbe chi legge a indovinare, e chi
    /// indovina sbaglia il giorno in cui ne ha aperti due.
    #[test]
    fn raccogliere_dice_in_quale_workspace() {
        let codice = codice_senza_commenti();
        let Some(inizio) = codice.find("pub fn collect_content(") else {
            panic!("la funzione deve esistere");
        };
        let Some(fine) = codice[inizio..].find("\n}\n") else {
            panic!("la funzione deve chiudersi");
        };
        let corpo = &codice[inizio..inizio + fine];
        assert!(
            corpo.contains("get_workspace_selected_name()"),
            "la frase deve nominare il raccoglitore"
        );
        assert!(
            corpo.contains("Nessun raccoglitore selezionato"),
            "senza un raccoglitore scelto lo si dichiara invece di indovinare"
        );
    }

    /// **Togliere un riferimento dice che non cancella nulla.**
    #[test]
    fn togliere_dichiara_che_non_cancella_nulla() {
        assert!(
            codice_senza_commenti().contains("La cosa referenziata resta dov'era"),
            "chi toglie deve leggere che non ha cancellato la prova"
        );
    }

    /// **La schermata non compone le frasi del dominio.**
    ///
    /// Le parole con cui si dice che cosa un workspace è e che cosa ha
    /// raccolto le compone il modello, una volta sola (DEC-252).
    #[test]
    fn la_schermata_non_compone_le_frasi_del_dominio() {
        let codice = codice_senza_commenti();
        assert!(
            codice.contains("workspace.as_sentence()"),
            "la frase del workspace la compone il modello"
        );
        assert!(
            codice.contains("elemento.target.as_sentence("),
            "la frase del riferimento la compone il repository"
        );
        for ricomposizione in ["aperto da", "non \u{e8} pi\u{f9} nell'archivio", "Fonte:"] {
            assert!(
                !codice.contains(ricomposizione),
                "la schermata scrive «{ricomposizione}»: ricomporrebbe cio' che il dominio \
                 dichiara gia'"
            );
        }
    }

    /// **La schermata esiste ed è raggiungibile.**
    ///
    /// # Perché questa prova
    ///
    /// Perché WS-01 ha lasciato una capacità costruita e mai raggiungibile, ed
    /// era dichiarata come il debito da chiudere subito. Questa prova impedisce
    /// che torni.
    #[test]
    fn la_schermata_e_raggiungibile_dalla_navigazione() {
        assert!(
            crate::surface_text::assegna(UI, "label", "Raccoglitori"),
            "deve esistere una voce di navigazione"
        );
        assert!(
            UI.contains("root.open-page(20);"),
            "la voce deve portare alla pagina"
        );
        assert!(
            UI.contains("root.workspaces-shown();"),
            "aprirla deve rileggere l'elenco"
        );
    }

    /// **Il conteggio delle righe si legge, e parte da zero.**
    ///
    /// # Perche. il backend di prova, e perche. non si esce in silenzio
    ///
    /// Perche. l.event loop di winit **si crea una volta sola per processo**, e
    /// fino a NOTE-01 questa prova usciva senza dire nulla quando la finestra
    /// non nasceva: passava verde **senza aver verificato niente**, e nessuno
    /// poteva distinguerla da una che aveva davvero contato le righe.
    ///
    /// Il backend di prova toglie il vincolo. Adesso un fallimento e. un
    /// fallimento, e lo dice.
    #[test]
    fn l_elenco_parte_vuoto() {
        i_slint_backend_testing::init_no_event_loop();
        let Ok(window) = crate::AppWindow::new() else {
            panic!("la finestra di prova deve potersi costruire");
        };
        assert_eq!(conta_righe(&window), 0);
        assert_eq!(window.get_workspace_selected(), 0);
    }
}

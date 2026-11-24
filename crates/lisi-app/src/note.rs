//! Le note dell'operatore, dove il materiale è e tutte insieme (NOTE-01).
//!
//! # Dove si scrive
//!
//! **Dove il materiale è**: davanti a un contenuto nello Storico, e dentro un
//! workspace. Chiedere di aprire un'altra schermata e indicare su che cosa
//! significherebbe chiedere di trascrivere un identificativo, cioè il lavoro
//! che il programma deve fare.
//!
//! La schermata Note serve a **rileggere** — «che cosa ho annotato» — che
//! nessuna schermata di materiale può rispondere.
//!
//! # Che cosa questo modulo non può fare
//!
//! Toccare la prova. Non nomina il contenuto se non per **riferirlo**, e il
//! servizio sotto non ha alcun modo di scriverci: una guardia lo verifica lì,
//! e un'altra qui.
//!
//! Riscrivere una nota. Non esiste un comando che lo faccia, in nessuno dei tre
//! posti: una nota porta chi l'ha scritta e quando, e cambiarne il testo
//! farebbe dire a quei due valori una cosa falsa. Si ritira.
//!
//! # Un unico comando che ritira
//!
//! Ritirare è lo **stesso atto** ovunque lo si faccia, e ha un solo comando:
//! una nota si ritira per identificativo, e chi la ritira non deve sapere da
//! quale schermata la sta guardando. Tre comandi separati, il giorno in cui la
//! regola cambia, cambierebbero in uno solo.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_core::model::note::NewOperatorNote;
use lisi_core::model::reference::{ArchiveRef, ArchiveRefKind};
use lisi_core::text::Note;
use lisi_core::{NoteId, Timestamp};
use lisi_services::note::NoteService;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::{AppWindow, NoteRow};

/// Servizio delle note, condiviso fra i gestori dei comandi.
pub type SharedNotes = Rc<RefCell<NoteService>>;

/// Costruisce il servizio sull'archivio indicato.
#[must_use]
pub fn create_service(database: lisi_services::Database) -> Option<SharedNotes> {
    Some(Rc::new(RefCell::new(NoteService::new(database))))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> Timestamp {
    lisi_core::time::anchored_now()
}

/// Una riga per una nota già letta.
///
/// # Perché `target` può essere vuoto
///
/// Perché accanto alla cosa annotata ripetere su che cosa è rumore: chi guarda
/// il contenuto sa che le note sotto sono di quel contenuto. Nella schermata
/// Note invece è la prima cosa da sapere, e c'è.
fn riga(nota: &lisi_core::model::note::OperatorNote, bersaglio: Option<String>) -> NoteRow {
    NoteRow {
        id: i32::try_from(nota.id.get()).unwrap_or(i32::MAX),
        body: SharedString::from(nota.body.as_str()),
        // LA FRASE LA COMPONE IL MODELLO (DEC-252): dice chi e quando, e se
        // ritirata anche da chi.
        sentence: crate::lingua::schermo(nota.as_sentence()),
        stands: nota.stands(),
        target: SharedString::from(bersaglio.unwrap_or_default()),
        present: true,
    }
}

/// Rilegge le note su un contenuto e le mette sotto il pannello dello Storico.
///
/// # Perché è pubblica
///
/// Perché lo Storico la chiama quando cambia la riga scelta: le note sotto un
/// contenuto devono essere di **quel** contenuto, e non dell'ultimo guardato.
pub fn refresh_content(window: &AppWindow, notes: &SharedNotes, content_id: i32) {
    if content_id <= 0 {
        window.set_history_content_notes(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        return;
    }
    let Ok(riferimento) = ArchiveRef::to(ArchiveRefKind::Content, i64::from(content_id)) else {
        window.set_history_content_notes(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        return;
    };

    let Ok(elenco) = notes.borrow().about(riferimento) else {
        window.set_history_note_message(crate::lingua::schermo(
            "Le note su questo contenuto non sono leggibili in questo momento: l'assenza qui \
             sotto non dice che non ce ne siano.",
        ));
        window.set_history_content_notes(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        return;
    };

    let righe: Vec<NoteRow> = elenco.iter().map(|nota| riga(nota, None)).collect();
    window.set_history_content_notes(ModelRc::from(Rc::new(VecModel::from(righe))));
}

/// Rilegge le note sul workspace selezionato.
pub fn refresh_workspace(window: &AppWindow, notes: &SharedNotes) {
    let selezionato = window.get_workspace_selected();
    if selezionato <= 0 {
        window.set_workspace_notes(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        return;
    }
    let Ok(riferimento) = ArchiveRef::to(ArchiveRefKind::Workspace, i64::from(selezionato)) else {
        window.set_workspace_notes(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        return;
    };

    let Ok(elenco) = notes.borrow().about(riferimento) else {
        window.set_workspace_note_message(crate::lingua::schermo(
            "Le note su questo raccoglitore non sono leggibili in questo momento.",
        ));
        window.set_workspace_notes(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        return;
    };

    let righe: Vec<NoteRow> = elenco.iter().map(|nota| riga(nota, None)).collect();
    window.set_workspace_notes(ModelRc::from(Rc::new(VecModel::from(righe))));
}

/// Rilegge tutte le note per la schermata Note.
///
/// # Perché si rilegge invece di ricordare
///
/// Perché una nota **riferisce senza copiare** ciò che annota: l'etichetta di
/// ciò a cui punta è quella di adesso, e tenerla fra un disegno e l'altro
/// sarebbe la seconda copia che il riferimento condiviso esiste per impedire.
pub fn refresh(window: &AppWindow, notes: &SharedNotes) {
    let Ok(elenco) = notes.borrow().all() else {
        window.set_note_message(crate::lingua::schermo(
            "Le note non sono leggibili in questo momento: quello qui sotto non dice che non ce \
             ne siano.",
        ));
        window.set_note_rows(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        return;
    };

    // OGNI RIGA COMPARE, COMPRESA QUELLA IL CUI RIFERIMENTO NON ARRIVA PIU' A
    // NULLA: nasconderla direbbe che quella cosa non e' mai stata annotata.
    let righe: Vec<NoteRow> = elenco
        .iter()
        .map(|risolta| {
            let mut riga = riga(
                &risolta.note,
                // LA FRASE LA COMPONE IL REPOSITORY, e dice o l'etichetta di
                // adesso o che la cosa non e' piu' nell'archivio.
                Some(risolta.target.as_sentence(risolta.note.reference.kind())),
            );
            riga.present = risolta.target.is_present();
            riga
        })
        .collect();
    window.set_note_rows(ModelRc::from(Rc::new(VecModel::from(righe))));
}

/// Scrive una nota su una cosa dell'archivio.
///
/// # Perché una funzione sola per due schermate
///
/// Perché scrivere una nota è lo stesso atto: cambia soltanto su che cosa. Due
/// funzioni divergerebbero il giorno in cui una regola cambia.
fn write(window: &AppWindow, notes: &SharedNotes, reference: ArchiveRef, testo: &str) -> bool {
    let Ok(corpo) = Note::try_new(testo) else {
        messaggio(
            window,
            reference.kind(),
            "Questa nota contiene qualcosa che non si pu\u{f2} conservare, oppure \u{e8} troppo \
             lunga.",
        );
        return false;
    };

    // UNA NOTA SENZA PAROLE NON E' UNA NOTA.
    //
    // Lo rifiuta il dominio, e l'archivio anche. Qui si traduce il rifiuto in
    // una frase, perche' «non riuscito» non direbbe che cosa fare.
    let Ok(nuova) = NewOperatorNote::about(reference, &corpo) else {
        messaggio(
            window,
            reference.kind(),
            "Una nota ha bisogno di parole: una riga vuota con un autore e un istante direbbe \
             che qualcuno ha annotato qualcosa senza dire niente.",
        );
        return false;
    };

    let Ok(attore) = crate::operator::audit_actor() else {
        messaggio(
            window,
            reference.kind(),
            "Non si riesce a stabilire chi stia agendo su questa postazione.",
        );
        return false;
    };

    match notes.borrow().write(&nuova, &attore, now()) {
        Ok(_) => {
            messaggio(
                window,
                reference.kind(),
                "Nota scritta. Il materiale non \u{e8} cambiato: la nota gli sta accanto, e \
                 dice chi l'ha scritta e quando.",
            );
            true
        }
        Err(errore) => {
            messaggio(window, reference.kind(), &errore.operator_message());
            false
        }
    }
}

/// Mette la frase nel posto dove chi ha agito la sta guardando.
///
/// # Perché non un messaggio solo
///
/// Perché una frase compare **dove si è agito**: chi scrive una nota su un
/// contenuto guarda il pannello del contenuto, e una risposta che comparisse
/// nella schermata Note non la leggerebbe nessuno.
fn messaggio(window: &AppWindow, kind: ArchiveRefKind, testo: &str) {
    let frase = SharedString::from(testo);
    match kind {
        ArchiveRefKind::Workspace => window.set_workspace_note_message(frase),
        _ => window.set_history_note_message(frase),
    }
}

/// Ritira una nota.
///
/// # Perché uno solo per tutte le schermate
///
/// Perché ritirare è lo stesso atto ovunque lo si faccia. La frase invece
/// compare dove si sta guardando, e per questo si aggiornano tutti e tre gli
/// elenchi: la nota ritirata **resta visibile**, e deve dirlo dovunque sia
/// mostrata.
fn withdraw(window: &AppWindow, notes: &SharedNotes, id: i32) {
    if id <= 0 {
        return;
    }
    let Ok(attore) = crate::operator::audit_actor() else {
        window.set_note_message(crate::lingua::schermo(
            "Non si riesce a stabilire chi stia agendo su questa postazione.",
        ));
        return;
    };

    let esito = notes
        .borrow()
        .withdraw(NoteId::new(i64::from(id)), &attore, now());

    let frase = match esito {
        Ok(()) => crate::lingua::schermo(
            "Nota ritirata. Resta visibile, perch\u{e9} qualcuno pu\u{f2} averci lavorato \
             sopra: dice chi l'aveva scritta, quando, e chi l'ha ritirata.",
        ),
        Err(errore) => crate::lingua::schermo(errore.operator_message()),
    };
    window.set_note_message(frase.clone());
    window.set_history_note_message(frase.clone());
    window.set_workspace_note_message(frase);

    // TUTTI E TRE GLI ELENCHI: la stessa nota puo' essere sotto gli occhi in
    // piu' di un posto, e uno che continuasse a mostrarla valida sarebbe una
    // bugia in attesa.
    refresh(window, notes);
    refresh_workspace(window, notes);
    refresh_content(window, notes, window.get_selected_content());
}

/// Collega i comandi.
pub fn wire(window: &AppWindow, notes: &SharedNotes) {
    {
        let handle = window.as_weak();
        let notes = Rc::clone(notes);
        window.on_notes_shown(move || {
            if let Some(window) = handle.upgrade() {
                refresh(&window, &notes);
            }
        });
    }

    {
        let handle = window.as_weak();
        let notes = Rc::clone(notes);
        window.on_history_write_note(move |testo| {
            if crate::lock::refuse_while_locked("history_write_note") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let content_id = window.get_selected_content();
            let Ok(riferimento) = ArchiveRef::to(ArchiveRefKind::Content, i64::from(content_id))
            else {
                return;
            };
            if write(&window, &notes, riferimento, testo.as_str()) {
                // IL CAMPO SI SVUOTA SOLO SE LA NOTA E' STATA SCRITTA.
                //
                // Svuotarlo comunque farebbe perdere le parole di chi ha
                // sbagliato qualcos'altro, e chi le riscrive non le riscrive
                // uguali.
                window.set_history_note_draft(SharedString::default());
            }
            refresh_content(&window, &notes, content_id);
            refresh(&window, &notes);
        });
    }

    {
        let handle = window.as_weak();
        let notes = Rc::clone(notes);
        window.on_workspace_write_note(move |testo| {
            if crate::lock::refuse_while_locked("workspace_write_note") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let workspace_id = window.get_workspace_selected();
            let Ok(riferimento) =
                ArchiveRef::to(ArchiveRefKind::Workspace, i64::from(workspace_id))
            else {
                return;
            };
            if write(&window, &notes, riferimento, testo.as_str()) {
                window.set_workspace_note_draft(SharedString::default());
            }
            refresh_workspace(&window, &notes);
            refresh(&window, &notes);
        });
    }

    {
        let handle = window.as_weak();
        let notes = Rc::clone(notes);
        window.on_withdraw_note(move |id| {
            if crate::lock::refuse_while_locked("withdraw_note") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                withdraw(&window, &notes, id);
            }
        });
    }

    {
        let handle = window.as_weak();
        let notes = Rc::clone(notes);
        window.on_workspace_chosen(move |_| {
            if crate::lock::refuse_while_locked("workspace_chosen") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                refresh_workspace(&window, &notes);
            }
        });
    }
}

/// Quante righe l'elenco mostra: serve alle prove.
#[cfg(test)]
fn conta_note(window: &AppWindow) -> usize {
    use slint::Model as _;
    window.get_note_rows().iter().count()
}

#[cfg(test)]
mod tests {
    use super::conta_note;

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("note.rs");

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

    /// Il blocco del pannello riusabile, e nient'altro.
    fn pannello_delle_note() -> &'static str {
        let Some(inizio) = UI.find("component NotesPanel inherits VerticalLayout {") else {
            panic!("il pannello deve esistere");
        };
        let Some(lunghezza) = UI[inizio..].find("\ncomponent ContentScreen") else {
            panic!("il pannello deve finire prima della schermata del contenuto");
        };
        &UI[inizio..inizio + lunghezza]
    }

    /// Il blocco della pagina 22, e nient'altro.
    ///
    /// # Perché estratto e senza ripiego
    ///
    /// Perché una guardia che cercasse in tutto il file troverebbe la parola
    /// giusta in un'altra schermata e resterebbe verde per la ragione
    /// sbagliata. E se il blocco non si trovasse, il ripiego «cerca ovunque»
    /// farebbe passare qualunque cosa: qui non c'è ripiego, si rompe.
    fn pagina_delle_note() -> String {
        // L'ESTRATTORE E' UNO SOLO, E DIMOSTRA DI AVER LETTO QUALCOSA.
        //
        // Prima di HARDEN-02 ogni modulo ritagliava il corpo della propria
        // pagina per conto proprio, e un ritaglio che coglieva troppo poco
        // non faceva fallire niente: ogni divieto restava vero perche' non
        // c'era niente da vietare (ADR-0111).
        crate::page_guard::corpo_della_pagina(22)
    }

    /// **Non esiste un comando che riscrive una nota.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un campo modificabile, o un pulsante «Modifica». Una nota porta chi
    /// l'ha scritta e quando: cambiarne il testo farebbe dire a quei due valori
    /// che quella persona ha scritto *quella* frase quel giorno, e sarebbe
    /// falso.
    ///
    /// L'archivio lo rifiuta con un trigger. Qui si verifica che **il comando
    /// non esista**: un comando che fallisce sempre insegna che il programma
    /// non funziona.
    #[test]
    fn non_esiste_un_comando_che_riscrive_una_nota() {
        for blocco in [pannello_delle_note().to_owned(), pagina_delle_note()] {
            for comando in ["Modifica", "modifica-nota", "edit-note", "Correggi"] {
                assert!(
                    !blocco.contains(comando),
                    "l'interfaccia offre «{comando}»: una nota si ritira, non si riscrive"
                );
            }
        }
        let codice = codice_senza_commenti();
        for comando in ["fn edit_note", "fn update_note", "set_body", "fn modifica"] {
            assert!(
                !codice.contains(comando),
                "il modulo espone «{comando}»: una nota si ritira, non si riscrive"
            );
        }
    }

    /// **Una nota ritirata resta visibile, e non offre comandi.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Due, di segno opposto. Nasconderla riscriverebbe che cosa aveva davanti
    /// chi ci ha lavorato sopra. Offrirle il comando che ritira darebbe un
    /// gesto che l'archivio rifiuterebbe sempre.
    #[test]
    fn una_nota_ritirata_resta_visibile_e_non_offre_comandi() {
        let pannello = pannello_delle_note();
        // Dal 2026-10-16 ogni elemento ripetuto sta in un `Rectangle` che ne
        // prende l'altezza (DEC-397): la forma dell'elemento non distingue più
        // la nota dalla riga del comando, e la prova guarda che cosa la
        // condizione racchiude.
        let condizioni: Vec<usize> = pannello
            .match_indices("if nota.stands:")
            .map(|(posizione, _)| posizione)
            .collect();
        let [condizione] = condizioni[..] else {
            panic!(
                "una sola parte della nota dipende dal suo valere ancora, il comando: {} trovate",
                condizioni.len()
            );
        };
        let racchiuso = &pannello[condizione..];
        let Some(comando) = racchiuso.find("root.withdraw(nota.id)") else {
            panic!("il comando che ritira compare solo su una nota che vale ancora");
        };
        let fino_al_comando = &racchiuso[..comando];
        assert!(
            !fino_al_comando.contains("nota.body") && !fino_al_comando.contains("nota.sentence"),
            "le note ritirate non si filtrano: nasconderle riscriverebbe che cosa aveva davanti \
             chi ci ha lavorato sopra"
        );
        assert!(
            !fino_al_comando.contains("\n            }\n"),
            "il comando che ritira sta dentro la condizione, non dopo"
        );
        assert!(
            pannello.contains("nota.stands ? Palette.text : Palette.text-muted"),
            "una nota ritirata si distingue a vista"
        );
    }

    /// **Un unico comando ritira, da qualunque schermata.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Tre comandi separati — uno per il contenuto, uno per il workspace, uno
    /// per la schermata Note — che il giorno in cui la regola cambia cambiano
    /// in uno solo.
    #[test]
    fn un_unico_comando_ritira() {
        let quanti = UI.matches("callback withdraw-note(int);").count();
        assert_eq!(
            quanti, 2,
            "il comando che ritira e' dichiarato due volte: nel pannello riusabile e nella \
             finestra \u{2014} trovati {quanti}"
        );
        let codice = codice_senza_commenti();
        assert_eq!(
            codice.matches("fn withdraw(").count(),
            1,
            "una funzione sola ritira: tre divergerebbero"
        );
    }

    /// **La schermata Note non scrive.**
    ///
    /// # Perché conta
    ///
    /// Perché si scrive dove il materiale è. Un campo qui chiederebbe di
    /// indicare su che cosa, cioè di trascrivere un identificativo — il lavoro
    /// che il programma deve fare.
    #[test]
    fn la_schermata_delle_note_non_scrive() {
        let pagina = pagina_delle_note();
        assert!(
            !pagina.contains("HudInput"),
            "questa schermata rilegge; scrivere avviene dove il materiale e'"
        );
        assert!(
            pagina.contains("Si scrivono dove il materiale è"),
            "la schermata deve dire dove si scrive, invece di lasciare cercare"
        );
    }

    /// **Il pannello è uno solo, e lo usano due schermate.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Due copie del pannello. Il giorno in cui una regola cambia — il ritiro,
    /// il vuoto rifiutato, la ritirata che resta visibile — cambierebbe in una
    /// sola, e nessuno se ne accorgerebbe.
    #[test]
    fn il_pannello_e_uno_solo_e_lo_usano_due_schermate() {
        assert_eq!(
            UI.matches("component NotesPanel inherits").count(),
            1,
            "il pannello e' uno solo"
        );
        // LA DICHIARAZIONE NON CONTA FRA GLI USI.
        //
        // `component NotesPanel inherits ...` non corrisponde a questo motivo:
        // qui si contano soltanto i punti in cui il pannello viene ADOPERATO.
        assert_eq!(
            UI.matches("NotesPanel {").count(),
            2,
            "il pannello si usa in due posti: davanti al contenuto e dentro il workspace"
        );
    }

    /// **Il campo si svuota solo se la nota è stata scritta.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Le parole perse. Chi sbaglia qualcos'altro — l'orologio non leggibile,
    /// l'archivio momentaneamente chiuso — si ritroverebbe il campo vuoto, e
    /// chi riscrive non riscrive uguale.
    #[test]
    fn il_campo_si_svuota_solo_se_la_nota_e_stata_scritta() {
        let codice = codice_senza_commenti();
        for svuotamento in [
            "if write(&window, &notes, riferimento, testo.as_str()) {\n                window.set_history_note_draft(SharedString::default());",
            "if write(&window, &notes, riferimento, testo.as_str()) {\n                window.set_workspace_note_draft(SharedString::default());",
        ] {
            assert!(
                codice.contains(svuotamento),
                "lo svuotamento del campo deve dipendere dall'esito"
            );
        }
    }

    /// **La schermata non conosce l'archivio.**
    ///
    /// ADR-0010: l'interfaccia dipende soltanto dai servizi applicativi.
    #[test]
    fn la_schermata_non_conosce_l_archivio() {
        assert!(
            !codice_senza_commenti().contains("lisi_storage"),
            "l'interfaccia dipende soltanto dai servizi applicativi (ADR-0010)"
        );
    }

    /// **La schermata esiste, ed è raggiungibile.**
    #[test]
    fn la_schermata_si_raggiunge() {
        assert!(
            crate::surface_text::assegna(UI, "label", "Note"),
            "la voce di navigazione deve esistere"
        );
        assert!(
            UI.contains("page == 22) {\n            root.notes-shown();"),
            "aprirla deve rileggere: cio' che mostra e' cio' che l'archivio dice adesso"
        );
    }

    /// **L'elenco parte vuoto, e non è un elenco ricordato.**
    #[test]
    fn l_elenco_parte_vuoto() {
        // L.EVENT LOOP DI WINIT SI CREA UNA VOLTA SOLA PER PROCESSO, e senza
        // questa riga le prove che costruiscono una finestra si contendono
        // l.unica occasione: quale perda dipende dall.ordine.
        i_slint_backend_testing::init_no_event_loop();
        let Ok(window) = crate::AppWindow::new() else {
            panic!("la finestra di prova deve potersi costruire");
        };
        assert_eq!(conta_note(&window), 0);
    }
}

//! La schermata dei segnalibri e delle raccolte (BOOK-01).
//!
//! # Dove si segna: non qui
//!
//! Si segna **dove il materiale è** — dallo Storico, davanti al contenuto — e
//! con **un gesto solo**. È la differenza che tiene separati i due meccanismi:
//! raccogliere in un workspace chiede prima di sceglierne uno, segnare non
//! chiede niente.
//!
//! Un segnalibro che costa una scelta non lo mette nessuno, e un segnalibro che
//! nessuno mette non serve a nulla.
//!
//! Questa schermata serve a **ritrovare** ciò che si è segnato, e a riordinarlo.
//!
//! # Perché riordinare esiste
//!
//! Perché chi segna non sceglie una raccolta. Se l'appartenenza si decidesse
//! soltanto al momento del segno, le raccolte sarebbero una capacità che nulla
//! raggiunge — LAB-01 ha insegnato quanto vale una capacità così. Riordinare è
//! un secondo atto, deliberato, e avviene qui.
//!
//! # Che cosa questa schermata non tiene
//!
//! Una copia del materiale. Ogni riga porta l'etichetta che il servizio ha
//! risolto **al momento del disegno**, e la si rilegge a ogni apertura. Non è
//! una precauzione di questo modulo: `ArchiveRef` è `Copy` e non può portare un
//! testo, e la tabella non ha una colonna in cui una copia possa stare.
//!
//! Né parole dell'operatore: quelle sono **NOTE-01**, e due posti in cui
//! scriverle divergono.
//!
//! # Un riferimento che non arriva più a nulla si vede
//!
//! Il riferimento è polimorfico e non ha una chiave esterna: ciò a cui punta può
//! essere stato cancellato. Quella riga **non si filtra via**, o l'elenco
//! direbbe che quella cosa non è mai stata segnata.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_core::model::bookmark::{NewBookmark, NewBookmarkCollection};
use lisi_core::model::reference::{ArchiveRef, ArchiveRefKind};
use lisi_core::text::DisplayName;
use lisi_core::{BookmarkCollectionId, BookmarkId, Timestamp};
use lisi_services::bookmark::BookmarkService;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::{AppWindow, BookmarkCollectionRow, BookmarkRow};

/// Servizio dei segnalibri, condiviso fra i gestori dei comandi.
pub type SharedBookmarks = Rc<RefCell<BookmarkService>>;

/// Costruisce il servizio sull'archivio indicato.
#[must_use]
pub fn create_service(database: lisi_services::Database) -> Option<SharedBookmarks> {
    Some(Rc::new(RefCell::new(BookmarkService::new(database))))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> Timestamp {
    lisi_core::time::anchored_now()
}

/// Rilegge le raccolte e i segnalibri della raccolta scelta.
///
/// # Perché si rilegge invece di ricordare
///
/// Perché un segnalibro **riferisce senza copiare**: ciò che mostra deve essere
/// ciò che l'archivio dice adesso. Tenere le righe fra un disegno e l'altro
/// sarebbe la seconda copia che BOOK-01 esiste per impedire, ricostruita qui.
pub fn refresh(window: &AppWindow, bookmarks: &SharedBookmarks) {
    let servizio = bookmarks.borrow();

    let (Ok(raccolte), Ok(tutti)) = (servizio.collections(), servizio.marked(None)) else {
        window.set_bookmark_message(crate::lingua::schermo(
            "I segnalibri non sono leggibili in questo momento: quello qui sotto non dice che non \
             ce ne siano.",
        ));
        window.set_bookmark_rows(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        window.set_bookmark_collections(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        return;
    };

    // QUANTI, PER OGNI RACCOLTA.
    //
    // Si contano sull'elenco completo, gia' letto: una seconda interrogazione
    // per raccolta produrrebbe tante interrogazioni quante righe.
    let righe_raccolte: Vec<BookmarkCollectionRow> = raccolte
        .iter()
        .map(|raccolta| BookmarkCollectionRow {
            id: i32::try_from(raccolta.id.get()).unwrap_or(i32::MAX),
            name: SharedString::from(raccolta.name.as_str()),
            created: crate::lingua::schermo(format!(
                "creata da {} il {}",
                raccolta.created_by.as_str(),
                raccolta.created_at.to_readable_local()
            )),
            count: i32::try_from(
                tutti
                    .iter()
                    .filter(|segno| segno.bookmark.collection == Some(raccolta.id))
                    .count(),
            )
            .unwrap_or(i32::MAX),
        })
        .collect();
    window.set_bookmark_collections(ModelRc::from(Rc::new(VecModel::from(righe_raccolte))));

    // QUALE RACCOLTA SI STA GUARDANDO: zero significa tutti, sciolti compresi.
    //
    // E' cio' che si guarda entrando, perche' chi cerca qualcosa che ha segnato
    // non ricorda in quale raccolta l'aveva messo — o non l'aveva messo affatto.
    let scelta = window.get_bookmark_collection_selected();
    let elenco = if scelta <= 0 {
        tutti
    } else {
        let id = BookmarkCollectionId::new(i64::from(scelta));
        let Ok(dentro) = servizio.marked(Some(id)) else {
            window.set_bookmark_message(crate::lingua::schermo(
                "Questa raccolta non \u{e8} leggibile in questo momento.",
            ));
            return;
        };
        dentro
    };

    let righe: Vec<BookmarkRow> = elenco
        .iter()
        .map(|segno| BookmarkRow {
            id: i32::try_from(segno.bookmark.id.get()).unwrap_or(i32::MAX),
            kind: SharedString::from(segno.bookmark.reference.kind().as_str()),
            target_id: i32::try_from(segno.bookmark.reference.target_id()).unwrap_or_default(),
            // LA FRASE LA COMPONE IL REPOSITORY, e dice o l'etichetta di adesso
            // o che la cosa non e' piu' nell'archivio.
            sentence: SharedString::from(segno.target.as_sentence(segno.bookmark.reference.kind())),
            present: segno.target.is_present(),
            marked: crate::lingua::schermo(format!(
                "segnato da {} il {}",
                segno.bookmark.created_by.as_str(),
                segno.bookmark.created_at.to_readable_local()
            )),
            collection_name: SharedString::from(
                segno.collection_name.as_deref().unwrap_or_default(),
            ),
            collection_id: segno
                .bookmark
                .collection
                .map_or(0, |id| i32::try_from(id.get()).unwrap_or(i32::MAX)),
        })
        .collect();
    window.set_bookmark_rows(ModelRc::from(Rc::new(VecModel::from(righe))));
}

/// Crea una raccolta.
fn create_collection(window: &AppWindow, bookmarks: &SharedBookmarks, name: &str) {
    let Ok(nome) = DisplayName::try_new(name) else {
        window.set_bookmark_message(crate::lingua::schermo(
            "Una raccolta ha bisogno di un nome: \u{e8} quello con cui la si ritrover\u{e0}.",
        ));
        return;
    };
    let Ok(attore) = crate::operator::audit_actor() else {
        window.set_bookmark_message(crate::lingua::schermo(
            "Non si riesce a stabilire chi stia agendo su questa postazione.",
        ));
        return;
    };

    let esito = bookmarks.borrow().create_collection(
        &NewBookmarkCollection {
            name: nome,
            created_by: attore,
        },
        now(),
    );

    match esito {
        Ok(_) => {
            window.set_bookmark_new_collection_name(SharedString::default());
            window.set_bookmark_message(crate::lingua::schermo(
                "Raccolta creata. I segnalibri si mettono dallo Storico, e si spostano qui: \
                 segnare resta un gesto solo.",
            ));
        }
        Err(errore) => {
            window.set_bookmark_message(crate::lingua::schermo(errore.operator_message()));
        }
    }

    refresh(window, bookmarks);
}

/// Cancella una raccolta.
fn delete_collection(window: &AppWindow, bookmarks: &SharedBookmarks, id: i32) {
    if id <= 0 {
        return;
    }
    let Ok(attore) = crate::operator::audit_actor() else {
        window.set_bookmark_message(crate::lingua::schermo(
            "Non si riesce a stabilire chi stia agendo su questa postazione.",
        ));
        return;
    };

    let esito = bookmarks.borrow().delete_collection(
        BookmarkCollectionId::new(i64::from(id)),
        &attore,
        now(),
    );

    match esito {
        Ok(()) => {
            // SE SI STAVA GUARDANDO QUELLA, si torna a tutti: mostrare le
            // righe di una raccolta che non c'e' piu' sarebbe mostrarle di
            // un'altra.
            if window.get_bookmark_collection_selected() == id {
                window.set_bookmark_collection_selected(0);
            }
            window.set_bookmark_message(crate::lingua::schermo(
                "Raccolta cancellata. I segnalibri che conteneva non c'erano: una raccolta \
                 piena non si cancella.",
            ));
        }
        Err(errore) => {
            window.set_bookmark_message(crate::lingua::schermo(errore.operator_message()));
        }
    }

    refresh(window, bookmarks);
}

/// Toglie un segnalibro.
fn remove_bookmark(window: &AppWindow, bookmarks: &SharedBookmarks, id: i32) {
    if id <= 0 {
        return;
    }
    let Ok(attore) = crate::operator::audit_actor() else {
        window.set_bookmark_message(crate::lingua::schermo(
            "Non si riesce a stabilire chi stia agendo su questa postazione.",
        ));
        return;
    };

    let esito = bookmarks
        .borrow()
        .unmark(BookmarkId::new(i64::from(id)), &attore, now());

    match esito {
        Ok(()) => {
            window.set_bookmark_filing(0);
            window.set_bookmark_message(crate::lingua::schermo(
                "Segno tolto. La cosa segnata resta dov'era: un segnalibro \u{e8} un \
                 riferimento, e toglierlo non cancella nulla.",
            ));
        }
        Err(errore) => {
            window.set_bookmark_message(crate::lingua::schermo(errore.operator_message()));
        }
    }

    refresh(window, bookmarks);
}

/// Sposta un segnalibro in una raccolta, o lo lascia sciolto.
fn file_into(window: &AppWindow, bookmarks: &SharedBookmarks, id: i32, collection: i32) {
    if id <= 0 {
        return;
    }
    let Ok(attore) = crate::operator::audit_actor() else {
        window.set_bookmark_message(crate::lingua::schermo(
            "Non si riesce a stabilire chi stia agendo su questa postazione.",
        ));
        return;
    };

    // ZERO SIGNIFICA NESSUNA RACCOLTA, e non e' un errore: e' il caso
    // ordinario, e uscire da una raccolta deve costare quanto entrarci.
    let raccolta = if collection <= 0 {
        None
    } else {
        Some(BookmarkCollectionId::new(i64::from(collection)))
    };

    let esito =
        bookmarks
            .borrow()
            .file_into(BookmarkId::new(i64::from(id)), raccolta, &attore, now());

    match esito {
        Ok(()) => {
            window.set_bookmark_filing(0);
            window.set_bookmark_message(SharedString::from(if raccolta.is_some() {
                "Segnalibro spostato. \u{c8} cambiato dove sta il segno, non che cosa segna."
            } else {
                "Segnalibro tolto dalla raccolta. Resta segnato: stare in nessuna raccolta \u{e8} \
                 il caso ordinario."
            }));
        }
        Err(errore) => {
            window.set_bookmark_message(crate::lingua::schermo(errore.operator_message()));
        }
    }

    refresh(window, bookmarks);
}

/// Segna o toglie il segno da un contenuto, dallo Storico.
///
/// # Perché il comando vive nello Storico e la funzione qui
///
/// Perché si segna **dove il materiale è**. E perché lo stesso comando fa e
/// disfa: due comandi accanto, di cui uno sempre inerte, chiedono a chi guarda
/// di capire quale sia quello buono.
pub fn toggle_content(window: &AppWindow, bookmarks: &SharedBookmarks, content_id: i32) {
    if content_id <= 0 {
        return;
    }
    let Ok(riferimento) = ArchiveRef::to(ArchiveRefKind::Content, i64::from(content_id)) else {
        return;
    };
    let Ok(attore) = crate::operator::audit_actor() else {
        window.set_history_message(crate::lingua::schermo(
            "Non si riesce a stabilire chi stia agendo su questa postazione.",
        ));
        return;
    };

    // SI CHIEDE ALL'ARCHIVIO SE SIA GIA' SEGNATO, non alla proprieta' che la
    // schermata sta mostrando: quella dice com'era all'ultimo disegno.
    let servizio = bookmarks.borrow();
    let Ok(esistente) = servizio.mark_of(riferimento) else {
        window.set_history_message(crate::lingua::schermo(
            "Non si riesce a stabilire se questo contenuto sia gi\u{e0} segnato: non \u{e8} stato \
             toccato.",
        ));
        return;
    };

    let messaggio = match esistente {
        Some(id) => match servizio.unmark(id, &attore, now()) {
            Ok(()) => String::from("Tolto dai segnalibri. Il contenuto resta nell'archivio."),
            Err(errore) => errore.operator_message(),
        },
        None => {
            let Ok(nuovo) = NewBookmark::of(riferimento, None) else {
                return;
            };
            match servizio.mark(nuovo, &attore, now()) {
                // LA FRASE DICE DOVE RITROVARLO.
                //
                // «Segnato» senza dire dove lascia chi legge a cercarlo.
                Ok(_) => String::from(
                    "Aggiunto ai segnalibri: si ritrova nella schermata Segnalibri, e da l\u{ec} \
                     lo si pu\u{f2} mettere in una raccolta.",
                ),
                Err(errore) => errore.operator_message(),
            }
        }
    };
    drop(servizio);

    window.set_history_message(crate::lingua::schermo(messaggio));
    refresh_content_mark(window, bookmarks, content_id);
    refresh(window, bookmarks);
}

/// Rilegge se il contenuto aperto nello Storico sia segnato.
///
/// # Perché è pubblica
///
/// Perché lo Storico la chiama quando apre un contenuto: il comando deve dire
/// lo **stato**, non l'augurio. Un comando che offre «Segna» su una cosa già
/// segnata fa credere di aver perso il segno.
pub fn refresh_content_mark(window: &AppWindow, bookmarks: &SharedBookmarks, content_id: i32) {
    if content_id <= 0 {
        window.set_history_content_marked(false);
        return;
    }
    let Ok(riferimento) = ArchiveRef::to(ArchiveRefKind::Content, i64::from(content_id)) else {
        window.set_history_content_marked(false);
        return;
    };
    let segnato = bookmarks
        .borrow()
        .mark_of(riferimento)
        .ok()
        .flatten()
        .is_some();
    window.set_history_content_marked(segnato);
}

/// Collega i comandi della schermata.
pub fn wire(window: &AppWindow, bookmarks: &SharedBookmarks) {
    {
        let handle = window.as_weak();
        let bookmarks = Rc::clone(bookmarks);
        window.on_bookmarks_shown(move || {
            if let Some(window) = handle.upgrade() {
                refresh(&window, &bookmarks);
            }
        });
    }

    {
        let handle = window.as_weak();
        let bookmarks = Rc::clone(bookmarks);
        window.on_bookmark_create_collection(move |name| {
            if crate::lock::refuse_while_locked("bookmark_create_collection") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                create_collection(&window, &bookmarks, name.as_str());
            }
        });
    }

    {
        let handle = window.as_weak();
        let bookmarks = Rc::clone(bookmarks);
        window.on_bookmark_delete_collection(move |id| {
            if crate::lock::refuse_while_locked("bookmark_delete_collection") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                delete_collection(&window, &bookmarks, id);
            }
        });
    }

    {
        let handle = window.as_weak();
        let bookmarks = Rc::clone(bookmarks);
        window.on_bookmark_remove(move |id| {
            if crate::lock::refuse_while_locked("bookmark_remove") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                remove_bookmark(&window, &bookmarks, id);
            }
        });
    }

    {
        let handle = window.as_weak();
        let bookmarks = Rc::clone(bookmarks);
        window.on_bookmark_file_into(move |id, collection| {
            if crate::lock::refuse_while_locked("bookmark_file_into") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                file_into(&window, &bookmarks, id, collection);
            }
        });
    }

    {
        let handle = window.as_weak();
        let bookmarks = Rc::clone(bookmarks);
        window.on_bookmark_choose_collection(move |id| {
            if crate::lock::refuse_while_locked("bookmark_choose_collection") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            // SCEGLIERE NON SCRIVE NIENTE: cambia che cosa si guarda, e
            // rilegge.
            window.set_bookmark_collection_selected(id);
            window.set_bookmark_filing(0);
            window.set_bookmark_message(SharedString::default());
            refresh(&window, &bookmarks);
        });
    }

    {
        let handle = window.as_weak();
        let bookmarks = Rc::clone(bookmarks);
        window.on_history_toggle_bookmark(move |content_id| {
            if crate::lock::refuse_while_locked("history_toggle_bookmark") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                toggle_content(&window, &bookmarks, content_id);
            }
        });
    }

    // LA DOMANDA «QUESTA RIGA E' GIA' SEGNATA?» NON SI REGISTRA QUI.
    //
    // Da NOTE-01 due moduli devono rispondere allo stesso cambio di riga: i
    // segnalibri e le note. In Slint un callback ha UN gestore solo, e il
    // secondo che si registra sostituisce il primo **in silenzio**.
    //
    // Percio' `history-content-chosen` lo compone `main.rs`, che conosce
    // entrambi i servizi, e chiama [`refresh_content_mark`] insieme all'altro.
    // Registrarlo di nuovo qui spegnerebbe le note senza che nulla lo dica.
}

/// Quante righe l'elenco mostra: serve alle prove.
#[cfg(test)]
fn conta_segnalibri(window: &AppWindow) -> usize {
    use slint::Model as _;
    window.get_bookmark_rows().iter().count()
}

#[cfg(test)]
mod tests {
    use super::conta_segnalibri;

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("bookmark.rs");

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

    /// Il blocco della pagina 21, e nient'altro.
    ///
    /// # Perché estratto e senza ripiego
    ///
    /// Perché una guardia che cercasse in tutto il file troverebbe la parola
    /// giusta in un'altra schermata e resterebbe verde per la ragione
    /// sbagliata. E se il blocco non si trovasse, il ripiego «cerca ovunque»
    /// farebbe passare qualunque cosa: qui non c'è ripiego, si rompe.
    fn pagina_dei_segnalibri() -> String {
        // L'ESTRATTORE E' UNO SOLO, E DIMOSTRA DI AVER LETTO QUALCOSA.
        //
        // Prima di HARDEN-02 ogni modulo ritagliava il corpo della propria
        // pagina per conto proprio, e un ritaglio che coglieva troppo poco
        // non faceva fallire niente: ogni divieto restava vero perche' non
        // c'era niente da vietare (ADR-0111).
        crate::page_guard::corpo_della_pagina(21)
    }

    /// **Segnare è un gesto solo: il comando non chiede dove.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// La cerimonia del workspace, copiata qui. «Raccogli nel workspace» dice
    /// «Nessun workspace selezionato: aprire la schermata e sceglierne uno»,
    /// ed è giusto — un workspace è un contenitore di lavoro. Un segnalibro no:
    /// se chiedesse la stessa cosa, nessuno lo metterebbe, e un segnalibro che
    /// nessuno mette non serve a nulla.
    #[test]
    fn segnare_non_chiede_dove() {
        let codice = codice_senza_commenti();
        let Some(inizio) = codice.find("pub fn toggle_content(") else {
            panic!("la funzione deve esistere");
        };
        let Some(fine) = codice[inizio..].find("\n}\n") else {
            panic!("la funzione deve chiudersi");
        };
        let corpo = &codice[inizio..inizio + fine];

        assert!(
            corpo.contains("NewBookmark::of(riferimento, None)"),
            "segnare mette il segnalibro FUORI da ogni raccolta: chiedere dove sarebbe la \
             cerimonia che un segnalibro esiste per non avere"
        );
        for cerimonia in [
            "get_bookmark_collection_selected",
            "Nessuna raccolta selezionata",
        ] {
            assert!(
                !corpo.contains(cerimonia),
                "segnare consulta «{cerimonia}»: sarebbe chiedere di scegliere prima"
            );
        }
    }

    /// **Il comando dice lo stato, non l'augurio.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un pulsante che dice «Segna» su una cosa già segnata. Chi lo legge crede
    /// di aver perso il segno, lo preme, e lo perde davvero.
    #[test]
    fn il_comando_dice_lo_stato() {
        let ui = UI;
        assert!(
            ui.contains(
                r#"label: root.marked ? @tr("Togli dai segnalibri") : @tr("Aggiungi ai segnalibri");"#
            ),
            "l'etichetta deve dipendere dallo stato"
        );
        assert!(
            ui.contains("in property <bool> marked: false;"),
            "lo stato deve arrivare alla schermata del contenuto"
        );
    }

    /// **Il segno si mette dallo Storico, e c'è un solo punto in cui accade.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un secondo comando «Segna» altrove, che il giorno in cui la regola
    /// cambia resta indietro.
    #[test]
    fn si_segna_da_un_punto_solo() {
        let quanti = UI.matches("root.toggle-bookmark(").count();
        assert_eq!(
            quanti, 1,
            "il comando che segna deve stare in un punto solo \u{2014} trovati {quanti}"
        );
    }

    /// **La schermata dei segnalibri non segna.**
    ///
    /// # Perché conta
    ///
    /// Perché si segna dove il materiale è. Un comando qui chiederebbe di
    /// trascrivere un identificativo, cioè il lavoro che il programma deve
    /// fare.
    #[test]
    fn la_schermata_dei_segnalibri_non_segna() {
        let pagina = pagina_dei_segnalibri();
        assert!(
            !pagina.contains("toggle-bookmark"),
            "questa schermata ritrova e riordina; segnare avviene dove il materiale e'"
        );
        assert!(
            pagina.contains("Si segna dove il materiale è"),
            "la schermata deve dire dove si segna, invece di lasciare cercare"
        );
    }

    /// **Le raccolte si raggiungono: non sono una capacità inerte.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// La lezione di LAB-01. Se l'appartenenza a una raccolta si potesse
    /// decidere soltanto al momento del segno — e segnare è un gesto solo, che
    /// non chiede dove — nessun segnalibro finirebbe mai in una raccolta, e le
    /// raccolte sarebbero un tavolo apparecchiato per nessuno.
    #[test]
    fn una_raccolta_si_riempie_davvero() {
        let pagina = pagina_dei_segnalibri();
        assert!(
            pagina.contains("root.bookmark-file-into(segno.id, raccolta.id)"),
            "deve esistere un modo di mettere un segnalibro in una raccolta"
        );
        assert!(
            pagina.contains("root.bookmark-file-into(segno.id, 0)"),
            "e un modo di tirarlo fuori: uscire deve costare quanto entrare"
        );
    }

    /// **Un riferimento che non arriva più a nulla resta visibile.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un elenco che filtra le righe rotte, e così dice «quella cosa non è mai
    /// stata segnata» — che è falso.
    #[test]
    fn un_riferimento_appeso_non_si_nasconde() {
        let codice = codice_senza_commenti();
        let Some(inizio) = codice.find("pub fn refresh(") else {
            panic!("la funzione deve esistere");
        };
        let Some(fine) = codice[inizio..].find("\n}\n") else {
            panic!("la funzione deve chiudersi");
        };
        let corpo = &codice[inizio..inizio + fine];
        assert!(
            !corpo.contains(".filter(|segno| segno.target"),
            "le righe rotte non si filtrano: nasconderle direbbe che quella cosa non e' mai \
             stata segnata"
        );

        let pagina = pagina_dei_segnalibri();
        assert!(
            pagina.contains("segno.present ? Palette.text : Palette.amber"),
            "la riga rotta si vede, e si distingue"
        );
        assert!(
            !pagina.contains("if segno.present:"),
            "la riga rotta compare comunque"
        );
    }

    /// **La schermata non porta il testo del materiale.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// La seconda copia della prova, ricostruita nell'interfaccia. Il dominio
    /// non può portarla — `ArchiveRef` è `Copy` — ma una riga dell'elenco sì, se
    /// qualcuno le desse un campo.
    #[test]
    fn le_righe_non_portano_il_materiale() {
        let Some(inizio) = UI.find("export struct BookmarkRow {") else {
            panic!("la struttura deve esistere");
        };
        let Some(fine) = UI[inizio..].find("\n}\n") else {
            panic!("la struttura deve chiudersi");
        };
        for materiale in ["body", "text:", "testo", "note", "nota", "preview"] {
            assert!(
                !UI[inizio..inizio + fine].contains(materiale),
                "la riga dichiara «{materiale}»: un segnalibro riferisce senza copiare, e le \
                 parole dell'operatore sono NOTE-01"
            );
        }
    }

    /// **La schermata esiste, ed è raggiungibile.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una pagina scritta e mai raggiunta: LAB-01 di nuovo, in un'altra forma.
    #[test]
    fn la_schermata_si_raggiunge() {
        assert!(
            crate::surface_text::assegna(UI, "label", "Segnalibri"),
            "la voce di navigazione deve esistere"
        );
        assert!(
            UI.contains("page == 21) {\n            root.bookmarks-shown();"),
            "aprirla deve rileggere: cio' che mostra e' cio' che l'archivio dice adesso"
        );
    }

    /// **L'elenco parte vuoto, e non è un elenco ricordato.**
    #[test]
    fn l_elenco_parte_vuoto() {
        // L.EVENT LOOP DI WINIT SI CREA UNA VOLTA SOLA PER PROCESSO.
        //
        // Senza il backend di prova, le prove che costruiscono una finestra si
        // contendono l.unica occasione e quale perda dipende dall.ordine. Se ne
        // e. accorta NOTE-01 aggiungendo la quarta.
        i_slint_backend_testing::init_no_event_loop();
        let Ok(window) = crate::AppWindow::new() else {
            panic!("la finestra di prova deve potersi costruire");
        };
        assert_eq!(conta_segnalibri(&window), 0);
    }

    /// **La schermata non conosce l'archivio.**
    ///
    /// # Perché conta
    ///
    /// ADR-0010: l'interfaccia dipende soltanto dai servizi applicativi. Il
    /// compilatore lo impedisce già — `lisi-app` non dipende da `lisi-storage`
    /// — e questa prova lo dice a chi legge, invece di lasciarlo scoprire con
    /// un errore di compilazione.
    #[test]
    fn la_schermata_non_conosce_l_archivio() {
        let codice = codice_senza_commenti();
        assert!(
            !codice.contains("lisi_storage"),
            "l'interfaccia dipende soltanto dai servizi applicativi (ADR-0010)"
        );
    }
}

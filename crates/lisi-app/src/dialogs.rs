//! Le finestre di Windows per scegliere un file o una cartella
//! (OPERATOR-E2E-REMEDIATION-01, F-01 e F-31).
//!
//! # Perché non si aprono più dal filo dell'interfaccia
//!
//! Fino a questa correzione ogni scelta di file o cartella apriva la finestra di
//! sistema **dal filo dell'interfaccia**, e la attendeva lì. Finché restava
//! aperta il programma era fermo: il ciclo dei 200 millisecondi non girava, e
//! con lui l'acquisizione, il blocco automatico e il comando «Blocca» del
//! vassoio. Chi apriva «Crea copia» e si allontanava lasciava la finestra di
//! scelta aperta su una postazione che non si sarebbe più bloccata: chi passava
//! poteva scegliere una chiavetta e portarsi via l'archivio.
//!
//! Ora la finestra si apre su un filo a parte (la variante asincrona di `rfd`,
//! che su Windows fa proprio questo) e il programma continua a girare. Quando la
//! finestra si chiude con una scelta, **il blocco si ricontrolla**: se nel
//! frattempo la postazione è stata bloccata, la scelta non si esegue.
//!
//! # Perché la finestra del programma ne è la proprietaria
//!
//! Perché così la finestra di scelta si apre **sopra** il programma, e non
//! nell'angolo dello schermo (F-31), e Windows non lascia premere nulla nel
//! programma finché è aperta: nessuno può chiedere una seconda copia mentre si
//! sceglie la cartella della prima.

use std::path::PathBuf;

use slint::ComponentHandle;

use crate::AppWindow;

/// Che cosa si chiede di scegliere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pick {
    /// Un file che esiste.
    File,
    /// Una cartella che esiste.
    Folder,
    /// Il nome di un file da scrivere.
    Save,
}

/// Apre la finestra di scelta e, se si sceglie qualcosa, esegue `then`.
///
/// `command` è il nome con cui il rifiuto si scrive nel registro se, quando la
/// finestra si chiude, la postazione è bloccata. Annullare non esegue nulla e
/// non chiama `then`: chi annulla non ha chiesto niente.
pub fn ask<F>(
    window: &AppWindow,
    dialog: rfd::AsyncFileDialog,
    pick: Pick,
    command: &'static str,
    then: F,
) where
    F: FnOnce(&AppWindow, PathBuf) + 'static,
{
    ask_or_cancel(window, dialog, pick, command, then, |_| {});
}

/// Come [`ask`], e chiama `cancelled` se la finestra si chiude senza scelta.
///
/// Serve dove la schermata dice che nulla è stato scritto: chi annulla
/// un'esportazione deve sapere che non c'è un file a metà.
pub fn ask_or_cancel<F, C>(
    window: &AppWindow,
    dialog: rfd::AsyncFileDialog,
    pick: Pick,
    command: &'static str,
    then: F,
    cancelled: C,
) where
    F: FnOnce(&AppWindow, PathBuf) + 'static,
    C: FnOnce(&AppWindow) + 'static,
{
    let dialog = dialog.set_parent(&window.window().window_handle());
    let handle = window.as_weak();
    let futuro = async move {
        let scelta = match pick {
            Pick::File => dialog.pick_file().await,
            Pick::Folder => dialog.pick_folder().await,
            Pick::Save => dialog.save_file().await,
        };
        let Some(scelta) = scelta else {
            if let Some(window) = handle.upgrade() {
                cancelled(&window);
            }
            return;
        };
        // IL BLOCCO SI RICONTROLLA AL RITORNO: la finestra di scelta può essere
        // rimasta aperta per minuti, e la postazione essersi bloccata intanto.
        if crate::lock::refuse_while_locked(command) {
            return;
        }
        let Some(window) = handle.upgrade() else {
            return;
        };
        then(&window, scelta.path().to_path_buf());
    };
    if let Err(errore) = slint::spawn_local(futuro) {
        tracing::warn!(
            errore = %errore,
            comando = command,
            "finestra di scelta non aperta"
        );
    }
}

#[cfg(test)]
mod tests {
    /// Il codice di produzione dell'applicazione, senza le prove.
    fn produzione(sorgente: &str) -> &str {
        sorgente
            .split_once("#[cfg(test)]\nmod tests {")
            .map_or(sorgente, |(prima, _)| prima)
    }

    /// **Nessuna finestra di scelta si apre più dal filo dell'interfaccia**
    /// (F-01): chi la usa passa da qui.
    ///
    /// La variante sincrona di `rfd` ferma il programma finché la finestra è
    /// aperta, e con lui il blocco automatico e l'acquisizione.
    #[test]
    fn nessuna_finestra_di_scelta_sincrona() {
        let cartella = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let Ok(voci) = std::fs::read_dir(cartella) else {
            panic!("la cartella dei sorgenti deve leggersi");
        };
        let mut trovati = Vec::new();
        for voce in voci.flatten() {
            let percorso = voce.path();
            if percorso.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let Ok(testo) = std::fs::read_to_string(&percorso) else {
                continue;
            };
            if produzione(&testo).contains("rfd::FileDialog") {
                trovati.push(percorso.display().to_string());
            }
        }
        assert!(
            trovati.is_empty(),
            "finestre di scelta sincrone in: {trovati:?}"
        );
    }

    /// **L'eseguibile parte**: nessuna funzione di `rfd` che chieda i controlli
    /// comuni versione 6 senza un manifesto che li dichiari.
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Con `common-controls-v6` la finestra di messaggio importa
    /// `TaskDialogIndirect`. Finché nessuno la usava, il collegatore la toglieva;
    /// la finestra «già aperto» (F-01) l'ha resa viva, e il binario di rilascio
    /// non si avviava più: `0xC0000139`, punto d'ingresso non trovato. Le prove
    /// non potevano vederlo, perché il programma di prova non chiama `run()` e
    /// quella funzione restava fuori. L'ha visto la verifica a vista.
    #[test]
    fn l_eseguibile_non_chiede_controlli_che_non_dichiara() {
        const CARGO: &str = include_str!("../Cargo.toml");
        const BUILD: &str = include_str!("../build.rs");
        let rfd = CARGO
            .lines()
            .find(|riga| riga.starts_with("rfd ="))
            .unwrap_or_default();
        assert!(!rfd.is_empty(), "la dipendenza da rfd non si trova più");
        assert!(
            !rfd.contains("common-controls-v6") || BUILD.contains("RT_MANIFEST"),
            "rfd chiede i controlli comuni versione 6 e l'eseguibile non porta un manifesto: \
             il programma non parte (0xC0000139)"
        );
    }
}

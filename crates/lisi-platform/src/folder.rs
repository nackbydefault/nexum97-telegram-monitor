// DODICESIMO modulo del crate autorizzato a contenere `unsafe`. Vedere ADR-0009
// per la regola e ADR-0137 per la decisione che ha portato qui.
#![cfg_attr(windows, allow(unsafe_code))]

//! Aprire in Esplora file la cartella in cui il prodotto ha appena scritto
//! dei documenti.
//!
//! # Perché serve, e a chi
//!
//! La relazione si salva per impostazione predefinita sotto `%LOCALAPPDATA%`,
//! una cartella che Esplora file nasconde. L'esito della relazione scriveva il
//! percorso e diceva «Per aprirla: Esplora file, poi la cartella scritta qui
//! sopra»: tre simulazioni su tre non ci sono arrivate (OPERATOR-SIM-03,
//! SIM3-03). Un comando «Apri la cartella» la apre.
//!
//! # Che cosa apre
//!
//! **Soltanto una cartella**, che esiste, indicata con un percorso assoluto.
//! Il verbo `open` di `ShellExecuteW` su un file eseguibile lo **avvierebbe**:
//! il controllo che sia una cartella è la ragione d'essere di questo modulo, e
//! sta qui e non in chi chiama, perché valga anche per un chiamante che se ne
//! dimentica.
//!
//! Nessuna riga di comando viene composta: il percorso è il **bersaglio** di
//! `ShellExecuteW`, non un argomento di `explorer.exe` né di una shell, e non
//! c'è nulla in cui iniettare un secondo comando.
//!
//! # Invarianti dell'FFI
//!
//! 1. `ShellExecuteW` riceve il verbo `"open"` e un percorso già controllato:
//!    assoluto, senza caratteri di controllo né zeri interni, di una cartella
//!    che esiste al momento del controllo.
//! 2. Le stringhe passate sono UTF-16 con terminatore nullo, vive per tutta la
//!    durata della chiamata.
//! 3. Parametri, cartella di lavoro e finestra genitrice sono nulli.
//! 4. L'esito si interpreta secondo il contratto documentato — un valore
//!    `> 32` è successo — senza dereferenziarlo.
//!
//! # Limite dichiarato
//!
//! Fra il controllo e l'apertura passa un istante, in cui la cartella potrebbe
//! essere sostituita: è la stessa cartella che il prodotto ha appena scritto,
//! sotto il profilo dell'operatore o in una cartella che l'operatore ha
//! scelto, e chi può sostituirla lì può già fare di peggio.

use std::path::Path;

use crate::error::{PlatformError, PlatformResult};

/// Apre in Esplora file la cartella indicata.
///
/// # Errori
///
/// Restituisce [`PlatformError::NotAFolder`] se il percorso non è assoluto,
/// contiene caratteri di controllo o non è una cartella esistente,
/// [`PlatformError::LaunchFailed`] se il sistema rifiuta l'apertura, e
/// [`PlatformError::Unsupported`] fuori da Windows.
pub fn open(folder: &Path) -> PlatformResult<()> {
    check(folder)?;
    launch(folder)
}

/// La rete di sicurezza, separata perché le prove la possano guidare senza
/// aprire nulla.
fn check(folder: &Path) -> PlatformResult<()> {
    if !folder.is_absolute() {
        return Err(PlatformError::NotAFolder);
    }
    let Some(testo) = folder.to_str() else {
        return Err(PlatformError::NotAFolder);
    };
    if testo.chars().any(char::is_control) {
        return Err(PlatformError::NotAFolder);
    }
    match std::fs::metadata(folder) {
        Ok(metadati) if metadati.is_dir() => Ok(()),
        _ => Err(PlatformError::NotAFolder),
    }
}

#[cfg(windows)]
fn launch(folder: &Path) -> PlatformResult<()> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    // Invariante 2: le stringhe restano vive per tutta la chiamata. Invariante
    // 1: `check` ha gia' escluso i caratteri di controllo, zero compreso.
    let verb: Vec<u16> = "open".encode_utf16().chain(core::iter::once(0)).collect();
    let target: Vec<u16> = folder
        .as_os_str()
        .encode_wide()
        .chain(core::iter::once(0))
        .collect();

    // Invarianti 1 e 3.
    let result = unsafe {
        ShellExecuteW(
            core::ptr::null_mut(),
            verb.as_ptr(),
            target.as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            SW_SHOWNORMAL,
        )
    };

    // Invariante 4.
    let code = result as isize;
    if code > 32 {
        return Ok(());
    }
    Err(PlatformError::LaunchFailed { code })
}

#[cfg(not(windows))]
fn launch(_folder: &Path) -> PlatformResult<()> {
    Err(PlatformError::Unsupported)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::check;
    use crate::error::PlatformError;

    /// **Un file non si apre, anche esistente**: il verbo `open` lo avvierebbe.
    #[test]
    fn un_file_non_e_una_cartella() {
        let Ok(cartella) = tempfile_dir() else {
            panic!("la cartella di prova deve potersi creare");
        };
        let file = cartella.join("relazione.exe");
        if std::fs::write(&file, b"MZ").is_err() {
            panic!("il file di prova deve potersi scrivere");
        }
        assert!(matches!(check(&file), Err(PlatformError::NotAFolder)));
        assert!(check(&cartella).is_ok(), "la cartella che esiste si apre");
        let _ = std::fs::remove_dir_all(&cartella);
    }

    #[test]
    fn un_percorso_relativo_o_strano_non_si_apre() {
        for percorso in [
            "relazioni",
            ".",
            "..\\..",
            "C:\\Windows\\System32\\cmd.exe\n",
        ] {
            assert!(
                matches!(check(Path::new(percorso)), Err(PlatformError::NotAFolder)),
                "«{percorso:?}» non deve passare"
            );
        }
        assert!(matches!(
            check(Path::new("C:\\cartella-che-non-esiste-davvero-nexum97")),
            Err(PlatformError::NotAFolder)
        ));
    }

    /// Una cartella temporanea propria, senza dipendenze in più.
    fn tempfile_dir() -> std::io::Result<std::path::PathBuf> {
        let cartella = std::env::temp_dir().join(format!(
            "nexum97-folder-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&cartella)?;
        Ok(cartella)
    }
}

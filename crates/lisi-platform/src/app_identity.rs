// QUINTO modulo del crate autorizzato a contenere `unsafe`, dopo `browser`,
// `window_chrome`, `wakefulness` e `autostart`. La deroga e' esplicita,
// circoscritta a un solo file e visibile in diff (ADR-0003, ADR-0023). Vale
// solo su Windows.
#![cfg_attr(windows, allow(unsafe_code))]

//! Identita' dell'applicazione presso Windows.
//!
//! # A che cosa serve, e perche' senza non c'e' il toast
//!
//! Windows non attribuisce un avviso a un eseguibile: lo attribuisce a un
//! **AppUserModelID**, una stringa che identifica l'applicazione a prescindere
//! da dove il suo file si trovi. Senza, `ToastNotificationManager` non ha a chi
//! intestare la notifica e non la mostra.
//!
//! L'identificativo deve comparire in **due** posti e deve essere lo stesso:
//!
//! - sul collegamento del menu Start, che l'installer crea (`wix/Package.wxs`);
//! - dichiarato dal **processo**, che e' ciò che fa questo modulo.
//!
//! Basta il collegamento? A volte. Windows lo deduce dal collegamento che ha
//! avviato il programma, ma non quando il programma parte in altro modo — da
//! Esplora file, dall'avvio automatico, da un debugger. Dichiararlo
//! esplicitamente rende l'attribuzione indipendente da **come** l'applicazione
//! e' stata avviata, che e' l'unica forma su cui si possa contare.
//!
//! # Perche' l'identificativo sta qui e non nell'installer
//!
//! Perche' devono essere lo stesso, e due copie di una stringa che devono
//! coincidere prima o poi non coincidono. `scripts/build-installer.ps1` legge
//! [`APP_USER_MODEL_ID`] **da questo sorgente** e lo passa a WiX: una sola
//! fonte, e un test che ne protegge la forma.
//!
//! # Invarianti di sicurezza
//!
//! 1. L'unico argomento e' una **costante del programma**, convertita in UTF-16
//!    terminata da zero; nessun dato esterno raggiunge la chiamata.
//! 2. La stringa vive per tutta la durata della chiamata, che non la conserva.
//! 3. L'esito e' un `HRESULT` interpretato secondo il contratto, senza
//!    dereferenziare nulla.
//! 4. Nessuna memoria di Windows viene allocata o liberata.

use crate::error::{PlatformError, PlatformResult};

/// Identificativo dell'applicazione presso Windows.
///
/// **Non si rinomina.** E' scritto nei collegamenti gia' installati sulle
/// postazioni: cambiarlo significherebbe che gli avvisi emessi da una
/// installazione nuova non sono piu' attribuiti alla stessa applicazione, e i
/// vecchi collegamenti resterebbero legati a un'identita' che non esiste piu'.
///
/// La forma e' quella raccomandata da Microsoft — `Editore.Prodotto.Componente`
/// — senza spazi e senza barre: la barra del nome pubblico `NEXUM/97` non e'
/// ammessa in un AppUserModelID.
pub const APP_USER_MODEL_ID: &str = "GiuseppeLisi.NEXUM97.TelegramMonitor";

/// Dichiara a Windows l'identita' di questo processo.
///
/// Va chiamata **prima** che la finestra esista: dopo, Windows ha gia' deciso
/// come raggruppare l'applicazione sulla barra delle applicazioni, e la
/// dichiarazione tardiva non sposta il raggruppamento gia' fatto.
///
/// # Errori
///
/// Restituisce [`PlatformError::AppIdentityRefused`] se il sistema rifiuta.
/// **Non e' fatale**: l'applicazione funziona, e semplicemente gli avvisi
/// nativi non le vengono attribuiti.
#[cfg(windows)]
pub fn declare() -> PlatformResult<()> {
    use windows_sys::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;

    let wide: Vec<u16> = APP_USER_MODEL_ID
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: le invarianti sono in testa al modulo. L'argomento e' una
    // costante del programma convertita in UTF-16 terminata da zero, che vive
    // per tutta la chiamata; la funzione non la conserva. L'esito e' un
    // HRESULT confrontato con zero e mai dereferenziato.
    let outcome = unsafe { SetCurrentProcessExplicitAppUserModelID(wide.as_ptr()) };

    if outcome < 0 {
        return Err(PlatformError::AppIdentityRefused { code: outcome });
    }
    Ok(())
}

/// Fuori da Windows non esiste alcuna identita' da dichiarare.
#[cfg(not(windows))]
pub fn declare() -> PlatformResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::APP_USER_MODEL_ID;

    #[test]
    fn the_identifier_has_the_shape_windows_accepts() {
        // Un AppUserModelID non ammette spazi, e la barra del nome pubblico
        // `NEXUM/97` non e' ammessa: se qualcuno un giorno lo derivasse dal
        // nome del prodotto, otterrebbe un identificativo che Windows rifiuta
        // **in silenzio**, e la sola conseguenza visibile sarebbe che gli
        // avvisi non compaiono piu'.
        assert!(!APP_USER_MODEL_ID.contains(' '));
        assert!(!APP_USER_MODEL_ID.contains('/'));
        assert!(!APP_USER_MODEL_ID.contains('\\'));

        // Microsoft pone il limite a 128 caratteri.
        assert!(APP_USER_MODEL_ID.len() <= 128);
        assert!(!APP_USER_MODEL_ID.is_empty());

        // La forma raccomandata ha tre parti: editore, prodotto, componente.
        assert_eq!(APP_USER_MODEL_ID.split('.').count(), 3);
    }

    #[test]
    fn the_identifier_is_the_one_the_installer_writes() {
        // L'installer legge questa costante **da questo sorgente**, quindi le
        // due non possono divergere. Il test protegge la **forma** della riga,
        // che e' cio' su cui lo script si appoggia: se un giorno diventasse una
        // `concat!` o venisse spezzata su piu' righe, lo script non la
        // troverebbe e passerebbe a WiX un identificativo vuoto — e il toast
        // sparirebbe senza che nulla lo segnali.
        const SOURCE: &str = include_str!("app_identity.rs");
        assert!(
            SOURCE.contains("pub const APP_USER_MODEL_ID: &str = \""),
            "la forma della costante e' un contratto con build-installer.ps1"
        );
    }
}

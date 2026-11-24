// UNICO modulo del crate autorizzato a contenere `unsafe`.
//
// Il divieto vale per tutto il resto di `lisi-platform`. Questa deroga è
// esplicita, circoscritta a un solo file e visibile in diff (ADR-0003, ADR-0018).
//
// La deroga è vincolata a Windows: solo lì c'è FFI. Fuori da Windows il modulo
// non contiene `unsafe`, e il `forbid` del crate resta pieno (senza un `allow`
// che vi confliggerebbe).
#![cfg_attr(windows, allow(unsafe_code))]

//! Apertura di un URL nel browser predefinito.
//!
//! # Che cosa apre, e con quale ambito
//!
//! La scelta è motivata in `docs/adr/ADR-0018-SECURE-URL-OPENING.md`. L'URL
//! arriva da un contenuto remoto, cioè ostile per ipotesi: si accetta soltanto
//! uno schema web (`http`/`https`) e lo si passa a `ShellExecuteW` con il verbo
//! `open`, che apre il browser predefinito. Nessuna stringa arbitraria
//! raggiunge il sistema.
//!
//! La validazione autorevole (schema, caratteri, lunghezza) è nei servizi, via
//! `ContentUrl`. Il controllo qui è la **rete di sicurezza**: anche un chiamante
//! diretto non può far aprire `file://` o `javascript:`.
//!
//! # Invarianti di sicurezza
//!
//! 1. `ShellExecuteW` riceve un URL già validato (schema web) e il verbo
//!    `"open"`; nessuna stringa arbitraria vi arriva.
//! 2. Le stringhe passate sono UTF-16 con terminatore nullo, vive per tutta la
//!    durata della chiamata (restano in scope nei `Vec<u16>`).
//! 3. I parametri non usati (parametri, cartella) sono puntatori nulli; la
//!    finestra genitrice è nulla.
//! 4. L'esito è interpretato secondo il contratto documentato — un valore
//!    `> 32` è successo, il resto è un codice d'errore — senza dereferenziare il
//!    valore restituito.
//! 5. Nessun puntatore di Windows sopravvive alla chiamata; non si alloca né si
//!    libera memoria di Windows.
//!
//! # Limite dichiarato
//!
//! Un URL validato può comunque portare a un sito ostile: la validazione
//! garantisce un URL web ben formato, non una destinazione fidata. La pagina si
//! apre nel browser (fuori dal processo), non qui.

use crate::error::{PlatformError, PlatformResult};

/// Apre l'URL indicato nel browser predefinito.
///
/// # Errori
///
/// Restituisce [`PlatformError::UnsupportedScheme`] se lo schema non è
/// `http`/`https`, [`PlatformError::LaunchFailed`] se il sistema rifiuta
/// l'apertura, e [`PlatformError::Unsupported`] fuori da Windows.
pub fn open_in_browser(url: &str) -> PlatformResult<()> {
    let trimmed = url.trim();

    // Rete di sicurezza indipendente dal chiamante. La validazione autorevole è
    // nei servizi (`ContentUrl`); qui si ripetono i due controlli che rendono
    // sicura la consegna a `ShellExecuteW`, così che valgano anche per un
    // chiamante diretto di questo crate:
    //
    // 1. nessuno spazio o carattere di controllo. L'assenza di spazi è ciò che
    //    neutralizza l'iniezione di argomenti verso l'handler del browser;
    if trimmed
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(PlatformError::MalformedUrl);
    }
    // 2. solo schema web: niente `file://`, `javascript:`, handler arbitrari.
    let lower = trimmed.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return Err(PlatformError::UnsupportedScheme);
    }

    launch(trimmed)
}

#[cfg(windows)]
fn launch(url: &str) -> PlatformResult<()> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    // Invariante 2: le stringhe restano vive per tutta la chiamata.
    let verb: Vec<u16> = "open".encode_utf16().chain(core::iter::once(0)).collect();
    let target: Vec<u16> = url.encode_utf16().chain(core::iter::once(0)).collect();

    // Invarianti 1 e 3: `url` è già validato; verbo "open"; nessuna finestra
    // genitrice, nessun parametro, nessuna cartella di lavoro.
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

    // Invariante 4: contratto documentato di ShellExecuteW.
    let code = result as isize;
    if code > 32 {
        return Ok(());
    }

    // `SE_ERR_NOASSOC` significa «nessuna applicazione associata a questo
    // schema», ed e' un caso diverso da un guasto: chi chiama puo' ripiegare su
    // un'altra strada invece di riportare un errore all'operatore. Distinguerlo
    // e' cio' che permette di aprire Telegram quando c'e' e il browser quando
    // non c'e', senza indovinare.
    if code == SE_ERR_NOASSOC {
        return Err(PlatformError::NoAssociatedApplication);
    }

    Err(PlatformError::LaunchFailed { code })
}

/// Codice di `ShellExecuteW` per «nessuna applicazione associata».
#[cfg(windows)]
const SE_ERR_NOASSOC: isize = 31;

#[cfg(not(windows))]
fn launch(_url: &str) -> PlatformResult<()> {
    Err(PlatformError::Unsupported)
}

/// Consegna al sistema un indirizzo **gia' composto dal prodotto**.
///
/// Non applica la validazione di schema di [`open_in_browser`], ed e' per
/// questo `pub(crate)`: l'unico chiamante e' `telegram_link`, che accetta
/// soltanto la forma numerica che il prodotto stesso genera e compone
/// l'indirizzo da due numeri. Nessuna stringa proveniente da un contenuto
/// acquisito arriva qui.
///
/// Le due garanzie che restano — niente spazi, niente caratteri di controllo —
/// sono verificate comunque, perche' sono quelle che neutralizzano l'iniezione
/// di argomenti verso l'handler.
pub(crate) fn launch_raw(target: &str) -> PlatformResult<()> {
    if target
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(PlatformError::MalformedUrl);
    }

    launch(target)
}

#[cfg(test)]
mod tests {
    use super::open_in_browser;
    use crate::error::PlatformError;

    #[test]
    fn a_non_web_scheme_is_refused_before_touching_the_system() {
        // La prova di sicurezza: nessuno di questi raggiunge `ShellExecute`,
        // perché lo schema è respinto prima del dispatch.
        for dangerous in [
            "file:///C:/Windows/System32/cmd.exe",
            "javascript:alert(1)",
            "ms-settings:",
            "\\\\server\\share",
            "C:\\Windows\\System32\\calc.exe",
            "mailto:qualcuno@example.invalid",
            "",
            "   ",
            "ftp://example.invalid/file",
        ] {
            assert!(
                matches!(
                    open_in_browser(dangerous),
                    Err(PlatformError::UnsupportedScheme)
                ),
                "'{dangerous}' doveva essere respinto per lo schema"
            );
        }
    }

    #[test]
    fn whitespace_or_control_in_the_url_is_refused_even_with_a_web_scheme() {
        // È il controllo che rende la rete indipendente dal chiamante: uno
        // spazio interno è il vettore dell'iniezione di argomenti, e va fermato
        // qui, non solo in `ContentUrl`.
        for malformed in [
            "http://esempio.invalid/ --arg",
            "https://t.me/a\tb",
            "http://esempio.invalid/\u{0}x",
        ] {
            assert!(
                matches!(open_in_browser(malformed), Err(PlatformError::MalformedUrl)),
                "'{malformed}' doveva essere respinto come malformato"
            );
        }
    }

    // Aprire davvero un browser in un test non è ammissibile, quindi il caso
    // ammesso (schema web che supera il controllo) non si prova qui contro
    // `ShellExecute`, ma al livello dei servizi, dove il destinatario
    // dell'apertura è iniettabile e i test usano un doppio che registra invece
    // di aprire (ADR-0018).
    //
    // Fuori da Windows lo si può però provare fino in fondo senza effetti: il
    // dispatch restituisce `Unsupported`, cioè lo schema **ha** superato il
    // controllo (non è `UnsupportedScheme`).
    #[cfg(not(windows))]
    #[test]
    fn a_web_scheme_passes_the_gate_and_reaches_the_dispatch() {
        assert!(matches!(
            open_in_browser("https://t.me/canale/1"),
            Err(PlatformError::Unsupported)
        ));
    }
}

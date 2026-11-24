// SECONDO modulo del crate autorizzato a contenere `unsafe`, dopo `browser`.
//
// La deroga e' esplicita, circoscritta a un solo file e visibile in diff
// (ADR-0003, ADR-0020). Vale solo su Windows: fuori da li' non c'e' FFI e il
// `forbid` del crate resta pieno.
#![cfg_attr(windows, allow(unsafe_code))]

//! Aspetto della cornice di finestra decisa dal sistema.
//!
//! # Che cosa fa, e perche' serve
//!
//! L'applicazione e' blu notte; la barra del titolo la disegna Windows, e senza
//! questa chiamata la disegna **bianca**. Il risultato e' una fascia chiara
//! sopra un'interfaccia scura: e' il difetto piu' vistoso che resta, e nessuna
//! quantita' di lavoro sotto lo compensa.
//!
//! `DWMWA_USE_IMMERSIVE_DARK_MODE` chiede al gestore delle finestre di rendere
//! la barra del titolo, i bordi e i comandi di sistema nella variante scura.
//! **Non disegna nulla di nostro**: la cornice resta quella del sistema, con i
//! suoi comandi, il suo comportamento e la sua accessibilita'. E' precisamente
//! il motivo per cui questa e' la strada scelta invece di una barra del titolo
//! costruita a mano, che avrebbe portato con se' trascinamento, aggancio ai
//! bordi, ridimensionamento e resa dei comandi - tutto da riscrivere e tutto da
//! sbagliare.
//!
//! # Perche' serve anche un ridisegno della cornice
//!
//! Impostare l'attributo su una finestra **gia' visibile** non basta: il
//! gestore delle finestre applica la variante scura al ridisegno successivo
//! della cornice, e finche' quel ridisegno non avviene la barra resta come
//! prima. `SetWindowPos` con `SWP_FRAMECHANGED` lo chiede senza spostare,
//! ridimensionare, riordinare o attivare la finestra.
//!
//! # Invarianti di sicurezza
//!
//! 1. `DwmSetWindowAttribute` e `SetWindowPos` ricevono un handle di finestra
//!    **non nullo**, che il chiamante ha ottenuto dal proprio gestore di
//!    finestre; il modulo non lo cerca, non lo indovina e non enumera le
//!    finestre altrui.
//! 2. Il puntatore passato punta a una variabile locale viva per tutta la
//!    durata della chiamata, e la dimensione dichiarata e' esattamente quella
//!    di quella variabile.
//! 3. L'attributo e il valore sono costanti note; nessun dato esterno raggiunge
//!    la chiamata.
//! 4. L'esito e' interpretato secondo il contratto documentato (`S_OK` vale
//!    zero) senza dereferenziare nulla.
//! 5. `SetWindowPos` riceve posizione e dimensione nulle **insieme ai flag che
//!    le rendono ignorate**: la finestra non viene ne' spostata ne'
//!    ridimensionata ne' riattivata.
//! 6. Nessun puntatore di Windows sopravvive alla chiamata; non si alloca ne'
//!    si libera memoria di Windows.
//!
//! # Limite dichiarato
//!
//! L'attributo esiste da Windows 10 versione 1809 e ha cambiato numero fra le
//! prime build: su un sistema che non lo conosce la chiamata **fallisce senza
//! effetti**, e la barra resta chiara. E' un difetto estetico, non funzionale,
//! e per questo l'esito non e' fatale: l'applicazione parte comunque.

use crate::error::PlatformResult;

/// Numero dell'attributo `DWMWA_USE_IMMERSIVE_DARK_MODE`.
///
/// Vale 20 dalla build 18985 in poi. Nelle build precedenti (1809, 1903, 1909)
/// lo stesso significato aveva il numero 19, e Microsoft lo ha rinumerato senza
/// mantenere il vecchio. Si tenta prima quello corrente e, se rifiutato, il
/// precedente: sono due numeri, non due comportamenti diversi.
#[cfg(windows)]
const DWMWA_USE_IMMERSIVE_DARK_MODE: u32 = 20;

/// Numero dello stesso attributo nelle build fra 1809 e 1909.
#[cfg(windows)]
const DWMWA_USE_IMMERSIVE_DARK_MODE_LEGACY: u32 = 19;

/// Rende scura la barra del titolo della finestra indicata.
///
/// `handle` e' l'handle nativo (`HWND`) ottenuto dal gestore di finestre. Zero
/// non e' un handle valido e viene rifiutato prima di attraversare la FFI.
///
/// **L'esito non e' fatale.** Su un sistema che non conosce l'attributo la
/// barra resta chiara e l'applicazione funziona: chi chiama registra l'esito e
/// prosegue.
#[cfg(windows)]
pub fn use_dark_title_bar(handle: isize) -> PlatformResult<()> {
    use crate::error::PlatformError;
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::Graphics::Dwm::DwmSetWindowAttribute;

    if handle == 0 {
        return Err(PlatformError::WindowUnavailable);
    }

    // `BOOL` di Windows e' un intero a 32 bit con segno. Si scrive il tipo
    // sottostante invece dell'alias perche' `windows-sys` 0.61 non lo espone
    // piu': il valore che attraversa la FFI e' lo stesso, ed e' la dimensione
    // dichiarata qui sotto a doverlo rispecchiare.
    let enabled: i32 = 1;
    let size =
        u32::try_from(core::mem::size_of::<i32>()).expect("la dimensione di un i32 sta in un u32");

    for attribute in [
        DWMWA_USE_IMMERSIVE_DARK_MODE,
        DWMWA_USE_IMMERSIVE_DARK_MODE_LEGACY,
    ] {
        // SAFETY: le invarianti sono in testa al modulo. `handle` e' non nullo
        // (verificato sopra) e proviene dal gestore di finestre del chiamante;
        // il puntatore punta a `enabled`, viva fino al termine del ciclo, e la
        // dimensione dichiarata e' quella di quella variabile; l'attributo e'
        // una costante nota. Il valore restituito e' un `HRESULT` confrontato
        // con zero, mai dereferenziato.
        let outcome = unsafe {
            DwmSetWindowAttribute(
                handle as HWND,
                attribute,
                core::ptr::addr_of!(enabled).cast(),
                size,
            )
        };

        if outcome == 0 {
            redraw_frame(handle);
            return Ok(());
        }
    }

    Err(PlatformError::WindowAttributeRefused)
}

/// Chiede il ridisegno della sola cornice, senza toccare la finestra.
///
/// Su una finestra gia' visibile l'attributo non produce effetto finche' la
/// cornice non viene ridisegnata: senza questa richiesta la barra resta chiara
/// fino al primo ridimensionamento fatto a mano dall'operatore.
#[cfg(windows)]
fn redraw_frame(handle: isize) {
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SWP_FRAMECHANGED, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, SetWindowPos,
    };

    // SAFETY: `handle` e' non nullo (verificato dal chiamante). Posizione e
    // dimensione valgono zero e sono **ignorate** per via di `SWP_NOMOVE` e
    // `SWP_NOSIZE`; `SWP_NOZORDER` e `SWP_NOACTIVATE` impediscono riordino e
    // attivazione. La finestra da inserire prima e' nulla e non viene usata.
    // L'esito non e' interpretato: se il ridisegno non avviene, la barra resta
    // com'era, che e' esattamente lo stato di partenza.
    unsafe {
        SetWindowPos(
            handle as HWND,
            core::ptr::null_mut(),
            0,
            0,
            0,
            0,
            SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
        );
    }
}

/// Una finestra di messaggio di Windows, per quando il programma **non è
/// riuscito ad aprire la propria** (FINAL-REVIEW-01, FR-033).
///
/// Il programma gira senza console: un errore d'avvio scritto su `stderr` non
/// lo legge nessuno, e chi ha fatto doppio clic vede soltanto che non succede
/// niente. Qui Windows mostra la frase e un pulsante, e aspetta.
///
/// # Invarianti di sicurezza
///
/// `MessageBoxW` riceve due stringhe UTF-16 terminate da zero, possedute da
/// questa funzione e vive per tutta la chiamata; nessuna finestra madre
/// (handle nullo, ammesso dall'API). Un carattere nullo dentro il testo lo
/// accorcerebbe, non lo renderebbe pericoloso: si toglie prima.
#[cfg(windows)]
pub fn show_fatal_message(title: &str, text: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};

    let utf16 = |testo: &str| -> Vec<u16> {
        testo
            .encode_utf16()
            .filter(|unita| *unita != 0)
            .chain(std::iter::once(0))
            .collect()
    };
    let titolo = utf16(title);
    let corpo = utf16(text);
    // SAFETY: vedere le invarianti qui sopra; i due vettori vivono fino alla
    // fine della chiamata, che è sincrona.
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            corpo.as_ptr(),
            titolo.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

/// Fuori da Windows non c'è una finestra di sistema da mostrare.
#[cfg(not(windows))]
pub fn show_fatal_message(_title: &str, _text: &str) {}

/// Fuori da Windows non c'e' alcuna barra del titolo da rendere scura.
///
/// Esiste perche' il chiamante non debba avvolgere la chiamata in `cfg`: il
/// confine di piattaforma sta qui, non nell'interfaccia.
#[cfg(not(windows))]
pub fn use_dark_title_bar(_handle: isize) -> PlatformResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::use_dark_title_bar;

    #[test]
    #[cfg(windows)]
    fn a_null_handle_is_refused_before_reaching_the_system() {
        // Zero non e' una finestra. Il controllo sta PRIMA della FFI: passarlo
        // al sistema per farselo rifiutare significherebbe attraversare il
        // confine con un valore che sappiamo gia' invalido.
        let Err(error) = use_dark_title_bar(0) else {
            panic!("un handle nullo deve essere rifiutato");
        };

        // Il messaggio non riecheggia il valore ricevuto: non c'e' nulla di
        // utile da dire su uno zero, e un messaggio che ripete l'input e' il
        // modo in cui un dato non fidato finisce sotto gli occhi di qualcuno.
        assert!(!format!("{error}").contains('0'));
    }
}

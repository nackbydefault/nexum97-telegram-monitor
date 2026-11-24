// TERZO modulo del crate autorizzato a contenere `unsafe`, dopo `browser` e
// `window_chrome`. La deroga e' esplicita, circoscritta a un solo file e
// visibile in diff (ADR-0003, ADR-0028). Vale solo su Windows.
#![cfg_attr(windows, allow(unsafe_code))]

//! Barra del titolo disegnata dal prodotto.
//!
//! # La scelta, e perche' non e' quella che sembra
//!
//! ADR-0020 aveva scartato una barra del titolo propria elencando cio' che
//! sarebbe stato **tutto da riscrivere**: trascinamento, aggancio ai bordi,
//! scorciatoie di Windows, ridimensionamento dai lati e dagli angoli, doppio
//! clic per massimizzare, menu di sistema. Quelle ragioni restano vere, e
//! questo modulo **non le sfida: le aggira**.
//!
//! La via ovvia sarebbe una finestra senza cornice (`WS_POPUP`), e con essa
//! ognuno di quei comportamenti andrebbe davvero riscritto a mano. La via presa
//! e' un'altra: la finestra resta una **normale finestra sovrapposta**, con la
//! sua cornice e la sua logica, e le si toglie soltanto **il disegno della
//! didascalia**.
//!
//! Due messaggi bastano:
//!
//! - `WM_NCCALCSIZE` dice a Windows che l'area cliente occupa anche lo spazio
//!   dove la didascalia sarebbe stata disegnata. Windows smette di disegnarla;
//!   la finestra resta quella di prima sotto ogni altro aspetto;
//! - `WM_NCHITTEST` dice, per ogni punto, **che cosa Windows deve credere di
//!   avere sotto il puntatore**. Sulla fascia in alto risponde «didascalia», e
//!   da quel momento il trascinamento, l'aggancio ai bordi, il doppio clic per
//!   massimizzare e il menu di sistema li fa **Windows**, esattamente come
//!   prima, perche' per Windows quella *e'* una didascalia.
//!
//! **Nulla di tutto cio' e' riscritto qui.** Il modulo non muove finestre, non
//! calcola agganci e non implementa il ridimensionamento: dice dove sono le
//! cose e lascia fare al sistema. E' la ragione per cui l'elenco di ADR-0020 non
//! si e' trasformato in altrettanti difetti.
//!
//! # La finestra non e' nostra, e due tentativi sono finiti male
//!
//! La finestra la crea **winit**, dentro Slint, e questo modulo vi si aggiunge.
//! Due strade sono state percorse e scartate, entrambe con un sintomo che
//! nessun test poteva mostrare:
//!
//! **Primo tentativo — `GWLP_USERDATA` per lo stato.** Quello slot **e' di
//! winit**, che vi tiene il proprio. Il controllo di idempotenza lo ha visto
//! occupato e ha rifiutato l'installazione — per fortuna, perche' scriverci
//! avrebbe corrotto lo stato di chi possiede la finestra. Sintomo: **due barre
//! del titolo, una sopra l'altra**, e una riga di avviso nel registro.
//!
//! **Secondo tentativo — `SetWindowSubclass` di comctl32.** E' l'API pensata
//! esattamente per aggiungere un gestore a una finestra di altri, e porta con se'
//! il proprio dato di riferimento. Usarla **importa comctl32**, e con quel
//! collegamento il processo **si blocca prima di `main`**: nessuna finestra,
//! nessun errore, nessuna riga di registro. Trovato con dei sassolini scritti su
//! file, perche' un'applicazione senza console non ha altro modo di dirlo.
//!
//! **Terza strada, quella in vigore.** Procedura di finestra sostituita con
//! `GWLP_WNDPROC` — user32, gia' collegato — e stato in una **proprieta' di
//! finestra** (`SetPropW`) con un nome proprio del prodotto. Non contende alcuno
//! slot a winit e non aggiunge alcuna libreria.
//!
//! **La lezione, doppia:** su una finestra che non si e' creata, `GWLP_USERDATA`
//! non e' libero; e aggiungere una libreria di sistema al collegamento puo'
//! costare l'avvio del programma, non solo qualche byte.
//!
//! # Invarianti di sicurezza
//!
//! 1. Ogni funzione riceve un handle **non nullo**, ottenuto dal chiamante dal
//!    proprio gestore di finestre; il modulo non cerca, non enumera e non
//!    indovina finestre altrui.
//! 2. Lo stato e' un `Box` il cui puntatore vive in una proprieta' di finestra
//!    dal nome del prodotto. Viene creato una volta sola in [`install`] e
//!    **liberato in `WM_NCDESTROY`**, l'ultimo messaggio che una finestra
//!    riceve, subito dopo aver tolto la proprieta': nessun puntatore sopravvive
//!    alla finestra.
//! 3. La procedura non dereferenzia una proprieta' assente: inoltra e basta.
//! 4. Ogni messaggio non gestito qui passa per `CallWindowProcW` verso la
//!    procedura precedente, mai saltato: deve ricevere il trattamento che
//!    avrebbe ricevuto senza questo modulo.
//! 5. `install` e' idempotente: la presenza della proprieta' dice che c'e' gia',
//!    e una seconda chiamata viene rifiutata invece di incatenare due volte la
//!    stessa procedura, che ricorrerebbe all'infinito.
//! 6. Nessuna memoria di Windows viene allocata o liberata; l'unico puntatore
//!    creato qui e' quello dello stato, e la sua vita e' descritta al punto 2.
//!
//! # Limiti dichiarati
//!
//! Il modulo **non e' stato provato** con l'aggancio ai bordi, le scorciatoie
//! `Win`+frecce, il ridimensionamento da ogni angolo, il menu di sistema e la
//! modalita' a contrasto elevato: sono comportamenti che Windows fornisce e che
//! questo modulo si limita a non ostacolare, ma «dovrebbero funzionare» non e'
//! «funzionano». Appartengono a MP-15E, e sono elencati nel pilot.

// Su Windows lo usa il modulo interno, che lo importa per conto proprio.
#[cfg(not(windows))]
use crate::error::PlatformResult;

/// Misure della barra, in pixel fisici della finestra.
///
/// Le riceve il chiamante dall'interfaccia invece di fissarle qui: la geometria
/// del guscio e' una decisione del sistema grafico (`Shell` in `tokens.slint`),
/// e duplicarla qui significherebbe che un giorno le due copie diranno cose
/// diverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TitleBarMetrics {
    /// Altezza della fascia trascinabile.
    pub height: i32,
    /// Larghezza della zona dei comandi, misurata dal bordo destro.
    ///
    /// Su quella zona la risposta e' «area cliente», cosi' che i clic arrivino
    /// ai comandi disegnati dal prodotto invece di iniziare un trascinamento.
    pub commands_width: i32,
    /// Spessore del bordo su cui si afferra per ridimensionare.
    pub border: i32,
}

/// Che cosa si trova sotto un punto della finestra.
///
/// E' un tipo del prodotto e non una costante di Windows perche' la geometria
/// si possa **provare senza una finestra**: e' la parte piu' facile da
/// sbagliare, ed e' l'unica che non richiede il sistema per essere verificata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Zone {
    TopLeft,
    Top,
    TopRight,
    Left,
    Right,
    BottomLeft,
    Bottom,
    BottomRight,
    /// La fascia trascinabile: Windows la trattera' come una didascalia.
    Caption,
    /// Tutto il resto, compresi i comandi della barra.
    Client,
}

/// Che cosa si trova nel punto indicato, in coordinate relative alla finestra.
///
/// Funzione pura: nessuna chiamata al sistema, nessuno stato. E' scritta cosi'
/// apposta, perche' e' il pezzo che decide se una finestra si ridimensiona
/// dall'angolo giusto, e provarlo a mano su uno schermo e' lento e incompleto.
///
/// **Una finestra massimizzata non si ridimensiona trascinandone i bordi**: li'
/// le zone di ridimensionamento non esistono, e la fascia in alto resta
/// trascinabile perche' trascinarla e' cio' che la ripristina.
#[must_use]
pub const fn zone_at(
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    metrics: TitleBarMetrics,
    maximised: bool,
) -> Zone {
    if !maximised {
        let left = x < metrics.border;
        let right = x >= width - metrics.border;
        let top = y < metrics.border;
        let bottom = y >= height - metrics.border;

        // Gli angoli prima dei lati: un punto nell'angolo appartiene a
        // entrambi, e chi lo afferra si aspetta di ridimensionare in diagonale.
        if top && left {
            return Zone::TopLeft;
        }
        if top && right {
            return Zone::TopRight;
        }
        if bottom && left {
            return Zone::BottomLeft;
        }
        if bottom && right {
            return Zone::BottomRight;
        }
        if top {
            return Zone::Top;
        }
        if bottom {
            return Zone::Bottom;
        }
        if left {
            return Zone::Left;
        }
        if right {
            return Zone::Right;
        }
    }

    if y < metrics.height && x < width - metrics.commands_width {
        return Zone::Caption;
    }

    Zone::Client
}

/// `WM_NCRBUTTONUP`: clic destro rilasciato su un'area non cliente.
const MESSAGE_NC_RIGHT_BUTTON_UP: u32 = 0x00A5;
/// `WM_SYSKEYDOWN`: tasto premuto con Alt.
const MESSAGE_SYSTEM_KEY_DOWN: u32 = 0x0104;
/// `HTCAPTION`, come lo dichiara Windows.
const HIT_CAPTION: usize = 2;
/// `VK_SPACE`.
const KEY_SPACE: usize = 0x20;
/// Bit 29 di `lparam`: Alt era premuto quando il tasto e' stato battuto.
const ALT_HELD: isize = 1 << 29;

/// Se questo messaggio e' **il gesto che apre il menu di sistema**.
///
/// I due gesti sono quelli di sempre: clic destro sulla fascia del titolo, e
/// Alt+Spazio.
///
/// # Perche' questa funzione esiste
///
/// ADR-0028 afferma che, rispondendo «didascalia» sulla fascia, il menu di
/// sistema resta di Windows. **Non e' cosi', e lo ha trovato il pilot** (voce
/// O7): il menu esiste — la finestra ha `WS_SYSMENU` e sette voci — ma nessuno
/// dei due gesti lo apre.
///
/// La causa non e' nel prodotto ed e' in winit: la sua procedura di finestra
/// consuma `WM_KEYDOWN`, `WM_SYSKEYDOWN`, `WM_KEYUP` e `WM_SYSKEYUP`
/// restituendo zero (`event_loop.rs`, ramo dei modificatori), quindi Alt+Spazio
/// non diventa mai `SC_KEYMENU`; e il clic destro sulla fascia non arriva a
/// `DefWindowProcW`. Con la didascalia di sistema il difetto non esisteva,
/// perche' quei gesti li intercettava Windows prima di chiunque altro.
///
/// Riconoscere il gesto e' aritmetica su tre numeri, quindi sta qui: **si prova
/// senza una finestra**, come `zone_at`.
#[must_use]
pub const fn opens_system_menu(message: u32, wparam: usize, lparam: isize) -> bool {
    match message {
        MESSAGE_NC_RIGHT_BUTTON_UP => wparam == HIT_CAPTION,
        MESSAGE_SYSTEM_KEY_DOWN => wparam == KEY_SPACE && (lparam & ALT_HELD) != 0,
        _ => false,
    }
}

#[cfg(windows)]
mod windows_impl {
    use super::{TitleBarMetrics, Zone, opens_system_menu, zone_at};
    use crate::error::{PlatformError, PlatformResult};
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CallWindowProcW, DefWindowProcW, GWLP_HINSTANCE, GWLP_WNDPROC, GetPropW, GetSystemMetrics,
        GetWindowLongPtrW, GetWindowRect, HTBOTTOM, HTBOTTOMLEFT, HTBOTTOMRIGHT, HTCAPTION,
        HTCLIENT, HTLEFT, HTRIGHT, HTTOP, HTTOPLEFT, HTTOPRIGHT, ICON_BIG, ICON_SMALL, IMAGE_ICON,
        IsZoomed, LR_DEFAULTCOLOR, LR_SHARED, LoadImageW, NCCALCSIZE_PARAMS, PostMessageW,
        RemovePropW, SC_KEYMENU, SM_CXICON, SM_CXSMICON, SM_CYICON, SM_CYSMICON, SW_MINIMIZE,
        SW_RESTORE, SW_SHOWMAXIMIZED, SWP_FRAMECHANGED, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE,
        SWP_NOZORDER, SendMessageW, SetPropW, SetWindowLongPtrW, SetWindowPos, ShowWindow,
        WM_CLOSE, WM_NCCALCSIZE, WM_NCDESTROY, WM_NCHITTEST, WM_SETICON, WM_SYSCOMMAND, WNDPROC,
    };

    /// Lo spazio, che `SC_KEYMENU` vuole in `lparam` per aprire il menu di
    /// finestra invece di una voce della barra dei menu.
    const KEY_SPACE_PARAM: u32 = 0x20;

    /// Identificatore della risorsa icona dentro l'eseguibile.
    ///
    /// E' `1` perche' e' quello che `build.rs` scrive, ed e' quello che la
    /// shell di Windows cerca per prima quando deve rappresentare un file.
    const RESOURCE_ICON: usize = 1;

    /// Nome della proprieta' di finestra in cui vive lo stato.
    ///
    /// **Non `GWLP_USERDATA`**: quello slot e' di winit, che vi tiene il
    /// proprio stato. Una proprieta' con un nome proprio non contende nulla a
    /// nessuno, ed e' il modo previsto per attaccare un dato a una finestra di
    /// altri senza comctl32 - che non si puo' usare, perche' importarlo blocca
    /// il processo prima ancora di `main` (vedi la nota in testa al modulo).
    ///
    /// Terminato da zero, come ogni stringa larga che attraversa la FFI.
    const PROPERTY: [u16; 15] = [
        b'N' as u16,
        b'E' as u16,
        b'X' as u16,
        b'U' as u16,
        b'M' as u16,
        b'9' as u16,
        b'7' as u16,
        b'.' as u16,
        b't' as u16,
        b'i' as u16,
        b't' as u16,
        b'l' as u16,
        b'e' as u16,
        b'.' as u16,
        0,
    ];

    /// Stato che il gestore rilegge a ogni messaggio.
    ///
    /// Vive in un `Box` il cui puntatore sta nella proprieta' di finestra, e
    /// muore con la finestra in `WM_NCDESTROY`.
    struct State {
        previous: WNDPROC,
        metrics: TitleBarMetrics,
    }

    /// Installa la barra del titolo del prodotto sulla finestra indicata.
    pub fn install(handle: isize, metrics: TitleBarMetrics) -> PlatformResult<()> {
        if handle == 0 {
            return Err(PlatformError::WindowUnavailable);
        }
        if metrics.height <= 0 || metrics.border < 0 || metrics.commands_width < 0 {
            return Err(PlatformError::WindowAttributeRefused);
        }

        // SAFETY: `handle` e' non nullo (verificato sopra). `GetPropW` legge un
        // valore associato alla finestra dal nome indicato, e non dereferenzia
        // nulla; il nome e' una costante terminata da zero.
        let already = unsafe { GetPropW(handle as HWND, PROPERTY.as_ptr()) };
        if !already.is_null() {
            // Invariante 5: reinstallare incatenerebbe due volte la stessa
            // procedura, con ricorsione infinita al primo messaggio.
            return Err(PlatformError::WindowAttributeRefused);
        }

        // Il nome di una funzione non e' un puntatore, e un puntatore a funzione
        // non e' un intero: si passa per un puntatore grezzo, che e' cio' che
        // `SetWindowLongPtrW` vuole davvero sotto le spoglie di un `isize`.
        let ours: unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT =
            window_procedure;
        let ours = ours as *const core::ffi::c_void as isize;

        // SAFETY: si sostituisce la procedura di finestra con la nostra,
        // conservando la precedente. Il valore restituito e' un puntatore a
        // funzione fornito da Windows, richiamato solo tramite `CallWindowProcW`.
        let previous = unsafe { SetWindowLongPtrW(handle as HWND, GWLP_WNDPROC, ours) };
        if previous == 0 {
            return Err(PlatformError::WindowAttributeRefused);
        }

        // SAFETY: la conversione porta l'intero restituito da
        // `SetWindowLongPtrW` al tipo di puntatore a funzione che
        // `CallWindowProcW` richiede. E' lo stesso valore, e Windows garantisce
        // che sia una procedura valida finche' la finestra vive.
        let previous: WNDPROC = unsafe { core::mem::transmute(previous) };

        let state = Box::new(State { previous, metrics });
        let pointer = Box::into_raw(state);

        // SAFETY: si associa alla finestra il puntatore allo stato, sotto un
        // nome proprio del prodotto. Da qui la finestra ne e' proprietaria, e la
        // procedura lo liberera' in `WM_NCDESTROY`.
        let stored = unsafe { SetPropW(handle as HWND, PROPERTY.as_ptr(), pointer.cast()) };
        if stored == 0 {
            // SAFETY: la proprieta' non e' stata scritta, quindi nessuno
            // possiede il puntatore: si ricostruisce il `Box` e lo si lascia
            // cadere invece di perderlo. La procedura resta installata ma
            // trovera' la proprieta' vuota e si limitera' a inoltrare.
            unsafe { drop(Box::from_raw(pointer)) };
            return Err(PlatformError::WindowAttributeRefused);
        }

        // La cornice va ricalcolata subito: senza, la didascalia resta
        // disegnata finche' qualcuno non ridimensiona a mano.
        redraw_frame(handle);
        Ok(())
    }

    /// Chiede il ricalcolo della cornice senza spostare la finestra.
    fn redraw_frame(handle: isize) {
        // SAFETY: `handle` e' non nullo. Posizione e dimensione valgono zero e
        // sono ignorate per via di `SWP_NOMOVE` e `SWP_NOSIZE`; la finestra non
        // viene ne' riordinata ne' riattivata.
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

    /// Gestore aggiunto alla finestra di winit.
    ///
    /// Gestisce **tre** messaggi e inoltra tutto il resto. Ogni messaggio non
    /// nominato qui riceve il trattamento che avrebbe ricevuto senza questo
    /// modulo (invariante 4).
    unsafe extern "system" fn window_procedure(
        window: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        // SAFETY: legge il valore associato alla finestra sotto il nostro nome.
        // Puo' essere nullo fra la sostituzione della procedura e la scrittura
        // della proprieta', e lo e' dopo `WM_NCDESTROY`.
        let pointer = unsafe { GetPropW(window, PROPERTY.as_ptr()) };
        if pointer.is_null() {
            // Invariante 3: senza stato non c'e' nulla da decidere, e non si
            // conosce la procedura precedente.
            // SAFETY: `DefWindowProcW` e' il trattamento predefinito corretto.
            return unsafe { DefWindowProcW(window, message, wparam, lparam) };
        }

        // SAFETY: il puntatore e' quello scritto in `install`, creato da
        // `Box::into_raw` e non ancora liberato: `WM_NCDESTROY` toglie la
        // proprieta' prima di liberarlo, quindi qui e' sempre valido.
        let state = unsafe { &*(pointer as *const State) };
        let previous = state.previous;
        let metrics = state.metrics;

        match message {
            // L'area cliente occupa anche lo spazio della didascalia, che
            // Windows smette percio' di disegnare.
            WM_NCCALCSIZE if wparam != 0 => {
                // Una finestra massimizzata viene ingrandita da Windows oltre
                // l'area di lavoro, dello spessore della cornice: senza
                // rientrare di altrettanto, il contenuto finirebbe sotto il
                // bordo dello schermo e sul monitor accanto.
                if is_maximised(window) {
                    // SAFETY: `lparam` punta a `NCCALCSIZE_PARAMS`, come il
                    // contratto del messaggio garantisce quando `wparam` non e'
                    // zero. Si scrive solo dentro `rgrc[0]`, che il messaggio
                    // designa come rettangolo proposto.
                    unsafe {
                        let params = lparam as *mut NCCALCSIZE_PARAMS;
                        let rectangle = &mut (*params).rgrc[0];
                        rectangle.left += metrics.border;
                        rectangle.top += metrics.border;
                        rectangle.right -= metrics.border;
                        rectangle.bottom -= metrics.border;
                    }
                }
                0
            }

            // Dove Windows crede di avere la didascalia, il bordo, o il
            // contenuto. Da questa risposta discendono trascinamento, aggancio,
            // doppio clic e menu di sistema, che restano suoi.
            WM_NCHITTEST => {
                let Some(zone) = zone_under_cursor(window, lparam, metrics) else {
                    // SAFETY: senza geometria non si puo' rispondere; si lascia
                    // decidere al gestore precedente.
                    return unsafe { CallWindowProcW(previous, window, message, wparam, lparam) };
                };
                hit_code(zone)
            }

            // Il menu di sistema, che senza questo ramo non si aprirebbe
            // affatto (voce O7 del pilot: il menu c'e', i gesti non arrivano).
            //
            // Si rimanda a Windows il comando che lo apre, invece di costruire
            // e tracciare il menu qui: `SC_KEYMENU` e' la via che
            // `DefWindowProcW` gia' conosce, ed e' **una riga di FFI invece di
            // quattro chiamate** — meno codice non sicuro per lo stesso esito.
            //
            // Il prezzo, dichiarato: con il clic destro il menu compare in alto
            // a sinistra della finestra e non sotto il puntatore, perche'
            // `SC_KEYMENU` e' il gesto da tastiera. Le voci e il loro effetto
            // sono gli stessi.
            // `WPARAM` e' gia' `usize` e `LPARAM` gia' `isize`: la funzione pura
            // li dichiara cosi' apposta, per restare provabile senza Windows.
            message if opens_system_menu(message, wparam, lparam) => {
                // SAFETY: si accoda un messaggio a una finestra viva; nessun
                // puntatore attraversa la chiamata.
                unsafe {
                    PostMessageW(
                        window,
                        WM_SYSCOMMAND,
                        SC_KEYMENU as WPARAM,
                        KEY_SPACE_PARAM as LPARAM,
                    );
                }
                0
            }

            // Ultimo messaggio che una finestra riceve: qui lo stato muore.
            WM_NCDESTROY => {
                // SAFETY: si toglie **prima** la proprieta', cosi' che nessun
                // messaggio successivo possa leggere un puntatore penzolante;
                // poi si inoltra al gestore precedente, e solo alla fine si
                // ricostruisce il `Box` e lo si lascia cadere. Il puntatore
                // proviene da `Box::into_raw` in `install`, e questa e' l'unica
                // liberazione (invariante 2).
                unsafe {
                    RemovePropW(window, PROPERTY.as_ptr());
                    let outcome = CallWindowProcW(previous, window, message, wparam, lparam);
                    drop(Box::from_raw(pointer as *mut State));
                    outcome
                }
            }

            // SAFETY: inoltro invariato al gestore precedente.
            _ => unsafe { CallWindowProcW(previous, window, message, wparam, lparam) },
        }
    }

    /// Zona sotto il puntatore, in coordinate relative alla finestra.
    ///
    /// `lparam` di `WM_NCHITTEST` porta la posizione in coordinate **dello
    /// schermo**: va riportata all'origine della finestra prima di confrontarla
    /// con la geometria della barra.
    fn zone_under_cursor(window: HWND, lparam: LPARAM, metrics: TitleBarMetrics) -> Option<Zone> {
        // Le due coordinate stanno nei due mezzi di `lparam`, con segno: su un
        // monitor a sinistra del principale sono negative, e leggerle senza
        // segno le trasformerebbe in numeri enormi.
        let screen_x = i32::from(((lparam as usize) & 0xFFFF) as u16 as i16);
        let screen_y = i32::from((((lparam as usize) >> 16) & 0xFFFF) as u16 as i16);

        let mut bounds = unsafe { core::mem::zeroed() };
        // SAFETY: `GetWindowRect` scrive in un `RECT` locale vivo per tutta la
        // chiamata; l'esito e' verificato prima di usarne il contenuto.
        if unsafe { GetWindowRect(window, &raw mut bounds) } == 0 {
            return None;
        }

        let width = bounds.right - bounds.left;
        let height = bounds.bottom - bounds.top;
        if width <= 0 || height <= 0 {
            return None;
        }

        Some(zone_at(
            screen_x - bounds.left,
            screen_y - bounds.top,
            width,
            height,
            metrics,
            is_maximised(window),
        ))
    }

    /// Traduce una zona del prodotto nel codice che Windows si aspetta.
    const fn hit_code(zone: Zone) -> LRESULT {
        match zone {
            Zone::TopLeft => HTTOPLEFT as LRESULT,
            Zone::Top => HTTOP as LRESULT,
            Zone::TopRight => HTTOPRIGHT as LRESULT,
            Zone::Left => HTLEFT as LRESULT,
            Zone::Right => HTRIGHT as LRESULT,
            Zone::BottomLeft => HTBOTTOMLEFT as LRESULT,
            Zone::Bottom => HTBOTTOM as LRESULT,
            Zone::BottomRight => HTBOTTOMRIGHT as LRESULT,
            Zone::Caption => HTCAPTION as LRESULT,
            Zone::Client => HTCLIENT as LRESULT,
        }
    }

    /// Se la finestra e' massimizzata.
    fn is_maximised(window: HWND) -> bool {
        // SAFETY: interroga lo stato della finestra e non dereferenzia nulla.
        unsafe { IsZoomed(window) != 0 }
    }

    /// Riduce a icona.
    pub fn minimise(handle: isize) -> PlatformResult<()> {
        command(handle, SW_MINIMIZE)
    }

    /// Massimizza, o ripristina se e' gia' massimizzata.
    pub fn toggle_maximised(handle: isize) -> PlatformResult<()> {
        if handle == 0 {
            return Err(PlatformError::WindowUnavailable);
        }
        let target = if is_maximised(handle as HWND) {
            SW_RESTORE
        } else {
            SW_SHOWMAXIMIZED
        };
        command(handle, target)
    }

    /// Chiede la chiusura, **senza** chiuderla d'autorita'.
    ///
    /// `WM_CLOSE` percorre la stessa strada del comando di sistema: chi ha
    /// qualcosa da salvare o da chiedere lo intercetta. Distruggere la finestra
    /// direttamente salterebbe quella strada.
    pub fn request_close(handle: isize) -> PlatformResult<()> {
        if handle == 0 {
            return Err(PlatformError::WindowUnavailable);
        }
        // SAFETY: si accoda un messaggio a una finestra non nulla; nessun
        // puntatore attraversa il confine.
        unsafe { PostMessageW(handle as HWND, WM_CLOSE, 0, 0) };
        Ok(())
    }

    /// Attacca alla finestra l'icona che l'eseguibile gia' porta.
    ///
    /// # Perche' serve, visto che l'eseguibile l'icona ce l'ha
    ///
    /// Perche' Windows la cerca in due posti diversi. La barra delle
    /// applicazioni e Esplora file risalgono al **file**, e mostravano il
    /// marchio approvato; **Alt+Tab chiede alla finestra** con `WM_GETICON`, e
    /// la finestra rispondeva **zero** su entrambe le misure. Il risultato era
    /// che il prodotto compariva nel commutatore di finestre con l'icona
    /// generica di Windows, accanto a un titolo che diceva NEXUM/97.
    ///
    /// Lo ha trovato il pilot guardando, alla voce B4: nessun controllo
    /// automatico lo vedeva, perche' `verify-executable-icon.ps1` verifica il
    /// **file** — e il file era a posto.
    ///
    /// # Da dove viene l'icona
    ///
    /// Dalle risorse dell'eseguibile stesso, identificatore `1`, che e' quello
    /// scritto da `build.rs`. Non da un file accanto: un'icona che si carica da
    /// disco puo' mancare, e allora la finestra torna senza. Cosi' invece o c'e'
    /// l'eseguibile, o non c'e' nulla da mostrare.
    ///
    /// Si caricano **due misure**, non una scalata: Windows usa la piccola per
    /// il commutatore e la grande per Alt+Tab prolungato e per la finestra di
    /// dialogo, e una sola immagine stirata si vede.
    pub fn set_icon_from_executable(handle: isize) -> PlatformResult<()> {
        if handle == 0 {
            return Err(PlatformError::WindowUnavailable);
        }
        let window = handle as HWND;

        // L'istanza che possiede la classe della finestra e' quella
        // dell'eseguibile: la si chiede alla finestra invece di aggiungere
        // `GetModuleHandleW` e con esso un altro gruppo di API.
        // SAFETY: legge un campo della finestra; nessun puntatore attraversa.
        let instance = unsafe { GetWindowLongPtrW(window, GWLP_HINSTANCE) };
        if instance == 0 {
            return Err(PlatformError::WindowUnavailable);
        }

        let mut attaccata = false;
        for (tipo, larghezza, altezza) in [
            (ICON_SMALL, SM_CXSMICON, SM_CYSMICON),
            (ICON_BIG, SM_CXICON, SM_CYICON),
        ] {
            // SAFETY: `LoadImageW` legge una risorsa dell'eseguibile e
            // restituisce un handle o zero; `RESOURCE_ICON` non e' un puntatore
            // ma un identificatore numerico, come `MAKEINTRESOURCE` prescrive.
            let icona = unsafe {
                LoadImageW(
                    instance as _,
                    RESOURCE_ICON as _,
                    IMAGE_ICON,
                    GetSystemMetrics(larghezza),
                    GetSystemMetrics(altezza),
                    LR_DEFAULTCOLOR | LR_SHARED,
                )
            };
            if icona.is_null() {
                continue;
            }
            // SAFETY: si consegna alla finestra un handle valido appena
            // ottenuto; `LR_SHARED` lascia la proprieta' al sistema, quindi non
            // c'e' nulla da liberare qui.
            unsafe { SendMessageW(window, WM_SETICON, tipo as WPARAM, icona as LPARAM) };
            attaccata = true;
        }

        if attaccata {
            Ok(())
        } else {
            Err(PlatformError::WindowUnavailable)
        }
    }

    fn command(handle: isize, command: i32) -> PlatformResult<()> {
        if handle == 0 {
            return Err(PlatformError::WindowUnavailable);
        }
        // SAFETY: `ShowWindow` prende una finestra non nulla e una costante
        // nota; l'esito riporta lo stato precedente e non viene interpretato.
        unsafe { ShowWindow(handle as HWND, command) };
        Ok(())
    }
}

#[cfg(windows)]
pub use windows_impl::{
    install, minimise, request_close, set_icon_from_executable, toggle_maximised,
};

/// Fuori da Windows non c'e' alcuna cornice da sostituire.
///
/// Esiste perche' il chiamante non debba avvolgere la chiamata in `cfg`: il
/// confine di piattaforma sta qui, non nell'interfaccia.
#[cfg(not(windows))]
pub fn install(_handle: isize, _metrics: TitleBarMetrics) -> PlatformResult<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn minimise(_handle: isize) -> PlatformResult<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn toggle_maximised(_handle: isize) -> PlatformResult<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn request_close(_handle: isize) -> PlatformResult<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn set_icon_from_executable(_handle: isize) -> PlatformResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const METRICS: TitleBarMetrics = TitleBarMetrics {
        height: 38,
        commands_width: 138,
        border: 8,
    };

    const WIDTH: i32 = 1000;
    const HEIGHT: i32 = 700;

    fn zone(x: i32, y: i32) -> Zone {
        zone_at(x, y, WIDTH, HEIGHT, METRICS, false)
    }

    // I due gesti del menu di sistema. Non sono un dettaglio di comodita': con
    // la didascalia di sistema c'erano, e senza questo riconoscimento sono
    // spariti (voce O7 del pilot). Chi lavora da tastiera perde l'unica strada
    // per spostare o ridimensionare la finestra senza mouse.

    #[test]
    fn a_right_click_on_the_caption_opens_the_system_menu() {
        assert!(opens_system_menu(0x00A5, 2, 0));
    }

    #[test]
    fn a_right_click_elsewhere_opens_nothing() {
        // Sul contenuto (HTCLIENT) e sul bordo (HTBOTTOMRIGHT) il clic destro
        // non e' il gesto del menu di finestra.
        assert!(!opens_system_menu(0x00A5, 1, 0));
        assert!(!opens_system_menu(0x00A5, 17, 0));
    }

    #[test]
    fn alt_and_space_open_the_system_menu() {
        assert!(opens_system_menu(0x0104, 0x20, 1 << 29));
    }

    #[test]
    fn space_without_alt_opens_nothing() {
        // Senza il bit 29 lo spazio e' uno spazio: se aprisse il menu, non si
        // potrebbe piu' scrivere una parola composta dentro un campo.
        assert!(!opens_system_menu(0x0104, 0x20, 0));
    }

    #[test]
    fn other_keys_with_alt_open_nothing() {
        // Alt+F4 deve restare quello che e', e arrivare dov'e' sempre arrivato.
        assert!(!opens_system_menu(0x0104, 0x73, 1 << 29));
    }

    #[test]
    fn the_strip_at_the_top_is_a_caption_so_windows_drags_it() {
        // E' la riga da cui discende tutto il resto: trascinamento, aggancio,
        // doppio clic per massimizzare e menu di sistema li fa Windows perche'
        // qui gli si risponde «didascalia».
        assert_eq!(zone(400, 20), Zone::Caption);
    }

    #[test]
    fn the_commands_are_client_so_the_clicks_reach_them() {
        // Se anche i comandi fossero didascalia, premere «chiudi» inizierebbe
        // un trascinamento invece di chiudere: il clic non arriverebbe mai al
        // prodotto.
        assert_eq!(zone(WIDTH - 40, 20), Zone::Client);
    }

    #[test]
    fn the_corner_wins_over_the_side_it_belongs_to() {
        // Un punto nell'angolo appartiene a due lati. Chi lo afferra si aspetta
        // di ridimensionare in diagonale, non lungo uno solo.
        assert_eq!(zone(2, 2), Zone::TopLeft);
        assert_eq!(zone(WIDTH - 2, 2), Zone::TopRight);
        assert_eq!(zone(2, HEIGHT - 2), Zone::BottomLeft);
        assert_eq!(zone(WIDTH - 2, HEIGHT - 2), Zone::BottomRight);
    }

    #[test]
    fn every_side_can_be_grabbed() {
        assert_eq!(zone(2, 300), Zone::Left);
        assert_eq!(zone(WIDTH - 2, 300), Zone::Right);
        assert_eq!(zone(500, 2), Zone::Top);
        assert_eq!(zone(500, HEIGHT - 2), Zone::Bottom);
    }

    #[test]
    fn the_top_border_wins_over_the_caption() {
        // I due si sovrappongono: la fascia comincia a zero e il bordo pure.
        // Se vincesse la didascalia, il bordo superiore non si potrebbe
        // afferrare e la finestra non si ridimensionerebbe dall'alto.
        assert_eq!(zone(400, 2), Zone::Top);
        assert_eq!(zone(400, METRICS.border + 1), Zone::Caption);
    }

    #[test]
    fn a_maximised_window_has_no_edges_to_grab() {
        // Massimizzata non si ridimensiona trascinando: rispondere «bordo»
        // darebbe un puntatore che promette qualcosa che non accade.
        let maximised = |x, y| zone_at(x, y, WIDTH, HEIGHT, METRICS, true);

        assert_eq!(maximised(2, 2), Zone::Caption);
        assert_eq!(maximised(2, 300), Zone::Client);
        assert_eq!(maximised(500, HEIGHT - 2), Zone::Client);
        // La fascia resta trascinabile: trascinarla e' cio' che ripristina.
        assert_eq!(maximised(400, 20), Zone::Caption);
    }

    #[test]
    fn below_the_strip_is_the_application() {
        assert_eq!(zone(400, METRICS.height + 1), Zone::Client);
    }
}

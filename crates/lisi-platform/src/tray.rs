// NONO modulo del crate autorizzato a contenere `unsafe`, dopo `browser`,
// `window_chrome`, `wakefulness`, `autostart`, `title_bar`, `signature`,
// `disk_space` e `app_identity`.
//
// La deroga e' esplicita, circoscritta a un solo file e visibile in diff
// (ADR-0003, ADR-0063). Vale solo su Windows: fuori da li' non c'e' FFI e il
// `forbid` del crate resta pieno.
#![cfg_attr(windows, allow(unsafe_code))]

//! L'icona nell'area di notifica di Windows.
//!
//! # Questo modulo non decide nulla
//!
//! È la parte che non si può provare senza una persona che guardi uno schermo, e
//! per questo **non contiene alcuna decisione**: riceve un suggerimento e un
//! elenco di voci già composte, disegna, e dice quale voce è stata scelta.
//!
//! **Non sa che cosa sia un monitoraggio, un blocco o un avviso**, e non ha modo
//! di scoprirlo: i suoi tipi non li nominano. Tutto ciò che ADR-0063 stabilisce
//! si prova in `lisi-services::tray`, in Rust sicuro.
//!
//! # Perché una finestra propria, e non quella dell'applicazione
//!
//! Perché un'icona dell'area di notifica ha bisogno di una finestra a cui
//! recapitare i propri messaggi, e prendersi quella dell'interfaccia
//! significherebbe **sostituirne la procedura**: da quel momento ogni messaggio
//! destinato alla finestra vera passerebbe da qui, e un difetto in queste righe
//! diventerebbe un difetto dell'applicazione intera.
//!
//! La finestra di soli messaggi (`HWND_MESSAGE`) non si vede, non compare nella
//! barra delle applicazioni, non riceve input, e serve a una cosa sola.
//!
//! # Perché nessun secondo ciclo di messaggi
//!
//! Perché la finestra vive sul **thread dell'interfaccia**, e il ciclo di Slint
//! recapita i messaggi di ogni finestra di quel thread. Un secondo ciclo su un
//! secondo thread avrebbe una propria cadenza da tenere allineata, ed è la
//! stessa ragione per cui il blocco automatico non ha un timer proprio.
//!
//! # Invarianti di sicurezza
//!
//! 1. **Un solo vassoio per thread, e resta sul proprio.** Lo stato vive in una
//!    variabile di thread; installarne un secondo sullo stesso thread è
//!    rifiutato invece di sovrascrivere il primo, e [`TrayIcon`] è `!Send`,
//!    perché lasciarlo cadere su un altro thread svuoterebbe lo stato sbagliato
//!    e lascerebbe l'icona sullo schermo per sempre.
//! 2. **La procedura di finestra non può andare in panico oltre il confine
//!    FFI.** Non indicizza, non srotola, non usa `unwrap`, e non tiene mai un
//!    prestito della variabile di thread mentre chiama Windows: `TrackPopupMenu`
//!    è modale e può rientrare qui.
//! 3. **Ogni stringa passata a Windows è UTF-16 terminata da zero**, costruita
//!    qui e viva per tutta la durata della chiamata.
//! 4. **Il suggerimento è troncato al campo che lo contiene** (128 unità,
//!    l'ultima riservata allo zero): Windows non lo legge oltre, e scriverci
//!    oltre sarebbe un errore di memoria.
//! 5. **L'icona non si distrugge.** `LoadIconW` su una risorsa restituisce un
//!    handle **condiviso** del modulo: distruggerlo distruggerebbe l'icona
//!    dell'eseguibile.
//! 6. **Nessun puntatore attraversa il confine.** Il vassoio non passa a Windows
//!    alcun puntatore a memoria di Rust che debba sopravvivere alla chiamata, e
//!    non riceve da Windows alcun puntatore da dereferenziare: le voci scelte
//!    tornano come numeri.
//! 7. **Ciò che si crea si distrugge, una volta sola.** Il menu a comparsa viene
//!    distrutto sullo stesso percorso in cui è creato; l'icona viene rimossa e
//!    la finestra distrutta in `Drop`, e lo stato di thread viene svuotato prima
//!    di distruggere la finestra, perché la sua distruzione rientra qui.
//!
//! # Limite dichiarato
//!
//! **L'area di notifica nasconde le icone per difetto.** Un'icona che l'operatore
//! non ha promosso finisce nel riquadro nascosto. Non si può forzare, e non si
//! deve: forzare la visibilità della propria icona è ciò che fa il software
//! invadente. Va detto nella guida, non aggirato.
//!
//! La decisione completa sta in
//! `docs/adr/ADR-0063-IL-VASSOIO-NON-E-UNA-FINESTRA-SUL-BLOCCO.md`.

use crate::error::{PlatformError, PlatformResult};

/// Una voce del menu, come il vassoio la disegna.
///
/// Non porta un comando: **questo modulo non sa che cosa significhi**. Porta un
/// testo e se sia premibile, e restituisce un indice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuEntry {
    /// Che cosa c'è scritto.
    pub label: String,
    /// Se si può premere.
    pub enabled: bool,
}

/// Che cosa una persona ha fatto sull'icona.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayEvent {
    /// L'icona è stata premuta con il tasto sinistro.
    Activated,
    /// È stata scelta la voce di menu all'indice indicato.
    Chosen(usize),
}

/// Quante unità UTF-16 entrano nel suggerimento, zero finale compreso.
///
/// È la misura del campo `szTip` di Windows. Il testo si tronca qui invece di
/// scoprirlo: scrivere oltre sarebbe un errore di memoria.
pub const TOOLTIP_CAPACITY: usize = 128;

#[cfg(windows)]
pub use windows_impl::{TrayIcon, bring_window_to_front};

#[cfg(not(windows))]
pub use elsewhere::{TrayIcon, bring_window_to_front};

/// Fuori da Windows non esiste un'area di notifica.
#[cfg(not(windows))]
mod elsewhere {
    use super::{MenuEntry, PlatformError, PlatformResult, TrayEvent};

    /// L'icona che su questa piattaforma non esiste.
    #[derive(Debug)]
    pub struct TrayIcon;

    impl TrayIcon {
        /// Non installa nulla.
        ///
        /// # Errori
        ///
        /// Sempre [`PlatformError::Unsupported`].
        pub fn install(_tooltip: &str, _entries: &[MenuEntry]) -> PlatformResult<Self> {
            Err(PlatformError::Unsupported)
        }

        /// Non aggiorna nulla.
        ///
        /// # Errori
        ///
        /// Sempre [`PlatformError::Unsupported`].
        pub fn update(&self, _tooltip: &str, _entries: &[MenuEntry]) -> PlatformResult<()> {
            Err(PlatformError::Unsupported)
        }

        /// Nessun evento.
        #[must_use]
        pub fn take_events(&self) -> Vec<TrayEvent> {
            Vec::new()
        }
    }

    /// Non porta avanti nulla.
    ///
    /// # Errori
    ///
    /// Sempre [`PlatformError::Unsupported`].
    pub fn bring_window_to_front(_handle: isize) -> PlatformResult<()> {
        Err(PlatformError::Unsupported)
    }
}

#[cfg(windows)]
mod windows_impl {
    use std::cell::RefCell;

    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::Shell::{
        NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
        Shell_NotifyIconW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow,
        GetCursorPos, HWND_MESSAGE, IDI_APPLICATION, IsIconic, LoadIconW, MF_GRAYED, MF_STRING,
        PostMessageW, RegisterClassW, RegisterWindowMessageW, SW_RESTORE, SW_SHOW,
        SetForegroundWindow, ShowWindow, TPM_NONOTIFY, TPM_RETURNCMD, TPM_RIGHTBUTTON,
        TrackPopupMenu, WM_APP, WM_CONTEXTMENU, WM_LBUTTONDBLCLK, WM_LBUTTONUP, WM_NULL,
        WM_RBUTTONUP, WNDCLASSW,
    };

    use super::{MenuEntry, PlatformError, PlatformResult, TOOLTIP_CAPACITY, TrayEvent};

    /// Il messaggio con cui Windows annuncia i clic sull'icona.
    ///
    /// `WM_APP` è l'inizio dell'intervallo riservato alle applicazioni: nessun
    /// messaggio di sistema vi ricade.
    const WM_TRAY_CALLBACK: u32 = WM_APP + 1;

    /// L'identificativo dell'icona dentro la nostra finestra.
    ///
    /// Ne esiste una sola, e Windows la distingue per la coppia (finestra, id).
    const TRAY_ICON_ID: u32 = 1;

    /// L'icona del prodotto, incorporata come risorsa numero 1 dall'eseguibile.
    const APPLICATION_ICON_RESOURCE: u16 = 1;

    /// Lo stato del vassoio di questo thread.
    struct TrayState {
        window: HWND,
        icon: windows_sys::Win32::UI::WindowsAndMessaging::HICON,
        entries: Vec<MenuEntry>,
        tooltip: [u16; TOOLTIP_CAPACITY],
        events: Vec<TrayEvent>,
        taskbar_created: u32,
    }

    thread_local! {
        /// **Un solo vassoio per thread** (invariante 1).
        static STATE: RefCell<Option<TrayState>> = const { RefCell::new(None) };
    }

    /// L'icona nell'area di notifica.
    ///
    /// Rimuove l'icona e distrugge la propria finestra quando viene lasciata
    /// cadere.
    #[derive(Debug)]
    pub struct TrayIcon {
        /// Non porta lo stato: quello vive nella variabile di thread, perché la
        /// procedura di finestra deve poterlo raggiungere senza un puntatore.
        ///
        /// # Perché questo campo rende il tipo NON trasferibile fra thread
        ///
        /// Perché lo stato vive in una **variabile di thread**, e questo valore
        /// ne è la ricevuta. Se lo si potesse spostare su un altro thread e
        /// lasciarlo cadere là, `Drop` svuoterebbe lo stato **di quel thread**
        /// — che è vuoto — e la finestra e l'icona del thread d'origine
        /// resterebbero per sempre: l'icona nell'area di notifica non se ne
        /// andrebbe più, e su quel thread non si potrebbe installarne un'altra
        /// perché lo stato direbbe «già installato».
        ///
        /// Un puntatore grezzo dentro la struttura è il modo con cui Rust
        /// esprime «questo valore resta dove è nato»: rende il tipo `!Send`, e
        /// il compilatore rifiuta lo spostamento invece di lasciarlo accadere.
        _non_trasferibile: std::marker::PhantomData<*const ()>,
    }

    impl TrayIcon {
        /// Installa l'icona, con il suggerimento e le voci indicate.
        ///
        /// # Errori
        ///
        /// Restituisce [`PlatformError::Unsupported`] se un vassoio è già
        /// installato su questo thread, e [`PlatformError::LaunchFailed`] se
        /// Windows rifiuta la finestra o l'icona.
        pub fn install(tooltip: &str, entries: &[MenuEntry]) -> PlatformResult<Self> {
            let gia_installato = STATE.with(|state| state.borrow().is_some());
            if gia_installato {
                return Err(PlatformError::Unsupported);
            }

            let window = create_message_window()?;
            let icon = load_application_icon();
            let taskbar_created = register_taskbar_created();

            STATE.with(|state| {
                *state.borrow_mut() = Some(TrayState {
                    window,
                    icon,
                    entries: entries.to_vec(),
                    tooltip: encode_tooltip(tooltip),
                    events: Vec::new(),
                    taskbar_created,
                });
            });

            if let Err(errore) = notify(NIM_ADD) {
                // Non si lascia una finestra orfana dietro un fallimento.
                teardown();
                return Err(errore);
            }

            Ok(Self {
                _non_trasferibile: std::marker::PhantomData,
            })
        }

        /// Aggiorna il suggerimento e le voci.
        ///
        /// # Errori
        ///
        /// Restituisce [`PlatformError::Unsupported`] se il vassoio non è
        /// installato, e [`PlatformError::LaunchFailed`] se Windows rifiuta
        /// l'aggiornamento.
        pub fn update(&self, tooltip: &str, entries: &[MenuEntry]) -> PlatformResult<()> {
            let presente = STATE.with(|state| {
                let mut state = state.borrow_mut();
                let Some(state) = state.as_mut() else {
                    return false;
                };
                state.entries = entries.to_vec();
                state.tooltip = encode_tooltip(tooltip);
                true
            });

            if !presente {
                return Err(PlatformError::Unsupported);
            }
            notify(NIM_MODIFY)
        }

        /// Ritira gli eventi accumulati, svuotandoli.
        #[must_use]
        pub fn take_events(&self) -> Vec<TrayEvent> {
            STATE.with(|state| {
                state
                    .borrow_mut()
                    .as_mut()
                    .map(|state| std::mem::take(&mut state.events))
                    .unwrap_or_default()
            })
        }
    }

    impl Drop for TrayIcon {
        fn drop(&mut self) {
            teardown();
        }
    }

    /// Toglie l'icona, svuota lo stato e distrugge la finestra.
    ///
    /// **Lo stato si svuota prima di distruggere la finestra** (invariante 7):
    /// `DestroyWindow` recapita `WM_DESTROY` alla nostra procedura, che rientra
    /// qui, e trovarlo già vuoto è ciò che rende l'operazione una sola.
    fn teardown() {
        let _ = notify(NIM_DELETE);

        let window = STATE.with(|state| state.borrow_mut().take().map(|state| state.window));

        if let Some(window) = window {
            // SAFETY (invariante 7): `window` e' l'handle che questo modulo ha
            // creato e non ha ancora distrutto, ed e' stato appena tolto dallo
            // stato di thread: nessun altro percorso puo' distruggerlo una
            // seconda volta. `DestroyWindow` non dereferenzia memoria di Rust.
            unsafe {
                DestroyWindow(window);
            }
        }
    }

    /// Crea la finestra di soli messaggi.
    fn create_message_window() -> PlatformResult<HWND> {
        let class_name = wide("Nexum97TrayWindow");

        // SAFETY (invariante 6): `GetModuleHandleW(null)` restituisce l'handle
        // del modulo corrente e non dereferenzia nulla.
        let instance = unsafe { GetModuleHandleW(std::ptr::null()) };

        // SAFETY (invariante 3): `class_name` e' UTF-16 terminata da zero e vive
        // per tutta la durata di questa funzione. La struttura e' azzerata e i
        // soli campi valorizzati sono la procedura, il modulo e il nome; i
        // puntatori restanti restano nulli, che e' il valore che Windows
        // documenta come «nessuno».
        //
        // Registrare una classe gia' registrata fallisce e non e' un errore: la
        // classe c'e' comunque. L'esito si ignora di proposito.
        unsafe {
            let mut class: WNDCLASSW = std::mem::zeroed();
            class.lpfnWndProc = Some(window_procedure);
            class.hInstance = instance;
            class.lpszClassName = class_name.as_ptr();
            RegisterClassW(&raw const class);
        }

        // SAFETY (invarianti 3 e 6): entrambe le stringhe sono terminate da zero
        // e vive; `HWND_MESSAGE` e' la costante documentata per una finestra di
        // soli messaggi; l'ultimo parametro e' nullo, cioe' «nessun dato di
        // creazione».
        let window = unsafe {
            CreateWindowExW(
                0,
                class_name.as_ptr(),
                std::ptr::null(),
                0,
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                std::ptr::null_mut(),
                instance,
                std::ptr::null(),
            )
        };

        if window.is_null() {
            return Err(PlatformError::LaunchFailed { code: 0 });
        }
        Ok(window)
    }

    /// Carica l'icona del prodotto, o quella predefinita del sistema.
    ///
    /// **Non si distrugge** (invariante 5): è un handle condiviso del modulo.
    fn load_application_icon() -> windows_sys::Win32::UI::WindowsAndMessaging::HICON {
        // SAFETY (invariante 5): il secondo argomento e' un identificativo di
        // risorsa passato per valore secondo la convenzione `MAKEINTRESOURCE`,
        // non un puntatore a memoria di Rust. L'handle restituito e' condiviso e
        // non va liberato.
        let icon = unsafe {
            let instance = GetModuleHandleW(std::ptr::null());
            LoadIconW(instance, APPLICATION_ICON_RESOURCE as usize as *const u16)
        };
        if !icon.is_null() {
            return icon;
        }

        // SAFETY (invariante 5): stessa convenzione, con modulo nullo, che
        // Windows documenta come «icona predefinita del sistema».
        unsafe { LoadIconW(std::ptr::null_mut(), IDI_APPLICATION) }
    }

    /// Registra il messaggio con cui Windows annuncia il riavvio di Explorer.
    ///
    /// Se Explorer si riavvia, l'area di notifica riparte vuota e l'icona va
    /// rimessa: senza questo, l'icona sparirebbe e nessuno saprebbe perché.
    fn register_taskbar_created() -> u32 {
        let nome = wide("TaskbarCreated");
        // SAFETY (invariante 3): la stringa e' terminata da zero e viva per la
        // durata della chiamata. La funzione restituisce un numero.
        unsafe { RegisterWindowMessageW(nome.as_ptr()) }
    }

    /// Comunica a Windows l'aggiunta, la modifica o la rimozione dell'icona.
    fn notify(operation: u32) -> PlatformResult<()> {
        let dati = STATE.with(|state| {
            let state = state.borrow();
            state.as_ref().map(|state| {
                // SAFETY (invarianti 3, 4 e 6): la struttura e' azzerata e poi
                // valorizzata con `cbSize` pari alla propria misura, la finestra
                // e l'icona create da questo modulo, e un suggerimento gia'
                // troncato alla capacita' del campo. Nessun puntatore a memoria
                // di Rust vi entra: `szTip` e' un vettore interno alla struttura,
                // copiato per valore.
                let mut dati: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
                dati.cbSize = u32::try_from(std::mem::size_of::<NOTIFYICONDATAW>()).unwrap_or(0);
                dati.hWnd = state.window;
                dati.uID = TRAY_ICON_ID;
                dati.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
                dati.uCallbackMessage = WM_TRAY_CALLBACK;
                dati.hIcon = state.icon;
                dati.szTip = state.tooltip;
                dati
            })
        });

        let Some(dati) = dati else {
            return Err(PlatformError::Unsupported);
        };

        // SAFETY (invariante 6): si passa un puntatore a una variabile locale
        // viva per tutta la durata della chiamata, e Windows non la conserva.
        let esito = unsafe { Shell_NotifyIconW(operation, &raw const dati) };
        if esito == 0 {
            return Err(PlatformError::LaunchFailed { code: 0 });
        }
        Ok(())
    }

    /// La procedura di finestra.
    ///
    /// # Sicurezza
    ///
    /// **Non può andare in panico** (invariante 2): non indicizza, non usa
    /// `unwrap`, e non tiene alcun prestito della variabile di thread mentre
    /// chiama Windows.
    unsafe extern "system" fn window_procedure(
        window: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        let taskbar_created = STATE.with(|state| {
            state
                .borrow()
                .as_ref()
                .map_or(0, |state| state.taskbar_created)
        });

        if message == WM_TRAY_CALLBACK {
            // Il tipo di clic arriva nella meta' bassa di `lparam`.
            let azione = u32::try_from(lparam as usize & 0xFFFF).unwrap_or(0);
            match azione {
                WM_LBUTTONUP | WM_LBUTTONDBLCLK => push_event(TrayEvent::Activated),
                WM_RBUTTONUP | WM_CONTEXTMENU => show_menu(window),
                _ => {}
            }
            return 0;
        }

        if taskbar_created != 0 && message == taskbar_created {
            // Explorer e' ripartito: l'icona va rimessa. Un fallimento qui non
            // ha un posto in cui essere riportato, e non e' fatale.
            let _ = notify(NIM_ADD);
            return 0;
        }

        // OGNI ALTRO MESSAGGIO VA AL COMPORTAMENTO PREDEFINITO, E
        // `WM_DESTROY` COMPRESO.
        //
        // Qui NON si chiama `PostQuitMessage`, che e' cio' che un'applicazione
        // Win32 fa di solito alla distruzione della propria finestra
        // principale. Questa non e' la finestra principale: e' una finestra di
        // soli messaggi che vive sul thread dell'interfaccia, e un `WM_QUIT`
        // fermerebbe il ciclo di eventi di Slint — cioe' chiuderebbe
        // l'applicazione perche' e' stata tolta un'icona.
        //
        // SAFETY (invariante 6): si inoltra a Windows ciò che Windows ha
        // passato, senza dereferenziare nulla.
        unsafe { DefWindowProcW(window, message, wparam, lparam) }
    }

    /// Registra un evento, se il vassoio è ancora installato.
    fn push_event(event: TrayEvent) {
        STATE.with(|state| {
            if let Some(state) = state.borrow_mut().as_mut() {
                state.events.push(event);
            }
        });
    }

    /// Mostra il menu a comparsa e registra la voce scelta.
    ///
    /// # Sicurezza
    ///
    /// Le voci si **copiano fuori** dalla variabile di thread prima di chiamare
    /// Windows (invariante 2): `TrackPopupMenu` è modale e può rientrare nella
    /// procedura di finestra, e un prestito ancora aperto la farebbe andare in
    /// panico oltre il confine FFI.
    fn show_menu(window: HWND) {
        let voci: Vec<MenuEntry> = STATE.with(|state| {
            state
                .borrow()
                .as_ref()
                .map(|state| state.entries.clone())
                .unwrap_or_default()
        });
        if voci.is_empty() {
            return;
        }

        let mut punto = POINT { x: 0, y: 0 };
        // SAFETY (invariante 6): si passa un puntatore a una variabile locale
        // viva per tutta la durata della chiamata; Windows vi scrive due interi
        // e non la conserva.
        let posizione_nota = unsafe { GetCursorPos(&raw mut punto) };

        // SENZA LA POSIZIONE NON SI APRE IL MENU.
        //
        // Se `GetCursorPos` fallisce, `punto` resta a zero e il menu
        // comparirebbe nell'angolo in alto a sinistra dello schermo, lontano
        // dall'icona che e' stata premuta: sembrerebbe un difetto del
        // programma. Meglio non aprirlo: chi ha premuto preme di nuovo.
        if posizione_nota == 0 {
            return;
        }

        // SAFETY (invariante 7): il menu creato qui viene distrutto qui, su ogni
        // percorso di uscita.
        let menu = unsafe { CreatePopupMenu() };
        if menu.is_null() {
            return;
        }

        for (indice, voce) in voci.iter().enumerate() {
            let testo = wide(&voce.label);
            let flag = if voce.enabled {
                MF_STRING
            } else {
                MF_STRING | MF_GRAYED
            };
            // Gli identificativi partono da 1: zero significa «nessuna scelta».
            let id = indice.saturating_add(1);
            // SAFETY (invariante 3): `testo` e' UTF-16 terminata da zero e viva
            // per tutta la durata della chiamata; Windows ne fa una copia.
            unsafe {
                AppendMenuW(menu, flag, id, testo.as_ptr());
            }
        }

        // SAFETY (invariante 6): la finestra e' la nostra. Portarla in primo
        // piano e' cio' che Windows documenta come necessario perche' il menu si
        // chiuda quando si fa clic altrove; senza, il menu resta aperto.
        unsafe {
            SetForegroundWindow(window);
        }

        // SAFETY (invarianti 2 e 6): nessun prestito e' aperto; l'ultimo
        // parametro e' nullo, cioe' «nessun rettangolo da evitare».
        let scelta = unsafe {
            TrackPopupMenu(
                menu,
                TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY,
                punto.x,
                punto.y,
                0,
                window,
                std::ptr::null(),
            )
        };

        // SAFETY (invariante 6): il messaggio nullo alla propria finestra e' il
        // modo documentato di far chiudere il menu quando il clic e' caduto
        // fuori. Non trasporta dati.
        unsafe {
            PostMessageW(window, WM_NULL, 0, 0);
            DestroyMenu(menu);
        }

        if scelta > 0 {
            let indice = usize::try_from(scelta).unwrap_or(0).saturating_sub(1);
            if indice < voci.len() {
                push_event(TrayEvent::Chosen(indice));
            }
        }
    }

    /// Porta davanti la finestra indicata, ripristinandola se è ridotta a icona.
    ///
    /// # Perché sta qui e non in un modulo delle finestre
    ///
    /// Perché **il vassoio è il suo unico chiamante**, e ADR-0063 promette che
    /// l'`unsafe` di questa milestone stia in un file solo. «Apri NEXUM» senza
    /// questa funzione non aprirebbe nulla: una finestra già visibile ma dietro
    /// le altre resterebbe dietro le altre.
    ///
    /// # Che cosa non fa
    ///
    /// **Non sblocca**, non cambia modalità, non tocca il contenuto: porta
    /// davanti la finestra che c'è, e se la postazione è bloccata porta davanti
    /// la finestra bloccata.
    ///
    /// # Errori
    ///
    /// Restituisce [`PlatformError::WindowUnavailable`] se l'handle è nullo.
    ///
    /// Un rifiuto di Windows **non è un errore**: il sistema nega il passaggio in
    /// primo piano a un processo che non ha l'input, ed è una difesa contro le
    /// finestre che si rubano il fuoco. In quel caso la barra delle applicazioni
    /// lampeggia, che è il comportamento voluto.
    pub fn bring_window_to_front(handle: isize) -> PlatformResult<()> {
        if handle == 0 {
            return Err(PlatformError::WindowUnavailable);
        }
        let window = handle as HWND;

        // SAFETY (invariante 6): `window` e' l'handle che il chiamante ha
        // ottenuto dal proprio gestore di finestre; questo modulo non lo cerca,
        // non lo indovina e non enumera le finestre altrui. Nessuna delle due
        // chiamate dereferenzia memoria di Rust, e l'esito non si interpreta:
        // il rifiuto del passaggio in primo piano e' una difesa del sistema, non
        // un guasto.
        // SW_RESTORE SOLO SE E' RIDOTTA A ICONA (UX-EXCELLENCE-02, indagine su
        // SIM3-24). Per il contratto di `ShowWindow`, SW_RESTORE riporta alla
        // misura normale anche una finestra **massimizzata**: «Apri NEXUM» dal
        // vassoio faceva uscire dalla massimizzazione chi lavorava a schermo
        // intero. Una finestra visibile si mostra com'e' (SW_SHOW), alla sua misura.
        unsafe {
            let comando = if IsIconic(window) != 0 {
                SW_RESTORE
            } else {
                SW_SHOW
            };
            ShowWindow(window, comando);
            SetForegroundWindow(window);
        }
        Ok(())
    }

    /// Converte in UTF-16 terminata da zero (invariante 3).
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Riempie il campo del suggerimento, troncando (invariante 4).
    fn encode_tooltip(value: &str) -> [u16; TOOLTIP_CAPACITY] {
        let mut campo = [0_u16; TOOLTIP_CAPACITY];
        // L'ultima unita' resta zero: e' il terminatore, e non va sovrascritto.
        for (posto, unita) in campo
            .iter_mut()
            .take(TOOLTIP_CAPACITY - 1)
            .zip(value.encode_utf16())
        {
            *posto = unita;
        }
        campo
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn una_stringa_larga_si_termina_con_uno_zero() {
            let codificata = wide("NEXUM/97");
            assert_eq!(codificata.last(), Some(&0));
            assert_eq!(codificata.len(), "NEXUM/97".encode_utf16().count() + 1);
        }

        /// **Il suggerimento non esce dal campo che lo contiene.**
        #[test]
        fn il_suggerimento_si_tronca_al_campo() {
            let lunghissimo = "a".repeat(1_000);
            let campo = encode_tooltip(&lunghissimo);
            assert_eq!(campo.len(), TOOLTIP_CAPACITY);
            assert_eq!(
                campo[TOOLTIP_CAPACITY - 1],
                0,
                "l'ultima unita' resta il terminatore"
            );
        }

        #[test]
        fn un_suggerimento_corto_resta_terminato() {
            let campo = encode_tooltip("NEXUM/97");
            assert_eq!(campo[8], 0);
        }

        /// **Il vassoio non può lasciare il proprio thread.**
        ///
        /// Lo stato vive in una variabile di thread: lasciar cadere l'icona su
        /// un altro thread svuoterebbe lo stato sbagliato, e l'icona resterebbe
        /// nell'area di notifica per sempre.
        ///
        /// La prova non sposta nulla — non c'è un vassoio da installare in un
        /// test — ma **fissa il tipo**: se un giorno qualcuno togliesse il
        /// campo che lo rende `!Send`, questa riga smetterebbe di compilare.
        #[test]
        fn il_vassoio_non_puo_lasciare_il_proprio_thread() {
            use core::marker::PhantomData;

            // Un metodo INERENTE ha la precedenza su uno di tratto, e l'impl
            // inerente esiste solo per i tipi `Send`: se `T` e' `Send` si
            // risolve al primo, altrimenti ricade sul secondo.
            //
            // La prima stesura provava lo stesso con delle costanti associate
            // su un percorso qualificato, e NON funzionava: `<Prova<T> as
            // Comunque>::SEND` sceglie sempre la costante del tratto, quindi la
            // prova era verde anche con il difetto dentro. E' stata vista
            // verde, ed e' per questo che e' stata riscritta.
            struct Prova<T>(PhantomData<T>);

            trait Ricaduta {
                fn e_trasferibile(&self) -> bool {
                    false
                }
            }
            impl<T> Ricaduta for Prova<T> {}

            impl<T: Send> Prova<T> {
                fn e_trasferibile(&self) -> bool {
                    true
                }
            }

            assert!(
                Prova::<u32>(PhantomData).e_trasferibile(),
                "la prova stessa deve saper riconoscere un tipo trasferibile, \
                 altrimenti non dimostra nulla"
            );
            assert!(
                !Prova::<TrayIcon>(PhantomData).e_trasferibile(),
                "TrayIcon deve restare sul thread che lo ha installato"
            );
        }
    }
}

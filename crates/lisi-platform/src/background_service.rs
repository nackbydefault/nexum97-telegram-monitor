// Modulo del crate autorizzato a contenere `unsafe`, dopo quelli elencati in
// `lib.rs`. Vedere ADR-0009 per la regola e ADR-0203 per la decisione che ha
// portato qui.
#![cfg_attr(windows, allow(unsafe_code))]

//! Il servizio di Windows del monitoraggio in background (SERVICE-01,
//! ADR-0203).
//!
//! # Che cosa fa
//!
//! - [`run_as_service`] consegna il processo al gestore dei servizi di Windows
//!   e chiama il corpo del servizio, che lavora finché [`StopSignal`] non dice
//!   di fermarsi;
//! - [`user_has_a_session`] dice se l'utente di Windows con cui il servizio
//!   gira è collegato: allora l'acquisizione la tiene la finestra;
//! - [`state`] dice se il servizio è installato e se gira;
//! - [`session_is_ending`] dice alla finestra se si chiude perché la persona
//!   esce da Windows, e non perché ha chiuso il programma.
//!
//! # Che cosa NON fa
//!
//! Non installa, non avvia e non ferma il servizio: chiede soltanto. Non legge
//! le sessioni degli altri utenti oltre al nome, che serve a riconoscere la
//! propria.
//!
//! # Le invarianti dell'FFI
//!
//! 1. Il nome del servizio passa in UTF-16 terminato da zero, tenuto in una
//!    statica che vive quanto il processo.
//! 2. La tabella delle sessioni e ogni nome letto si liberano con
//!    `WTSFreeMemory` una volta sola, dopo averli copiati.
//! 3. Ogni handle del gestore dei servizi si chiude con `CloseServiceHandle`
//!    una volta sola.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::PlatformError;

/// Il segnale di fermata, che il gestore dei servizi accende.
#[derive(Debug, Default)]
pub struct StopSignal(AtomicBool);

impl StopSignal {
    /// Un segnale spento.
    #[must_use]
    pub const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    /// Se Windows ha chiesto di fermarsi.
    #[must_use]
    pub fn requested(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    fn request(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Lo stato del servizio, secondo Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// Non è installato.
    NotInstalled,
    /// È installato e fermo.
    Stopped,
    /// Gira.
    Running,
    /// Sta partendo o fermandosi.
    Changing,
}

/// Consegna il processo al gestore dei servizi e chiama `body`.
///
/// Torna quando il servizio si è fermato.
///
/// # Errori
///
/// Restituisce un errore se il processo non è stato avviato da Windows come
/// servizio, o se il gestore lo rifiuta.
pub fn run_as_service(name: &str, body: fn(&StopSignal)) -> Result<(), PlatformError> {
    #[cfg(windows)]
    {
        windows_impl::run_as_service(name, body)
    }
    #[cfg(not(windows))]
    {
        let _ = (name, body);
        Err(PlatformError::Unsupported)
    }
}

/// Se l'utente di Windows di questo processo ha una sessione aperta, attiva o
/// no: con la persona collegata l'acquisizione la tiene la finestra.
///
/// # Errori
///
/// Restituisce un errore se Windows non elenca le sessioni o non dice il nome
/// dell'utente.
pub fn user_has_a_session() -> Result<bool, PlatformError> {
    #[cfg(windows)]
    {
        windows_impl::user_has_a_session()
    }
    #[cfg(not(windows))]
    {
        Err(PlatformError::Unsupported)
    }
}

/// Lo stato del servizio `name`.
///
/// # Errori
///
/// Restituisce un errore se il gestore dei servizi non risponde.
pub fn state(name: &str) -> Result<ServiceState, PlatformError> {
    #[cfg(windows)]
    {
        windows_impl::state(name)
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        Err(PlatformError::Unsupported)
    }
}

/// Se la sessione di Windows si sta chiudendo: la persona esce o il PC si
/// spegne.
#[must_use]
pub fn session_is_ending() -> bool {
    #[cfg(windows)]
    {
        windows_impl::session_is_ending()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Il nome dell'utente di questo processo, nella forma `DOMINIO\nome`.
///
/// # Errori
///
/// Restituisce un errore se Windows non lo dice.
pub fn own_account_name() -> Result<String, PlatformError> {
    #[cfg(windows)]
    {
        windows_impl::own_account_name()
    }
    #[cfg(not(windows))]
    {
        Err(PlatformError::Unsupported)
    }
}

/// UTF-16 terminato da zero.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
mod windows_impl {
    use std::ffi::c_void;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicPtr, Ordering};

    use windows_sys::Win32::Foundation::{
        ERROR_CALL_NOT_IMPLEMENTED, ERROR_SERVICE_DOES_NOT_EXIST, GetLastError, NO_ERROR,
    };
    use windows_sys::Win32::Security::Authentication::Identity::{
        GetUserNameExW, NameSamCompatible,
    };
    use windows_sys::Win32::System::RemoteDesktop::{
        WTS_CURRENT_SERVER_HANDLE, WTS_INFO_CLASS, WTS_SESSION_INFOW, WTSDomainName,
        WTSEnumerateSessionsW, WTSFreeMemory, WTSQuerySessionInformationW, WTSUserName,
    };
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus,
        RegisterServiceCtrlHandlerExW, SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_ACCEPT_SHUTDOWN,
        SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN,
        SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS,
        SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING, SERVICE_STOPPED,
        SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus,
        StartServiceCtrlDispatcherW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_SHUTTINGDOWN};

    use super::{ServiceState, StopSignal, wide};
    use crate::error::PlatformError;

    /// Il nome del servizio, vivo quanto il processo (invariante 1).
    static NOME: OnceLock<Vec<u16>> = OnceLock::new();
    /// Il corpo del servizio.
    static CORPO: OnceLock<fn(&StopSignal)> = OnceLock::new();
    /// Il segnale di fermata.
    static FERMATA: StopSignal = StopSignal::new();
    /// L'handle dello stato, che il gestore dà a `service_main`.
    static STATO: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

    fn errore() -> PlatformError {
        // SAFETY: `GetLastError` legge soltanto il codice del thread.
        let code = unsafe { GetLastError() };
        PlatformError::BackgroundService { code }
    }

    pub fn run_as_service(name: &str, body: fn(&StopSignal)) -> Result<(), PlatformError> {
        let nome = NOME.get_or_init(|| wide(name));
        let _ = CORPO.set(body);
        let tabella = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: nome.as_ptr().cast_mut(),
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: std::ptr::null_mut(),
                lpServiceProc: None,
            },
        ];
        // SAFETY: la tabella termina con la voce nulla, e il nome vive in una
        // statica (invariante 1). La chiamata torna quando il servizio si è
        // fermato.
        if unsafe { StartServiceCtrlDispatcherW(tabella.as_ptr()) } == 0 {
            return Err(errore());
        }
        Ok(())
    }

    fn imposta(stato: SERVICE_STATUS_CURRENT_STATE, accetta: u32) {
        let handle: SERVICE_STATUS_HANDLE = STATO.load(Ordering::SeqCst);
        if handle.is_null() {
            return;
        }
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: stato,
            dwControlsAccepted: accetta,
            dwWin32ExitCode: NO_ERROR,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: if stato == SERVICE_STOP_PENDING {
                30_000
            } else {
                0
            },
        };
        // SAFETY: l'handle viene da `RegisterServiceCtrlHandlerExW` e la
        // struttura vive per la chiamata.
        unsafe {
            SetServiceStatus(handle, &raw const status);
        }
    }

    unsafe extern "system" fn handler(
        control: u32,
        _event: u32,
        _data: *mut c_void,
        _context: *mut c_void,
    ) -> u32 {
        match control {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                FERMATA.request();
                imposta(SERVICE_STOP_PENDING, 0);
                NO_ERROR
            }
            SERVICE_CONTROL_INTERROGATE => NO_ERROR,
            _ => ERROR_CALL_NOT_IMPLEMENTED,
        }
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
        let Some(nome) = NOME.get() else {
            return;
        };
        // SAFETY: il nome vive in una statica (invariante 1); il gestore non
        // usa il contesto, che resta nullo.
        let handle = unsafe {
            RegisterServiceCtrlHandlerExW(nome.as_ptr(), Some(handler), std::ptr::null())
        };
        if handle.is_null() {
            return;
        }
        STATO.store(handle, Ordering::SeqCst);
        imposta(
            SERVICE_RUNNING,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
        );
        if let Some(corpo) = CORPO.get() {
            corpo(&FERMATA);
        }
        imposta(SERVICE_STOPPED, 0);
    }

    /// Un nome della sessione, copiato e liberato (invariante 2).
    fn nome_della_sessione(sessione: u32, genere: WTS_INFO_CLASS) -> Option<String> {
        let mut testo: windows_sys::core::PWSTR = std::ptr::null_mut();
        let mut byte = 0u32;
        // SAFETY: Windows scrive un puntatore suo e la sua lunghezza.
        let riuscita = unsafe {
            WTSQuerySessionInformationW(
                WTS_CURRENT_SERVER_HANDLE,
                sessione,
                genere,
                &raw mut testo,
                &raw mut byte,
            )
        };
        if riuscita == 0 || testo.is_null() {
            return None;
        }
        let unita = (byte as usize) / 2;
        // SAFETY: il blocco è lungo `byte` byte, cioè `unita` caratteri UTF-16,
        // e si legge prima di liberarlo.
        let lette = unsafe { std::slice::from_raw_parts(testo, unita) };
        let fine = lette.iter().position(|&c| c == 0).unwrap_or(lette.len());
        let nome = String::from_utf16_lossy(&lette[..fine]);
        // SAFETY: liberato una volta sola, dopo la copia.
        unsafe { WTSFreeMemory(testo.cast()) };
        Some(nome)
    }

    pub fn own_account_name() -> Result<String, PlatformError> {
        let mut buffer = vec![0u16; 512];
        let mut lunghezza = 512u32;
        // SAFETY: il buffer è lungo quanto `lunghezza` dice.
        let riuscita =
            unsafe { GetUserNameExW(NameSamCompatible, buffer.as_mut_ptr(), &raw mut lunghezza) };
        if !riuscita {
            return Err(errore());
        }
        let fine = (lunghezza as usize).min(buffer.len());
        Ok(String::from_utf16_lossy(&buffer[..fine]))
    }

    pub fn user_has_a_session() -> Result<bool, PlatformError> {
        let io = own_account_name()?.to_lowercase();
        let mut sessioni: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut quante = 0u32;
        // SAFETY: Windows scrive un elenco suo e la sua lunghezza.
        let riuscita = unsafe {
            WTSEnumerateSessionsW(
                WTS_CURRENT_SERVER_HANDLE,
                0,
                1,
                &raw mut sessioni,
                &raw mut quante,
            )
        };
        if riuscita == 0 || sessioni.is_null() {
            return Err(errore());
        }
        // SAFETY: l'elenco ha `quante` voci, e si legge prima di liberarlo.
        let elenco = unsafe { std::slice::from_raw_parts(sessioni, quante as usize) };
        let identificativi: Vec<u32> = elenco
            .iter()
            .map(|s| s.SessionId)
            .filter(|&id| id != 0)
            .collect();
        // SAFETY: liberato una volta sola, dopo la copia (invariante 2).
        unsafe { WTSFreeMemory(sessioni.cast()) };
        Ok(identificativi.into_iter().any(|id| {
            let utente = nome_della_sessione(id, WTSUserName).unwrap_or_default();
            if utente.is_empty() {
                return false;
            }
            let dominio = nome_della_sessione(id, WTSDomainName).unwrap_or_default();
            format!("{dominio}\\{utente}").to_lowercase() == io
        }))
    }

    /// Chiude un handle del gestore, una volta sola (invariante 3).
    fn chiudi(handle: SC_HANDLE) {
        // SAFETY: l'handle è aperto e non si usa più.
        unsafe {
            CloseServiceHandle(handle);
        }
    }

    pub fn state(name: &str) -> Result<ServiceState, PlatformError> {
        // SAFETY: macchina e archivio nulli: quelli locali, in sola connessione.
        let gestore =
            unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
        if gestore.is_null() {
            return Err(errore());
        }
        let nome = wide(name);
        // SAFETY: il nome è terminato da zero e vive per la chiamata.
        let servizio = unsafe { OpenServiceW(gestore, nome.as_ptr(), SERVICE_QUERY_STATUS) };
        if servizio.is_null() {
            // SAFETY: letto subito dopo la chiamata che non è riuscita.
            let code = unsafe { GetLastError() };
            chiudi(gestore);
            return if code == ERROR_SERVICE_DOES_NOT_EXIST {
                Ok(ServiceState::NotInstalled)
            } else {
                Err(PlatformError::BackgroundService { code })
            };
        }
        let mut status = SERVICE_STATUS::default();
        // SAFETY: la struttura vive per la chiamata.
        let riuscita = unsafe { QueryServiceStatus(servizio, &raw mut status) };
        let esito = if riuscita == 0 {
            Err(errore())
        } else {
            Ok(match status.dwCurrentState {
                SERVICE_RUNNING => ServiceState::Running,
                SERVICE_STOPPED => ServiceState::Stopped,
                _ => ServiceState::Changing,
            })
        };
        chiudi(servizio);
        chiudi(gestore);
        esito
    }

    pub fn session_is_ending() -> bool {
        // SAFETY: legge soltanto una metrica del sistema.
        unsafe { GetSystemMetrics(SM_SHUTTINGDOWN) != 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Il nome passa terminato da zero.**
    #[test]
    fn il_nome_passa_terminato_da_zero() {
        let nome = wide("Ab");
        assert_eq!(nome, vec![u16::from(b'A'), u16::from(b'b'), 0]);
        let segnale = StopSignal::new();
        assert!(!segnale.requested());
        segnale.request();
        assert!(segnale.requested());
    }

    /// **Un servizio che non c'è si dice non installato**, senza errore: è
    /// la risposta di Windows per la postazione senza la casella scelta.
    #[cfg(windows)]
    #[test]
    fn windows_dice_che_un_servizio_assente_non_e_installato() {
        let esito = state("Nexum97ServizioCheNonEsisteDiProva");
        assert_eq!(esito.ok(), Some(ServiceState::NotInstalled));
    }

    /// **Il nome dell'utente ha il dominio davanti**: è la forma con cui si
    /// confronta quello delle sessioni.
    #[cfg(windows)]
    #[test]
    fn il_nome_dell_utente_ha_il_dominio_davanti() {
        let Ok(nome) = own_account_name() else {
            panic!("Windows deve dire il nome dell'utente");
        };
        assert!(nome.contains('\\'), "{nome}");
    }
}

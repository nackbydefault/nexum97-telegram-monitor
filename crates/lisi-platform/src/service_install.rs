// Modulo del crate autorizzato a contenere `unsafe`, dopo quelli elencati in
// `lib.rs`. Vedere ADR-0009 per la regola e ADR-0203 per la decisione che ha
// portato qui.
#![cfg_attr(windows, allow(unsafe_code))]

//! L'installazione del servizio del monitoraggio in background (SERVICE-01
//! parte 2, ADR-0203 decisione 9).
//!
//! # Che cosa fa
//!
//! - [`ask_password`] fa chiedere a Windows, con la sua finestra, la password
//!   dell'utente con cui il servizio girerà, e la prova accedendo;
//! - [`install`] concede a quell'utente il diritto di accedere come servizio,
//!   crea il servizio (o ne riscrive la password), permette all'utente di
//!   avviarlo e fermarlo, e lo avvia;
//! - [`remove`] lo ferma e lo toglie;
//! - [`start`] e [`stop`] lo avviano e lo fermano, per l'aggiornamento;
//! - [`is_elevated`] e [`run_elevated`] dicono se il processo ha i permessi
//!   dell'amministratore, e li chiedono a Windows per un secondo processo.
//!
//! # Che cosa NON fa
//!
//! Non conserva la password: la passa al gestore dei servizi, che la custodisce
//! lui, e la cancella dalla memoria subito dopo. Non toglie il diritto di
//! accedere come servizio quando il servizio si toglie: altri servizi
//! dell'utente potrebbero averne bisogno.
//!
//! # Le invarianti dell'FFI
//!
//! 1. Ogni testo passa in UTF-16 terminato da zero, e vive per la chiamata.
//! 2. La password vive soltanto in un buffer [`Zeroizing`], e il pacchetto che
//!    restituisce la finestra di Windows si cancella prima di liberarlo con
//!    `CoTaskMemFree`.
//! 3. Ogni handle del gestore dei servizi si chiude con `CloseServiceHandle`,
//!    ogni handle di processo o di token con `CloseHandle`, la politica di
//!    sicurezza con `LsaClose`, ogni testo e descrittore di Windows con
//!    `LocalFree`: una volta sola.

use std::path::Path;

use zeroize::Zeroizing;

use crate::error::PlatformError;

/// Le credenziali dell'utente del servizio, provate.
pub struct Credentials {
    /// L'utente, nella forma `DOMINIO\nome`.
    pub account: String,
    /// La password in UTF-16 terminata da zero (invariante 2).
    password: Zeroizing<Vec<u16>>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(std::any::type_name::<Self>())
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

/// Com'è finito un processo avviato con i permessi dell'amministratore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Elevated {
    /// È finito con questo codice.
    Exited(u32),
    /// La persona non ha dato i permessi.
    Declined,
}

/// Lo stesso utente, scritto in due modi: `DOMINIO\nome` e `nome` valgono
/// uguale, maiuscole o no.
#[must_use]
pub fn same_account(expected: &str, typed: &str) -> bool {
    let atteso = expected.to_lowercase();
    let scritto = typed.trim().to_lowercase();
    if scritto.contains('\\') {
        return scritto == atteso;
    }
    atteso
        .rsplit_once('\\')
        .map_or(atteso.as_str(), |(_, nome)| nome)
        == scritto
}

/// Fa chiedere a Windows la password di `account` e la prova.
///
/// Restituisce `None` se la persona chiude la finestra.
///
/// # Errori
///
/// Restituisce un errore se la finestra non si apre, se l'utente scritto è un
/// altro, o se Windows rifiuta la password (`ERROR_LOGON_FAILURE`).
pub fn ask_password(
    account: &str,
    caption: &str,
    message: &str,
) -> Result<Option<Credentials>, PlatformError> {
    #[cfg(windows)]
    {
        windows_impl::ask_password(account, caption, message)
    }
    #[cfg(not(windows))]
    {
        let _ = (account, caption, message);
        Err(PlatformError::Unsupported)
    }
}

/// Crea il servizio `name` per l'utente delle credenziali, o ne riscrive
/// utente e password se c'è già, e lo avvia.
///
/// # Errori
///
/// Restituisce un errore se il processo non ha i permessi
/// dell'amministratore, o se Windows rifiuta un passo.
pub fn install(
    name: &str,
    display_name: &str,
    description: &str,
    command_line: &str,
    credentials: &Credentials,
) -> Result<(), PlatformError> {
    #[cfg(windows)]
    {
        windows_impl::install(name, display_name, description, command_line, credentials)
    }
    #[cfg(not(windows))]
    {
        let _ = (name, display_name, description, command_line, credentials);
        Err(PlatformError::Unsupported)
    }
}

/// Ferma e toglie il servizio `name`. Se non c'è, non fa nulla.
///
/// # Errori
///
/// Restituisce un errore se il processo non ha i permessi
/// dell'amministratore, o se Windows rifiuta.
pub fn remove(name: &str) -> Result<(), PlatformError> {
    #[cfg(windows)]
    {
        windows_impl::remove(name)
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        Err(PlatformError::Unsupported)
    }
}

/// Avvia il servizio `name`. Se non c'è, o gira già, non fa nulla.
///
/// # Errori
///
/// Restituisce un errore se Windows rifiuta.
pub fn start(name: &str) -> Result<(), PlatformError> {
    #[cfg(windows)]
    {
        windows_impl::start(name)
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        Err(PlatformError::Unsupported)
    }
}

/// Ferma il servizio `name` e aspetta che sia fermo, fino a trenta secondi.
/// Se non c'è, o è già fermo, non fa nulla.
///
/// # Errori
///
/// Restituisce un errore se Windows rifiuta, o se dopo trenta secondi gira
/// ancora.
pub fn stop(name: &str) -> Result<(), PlatformError> {
    #[cfg(windows)]
    {
        windows_impl::stop(name)
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        Err(PlatformError::Unsupported)
    }
}

/// Se questo processo ha i permessi dell'amministratore.
#[must_use]
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        windows_impl::is_elevated()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Avvia `program` con `arguments` chiedendo a Windows i permessi
/// dell'amministratore, e ne aspetta la fine.
///
/// # Errori
///
/// Restituisce un errore se Windows non lo avvia per una ragione diversa dal
/// rifiuto della persona.
pub fn run_elevated(program: &Path, arguments: &str) -> Result<Elevated, PlatformError> {
    #[cfg(windows)]
    {
        windows_impl::run_elevated(program, arguments)
    }
    #[cfg(not(windows))]
    {
        let _ = (program, arguments);
        Err(PlatformError::Unsupported)
    }
}

/// UTF-16 terminato da zero.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// La voce che concede all'utente `sid` di avviare, fermare e interrogare il
/// servizio, in SDDL: RP avvia, WP ferma, LC e LO chiedono lo stato, RC legge
/// i permessi.
fn user_ace(sid: &str) -> String {
    format!("(A;;RPWPLCLORC;;;{sid})")
}

/// I permessi del servizio con la voce dell'utente in più, se manca.
fn with_user_ace(dacl: &str, sid: &str) -> String {
    let voce = user_ace(sid);
    if dacl.contains(&voce) {
        dacl.to_owned()
    } else {
        format!("{dacl}{voce}")
    }
}

#[cfg(windows)]
mod windows_impl {
    use std::ffi::c_void;
    use std::path::Path;
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_CANCELLED, ERROR_INSUFFICIENT_BUFFER, ERROR_LOGON_FAILURE,
        ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_EXISTS,
        ERROR_SERVICE_NOT_ACTIVE, GetLastError, HANDLE, LocalFree,
    };
    use windows_sys::Win32::Security::Authentication::Identity::{
        LSA_HANDLE, LSA_OBJECT_ATTRIBUTES, LSA_UNICODE_STRING, LsaAddAccountRights, LsaClose,
        LsaNtStatusToWinError, LsaOpenPolicy, POLICY_CREATE_ACCOUNT, POLICY_LOOKUP_NAMES,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::Credentials::{
        CRED_PACK_GENERIC_CREDENTIALS, CREDUI_INFOW, CREDUIWIN_GENERIC,
        CredPackAuthenticationBufferW, CredUIPromptForWindowsCredentialsW,
        CredUnPackAuthenticationBufferW,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetTokenInformation, LOGON32_LOGON_INTERACTIVE,
        LOGON32_PROVIDER_DEFAULT, LogonUserW, LookupAccountNameW, PSECURITY_DESCRIPTOR,
        SID_NAME_USE, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::System::Services::{
        ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService,
        CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW, QueryServiceObjectSecurity,
        QueryServiceStatus, SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE,
        SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION, SERVICE_CONTROL_STOP,
        SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL, SERVICE_NO_CHANGE, SERVICE_QUERY_STATUS,
        SERVICE_START, SERVICE_STATUS, SERVICE_STOP, SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS,
        SetServiceObjectSecurity, StartServiceW,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcessToken, WaitForSingleObject,
    };
    use windows_sys::Win32::UI::Shell::{
        SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    use zeroize::{Zeroize, Zeroizing};

    use super::{Credentials, Elevated, same_account, wide, with_user_ace};
    use crate::error::PlatformError;

    /// Il diritto di accedere come servizio.
    const DIRITTO: &str = "SeServiceLogonRight";
    /// Quanto si aspetta un servizio che si ferma.
    const ATTESA: Duration = Duration::from_secs(30);

    fn errore() -> PlatformError {
        // SAFETY: `GetLastError` legge soltanto il codice del thread.
        let code = unsafe { GetLastError() };
        PlatformError::BackgroundService { code }
    }

    fn codice(code: u32) -> PlatformError {
        PlatformError::BackgroundService { code }
    }

    /// Un testo di Windows terminato da zero, copiato e liberato con
    /// `LocalFree` (invariante 3).
    fn testo_locale(testo: *mut u16) -> String {
        if testo.is_null() {
            return String::new();
        }
        let mut lunghezza = 0usize;
        // SAFETY: Windows termina il testo con zero; si legge fino a lì.
        while unsafe { *testo.add(lunghezza) } != 0 {
            lunghezza += 1;
        }
        // SAFETY: `lunghezza` caratteri letti qui sopra.
        let copia =
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(testo, lunghezza) });
        // SAFETY: liberato una volta sola, dopo la copia.
        unsafe { LocalFree(testo.cast()) };
        copia
    }

    pub fn ask_password(
        account: &str,
        caption: &str,
        message: &str,
    ) -> Result<Option<Credentials>, PlatformError> {
        let utente = wide(account);
        let vuota = wide("");
        let mut grandezza = 0u32;
        // SAFETY: la prima chiamata chiede soltanto la grandezza del pacchetto.
        unsafe {
            CredPackAuthenticationBufferW(
                CRED_PACK_GENERIC_CREDENTIALS,
                utente.as_ptr(),
                vuota.as_ptr(),
                std::ptr::null_mut(),
                &raw mut grandezza,
            );
        }
        let mut pacchetto = vec![0u8; grandezza as usize];
        // SAFETY: il buffer è lungo quanto `grandezza` dice.
        if unsafe {
            CredPackAuthenticationBufferW(
                CRED_PACK_GENERIC_CREDENTIALS,
                utente.as_ptr(),
                vuota.as_ptr(),
                pacchetto.as_mut_ptr(),
                &raw mut grandezza,
            )
        } == 0
        {
            return Err(errore());
        }
        let didascalia = wide(caption);
        let messaggio = wide(message);
        let info = CREDUI_INFOW {
            cbSize: u32::try_from(std::mem::size_of::<CREDUI_INFOW>()).unwrap_or(u32::MAX),
            hwndParent: std::ptr::null_mut(),
            pszMessageText: messaggio.as_ptr(),
            pszCaptionText: didascalia.as_ptr(),
            hbmBanner: std::ptr::null_mut(),
        };
        let mut genere = 0u32;
        let mut uscita: *mut c_void = std::ptr::null_mut();
        let mut lunghezza_uscita = 0u32;
        let mut salva = 0;
        // SAFETY: tutti i testi e il pacchetto vivono per la chiamata; Windows
        // scrive un pacchetto suo e la sua lunghezza.
        let esito = unsafe {
            CredUIPromptForWindowsCredentialsW(
                &raw const info,
                0,
                &raw mut genere,
                pacchetto.as_ptr().cast(),
                grandezza,
                &raw mut uscita,
                &raw mut lunghezza_uscita,
                &raw mut salva,
                CREDUIWIN_GENERIC,
            )
        };
        if esito == ERROR_CANCELLED {
            return Ok(None);
        }
        if esito != 0 || uscita.is_null() {
            return Err(codice(esito));
        }
        let mut nome = vec![0u16; 514];
        let mut lunghezza_nome = 514u32;
        let mut dominio = vec![0u16; 256];
        let mut lunghezza_dominio = 256u32;
        let mut password = Zeroizing::new(vec![0u16; 512]);
        let mut lunghezza_password = 512u32;
        // SAFETY: i tre buffer sono lunghi quanto dicono le lunghezze, e il
        // pacchetto è quello appena scritto da Windows.
        let aperto = unsafe {
            CredUnPackAuthenticationBufferW(
                0,
                uscita,
                lunghezza_uscita,
                nome.as_mut_ptr(),
                &raw mut lunghezza_nome,
                dominio.as_mut_ptr(),
                &raw mut lunghezza_dominio,
                password.as_mut_ptr(),
                &raw mut lunghezza_password,
            )
        };
        let errore_apertura = if aperto == 0 { Some(errore()) } else { None };
        // SAFETY: il pacchetto è lungo `lunghezza_uscita` byte; si cancella e
        // si libera una volta sola (invariante 2).
        unsafe {
            std::slice::from_raw_parts_mut(uscita.cast::<u8>(), lunghezza_uscita as usize)
                .zeroize();
            CoTaskMemFree(uscita);
        }
        if let Some(errore) = errore_apertura {
            return Err(errore);
        }
        let fine = nome.iter().position(|&c| c == 0).unwrap_or(nome.len());
        let scritto = String::from_utf16_lossy(&nome[..fine]);
        if !same_account(account, &scritto) {
            return Err(codice(ERROR_LOGON_FAILURE));
        }
        prova(account, &password)?;
        Ok(Some(Credentials {
            account: account.to_owned(),
            password,
        }))
    }

    /// Prova la password accedendo come la persona, e chiude subito il token.
    fn prova(account: &str, password: &[u16]) -> Result<(), PlatformError> {
        let (dominio, nome) = account.split_once('\\').unwrap_or((".", account));
        let dominio = wide(dominio);
        let nome = wide(nome);
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: i testi sono terminati da zero, e la password lo è
        // (invariante 1).
        let riuscita = unsafe {
            LogonUserW(
                nome.as_ptr(),
                dominio.as_ptr(),
                password.as_ptr(),
                LOGON32_LOGON_INTERACTIVE,
                LOGON32_PROVIDER_DEFAULT,
                &raw mut token,
            )
        };
        if riuscita == 0 {
            return Err(errore());
        }
        // SAFETY: il token è aperto e non si usa più (invariante 3).
        unsafe { CloseHandle(token) };
        Ok(())
    }

    /// Il SID dell'utente, in binario.
    fn sid(account: &str) -> Result<Vec<u8>, PlatformError> {
        let nome = wide(account);
        let mut grandezza = 0u32;
        let mut lunghezza_dominio = 0u32;
        let mut uso: SID_NAME_USE = 0;
        // SAFETY: la prima chiamata chiede soltanto le grandezze.
        unsafe {
            LookupAccountNameW(
                std::ptr::null(),
                nome.as_ptr(),
                std::ptr::null_mut(),
                &raw mut grandezza,
                std::ptr::null_mut(),
                &raw mut lunghezza_dominio,
                &raw mut uso,
            );
        }
        // SAFETY: letto subito dopo la chiamata.
        let code = unsafe { GetLastError() };
        if code != ERROR_INSUFFICIENT_BUFFER {
            return Err(codice(code));
        }
        let mut sid = vec![0u8; grandezza as usize];
        let mut dominio = vec![0u16; lunghezza_dominio as usize];
        // SAFETY: i due buffer sono lunghi quanto dicono le grandezze.
        if unsafe {
            LookupAccountNameW(
                std::ptr::null(),
                nome.as_ptr(),
                sid.as_mut_ptr().cast(),
                &raw mut grandezza,
                dominio.as_mut_ptr(),
                &raw mut lunghezza_dominio,
                &raw mut uso,
            )
        } == 0
        {
            return Err(errore());
        }
        Ok(sid)
    }

    /// Il SID in testo, come lo vuole SDDL.
    fn sid_in_testo(sid: &mut [u8]) -> Result<String, PlatformError> {
        let mut testo: *mut u16 = std::ptr::null_mut();
        // SAFETY: il SID viene da `LookupAccountNameW`.
        if unsafe { ConvertSidToStringSidW(sid.as_mut_ptr().cast(), &raw mut testo) } == 0 {
            return Err(errore());
        }
        Ok(testo_locale(testo))
    }

    /// Concede all'utente il diritto di accedere come servizio.
    fn concedi_il_diritto(sid: &mut [u8]) -> Result<(), PlatformError> {
        let attributi = LSA_OBJECT_ATTRIBUTES {
            Length: 0,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: std::ptr::null_mut(),
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let mut politica: LSA_HANDLE = 0;
        // SAFETY: macchina nulla, quella locale; gli attributi sono vuoti come
        // la documentazione chiede.
        let stato = unsafe {
            LsaOpenPolicy(
                std::ptr::null(),
                &raw const attributi,
                (POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES) as u32,
                &raw mut politica,
            )
        };
        if stato != 0 {
            // SAFETY: converte soltanto un codice.
            return Err(codice(unsafe { LsaNtStatusToWinError(stato) }));
        }
        let mut diritto: Vec<u16> = super::wide(DIRITTO);
        let byte = u16::try_from((diritto.len() - 1) * 2).unwrap_or(u16::MAX);
        let nome = LSA_UNICODE_STRING {
            Length: byte,
            MaximumLength: byte,
            Buffer: diritto.as_mut_ptr(),
        };
        // SAFETY: la politica è aperta, il SID e il nome vivono per la
        // chiamata.
        let stato =
            unsafe { LsaAddAccountRights(politica, sid.as_mut_ptr().cast(), &raw const nome, 1) };
        // SAFETY: chiusa una volta sola (invariante 3).
        unsafe { LsaClose(politica) };
        if stato != 0 {
            // SAFETY: converte soltanto un codice.
            return Err(codice(unsafe { LsaNtStatusToWinError(stato) }));
        }
        Ok(())
    }

    /// Chiude un handle del gestore, una volta sola (invariante 3).
    fn chiudi(handle: SC_HANDLE) {
        // SAFETY: l'handle è aperto e non si usa più.
        unsafe {
            CloseServiceHandle(handle);
        }
    }

    fn gestore(accesso: u32) -> Result<SC_HANDLE, PlatformError> {
        // SAFETY: macchina e archivio nulli: quelli locali.
        let gestore = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), accesso) };
        if gestore.is_null() {
            return Err(errore());
        }
        Ok(gestore)
    }

    /// Apre il servizio; `None` se non è installato.
    fn apri(
        gestore: SC_HANDLE,
        name: &str,
        accesso: u32,
    ) -> Result<Option<SC_HANDLE>, PlatformError> {
        let nome = wide(name);
        // SAFETY: il nome è terminato da zero e vive per la chiamata.
        let servizio = unsafe { OpenServiceW(gestore, nome.as_ptr(), accesso) };
        if servizio.is_null() {
            // SAFETY: letto subito dopo la chiamata.
            let code = unsafe { GetLastError() };
            return if code == ERROR_SERVICE_DOES_NOT_EXIST {
                Ok(None)
            } else {
                Err(codice(code))
            };
        }
        Ok(Some(servizio))
    }

    /// Aggiunge ai permessi del servizio la voce dell'utente.
    fn permetti_all_utente(servizio: SC_HANDLE, sid: &str) -> Result<(), PlatformError> {
        let mut grandezza = 0u32;
        // SAFETY: la prima chiamata chiede soltanto la grandezza.
        unsafe {
            QueryServiceObjectSecurity(
                servizio,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                0,
                &raw mut grandezza,
            );
        }
        let mut descrittore = vec![0u8; grandezza as usize];
        // SAFETY: il buffer è lungo quanto `grandezza` dice.
        if unsafe {
            QueryServiceObjectSecurity(
                servizio,
                DACL_SECURITY_INFORMATION,
                descrittore.as_mut_ptr().cast(),
                grandezza,
                &raw mut grandezza,
            )
        } == 0
        {
            return Err(errore());
        }
        let mut testo: *mut u16 = std::ptr::null_mut();
        // SAFETY: il descrittore è quello appena letto; Windows scrive un testo
        // suo, liberato da `testo_locale`.
        if unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descrittore.as_mut_ptr().cast(),
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &raw mut testo,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(errore());
        }
        let nuovo = wide(&with_user_ace(&testo_locale(testo), sid));
        let mut convertito: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: il testo è terminato da zero; Windows scrive un descrittore
        // suo, liberato qui sotto.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                nuovo.as_ptr(),
                SDDL_REVISION_1,
                &raw mut convertito,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(errore());
        }
        // SAFETY: il descrittore è valido fino a `LocalFree`.
        let riuscita =
            unsafe { SetServiceObjectSecurity(servizio, DACL_SECURITY_INFORMATION, convertito) };
        let esito = if riuscita == 0 { Err(errore()) } else { Ok(()) };
        // SAFETY: liberato una volta sola (invariante 3).
        unsafe { LocalFree(convertito) };
        esito
    }

    pub fn install(
        name: &str,
        display_name: &str,
        description: &str,
        command_line: &str,
        credentials: &Credentials,
    ) -> Result<(), PlatformError> {
        let mut sid_binario = sid(&credentials.account)?;
        let sid = sid_in_testo(&mut sid_binario)?;
        concedi_il_diritto(&mut sid_binario)?;
        let gestore = gestore(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
        let esito = crea_o_riscrivi(
            gestore,
            name,
            display_name,
            description,
            command_line,
            credentials,
            &sid,
        );
        chiudi(gestore);
        esito
    }

    fn crea_o_riscrivi(
        gestore: SC_HANDLE,
        name: &str,
        display_name: &str,
        description: &str,
        command_line: &str,
        credentials: &Credentials,
        sid: &str,
    ) -> Result<(), PlatformError> {
        let nome = wide(name);
        let visibile = wide(display_name);
        let comando = wide(command_line);
        let utente = wide(&credentials.account);
        // SAFETY: tutti i testi sono terminati da zero e vivono per la
        // chiamata, la password compresa (invarianti 1 e 2).
        let mut servizio = unsafe {
            CreateServiceW(
                gestore,
                nome.as_ptr(),
                visibile.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                comando.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                utente.as_ptr(),
                credentials.password.as_ptr(),
            )
        };
        if servizio.is_null() {
            // SAFETY: letto subito dopo la chiamata.
            let code = unsafe { GetLastError() };
            if code != ERROR_SERVICE_EXISTS {
                return Err(codice(code));
            }
            // C'è già: si riscrivono comando, utente e password, per chi la
            // password di Windows l'ha cambiata.
            servizio = apri(gestore, name, SERVICE_ALL_ACCESS)?
                .ok_or(codice(ERROR_SERVICE_DOES_NOT_EXIST))?;
            // SAFETY: come sopra.
            if unsafe {
                ChangeServiceConfigW(
                    servizio,
                    SERVICE_NO_CHANGE,
                    SERVICE_AUTO_START,
                    SERVICE_NO_CHANGE,
                    comando.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    utente.as_ptr(),
                    credentials.password.as_ptr(),
                    visibile.as_ptr(),
                )
            } == 0
            {
                let errore = errore();
                chiudi(servizio);
                return Err(errore);
            }
        }
        let esito = completa(servizio, description, sid);
        chiudi(servizio);
        esito
    }

    fn completa(servizio: SC_HANDLE, description: &str, sid: &str) -> Result<(), PlatformError> {
        let mut descrizione = wide(description);
        let voce = SERVICE_DESCRIPTIONW {
            lpDescription: descrizione.as_mut_ptr(),
        };
        // SAFETY: la struttura e il testo vivono per la chiamata.
        if unsafe {
            ChangeServiceConfig2W(
                servizio,
                SERVICE_CONFIG_DESCRIPTION,
                (&raw const voce).cast(),
            )
        } == 0
        {
            return Err(errore());
        }
        permetti_all_utente(servizio, sid)?;
        avvia(servizio)
    }

    fn avvia(servizio: SC_HANDLE) -> Result<(), PlatformError> {
        // SAFETY: nessun argomento.
        if unsafe { StartServiceW(servizio, 0, std::ptr::null()) } == 0 {
            // SAFETY: letto subito dopo la chiamata.
            let code = unsafe { GetLastError() };
            if code != ERROR_SERVICE_ALREADY_RUNNING {
                return Err(codice(code));
            }
        }
        Ok(())
    }

    /// Chiede di fermarsi e aspetta (invariante: il servizio è aperto con
    /// `SERVICE_STOP` e `SERVICE_QUERY_STATUS`).
    fn ferma(servizio: SC_HANDLE) -> Result<(), PlatformError> {
        let mut status = SERVICE_STATUS::default();
        // SAFETY: la struttura vive per la chiamata.
        if unsafe { ControlService(servizio, SERVICE_CONTROL_STOP, &raw mut status) } == 0 {
            // SAFETY: letto subito dopo la chiamata.
            let code = unsafe { GetLastError() };
            if code == ERROR_SERVICE_NOT_ACTIVE {
                return Ok(());
            }
            return Err(codice(code));
        }
        let inizio = Instant::now();
        loop {
            // SAFETY: la struttura vive per la chiamata.
            if unsafe { QueryServiceStatus(servizio, &raw mut status) } == 0 {
                return Err(errore());
            }
            if status.dwCurrentState == SERVICE_STOPPED {
                return Ok(());
            }
            if inizio.elapsed() > ATTESA {
                return Err(codice(windows_sys::Win32::Foundation::ERROR_TIMEOUT));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    pub fn remove(name: &str) -> Result<(), PlatformError> {
        let gestore = gestore(SC_MANAGER_CONNECT)?;
        let esito = (|| {
            let Some(servizio) = apri(
                gestore,
                name,
                SERVICE_STOP
                    | SERVICE_QUERY_STATUS
                    | windows_sys::Win32::Storage::FileSystem::DELETE,
            )?
            else {
                return Ok(());
            };
            let fermato = ferma(servizio);
            // SAFETY: il servizio è aperto con il permesso di toglierlo.
            let tolto = if unsafe { DeleteService(servizio) } == 0 {
                Err(errore())
            } else {
                Ok(())
            };
            chiudi(servizio);
            fermato.and(tolto)
        })();
        chiudi(gestore);
        esito
    }

    pub fn start(name: &str) -> Result<(), PlatformError> {
        let gestore = gestore(SC_MANAGER_CONNECT)?;
        let esito = match apri(gestore, name, SERVICE_START) {
            Ok(Some(servizio)) => {
                let esito = avvia(servizio);
                chiudi(servizio);
                esito
            }
            Ok(None) => Ok(()),
            Err(errore) => Err(errore),
        };
        chiudi(gestore);
        esito
    }

    pub fn stop(name: &str) -> Result<(), PlatformError> {
        let gestore = gestore(SC_MANAGER_CONNECT)?;
        let esito = match apri(gestore, name, SERVICE_STOP | SERVICE_QUERY_STATUS) {
            Ok(Some(servizio)) => {
                let esito = ferma(servizio);
                chiudi(servizio);
                esito
            }
            Ok(None) => Ok(()),
            Err(errore) => Err(errore),
        };
        chiudi(gestore);
        esito
    }

    pub fn is_elevated() -> bool {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: lo pseudo-handle del processo corrente non si chiude.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
            return false;
        }
        let mut elevazione = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut scritti = 0u32;
        // SAFETY: la struttura vive per la chiamata ed è lunga quanto si dice.
        let riuscita = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                (&raw mut elevazione).cast(),
                u32::try_from(std::mem::size_of::<TOKEN_ELEVATION>()).unwrap_or(0),
                &raw mut scritti,
            )
        };
        // SAFETY: chiuso una volta sola (invariante 3).
        unsafe { CloseHandle(token) };
        riuscita != 0 && elevazione.TokenIsElevated != 0
    }

    pub fn run_elevated(program: &Path, arguments: &str) -> Result<Elevated, PlatformError> {
        let verbo = wide("runas");
        let programma = wide(&program.to_string_lossy());
        let argomenti = wide(arguments);
        // SAFETY: la struttura è fatta di numeri e puntatori: tutta a zero è
        // valida, e si riempie qui sotto.
        let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
        info.cbSize = u32::try_from(std::mem::size_of::<SHELLEXECUTEINFOW>()).unwrap_or(u32::MAX);
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = verbo.as_ptr();
        info.lpFile = programma.as_ptr();
        info.lpParameters = argomenti.as_ptr();
        info.nShow = SW_SHOWNORMAL;
        // SAFETY: i testi vivono per la chiamata.
        if unsafe { ShellExecuteExW(&raw mut info) } == 0 {
            // SAFETY: letto subito dopo la chiamata.
            let code = unsafe { GetLastError() };
            return if code == ERROR_CANCELLED {
                Ok(Elevated::Declined)
            } else {
                Err(codice(code))
            };
        }
        if info.hProcess.is_null() {
            return Ok(Elevated::Exited(0));
        }
        let mut uscita = 0u32;
        // SAFETY: l'handle del processo è aperto finché non si chiude qui.
        let riuscita = unsafe {
            WaitForSingleObject(info.hProcess, INFINITE);
            GetExitCodeProcess(info.hProcess, &raw mut uscita)
        };
        // SAFETY: chiuso una volta sola (invariante 3).
        unsafe { CloseHandle(info.hProcess) };
        if riuscita == 0 {
            return Err(errore());
        }
        Ok(Elevated::Exited(uscita))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Lo stesso utente, scritto in due modi**: con il dominio o senza,
    /// maiuscole o no; un altro nome no.
    #[test]
    fn lo_stesso_utente_scritto_in_due_modi() {
        assert!(same_account("UFFICIO\\Mario", "mario"));
        assert!(same_account("UFFICIO\\Mario", "ufficio\\MARIO"));
        assert!(same_account("UFFICIO\\Mario", " Mario "));
        assert!(!same_account("UFFICIO\\Mario", "ALTRO\\Mario"));
        assert!(!same_account("UFFICIO\\Mario", "Luigi"));
    }

    /// **La voce dell'utente si aggiunge una volta sola**, in fondo ai
    /// permessi che Windows ha dato al servizio.
    #[test]
    fn la_voce_dell_utente_si_aggiunge_una_volta() {
        let dacl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)";
        let una = with_user_ace(dacl, "S-1-5-21-1-2-3-1001");
        assert_eq!(una, format!("{dacl}(A;;RPWPLCLORC;;;S-1-5-21-1-2-3-1001)"));
        assert_eq!(with_user_ace(&una, "S-1-5-21-1-2-3-1001"), una);
    }

    /// **Senza i permessi dell'amministratore si dice di no**: le prove non
    /// girano elevate, e la risposta deve arrivare senza errore.
    #[cfg(windows)]
    #[test]
    fn windows_dice_se_il_processo_e_elevato() {
        let _ = is_elevated();
        assert_eq!(start("Nexum97ServizioCheNonEsisteDiProva").ok(), Some(()));
        assert_eq!(stop("Nexum97ServizioCheNonEsisteDiProva").ok(), Some(()));
    }
}

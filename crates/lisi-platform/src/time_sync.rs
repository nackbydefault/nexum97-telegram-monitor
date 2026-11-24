// TREDICESIMO modulo del crate autorizzato a contenere `unsafe`. Vedere ADR-0003
// per la regola e ADR-0168 per la decisione che ha portato qui.
#![cfg_attr(windows, allow(unsafe_code))]

//! Se Windows sincronizza l'ora (CLOCK-01, ADR-0168).
//!
//! # Si legge, non si chiede
//!
//! Due valori del registro di sistema, in sola lettura: il genere di
//! sincronizzazione del servizio dell'ora e se il servizio è disattivato.
//! **Nessuna rete**: il programma non interroga orologi in rete.
//!
//! # Che cosa non dice
//!
//! Che l'ora sia giusta. Il registro dice come Windows è configurato, non
//! com'è andata l'ultima sincronizzazione. Le frasi per l'operatore stanno nel
//! controllo di avvio (`lisi-services::preflight`), non qui.

/// Dove si legge il genere di sincronizzazione.
#[cfg(windows)]
const PARAMETERS: &str = r"SYSTEM\CurrentControlSet\Services\W32Time\Parameters";
/// Dove si legge se il servizio è disattivato.
#[cfg(windows)]
const SERVICE: &str = r"SYSTEM\CurrentControlSet\Services\W32Time";
/// Il valore di `Start` di un servizio disattivato.
const SERVICE_DISABLED: u32 = 4;
/// Quanti caratteri, al più, del genere di sincronizzazione.
#[cfg(windows)]
const READ_CAPACITY: usize = 64;

/// Come Windows tiene l'ora.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeSyncState {
    /// Da un orologio in rete (`NTP`).
    FromServer,
    /// Dal dominio (`NT5DS`).
    FromDomain,
    /// Dal dominio e da un orologio in rete (`AllSync`).
    FromBoth,
    /// Non la sincronizza (`NoSync`).
    NotSynchronized,
    /// Il servizio dell'ora è disattivato.
    ServiceDisabled,
    /// Non si è potuto leggere, o il valore non è uno di quelli noti.
    Undeterminable,
}

impl TimeSyncState {
    /// Se Windows è configurato per sincronizzare l'ora.
    #[must_use]
    pub const fn is_synchronized(self) -> bool {
        matches!(self, Self::FromServer | Self::FromDomain | Self::FromBoth)
    }
}

/// Classifica i due valori letti. **Un valore che non si riconosce non
/// diventa «sincronizzato»**: è non determinabile.
#[must_use]
pub fn classify(tipo: Option<&str>, avvio: Option<u32>) -> TimeSyncState {
    if avvio == Some(SERVICE_DISABLED) {
        return TimeSyncState::ServiceDisabled;
    }
    let Some(tipo) = tipo else {
        return TimeSyncState::Undeterminable;
    };
    match tipo.trim().to_ascii_uppercase().as_str() {
        "NTP" => TimeSyncState::FromServer,
        "NT5DS" => TimeSyncState::FromDomain,
        "ALLSYNC" => TimeSyncState::FromBoth,
        "NOSYNC" => TimeSyncState::NotSynchronized,
        _ => TimeSyncState::Undeterminable,
    }
}

/// Chiede a Windows, leggendo il registro, come tiene l'ora.
#[cfg(windows)]
#[must_use]
pub fn time_sync_state() -> TimeSyncState {
    classify(
        read_text(PARAMETERS, "Type").as_deref(),
        read_number(SERVICE, "Start"),
    )
}

/// Fuori da Windows non c'è nulla da leggere.
#[cfg(not(windows))]
#[must_use]
pub const fn time_sync_state() -> TimeSyncState {
    TimeSyncState::Undeterminable
}

/// Una stringa terminata da zero, per le funzioni di Windows.
#[cfg(windows)]
fn wide(testo: &str) -> Vec<u16> {
    testo.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Legge un valore testuale da `HKEY_LOCAL_MACHINE`, se c'è e se è testo.
#[cfg(windows)]
fn read_text(subkey: &str, value_name: &str) -> Option<String> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};

    let subkey = wide(subkey);
    let name = wide(value_name);
    let mut buffer = [0_u16; READ_CAPACITY];
    let mut size = u32::try_from(std::mem::size_of_val(&buffer)).ok()?;
    // SAFETY: `subkey` e `name` sono UTF-16 terminati da zero e vivono fino
    // alla fine della chiamata; `buffer` ha `READ_CAPACITY` elementi e `size`
    // ne dichiara la capienza in byte. `RRF_RT_REG_SZ` fa rifiutare a Windows
    // un valore che non sia testo; RegGetValueW non scrive oltre `size` byte e,
    // se il valore non ci sta, restituisce un errore invece di troncarlo.
    let esito = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &raw mut size,
        )
    };
    if esito != ERROR_SUCCESS {
        return None;
    }
    let caratteri = usize::try_from(size).ok()? / std::mem::size_of::<u16>();
    let letto = buffer.get(..caratteri.min(buffer.len()))?;
    let fine = letto.iter().position(|&c| c == 0).unwrap_or(letto.len());
    String::from_utf16(letto.get(..fine)?).ok()
}

/// Legge un valore numerico da `HKEY_LOCAL_MACHINE`, se c'è e se è un numero.
#[cfg(windows)]
fn read_number(subkey: &str, value_name: &str) -> Option<u32> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RegGetValueW,
    };

    let subkey = wide(subkey);
    let name = wide(value_name);
    let mut valore: u32 = 0;
    let mut size = u32::try_from(std::mem::size_of::<u32>()).ok()?;
    // SAFETY: `subkey` e `name` sono UTF-16 terminati da zero; `valore` è un
    // `u32` vivo per tutta la chiamata e `size` ne dichiara i quattro byte.
    // `RRF_RT_REG_DWORD` fa rifiutare a Windows un valore che non sia un DWORD.
    let esito = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            (&raw mut valore).cast(),
            &raw mut size,
        )
    };
    (esito == ERROR_SUCCESS).then_some(valore)
}

#[cfg(test)]
mod tests {
    use super::{TimeSyncState, classify};

    /// **I generi noti si riconoscono, il servizio disattivato prevale, e
    /// tutto il resto è non determinabile** (CLOCK-01, criterio 1; prova
    /// negativa: un genere sconosciuto letto come sincronizzato → rossa).
    #[test]
    fn i_generi_noti_si_riconoscono_e_il_resto_non_si_indovina() {
        assert_eq!(classify(Some("NTP"), Some(3)), TimeSyncState::FromServer);
        assert_eq!(
            classify(Some(" nt5ds "), Some(2)),
            TimeSyncState::FromDomain
        );
        assert_eq!(classify(Some("AllSync"), None), TimeSyncState::FromBoth);
        assert_eq!(
            classify(Some("NoSync"), Some(3)),
            TimeSyncState::NotSynchronized
        );
        assert_eq!(
            classify(Some("NTP"), Some(4)),
            TimeSyncState::ServiceDisabled
        );
        for sconosciuto in [None, Some(""), Some("ntp2"), Some("Sincronizzato")] {
            let stato = classify(sconosciuto, Some(3));
            assert_eq!(stato, TimeSyncState::Undeterminable, "{sconosciuto:?}");
            assert!(!stato.is_synchronized());
        }
    }

    /// **Solo i tre generi di sincronizzazione contano come sincronizzati**
    /// (criterio 1): il servizio disattivato, `NoSync` e il non determinabile
    /// no.
    #[test]
    fn solo_chi_sincronizza_e_sincronizzato() {
        for (stato, atteso) in [
            (TimeSyncState::FromServer, true),
            (TimeSyncState::FromDomain, true),
            (TimeSyncState::FromBoth, true),
            (TimeSyncState::NotSynchronized, false),
            (TimeSyncState::ServiceDisabled, false),
            (TimeSyncState::Undeterminable, false),
        ] {
            assert_eq!(stato.is_synchronized(), atteso, "{stato:?}");
        }
    }

    /// **La lettura vera si compie** (criterio 1): le due chiamate al registro
    /// tornano senza guastare il processo. Che cosa rispondano, sulla
    /// postazione di prova, non si sa, e la prova non lo finge.
    #[test]
    fn la_lettura_vera_si_compie() {
        let stato = super::time_sync_state();
        assert_eq!(
            stato.is_synchronized(),
            !matches!(
                stato,
                TimeSyncState::NotSynchronized
                    | TimeSyncState::ServiceDisabled
                    | TimeSyncState::Undeterminable
            ),
            "{stato:?}"
        );
    }
}

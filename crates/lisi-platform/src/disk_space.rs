// SESTO modulo del crate autorizzato a contenere `unsafe`, dopo `browser`,
// `window_chrome`, `title_bar`, `autostart` e `signature`. Vedere ADR-0009 per
// la regola e ADR-0054 per la decisione che ha portato qui.
#![cfg_attr(windows, allow(unsafe_code))]

//! Quanto spazio resta sul volume che contiene una cartella.
//!
//! # Perché serve, e a chi
//!
//! Un archivio SQLite che finisce lo spazio non restituisce un errore
//! comprensibile: restituisce `SQLITE_FULL` nel mezzo di una scrittura, e ciò
//! che l'operatore vede è un monitoraggio che smette di registrare senza dire
//! perché. Lo spazio è la sola causa fra quelle frequenti che **si vede
//! arrivare**, e vederla arrivare è tutta la differenza.
//!
//! # Quale numero, e perché quello
//!
//! `GetDiskFreeSpaceExW` restituisce **tre** numeri, e non dicono la stessa
//! cosa. Questo modulo usa `lpFreeBytesAvailableToCaller`: lo spazio che
//! **questo** utente può davvero usare. Dove esiste una quota di disco — che in
//! un dominio aziendale è normale — lo spazio libero del volume è più grande di
//! quello scrivibile, e mostrare il primo direbbe all'operatore che c'è posto
//! mentre la prossima scrittura fallisce.
//!
//! Il totale resta accanto, perché «due gigabyte liberi» significa una cosa su
//! un disco da otto e un'altra su uno da mille.
//!
//! # Che cosa questo modulo NON fa
//!
//! **Non nomina il percorso in alcun messaggio.** Un percorso reale su Windows
//! contiene il nome dell'account Windows con cui si è entrati, che è un dato
//! personale: farlo comparire in una diagnostica esportabile lo porterebbe
//! fuori dalla postazione. Il modulo restituisce **numeri**; chi li mostra non
//! riceve mai una stringa che possa contenerne uno.
//!
//! **Non decide se lo spazio basti.** Quella è una soglia, e una soglia è una
//! decisione di prodotto: vive nel servizio che compone la diagnostica, dove è
//! visibile e discutibile, non qui.
//!
//! # Le invarianti dell'FFI
//!
//! `GetDiskFreeSpaceExW` riceve un percorso in UTF-16 terminato da zero e tre
//! puntatori a `u64` che scrive:
//!
//! 1. il vettore del percorso è posseduto dalla funzione e resta vivo per
//!    l'intera chiamata;
//! 2. uno zero **dentro** il percorso lo troncherebbe in silenzio, e si
//!    misurerebbe un volume diverso da quello chiesto: viene rifiutato prima;
//! 3. i tre `u64` sono variabili locali inizializzate a zero, e si leggono
//!    **solo** se la funzione ha restituito un valore diverso da zero. Su
//!    fallimento Windows non garantisce di averle scritte.

use std::path::Path;

/// Quanto spazio c'è, o perché non si è potuto sapere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskSpace {
    /// Misurato.
    Measured {
        /// Byte che **questo utente** può ancora scrivere, quote comprese.
        available_to_user: u64,
        /// Capienza totale del volume.
        total: u64,
    },
    /// Non misurato.
    ///
    /// # Perché non è «zero»
    ///
    /// Perché non sapere quanto spazio ci sia e sapere che non ce n'è sono due
    /// fatti diversi, e il secondo è un allarme. Confonderli farebbe comparire
    /// un disco pieno su ogni postazione in cui la misura non riesce.
    Unmeasured {
        /// Il codice restituito da Windows, per chi indaga.
        code: u32,
    },
}

impl DiskSpace {
    /// Byte disponibili, quando la misura è riuscita.
    #[must_use]
    pub const fn available(self) -> Option<u64> {
        match self {
            Self::Measured {
                available_to_user, ..
            } => Some(available_to_user),
            Self::Unmeasured { .. } => None,
        }
    }

    /// Se la misura è stata presa.
    #[must_use]
    pub const fn is_measured(self) -> bool {
        matches!(self, Self::Measured { .. })
    }
}

/// Lo spazio sul volume che contiene la cartella indicata.
///
/// Fuori da Windows non si misura, e lo dichiara: questo prodotto è per
/// Windows, e una misura inventata altrove sarebbe peggio dell'assenza.
#[must_use]
pub fn for_directory(path: &Path) -> DiskSpace {
    #[cfg(windows)]
    {
        windows_impl::measure(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        DiskSpace::Unmeasured { code: 0 }
    }
}

#[cfg(windows)]
mod windows_impl {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    use super::DiskSpace;

    /// Codice usato quando il rifiuto è nostro, non di Windows.
    ///
    /// `ERROR_INVALID_NAME`: il percorso non è utilizzabile come nome.
    const ERROR_INVALID_NAME: u32 = 123;

    /// Chiede a Windows quanto spazio resta.
    pub fn measure(path: &Path) -> DiskSpace {
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            // Uno zero dentro il percorso lo troncherebbe in silenzio: si
            // misurerebbe un volume diverso da quello chiesto, e il numero
            // sembrerebbe buono.
            return DiskSpace::Unmeasured {
                code: ERROR_INVALID_NAME,
            };
        }
        wide.push(0);

        let mut disponibili: u64 = 0;
        let mut totali: u64 = 0;
        let mut liberi: u64 = 0;

        // SAFETY: `wide` è posseduto da questa funzione, terminato da zero e
        // privo di zeri interni (verificato sopra), e resta vivo per l'intera
        // chiamata. I tre puntatori sono a variabili locali di questa funzione,
        // vive anch'esse fino al ritorno, e i valori si leggono solo se la
        // funzione ha restituito un valore diverso da zero.
        let esito = unsafe {
            GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &raw mut disponibili,
                &raw mut totali,
                &raw mut liberi,
            )
        };

        if esito == 0 {
            // SAFETY: `GetLastError` non ha parametri e legge una variabile di
            // thread scritta dalla chiamata precedente. Va letta subito: ogni
            // altra chiamata a Windows la sovrascriverebbe.
            let code = unsafe { GetLastError() };
            return DiskSpace::Unmeasured { code };
        }

        DiskSpace::Measured {
            available_to_user: disponibili,
            total: totali,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DiskSpace, for_directory};

    /// Non misurato non è zero, e non deve poterlo diventare per distrazione.
    #[test]
    fn an_unmeasured_volume_reports_no_number_at_all() {
        let non_misurato = DiskSpace::Unmeasured { code: 5 };

        assert_eq!(non_misurato.available(), None);
        assert!(!non_misurato.is_measured());
        // E non è uguale a un volume misurato che risulti pieno: sono due
        // fatti diversi, e solo il secondo è un allarme.
        assert_ne!(
            non_misurato,
            DiskSpace::Measured {
                available_to_user: 0,
                total: 1_000,
            }
        );
    }

    /// Un percorso inesistente non produce un numero.
    #[test]
    fn a_path_that_does_not_exist_is_not_measured() {
        let esito = for_directory(std::path::Path::new(
            "Z:\\nexum97-cartella-che-non-esiste\\mai",
        ));

        assert!(
            !esito.is_measured(),
            "un volume che non c'è non deve produrre una misura"
        );
    }

    /// Su Windows la cartella temporanea si misura davvero.
    #[cfg(windows)]
    #[test]
    fn the_temporary_directory_is_measurable() {
        let esito = for_directory(&std::env::temp_dir());

        let DiskSpace::Measured { total, .. } = esito else {
            panic!("la cartella temporanea deve essere misurabile: {esito:?}");
        };
        assert!(
            total > 0,
            "un volume reale ha una capienza maggiore di zero"
        );
    }
}

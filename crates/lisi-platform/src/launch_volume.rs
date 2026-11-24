// QUATTORDICESIMO modulo del crate autorizzato a contenere `unsafe`, dopo
// quelli elencati in `lib.rs`. Vedere ADR-0009 per la regola e ADR-0176 per la
// decisione che ha portato qui.
#![cfg_attr(windows, allow(unsafe_code))]

//! Da che genere di volume è partito il programma (PORTABLE-01, ADR-0176).
//!
//! # Perché serve
//!
//! Partito da una chiavetta, il programma lo deve dire in ogni schermata e
//! nei documenti, e non deve iscriversi all'avvio automatico: la voce di
//! Windows punterebbe a un percorso che domani non c'è. Per dirlo deve
//! saperlo, e lo sa dal **volume del proprio eseguibile**, non dal nome della
//! cartella e non da una domanda all'operatore.
//!
//! # Come
//!
//! `GetVolumePathNameW` dà la radice del volume che contiene il percorso, e
//! `GetDriveTypeW` ne dà il genere. Nessuna delle due chiede privilegi, e
//! nessuna legge o scrive un file.
//!
//! # Che cosa questo modulo NON dice
//!
//! **Non dice se il volume è cifrato.** Senza privilegi non c'è un modo
//! documentato di saperlo (ADR-0176, contesto): per questo l'archivio non va
//! mai sulla chiavetta, e questo modulo non serve a deciderlo.
//!
//! **Non nomina il percorso.** Restituisce un genere, mai una stringa: un
//! percorso reale contiene il nome dell'account Windows.
//!
//! # Le invarianti dell'FFI
//!
//! 1. il percorso in UTF-16 è posseduto dalla funzione, terminato da zero e
//!    privo di zeri interni (verificato prima: uno zero lo troncherebbe, e si
//!    guarderebbe un altro volume);
//! 2. il buffer della radice è locale, di `MAX_PATH + 1` unità, e se ne passa
//!    la lunghezza vera; si legge solo se la funzione ha restituito un valore
//!    diverso da zero, e fino al primo zero, che Windows garantisce;
//! 3. a `GetDriveTypeW` arriva la radice letta, terminata da zero.

use std::path::Path;

/// Il genere del volume da cui il programma è partito.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchVolume {
    /// Un supporto rimovibile: una chiavetta, una scheda.
    Removable,
    /// Un disco della postazione.
    Fixed,
    /// Una cartella di rete.
    Network,
    /// Un genere diverso (un disco ottico, un disco in memoria).
    Other,
    /// Non si è potuto sapere.
    ///
    /// # Perché non è «disco della postazione»
    ///
    /// Non sapere da dove si è partiti e sapere di essere partiti dal disco
    /// sono due fatti diversi: confonderli farebbe tacere la fascia proprio
    /// quando non si sa.
    Undetermined,
}

impl LaunchVolume {
    /// Il genere di `GetDriveTypeW`, tradotto.
    #[must_use]
    pub const fn from_drive_type(drive_type: u32) -> Self {
        match drive_type {
            2 => Self::Removable,
            3 => Self::Fixed,
            4 => Self::Network,
            5 | 6 => Self::Other,
            // 0: sconosciuto; 1: la radice non esiste.
            _ => Self::Undetermined,
        }
    }

    /// Se il programma non è partito da un disco della postazione: una
    /// chiavetta, la rete, un genere diverso, o non si sa.
    #[must_use]
    pub const fn is_away_from_station(self) -> bool {
        !matches!(self, Self::Fixed)
    }

    /// La riga che i documenti portano quando il programma non è partito da
    /// un disco della postazione (ADR-0176, decisione 5). Da un disco della
    /// postazione, nessuna: è il caso ordinario.
    #[must_use]
    pub const fn document_line(self) -> Option<&'static str> {
        match self {
            Self::Fixed => None,
            Self::Removable => Some("Programma avviato da un supporto rimovibile"),
            Self::Network => Some("Programma avviato da una cartella di rete"),
            Self::Other => {
                Some("Programma avviato da un supporto che non è un disco della postazione")
            }
            Self::Undetermined => Some("Programma avviato da un supporto non riconosciuto"),
        }
    }

    /// La fascia in cima a ogni schermata (ADR-0176, decisioni 5 e 7).
    #[must_use]
    pub fn station_notice(self) -> Option<String> {
        self.document_line().map(|riga| {
            format!(
                "{riga}. I dati restano su questa postazione, non sul supporto. \
                 Gli avvisi di Windows potrebbero non comparire: quelli nella finestra restano."
            )
        })
    }

    /// Perché l'avvio automatico non si cambia da qui (ADR-0176, decisione 6).
    ///
    /// Vale per attivarlo e per disattivarlo. Attivato, punterebbe a un
    /// percorso che domani potrebbe non esserci; disattivato, toglierebbe la
    /// voce scritta da un programma installato, che non si tocca.
    #[must_use]
    pub const fn autostart_refusal(self) -> Option<&'static str> {
        if self.is_away_from_station() {
            Some(
                "L'avvio automatico non si cambia da qui: il programma non è partito da un \
                 disco della postazione. La voce punterebbe a un percorso che domani potrebbe \
                 non esserci. Una voce già scritta resta com'è.",
            )
        } else {
            None
        }
    }
}

/// Il genere del volume che contiene il percorso indicato.
///
/// Fuori da Windows non si sa, e lo dichiara.
#[must_use]
pub fn for_path(path: &Path) -> LaunchVolume {
    #[cfg(windows)]
    {
        windows_impl::classify(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        LaunchVolume::Undetermined
    }
}

/// Il genere del volume dell'eseguibile in esecuzione.
#[must_use]
pub fn of_current_executable() -> LaunchVolume {
    std::env::current_exe().map_or(LaunchVolume::Undetermined, |programma| for_path(&programma))
}

#[cfg(windows)]
mod windows_impl {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetVolumePathNameW};

    use super::LaunchVolume;

    /// Lunghezza della radice, in unità UTF-16, zero compreso.
    const ROOT_CAPACITY: usize = 261;

    /// Chiede a Windows la radice del volume e il suo genere.
    pub fn classify(path: &Path) -> LaunchVolume {
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.is_empty() || wide.contains(&0) {
            return LaunchVolume::Undetermined;
        }
        wide.push(0);

        let mut radice = [0u16; ROOT_CAPACITY];
        let Ok(capienza) = u32::try_from(radice.len()) else {
            return LaunchVolume::Undetermined;
        };

        // SAFETY: `wide` è posseduto da questa funzione, terminato da zero e
        // privo di zeri interni (verificato sopra), vivo per l'intera
        // chiamata. `radice` è un buffer locale di `capienza` unità, e si
        // legge solo se la funzione ha restituito un valore diverso da zero.
        let esito = unsafe { GetVolumePathNameW(wide.as_ptr(), radice.as_mut_ptr(), capienza) };
        if esito == 0 {
            return LaunchVolume::Undetermined;
        }
        // Windows termina la radice con uno zero dentro il buffer; se non lo
        // trovassimo, non ci si fida del buffer.
        if !radice.contains(&0) {
            return LaunchVolume::Undetermined;
        }

        // SAFETY: `radice` è terminata da zero (verificato sopra), locale e
        // viva per l'intera chiamata.
        let genere = unsafe { GetDriveTypeW(radice.as_ptr()) };
        LaunchVolume::from_drive_type(genere)
    }
}

#[cfg(test)]
mod tests {
    use super::LaunchVolume;

    /// **I generi di Windows si traducono, e ciò che non si conosce resta
    /// «non determinato».**
    #[test]
    fn i_generi_di_windows_si_traducono() {
        assert_eq!(LaunchVolume::from_drive_type(2), LaunchVolume::Removable);
        assert_eq!(LaunchVolume::from_drive_type(3), LaunchVolume::Fixed);
        assert_eq!(LaunchVolume::from_drive_type(4), LaunchVolume::Network);
        assert_eq!(LaunchVolume::from_drive_type(5), LaunchVolume::Other);
        assert_eq!(LaunchVolume::from_drive_type(6), LaunchVolume::Other);
        for ignoto in [0, 1, 7, u32::MAX] {
            assert_eq!(
                LaunchVolume::from_drive_type(ignoto),
                LaunchVolume::Undetermined
            );
        }
    }

    /// **Soltanto un disco della postazione è «a casa»**: non sapere è come
    /// essere fuori, perché la fascia deve parlare quando non si sa.
    #[test]
    fn soltanto_un_disco_della_postazione_e_a_casa() {
        assert!(!LaunchVolume::Fixed.is_away_from_station());
        for fuori in [
            LaunchVolume::Removable,
            LaunchVolume::Network,
            LaunchVolume::Other,
            LaunchVolume::Undetermined,
        ] {
            assert!(fuori.is_away_from_station(), "{fuori:?}");
        }
    }

    /// **Fuori da un disco della postazione, la fascia e i documenti lo
    /// dicono; da un disco della postazione tacciono.** Non sapere parla.
    #[test]
    fn fuori_dalla_postazione_la_fascia_e_i_documenti_lo_dicono() {
        assert_eq!(LaunchVolume::Fixed.document_line(), None);
        assert_eq!(LaunchVolume::Fixed.station_notice(), None);
        assert_eq!(
            LaunchVolume::Removable.document_line(),
            Some("Programma avviato da un supporto rimovibile")
        );
        for fuori in [
            LaunchVolume::Removable,
            LaunchVolume::Network,
            LaunchVolume::Other,
            LaunchVolume::Undetermined,
        ] {
            let Some(riga) = fuori.document_line() else {
                panic!("{fuori:?} deve avere la sua riga");
            };
            assert!(riga.starts_with("Programma avviato da "), "{riga}");
            let Some(fascia) = fuori.station_notice() else {
                panic!("{fuori:?} deve avere la sua fascia");
            };
            assert!(fascia.starts_with(riga), "{fascia}");
            assert!(fascia.contains("restano su questa postazione"), "{fascia}");
            assert!(fascia.contains("avvisi di Windows"), "{fascia}");
        }
    }

    /// **L'avvio automatico si rifiuta soltanto fuori da un disco della
    /// postazione**, e il rifiuto dice la ragione e che la voce esistente
    /// resta.
    #[test]
    fn l_avvio_automatico_si_rifiuta_fuori_dalla_postazione() {
        assert_eq!(LaunchVolume::Fixed.autostart_refusal(), None);
        for fuori in [
            LaunchVolume::Removable,
            LaunchVolume::Network,
            LaunchVolume::Other,
            LaunchVolume::Undetermined,
        ] {
            let Some(rifiuto) = fuori.autostart_refusal() else {
                panic!("{fuori:?} deve rifiutare");
            };
            assert!(rifiuto.contains("domani potrebbe non"), "{rifiuto}");
            assert!(rifiuto.contains("resta com'è"), "{rifiuto}");
        }
    }

    /// **Le prove girano da un disco della postazione**: l'eseguibile delle
    /// prove sta sotto `target`, su un disco fisso.
    #[cfg(windows)]
    #[test]
    fn l_eseguibile_delle_prove_sta_su_un_disco_della_postazione() {
        assert_eq!(super::of_current_executable(), LaunchVolume::Fixed);
    }

    /// **Un percorso con uno zero dentro non si guarda**: si guarderebbe un
    /// altro volume.
    #[cfg(windows)]
    #[test]
    fn un_percorso_con_uno_zero_dentro_non_si_guarda() {
        let percorso = std::path::PathBuf::from("C:\\cartella\0altro");
        assert_eq!(super::for_path(&percorso), LaunchVolume::Undetermined);
        assert_eq!(
            super::for_path(std::path::Path::new("")),
            LaunchVolume::Undetermined
        );
    }
}

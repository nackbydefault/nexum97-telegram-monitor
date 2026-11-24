// UNDICESIMO modulo del crate autorizzato a contenere `unsafe`, dopo
// `browser`, `window_chrome`, `wakefulness`, `autostart`, `title_bar`,
// `signature`, `disk_space`, `app_identity`, `tray` e `https`. Vedere ADR-0009
// per la regola e ADR-0136 per la decisione che ha portato qui.
#![cfg_attr(windows, allow(unsafe_code))]

//! Lo scarto fra l'ora UTC e l'ora che segna l'orologio di Windows, in un
//! istante dato.
//!
//! # Perché serve, e a chi
//!
//! Il prodotto conserva ogni istante in UTC (ADR-0006) e lo mostrava in UTC.
//! Un operatore italiano in ottobre leggeva «07:07 UTC» mentre l'orologio della
//! barra delle applicazioni segnava le 09:07: tre simulazioni su tre ci sono
//! inciampate (OPERATOR-SIM-01, 02 e 03, SIM3-05). Lo schermo ora mostra l'ora
//! locale e, accanto, quella UTC (ADR-0136). Questo modulo dice soltanto
//! **quanti minuti** separano le due in un istante; la frase la compone
//! `lisi-core`.
//!
//! # Perché l'istante, e non «il fuso di adesso»
//!
//! Lo scarto cambia due volte l'anno con l'ora legale, e un contenuto
//! acquisito a luglio si rilegge a dicembre: va convertito con le regole del
//! **suo** giorno, non di oggi. `SystemTimeToTzSpecificLocalTimeEx` con le
//! informazioni **dinamiche** del fuso fa esattamente questo, anche per gli
//! anni in cui le regole erano diverse; la versione senza `Ex` userebbe le
//! regole correnti per ogni anno.
//!
//! # Che cosa questo modulo NON fa
//!
//! **Non tocca alcun istante conservato.** Restituisce un numero di minuti;
//! l'istante UTC resta quello che è, nell'archivio, nell'audit e nei documenti
//! probatori.
//!
//! **Non indovina.** Se Windows non risponde, restituisce `None` e lo schermo
//! mostra il solo UTC, dichiarato, come prima.
//!
//! # Le invarianti dell'FFI
//!
//! 1. Tutte le strutture passate a Windows sono variabili locali inizializzate
//!    a zero, vive per tutta la durata della chiamata; nessun puntatore di
//!    Windows sopravvive alla funzione.
//! 2. Le strutture scritte da Windows si leggono **solo** se la funzione ha
//!    restituito successo: su fallimento Windows non garantisce di averle
//!    scritte.
//! 3. Nessuna memoria di Windows viene allocata o liberata.
//! 4. L'istante in ingresso è controllato prima della conversione: un valore
//!    negativo o che traboccherebbe nei cento nanosecondi di `FILETIME` non
//!    raggiunge il sistema.

/// Minuti da aggiungere all'UTC per ottenere l'ora locale della postazione
/// **in quell'istante**, ora legale compresa.
///
/// `millis` è l'istante in millisecondi dall'epoca Unix, in UTC.
///
/// Restituisce `None` se l'istante non è rappresentabile, se Windows non
/// risponde, o fuori da Windows.
#[must_use]
pub fn utc_offset_minutes(millis: i64) -> Option<i32> {
    let ticks = filetime_ticks(millis)?;
    offset_from_ticks(ticks)
}

/// Cento nanosecondi fra il 1601-01-01 e il 1970-01-01, l'origine di
/// `FILETIME` e quella Unix.
const UNIX_EPOCH_IN_TICKS: i64 = 116_444_736_000_000_000;

/// L'istante Unix in millisecondi, nei cento nanosecondi di `FILETIME`.
///
/// Invariante 4: niente valori negativi, niente traboccamenti.
fn filetime_ticks(millis: i64) -> Option<u64> {
    if millis < 0 {
        return None;
    }
    let ticks = millis
        .checked_mul(10_000)?
        .checked_add(UNIX_EPOCH_IN_TICKS)?;
    u64::try_from(ticks).ok()
}

/// La differenza fra due istanti `FILETIME`, in minuti interi.
///
/// I fusi esistenti sono multipli di quindici minuti; si arrotonda al minuto
/// per non far comparire uno scarto di 59 minuti e 59 secondi per effetto del
/// troncamento al millesimo di `SYSTEMTIME`. Uno scarto oltre le diciotto ore
/// non esiste su questo pianeta, e si rifiuta invece di mostrarlo.
fn minutes_between(local_ticks: u64, utc_ticks: u64) -> Option<i32> {
    let locale = i128::from(local_ticks);
    let universale = i128::from(utc_ticks);
    let minuto = 600_000_000_i128;
    let differenza = locale - universale;
    let minuti = (differenza + minuto / 2).div_euclid(minuto);
    let minuti = i32::try_from(minuti).ok()?;
    if minuti.abs() > 18 * 60 {
        return None;
    }
    Some(minuti)
}

#[cfg(windows)]
fn offset_from_ticks(ticks: u64) -> Option<i32> {
    use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows_sys::Win32::System::Time::{
        DYNAMIC_TIME_ZONE_INFORMATION, FileTimeToSystemTime, GetDynamicTimeZoneInformation,
        SystemTimeToFileTime, SystemTimeToTzSpecificLocalTimeEx, TIME_ZONE_ID_INVALID,
    };

    const fn zero_systemtime() -> SYSTEMTIME {
        SYSTEMTIME {
            wYear: 0,
            wMonth: 0,
            wDayOfWeek: 0,
            wDay: 0,
            wHour: 0,
            wMinute: 0,
            wSecond: 0,
            wMilliseconds: 0,
        }
    }

    fn ticks_of(time: &SYSTEMTIME) -> Option<u64> {
        let mut file_time = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        // Invarianti 1 e 2: entrambe le strutture sono locali; il risultato si
        // legge solo se la conversione e' riuscita.
        let ok = unsafe { SystemTimeToFileTime(time, &mut file_time) };
        if ok == 0 {
            return None;
        }
        Some((u64::from(file_time.dwHighDateTime) << 32) | u64::from(file_time.dwLowDateTime))
    }

    // Invariante 4 gia' garantita da `filetime_ticks`: qui `ticks` e' un valore
    // valido e non negativo.
    let file_time = FILETIME {
        dwLowDateTime: u32::try_from(ticks & 0xFFFF_FFFF).ok()?,
        dwHighDateTime: u32::try_from(ticks >> 32).ok()?,
    };

    let mut universale = zero_systemtime();
    // Invarianti 1 e 2.
    let ok = unsafe { FileTimeToSystemTime(&file_time, &mut universale) };
    if ok == 0 {
        return None;
    }

    let mut fuso = DYNAMIC_TIME_ZONE_INFORMATION::default();
    // Invarianti 1 e 2: la struttura e' locale; `TIME_ZONE_ID_INVALID` e' il
    // solo valore di fallimento documentato.
    let esito = unsafe { GetDynamicTimeZoneInformation(&mut fuso) };
    if esito == TIME_ZONE_ID_INVALID {
        return None;
    }

    let mut locale = zero_systemtime();
    // Invarianti 1 e 2: `fuso` e `universale` sono stati scritti da Windows con
    // successo; `locale` e' locale e si legge solo dopo il successo.
    let ok = unsafe { SystemTimeToTzSpecificLocalTimeEx(&fuso, &universale, &mut locale) };
    if ok == 0 {
        return None;
    }

    // Entrambi gli estremi passano dalla stessa conversione, cosi' che il
    // troncamento al millesimo di `SYSTEMTIME` non entri nella differenza.
    minutes_between(ticks_of(&locale)?, ticks_of(&universale)?)
}

#[cfg(not(windows))]
const fn offset_from_ticks(_ticks: u64) -> Option<i32> {
    None
}

#[cfg(test)]
mod tests {
    use super::{filetime_ticks, minutes_between, utc_offset_minutes};

    #[test]
    fn un_istante_non_rappresentabile_non_raggiunge_il_sistema() {
        assert_eq!(filetime_ticks(-1), None);
        assert_eq!(filetime_ticks(i64::MAX), None);
        assert_eq!(utc_offset_minutes(-1), None);
        assert_eq!(filetime_ticks(0), Some(116_444_736_000_000_000));
    }

    #[test]
    fn lo_scarto_si_arrotonda_al_minuto_e_ha_un_tetto() {
        let ora = 600_000_000_u64 * 60;
        assert_eq!(minutes_between(ora * 2, 0), Some(120));
        // Un millesimo in meno non fa comparire «un'ora e 59 minuti».
        assert_eq!(minutes_between(ora * 2 - 10_000, 0), Some(120));
        assert_eq!(minutes_between(0, ora), Some(-60));
        assert_eq!(minutes_between(ora * 19, 0), None);
    }

    /// Su Windows lo scarto si legge e sta fra i fusi che esistono; un'ora
    /// d'estate e una d'inverno differiscono al più di un'ora.
    #[cfg(windows)]
    #[test]
    fn su_windows_lo_scarto_si_legge() {
        // 2026-07-15 12:00 UTC e 2026-01-15 12:00 UTC.
        let estate = utc_offset_minutes(1_784_116_800_000);
        let inverno = utc_offset_minutes(1_768_478_400_000);
        let (Some(estate), Some(inverno)) = (estate, inverno) else {
            panic!("Windows deve rispondere");
        };
        assert!(estate.abs() <= 14 * 60);
        assert!(inverno.abs() <= 14 * 60);
        assert!((estate - inverno).abs() <= 60);
    }
}

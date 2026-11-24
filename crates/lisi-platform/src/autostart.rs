// QUARTO modulo del crate autorizzato a contenere `unsafe`, dopo `browser`,
// `window_chrome` e `wakefulness`. La deroga e' esplicita, circoscritta a un
// solo file e visibile in diff (ADR-0003, ADR-0022). Vale solo su Windows.
#![cfg_attr(windows, allow(unsafe_code))]

//! Avvio dell'applicazione all'accesso a Windows.
//!
//! # Il problema
//!
//! Un monitoraggio lungo non sopravvive a un riavvio, e nemmeno a un logout:
//! il processo muore e nessuno lo riavvia. La sessione resta in archivio nello
//! stato in cui era, ma **nessuno la sta piu' osservando** — e questo non lo
//! dice nessuno. `wakefulness` toglie la causa piu' frequente di interruzione
//! (la sospensione); questa toglie la seconda (lo spegnimento).
//!
//! # Dove si registra, e perche' proprio li'
//!
//! In `HKEY_CURRENT_USER`, non in `HKEY_LOCAL_MACHINE`. Tre ragioni, tutte
//! della stessa famiglia:
//!
//! - non richiede elevazione, quindi la scelta non ha bisogno di un
//!   amministratore di sistema per essere fatta o disfatta;
//! - su una **postazione condivisa** ogni profilo Windows decide per se': non
//!   si impone l'avvio automatico a colleghi che non l'hanno chiesto;
//! - l'ambito della voce coincide con l'ambito dei dati, che DPAPI protegge
//!   **per utente** (ADR-0009). Una voce di macchina avvierebbe l'applicazione
//!   sotto profili che non possono decifrare nulla.
//!
//! # Il registro e' l'unica fonte
//!
//! Lo stato non viene duplicato in archivio. Due copie della stessa verita'
//! divergono — qualcuno rimuove la voce dal registro con `msconfig`, e
//! l'applicazione continuerebbe a dire «avvio automatico attivo» — e fra le
//! due chi comanda davvero e' il registro. Si legge da li', sempre.
//!
//! # Il difetto silenzioso da cui questo modulo si guarda
//!
//! Una voce **presente ma che punta altrove**. L'eseguibile viene spostato,
//! reinstallato in un'altra cartella, o la voce l'ha scritta una versione
//! precedente: il registro dice «attivo», il sistema avvia un percorso che non
//! esiste piu', e non parte nulla. Chi guarda l'impostazione la vede accesa e
//! crede di essere coperto. Per questo lo stato non e' un booleano ma
//! [`AutostartState`], che distingue *attivo per questo eseguibile* da *attivo
//! per un altro*.
//!
//! # Invarianti di sicurezza
//!
//! 1. Il **nome della chiave e del valore sono costanti** del programma: nessun
//!    dato esterno decide dove si scrive.
//! 2. Il solo dato variabile e' il **percorso dell'eseguibile corrente**,
//!    ottenuto da `std::env::current_exe()` e non da un input.
//! 3. Ogni stringa passata a Windows e' convertita in UTF-16 **terminata da
//!    zero**, e la lunghezza dichiarata in byte include quel terminatore, come
//!    il contratto di `RegSetValueExW` richiede.
//! 4. Ogni chiave aperta viene chiusa su **ogni** percorso di uscita, compreso
//!    quello d'errore.
//! 5. La lettura dichiara la capienza del proprio buffer e **non si fida** della
//!    lunghezza restituita: viene ricontrollata prima di ricavarne una stringa.
//! 6. Il valore letto e' trattato come **non fidato** — puo' averlo scritto
//!    chiunque abbia accesso al profilo — e non viene mai eseguito, mostrato o
//!    riecheggiato in un messaggio: se ne ricava soltanto un confronto.
//! 7. Cancellare una voce che non esiste **non e' un errore**: disattivare deve
//!    essere idempotente, altrimenti chi la disattiva due volte vede un guasto.

use crate::error::{PlatformError, PlatformResult};

/// Chiave in cui Windows cerca i programmi da avviare all'accesso dell'utente.
#[cfg(windows)]
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// Nome della voce. Stabile: cambiarlo lascerebbe orfana quella precedente.
#[cfg(windows)]
const VALUE_NAME: &str = "NEXUM97 Telegram Monitor";

/// Capienza del buffer di lettura, in caratteri UTF-16.
///
/// Il percorso di un eseguibile su Windows sta ampiamente sotto questo limite;
/// un valore piu' lungo non e' nostro e viene rifiutato invece che troncato,
/// perche' un percorso troncato produrrebbe un confronto falso.
#[cfg(windows)]
const READ_CAPACITY: usize = 1024;

/// Che cosa il registro dice dell'avvio automatico.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutostartState {
    /// Nessuna voce: l'applicazione non parte da sola.
    Disabled,
    /// Attivo, e la voce punta **a questo** eseguibile.
    Enabled,
    /// Attivo, ma la voce punta a un altro percorso.
    ///
    /// E' il caso che conta: l'applicazione e' stata spostata o reinstallata
    /// altrove, il sistema avvia qualcosa che non c'e' piu', e chi guarda
    /// l'impostazione la vede accesa. Va detto all'operatore e va corretto
    /// riscrivendo la voce, non lasciato passare per «attivo».
    EnabledElsewhere,
}

impl AutostartState {
    /// Se una voce esiste, comunque punti.
    #[must_use]
    pub const fn is_registered(self) -> bool {
        matches!(self, Self::Enabled | Self::EnabledElsewhere)
    }

    /// Se l'avvio automatico funzionera' davvero.
    ///
    /// Distinta da [`Self::is_registered`] di proposito: una voce che punta
    /// altrove e' registrata e **non** funzionante, e confondere le due cose e'
    /// esattamente il difetto silenzioso che questo tipo esiste per evitare.
    #[must_use]
    pub const fn is_effective(self) -> bool {
        matches!(self, Self::Enabled)
    }

    /// Frase per l'operatore.
    #[must_use]
    pub const fn operator_message(self) -> &'static str {
        match self {
            Self::Disabled => {
                "L'applicazione non si avvia da sola: dopo un riavvio il monitoraggio \
                 resta fermo finché qualcuno non la apre."
            }
            Self::Enabled => {
                "L'applicazione si avvia all'accesso a Windows e riprende il monitoraggio \
                 che non era stato arrestato."
            }
            Self::EnabledElsewhere => {
                "L'avvio automatico è registrato ma punta a un'altra copia del programma: \
                 non partirebbe questa. Disattivarlo e riattivarlo lo corregge."
            }
        }
    }
}

/// Legge dal registro lo stato dell'avvio automatico.
///
/// # Errori
///
/// Restituisce [`PlatformError::AutostartUnavailable`] se il registro non e'
/// leggibile o se il percorso dell'eseguibile corrente non e' determinabile.
#[cfg(windows)]
pub fn state() -> PlatformResult<AutostartState> {
    let Some(stored) = read_value(RUN_KEY, VALUE_NAME)? else {
        return Ok(AutostartState::Disabled);
    };

    let expected = command_line()?;

    // Il confronto ignora maiuscole e minuscole perche' i percorsi di Windows
    // le ignorano: `C:\Programmi\...` e `c:\programmi\...` sono lo stesso file,
    // e trattarli come diversi segnalerebbe uno spostamento inesistente.
    if stored.eq_ignore_ascii_case(&expected) {
        Ok(AutostartState::Enabled)
    } else {
        Ok(AutostartState::EnabledElsewhere)
    }
}

/// Registra l'applicazione fra i programmi avviati all'accesso.
///
/// Riscrive la voce anche quando esiste gia': e' cosi' che si corregge una
/// [`AutostartState::EnabledElsewhere`].
///
/// # Errori
///
/// Restituisce [`PlatformError::AutostartUnavailable`] se il registro non e'
/// scrivibile o se il percorso dell'eseguibile non e' determinabile.
#[cfg(windows)]
pub fn enable() -> PlatformResult<()> {
    let value = command_line()?;
    write_value(RUN_KEY, VALUE_NAME, &value)
}

/// Toglie la voce, se c'e'.
///
/// Idempotente: disattivare due volte non e' un errore.
///
/// # Errori
///
/// Restituisce [`PlatformError::AutostartUnavailable`] se il registro non e'
/// scrivibile.
#[cfg(windows)]
pub fn disable() -> PlatformResult<()> {
    delete_value(RUN_KEY, VALUE_NAME)
}

/// Il valore da scrivere: il percorso dell'eseguibile, fra virgolette.
///
/// Le virgolette non sono un abbellimento. Senza, un percorso con spazi —
/// `C:\Program Files\...` e' il caso normale — verrebbe letto dal sistema come
/// un comando piu' i suoi argomenti, e avvierebbe il programma sbagliato o
/// nessuno.
#[cfg(windows)]
fn command_line() -> PlatformResult<String> {
    let executable =
        std::env::current_exe().map_err(|_| PlatformError::AutostartUnavailable { code: 0 })?;
    let path = executable
        .to_str()
        .ok_or(PlatformError::AutostartUnavailable { code: 0 })?;

    // Un percorso che contenesse gia' una virgoletta romperebbe la citazione.
    // Non e' un caso che possa capitare a un eseguibile — Windows non ammette
    // `"` nei nomi di file — ma il controllo costa una riga e toglie la
    // domanda invece di lasciarla al lettore.
    if path.contains('"') {
        return Err(PlatformError::AutostartUnavailable { code: 0 });
    }

    Ok(format!("\"{path}\""))
}

/// Converte in UTF-16 terminato da zero, come le API `W` richiedono.
#[cfg(windows)]
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Scrive un valore testuale sotto `HKEY_CURRENT_USER`.
///
/// La chiave e il nome sono parametri e non costanti **perche' i test possano
/// esercitare questo stesso codice su una chiave propria**, invece di lasciarlo
/// non provato o di scrivere davvero nell'avvio automatico di chi compila. Il
/// percorso reale resta l'unico chiamante non di prova, e passa le costanti.
#[cfg(windows)]
fn write_value(subkey: &str, value_name: &str, value: &str) -> PlatformResult<()> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey,
        RegCreateKeyExW, RegSetValueExW,
    };

    let subkey = wide(subkey);
    let name = wide(value_name);
    let data = wide(value);

    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: le invarianti sono in testa al modulo. `subkey` e' UTF-16
    // terminato da zero e vive per tutta la chiamata; `key` e' un puntatore a
    // una variabile locale valida; gli altri puntatori sono nulli, che il
    // contratto ammette per la classe, il descrittore di sicurezza e lo stato
    // di creazione. La chiave viene chiusa su ogni percorso di uscita.
    let opened = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            std::ptr::null_mut(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            std::ptr::null(),
            &raw mut key,
            std::ptr::null_mut(),
        )
    };
    if opened != ERROR_SUCCESS {
        return Err(PlatformError::AutostartUnavailable {
            code: opened as i64,
        });
    }

    // La lunghezza si dichiara **in byte** e comprende il terminatore: e' il
    // contratto di RegSetValueExW per REG_SZ. Dichiararla senza il terminatore
    // produrrebbe un valore che si legge fino a un carattere qualsiasi.
    let bytes = data.len().saturating_mul(std::mem::size_of::<u16>());
    let Ok(bytes) = u32::try_from(bytes) else {
        // SAFETY: `key` e' stata aperta con successo poco sopra e non e' ancora
        // stata chiusa.
        unsafe { RegCloseKey(key) };
        return Err(PlatformError::AutostartUnavailable { code: 0 });
    };

    // SAFETY: `key` e' valida; `name` e `data` sono UTF-16 terminati da zero e
    // vivono per tutta la chiamata; `bytes` e' la dimensione in byte di `data`,
    // terminatore compreso, come REG_SZ richiede.
    let written = unsafe {
        RegSetValueExW(
            key,
            name.as_ptr(),
            0,
            REG_SZ,
            data.as_ptr().cast::<u8>(),
            bytes,
        )
    };

    // SAFETY: `key` e' valida e viene chiusa una volta sola, prima di ogni
    // ritorno.
    unsafe { RegCloseKey(key) };

    if written != ERROR_SUCCESS {
        return Err(PlatformError::AutostartUnavailable {
            code: written as i64,
        });
    }

    Ok(())
}

/// Legge un valore testuale da `HKEY_CURRENT_USER`, se c'e'.
///
/// Parametrizzata per la stessa ragione di [`write_value`].
#[cfg(windows)]
fn read_value(subkey: &str, value_name: &str) -> PlatformResult<Option<String>> {
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
    };

    let subkey = wide(subkey);
    let name = wide(value_name);

    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: come in `write_value`; qui si chiede il solo diritto di lettura.
    let opened = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &raw mut key,
        )
    };
    if opened == ERROR_FILE_NOT_FOUND {
        // La chiave `Run` esiste su ogni Windows, ma la sua assenza significa
        // comunque «nessun avvio automatico», non un guasto.
        return Ok(None);
    }
    if opened != ERROR_SUCCESS {
        return Err(PlatformError::AutostartUnavailable {
            code: opened as i64,
        });
    }

    let mut buffer = [0_u16; READ_CAPACITY];
    let Ok(capacity) = u32::try_from(std::mem::size_of_val(&buffer)) else {
        // SAFETY: `key` e' valida e non ancora chiusa.
        unsafe { RegCloseKey(key) };
        return Err(PlatformError::AutostartUnavailable { code: 0 });
    };
    let mut size = capacity;

    // SAFETY: `key` e' valida; `name` e' UTF-16 terminato da zero; `buffer` ha
    // `READ_CAPACITY` elementi e `size` ne dichiara la capienza **in byte**,
    // come RegQueryValueExW richiede. Windows scrive al piu' quel numero di
    // byte e aggiorna `size` con quanti ne ha scritti.
    let queried = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast::<u8>(),
            &raw mut size,
        )
    };

    // SAFETY: `key` e' valida e viene chiusa una volta sola.
    unsafe { RegCloseKey(key) };

    if queried == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if queried != ERROR_SUCCESS {
        return Err(PlatformError::AutostartUnavailable {
            code: queried as i64,
        });
    }

    Ok(decode(&buffer, size))
}

/// Ricava la stringa dal buffer, senza fidarsi della lunghezza dichiarata.
///
/// Windows restituisce una dimensione in byte che dovrebbe stare nella
/// capienza dichiarata, ma il valore lo ha scritto **chiunque** abbia accesso
/// al profilo: un valore malformato non deve poter far leggere oltre il
/// buffer. Da qui esce `None` invece di un dato dubbio, e `None` significa
/// «nessun avvio automatico affidabile», che e' la lettura prudente.
#[cfg(windows)]
fn decode(buffer: &[u16], size_in_bytes: u32) -> Option<String> {
    let bytes = usize::try_from(size_in_bytes).ok()?;
    let chars = bytes / std::mem::size_of::<u16>();
    if chars == 0 || chars > buffer.len() {
        return None;
    }

    let slice = buffer.get(..chars)?;
    // REG_SZ dovrebbe includere il terminatore, ma non e' garantito che ci sia:
    // si taglia al primo zero se c'e', altrimenti si prende tutto.
    let end = slice.iter().position(|value| *value == 0).unwrap_or(chars);
    let text = String::from_utf16(slice.get(..end)?).ok()?;
    if text.is_empty() { None } else { Some(text) }
}

/// Toglie un valore da `HKEY_CURRENT_USER`, se c'e'.
///
/// Parametrizzata per la stessa ragione di [`write_value`].
#[cfg(windows)]
fn delete_value(subkey: &str, value_name: &str) -> PlatformResult<()> {
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, RegCloseKey, RegDeleteValueW, RegOpenKeyExW,
    };

    let subkey = wide(subkey);
    let name = wide(value_name);

    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: come in `write_value`.
    let opened = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            KEY_SET_VALUE,
            &raw mut key,
        )
    };
    if opened == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    if opened != ERROR_SUCCESS {
        return Err(PlatformError::AutostartUnavailable {
            code: opened as i64,
        });
    }

    // SAFETY: `key` e' valida; `name` e' UTF-16 terminato da zero.
    let deleted = unsafe { RegDeleteValueW(key, name.as_ptr()) };

    // SAFETY: `key` e' valida e viene chiusa una volta sola.
    unsafe { RegCloseKey(key) };

    // Cancellare cio' che non c'e' e' il risultato voluto, non un guasto: chi
    // disattiva due volte non deve vedere un errore.
    if deleted != ERROR_SUCCESS && deleted != ERROR_FILE_NOT_FOUND {
        return Err(PlatformError::AutostartUnavailable {
            code: deleted as i64,
        });
    }

    Ok(())
}

/// Toglie una chiave vuota da `HKEY_CURRENT_USER`.
///
/// Esiste **per i test**, che devono poter esercitare il codice reale del
/// registro senza lasciare in giro le chiavi che si sono create: una suite che
/// sporca il profilo di chi la esegue e' una suite che si finisce per non
/// eseguire piu'.
#[cfg(all(windows, test))]
fn delete_key(subkey: &str) -> PlatformResult<()> {
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, RegDeleteKeyW};

    let subkey = wide(subkey);

    // SAFETY: `subkey` e' UTF-16 terminato da zero e vive per tutta la
    // chiamata. `RegDeleteKeyW` non apre nulla che vada chiuso, e rifiuta di
    // cancellare una chiave che abbia sottochiavi.
    let deleted = unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, subkey.as_ptr()) };

    if deleted != ERROR_SUCCESS && deleted != ERROR_FILE_NOT_FOUND {
        return Err(PlatformError::AutostartUnavailable {
            code: deleted as i64,
        });
    }

    Ok(())
}

/// Fuori da Windows non esiste alcun avvio automatico da leggere.
#[cfg(not(windows))]
pub fn state() -> PlatformResult<AutostartState> {
    Ok(AutostartState::Disabled)
}

/// Fuori da Windows non esiste alcun avvio automatico da registrare.
#[cfg(not(windows))]
pub fn enable() -> PlatformResult<()> {
    Err(PlatformError::Unsupported)
}

/// Fuori da Windows non c'e' nulla da togliere.
#[cfg(not(windows))]
pub fn disable() -> PlatformResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::AutostartState;

    #[test]
    fn a_registered_entry_that_points_elsewhere_is_not_effective() {
        // E' la distinzione per cui questo tipo esiste. Un booleano avrebbe
        // detto «attivo» e l'operatore avrebbe creduto di essere coperto,
        // mentre all'accesso non parte nulla.
        assert!(AutostartState::EnabledElsewhere.is_registered());
        assert!(
            !AutostartState::EnabledElsewhere.is_effective(),
            "una voce che punta altrove non avvia questa applicazione"
        );

        assert!(AutostartState::Enabled.is_registered());
        assert!(AutostartState::Enabled.is_effective());

        assert!(!AutostartState::Disabled.is_registered());
        assert!(!AutostartState::Disabled.is_effective());
    }

    #[test]
    fn every_state_says_something_useful_and_different() {
        let states = [
            AutostartState::Disabled,
            AutostartState::Enabled,
            AutostartState::EnabledElsewhere,
        ];
        for (index, state) in states.iter().enumerate() {
            assert!(!state.operator_message().is_empty());
            for other in states.iter().skip(index + 1) {
                assert_ne!(state.operator_message(), other.operator_message());
            }
        }
    }

    #[test]
    #[cfg(windows)]
    fn the_command_line_is_quoted_so_that_a_path_with_spaces_survives() {
        let Ok(value) = super::command_line() else {
            panic!("il percorso dell'eseguibile di prova deve essere determinabile");
        };
        // Senza virgolette un percorso come `C:\Program Files\...` verrebbe
        // letto come comando piu' argomenti, e avvierebbe il programma
        // sbagliato o nessuno.
        assert!(value.starts_with('"'), "manca la virgoletta iniziale");
        assert!(value.ends_with('"'), "manca la virgoletta finale");
        assert!(value.len() > 2, "il percorso non puo' essere vuoto");
    }

    #[test]
    #[cfg(windows)]
    fn a_malformed_stored_value_is_read_as_absent_rather_than_as_something() {
        // Il valore lo puo' aver scritto chiunque abbia accesso al profilo: una
        // lunghezza che eccede il buffer non deve produrre una lettura fuori
        // limite ne' un dato dubbio, ma l'assenza — che e' la lettura prudente.
        let buffer = [0x0041_u16; 4];
        assert_eq!(super::decode(&buffer, 0), None, "lunghezza nulla");
        assert_eq!(
            super::decode(&buffer, 4_000),
            None,
            "lunghezza oltre la capienza del buffer"
        );

        // Un valore ben formato invece si legge.
        let mut valid = [0_u16; 4];
        valid[0] = u16::from(b'A');
        valid[1] = u16::from(b'B');
        assert_eq!(super::decode(&valid, 6).as_deref(), Some("AB"));
    }

    /// Chiave di prova: sotto il ramo del prodotto, **non** sotto quello
    /// dell'avvio automatico. Esercitare il codice reale non deve significare
    /// mettere in avvio automatico il computer di chi compila.
    #[cfg(windows)]
    const TEST_KEY: &str = r"Software\NEXUM97 prove registro";

    #[test]
    #[cfg(windows)]
    fn a_value_written_is_read_back_identical_and_then_disappears() {
        // E' il test che conta di questo modulo: la conversione UTF-16, la
        // lunghezza in byte con il terminatore, e la rilettura sono le tre cose
        // che si sbagliano, e nessuna si vedrebbe da un test sui soli tipi.
        let name = "giro-di-prova";
        let value = r#""C:\Program Files\Cartella con spazi\programma.exe""#;

        // Si parte pulito anche se una corsa precedente e' stata interrotta.
        let _ = super::delete_value(TEST_KEY, name);

        assert!(
            super::write_value(TEST_KEY, name, value).is_ok(),
            "la scrittura deve riuscire"
        );

        let Ok(stored) = super::read_value(TEST_KEY, name) else {
            panic!("la rilettura deve riuscire");
        };
        assert_eq!(
            stored.as_deref(),
            Some(value),
            "il valore riletto deve essere identico, virgolette e spazi compresi"
        );

        assert!(
            super::delete_value(TEST_KEY, name).is_ok(),
            "la cancellazione deve riuscire"
        );
        let Ok(after) = super::read_value(TEST_KEY, name) else {
            panic!("la rilettura dopo la cancellazione deve riuscire");
        };
        assert_eq!(after, None, "dopo la cancellazione non deve restare nulla");

        // La seconda cancellazione e' quella che dimostra l'idempotenza.
        assert!(
            super::delete_value(TEST_KEY, name).is_ok(),
            "cancellare cio' che non c'e' non e' un errore"
        );

        // La chiave creata per la prova non resta nel profilo di chi compila.
        assert!(
            super::delete_key(TEST_KEY).is_ok(),
            "la chiave di prova deve potersi togliere"
        );
    }

    #[test]
    #[cfg(windows)]
    fn reading_a_value_that_was_never_written_is_absence_not_failure() {
        // Chiave **propria**, non quella condivisa: i test di questo modulo
        // girano in parallelo, e uno che legge mentre un altro cancella la
        // stessa chiave fallisce a caso. Un test che fallisce a caso smette
        // molto presto di essere letto.
        const OWN_KEY: &str = r"Software\NEXUM97 prove lettura";

        let Ok(()) = super::write_value(OWN_KEY, "presente", "valore") else {
            panic!("la scrittura di prova deve riuscire");
        };
        let Ok(missing) = super::read_value(OWN_KEY, "nome-che-non-esiste") else {
            panic!("un valore assente non deve produrre un errore");
        };
        assert_eq!(missing, None);

        let Ok(()) = super::delete_value(OWN_KEY, "presente") else {
            panic!("la pulizia deve riuscire");
        };
        let Ok(()) = super::delete_key(OWN_KEY) else {
            panic!("la chiave di prova deve potersi togliere");
        };

        let Ok(missing) = super::read_value(r"Software\NEXUM97 chiave inesistente", "qualsiasi")
        else {
            panic!("una chiave assente non deve produrre un errore");
        };
        assert_eq!(missing, None);
    }

    #[test]
    #[cfg(windows)]
    fn disabling_is_idempotent_and_reading_never_fails() {
        // Il test **non** attiva l'avvio automatico: modificherebbe il profilo
        // Windows di chi esegue i test, che non e' cio' che una suite deve
        // fare. Verifica le due operazioni che non lasciano traccia:
        // disattivare quando non c'e' nulla, e leggere.
        assert!(
            super::disable().is_ok(),
            "disattivare cio' che non c'e' deve riuscire"
        );
        assert!(
            super::disable().is_ok(),
            "e deve riuscire anche la seconda volta"
        );
        assert!(super::state().is_ok(), "lo stato deve essere leggibile");
    }
}

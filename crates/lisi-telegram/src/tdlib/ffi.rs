// UNICO modulo del crate autorizzato a contenere `unsafe`.
//
// Il divieto vale per tutto il resto di `lisi-telegram`: `lib.rs` applica
// `forbid(unsafe_code)` senza la feature del proof of concept e `deny` con la
// feature attiva. Questa deroga è esplicita, circoscritta a un solo file e
// visibile in diff, come prescrive ADR-0003.
#![allow(unsafe_code)]

//! Confine FFI verso l'interfaccia JSON di TDLib.
//!
//! # Perché questo modulo esiste
//!
//! TDLib offre due interfacce: una C++ e una C basata su JSON. La
//! documentazione ufficiale raccomanda la seconda per i linguaggi diversi dal
//! C++. La superficie da attraversare è di **quattro funzioni**, il che rende
//! l'`unsafe` circoscrivibile e le invarianti scrivibili per intero. La scelta
//! rispetto ai binding Rust esistenti è motivata in
//! `docs/adr/ADR-0008-TDLIB-INTEGRATION.md`.
//!
//! # Invarianti di sicurezza
//!
//! Derivano dalla documentazione ufficiale di `td_json_client.h` e valgono per
//! ogni blocco `unsafe` di questo file.
//!
//! 1. **La memoria restituita non è nostra.** `td_receive` e `td_execute`
//!    restituiscono un puntatore a una stringa C che appartiene a TDLib. Non va
//!    mai liberata: niente `free`, niente `CString::from_raw`,
//!    niente `Box::from_raw`.
//! 2. **La validità è brevissima.** Il puntatore resta valido *fino alla
//!    successiva chiamata a `td_receive` oppure `td_execute`*: le due funzioni
//!    condividono lo stesso buffer, e una invalida il risultato dell'altra. Il
//!    contenuto viene quindi **copiato subito** in una `String` di proprietà del
//!    chiamante, prima di rilasciare il lock e prima di qualunque altra chiamata
//!    FFI. Nessun riferimento con durata derivata dal puntatore C esce da qui.
//! 3. **Il puntatore può essere nullo.** `td_receive` restituisce `NULL` allo
//!    scadere dell'attesa. Il caso è gestito come «nessun evento» e il puntatore
//!    non viene mai dereferenziato senza controllo.
//! 4. **`td_receive` non è rientrante.** La documentazione vieta di chiamarla da
//!    due thread contemporaneamente. Poiché all'interno di uno stesso thread il
//!    buffer di ritorno è condiviso con `td_execute`, **entrambe** sono
//!    serializzate dallo *stesso* lock di processo, non da due lock distinti e
//!    non dal solo `&mut self`. Vedere la sezione sulla semantica del buffer.
//! 5. **L'input deve essere una stringa C valida.** Le richieste sono convertite
//!    in `CString`; un byte NUL interno fa fallire la conversione e l'errore è
//!    propagato, non ignorato.
//! 6. **Il testo restituito è trattato come non fidato.** La documentazione non
//!    garantisce che sia UTF-8 valido, quindi la conversione è a perdita
//!    controllata e non può causare panico.
//! 7. **`client_id` è opaco.** Non viene interpretato, né riusato dopo la
//!    chiusura, né si assume che sia crescente.
//!
//! # Semantica del buffer, verificata sul sorgente
//!
//! La documentazione afferma che il puntatore è valido «fino alla chiamata
//! successiva» **senza qualificare il thread**. La questione è stata risolta
//! leggendo il sorgente del commit realmente compilato,
//! `td/telegram/ClientJson.cpp`:
//!
//! ```cpp
//! static TD_THREAD_LOCAL string *current_output;
//!
//! static const char *store_string(string str) {
//!   init_thread_local<string>(current_output);
//!   *current_output = std::move(str);
//!   return current_output->c_str();
//! }
//! ```
//!
//! `json_receive` e `json_execute` restituiscono entrambe `store_string(...)`.
//! Il buffer è dunque **locale al thread**: due thread non si invalidano il
//! risultato a vicenda, mentre **all'interno dello stesso thread** le due
//! funzioni condividono lo stesso buffer e continuano a invalidarsi.
//!
//! Il lock unico di processo resta comunque adottato, per due ragioni. La prima
//! è che la documentazione vieta comunque di chiamare `td_receive` da due thread
//! contemporaneamente, e quel divieto riguarda la coda degli aggiornamenti, non
//! il buffer. La seconda è che per un'applicazione desktop con un solo client il
//! costo del lock è irrilevante, mentre il costo di un errore in quest'area è
//! comportamento indefinito. La conservatività è ora una **scelta motivata** e
//! non una difesa contro un'incognita.

use std::ffi::{CStr, CString, c_char, c_double, c_int};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use libloading::{Library, Symbol};

use crate::error::{TelegramError, TelegramResult};

/// Firma di `int td_create_client_id(void)`.
type TdCreateClientId = unsafe extern "C" fn() -> c_int;
/// Firma di `void td_send(int client_id, const char *request)`.
type TdSend = unsafe extern "C" fn(c_int, *const c_char);
/// Firma di `const char *td_receive(double timeout)`.
type TdReceive = unsafe extern "C" fn(c_double) -> *const c_char;
/// Firma di `const char *td_execute(const char *request)`.
type TdExecute = unsafe extern "C" fn(*const c_char) -> *const c_char;

/// Serializza `td_receive` e `td_execute` per l'intero processo.
///
/// Invariante 4: il buffer di ritorno è condiviso fra le due funzioni e
/// `td_receive` non è rientrante. Il lock è di processo e non per istanza,
/// perché due istanze diverse userebbero comunque lo stesso buffer.
static SHARED_BUFFER_LOCK: Mutex<()> = Mutex::new(());

/// Acquisisce il lock condiviso senza mai causare panico.
///
/// Un lock avvelenato significa che un altro thread è terminato in modo anomalo
/// mentre lo deteneva. Il dato protetto è `()`: non c'è alcuno stato da
/// considerare corrotto, quindi il guard viene recuperato invece di propagare il
/// panico. I requisiti vietano `unwrap` nel codice di produzione.
fn lock_shared_buffer() -> MutexGuard<'static, ()> {
    SHARED_BUFFER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Libreria `tdjson` caricata a runtime.
///
/// Il caricamento è **esplicito e ritardato**: l'applicazione non dichiara una
/// dipendenza di collegamento verso la DLL e può avviarsi anche se la libreria
/// non è presente. Questo è ciò che permette al prodotto di restare utilizzabile
/// mentre il connettore è indisponibile, invece di rifiutarsi di partire.
#[derive(Debug)]
pub struct TdJsonLibrary {
    library: Library,
}

impl TdJsonLibrary {
    /// Nome predefinito della libreria su Windows.
    pub const DEFAULT_WINDOWS_NAME: &'static str = "tdjson.dll";

    /// Carica la libreria dal percorso indicato.
    ///
    /// Il percorso è **esplicito** e non affidato al meccanismo di ricerca del
    /// sistema: caricare una libreria per nome lascerebbe decidere all'ordine
    /// delle cartelle di ricerca quale file venga aperto, che è una via nota di
    /// dirottamento su Windows.
    ///
    /// # Errori
    ///
    /// Restituisce [`TelegramError::Tdlib`] se il file non esiste o non può
    /// essere caricato.
    pub fn load(path: &Path) -> TelegramResult<Self> {
        if !path.is_file() {
            return Err(TelegramError::Tdlib {
                reason: format!(
                    "la libreria non esiste al percorso indicato: {}",
                    path.display()
                ),
            });
        }

        // SAFETY (invariante generale del caricamento dinamico): `Library::new`
        // è unsafe perché caricare una libreria esegue le sue routine di
        // inizializzazione, e nulla può garantire che una libreria arbitraria
        // sia benigna. Qui il percorso è fornito dall'operatore o dallo script
        // di build verificato, non deriva da contenuto remoto, e l'artefatto
        // atteso è una `tdjson` di cui lo script di build registra l'impronta
        // SHA-256. Il rischio residuo è dichiarato nel threat model M2.
        let library = unsafe { Library::new(path) }.map_err(|error| TelegramError::Tdlib {
            reason: format!("caricamento non riuscito: {error}"),
        })?;

        let loaded = Self { library };
        // Verifica immediata che i quattro simboli attesi esistano: meglio
        // fallire ora, con un messaggio chiaro, che alla prima chiamata.
        loaded.check_symbols()?;
        Ok(loaded)
    }

    /// Verifica la presenza dei simboli richiesti.
    fn check_symbols(&self) -> TelegramResult<()> {
        for symbol in [
            &b"td_create_client_id\0"[..],
            &b"td_send\0"[..],
            &b"td_receive\0"[..],
            &b"td_execute\0"[..],
        ] {
            // SAFETY: `get` è unsafe perché il chiamante dichiara il tipo del
            // simbolo. Qui il tipo richiesto è `*const ()`, cioè nessuna
            // assunzione sulla firma: si verifica soltanto che il simbolo
            // esista. Il puntatore non viene mai chiamato.
            let found: Result<Symbol<'_, *const ()>, _> = unsafe { self.library.get(symbol) };
            if found.is_err() {
                let name = String::from_utf8_lossy(&symbol[..symbol.len().saturating_sub(1)]);
                return Err(TelegramError::Tdlib {
                    reason: format!(
                        "la libreria non espone il simbolo «{name}»: non sembra il componente \
                         per Telegram previsto"
                    ),
                });
            }
        }
        Ok(())
    }

    /// Crea una nuova istanza di client e ne restituisce l'identificativo opaco.
    ///
    /// # Errori
    ///
    /// Restituisce [`TelegramError::Tdlib`] se il simbolo non è disponibile.
    pub fn create_client_id(&self) -> TelegramResult<i32> {
        // SAFETY: il tipo dichiarato corrisponde alla firma documentata
        // `int td_create_client_id(void)`. La presenza del simbolo è già stata
        // verificata al caricamento.
        let symbol: Symbol<'_, TdCreateClientId> = unsafe {
            self.library
                .get(b"td_create_client_id\0")
                .map_err(|error| TelegramError::Tdlib {
                    reason: format!("simbolo 'td_create_client_id' non disponibile: {error}"),
                })?
        };

        // SAFETY: la funzione non riceve puntatori, non ne restituisce e la
        // documentazione non le impone vincoli di thread. Restituisce un intero
        // opaco (invariante 7).
        Ok(unsafe { symbol() })
    }

    /// Invia una richiesta JSON al client indicato.
    ///
    /// La chiamata è asincrona: la risposta arriverà da [`Self::receive`].
    ///
    /// # Errori
    ///
    /// Restituisce [`TelegramError::Tdlib`] se la richiesta contiene un byte NUL
    /// o se il simbolo non è disponibile.
    pub fn send(&self, client_id: i32, request: &str) -> TelegramResult<()> {
        // Invariante 5: un NUL interno renderebbe la stringa C troncata rispetto
        // a ciò che il chiamante intendeva inviare. È un errore, non un dettaglio.
        let request = CString::new(request).map_err(|_| TelegramError::Tdlib {
            reason: String::from("la richiesta contiene un byte NUL e non è una stringa C valida"),
        })?;

        // SAFETY: il tipo dichiarato corrisponde a
        // `void td_send(int, const char *)`.
        let symbol: Symbol<'_, TdSend> =
            unsafe { self.library.get(b"td_send\0") }.map_err(|error| TelegramError::Tdlib {
                reason: format!("simbolo 'td_send' non disponibile: {error}"),
            })?;

        // SAFETY: `request.as_ptr()` punta a una stringa C valida e terminata da
        // NUL, viva per tutta la durata della chiamata perché `request` è ancora
        // in scope. La documentazione dichiara `td_send` chiamabile da qualunque
        // thread e non restituisce memoria, quindi non richiede il lock del
        // buffer condiviso (invariante 4, che riguarda receive ed execute).
        unsafe { symbol(client_id, request.as_ptr()) };
        Ok(())
    }

    /// Attende il prossimo aggiornamento o risposta.
    ///
    /// Restituisce `None` allo scadere dell'attesa: è la condizione normale di
    /// una fonte silenziosa e non un errore.
    ///
    /// # Errori
    ///
    /// Restituisce [`TelegramError::Tdlib`] se il simbolo non è disponibile.
    pub fn receive(&self, timeout_seconds: f64) -> TelegramResult<Option<String>> {
        // SAFETY: il tipo dichiarato corrisponde a
        // `const char *td_receive(double)`.
        let symbol: Symbol<'_, TdReceive> =
            unsafe { self.library.get(b"td_receive\0") }.map_err(|error| TelegramError::Tdlib {
                reason: format!("simbolo 'td_receive' non disponibile: {error}"),
            })?;

        // Invariante 4: il lock copre la chiamata **e** la copia del risultato.
        let guard = lock_shared_buffer();

        // SAFETY: la chiamata avviene con il lock di processo detenuto, quindi
        // nessun altro thread può invocare `td_receive` o `td_execute` mentre il
        // buffer restituito è ancora in uso (invarianti 2 e 4).
        let pointer = unsafe { symbol(timeout_seconds) };
        let received = copy_c_string(pointer);

        drop(guard);
        Ok(received)
    }

    /// Esegue una richiesta sincrona che non passa dalla coda degli
    /// aggiornamenti.
    ///
    /// # Errori
    ///
    /// Restituisce [`TelegramError::Tdlib`] se la richiesta contiene un byte NUL
    /// o se il simbolo non è disponibile.
    pub fn execute(&self, request: &str) -> TelegramResult<Option<String>> {
        let request = CString::new(request).map_err(|_| TelegramError::Tdlib {
            reason: String::from("la richiesta contiene un byte NUL e non è una stringa C valida"),
        })?;

        // SAFETY: il tipo dichiarato corrisponde a
        // `const char *td_execute(const char *)`.
        let symbol: Symbol<'_, TdExecute> =
            unsafe { self.library.get(b"td_execute\0") }.map_err(|error| TelegramError::Tdlib {
                reason: format!("simbolo 'td_execute' non disponibile: {error}"),
            })?;

        let guard = lock_shared_buffer();

        // SAFETY: `request.as_ptr()` è una stringa C valida viva per tutta la
        // chiamata. Il lock è detenuto per l'intera durata della chiamata e
        // della copia del risultato, perché `td_execute` condivide il buffer con
        // `td_receive` (invarianti 2 e 4).
        let pointer = unsafe { symbol(request.as_ptr()) };
        let executed = copy_c_string(pointer);

        drop(guard);
        Ok(executed)
    }
}

/// Copia una stringa C in una `String` di proprietà del chiamante.
///
/// È il solo punto in cui un puntatore proveniente da TDLib viene
/// dereferenziato. Restituisce `None` per il puntatore nullo.
///
/// # Sicurezza
///
/// Il chiamante deve garantire che `pointer` sia nullo oppure punti a una
/// stringa C valida e terminata da NUL, e che nessuna altra chiamata a
/// `td_receive` o `td_execute` avvenga prima del ritorno di questa funzione.
fn copy_c_string(pointer: *const c_char) -> Option<String> {
    // Invariante 3.
    if pointer.is_null() {
        return None;
    }

    // SAFETY: il puntatore è stato verificato non nullo; il chiamante detiene il
    // lock del buffer condiviso, quindi nessuna altra chiamata può averlo
    // invalidato (invariante 2). La stringa è terminata da NUL come documentato.
    let borrowed = unsafe { CStr::from_ptr(pointer) };

    // Invariante 6: conversione a perdita controllata, mai un panico. La copia
    // avviene qui: da questo punto in poi il puntatore di TDLib non serve più.
    // Invariante 1: nessuna deallocazione, la memoria resta di TDLib.
    Some(borrowed.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::path::Path;

    use super::{TdJsonLibrary, copy_c_string, lock_shared_buffer};
    use crate::error::TelegramError;

    #[test]
    fn a_null_pointer_is_reported_as_absence_and_never_dereferenced() {
        assert_eq!(copy_c_string(core::ptr::null()), None);
    }

    #[test]
    fn a_valid_c_string_is_copied_into_an_owned_string() {
        let Ok(source) = CString::new(r#"{"@type":"updateOption"}"#) else {
            panic!("la stringa di prova deve essere convertibile");
        };

        // SAFETY: `source` è viva per tutta la durata della chiamata e contiene
        // una stringa C valida terminata da NUL.
        let copied = copy_c_string(source.as_ptr());

        assert_eq!(copied.as_deref(), Some(r#"{"@type":"updateOption"}"#));
    }

    #[test]
    fn an_empty_c_string_is_copied_as_an_empty_string() {
        let Ok(source) = CString::new("") else {
            panic!("la stringa vuota deve essere convertibile");
        };
        assert_eq!(copy_c_string(source.as_ptr()).as_deref(), Some(""));
    }

    #[test]
    fn invalid_utf8_is_converted_without_panicking() {
        // 0xFF non è una sequenza UTF-8 valida. La documentazione di TDLib non
        // garantisce la validità UTF-8 del buffer: la conversione deve reggere.
        let Ok(source) = CString::new(vec![b'a', 0xFF, b'b']) else {
            panic!("la sequenza di prova deve essere convertibile in CString");
        };

        let Some(copied) = copy_c_string(source.as_ptr()) else {
            panic!("il puntatore non era nullo");
        };
        assert!(copied.contains('a'));
        assert!(copied.contains('b'));
        assert!(
            copied.contains('\u{FFFD}'),
            "il byte non valido è sostituito"
        );
    }

    #[test]
    fn a_missing_library_is_reported_without_attempting_to_load_it() {
        let missing = Path::new("C:\\percorso\\che\\non\\esiste\\tdjson.dll");
        let Err(error) = TdJsonLibrary::load(missing) else {
            panic!("il caricamento di una libreria inesistente doveva fallire");
        };

        assert!(matches!(error, TelegramError::Tdlib { .. }));
        assert!(error.to_string().contains("non esiste"));
    }

    #[test]
    fn a_directory_is_not_accepted_as_a_library() {
        let Ok(directory) = std::env::current_dir() else {
            panic!("la cartella corrente deve essere leggibile");
        };
        assert!(TdJsonLibrary::load(&directory).is_err());
    }

    #[test]
    fn the_shared_lock_survives_a_poisoned_state() {
        // Un thread che termina in modo anomalo mentre detiene il lock non deve
        // rendere il connettore inutilizzabile: il dato protetto è `()`.
        let poisoned = std::thread::spawn(|| {
            let _guard = lock_shared_buffer();
            panic!("panico deliberato per avvelenare il lock");
        })
        .join();
        assert!(poisoned.is_err(), "il thread doveva terminare in panico");

        // Non deve andare in panico a sua volta.
        let guard = lock_shared_buffer();
        drop(guard);
    }
}

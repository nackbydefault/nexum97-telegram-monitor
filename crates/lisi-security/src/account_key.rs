//! Chiave di cifratura del database TDLib, **distinta per account**.
//!
//! Ogni account d'ufficio ha un database TDLib proprio, cifrato con una chiave
//! casuale a sé stante (ADR-0019, sezione 2). Questo modulo genera quella
//! chiave, la protegge con DPAPI e la ricarica. Non conosce la struttura delle
//! cartelle dati: **riceve il percorso dall'esterno**, esattamente come
//! [`crate::store::ProtectedStore::at`]. È il chiamante (i servizi) a comporre
//! `.../accounts/<uuid>/tdlib.key.protetto` a partire dall'UUID dell'account,
//! **mai dal numero di telefono**, così che un elenco di cartelle non riveli a
//! chi appartengono.
//!
//! # Dove finisce la chiave e dove no
//!
//! La chiave non compare in log, errori, audit o nomi di file. Il nome del file
//! deriva dall'UUID (scelto dal chiamante); il valore vive nel file solo in
//! forma protetta da DPAPI. In memoria è custodita da [`AccountKey`], che
//! **redige** la propria resa `Debug`, non implementa `Display` né
//! serializzazione, ed espone il valore solo con metodi dal nome esplicito.
//!
//! # Riuso di `ProtectedStore` e sue conseguenze
//!
//! La chiave è persistita riusando [`ProtectedStore`]: se ne ereditano la
//! scrittura atomica, la restrizione dei permessi al proprietario e la
//! protezione DPAPI, tutte già collaudate. Il prezzo è che la chiave, per essere
//! conservata in un archivio chiave/valore testuale, transita come stringa
//! **base64**. Questa copia transitoria — e la copia serializzata interna a
//! `ProtectedStore` — non è azzerabile da qui. È un limite reale, coerente con
//! il rischio residuo dichiarato in ADR-0019: Rust non garantisce la
//! cancellazione fisica della memoria. Vedere la nota su [`AccountKey`].

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::dpapi;
use crate::error::{SecurityError, SecurityResult};
use crate::store::ProtectedStore;

/// Lunghezza della chiave, in byte.
///
/// Trentadue byte: la dimensione consigliata per la chiave di cifratura del
/// database TDLib.
const KEY_LEN: usize = 32;

/// Nome della voce che custodisce la chiave nell'archivio protetto.
///
/// Non è un segreto e non ne contiene: è una costante di formato. Il valore
/// associato è protetto da DPAPI insieme al resto dell'archivio.
const KEY_ENTRY: &str = "tdlib_db_key";

/// Chiave di cifratura del database TDLib di un account.
///
/// # Redazione e serializzazione
///
/// La resa `Debug` è redatta, `Display` **non è implementato** (così che
/// `format!("{}", chiave)` non compili) e non esiste alcuna derivazione di
/// serializzazione: ogni via che porti fuori il valore è un metodo esplicito
/// ([`AccountKey::expose_secret`], [`AccountKey::as_base64`]).
///
/// # Azzeramento della memoria: limite dichiarato
///
/// Alla distruzione il buffer viene sovrascritto con zeri. Poiché è un array di
/// lunghezza fissa, **non** subisce riallocazioni: la sovrascrittura agisce
/// sulla stessa memoria che ha contenuto la chiave. Resta però un limite reale
/// e non aggirabile da qui: il compilatore può averne tenuto copie in registri
/// o sullo stack, e il sistema operativo può aver paginato quella memoria su
/// disco. Si riduce la finestra di esposizione, non la si annulla: è il limite
/// dichiarato in ADR-0019, non un difetto di questa implementazione.
pub struct AccountKey {
    bytes: [u8; KEY_LEN],
}

impl AccountKey {
    /// Lunghezza della chiave, in byte.
    pub const LEN: usize = KEY_LEN;

    /// Genera una chiave nuova con il generatore crittografico di sistema.
    ///
    /// Il buffer è riempito **in loco**: nessuna variabile intermedia detiene il
    /// materiale della chiave oltre alla struttura restituita.
    fn generate() -> SecurityResult<Self> {
        let mut key = Self {
            bytes: [0_u8; KEY_LEN],
        };
        dpapi::random_bytes(&mut key.bytes)?;
        Ok(key)
    }

    /// Ricostruisce la chiave da byte già noti (per esempio decodificati dal
    /// file protetto).
    fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self { bytes }
    }

    /// Espone il valore in chiaro come byte.
    ///
    /// Il nome è volutamente scomodo: ogni chiamata è un punto in cui la chiave
    /// lascia il proprio contenitore e va giustificata. Non passare mai il
    /// risultato a una macro di logging.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.bytes
    }

    /// Espone la chiave come stringa base64 standard, con riempimento.
    ///
    /// È la forma attesa da TDLib per `database_encryption_key`, che nella
    /// tdjson è un campo `bytes` e viaggia quindi codificato in base64. Vale la
    /// stessa cautela di [`Self::expose_secret`]: è materiale della chiave.
    #[must_use]
    pub fn as_base64(&self) -> String {
        base64_encode(&self.bytes)
    }
}

impl core::fmt::Debug for AccountKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Nessun byte della chiave finisce nella resa di debug.
        formatter.write_str("AccountKey(«redatto»)")
    }
}

impl Drop for AccountKey {
    fn drop(&mut self) {
        // Sovrascrittura best-effort del buffer fisso. Il limite è dichiarato
        // nella documentazione del tipo: riduce la finestra, non la elimina.
        self.bytes.fill(0);
        let _ = core::hint::black_box(&self.bytes);
    }
}

/// Assicura la chiave dell'account al percorso indicato.
///
/// Se il file protetto è assente, genera una chiave casuale, la salva e la
/// restituisce; se è presente, la ricarica. Chiamate successive sullo stesso
/// percorso restituiscono quindi **sempre la stessa** chiave.
///
/// Il `store_path` è fornito dal chiamante e deve derivare dall'UUID
/// dell'account, non dal numero: questo modulo non calcola la cartella dati.
///
/// # Errori
///
/// Restituisce un errore se il generatore di sistema rifiuta, se la protezione
/// DPAPI o la scrittura non riescono, o — al ricarico — se il file è
/// danneggiato. Fuori da Windows restituisce
/// [`SecurityError::UnsupportedPlatform`].
pub fn ensure_account_key(store_path: PathBuf) -> SecurityResult<AccountKey> {
    let store = ProtectedStore::at(store_path);
    if store.exists() {
        return load_from_store(&store);
    }

    let key = AccountKey::generate()?;
    save_to_store(&store, &key)?;
    Ok(key)
}

/// Carica la chiave dell'account dal percorso indicato.
///
/// # Errori
///
/// Restituisce [`SecurityError::NotConfigured`] se il file è assente (l'account
/// non ha ancora una chiave), [`SecurityError::UnprotectionFailed`] se il file
/// non è decifrabile con il profilo Windows corrente e
/// [`SecurityError::Corrupted`] se il contenuto non è una chiave valida.
pub fn load_account_key(store_path: PathBuf) -> SecurityResult<AccountKey> {
    let store = ProtectedStore::at(store_path);
    load_from_store(&store)
}

/// Salva la chiave nell'archivio protetto, in forma base64.
fn save_to_store(store: &ProtectedStore, key: &AccountKey) -> SecurityResult<()> {
    let mut entries = BTreeMap::new();
    entries.insert(String::from(KEY_ENTRY), key.as_base64());
    let outcome = store.save(&entries);

    // Best-effort: la copia base64 nella mappa detiene materiale della chiave.
    // La si azzera dopo la scrittura. Resta la copia serializzata interna a
    // `ProtectedStore`, che non è raggiungibile da qui (limite dichiarato).
    if let Some(encoded) = entries.remove(KEY_ENTRY) {
        zeroize_string(encoded);
    }

    outcome
}

/// Ricostruisce la chiave dall'archivio protetto.
fn load_from_store(store: &ProtectedStore) -> SecurityResult<AccountKey> {
    let encoded = store.load_entry(KEY_ENTRY)?;
    let decoded = base64_decode(&encoded);
    // La stringa base64 detiene materiale della chiave: azzerata subito.
    zeroize_string(encoded);

    let decoded = decoded.ok_or(SecurityError::Corrupted {
        reason: "la chiave di cifratura dell'account non è codificata correttamente",
    })?;

    let bytes: [u8; KEY_LEN] = decoded.try_into().map_err(|_| SecurityError::Corrupted {
        reason: "la chiave di cifratura dell'account non ha la lunghezza attesa",
    })?;

    Ok(AccountKey::from_bytes(bytes))
}

/// Sovrascrive best-effort i byte di una stringa prima del rilascio.
///
/// Usa [`String::into_bytes`], che restituisce il buffer **riusandone
/// l'allocazione** senza copiarlo: la sovrascrittura agisce quindi sulla stessa
/// memoria che ha contenuto il testo. Vale il limite dichiarato per
/// [`AccountKey`]: se durante la vita della stringa c'erano state riallocazioni,
/// i buffer precedenti restano irraggiungibili da qui.
pub(crate) fn zeroize_string(value: String) {
    let mut bytes = value.into_bytes();
    bytes.fill(0);
    let _ = core::hint::black_box(&bytes);
}

/// Alfabeto base64 standard (RFC 4648).
const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Codifica byte in base64 standard con riempimento.
pub(crate) fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);

    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let triple = (b0 << 16) | (b1 << 8) | b2;

        let index = |shift: u32| BASE64_ALPHABET[((triple >> shift) & 0x3f) as usize] as char;
        out.push(index(18));
        out.push(index(12));
        match chunk.len() {
            1 => {
                out.push('=');
                out.push('=');
            }
            2 => {
                out.push(index(6));
                out.push('=');
            }
            _ => {
                out.push(index(6));
                out.push(index(0));
            }
        }
    }

    out
}

/// Valore di una cifra base64, oppure `None` se il carattere non appartiene
/// all'alfabeto.
fn base64_value(symbol: u8) -> Option<u8> {
    match symbol {
        b'A'..=b'Z' => Some(symbol - b'A'),
        b'a'..=b'z' => Some(symbol - b'a' + 26),
        b'0'..=b'9' => Some(symbol - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodifica una stringa base64 standard con riempimento.
///
/// Restituisce `None` se la lunghezza non è multipla di quattro, se compare un
/// carattere fuori alfabeto o se il riempimento è malformato. Non emette panic.
pub(crate) fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let v0 = base64_value(chunk[0])?;
        let v1 = base64_value(chunk[1])?;

        let pad2 = chunk[2] == b'=';
        let pad3 = chunk[3] == b'=';
        // Il riempimento può solo chiudere l'ultimo gruppo: "=X" è malformato.
        if pad2 && !pad3 {
            return None;
        }

        let v2 = if pad2 { 0 } else { base64_value(chunk[2])? };
        let v3 = if pad3 { 0 } else { base64_value(chunk[3])? };

        let triple =
            (u32::from(v0) << 18) | (u32::from(v1) << 12) | (u32::from(v2) << 6) | u32::from(v3);

        out.push(((triple >> 16) & 0xff) as u8);
        if !pad2 {
            out.push(((triple >> 8) & 0xff) as u8);
        }
        if !pad3 {
            out.push((triple & 0xff) as u8);
        }
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{AccountKey, base64_decode, base64_encode};

    #[test]
    fn base64_matches_the_rfc_test_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_round_trips_every_byte_value() {
        let all: Vec<u8> = (0..=255_u8).collect();
        let encoded = base64_encode(&all);
        assert_eq!(base64_decode(&encoded).as_deref(), Some(all.as_slice()));
    }

    #[test]
    fn base64_rejects_malformed_input() {
        assert_eq!(
            base64_decode("abc"),
            None,
            "lunghezza non multipla di quattro"
        );
        assert_eq!(base64_decode("****"), None, "caratteri fuori alfabeto");
        assert_eq!(
            base64_decode("=AAA"),
            None,
            "riempimento in posizione errata"
        );
    }

    #[test]
    fn a_thirty_two_byte_key_encodes_to_forty_four_base64_chars() {
        let key = AccountKey::from_bytes([0x5a; AccountKey::LEN]);
        assert_eq!(key.as_base64().len(), 44);
    }

    #[test]
    fn the_debug_rendering_hides_the_key() {
        // Byte riconoscibili: la loro forma base64 non deve comparire nel debug.
        let key = AccountKey::from_bytes([0xab; AccountKey::LEN]);
        let rendered = format!("{key:?}");

        assert!(rendered.contains("redatto"));
        assert!(!rendered.contains(&key.as_base64()));
        assert!(!rendered.contains("ab"));
    }

    #[test]
    fn a_key_survives_the_base64_round_trip_used_for_storage() {
        let key = AccountKey::from_bytes([0x11; AccountKey::LEN]);
        let Some(decoded) = base64_decode(&key.as_base64()) else {
            panic!("la chiave deve ridecodificarsi");
        };
        assert_eq!(decoded.as_slice(), key.expose_secret());
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::{AccountKey, ensure_account_key, load_account_key};
    use crate::error::SecurityError;

    fn key_path(directory: &std::path::Path, name: &str) -> std::path::PathBuf {
        directory
            .join("accounts")
            .join(name)
            .join("tdlib.key.protetto")
    }

    #[test]
    fn a_key_is_generated_once_and_reloaded_identical() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let path = key_path(directory.path(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let Ok(generated) = ensure_account_key(path.clone()) else {
            panic!("la generazione deve riuscire");
        };
        // Seconda chiamata: ricarica, non rigenera.
        let Ok(reloaded) = ensure_account_key(path.clone()) else {
            panic!("il ricarico deve riuscire");
        };
        assert_eq!(generated.expose_secret(), reloaded.expose_secret());

        // Anche il caricamento esplicito restituisce lo stesso valore.
        let Ok(loaded) = load_account_key(path) else {
            panic!("il caricamento esplicito deve riuscire");
        };
        assert_eq!(generated.expose_secret(), loaded.expose_secret());
        assert_eq!(loaded.expose_secret().len(), AccountKey::LEN);
    }

    #[test]
    fn two_different_paths_yield_different_keys() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let first = key_path(directory.path(), "11111111111111111111111111111111");
        let second = key_path(directory.path(), "22222222222222222222222222222222");

        let (Ok(a), Ok(b)) = (ensure_account_key(first), ensure_account_key(second)) else {
            panic!("entrambe le generazioni devono riuscire");
        };
        assert_ne!(
            a.expose_secret(),
            b.expose_secret(),
            "account distinti non devono condividere la chiave"
        );
    }

    #[test]
    fn an_absent_key_is_reported_without_panic() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let path = key_path(directory.path(), "33333333333333333333333333333333");

        assert!(matches!(
            load_account_key(path),
            Err(SecurityError::NotConfigured)
        ));
    }

    #[test]
    fn the_key_does_not_appear_in_clear_on_disk() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let path = key_path(directory.path(), "44444444444444444444444444444444");

        let Ok(key) = ensure_account_key(path.clone()) else {
            panic!("la generazione deve riuscire");
        };

        let Ok(raw) = std::fs::read(&path) else {
            panic!("il file deve essere leggibile");
        };
        // Né i byte grezzi né la forma base64 devono comparire nel file.
        let secret = key.expose_secret();
        let appears_raw = raw.windows(secret.len()).any(|window| window == secret);
        assert!(
            !appears_raw,
            "la chiave non deve comparire in chiaro sul disco"
        );

        let base64 = key.as_base64();
        let appears_base64 = raw
            .windows(base64.len())
            .any(|window| window == base64.as_bytes());
        assert!(
            !appears_base64,
            "la forma base64 della chiave non deve comparire sul disco"
        );
    }

    #[test]
    fn the_file_name_never_carries_the_key() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let path = key_path(directory.path(), "55555555555555555555555555555555");
        let Ok(key) = ensure_account_key(path.clone()) else {
            panic!("la generazione deve riuscire");
        };

        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            panic!("il nome del file deve essere rappresentabile");
        };
        assert!(!name.contains(&key.as_base64()));
        assert_eq!(name, "tdlib.key.protetto");
    }
}

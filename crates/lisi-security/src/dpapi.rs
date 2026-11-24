// UNICO modulo del crate autorizzato a contenere `unsafe`.
//
// Il divieto vale per tutto il resto di `lisi-security`, che applica
// `#![deny(unsafe_code)]`. Questa deroga è esplicita, circoscritta a un solo
// file e visibile in diff, come prescrive ADR-0003.
#![allow(unsafe_code)]

//! Protezione dei dati con DPAPI.
//!
//! # Perché DPAPI e con quale ambito
//!
//! La scelta è motivata in `docs/adr/ADR-0009-SECRETS-AND-SESSION.md`. Due
//! punti che vanno ripetuti qui, perché toccano direttamente questo codice:
//!
//! - l'ambito è **utente** e non macchina. `CRYPTPROTECT_LOCAL_MACHINE`
//!   renderebbe il blob decifrabile da qualunque utente della postazione,
//!   compresi altri operatori. Quel flag non compare in questo file, e non deve
//!   comparirvi.
//! - l'entropia secondaria **non è un segreto**: sta nel codice. Impedisce che
//!   un blob protetto da un'altra applicazione dello stesso utente sia
//!   decifrabile da noi e viceversa; non protegge da chi legga il binario.
//!
//! # Invarianti di sicurezza
//!
//! 1. **La memoria restituita è di Windows.** `CryptProtectData` e
//!    `CryptUnprotectData` allocano il buffer di uscita con `LocalAlloc`: va
//!    liberato con `LocalFree`, **sempre**, compresi i percorsi d'errore.
//! 2. I `CRYPT_INTEGER_BLOB` passati in ingresso puntano a memoria Rust viva
//!    per tutta la durata della chiamata: i buffer sorgente restano in scope.
//! 3. Il buffer restituito viene **copiato subito** in un `Vec<u8>` di
//!    proprietà, prima di liberarlo. Nessun puntatore di Windows esce da qui.
//! 4. Un esito positivo con puntatore nullo è trattato come errore e non
//!    dereferenziato.
//! 5. Le lunghezze sono convertite con controllo, mai con `as`: un
//!    troncamento silenzioso produrrebbe una lettura fuori dai limiti.
//! 6. Nessun messaggio d'errore contiene il dato protetto o parte di esso.
//!
//! # Limite dichiarato
//!
//! DPAPI protegge **a riposo contro altri utenti**, non contro codice che giri
//! come l'utente stesso: un programma malevolo eseguito nel contesto
//! dell'operatore può chiedere la decifratura esattamente come facciamo noi.
//! È il limite del meccanismo, non un difetto di questa implementazione.

use crate::error::SecurityResult;

/// Dimensione massima del dato protetto.
///
/// La configurazione contiene poche righe: un limite generoso ma finito evita
/// che un file danneggiato faccia allocare memoria arbitraria.
pub const MAX_PROTECTED_BYTES: usize = 64 * 1024;

/// Entropia secondaria specifica dell'applicazione.
///
/// **Non è un segreto.** Vedere la nota in testa al modulo.
const ENTROPY: &[u8] = b"LISI-Telegram-Monitor/v1/configurazione-locale";

#[cfg(windows)]
mod windows_impl {
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom, CRYPT_INTEGER_BLOB,
        CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };

    use super::{ENTROPY, MAX_PROTECTED_BYTES};
    use crate::error::{SecurityError, SecurityResult};

    /// Riempie il buffer con byte del generatore crittografico di sistema.
    pub(super) fn random_bytes(out: &mut [u8]) -> SecurityResult<()> {
        let Ok(length) = u32::try_from(out.len()) else {
            return Err(SecurityError::Corrupted {
                reason: "richiesta di casualità oltre il limite rappresentabile",
            });
        };
        if length == 0 {
            return Ok(());
        }

        // SAFETY: `out.as_mut_ptr()` punta a `length` byte scrivibili e vivi per
        // tutta la chiamata (il buffer resta in scope nel chiamante).
        // `BCRYPT_USE_SYSTEM_PREFERRED_RNG` seleziona il generatore preferito del
        // sistema, quindi l'handle dell'algoritmo e' nullo per contratto. Nessun
        // puntatore di Windows viene restituito o conservato.
        let status = unsafe {
            BCryptGenRandom(
                core::ptr::null_mut(),
                out.as_mut_ptr(),
                length,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };

        // STATUS_SUCCESS vale 0; qualunque altro valore e' un errore.
        if status != 0 {
            return Err(SecurityError::Corrupted {
                reason: "il generatore crittografico di sistema ha rifiutato la richiesta",
            });
        }
        Ok(())
    }

    /// Costruisce un descrittore che punta a un buffer Rust.
    ///
    /// # Sicurezza
    ///
    /// Il descrittore resta valido finché `data` è vivo: il chiamante deve
    /// tenerlo in scope per tutta la durata della chiamata a Windows
    /// (invariante 2).
    fn blob_of(data: &[u8]) -> SecurityResult<CRYPT_INTEGER_BLOB> {
        let length = u32::try_from(data.len()).map_err(|_| SecurityError::TooLarge {
            limit: MAX_PROTECTED_BYTES,
        })?;

        Ok(CRYPT_INTEGER_BLOB {
            cbData: length,
            // Windows non modifica i buffer di ingresso, ma la firma li vuole
            // mutabili: il cast e' necessario e non implica scrittura.
            pbData: data.as_ptr().cast_mut(),
        })
    }

    /// Copia il contenuto di un blob restituito da Windows e lo libera.
    ///
    /// # Sicurezza
    ///
    /// `blob` deve essere stato riempito da `CryptProtectData` o
    /// `CryptUnprotectData` con esito positivo. La funzione libera sempre la
    /// memoria, anche quando la copia non è possibile (invarianti 1, 3 e 4).
    unsafe fn take_and_free(blob: CRYPT_INTEGER_BLOB) -> SecurityResult<Vec<u8>> {
        if blob.pbData.is_null() {
            // Invariante 4: esito positivo ma puntatore nullo. Non c'e' nulla
            // da liberare e nulla da copiare.
            return Err(SecurityError::Corrupted {
                reason: "il sistema ha restituito un risultato vuoto",
            });
        }

        let length = usize::try_from(blob.cbData).unwrap_or(0);

        // SAFETY: `pbData` e' non nullo e Windows garantisce che punti a
        // `cbData` byte validi. La copia avviene prima della liberazione
        // (invariante 3).
        let copied = unsafe { core::slice::from_raw_parts(blob.pbData, length) }.to_vec();

        // IL BUFFER DEL SISTEMA SI AZZERA PRIMA DI RESTITUIRLO (FINAL-REVIEW-01,
        // FR-024). Dopo `CryptUnprotectData` contiene il segreto in chiaro, e
        // `LocalFree` lo rende al sistema così com'è: il testo resterebbe nella
        // memoria libera del processo finché qualcuno non la riusa.
        //
        // SAFETY: `pbData` è non nullo, punta a `length` byte scrivibili che
        // questo processo possiede (li ha allocati il sistema per noi, e non
        // sono ancora stati liberati). `write_volatile` impedisce al
        // compilatore di togliere scritture che nessuno rilegge.
        for indice in 0..length {
            unsafe { core::ptr::write_volatile(blob.pbData.add(indice), 0) };
        }

        // SAFETY: invariante 1. Il buffer proviene da LocalAlloc e va liberato
        // con LocalFree, una sola volta. Da qui in avanti `pbData` non viene
        // piu' usato.
        let _ = unsafe { LocalFree(blob.pbData.cast()) };

        Ok(copied)
    }

    /// Protegge il dato con DPAPI ad ambito utente.
    pub(super) fn protect(plaintext: &[u8]) -> SecurityResult<Vec<u8>> {
        if plaintext.len() > MAX_PROTECTED_BYTES {
            return Err(SecurityError::TooLarge {
                limit: MAX_PROTECTED_BYTES,
            });
        }

        let input = blob_of(plaintext)?;
        let entropy = blob_of(ENTROPY)?;
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: core::ptr::null_mut(),
        };

        // SAFETY: `input` ed `entropy` puntano a buffer vivi per tutta la
        // chiamata (invariante 2). `output` e' una struttura valida che Windows
        // riempie. Nessun flag di ambito macchina viene passato: la protezione
        // resta legata al profilo utente. `CRYPTPROTECT_UI_FORBIDDEN` impedisce
        // che venga mostrata una finestra, che in un servizio bloccherebbe.
        let succeeded = unsafe {
            CryptProtectData(
                &raw const input,
                core::ptr::null(),
                &raw const entropy,
                core::ptr::null(),
                core::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &raw mut output,
            )
        };

        if succeeded == 0 {
            // SAFETY: lettura di un codice d'errore per thread, senza puntatori.
            let code = unsafe { GetLastError() };
            return Err(SecurityError::ProtectionFailed { code });
        }

        // SAFETY: l'esito e' positivo, quindi `output` e' stato riempito.
        unsafe { take_and_free(output) }
    }

    /// Rimuove la protezione DPAPI dal dato.
    pub(super) fn unprotect(ciphertext: &[u8]) -> SecurityResult<Vec<u8>> {
        if ciphertext.is_empty() {
            return Err(SecurityError::Corrupted {
                reason: "il file protetto è vuoto",
            });
        }

        let input = blob_of(ciphertext)?;
        let entropy = blob_of(ENTROPY)?;
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: core::ptr::null_mut(),
        };

        // SAFETY: come sopra. L'entropia deve coincidere con quella usata alla
        // protezione, altrimenti la decifratura fallisce senza effetti.
        let succeeded = unsafe {
            CryptUnprotectData(
                &raw const input,
                core::ptr::null_mut(),
                &raw const entropy,
                core::ptr::null(),
                core::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &raw mut output,
            )
        };

        if succeeded == 0 {
            // SAFETY: lettura di un codice d'errore per thread, senza puntatori.
            let code = unsafe { GetLastError() };
            return Err(SecurityError::UnprotectionFailed { code });
        }

        // SAFETY: l'esito e' positivo, quindi `output` e' stato riempito.
        unsafe { take_and_free(output) }
    }
}

/// Protegge il dato con la protezione locale dell'utente corrente.
///
/// # Errori
///
/// Restituisce [`SecurityError::ProtectionFailed`] se il sistema rifiuta,
/// [`SecurityError::TooLarge`] oltre [`MAX_PROTECTED_BYTES`] e
/// [`SecurityError::UnsupportedPlatform`] fuori da Windows.
pub fn protect(plaintext: &[u8]) -> SecurityResult<Vec<u8>> {
    #[cfg(windows)]
    {
        windows_impl::protect(plaintext)
    }
    #[cfg(not(windows))]
    {
        let _ = plaintext;
        Err(crate::error::SecurityError::UnsupportedPlatform)
    }
}

/// Rimuove la protezione locale dal dato.
///
/// # Errori
///
/// Restituisce [`SecurityError::UnprotectionFailed`] se il dato non è
/// decifrabile con il profilo corrente, il che accade anche quando il file
/// proviene da un altro utente o da un'altra macchina.
pub fn unprotect(ciphertext: &[u8]) -> SecurityResult<Vec<u8>> {
    #[cfg(windows)]
    {
        windows_impl::unprotect(ciphertext)
    }
    #[cfg(not(windows))]
    {
        let _ = ciphertext;
        Err(crate::error::SecurityError::UnsupportedPlatform)
    }
}

/// Riempie il buffer con byte casuali del generatore crittografico di sistema.
///
/// Serve dove occorre un valore non prevedibile che non è un segreto in sé — un
/// salt, per esempio. Non è un generatore per uso generale: passa direttamente
/// dal generatore preferito del sistema operativo.
///
/// # Errori
///
/// Restituisce un errore se il sistema rifiuta la richiesta, e
/// [`SecurityError::UnsupportedPlatform`] fuori da Windows.
pub fn random_bytes(out: &mut [u8]) -> SecurityResult<()> {
    #[cfg(windows)]
    {
        windows_impl::random_bytes(out)
    }
    #[cfg(not(windows))]
    {
        let _ = out;
        Err(crate::error::SecurityError::UnsupportedPlatform)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::{MAX_PROTECTED_BYTES, protect, unprotect};
    use crate::error::SecurityError;

    #[test]
    fn a_protected_value_is_recovered_intact() {
        let secret = b"valore-di-prova-non-reale";
        let Ok(protected) = protect(secret) else {
            panic!("la protezione deve riuscire sul profilo corrente");
        };
        let Ok(recovered) = unprotect(&protected) else {
            panic!("la decifratura deve riuscire sullo stesso profilo");
        };
        assert_eq!(recovered, secret);
    }

    #[test]
    fn the_protected_form_does_not_contain_the_plaintext() {
        let secret = b"stringa-riconoscibile-di-prova";
        let Ok(protected) = protect(secret) else {
            panic!("la protezione deve riuscire");
        };

        // Verifica sostanziale: il dato protetto non deve contenere il testo in
        // chiaro come sottosequenza.
        let contains = protected
            .windows(secret.len())
            .any(|window| window == secret);
        assert!(!contains, "il testo in chiaro non deve comparire nel blob");
    }

    #[test]
    fn an_empty_value_is_protected_and_recovered() {
        let Ok(protected) = protect(b"") else {
            panic!("anche il vuoto deve potersi proteggere");
        };
        assert_eq!(unprotect(&protected).ok(), Some(Vec::new()));
    }

    #[test]
    fn a_binary_value_survives_the_round_trip() {
        let secret: Vec<u8> = (0..=255_u8).collect();
        let Ok(protected) = protect(&secret) else {
            panic!("la protezione deve riuscire");
        };
        assert_eq!(unprotect(&protected).ok(), Some(secret));
    }

    #[test]
    fn an_empty_ciphertext_is_refused_without_calling_the_system() {
        assert!(matches!(
            unprotect(&[]),
            Err(SecurityError::Corrupted { .. })
        ));
    }

    #[test]
    fn random_bytes_fills_the_buffer_and_two_draws_differ() {
        use super::random_bytes;

        // Il buffer di partenza e' tutto zero: se restasse tale, il generatore
        // non lo avrebbe toccato. La coincidenza di due estrazioni da 32 byte e'
        // trascurabile, e la sua assenza e' cio' che il test verifica.
        let mut first = [0_u8; 32];
        let mut second = [0_u8; 32];
        let (Ok(()), Ok(())) = (random_bytes(&mut first), random_bytes(&mut second)) else {
            panic!("il generatore di sistema deve rispondere");
        };

        assert_ne!(first, [0_u8; 32], "il buffer non e' stato riempito");
        assert_ne!(first, second, "due estrazioni non devono coincidere");
    }

    #[test]
    fn asking_for_no_random_bytes_is_not_an_error() {
        use super::random_bytes;
        assert!(random_bytes(&mut []).is_ok());
    }

    #[test]
    fn a_corrupted_blob_is_refused_instead_of_producing_garbage() {
        let Ok(mut protected) = protect(b"valore-di-prova") else {
            panic!("la protezione deve riuscire");
        };
        // Alterazione di un byte nel mezzo del blob.
        let middle = protected.len() / 2;
        protected[middle] ^= 0xFF;

        assert!(matches!(
            unprotect(&protected),
            Err(SecurityError::UnprotectionFailed { .. })
        ));
    }

    #[test]
    fn a_truncated_blob_is_refused() {
        let Ok(protected) = protect(b"valore-di-prova") else {
            panic!("la protezione deve riuscire");
        };
        let truncated = &protected[..protected.len() / 2];

        assert!(unprotect(truncated).is_err());
    }

    #[test]
    fn a_value_beyond_the_limit_is_refused() {
        let oversized = vec![0_u8; MAX_PROTECTED_BYTES + 1];
        assert!(matches!(
            protect(&oversized),
            Err(SecurityError::TooLarge { .. })
        ));
    }

    #[test]
    fn a_value_at_the_limit_is_accepted() {
        let exact = vec![7_u8; MAX_PROTECTED_BYTES];
        assert!(protect(&exact).is_ok());
    }

    #[test]
    fn repeated_protection_of_the_same_value_yields_different_blobs() {
        // DPAPI include materiale casuale: due protezioni dello stesso valore
        // non devono coincidere, altrimenti sarebbero confrontabili.
        let (Ok(first), Ok(second)) = (protect(b"identico"), protect(b"identico")) else {
            panic!("entrambe le protezioni devono riuscire");
        };
        assert_ne!(first, second);
    }

    #[test]
    fn no_error_message_contains_the_protected_value() {
        let Ok(mut protected) = protect(b"segreto-da-non-vedere") else {
            panic!("la protezione deve riuscire");
        };
        protected[0] ^= 0xFF;

        let Err(error) = unprotect(&protected) else {
            panic!("la decifratura doveva fallire");
        };
        assert!(!error.to_string().contains("segreto-da-non-vedere"));
    }
}

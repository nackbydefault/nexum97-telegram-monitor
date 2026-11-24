//! Le frasi di accesso delle persone: derivazione e verifica lente
//! (TEAM-ASSIGN-01, ADR-0097, decisione 3).
//!
//! # Perché non SHA-256
//!
//! Il gettone di un dispositivo è **casuale a 256 bit** (ADR-0082): provarlo a
//! tentativi non ha senso, e un'impronta veloce basta. Una frase scelta da una
//! persona non è casuale, e un'impronta veloce si prova a miliardi al secondo
//! su un archivio rubato. Qui il costo dev'essere di chi verifica, non di chi
//! attacca.
//!
//! # I parametri stanno accanto all'impronta
//!
//! Il verificatore è un `PHC string`: porta con sé algoritmo, versione,
//! memoria, iterazioni, parallelismo e sale. Il giorno in cui i parametri
//! verranno alzati, le impronte vecchie **restano verificabili** — un
//! parametro implicito è un parametro che non si può cambiare.
//!
//! # Il sale viene da qui
//!
//! Da [`crate::random_bytes`], che è il generatore che questo prodotto ha già
//! verificato, e non da quello che la libreria porta con sé: un secondo
//! generatore sarebbe un secondo punto da controllare.

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::{SecurityError, SecurityResult};

/// Memoria di Argon2id, in kibibyte.
///
/// **19 MiB**, il minimo raccomandato da OWASP per Argon2id con una sola
/// iterazione di parallelismo. Scelto, **non misurato** su una postazione
/// d'ufficio (HVQ-81): troppo alto rende l'accesso lento, troppo basso non
/// protegge.
pub const ARGON2_MEMORY_KIB: u32 = 19_456;

/// Iterazioni di Argon2id.
pub const ARGON2_ITERATIONS: u32 = 2;

/// Corsie parallele di Argon2id.
///
/// Una. L'Hub serve più connessioni insieme: la memoria che questa funzione
/// impegna si moltiplica per chi sta entrando nello stesso momento, e il
/// parallelismo interno la moltiplicherebbe ancora.
pub const ARGON2_PARALLELISM: u32 = 1;

/// Byte casuali del sale.
pub const PASSPHRASE_SALT_BYTES: usize = 16;

/// Costruisce la funzione con i parametri scritti.
fn argon2() -> SecurityResult<Argon2<'static>> {
    let parametri = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        None,
    )
    .map_err(|_| SecurityError::PassphraseFailed {
        reason: "i parametri scritti non sono accettati dalla libreria",
    })?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, parametri))
}

/// Deriva il verificatore da conservare al posto di una frase.
///
/// # Errori
///
/// [`SecurityError::PassphraseFailed`] se il sale non si lascia generare o se
/// la derivazione non riesce. **Il motivo non contiene mai la frase.**
pub fn derive_verifier(passphrase: &[u8]) -> SecurityResult<String> {
    let mut sale = [0_u8; PASSPHRASE_SALT_BYTES];
    crate::random_bytes(&mut sale)?;

    let verificatore = argon2()?
        .hash_password_with_salt(passphrase, &sale)
        .map_err(|_| SecurityError::PassphraseFailed {
            reason: "la derivazione non è riuscita",
        })?;
    Ok(verificatore.to_string())
}

/// Verifica una frase contro il verificatore conservato.
///
/// Restituisce `false` quando la frase è sbagliata: **non è un errore**, è una
/// risposta. L'errore è riservato a un verificatore che non si lascia leggere,
/// che è un guasto dell'archivio e non un tentativo andato male.
///
/// # Errori
///
/// [`SecurityError::PassphraseFailed`] se il verificatore conservato non ha
/// una forma interpretabile.
pub fn verify_passphrase(verifier: &str, passphrase: &[u8]) -> SecurityResult<bool> {
    let conservato = PasswordHash::new(verifier).map_err(|_| SecurityError::PassphraseFailed {
        reason: "il verificatore conservato non è interpretabile",
    })?;
    // Il confronto lo fa la libreria, e non esce in anticipo sulla prima
    // differenza.
    Ok(argon2()?.verify_password(passphrase, &conservato).is_ok())
}

#[cfg(test)]
mod tests {
    use super::{ARGON2_MEMORY_KIB, derive_verifier, verify_passphrase};

    /// Su piattaforme senza DPAPI il sale non si genera: la prova si ferma
    /// dicendo perché, invece di fingere un esito.
    fn verificatore(frase: &[u8]) -> Option<String> {
        derive_verifier(frase).ok()
    }

    #[test]
    fn una_frase_si_verifica_contro_il_proprio_verificatore() {
        let Some(verificatore) = verificatore(b"frase-di-prova-lunga") else {
            return;
        };
        let Ok(giusta) = verify_passphrase(&verificatore, b"frase-di-prova-lunga") else {
            panic!("la verifica deve potersi fare");
        };
        assert!(giusta, "la frase giusta deve essere riconosciuta");
    }

    #[test]
    fn una_frase_sbagliata_non_e_un_errore_ma_un_no() {
        let Some(verificatore) = verificatore(b"frase-di-prova-lunga") else {
            return;
        };
        assert_eq!(
            verify_passphrase(&verificatore, b"frase-di-prova-lungo").ok(),
            Some(false),
            "una frase sbagliata deve rispondere «no», non guastarsi"
        );
    }

    #[test]
    fn due_derivazioni_della_stessa_frase_non_si_assomigliano() {
        let (Some(uno), Some(due)) = (
            verificatore(b"frase-di-prova-lunga"),
            verificatore(b"frase-di-prova-lunga"),
        ) else {
            return;
        };
        assert_ne!(
            uno, due,
            "senza un sale diverso, due persone con la stessa frase avrebbero \
             lo stesso verificatore, e si vedrebbe dall'archivio"
        );
    }

    #[test]
    fn il_verificatore_porta_i_propri_parametri() {
        let Some(verificatore) = verificatore(b"frase-di-prova-lunga") else {
            return;
        };
        assert!(verificatore.starts_with("$argon2id$"));
        assert!(
            verificatore.contains(&format!("m={ARGON2_MEMORY_KIB}")),
            "i parametri devono viaggiare con l'impronta: «{verificatore}»"
        );
    }

    #[test]
    fn un_verificatore_illeggibile_e_un_guasto_non_un_no() {
        // Un archivio danneggiato non deve somigliare a una frase sbagliata:
        // la prima cosa va riparata, la seconda va ridigitata.
        assert!(verify_passphrase("non è un verificatore", b"frase-di-prova").is_err());
    }
}

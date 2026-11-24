//! La chiave privata dell'Hub, **conservata sotto DPAPI** (ADR-0083, decisione 3).
//!
//! # Che cosa fa questo modulo, e che cosa no
//!
//! Conserva e ricarica **byte opachi**: il PKCS#8 della chiave Ed25519 che il
//! trasporto (`lisi-hub-transport`) genera. Non genera la chiave, non la
//! analizza e non firma nulla: qui non entra alcuna libreria crittografica, e
//! la sola crate che nomina `ring` resta quella del trasporto (ADR-0083,
//! decisione 8).
//!
//! # Un file proprio
//!
//! La chiave dell'Hub sta in un file **distinto** dal segreto di dispositivo e
//! dalle credenziali Telegram (ADR-0046, ADR-0082 decisione 5): una postazione
//! che non fa da Hub non ha questo file, e chi ne copia uno non ottiene gli
//! altri. Il nome è [`HUB_KEY_FILE`]; la cartella la sceglie il chiamante.
//!
//! # Non si esporta, non si importa, non si mostra
//!
//! Il tipo [`HubKeyMaterial`] non ha `Display` né serializzazione, e il suo
//! `Debug` è redatto. Si mostra l'**impronta**, che calcola il trasporto.
//!
//! # Limite dichiarato
//!
//! Lo stesso di [`crate::account_key`]: la chiave transita come base64 dentro
//! l'archivio chiave/valore, e le copie interne a [`ProtectedStore`] e alla
//! libreria che firma non sono azzerabili da qui.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::account_key::{base64_decode, base64_encode, zeroize_string};
use crate::error::{SecurityError, SecurityResult};
use crate::store::ProtectedStore;

/// Nome del file che custodisce la chiave dell'Hub.
pub const HUB_KEY_FILE: &str = "hub.protetto";

/// Nome della voce nell'archivio protetto. Costante di formato, non un segreto.
const HUB_KEY_ENTRY: &str = "hub_ed25519_pkcs8";

/// Dimensione massima accettata, in byte.
///
/// Un PKCS#8 Ed25519 occupa poco più di ottanta byte. Il tetto esiste perché un
/// file danneggiato o sostituito non faccia allocare quanto dice di contenere.
const HUB_KEY_MAX_BYTES: usize = 256;

/// Il materiale della chiave privata dell'Hub, in chiaro, in memoria.
///
/// `Debug` è redatto, `Display` non esiste, nessuna serializzazione: l'unica
/// via per leggere il valore è [`Self::expose_secret`], dal nome scomodo.
pub struct HubKeyMaterial {
    bytes: Vec<u8>,
}

impl HubKeyMaterial {
    /// Prende possesso dei byte forniti dal trasporto.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Espone il materiale in chiaro. Non passarlo mai a una macro di log.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.bytes
    }
}

impl core::fmt::Debug for HubKeyMaterial {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("HubKeyMaterial(«redatto»)")
    }
}

impl Drop for HubKeyMaterial {
    fn drop(&mut self) {
        // Sovrascrittura best-effort: vedere il limite dichiarato del modulo.
        self.bytes.fill(0);
        let _ = core::hint::black_box(&self.bytes);
    }
}

/// Conserva una chiave dell'Hub **nuova** sotto DPAPI.
///
/// **Rifiuta di sovrascrivere** una chiave esistente: cambiare la chiave
/// dell'Hub è l'atto visibile di ADR-0082 decisione 5, che costringe ogni
/// postazione a ricevere una nuova impronta fuori banda. Non deve poter
/// accadere come effetto collaterale di una seconda attivazione.
///
/// # Errori
///
/// [`SecurityError::Corrupted`] se esiste già una chiave in quel percorso o se
/// il materiale è vuoto o fuori misura; gli errori di DPAPI e di scrittura di
/// [`ProtectedStore::save`].
pub fn store_new_hub_key(store_path: PathBuf, material: &HubKeyMaterial) -> SecurityResult<()> {
    let store = ProtectedStore::at(store_path);
    if store.exists() {
        return Err(SecurityError::Corrupted {
            reason: "esiste già una chiave dell'Hub: cambiarla è un atto a sé",
        });
    }
    if material.bytes.is_empty() || material.bytes.len() > HUB_KEY_MAX_BYTES {
        return Err(SecurityError::Corrupted {
            reason: "il materiale della chiave dell'Hub non ha una misura plausibile",
        });
    }

    let mut entries = BTreeMap::new();
    entries.insert(String::from(HUB_KEY_ENTRY), base64_encode(&material.bytes));
    let outcome = store.save(&entries);
    if let Some(encoded) = entries.remove(HUB_KEY_ENTRY) {
        zeroize_string(encoded);
    }
    outcome
}

/// Ricarica la chiave dell'Hub.
///
/// # Errori
///
/// [`SecurityError::NotConfigured`] se questa postazione non ha una chiave
/// dell'Hub, [`SecurityError::UnprotectionFailed`] se il file non è decifrabile
/// con il profilo corrente, [`SecurityError::Corrupted`] se il contenuto non è
/// plausibile.
pub fn load_hub_key(store_path: PathBuf) -> SecurityResult<HubKeyMaterial> {
    let store = ProtectedStore::at(store_path);
    let encoded = store.load_entry(HUB_KEY_ENTRY)?;
    if encoded.len() > HUB_KEY_MAX_BYTES.div_ceil(3) * 4 {
        zeroize_string(encoded);
        return Err(SecurityError::Corrupted {
            reason: "la chiave dell'Hub conservata è fuori misura",
        });
    }
    let decoded = base64_decode(&encoded);
    zeroize_string(encoded);

    match decoded {
        Some(bytes) if !bytes.is_empty() => Ok(HubKeyMaterial::from_bytes(bytes)),
        Some(_) => Err(SecurityError::Corrupted {
            reason: "la chiave dell'Hub conservata è vuota",
        }),
        None => Err(SecurityError::Corrupted {
            reason: "la chiave dell'Hub non è codificata correttamente",
        }),
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::{HUB_KEY_FILE, HubKeyMaterial, base64_encode, load_hub_key, store_new_hub_key};
    use crate::error::SecurityError;

    fn cartella() -> tempfile::TempDir {
        match tempfile::tempdir() {
            Ok(cartella) => cartella,
            Err(errore) => panic!("cartella temporanea: {errore}"),
        }
    }

    fn contiene(pagliaio: &[u8], ago: &[u8]) -> bool {
        pagliaio.windows(ago.len()).any(|finestra| finestra == ago)
    }

    #[test]
    fn the_key_round_trips_under_dpapi_and_is_not_stored_in_clear() {
        let cartella = cartella();
        let percorso = cartella.path().join(HUB_KEY_FILE);
        let segreto: Vec<u8> = (0_u8..83)
            .map(|valore| valore.wrapping_mul(37) ^ 0x5A)
            .collect();

        if let Err(errore) = store_new_hub_key(
            percorso.clone(),
            &HubKeyMaterial::from_bytes(segreto.clone()),
        ) {
            panic!("la chiave deve potersi conservare: {errore}");
        }

        // Il file non contiene il materiale in chiaro, in nessuna delle due forme.
        let Ok(sul_disco) = std::fs::read(&percorso) else {
            panic!("il file protetto deve esistere");
        };
        assert!(!contiene(&sul_disco, &segreto));
        assert!(!contiene(&sul_disco, base64_encode(&segreto).as_bytes()));

        let Ok(riletta) = load_hub_key(percorso) else {
            panic!("la chiave conservata deve ricaricarsi");
        };
        assert_eq!(riletta.expose_secret(), segreto.as_slice());
        assert_eq!(format!("{riletta:?}"), "HubKeyMaterial(«redatto»)");
    }

    #[test]
    fn an_existing_key_is_never_overwritten() {
        let cartella = cartella();
        let percorso = cartella.path().join(HUB_KEY_FILE);
        assert!(
            store_new_hub_key(percorso.clone(), &HubKeyMaterial::from_bytes(vec![1; 83])).is_ok()
        );

        assert!(matches!(
            store_new_hub_key(percorso.clone(), &HubKeyMaterial::from_bytes(vec![2; 83])),
            Err(SecurityError::Corrupted { .. })
        ));
        let Ok(riletta) = load_hub_key(percorso) else {
            panic!("la prima chiave deve restare");
        };
        assert_eq!(riletta.expose_secret(), [1_u8; 83].as_slice());
    }

    #[test]
    fn a_missing_or_implausible_key_is_refused() {
        let cartella = cartella();
        assert!(matches!(
            load_hub_key(cartella.path().join(HUB_KEY_FILE)),
            Err(SecurityError::NotConfigured)
        ));
        for misura in [0_usize, 257] {
            assert!(matches!(
                store_new_hub_key(
                    cartella.path().join(format!("{misura}.protetto")),
                    &HubKeyMaterial::from_bytes(vec![7; misura])
                ),
                Err(SecurityError::Corrupted { .. })
            ));
        }
    }
}

//! La chiave dell'Hub: Ed25519, generata sull'Hub (ADR-0083, decisione 3).
//!
//! # Perché Ed25519
//!
//! Firme **deterministiche**: al momento della firma non serve alcun numero
//! casuale, quindi nessun generatore debole può rovinarla. Il caso serve una
//! volta sola, alla generazione, e viene dal generatore del sistema.
//!
//! # Dove vive
//!
//! In memoria qui, il PKCS#8 in chiaro solo il tempo necessario. Sul disco
//! sotto DPAPI, in `hub.protetto`, attraverso `lisi_security::hub_key`: questa
//! crate non scrive file.
//!
//! # Che cosa si mostra
//!
//! Mai la chiave. Si mostra l'**impronta** ([`HubKey::fingerprint`]): la forma a
//! 24 cifre per il foglietto, quella intera per chi amministra.

use std::sync::Arc;

use lisi_core::model::hub_identity::HubFingerprint;
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use rustls::SignatureAlgorithm;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::{CertifiedKey, SigningKey};

use crate::error::{TransportError, TransportResult};

/// La chiave privata dell'Hub, pronta a firmare handshake.
pub struct HubKey {
    pkcs8: Vec<u8>,
    signing: Arc<dyn SigningKey>,
    public_key_info: Vec<u8>,
}

impl HubKey {
    /// Genera una chiave nuova con il generatore del sistema.
    ///
    /// Va chiamata **una volta**, quando una persona attiva la modalità Hub, e
    /// il risultato va conservato sotto DPAPI prima di essere usato: una chiave
    /// usata e poi persa è un Hub che nessuna postazione riconoscerà più.
    ///
    /// # Errori
    ///
    /// [`TransportError::RandomUnavailable`] se il generatore rifiuta.
    pub fn generate() -> TransportResult<Self> {
        let documento = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| TransportError::RandomUnavailable)?;
        Self::from_pkcs8(documento.as_ref())
    }

    /// Ricostruisce la chiave dal PKCS#8 conservato.
    ///
    /// # Errori
    ///
    /// [`TransportError::KeyRejected`] se i byte non sono un PKCS#8 Ed25519
    /// coerente — anche se fossero una chiave valida di un altro algoritmo.
    pub fn from_pkcs8(pkcs8: &[u8]) -> TransportResult<Self> {
        // `from_pkcs8` di ring verifica anche che la chiave pubblica inclusa
        // corrisponda alla privata: un file manomesso che accoppiasse le due
        // parti di chiavi diverse viene rifiutato qui, non al primo handshake.
        Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| TransportError::KeyRejected {
            reason: "non è una chiave valida per questo uso",
        })?;

        let signing = default_provider()
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                pkcs8.to_vec(),
            )))
            .map_err(|_| TransportError::KeyRejected {
                reason: "il collegamento cifrato non accetta la chiave",
            })?;
        if signing.algorithm() != SignatureAlgorithm::ED25519 {
            return Err(TransportError::KeyRejected {
                reason: "la chiave dell'Hub deve essere Ed25519",
            });
        }
        // La `SubjectPublicKeyInfo` si prende dalla chiave che firmerà: è
        // esattamente ciò che viaggerà nell'handshake, e quindi ciò di cui il
        // client calcolerà l'impronta.
        let public_key_info = signing
            .public_key()
            .map(|spki| spki.as_ref().to_vec())
            .ok_or(TransportError::KeyRejected {
                reason: "la chiave non espone la propria parte pubblica",
            })?;

        Ok(Self {
            pkcs8: pkcs8.to_vec(),
            signing,
            public_key_info,
        })
    }

    /// Il PKCS#8 in chiaro, **da consegnare soltanto alla protezione DPAPI**.
    ///
    /// Il nome è scomodo apposta. Non si esporta, non si mostra, non si scrive
    /// altrove.
    #[must_use]
    pub fn pkcs8_for_protection(&self) -> &[u8] {
        &self.pkcs8
    }

    /// La `SubjectPublicKeyInfo` in DER: ciò che l'Hub presenta.
    #[must_use]
    pub fn public_key_info(&self) -> &[u8] {
        &self.public_key_info
    }

    /// L'impronta che le postazioni confrontano.
    #[must_use]
    pub fn fingerprint(&self) -> HubFingerprint {
        HubFingerprint::of_public_key_info(&self.public_key_info)
    }

    /// La coppia «chiave nuda + chiave che firma» per il server.
    pub(crate) fn certified_key(&self) -> Arc<CertifiedKey> {
        Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(self.public_key_info.clone())],
            Arc::clone(&self.signing),
        ))
    }
}

impl core::fmt::Debug for HubKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // L'impronta non è un segreto e aiuta a capire quale chiave si ha in
        // mano; il PKCS#8 non compare.
        write!(formatter, "HubKey({:?})", self.fingerprint())
    }
}

impl Drop for HubKey {
    fn drop(&mut self) {
        // Best-effort, come per gli altri segreti del prodotto: la copia dentro
        // la libreria che firma non è raggiungibile da qui (limite dichiarato
        // in ADR-0083).
        self.pkcs8.fill(0);
        let _ = core::hint::black_box(&self.pkcs8);
    }
}

#[cfg(test)]
mod tests {
    use super::HubKey;

    fn nuova() -> HubKey {
        match HubKey::generate() {
            Ok(chiave) => chiave,
            Err(errore) => panic!("la chiave deve potersi generare: {errore}"),
        }
    }

    #[test]
    fn a_generated_key_reloads_with_the_same_fingerprint() {
        let chiave = nuova();
        let Ok(riletta) = HubKey::from_pkcs8(chiave.pkcs8_for_protection()) else {
            panic!("il PKCS#8 conservato deve ricaricarsi");
        };
        assert_eq!(riletta.fingerprint(), chiave.fingerprint());
        assert_eq!(riletta.public_key_info(), chiave.public_key_info());
    }

    #[test]
    fn two_generated_keys_differ() {
        assert_ne!(nuova().fingerprint(), nuova().fingerprint());
    }

    #[test]
    fn the_public_key_info_is_an_ed25519_spki() {
        // RFC 8410: SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING (32 byte) }.
        let chiave = nuova();
        let spki = chiave.public_key_info();
        assert_eq!(spki.len(), 44);
        assert_eq!(
            &spki[..12],
            &[
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
            ]
        );
    }

    #[test]
    fn garbage_and_tampered_keys_are_refused() {
        assert!(HubKey::from_pkcs8(&[]).is_err());
        assert!(HubKey::from_pkcs8(&[0x30; 83]).is_err());

        // Un solo byte cambiato nella parte pubblica inclusa: ring deve
        // accorgersi che non corrisponde più alla privata.
        let chiave = nuova();
        let mut manomessa = chiave.pkcs8_for_protection().to_vec();
        let ultimo = manomessa.len() - 1;
        manomessa[ultimo] ^= 0x01;
        assert!(HubKey::from_pkcs8(&manomessa).is_err());
    }

    #[test]
    fn debug_never_shows_the_private_key() {
        let chiave = nuova();
        let resa = format!("{chiave:?}");
        assert!(resa.starts_with("HubKey(HubFingerprint("));
        assert!(!resa.contains("pkcs8"));
    }
}

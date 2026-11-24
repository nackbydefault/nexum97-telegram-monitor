//! Il verificatore dell'Hub: **l'impronta e la firma, entrambe** (ADR-0083,
//! decisione 4).
//!
//! # Perché questo file esiste, e perché è l'unico
//!
//! rustls installa un verificatore proprio solo passando dal ramo
//! `.dangerous()`, ed è giusto che si chiami così: **è il punto in cui un errore
//! rende la connessione non autenticata e nessuno se ne accorge.** È quindi
//! l'unico file del prodotto scritto nell'elenco `CHI_PUO_SOSPENDERE` di
//! `hub_trust_guard`, e la costruzione della configurazione del client sta
//! **qui**, accanto al confronto, e non altrove.
//!
//! # Le due verifiche
//!
//! 1. [`HubKeyVerifier::verify_server_cert`] calcola `SHA-256` della
//!    `SubjectPublicKeyInfo` presentata e la confronta con ciò che la postazione
//!    sa dell'Hub, senza uscire in anticipo alla prima differenza.
//! 2. [`HubKeyVerifier::verify_tls13_signature`] verifica la firma
//!    dell'handshake con **quella** chiave. È la firma a dimostrare che l'altro
//!    capo possiede la privata: senza, l'impronta dimostrerebbe soltanto che
//!    qualcuno conosce una chiave pubblica, che è un dato pubblico.
//!
//! TLS 1.2 non è abilitato, e il suo ramo **rifiuta sempre**: un ramo che non
//! deve accadere non restituisce «valido».
//!
//! # Che cosa il verificatore non guarda, di proposito
//!
//! - **Le date**: una chiave nuda non ne ha, e nessuna decisione di fiducia
//!   dipende dall'orologio (ADR-0083, decisione 6).
//! - **Il nome del server**: l'Hub è riconosciuto dalla chiave, non
//!   dall'indirizzo, che in una LAN cambia.
//! - **Le risposte OCSP**: la revoca della chiave dell'Hub è una chiave nuova
//!   portata fuori banda (ADR-0082, decisione 5).

use std::sync::Arc;

use lisi_core::model::hub_identity::{HubExpectation, HubFingerprint};
use rustls::client::Resumption;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature_with_raw_key};
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::version::TLS13;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error, PeerIncompatible, PeerMisbehaved,
    SignatureScheme,
};

use crate::HUB_ALPN;
use crate::error::{TransportError, TransportResult};

/// Il verificatore che riconosce l'Hub dalla chiave.
#[derive(Debug)]
pub(crate) struct HubKeyVerifier {
    expected: HubExpectation,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for HubKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // Con le chiavi nude non esiste una catena: qualcosa in più è un altro
        // protocollo, non un Hub.
        if !intermediates.is_empty() {
            return Err(Error::InvalidCertificate(CertificateError::BadEncoding));
        }

        // IL CONFRONTO DELL'IMPRONTA. `accepts` non esce in anticipo.
        let presented = HubFingerprint::of_public_key_info(end_entity.as_ref());
        if self.expected.accepts(&presented) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // TLS 1.2 non è abilitato: se questo ramo venisse raggiunto sarebbe un
        // difetto, e un difetto non restituisce «valido».
        Err(Error::PeerIncompatible(PeerIncompatible::Tls12NotOffered))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // La chiave dell'Hub è Ed25519 (ADR-0083, decisione 3): uno schema
        // diverso non è l'Hub, qualunque cosa dica l'impronta.
        if dss.scheme != SignatureScheme::ED25519 {
            return Err(Error::PeerMisbehaved(
                PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
            ));
        }
        // LA VERIFICA DELLA FIRMA, con la chiave appena riconosciuta.
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// La configurazione del client verso l'Hub atteso.
///
/// Solo TLS 1.3, provider ring, verificatore dell'Hub, ALPN obbligatorio,
/// nessuna ripresa di sessione, nessun 0-RTT, nessun SNI.
pub(crate) fn client_config(expected: HubExpectation) -> TransportResult<Arc<ClientConfig>> {
    let provider = Arc::new(default_provider());
    let verifier = Arc::new(HubKeyVerifier {
        expected,
        algorithms: provider.signature_verification_algorithms,
    });

    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .map_err(|_| TransportError::Configuration)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    config.alpn_protocols = vec![HUB_ALPN.to_vec()];
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    config.enable_sni = false;
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use lisi_core::model::hub_identity::{HubExpectation, HubFingerprint};
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    use super::{HubKeyVerifier, client_config};
    use crate::key::HubKey;

    fn verificatore(atteso: HubExpectation) -> HubKeyVerifier {
        HubKeyVerifier {
            expected: atteso,
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }

    fn chiave() -> HubKey {
        match HubKey::generate() {
            Ok(chiave) => chiave,
            Err(errore) => panic!("chiave: {errore}"),
        }
    }

    fn verifica(
        verificatore: &HubKeyVerifier,
        spki: &[u8],
        intermedi: &[CertificateDer<'_>],
    ) -> bool {
        let Ok(nome) = ServerName::try_from("192.0.2.1") else {
            panic!("indirizzo di prova");
        };
        verificatore
            .verify_server_cert(
                &CertificateDer::from(spki),
                intermedi,
                &nome,
                &[],
                UnixTime::now(),
            )
            .is_ok()
    }

    #[test]
    fn the_fingerprint_decides_both_at_enrollment_and_after() {
        let hub = chiave();
        let estraneo = chiave();

        let fissato = verificatore(HubExpectation::Pinned(hub.fingerprint()));
        assert!(verifica(&fissato, hub.public_key_info(), &[]));
        assert!(!verifica(&fissato, estraneo.public_key_info(), &[]));

        let foglietto = verificatore(HubExpectation::Enrollment(hub.fingerprint().prefix()));
        assert!(verifica(&foglietto, hub.public_key_info(), &[]));
        assert!(!verifica(&foglietto, estraneo.public_key_info(), &[]));
    }

    #[test]
    fn a_chain_is_not_a_raw_key() {
        let hub = chiave();
        let verificatore = verificatore(HubExpectation::Pinned(hub.fingerprint()));
        let intermedio = CertificateDer::from(hub.public_key_info());
        assert!(!verifica(
            &verificatore,
            hub.public_key_info(),
            &[intermedio]
        ));
    }

    #[test]
    fn garbage_is_simply_another_fingerprint() {
        let hub = chiave();
        let verificatore = verificatore(HubExpectation::Pinned(hub.fingerprint()));
        assert!(!verifica(&verificatore, &[], &[]));
        assert!(!verifica(&verificatore, &[0xFF; 4096], &[]));
        let _ = HubFingerprint::of_public_key_info(&[]);
    }

    #[test]
    fn only_raw_ed25519_keys_are_accepted() {
        let hub = chiave();
        let verificatore = verificatore(HubExpectation::Pinned(hub.fingerprint()));
        assert!(verificatore.requires_raw_public_keys());
        assert_eq!(
            verificatore.supported_verify_schemes(),
            vec![rustls::SignatureScheme::ED25519]
        );
    }

    #[test]
    fn the_client_configuration_leaves_no_second_path() {
        let hub = chiave();
        let Ok(config) = client_config(HubExpectation::Pinned(hub.fingerprint())) else {
            panic!("la configurazione deve costruirsi");
        };
        assert_eq!(config.alpn_protocols, vec![crate::HUB_ALPN.to_vec()]);
        assert!(!config.enable_early_data);
        assert!(!config.enable_sni);
    }
}

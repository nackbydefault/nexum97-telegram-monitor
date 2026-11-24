//! Il protocollo sopra il trasporto vero: TLS verificato, handshake
//! applicativo, un frame per parte (HUB-PROTO-01, ADR-0084).
//!
//! Le prove di dettaglio stanno accanto al codice, su flussi in memoria; qui si
//! verifica che i pezzi si parlino attraverso un socket e un TLS reali, su
//! loopback. **Nessuna seconda macchina** (HVQ-08).

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use lisi_core::model::enrollment::{DeviceToken, EnrollmentSalt};
use lisi_core::model::hub_identity::HubExpectation;
use lisi_core::model::identity::{DeviceId, DeviceSecret};
use lisi_hub_transport::protocol::frame::{FrameError, read_frame, write_frame};
use lisi_hub_transport::protocol::handshake::{
    AuthDecision, ClientOffer, HandshakeError, HubOffer, RefusalReason, client_handshake,
    hub_handshake,
};
use lisi_hub_transport::protocol::negotiation::{MAX_SUPPORTED_VERSION, VersionRange};
use lisi_hub_transport::{ClientLimits, HubKey, HubListener, HubServer, ServerLimits, connect};

const LOOPBACK: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

fn chiave() -> HubKey {
    match HubKey::generate() {
        Ok(chiave) => chiave,
        Err(errore) => panic!("chiave: {errore}"),
    }
}

fn dispositivo() -> DeviceId {
    DeviceId::from_random_bytes(&[5; 15])
}

fn gettone(segreto: u8) -> DeviceToken {
    DeviceToken::derive(
        &EnrollmentSalt::from_random_bytes(&[1; 16]),
        &DeviceSecret::from_random_bytes([segreto; 32]),
    )
}

/// Un Hub che conosce un solo gettone, risponde a un frame con lo stesso
/// frame, e riferisce l'esito del proprio handshake.
fn hub(
    chiave: &HubKey,
    offerta: HubOffer,
) -> (HubServer, mpsc::Receiver<Result<u16, HandshakeError>>) {
    let (invia, ricevi) = mpsc::channel();
    let Ok(ascolto) = HubListener::bind(LOOPBACK, chiave, ServerLimits::default()) else {
        panic!("ascolto");
    };
    let atteso = gettone(7).verifier();
    let Ok(server) = ascolto.serve(move |mut canale| {
        let esito = hub_handshake(&mut canale, &offerta, |_, presentato| {
            if presentato.verifier() == atteso {
                AuthDecision::Accepted
            } else {
                AuthDecision::NotRecognized
            }
        });
        let _ = invia.send(esito.clone().map(|accettato| accettato.negotiated.version));
        if esito.is_ok() {
            let scadenza = Instant::now() + Duration::from_secs(2);
            if let Ok(frame) = read_frame(&mut canale, 1024, scadenza) {
                let _ = write_frame(&mut canale, &frame, 1024);
            }
        }
        canale.close();
    }) else {
        panic!("avvio");
    };
    (server, ricevi)
}

#[test]
fn a_device_with_the_right_token_completes_the_handshake_and_exchanges_a_frame() {
    let chiave = chiave();
    let (server, esiti) = hub(&chiave, HubOffer::default());
    let Ok(mut canale) = connect(
        server.local_addr(),
        HubExpectation::Pinned(chiave.fingerprint()),
        &ClientLimits::default(),
    ) else {
        panic!("TLS");
    };

    let accordo = client_handshake(
        &mut canale,
        &dispositivo(),
        &gettone(7),
        &ClientOffer::default(),
    );
    // La versione e' la piu' alta in comune, e le due estremita' sono questo
    // stesso programma: non si scrive un numero a mano, che scadrebbe alla
    // prima versione nuova (ADR-0084).
    assert_eq!(accordo.map(|a| a.version), Ok(MAX_SUPPORTED_VERSION));
    assert_eq!(
        esiti.recv_timeout(Duration::from_secs(5)),
        Ok(Ok(MAX_SUPPORTED_VERSION))
    );

    assert_eq!(write_frame(&mut canale, b"primo messaggio", 1024), Ok(()));
    let _ = canale.flush();
    assert_eq!(
        read_frame(&mut canale, 1024, Instant::now() + Duration::from_secs(2)),
        Ok(b"primo messaggio".to_vec())
    );
    canale.close();
    server.stop();
}

#[test]
fn a_wrong_token_is_refused_without_saying_why() {
    let chiave = chiave();
    let (server, esiti) = hub(&chiave, HubOffer::default());
    let Ok(mut canale) = connect(
        server.local_addr(),
        HubExpectation::Pinned(chiave.fingerprint()),
        &ClientLimits::default(),
    ) else {
        panic!("TLS");
    };
    let esito = client_handshake(
        &mut canale,
        &dispositivo(),
        &gettone(8),
        &ClientOffer::default(),
    );
    assert_eq!(
        esito,
        Err(HandshakeError::Refused {
            reason: RefusalReason::NotRecognized,
            hub_versions: VersionRange::SUPPORTED
        })
    );
    assert!(matches!(
        esiti.recv_timeout(Duration::from_secs(5)),
        Ok(Err(HandshakeError::Refused { .. }))
    ));
    // Dopo il rifiuto l'Hub non ascolta altro su quella connessione.
    let _ = write_frame(&mut canale, b"insisto", 1024);
    assert!(matches!(
        read_frame(&mut canale, 1024, Instant::now() + Duration::from_secs(2)),
        Err(FrameError::Closed | FrameError::Io(_))
    ));
    server.stop();
}

#[test]
fn a_hub_of_another_generation_is_refused_with_its_versions() {
    let chiave = chiave();
    let (server, _esiti) = hub(
        &chiave,
        HubOffer {
            versions: VersionRange {
                min: MAX_SUPPORTED_VERSION + 1,
                max: MAX_SUPPORTED_VERSION + 2,
            },
            ..HubOffer::default()
        },
    );
    let Ok(mut canale) = connect(
        server.local_addr(),
        HubExpectation::Pinned(chiave.fingerprint()),
        &ClientLimits::default(),
    ) else {
        panic!("TLS");
    };
    let esito = client_handshake(
        &mut canale,
        &dispositivo(),
        &gettone(7),
        &ClientOffer::default(),
    );
    assert_eq!(
        esito,
        Err(HandshakeError::Refused {
            reason: RefusalReason::UnsupportedVersion,
            hub_versions: VersionRange {
                min: MAX_SUPPORTED_VERSION + 1,
                max: MAX_SUPPORTED_VERSION + 2
            }
        })
    );
    server.stop();
}

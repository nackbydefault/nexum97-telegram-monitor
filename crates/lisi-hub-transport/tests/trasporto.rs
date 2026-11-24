//! Le prove del trasporto, su loopback (ADR-0083, decisione 4).
//!
//! # Le tre prove che la decisione impone
//!
//! - **la chiave sbagliata** → «l'Hub non è quello atteso»;
//! - **la chiave pubblica giusta senza la privata** → rifiutata: è la prova che
//!   la **firma** viene verificata, non solo l'impronta;
//! - **il verificatore è l'unica cosa che ferma**: non è una prova del
//!   repository. Il verificatore permissivo esiste **solo** dentro il controllo
//!   negativo, eseguito e annotato nell'handoff, e mai scritto qui — altrimenti
//!   sarebbe la chiave di scorta che ADR-0082 vieta.
//!
//! # Gli impostori
//!
//! Un impostore è un **server** ostile costruito direttamente con rustls: non
//! indebolisce alcuna verifica, simula chi sta dall'altra parte. Nessuna prova
//! usa un client che salti il confronto.
//!
//! # Limite dichiarato
//!
//! Tutto gira su `127.0.0.1` di una sola macchina (HVQ-08, POC-08).

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use lisi_core::model::hub_identity::HubExpectation;
use lisi_hub_transport::{
    ClientLimits, ConnectOutcome, HUB_ALPN, HubKey, HubListener, HubServer, ServerLimits,
    TransportError, connect,
};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::sign::CertifiedKey;
use rustls::version::TLS13;
use rustls::{ServerConfig, ServerConnection};

const LOOPBACK: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

fn chiave() -> HubKey {
    match HubKey::generate() {
        Ok(chiave) => chiave,
        Err(errore) => panic!("la chiave deve potersi generare: {errore}"),
    }
}

fn limiti_brevi() -> ClientLimits {
    ClientLimits {
        connect_timeout: Duration::from_secs(2),
        handshake_timeout: Duration::from_secs(2),
        io_timeout: Duration::from_secs(5),
    }
}

/// Un Hub vero che rimanda indietro cinque byte.
fn hub_che_risponde(chiave: &HubKey, limiti: ServerLimits) -> HubServer {
    let Ok(ascolto) = HubListener::bind(LOOPBACK, chiave, limiti) else {
        panic!("l'Hub deve poter ascoltare su loopback");
    };
    let Ok(server) = ascolto.serve(|mut canale| {
        let mut ricevuti = [0_u8; 5];
        if canale.read_exact(&mut ricevuti).is_ok() {
            let _ = canale.write_all(&ricevuti);
            let _ = canale.flush();
        }
        canale.close();
    }) else {
        panic!("l'Hub deve partire");
    };
    server
}

fn eco(indirizzo: SocketAddr, atteso: HubExpectation) -> Result<[u8; 5], TransportError> {
    let mut canale = connect(indirizzo, atteso, &limiti_brevi())?;
    let Ok(()) = canale.write_all(b"ciao!") else {
        panic!("scrittura sul canale verificato");
    };
    let mut risposta = [0_u8; 5];
    let Ok(()) = canale.read_exact(&mut risposta) else {
        panic!("lettura sul canale verificato");
    };
    canale.close();
    Ok(risposta)
}

/// Un server impostore costruito con rustls: presenta `spki` e firma con
/// `firma`, annunciando `alpn`. Serve una connessione e si ferma.
fn impostore(spki: &[u8], firma: &HubKey, alpn: &[u8]) -> (SocketAddr, JoinHandle<()>) {
    let provider = Arc::new(default_provider());
    let Ok(chiave_che_firma) =
        provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                firma.pkcs8_for_protection().to_vec(),
            )))
    else {
        panic!("la chiave dell'impostore deve caricarsi");
    };
    // `CertifiedKey::new` NON controlla che le due parti combacino: è proprio
    // ciò che serve a un impostore.
    let coppia = Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(spki.to_vec())],
        chiave_che_firma,
    ));
    let Ok(costruttore) =
        ServerConfig::builder_with_provider(provider).with_protocol_versions(&[&TLS13])
    else {
        panic!("configurazione dell'impostore");
    };
    let mut config = costruttore
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(coppia)));
    config.alpn_protocols = vec![alpn.to_vec()];
    let config = Arc::new(config);

    let Ok(ascolto) = TcpListener::bind(LOOPBACK) else {
        panic!("l'impostore deve poter ascoltare");
    };
    let Ok(indirizzo) = ascolto.local_addr() else {
        panic!("indirizzo dell'impostore");
    };
    let filo = std::thread::spawn(move || {
        let Ok((mut tcp, _)) = ascolto.accept() else {
            return;
        };
        let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
        let Ok(mut connessione) = ServerConnection::new(config) else {
            return;
        };
        while connessione.is_handshaking() {
            if connessione.complete_io(&mut tcp).is_err() {
                return;
            }
        }
        let mut ricevuti = [0_u8; 5];
        let mut canale = rustls::Stream::new(&mut connessione, &mut tcp);
        if canale.read_exact(&mut ricevuti).is_ok() {
            let _ = canale.write_all(&ricevuti);
        }
    });
    (indirizzo, filo)
}

/// Un server TCP che accetta e non dice nulla, o dice qualcosa che non è TLS.
fn server_grezzo(risposta: Option<&'static [u8]>, silenzio: Duration) -> SocketAddr {
    let Ok(ascolto) = TcpListener::bind(LOOPBACK) else {
        panic!("server grezzo");
    };
    let Ok(indirizzo) = ascolto.local_addr() else {
        panic!("indirizzo del server grezzo");
    };
    std::thread::spawn(move || {
        let Ok((mut tcp, _)) = ascolto.accept() else {
            return;
        };
        if let Some(testo) = risposta {
            let _ = tcp.write_all(testo);
        }
        std::thread::sleep(silenzio);
    });
    indirizzo
}

// ---------------------------------------------------------------------------
// L'Hub atteso
// ---------------------------------------------------------------------------

#[test]
fn the_expected_hub_is_reached_both_at_enrollment_and_after() {
    let hub = chiave();
    let server = hub_che_risponde(&hub, ServerLimits::default());

    // Dopo: tutti i 256 bit.
    let Ok(risposta) = eco(
        server.local_addr(),
        HubExpectation::Pinned(hub.fingerprint()),
    ) else {
        panic!("l'Hub atteso deve rispondere");
    };
    assert_eq!(&risposta, b"ciao!");

    // All'arruolamento: i 120 bit del foglietto, riletti dalla forma leggibile.
    let Ok(foglietto) = lisi_core::model::hub_identity::HubFingerprintPrefix::parse(
        &hub.fingerprint().prefix().to_readable().to_lowercase(),
    ) else {
        panic!("la forma del foglietto deve rileggersi");
    };
    let Ok(mut canale) = connect(
        server.local_addr(),
        HubExpectation::Enrollment(foglietto),
        &limiti_brevi(),
    ) else {
        panic!("l'arruolamento deve raggiungere l'Hub del foglietto");
    };
    // La postazione ora conosce l'impronta intera, da conservare.
    assert_eq!(canale.hub_fingerprint(), hub.fingerprint());
    let _ = canale.write_all(b"ciao!");
    let mut risposta = [0_u8; 5];
    let _ = canale.read_exact(&mut risposta);
    canale.close();

    server.stop();
}

// ---------------------------------------------------------------------------
// Le tre prove di ADR-0083 decisione 4
// ---------------------------------------------------------------------------

/// **La chiave sbagliata** → l'Hub non è quello atteso, e non si riprova.
#[test]
fn a_hub_with_another_key_is_not_the_expected_hub() {
    let atteso = chiave();
    let estraneo = chiave();
    let server = hub_che_risponde(&estraneo, ServerLimits::default());

    for aspettativa in [
        HubExpectation::Pinned(atteso.fingerprint()),
        HubExpectation::Enrollment(atteso.fingerprint().prefix()),
    ] {
        let Err(errore) = eco(server.local_addr(), aspettativa) else {
            panic!("un Hub con un'altra chiave NON deve essere raggiunto");
        };
        assert!(
            matches!(errore, TransportError::NotTheExpectedHub),
            "esito sbagliato: {errore:?}"
        );
        assert_eq!(errore.outcome(), ConnectOutcome::NotTheExpectedHub);
    }
    server.stop();
}

/// **La chiave pubblica giusta senza la privata** → rifiutata.
///
/// L'impostore presenta la `SubjectPublicKeyInfo` dell'Hub vero — l'impronta
/// quindi coincide — ma firma l'handshake con un'altra chiave. Se questa prova
/// passa, è la **firma** che viene verificata.
#[test]
fn the_right_public_key_signed_with_the_wrong_private_key_is_refused() {
    let vero = chiave();
    let altra = chiave();
    let (indirizzo, filo) = impostore(vero.public_key_info(), &altra, HUB_ALPN);

    let esito = eco(indirizzo, HubExpectation::Pinned(vero.fingerprint()));
    let Err(errore) = esito else {
        panic!(
            "un impostore con la chiave pubblica giusta e la privata sbagliata e' stato \
             accettato: la firma dell'handshake NON viene verificata (ADR-0083, decisione 4)"
        );
    };
    assert!(
        matches!(errore, TransportError::NotTheExpectedHub),
        "esito sbagliato: {errore:?}"
    );
    let _ = filo.join();
}

/// Il controllo di coerenza della prova precedente: lo **stesso** impostore,
/// con la privata giusta, passa. Senza questo, la prova sopra potrebbe essere
/// rossa per una ragione che non è la firma.
#[test]
fn the_same_impostor_setup_with_the_right_private_key_is_accepted() {
    let vero = chiave();
    let (indirizzo, filo) = impostore(vero.public_key_info(), &vero, HUB_ALPN);
    let Ok(risposta) = eco(indirizzo, HubExpectation::Pinned(vero.fingerprint())) else {
        panic!("la costruzione dell'impostore con la chiave giusta deve funzionare");
    };
    assert_eq!(&risposta, b"ciao!");
    let _ = filo.join();
}

// ---------------------------------------------------------------------------
// Chi risponde ma non parla come l'Hub
// ---------------------------------------------------------------------------

#[test]
fn a_tls_service_with_another_alpn_is_not_the_hub() {
    let vero = chiave();
    let (indirizzo, filo) = impostore(vero.public_key_info(), &vero, b"http/1.1");
    let Err(errore) = eco(indirizzo, HubExpectation::Pinned(vero.fingerprint())) else {
        panic!("un servizio con un altro ALPN non e' l'Hub, anche con la chiave giusta");
    };
    assert!(
        matches!(errore, TransportError::ProtocolMismatch),
        "{errore:?}"
    );
    assert_eq!(errore.outcome(), ConnectOutcome::NotTheExpectedHub);
    let _ = filo.join();
}

#[test]
fn a_service_that_does_not_speak_tls_is_not_the_hub() {
    let vero = chiave();
    let indirizzo = server_grezzo(
        Some(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
        Duration::from_secs(3),
    );
    let Err(errore) = eco(indirizzo, HubExpectation::Pinned(vero.fingerprint())) else {
        panic!("un servizio in chiaro non e' l'Hub");
    };
    assert!(
        matches!(errore, TransportError::ProtocolMismatch),
        "{errore:?}"
    );
}

// ---------------------------------------------------------------------------
// Silenzio, tempi, tetti
// ---------------------------------------------------------------------------

#[test]
fn nobody_listening_is_unreachable_and_worth_retrying() {
    let Ok(occupato) = TcpListener::bind(LOOPBACK) else {
        panic!("porta di prova");
    };
    let Ok(indirizzo) = occupato.local_addr() else {
        panic!("indirizzo di prova");
    };
    drop(occupato);

    let Err(errore) = connect(
        indirizzo,
        HubExpectation::Pinned(chiave().fingerprint()),
        &limiti_brevi(),
    ) else {
        panic!("nessuno ascolta");
    };
    assert!(matches!(errore, TransportError::Unreachable), "{errore:?}");
    assert_eq!(errore.outcome(), ConnectOutcome::HubUnreachable);
}

#[test]
fn a_silent_server_cannot_hold_the_handshake_past_its_deadline() {
    let indirizzo = server_grezzo(None, Duration::from_secs(6));
    let limiti = ClientLimits {
        handshake_timeout: Duration::from_millis(500),
        ..limiti_brevi()
    };
    let inizio = Instant::now();
    let Err(errore) = connect(
        indirizzo,
        HubExpectation::Pinned(chiave().fingerprint()),
        &limiti,
    ) else {
        panic!("un server muto non completa un handshake");
    };
    assert!(
        matches!(errore, TransportError::HandshakeTimedOut),
        "{errore:?}"
    );
    assert!(
        inizio.elapsed() < Duration::from_secs(3),
        "la scadenza dell'handshake non e' stata rispettata: {:?}",
        inizio.elapsed()
    );
}

#[test]
fn the_hub_closes_a_client_that_never_finishes_the_handshake() {
    let hub = chiave();
    let server = hub_che_risponde(
        &hub,
        ServerLimits {
            handshake_timeout: Duration::from_millis(400),
            ..ServerLimits::default()
        },
    );
    let Ok(mut muto) = TcpStream::connect(server.local_addr()) else {
        panic!("connessione TCP muta");
    };
    let _ = muto.set_read_timeout(Some(Duration::from_secs(5)));
    let inizio = Instant::now();
    let mut buffer = [0_u8; 16];
    // L'Hub non manda nulla a chi non parla, e chiude alla scadenza.
    let letti = muto.read(&mut buffer).unwrap_or(0);
    assert_eq!(letti, 0, "l'Hub non deve mandare nulla a un client muto");
    assert!(
        inizio.elapsed() < Duration::from_secs(3),
        "l'Hub ha tenuto aperto un handshake oltre la scadenza: {:?}",
        inizio.elapsed()
    );
    server.stop();
}

#[test]
fn beyond_the_handshake_cap_a_new_connection_is_closed_at_once() {
    let hub = chiave();
    let server = hub_che_risponde(
        &hub,
        ServerLimits {
            max_connections: 1,
            max_handshakes: 1,
            handshake_timeout: Duration::from_secs(2),
            io_timeout: Duration::from_secs(5),
        },
    );

    // Un client muto occupa l'unico posto.
    let Ok(muto) = TcpStream::connect(server.local_addr()) else {
        panic!("connessione TCP muta");
    };
    let inizio = Instant::now();
    while server.active_connections() == 0 && inizio.elapsed() < Duration::from_secs(2) {
        std::thread::yield_now();
    }
    assert_eq!(server.active_connections(), 1);

    let Err(errore) = eco(
        server.local_addr(),
        HubExpectation::Pinned(hub.fingerprint()),
    ) else {
        panic!("oltre il tetto la connessione nuova deve essere chiusa");
    };
    assert_eq!(
        errore.outcome(),
        ConnectOutcome::HubUnreachable,
        "{errore:?}"
    );

    // Liberato il posto, l'Hub torna raggiungibile.
    drop(muto);
    let inizio = Instant::now();
    while server.active_connections() > 0 && inizio.elapsed() < Duration::from_secs(4) {
        std::thread::sleep(Duration::from_millis(10));
    }
    let Ok(risposta) = eco(
        server.local_addr(),
        HubExpectation::Pinned(hub.fingerprint()),
    ) else {
        panic!("liberato il posto, l'Hub deve tornare raggiungibile");
    };
    assert_eq!(&risposta, b"ciao!");
    server.stop();
}

#[test]
fn garbage_from_one_client_does_not_stop_the_hub() {
    let hub = chiave();
    let server = hub_che_risponde(&hub, ServerLimits::default());
    if let Ok(mut molesto) = TcpStream::connect(server.local_addr()) {
        let _ = molesto.write_all(&[0x16, 0x03, 0x01, 0xFF, 0xFF, 0x00, 0x00, 0x00]);
        let _ = molesto.write_all(b"GET / HTTP/1.1\r\n\r\n");
    }
    let Ok(risposta) = eco(
        server.local_addr(),
        HubExpectation::Pinned(hub.fingerprint()),
    ) else {
        panic!("l'Hub deve continuare a servire dopo un client molesto");
    };
    assert_eq!(&risposta, b"ciao!");
    server.stop();
}

// ---------------------------------------------------------------------------
// Indirizzi e tetti rifiutati
// ---------------------------------------------------------------------------

#[test]
fn the_hub_never_listens_on_every_interface() {
    let hub = chiave();
    for tutte in ["0.0.0.0:0", "[::]:0"] {
        let Ok(indirizzo) = tutte.parse::<SocketAddr>() else {
            panic!("indirizzo di prova");
        };
        assert!(matches!(
            HubListener::bind(indirizzo, &hub, ServerLimits::default()),
            Err(TransportError::AddressNotAllowed { .. })
        ));
    }
}

#[test]
fn unusable_limits_and_addresses_are_refused_before_any_socket() {
    let hub = chiave();
    assert!(matches!(
        HubListener::bind(
            LOOPBACK,
            &hub,
            ServerLimits {
                max_connections: 0,
                ..ServerLimits::default()
            }
        ),
        Err(TransportError::Configuration)
    ));
    let Ok(ovunque) = "0.0.0.0:4000".parse::<SocketAddr>() else {
        panic!("indirizzo di prova");
    };
    assert!(matches!(
        connect(
            ovunque,
            HubExpectation::Pinned(hub.fingerprint()),
            &limiti_brevi()
        ),
        Err(TransportError::AddressNotAllowed { .. })
    ));
    assert!(matches!(
        connect(
            LOOPBACK,
            HubExpectation::Pinned(hub.fingerprint()),
            &limiti_brevi()
        ),
        Err(TransportError::AddressNotAllowed { .. })
    ));
}

/// **Con le reti dell'ufficio, il proprio computer si raggiunge e nessuno è
/// contato fra i rifiutati** (HUB-SITES-01, ADR-0198).
///
/// Il rifiuto di un indirizzo di fuori non si può provocare da qui: sulla
/// postazione non c'è un indirizzo pubblico da cui collegarsi. La regola si
/// prova in `lisi_core::model::office_network`, la prova dal vivo è HVQ-166.
#[test]
fn with_the_office_networks_the_local_computer_is_still_admitted() {
    let hub = chiave();
    let Ok(ascolto) = HubListener::bind(LOOPBACK, &hub, ServerLimits::default()) else {
        panic!("l'Hub deve poter ascoltare su loopback");
    };
    let Ok(ascolto) =
        ascolto.admit_only(lisi_core::model::office_network::OfficeNetworks::default())
    else {
        panic!("loopback è dell'ufficio per norma");
    };
    let Ok(server) = ascolto.serve(|mut canale| {
        let mut ricevuti = [0_u8; 5];
        if canale.read_exact(&mut ricevuti).is_ok() {
            let _ = canale.write_all(&ricevuti);
            let _ = canale.flush();
        }
        canale.close();
    }) else {
        panic!("l'Hub deve partire");
    };
    let Ok(risposta) = eco(
        server.local_addr(),
        HubExpectation::Pinned(hub.fingerprint()),
    ) else {
        panic!("il proprio computer deve raggiungere l'Hub");
    };
    assert_eq!(&risposta, b"ciao!");
    assert_eq!(server.refused_outside(), 0);
    server.stop();
}

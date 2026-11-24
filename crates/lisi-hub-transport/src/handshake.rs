//! L'handshake con una scadenza, e la lettura dei suoi esiti.
//!
//! Comune alle due estremità. Tre regole:
//!
//! - **una scadenza sola per tutto l'handshake**, non per ogni lettura: un
//!   interlocutore che manda un byte al secondo non deve poter allungare
//!   l'handshake all'infinito;
//! - **gli esiti si classificano** nei due che contano per l'operatore
//!   ([`crate::error::ConnectOutcome`]), senza portarsi dietro i messaggi della
//!   libreria, che possono contenere dati ricevuti;
//! - **dopo l'handshake si controlla che cosa si è negoziato**: TLS 1.3 e l'ALPN
//!   dell'Hub, o la connessione non esiste.

use std::io;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use rustls::{CommonState, ConnectionCommon, Error, ProtocolVersion};

use crate::HUB_ALPN;
use crate::error::{TransportError, TransportResult};

/// Porta a termine l'handshake entro `timeout`.
pub(crate) fn drive<Data>(
    connection: &mut ConnectionCommon<Data>,
    tcp: &mut TcpStream,
    timeout: Duration,
) -> TransportResult<()> {
    let deadline = Instant::now() + timeout;
    while connection.is_handshaking() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(TransportError::HandshakeTimedOut);
        }
        // Il tempo che resta, non il tempo intero: la scadenza è una.
        set_timeouts(tcp, remaining)?;

        match connection.complete_io(tcp) {
            Ok((0, 0)) if connection.is_handshaking() => {
                // Nessun progresso e nessun errore: l'altro capo ha chiuso.
                return Err(TransportError::Unreachable);
            }
            Ok(_) => {}
            Err(errore) => match errore.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                    if Instant::now() >= deadline {
                        return Err(TransportError::HandshakeTimedOut);
                    }
                }
                io::ErrorKind::Interrupted => {}
                _ => return Err(classify(&errore)),
            },
        }
    }
    Ok(())
}

/// Verifica che cosa l'handshake ha negoziato.
pub(crate) fn check_negotiated(state: &CommonState) -> TransportResult<()> {
    if state.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
        return Err(TransportError::ProtocolMismatch);
    }
    // Obbligatorio su entrambe le estremità: rustls, dal lato del server, non
    // rifiuta un client che non offre ALPN. Lo rifiutiamo noi.
    if state.alpn_protocol() != Some(HUB_ALPN) {
        return Err(TransportError::ProtocolMismatch);
    }
    Ok(())
}

/// Imposta i tempi massimi di lettura e scrittura.
pub(crate) fn set_timeouts(tcp: &TcpStream, timeout: Duration) -> TransportResult<()> {
    // Una durata nulla, per un socket, significa «nessun limite»: si arrotonda
    // al millisecondo invece di togliere il limite.
    let timeout = timeout.max(Duration::from_millis(1));
    tcp.set_read_timeout(Some(timeout)).map_err(io_error)?;
    tcp.set_write_timeout(Some(timeout)).map_err(io_error)
}

/// Un errore d'ingresso e uscita, senza il messaggio del sistema.
pub(crate) fn io_error(errore: io::Error) -> TransportError {
    match errore.kind() {
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::NotConnected
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::UnexpectedEof
        | io::ErrorKind::TimedOut
        | io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::NetworkDown
        | io::ErrorKind::AddrNotAvailable => TransportError::Unreachable,
        kind => TransportError::Io { kind },
    }
}

/// Classifica un errore dell'handshake.
fn classify(errore: &io::Error) -> TransportError {
    let tls = errore
        .get_ref()
        .and_then(|interno| interno.downcast_ref::<Error>());
    match tls {
        // La chiave presentata non è quella attesa, o la firma non torna.
        Some(Error::InvalidCertificate(_) | Error::NoCertificatesPresented) => {
            TransportError::NotTheExpectedHub
        }
        // Tutto il resto che viene dalla libreria TLS: un servizio che non
        // parla come l'Hub, o un interlocutore che ha rifiutato noi.
        Some(_) => TransportError::ProtocolMismatch,
        None => io_error(io::Error::from(errore.kind())),
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use rustls::{CertificateError, Error};

    use super::classify;
    use crate::error::TransportError;

    fn avvolto(errore: Error) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, errore)
    }

    #[test]
    fn a_wrong_key_or_a_wrong_signature_is_an_unexpected_hub() {
        for errore in [
            Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure),
            Error::InvalidCertificate(CertificateError::BadSignature),
            Error::NoCertificatesPresented,
        ] {
            assert!(matches!(
                classify(&avvolto(errore)),
                TransportError::NotTheExpectedHub
            ));
        }
    }

    #[test]
    fn other_tls_failures_are_a_protocol_mismatch_and_io_is_silence() {
        assert!(matches!(
            classify(&avvolto(Error::NoApplicationProtocol)),
            TransportError::ProtocolMismatch
        ));
        assert!(matches!(
            classify(&io::Error::from(io::ErrorKind::ConnectionReset)),
            TransportError::Unreachable
        ));
    }
}

//! Il lato della postazione: collegarsi all'Hub atteso, e a nessun altro.
//!
//! **Prima si verifica l'Hub, poi si parla** (ADR-0082, decisione 2): la
//! funzione [`connect`] restituisce un canale **solo** dopo che l'altro capo ha
//! presentato la chiave attesa e ha firmato l'handshake con essa. Nulla può
//! essere scritto prima, perché prima non esiste un canale su cui scrivere.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};

use lisi_core::model::hub_identity::{HubExpectation, HubFingerprint};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};

use crate::error::{TransportError, TransportResult};
use crate::handshake;
use crate::limits::ClientLimits;
use crate::verifier;

/// Un canale verso l'Hub, autenticato e cifrato.
pub struct HubClientStream {
    inner: StreamOwned<ClientConnection, TcpStream>,
    hub: HubFingerprint,
}

impl HubClientStream {
    /// L'impronta intera dell'Hub a cui ci si è collegati.
    ///
    /// Dopo un arruolamento riuscito è ciò che la postazione conserva, per
    /// confrontare da lì in poi tutti i 256 bit (ADR-0082).
    #[must_use]
    pub fn hub_fingerprint(&self) -> HubFingerprint {
        self.hub
    }

    /// Chiude il canale annunciandolo all'altro capo.
    ///
    /// La chiusura è best-effort: un Hub già sparito non la riceve, e non è un
    /// errore di chi chiude.
    pub fn close(mut self) {
        self.inner.conn.send_close_notify();
        let _ = self.inner.conn.complete_io(&mut self.inner.sock);
        let _ = self.inner.sock.shutdown(std::net::Shutdown::Both);
    }
}

impl Read for HubClientStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for HubClientStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl core::fmt::Debug for HubClientStream {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "HubClientStream({:?})", self.hub)
    }
}

/// Si collega all'Hub all'indirizzo indicato, **se** è quello atteso.
///
/// # Errori
///
/// - [`TransportError::Unreachable`] o [`TransportError::HandshakeTimedOut`]:
///   nessuno ha risposto in tempo. Si può riprovare ([`crate::RetryPolicy`]).
/// - [`TransportError::NotTheExpectedHub`]: ha risposto una chiave diversa, o
///   la chiave giusta senza la privata. **Non si riprova da soli.**
/// - [`TransportError::ProtocolMismatch`]: risponde un servizio che non è
///   l'Hub.
/// - [`TransportError::AddressNotAllowed`] o [`TransportError::Configuration`]:
///   indirizzo o tetti inutilizzabili.
pub fn connect(
    address: SocketAddr,
    expected: HubExpectation,
    limits: &ClientLimits,
) -> TransportResult<HubClientStream> {
    if !limits.is_usable() {
        return Err(TransportError::Configuration);
    }
    if address.ip().is_unspecified() || address.ip().is_multicast() || address.port() == 0 {
        return Err(TransportError::AddressNotAllowed {
            reason: "l'Hub si raggiunge a un indirizzo e a una porta precisi",
        });
    }

    let config = verifier::client_config(expected)?;
    let mut tcp = TcpStream::connect_timeout(&address, limits.connect_timeout)
        .map_err(handshake::io_error)?;
    // Latenza, non sicurezza: se il sistema rifiuta, si prosegue.
    let _ = tcp.set_nodelay(true);

    // L'Hub non ha un nome: l'indirizzo serve solo alla libreria, che con un IP
    // non invia SNI.
    let server_name = ServerName::IpAddress(address.ip().into());
    let mut connection =
        ClientConnection::new(config, server_name).map_err(|_| TransportError::Configuration)?;

    handshake::drive(&mut connection, &mut tcp, limits.handshake_timeout)?;
    handshake::check_negotiated(&connection)?;

    let hub = connection
        .peer_certificates()
        .and_then(|presentate| presentate.first())
        .map(|chiave| HubFingerprint::of_public_key_info(chiave.as_ref()))
        .ok_or(TransportError::NotTheExpectedHub)?;

    handshake::set_timeouts(&tcp, limits.io_timeout)?;
    Ok(HubClientStream {
        inner: StreamOwned::new(connection, tcp),
        hub,
    })
}

impl crate::protocol::frame::TimedStream for HubClientStream {
    fn set_io_timeout(&mut self, timeout: std::time::Duration) -> io::Result<()> {
        self.inner.sock.set_read_timeout(Some(timeout))?;
        self.inner.sock.set_write_timeout(Some(timeout))
    }
}

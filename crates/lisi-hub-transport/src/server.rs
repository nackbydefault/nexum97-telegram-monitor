//! Il lato dell'Hub: un indirizzo scelto, e nulla finché nessuno lo sceglie.
//!
//! # Le regole (ADR-0083, decisione 5)
//!
//! - **Nessuna porta in ascolto finché una persona non attiva la modalità
//!   Hub.** Questa crate non ascolta da sola: ascolta chi costruisce un
//!   [`HubListener`], e oggi nel prodotto nessuno lo fa.
//! - **Si ascolta su un indirizzo scelto, non su tutte le interfacce.**
//!   `0.0.0.0` e `::` sono **rifiutati**, non solo sconsigliati: chi attiva
//!   l'Hub sceglie su quale rete sta.
//! - **L'Hub non autentica il client in TLS**: il dispositivo si autentica con
//!   il gettone, subito dopo, dentro il canale (ADR-0082, decisione 4).
//! - **Tetti** su connessioni contemporanee, handshake in corso e durata
//!   dell'handshake ([`ServerLimits`]). Oltre il tetto la connessione nuova si
//!   chiude **subito**, senza handshake.
//!
//! - **Si accetta soltanto dalle reti dell'ufficio** (HUB-SITES-01, ADR-0198):
//!   con [`HubListener::admit_only`] una connessione da un indirizzo di fuori si
//!   chiude subito, prima della negoziazione, e si conta.
//!
//! # Il firewall di Windows
//!
//! La prima volta che il programma ascolta, Windows chiede se permetterlo, e su
//! una postazione d'ufficio consentirlo richiede spesso un amministratore. È
//! una decisione dell'ufficio: il prodotto la dirà e non la aggirerà
//! (HVQ-79).

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use rustls::crypto::ring::default_provider;
use rustls::server::{AlwaysResolvesServerRawPublicKeys, NoServerSessionStorage};
use rustls::version::TLS13;
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use crate::HUB_ALPN;
use crate::error::{TransportError, TransportResult};
use crate::handshake;
use crate::key::HubKey;
use crate::limits::ServerLimits;
use lisi_core::model::office_network::OfficeNetworks;

/// Quanto aspetta il ciclo di accettazione quando non c'è nessuno.
///
/// Il socket è non bloccante perché fermare l'Hub non debba aspettare una
/// connessione che forse non arriverà mai.
const ACCEPT_IDLE: Duration = Duration::from_millis(20);

/// Quanto aspetta dopo un errore di accettazione, perché un errore ripetuto non
/// diventi un ciclo che consuma un processore.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(250);

/// La configurazione del server per la chiave indicata.
fn server_config(key: &HubKey) -> TransportResult<Arc<ServerConfig>> {
    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&TLS13])
        .map_err(|_| TransportError::Configuration)?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(
            key.certified_key(),
        )));

    config.alpn_protocols = vec![HUB_ALPN.to_vec()];
    // Nessuna ripresa di sessione e nessun 0-RTT (ADR-0083, decisione 2).
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

/// Un indirizzo scelto su cui l'Hub è pronto ad ascoltare.
pub struct HubListener {
    listener: TcpListener,
    config: Arc<ServerConfig>,
    limits: ServerLimits,
    networks: Option<OfficeNetworks>,
}

impl HubListener {
    /// Apre l'ascolto sull'indirizzo scelto.
    ///
    /// # Errori
    ///
    /// [`TransportError::AddressNotAllowed`] per un indirizzo non specificato o
    /// multicast; [`TransportError::Configuration`] per tetti inutilizzabili;
    /// [`TransportError::Io`] se il sistema rifiuta l'ascolto.
    pub fn bind(address: SocketAddr, key: &HubKey, limits: ServerLimits) -> TransportResult<Self> {
        if !limits.is_usable() {
            return Err(TransportError::Configuration);
        }
        if address.ip().is_unspecified() {
            return Err(TransportError::AddressNotAllowed {
                reason: "non si ascolta su tutte le interfacce: va scelto un indirizzo",
            });
        }
        if address.ip().is_multicast() {
            return Err(TransportError::AddressNotAllowed {
                reason: "un indirizzo che raggiunge molti computer insieme non è un indirizzo su cui ascoltare",
            });
        }
        let config = server_config(key)?;
        let listener = TcpListener::bind(address).map_err(|errore| TransportError::Io {
            kind: errore.kind(),
        })?;
        Ok(Self {
            listener,
            config,
            limits,
            networks: None,
        })
    }

    /// Accetta soltanto dalle reti dell'ufficio (HUB-SITES-01, ADR-0198).
    ///
    /// Anche l'indirizzo di ascolto deve esserne parte: un Hub acceso su un
    /// indirizzo che Internet raggiunge non lo ha deciso nessuno.
    ///
    /// # Errori
    ///
    /// [`TransportError::AddressNotAllowed`] se l'indirizzo di ascolto non è
    /// dell'ufficio; [`TransportError::Io`] se il sistema non lo sa dire.
    pub fn admit_only(mut self, networks: OfficeNetworks) -> TransportResult<Self> {
        if !networks.admits(self.local_addr()?.ip()) {
            return Err(TransportError::AddressNotAllowed {
                reason: "l'Hub ascolta soltanto su un indirizzo delle reti dell'ufficio, mai su uno che Internet raggiunge",
            });
        }
        self.networks = Some(networks);
        Ok(self)
    }

    /// L'indirizzo effettivo, porta compresa.
    ///
    /// # Errori
    ///
    /// [`TransportError::Io`] se il sistema non lo sa dire.
    pub fn local_addr(&self) -> TransportResult<SocketAddr> {
        self.listener
            .local_addr()
            .map_err(|errore| TransportError::Io {
                kind: errore.kind(),
            })
    }

    /// Comincia ad accettare connessioni, e consegna ciascun canale verificato
    /// a `handler`, in un thread proprio.
    ///
    /// # Errori
    ///
    /// [`TransportError::Io`] se il socket non diventa non bloccante o se il
    /// thread di accettazione non parte.
    pub fn serve<H>(self, handler: H) -> TransportResult<HubServer>
    where
        H: Fn(HubServerStream) + Send + Sync + 'static,
    {
        let local = self.local_addr()?;
        self.listener
            .set_nonblocking(true)
            .map_err(|errore| TransportError::Io {
                kind: errore.kind(),
            })?;

        let stop = Arc::new(AtomicBool::new(false));
        let counters = Arc::new(Counters::default());
        let acceptor = {
            let stop = Arc::clone(&stop);
            let counters = Arc::clone(&counters);
            let handler = Arc::new(handler);
            std::thread::Builder::new()
                .name(String::from("hub-accept"))
                .spawn(move || accept_loop(&self, &stop, &counters, &handler))
                .map_err(|errore| TransportError::Io {
                    kind: errore.kind(),
                })?
        };

        Ok(HubServer {
            stop,
            acceptor: Some(acceptor),
            counters,
            local,
        })
    }
}

/// L'Hub in ascolto. Fermarlo (o lasciarlo cadere) chiude l'ascolto.
pub struct HubServer {
    stop: Arc<AtomicBool>,
    acceptor: Option<JoinHandle<()>>,
    counters: Arc<Counters>,
    local: SocketAddr,
}

impl HubServer {
    /// L'indirizzo su cui ascolta.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Le connessioni chiuse perché arrivavano da fuori delle reti
    /// dell'ufficio, da quando l'Hub ascolta.
    #[must_use]
    pub fn refused_outside(&self) -> usize {
        self.counters.refused_outside.load(Ordering::SeqCst)
    }

    /// Le connessioni aperte in questo momento, handshake compresi.
    #[must_use]
    pub fn active_connections(&self) -> usize {
        self.counters.connections.load(Ordering::SeqCst)
    }

    /// Smette di accettare connessioni nuove.
    ///
    /// Le connessioni già consegnate restano a chi le gestisce, e finiscono
    /// entro il loro tempo massimo di inattività.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(acceptor) = self.acceptor.take() {
            let _ = acceptor.join();
        }
    }
}

impl Drop for HubServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Un canale verificato dal lato dell'Hub.
///
/// **Il client non è ancora autenticato**: è soltanto qualcuno che ha concluso
/// un handshake con la chiave dell'Hub. Chi è lo dirà il gettone (HUB-AUTHZ-01).
pub struct HubServerStream {
    inner: StreamOwned<ServerConnection, TcpStream>,
    peer: SocketAddr,
}

impl HubServerStream {
    /// L'indirizzo da cui arriva la connessione. **Non è un'identità.**
    #[must_use]
    pub fn peer_address(&self) -> SocketAddr {
        self.peer
    }

    /// Chiude il canale annunciandolo all'altro capo.
    pub fn close(mut self) {
        self.inner.conn.send_close_notify();
        let _ = self.inner.conn.complete_io(&mut self.inner.sock);
        let _ = self.inner.sock.shutdown(Shutdown::Both);
    }
}

impl Read for HubServerStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for HubServerStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[derive(Default)]
struct Counters {
    connections: AtomicUsize,
    handshakes: AtomicUsize,
    refused_outside: AtomicUsize,
}

/// Quale contatore un posto occupa.
#[derive(Clone, Copy)]
enum Which {
    Connections,
    Handshakes,
}

/// Un posto occupato in un contatore, restituito quando cade.
///
/// Possiede il contatore: comunque finisca il thread che lo tiene — anche se
/// non parte affatto — il posto torna libero.
struct Slot {
    counters: Arc<Counters>,
    which: Which,
}

impl Slot {
    /// Occupa un posto se ce n'e' uno libero.
    fn acquire(counters: &Arc<Counters>, which: Which, max: usize) -> Option<Self> {
        // IL POSTO SI COSTRUISCE SOLO DOPO AVERLO OTTENUTO.
        //
        // Trovato da `beyond_the_handshake_cap_a_new_connection_is_closed_at_once`:
        // la prima versione costruiva il posto prima di riservarlo, e un rifiuto
        // lo lasciava cadere — il `Drop` restituiva un posto mai preso, il
        // contatore scendeva sotto zero, e il thread di accettazione moriva
        // alla connessione successiva. Un Hub che smette di accettare dopo il
        // primo rifiuto per tetto è un Hub che un client ostile spegne.
        counter_of(counters, which)
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |attuali| {
                (attuali < max).then_some(attuali + 1)
            })
            .ok()?;
        Some(Self {
            counters: Arc::clone(counters),
            which,
        })
    }

    fn counter(&self) -> &AtomicUsize {
        counter_of(&self.counters, self.which)
    }
}

fn counter_of(counters: &Counters, which: Which) -> &AtomicUsize {
    match which {
        Which::Connections => &counters.connections,
        Which::Handshakes => &counters.handshakes,
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.counter().fetch_sub(1, Ordering::SeqCst);
    }
}

fn accept_loop<H>(
    listener: &HubListener,
    stop: &AtomicBool,
    counters: &Arc<Counters>,
    handler: &Arc<H>,
) where
    H: Fn(HubServerStream) + Send + Sync + 'static,
{
    while !stop.load(Ordering::SeqCst) {
        match listener.listener.accept() {
            Ok((tcp, peer)) => dispatch(listener, counters, handler, tcp, peer),
            Err(errore) if errore.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_IDLE);
            }
            Err(_) => std::thread::sleep(ACCEPT_ERROR_BACKOFF),
        }
    }
}

fn dispatch<H>(
    listener: &HubListener,
    counters: &Arc<Counters>,
    handler: &Arc<H>,
    tcp: TcpStream,
    peer: SocketAddr,
) where
    H: Fn(HubServerStream) + Send + Sync + 'static,
{
    // DA FUORI DELLE RETI DELL'UFFICIO si chiude SUBITO (ADR-0198, decisione
    // 4), prima dei tetti: chi arriva da Internet non occupa nemmeno un posto.
    if listener
        .networks
        .as_ref()
        .is_some_and(|reti| !reti.admits(peer.ip()))
    {
        counters.refused_outside.fetch_add(1, Ordering::SeqCst);
        let _ = tcp.shutdown(Shutdown::Both);
        return;
    }
    // Oltre il tetto si chiude SUBITO, senza handshake: un handshake costa
    // all'Hub prima che l'altro capo abbia dimostrato qualcosa.
    let Some(connessione) = Slot::acquire(
        counters,
        Which::Connections,
        listener.limits.max_connections,
    ) else {
        let _ = tcp.shutdown(Shutdown::Both);
        return;
    };
    let Some(handshake) =
        Slot::acquire(counters, Which::Handshakes, listener.limits.max_handshakes)
    else {
        let _ = tcp.shutdown(Shutdown::Both);
        return;
    };

    let config = Arc::clone(&listener.config);
    let limits = listener.limits;
    let handler = Arc::clone(handler);
    // Se il thread non parte, la chiusura cade con il socket e i due posti
    // dentro: nulla resta occupato.
    let _ = std::thread::Builder::new()
        .name(String::from("hub-conn"))
        .spawn(move || {
            let _connessione = connessione;
            if let Some(canale) = accept_one(tcp, peer, config, limits, handshake) {
                handler(canale);
            }
        });
}

fn accept_one(
    mut tcp: TcpStream,
    peer: SocketAddr,
    config: Arc<ServerConfig>,
    limits: ServerLimits,
    handshake_slot: Slot,
) -> Option<HubServerStream> {
    if tcp.set_nonblocking(false).is_err() {
        return None;
    }
    let _ = tcp.set_nodelay(true);
    let mut connection = ServerConnection::new(config).ok()?;

    let esito = handshake::drive(&mut connection, &mut tcp, limits.handshake_timeout)
        .and_then(|()| handshake::check_negotiated(&connection))
        .and_then(|()| handshake::set_timeouts(&tcp, limits.io_timeout));
    // L'handshake e' finito, bene o male: il suo posto torna libero.
    drop(handshake_slot);

    if esito.is_err() {
        let _ = tcp.shutdown(Shutdown::Both);
        return None;
    }
    Some(HubServerStream {
        inner: StreamOwned::new(connection, tcp),
        peer,
    })
}

impl crate::protocol::frame::TimedStream for HubServerStream {
    fn set_io_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.inner.sock.set_read_timeout(Some(timeout))?;
        self.inner.sock.set_write_timeout(Some(timeout))
    }
}

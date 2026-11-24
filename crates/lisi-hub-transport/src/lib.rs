//! Il trasporto TLS autenticato fra postazione e Hub (HUB-TLS-01, ADR-0083).
//!
//! # Che cosa è
//!
//! **L'unica crate del prodotto che parla TLS** (ADR-0083, decisione 8). Pila:
//! **rustls con ring**, scelta da Giuseppe LISI; **solo TLS 1.3**; l'Hub
//! presenta la propria **chiave pubblica nuda** (RFC 7250) e nessun certificato.
//!
//! # Le tre cose che rendono il canale autenticato
//!
//! 1. **L'impronta.** Il client calcola `SHA-256` della `SubjectPublicKeyInfo`
//!    ricevuta e la confronta con ciò che sa dell'Hub
//!    ([`lisi_core::model::hub_identity::HubExpectation`]): i 120 bit del
//!    foglietto all'arruolamento, i 256 bit dopo.
//! 2. **La firma.** L'impronta da sola dimostra che l'altro capo conosce un dato
//!    pubblico. È la firma dell'handshake, verificata con **quella** chiave, a
//!    dimostrare che possiede la privata.
//! 3. **L'ALPN.** Un servizio diverso che parla TLS sulla stessa porta non viene
//!    scambiato per l'Hub.
//!
//! Tutto questo sta in [`verifier`], ed è l'unico file del prodotto autorizzato
//! a usare il ramo «dangerous» di rustls (`hub_trust_guard`).
//!
//! # Che cosa non c'è, per decisione
//!
//! - **Nessun ripiego in chiaro**, nessuna modalità «temporaneamente insicura»,
//!   nessuna retrocessione, nessun TLS 1.2.
//! - **Nessuna ripresa di sessione e nessun 0-RTT**: ogni connessione rifà la
//!   verifica per intero, e non esiste un secondo percorso di autenticazione.
//! - **Nessun runtime asincrono**: un thread per connessione, con un tetto.
//! - **Nessuna porta in ascolto finché qualcuno non costruisce un
//!   [`server::HubListener`]**, e mai su tutte le interfacce.
//! - **Nessun gettone, nessun messaggio applicativo**: il formato è di
//!   HUB-PROTO-01, l'autorizzazione di HUB-AUTHZ-01.
//!
//! # Limite dichiarato
//!
//! Nulla di questo è stato provato fra due macchine (HVQ-08, POC-08): le prove
//! girano sull'interfaccia di loopback di una sola postazione.

#![forbid(unsafe_code)]

pub mod client;
pub mod error;
pub mod key;
pub mod limits;
pub mod protocol;
pub mod retry;
pub mod server;
pub mod verifier;

mod handshake;

pub use crate::client::{HubClientStream, connect};
pub use crate::error::{ConnectOutcome, TransportError, TransportResult};
pub use crate::key::HubKey;
pub use crate::limits::{ClientLimits, ServerLimits};
pub use crate::retry::RetryPolicy;
pub use crate::server::{HubListener, HubServer, HubServerStream};

/// L'identificativo ALPN del protocollo dell'Hub.
///
/// Obbligatorio su entrambe le estremità: una connessione senza accordo si
/// chiude (ADR-0083, decisione 2).
///
/// **Fissato da HUB-PROTO-01 (ADR-0084): è il nome del protocollo, senza
/// versione, e non cambia.** La versione si negozia dentro il canale
/// ([`protocol::negotiation`]): mettere la versione nell'ALPN farebbe fallire
/// il TLS stesso fra una postazione e un Hub di versioni diverse, e
/// l'operatore leggerebbe «non risponde un Hub» dove la verità è «l'Hub va
/// aggiornato».
pub const HUB_ALPN: &[u8] = protocol::handshake::PROTOCOL_NAME.as_bytes();

//! Il protocollo dell'Hub, sopra il trasporto (HUB-PROTO-01, ADR-0084).
//!
//! - [`frame`]: frame con lunghezza prefissa, tetto controllato prima di
//!   allocare, scadenza unica;
//! - [`negotiation`]: versioni, capacità, regole di compatibilità;
//! - [`handshake`]: il primo scambio, con il gettone e il rifiuto della
//!   retrocessione.

pub mod events;
pub mod frame;
pub mod handshake;
pub mod negotiation;

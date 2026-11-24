// Senza Windows il crate non contiene alcun `unsafe`. Su Windows i soli file
// che vi derogano sono `dpapi.rs` (ADR-0003) e `acl.rs` (ADR-0206), in modo
// esplicito e visibile in diff.
#![cfg_attr(not(windows), forbid(unsafe_code))]
#![cfg_attr(windows, deny(unsafe_code))]

//! Protezione locale dei segreti di LISI Telegram Monitor.
//!
//! Il crate non conosce Telegram né l'interfaccia grafica: protegge byte e
//! scrive file. Le scelte sono motivate in
//! `docs/adr/ADR-0009-SECRETS-AND-SESSION.md`.
//!
//! **Limite dichiarato in testa, non in fondo:** DPAPI protegge a riposo contro
//! *altri utenti*, non contro codice che giri come l'utente stesso. Chiamare
//! «cifrato» un dato così protetto senza aggiungere questo sarebbe fuorviante.

pub mod account_key;
#[cfg(windows)]
mod acl;
pub mod dpapi;
pub mod error;
pub mod hub_key;
pub mod owner_only;
pub mod passphrase;
pub mod sealed_copy;
pub mod store;

pub use crate::account_key::{AccountKey, ensure_account_key, load_account_key};
pub use crate::dpapi::random_bytes;
pub use crate::error::{SecurityError, SecurityResult};
pub use crate::hub_key::{HUB_KEY_FILE, HubKeyMaterial, load_hub_key, store_new_hub_key};
pub use crate::passphrase::{derive_verifier, verify_passphrase};
pub use crate::store::ProtectedStore;

#![forbid(unsafe_code)]

//! Persistenza SQLite di LISI Telegram Monitor.
//!
//! Il crate conserva fonti, sessioni, contenuti, riscontri, alert, revisioni,
//! errori, audit ed export. Vi rientra **ogni contenuto effettivamente
//! acquisito e analizzato**, anche quello di livello 0 che non genera alcun
//! alert: lo storico documenta ciò che è stato osservato, non soltanto ciò che
//! ha prodotto un allarme.
//!
//! I vincoli che contano stanno nello schema e non nel codice applicativo: la
//! foreign key composta che impedisce di collegare un contenuto a una fonte non
//! selezionata, il vincolo di unicità che realizza la deduplicazione e i trigger
//! che rendono l'audit append-only. Un vincolo scritto solo nel codice viene
//! aggirato dal primo percorso che dimentica di controllarlo.
//!
//! Le scelte di progetto sono motivate in `docs/adr/ADR-0006-SQLITE-STORAGE.md`.

pub mod database;
pub mod error;
pub mod migrations;
pub mod repository;

#[cfg(test)]
mod test_support;

pub use crate::database::Database;
pub use crate::error::{StorageError, StorageResult};
pub use crate::migrations::LATEST_VERSION;
pub use crate::repository::notification::{EmittedCyberNotification, NewCyberNotification};
/// La transazione dell'archivio, per chi deve eseguire un effetto DENTRO una
/// transazione gia' aperta (ADR-0089): i comandi dell'Hub.
///
/// E' il solo tipo di `rusqlite` che esce da questa crate, e esce perche' un
/// effetto atomico non si puo' descrivere senza nominarlo.
pub use rusqlite::Transaction;

// Senza la feature del proof of concept il crate non contiene alcun `unsafe` e
// la garanzia più forte è mantenuta. Con la feature attiva il divieto resta un
// errore di compilazione ovunque tranne che nell'unico modulo FFI, che vi deroga
// esplicitamente e in modo visibile in diff.
#![cfg_attr(not(feature = "tdlib-runtime"), forbid(unsafe_code))]
#![cfg_attr(feature = "tdlib-runtime", deny(unsafe_code))]

//! Connettore Telegram di LISI Telegram Monitor.
//!
//! Il crate è **isolato dall'applicazione**: `lisi-app` non vi dipende. Contiene
//! l'astrazione del connettore, la macchina a stati dell'autorizzazione, i tipi
//! riservati con la loro redazione, gli eventi normalizzati, la traduzione verso
//! il dominio e un connettore simulato deterministico.
//!
//! Il proof of concept che carica realmente TDLib è dietro la feature
//! `tdlib-runtime`, assente per impostazione predefinita: **il workspace
//! compila, supera Clippy e supera i test su una macchina priva di TDLib**.
//!
//! In questa milestone non esiste alcun accesso operativo a Telegram: nessuna
//! credenziale reale, nessun login, nessuna acquisizione. Le scelte sono
//! motivate in `docs/adr/ADR-0008-TDLIB-INTEGRATION.md`.

pub mod attachment;
pub mod auth;
pub mod author;
pub mod backoff;
pub mod chat;
pub mod connector;
pub mod correlation;
pub mod error;
pub mod event;
pub mod identifier;
pub mod link;
pub mod lookup;
pub mod mapping;
pub mod members;
pub mod mock;
pub mod profile;
pub mod prohibitions;
pub mod queue;
pub mod relation;
pub mod search;
pub mod secret;

#[cfg(feature = "tdlib-runtime")]
pub mod tdlib;

/// Connettore reale verso Telegram, disponibile solo con la feature che carica
/// TDLib. Riesportato qui per comodità dei servizi, che vi passano la chiave del
/// database dell'account già in base64.
#[cfg(feature = "tdlib-runtime")]
pub use crate::tdlib::LiveTdlibConnector;

pub use crate::attachment::{AttachmentDescriptor, AttachmentKind};
pub use crate::auth::{AuthorizationMachine, AuthorizationState};
pub use crate::backoff::BackoffPolicy;
pub use crate::chat::{AccessibleChat, ChatKind};
pub use crate::connector::{ClientParameters, TelegramConnector, Timeouts};
pub use crate::correlation::{Correlator, Delivery, Incoming, RequestId, Resolution};
pub use crate::error::{TelegramError, TelegramResult};
pub use crate::event::{
    ConnectionState, ConnectorEvent, DeletedMessages, EditedMessage, IncomingMessage,
};
pub use crate::identifier::{ChatId, MessageId};
pub use crate::link::{LinkGap, LinkOutcome, MessageLink, SourceLink};
pub use crate::mock::MockTelegramConnector;
pub use crate::queue::EventQueue;
pub use crate::relation::{
    ContextMessage, ForwardOrigin, Forwarded, MessageRelations, ReplyTo, Thread,
};
pub use crate::secret::{ApiHash, ApiId, LoginCode, PhoneNumber, TwoFactorPassword};

/// Se questa build può caricare realmente TDLib.
///
/// Serve alla diagnostica e ai rapporti: una build senza la feature non è una
/// build a cui manca la libreria, è una build che non la carica affatto.
#[must_use]
pub const fn tdlib_runtime_enabled() -> bool {
    cfg!(feature = "tdlib-runtime")
}

#[cfg(test)]
mod tests {
    use super::tdlib_runtime_enabled;

    #[test]
    fn the_runtime_flag_matches_the_compiled_feature() {
        assert_eq!(tdlib_runtime_enabled(), cfg!(feature = "tdlib-runtime"));
    }
}

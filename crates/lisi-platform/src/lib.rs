// Senza Windows il crate non contiene alcun `unsafe`. Su Windows gli unici file
// che vi derogano sono `browser.rs`, `window_chrome.rs`, `wakefulness.rs`,
// `autostart.rs`, `title_bar.rs`, `signature.rs`, `disk_space.rs`, `app_identity.rs`,
// `tray.rs`, `https.rs`, `local_time.rs`, `folder.rs`, `time_sync.rs`,
// `launch_volume.rs`, `detached_signature.rs`, `document_signing.rs`,
// `recipient_encryption.rs`, `name_lookup.rs`, `background_service.rs` e
// `service_install.rs`, in modo
// esplicito e visibile in diff (ADR-0003, ADR-0018, ADR-0020, ADR-0021,
// ADR-0022, ADR-0028, ADR-0037, ADR-0054, ADR-0063, ADR-0067, ADR-0136,
// ADR-0137, ADR-0168, ADR-0176, ADR-0178, ADR-0181, ADR-0190, ADR-0202,
// ADR-0203).
#![cfg_attr(not(windows), forbid(unsafe_code))]
#![cfg_attr(windows, deny(unsafe_code))]

//! Integrazione con il sistema operativo di NEXUM/97.
//!
//! Il crate non conosce Telegram, i segreti, né l'interfaccia grafica: parla con
//! il sistema. Apre un URL nel browser predefinito, chiede al gestore delle
//! finestre la barra del titolo scura, tiene sveglia la postazione, configura
//! l'avvio automatico, dichiara l'identità dell'applicazione e mostra il
//! riquadro di avviso di Windows.
//!
//! **E da UPDATE-02 apre una porta verso la rete, che prima non esisteva.** È
//! una sola, va in un posto solo, e ciò che sa fare è una richiesta `GET` in
//! `https` con un limite e un timeout: `https.rs`, ADR-0067. Il crate continua a
//! non sapere nulla di Telegram e dei contenuti monitorati, e quella porta non
//! fa eccezione.
//!
//! **Da WHOIS-01 c'è una seconda porta in uscita**, `whois.rs` (ADR-0205): una
//! domanda in chiaro alla porta 43 di un registro, per i registri che non
//! offrono RDAP. Senza `unsafe`: è il socket di `std`, in uscita soltanto.
//!
//! **Limite dichiarato in testa, non in fondo:** aprire un URL validato non lo
//! rende innocuo. La validazione garantisce un URL web ben formato, non una
//! destinazione fidata; la pagina si apre nel browser (fuori dal processo), non
//! qui. Le scelte sono in `docs/adr/ADR-0018-SECURE-URL-OPENING.md`.

pub mod app_identity;
pub mod autostart;
pub mod background_service;
pub mod browser;
pub mod detached_signature;
pub mod disk_space;
pub mod document_signing;
pub mod error;
pub mod folder;
pub mod https;
pub mod launch_volume;
pub mod local_time;
pub mod motion;
pub mod name_lookup;
pub mod os_version;
pub mod recipient_encryption;
pub mod service_install;
pub mod signature;
pub mod telegram_link;
pub mod time_sync;
pub mod title_bar;
pub mod toast;
pub mod tray;
pub mod wakefulness;
pub mod whois;
pub mod window_chrome;

pub use crate::app_identity::APP_USER_MODEL_ID;
pub use crate::autostart::AutostartState;
pub use crate::browser::open_in_browser;
pub use crate::detached_signature::DetachedVerdict;
pub use crate::disk_space::DiskSpace;
pub use crate::error::{PlatformError, PlatformResult};
pub use crate::motion::SystemMotion;
pub use crate::signature::SignatureState;
pub use crate::telegram_link::open_message;
pub use crate::time_sync::TimeSyncState;
pub use crate::title_bar::TitleBarMetrics;
pub use crate::toast::show as show_toast;
pub use crate::tray::{MenuEntry, TrayEvent, TrayIcon};
pub use crate::wakefulness::{allow_system_sleep, keep_system_awake};
pub use crate::window_chrome::use_dark_title_bar;

//! Entità del dominio.
//!
//! Per ogni entità esistono due forme: un tipo `New*`, che descrive ciò che
//! l'applicazione vuole registrare, e un tipo completo, che rappresenta ciò che
//! è stato registrato e possiede quindi identificatore e istanti assegnati dalla
//! persistenza. La distinzione impedisce di costruire a mano un'entità come se
//! fosse già stata salvata.

/// Genera un'enumerazione con una rappresentazione testuale stabile.
///
/// I valori testuali finiscono nel database e sono vincolati da un `CHECK`: non
/// vanno cambiati senza una migrazione. La macro genera anche la conversione
/// inversa, così che ogni variante sia garantita percorribile in entrambi i
/// versi da un solo test.
macro_rules! string_enum {
    (
        $(#[$meta:meta])*
        $name:ident {
            $($(#[$variant_meta:meta])* $variant:ident => $repr:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $($(#[$variant_meta])* $variant),+
        }

        impl $name {
            /// Rappresentazione stabile usata nella persistenza.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $repr),+
                }
            }

            /// Tutte le varianti, per validazione, test e interfaccia.
            #[must_use]
            pub const fn all() -> &'static [Self] {
                &[$(Self::$variant),+]
            }
        }

        impl ::core::str::FromStr for $name {
            type Err = $crate::error::DomainError;

            fn from_str(raw: &str) -> $crate::error::DomainResult<Self> {
                match raw {
                    $($repr => Ok(Self::$variant),)+
                    other => Err($crate::error::unknown_variant(stringify!($name), other)),
                }
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

pub mod acquisition;
pub mod acquisition_pause;
pub mod alert;
pub mod analysis;
pub mod assessment;
pub mod association;
pub mod attack;
pub mod attack_association;
pub mod attack_citation;
pub mod attack_guidance;
pub mod audit;
pub mod background;
pub mod bookmark;
pub mod content;
pub mod content_history;
pub mod context_snapshot;
pub mod context_state;
pub mod coverage;
pub mod cve;
pub mod cvss;
pub mod cyber_candidate;
pub mod cyber_event;
pub mod cyber_timeline;
pub mod destination;
pub mod dictionary;
pub mod discovery;
pub mod discovery_paging;
pub mod discovery_plan;
pub mod discovery_rank;
pub mod enrollment;
pub mod evidence_graph;
pub mod explanation;
pub mod export;
pub mod fault;
pub mod graph_layout;
pub mod hub_access;
pub mod hub_backpressure;
pub mod hub_catchup;
pub mod hub_client;
pub mod hub_command;
pub mod hub_cyber;
pub mod hub_event;
pub mod hub_identity;
pub mod hub_live;
pub mod hub_notes;
pub mod hub_person;
pub mod hub_presence;
pub mod hub_report;
pub mod hub_review;
pub mod identity;
pub mod identity_link;
pub mod identity_resolution;
pub mod indicator;
pub mod interruption;
pub mod kev;
pub mod language;
pub mod monitoring_account;
pub mod monitoring_template;
pub mod motion;
pub mod note;
pub mod notification;
pub mod observation_window;
pub mod observed_identity;
pub mod office_network;
pub mod organisation;
pub mod origin;
pub mod person;
pub mod person_timeline;
pub mod provenance;
pub(crate) mod readable_code;
pub mod reason;
pub mod reference;
pub mod relevance;
pub mod remote_command;
pub mod report;
pub mod report_template;
pub mod retention;
pub mod review;
pub mod run_mode;
pub mod saved_search;
pub mod schedule;
pub mod session;
pub mod settings;
pub mod source;
pub mod source_health;
pub mod source_reliability;
pub mod stix;
pub mod telegram_account;
pub mod tour;
pub mod why;
pub mod workspace;

pub use crate::model::acquisition::{
    ContentDeletion, ContentVersion, IdempotencyKey, InboxEntry, InboxEventKind, InboxOutcome,
    InboxState, NewContentDeletion, NewContentVersion, NewInboxEntry,
};
pub use crate::model::alert::{Alert, AlertLevel, NewAlert};
pub use crate::model::analysis::{AnalysisLevel, ContentMatch, MatchRange, NewMatch};
pub use crate::model::audit::{AuditEntry, NewAuditEntry};
pub use crate::model::content::{
    AcquisitionMode, AcquisitionOrigin, Content, ContentInsertion, NewContent, RECOVERY_LIMITS,
    dates_sentence,
};
pub use crate::model::destination::ExportDestination;
pub use crate::model::enrollment::{
    DeviceToken, EnrollmentCode, EnrollmentGrant, EnrollmentRefusal, EnrollmentRequest,
    EnrollmentSalt,
};
pub use crate::model::export::{Export, ExportFormat, NewExport};
pub use crate::model::fault::{Fault, FaultKind, NewFault};
pub use crate::model::identity::{
    DEVICE_ID_BYTES, DEVICE_SECRET_BYTES, DeviceId, DeviceIdentity, DeviceSecret, DeviceState,
    LOCAL_OPERATOR, OperatorId,
};
pub use crate::model::indicator::{CyberIndicator, Extraction, IndicatorKind};
pub use crate::model::notification::{EmittedNotification, NewNotification, NotificationPrivacy};
pub use crate::model::review::{NewReview, Review, ReviewState};
pub use crate::model::session::{
    NewSession, Session, SessionDuration, SessionDurationMode, SessionState,
};
pub use crate::model::settings::{
    MAX_NOTIFY_LEVEL, MAX_PER_SESSION_CAP, MIN_NOTIFY_LEVEL, NotificationSettings,
};
pub use crate::model::source::{NewSource, Source, SourceKind};
pub use crate::model::telegram_account::{
    AccountUuid, ApiCredentialProfile, MaskedPhoneNumber, NewApiCredentialProfile,
    NewTelegramAccount, PersistedAuthStatus, PersistedConnectionStatus, TelegramAccount,
};

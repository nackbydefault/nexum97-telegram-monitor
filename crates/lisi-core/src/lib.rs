#![forbid(unsafe_code)]

//! Modello di dominio condiviso di LISI Telegram Monitor.
//!
//! Il crate non conosce né la persistenza né l'interfaccia grafica: contiene i
//! tipi, le loro invarianti e la validazione. La Milestone 1 introduce le entità
//! di fonti, sessioni, contenuti, match, alert, revisioni, errori, audit ed
//! export.

pub mod analysis;
pub mod attribution;
pub mod branding;
pub mod digest;
pub mod error;
pub mod glossary;
pub mod guide;
pub mod id;
pub mod model;
#[cfg(test)]
mod prova_di_proprieta;
pub mod role;
pub mod security_messages;
pub mod security_translations;
pub mod text;
pub mod time;

use core::fmt;

pub use crate::attribution::{PRODUCT_LICENSE, THIRD_PARTY_COMPONENTS, ThirdPartyComponent};
pub use crate::branding::{PRODUCT_NAME, PRODUCT_SUBTITLE, window_title};
pub use crate::digest::Sha256Digest;
pub use crate::error::{DomainError, DomainResult};
pub use crate::id::{
    AlertId, ApiCredentialProfileId, AssessmentId, AttackAssociationId, AttackSnapshotId, AuditId,
    BookmarkCollectionId, BookmarkId, ContentDeletionId, ContentId, ContentVersionId,
    ContextSnapshotId, CveSnapshotId, DictionaryId, DictionaryProfileId, DictionaryTermId,
    DictionaryVersionId, ExportId, FaultId, IdentityLinkId, IdentityResolutionId, InboxId,
    KevSnapshotId, MatchId, MonitoringTemplateId, NoteId, NotificationId, PersonId,
    ReportArtifactId, ReportPackageId, ReviewId, SavedSearchId, SessionId, SourceId,
    TelegramAccountId, WatchedOrganisationId, WorkspaceId,
};
pub use crate::role::{OperatingMode, RestrictedAction};
pub use crate::time::Timestamp;

/// Nome pubblico dell'applicazione.
///
/// Rimanda a [`crate::branding::PRODUCT_NAME`], dove il nome sta accanto agli
/// identificatori persistenti che **non** cambiano con esso.
pub const APP_NAME: &str = crate::branding::PRODUCT_NAME;

/// Formula di attribuzione del prodotto, unica per ogni superficie.
pub const ATTRIBUTION: &str = crate::branding::ATTRIBUTION;

/// Stato iniziale esposto dalla shell grafica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationState {
    /// La shell è stata inizializzata e non è ancora configurato alcun account.
    ReadyForConfiguration,
}

impl ApplicationState {
    /// Testo semplice destinato all'operatore.
    #[must_use]
    pub const fn operator_message(self) -> &'static str {
        match self {
            Self::ReadyForConfiguration => {
                "Applicazione pronta. I moduli Telegram saranno aggiunti nelle prossime milestone."
            }
        }
    }
}

impl fmt::Display for ApplicationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.operator_message())
    }
}

/// Metadati mostrati nella finestra e utilizzati dai log di avvio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppMetadata {
    /// Nome pubblico dell'applicazione.
    pub name: &'static str,
    /// Versione compilata.
    pub version: &'static str,
    /// Formula di attribuzione del prodotto.
    pub attribution: &'static str,
    /// Stato iniziale.
    pub state: ApplicationState,
}

impl AppMetadata {
    /// Costruisce i metadati dalla versione Cargo compilata.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            name: APP_NAME,
            version: env!("CARGO_PKG_VERSION"),
            attribution: ATTRIBUTION,
            state: ApplicationState::ReadyForConfiguration,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{APP_NAME, ATTRIBUTION, AppMetadata, ApplicationState};

    #[test]
    fn current_metadata_contains_the_expected_identity() {
        let metadata = AppMetadata::current();

        assert_eq!(metadata.name, APP_NAME);
        assert_eq!(metadata.attribution, ATTRIBUTION);
        assert!(!metadata.version.is_empty());
        assert_eq!(metadata.state, ApplicationState::ReadyForConfiguration);
    }

    #[test]
    fn initial_state_is_explained_without_technical_jargon() {
        let message = ApplicationState::ReadyForConfiguration.operator_message();

        assert!(message.contains("Applicazione pronta"));
        assert!(!message.contains("panic"));
    }
}

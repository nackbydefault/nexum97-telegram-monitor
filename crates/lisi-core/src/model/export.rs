//! Export prodotti.
//!
//! Di ogni export si conserva il percorso e l'impronta del file prodotto, così
//! che sia possibile verificare in seguito che il documento consegnato sia
//! esattamente quello generato dall'applicazione.

use crate::digest::Sha256Digest;
use crate::id::{ExportId, SessionId};
use crate::text::{Actor, ExportPath};
use crate::time::Timestamp;

string_enum!(
    /// Formato del documento prodotto.
    ExportFormat {
        /// Documento PDF.
        Pdf => "pdf",
        /// Testo semplice.
        Txt => "txt",
        /// Foglio di calcolo.
        Xlsx => "xlsx",
    }
);

impl ExportFormat {
    /// Estensione del file, senza punto.
    #[must_use]
    pub const fn extension(self) -> &'static str {
        self.as_str()
    }
}

/// Export che si intende registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewExport {
    /// Sessione documentata dall'export.
    pub session_id: SessionId,
    /// Formato prodotto.
    pub format: ExportFormat,
    /// Percorso del file generato.
    pub path: ExportPath,
    /// Impronta del file generato.
    pub sha256: Sha256Digest,
    /// Soggetto che ha richiesto l'export.
    pub requested_by: Actor,
    /// Istante di produzione.
    pub created_at: Timestamp,
}

/// Export registrato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    /// Identificatore assegnato dalla persistenza.
    pub id: ExportId,
    /// Sessione documentata dall'export.
    pub session_id: SessionId,
    /// Formato prodotto.
    pub format: ExportFormat,
    /// Percorso del file generato.
    pub path: ExportPath,
    /// Impronta del file generato.
    pub sha256: Sha256Digest,
    /// Soggetto che ha richiesto l'export.
    pub requested_by: Actor,
    /// Istante di produzione.
    pub created_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::ExportFormat;
    use crate::error::DomainError;

    #[test]
    fn every_format_survives_a_round_trip_through_its_stored_form() {
        for format in ExportFormat::all() {
            assert_eq!(ExportFormat::from_str(format.as_str()), Ok(*format));
        }
    }

    #[test]
    fn the_three_required_formats_are_present() {
        assert_eq!(
            ExportFormat::all(),
            &[ExportFormat::Pdf, ExportFormat::Txt, ExportFormat::Xlsx]
        );
    }

    #[test]
    fn an_unsupported_format_is_rejected() {
        assert!(matches!(
            ExportFormat::from_str("csv"),
            Err(DomainError::UnknownVariant { .. })
        ));
    }

    #[test]
    fn the_extension_matches_the_stored_form() {
        assert_eq!(ExportFormat::Pdf.extension(), "pdf");
        assert_eq!(ExportFormat::Xlsx.extension(), "xlsx");
    }
}

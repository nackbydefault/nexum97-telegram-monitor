//! Le relazioni dell'ufficio, come una postazione le vede (TEAM-REPORT-01,
//! ADR-0100).
//!
//! # Che cosa una postazione vede di una relazione
//!
//! Quale sessione, chi l'ha chiesta, in quale stato è, **di quando è la
//! fotografia**, quanti contenuti erano monitorati e quanti rappresentati, e
//! **come si chiamano** i documenti prodotti con la loro impronta.
//!
//! **Nomi e impronte, non byte.** Il protocollo dell'Hub non trasporta
//! documenti: sono grandi, e farli passare da un canale pensato per messaggi
//! brevi vorrebbe dire inventare lì un trasferimento di file con le sue
//! interruzioni e i suoi riavvii. L'impronta serve a chi riceve il documento
//! per altra via a **verificare che sia quello**.
//!
//! # Perché l'istante della fotografia è un campo a sé
//!
//! Perché è la cosa che rende una relazione leggibile domani: dice **di
//! quando parla**. Una relazione senza quell'istante sembra parlare di adesso
//! anche quando è di un mese fa (DEC-152).

use crate::model::report::ReportGenerationStatus;
use crate::{SessionId, Timestamp};

/// Relazioni al più in una pagina.
pub const MAX_SHARED_REPORTS_PAGE: usize = 50;

/// Contenuti al più in una selezione che arriva da una postazione.
///
/// Cinquecento: una relazione con più riscontri di così non si legge, e un
/// elenco senza tetto è un frame senza tetto.
pub const MAX_REPORT_SELECTION: usize = 500;

/// Un documento prodotto, come una postazione lo vede.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedArtifact {
    /// Come si chiama il file.
    pub file_name: String,
    /// Quanto è grande, in byte.
    pub size_bytes: u64,
    /// L'impronta SHA-256, per chi lo riceve per altra via.
    pub sha256: String,
}

/// Una relazione dell'ufficio, come una postazione la vede.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedReport {
    /// L'identificativo citabile.
    pub report_id: String,
    /// Quale sessione documenta.
    pub session_id: SessionId,
    /// Chi l'ha chiesta.
    pub requested_by: String,
    /// In quale stato è.
    pub status: ReportGenerationStatus,
    /// Quando è stata chiesta.
    pub requested_at: Timestamp,
    /// Quando è stata completata, se lo è stata.
    pub completed_at: Option<Timestamp>,
    /// Quanti contenuti la sessione aveva al momento della fotografia.
    pub monitored: usize,
    /// Quanti se ne rappresentano.
    pub selected: usize,
    /// I documenti prodotti: **nomi e impronte, mai byte**.
    pub artifacts: Vec<SharedArtifact>,
}

impl SharedReport {
    /// Quanti contenuti **non** sono rappresentati.
    ///
    /// Non è un dettaglio di comodità: una selezione si giudica sapendo che
    /// cosa resta fuori.
    #[must_use]
    pub const fn excluded(&self) -> usize {
        self.monitored.saturating_sub(self.selected)
    }

    /// Se questa relazione è consegnabile.
    #[must_use]
    pub const fn is_deliverable(&self) -> bool {
        self.status.is_deliverable()
    }
}

#[cfg(test)]
mod tests {
    use super::{SharedArtifact, SharedReport};
    use crate::model::report::ReportGenerationStatus;
    use crate::{SessionId, Timestamp};

    fn relazione(monitored: usize, selected: usize) -> SharedReport {
        SharedReport {
            report_id: String::from("2026-0001"),
            session_id: SessionId::new(1),
            requested_by: String::from("persona.mrossi"),
            status: ReportGenerationStatus::Completed,
            requested_at: Timestamp::from_millis(0),
            completed_at: Some(Timestamp::from_millis(10)),
            monitored,
            selected,
            artifacts: vec![SharedArtifact {
                file_name: String::from("Relazione_2026-0001.docx"),
                size_bytes: 1_024,
                sha256: "a".repeat(64),
            }],
        }
    }

    #[test]
    fn una_relazione_dice_anche_che_cosa_resta_fuori() {
        assert_eq!(relazione(10, 3).excluded(), 7);
    }

    #[test]
    fn i_conteggi_incoerenti_non_producono_un_numero_assurdo() {
        // Una fotografia con più selezionati che monitorati non dovrebbe
        // esistere; se arrivasse dalla rete, «meno tre esclusi» sarebbe
        // peggio di «zero».
        assert_eq!(relazione(1, 5).excluded(), 0);
    }

    #[test]
    fn un_documento_porta_il_nome_e_l_impronta_e_non_i_byte() {
        let relazione = relazione(5, 5);
        let mostrata = format!("{relazione:?}");
        assert!(mostrata.contains("Relazione_2026-0001.docx"));
        assert!(mostrata.contains(&"a".repeat(64)));
        assert!(
            !mostrata.contains("body"),
            "una relazione vista da una postazione non porta contenuti"
        );
    }
}

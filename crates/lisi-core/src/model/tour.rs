//! Lo stato di «Scopri NEXUM», il tour guidato (TOUR-01, ADR-0134).
//!
//! # Che cosa è
//!
//! Una **preferenza di interfaccia**: se il tour è stato proposto, saltato,
//! interrotto a un passo, completato. Non è una prova, non è un contenuto e non
//! è un atto: non entra nell'audit, non porta un attore e non porta testo
//! libero (migrazione 0057).
//!
//! # Perché l'assenza è uno stato
//!
//! «Mai proposto» non ha una riga: è l'assenza della riga, come per il profilo
//! documentale (migrazione 0015). Lo rappresenta [`TourStatus::NeverProposed`],
//! e nessun valore di [`TourPhase`] lo imita.

use core::fmt;

/// La versione del tour che questo programma mostra.
///
/// Cresce quando il percorso cambia abbastanza da meritare che chi lo ha già
/// completato lo sappia. Chi ha completato una versione precedente **non** si
/// vede riproporre il tour intero: il servizio ne espone soltanto il fatto
/// (ADR-0134 §10).
///
/// Versione 2 (OPERATOR-E2E-REMEDIATION-01, F-20): l'ordine del primo uso, il
/// passo dell'Esercitazione e l'Account per tutti.
pub const TOUR_VERSION: u32 = 2;

/// La lunghezza massima di una chiave di passo, la stessa dello schema.
pub const MAX_STEP_KEY_LEN: usize = 64;

/// A che punto è il tour, quando ha una riga.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TourPhase {
    /// Proposto, senza una scelta: dalla finestra del primo avvio chiusa senza
    /// rispondere, oppure su una configurazione che esisteva già.
    Proposed,
    /// Saltato: «Salta per ora», o il pannello aperto e chiuso senza avviare.
    Skipped,
    /// Iniziato e non finito: si può continuare dal passo conservato.
    InProgress,
    /// Percorso fino all'ultimo passo.
    Completed,
}

impl TourPhase {
    /// L'etichetta stabile, per l'archivio. Sono i valori ammessi dal `CHECK`
    /// della migrazione 0057.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposto",
            Self::Skipped => "saltato",
            Self::InProgress => "in_corso",
            Self::Completed => "completato",
        }
    }

    /// Riconosce una fase dalla propria etichetta.
    ///
    /// Un valore sconosciuto diventa **saltato**: davanti a uno stato che non
    /// si capisce, la risposta prudente è non riproporre nulla da sé. Il
    /// tour resta raggiungibile dalla sua voce.
    #[must_use]
    pub fn from_stored(raw: &str) -> Self {
        [
            Self::Proposed,
            Self::Skipped,
            Self::InProgress,
            Self::Completed,
        ]
        .into_iter()
        .find(|phase| phase.as_str() == raw)
        .unwrap_or(Self::Skipped)
    }
}

/// La chiave di un passo: lettere minuscole e trattini bassi, al più
/// [`MAX_STEP_KEY_LEN`] caratteri. Mai testo libero.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TourStepKey(String);

impl TourStepKey {
    /// Una chiave, se ha la forma ammessa.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let ammessa = !raw.is_empty()
            && raw.len() <= MAX_STEP_KEY_LEN
            && raw
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_');
        ammessa.then(|| Self(raw.to_owned()))
    }

    /// La chiave come testo.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TourStepKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// La riga di `tour_state`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TourRecord {
    /// La fase.
    pub phase: TourPhase,
    /// La versione del tour a cui la fase si riferisce.
    pub tour_version: u32,
    /// L'ultimo passo raggiunto: solo per un tour in corso.
    pub last_step: Option<TourStepKey>,
    /// L'ultima versione completata per intero.
    pub completed_version: Option<u32>,
}

/// Lo stato del tour su questa postazione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TourStatus {
    /// Nessuna riga: il tour non è mai stato proposto.
    NeverProposed,
    /// La riga conservata.
    Recorded(TourRecord),
}

impl TourStatus {
    /// La fase, se c'è una riga.
    #[must_use]
    pub const fn phase(&self) -> Option<TourPhase> {
        match self {
            Self::NeverProposed => None,
            Self::Recorded(record) => Some(record.phase),
        }
    }

    /// L'ultima versione completata, se c'è.
    #[must_use]
    pub const fn completed_version(&self) -> Option<u32> {
        match self {
            Self::NeverProposed => None,
            Self::Recorded(record) => record.completed_version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TourPhase, TourStepKey};

    #[test]
    fn ogni_fase_si_rilegge_dalla_propria_etichetta() {
        for fase in [
            TourPhase::Proposed,
            TourPhase::Skipped,
            TourPhase::InProgress,
            TourPhase::Completed,
        ] {
            assert_eq!(TourPhase::from_stored(fase.as_str()), fase);
        }
    }

    /// **Una fase che questo programma non conosce non fa riproporre il
    /// tour**: diventa «saltato».
    #[test]
    fn una_fase_sconosciuta_diventa_saltato() {
        assert_eq!(TourPhase::from_stored("novita"), TourPhase::Skipped);
        assert_eq!(TourPhase::from_stored(""), TourPhase::Skipped);
    }

    #[test]
    fn una_chiave_e_fatta_di_minuscole_e_trattini_bassi() {
        assert!(TourStepKey::parse("coda_di_lavoro").is_some());
        for vietata in ["", "Fonti", "fonti 2", "fonti-2", "perché", &"a".repeat(65)] {
            assert!(
                TourStepKey::parse(vietata).is_none(),
                "«{vietata}» non è una chiave"
            );
        }
    }
}

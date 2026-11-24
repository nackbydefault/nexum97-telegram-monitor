//! Mitigazioni e rilevazioni di ATT&CK, per la scheda della tecnica
//! (ATTACK-03, ADR-0185, decisioni 4–6).
//!
//! Sono materiale di riferimento di MITRE: ciò che ATT&CK suggerisce per
//! difendersi da una tecnica e come riconoscerla. Nessun attore passa di qui.

use crate::model::attack::AttackTechniqueId;

/// Quanto può essere lungo un nome.
const MAX_NAME_CHARS: usize = 200;

/// Quanto può essere lunga una descrizione.
const MAX_DESCRIPTION_CHARS: usize = 20_000;

/// Che cosa suggerisce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuidanceKind {
    /// Una contromisura (`course-of-action`, identificativo `M` più quattro
    /// cifre).
    Mitigation,
    /// Una strategia di rilevamento (`x-mitre-detection-strategy`,
    /// identificativo `DET` più quattro cifre).
    Detection,
}

impl GuidanceKind {
    /// La forma conservata.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mitigation => "mitigazione",
            Self::Detection => "rilevazione",
        }
    }

    /// Dalla forma conservata.
    #[must_use]
    pub fn from_stored(testo: &str) -> Option<Self> {
        match testo {
            "mitigazione" => Some(Self::Mitigation),
            "rilevazione" => Some(Self::Detection),
            _ => None,
        }
    }

    /// Se l'identificativo ha la forma di questo genere.
    #[must_use]
    pub fn accepts(self, id: &str) -> bool {
        let (prefisso, cifre) = match self {
            Self::Mitigation => ("M", 4),
            Self::Detection => ("DET", 4),
        };
        id.strip_prefix(prefisso)
            .is_some_and(|resto| resto.len() == cifre && resto.chars().all(|c| c.is_ascii_digit()))
    }
}

/// Una mitigazione o una rilevazione, con le tecniche a cui si riferisce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackGuidance {
    kind: GuidanceKind,
    id: String,
    name: String,
    description: String,
    techniques: Vec<AttackTechniqueId>,
}

impl AttackGuidance {
    /// Conserva una voce, o `None` se non ha la forma attesa: identificativo
    /// del suo genere, nome su una riga, descrizione entro il tetto.
    #[must_use]
    pub fn new(
        kind: GuidanceKind,
        id: &str,
        name: &str,
        description: &str,
        techniques: Vec<AttackTechniqueId>,
    ) -> Option<Self> {
        let name = name.trim();
        if !kind.accepts(id)
            || name.is_empty()
            || name.chars().count() > MAX_NAME_CHARS
            || name.chars().any(char::is_control)
            || description.chars().count() > MAX_DESCRIPTION_CHARS
        {
            return None;
        }
        Some(Self {
            kind,
            id: id.to_owned(),
            name: name.to_owned(),
            description: description.to_owned(),
            techniques,
        })
    }

    /// Il genere.
    #[must_use]
    pub const fn kind(&self) -> GuidanceKind {
        self.kind
    }

    /// L'identificativo ATT&CK.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Il nome.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// La descrizione di MITRE.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Le tecniche a cui si riferisce.
    #[must_use]
    pub fn techniques(&self) -> &[AttackTechniqueId] {
        &self.techniques
    }
}

#[cfg(test)]
mod tests {
    use super::{AttackGuidance, GuidanceKind};

    /// **Ogni genere ha la sua forma di identificativo**, e una voce storta
    /// non si conserva.
    #[test]
    fn ogni_genere_ha_la_sua_forma() {
        assert!(GuidanceKind::Mitigation.accepts("M1038"));
        assert!(GuidanceKind::Detection.accepts("DET0001"));
        for (genere, storto) in [
            (GuidanceKind::Mitigation, "M103"),
            (GuidanceKind::Mitigation, "DET0001"),
            (GuidanceKind::Detection, "M1038"),
            (GuidanceKind::Detection, "DET00011"),
        ] {
            assert!(!genere.accepts(storto), "{storto}");
        }
        assert!(
            AttackGuidance::new(GuidanceKind::Mitigation, "M1038", " ", "", Vec::new()).is_none()
        );
        assert!(
            AttackGuidance::new(
                GuidanceKind::Mitigation,
                "M1038",
                "Ex\necution",
                "",
                Vec::new()
            )
            .is_none()
        );
        assert_eq!(
            GuidanceKind::from_stored(GuidanceKind::Detection.as_str()),
            Some(GuidanceKind::Detection)
        );
    }
}

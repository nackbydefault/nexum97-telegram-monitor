//! Il punteggio CVSS di una CVE (CVSS-01, ADR-0184).
//!
//! Sta qui e non in [`crate::model::cve`] di proposito: il record della CVE
//! non porta punteggi, e una guardia lo sorveglia. Il punteggio si legge
//! soltanto nella scheda della CVE, e la sua frase dice sempre che cosa grada
//! (ADR-0184, decisione 3).

use std::fmt;

/// La frase che accompagna sempre il punteggio.
pub const WHAT_IT_GRADES: &str =
    "Il punteggio grada la vulnerabilità, non un messaggio né chi lo ha scritto.";

/// Quanto può essere lungo un vettore CVSS.
const MAX_VECTOR_CHARS: usize = 255;

/// Quanto può essere lunga la fonte che ha assegnato il punteggio.
const MAX_SOURCE_CHARS: usize = 120;

/// La versione di CVSS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CvssVersion {
    /// CVSS 2.0.
    V2,
    /// CVSS 3.0.
    V30,
    /// CVSS 3.1.
    V31,
    /// CVSS 4.0.
    V40,
}

impl CvssVersion {
    /// La forma conservata e mostrata.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V2 => "2.0",
            Self::V30 => "3.0",
            Self::V31 => "3.1",
            Self::V40 => "4.0",
        }
    }

    /// Dalla forma conservata.
    #[must_use]
    pub fn from_stored(testo: &str) -> Option<Self> {
        match testo {
            "2.0" => Some(Self::V2),
            "3.0" => Some(Self::V30),
            "3.1" => Some(Self::V31),
            "4.0" => Some(Self::V40),
            _ => None,
        }
    }
}

/// Perché un punteggio non si accetta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CvssRefusal {
    /// Il punteggio di base è fuori da 0–10 o ha più di un decimale.
    BaseOutOfRange,
    /// Il vettore è vuoto, troppo lungo o ha caratteri inattesi.
    MalformedVector,
    /// La severità è vuota o su più righe.
    MalformedSeverity,
    /// La fonte è vuota, troppo lunga o su più righe.
    MalformedSource,
}

/// Il punteggio di una CVE, come NVD lo dichiara.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CvssScore {
    version: CvssVersion,
    vector: String,
    base_tenths: u8,
    severity: String,
    source: String,
}

impl CvssScore {
    /// Conserva un punteggio, o dice perché non si può.
    ///
    /// Il punteggio di base è in decimi (da 0 a 100): `9.8` è `98`. Un valore
    /// che non si legge non si corregge (ADR-0184, decisione 6).
    ///
    /// # Errori
    ///
    /// [`CvssRefusal`], con il motivo.
    pub fn try_new(
        version: CvssVersion,
        vector: &str,
        base_tenths: u8,
        severity: &str,
        source: &str,
    ) -> Result<Self, CvssRefusal> {
        if base_tenths > 100 {
            return Err(CvssRefusal::BaseOutOfRange);
        }
        if vector.is_empty()
            || vector.chars().count() > MAX_VECTOR_CHARS
            || !vector
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '/' | '.' | '(' | ')'))
        {
            return Err(CvssRefusal::MalformedVector);
        }
        let severity = severity.trim();
        if severity.is_empty()
            || severity.chars().count() > 20
            || severity.chars().any(char::is_control)
        {
            return Err(CvssRefusal::MalformedSeverity);
        }
        let source = source.trim();
        if source.is_empty()
            || source.chars().count() > MAX_SOURCE_CHARS
            || source.chars().any(char::is_control)
        {
            return Err(CvssRefusal::MalformedSource);
        }
        Ok(Self {
            version,
            vector: vector.to_owned(),
            base_tenths,
            severity: severity.to_owned(),
            source: source.to_owned(),
        })
    }

    /// Il punteggio di base, come NVD lo scrive (`9.8`), in decimi.
    ///
    /// # Errori
    ///
    /// [`CvssRefusal::BaseOutOfRange`] se non è un numero da 0 a 10 con al più
    /// un decimale.
    pub fn tenths_of(base: f64) -> Result<u8, CvssRefusal> {
        let decimi = (base * 10.0).round();
        if !(0.0..=100.0).contains(&decimi) || (base * 10.0 - decimi).abs() > 1e-6 {
            return Err(CvssRefusal::BaseOutOfRange);
        }
        // Il controllo qui sopra tiene il valore fra 0 e 100.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Ok(decimi as u8)
    }

    /// La versione.
    #[must_use]
    pub const fn version(&self) -> CvssVersion {
        self.version
    }

    /// Il vettore.
    #[must_use]
    pub fn vector(&self) -> &str {
        &self.vector
    }

    /// Il punteggio di base, in decimi.
    #[must_use]
    pub const fn base_tenths(&self) -> u8 {
        self.base_tenths
    }

    /// La severità, come NVD la scrive.
    #[must_use]
    pub fn severity(&self) -> &str {
        &self.severity
    }

    /// Chi ha assegnato il punteggio.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// La frase della scheda della CVE: versione, punteggio, severità, fonte,
    /// e che cosa grada (ADR-0184, decisione 3).
    #[must_use]
    pub fn as_sentence(&self) -> String {
        format!(
            "CVSS {}: {},{} ({}), assegnato da {}. Vettore: {}. {WHAT_IT_GRADES}",
            self.version.as_str(),
            self.base_tenths / 10,
            self.base_tenths % 10,
            self.severity,
            self.source,
            self.vector
        )
    }
}

impl fmt::Display for CvssScore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.as_sentence())
    }
}

#[cfg(test)]
mod tests {
    use super::{CvssRefusal, CvssScore, CvssVersion, WHAT_IT_GRADES};

    fn punteggio() -> CvssScore {
        let Ok(punteggio) = CvssScore::try_new(
            CvssVersion::V31,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            98,
            "CRITICAL",
            "nvd@nist.gov",
        ) else {
            panic!("un punteggio di NVD si conserva");
        };
        punteggio
    }

    /// **La frase dice versione, punteggio, fonte e che cosa grada**
    /// (ADR-0184, decisione 3).
    #[test]
    fn la_frase_dice_che_cosa_grada() {
        let frase = punteggio().as_sentence();
        assert!(frase.starts_with("CVSS 3.1: 9,8 (CRITICAL), assegnato da nvd@nist.gov."));
        assert!(frase.ends_with(WHAT_IT_GRADES));
    }

    /// **Un punteggio che non si legge non si corregge** (ADR-0184,
    /// decisione 6).
    #[test]
    fn un_punteggio_che_non_si_legge_si_rifiuta() {
        assert_eq!(CvssScore::tenths_of(9.8), Ok(98));
        assert_eq!(CvssScore::tenths_of(0.0), Ok(0));
        assert_eq!(CvssScore::tenths_of(10.0), Ok(100));
        for sbagliato in [10.1, -0.1, 9.85, f64::NAN] {
            assert_eq!(
                CvssScore::tenths_of(sbagliato),
                Err(CvssRefusal::BaseOutOfRange),
                "{sbagliato}"
            );
        }
        assert_eq!(
            CvssScore::try_new(CvssVersion::V31, "AV:N <script>", 50, "MEDIUM", "nvd"),
            Err(CvssRefusal::MalformedVector)
        );
        assert_eq!(
            CvssScore::try_new(CvssVersion::V31, "AV:N", 101, "MEDIUM", "nvd"),
            Err(CvssRefusal::BaseOutOfRange)
        );
        assert_eq!(
            CvssScore::try_new(CvssVersion::V31, "AV:N", 50, "ME\nDIUM", "nvd"),
            Err(CvssRefusal::MalformedSeverity)
        );
        assert_eq!(
            CvssScore::try_new(CvssVersion::V31, "AV:N", 50, "MEDIUM", " "),
            Err(CvssRefusal::MalformedSource)
        );
        assert_eq!(CvssVersion::from_stored("3.1"), Some(CvssVersion::V31));
        assert_eq!(CvssVersion::from_stored("5.0"), None);
        assert!(CvssVersion::V40 > CvssVersion::V31);
    }
}

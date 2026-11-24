//! In che lingua l'interfaccia parla all'operatore (I18N-01, ADR-0197).
//!
//! # Perché la scelta sta nel dominio e il catalogo no
//!
//! Che cosa la postazione ha scelto è una **configurazione**: si conserva in
//! archivio, con chi l'ha fatta e quando, come la preferenza sul movimento.
//! Le traduzioni invece sono testo dell'interfaccia e vivono accanto a essa,
//! nel catalogo di `lisi-app`.
//!
//! L'italiano è la lingua di partenza: il testo italiano è la chiave del
//! catalogo, e scegliere l'italiano significa non tradurre niente.

/// La lingua dell'interfaccia scelta per la postazione.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InterfaceLanguage {
    /// La lingua in cui il prodotto è scritto. È il predefinito.
    #[default]
    Italian,
    /// La prima lingua aggiunta (ADR-0197, decisione 3).
    English,
}

impl InterfaceLanguage {
    /// Le scelte, nell'ordine in cui si mostrano.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Italian, Self::English]
    }

    /// Il nome della lingua, scritto nella lingua stessa: chi non legge
    /// l'italiano deve poter riconoscere la propria.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Italian => "Italiano",
            Self::English => "English",
        }
    }

    /// Che cosa comporta, detto in una frase.
    #[must_use]
    pub const fn consequence(&self) -> &'static str {
        match self {
            Self::Italian => "L'interfaccia è in italiano, come i documenti consegnati.",
            Self::English => {
                "L'interfaccia è in inglese dove la traduzione c'è. I documenti \
                 consegnati restano in italiano. Un'avvertenza tradotta si legge \
                 in inglese solo dopo la revisione di una persona."
            }
        }
    }

    /// L'etichetta stabile, per l'archivio. È anche il nome della cartella
    /// del catalogo (`translations/<codice>/`).
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Italian => "it",
            Self::English => "en",
        }
    }

    /// Riconosce una scelta dalla propria etichetta.
    ///
    /// Un valore sconosciuto diventa l'italiano: è la lingua in cui ogni
    /// testo esiste per intero.
    #[must_use]
    pub fn from_stored(raw: &str) -> Self {
        Self::all()
            .iter()
            .copied()
            .find(|choice| choice.as_str() == raw)
            .unwrap_or(Self::Italian)
    }

    /// Se il testo va cercato in un catalogo. L'italiano non ne ha: è la
    /// chiave.
    #[must_use]
    pub const fn translates(&self) -> bool {
        !matches!(self, Self::Italian)
    }
}

#[cfg(test)]
mod tests {
    use super::InterfaceLanguage;

    #[test]
    fn l_italiano_e_il_predefinito_e_non_traduce() {
        assert_eq!(InterfaceLanguage::default(), InterfaceLanguage::Italian);
        assert!(!InterfaceLanguage::Italian.translates());
        assert!(InterfaceLanguage::English.translates());
    }

    #[test]
    fn ogni_scelta_torna_dalla_propria_etichetta() {
        for scelta in InterfaceLanguage::all() {
            assert_eq!(InterfaceLanguage::from_stored(scelta.as_str()), *scelta);
        }
        assert_eq!(
            InterfaceLanguage::from_stored("klingon"),
            InterfaceLanguage::Italian
        );
    }
}

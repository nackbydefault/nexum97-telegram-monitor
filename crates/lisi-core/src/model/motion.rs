//! Come l'operatore vuole il movimento dell'interfaccia.
//!
//! # Perche' la scelta sta nel dominio e la lettura del sistema no
//!
//! Che cosa Windows preferisce e' una domanda alla **piattaforma**, e vive in
//! `lisi-platform`. Che cosa l'ufficio ha scelto e' una **configurazione**, si
//! conserva in archivio e si cita in un audit: vive qui, dove l'archivio puo'
//! raggiungerla senza dipendere da Windows.
//!
//! Il movimento del prodotto e' deliberato — il radar che ruota dice a colpo
//! d'occhio se il monitoraggio gira (ADR-0026) — ma per una parte delle persone
//! il movimento non e' un'informazione, e' un sintomo.

/// Che cosa l'operatore ha scelto, sopra la preferenza del sistema.
///
/// # Perché tre valori e non un booleano
///
/// «Segui Windows» è uno stato diverso da «pieno» e da «ridotto», e non è
/// riducibile a nessuno dei due: se una persona sposta l'interruttore di Windows
/// domani, chi ha scelto «segui» deve vederlo cambiare e chi ha scelto «pieno»
/// no. Un booleano perderebbe proprio quella differenza.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MotionPreference {
    /// Si segue ciò che Windows preferisce. È il predefinito.
    #[default]
    System,
    /// Movimento pieno, qualunque cosa dica Windows.
    Full,
    /// Movimento ridotto, qualunque cosa dica Windows.
    Reduced,
}

impl MotionPreference {
    /// Le scelte, nell'ordine in cui si mostrano.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::System, Self::Full, Self::Reduced]
    }

    /// L'etichetta che l'operatore legge.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::System => "Come Windows",
            Self::Full => "Movimento pieno",
            Self::Reduced => "Movimento ridotto",
        }
    }

    /// Che cosa comporta, detto in una frase.
    #[must_use]
    pub const fn consequence(&self) -> &'static str {
        match self {
            Self::System => {
                "Segue la preferenza di accessibilità di Windows, e la rispetta se \
                 cambia."
            }
            Self::Full => {
                "Il radar ruota e il puntino respira mentre il monitoraggio è \
                 attivo. È il modo in cui si vede a colpo d'occhio che sta girando."
            }
            Self::Reduced => {
                "Nessuna animazione continua. Lo stato del monitoraggio resta \
                 scritto e colorato: si legge invece di vedersi."
            }
        }
    }

    /// L'etichetta stabile, per l'archivio.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::System => "sistema",
            Self::Full => "pieno",
            Self::Reduced => "ridotto",
        }
    }

    /// Riconosce una scelta dalla propria etichetta.
    ///
    /// Un valore sconosciuto diventa «come Windows»: davanti a una scelta che
    /// non si capisce, seguire l'accessibilità del sistema è la risposta
    /// prudente.
    #[must_use]
    pub fn from_stored(raw: &str) -> Self {
        Self::all()
            .iter()
            .copied()
            .find(|choice| choice.as_str() == raw)
            .unwrap_or(Self::System)
    }

    /// Se il movimento va ridotto.
    ///
    /// # Perche' un booleano e non il tipo della piattaforma
    ///
    /// Questo modulo vive nel dominio, che non conosce Windows. Chi chiama passa
    /// cio' che il sistema chiede — `SystemMotion::asks_for_reduction()` su
    /// Windows, `false` altrove — e il dominio resta compilabile e provabile
    /// senza alcuna piattaforma sotto.
    ///
    /// E' l'unica funzione che il resto del prodotto deve chiamare: mette
    /// insieme la scelta dell'operatore e quella del sistema in una risposta
    /// sola.
    #[must_use]
    pub const fn reduces(&self, system_asks_for_reduction: bool) -> bool {
        match self {
            Self::Full => false,
            Self::Reduced => true,
            Self::System => system_asks_for_reduction,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MotionPreference;

    #[test]
    fn seguire_windows_e_il_predefinito() {
        // Chi ha gia' chiesto a Windows di ridurre lo ottiene subito, e chi non
        // ha chiesto nulla non vede cambiare l'aspetto per un aggiornamento.
        assert_eq!(MotionPreference::default(), MotionPreference::System);
    }

    #[test]
    fn una_scelta_esplicita_scavalca_il_sistema_in_entrambe_le_direzioni() {
        // Una preferenza di accessibilita' che non si potesse scavalcare sarebbe
        // una preferenza imposta.
        assert!(!MotionPreference::Full.reduces(true));
        assert!(MotionPreference::Reduced.reduces(false));
    }

    #[test]
    fn seguire_il_sistema_significa_seguirlo_davvero() {
        assert!(MotionPreference::System.reduces(true));
        assert!(!MotionPreference::System.reduces(false));
    }

    #[test]
    fn ogni_scelta_si_rilegge_uguale() {
        for scelta in MotionPreference::all() {
            assert_eq!(MotionPreference::from_stored(scelta.as_str()), *scelta);
        }
    }

    #[test]
    fn un_valore_sconosciuto_torna_a_seguire_windows() {
        // Davanti a una scelta che non si capisce, seguire l'accessibilita' del
        // sistema e' la risposta prudente.
        assert_eq!(
            MotionPreference::from_stored("qualcos'altro"),
            MotionPreference::System
        );
        assert_eq!(MotionPreference::from_stored(""), MotionPreference::System);
    }

    #[test]
    fn ogni_scelta_dice_che_cosa_comporta() {
        let mut etichette = Vec::new();
        for scelta in MotionPreference::all() {
            assert!(!scelta.label().is_empty());
            assert!(
                scelta.consequence().len() > 40,
                "{scelta:?} non dice che cosa comporta"
            );
            etichette.push(scelta.label());
        }
        etichette.sort_unstable();
        let quante = etichette.len();
        etichette.dedup();
        assert_eq!(
            etichette.len(),
            quante,
            "due scelte hanno la stessa etichetta"
        );
    }

    /// **Il movimento ridotto non toglie l'informazione, la sposta.**
    ///
    /// Il radar dice a colpo d'occhio se il monitoraggio gira. Toglierlo senza
    /// dire dove quell'informazione sia finita lascerebbe l'operatore senza, ed
    /// e' il modo in cui una funzione di accessibilita' diventa una funzione che
    /// nessuno accende.
    #[test]
    fn ridurre_dichiara_dove_finisce_l_informazione() {
        let conseguenza = MotionPreference::Reduced.consequence();
        assert!(
            conseguenza.contains("scritto") || conseguenza.contains("colorato"),
            "non dice dove finisce l'informazione che l'animazione portava: \
             «{conseguenza}»"
        );
    }
}

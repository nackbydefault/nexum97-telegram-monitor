//! La preferenza di sistema sul movimento.
//!
//! # Perché esiste
//!
//! Il movimento del prodotto — il radar che ruota, il puntino che respira, le
//! transizioni — è deliberato: dice a colpo d'occhio se il monitoraggio sta
//! davvero girando, e ADR-0026 lo tratta come informazione e non come
//! decorazione.
//!
//! Per una parte delle persone però il movimento **non è un'informazione, è un
//! sintomo**. Chi ha un disturbo vestibolare, chi soffre di emicrania con aura,
//! chi ha una sensibilità al movimento periferico paga un prezzo reale per
//! un'animazione che continua nel campo visivo mentre lavora ad altro.
//!
//! Windows ha una preferenza per questo, e il prodotto non la leggeva.
//!
//! # Perché WinRT e non Win32
//!
//! `UISettings.AnimationsEnabled` è la stessa preferenza che
//! `SystemParametersInfo(SPI_GETCLIENTAREAANIMATION)` restituisce, esposta come
//! oggetto invece che come chiamata C: **non serve `unsafe`**, e questo modulo
//! resta fuori dall'elenco dei moduli FFI che ADR-0009 governa.
//!
//! # Che cosa questo modulo NON decide
//!
//! Se ridurre il movimento. Restituisce che cosa il **sistema** preferisce; la
//! scelta finale è dell'operatore, che può contraddire il sistema in entrambe le
//! direzioni. Una preferenza di accessibilità che non si potesse scavalcare
//! sarebbe una preferenza imposta.

/// Che cosa Windows preferisce quanto al movimento.
///
/// La SCELTA dell'operatore non sta qui: vive in `lisi-core`, perche' e' una
/// configurazione che l'archivio conserva e l'audit cita. Questo crate e' il
/// livello piu' basso e non conosce il dominio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemMotion {
    /// Il sistema non chiede di ridurre le animazioni.
    Full,
    /// Il sistema chiede di ridurre le animazioni.
    Reduced,
    /// La preferenza non è stata leggibile.
    ///
    /// **Non è «ridotto».** Ridurre il movimento a chi non l'ha chiesto toglie
    /// un'informazione che il prodotto usa per dire se sta lavorando; dichiarare
    /// «pieno» a chi l'ha chiesto è peggio. Non sapere è un terzo stato, e chi
    /// chiama decide che farne — qui la scelta è ricadere su `Full`, perché è
    /// ciò che il prodotto faceva prima che questa preferenza esistesse, e un
    /// aggiornamento non deve cambiare l'aspetto a nessuno senza che lo chieda.
    Undeterminable,
}

impl SystemMotion {
    /// Vero se il sistema chiede esplicitamente di ridurre.
    ///
    /// «Non leggibile» **non** conta come richiesta.
    #[must_use]
    pub const fn asks_for_reduction(&self) -> bool {
        matches!(self, Self::Reduced)
    }

    /// La preferenza, in una frase che una persona legge.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match self {
            Self::Full => {
                String::from("Windows non chiede di ridurre le animazioni su questa postazione.")
            }
            Self::Reduced => String::from(
                "Windows chiede di ridurre le animazioni su questa postazione, e il \
                 prodotto lo rispetta. La scelta qui sotto vale comunque su questa.",
            ),
            Self::Undeterminable => String::from(
                "Non è stato possibile leggere la preferenza di Windows sulle \
                 animazioni. Il prodotto si comporta come se non fosse richiesta \
                 alcuna riduzione.",
            ),
        }
    }
}

#[cfg(windows)]
#[must_use]
pub fn system_motion() -> SystemMotion {
    use windows::UI::ViewManagement::UISettings;

    let Ok(settings) = UISettings::new() else {
        return SystemMotion::Undeterminable;
    };
    match settings.AnimationsEnabled() {
        Ok(true) => SystemMotion::Full,
        Ok(false) => SystemMotion::Reduced,
        Err(_) => SystemMotion::Undeterminable,
    }
}

/// Fuori da Windows non c'è alcuna preferenza di sistema da leggere.
#[cfg(not(windows))]
#[must_use]
pub fn system_motion() -> SystemMotion {
    SystemMotion::Undeterminable
}

#[cfg(test)]
mod tests {
    use super::{SystemMotion, system_motion};

    /// **Non sapere non e' «ridotto», e non e' nemmeno «pieno» per caso.**
    ///
    /// La ricaduta su «pieno» e' una scelta dichiarata: e' cio' che il prodotto
    /// faceva prima che questa preferenza esistesse.
    #[test]
    fn una_preferenza_non_leggibile_non_chiede_riduzione() {
        assert!(!SystemMotion::Undeterminable.asks_for_reduction());
        assert!(!SystemMotion::Full.asks_for_reduction());
        assert!(SystemMotion::Reduced.asks_for_reduction());
    }

    #[test]
    fn il_sistema_risponde_sempre_qualcosa() {
        // Non si asserisce QUALE: dipende dalla postazione. Si asserisce che la
        // domanda non esploda e che ogni esito sia dicibile.
        let stato = system_motion();
        assert!(!stato.operator_message().is_empty());
    }

    #[test]
    fn ogni_stato_di_sistema_dice_qualcosa_di_utile() {
        for stato in [
            SystemMotion::Full,
            SystemMotion::Reduced,
            SystemMotion::Undeterminable,
        ] {
            assert!(
                stato.operator_message().len() > 40,
                "{stato:?} liquida la questione"
            );
        }
    }
}

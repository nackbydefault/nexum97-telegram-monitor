//! Per quanto tempo l'ufficio conserva ciò che ha acquisito.
//!
//! # Perché il valore predefinito è «tutto»
//!
//! Non è una scelta neutra. Qualunque altro predefinito **cancellerebbe dati**
//! il giorno dell'aggiornamento, su archivi esistenti, senza che nessuno lo
//! abbia chiesto.
//!
//! Un prodotto che si porta via del materiale di servizio perché «era la
//! politica predefinita» ha fatto un danno che nessuna configurazione
//! successiva ripara. Chi vuole una conservazione limitata la sceglie.
//!
//! # Che cosa questa politica non tocca mai
//!
//! L'audit, le fotografie dei rapporti, i contenuti citati da un pacchetto
//! prodotto, e tutto ciò che è configurazione — dizionari, fonti, account,
//! credenziali. Il vincolo vive nel servizio che applica la politica; qui c'è
//! solo la politica.

/// Quanto a lungo si conserva il materiale acquisito.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RetentionPolicy {
    /// Si conserva tutto. È il predefinito, ed è la scelta prudente.
    #[default]
    Unlimited,
    /// Si conserva ciò che è più recente del numero di giorni indicato.
    Days(RetentionDays),
}

/// Un numero di giorni ammesso per la conservazione.
///
/// # Perché un tipo e non un `u32`
///
/// Una conservazione di **zero giorni** cancellerebbe ciò che si è appena
/// acquisito: non è una politica, è un guasto travestito da configurazione. Il
/// tipo lo rende impossibile invece di lasciarlo a un controllo che qualcuno
/// dimenticherà.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RetentionDays(u32);

/// Il minimo ammesso: un giorno.
pub const MIN_RETENTION_DAYS: u32 = 1;

/// Il massimo ammesso: dieci anni.
///
/// Oltre, «limitata» e «illimitata» smettono di essere due cose diverse, e una
/// politica che non si distingue dall'assenza di politica confonde chi la legge.
pub const MAX_RETENTION_DAYS: u32 = 3_650;

impl RetentionDays {
    /// Costruisce un numero di giorni ammesso.
    ///
    /// # Errori
    ///
    /// Restituisce la ragione, in italiano piano, se il valore è fuori dai
    /// limiti: chi digita un numero deve sapere perché è stato rifiutato.
    pub fn try_new(days: u32) -> Result<Self, String> {
        if days < MIN_RETENTION_DAYS {
            return Err(String::from(
                "La conservazione più breve ammessa è di un giorno: a zero \
                 giorni si cancellerebbe ciò che si è appena acquisito.",
            ));
        }
        if days > MAX_RETENTION_DAYS {
            return Err(format!(
                "La conservazione più lunga ammessa è di {MAX_RETENTION_DAYS} giorni \
                 (dieci anni). Oltre, conviene scegliere «si conserva tutto»."
            ));
        }
        Ok(Self(days))
    }

    /// Il numero di giorni.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl RetentionPolicy {
    /// I valori proposti dall'interfaccia, nell'ordine in cui si mostrano.
    ///
    /// Sono giorni, non mesi: un mese dura fra ventotto e trentun giorni, e una
    /// politica di conservazione che cambia lunghezza secondo il calendario è
    /// una politica che nessuno sa spiegare a chi chiede conto.
    #[must_use]
    pub fn presets() -> Vec<Self> {
        let mut presets = vec![Self::Unlimited];
        for days in [30_u32, 90, 180, 365, 730] {
            if let Ok(days) = RetentionDays::try_new(days) {
                presets.push(Self::Days(days));
            }
        }
        presets
    }

    /// L'etichetta che l'operatore legge.
    #[must_use]
    pub fn label(self) -> String {
        match self {
            Self::Unlimited => String::from("Si conserva tutto"),
            Self::Days(days) => match days.get() {
                30 => String::from("30 giorni"),
                90 => String::from("90 giorni (tre mesi)"),
                180 => String::from("180 giorni (sei mesi)"),
                365 => String::from("365 giorni (un anno)"),
                730 => String::from("730 giorni (due anni)"),
                other => format!("{other} giorni"),
            },
        }
    }

    /// Che cosa comporta, detto in una frase.
    ///
    /// Un'impostazione che cancella dati deve dire **che cosa cancella**, non
    /// soltanto quanto tiene: «90 giorni» e «dopo 90 giorni il contenuto sparisce
    /// dall'archivio» non si leggono allo stesso modo.
    #[must_use]
    pub fn consequence(self) -> String {
        match self {
            Self::Unlimited => String::from(
                "Nulla viene cancellato automaticamente. L'archivio cresce finché \
                 c'è spazio.",
            ),
            Self::Days(days) => format!(
                "I contenuti acquisiti da più di {} giorni vengono cancellati, con \
                 le loro corrispondenze e i loro avvisi. Restano sempre il registro delle operazioni, le \
                 fotografie dei rapporti e i contenuti citati da un documento già \
                 prodotto.",
                days.get()
            ),
        }
    }

    /// I giorni, quando la politica ne prevede.
    #[must_use]
    pub const fn days(self) -> Option<u32> {
        match self {
            Self::Unlimited => None,
            Self::Days(days) => Some(days.get()),
        }
    }

    /// Ricostruisce la politica dal valore conservato.
    ///
    /// Un valore fuori dai limiti — un archivio modificato a mano, una versione
    /// futura — diventa «si conserva tutto»: davanti a una politica che non si
    /// capisce, la cosa prudente è **non cancellare nulla**.
    #[must_use]
    pub fn from_stored(days: Option<u32>) -> Self {
        match days {
            None => Self::Unlimited,
            Some(days) => RetentionDays::try_new(days).map_or(Self::Unlimited, Self::Days),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_RETENTION_DAYS, RetentionDays, RetentionPolicy};

    #[test]
    fn il_predefinito_conserva_tutto() {
        // Qualunque altro predefinito cancellerebbe dati il giorno
        // dell'aggiornamento, su archivi esistenti, senza che nessuno lo abbia
        // chiesto.
        assert_eq!(RetentionPolicy::default(), RetentionPolicy::Unlimited);
        assert_eq!(RetentionPolicy::default().days(), None);
    }

    #[test]
    fn zero_giorni_non_e_una_politica() {
        let esito = RetentionDays::try_new(0);
        assert!(esito.is_err());
        let Err(ragione) = esito else {
            panic!("zero giorni deve essere rifiutato");
        };
        assert!(
            ragione.contains("appena acquisito"),
            "la ragione deve dire che cosa accadrebbe: «{ragione}»"
        );
    }

    #[test]
    fn oltre_dieci_anni_si_sceglie_illimitata() {
        let esito = RetentionDays::try_new(MAX_RETENTION_DAYS + 1);
        assert!(esito.is_err());
        assert!(RetentionDays::try_new(MAX_RETENTION_DAYS).is_ok());
    }

    #[test]
    fn un_valore_conservato_incomprensibile_non_cancella_nulla() {
        // Un archivio modificato a mano, o scritto da una versione futura,
        // potrebbe portare un valore fuori dai limiti. Davanti a una politica
        // che non si capisce la cosa prudente e' non cancellare.
        assert_eq!(
            RetentionPolicy::from_stored(Some(0)),
            RetentionPolicy::Unlimited
        );
        assert_eq!(
            RetentionPolicy::from_stored(Some(MAX_RETENTION_DAYS + 1)),
            RetentionPolicy::Unlimited
        );
        assert_eq!(
            RetentionPolicy::from_stored(None),
            RetentionPolicy::Unlimited
        );
    }

    #[test]
    fn ogni_scelta_dice_che_cosa_comporta_e_che_cosa_resta() {
        // «90 giorni» e «dopo 90 giorni il contenuto sparisce dall'archivio» non
        // si leggono allo stesso modo.
        for policy in RetentionPolicy::presets() {
            let conseguenza = policy.consequence();
            assert!(
                !conseguenza.is_empty(),
                "{policy:?} non dice che cosa comporta"
            );

            if policy != RetentionPolicy::Unlimited {
                assert!(
                    conseguenza.contains("cancellati"),
                    "{policy:?} non dice che cancella: «{conseguenza}»"
                );
                assert!(
                    conseguenza.contains("registro delle operazioni"),
                    "{policy:?} non dice che cosa RESTA: «{conseguenza}»"
                );
            }
        }
    }

    #[test]
    fn i_valori_proposti_partono_dal_conservare_tutto() {
        let presets = RetentionPolicy::presets();
        assert_eq!(
            presets.first(),
            Some(&RetentionPolicy::Unlimited),
            "la scelta prudente si mostra per prima"
        );
        assert!(presets.len() >= 4);

        // Le etichette sono tutte diverse: due voci con lo stesso nome in un
        // elenco a discesa sono due voci che nessuno sa distinguere.
        let mut etichette: Vec<String> = presets.iter().map(|p| p.label()).collect();
        let quante = etichette.len();
        etichette.sort();
        etichette.dedup();
        assert_eq!(
            etichette.len(),
            quante,
            "due valori proposti hanno la stessa etichetta"
        );
    }
}

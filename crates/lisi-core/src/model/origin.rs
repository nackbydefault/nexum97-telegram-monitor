//! Chi dice il dato che si sta leggendo (PR-03, ADR-0118).
//!
//! # Tre valori, e nessun altro
//!
//! Il freeze separa per costruzione il **dato originale**, l'**analisi
//! deterministica di NEXUM** e la **valutazione dell'operatore**. Questo tipo è
//! quella separazione, con un nome solo per ciascuna parte:
//!
//! - [`Origin::Observed`] — **Osservato**: viene da Telegram o da una fonte
//!   esterna, così com'era;
//! - [`Origin::Computed`] — **Calcolato**: lo ha prodotto una regola fissa di
//!   NEXUM, con nome e versione;
//! - [`Origin::Operator`] — **Operatore**: lo ha scritto o deciso una persona,
//!   con nome, motivo e istante.
//!
//! **Non c'è un quarto valore.** Niente «dedotto», «probabile», «stimato»: il
//! prodotto non deduce (ADR-0048). Dove l'archivio non sa distinguere si dice
//! [`RecordedOrigin::NotRecorded`], e non si riempie il vuoto.
//!
//! # Perché non ha un valore predefinito
//!
//! Perché un'origine non si presume. Un `Default` sarebbe esattamente il
//! valore plausibile che il piano vieta di scrivere al posto di quello vero, e
//! una prova qui sotto impedisce di aggiungerlo.
//!
//! # Il modo di acquisizione è un altro asse
//!
//! `Origin` dice **chi** afferma la cosa; il modo di acquisizione dice **come e
//! quando** un messaggio di Telegram è entrato in archivio. Un messaggio
//! recuperato dalla cronologia resta **Osservato**: viene da Telegram. I due
//! assi non si fondono, e nessuna parola vale per entrambi (DEC-356).

/// Chi afferma il dato: Telegram, NEXUM o una persona.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    /// **Osservato:** viene da Telegram o da una fonte esterna, così com'era.
    Observed,
    /// **Calcolato:** lo ha prodotto una regola fissa di NEXUM.
    Computed,
    /// **Operatore:** lo ha scritto o deciso una persona.
    Operator,
}

impl Origin {
    /// Le tre origini, nell'ordine in cui si leggono: prima il dato, poi ciò
    /// che il programma ne ha fatto, poi ciò che una persona ha deciso.
    pub const ALL: [Self; 3] = [Self::Observed, Self::Computed, Self::Operator];

    /// La parola che l'operatore legge.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Observed => "Osservato",
            Self::Computed => "Calcolato",
            Self::Operator => "Operatore",
        }
    }

    /// Che cosa significa, e **che cosa non significa**.
    ///
    /// Ogni origine dice anche il proprio limite: è l'unica cosa che impedisce
    /// di leggere tre risposte come tre fatti dello stesso peso.
    #[must_use]
    pub const fn as_sentence(self) -> &'static str {
        match self {
            Self::Observed => {
                "Viene da Telegram, così com'era: sta nell'archivio e si può riaprire. Il \
                 programma non l'ha calcolato, l'ha registrato."
            }
            Self::Computed => {
                "L'ha calcolato il programma, con una regola fissa: non è un dato osservato. \
                 Con parametri diversi il risultato sarebbe diverso, e non sarebbe né più né \
                 meno vero."
            }
            Self::Operator => {
                "L'ha scritto o deciso una persona, non il programma. Il motivo scritto è \
                 il suo, e ne risponde chi l'ha scritto."
            }
        }
    }

    /// Se un dato di questa origine deve dichiarare il proprio metodo.
    ///
    /// Solo un calcolo: un numero senza il proprio metodo sembra oggettivo.
    #[must_use]
    pub const fn requires_a_method(self) -> bool {
        matches!(self, Self::Computed)
    }
}

/// L'origine com'è registrata: nota, oppure **non registrata**.
///
/// # Perché non basta `Option<Origin>`
///
/// Perché «non registrata» è una frase che l'operatore legge, non un vuoto: dice
/// che l'archivio non sa, e che nessuno ha indovinato al suo posto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordedOrigin {
    /// L'origine è nota.
    Known(Origin),
    /// L'archivio non la sa distinguere.
    NotRecorded,
}

impl RecordedOrigin {
    /// La parola che l'operatore legge.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Known(origin) => origin.label(),
            Self::NotRecorded => "Origine non registrata",
        }
    }
}

impl From<Origin> for RecordedOrigin {
    fn from(origin: Origin) -> Self {
        Self::Known(origin)
    }
}

#[cfg(test)]
mod tests {
    use super::{Origin, RecordedOrigin};

    /// Il sorgente di questo modulo, per la prova sulla forma.
    const THIS_MODULE: &str = include_str!("origin.rs");

    #[test]
    fn le_tre_parole_sono_distinte_e_sono_quelle_del_glossario() {
        let parole: Vec<&str> = Origin::ALL.iter().map(|o| o.label()).collect();
        assert_eq!(parole, vec!["Osservato", "Calcolato", "Operatore"]);
        for origine in Origin::ALL {
            assert!(
                crate::glossary::GLOSSARY
                    .iter()
                    .any(|voce| voce.term == origine.label()),
                "«{}» deve essere un concetto del glossario",
                origine.label()
            );
        }
    }

    #[test]
    fn solo_un_calcolo_dichiara_un_metodo() {
        assert!(Origin::Computed.requires_a_method());
        assert!(!Origin::Observed.requires_a_method());
        assert!(!Origin::Operator.requires_a_method());
    }

    #[test]
    fn ogni_origine_dice_anche_il_proprio_limite() {
        assert!(
            Origin::Observed
                .as_sentence()
                .contains("non l'ha calcolato")
        );
        assert!(
            Origin::Computed
                .as_sentence()
                .contains("non è un dato osservato")
        );
        assert!(Origin::Operator.as_sentence().contains("non il programma"));
    }

    #[test]
    fn non_registrata_si_dice_e_non_si_indovina() {
        assert_eq!(
            RecordedOrigin::NotRecorded.label(),
            "Origine non registrata"
        );
        assert_eq!(RecordedOrigin::from(Origin::Operator).label(), "Operatore");
    }

    /// **Un'origine non si presume.**
    ///
    /// Un valore predefinito sarebbe il valore plausibile che il piano vieta
    /// (PR-03, controllo negativo 3): chi costruisce una vista senza sapere
    /// l'origine di un dato otterrebbe un'origine inventata, e nessuno se ne
    /// accorgerebbe.
    #[test]
    fn un_origine_non_ha_un_valore_predefinito() {
        let codice: String = THIS_MODULE
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default()
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !codice.contains("Default"),
            "un'origine non si presume: né `derive(Default)` né `impl Default`"
        );
    }
}

//! Quando l'archivio **stava guardando**, e dove.
//!
//! # Perché questo tipo ha un modulo suo
//!
//! Perché non è un dettaglio della cronologia di una persona: è la condizione
//! che rende leggibile **qualunque** linea del tempo che questo prodotto
//! disegni. PERS-04 lo ha scoperto sulle persone; CYT-01 incontra lo stesso
//! problema sui grappoli di segnali, e ne incontrerà altri.
//!
//! Sta qui, e non in [`crate::model::person_timeline`] dov'è nato, per una
//! ragione sola: **una seconda copia sarebbe la fine della garanzia**. Due
//! definizioni della stessa cosa restano d'accordo finché nessuno tocca una
//! delle due, e il giorno in cui una imparasse a dire «fino a oggi» e l'altra
//! no, due schermate direbbero due verità diverse sullo stesso periodo.
//!
//! Il percorso vecchio continua a funzionare: `person_timeline` lo riespone.

use crate::SessionId;
use crate::time::Timestamp;

/// Quando l'archivio **stava guardando**, e dove.
///
/// # Perché è parte di una cronologia e non un contorno
///
/// Perché è l'unica cosa che rende leggibile un vuoto. Senza, un periodo senza
/// righe si legge come «non è successo niente», che è un fatto che nessuno ha
/// misurato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationWindow {
    /// Quale monitoraggio.
    pub session: SessionId,
    /// Da quando.
    pub from: Timestamp,
    /// Fino a quando, **se è finito**.
    ///
    /// # Perché `None` non significa «fino a ora»
    ///
    /// Perché un monitoraggio senza istante di conclusione o è ancora in corso,
    /// o è stato interrotto senza chiudersi. Trattarlo come «osservato fino a
    /// oggi» dichiarerebbe una copertura che nessuno ha verificato — ed è
    /// esattamente la confusione che ADR-0053 vieta per le fonti: «non aver
    /// potuto verificare» non è «aver verificato».
    pub to: Option<Timestamp>,
}

impl ObservationWindow {
    /// La finestra, detta a chi legge.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self.to {
            Some(fine) => format!(
                "Monitoraggio #{}: si \u{e8} osservato dal {} al {}.",
                self.session.get(),
                self.from.to_readable_utc(),
                fine.to_readable_utc()
            ),
            None => format!(
                "Monitoraggio #{}: si \u{e8} osservato dal {}, e non risulta concluso. Non \
                 significa che l'osservazione sia arrivata fino a oggi.",
                self.session.get(),
                self.from.to_readable_utc()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ObservationWindow;
    use crate::SessionId;
    use crate::time::Timestamp;

    const INIZIO: Timestamp = Timestamp::from_millis(1_760_000_000_000);

    /// **Un monitoraggio non concluso non è un monitoraggio arrivato a oggi.**
    ///
    /// # Perché è la guardia di questo tipo
    ///
    /// Perché la frase sbagliata qui non si vede: dichiarare una copertura fino
    /// a oggi è ciò che qualcuno scriverebbe in una relazione senza accorgersi
    /// di aver affermato un fatto che nessuno ha misurato.
    #[test]
    fn una_finestra_aperta_non_dichiara_di_arrivare_a_oggi() {
        let aperta = ObservationWindow {
            session: SessionId::new(3),
            from: INIZIO,
            to: None,
        };

        let frase = aperta.as_sentence();
        assert!(
            frase.contains("non risulta concluso"),
            "una finestra aperta deve dirlo: {frase}"
        );
        assert!(
            frase.contains("Non significa che l'osservazione sia arrivata fino a oggi"),
            "una finestra aperta non dichiara una copertura fino a oggi: {frase}"
        );
    }

    /// Una finestra chiusa nomina i due estremi, e non una durata.
    #[test]
    fn una_finestra_chiusa_nomina_i_due_estremi() {
        let chiusa = ObservationWindow {
            session: SessionId::new(3),
            from: INIZIO,
            to: Some(Timestamp::from_millis(1_760_003_600_000)),
        };

        let frase = chiusa.as_sentence();
        assert!(frase.contains(&INIZIO.to_readable_utc()));
        assert!(frase.contains("Monitoraggio #3"));
        assert!(!frase.contains("non risulta concluso"));
    }
}

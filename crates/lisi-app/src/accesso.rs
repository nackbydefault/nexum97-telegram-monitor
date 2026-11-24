//! L'accesso di una persona, condiviso fra le schermate (TEAM-WS-01,
//! ADR-0097 decisione 6).
//!
//! # Perché esiste
//!
//! L'accesso di una persona vale per **una connessione**: si entra dentro una
//! sessione e si esce chiudendola. Due schermate che ne tenessero ciascuna una
//! propria vorrebbero dire due accessi, e una persona dovrebbe entrare due
//! volte per fare due cose dello stesso lavoro.
//!
//! Qui la sessione è **una**: chi entra la apre, chi scrive la usa, chi esce la
//! chiude.
//!
//! # Che cosa non fa
//!
//! **Non conserva niente.** Non c'è un file, non c'è un «ricordami», e
//! chiudendo il programma l'accesso finisce con la connessione che lo
//! portava: un accesso che sopravvivesse alla sessione sopravvivrebbe alla
//! persona che se ne va dalla scrivania.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_core::model::hub_person::PersonId;
use lisi_services::hub_client::HubReviewSession;

/// L'accesso di una persona, finché dura.
#[derive(Debug, Default)]
pub struct Accesso {
    /// La sessione **aperta**, quando una persona è entrata.
    session: RefCell<Option<Box<HubReviewSession>>>,
    /// Chi è entrato.
    person: RefCell<Option<PersonId>>,
}

/// L'accesso condiviso fra le schermate.
pub type SharedAccesso = Rc<Accesso>;

impl Accesso {
    /// Un accesso in cui non è entrato nessuno.
    #[must_use]
    pub fn new() -> SharedAccesso {
        Rc::new(Self::default())
    }

    /// Chi è entrato, se qualcuno.
    #[must_use]
    pub fn person(&self) -> Option<PersonId> {
        self.person.borrow().clone()
    }

    /// Se è entrato qualcuno.
    #[must_use]
    pub fn c_e_qualcuno(&self) -> bool {
        self.person.borrow().is_some()
    }

    /// Prende in consegna la sessione di chi è appena entrato.
    ///
    /// Se c'era già qualcuno, la sua sessione si chiude: una persona alla
    /// volta, perché una sola persona per volta siede alla postazione.
    pub fn entra(&self, person: PersonId, session: HubReviewSession) {
        self.esci();
        *self.person.borrow_mut() = Some(person);
        *self.session.borrow_mut() = Some(Box::new(session));
    }

    /// Chiude l'accesso, se c'era.
    pub fn esci(&self) {
        if let Some(aperta) = self.session.borrow_mut().take() {
            aperta.close();
        }
        *self.person.borrow_mut() = None;
    }

    /// Fa una cosa dentro la sessione di chi è entrato, se c'è.
    ///
    /// Restituisce `None` quando non è entrato nessuno: chi chiama lo dice con
    /// le parole della propria schermata, invece di ricevere una sessione
    /// anonima in cui l'atto non avrebbe un autore.
    ///
    /// Se lo scambio fa cadere la connessione, l'accesso si chiude
    /// (FINAL-REVIEW-01, FR-017): fino al 2026-10-03 restava «qualcuno è
    /// entrato» su una connessione morta, e ogni atto successivo falliva senza
    /// che la schermata dicesse di entrare di nuovo.
    pub fn con_sessione<T>(&self, azione: impl FnOnce(&mut HubReviewSession) -> T) -> Option<T> {
        let (esito, caduta) = {
            let mut sessione = self.session.borrow_mut();
            let aperta = sessione.as_mut()?;
            let esito = azione(aperta);
            (esito, aperta.is_dropped())
        };
        if caduta {
            self.esci();
        }
        Some(esito)
    }
}

#[cfg(test)]
mod tests {
    use super::Accesso;

    #[test]
    fn un_accesso_nuovo_non_ha_nessuno_dentro() {
        let accesso = Accesso::new();
        assert!(!accesso.c_e_qualcuno());
        assert!(accesso.person().is_none());
        assert!(accesso.con_sessione(|_| ()).is_none());
    }

    #[test]
    fn uscire_senza_essere_entrati_non_rompe_niente() {
        let accesso = Accesso::new();
        accesso.esci();
        assert!(!accesso.c_e_qualcuno());
    }
}

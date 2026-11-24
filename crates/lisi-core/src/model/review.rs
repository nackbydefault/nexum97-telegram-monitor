//! Revisione umana dei contenuti.
//!
//! Il motore propone, l'operatore decide. La revisione è il punto in cui una
//! valutazione automatica diventa una valutazione assunta da una persona, ed è
//! per questo che ogni revisione registra chi l'ha compiuta e quando.

use crate::id::{ContentId, ReviewId};
use crate::text::{Actor, Note};
use crate::time::Timestamp;

string_enum!(
    /// Esito della revisione umana di un contenuto.
    ReviewState {
        /// Non ancora esaminato.
        New => "new",
        /// Preso in carico e non ancora concluso.
        InReview => "in_review",
        /// Confermato come rilevante.
        Relevant => "relevant",
        /// Giudicato non rilevante.
        NotRelevant => "not_relevant",
        /// Ripetizione di un contenuto già valutato.
        Duplicate => "duplicate",
        /// Concluso e messo da parte.
        Archived => "archived",
        /// Trasmesso o portato all'attenzione di terzi.
        Reported => "reported",
    }
);

impl ReviewState {
    /// Se lo stato rappresenta una decisione conclusa.
    #[must_use]
    pub const fn is_decided(self) -> bool {
        matches!(
            self,
            Self::Relevant | Self::NotRelevant | Self::Duplicate | Self::Archived | Self::Reported
        )
    }

    /// Se la decisione **smentisce** ciò che il motore aveva segnalato.
    ///
    /// # Perché la definizione sta qui
    ///
    /// Perché la usano due parti che devono restare d'accordo: la revisione,
    /// che pretende una motivazione da chi contraddice il motore, e
    /// l'aggregazione del riscontro sui dizionari, che conta quelle
    /// contraddizioni. Due definizioni della stessa cosa diventerebbero, alla
    /// prima aggiunta di uno stato, due cose diverse — e la seconda conterebbe
    /// come smentita qualcosa che la prima non aveva mai chiesto di motivare.
    ///
    /// Smentire significa dichiarare non rilevante, o duplicato, un contenuto
    /// che era stato segnalato.
    #[must_use]
    pub const fn contradicts_the_engine(self) -> bool {
        matches!(self, Self::NotRelevant | Self::Duplicate)
    }

    /// Se la decisione **conferma** ciò che il motore aveva segnalato.
    ///
    /// «Archiviato» non è qui, ed è deliberato: chiude un esame senza dire se
    /// la segnalazione fosse giusta. Contarlo fra le conferme attribuirebbe a
    /// chi ha archiviato un'opinione che non ha espresso.
    #[must_use]
    pub const fn confirms_the_engine(self) -> bool {
        matches!(self, Self::Relevant | Self::Reported)
    }

    /// Descrizione mostrata all'operatore.
    ///
    /// Sta qui e non nell'interfaccia perché la stessa parola deve comparire
    /// nella schermata, nel report e nella guida: tre traduzioni separate
    /// diventerebbero tre parole diverse per la stessa cosa.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::New => "Da esaminare",
            Self::InReview => "In esame",
            Self::Relevant => "Rilevante",
            Self::NotRelevant => "Non rilevante",
            Self::Duplicate => "Duplicato",
            Self::Archived => "Archiviato",
            Self::Reported => "Segnalato",
        }
    }
}

/// Revisione che si intende registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewReview {
    /// Contenuto revisionato.
    pub content_id: ContentId,
    /// Esito della revisione.
    pub state: ReviewState,
    /// Persona che ha compiuto la revisione.
    pub reviewer: Actor,
    /// Annotazione facoltativa.
    pub note: Option<Note>,
    /// Istante della decisione.
    pub decided_at: Timestamp,
}

/// Revisione registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    /// Identificatore assegnato dalla persistenza.
    pub id: ReviewId,
    /// Contenuto revisionato.
    pub content_id: ContentId,
    /// Esito della revisione.
    pub state: ReviewState,
    /// Persona che ha compiuto la revisione.
    pub reviewer: Actor,
    /// Annotazione facoltativa.
    pub note: Option<Note>,
    /// Istante della decisione.
    pub decided_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::ReviewState;
    use crate::error::DomainError;

    #[test]
    fn all_seven_required_states_are_present() {
        assert_eq!(ReviewState::all().len(), 7);
    }

    #[test]
    fn every_state_survives_a_round_trip_through_its_stored_form() {
        for state in ReviewState::all() {
            assert_eq!(ReviewState::from_str(state.as_str()), Ok(*state));
        }
    }

    #[test]
    fn an_unknown_state_is_rejected() {
        assert!(matches!(
            ReviewState::from_str("da_rivedere"),
            Err(DomainError::UnknownVariant { .. })
        ));
    }

    #[test]
    fn every_state_has_a_distinct_readable_label() {
        // Due stati con la stessa etichetta sarebbero indistinguibili nella
        // schermata pur essendo decisioni diverse nel registro.
        let labels: Vec<&str> = ReviewState::all().iter().map(|s| s.label()).collect();
        for label in &labels {
            assert!(!label.is_empty());
            assert_eq!(
                labels.iter().filter(|other| *other == label).count(),
                1,
                "etichetta ripetuta: {label}"
            );
        }
    }

    #[test]
    fn no_state_both_confirms_and_contradicts_the_engine() {
        // Se uno stato facesse entrambe le cose, la stessa decisione
        // comparirebbe fra le conferme e fra le smentite della stessa regola.
        for state in ReviewState::all() {
            assert!(
                !(state.confirms_the_engine() && state.contradicts_the_engine()),
                "stato ambiguo: {}",
                state.as_str()
            );
        }
    }

    #[test]
    fn an_open_state_passes_no_judgement_on_the_engine() {
        // Un esame non concluso non è un'opinione: contarlo ne inventerebbe una
        // e la conterebbe di nuovo quando la persona avrà davvero deciso.
        for state in ReviewState::all().iter().filter(|s| !s.is_decided()) {
            assert!(!state.confirms_the_engine(), "{}", state.as_str());
            assert!(!state.contradicts_the_engine(), "{}", state.as_str());
        }
    }

    #[test]
    fn archiving_closes_an_examination_without_judging_the_engine() {
        // «Archiviato» è una decisione conclusa che non dice se la
        // segnalazione fosse giusta. Contarla fra le conferme attribuirebbe a
        // chi ha archiviato un'opinione che non ha espresso.
        assert!(ReviewState::Archived.is_decided());
        assert!(!ReviewState::Archived.confirms_the_engine());
        assert!(!ReviewState::Archived.contradicts_the_engine());
    }

    #[test]
    fn the_open_states_are_not_decisions() {
        assert!(!ReviewState::New.is_decided());
        assert!(!ReviewState::InReview.is_decided());
    }

    #[test]
    fn the_closing_states_are_decisions() {
        for state in [
            ReviewState::Relevant,
            ReviewState::NotRelevant,
            ReviewState::Duplicate,
            ReviewState::Archived,
            ReviewState::Reported,
        ] {
            assert!(state.is_decided(), "{state} doveva essere una decisione");
        }
    }
}

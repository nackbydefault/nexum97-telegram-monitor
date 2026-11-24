//! Ciò che l'ufficio scrive insieme (TEAM-WS-01, ADR-0099).
//!
//! # Due cose, non una
//!
//! Una **nota condivisa** sono parole di una persona su qualcosa. Un
//! **raccoglitore condiviso** è un elenco di riferimenti che l'ufficio tiene
//! insieme. La prima si scrive e si ritira; il secondo si apre, si riempie e
//! si chiude.
//!
//! # Che cosa non c'è qui
//!
//! Il **testo di un contenuto**. Un raccoglitore porta riferimenti — che cosa
//! e quale — e una nota porta le parole di chi l'ha scritta, mai quelle del
//! messaggio annotato: il contenuto si chiede uno per volta (ADR-0094), e un
//! raccoglitore che portasse i testi sarebbe la copia dell'archivio dell'Hub
//! con un nome diverso.
//!
//! # Ritirare non è cancellare
//!
//! Una nota ritirata **resta**, con chi l'ha ritirata e quando. Chi l'aveva
//! letta deve poter capire che cosa è successo a ciò che aveva letto: una riga
//! sparita si legge come una riga mai esistita.

use crate::model::hub_person::PersonId;
use crate::model::reference::ArchiveRef;
use crate::text::{DisplayName, Note};
use crate::{NoteId, Timestamp};

/// Note al più in una pagina.
///
/// Cinquanta, come la coda di revisione: è più di quante se ne leggano in una
/// schermata, e un tetto più alto farebbe comporre all'Hub una risposta che
/// nessuno guarda.
pub const MAX_SHARED_NOTES_PAGE: usize = 50;

/// Raccoglitori al più in una pagina.
pub const MAX_SHARED_WORKSPACES_PAGE: usize = 50;

/// Elementi al più in una pagina di un raccoglitore.
pub const MAX_WORKSPACE_ITEMS_PAGE: usize = 200;

/// Una nota dell'ufficio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedNote {
    /// Quale nota.
    pub id: NoteId,
    /// Su che cosa.
    pub about: ArchiveRef,
    /// Le parole.
    pub body: Note,
    /// Chi l'ha scritta: **una persona**, mai una postazione (ADR-0099,
    /// decisione 3).
    pub author: PersonId,
    /// Quando.
    pub written_at: Timestamp,
    /// Chi l'ha ritirata e quando, se è stata ritirata.
    pub withdrawn: Option<(PersonId, Timestamp)>,
}

impl SharedNote {
    /// Se questa nota è stata ritirata.
    #[must_use]
    pub const fn is_withdrawn(&self) -> bool {
        self.withdrawn.is_some()
    }

    /// Chi può ritirarla.
    ///
    /// **Chi l'ha scritta**, e chi amministra. Un terzo che potesse ritirare
    /// le parole altrui potrebbe far sparire un'obiezione (ADR-0099,
    /// decisione 3).
    #[must_use]
    pub fn may_withdraw(&self, who: &PersonId, administers: bool) -> bool {
        administers || &self.author == who
    }
}

/// Lo stato di un raccoglitore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SharedWorkspaceState {
    /// Accetta elementi.
    #[default]
    Open,
    /// Non accetta più elementi. **Non ha perso niente.**
    Closed,
}

impl SharedWorkspaceState {
    /// Forma conservata.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "aperto",
            Self::Closed => "chiuso",
        }
    }

    /// Nome per chi legge.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Open => "Aperto",
            Self::Closed => "Chiuso",
        }
    }

    /// Se accetta elementi.
    #[must_use]
    pub const fn accepts_items(self) -> bool {
        matches!(self, Self::Open)
    }

    /// Riconosce la forma conservata.
    ///
    /// # Errori
    ///
    /// [`crate::error::DomainError::UnknownVariant`] se il valore non è
    /// previsto.
    pub fn parse(raw: &str) -> crate::error::DomainResult<Self> {
        match raw {
            "aperto" => Ok(Self::Open),
            "chiuso" => Ok(Self::Closed),
            _ => Err(crate::error::DomainError::UnknownVariant {
                kind: "stato del raccoglitore condiviso",
                value: String::from(raw),
            }),
        }
    }
}

/// Un raccoglitore dell'ufficio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedWorkspace {
    /// Quale raccoglitore.
    pub id: i64,
    /// Come lo chiama l'ufficio.
    pub name: DisplayName,
    /// A che cosa serve, quando qualcuno l'ha scritto.
    pub description: Option<Note>,
    /// Se accetta elementi.
    pub state: SharedWorkspaceState,
    /// Chi l'ha aperto.
    pub opened_by: PersonId,
    /// Quando.
    pub opened_at: Timestamp,
    /// Quanti elementi ha raccolto.
    pub items: usize,
}

/// Un riferimento raccolto in un raccoglitore.
///
/// **Che cosa e quale**, mai il testo (ADR-0099, decisione 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedWorkspaceItem {
    /// A che cosa punta.
    pub item: ArchiveRef,
    /// Chi l'ha raccolto.
    pub added_by: PersonId,
    /// Quando.
    pub added_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::{SharedNote, SharedWorkspaceState};
    use crate::model::hub_person::PersonId;
    use crate::model::reference::{ArchiveRef, ArchiveRefKind};
    use crate::text::Note;
    use crate::{NoteId, Timestamp};

    fn persona(nome: &str) -> PersonId {
        match PersonId::parse(nome) {
            Ok(persona) => persona,
            Err(errore) => panic!("identificativo di prova: {errore}"),
        }
    }

    fn nota(autore: &str) -> SharedNote {
        let (Ok(corpo), Ok(riferimento)) = (
            Note::try_new("questa fonte ripete il canale di ieri"),
            ArchiveRef::to(ArchiveRefKind::Content, 42),
        ) else {
            panic!("dati della nota");
        };
        SharedNote {
            id: NoteId::new(1),
            about: riferimento,
            body: corpo,
            author: persona(autore),
            written_at: Timestamp::from_millis(0),
            withdrawn: None,
        }
    }

    #[test]
    fn chi_ha_scritto_puo_ritirare_e_un_terzo_no() {
        let mia = nota("mrossi");
        assert!(mia.may_withdraw(&persona("mrossi"), false));
        assert!(
            !mia.may_withdraw(&persona("gverdi"), false),
            "un terzo che ritirasse le parole altrui potrebbe far sparire un'obiezione"
        );
    }

    #[test]
    fn chi_amministra_puo_ritirare_qualunque_nota() {
        let altrui = nota("mrossi");
        assert!(altrui.may_withdraw(&persona("gverdi"), true));
    }

    #[test]
    fn una_nota_ritirata_resta_e_lo_dice() {
        let mut nota = nota("mrossi");
        assert!(!nota.is_withdrawn());
        nota.withdrawn = Some((persona("mrossi"), Timestamp::from_millis(10)));
        assert!(nota.is_withdrawn());
        assert_eq!(
            nota.body.as_str(),
            "questa fonte ripete il canale di ieri",
            "ritirare non cancella le parole: chi le aveva lette deve capire che cosa è successo"
        );
    }

    #[test]
    fn un_raccoglitore_chiuso_non_accetta_piu_niente() {
        assert!(SharedWorkspaceState::Open.accepts_items());
        assert!(!SharedWorkspaceState::Closed.accepts_items());
    }

    #[test]
    fn lo_stato_di_un_raccoglitore_va_e_torna_dall_archivio() {
        for stato in [SharedWorkspaceState::Open, SharedWorkspaceState::Closed] {
            let Ok(riletto) = SharedWorkspaceState::parse(stato.as_str()) else {
                panic!("lo stato {stato:?} deve potersi rileggere");
            };
            assert_eq!(riletto, stato);
            assert!(!stato.label().is_empty());
        }
        assert!(SharedWorkspaceState::parse("qualunque").is_err());
    }
}

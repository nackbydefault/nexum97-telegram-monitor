//! Workspace operativi: contenitori di lavoro che **riferiscono senza
//! copiare**.
//!
//! # Che cos'è, e che cosa non è
//!
//! È il posto dove una persona raccoglie ciò di cui si sta occupando: alcune
//! fonti, alcuni contenuti, alcuni rapporti. Ha un nome, una descrizione, uno
//! stato del ciclo di vita, chi lo ha aperto e quando.
//!
//! **Non è il «fascicolo» condivisibile di TM-01**, che è una configurazione, e
//! il congelamento lo dice con queste parole per evitare proprio questa
//! confusione. **E non è un archivio.**
//!
//! # La garanzia: un riferimento non può contenere una copia
//!
//! Il congelamento lo scrive due volte — «riferisce senza copiare», «riferimenti
//! a materiale esistente, mai copie della prova». Il modo di rispettarlo non è
//! ricordarsene.
//!
//! [`ArchiveRef`] è **`Copy`**, e un tipo `Copy` non può contenere una
//! `String`. Il giorno in cui qualcuno vi aggiungesse il testo del messaggio
//! raccolto — per mostrarlo senza rileggerlo, che è la cosa più naturale del
//! mondo — **il progetto non compilerebbe**.
//!
//! La tabella corrispondente non ha, per la stessa ragione, alcuna colonna di
//! testo per il materiale referenziato.
//!
//! Ne segue la proprietà che serve davvero: **ciò che un workspace mostra è
//! sempre ciò che l'archivio dice adesso.** Non può divergere, perché non ha una
//! seconda copia da cui divergere.
//!
//! # Che cosa si può raccogliere, e perché non tutto
//!
//! Il congelamento elenca otto generi: fonti, contenuti, persone, CyberEvent,
//! segnalibri, note, ricerche salvate, rapporti. **Quattro non esistono
//! ancora** — arrivano con PERS-01, NOTE-01 e SEARCH-01.
//!
//! [`ArchiveRefKind`] ha **quattro varianti**, quelle che qualcosa può davvero
//! produrre: le prime tre da WS-01, i segnalibri da BOOK-01. Le altre
//! arriveranno con le loro milestone. Un genere che nulla può costruire sarebbe
//! una capacità costruita, protetta e mai raggiungibile: è il debito che questo
//! progetto ha già pagato una volta con LAB-01, e non lo ripaga.
//!
//! # Il costo dichiarato: un riferimento può restare appeso
//!
//! Un riferimento polimorfico — genere più identificativo — **non può avere una
//! chiave esterna**. Se ciò a cui punta viene cancellato, il riferimento resta.
//!
//! Non è nascosto: chi legge un workspace riceve, per ogni riferimento, o la
//! cosa risolta o la dichiarazione che **non è più nell'archivio**. Mai il
//! silenzio, e mai una riga che sparisce senza che nulla lo dica.

use core::fmt;
use core::str::FromStr;

use crate::WorkspaceId;
use crate::error::{DomainError, DomainResult};
pub use crate::model::reference::{ArchiveRef, ArchiveRefKind};
use crate::text::{Actor, DisplayName, Note};
use crate::time::Timestamp;

/// Lo stato del ciclo di vita di un workspace.
///
/// # Perché due stati e non tre
///
/// Perché «sospeso», «in attesa» o «archiviato» sarebbero stati che nessuno sa
/// distinguere da «aperto» guardando lo schermo, e uno stato che non cambia che
/// cosa si può fare è una decorazione. Qui la differenza è netta: un workspace
/// chiuso **non accetta né perde elementi**, e l'archivio lo impone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceState {
    /// In lavorazione: accetta e perde elementi.
    Open,
    /// Concluso: non accetta né perde elementi, e non si riapre.
    Closed,
}

impl WorkspaceState {
    /// Etichetta stabile, quella che finisce nell'archivio.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "aperto",
            Self::Closed => "chiuso",
        }
    }
}

impl fmt::Display for WorkspaceState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for WorkspaceState {
    type Err = DomainError;

    fn from_str(raw: &str) -> DomainResult<Self> {
        match raw {
            "aperto" => Ok(Self::Open),
            "chiuso" => Ok(Self::Closed),
            altro => Err(crate::error::unknown_variant(
                "stato del raccoglitore",
                altro,
            )),
        }
    }
}

/// Un workspace da aprire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewWorkspace {
    /// Il nome con cui le persone lo chiameranno.
    pub name: DisplayName,
    /// A che cosa serve. Facoltativa: obbligarla produrrebbe descrizioni finte.
    pub description: Option<Note>,
    /// Chi lo apre.
    pub created_by: Actor,
}

/// Chi ha chiuso un workspace, e quando.
///
/// # Perché i due valori stanno insieme
///
/// Perché un workspace chiuso da nessuno, o chiuso in nessun istante, sarebbe
/// un ciclo di vita a metà. Il tipo li tiene insieme, e l'archivio lo impone con
/// un vincolo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceClosure {
    /// Chi lo ha chiuso.
    pub by: Actor,
    /// Quando.
    pub at: Timestamp,
}

/// Un workspace conservato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    /// Identificativo stabile.
    pub id: WorkspaceId,
    /// Il nome.
    pub name: DisplayName,
    /// A che cosa serve.
    pub description: Option<Note>,
    /// Lo stato del ciclo di vita.
    pub state: WorkspaceState,
    /// Chi lo ha aperto.
    pub created_by: Actor,
    /// Quando.
    pub created_at: Timestamp,
    /// Chi lo ha chiuso e quando, se è chiuso.
    pub closure: Option<WorkspaceClosure>,
}

impl Workspace {
    /// Se accetta ancora elementi.
    #[must_use]
    pub const fn accepts_items(&self) -> bool {
        matches!(self.state, WorkspaceState::Open)
    }

    /// Che cosa questo workspace è, detto a chi legge.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self.closure.as_ref() {
            None => format!(
                "«{}», aperto da {} il {}. Raccoglie riferimenti a materiale dell'archivio: \
                 non ne conserva copie, e ci\u{f2} che mostra \u{e8} ci\u{f2} che l'archivio \
                 dice adesso.",
                self.name.as_str(),
                self.created_by.as_str(),
                self.created_at.to_readable_utc()
            ),
            Some(chiusura) => format!(
                "«{}», aperto da {} il {} e chiuso da {} il {}. Non accetta n\u{e9} perde \
                 elementi, e non si riapre: se serve continuare, se ne apre un altro.",
                self.name.as_str(),
                self.created_by.as_str(),
                self.created_at.to_readable_utc(),
                chiusura.by.as_str(),
                chiusura.at.to_readable_utc()
            ),
        }
    }
}

/// Un riferimento raccolto, con chi lo ha messo e quando.
///
/// # Perché la provenienza non sta dentro il riferimento
///
/// Perché [`ArchiveRef`] deve restare `Copy`, e un `Actor` è una `String`.
/// La separazione non è un ripiego: il riferimento è **che cosa e quale**, e chi
/// ce l'ha messo è un'altra cosa che gli sta attorno.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceEntry {
    /// Il riferimento.
    pub item: ArchiveRef,
    /// Chi lo ha aggiunto.
    pub added_by: Actor,
    /// Quando.
    pub added_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::{NewWorkspace, Workspace, WorkspaceClosure, WorkspaceState};
    use crate::WorkspaceId;
    use crate::text::{Actor, DisplayName, Note};
    use crate::time::Timestamp;
    use core::str::FromStr;

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("workspace.rs");

    const ORA: i64 = 1_700_000_000_000;

    fn attore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn nome(testo: &str) -> DisplayName {
        let Ok(nome) = DisplayName::try_new(testo) else {
            panic!("il nome di prova deve essere valido");
        };
        nome
    }

    fn workspace(stato: WorkspaceState) -> Workspace {
        Workspace {
            id: WorkspaceId::new(1),
            name: nome("Indagine di marzo"),
            description: None,
            state: stato,
            created_by: attore(),
            created_at: Timestamp::from_millis(ORA),
            closure: match stato {
                WorkspaceState::Open => None,
                WorkspaceState::Closed => Some(WorkspaceClosure {
                    by: attore(),
                    at: Timestamp::from_millis(ORA + 3_600_000),
                }),
            },
        }
    }

    /// **Le etichette scritte nell'archivio sono parole, non indici.**
    ///
    /// Un indice cambia significato il giorno in cui qualcuno riordina
    /// l'enumerazione, e le righe già scritte comincerebbero a riferire un'altra
    /// cosa senza che nulla cambi nell'archivio.
    #[test]
    fn le_etichette_vanno_e_tornano_identiche() {
        for stato in [WorkspaceState::Open, WorkspaceState::Closed] {
            let Ok(letto) = WorkspaceState::from_str(stato.as_str()) else {
                panic!("lo stato «{}» deve tornare indietro", stato.as_str());
            };
            assert_eq!(letto, stato);
        }
        assert!(WorkspaceState::from_str("sospeso").is_err());
    }

    /// **Un workspace aperto accetta, uno chiuso no.**
    #[test]
    fn lo_stato_cambia_che_cosa_si_puo_fare() {
        assert!(workspace(WorkspaceState::Open).accepts_items());
        assert!(!workspace(WorkspaceState::Closed).accepts_items());
    }

    /// **La frase dice sempre che un workspace non conserva copie.**
    ///
    /// È l'unica cosa che lo distingue da un archivio, e chi lo usa a lungo
    /// smette di ricordarsene.
    #[test]
    fn la_frase_dice_che_non_conserva_copie() {
        let frase = workspace(WorkspaceState::Open).as_sentence();
        assert!(frase.contains("non ne conserva copie"), "{frase}");
        assert!(
            frase.contains("ci\u{f2} che l'archivio dice adesso"),
            "{frase}"
        );
        assert!(frase.contains("Indagine di marzo"), "{frase}");
        assert!(frase.contains("operatore.prova"), "{frase}");
    }

    /// **La frase di un workspace chiuso dice che non si riapre.**
    #[test]
    fn la_frase_di_uno_chiuso_dice_che_non_si_riapre() {
        let frase = workspace(WorkspaceState::Closed).as_sentence();
        assert!(frase.contains("non si riapre"), "{frase}");
        assert!(frase.contains("se ne apre un altro"), "{frase}");
    }

    /// **La chiusura tiene insieme chi e quando.**
    #[test]
    fn una_chiusura_porta_chi_e_quando() {
        let chiuso = workspace(WorkspaceState::Closed);
        let Some(chiusura) = chiuso.closure.as_ref() else {
            panic!("un workspace chiuso deve avere una chiusura");
        };
        assert_eq!(chiusura.by.as_str(), "operatore.prova");
        assert_eq!(chiusura.at.as_millis(), ORA + 3_600_000);
        assert!(workspace(WorkspaceState::Open).closure.is_none());
    }

    /// **Ciò che sta attorno al riferimento non porta il materiale.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// `ArchiveRef` è `Copy` e non può contenere una `String`: il compilatore
    /// chiude quella porta. Ma [`WorkspaceEntry`] gli sta **attorno**, non
    /// dentro, e non è `Copy` — deve portare un `Actor`. Nulla impedirebbe a
    /// qualcuno di aggiungere qui il testo del contenuto raccolto «per non
    /// rileggerlo», che è la seconda copia con un passo di lato.
    ///
    /// La guardia è nata in BOOK-01, che aveva la stessa sui segnalibri:
    /// spostando il riferimento in [`crate::model::reference`] questa fixture
    /// era rimasta senza prove, e `clippy` lo ha detto. Il modo di rispondere
    /// non era toglierla — era accorgersi che qui mancava.
    #[test]
    fn cio_che_sta_attorno_al_riferimento_non_porta_il_materiale() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let Some(inizio) = produzione.find("pub struct WorkspaceEntry {") else {
            panic!("il tipo deve esistere");
        };
        let Some(fine) = produzione[inizio..].find("\n}\n") else {
            panic!("il tipo deve chiudersi");
        };
        for materiale in ["body", "text", "testo", "label", "etichetta", "preview"] {
            assert!(
                !produzione[inizio..inizio + fine].contains(materiale),
                "l'elemento dichiara «{materiale}»: un workspace riferisce senza copiare, e cio' \
                 che sta attorno al riferimento non e' il posto dove aggirarlo"
            );
        }
    }

    /// **La descrizione è facoltativa.**
    ///
    /// Obbligarla produrrebbe descrizioni finte, che è peggio di nessuna
    /// descrizione: farebbero credere che qualcuno abbia detto a che cosa serve.
    #[test]
    fn la_descrizione_e_facoltativa() {
        let Ok(descrizione) = Note::try_new("le fonti del marzo 2026") else {
            panic!("la descrizione di prova deve essere valida");
        };
        let con = NewWorkspace {
            name: nome("Con descrizione"),
            description: Some(descrizione),
            created_by: attore(),
        };
        let senza = NewWorkspace {
            name: nome("Senza descrizione"),
            description: None,
            created_by: attore(),
        };
        assert!(con.description.is_some());
        assert!(senza.description.is_none());
    }
}

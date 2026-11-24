//! Segnalibri e raccolte: **riferimenti a materiale esistente, mai copie della
//! prova**.
//!
//! # Che cos'è un segnalibro, e perché non è un workspace
//!
//! È un segno: «questo lo ritrovo». **Un gesto solo, senza cerimonia.**
//!
//! Un workspace è un contenitore di **lavoro**: ha un nome, una descrizione, un
//! ciclo di vita, e per metterci qualcosa bisogna prima averlo aperto. Se
//! segnare una cosa richiedesse tutto questo, nessuno segnerebbe niente — e un
//! segnalibro che nessuno mette non serve a nulla.
//!
//! **La differenza è la cerimonia**, ed è la ragione per cui i due meccanismi
//! restano due. Il congelamento li elenca separati, e dice anche che un
//! workspace può riferire un segnalibro: sono due cose, e una può contenere
//! l'altra.
//!
//! # Che cosa NON li distingue: il modo di riferire
//!
//! Quello è **uno solo**, e vive in [`crate::model::reference`]. Fino a BOOK-01
//! stava dentro il workspace; darne uno anche qui avrebbe prodotto due nozioni
//! di riferimento — due elenchi di generi ammessi, due convalide, due punti in
//! cui aggiungere «persona» il giorno in cui le persone esisteranno.
//!
//! # Perché un segnalibro non ha un testo proprio
//!
//! Perché le parole dell'operatore sono **NOTE-01**, e darne un pezzo anche qui
//! creerebbe due posti in cui scrivere la stessa cosa. Un segnalibro è un
//! segno: che cosa, quale, chi, quando, ed eventualmente in quale raccolta.
//!
//! Il suo nome, quando serve, è **ciò a cui punta** — risolto al momento, dal
//! materiale che c'è adesso.
//!
//! # Un segnalibro non punta a un segnalibro
//!
//! Il genere condiviso ne ammette quattro; un segnalibro ne accetta **tre**.
//! Una catena di segnalibri non significherebbe nulla, e nessuna lettura
//! saprebbe dove fermarsi. È un fatto del dominio, non una dimenticanza: il
//! costruttore lo rifiuta, e l'archivio anche.

use crate::error::{DomainError, DomainResult};
use crate::model::reference::{ArchiveRef, ArchiveRefKind};
use crate::text::{Actor, DisplayName};
use crate::time::Timestamp;
use crate::{BookmarkCollectionId, BookmarkId};

/// Una raccolta da creare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewBookmarkCollection {
    /// Il nome con cui la si sceglie.
    pub name: DisplayName,
    /// Chi la crea.
    pub created_by: Actor,
}

/// Una raccolta di segnalibri.
///
/// # Perché senza ciclo di vita
///
/// Perché una raccolta non è un lavoro che si conclude: è un'etichetta. Darle
/// uno stato aperto/chiuso sarebbe copiare il workspace cambiandogli nome, e
/// due meccanismi uguali con nomi diversi divergono.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookmarkCollection {
    /// Identificativo stabile.
    pub id: BookmarkCollectionId,
    /// Il nome.
    pub name: DisplayName,
    /// Chi l'ha creata.
    pub created_by: Actor,
    /// Quando.
    pub created_at: Timestamp,
}

/// Un segnalibro da mettere.
///
/// # Perché i campi sono privati
///
/// Perché il tipo garantisce una cosa che una struttura aperta non
/// garantirebbe: che non si segni un segnalibro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewBookmark {
    reference: ArchiveRef,
    collection: Option<BookmarkCollectionId>,
}

impl NewBookmark {
    /// Segna una cosa dell'archivio.
    ///
    /// # Errori
    ///
    /// Rifiuta un riferimento a un **segnalibro**: una catena di segnalibri non
    /// significherebbe nulla, e nessuna lettura saprebbe dove fermarsi.
    pub const fn of(
        reference: ArchiveRef,
        collection: Option<BookmarkCollectionId>,
    ) -> DomainResult<Self> {
        if matches!(reference.kind(), ArchiveRefKind::Bookmark) {
            return Err(DomainError::Empty {
                field: "bookmark_target",
            });
        }
        Ok(Self {
            reference,
            collection,
        })
    }

    /// Che cosa segna.
    #[must_use]
    pub const fn reference(self) -> ArchiveRef {
        self.reference
    }

    /// In quale raccolta, se in una.
    ///
    /// `None` è il caso ordinario: obbligare una raccolta sarebbe
    /// reintrodurre la cerimonia che un segnalibro esiste per non avere.
    #[must_use]
    pub const fn collection(self) -> Option<BookmarkCollectionId> {
        self.collection
    }
}

/// Un segnalibro conservato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bookmark {
    /// Identificativo stabile.
    pub id: BookmarkId,
    /// Che cosa segna.
    pub reference: ArchiveRef,
    /// In quale raccolta, se in una.
    pub collection: Option<BookmarkCollectionId>,
    /// Chi lo ha messo.
    pub created_by: Actor,
    /// Quando.
    pub created_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::{Bookmark, BookmarkCollection, NewBookmark, NewBookmarkCollection};
    use crate::model::reference::{ArchiveRef, ArchiveRefKind};
    use crate::text::{Actor, DisplayName};
    use crate::time::Timestamp;
    use crate::{BookmarkCollectionId, BookmarkId};

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("bookmark.rs");

    const ORA: i64 = 1_700_000_000_000;

    fn attore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn riferimento(kind: ArchiveRefKind, id: i64) -> ArchiveRef {
        let Ok(riferimento) = ArchiveRef::to(kind, id) else {
            panic!("il riferimento di prova deve essere valido");
        };
        riferimento
    }

    /// **Un segnalibro non segna un segnalibro.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una catena. Non significherebbe nulla, e nessuna lettura saprebbe dove
    /// fermarsi: chi risolve un segnalibro risolve ciò a cui punta, e se quello
    /// fosse un altro segnalibro dovrebbe decidere quanto in profondità andare
    /// — una decisione che nessuno può prendere bene.
    #[test]
    fn un_segnalibro_non_segna_un_segnalibro() {
        assert!(
            NewBookmark::of(riferimento(ArchiveRefKind::Bookmark, 1), None).is_err(),
            "una catena di segnalibri non significa nulla"
        );
        for genere in [
            ArchiveRefKind::Source,
            ArchiveRefKind::Content,
            ArchiveRefKind::Report,
        ] {
            assert!(
                NewBookmark::of(riferimento(genere, 1), None).is_ok(),
                "«{}» si puo' segnare",
                genere.as_str()
            );
        }
    }

    /// **Un segnalibro non porta un testo proprio.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un campo in cui l'operatore scriva due parole «per ricordarsi perché».
    /// Sarebbe **NOTE-01 scritta qui**, e da quel momento le parole
    /// dell'operatore starebbero in due posti — che divergono.
    ///
    /// E sarebbe anche il posto in cui, un giorno, qualcuno incollerebbe il
    /// testo del messaggio: il tipo è `Copy`, e quel giorno il progetto non
    /// compilerebbe.
    #[test]
    fn un_segnalibro_non_porta_un_testo_proprio() {
        const fn richiede_copy<T: Copy>() {}
        richiede_copy::<NewBookmark>();

        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let Some(inizio) = produzione.find("pub struct Bookmark {") else {
            panic!("il tipo deve esistere");
        };
        let Some(fine) = produzione[inizio..].find("\n}\n") else {
            panic!("il tipo deve chiudersi");
        };
        for testo in ["note", "label", "title", "titolo", "descrizione", "body"] {
            assert!(
                !produzione[inizio..inizio + fine].contains(testo),
                "il segnalibro dichiara «{testo}»: le parole dell'operatore sono NOTE-01, e due \
                 posti in cui scriverle divergono"
            );
        }
    }

    /// **La raccolta è facoltativa.**
    ///
    /// Obbligarla reintrodurrebbe la cerimonia che un segnalibro esiste per non
    /// avere: se segnare richiedesse prima di scegliere dove, nessuno
    /// segnerebbe.
    #[test]
    fn la_raccolta_e_facoltativa() {
        let Ok(senza) = NewBookmark::of(riferimento(ArchiveRefKind::Content, 7), None) else {
            panic!("un segnalibro senza raccolta deve potersi costruire");
        };
        assert_eq!(senza.collection(), None);

        let Ok(dentro) = NewBookmark::of(
            riferimento(ArchiveRefKind::Content, 7),
            Some(BookmarkCollectionId::new(3)),
        ) else {
            panic!("un segnalibro in una raccolta deve potersi costruire");
        };
        assert_eq!(dentro.collection(), Some(BookmarkCollectionId::new(3)));
    }

    /// **Una raccolta non ha un ciclo di vita.**
    ///
    /// # Perché conta
    ///
    /// Perché darglielo sarebbe copiare il workspace cambiandogli nome, e due
    /// meccanismi uguali con nomi diversi divergono. Una raccolta è
    /// un'etichetta, non un lavoro che si conclude.
    #[test]
    fn una_raccolta_non_ha_un_ciclo_di_vita() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let Some(inizio) = produzione.find("pub struct BookmarkCollection {") else {
            panic!("il tipo deve esistere");
        };
        let Some(fine) = produzione[inizio..].find("\n}\n") else {
            panic!("il tipo deve chiudersi");
        };
        for stato in ["state", "stato", "closed", "chiusa", "closure", "archived"] {
            assert!(
                !produzione[inizio..inizio + fine].contains(stato),
                "la raccolta dichiara «{stato}»: sarebbe il workspace con un altro nome"
            );
        }
    }

    /// **Il riferimento e la raccolta si rileggono identici.**
    #[test]
    fn un_segnalibro_conservato_porta_cio_che_gli_e_stato_dato() {
        let Ok(nome) = DisplayName::try_new("Da rileggere") else {
            panic!("il nome di prova deve essere valido");
        };
        let raccolta = BookmarkCollection {
            id: BookmarkCollectionId::new(3),
            name: nome,
            created_by: attore(),
            created_at: Timestamp::from_millis(ORA),
        };
        let segnalibro = Bookmark {
            id: BookmarkId::new(1),
            reference: riferimento(ArchiveRefKind::Content, 42),
            collection: Some(raccolta.id),
            created_by: attore(),
            created_at: Timestamp::from_millis(ORA + 10),
        };

        assert_eq!(segnalibro.reference.kind(), ArchiveRefKind::Content);
        assert_eq!(segnalibro.reference.target_id(), 42);
        assert_eq!(segnalibro.collection, Some(BookmarkCollectionId::new(3)));
        assert_eq!(raccolta.name.as_str(), "Da rileggere");
    }

    /// **Una raccolta da creare porta chi la crea.**
    #[test]
    fn una_raccolta_da_creare_porta_chi_la_crea() {
        let Ok(nome) = DisplayName::try_new("Da rileggere") else {
            panic!("il nome di prova deve essere valido");
        };
        let nuova = NewBookmarkCollection {
            name: nome,
            created_by: attore(),
        };
        assert_eq!(nuova.created_by.as_str(), "operatore.prova");
    }
}

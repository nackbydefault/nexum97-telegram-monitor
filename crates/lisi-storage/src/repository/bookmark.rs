//! Segnalibri e raccolte (BOOK-01).
//!
//! # Che cosa questo modulo non scrive mai
//!
//! Il testo del materiale segnato. La tabella `bookmarks` non ha una colonna in
//! cui possa stare, e [`lisi_core::model::reference::ArchiveRef`] è `Copy`,
//! quindi non può portarlo.
//!
//! # Un riferimento appeso si dichiara
//!
//! Come per i workspace: il riferimento è polimorfico e non ha una chiave
//! esterna. Leggere i segnalibri restituisce, per ciascuno, **o l'etichetta
//! risolta o la dichiarazione che non è più nell'archivio**. Mai una riga che
//! sparisce senza che nulla lo dica.

use core::str::FromStr;

use lisi_core::model::bookmark::{
    Bookmark, BookmarkCollection, NewBookmark, NewBookmarkCollection,
};
use lisi_core::model::reference::{ArchiveRef, ArchiveRefKind};
use lisi_core::text::{Actor, DisplayName};
use lisi_core::{BookmarkCollectionId, BookmarkId, Timestamp};
use rusqlite::OptionalExtension;

use crate::database::Database;
use crate::error::{StorageError, StorageResult};
use crate::repository::workspace::ResolvedTarget;
use crate::repository::{instant, millis};

/// Un segnalibro riletto, con ciò che il suo riferimento raggiunge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBookmark {
    /// Il segnalibro.
    pub bookmark: Bookmark,
    /// Che cosa raggiunge.
    pub target: ResolvedTarget,
    /// Il nome della raccolta, quando è in una.
    ///
    /// # Perché il nome e non solo l'identificativo
    ///
    /// Perché chi legge l'elenco vuole sapere **in quale raccolta**, e
    /// costringere ogni chiamante a una seconda interrogazione produrrebbe
    /// tante interrogazioni quante righe — o, peggio, un chiamante che se la
    /// dimentica e mostra un numero.
    pub collection_name: Option<String>,
}

impl Database {
    /// Crea una raccolta.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se una raccolta con quel nome esiste già, o se la
    /// scrittura non riesce.
    pub fn insert_bookmark_collection(
        &self,
        collection: &NewBookmarkCollection,
        created_at: Timestamp,
    ) -> StorageResult<BookmarkCollectionId> {
        self.connection.execute(
            "INSERT INTO bookmark_collections (name, created_by, created_at)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![
                collection.name.as_str(),
                collection.created_by.as_str(),
                millis(created_at),
            ],
        )?;
        Ok(BookmarkCollectionId::new(
            self.connection.last_insert_rowid(),
        ))
    }

    /// Le raccolte, in ordine di nome.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn bookmark_collections(&self) -> StorageResult<Vec<BookmarkCollection>> {
        let mut statement = self.connection.prepare(
            "SELECT id, name, created_by, created_at
             FROM bookmark_collections
             ORDER BY name ASC",
        )?;
        let righe: Vec<(i64, String, String, i64)> = statement
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        righe
            .into_iter()
            .map(|(id, nome, chi, quando)| {
                Ok(BookmarkCollection {
                    id: BookmarkCollectionId::new(id),
                    name: DisplayName::try_new(&nome)?,
                    created_by: Actor::try_new(&chi)?,
                    created_at: instant(quando),
                })
            })
            .collect()
    }

    /// Cancella una raccolta.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la raccolta **contiene segnalibri** — lo
    /// rifiuta l'archivio — o se non esiste.
    pub fn delete_bookmark_collection(&self, id: BookmarkCollectionId) -> StorageResult<()> {
        let toccate = self
            .connection
            .execute("DELETE FROM bookmark_collections WHERE id = ?1", [id.get()])?;
        if toccate == 0 {
            return Err(StorageError::NotFound {
                entity: "raccolta di segnalibri",
                id: id.get(),
            });
        }
        Ok(())
    }

    /// Mette un segnalibro.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la stessa persona ha già segnato quella cosa, o
    /// se la raccolta indicata non esiste.
    pub fn insert_bookmark(
        &self,
        bookmark: NewBookmark,
        created_by: &Actor,
        created_at: Timestamp,
    ) -> StorageResult<BookmarkId> {
        self.connection.execute(
            "INSERT INTO bookmarks (kind, target_id, collection_id, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                bookmark.reference().kind().as_str(),
                bookmark.reference().target_id(),
                bookmark.collection().map(BookmarkCollectionId::get),
                created_by.as_str(),
                millis(created_at),
            ],
        )?;
        Ok(BookmarkId::new(self.connection.last_insert_rowid()))
    }

    /// Sposta un segnalibro in una raccolta, o lo lascia sciolto.
    ///
    /// # Perché questa esiste
    ///
    /// Perché segnare è **un gesto solo**: chi segna non sceglie una raccolta,
    /// e il caso ordinario è nessuna. Se l'appartenenza si potesse decidere
    /// soltanto al momento del segno, le raccolte sarebbero una capacità che
    /// nulla raggiunge — LAB-01 ha insegnato che cosa vale una capacità così.
    ///
    /// Riordinare è un secondo atto, deliberato, e avviene dove i segnalibri si
    /// guardano.
    ///
    /// # Che cosa NON tocca
    ///
    /// Il riferimento. Spostare un segnalibro cambia **dove sta il segno**, non
    /// che cosa segna.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se il segnalibro non c'è, e un
    /// errore se la raccolta indicata non esiste.
    pub fn set_bookmark_collection(
        &self,
        id: BookmarkId,
        collection: Option<BookmarkCollectionId>,
    ) -> StorageResult<()> {
        let toccate = self.connection.execute(
            "UPDATE bookmarks SET collection_id = ?2 WHERE id = ?1",
            rusqlite::params![id.get(), collection.map(BookmarkCollectionId::get)],
        )?;
        if toccate == 0 {
            return Err(StorageError::NotFound {
                entity: "segnalibro",
                id: id.get(),
            });
        }
        Ok(())
    }

    /// Toglie un segnalibro.
    ///
    /// # Che cosa NON tocca
    ///
    /// La cosa segnata. Togliere un segnalibro da un contenuto **non** cancella
    /// il contenuto: l'istruzione insiste su `bookmarks` e su null'altro.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se il segnalibro non c'era.
    pub fn delete_bookmark(&self, id: BookmarkId) -> StorageResult<()> {
        let toccate = self
            .connection
            .execute("DELETE FROM bookmarks WHERE id = ?1", [id.get()])?;
        if toccate == 0 {
            return Err(StorageError::NotFound {
                entity: "segnalibro",
                id: id.get(),
            });
        }
        Ok(())
    }

    /// I segnalibri, dal più recente, **con ciò che i riferimenti raggiungono**.
    ///
    /// Passando una raccolta restituisce i soli segnalibri che vi appartengono.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn bookmarks(
        &self,
        collection: Option<BookmarkCollectionId>,
    ) -> StorageResult<Vec<ResolvedBookmark>> {
        // DUE INTERROGAZIONI, NON UNA CON UN FILTRO OPZIONALE IN SQL.
        //
        // Un `WHERE (?1 IS NULL OR collection_id = ?1)` funziona e si legge
        // male: chi lo rilegge non sa dire, senza eseguirlo, che cosa faccia
        // quando il parametro e' nullo.
        let mut statement = match collection {
            None => self.connection.prepare(
                "SELECT b.id, b.kind, b.target_id, b.collection_id, b.created_by, b.created_at,
                        c.name
                 FROM bookmarks b
                 LEFT JOIN bookmark_collections c ON c.id = b.collection_id
                 ORDER BY b.created_at DESC, b.id DESC",
            )?,
            Some(_) => self.connection.prepare(
                "SELECT b.id, b.kind, b.target_id, b.collection_id, b.created_by, b.created_at,
                        c.name
                 FROM bookmarks b
                 LEFT JOIN bookmark_collections c ON c.id = b.collection_id
                 WHERE b.collection_id = ?1
                 ORDER BY b.created_at DESC, b.id DESC",
            )?,
        };

        type Riga = (i64, String, i64, Option<i64>, String, i64, Option<String>);
        let leggi = |row: &rusqlite::Row<'_>| -> rusqlite::Result<Riga> {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        };
        let righe: Vec<Riga> = match collection {
            None => statement.query_map([], leggi)?,
            Some(id) => statement.query_map([id.get()], leggi)?,
        }
        .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut segnalibri = Vec::with_capacity(righe.len());
        for (id, genere, identificativo, raccolta, chi, quando, nome_raccolta) in righe {
            let kind = ArchiveRefKind::from_str(&genere)?;
            // UN SEGNALIBRO SU UN SEGNALIBRO NON ESISTE, e l'archivio lo vieta
            // con un CHECK. Se ne trovassimo uno, la riga e' malformata: non si
            // indovina che cosa intendesse.
            if matches!(kind, ArchiveRefKind::Bookmark) {
                return Err(StorageError::CorruptedRow {
                    detail: "un segnalibro dichiara di segnare un segnalibro, che non \u{e8} \
                             una cosa che il dominio ammette",
                });
            }
            let reference = ArchiveRef::to(kind, identificativo)?;
            let target = self.resolve_reference(kind, identificativo)?;
            segnalibri.push(ResolvedBookmark {
                bookmark: Bookmark {
                    id: BookmarkId::new(id),
                    reference,
                    collection: raccolta.map(BookmarkCollectionId::new),
                    created_by: Actor::try_new(&chi)?,
                    created_at: instant(quando),
                },
                target,
                collection_name: nome_raccolta,
            });
        }
        Ok(segnalibri)
    }

    /// Se una cosa è già segnata da qualcuno.
    ///
    /// # Perché serve
    ///
    /// Perché un comando «Segna» che compare anche su ciò che è già segnato
    /// invita a premerlo, e produce un rifiuto che chi legge non si aspetta.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn bookmark_of(&self, reference: ArchiveRef) -> StorageResult<Option<BookmarkId>> {
        let trovato: Option<i64> = self
            .connection
            .query_row(
                "SELECT id FROM bookmarks WHERE kind = ?1 AND target_id = ?2",
                rusqlite::params![reference.kind().as_str(), reference.target_id()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(trovato.map(BookmarkId::new))
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::bookmark::{NewBookmark, NewBookmarkCollection};
    use lisi_core::model::reference::{ArchiveRef, ArchiveRefKind};
    use lisi_core::text::DisplayName;
    use lisi_core::{BookmarkCollectionId, Timestamp};

    use crate::repository::workspace::ResolvedTarget;
    use crate::test_support::{actor, database_with_session, new_content};

    const ORA: i64 = 1_700_000_000_000;

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    fn nome(testo: &str) -> DisplayName {
        let Ok(nome) = DisplayName::try_new(testo) else {
            panic!("il nome di prova deve essere valido");
        };
        nome
    }

    fn segnalibro(
        kind: ArchiveRefKind,
        id: i64,
        raccolta: Option<BookmarkCollectionId>,
    ) -> NewBookmark {
        let (Ok(riferimento), _) = (ArchiveRef::to(kind, id), ()) else {
            panic!("il riferimento di prova deve essere valido");
        };
        let Ok(segnalibro) = NewBookmark::of(riferimento, raccolta) else {
            panic!("il segnalibro di prova deve essere valido");
        };
        segnalibro
    }

    /// **Un segnalibro si mette e si rilegge, con ciò a cui punta.**
    #[test]
    fn un_segnalibro_si_mette_e_si_rilegge() {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(inserimento) =
            database.insert_content(&new_content(session_id, source_id, "777", "testo"))
        else {
            panic!("il contenuto deve potersi registrare");
        };

        let Ok(_) = database.insert_bookmark(
            segnalibro(
                ArchiveRefKind::Content,
                inserimento.content_id().get(),
                None,
            ),
            &actor("operatore.prova"),
            istante(ORA),
        ) else {
            panic!("il segnalibro deve potersi mettere");
        };

        let Ok(elenco) = database.bookmarks(None) else {
            panic!("i segnalibri devono potersi leggere");
        };
        assert_eq!(elenco.len(), 1);
        assert_eq!(elenco[0].bookmark.created_by.as_str(), "operatore.prova");
        assert_eq!(elenco[0].collection_name, None);
        let ResolvedTarget::Present { label } = &elenco[0].target else {
            panic!("il contenuto esiste, e deve risolversi");
        };
        // Con il testo e la fonte, non più il solo numero (OS-02).
        assert!(label.ends_with(", messaggio 777"), "{label}");
        assert!(label.len() > "messaggio 777".len() + 2, "{label}");
    }

    /// **La stessa persona non segna due volte la stessa cosa.**
    #[test]
    fn la_stessa_cosa_non_si_segna_due_volte() {
        let (database, source_id, _) = database_with_session();
        let Ok(_) = database.insert_bookmark(
            segnalibro(ArchiveRefKind::Source, source_id.get(), None),
            &actor("operatore.prova"),
            istante(ORA),
        ) else {
            panic!("il primo segnalibro deve potersi mettere");
        };
        assert!(
            database
                .insert_bookmark(
                    segnalibro(ArchiveRefKind::Source, source_id.get(), None),
                    &actor("operatore.prova"),
                    istante(ORA + 1),
                )
                .is_err(),
            "due righe identiche non direbbero nulla di piu'"
        );
    }

    /// **Un segnalibro appeso lo dichiara, e non sparisce.**
    #[test]
    fn un_segnalibro_appeso_si_dichiara() {
        let (database, _, _) = database_with_session();
        let Ok(_) = database.insert_bookmark(
            segnalibro(ArchiveRefKind::Content, 999_999, None),
            &actor("operatore.prova"),
            istante(ORA),
        ) else {
            panic!("il segnalibro deve potersi mettere");
        };

        let Ok(elenco) = database.bookmarks(None) else {
            panic!("i segnalibri devono potersi leggere");
        };
        assert_eq!(elenco.len(), 1, "la riga NON sparisce");
        assert_eq!(elenco[0].target, ResolvedTarget::NoLongerInArchive);
    }

    /// **Una raccolta raggruppa, e il nome arriva con la riga.**
    #[test]
    fn una_raccolta_raggruppa_e_il_nome_arriva() {
        let (database, source_id, _) = database_with_session();
        let Ok(raccolta) = database.insert_bookmark_collection(
            &NewBookmarkCollection {
                name: nome("Da rileggere"),
                created_by: actor("operatore.prova"),
            },
            istante(ORA),
        ) else {
            panic!("la raccolta deve potersi creare");
        };

        let Ok(_) = database.insert_bookmark(
            segnalibro(ArchiveRefKind::Source, source_id.get(), Some(raccolta)),
            &actor("operatore.prova"),
            istante(ORA + 10),
        ) else {
            panic!("il segnalibro deve potersi mettere");
        };

        let Ok(dentro) = database.bookmarks(Some(raccolta)) else {
            panic!("i segnalibri della raccolta devono potersi leggere");
        };
        assert_eq!(dentro.len(), 1);
        assert_eq!(dentro[0].collection_name.as_deref(), Some("Da rileggere"));

        // E l'elenco completo li contiene comunque.
        let Ok(tutti) = database.bookmarks(None) else {
            panic!("l'elenco completo deve potersi leggere");
        };
        assert_eq!(tutti.len(), 1);
    }

    /// **Due raccolte non si chiamano allo stesso modo.**
    #[test]
    fn due_raccolte_non_hanno_lo_stesso_nome() {
        let (database, _, _) = database_with_session();
        let nuova = || NewBookmarkCollection {
            name: nome("Da rileggere"),
            created_by: actor("operatore.prova"),
        };
        let Ok(_) = database.insert_bookmark_collection(&nuova(), istante(ORA)) else {
            panic!("la prima deve potersi creare");
        };
        assert!(
            database
                .insert_bookmark_collection(&nuova(), istante(ORA + 1))
                .is_err()
        );
    }

    /// **Una raccolta che contiene segnalibri non si cancella.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che cancellare un'etichetta porti via, o lasci orfani, i segni che
    /// qualcuno aveva messo. Prima si tolgono, e allora la raccolta se ne va.
    #[test]
    fn una_raccolta_piena_non_si_cancella() {
        let (database, source_id, _) = database_with_session();
        let Ok(raccolta) = database.insert_bookmark_collection(
            &NewBookmarkCollection {
                name: nome("Da rileggere"),
                created_by: actor("operatore.prova"),
            },
            istante(ORA),
        ) else {
            panic!("la raccolta deve potersi creare");
        };
        let Ok(id) = database.insert_bookmark(
            segnalibro(ArchiveRefKind::Source, source_id.get(), Some(raccolta)),
            &actor("operatore.prova"),
            istante(ORA + 10),
        ) else {
            panic!("il segnalibro deve potersi mettere");
        };

        let Err(rifiuto) = database.delete_bookmark_collection(raccolta) else {
            panic!("una raccolta piena non si cancella");
        };

        // IL RIFIUTO DEVE DIRE CHE COSA FARE.
        //
        // Il divieto lo impone gia' `ON DELETE RESTRICT`, e questa prova
        // resterebbe verde anche senza il trigger — l'ha dimostrato il suo
        // controllo negativo, com'era gia' successo in WS-01. Ma il trigger non
        // esiste per vietare: esiste per le PAROLE. Toglierlo lascerebbe in
        // piedi il divieto e riporterebbe il messaggio a parlare di chiavi
        // esterne, che chi legge non sa come usare, e nessuno se ne
        // accorgerebbe.
        //
        // Percio' la prova guarda che cosa il rifiuto DICE.
        let detto = rifiuto.to_string();
        assert!(
            detto.contains("prima si tolgono"),
            "il rifiuto deve dire che cosa fare, non nominare un vincolo \u{2014} «{detto}»"
        );

        let Ok(()) = database.delete_bookmark(id) else {
            panic!("il segnalibro deve potersi togliere");
        };
        assert!(
            database.delete_bookmark_collection(raccolta).is_ok(),
            "svuotata, la raccolta se ne va"
        );
    }

    /// **Togliere un segnalibro non cancella la cosa segnata.**
    #[test]
    fn togliere_un_segnalibro_non_cancella_nulla() {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(inserimento) =
            database.insert_content(&new_content(session_id, source_id, "500", "testo"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = inserimento.content_id();
        let Ok(id) = database.insert_bookmark(
            segnalibro(ArchiveRefKind::Content, content_id.get(), None),
            &actor("operatore.prova"),
            istante(ORA),
        ) else {
            panic!("il segnalibro deve potersi mettere");
        };

        let Ok(()) = database.delete_bookmark(id) else {
            panic!("il segnalibro deve potersi togliere");
        };
        assert!(
            database.content(content_id).is_ok(),
            "togliere un segnalibro non cancella la prova"
        );
    }

    /// **Si sa se una cosa è già segnata.**
    ///
    /// Un comando «Segna» che compare anche su ciò che è già segnato invita a
    /// premerlo, e produce un rifiuto che chi legge non si aspetta.
    #[test]
    fn si_sa_se_una_cosa_e_gia_segnata() {
        let (database, source_id, _) = database_with_session();
        let Ok(riferimento) = ArchiveRef::to(ArchiveRefKind::Source, source_id.get()) else {
            panic!("il riferimento di prova deve essere valido");
        };

        let Ok(prima) = database.bookmark_of(riferimento) else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(prima, None);

        let Ok(id) = database.insert_bookmark(
            segnalibro(ArchiveRefKind::Source, source_id.get(), None),
            &actor("operatore.prova"),
            istante(ORA),
        ) else {
            panic!("il segnalibro deve potersi mettere");
        };

        let Ok(dopo) = database.bookmark_of(riferimento) else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(dopo, Some(id));
    }

    /// **Un segnalibro si sposta in una raccolta, e ne esce.**
    ///
    /// # Perché questo deve esistere
    ///
    /// Perché segnare è un gesto solo, e chi segna non sceglie una raccolta: se
    /// l'appartenenza si decidesse soltanto al momento del segno, le raccolte
    /// sarebbero una capacità che nulla raggiunge.
    ///
    /// # Che cosa questa prova sorveglia
    ///
    /// Che spostare cambi **dove sta il segno** e non che cosa segna: il
    /// riferimento si rilegge identico prima e dopo.
    #[test]
    fn un_segnalibro_si_sposta_in_una_raccolta_e_ne_esce() {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(inserimento) =
            database.insert_content(&new_content(session_id, source_id, "777", "testo"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let contenuto = inserimento.content_id();

        let Ok(raccolta) = database.insert_bookmark_collection(
            &NewBookmarkCollection {
                name: nome("Da rileggere"),
                created_by: actor("operatore.prova"),
            },
            istante(ORA),
        ) else {
            panic!("la raccolta deve potersi creare");
        };
        let Ok(id) = database.insert_bookmark(
            segnalibro(ArchiveRefKind::Content, contenuto.get(), None),
            &actor("operatore.prova"),
            istante(ORA + 10),
        ) else {
            panic!("il segnalibro deve potersi mettere");
        };

        let Ok(()) = database.set_bookmark_collection(id, Some(raccolta)) else {
            panic!("lo spostamento deve riuscire");
        };
        let Ok(dentro) = database.bookmarks(Some(raccolta)) else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(dentro.len(), 1);
        assert_eq!(dentro[0].collection_name.as_deref(), Some("Da rileggere"));
        // IL RIFERIMENTO NON E' CAMBIATO: si e' spostato il segno, non cio'
        // che segna.
        assert_eq!(dentro[0].bookmark.reference.kind(), ArchiveRefKind::Content);
        assert_eq!(dentro[0].bookmark.reference.target_id(), contenuto.get());

        let Ok(()) = database.set_bookmark_collection(id, None) else {
            panic!("l'uscita deve riuscire");
        };
        let Ok(vuota) = database.bookmarks(Some(raccolta)) else {
            panic!("la lettura deve riuscire");
        };
        assert!(vuota.is_empty());
        let Ok(sciolti) = database.bookmarks(None) else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(sciolti.len(), 1);
        assert_eq!(sciolti[0].collection_name, None);
    }

    /// **Spostare un segnalibro che non c'è lo dichiara.**
    #[test]
    fn spostare_un_segnalibro_che_non_c_e_lo_dichiara() {
        let (database, _, _) = database_with_session();
        let esito = database.set_bookmark_collection(lisi_core::BookmarkId::new(999), None);
        assert!(esito.is_err(), "non c'e' nulla da spostare");
    }

    /// **L'archivio rifiuta un segnalibro su un segnalibro.**
    ///
    /// Il dominio lo rifiuta nel costruttore; qui si verifica che lo rifiuti
    /// anche l'archivio, per chi scrivesse un secondo servizio domani.
    #[test]
    fn l_archivio_rifiuta_un_segnalibro_su_un_segnalibro() {
        let (database, _, _) = database_with_session();
        let esito = database.connection.execute(
            "INSERT INTO bookmarks (kind, target_id, created_by, created_at)
             VALUES ('segnalibro', 1, 'operatore.prova', 0)",
            [],
        );
        assert!(
            esito.is_err(),
            "una catena di segnalibri non significa nulla"
        );
    }
}

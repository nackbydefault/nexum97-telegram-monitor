//! Segnare, raggruppare, togliere (BOOK-01).
//!
//! # Che cosa questo servizio garantisce, e che cosa garantisce l'archivio
//!
//! Le regole che **non si possono dimenticare** stanno nell'archivio: la stessa
//! cosa non si segna due volte, due raccolte non si chiamano allo stesso modo,
//! una raccolta piena non si cancella, e un segnalibro non segna un segnalibro.
//! Sono vincoli e un trigger, e valgono anche per chi scrivesse un secondo
//! servizio domani.
//!
//! Qui sta ciò che un archivio non può fare: **tradurre il rifiuto in una frase
//! che dice perché**, e registrare nell'audit chi ha fatto che cosa.
//!
//! # Riferimenti, mai copie della prova
//!
//! Questo servizio non ha alcun modo di conservare il testo di ciò che è
//! segnato: il riferimento è `Copy`, e la tabella non ha una colonna in cui una
//! copia possa stare. Non è una disciplina di questo modulo — è una proprietà
//! dei tipi che usa.

use lisi_core::model::audit::NewAuditEntry;
use lisi_core::model::bookmark::{BookmarkCollection, NewBookmark, NewBookmarkCollection};
use lisi_core::model::reference::ArchiveRef;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{BookmarkCollectionId, BookmarkId, Timestamp};
use lisi_storage::Database;

/// Riesportato perché l'interfaccia dipenda **soltanto** dai servizi
/// (ADR-0010): una schermata che nominasse `lisi_storage` avrebbe attraversato
/// il confine che quel documento tiene chiuso.
pub use lisi_storage::repository::bookmark::ResolvedBookmark;

use crate::error::{ServiceError, ServiceResult};

/// Servizio dei segnalibri e delle raccolte.
#[derive(Debug)]
pub struct BookmarkService {
    database: Database,
}

impl BookmarkService {
    /// Costruisce il servizio sull'archivio indicato.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// L'archivio, in sola lettura.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Restituisce l'archivio al chiamante.
    #[must_use]
    pub fn into_database(self) -> Database {
        self.database
    }

    /// Segna una cosa dell'archivio.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::AlreadyBookmarked`] se quella cosa è già
    /// segnata, e un errore di archivio se la scrittura non riesce.
    pub fn mark(
        &self,
        bookmark: NewBookmark,
        created_by: &Actor,
        now: Timestamp,
    ) -> ServiceResult<BookmarkId> {
        // IL DOPPIONE LO RIFIUTA L'ARCHIVIO, con un vincolo di unicita'.
        //
        // Qui non si ricontrolla prima di scrivere: fra il controllo e la
        // scrittura ci sarebbe una fessura. Si scrive, e si traduce il rifiuto.
        let id = self
            .database
            .insert_bookmark(bookmark, created_by, now)
            .map_err(Self::gia_segnato)?;

        self.database.append_audit(&NewAuditEntry {
            actor: created_by.clone(),
            action: AuditAction::try_new("segnalibro_messo")?,
            entity: AuditEntity::try_new("bookmark")?,
            entity_id: Some(id.get()),
            actor_mode: None,
            // L'AUDIT DICE CHE COSA E QUALE, NON CHE COSA DICEVA.
            detail: Some(AuditDetail::try_new(&format!(
                "{} {}",
                bookmark.reference().kind().as_str(),
                bookmark.reference().target_id()
            ))?),
            recorded_at: now,
        })?;

        Ok(id)
    }

    /// Traduce il rifiuto del vincolo di unicità in una frase che dice perché.
    fn gia_segnato(errore: lisi_storage::StorageError) -> ServiceError {
        if matches!(errore, lisi_storage::StorageError::Sqlite(_)) {
            return ServiceError::AlreadyBookmarked;
        }
        ServiceError::Storage(errore)
    }

    /// Toglie un segnalibro.
    ///
    /// # Che cosa NON tocca
    ///
    /// La cosa segnata. Togliere un segnalibro non cancella il contenuto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il segnalibro non c'era.
    pub fn unmark(&self, id: BookmarkId, removed_by: &Actor, now: Timestamp) -> ServiceResult<()> {
        self.database.delete_bookmark(id)?;

        self.database.append_audit(&NewAuditEntry {
            actor: removed_by.clone(),
            action: AuditAction::try_new("segnalibro_tolto")?,
            entity: AuditEntity::try_new("bookmark")?,
            entity_id: Some(id.get()),
            actor_mode: None,
            detail: None,
            recorded_at: now,
        })?;

        Ok(())
    }

    /// Sposta un segnalibro in una raccolta, o lo lascia sciolto.
    ///
    /// # Perché questa esiste
    ///
    /// Perché segnare è **un gesto solo**: chi segna non sceglie una raccolta.
    /// Se l'appartenenza si decidesse soltanto lì, le raccolte sarebbero una
    /// capacità che nulla raggiunge. Riordinare è un secondo atto, deliberato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il segnalibro non c'è o la raccolta non esiste.
    pub fn file_into(
        &self,
        id: BookmarkId,
        collection: Option<BookmarkCollectionId>,
        moved_by: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.database.set_bookmark_collection(id, collection)?;

        self.database.append_audit(&NewAuditEntry {
            actor: moved_by.clone(),
            action: AuditAction::try_new("segnalibro_spostato")?,
            entity: AuditEntity::try_new("bookmark")?,
            entity_id: Some(id.get()),
            actor_mode: None,
            // QUALE RACCOLTA, O NESSUNA. «Spostato» senza dire dove non
            // documenta niente.
            detail: Some(AuditDetail::try_new(&match collection {
                Some(raccolta) => format!("raccolta {}", raccolta.get()),
                None => String::from("nessuna raccolta"),
            })?),
            recorded_at: now,
        })?;

        Ok(())
    }

    /// Crea una raccolta.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::CollectionNameTaken`] se una raccolta con
    /// quel nome esiste già.
    pub fn create_collection(
        &self,
        collection: &NewBookmarkCollection,
        now: Timestamp,
    ) -> ServiceResult<BookmarkCollectionId> {
        let id = self
            .database
            .insert_bookmark_collection(collection, now)
            .map_err(|errore| Self::nome_gia_preso(errore, collection))?;

        self.database.append_audit(&NewAuditEntry {
            actor: collection.created_by.clone(),
            action: AuditAction::try_new("raccolta_creata")?,
            entity: AuditEntity::try_new("bookmark_collection")?,
            entity_id: Some(id.get()),
            actor_mode: None,
            detail: Some(AuditDetail::try_new(collection.name.as_str())?),
            recorded_at: now,
        })?;

        Ok(id)
    }

    /// Traduce il rifiuto del nome duplicato.
    fn nome_gia_preso(
        errore: lisi_storage::StorageError,
        collection: &NewBookmarkCollection,
    ) -> ServiceError {
        if matches!(errore, lisi_storage::StorageError::Sqlite(_)) {
            return ServiceError::CollectionNameTaken {
                name: collection.name.as_str().to_owned(),
            };
        }
        ServiceError::Storage(errore)
    }

    /// Cancella una raccolta.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::CollectionNotEmpty`] se contiene ancora
    /// segnalibri: cancellarla porterebbe via, o lascerebbe orfani, i segni che
    /// qualcuno aveva messo.
    pub fn delete_collection(
        &self,
        id: BookmarkCollectionId,
        removed_by: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        // SE E' PIENA LO DICE PRIMA, per poterlo dire con parole utili.
        //
        // Il rifiuto vero resta dell'archivio: questa lettura serve alla frase,
        // non alla protezione, e se le due divergessero vincerebbe il trigger.
        let dentro = self.database.bookmarks(Some(id))?;
        if !dentro.is_empty() {
            return Err(ServiceError::CollectionNotEmpty {
                count: dentro.len(),
            });
        }

        self.database.delete_bookmark_collection(id)?;

        self.database.append_audit(&NewAuditEntry {
            actor: removed_by.clone(),
            action: AuditAction::try_new("raccolta_cancellata")?,
            entity: AuditEntity::try_new("bookmark_collection")?,
            entity_id: Some(id.get()),
            actor_mode: None,
            detail: None,
            recorded_at: now,
        })?;

        Ok(())
    }

    /// Le raccolte, in ordine di nome.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn collections(&self) -> ServiceResult<Vec<BookmarkCollection>> {
        Ok(self.database.bookmark_collections()?)
    }

    /// I segnalibri, dal più recente, con ciò che i riferimenti raggiungono.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn marked(
        &self,
        collection: Option<BookmarkCollectionId>,
    ) -> ServiceResult<Vec<ResolvedBookmark>> {
        Ok(self.database.bookmarks(collection)?)
    }

    /// Se una cosa è già segnata.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn mark_of(&self, reference: ArchiveRef) -> ServiceResult<Option<BookmarkId>> {
        Ok(self.database.bookmark_of(reference)?)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::bookmark::{NewBookmark, NewBookmarkCollection};
    use lisi_core::model::reference::{ArchiveRef, ArchiveRefKind};
    use lisi_core::text::{Actor, DisplayName};

    use super::BookmarkService;
    use crate::error::ServiceError;

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("bookmark.rs");

    const ORA: i64 = 1_700_000_000_000;

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    fn attore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn servizio() -> BookmarkService {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        BookmarkService::new(database)
    }

    fn segnalibro(id: i64) -> NewBookmark {
        let Ok(riferimento) = ArchiveRef::to(ArchiveRefKind::Content, id) else {
            panic!("il riferimento di prova deve essere valido");
        };
        let Ok(segnalibro) = NewBookmark::of(riferimento, None) else {
            panic!("il segnalibro di prova deve essere valido");
        };
        segnalibro
    }

    fn raccolta(nome: &str) -> NewBookmarkCollection {
        let Ok(nome) = DisplayName::try_new(nome) else {
            panic!("il nome di prova deve essere valido");
        };
        NewBookmarkCollection {
            name: nome,
            created_by: attore(),
        }
    }

    /// Il codice di produzione senza i commenti.
    fn codice_senza_commenti() -> String {
        let Some((produzione, prove)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        for riga in prove.lines() {
            let e_codice = ["impl ", "fn ", "struct ", "enum ", "const ", "use ", "pub "]
                .iter()
                .any(|inizio| riga.starts_with(inizio));
            assert!(
                !e_codice,
                "c'e' del codice dopo il blocco di prove, invisibile a ogni guardia: «{riga}»"
            );
        }
        produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// **Segnare, rileggere, togliere.**
    #[test]
    fn si_segna_si_rilegge_e_si_toglie() {
        let servizio = servizio();
        let Ok(id) = servizio.mark(segnalibro(42), &attore(), istante(ORA)) else {
            panic!("il segnalibro deve potersi mettere");
        };

        let Ok(elenco) = servizio.marked(None) else {
            panic!("i segnalibri devono potersi leggere");
        };
        assert_eq!(elenco.len(), 1);

        let Ok(()) = servizio.unmark(id, &attore(), istante(ORA + 10)) else {
            panic!("il segnalibro deve potersi togliere");
        };
        let Ok(dopo) = servizio.marked(None) else {
            panic!("la lettura deve riuscire");
        };
        assert!(dopo.is_empty());
    }

    /// **Segnare due volte la stessa cosa produce una frase che spiega.**
    #[test]
    fn segnare_due_volte_produce_una_frase_che_spiega() {
        let servizio = servizio();
        let Ok(_) = servizio.mark(segnalibro(42), &attore(), istante(ORA)) else {
            panic!("il primo deve potersi mettere");
        };

        let esito = servizio.mark(segnalibro(42), &attore(), istante(ORA + 1));
        assert!(matches!(esito, Err(ServiceError::AlreadyBookmarked)));

        let frase = ServiceError::AlreadyBookmarked.operator_message();
        assert!(frase.contains("gi\u{e0} segnat"), "{frase}");
    }

    /// **Una raccolta piena non si cancella, e la frase dice quanti.**
    ///
    /// «Non si può» senza dire quanti lascerebbe chi legge a indovinare quanto
    /// lavoro ha davanti.
    #[test]
    fn una_raccolta_piena_non_si_cancella_e_la_frase_dice_quanti() {
        let servizio = servizio();
        let Ok(id) = servizio.create_collection(&raccolta("Da rileggere"), istante(ORA)) else {
            panic!("la raccolta deve potersi creare");
        };

        let Ok(riferimento) = ArchiveRef::to(ArchiveRefKind::Content, 42) else {
            panic!("il riferimento di prova deve essere valido");
        };
        let Ok(dentro) = NewBookmark::of(riferimento, Some(id)) else {
            panic!("il segnalibro di prova deve essere valido");
        };
        let Ok(_) = servizio.mark(dentro, &attore(), istante(ORA + 10)) else {
            panic!("il segnalibro deve potersi mettere");
        };

        let esito = servizio.delete_collection(id, &attore(), istante(ORA + 20));
        let Err(ServiceError::CollectionNotEmpty { count }) = esito else {
            panic!("una raccolta piena non si cancella");
        };
        assert_eq!(count, 1);

        let frase = ServiceError::CollectionNotEmpty { count: 3 }.operator_message();
        assert!(
            frase.contains('3'),
            "la frase deve dire quanti \u{2014} {frase}"
        );
    }

    /// **Due raccolte con lo stesso nome: la frase dice quale.**
    #[test]
    fn due_raccolte_omonime_producono_una_frase_che_nomina() {
        let servizio = servizio();
        let Ok(_) = servizio.create_collection(&raccolta("Da rileggere"), istante(ORA)) else {
            panic!("la prima deve potersi creare");
        };

        let esito = servizio.create_collection(&raccolta("Da rileggere"), istante(ORA + 1));
        let Err(ServiceError::CollectionNameTaken { name }) = esito else {
            panic!("la seconda deve essere rifiutata");
        };
        assert_eq!(name, "Da rileggere");
    }

    /// **Si sa se una cosa è già segnata.**
    #[test]
    fn si_sa_se_una_cosa_e_gia_segnata() {
        let servizio = servizio();
        let Ok(riferimento) = ArchiveRef::to(ArchiveRefKind::Content, 42) else {
            panic!("il riferimento di prova deve essere valido");
        };

        let Ok(prima) = servizio.mark_of(riferimento) else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(prima, None);

        let Ok(id) = servizio.mark(segnalibro(42), &attore(), istante(ORA)) else {
            panic!("il segnalibro deve potersi mettere");
        };
        let Ok(dopo) = servizio.mark_of(riferimento) else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(dopo, Some(id));
    }

    /// **Ogni atto lascia traccia nell'audit.**
    #[test]
    fn ogni_atto_lascia_traccia() {
        let servizio = servizio();
        let Ok(raccolta_id) = servizio.create_collection(&raccolta("Da rileggere"), istante(ORA))
        else {
            panic!("la raccolta deve potersi creare");
        };
        let Ok(id) = servizio.mark(segnalibro(42), &attore(), istante(ORA + 10)) else {
            panic!("il segnalibro deve potersi mettere");
        };
        let Ok(()) = servizio.file_into(id, Some(raccolta_id), &attore(), istante(ORA + 15)) else {
            panic!("lo spostamento deve riuscire");
        };
        let Ok(()) = servizio.unmark(id, &attore(), istante(ORA + 20)) else {
            panic!("il segnalibro deve potersi togliere");
        };
        let Ok(()) = servizio.delete_collection(raccolta_id, &attore(), istante(ORA + 30)) else {
            panic!("la raccolta vuota deve potersi cancellare");
        };

        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        for azione in [
            "raccolta_creata",
            "segnalibro_messo",
            "segnalibro_spostato",
            "segnalibro_tolto",
            "raccolta_cancellata",
        ] {
            assert!(
                voci.iter().any(|voce| voce.action.as_str() == azione),
                "l'azione «{azione}» deve comparire nell'audit"
            );
        }
    }

    /// **Il servizio non tiene copie: non ha nulla con cui farlo.**
    #[test]
    fn il_servizio_non_tiene_copie_del_materiale() {
        let codice = codice_senza_commenti();
        let Some(inizio) = codice.find("pub struct BookmarkService {") else {
            panic!("il servizio deve esistere");
        };
        let Some(fine) = codice[inizio..].find("\n}\n") else {
            panic!("la struttura deve chiudersi");
        };
        let campi: Vec<&str> = codice[inizio..inizio + fine]
            .lines()
            .map(str::trim)
            .filter(|riga| riga.contains(':'))
            .collect();
        assert_eq!(
            campi.len(),
            1,
            "il servizio ha un campo solo, l'archivio \u{2014} {campi:?}"
        );
    }

    /// **L'audit non porta il materiale segnato.**
    #[test]
    fn l_audit_non_porta_il_materiale() {
        let codice = codice_senza_commenti();
        let Some(inizio) = codice.find("pub fn mark(") else {
            panic!("la funzione deve esistere");
        };
        let Some(fine) = codice[inizio..].find("\n    }\n") else {
            panic!("la funzione deve chiudersi");
        };
        for materiale in [".body", ".text", "label", "remote_message_id"] {
            assert!(
                !codice[inizio..inizio + fine].contains(materiale),
                "l'audit porta «{materiale}»: documenta le azioni, non i dati"
            );
        }
    }
}

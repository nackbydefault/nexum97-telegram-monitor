//! Dizionari, versioni e termini.
//!
//! Il dizionario è un contenitore con identità stabile; il suo contenuto vive
//! nelle versioni. Le regole che rendono ripetibile una sessione conclusa —
//! l'immutabilità di ciò che è pubblicato e la sola lettura dei dizionari di
//! sistema — stanno nei trigger della migrazione `0003`. Qui i loro effetti
//! vengono **tradotti** in errori di dominio: il chiamante deve poter
//! distinguere «questa versione è già pubblicata» da «il database è
//! irraggiungibile» senza leggere il testo di un messaggio del motore.
//!
//! # Un dizionario pubblicato non si cancella
//!
//! La cancellazione di un dizionario si propaga alle sue versioni, e lì incontra
//! il trigger che rende immutabile ciò che è pubblicato. La conseguenza è che
//! **un dizionario con anche una sola versione pubblicata non è cancellabile**.
//!
//! Non è un effetto collaterale da aggirare: pubblicare è un impegno, e da quel
//! momento una sessione può essere stata condotta con quei termini. Ciò che
//! l'operatore vuole quasi sempre — togliere dalla scelta un dizionario che non
//! serve più — si ottiene archiviandolo. La regola è verificata da un test, così
//! che nessuno la scopra per caso mentre cerca di capire perché una
//! cancellazione fallisce.

use core::str::FromStr;

use lisi_core::model::dictionary::{
    Dictionary, DictionaryOrigin, DictionaryScope, DictionaryStatus, DictionaryTerm,
    DictionaryVersion, DictionaryVisibility, MAX_TERMS_PER_DICTIONARY, MatchMode, NewDictionary,
    NewDictionaryTerm, NewDictionaryVersion, SuggestedLevel, UnboundTerm, normalise_for_matching,
};
use lisi_core::text::{
    Actor, DictionaryDescription, DictionaryName, LanguageTag, TermCategory, TermNote, TermText,
};
use lisi_core::{DictionaryId, DictionaryTermId, DictionaryVersionId, Timestamp};
use rusqlite::{OptionalExtension, Row};

use crate::database::Database;
use crate::error::{ConstraintKind, StorageError, StorageResult, classify, constraint_kind};
use crate::repository::{instant, millis};

/// Colonne lette per ricostruire un dizionario.
const DICTIONARY_COLUMNS: &str = "id, name, description, scope, origin, visibility, status,
     created_by, derived_from, created_at, updated_at";

/// Colonne lette per ricostruire una versione.
const VERSION_COLUMNS: &str =
    "id, dictionary_id, number, note, created_by, created_at, published_at";

/// Colonne lette per ricostruire un termine.
const TERM_COLUMNS: &str =
    "id, version_id, text, category, language, match_mode, suggested_level, note";

/// Riga grezza della tabella `dictionaries`.
struct DictionaryRow {
    id: i64,
    name: String,
    description: String,
    scope: String,
    origin: String,
    visibility: String,
    status: String,
    created_by: String,
    derived_from: Option<i64>,
    created_at: i64,
    updated_at: i64,
}

impl DictionaryRow {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            name: row.get(1)?,
            description: row.get(2)?,
            scope: row.get(3)?,
            origin: row.get(4)?,
            visibility: row.get(5)?,
            status: row.get(6)?,
            created_by: row.get(7)?,
            derived_from: row.get(8)?,
            created_at: row.get(9)?,
            updated_at: row.get(10)?,
        })
    }

    fn into_domain(self) -> StorageResult<Dictionary> {
        Ok(Dictionary {
            id: DictionaryId::new(self.id),
            name: DictionaryName::try_new(&self.name)?,
            description: DictionaryDescription::try_new(&self.description)?,
            scope: DictionaryScope::from_str(&self.scope)?,
            origin: DictionaryOrigin::from_str(&self.origin)?,
            visibility: DictionaryVisibility::from_str(&self.visibility)?,
            status: DictionaryStatus::from_str(&self.status)?,
            created_by: Actor::try_new(&self.created_by)?,
            derived_from: self.derived_from.map(DictionaryId::new),
            created_at: instant(self.created_at),
            updated_at: instant(self.updated_at),
        })
    }
}

/// Riga grezza della tabella `dictionary_versions`.
struct VersionRow {
    id: i64,
    dictionary_id: i64,
    number: i64,
    note: String,
    created_by: String,
    created_at: i64,
    published_at: Option<i64>,
}

impl VersionRow {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            dictionary_id: row.get(1)?,
            number: row.get(2)?,
            note: row.get(3)?,
            created_by: row.get(4)?,
            created_at: row.get(5)?,
            published_at: row.get(6)?,
        })
    }

    fn into_domain(self) -> StorageResult<DictionaryVersion> {
        let Ok(number) = u32::try_from(self.number) else {
            return Err(StorageError::CorruptedRow {
                detail: "numero di versione fuori dall'intervallo ammesso",
            });
        };

        Ok(DictionaryVersion {
            id: DictionaryVersionId::new(self.id),
            dictionary_id: DictionaryId::new(self.dictionary_id),
            number,
            note: DictionaryDescription::try_new(&self.note)?,
            created_by: Actor::try_new(&self.created_by)?,
            created_at: instant(self.created_at),
            published_at: self.published_at.map(instant),
        })
    }
}

/// Riga grezza della tabella `dictionary_terms`.
struct TermRow {
    id: i64,
    version_id: i64,
    text: String,
    category: String,
    language: String,
    match_mode: String,
    suggested_level: i64,
    note: String,
}

impl TermRow {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            version_id: row.get(1)?,
            text: row.get(2)?,
            category: row.get(3)?,
            language: row.get(4)?,
            match_mode: row.get(5)?,
            suggested_level: row.get(6)?,
            note: row.get(7)?,
        })
    }

    fn into_domain(self) -> StorageResult<DictionaryTerm> {
        Ok(DictionaryTerm {
            id: DictionaryTermId::new(self.id),
            version_id: DictionaryVersionId::new(self.version_id),
            text: TermText::try_new(&self.text)?,
            category: TermCategory::try_new(&self.category)?,
            language: LanguageTag::try_new(&self.language)?,
            match_mode: MatchMode::from_str(&self.match_mode)?,
            suggested_level: suggested_level(self.suggested_level)?,
            note: TermNote::try_new(&self.note)?,
        })
    }
}

/// Converte il livello suggerito conservato nel database.
pub(crate) fn suggested_level(raw: i64) -> StorageResult<SuggestedLevel> {
    let Ok(narrowed) = i8::try_from(raw) else {
        return Err(StorageError::CorruptedRow {
            detail: "livello suggerito fuori dall'intervallo ammesso",
        });
    };
    Ok(SuggestedLevel::try_new(narrowed)?)
}

/// Traduce l'errore residuo di una cancellazione già respinta dai controlli.
///
/// Le tre ragioni per cui una cancellazione non passa sono distinte **prima**
/// di provarci, perché il motore non le distingue: la `CASCADE` verso le
/// versioni fa scattare il trigger di immutabilità con lo stesso codice del
/// trigger che difende i dizionari di sistema, e i due casi vanno detti
/// all'operatore in modo diverso. Qui resta la rete: se un vincolo si oppone
/// lo stesso, l'errore riporta la causa più probabile invece della diagnostica
/// del motore.
/// Scrive i termini di una versione dentro una transazione già aperta.
///
/// Condiviso dai due percorsi che scrivono un dizionario intero, perché la
/// normalizzazione applicata alla scrittura deve essere una sola: due copie di
/// questo ciclo diventerebbero due normalizzazioni che un giorno divergono.
fn write_terms(
    transaction: &rusqlite::Transaction<'_>,
    version_id: i64,
    terms: &[UnboundTerm],
) -> StorageResult<()> {
    let mut statement = transaction.prepare(
        "INSERT INTO dictionary_terms (
             version_id, text, normalised, category, language, match_mode,
             suggested_level, note
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?;

    for term in terms {
        statement
            .execute(rusqlite::params![
                version_id,
                term.text.as_str(),
                normalise_for_matching(term.text.as_str()),
                term.category.as_str(),
                term.language.as_str(),
                term.match_mode.as_str(),
                term.suggested_level.get(),
                term.note.as_str(),
            ])
            .map_err(|error| {
                classify(error, ConstraintKind::Unique, StorageError::DuplicateTerm)
            })?;
    }

    Ok(())
}

fn classify_dictionary_deletion(error: rusqlite::Error) -> StorageError {
    match constraint_kind(&error) {
        Some(ConstraintKind::Trigger) => StorageError::PublishedDictionaryIsNotDeletable,
        Some(ConstraintKind::ForeignKey) => StorageError::DictionaryStillInUse,
        _ => StorageError::Sqlite(error),
    }
}

impl Database {
    // ------------------------------------------------------------ dizionari

    /// Registra un dizionario in stato di bozza.
    ///
    /// Lo stato iniziale è [`DictionaryStatus::Draft`] e non è negoziabile: un
    /// dizionario senza alcuna versione pubblicata non ha termini da offrire, e
    /// renderlo subito selezionabile significherebbe permettere una sessione
    /// condotta con un insieme vuoto senza che nulla lo segnali.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::DuplicateDictionary`] se lo stesso autore ha
    /// già un dizionario con quel nome, e [`StorageError::NotFound`] se
    /// `derived_from` indica un dizionario inesistente.
    pub fn insert_dictionary(
        &self,
        dictionary: &NewDictionary,
        now: Timestamp,
    ) -> StorageResult<DictionaryId> {
        let id: i64 = self
            .connection
            .query_row(
                "INSERT INTO dictionaries (
                     name, description, scope, origin, visibility, status,
                     created_by, derived_from, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
                 RETURNING id",
                rusqlite::params![
                    dictionary.name.as_str(),
                    dictionary.description.as_str(),
                    dictionary.scope.as_str(),
                    dictionary.origin.as_str(),
                    dictionary.visibility.as_str(),
                    DictionaryStatus::Draft.as_str(),
                    dictionary.created_by.as_str(),
                    dictionary.derived_from.map(DictionaryId::get),
                    millis(now),
                ],
                |row| row.get(0),
            )
            .map_err(|error| match constraint_kind(&error) {
                Some(ConstraintKind::Unique) => StorageError::DuplicateDictionary,
                Some(ConstraintKind::ForeignKey) => StorageError::NotFound {
                    entity: "dizionario di origine",
                    id: dictionary.derived_from.map_or(0, DictionaryId::get),
                },
                _ => StorageError::Sqlite(error),
            })?;

        Ok(DictionaryId::new(id))
    }

    /// Legge un dizionario.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se il dizionario non esiste.
    pub fn dictionary(&self, id: DictionaryId) -> StorageResult<Dictionary> {
        let row = self
            .connection
            .query_row(
                &format!("SELECT {DICTIONARY_COLUMNS} FROM dictionaries WHERE id = ?1"),
                [id.get()],
                DictionaryRow::read,
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound {
                    entity: "dizionario",
                    id: id.get(),
                },
                other => StorageError::Sqlite(other),
            })?;

        row.into_domain()
    }

    /// Elenca tutti i dizionari, in ordine stabile per nome.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// valore non conforme al dominio.
    pub fn dictionaries(&self) -> StorageResult<Vec<Dictionary>> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT {DICTIONARY_COLUMNS} FROM dictionaries ORDER BY name, id"
        ))?;

        let rows = statement.query_map([], DictionaryRow::read)?;

        let mut dictionaries = Vec::new();
        for row in rows {
            dictionaries.push(row?.into_domain()?);
        }
        Ok(dictionaries)
    }

    /// Elenca i dizionari selezionabili per una nuova sessione.
    ///
    /// Sono i soli attivi che abbiano almeno una versione pubblicata: un
    /// dizionario senza versioni pubblicate non contribuirebbe alcun termine, e
    /// offrirlo in scelta lascerebbe credere il contrario.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// valore non conforme al dominio.
    pub fn selectable_dictionaries(&self) -> StorageResult<Vec<Dictionary>> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT {DICTIONARY_COLUMNS}
             FROM dictionaries
             WHERE status = ?1
               AND EXISTS (
                   SELECT 1 FROM dictionary_versions
                   WHERE dictionary_id = dictionaries.id AND published_at IS NOT NULL
               )
             ORDER BY name, id"
        ))?;

        let rows = statement.query_map([DictionaryStatus::Active.as_str()], DictionaryRow::read)?;

        let mut dictionaries = Vec::new();
        for row in rows {
            dictionaries.push(row?.into_domain()?);
        }
        Ok(dictionaries)
    }

    /// Cambia lo stato di un dizionario.
    ///
    /// È ammesso anche sui dizionari di sistema: un seed più recente può
    /// rendere superata una versione precedente. Ciò che resta bloccato è
    /// l'**identità**, non lo stato.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se il dizionario non esiste.
    pub fn set_dictionary_status(
        &self,
        id: DictionaryId,
        status: DictionaryStatus,
        now: Timestamp,
    ) -> StorageResult<()> {
        let updated = self
            .connection
            .execute(
                "UPDATE dictionaries SET status = ?2, updated_at = ?3 WHERE id = ?1",
                rusqlite::params![id.get(), status.as_str(), millis(now)],
            )
            .map_err(|error| {
                classify(
                    error,
                    ConstraintKind::Trigger,
                    StorageError::BuiltInDictionaryIsReadOnly,
                )
            })?;

        if updated == 0 {
            return Err(StorageError::NotFound {
                entity: "dizionario",
                id: id.get(),
            });
        }
        Ok(())
    }

    /// Rinomina un dizionario e ne aggiorna la descrizione.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::BuiltInDictionaryIsReadOnly`] su un
    /// dizionario di sistema, [`StorageError::DuplicateDictionary`] se il nuovo
    /// nome è già usato dallo stesso autore e [`StorageError::NotFound`] se il
    /// dizionario non esiste.
    pub fn rename_dictionary(
        &self,
        id: DictionaryId,
        name: &DictionaryName,
        description: &DictionaryDescription,
        now: Timestamp,
    ) -> StorageResult<()> {
        let updated = self
            .connection
            .execute(
                "UPDATE dictionaries SET name = ?2, description = ?3, updated_at = ?4
                 WHERE id = ?1",
                rusqlite::params![id.get(), name.as_str(), description.as_str(), millis(now)],
            )
            .map_err(|error| match constraint_kind(&error) {
                Some(ConstraintKind::Trigger) => StorageError::BuiltInDictionaryIsReadOnly,
                Some(ConstraintKind::Unique) => StorageError::DuplicateDictionary,
                _ => StorageError::Sqlite(error),
            })?;

        if updated == 0 {
            return Err(StorageError::NotFound {
                entity: "dizionario",
                id: id.get(),
            });
        }
        Ok(())
    }

    /// Se il dizionario è stato selezionato da almeno una sessione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn dictionary_is_used(&self, id: DictionaryId) -> StorageResult<bool> {
        let count: i64 = self.connection.query_row(
            "SELECT count(*) FROM session_dictionary_selections WHERE dictionary_id = ?1",
            [id.get()],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Cancella un dizionario mai pubblicato e mai usato in una sessione.
    ///
    /// Solo una **bozza mai usata** si cancella davvero. Pubblicare è un
    /// impegno: da quel momento una sessione può essere stata condotta con quei
    /// termini. Un dizionario che non serve più si **archivia** con
    /// [`Database::set_dictionary_status`], il che lo toglie dalla scelta senza
    /// cancellare nulla.
    ///
    /// Le tre ragioni del rifiuto sono verificate in ordine di specificità, e
    /// la più precisa prevale: il motore le confonderebbe tutte in un solo
    /// codice di vincolo.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::BuiltInDictionaryIsReadOnly`] su un
    /// dizionario di sistema, [`StorageError::DictionaryStillInUse`] se una
    /// sessione lo ha selezionato, [`StorageError::PublishedDictionaryIsNotDeletable`]
    /// se ha versioni pubblicate e [`StorageError::NotFound`] se non esiste.
    pub fn delete_dictionary(&self, id: DictionaryId) -> StorageResult<()> {
        let dictionary = self.dictionary(id)?;

        if !dictionary.visibility.is_deletable() {
            return Err(StorageError::BuiltInDictionaryIsReadOnly);
        }
        if self.dictionary_is_used(id)? {
            return Err(StorageError::DictionaryStillInUse);
        }
        if self.latest_published_version(id)?.is_some() {
            return Err(StorageError::PublishedDictionaryIsNotDeletable);
        }

        let removed = self
            .connection
            .execute("DELETE FROM dictionaries WHERE id = ?1", [id.get()])
            .map_err(classify_dictionary_deletion)?;

        if removed == 0 {
            return Err(StorageError::NotFound {
                entity: "dizionario",
                id: id.get(),
            });
        }
        Ok(())
    }

    /// Scrive un dizionario intero — contenitore, prima versione e termini — in
    /// un'unica transazione.
    ///
    /// È il percorso di chi riceve un dizionario **già completo**: un import,
    /// un dizionario fornito con il prodotto. Scriverlo in tre transazioni
    /// distinte lascerebbe, al primo termine rifiutato, un contenitore vuoto
    /// che ha già consumato il nome: il secondo tentativo con il file corretto
    /// fallirebbe per nome già usato, e l'operatore non avrebbe modo di capire
    /// perché.
    ///
    /// I termini arrivano **non legati** ad alcuna versione, perché la versione
    /// non esiste finché questa funzione non l'ha scritta.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::DuplicateDictionary`] se il nome è già usato
    /// dallo stesso autore, [`StorageError::DuplicateTerm`] se due termini
    /// coincidono dopo la normalizzazione, [`StorageError::LimitExceeded`]
    /// oltre [`MAX_TERMS_PER_DICTIONARY`]. In ogni caso di errore **non resta
    /// scritto nulla**.
    pub fn insert_dictionary_with_terms(
        &mut self,
        dictionary: &NewDictionary,
        number: u32,
        note: &DictionaryDescription,
        terms: &[UnboundTerm],
        now: Timestamp,
    ) -> StorageResult<(DictionaryId, DictionaryVersionId)> {
        if terms.len() > MAX_TERMS_PER_DICTIONARY {
            return Err(StorageError::LimitExceeded {
                limit: "termini_per_dizionario",
                max: MAX_TERMS_PER_DICTIONARY,
                requested: terms.len(),
            });
        }

        let transaction = self.connection.transaction()?;

        let dictionary_id: i64 = transaction
            .query_row(
                "INSERT INTO dictionaries (
                     name, description, scope, origin, visibility, status,
                     created_by, derived_from, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
                 RETURNING id",
                rusqlite::params![
                    dictionary.name.as_str(),
                    dictionary.description.as_str(),
                    dictionary.scope.as_str(),
                    dictionary.origin.as_str(),
                    dictionary.visibility.as_str(),
                    DictionaryStatus::Draft.as_str(),
                    dictionary.created_by.as_str(),
                    dictionary.derived_from.map(DictionaryId::get),
                    millis(now),
                ],
                |row| row.get(0),
            )
            .map_err(|error| {
                classify(
                    error,
                    ConstraintKind::Unique,
                    StorageError::DuplicateDictionary,
                )
            })?;

        let version_id: i64 = transaction.query_row(
            "INSERT INTO dictionary_versions (
                 dictionary_id, number, note, created_by, created_at, published_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, NULL)
             RETURNING id",
            rusqlite::params![
                dictionary_id,
                number,
                note.as_str(),
                dictionary.created_by.as_str(),
                millis(now),
            ],
            |row| row.get(0),
        )?;

        write_terms(&transaction, version_id, terms)?;
        transaction.commit()?;

        Ok((
            DictionaryId::new(dictionary_id),
            DictionaryVersionId::new(version_id),
        ))
    }

    /// Aggiunge a un dizionario esistente una versione intera, in un'unica
    /// transazione.
    ///
    /// Come [`Database::insert_dictionary_with_terms`], ma per un dizionario che
    /// c'è già: è il percorso dell'aggiornamento di un dizionario fornito con il
    /// prodotto. In due transazioni distinte, un termine rifiutato lascerebbe
    /// una bozza vuota che occupa quel numero di versione, e ogni avvio
    /// successivo fallirebbe sul vincolo di unicità.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::DuplicateDictionaryVersion`] se quel numero
    /// esiste già, [`StorageError::DuplicateTerm`] se due termini coincidono, e
    /// [`StorageError::LimitExceeded`] oltre [`MAX_TERMS_PER_DICTIONARY`]. In
    /// ogni caso di errore **non resta scritto nulla**.
    pub fn insert_version_with_terms(
        &mut self,
        dictionary_id: DictionaryId,
        number: u32,
        note: &DictionaryDescription,
        created_by: &Actor,
        terms: &[UnboundTerm],
        now: Timestamp,
    ) -> StorageResult<DictionaryVersionId> {
        if terms.len() > MAX_TERMS_PER_DICTIONARY {
            return Err(StorageError::LimitExceeded {
                limit: "termini_per_dizionario",
                max: MAX_TERMS_PER_DICTIONARY,
                requested: terms.len(),
            });
        }

        let transaction = self.connection.transaction()?;

        let version_id: i64 = transaction
            .query_row(
                "INSERT INTO dictionary_versions (
                     dictionary_id, number, note, created_by, created_at, published_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, NULL)
                 RETURNING id",
                rusqlite::params![
                    dictionary_id.get(),
                    number,
                    note.as_str(),
                    created_by.as_str(),
                    millis(now),
                ],
                |row| row.get(0),
            )
            .map_err(|error| match constraint_kind(&error) {
                Some(ConstraintKind::Unique) => StorageError::DuplicateDictionaryVersion,
                Some(ConstraintKind::ForeignKey) => StorageError::NotFound {
                    entity: "dizionario",
                    id: dictionary_id.get(),
                },
                _ => StorageError::Sqlite(error),
            })?;

        write_terms(&transaction, version_id, terms)?;
        transaction.commit()?;

        Ok(DictionaryVersionId::new(version_id))
    }

    /// Duplica un dizionario a partire da una sua versione.
    ///
    /// È il modo previsto per partire da un dizionario di sistema: la copia
    /// nasce come **bozza** con i termini della versione indicata, e da lì
    /// l'operatore la modifica liberamente. La provenienza resta registrata in
    /// `derived_from`, così che si possa sempre dire da che cosa una copia è
    /// nata.
    ///
    /// Tutto avviene in un'unica transazione: una copia senza i termini che
    /// dovevano accompagnarla non deve esistere nemmeno per un istante.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::DuplicateDictionary`] se il nome è già usato
    /// dallo stesso autore e [`StorageError::NotFound`] se la versione di
    /// origine non esiste.
    pub fn duplicate_dictionary(
        &mut self,
        copy: &NewDictionary,
        source_version: DictionaryVersionId,
        note: &DictionaryDescription,
        now: Timestamp,
    ) -> StorageResult<(DictionaryId, DictionaryVersionId)> {
        let transaction = self.connection.transaction()?;

        // La verifica sta dentro la transazione. Fuori, fra il controllo e la
        // copia resterebbe un istante in cui la versione di origine puo'
        // sparire, e la copia nascerebbe vuota senza che nulla lo segnali.
        let source_exists: bool = transaction.query_row(
            "SELECT EXISTS (SELECT 1 FROM dictionary_versions WHERE id = ?1)",
            [source_version.get()],
            |row| row.get(0),
        )?;
        if !source_exists {
            return Err(StorageError::NotFound {
                entity: "versione di dizionario",
                id: source_version.get(),
            });
        }

        let dictionary_id: i64 = transaction
            .query_row(
                "INSERT INTO dictionaries (
                     name, description, scope, origin, visibility, status,
                     created_by, derived_from, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
                 RETURNING id",
                rusqlite::params![
                    copy.name.as_str(),
                    copy.description.as_str(),
                    copy.scope.as_str(),
                    copy.origin.as_str(),
                    copy.visibility.as_str(),
                    DictionaryStatus::Draft.as_str(),
                    copy.created_by.as_str(),
                    copy.derived_from.map(DictionaryId::get),
                    millis(now),
                ],
                |row| row.get(0),
            )
            .map_err(|error| {
                classify(
                    error,
                    ConstraintKind::Unique,
                    StorageError::DuplicateDictionary,
                )
            })?;

        let version_id: i64 = transaction.query_row(
            "INSERT INTO dictionary_versions (
                 dictionary_id, number, note, created_by, created_at, published_at
             ) VALUES (?1, 1, ?2, ?3, ?4, NULL)
             RETURNING id",
            rusqlite::params![
                dictionary_id,
                note.as_str(),
                copy.created_by.as_str(),
                millis(now),
            ],
            |row| row.get(0),
        )?;

        // La copia dei termini avviene interamente nel motore: estrarli e
        // reinserirli uno per uno li farebbe passare da qui senza motivo, e un
        // dizionario da diecimila termini pagherebbe diecimila andate e ritorni.
        transaction.execute(
            "INSERT INTO dictionary_terms (
                 version_id, text, normalised, category, language, match_mode,
                 suggested_level, note
             )
             SELECT ?1, text, normalised, category, language, match_mode,
                    suggested_level, note
             FROM dictionary_terms
             WHERE version_id = ?2",
            rusqlite::params![version_id, source_version.get()],
        )?;

        transaction.commit()?;

        Ok((
            DictionaryId::new(dictionary_id),
            DictionaryVersionId::new(version_id),
        ))
    }

    // ------------------------------------------------------------- versioni

    /// Registra una nuova versione in bozza.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se il dizionario non esiste e
    /// [`StorageError::DuplicateDictionaryVersion`] se quel numero di versione
    /// è già presente.
    pub fn insert_dictionary_version(
        &self,
        version: &NewDictionaryVersion,
        now: Timestamp,
    ) -> StorageResult<DictionaryVersionId> {
        let id: i64 = self
            .connection
            .query_row(
                "INSERT INTO dictionary_versions (
                     dictionary_id, number, note, created_by, created_at, published_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, NULL)
                 RETURNING id",
                rusqlite::params![
                    version.dictionary_id.get(),
                    version.number,
                    version.note.as_str(),
                    version.created_by.as_str(),
                    millis(now),
                ],
                |row| row.get(0),
            )
            .map_err(|error| match constraint_kind(&error) {
                Some(ConstraintKind::ForeignKey) => StorageError::NotFound {
                    entity: "dizionario",
                    id: version.dictionary_id.get(),
                },
                Some(ConstraintKind::Unique) => StorageError::DuplicateDictionaryVersion,
                _ => StorageError::Sqlite(error),
            })?;

        Ok(DictionaryVersionId::new(id))
    }

    /// Legge una versione.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se la versione non esiste.
    pub fn dictionary_version(&self, id: DictionaryVersionId) -> StorageResult<DictionaryVersion> {
        let row = self
            .connection
            .query_row(
                &format!("SELECT {VERSION_COLUMNS} FROM dictionary_versions WHERE id = ?1"),
                [id.get()],
                VersionRow::read,
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound {
                    entity: "versione di dizionario",
                    id: id.get(),
                },
                other => StorageError::Sqlite(other),
            })?;

        row.into_domain()
    }

    /// Elenca le versioni di un dizionario, dalla più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// valore non conforme al dominio.
    pub fn dictionary_versions(
        &self,
        dictionary_id: DictionaryId,
    ) -> StorageResult<Vec<DictionaryVersion>> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT {VERSION_COLUMNS}
             FROM dictionary_versions
             WHERE dictionary_id = ?1
             ORDER BY number DESC"
        ))?;

        let rows = statement.query_map([dictionary_id.get()], VersionRow::read)?;

        let mut versions = Vec::new();
        for row in rows {
            versions.push(row?.into_domain()?);
        }
        Ok(versions)
    }

    /// Versione pubblicata più recente di un dizionario, se esiste.
    ///
    /// È quella che la risoluzione sceglie: un profilo riferisce dizionari, non
    /// versioni, e la scelta della versione avviene qui.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se la riga contiene un
    /// valore non conforme al dominio.
    pub fn latest_published_version(
        &self,
        dictionary_id: DictionaryId,
    ) -> StorageResult<Option<DictionaryVersion>> {
        let row = self
            .connection
            .query_row(
                &format!(
                    "SELECT {VERSION_COLUMNS}
                     FROM dictionary_versions
                     WHERE dictionary_id = ?1 AND published_at IS NOT NULL
                     ORDER BY number DESC
                     LIMIT 1"
                ),
                [dictionary_id.get()],
                VersionRow::read,
            )
            .optional()?;

        row.map(VersionRow::into_domain).transpose()
    }

    /// Pubblica una versione, rendendola immutabile.
    ///
    /// Da questo momento i suoi termini non si aggiungono, non si modificano e
    /// non si cancellano più. Una correzione richiede una nuova versione: è il
    /// prezzo perché una sessione conclusa resti ripetibile.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se la versione non esiste e
    /// [`StorageError::PublishedVersionIsImmutable`] se era già pubblicata.
    pub fn publish_dictionary_version(
        &self,
        id: DictionaryVersionId,
        now: Timestamp,
    ) -> StorageResult<()> {
        // Il controllo esplicito serve a dare un errore comprensibile al caso
        // piu' probabile, la doppia pubblicazione. Il trigger resta la difesa
        // vera: due chiamate simultanee non passerebbero comunque entrambe.
        if self.dictionary_version(id)?.is_published() {
            return Err(StorageError::PublishedVersionIsImmutable);
        }

        self.connection
            .execute(
                "UPDATE dictionary_versions SET published_at = ?2 WHERE id = ?1",
                rusqlite::params![id.get(), millis(now)],
            )
            .map_err(|error| {
                classify(
                    error,
                    ConstraintKind::Trigger,
                    StorageError::PublishedVersionIsImmutable,
                )
            })?;

        Ok(())
    }

    /// Cancella una versione ancora in bozza.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::PublishedVersionIsImmutable`] se la versione
    /// è pubblicata e [`StorageError::NotFound`] se non esiste.
    pub fn delete_draft_version(&self, id: DictionaryVersionId) -> StorageResult<()> {
        let removed = self
            .connection
            .execute("DELETE FROM dictionary_versions WHERE id = ?1", [id.get()])
            .map_err(|error| {
                classify(
                    error,
                    ConstraintKind::Trigger,
                    StorageError::PublishedVersionIsImmutable,
                )
            })?;

        if removed == 0 {
            return Err(StorageError::NotFound {
                entity: "versione di dizionario",
                id: id.get(),
            });
        }
        Ok(())
    }

    // -------------------------------------------------------------- termini

    /// Numero di termini di una versione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn dictionary_term_count(&self, version_id: DictionaryVersionId) -> StorageResult<usize> {
        let count: i64 = self.connection.query_row(
            "SELECT count(*) FROM dictionary_terms WHERE version_id = ?1",
            [version_id.get()],
            |row| row.get(0),
        )?;

        usize::try_from(count).map_err(|_| StorageError::CorruptedRow {
            detail: "conteggio dei termini non rappresentabile",
        })
    }

    /// Inserisce un blocco di termini in una versione in bozza.
    ///
    /// L'inserimento è unico e transazionale: un import parziale lascerebbe un
    /// dizionario che sembra completo e non lo è, e nessuno se ne accorgerebbe
    /// finché una sessione non mancasse i riscontri attesi.
    ///
    /// Il limite [`MAX_TERMS_PER_DICTIONARY`] è verificato **qui** oltre che
    /// nel livello superiore: un limite controllato in un solo punto viene
    /// aggirato dal primo percorso che dimentica di passare da lì.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::LimitExceeded`] se il blocco porta la
    /// versione oltre il limite, [`StorageError::PublishedVersionIsImmutable`]
    /// se la versione è pubblicata, [`StorageError::DuplicateTerm`] se un
    /// termine è già presente con la stessa modalità di riscontro e
    /// [`StorageError::NotFound`] se la versione non esiste.
    pub fn insert_dictionary_terms(
        &mut self,
        version_id: DictionaryVersionId,
        terms: &[NewDictionaryTerm],
    ) -> StorageResult<usize> {
        if terms.is_empty() {
            return Ok(0);
        }

        let existing = self.dictionary_term_count(version_id)?;
        let requested = existing.saturating_add(terms.len());
        if requested > MAX_TERMS_PER_DICTIONARY {
            return Err(StorageError::LimitExceeded {
                limit: "termini_per_dizionario",
                max: MAX_TERMS_PER_DICTIONARY,
                requested,
            });
        }

        let transaction = self.connection.transaction()?;

        {
            let mut statement = transaction.prepare(
                "INSERT INTO dictionary_terms (
                     version_id, text, normalised, category, language, match_mode,
                     suggested_level, note
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;

            for term in terms {
                statement
                    .execute(rusqlite::params![
                        version_id.get(),
                        term.text.as_str(),
                        normalise_for_matching(term.text.as_str()),
                        term.category.as_str(),
                        term.language.as_str(),
                        term.match_mode.as_str(),
                        term.suggested_level.get(),
                        term.note.as_str(),
                    ])
                    .map_err(|error| match constraint_kind(&error) {
                        Some(ConstraintKind::Trigger) => StorageError::PublishedVersionIsImmutable,
                        Some(ConstraintKind::Unique) => StorageError::DuplicateTerm,
                        Some(ConstraintKind::ForeignKey) => StorageError::NotFound {
                            entity: "versione di dizionario",
                            id: version_id.get(),
                        },
                        _ => StorageError::Sqlite(error),
                    })?;
            }
        }

        transaction.commit()?;
        Ok(terms.len())
    }

    /// Termini di una versione, in ordine stabile.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// valore non conforme al dominio.
    pub fn dictionary_terms(
        &self,
        version_id: DictionaryVersionId,
    ) -> StorageResult<Vec<DictionaryTerm>> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT {TERM_COLUMNS}
             FROM dictionary_terms
             WHERE version_id = ?1
             ORDER BY normalised, match_mode"
        ))?;

        let rows = statement.query_map([version_id.get()], TermRow::read)?;

        let mut collected = Vec::new();
        for row in rows {
            collected.push(row?.into_domain()?);
        }
        Ok(collected)
    }

    /// Cancella un termine da una versione in bozza.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::PublishedVersionIsImmutable`] se la versione
    /// è pubblicata e [`StorageError::NotFound`] se il termine non esiste.
    pub fn delete_dictionary_term(&self, id: DictionaryTermId) -> StorageResult<()> {
        let removed = self
            .connection
            .execute("DELETE FROM dictionary_terms WHERE id = ?1", [id.get()])
            .map_err(|error| {
                classify(
                    error,
                    ConstraintKind::Trigger,
                    StorageError::PublishedVersionIsImmutable,
                )
            })?;

        if removed == 0 {
            return Err(StorageError::NotFound {
                entity: "termine",
                id: id.get(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::dictionary::{
        DictionaryStatus, DictionaryVisibility, MAX_TERMS_PER_DICTIONARY,
    };
    use lisi_core::{DictionaryId, DictionaryVersionId};

    use crate::error::StorageError;
    use crate::test_support::{
        actor, database, description, dictionary_name, new_dictionary, new_term, new_version, now,
        published_dictionary,
    };

    // ------------------------------------------------------------ dizionari

    #[test]
    fn a_dictionary_is_written_and_read_back_unchanged() {
        let database = database();
        let new = new_dictionary("Incendi", DictionaryVisibility::Personal);

        let Ok(id) = database.insert_dictionary(&new, now()) else {
            panic!("il dizionario deve potersi registrare");
        };
        let Ok(dictionary) = database.dictionary(id) else {
            panic!("il dizionario deve potersi rileggere");
        };

        assert_eq!(dictionary.id, id);
        assert_eq!(dictionary.name, new.name);
        assert_eq!(dictionary.scope, new.scope);
        assert_eq!(dictionary.origin, new.origin);
        assert_eq!(dictionary.visibility, new.visibility);
        assert_eq!(dictionary.created_by, new.created_by);
        assert_eq!(dictionary.derived_from, None);
        assert_eq!(dictionary.created_at, now());
        assert_eq!(dictionary.updated_at, now());
    }

    #[test]
    fn a_new_dictionary_starts_as_a_draft_and_is_not_selectable() {
        // Un dizionario senza versioni pubblicate non ha termini da offrire:
        // renderlo subito selezionabile permetterebbe una sessione condotta con
        // un insieme vuoto senza che nulla lo segnali.
        let database = database();
        let Ok(id) = database.insert_dictionary(
            &new_dictionary("Bozza", DictionaryVisibility::Personal),
            now(),
        ) else {
            panic!("il dizionario deve potersi registrare");
        };

        let Ok(dictionary) = database.dictionary(id) else {
            panic!("il dizionario deve potersi rileggere");
        };
        assert_eq!(dictionary.status, DictionaryStatus::Draft);
        assert!(!dictionary.is_selectable());
    }

    #[test]
    fn the_same_author_cannot_have_two_dictionaries_with_the_same_name() {
        let database = database();
        let new = new_dictionary("Incendi", DictionaryVisibility::Personal);

        let Ok(_) = database.insert_dictionary(&new, now()) else {
            panic!("la prima registrazione deve riuscire");
        };
        assert!(matches!(
            database.insert_dictionary(&new, now()),
            Err(StorageError::DuplicateDictionary)
        ));
    }

    #[test]
    fn two_authors_can_each_have_a_dictionary_with_the_same_name() {
        // L'unicita' e' per autore: due operatori non devono accordarsi sui
        // nomi dei propri dizionari personali.
        let database = database();
        let mut second = new_dictionary("Incendi", DictionaryVisibility::Personal);
        second.created_by = actor("altro.operatore");

        let Ok(_) = database.insert_dictionary(
            &new_dictionary("Incendi", DictionaryVisibility::Personal),
            now(),
        ) else {
            panic!("la prima registrazione deve riuscire");
        };
        assert!(database.insert_dictionary(&second, now()).is_ok());
    }

    #[test]
    fn a_missing_dictionary_is_reported_as_not_found() {
        let database = database();
        assert!(matches!(
            database.dictionary(DictionaryId::new(404)),
            Err(StorageError::NotFound {
                entity: "dizionario",
                id: 404
            })
        ));
    }

    #[test]
    fn a_dictionary_name_with_sql_metacharacters_is_stored_verbatim() {
        let database = database();
        let hostile = "'; DROP TABLE dictionaries; --";

        let Ok(id) = database.insert_dictionary(
            &new_dictionary(hostile, DictionaryVisibility::Personal),
            now(),
        ) else {
            panic!("il nome ostile deve essere trattato come dato");
        };
        let Ok(dictionary) = database.dictionary(id) else {
            panic!("il dizionario deve potersi rileggere");
        };

        assert_eq!(dictionary.name.as_str(), hostile);
        let Ok(all) = database.dictionaries() else {
            panic!("la tabella deve esistere ancora");
        };
        assert_eq!(all.len(), 1);
    }

    // ------------------------------------------------------ dizionari di sistema

    #[test]
    fn a_built_in_dictionary_cannot_be_renamed() {
        let database = database();
        let Ok(id) = database.insert_dictionary(
            &new_dictionary("Globale", DictionaryVisibility::BuiltIn),
            now(),
        ) else {
            panic!("il dizionario di sistema deve potersi registrare");
        };

        assert!(matches!(
            database.rename_dictionary(
                id,
                &dictionary_name("Rinominato"),
                &description("altra"),
                now()
            ),
            Err(StorageError::BuiltInDictionaryIsReadOnly)
        ));
    }

    #[test]
    fn a_built_in_dictionary_cannot_be_deleted() {
        let database = database();
        let Ok(id) = database.insert_dictionary(
            &new_dictionary("Globale", DictionaryVisibility::BuiltIn),
            now(),
        ) else {
            panic!("il dizionario di sistema deve potersi registrare");
        };

        assert!(matches!(
            database.delete_dictionary(id),
            Err(StorageError::BuiltInDictionaryIsReadOnly)
        ));
    }

    #[test]
    fn the_status_of_a_built_in_dictionary_can_still_change() {
        // Un seed piu' recente puo' rendere superata una versione precedente:
        // e' l'identita' a essere bloccata, non lo stato.
        let database = database();
        let Ok(id) = database.insert_dictionary(
            &new_dictionary("Globale", DictionaryVisibility::BuiltIn),
            now(),
        ) else {
            panic!("il dizionario di sistema deve potersi registrare");
        };

        let Ok(()) = database.set_dictionary_status(id, DictionaryStatus::Superseded, now()) else {
            panic!("lo stato di un dizionario di sistema deve potersi cambiare");
        };
        assert_eq!(
            database.dictionary(id).map(|entry| entry.status).ok(),
            Some(DictionaryStatus::Superseded)
        );
    }

    #[test]
    fn a_personal_dictionary_can_be_renamed_and_deleted() {
        let database = database();
        let Ok(id) = database.insert_dictionary(
            &new_dictionary("Miei", DictionaryVisibility::Personal),
            now(),
        ) else {
            panic!("il dizionario deve potersi registrare");
        };

        assert!(
            database
                .rename_dictionary(id, &dictionary_name("Altri"), &description("altra"), now())
                .is_ok()
        );
        assert!(database.delete_dictionary(id).is_ok());
        assert!(matches!(
            database.dictionary(id),
            Err(StorageError::NotFound { .. })
        ));
    }

    #[test]
    fn a_dictionary_with_a_published_version_cannot_be_deleted_but_can_be_archived() {
        // La cancellazione si propaga alle versioni e li' incontra il trigger
        // di immutabilita'. E' voluto: pubblicare e' un impegno. Cio' che
        // l'operatore vuole quasi sempre e' toglierlo dalla scelta, e per
        // quello c'e' l'archiviazione.
        let mut database = database();
        let (dictionary, _) = published_dictionary(&mut database, "Pubblicato", &["incendio"]);

        assert!(matches!(
            database.delete_dictionary(dictionary),
            Err(StorageError::PublishedDictionaryIsNotDeletable)
        ));

        let Ok(()) = database.set_dictionary_status(dictionary, DictionaryStatus::Archived, now())
        else {
            panic!("l'archiviazione deve riuscire");
        };
        assert_eq!(
            database.selectable_dictionaries().map(|all| all.len()).ok(),
            Some(0)
        );
        assert!(database.dictionary(dictionary).is_ok(), "resta leggibile");
    }

    #[test]
    fn renaming_onto_an_existing_name_of_the_same_author_is_refused() {
        let database = database();
        let Ok(_) = database.insert_dictionary(
            &new_dictionary("Primo", DictionaryVisibility::Personal),
            now(),
        ) else {
            panic!("il primo dizionario deve potersi registrare");
        };
        let Ok(second) = database.insert_dictionary(
            &new_dictionary("Secondo", DictionaryVisibility::Personal),
            now(),
        ) else {
            panic!("il secondo dizionario deve potersi registrare");
        };

        assert!(matches!(
            database.rename_dictionary(
                second,
                &dictionary_name("Primo"),
                &description("altra"),
                now()
            ),
            Err(StorageError::DuplicateDictionary)
        ));
    }

    // ------------------------------------------------------------- versioni

    #[test]
    fn publishing_a_version_makes_it_immutable() {
        let mut database = database();
        let Ok(dictionary) = database.insert_dictionary(
            &new_dictionary("Incendi", DictionaryVisibility::Personal),
            now(),
        ) else {
            panic!("il dizionario deve potersi registrare");
        };
        let Ok(version) = database.insert_dictionary_version(&new_version(dictionary, 1), now())
        else {
            panic!("la versione deve potersi registrare");
        };

        let Ok(_) = database.insert_dictionary_terms(version, &[new_term(version, "incendio", 2)])
        else {
            panic!("il termine deve potersi inserire in bozza");
        };
        let Ok(()) = database.publish_dictionary_version(version, now()) else {
            panic!("la pubblicazione deve riuscire");
        };

        assert!(matches!(
            database.insert_dictionary_terms(version, &[new_term(version, "molotov", 3)]),
            Err(StorageError::PublishedVersionIsImmutable)
        ));
        assert!(matches!(
            database.delete_draft_version(version),
            Err(StorageError::PublishedVersionIsImmutable)
        ));
    }

    #[test]
    fn a_version_cannot_be_published_twice() {
        let mut database = database();
        let (_, version) = published_dictionary(&mut database, "Incendi", &["incendio"]);

        assert!(matches!(
            database.publish_dictionary_version(version, now()),
            Err(StorageError::PublishedVersionIsImmutable)
        ));
    }

    #[test]
    fn a_draft_version_can_still_be_deleted() {
        let database = database();
        let Ok(dictionary) = database.insert_dictionary(
            &new_dictionary("Bozza", DictionaryVisibility::Personal),
            now(),
        ) else {
            panic!("il dizionario deve potersi registrare");
        };
        let Ok(version) = database.insert_dictionary_version(&new_version(dictionary, 1), now())
        else {
            panic!("la versione deve potersi registrare");
        };

        assert!(database.delete_draft_version(version).is_ok());
        assert!(matches!(
            database.dictionary_version(version),
            Err(StorageError::NotFound { .. })
        ));
    }

    #[test]
    fn a_dictionary_cannot_have_two_versions_with_the_same_number() {
        let database = database();
        let Ok(dictionary) = database.insert_dictionary(
            &new_dictionary("Incendi", DictionaryVisibility::Personal),
            now(),
        ) else {
            panic!("il dizionario deve potersi registrare");
        };

        let Ok(_) = database.insert_dictionary_version(&new_version(dictionary, 1), now()) else {
            panic!("la prima versione deve potersi registrare");
        };
        assert!(matches!(
            database.insert_dictionary_version(&new_version(dictionary, 1), now()),
            Err(StorageError::DuplicateDictionaryVersion)
        ));
    }

    #[test]
    fn a_version_of_a_missing_dictionary_is_refused() {
        let database = database();
        assert!(matches!(
            database.insert_dictionary_version(&new_version(DictionaryId::new(404), 1), now()),
            Err(StorageError::NotFound {
                entity: "dizionario",
                id: 404
            })
        ));
    }

    #[test]
    fn the_latest_published_version_ignores_the_drafts() {
        // E' la versione che la risoluzione sceglie: se prendesse anche le
        // bozze, una sessione userebbe termini non ancora approvati.
        let mut database = database();
        let (dictionary, published) = published_dictionary(&mut database, "Incendi", &["incendio"]);

        let Ok(draft) = database.insert_dictionary_version(&new_version(dictionary, 2), now())
        else {
            panic!("la bozza deve potersi registrare");
        };

        let Ok(Some(latest)) = database.latest_published_version(dictionary) else {
            panic!("la versione pubblicata deve essere trovata");
        };
        assert_eq!(latest.id, published);
        assert_ne!(latest.id, draft);
        assert_eq!(latest.number, 1);
    }

    #[test]
    fn a_dictionary_without_published_versions_has_none() {
        let database = database();
        let Ok(dictionary) = database.insert_dictionary(
            &new_dictionary("Bozza", DictionaryVisibility::Personal),
            now(),
        ) else {
            panic!("il dizionario deve potersi registrare");
        };

        assert_eq!(
            database.latest_published_version(dictionary).ok(),
            Some(None)
        );
    }

    #[test]
    fn versions_are_listed_from_the_most_recent() {
        let database = database();
        let Ok(dictionary) = database.insert_dictionary(
            &new_dictionary("Incendi", DictionaryVisibility::Personal),
            now(),
        ) else {
            panic!("il dizionario deve potersi registrare");
        };
        for number in 1..=3 {
            let Ok(_) = database.insert_dictionary_version(&new_version(dictionary, number), now())
            else {
                panic!("la versione {number} deve potersi registrare");
            };
        }

        let Ok(versions) = database.dictionary_versions(dictionary) else {
            panic!("l'elenco deve potersi leggere");
        };
        let numbers: Vec<u32> = versions.iter().map(|entry| entry.number).collect();
        assert_eq!(numbers, [3, 2, 1]);
    }

    // -------------------------------------------------------------- termini

    #[test]
    fn a_term_is_written_and_read_back_unchanged() {
        let mut database = database();
        let (_, version) = published_dictionary(&mut database, "Incendi", &[]);

        // La versione e' gia' pubblicata: i termini vanno in una nuova bozza.
        let Ok(dictionary) = database
            .dictionary_version(version)
            .map(|v| v.dictionary_id)
        else {
            panic!("la versione deve potersi rileggere");
        };
        let Ok(draft) = database.insert_dictionary_version(&new_version(dictionary, 2), now())
        else {
            panic!("la bozza deve potersi registrare");
        };
        let Ok(_) = database.insert_dictionary_terms(draft, &[new_term(draft, "INCENDIO", -2)])
        else {
            panic!("il termine deve potersi inserire");
        };

        let Ok(terms) = database.dictionary_terms(draft) else {
            panic!("i termini devono potersi rileggere");
        };
        assert_eq!(terms.len(), 1);
        assert_eq!(terms[0].text.as_str(), "INCENDIO");
        assert_eq!(terms[0].suggested_level.get(), -2);
        assert!(terms[0].suggested_level.is_mitigating());
    }

    #[test]
    fn the_same_term_cannot_be_added_twice_with_the_same_match_mode() {
        let mut database = database();
        let Ok(dictionary) = database.insert_dictionary(
            &new_dictionary("Incendi", DictionaryVisibility::Personal),
            now(),
        ) else {
            panic!("il dizionario deve potersi registrare");
        };
        let Ok(version) = database.insert_dictionary_version(&new_version(dictionary, 1), now())
        else {
            panic!("la versione deve potersi registrare");
        };

        // La normalizzazione precede l'unicita': maiuscolo e minuscolo sono la
        // stessa parola.
        assert!(matches!(
            database.insert_dictionary_terms(
                version,
                &[
                    new_term(version, "incendio", 1),
                    new_term(version, "INCENDIO", 2),
                ]
            ),
            Err(StorageError::DuplicateTerm)
        ));

        // L'inserimento e' transazionale: il primo termine non deve essere
        // rimasto.
        assert_eq!(database.dictionary_term_count(version).ok(), Some(0));
    }

    #[test]
    fn the_limit_on_the_terms_of_a_dictionary_is_enforced_by_the_persistence() {
        // Il limite e' riaffermato qui e non solo nel livello superiore: uno
        // controllato in un solo punto viene aggirato dal primo percorso che
        // dimentica di passare da li'.
        let mut database = database();
        let Ok(dictionary) = database.insert_dictionary(
            &new_dictionary("Grande", DictionaryVisibility::Personal),
            now(),
        ) else {
            panic!("il dizionario deve potersi registrare");
        };
        let Ok(version) = database.insert_dictionary_version(&new_version(dictionary, 1), now())
        else {
            panic!("la versione deve potersi registrare");
        };

        let full: Vec<_> = (0..MAX_TERMS_PER_DICTIONARY)
            .map(|index| new_term(version, &format!("termine{index}"), 1))
            .collect();
        let Ok(written) = database.insert_dictionary_terms(version, &full) else {
            panic!("il dizionario pieno deve potersi scrivere");
        };
        assert_eq!(written, MAX_TERMS_PER_DICTIONARY);

        assert!(matches!(
            database.insert_dictionary_terms(version, &[new_term(version, "uno di troppo", 1)]),
            Err(StorageError::LimitExceeded {
                limit: "termini_per_dizionario",
                max: MAX_TERMS_PER_DICTIONARY,
                ..
            })
        ));
    }

    #[test]
    fn an_empty_block_of_terms_writes_nothing_and_is_not_an_error() {
        let mut database = database();
        let (_, version) = published_dictionary(&mut database, "Incendi", &["incendio"]);

        assert_eq!(database.insert_dictionary_terms(version, &[]).ok(), Some(0));
    }

    #[test]
    fn a_term_of_a_missing_version_is_refused() {
        let mut database = database();
        let absent = DictionaryVersionId::new(404);

        assert!(matches!(
            database.insert_dictionary_terms(absent, &[new_term(absent, "incendio", 1)]),
            Err(StorageError::NotFound {
                entity: "versione di dizionario",
                id: 404
            })
        ));
    }

    #[test]
    fn a_term_of_a_draft_version_can_be_removed() {
        let mut database = database();
        let Ok(dictionary) = database.insert_dictionary(
            &new_dictionary("Bozza", DictionaryVisibility::Personal),
            now(),
        ) else {
            panic!("il dizionario deve potersi registrare");
        };
        let Ok(version) = database.insert_dictionary_version(&new_version(dictionary, 1), now())
        else {
            panic!("la versione deve potersi registrare");
        };
        let Ok(_) = database.insert_dictionary_terms(version, &[new_term(version, "incendio", 1)])
        else {
            panic!("il termine deve potersi inserire");
        };

        let Ok(terms) = database.dictionary_terms(version) else {
            panic!("i termini devono potersi rileggere");
        };
        assert!(database.delete_dictionary_term(terms[0].id).is_ok());
        assert_eq!(database.dictionary_term_count(version).ok(), Some(0));
    }

    // ----------------------------------------------------------- duplicazione

    #[test]
    fn duplicating_a_dictionary_copies_its_terms_into_a_fresh_draft() {
        // E' il modo previsto per partire da un dizionario di sistema, che non
        // si modifica.
        let mut database = database();
        let (source, source_version) =
            published_dictionary(&mut database, "Globale", &["incendio", "molotov"]);

        let mut copy = new_dictionary("Globale mio", DictionaryVisibility::Personal);
        copy.derived_from = Some(source);

        let Ok((copy_id, copy_version)) = database.duplicate_dictionary(
            &copy,
            source_version,
            &description("copia di lavoro"),
            now(),
        ) else {
            panic!("la duplicazione deve riuscire");
        };

        let Ok(duplicated) = database.dictionary(copy_id) else {
            panic!("la copia deve potersi rileggere");
        };
        assert_eq!(duplicated.status, DictionaryStatus::Draft);
        assert_eq!(duplicated.derived_from, Some(source));

        let (Ok(original_terms), Ok(copied_terms)) = (
            database.dictionary_terms(source_version),
            database.dictionary_terms(copy_version),
        ) else {
            panic!("i termini devono potersi rileggere");
        };
        let original: Vec<&str> = original_terms
            .iter()
            .map(|term| term.text.as_str())
            .collect();
        let copied: Vec<&str> = copied_terms.iter().map(|term| term.text.as_str()).collect();
        assert_eq!(original, copied);
    }

    #[test]
    fn the_copy_can_be_changed_without_touching_the_original() {
        let mut database = database();
        let (source, source_version) =
            published_dictionary(&mut database, "Globale", &["incendio"]);

        let Ok((_, copy_version)) = database.duplicate_dictionary(
            &new_dictionary("Copia", DictionaryVisibility::Personal),
            source_version,
            &description("copia"),
            now(),
        ) else {
            panic!("la duplicazione deve riuscire");
        };

        let Ok(_) = database
            .insert_dictionary_terms(copy_version, &[new_term(copy_version, "aggiunto", 1)])
        else {
            panic!("la copia deve essere modificabile");
        };

        assert_eq!(database.dictionary_term_count(source_version).ok(), Some(1));
        assert_eq!(database.dictionary_term_count(copy_version).ok(), Some(2));
        assert_eq!(
            database.dictionary(source).map(|entry| entry.status).ok(),
            Some(DictionaryStatus::Active)
        );
    }

    #[test]
    fn duplicating_from_a_missing_version_writes_nothing() {
        let mut database = database();

        assert!(matches!(
            database.duplicate_dictionary(
                &new_dictionary("Copia", DictionaryVisibility::Personal),
                DictionaryVersionId::new(404),
                &description("copia"),
                now(),
            ),
            Err(StorageError::NotFound {
                entity: "versione di dizionario",
                id: 404
            })
        ));
        assert_eq!(database.dictionaries().map(|all| all.len()).ok(), Some(0));
    }

    #[test]
    fn duplicating_onto_an_existing_name_writes_nothing() {
        let mut database = database();
        let (_, source_version) = published_dictionary(&mut database, "Globale", &["incendio"]);

        assert!(matches!(
            database.duplicate_dictionary(
                &new_dictionary("Globale", DictionaryVisibility::Personal),
                source_version,
                &description("copia"),
                now(),
            ),
            Err(StorageError::DuplicateDictionary)
        ));
        assert_eq!(database.dictionaries().map(|all| all.len()).ok(), Some(1));
    }

    // ----------------------------------------------------------- selezionabili

    #[test]
    fn only_active_dictionaries_with_a_published_version_are_selectable() {
        let mut database = database();
        let (active, _) = published_dictionary(&mut database, "Attivo", &["incendio"]);

        // Attivo ma senza versioni pubblicate: non offrirebbe alcun termine.
        let Ok(empty) = database.insert_dictionary(
            &new_dictionary("Vuoto", DictionaryVisibility::Personal),
            now(),
        ) else {
            panic!("il dizionario deve potersi registrare");
        };
        let Ok(()) = database.set_dictionary_status(empty, DictionaryStatus::Active, now()) else {
            panic!("lo stato deve potersi cambiare");
        };

        // Pubblicato ma disattivato.
        let (inactive, _) = published_dictionary(&mut database, "Disattivato", &["molotov"]);
        let Ok(()) = database.set_dictionary_status(inactive, DictionaryStatus::Inactive, now())
        else {
            panic!("lo stato deve potersi cambiare");
        };

        let Ok(selectable) = database.selectable_dictionaries() else {
            panic!("l'elenco deve potersi leggere");
        };
        let identifiers: Vec<_> = selectable.iter().map(|entry| entry.id).collect();
        assert_eq!(identifiers, [active]);
    }

    #[test]
    fn dictionaries_are_listed_in_a_stable_order() {
        let database = database();
        for name in ["Zeta", "Alfa", "Mike"] {
            let Ok(_) = database
                .insert_dictionary(&new_dictionary(name, DictionaryVisibility::Personal), now())
            else {
                panic!("il dizionario '{name}' deve potersi registrare");
            };
        }

        let Ok(all) = database.dictionaries() else {
            panic!("l'elenco deve potersi leggere");
        };
        let names: Vec<&str> = all.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(names, ["Alfa", "Mike", "Zeta"]);
    }
}

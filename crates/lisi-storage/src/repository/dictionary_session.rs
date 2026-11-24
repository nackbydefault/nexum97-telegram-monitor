//! Profili, selezione di sessione e configurazione risolta.
//!
//! Qui vive il legame fra una sessione e i termini con cui Ã¨ stata condotta.
//! Il punto che regge tutto il resto Ã¨ la **fotografia**: al momento di
//! avviare, i dizionari scelti vengono risolti in un elenco di termini scritto
//! una volta sola e mai piÃ¹ toccato. La sessione guarda quello. Se un
//! dizionario cambia mentre la sessione Ã¨ in corso, la sessione continua con i
//! termini di prima, e a distanza di mesi resta possibile dire con che cosa fu
//! condotta.
//!
//! L'impronta conservata accanto alla fotografia **non Ã¨ una firma**: riconosce
//! che due configurazioni sono la stessa e si accorge che la copia Ã¨ stata
//! alterata, ma non prova chi l'abbia composta nÃ© chi l'abbia toccata.

use core::str::FromStr;

use lisi_core::model::dictionary::{
    DictionaryProfile, MAX_DICTIONARIES_PER_SESSION, MAX_PERSONAL_PROFILES, MAX_RESOLVED_TERMS,
    MatchMode, NewDictionaryProfile, ResolvedDictionaryConfiguration, ResolvedTerm,
    SessionCustomTerm, SuggestedLevel, TermProvenance, normalise_for_matching,
};
use lisi_core::text::{
    Actor, DictionaryDescription, LanguageTag, ProfileName, TermCategory, TermText,
};
use lisi_core::{DictionaryId, DictionaryProfileId, DictionaryVersionId, SessionId, Timestamp};
use rusqlite::Row;

use crate::database::Database;
use crate::error::{ConstraintKind, StorageError, StorageResult, classify, constraint_kind};
use crate::repository::dictionary::suggested_level;
use crate::repository::{instant, millis};

/// Separatore fra due provenienze nel campo che le raccoglie.
const PROVENANCE_SEPARATOR: char = '\u{1e}';

/// Separatore fra i campi di una singola provenienza.
const FIELD_SEPARATOR: char = '\u{1f}';

/// Codifica le provenienze di un termine in un solo campo.
///
/// I separatori sono caratteri di controllo, che i tipi testuali del dominio
/// rifiutano: nessun nome di dizionario puÃ² contenerli. L'etichetta perÃ² Ã¨ una
/// stringa libera, quindi il controllo viene fatto lo stesso â€” un'invariante
/// che vale Â«per costruzioneÂ» smette di valere il giorno in cui la costruzione
/// cambia.
fn encode_provenances(provenances: &[TermProvenance]) -> StorageResult<String> {
    let mut encoded = String::new();

    for (index, provenance) in provenances.iter().enumerate() {
        if provenance.label.contains(PROVENANCE_SEPARATOR)
            || provenance.label.contains(FIELD_SEPARATOR)
        {
            return Err(StorageError::InvalidProvenanceLabel);
        }

        // La lettura rifiuta una provenienza con un solo identificatore dei
        // due. Scriverla comunque produrrebbe uno snapshot illeggibile **per
        // sempre**: i trigger dello schema impediscono sia di correggerlo sia
        // di cancellarlo. Cio' che la lettura non accetta non si scrive.
        if provenance.dictionary_id.is_some() != provenance.version_id.is_some() {
            return Err(StorageError::InvalidProvenanceLabel);
        }

        if index > 0 {
            encoded.push(PROVENANCE_SEPARATOR);
        }

        if let Some(dictionary) = provenance.dictionary_id {
            encoded.push_str(&dictionary.get().to_string());
        }
        encoded.push(FIELD_SEPARATOR);
        if let Some(version) = provenance.version_id {
            encoded.push_str(&version.get().to_string());
        }
        encoded.push(FIELD_SEPARATOR);
        encoded.push_str(&provenance.label);
    }

    Ok(encoded)
}

/// Decodifica il campo delle provenienze.
///
/// Un campo malformato Ã¨ un errore, non qualcosa da interpretare come si puÃ²:
/// una provenienza indovinata risponderebbe alla domanda Â«perchÃ© questo
/// contenuto Ã¨ stato segnalatoÂ» con qualcosa che nessuno ha scritto.
fn decode_provenances(encoded: &str) -> StorageResult<Vec<TermProvenance>> {
    if encoded.is_empty() {
        return Ok(Vec::new());
    }

    let mut provenances = Vec::new();

    for record in encoded.split(PROVENANCE_SEPARATOR) {
        let mut fields = record.split(FIELD_SEPARATOR);
        let (Some(dictionary), Some(version), Some(label), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(StorageError::CorruptedRow {
                detail: "provenienza con un numero di campi inatteso",
            });
        };

        let dictionary_id = parse_optional_id(dictionary)?.map(DictionaryId::new);
        let version_id = parse_optional_id(version)?.map(DictionaryVersionId::new);

        // Un identificatore senza l'altro non descrive nulla: una provenienza
        // o nomina dizionario e versione, o Ã¨ una parola aggiunta alla sessione.
        if dictionary_id.is_some() != version_id.is_some() {
            return Err(StorageError::CorruptedRow {
                detail: "provenienza con un solo identificatore dei due",
            });
        }

        provenances.push(TermProvenance {
            dictionary_id,
            version_id,
            label: label.to_owned(),
        });
    }

    Ok(provenances)
}

/// Interpreta un identificatore che puÃ² essere assente.
fn parse_optional_id(raw: &str) -> StorageResult<Option<i64>> {
    if raw.is_empty() {
        return Ok(None);
    }
    raw.parse::<i64>()
        .map(Some)
        .map_err(|_| StorageError::CorruptedRow {
            detail: "identificatore di provenienza non numerico",
        })
}

/// Riga grezza della tabella `session_resolved_terms`.
struct ResolvedTermRow {
    normalised: String,
    original: String,
    category: String,
    language: String,
    match_mode: String,
    suggested_level: i64,
    provenances: String,
}

impl ResolvedTermRow {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            normalised: row.get(0)?,
            original: row.get(1)?,
            category: row.get(2)?,
            language: row.get(3)?,
            match_mode: row.get(4)?,
            suggested_level: row.get(5)?,
            provenances: row.get(6)?,
        })
    }

    fn into_domain(self) -> StorageResult<ResolvedTerm> {
        Ok(ResolvedTerm {
            normalised: self.normalised,
            original: TermText::try_new(&self.original)?,
            category: TermCategory::try_new(&self.category)?,
            language: LanguageTag::try_new(&self.language)?,
            match_mode: MatchMode::from_str(&self.match_mode)?,
            suggested_level: suggested_level(self.suggested_level)?.get(),
            provenances: decode_provenances(&self.provenances)?,
        })
    }
}

impl Database {
    // -------------------------------------------------------------- profili

    /// Registra un profilo di selezione.
    ///
    /// Profilo e dizionari inclusi sono scritti in un'unica transazione: un
    /// profilo senza i propri dizionari selezionerebbe il nulla.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::DuplicateProfile`] se lo stesso autore ha
    /// giÃ  un profilo con quel nome, [`StorageError::LimitExceeded`] se supera
    /// il numero di profili o di dizionari ammessi, e
    /// [`StorageError::NotFound`] se uno dei dizionari non esiste.
    pub fn insert_dictionary_profile(
        &mut self,
        profile: &NewDictionaryProfile,
        now: Timestamp,
    ) -> StorageResult<DictionaryProfileId> {
        if profile.dictionary_ids.len() > MAX_DICTIONARIES_PER_SESSION {
            return Err(StorageError::LimitExceeded {
                limit: "dizionari_per_profilo",
                max: MAX_DICTIONARIES_PER_SESSION,
                requested: profile.dictionary_ids.len(),
            });
        }

        let existing: i64 = self.connection.query_row(
            "SELECT count(*) FROM dictionary_profiles WHERE created_by = ?1",
            [profile.created_by.as_str()],
            |row| row.get(0),
        )?;
        let requested = usize::try_from(existing)
            .unwrap_or(usize::MAX)
            .saturating_add(1);
        if requested > MAX_PERSONAL_PROFILES {
            return Err(StorageError::LimitExceeded {
                limit: "profili_per_autore",
                max: MAX_PERSONAL_PROFILES,
                requested,
            });
        }

        let transaction = self.connection.transaction()?;

        let profile_id: i64 = transaction
            .query_row(
                "INSERT INTO dictionary_profiles (
                     name, description, created_by, shared, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5)
                 RETURNING id",
                rusqlite::params![
                    profile.name.as_str(),
                    profile.description.as_str(),
                    profile.created_by.as_str(),
                    profile.shared,
                    millis(now),
                ],
                |row| row.get(0),
            )
            .map_err(|error| {
                classify(
                    error,
                    ConstraintKind::Unique,
                    StorageError::DuplicateProfile,
                )
            })?;

        {
            let mut statement = transaction.prepare(
                "INSERT OR IGNORE INTO dictionary_profile_items (profile_id, dictionary_id)
                 VALUES (?1, ?2)",
            )?;

            for dictionary_id in &profile.dictionary_ids {
                // `OR IGNORE` copre solo la ripetizione dello stesso dizionario
                // nell'elenco, che Ã¨ una svista innocua. La foreign key resta
                // attiva e un dizionario inesistente annulla tutto.
                statement
                    .execute(rusqlite::params![profile_id, dictionary_id.get()])
                    .map_err(|error| {
                        if constraint_kind(&error) == Some(ConstraintKind::ForeignKey) {
                            StorageError::NotFound {
                                entity: "dizionario",
                                id: dictionary_id.get(),
                            }
                        } else {
                            StorageError::Sqlite(error)
                        }
                    })?;
            }
        }

        transaction.commit()?;
        Ok(DictionaryProfileId::new(profile_id))
    }

    /// Legge un profilo con i dizionari che include.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se il profilo non esiste.
    pub fn dictionary_profile(&self, id: DictionaryProfileId) -> StorageResult<DictionaryProfile> {
        let (name, description, created_by, shared, created_at): (
            String,
            String,
            String,
            bool,
            i64,
        ) = self
            .connection
            .query_row(
                "SELECT name, description, created_by, shared, created_at
                 FROM dictionary_profiles
                 WHERE id = ?1",
                [id.get()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound {
                    entity: "profilo",
                    id: id.get(),
                },
                other => StorageError::Sqlite(other),
            })?;

        let mut statement = self.connection.prepare(
            "SELECT dictionary_id FROM dictionary_profile_items
             WHERE profile_id = ?1
             ORDER BY dictionary_id",
        )?;
        let rows = statement.query_map([id.get()], |row| row.get::<_, i64>(0))?;

        let mut dictionary_ids = Vec::new();
        for row in rows {
            dictionary_ids.push(DictionaryId::new(row?));
        }

        Ok(DictionaryProfile {
            id,
            name: ProfileName::try_new(&name)?,
            description: DictionaryDescription::try_new(&description)?,
            dictionary_ids,
            created_by: Actor::try_new(&created_by)?,
            shared,
            created_at: instant(created_at),
        })
    }

    /// Elenca i profili visibili a un soggetto: i propri e quelli condivisi.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// valore non conforme al dominio.
    pub fn dictionary_profiles_for(&self, actor: &Actor) -> StorageResult<Vec<DictionaryProfile>> {
        let mut statement = self.connection.prepare(
            "SELECT id FROM dictionary_profiles
             WHERE created_by = ?1 OR shared = 1
             ORDER BY name, id",
        )?;
        let rows = statement.query_map([actor.as_str()], |row| row.get::<_, i64>(0))?;

        let mut identifiers = Vec::new();
        for row in rows {
            identifiers.push(DictionaryProfileId::new(row?));
        }

        let mut profiles = Vec::with_capacity(identifiers.len());
        for id in identifiers {
            profiles.push(self.dictionary_profile(id)?);
        }
        Ok(profiles)
    }

    /// Cancella un profilo.
    ///
    /// Cancellarlo non tocca alcuna sessione: la sessione conserva la propria
    /// fotografia dei termini, non un rimando al profilo.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se il profilo non esiste.
    pub fn delete_dictionary_profile(&self, id: DictionaryProfileId) -> StorageResult<()> {
        let removed = self
            .connection
            .execute("DELETE FROM dictionary_profiles WHERE id = ?1", [id.get()])?;

        if removed == 0 {
            return Err(StorageError::NotFound {
                entity: "profilo",
                id: id.get(),
            });
        }
        Ok(())
    }

    // ------------------------------------------- configurazione di sessione

    /// Registra i dizionari scelti per una sessione, con la versione precisa.
    ///
    /// La versione Ã¨ ciÃ² che conta: il dizionario evolve, la versione no.
    /// L'operazione sostituisce per intero la scelta precedente, cosÃ¬ che non
    /// possa restare una selezione a metÃ  fra due ripensamenti.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::SessionConfigurationAlreadyResolved`] se la
    /// sessione ha giÃ  la propria fotografia, [`StorageError::LimitExceeded`]
    /// oltre [`MAX_DICTIONARIES_PER_SESSION`] e [`StorageError::NotFound`] se
    /// la sessione, un dizionario o una versione non esistono.
    pub fn set_session_dictionary_selection(
        &mut self,
        session_id: SessionId,
        selection: &[(DictionaryId, DictionaryVersionId)],
        now: Timestamp,
    ) -> StorageResult<()> {
        if selection.len() > MAX_DICTIONARIES_PER_SESSION {
            return Err(StorageError::LimitExceeded {
                limit: "dizionari_per_sessione",
                max: MAX_DICTIONARIES_PER_SESSION,
                requested: selection.len(),
            });
        }

        let transaction = self.connection.transaction()?;

        // Cambiare la scelta dopo la risoluzione lascerebbe una sessione i cui
        // dizionari dichiarati non sono quelli con cui sta lavorando.
        let resolved: bool = transaction
            .query_row(
                "SELECT dictionary_digest IS NOT NULL FROM sessions WHERE id = ?1",
                [session_id.get()],
                |row| row.get(0),
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound {
                    entity: "sessione",
                    id: session_id.get(),
                },
                other => StorageError::Sqlite(other),
            })?;
        if resolved {
            return Err(StorageError::SessionConfigurationAlreadyResolved);
        }

        transaction.execute(
            "DELETE FROM session_dictionary_selections WHERE session_id = ?1",
            [session_id.get()],
        )?;

        {
            let mut statement = transaction.prepare(
                "INSERT INTO session_dictionary_selections (
                     session_id, dictionary_id, version_id, selected_at
                 ) VALUES (?1, ?2, ?3, ?4)",
            )?;

            for (dictionary_id, version_id) in selection {
                statement
                    .execute(rusqlite::params![
                        session_id.get(),
                        dictionary_id.get(),
                        version_id.get(),
                        millis(now),
                    ])
                    .map_err(|error| match constraint_kind(&error) {
                        Some(ConstraintKind::ForeignKey) => StorageError::NotFound {
                            entity: "dizionario o versione",
                            id: dictionary_id.get(),
                        },
                        Some(ConstraintKind::Unique) => StorageError::DuplicateDictionary,
                        _ => StorageError::Sqlite(error),
                    })?;
            }
        }

        transaction.commit()?;
        Ok(())
    }

    /// Dizionari scelti per una sessione, con la versione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn session_dictionary_selection(
        &self,
        session_id: SessionId,
    ) -> StorageResult<Vec<(DictionaryId, DictionaryVersionId)>> {
        let mut statement = self.connection.prepare(
            "SELECT dictionary_id, version_id FROM session_dictionary_selections
             WHERE session_id = ?1
             ORDER BY dictionary_id",
        )?;
        let rows = statement.query_map([session_id.get()], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })?;

        let mut selection = Vec::new();
        for row in rows {
            let (dictionary_id, version_id) = row?;
            selection.push((
                DictionaryId::new(dictionary_id),
                DictionaryVersionId::new(version_id),
            ));
        }
        Ok(selection)
    }

    /// Aggiunge parole valide per la sola sessione indicata.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::SessionConfigurationAlreadyResolved`] se la
    /// sessione ha giÃ  la propria fotografia, [`StorageError::DuplicateTerm`]
    /// se una parola Ã¨ giÃ  presente con la stessa modalitÃ  e
    /// [`StorageError::NotFound`] se la sessione non esiste.
    pub fn insert_session_custom_terms(
        &mut self,
        session_id: SessionId,
        terms: &[SessionCustomTerm],
        now: Timestamp,
    ) -> StorageResult<usize> {
        if terms.is_empty() {
            return Ok(0);
        }

        let transaction = self.connection.transaction()?;

        let resolved: bool = transaction
            .query_row(
                "SELECT dictionary_digest IS NOT NULL FROM sessions WHERE id = ?1",
                [session_id.get()],
                |row| row.get(0),
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound {
                    entity: "sessione",
                    id: session_id.get(),
                },
                other => StorageError::Sqlite(other),
            })?;
        if resolved {
            return Err(StorageError::SessionConfigurationAlreadyResolved);
        }

        {
            let mut statement = transaction.prepare(
                "INSERT INTO session_custom_terms (
                     session_id, text, normalised, match_mode, added_at, suggested_level
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;

            for term in terms {
                statement
                    .execute(rusqlite::params![
                        session_id.get(),
                        term.text.as_str(),
                        normalise_for_matching(term.text.as_str()),
                        term.match_mode.as_str(),
                        millis(now),
                        term.suggested_level.get(),
                    ])
                    .map_err(|error| {
                        classify(error, ConstraintKind::Unique, StorageError::DuplicateTerm)
                    })?;
            }
        }

        transaction.commit()?;
        Ok(terms.len())
    }

    /// Parole aggiunte alla sessione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// valore non conforme al dominio.
    pub fn session_custom_terms(
        &self,
        session_id: SessionId,
    ) -> StorageResult<Vec<SessionCustomTerm>> {
        let mut statement = self.connection.prepare(
            "SELECT text, match_mode, suggested_level FROM session_custom_terms
             WHERE session_id = ?1
             ORDER BY normalised, match_mode",
        )?;
        let rows = statement.query_map([session_id.get()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;

        let mut terms = Vec::new();
        for row in rows {
            let (text, match_mode, suggested_level) = row?;
            // Il vincolo di colonna limita il valore a 1..=4, ma la conversione
            // resta verificata invece di essere data per scontata: un archivio
            // e' un file che qualcuno potrebbe aver toccato, e un livello fuori
            // intervallo va respinto qui e non propagato nel dominio.
            let Ok(level) = i8::try_from(suggested_level) else {
                return Err(StorageError::CorruptedRow {
                    detail: "livello suggerito di una parola aggiunta fuori dall'intervallo",
                });
            };
            terms.push(SessionCustomTerm {
                text: TermText::try_new(&text)?,
                match_mode: MatchMode::from_str(&match_mode)?,
                suggested_level: SuggestedLevel::try_new(level)?,
            });
        }
        Ok(terms)
    }

    // ----------------------------------------------------------- fotografia

    /// Scrive la configurazione risolta di una sessione.
    ///
    /// Ãˆ l'operazione che rende ripetibile la sessione, e si compie **una volta
    /// sola**: i trigger dello schema rendono la fotografia immutabile, e qui
    /// il tentativo di sostituirla viene respinto con un errore comprensibile
    /// invece che con la diagnostica del motore.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::SessionConfigurationAlreadyResolved`] se la
    /// sessione ne ha giÃ  una, [`StorageError::LimitExceeded`] oltre
    /// [`MAX_RESOLVED_TERMS`], [`StorageError::InvalidProvenanceLabel`] se
    /// un'etichetta contiene i separatori riservati e
    /// [`StorageError::NotFound`] se la sessione non esiste.
    pub fn save_resolved_configuration(
        &mut self,
        session_id: SessionId,
        configuration: &ResolvedDictionaryConfiguration,
    ) -> StorageResult<()> {
        if configuration.terms.len() > MAX_RESOLVED_TERMS {
            return Err(StorageError::LimitExceeded {
                limit: "termini_risolti",
                max: MAX_RESOLVED_TERMS,
                requested: configuration.terms.len(),
            });
        }

        // L'impronta viene ricalcolata dai termini che si stanno per scrivere.
        // Scrivere quella consegnata dal chiamante significherebbe fidarsi di
        // una struttura a campi pubblici: se le due non coincidessero, lo
        // snapshot sarebbe illeggibile per sempre, perche' i trigger dello
        // schema impediscono sia di correggerlo sia di cancellarlo.
        let recomputed = ResolvedDictionaryConfiguration::from_terms(configuration.terms.clone());
        if recomputed.digest != configuration.digest {
            return Err(StorageError::SnapshotDigestMismatch);
        }

        // La codifica avviene prima di aprire la transazione: un'etichetta
        // inaccettabile deve fermare l'operazione senza averne scritto nulla.
        let mut encoded = Vec::with_capacity(configuration.terms.len());
        for term in &configuration.terms {
            encoded.push(encode_provenances(&term.provenances)?);
        }

        let transaction = self.connection.transaction()?;

        let already: bool = transaction
            .query_row(
                "SELECT dictionary_digest IS NOT NULL FROM sessions WHERE id = ?1",
                [session_id.get()],
                |row| row.get(0),
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound {
                    entity: "sessione",
                    id: session_id.get(),
                },
                other => StorageError::Sqlite(other),
            })?;
        if already {
            return Err(StorageError::SessionConfigurationAlreadyResolved);
        }

        {
            let mut statement = transaction.prepare(
                "INSERT INTO session_resolved_terms (
                     session_id, normalised, original, category, language, match_mode,
                     suggested_level, provenances
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;

            for (term, provenances) in configuration.terms.iter().zip(&encoded) {
                statement.execute(rusqlite::params![
                    session_id.get(),
                    term.normalised,
                    term.original.as_str(),
                    term.category.as_str(),
                    term.language.as_str(),
                    term.match_mode.as_str(),
                    term.suggested_level,
                    provenances,
                ])?;
            }
        }

        transaction.execute(
            "UPDATE sessions SET dictionary_digest = ?2 WHERE id = ?1",
            rusqlite::params![session_id.get(), configuration.digest.as_str()],
        )?;

        transaction.commit()?;
        Ok(())
    }

    /// Rilegge la configurazione risolta di una sessione.
    ///
    /// L'impronta viene **ricalcolata** dai termini riletti e confrontata con
    /// quella conservata. Rileggerla e basta non direbbe nulla: sarebbe il
    /// confronto di un valore con sÃ© stesso.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::SnapshotDigestMismatch`] se la copia
    /// conservata non corrisponde piÃ¹ alla propria impronta,
    /// [`StorageError::CorruptedRow`] se una provenienza Ã¨ illeggibile e
    /// [`StorageError::NotFound`] se la sessione non esiste.
    pub fn session_resolved_configuration(
        &self,
        session_id: SessionId,
    ) -> StorageResult<Option<ResolvedDictionaryConfiguration>> {
        let stored: Option<String> = self
            .connection
            .query_row(
                "SELECT dictionary_digest FROM sessions WHERE id = ?1",
                [session_id.get()],
                |row| row.get(0),
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound {
                    entity: "sessione",
                    id: session_id.get(),
                },
                other => StorageError::Sqlite(other),
            })?;

        let Some(stored) = stored else {
            return Ok(None);
        };

        let mut statement = self.connection.prepare(
            "SELECT normalised, original, category, language, match_mode,
                    suggested_level, provenances
             FROM session_resolved_terms
             WHERE session_id = ?1",
        )?;
        let rows = statement.query_map([session_id.get()], ResolvedTermRow::read)?;

        let mut terms = Vec::new();
        for row in rows {
            terms.push(row?.into_domain()?);
        }

        let configuration = ResolvedDictionaryConfiguration::from_terms(terms);
        if configuration.digest.as_str() != stored {
            return Err(StorageError::SnapshotDigestMismatch);
        }

        Ok(Some(configuration))
    }

    /// L'impronta registrata all'avvio, così come è conservata, **senza**
    /// ricalcolarla.
    ///
    /// Serve a un solo scopo: quando [`Self::session_resolved_configuration`]
    /// dice che i termini non corrispondono più, un documento deve poter
    /// riportare l'impronta che era stata registrata (ADR-0156). Per sapere se
    /// la configurazione è integra si usa l'altra lettura, non questa.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se la sessione non esiste.
    pub fn session_recorded_dictionary_digest(
        &self,
        session_id: SessionId,
    ) -> StorageResult<Option<String>> {
        self.connection
            .query_row(
                "SELECT dictionary_digest FROM sessions WHERE id = ?1",
                [session_id.get()],
                |row| row.get(0),
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound {
                    entity: "sessione",
                    id: session_id.get(),
                },
                other => StorageError::Sqlite(other),
            })
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::dictionary::{
        ConfigurationResolver, DictionaryVisibility, MAX_DICTIONARIES_PER_SESSION,
        MAX_PERSONAL_PROFILES, MatchMode, NewDictionaryProfile, ResolvedDictionaryConfiguration,
        SessionCustomTerm, SuggestedLevel, TermProvenance,
    };
    use lisi_core::text::{LanguageTag, TermCategory};
    use lisi_core::{DictionaryId, DictionaryProfileId, DictionaryVersionId, SessionId};

    use super::{decode_provenances, encode_provenances};
    use crate::error::StorageError;
    use crate::test_support::{
        actor, database_with_session, description, dictionary_name, new_dictionary, now,
        profile_name, published_dictionary, term_text,
    };

    /// Profilo di prova sui dizionari indicati.
    fn new_profile(name: &str, dictionary_ids: Vec<DictionaryId>) -> NewDictionaryProfile {
        NewDictionaryProfile {
            name: profile_name(name),
            description: description("profilo di prova"),
            dictionary_ids,
            created_by: actor("operatore.prova"),
            shared: false,
        }
    }

    /// Configurazione risolta di prova, con le provenienze indicate.
    fn resolved(entries: &[(&str, i8, Option<i64>)]) -> ResolvedDictionaryConfiguration {
        let (Ok(category), Ok(language)) =
            (TermCategory::try_new("prova"), LanguageTag::try_new("it"))
        else {
            panic!("i valori di prova devono essere validi");
        };

        let mut resolver = ConfigurationResolver::new();
        for (text, level, source) in entries {
            let provenance = match source {
                Some(number) => TermProvenance::from_dictionary(
                    DictionaryId::new(*number),
                    DictionaryVersionId::new(number * 10),
                    &dictionary_name(&format!("Dizionario {number}")),
                    1,
                ),
                None => TermProvenance::ad_hoc(),
            };
            let Ok(()) = resolver.add(
                term_text(text),
                category.clone(),
                language.clone(),
                MatchMode::NormalizedWord,
                *level,
                provenance,
            ) else {
                panic!("il termine di prova '{text}' doveva essere accettato");
            };
        }
        resolver.finish()
    }

    // ------------------------------------------------------------- codifica

    #[test]
    fn the_provenances_survive_a_round_trip_through_the_stored_field() {
        let provenances = vec![
            TermProvenance::from_dictionary(
                DictionaryId::new(7),
                DictionaryVersionId::new(70),
                &dictionary_name("Globale"),
                3,
            ),
            TermProvenance::ad_hoc(),
        ];

        let Ok(encoded) = encode_provenances(&provenances) else {
            panic!("le provenienze devono potersi codificare");
        };
        assert_eq!(decode_provenances(&encoded).ok(), Some(provenances));
    }

    #[test]
    fn an_empty_list_of_provenances_round_trips_as_empty() {
        let Ok(encoded) = encode_provenances(&[]) else {
            panic!("l'elenco vuoto deve potersi codificare");
        };
        assert!(encoded.is_empty());
        assert_eq!(decode_provenances(&encoded).ok(), Some(Vec::new()));
    }

    #[test]
    fn a_label_carrying_the_reserved_separators_is_refused() {
        // L'etichetta e' una stringa libera: l'invariante Â«i tipi del dominio
        // rifiutano i caratteri di controlloÂ» non la protegge.
        let hostile = TermProvenance {
            dictionary_id: None,
            version_id: None,
            label: String::from("prima\u{1e}seconda"),
        };

        assert!(matches!(
            encode_provenances(&[hostile]),
            Err(StorageError::InvalidProvenanceLabel)
        ));
    }

    #[test]
    fn a_malformed_stored_field_is_an_error_and_not_a_guess() {
        assert!(matches!(
            decode_provenances("senza separatori"),
            Err(StorageError::CorruptedRow { .. })
        ));
        assert!(matches!(
            decode_provenances("7\u{1f}\u{1f}Globale"),
            Err(StorageError::CorruptedRow {
                detail: "provenienza con un solo identificatore dei due"
            })
        ));
        assert!(matches!(
            decode_provenances("sette\u{1f}settanta\u{1f}Globale"),
            Err(StorageError::CorruptedRow {
                detail: "identificatore di provenienza non numerico"
            })
        ));
    }

    // -------------------------------------------------------------- profili

    #[test]
    fn a_profile_is_written_and_read_back_with_its_dictionaries() {
        let (mut database, _, _) = database_with_session();
        let (first, _) = published_dictionary(&mut database, "Uno", &["incendio"]);
        let (second, _) = published_dictionary(&mut database, "Due", &["molotov"]);

        let new = new_profile("Ordine pubblico", vec![first, second]);
        let Ok(id) = database.insert_dictionary_profile(&new, now()) else {
            panic!("il profilo deve potersi registrare");
        };
        let Ok(profile) = database.dictionary_profile(id) else {
            panic!("il profilo deve potersi rileggere");
        };

        assert_eq!(profile.name, new.name);
        assert_eq!(profile.created_by, new.created_by);
        assert!(!profile.shared);
        assert_eq!(profile.dictionary_ids, vec![first, second]);
        assert_eq!(profile.created_at, now());
    }

    #[test]
    fn the_same_author_cannot_have_two_profiles_with_the_same_name() {
        let (mut database, _, _) = database_with_session();

        let Ok(_) = database.insert_dictionary_profile(&new_profile("Uguale", Vec::new()), now())
        else {
            panic!("la prima registrazione deve riuscire");
        };
        assert!(matches!(
            database.insert_dictionary_profile(&new_profile("Uguale", Vec::new()), now()),
            Err(StorageError::DuplicateProfile)
        ));
    }

    #[test]
    fn a_profile_naming_a_missing_dictionary_writes_nothing() {
        let (mut database, _, _) = database_with_session();

        assert!(matches!(
            database.insert_dictionary_profile(
                &new_profile("Rotto", vec![DictionaryId::new(404)]),
                now()
            ),
            Err(StorageError::NotFound {
                entity: "dizionario",
                id: 404
            })
        ));
        assert_eq!(
            database
                .dictionary_profiles_for(&actor("operatore.prova"))
                .map(|all| all.len())
                .ok(),
            Some(0)
        );
    }

    #[test]
    fn a_profile_cannot_name_more_dictionaries_than_a_session_can_use() {
        let (mut database, _, _) = database_with_session();
        let too_many: Vec<DictionaryId> = (1..=MAX_DICTIONARIES_PER_SESSION + 1)
            .map(|index| DictionaryId::new(index as i64))
            .collect();

        assert!(matches!(
            database.insert_dictionary_profile(&new_profile("Troppi", too_many), now()),
            Err(StorageError::LimitExceeded {
                limit: "dizionari_per_profilo",
                max: MAX_DICTIONARIES_PER_SESSION,
                ..
            })
        ));
    }

    #[test]
    fn the_number_of_profiles_of_one_author_is_limited() {
        let (mut database, _, _) = database_with_session();

        for index in 0..MAX_PERSONAL_PROFILES {
            let Ok(_) = database
                .insert_dictionary_profile(&new_profile(&format!("P{index}"), Vec::new()), now())
            else {
                panic!("il profilo {index} deve potersi registrare");
            };
        }

        assert!(matches!(
            database.insert_dictionary_profile(&new_profile("Uno di troppo", Vec::new()), now()),
            Err(StorageError::LimitExceeded {
                limit: "profili_per_autore",
                max: MAX_PERSONAL_PROFILES,
                ..
            })
        ));
    }

    #[test]
    fn an_operator_sees_their_own_profiles_and_the_shared_ones() {
        let (mut database, _, _) = database_with_session();

        let mut altrui = new_profile("Altrui personale", Vec::new());
        altrui.created_by = actor("altro.operatore");
        let mut condiviso = new_profile("Altrui condiviso", Vec::new());
        condiviso.created_by = actor("altro.operatore");
        condiviso.shared = true;

        for profile in [&new_profile("Mio", Vec::new()), &altrui, &condiviso] {
            let Ok(_) = database.insert_dictionary_profile(profile, now()) else {
                panic!("i profili di prova devono potersi registrare");
            };
        }

        let Ok(visible) = database.dictionary_profiles_for(&actor("operatore.prova")) else {
            panic!("l'elenco deve potersi leggere");
        };
        let names: Vec<&str> = visible.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(names, ["Altrui condiviso", "Mio"]);
    }

    #[test]
    fn a_missing_profile_is_reported_as_not_found() {
        let (database, _, _) = database_with_session();
        assert!(matches!(
            database.dictionary_profile(DictionaryProfileId::new(404)),
            Err(StorageError::NotFound {
                entity: "profilo",
                id: 404
            })
        ));
        assert!(matches!(
            database.delete_dictionary_profile(DictionaryProfileId::new(404)),
            Err(StorageError::NotFound { .. })
        ));
    }

    // ------------------------------------------------ selezione di sessione

    #[test]
    fn the_selection_of_a_session_records_the_exact_version() {
        // E' la versione a rendere ripetibile la sessione: il dizionario
        // evolve, la versione no.
        let (mut database, _, session) = database_with_session();
        let (dictionary, version) = published_dictionary(&mut database, "Incendi", &["incendio"]);

        let Ok(()) =
            database.set_session_dictionary_selection(session, &[(dictionary, version)], now())
        else {
            panic!("la selezione deve potersi registrare");
        };

        assert_eq!(
            database.session_dictionary_selection(session).ok(),
            Some(vec![(dictionary, version)])
        );
    }

    #[test]
    fn a_second_selection_replaces_the_first_entirely() {
        let (mut database, _, session) = database_with_session();
        let (first, first_version) = published_dictionary(&mut database, "Uno", &["incendio"]);
        let (second, second_version) = published_dictionary(&mut database, "Due", &["molotov"]);

        let (Ok(()), Ok(())) = (
            database.set_session_dictionary_selection(session, &[(first, first_version)], now()),
            database.set_session_dictionary_selection(session, &[(second, second_version)], now()),
        ) else {
            panic!("le selezioni devono potersi registrare");
        };

        assert_eq!(
            database.session_dictionary_selection(session).ok(),
            Some(vec![(second, second_version)])
        );
    }

    #[test]
    fn a_session_cannot_select_more_dictionaries_than_the_limit() {
        let (mut database, _, session) = database_with_session();
        let too_many: Vec<(DictionaryId, DictionaryVersionId)> = (1..=MAX_DICTIONARIES_PER_SESSION
            + 1)
            .map(|index| {
                (
                    DictionaryId::new(index as i64),
                    DictionaryVersionId::new(index as i64),
                )
            })
            .collect();

        assert!(matches!(
            database.set_session_dictionary_selection(session, &too_many, now()),
            Err(StorageError::LimitExceeded {
                limit: "dizionari_per_sessione",
                max: MAX_DICTIONARIES_PER_SESSION,
                ..
            })
        ));
    }

    #[test]
    fn the_selection_of_a_missing_session_is_refused() {
        let (mut database, _, _) = database_with_session();
        assert!(matches!(
            database.set_session_dictionary_selection(SessionId::new(404), &[], now()),
            Err(StorageError::NotFound {
                entity: "sessione",
                id: 404
            })
        ));
    }

    #[test]
    fn selecting_a_missing_dictionary_writes_nothing() {
        let (mut database, _, session) = database_with_session();
        let (dictionary, version) = published_dictionary(&mut database, "Incendi", &["incendio"]);

        assert!(matches!(
            database.set_session_dictionary_selection(
                session,
                &[
                    (dictionary, version),
                    (DictionaryId::new(404), DictionaryVersionId::new(404)),
                ],
                now()
            ),
            Err(StorageError::NotFound { .. })
        ));
        assert_eq!(
            database
                .session_dictionary_selection(session)
                .map(|all| all.len())
                .ok(),
            Some(0)
        );
    }

    #[test]
    fn a_dictionary_selected_by_a_session_cannot_be_deleted() {
        // Cancellarlo renderebbe lo storico non piu' interpretabile. Fra le
        // ragioni del rifiuto prevale la piu' specifica: «usato in una
        // sessione» dice all'operatore piu' di «ha versioni pubblicate».
        let (mut database, _, session) = database_with_session();
        let (dictionary, version) = published_dictionary(&mut database, "Incendi", &["incendio"]);
        let Ok(()) =
            database.set_session_dictionary_selection(session, &[(dictionary, version)], now())
        else {
            panic!("la selezione deve potersi registrare");
        };

        assert!(matches!(
            database.delete_dictionary(dictionary),
            Err(StorageError::DictionaryStillInUse)
        ));
    }

    // ------------------------------------------------ parole della sessione

    #[test]
    fn the_added_words_of_a_session_are_written_and_read_back() {
        let (mut database, _, session) = database_with_session();
        let terms = vec![
            SessionCustomTerm::normalised(term_text("Incendio")),
            SessionCustomTerm {
                text: term_text("appiccare il fuoco"),
                match_mode: MatchMode::Phrase,
                suggested_level: SuggestedLevel::weakest_that_alerts(),
            },
        ];

        assert_eq!(
            database
                .insert_session_custom_terms(session, &terms, now())
                .ok(),
            Some(2)
        );
        let Ok(read) = database.session_custom_terms(session) else {
            panic!("le parole devono potersi rileggere");
        };
        assert_eq!(read.len(), 2);
        assert!(read.contains(&terms[0]));
        assert!(read.contains(&terms[1]));
    }

    #[test]
    fn the_same_word_added_twice_with_the_same_mode_writes_nothing() {
        let (mut database, _, session) = database_with_session();
        let repeated = vec![
            SessionCustomTerm::normalised(term_text("incendio")),
            SessionCustomTerm::normalised(term_text("INCENDIO")),
        ];

        assert!(matches!(
            database.insert_session_custom_terms(session, &repeated, now()),
            Err(StorageError::DuplicateTerm)
        ));
        assert_eq!(
            database
                .session_custom_terms(session)
                .map(|all| all.len())
                .ok(),
            Some(0)
        );
    }

    #[test]
    fn the_same_word_with_two_modes_stays_two_words() {
        let (mut database, _, session) = database_with_session();
        let terms = vec![
            SessionCustomTerm::normalised(term_text("incendio")),
            SessionCustomTerm {
                text: term_text("incendio"),
                match_mode: MatchMode::Phrase,
                suggested_level: SuggestedLevel::weakest_that_alerts(),
            },
        ];

        assert_eq!(
            database
                .insert_session_custom_terms(session, &terms, now())
                .ok(),
            Some(2)
        );
    }

    // ----------------------------------------------------------- fotografia

    #[test]
    fn a_resolved_configuration_is_written_and_read_back_with_the_same_digest() {
        let (mut database, _, session) = database_with_session();
        let configuration = resolved(&[
            ("incendio", 2, Some(1)),
            ("molotov", 4, Some(2)),
            ("parola aggiunta", 0, None),
        ]);

        let Ok(()) = database.save_resolved_configuration(session, &configuration) else {
            panic!("la fotografia deve potersi scrivere");
        };
        let Ok(Some(read)) = database.session_resolved_configuration(session) else {
            panic!("la fotografia deve potersi rileggere");
        };

        assert_eq!(read.digest, configuration.digest);
        assert_eq!(read.terms, configuration.terms);
        assert_eq!(read.unique_count, 3);
    }

    #[test]
    fn the_provenances_of_a_resolved_term_survive_the_persistence() {
        // Alla domanda Â«perche' questo contenuto e' stato segnalatoÂ» la
        // risposta deve poter nominare i dizionari, non solo il termine.
        let (mut database, _, session) = database_with_session();
        let configuration = resolved(&[("incendio", 2, Some(1)), ("incendio", 3, Some(2))]);

        let Ok(()) = database.save_resolved_configuration(session, &configuration) else {
            panic!("la fotografia deve potersi scrivere");
        };
        let Ok(Some(read)) = database.session_resolved_configuration(session) else {
            panic!("la fotografia deve potersi rileggere");
        };

        assert_eq!(read.terms.len(), 1);
        assert_eq!(read.terms[0].provenances.len(), 2);
        assert_eq!(read.terms[0].suggested_level, 3, "prevale il piu' alto");
        assert_eq!(read.shared_count, 1);
        let labels: Vec<&str> = read.terms[0]
            .provenances
            .iter()
            .map(|entry| entry.label.as_str())
            .collect();
        assert_eq!(labels, ["Dizionario 1 v1", "Dizionario 2 v1"]);
    }

    #[test]
    fn a_session_without_a_resolved_configuration_has_none() {
        let (database, _, session) = database_with_session();
        assert!(matches!(
            database.session_resolved_configuration(session),
            Ok(None)
        ));
    }

    #[test]
    fn a_resolved_configuration_cannot_be_replaced() {
        let (mut database, _, session) = database_with_session();
        let Ok(()) =
            database.save_resolved_configuration(session, &resolved(&[("uno", 1, Some(1))]))
        else {
            panic!("la prima scrittura deve riuscire");
        };

        assert!(matches!(
            database.save_resolved_configuration(session, &resolved(&[("due", 1, Some(1))])),
            Err(StorageError::SessionConfigurationAlreadyResolved)
        ));
    }

    #[test]
    fn after_the_resolution_the_declared_choice_can_no_longer_change() {
        // Altrimenti resterebbe una sessione i cui dizionari dichiarati non
        // sono quelli con cui sta lavorando.
        let (mut database, _, session) = database_with_session();
        let (dictionary, version) = published_dictionary(&mut database, "Incendi", &["incendio"]);
        let Ok(()) =
            database.save_resolved_configuration(session, &resolved(&[("uno", 1, Some(1))]))
        else {
            panic!("la fotografia deve potersi scrivere");
        };

        assert!(matches!(
            database.set_session_dictionary_selection(session, &[(dictionary, version)], now()),
            Err(StorageError::SessionConfigurationAlreadyResolved)
        ));
        assert!(matches!(
            database.insert_session_custom_terms(
                session,
                &[SessionCustomTerm::normalised(term_text("tardi"))],
                now()
            ),
            Err(StorageError::SessionConfigurationAlreadyResolved)
        ));
    }

    #[test]
    fn a_term_slipped_into_the_snapshot_from_outside_is_detected() {
        // Lo schema vieta modifiche e cancellazioni, non gli inserimenti: e'
        // l'impronta ricalcolata ad accorgersi dell'aggiunta.
        let (mut database, _, session) = database_with_session();
        let Ok(()) =
            database.save_resolved_configuration(session, &resolved(&[("incendio", 2, Some(1))]))
        else {
            panic!("la fotografia deve potersi scrivere");
        };

        let Ok(_) = database.connection.execute(
            "INSERT INTO session_resolved_terms (
                 session_id, normalised, original, category, language, match_mode,
                 suggested_level, provenances
             ) VALUES (?1, 'intruso', 'intruso', 'prova', 'it', 'normalized_word', 4, '')",
            [session.get()],
        ) else {
            panic!("l'inserimento diretto deve riuscire: e' cio' che il test simula");
        };

        assert!(matches!(
            database.session_resolved_configuration(session),
            Err(StorageError::SnapshotDigestMismatch)
        ));
    }

    #[test]
    fn a_configuration_with_a_hostile_label_writes_nothing() {
        // Due percorsi distinti portano allo stesso risultato, ed e' bene che
        // sia cosi': l'etichetta entra nell'impronta, quindi alterarla dopo il
        // calcolo rende la struttura incoerente prima ancora che la codifica
        // possa lamentarsene.
        let (mut database, _, session) = database_with_session();

        // Primo percorso: impronta non piu' coerente con i termini.
        let mut tampered = resolved(&[("incendio", 2, Some(1))]);
        tampered.terms[0].provenances[0].label = String::from("finto\u{1f}separatore");
        assert!(matches!(
            database.save_resolved_configuration(session, &tampered),
            Err(StorageError::SnapshotDigestMismatch)
        ));

        // Secondo percorso: struttura coerente, ma etichetta non codificabile.
        let coherent = ResolvedDictionaryConfiguration::from_terms(tampered.terms.clone());
        assert!(matches!(
            database.save_resolved_configuration(session, &coherent),
            Err(StorageError::InvalidProvenanceLabel)
        ));

        assert!(matches!(
            database.session_resolved_configuration(session),
            Ok(None)
        ));
    }

    #[test]
    fn a_configuration_whose_digest_does_not_match_its_terms_is_not_written() {
        // `ResolvedDictionaryConfiguration` ha campi pubblici: se la scrittura
        // si fidasse dell'impronta consegnata, uno snapshot incoerente
        // resterebbe illeggibile per sempre, perche' i trigger dello schema
        // impediscono sia di correggerlo sia di cancellarlo.
        let (mut database, _, session) = database_with_session();
        let mut configuration = resolved(&[("incendio", 2, Some(1))]);
        configuration.terms[0].suggested_level = 4;

        assert!(matches!(
            database.save_resolved_configuration(session, &configuration),
            Err(StorageError::SnapshotDigestMismatch)
        ));
        assert!(matches!(
            database.session_resolved_configuration(session),
            Ok(None)
        ));
    }

    #[test]
    fn a_provenance_with_only_one_identifier_is_not_written() {
        // Cio' che la lettura rifiuta non si scrive: una riga simile sarebbe
        // illeggibile e, per i trigger, nemmeno cancellabile.
        let broken = TermProvenance {
            dictionary_id: Some(DictionaryId::new(7)),
            version_id: None,
            label: String::from("meta' provenienza"),
        };

        assert!(matches!(
            encode_provenances(&[broken]),
            Err(StorageError::InvalidProvenanceLabel)
        ));
    }

    #[test]
    fn an_empty_configuration_is_written_and_recognised_as_resolved() {
        // Una sessione risolta senza termini e' una scelta discutibile, ma non
        // e' la persistenza a doverla impedire: deve pero' restare distinguibile
        // da una sessione non ancora risolta.
        let (mut database, _, session) = database_with_session();
        let empty = ResolvedDictionaryConfiguration::from_terms(Vec::new());

        let Ok(()) = database.save_resolved_configuration(session, &empty) else {
            panic!("la fotografia vuota deve potersi scrivere");
        };
        let Ok(Some(read)) = database.session_resolved_configuration(session) else {
            panic!("la fotografia vuota deve potersi rileggere");
        };
        assert!(read.is_empty());
        assert_eq!(read.digest, empty.digest);
    }

    #[test]
    fn the_configuration_of_a_missing_session_is_reported_as_not_found() {
        let (mut database, _, _) = database_with_session();
        assert!(matches!(
            database.session_resolved_configuration(SessionId::new(404)),
            Err(StorageError::NotFound {
                entity: "sessione",
                id: 404
            })
        ));
        assert!(matches!(
            database.save_resolved_configuration(SessionId::new(404), &resolved(&[])),
            Err(StorageError::NotFound { .. })
        ));
    }

    #[test]
    fn a_dictionary_visibility_does_not_affect_the_snapshot() {
        // Il dizionario di sistema puo' cambiare stato dopo la risoluzione: la
        // fotografia resta quella.
        let (mut database, _, session) = database_with_session();
        let Ok(built_in) = database.insert_dictionary(
            &new_dictionary("Globale", DictionaryVisibility::BuiltIn),
            now(),
        ) else {
            panic!("il dizionario di sistema deve potersi registrare");
        };
        let configuration = resolved(&[("incendio", 2, Some(built_in.get()))]);
        let Ok(()) = database.save_resolved_configuration(session, &configuration) else {
            panic!("la fotografia deve potersi scrivere");
        };

        let Ok(()) = database.set_dictionary_status(
            built_in,
            lisi_core::model::dictionary::DictionaryStatus::Archived,
            now(),
        ) else {
            panic!("lo stato deve potersi cambiare");
        };

        assert_eq!(
            database
                .session_resolved_configuration(session)
                .ok()
                .flatten()
                .map(|read| read.digest),
            Some(configuration.digest)
        );
    }
}

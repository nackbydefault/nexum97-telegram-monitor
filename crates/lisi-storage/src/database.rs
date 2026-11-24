//! Apertura e configurazione del database.
//!
//! L'apertura è l'unico punto in cui si stabiliscono i pragma. In SQLite le
//! foreign key sono disattivate per impostazione predefinita e vanno abilitate
//! **per connessione**: se questo punto venisse aggirato, tutti i vincoli di
//! integrità dello schema diventerebbero decorativi. Un test lo verifica sulla
//! connessione realmente aperta, non nel codice sorgente.

use std::path::Path;
use std::time::Duration;

use rusqlite::Connection;

use crate::error::StorageResult;
use crate::migrations;

/// Attesa massima su un lock conteso, prima di segnalare l'errore.
const BUSY_TIMEOUT: Duration = Duration::from_millis(5_000);

/// Database aperto e portato alla versione di schema corrente.
#[derive(Debug)]
pub struct Database {
    pub(crate) connection: Connection,
}

impl Database {
    /// Apre il database al percorso indicato, creando la cartella se manca e
    /// applicando le migrazioni mancanti.
    ///
    /// # Errori
    ///
    /// Restituisce [`crate::StorageError::DatabaseDirectory`] se la cartella non
    /// è utilizzabile, [`crate::StorageError::SchemaTooNew`] se il file è stato
    /// scritto da una versione più recente dell'applicazione, e un errore di
    /// migrazione se lo schema non può essere portato alla versione corrente.
    pub fn open(path: &Path) -> StorageResult<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }

        Self::from_connection(Connection::open(path)?)
    }

    /// Apre un database temporaneo in memoria.
    ///
    /// Serve ai test e alle verifiche: non persiste nulla e viene distrutto con
    /// la connessione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la connessione non può essere aperta o
    /// configurata.
    pub fn open_in_memory() -> StorageResult<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    /// Apre una connessione a un database in memoria **condiviso per nome**,
    /// nello stesso processo.
    ///
    /// A differenza di [`Self::open_in_memory`], che crea un database privato
    /// della sola connessione che lo apre, questo usa la modalità "shared
    /// cache" di SQLite tramite un nome indicato in un URI
    /// (`mode=memory&cache=shared`): connessioni diverse aperte con lo stesso
    /// nome, nello stesso processo, vedono lo stesso contenuto. Il contenuto
    /// esiste finché almeno una connessione resta aperta: scompare quando
    /// l'ultima si chiude, come ogni database in memoria.
    ///
    /// Serve al ripiego di avvio quando l'archivio persistente non è apribile:
    /// più servizi devono osservare gli stessi dati invece di uno ciascuno.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la connessione non può essere aperta o
    /// configurata.
    pub fn open_shared_in_memory(name: &str) -> StorageResult<Self> {
        Self::from_connection(Connection::open(format!(
            "file:{name}?mode=memory&cache=shared"
        ))?)
    }

    fn from_connection(mut connection: Connection) -> StorageResult<Self> {
        configure(&connection)?;
        migrations::apply(&mut connection)?;
        Ok(Self { connection })
    }

    /// Versione di schema dichiarata dal database.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il pragma non è leggibile.
    pub fn schema_version(&self) -> StorageResult<u32> {
        migrations::schema_version(&self.connection)
    }

    /// Verifica sulla connessione aperta che le foreign key siano attive.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il pragma non è leggibile.
    pub fn foreign_keys_enabled(&self) -> StorageResult<bool> {
        let enabled: i64 = self
            .connection
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
        Ok(enabled == 1)
    }

    /// Quante righe questa connessione ha scritto, aggiornato o cancellato da
    /// quando è aperta, trigger compresi.
    ///
    /// Serve alle prove che dimostrano che un'operazione **non scrive**: un
    /// contatore che non si muove è una prova più forte di una tabella
    /// controllata a mano, perché vale anche per le tabelle che nessuno ha
    /// pensato di controllare.
    #[must_use]
    pub fn total_changes(&self) -> u64 {
        self.connection.total_changes()
    }
}

/// Applica i pragma alla connessione.
fn configure(connection: &Connection) -> StorageResult<()> {
    // Senza questo, ogni foreign key dello schema sarebbe ignorata.
    connection.pragma_update(None, "foreign_keys", "ON")?;

    // I dati sono di natura investigativa: la durabilità prevale sulla
    // velocità di scrittura.
    connection.pragma_update(None, "synchronous", "FULL")?;

    // Riduce la superficie di attacco se il file di database viene sostituito
    // con uno che dichiara indici o viste basati su funzioni.
    connection.pragma_update(None, "trusted_schema", "OFF")?;

    connection.busy_timeout(BUSY_TIMEOUT)?;

    // `journal_mode` restituisce la modalità effettivamente adottata, quindi va
    // eseguito come interrogazione. Un database in memoria non supporta WAL e
    // risponde `memory`: è atteso e non è un errore.
    let _mode: String = connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Database;
    use crate::error::StorageError;
    use crate::migrations::LATEST_VERSION;

    #[test]
    fn a_new_database_is_migrated_to_the_latest_version() {
        let Ok(database) = Database::open_in_memory() else {
            panic!("il database in memoria deve potersi aprire");
        };
        assert_eq!(database.schema_version().ok(), Some(LATEST_VERSION));
    }

    #[test]
    fn foreign_keys_are_really_enabled_on_the_open_connection() {
        let Ok(database) = Database::open_in_memory() else {
            panic!("il database in memoria deve potersi aprire");
        };
        assert_eq!(database.foreign_keys_enabled().ok(), Some(true));
    }

    #[test]
    fn synchronous_is_full_and_trusted_schema_is_off() {
        let Ok(database) = Database::open_in_memory() else {
            panic!("il database in memoria deve potersi aprire");
        };

        let synchronous: Result<i64, _> =
            database
                .connection
                .query_row("PRAGMA synchronous", [], |row| row.get(0));
        // 2 corrisponde a FULL.
        assert_eq!(synchronous, Ok(2));

        let trusted: Result<i64, _> =
            database
                .connection
                .query_row("PRAGMA trusted_schema", [], |row| row.get(0));
        assert_eq!(trusted, Ok(0));
    }

    #[test]
    fn a_database_file_is_created_together_with_its_directory() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let path = directory.path().join("nuova").join("monitor.sqlite");

        let Ok(database) = Database::open(&path) else {
            panic!("il database su file deve potersi aprire");
        };
        assert_eq!(database.schema_version().ok(), Some(LATEST_VERSION));
        assert!(path.exists());
    }

    #[test]
    fn a_database_written_by_a_newer_version_is_refused_on_reopening() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let path = directory.path().join("monitor.sqlite");

        {
            let Ok(database) = Database::open(&path) else {
                panic!("il database su file deve potersi aprire");
            };
            let Ok(()) = database
                .connection
                .execute_batch("PRAGMA user_version = 4242;")
            else {
                panic!("il pragma deve potersi impostare nei test");
            };
        }

        assert!(matches!(
            Database::open(&path),
            Err(StorageError::SchemaTooNew {
                found: 4242,
                supported: LATEST_VERSION,
            })
        ));
    }

    #[test]
    fn a_shared_in_memory_database_is_migrated_like_any_other() {
        let Ok(database) = Database::open_shared_in_memory("prova-migrazione-condivisa") else {
            panic!("il database condiviso in memoria deve potersi aprire");
        };
        assert_eq!(database.schema_version().ok(), Some(LATEST_VERSION));
    }

    #[test]
    fn two_connections_with_the_same_shared_name_see_the_same_content() {
        // Il ripiego di avvio (M3B.2) serve a piu' servizi che devono vedere
        // gli stessi dati: senza la modalita' condivisa, ognuno aprirebbe un
        // archivio privato e isolato, come gia' capitava a `open_in_memory`.
        let (Ok(first), Ok(second)) = (
            Database::open_shared_in_memory("prova-condivisione"),
            Database::open_shared_in_memory("prova-condivisione"),
        ) else {
            panic!("due connessioni con lo stesso nome devono potersi aprire");
        };

        let Ok(()) = first
            .connection
            .execute_batch("INSERT INTO sources (kind, identifier, display_name, authorized_by, active, created_at, updated_at) VALUES ('channel', 'c1', 'Canale di prova', 'test', 1, 0, 0);")
        else {
            panic!("l'inserimento attraverso la prima connessione deve riuscire");
        };

        let visible: i64 = second
            .connection
            .query_row("SELECT COUNT(*) FROM sources", [], |row| row.get(0))
            .unwrap_or(0);
        assert_eq!(
            visible, 1,
            "la seconda connessione deve vedere la riga scritta dalla prima"
        );
    }

    #[test]
    fn two_different_shared_names_stay_isolated() {
        let (Ok(first), Ok(second)) = (
            Database::open_shared_in_memory("prova-isolamento-a"),
            Database::open_shared_in_memory("prova-isolamento-b"),
        ) else {
            panic!("le due connessioni devono potersi aprire");
        };

        let Ok(()) = first
            .connection
            .execute_batch("INSERT INTO sources (kind, identifier, display_name, authorized_by, active, created_at, updated_at) VALUES ('channel', 'c1', 'Canale di prova', 'test', 1, 0, 0);")
        else {
            panic!("l'inserimento attraverso la prima connessione deve riuscire");
        };

        let visible: i64 = second
            .connection
            .query_row("SELECT COUNT(*) FROM sources", [], |row| row.get(0))
            .unwrap_or(-1);
        assert_eq!(
            visible, 0,
            "un nome diverso deve restare un archivio distinto"
        );
    }
}

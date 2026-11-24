//! Archivio protetto su file.
//!
//! Conserva coppie chiave/valore protette con DPAPI. La scrittura è **atomica**
//! e i permessi sono ristretti al proprietario.
//!
//! # Perché la scrittura è atomica
//!
//! Un blob DPAPI troncato **non è recuperabile**: non esiste modo di decifrare
//! metà cifratura. Se il processo terminasse a metà scrittura, la
//! configurazione andrebbe reinserita. Scrivere su un temporaneo e sostituire
//! il file in un'unica operazione fa sì che uno spegnimento improvviso lasci il
//! file precedente intatto invece di un file inutilizzabile.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::dpapi;
use crate::error::{SecurityError, SecurityResult};

/// Archivio di valori protetti su file.
#[derive(Debug, Clone)]
pub struct ProtectedStore {
    path: PathBuf,
}

impl ProtectedStore {
    /// Crea l'archivio al percorso indicato.
    ///
    /// Il file non viene creato finché non si scrive.
    #[must_use]
    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }

    /// Percorso del file protetto.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Se una configurazione protetta è presente.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.path.is_file()
    }

    /// Scrive le voci indicate, sostituendo il contenuto precedente.
    ///
    /// # Errori
    ///
    /// Restituisce [`SecurityError::ProtectionFailed`] se il sistema rifiuta la
    /// protezione e [`SecurityError::Io`] se la scrittura non riesce.
    pub fn save(&self, entries: &BTreeMap<String, String>) -> SecurityResult<()> {
        let serialised = serialise(entries);
        let protected = dpapi::protect(serialised.as_bytes())?;

        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
            restrict_to_owner(parent);
        }

        write_atomically(&self.path, &protected)?;
        restrict_to_owner(&self.path);
        Ok(())
    }

    /// Legge le voci protette.
    ///
    /// # Errori
    ///
    /// Restituisce [`SecurityError::NotConfigured`] se il file non esiste,
    /// [`SecurityError::UnprotectionFailed`] se il file non è decifrabile con
    /// il profilo corrente e [`SecurityError::Corrupted`] se il contenuto non è
    /// interpretabile.
    pub fn load(&self) -> SecurityResult<BTreeMap<String, String>> {
        if !self.exists() {
            return Err(SecurityError::NotConfigured);
        }

        let protected = std::fs::read(&self.path)?;
        if protected.is_empty() {
            return Err(SecurityError::Corrupted {
                reason: "il file protetto è vuoto",
            });
        }

        let plaintext = dpapi::unprotect(&protected)?;
        let text = String::from_utf8(plaintext).map_err(|_| SecurityError::NotValidText)?;
        deserialise(&text)
    }

    /// Legge una singola voce.
    ///
    /// # Errori
    ///
    /// Restituisce [`SecurityError::MissingEntry`] se la voce non è presente.
    pub fn load_entry(&self, key: &'static str) -> SecurityResult<String> {
        self.load()?
            .remove(key)
            .ok_or(SecurityError::MissingEntry { key })
    }

    /// Cancella la configurazione protetta.
    ///
    /// La cancellazione è **controllata**: l'assenza del file non è un errore,
    /// perché il risultato voluto — nessuna configurazione presente — è quello
    /// in entrambi i casi.
    ///
    /// # Errori
    ///
    /// Restituisce [`SecurityError::Io`] se il file esiste ma non può essere
    /// rimosso.
    pub fn delete(&self) -> SecurityResult<()> {
        if !self.exists() {
            return Ok(());
        }
        std::fs::remove_file(&self.path)?;
        Ok(())
    }
}

/// Trasforma le voci in testo.
///
/// Formato deliberatamente elementare: una voce per riga, chiave e valore
/// separati dal primo segno di uguale. Il contenuto è già protetto, quindi il
/// formato non deve difendersi da nulla; deve solo essere ispezionabile senza
/// dipendenze quando qualcosa va storto.
fn serialise(entries: &BTreeMap<String, String>) -> String {
    let mut text = String::new();
    for (key, value) in entries {
        text.push_str(key);
        text.push('=');
        text.push_str(value);
        text.push('\n');
    }
    text
}

/// Ricostruisce le voci dal testo.
fn deserialise(text: &str) -> SecurityResult<BTreeMap<String, String>> {
    let mut entries = BTreeMap::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            return Err(SecurityError::Corrupted {
                reason: "una riga della configurazione non ha la forma chiave=valore",
            });
        };
        entries.insert(key.trim().to_owned(), value.to_owned());
    }

    Ok(entries)
}

/// Scrive il file in modo atomico.
///
/// Il temporaneo è creato **nella stessa cartella** del file finale: una
/// sostituzione fra volumi diversi non sarebbe atomica.
fn write_atomically(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temporary = parent.to_path_buf();

    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("configurazione");
    temporary.push(format!(".{name}.parziale"));

    std::fs::write(&temporary, contents)?;
    restrict_to_owner(&temporary);

    // LA DESTINAZIONE NON SI CANCELLA PRIMA (FINAL-REVIEW-01, FR-013).
    //
    // Qui c'era una rimozione preventiva, con il commento «`rename` su Windows
    // fallisce se la destinazione esiste». Non e' vero: `std::fs::rename` su
    // Windows usa `MoveFileExW` con `MOVEFILE_REPLACE_EXISTING`, e sostituisce.
    // La rimozione apriva invece una finestra pericolosa: se la rinomina
    // falliva — un antivirus che tiene il temporaneo — sparivano sia il file
    // nuovo sia il vecchio, e una postazione che seguiva un Hub tornava «non
    // configurata», cioè da sola, cioè con l'autorita' di acquisire. Ora, se
    // la rinomina fallisce, il file di prima resta com'era.
    match std::fs::rename(&temporary, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            Err(error)
        }
    }
}

/// Restringe i permessi al solo proprietario.
///
/// Fino al 2026-11-18 era realizzata con `icacls`; ora la restrizione è
/// quella di [`crate::owner_only`], con le API di sicurezza di Windows nel
/// modulo isolato `acl` (ADR-0206).
///
/// **Limite dichiarato:** l'impostazione avviene *dopo* la creazione, quindi
/// esiste una finestra brevissima in cui il file eredita le ACL della cartella
/// genitore. La cartella dell'applicazione è già ristretta all'utente, quindi
/// la finestra non espone a un altro utente; resta annotata perché è reale.
///
/// Un fallimento non interrompe l'operazione: il file resta protetto da DPAPI,
/// che è la difesa sostanziale. Viene registrato e basta.
///
/// # L'utente si indica con il SID (SEC-02, ADR-0157 decisione 3)
///
/// Fino al 2026-10-22 la concessione nominava l'utente con `USERNAME`: un nome
/// non qualificato, che su una postazione in dominio si risolve prima fra gli
/// account locali e può indicare un'altra persona con lo stesso nome. Ora la
/// restrizione è quella di [`crate::owner_only`]: il SID del token (fino al
/// 2026-11-18 letto da `whoami /user`), il DACL protetto, e il risultato
/// **riletto**. Su una
/// cartella la concessione resta ereditabile, `(OI)(CI)`: senza, la cartella
/// resterebbe accessibile e il suo contenuto no (lo si era trovato costruendo
/// TEAM-CLIENT-01, dove salvare `hub.protetto` rendeva illeggibile l'archivio
/// SQLite nella stessa cartella).
///
/// Il registro non riporta la ragione di un fallimento: potrebbe nominare il
/// SID di un altro account della postazione.
fn restrict_to_owner(path: &Path) {
    if !crate::owner_only::restrict_to_current_user(path).is_owner_only() {
        tracing::warn!("restrizione dei permessi non verificata: il dato resta protetto da DPAPI");
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{ProtectedStore, deserialise, serialise};
    use crate::error::SecurityError;

    fn entries() -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        map.insert(String::from("api_id"), String::from("1"));
        map.insert(
            String::from("api_hash"),
            String::from("00000000000000000000000000000000"),
        );
        map
    }

    /// **Una rinomina fallita lascia il file di prima com'era**
    /// (FINAL-REVIEW-01, FR-013).
    ///
    /// Il temporaneo è tenuto aperto senza il permesso di cancellazione, come
    /// farebbe un antivirus che lo sta esaminando: la scrittura riesce, la
    /// rinomina no. Fino al 2026-10-03 la destinazione era già stata
    /// cancellata a quel punto, e sparivano tutti e due.
    #[cfg(windows)]
    #[test]
    fn a_failed_rename_keeps_the_previous_file() {
        use std::os::windows::fs::OpenOptionsExt;

        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        let destinazione = cartella.path().join("hub-client.protetto");
        if std::fs::write(&destinazione, b"configurazione di prima").is_err() {
            panic!("il file di prima deve potersi scrivere");
        }
        let temporaneo = cartella.path().join(".hub-client.protetto.parziale");
        // FILE_SHARE_READ | FILE_SHARE_WRITE, senza FILE_SHARE_DELETE.
        let Ok(tenuto) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0x1 | 0x2)
            .open(&temporaneo)
        else {
            panic!("il temporaneo deve potersi tenere aperto");
        };

        let esito = super::write_atomically(&destinazione, b"configurazione nuova");
        drop(tenuto);

        assert!(esito.is_err(), "la rinomina doveva fallire");
        assert_eq!(
            std::fs::read(&destinazione).ok().as_deref(),
            Some(&b"configurazione di prima"[..]),
            "il file di prima deve restare com'era"
        );
    }

    /// **Salvare un file protetto non deve chiudere fuori ciò che gli sta
    /// accanto.**
    ///
    /// La restrizione dei permessi agisce anche sulla cartella. Finché il
    /// permesso concesso alla cartella non era ereditabile, `/inheritance:r`
    /// toglieva ai file già presenti ogni permesso e non ne concedeva alcuno:
    /// l'archivio SQLite nella stessa cartella diventava illeggibile **dallo
    /// stesso utente**. Il difetto è stato trovato costruendo TEAM-CLIENT-01.
    #[test]
    fn saving_does_not_lock_the_owner_out_of_the_neighbouring_files() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        let vicino = cartella.path().join("archivio.txt");
        if std::fs::write(&vicino, b"prima").is_err() {
            panic!("il file vicino deve potersi scrivere");
        }

        let store = ProtectedStore::at(cartella.path().join("segreti.protetto"));
        if store.save(&entries()).is_err() {
            panic!("il file protetto deve potersi salvare");
        }

        assert_eq!(
            std::fs::read(&vicino).ok(),
            Some(b"prima".to_vec()),
            "il file accanto a quello protetto deve restare leggibile"
        );
        assert!(
            std::fs::write(&vicino, b"dopo").is_ok(),
            "il file accanto a quello protetto deve restare scrivibile"
        );
        let nuovo = cartella.path().join("nato-dopo.txt");
        assert!(
            std::fs::write(&nuovo, b"nuovo").is_ok() && std::fs::read(&nuovo).is_ok(),
            "un file creato dopo nella stessa cartella deve essere utilizzabile"
        );
        assert_eq!(store.load().ok(), Some(entries()));
    }

    /// **Il magazzino e la sua cartella sono del solo utente, indicato con il
    /// SID, e lo si rilegge** (SEC-02, ADR-0157 decisione 3).
    ///
    /// Su una postazione senza dominio il nome e il SID indicano la stessa
    /// persona: questa prova non può essere vista rossa sul codice di prima,
    /// che concedeva per nome. Il caso che il SID evita — un account locale
    /// omonimo di un account di dominio — non si riproduce senza un dominio.
    #[cfg(windows)]
    #[test]
    fn il_magazzino_e_la_sua_cartella_sono_del_solo_utente() {
        use crate::owner_only::verify_current_user_only;

        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        let dati = cartella.path().join("dati");
        let store = ProtectedStore::at(dati.join("segreti.protetto"));
        if store.save(&entries()).is_err() {
            panic!("il file protetto deve potersi salvare");
        }
        for percorso in [store.path(), dati.as_path()] {
            let accesso = verify_current_user_only(percorso);
            assert!(
                accesso.is_owner_only(),
                "«{}» non è del solo utente: {accesso:?}",
                percorso.display()
            );
        }
    }

    #[test]
    fn entries_survive_serialisation_and_parsing() {
        let text = serialise(&entries());
        assert_eq!(deserialise(&text).ok(), Some(entries()));
    }

    #[test]
    fn a_value_containing_an_equals_sign_is_preserved() {
        // Il separatore e' il *primo* uguale: un valore che ne contiene altri
        // non deve essere troncato.
        let mut map = BTreeMap::new();
        map.insert(String::from("chiave"), String::from("a=b=c"));

        let text = serialise(&map);
        assert_eq!(deserialise(&text).ok(), Some(map));
    }

    #[test]
    fn a_malformed_line_is_refused_instead_of_being_guessed() {
        assert!(matches!(
            deserialise("riga-senza-uguale\n"),
            Err(SecurityError::Corrupted { .. })
        ));
    }

    #[test]
    fn empty_lines_are_ignored() {
        let parsed = deserialise("\n\n  \nchiave=valore\n\n");
        assert_eq!(parsed.map(|map| map.len()).ok(), Some(1));
    }

    #[test]
    fn an_absent_store_reports_that_nothing_is_configured() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let store = ProtectedStore::at(directory.path().join("assente.protetto"));

        assert!(!store.exists());
        assert!(matches!(store.load(), Err(SecurityError::NotConfigured)));
    }

    #[test]
    fn deleting_an_absent_store_is_not_an_error() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let store = ProtectedStore::at(directory.path().join("assente.protetto"));
        assert!(store.delete().is_ok());
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::collections::BTreeMap;

    use super::ProtectedStore;
    use crate::error::SecurityError;

    fn sample() -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        map.insert(String::from("api_id"), String::from("1"));
        map.insert(
            String::from("api_hash"),
            String::from("00000000000000000000000000000000"),
        );
        map
    }

    #[test]
    fn saved_entries_are_read_back_intact() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let store = ProtectedStore::at(directory.path().join("configurazione.protetta"));

        let Ok(()) = store.save(&sample()) else {
            panic!("il salvataggio deve riuscire");
        };
        assert!(store.exists());
        assert_eq!(store.load().ok(), Some(sample()));
    }

    #[test]
    fn the_file_on_disk_does_not_contain_the_values_in_clear() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let path = directory.path().join("configurazione.protetta");
        let store = ProtectedStore::at(path.clone());

        let Ok(()) = store.save(&sample()) else {
            panic!("il salvataggio deve riuscire");
        };

        let Ok(raw) = std::fs::read(&path) else {
            panic!("il file deve essere leggibile");
        };
        let hash_bytes = b"00000000000000000000000000000000";
        let contains = raw
            .windows(hash_bytes.len())
            .any(|window| window == hash_bytes);
        assert!(
            !contains,
            "il valore non deve comparire in chiaro sul disco"
        );
    }

    #[test]
    fn saving_twice_replaces_the_previous_content() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let store = ProtectedStore::at(directory.path().join("configurazione.protetta"));

        let Ok(()) = store.save(&sample()) else {
            panic!("il primo salvataggio deve riuscire");
        };

        let mut updated = BTreeMap::new();
        updated.insert(String::from("api_id"), String::from("2"));
        let Ok(()) = store.save(&updated) else {
            panic!("il secondo salvataggio deve riuscire");
        };

        assert_eq!(store.load().ok(), Some(updated));
    }

    #[test]
    fn no_partial_file_is_left_behind_after_a_save() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let store = ProtectedStore::at(directory.path().join("configurazione.protetta"));
        let Ok(()) = store.save(&sample()) else {
            panic!("il salvataggio deve riuscire");
        };

        let Ok(listing) = std::fs::read_dir(directory.path()) else {
            panic!("la cartella deve essere leggibile");
        };
        for entry in listing.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            assert!(
                !name.contains("parziale"),
                "nessun file temporaneo deve sopravvivere alla scrittura"
            );
        }
    }

    #[test]
    fn a_corrupted_file_is_reported_and_does_not_produce_garbage() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let path = directory.path().join("configurazione.protetta");
        let store = ProtectedStore::at(path.clone());
        let Ok(()) = store.save(&sample()) else {
            panic!("il salvataggio deve riuscire");
        };

        let Ok(mut raw) = std::fs::read(&path) else {
            panic!("il file deve essere leggibile");
        };
        let middle = raw.len() / 2;
        raw[middle] ^= 0xFF;
        let Ok(()) = std::fs::write(&path, &raw) else {
            panic!("il file deve essere scrivibile");
        };

        assert!(matches!(
            store.load(),
            Err(SecurityError::UnprotectionFailed { .. })
        ));
    }

    #[test]
    fn a_truncated_file_is_reported() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let path = directory.path().join("configurazione.protetta");
        let store = ProtectedStore::at(path.clone());
        let Ok(()) = store.save(&sample()) else {
            panic!("il salvataggio deve riuscire");
        };

        let Ok(raw) = std::fs::read(&path) else {
            panic!("il file deve essere leggibile");
        };
        let Ok(()) = std::fs::write(&path, &raw[..raw.len() / 3]) else {
            panic!("il file deve essere scrivibile");
        };

        assert!(store.load().is_err());
    }

    #[test]
    fn an_empty_file_is_reported_as_corrupted() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let path = directory.path().join("configurazione.protetta");
        let Ok(()) = std::fs::write(&path, b"") else {
            panic!("il file deve essere scrivibile");
        };

        let store = ProtectedStore::at(path);
        assert!(matches!(store.load(), Err(SecurityError::Corrupted { .. })));
    }

    #[test]
    fn a_deleted_store_reports_that_nothing_is_configured() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let store = ProtectedStore::at(directory.path().join("configurazione.protetta"));
        let Ok(()) = store.save(&sample()) else {
            panic!("il salvataggio deve riuscire");
        };

        let Ok(()) = store.delete() else {
            panic!("la cancellazione deve riuscire");
        };
        assert!(!store.exists());
        assert!(matches!(store.load(), Err(SecurityError::NotConfigured)));
    }

    #[test]
    fn a_missing_entry_is_reported_by_name() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let store = ProtectedStore::at(directory.path().join("configurazione.protetta"));
        let Ok(()) = store.save(&sample()) else {
            panic!("il salvataggio deve riuscire");
        };

        assert!(matches!(
            store.load_entry("assente"),
            Err(SecurityError::MissingEntry { key: "assente" })
        ));
        assert_eq!(store.load_entry("api_id").ok(), Some(String::from("1")));
    }
}

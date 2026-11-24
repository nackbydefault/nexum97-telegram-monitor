//! La copia di sicurezza dell'archivio.
//!
//! # Perché non si copia il file
//!
//! L'archivio è in modalità WAL: a programma aperto, le scritture più recenti
//! vivono in un file accanto. Copiare il solo file principale produce una copia
//! che **si apre, sembra a posto, e ha perso l'ultima parte del lavoro** — un
//! errore che si scopre il giorno in cui la copia serve.
//!
//! `VACUUM INTO` legge attraverso il meccanismo di transazione di SQLite: la
//! copia contiene uno stato che è realmente esistito, giornale compreso.
//!
//! # L'effetto secondario che vale doppio
//!
//! La copia è anche **compattata**: le pagine libere non vengono trasferite, e i
//! byte di ciò che era stato cancellato non finiscono dentro. È la stessa
//! proprietà di WL-02, e qui conta di più: una copia che portasse con sé
//! materiale cancellato lo porterebbe **anche fuori dalla postazione**.
//!
//! # Che cosa questo modulo non fa
//!
//! Non ripristina. Scrivere una copia non può danneggiare nulla; **sovrascrivere
//! un archivio con uno più vecchio è la cosa più distruttiva che questo prodotto
//! potrebbe fare**, e non è un pulsante (ADR-0043).

use std::path::Path;

use crate::Database;
use crate::error::{StorageError, StorageResult};

/// Che cosa è stato prodotto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupOutcome {
    /// Quanto pesa la copia, in byte.
    pub bytes: u64,
    /// Se la copia risulta integra alla rilettura.
    ///
    /// # Perché si rilegge
    ///
    /// Una copia di sicurezza che nessuno ha mai aperto è una speranza, non una
    /// copia. Riaprirla costa una frazione del tempo che è costato scriverla, e
    /// distingue «il comando è riuscito» da «esiste un archivio utilizzabile».
    pub verified: bool,
}

impl Database {
    /// Scrive una copia coerente dell'archivio nel percorso indicato.
    ///
    /// # Perché rifiuta un file che esiste già
    ///
    /// `VACUUM INTO` fallisce da sé se la destinazione esiste, e questo modulo
    /// **non** aggira quel comportamento: sovrascrivere una copia di sicurezza
    /// precedente significa distruggerla, e chi lo vuole deve dirlo togliendo il
    /// file, non ottenerlo per distrazione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il percorso non è utilizzabile, se il file
    /// esiste già, se lo spazio non basta, o se la copia scritta non si rilegge.
    pub fn backup_to(&self, destination: &Path) -> StorageResult<BackupOutcome> {
        if destination.exists() {
            return Err(StorageError::CorruptedRow {
                detail: "la destinazione della copia esiste già: toglierla prima, \
                         perché sovrascriverla significherebbe distruggerla",
            });
        }

        // Il percorso entra in una istruzione SQL, e un percorso e' testo di cui
        // non ci si fida: gli apici si raddoppiano, come per qualunque
        // letterale. Non e' teorico — una cartella puo' contenere un apice.
        let Some(percorso) = destination.to_str() else {
            return Err(StorageError::CorruptedRow {
                detail: "il percorso della copia non è rappresentabile in testo",
            });
        };
        let protetto = percorso.replace('\'', "''");

        self.connection
            .execute_batch(&format!("VACUUM INTO '{protetto}'"))?;

        let bytes = std::fs::metadata(destination)
            .map(|dati| dati.len())
            .unwrap_or(0);

        // Si riapre la copia appena scritta e le si chiede se e' integra. Una
        // copia che nessuno ha mai aperto e' una speranza, non una copia.
        let verified = Self::open(destination)
            .and_then(|copia| copia.verify_integrity())
            .is_ok_and(|rapporto| rapporto.is_healthy());

        Ok(BackupOutcome { bytes, verified })
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{database_with_session, new_content};

    /// **La copia contiene davvero i dati, e si riapre.**
    #[test]
    fn la_copia_si_riapre_e_contiene_cio_che_c_era() {
        let (mut database, source_id, session_id) = database_with_session();
        for numero in 0..5_u32 {
            let contenuto = new_content(
                session_id,
                source_id,
                &format!("m-{numero}"),
                "testo di prova",
            );
            let Ok(_) = database.insert_content(&contenuto) else {
                panic!("il contenuto di prova deve potersi registrare");
            };
        }

        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let copia = cartella.path().join("archivio-copia.sqlite3");

        let Ok(esito) = database.backup_to(&copia) else {
            panic!("la copia deve potersi scrivere");
        };
        assert!(esito.bytes > 0);
        assert!(
            esito.verified,
            "una copia che non si rilegge integra e' una speranza, non una copia"
        );

        let Ok(riaperta) = crate::Database::open(&copia) else {
            panic!("la copia deve potersi riaprire");
        };
        let quanti: i64 = riaperta
            .connection
            .query_row("SELECT count(*) FROM contents", [], |row| row.get(0))
            .expect("il conteggio deve riuscire");
        assert_eq!(
            quanti, 5,
            "la copia non contiene i contenuti dell'originale"
        );
    }

    /// **La copia non sovrascrive una copia precedente.**
    ///
    /// Sovrascrivere una copia di sicurezza significa distruggerla, e chi lo
    /// vuole deve dirlo togliendo il file — non ottenerlo per distrazione.
    #[test]
    fn una_copia_non_ne_distrugge_un_altra() {
        let (database, _, _) = database_with_session();
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let copia = cartella.path().join("copia.sqlite3");

        let Ok(_) = database.backup_to(&copia) else {
            panic!("la prima copia deve potersi scrivere");
        };
        assert!(
            database.backup_to(&copia).is_err(),
            "la seconda copia ha sovrascritto la prima"
        );
    }

    /// **La copia non porta con se' cio' che era stato cancellato.**
    ///
    /// Una copia di sicurezza che portasse con se' materiale cancellato lo
    /// porterebbe anche FUORI dalla postazione, dove il prodotto non ha piu'
    /// alcuna difesa.
    #[test]
    fn la_copia_non_porta_fuori_cio_che_era_stato_cancellato() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let percorso = cartella.path().join("originale.sqlite3");

        let segreto = "PAROLA-CHE-NON-DEVE-USCIRE-1234567890";
        {
            let Ok(mut database) = crate::Database::open(&percorso) else {
                panic!("l'archivio di prova deve potersi aprire");
            };
            let Ok(source_id) = database.insert_source(
                &crate::test_support::new_source("canale_uno"),
                crate::test_support::now(),
            ) else {
                panic!("la fonte deve potersi registrare");
            };
            let Ok(session_id) = database.insert_session(
                &crate::test_support::new_session(vec![source_id]),
                crate::test_support::now(),
            ) else {
                panic!("la sessione deve potersi creare");
            };

            // Materiale abbondante, cosi' che le pagine liberate siano molte.
            let corpo = format!("{segreto} {}", "x".repeat(2_000));
            for numero in 0..200_u32 {
                let contenuto = new_content(session_id, source_id, &format!("m-{numero}"), &corpo);
                let Ok(_) = database.insert_content(&contenuto) else {
                    panic!("il contenuto di prova deve potersi registrare");
                };
            }

            // Si cancella tutto, SENZA compattare: le pagine restano libere e i
            // byte restano nel file.
            let Ok(_) = database.connection.execute("DELETE FROM contents", []) else {
                panic!("la cancellazione deve riuscire");
            };
        }

        let originale = std::fs::read(&percorso).expect("l'originale deve potersi leggere");
        let dentro_originale = originale
            .windows(segreto.len())
            .any(|finestra| finestra == segreto.as_bytes());
        assert!(
            dentro_originale,
            "la premessa della prova non regge: nell'originale il testo cancellato \
             doveva restare leggibile, altrimenti non si sta misurando nulla"
        );

        let copia = cartella.path().join("copia.sqlite3");
        {
            let Ok(database) = crate::Database::open(&percorso) else {
                panic!("l'archivio deve potersi riaprire");
            };
            let Ok(_) = database.backup_to(&copia) else {
                panic!("la copia deve potersi scrivere");
            };
        }

        let byte = std::fs::read(&copia).expect("la copia deve potersi leggere");
        let dentro_copia = byte
            .windows(segreto.len())
            .any(|finestra| finestra == segreto.as_bytes());
        assert!(
            !dentro_copia,
            "la copia porta fuori dalla postazione del materiale che era stato \
             cancellato"
        );
    }

    /// **Un percorso con un apice non rompe l'istruzione.**
    ///
    /// Non e' teorico: una cartella d'ufficio puo' chiamarsi «Relazioni d'ufficio».
    #[test]
    fn un_percorso_con_un_apice_non_rompe_nulla() {
        let (database, _, _) = database_with_session();
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let con_apice = cartella.path().join("copie d'ufficio");
        let Ok(()) = std::fs::create_dir_all(&con_apice) else {
            panic!("la cartella con l'apice deve potersi creare");
        };

        let copia = con_apice.join("archivio.sqlite3");
        let Ok(esito) = database.backup_to(&copia) else {
            panic!("un apice nel percorso non deve impedire la copia");
        };
        assert!(esito.verified);
    }
}

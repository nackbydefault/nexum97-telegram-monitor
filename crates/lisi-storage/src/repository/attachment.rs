//! La descrizione dell'allegato di un contenuto (ATTACH-01, ADR-0177,
//! migrazione 0075).
//!
//! Il genere e ciò che il mittente dichiara, scritti una volta: una seconda
//! scrittura per lo stesso contenuto non cambia niente, perché una ripresa
//! della coda rilegge lo stesso messaggio e la descrizione è la stessa. Nessun
//! byte: l'allegato non si scarica all'acquisizione.

use lisi_core::ContentId;
use rusqlite::OptionalExtension;

use crate::Database;
use crate::error::StorageResult;

/// La descrizione di un allegato, come l'archivio la conserva.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentAttachment {
    /// La chiave del genere (`documento`, `foto`, …).
    pub kind: String,
    /// Il nome dichiarato, già ripulito dal connettore.
    pub declared_name: Option<String>,
    /// La dimensione dichiarata, in byte.
    pub declared_size: Option<u64>,
    /// Il tipo dichiarato, già ripulito dal connettore.
    pub declared_mime: Option<String>,
}

impl Database {
    /// Registra la descrizione dell'allegato di un contenuto. Se ce n'è già
    /// una, resta quella: la descrizione non cambia.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo schema rifiuta la riga (un genere che non
    /// esiste, un nome vuoto o troppo lungo, un tipo malformato) o se la
    /// scrittura non riesce.
    pub fn record_content_attachment(
        &self,
        content_id: ContentId,
        allegato: &ContentAttachment,
    ) -> StorageResult<()> {
        // Una dimensione oltre il massimo di SQLite non è una dimensione che
        // si possa credere: si conserva come non dichiarata.
        let dimensione = allegato
            .declared_size
            .and_then(|byte| i64::try_from(byte).ok());
        self.connection.execute(
            "INSERT INTO content_attachments (content_id, kind, declared_name, declared_size,
                 declared_mime)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (content_id) DO NOTHING",
            rusqlite::params![
                content_id.get(),
                allegato.kind,
                allegato.declared_name,
                dimensione,
                allegato.declared_mime,
            ],
        )?;
        Ok(())
    }

    /// La descrizione dell'allegato di un contenuto, se ne ha uno.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn content_attachment(
        &self,
        content_id: ContentId,
    ) -> StorageResult<Option<ContentAttachment>> {
        Ok(self
            .connection
            .query_row(
                "SELECT kind, declared_name, declared_size, declared_mime
                 FROM content_attachments WHERE content_id = ?1",
                [content_id.get()],
                |row| {
                    Ok(ContentAttachment {
                        kind: row.get(0)?,
                        declared_name: row.get(1)?,
                        declared_size: row
                            .get::<_, Option<i64>>(2)?
                            .and_then(|byte| u64::try_from(byte).ok()),
                        declared_mime: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }
}

#[cfg(test)]
mod tests {
    use super::ContentAttachment;
    use crate::test_support::{database_with_session, new_content};

    fn documento() -> ContentAttachment {
        ContentAttachment {
            kind: String::from("documento"),
            declared_name: Some(String::from("rapporto.pdf")),
            declared_size: Some(73_728),
            declared_mime: Some(String::from("application/pdf")),
        }
    }

    /// **La descrizione si scrive una volta, si rilegge com'è, e una seconda
    /// scrittura non la cambia**: una ripresa della coda non la riscrive.
    #[test]
    fn la_descrizione_si_scrive_una_volta() {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(inserito) =
            database.insert_content(&new_content(session_id, source_id, "7", "guarda"))
        else {
            panic!("il contenuto di prova deve registrarsi");
        };
        let contenuto = inserito.content_id();
        assert_eq!(database.content_attachment(contenuto).ok(), Some(None));

        let Ok(()) = database.record_content_attachment(contenuto, &documento()) else {
            panic!("la descrizione deve registrarsi");
        };
        let diverso = ContentAttachment {
            kind: String::from("foto"),
            declared_name: None,
            declared_size: None,
            declared_mime: None,
        };
        let Ok(()) = database.record_content_attachment(contenuto, &diverso) else {
            panic!("una seconda scrittura non è un errore");
        };
        assert_eq!(
            database.content_attachment(contenuto).ok(),
            Some(Some(documento()))
        );
    }

    /// **Lo schema rifiuta un genere che non esiste, un nome vuoto e un tipo
    /// malformato** (prova negativa).
    #[test]
    fn lo_schema_rifiuta_una_descrizione_malformata() {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(inserito) =
            database.insert_content(&new_content(session_id, source_id, "8", "guarda"))
        else {
            panic!("il contenuto di prova deve registrarsi");
        };
        let contenuto = inserito.content_id();
        for sbagliata in [
            ContentAttachment {
                kind: String::from("eseguibile"),
                ..documento()
            },
            ContentAttachment {
                declared_name: Some(String::from("   ")),
                ..documento()
            },
            ContentAttachment {
                declared_mime: Some(String::from("pdf")),
                ..documento()
            },
        ] {
            assert!(
                database
                    .record_content_attachment(contenuto, &sbagliata)
                    .is_err(),
                "{sbagliata:?} va rifiutata"
            );
        }
        assert_eq!(database.content_attachment(contenuto).ok(), Some(None));
    }
}

//! Ciò che l'ufficio scrive insieme, dal lato dell'Hub (TEAM-WS-01,
//! ADR-0099).
//!
//! # Le regole che non si possono dimenticare stanno nell'archivio
//!
//! Una nota condivisa non si riscrive, non si cancella, un ritiro non si
//! annulla, una nota vuota non si scrive, un raccoglitore chiuso non accetta
//! elementi. Sono vincoli e trigger della migrazione 0050, e valgono anche per
//! chi scrivesse un secondo servizio domani.
//!
//! Qui sta ciò che un archivio non può fare: comporre i tipi del dominio e
//! tradurre un rifiuto in qualcosa che chi chiama può spiegare.

use core::str::FromStr;

use lisi_core::model::hub_notes::{
    SharedNote, SharedWorkspace, SharedWorkspaceItem, SharedWorkspaceState,
};
use lisi_core::model::hub_person::PersonId;
use lisi_core::model::reference::{ArchiveRef, ArchiveRefKind};
use lisi_core::text::{DisplayName, Note};
use lisi_core::{NoteId, Timestamp};
use rusqlite::{OptionalExtension, params};

use crate::database::Database;
use crate::error::{StorageError, StorageResult};
use crate::repository::millis;

/// Una nota condivisa da scrivere.
#[derive(Debug)]
pub struct NewSharedNote<'dati> {
    /// Su che cosa.
    pub about: ArchiveRef,
    /// Le parole.
    pub body: &'dati Note,
    /// Chi la scrive.
    pub author: &'dati PersonId,
    /// Quando.
    pub written_at: Timestamp,
}

impl Database {
    /// Scrive una nota dell'ufficio.
    ///
    /// # Errori
    ///
    /// Un errore di scrittura, o il rifiuto di un vincolo.
    pub fn insert_hub_note(&self, note: &NewSharedNote<'_>) -> StorageResult<NoteId> {
        let id: i64 = self
            .connection
            .query_row(
                "INSERT INTO hub_notes (kind, target_id, body, author, written_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 RETURNING id",
                params![
                    note.about.kind().as_str(),
                    note.about.target_id(),
                    note.body.as_str(),
                    note.author.as_str(),
                    millis(note.written_at),
                ],
                |row| row.get(0),
            )
            .map_err(StorageError::Sqlite)?;
        Ok(NoteId::new(id))
    }

    /// Ritira una nota dell'ufficio.
    ///
    /// **Non la cancella e non ne cambia il testo.**
    ///
    /// # Errori
    ///
    /// [`StorageError::NotFound`] se la nota non esiste, o il rifiuto del
    /// trigger se era già ritirata.
    pub fn withdraw_hub_note(
        &self,
        id: NoteId,
        by: &PersonId,
        now: Timestamp,
    ) -> StorageResult<()> {
        let cambiate = self
            .connection
            .execute(
                "UPDATE hub_notes SET withdrawn_by = ?2, withdrawn_at = ?3 WHERE id = ?1",
                params![id.get(), by.as_str(), millis(now)],
            )
            .map_err(StorageError::Sqlite)?;
        if cambiate == 0 {
            return Err(StorageError::NotFound {
                entity: "nota condivisa",
                id: id.get(),
            });
        }
        Ok(())
    }

    /// Le note dell'ufficio su qualcosa, dalla più recente.
    ///
    /// Comprende **anche quelle ritirate**: chi le aveva lette deve poter
    /// capire che cosa è successo a ciò che aveva letto.
    ///
    /// # Errori
    ///
    /// Un errore di lettura, o se una riga conservata non è interpretabile.
    pub fn hub_notes_about(
        &self,
        about: ArchiveRef,
        limit: usize,
    ) -> StorageResult<Vec<SharedNote>> {
        let mut statement = self.connection.prepare(
            "SELECT id, kind, target_id, body, author, written_at, withdrawn_by, withdrawn_at
               FROM hub_notes WHERE kind = ?1 AND target_id = ?2
              ORDER BY id DESC LIMIT ?3",
        )?;
        let righe = statement.query_map(
            params![
                about.kind().as_str(),
                about.target_id(),
                i64::try_from(limit).unwrap_or(i64::MAX)
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                ))
            },
        )?;

        let mut note = Vec::new();
        for riga in righe {
            let (id, genere, bersaglio, corpo, autore, scritta, ritirata_da, ritirata_il) = riga?;
            note.push(SharedNote {
                id: NoteId::new(id),
                about: ArchiveRef::to(ArchiveRefKind::from_str(&genere)?, bersaglio)?,
                body: Note::try_new(&corpo)?,
                author: PersonId::parse(&autore)?,
                written_at: Timestamp::from_millis(scritta),
                withdrawn: match (ritirata_da, ritirata_il) {
                    (Some(chi), Some(quando)) => {
                        Some((PersonId::parse(&chi)?, Timestamp::from_millis(quando)))
                    }
                    _ => None,
                },
            });
        }
        Ok(note)
    }

    /// Una nota dell'ufficio, se esiste.
    ///
    /// # Errori
    ///
    /// Un errore di lettura, o se la riga conservata non è interpretabile.
    pub fn hub_note(&self, id: NoteId) -> StorageResult<Option<SharedNote>> {
        let riga = self
            .connection
            .query_row(
                "SELECT kind, target_id, body, author, written_at, withdrawn_by, withdrawn_at
                   FROM hub_notes WHERE id = ?1",
                params![id.get()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(StorageError::Sqlite)?;

        let Some((genere, bersaglio, corpo, autore, scritta, ritirata_da, ritirata_il)) = riga
        else {
            return Ok(None);
        };
        Ok(Some(SharedNote {
            id,
            about: ArchiveRef::to(ArchiveRefKind::from_str(&genere)?, bersaglio)?,
            body: Note::try_new(&corpo)?,
            author: PersonId::parse(&autore)?,
            written_at: Timestamp::from_millis(scritta),
            withdrawn: match (ritirata_da, ritirata_il) {
                (Some(chi), Some(quando)) => {
                    Some((PersonId::parse(&chi)?, Timestamp::from_millis(quando)))
                }
                _ => None,
            },
        }))
    }

    /// Apre un raccoglitore dell'ufficio.
    ///
    /// # Errori
    ///
    /// Un errore di scrittura, o il rifiuto dell'indice unico se un
    /// raccoglitore **aperto** ha già quel nome.
    pub fn insert_hub_workspace(
        &self,
        name: &DisplayName,
        description: Option<&Note>,
        opened_by: &PersonId,
        now: Timestamp,
    ) -> StorageResult<i64> {
        self.connection
            .query_row(
                "INSERT INTO hub_workspaces (name, description, state, opened_by, opened_at)
                 VALUES (?1, ?2, 'aperto', ?3, ?4)
                 RETURNING id",
                params![
                    name.as_str(),
                    description.map(Note::as_str),
                    opened_by.as_str(),
                    millis(now)
                ],
                |row| row.get(0),
            )
            .map_err(StorageError::Sqlite)
    }

    /// Chiude un raccoglitore. **Non cancella niente.**
    ///
    /// # Errori
    ///
    /// [`StorageError::NotFound`] se il raccoglitore non esiste o era già
    /// chiuso: in entrambi i casi non c'è nulla da chiudere.
    pub fn close_hub_workspace(&self, id: i64, by: &PersonId, now: Timestamp) -> StorageResult<()> {
        let cambiate = self
            .connection
            .execute(
                "UPDATE hub_workspaces SET state = 'chiuso', closed_by = ?2, closed_at = ?3
                  WHERE id = ?1 AND state = 'aperto'",
                params![id, by.as_str(), millis(now)],
            )
            .map_err(StorageError::Sqlite)?;
        if cambiate == 0 {
            return Err(StorageError::NotFound {
                entity: "raccoglitore condiviso aperto",
                id,
            });
        }
        Ok(())
    }

    /// I raccoglitori dell'ufficio, dal più recente.
    ///
    /// # Errori
    ///
    /// Un errore di lettura, o se una riga conservata non è interpretabile.
    pub fn hub_workspaces(&self, limit: usize) -> StorageResult<Vec<SharedWorkspace>> {
        let mut statement = self.connection.prepare(
            "SELECT id, name, description, state, opened_by, opened_at,
                    (SELECT COUNT(*) FROM hub_workspace_items
                      WHERE hub_workspace_items.workspace_id = hub_workspaces.id)
               FROM hub_workspaces ORDER BY id DESC LIMIT ?1",
        )?;
        let righe =
            statement.query_map(params![i64::try_from(limit).unwrap_or(i64::MAX)], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })?;

        let mut raccoglitori = Vec::new();
        for riga in righe {
            let (id, nome, descrizione, stato, aperto_da, aperto_il, quanti) = riga?;
            raccoglitori.push(SharedWorkspace {
                id,
                name: DisplayName::try_new(&nome)?,
                description: descrizione.as_deref().map(Note::try_new).transpose()?,
                state: SharedWorkspaceState::parse(&stato)?,
                opened_by: PersonId::parse(&aperto_da)?,
                opened_at: Timestamp::from_millis(aperto_il),
                items: usize::try_from(quanti).unwrap_or_default(),
            });
        }
        Ok(raccoglitori)
    }

    /// Raccoglie un riferimento in un raccoglitore.
    ///
    /// # Errori
    ///
    /// Il rifiuto del trigger se il raccoglitore è chiuso, o un errore di
    /// scrittura.
    pub fn add_hub_workspace_item(
        &self,
        workspace_id: i64,
        item: ArchiveRef,
        added_by: &PersonId,
        now: Timestamp,
    ) -> StorageResult<()> {
        self.connection
            .execute(
                "INSERT OR IGNORE INTO hub_workspace_items
                    (workspace_id, kind, target_id, added_by, added_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    workspace_id,
                    item.kind().as_str(),
                    item.target_id(),
                    added_by.as_str(),
                    millis(now)
                ],
            )
            .map_err(StorageError::Sqlite)?;
        Ok(())
    }

    /// Toglie un riferimento da un raccoglitore.
    ///
    /// # Errori
    ///
    /// Un errore di scrittura.
    pub fn remove_hub_workspace_item(
        &self,
        workspace_id: i64,
        item: ArchiveRef,
    ) -> StorageResult<()> {
        self.connection
            .execute(
                "DELETE FROM hub_workspace_items
                  WHERE workspace_id = ?1 AND kind = ?2 AND target_id = ?3",
                params![workspace_id, item.kind().as_str(), item.target_id()],
            )
            .map_err(StorageError::Sqlite)?;
        Ok(())
    }

    /// Ciò che un raccoglitore ha raccolto.
    ///
    /// # Errori
    ///
    /// Un errore di lettura, o se una riga conservata non è interpretabile.
    pub fn hub_workspace_items(
        &self,
        workspace_id: i64,
        limit: usize,
    ) -> StorageResult<Vec<SharedWorkspaceItem>> {
        let mut statement = self.connection.prepare(
            "SELECT kind, target_id, added_by, added_at
               FROM hub_workspace_items WHERE workspace_id = ?1
              ORDER BY added_at ASC, target_id ASC LIMIT ?2",
        )?;
        let righe = statement.query_map(
            params![workspace_id, i64::try_from(limit).unwrap_or(i64::MAX)],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )?;

        let mut elementi = Vec::new();
        for riga in righe {
            let (genere, bersaglio, chi, quando) = riga?;
            elementi.push(SharedWorkspaceItem {
                item: ArchiveRef::to(ArchiveRefKind::from_str(&genere)?, bersaglio)?,
                added_by: PersonId::parse(&chi)?,
                added_at: Timestamp::from_millis(quando),
            });
        }
        Ok(elementi)
    }

    /// Se un raccoglitore accetta ancora elementi.
    ///
    /// # Errori
    ///
    /// Un errore di lettura.
    pub fn hub_workspace_accepts_items(&self, workspace_id: i64) -> StorageResult<bool> {
        let stato: Option<String> = self
            .connection
            .query_row(
                "SELECT state FROM hub_workspaces WHERE id = ?1",
                params![workspace_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(StorageError::Sqlite)?;
        Ok(stato.as_deref() == Some(SharedWorkspaceState::Open.as_str()))
    }
}

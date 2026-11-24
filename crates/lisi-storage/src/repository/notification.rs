//! Notifiche emesse.
//!
//! La registrazione serve alla deduplica: una notifica per contenuto, imposta
//! dal vincolo unico dello schema e non da un controllo applicativo.

use core::str::FromStr;

use lisi_core::model::{EmittedNotification, NewNotification, NotificationPrivacy};
use lisi_core::{ContentId, NotificationId, SessionId};
use rusqlite::{OptionalExtension, Row};

use crate::database::Database;
use crate::error::{ConstraintKind, StorageError, StorageResult, constraint_kind};
use crate::repository::{instant, millis};

fn read(row: &Row<'_>) -> StorageResult<EmittedNotification> {
    let privacy = NotificationPrivacy::from_str(&row.get::<_, String>(3)?)?;
    let level = u8::try_from(row.get::<_, i64>(4)?).unwrap_or(0);

    Ok(EmittedNotification {
        id: NotificationId::new(row.get(0)?),
        content_id: ContentId::new(row.get(1)?),
        session_id: SessionId::new(row.get(2)?),
        privacy,
        level,
        emitted_at: instant(row.get(5)?),
    })
}

impl Database {
    /// Registra una notifica emessa, in modo idempotente.
    ///
    /// Se una notifica per quel contenuto esiste già, non ne inserisce una
    /// seconda e restituisce `None`: la stessa segnalazione non si notifica due
    /// volte, e il vincolo unico lo rende impossibile per costruzione.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se il contenuto non esiste, o un
    /// errore se la scrittura non riesce.
    pub fn insert_notification(
        &self,
        notification: &NewNotification,
    ) -> StorageResult<Option<NotificationId>> {
        let inserted: Option<i64> = self
            .connection
            .query_row(
                "INSERT INTO notifications (
                     content_id, session_id, privacy, level, emitted_at, recovered
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (content_id) DO NOTHING
                 RETURNING id",
                rusqlite::params![
                    notification.content_id.get(),
                    notification.session_id.get(),
                    notification.privacy.as_str(),
                    i64::from(notification.level),
                    millis(notification.emitted_at),
                    i64::from(notification.recovered),
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| {
                if constraint_kind(&error) == Some(ConstraintKind::ForeignKey) {
                    StorageError::NotFound {
                        entity: "contenuto",
                        id: notification.content_id.get(),
                    }
                } else {
                    StorageError::Sqlite(error)
                }
            })?;

        Ok(inserted.map(NotificationId::new))
    }

    /// Se un contenuto è già stato notificato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn notification_exists(&self, content_id: ContentId) -> StorageResult<bool> {
        let count: i64 = self.connection.query_row(
            "SELECT count(*) FROM notifications WHERE content_id = ?1",
            [content_id.get()],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Notifica emessa per un contenuto, se ce n'è una.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn content_notification(
        &self,
        content_id: ContentId,
    ) -> StorageResult<Option<EmittedNotification>> {
        self.connection
            .query_row(
                "SELECT id, content_id, session_id, privacy, level, emitted_at
                 FROM notifications WHERE content_id = ?1",
                [content_id.get()],
                |row| Ok(read(row)),
            )
            .optional()?
            .transpose()
    }

    /// Tutte le notifiche emesse, dalla più recente alla più vecchia.
    ///
    /// È l'elenco del centro notifiche. L'ordine è cronologico inverso: la
    /// notifica più recente è quella che l'operatore vuole vedere per prima.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se un valore conservato
    /// non è interpretabile (database alterato).
    pub fn emitted_notifications(&self) -> StorageResult<Vec<EmittedNotification>> {
        let mut statement = self.connection.prepare(
            "SELECT id, content_id, session_id, privacy, level, emitted_at
             FROM notifications
             ORDER BY emitted_at DESC, id DESC",
        )?;

        let rows = statement.query_map([], |row| Ok(read(row)))?;

        let mut notifications = Vec::new();
        for row in rows {
            notifications.push(row??);
        }
        Ok(notifications)
    }

    /// Numero di notifiche emesse per una sessione.
    ///
    /// Serve al limite: oltre un tetto, le nuove segnalazioni restano nello
    /// storico ma non producono altre notifiche, per non sommergere il sistema.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    /// I contenuti recuperati dallo storico con un avviso di almeno quel
    /// livello e nessuna notifica, i più vecchi prima, al più `limit`
    /// (NOTIFY-BACKFILL-01, ADR-0188).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn recovered_contents_to_notify(
        &self,
        minimum_level: u8,
        limit: usize,
    ) -> StorageResult<Vec<ContentId>> {
        let mut richiesta = self.connection.prepare(
            "SELECT c.id
             FROM contents AS c
             JOIN alerts AS a ON a.content_id = c.id
             LEFT JOIN notifications AS n ON n.content_id = c.id
             WHERE c.acquisition_origin = 'recuperato'
               AND n.id IS NULL
               AND a.level >= ?1
             ORDER BY c.id
             LIMIT ?2",
        )?;
        let righe = richiesta.query_map(
            rusqlite::params![
                i64::from(minimum_level),
                i64::try_from(limit).unwrap_or(i64::MAX)
            ],
            |row| row.get::<_, i64>(0),
        )?;
        let mut trovati = Vec::new();
        for riga in righe {
            trovati.push(ContentId::new(riga?));
        }
        Ok(trovati)
    }

    pub fn session_notification_count(&self, session_id: SessionId) -> StorageResult<usize> {
        let count: i64 = self.connection.query_row(
            // I recuperati non contano: si annunciano con un avviso solo, e un
            // recupero grande non deve togliere posto agli avvisi dal vivo
            // (NOTIFY-BACKFILL-01, ADR-0188, decisione 4).
            "SELECT count(*) FROM notifications WHERE session_id = ?1 AND recovered = 0",
            [session_id.get()],
            |row| row.get(0),
        )?;
        Ok(usize::try_from(count).unwrap_or(usize::MAX))
    }
}

/// Una notifica cyber già emessa, come si rilegge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmittedCyberNotification {
    /// La sessione in cui il grappolo si è formato.
    pub session_id: SessionId,
    /// Il genere dell'indicatore che tiene insieme il grappolo.
    pub indicator_kind: String,
    /// Il valore normalizzato dell'indicatore.
    pub indicator_value: String,
    /// Quanti contenuti aveva il grappolo quando è stato annunciato.
    pub contents_at_emission: usize,
    /// Da quante fonti distinte.
    pub distinct_sources_at_emission: usize,
    /// Con quale riservatezza è stato annunciato.
    pub privacy: NotificationPrivacy,
    /// Quando.
    pub emitted_at: lisi_core::Timestamp,
}

/// Una notifica cyber che si intende registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCyberNotification {
    /// La sessione in cui il grappolo si è formato.
    pub session_id: SessionId,
    /// Il genere dell'indicatore.
    pub indicator_kind: String,
    /// Il valore normalizzato.
    pub indicator_value: String,
    /// Quanti contenuti ha il grappolo adesso.
    pub contents: usize,
    /// Da quante fonti distinte.
    pub distinct_sources: usize,
    /// Con quale riservatezza si annuncia.
    pub privacy: NotificationPrivacy,
    /// Quando.
    pub emitted_at: lisi_core::Timestamp,
}

impl Database {
    /// Registra una notifica cyber, se quel grappolo non è già stato annunciato.
    ///
    /// # Perché il risultato è un `Option` e non un `bool`
    ///
    /// È lo stesso meccanismo delle notifiche ordinarie: la **registrazione è
    /// la deduplica**, e il vincolo unico dello schema è ciò che la impone. Una
    /// lettura seguita da una scrittura lascia una finestra fra le due, e in
    /// quella finestra due valutazioni possono decidere entrambe di annunciare.
    ///
    /// Chi chiama legge l'esito dell'inserimento: `None` significa «qualcun
    /// altro lo ha già annunciato», e allora non si emette nulla.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se la sessione non esiste, e un
    /// errore se la scrittura non riesce.
    pub fn insert_cyber_notification(
        &self,
        notification: &NewCyberNotification,
    ) -> StorageResult<Option<i64>> {
        let inserted: Option<i64> = self
            .connection
            .query_row(
                "INSERT INTO cyber_notifications (
                     session_id, indicator_kind, indicator_value,
                     contents_at_emission, distinct_sources_at_emission,
                     privacy, emitted_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT (session_id, indicator_kind, indicator_value) DO NOTHING
                 RETURNING id",
                rusqlite::params![
                    notification.session_id.get(),
                    notification.indicator_kind.as_str(),
                    notification.indicator_value.as_str(),
                    i64::try_from(notification.contents).unwrap_or(i64::MAX),
                    i64::try_from(notification.distinct_sources).unwrap_or(i64::MAX),
                    notification.privacy.as_str(),
                    millis(notification.emitted_at),
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| {
                if constraint_kind(&error) == Some(ConstraintKind::ForeignKey) {
                    StorageError::NotFound {
                        entity: "sessione",
                        id: notification.session_id.get(),
                    }
                } else {
                    StorageError::Sqlite(error)
                }
            })?;

        Ok(inserted)
    }

    /// Se quel grappolo è già stato annunciato in quella sessione.
    ///
    /// Evita di comporre un avviso che verrebbe comunque scartato. **Non è la
    /// garanzia**: quella è il vincolo unico, letto dall'esito
    /// dell'inserimento.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn cyber_notification_exists(
        &self,
        session_id: SessionId,
        kind: &str,
        value: &str,
    ) -> StorageResult<bool> {
        let count: i64 = self.connection.query_row(
            "SELECT count(*) FROM cyber_notifications
             WHERE session_id = ?1 AND indicator_kind = ?2 AND indicator_value = ?3",
            rusqlite::params![session_id.get(), kind, value],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Le notifiche cyber emesse per una sessione, dalla più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga porta una
    /// riservatezza che il dominio non conosce.
    pub fn cyber_notifications(
        &self,
        session_id: SessionId,
    ) -> StorageResult<Vec<EmittedCyberNotification>> {
        let mut statement = self.connection.prepare(
            "SELECT session_id, indicator_kind, indicator_value,
                    contents_at_emission, distinct_sources_at_emission,
                    privacy, emitted_at
             FROM cyber_notifications
             WHERE session_id = ?1
             ORDER BY emitted_at DESC, id DESC",
        )?;
        let righe = statement.query_map([session_id.get()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?;

        let mut trovate = Vec::new();
        for riga in righe {
            let (session, kind, value, contents, sources, privacy, emitted) = riga?;
            trovate.push(EmittedCyberNotification {
                session_id: SessionId::new(session),
                indicator_kind: kind,
                indicator_value: value,
                contents_at_emission: usize::try_from(contents).unwrap_or(0),
                distinct_sources_at_emission: usize::try_from(sources).unwrap_or(0),
                privacy: NotificationPrivacy::from_str(&privacy)?,
                emitted_at: instant(emitted),
            });
        }
        Ok(trovate)
    }
}

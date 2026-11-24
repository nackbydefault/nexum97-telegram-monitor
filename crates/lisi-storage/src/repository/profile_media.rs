//! Foto, biografia e stato di un autore, osservati su richiesta
//! (PERSON-MEDIA-01, ADR-0174, migrazione 0073).
//!
//! Una riga per richiesta, con la riga d'audit nella stessa transazione. Lo
//! schema impedisce di riscriverla e di cancellarla. L'impronta della foto la
//! calcola questo modulo dai byte che riceve: chi scrive non può dichiararne
//! una diversa.

use lisi_core::model::NewAuditEntry;
use lisi_core::{SessionId, Sha256Digest, Timestamp};
use rusqlite::{OptionalExtension, Row};

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// Un'osservazione da registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewProfileMediaObservation {
    /// Il monitoraggio in cui l'autore è stato osservato.
    pub session_id: SessionId,
    /// L'identificativo numerico dell'autore su Telegram.
    pub author_identifier: String,
    /// L'account d'ufficio che ha letto, se il monitoraggio ne ha uno.
    pub account_uuid: Option<String>,
    /// Chi ha chiesto.
    pub requested_by: String,
    /// Perché.
    pub reason: String,
    /// Quando.
    pub requested_at: Timestamp,
    /// `osservato`, `rifiutato` o `non_riuscito`.
    pub outcome: String,
    /// Il perché di un rifiuto o di una richiesta non riuscita.
    pub outcome_detail: Option<String>,
    /// La biografia, se restituita.
    pub bio: Option<String>,
    /// La chiave dello stato, se restituito.
    pub status: Option<String>,
    /// L'ultimo accesso, quando lo stato lo porta.
    pub status_was_online: Option<Timestamp>,
    /// I byte della foto, non decodificati.
    pub photo: Option<Vec<u8>>,
    /// Perché la foto manca, quando l'account ne ha una che non si è letta.
    pub photo_not_read: Option<String>,
}

/// Un'osservazione registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredProfileMediaObservation {
    /// La riga.
    pub id: i64,
    /// Il monitoraggio.
    pub session_id: SessionId,
    /// L'autore.
    pub author_identifier: String,
    /// L'account d'ufficio che ha letto.
    pub account_uuid: Option<String>,
    /// Chi ha chiesto.
    pub requested_by: String,
    /// Perché.
    pub reason: String,
    /// Quando.
    pub requested_at: Timestamp,
    /// L'esito.
    pub outcome: String,
    /// Il perché di un esito che non è un'osservazione.
    pub outcome_detail: Option<String>,
    /// La biografia.
    pub bio: Option<String>,
    /// La chiave dello stato.
    pub status: Option<String>,
    /// L'ultimo accesso.
    pub status_was_online: Option<Timestamp>,
    /// I byte della foto.
    pub photo: Option<Vec<u8>>,
    /// L'impronta SHA-256 della foto, in esadecimale.
    pub photo_sha256: Option<String>,
    /// Perché la foto manca.
    pub photo_not_read: Option<String>,
}

impl StoredProfileMediaObservation {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            session_id: SessionId::new(row.get(1)?),
            author_identifier: row.get(2)?,
            account_uuid: row.get(3)?,
            requested_by: row.get(4)?,
            reason: row.get(5)?,
            requested_at: instant(row.get(6)?),
            outcome: row.get(7)?,
            outcome_detail: row.get(8)?,
            bio: row.get(9)?,
            status: row.get(10)?,
            status_was_online: row.get::<_, Option<i64>>(11)?.map(instant),
            photo: row.get(12)?,
            photo_sha256: row.get(13)?,
            photo_not_read: row.get(14)?,
        })
    }
}

impl Database {
    /// Registra un'osservazione con la sua riga d'audit, nella stessa
    /// transazione: o entrambe, o nessuna.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo schema rifiuta la riga o se la scrittura
    /// non riesce.
    pub fn insert_profile_media_observation(
        &mut self,
        osservazione: &NewProfileMediaObservation,
        audit: &NewAuditEntry,
    ) -> StorageResult<i64> {
        let impronta = osservazione
            .photo
            .as_deref()
            .map(|byte| Sha256Digest::of_bytes(byte).as_str().to_owned());
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO profile_media_observations (
                 session_id, author_identifier, account_uuid, requested_by, reason,
                 requested_at, outcome, outcome_detail, bio, status, status_was_online,
                 photo, photo_sha256, photo_not_read
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            rusqlite::params![
                osservazione.session_id.get(),
                osservazione.author_identifier,
                osservazione.account_uuid,
                osservazione.requested_by,
                osservazione.reason,
                millis(osservazione.requested_at),
                osservazione.outcome,
                osservazione.outcome_detail,
                osservazione.bio,
                osservazione.status,
                osservazione.status_was_online.map(millis),
                osservazione.photo,
                impronta,
                osservazione.photo_not_read,
            ],
        )?;
        let id = transazione.last_insert_rowid();
        transazione.execute(
            "INSERT INTO audit (actor, action, entity, entity_id, detail, recorded_at, actor_mode)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                audit.actor.as_str(),
                audit.action.as_str(),
                audit.entity.as_str(),
                Some(id),
                audit
                    .detail
                    .as_ref()
                    .map(|dettaglio| dettaglio.as_str().to_owned()),
                millis(audit.recorded_at),
                audit.actor_mode.map(|modo| modo.as_str()),
            ],
        )?;
        transazione.commit()?;
        Ok(id)
    }

    /// Le osservazioni di un autore in un monitoraggio, dalla più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn profile_media_observations(
        &self,
        session_id: SessionId,
        author_identifier: &str,
    ) -> StorageResult<Vec<StoredProfileMediaObservation>> {
        let mut statement = self.connection.prepare(
            "SELECT id, session_id, author_identifier, account_uuid, requested_by, reason,
                    requested_at, outcome, outcome_detail, bio, status, status_was_online,
                    photo, photo_sha256, photo_not_read
             FROM profile_media_observations
             WHERE session_id = ?1 AND author_identifier = ?2
             ORDER BY requested_at DESC, id DESC",
        )?;
        let righe = statement.query_map(
            rusqlite::params![session_id.get(), author_identifier],
            StoredProfileMediaObservation::read,
        )?;
        let mut osservazioni = Vec::new();
        for riga in righe {
            osservazioni.push(riga?);
        }
        Ok(osservazioni)
    }

    /// Un'osservazione, se esiste.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn profile_media_observation(
        &self,
        id: i64,
    ) -> StorageResult<Option<StoredProfileMediaObservation>> {
        let mut statement = self.connection.prepare(
            "SELECT id, session_id, author_identifier, account_uuid, requested_by, reason,
                    requested_at, outcome, outcome_detail, bio, status, status_was_online,
                    photo, photo_sha256, photo_not_read
             FROM profile_media_observations WHERE id = ?1",
        )?;
        let mut righe = statement.query_map([id], StoredProfileMediaObservation::read)?;
        Ok(righe.next().transpose()?)
    }

    /// Registra la scelta, o il suo contrario, di riportare un'osservazione
    /// nei documenti (PERSON-MEDIA-01 parte 3, migrazione 0074), con la riga
    /// d'audit nella stessa transazione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo schema rifiuta la riga o se la scrittura
    /// non riesce.
    pub fn insert_profile_media_mark(
        &mut self,
        observation_id: i64,
        chosen: bool,
        marked_by: &str,
        at: Timestamp,
        audit: &NewAuditEntry,
    ) -> StorageResult<()> {
        let transazione = self.connection.transaction()?;
        transazione.execute(
            "INSERT INTO profile_media_report_marks (observation_id, chosen, marked_by, marked_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![observation_id, i64::from(chosen), marked_by, millis(at)],
        )?;
        transazione.execute(
            "INSERT INTO audit (actor, action, entity, entity_id, detail, recorded_at, actor_mode)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                audit.actor.as_str(),
                audit.action.as_str(),
                audit.entity.as_str(),
                Some(observation_id),
                audit
                    .detail
                    .as_ref()
                    .map(|dettaglio| dettaglio.as_str().to_owned()),
                millis(audit.recorded_at),
                audit.actor_mode.map(|modo| modo.as_str()),
            ],
        )?;
        transazione.commit()?;
        Ok(())
    }

    /// Se l'osservazione è scelta per i documenti: l'ultima scelta registrata;
    /// nessuna vuol dire no.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn profile_media_chosen(&self, observation_id: i64) -> StorageResult<bool> {
        let ultima: Option<i64> = self
            .connection
            .query_row(
                "SELECT chosen FROM profile_media_report_marks WHERE observation_id = ?1
                 ORDER BY id DESC LIMIT 1",
                [observation_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(ultima == Some(1))
    }

    /// Le osservazioni di un monitoraggio scelte per i documenti, dalla più
    /// vecchia.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn chosen_profile_media_for_session(
        &self,
        session_id: SessionId,
    ) -> StorageResult<Vec<StoredProfileMediaObservation>> {
        let mut statement = self.connection.prepare(
            "SELECT id, session_id, author_identifier, account_uuid, requested_by, reason,
                    requested_at, outcome, outcome_detail, bio, status, status_was_online,
                    photo, photo_sha256, photo_not_read
             FROM profile_media_observations o
             WHERE session_id = ?1
               AND (SELECT chosen FROM profile_media_report_marks m
                    WHERE m.observation_id = o.id ORDER BY m.id DESC LIMIT 1) = 1
             ORDER BY requested_at, id",
        )?;
        let righe = statement.query_map([session_id.get()], StoredProfileMediaObservation::read)?;
        let mut scelte = Vec::new();
        for riga in righe {
            scelte.push(riga?);
        }
        Ok(scelte)
    }

    /// L'istante dell'ultima richiesta registrata sulla postazione, se ce n'è
    /// una: il servizio non ne accetta un'altra troppo presto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn last_profile_media_request_at(&self) -> StorageResult<Option<Timestamp>> {
        let ultimo: Option<i64> = self.connection.query_row(
            "SELECT max(requested_at) FROM profile_media_observations",
            [],
            |row| row.get(0),
        )?;
        Ok(ultimo.map(instant))
    }

    /// Se l'autore ha scritto almeno un contenuto acquisito in quel
    /// monitoraggio (ADR-0174, decisione 1): una richiesta parte soltanto da un
    /// autore già osservato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn author_observed_in_session(
        &self,
        session_id: SessionId,
        author_identifier: &str,
    ) -> StorageResult<bool> {
        let trovato: i64 = self.connection.query_row(
            "SELECT EXISTS (SELECT 1 FROM contents
                            WHERE session_id = ?1 AND author_identifier = ?2)",
            rusqlite::params![session_id.get(), author_identifier],
            |row| row.get(0),
        )?;
        Ok(trovato == 1)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::NewAuditEntry;
    use lisi_core::text::{AuditAction, AuditDetail, AuditEntity};

    use super::NewProfileMediaObservation;
    use crate::test_support::{actor, database_with_session, later, new_content};

    fn audit(quando: i64) -> NewAuditEntry {
        let (Ok(action), Ok(entity), Ok(detail)) = (
            AuditAction::try_new("profilo_osservato"),
            AuditEntity::try_new("profilo"),
            AuditDetail::try_new("prova"),
        ) else {
            panic!("valori d'audit validi");
        };
        NewAuditEntry {
            actor: actor("operatore.prova"),
            action,
            entity,
            entity_id: None,
            detail: Some(detail),
            recorded_at: later(quando),
            actor_mode: None,
        }
    }

    fn osservazione(
        session_id: lisi_core::SessionId,
        quando: i64,
        foto: Option<Vec<u8>>,
    ) -> NewProfileMediaObservation {
        NewProfileMediaObservation {
            session_id,
            author_identifier: String::from("42"),
            account_uuid: None,
            requested_by: String::from("operatore.prova"),
            reason: String::from("Verifica dell'autore del messaggio di minaccia"),
            requested_at: later(quando),
            outcome: String::from("osservato"),
            outcome_detail: None,
            bio: Some(String::from("Cronista")),
            status: Some(String::from("di_recente")),
            status_was_online: None,
            photo: foto,
            photo_not_read: None,
        }
    }

    /// **Due richieste sono due osservazioni, con l'impronta calcolata qui e
    /// la riga d'audit nella stessa transazione** (PERSON-MEDIA-01).
    #[test]
    fn due_richieste_sono_due_osservazioni_e_l_impronta_si_calcola_qui() {
        let (mut database, _, sessione) = database_with_session();
        let foto = vec![0xff_u8, 0xd8, 0xff, 0xe0];
        let Ok(prima) = database.insert_profile_media_observation(
            &osservazione(sessione, 1, Some(foto.clone())),
            &audit(1),
        ) else {
            panic!("la prima osservazione si registra");
        };
        let Ok(seconda) =
            database.insert_profile_media_observation(&osservazione(sessione, 2, None), &audit(2))
        else {
            panic!("la seconda osservazione si registra");
        };
        let Ok(lette) = database.profile_media_observations(sessione, "42") else {
            panic!("le osservazioni si leggono");
        };
        assert_eq!(
            lette.iter().map(|o| o.id).collect::<Vec<_>>(),
            vec![seconda, prima],
            "dalla più recente, e la prima resta"
        );
        assert_eq!(
            lette.last().and_then(|o| o.photo_sha256.clone()),
            Some(lisi_core::Sha256Digest::of_bytes(&foto).as_str().to_owned())
        );
        let Ok(audit) = database.audit_entries() else {
            panic!("l'audit si legge");
        };
        assert_eq!(
            audit
                .iter()
                .filter(|voce| voce.action.as_str() == "profilo_osservato")
                .count(),
            2
        );
    }

    /// **Un autore è osservato soltanto se ha scritto nel monitoraggio**
    /// (ADR-0174, decisione 1).
    #[test]
    fn un_autore_e_osservato_soltanto_se_ha_scritto_nel_monitoraggio() {
        let (mut database, fonte, sessione) = database_with_session();
        let mut contenuto = new_content(sessione, fonte, "1", "un messaggio");
        contenuto.author_identifier = Some(String::from("42"));
        let Ok(_) = database.insert_content(&contenuto) else {
            panic!("il contenuto di prova si registra");
        };
        assert_eq!(
            database.author_observed_in_session(sessione, "42").ok(),
            Some(true)
        );
        assert_eq!(
            database.author_observed_in_session(sessione, "43").ok(),
            Some(false),
            "un autore che non ha scritto non è osservato"
        );
    }

    /// **Vale l'ultima scelta, e la storia resta** (PERSON-MEDIA-01 parte 3):
    /// scelta, tolta, scelta di nuovo; soltanto le scelte entrano
    /// nell'elenco per i documenti. Prova negativa: un'osservazione mai scelta
    /// non c'è.
    #[test]
    fn vale_l_ultima_scelta_e_la_storia_resta() {
        let (mut database, _, sessione) = database_with_session();
        let Ok(prima) =
            database.insert_profile_media_observation(&osservazione(sessione, 1, None), &audit(1))
        else {
            panic!("la prima osservazione si registra");
        };
        let Ok(seconda) =
            database.insert_profile_media_observation(&osservazione(sessione, 2, None), &audit(2))
        else {
            panic!("la seconda osservazione si registra");
        };
        assert_eq!(database.profile_media_chosen(prima).ok(), Some(false));
        fn segna(database: &mut crate::Database, prima: i64, scelta: bool, quando: i64) {
            let Ok(()) = database.insert_profile_media_mark(
                prima,
                scelta,
                "operatore.prova",
                later(quando),
                &audit(quando),
            ) else {
                panic!("la scelta si registra");
            };
        }
        segna(&mut database, prima, true, 3);
        segna(&mut database, prima, false, 4);
        assert_eq!(
            database.profile_media_chosen(prima).ok(),
            Some(false),
            "tolta dopo la scelta: vale il ritiro"
        );
        assert_eq!(
            database
                .chosen_profile_media_for_session(sessione)
                .map(|scelte| scelte.len())
                .ok(),
            Some(0)
        );
        segna(&mut database, prima, true, 5);
        assert_eq!(database.profile_media_chosen(prima).ok(), Some(true));
        let Ok(scelte) = database.chosen_profile_media_for_session(sessione) else {
            panic!("le scelte si leggono");
        };
        assert_eq!(
            scelte.iter().map(|o| o.id).collect::<Vec<_>>(),
            vec![prima],
            "la seconda, mai scelta, non c'è"
        );
        assert_ne!(prima, seconda);
        let Ok(Some(letta)) = database.profile_media_observation(prima) else {
            panic!("l'osservazione si rilegge");
        };
        assert_eq!(letta.id, prima);
        assert_eq!(database.profile_media_observation(9_999).ok(), Some(None));
    }
}

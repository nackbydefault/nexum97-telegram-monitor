//! Contenuti acquisiti.
//!
//! Ogni contenuto acquisito e analizzato viene registrato, anche quando il
//! livello è 0 e non genera alcun alert. Lo storico documenta ciò che è stato
//! osservato, e un archivio che conservasse solo gli allarmi non permetterebbe
//! di dimostrare che cosa è stato visto e giudicato non rilevante.

use lisi_core::digest::Sha256Digest;
use lisi_core::model::{AnalysisLevel, Content, ContentInsertion, NewContent};
use lisi_core::text::{Actor, ContentBody, ContentUrl, RemoteMessageId};
use lisi_core::{ContentId, SessionId, SourceId, Timestamp};
use rusqlite::{OptionalExtension, Row, Transaction};

use crate::database::Database;
use crate::error::{ConstraintKind, StorageError, StorageResult, constraint_kind};
use crate::repository::{instant, millis};

/// Riga grezza della tabella `contents`.
struct ContentRow {
    id: i64,
    session_id: i64,
    source_id: i64,
    remote_message_id: String,
    author: Option<String>,
    author_identifier: Option<String>,
    author_username: Option<String>,
    body: String,
    url: Option<String>,
    published_at: i64,
    acquired_at: i64,
    acquisition_origin: String,
    analysis_level: i64,
    body_sha256: String,
    duplicate_of_id: Option<i64>,
    engine_version: Option<i64>,
}

impl ContentRow {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            session_id: row.get(1)?,
            source_id: row.get(2)?,
            remote_message_id: row.get(3)?,
            author: row.get(4)?,
            author_identifier: row.get(5)?,
            author_username: row.get(6)?,
            body: row.get(7)?,
            url: row.get(8)?,
            published_at: row.get(9)?,
            acquired_at: row.get(10)?,
            acquisition_origin: row.get(11)?,
            analysis_level: row.get(12)?,
            body_sha256: row.get(13)?,
            duplicate_of_id: row.get(14)?,
            engine_version: row.get(15)?,
        })
    }

    fn into_domain(self) -> StorageResult<Content> {
        let author = match self.author {
            Some(ref raw) => Some(Actor::try_new(raw)?),
            None => None,
        };
        let url = match self.url {
            Some(ref raw) => Some(ContentUrl::try_new(raw)?),
            None => None,
        };
        let level = u8::try_from(self.analysis_level)
            .map_err(|_| lisi_core::DomainError::InvalidAnalysisLevel(u8::MAX))?;

        Ok(Content {
            id: ContentId::new(self.id),
            session_id: SessionId::new(self.session_id),
            source_id: SourceId::new(self.source_id),
            remote_message_id: RemoteMessageId::try_new(&self.remote_message_id)?,
            author,
            author_identifier: self.author_identifier,
            author_username: self.author_username,
            body: ContentBody::try_new(&self.body)?,
            url,
            published_at: instant(self.published_at),
            acquired_at: instant(self.acquired_at),
            // Un valore non riconoscibile è un **errore**, non un ripiego
            // silenzioso su «osservato»: leggere «osservato» da una riga che
            // dice altro sarebbe l'archivio che afferma di aver visto ciò che
            // non sa se ha visto. Lo schema lo vincola già; questa è la seconda
            // rete, e le due si controllano a vicenda.
            origin: self.acquisition_origin.parse()?,
            analysis_level: AnalysisLevel::try_new(level)?,
            body_sha256: Sha256Digest::from_hex(&self.body_sha256)?,
            duplicate_of_id: self.duplicate_of_id.map(ContentId::new),
            engine_version: self
                .engine_version
                .and_then(|valore| u32::try_from(valore).ok()),
        })
    }
}

impl Database {
    /// Registra un contenuto acquisito.
    ///
    /// L'operazione avviene in una transazione: l'impronta del corpo viene
    /// calcolata, la prima occorrenza dello stesso corpo viene cercata e il
    /// contenuto viene inserito con il collegamento all'eventuale duplicato.
    ///
    /// Il ritentativo di acquisizione dello stesso messaggio nella stessa
    /// sessione **non è un errore**: restituisce
    /// [`ContentInsertion::AlreadyPresent`] con l'identificatore già assegnato.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::SourceNotSelectedForSession`] se la fonte non
    /// era fra quelle selezionate per la sessione. Il vincolo è nello schema:
    /// non dipende da un controllo che questo metodo potrebbe dimenticare.
    pub fn insert_content(&mut self, content: &NewContent) -> StorageResult<ContentInsertion> {
        let digest = content.body_digest();
        let transaction = self.connection.transaction()?;

        let duplicate_of_id =
            first_occurrence(&transaction, &digest, content.session_id, content.source_id)?;

        let inserted: Option<i64> = transaction
            .query_row(
                // LA VERSIONE DEL MOTORE LA SCRIVE QUESTA FUNZIONE, e non chi
                // la chiama (ENGINE-01).
                //
                // Se fosse un campo di `NewContent`, esisterebbe un modo di
                // registrare un contenuto senza la versione — o con quella
                // sbagliata — e prima o poi qualcuno lo troverebbe. Qui non
                // c'e' nulla da ricordare: chi analizza e' il motore di questo
                // binario, e questa e' la sua versione.
                "INSERT INTO contents (
                     session_id, source_id, remote_message_id, author, author_identifier,
                     author_username, body, url, published_at, acquired_at,
                     acquisition_origin, analysis_level, body_sha256, duplicate_of_id,
                     engine_version
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
                 ON CONFLICT (session_id, source_id, remote_message_id) DO NOTHING
                 RETURNING id",
                rusqlite::params![
                    content.session_id.get(),
                    content.source_id.get(),
                    content.remote_message_id.as_str(),
                    content.author.as_ref().map(Actor::as_str),
                    content.author_identifier.as_deref(),
                    content.author_username.as_deref(),
                    content.body.as_str(),
                    content.url.as_ref().map(ContentUrl::as_str),
                    millis(content.published_at),
                    millis(content.acquired_at),
                    content.origin.as_str(),
                    i64::from(content.analysis_level.get()),
                    digest.as_str(),
                    duplicate_of_id,
                    i64::from(lisi_core::analysis::ENGINE_VERSION),
                ],
                |row| row.get(0),
            )
            // `DO NOTHING` non inserisce nulla e `RETURNING` non produce righe:
            // è il caso del contenuto già acquisito, che non è un errore.
            .optional()
            .map_err(|error| {
                if constraint_kind(&error) == Some(ConstraintKind::ForeignKey) {
                    StorageError::SourceNotSelectedForSession
                } else {
                    StorageError::Sqlite(error)
                }
            })?;

        let insertion = match inserted {
            Some(id) => ContentInsertion::Recorded(ContentId::new(id)),
            None => {
                let existing: i64 = transaction.query_row(
                    "SELECT id FROM contents
                     WHERE session_id = ?1 AND source_id = ?2 AND remote_message_id = ?3",
                    rusqlite::params![
                        content.session_id.get(),
                        content.source_id.get(),
                        content.remote_message_id.as_str(),
                    ],
                    |row| row.get(0),
                )?;
                ContentInsertion::AlreadyPresent(ContentId::new(existing))
            }
        };

        transaction.commit()?;
        Ok(insertion)
    }

    /// Legge un contenuto.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se il contenuto non esiste.
    pub fn content(&self, id: ContentId) -> StorageResult<Content> {
        let row = self
            .connection
            .query_row(
                "SELECT id, session_id, source_id, remote_message_id, author, author_identifier, author_username, body, url,
                        published_at, acquired_at, acquisition_origin, analysis_level,
                        body_sha256, duplicate_of_id, engine_version
                 FROM contents
                 WHERE id = ?1",
                [id.get()],
                ContentRow::read,
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound {
                    entity: "contenuto",
                    id: id.get(),
                },
                other => StorageError::Sqlite(other),
            })?;

        row.into_domain()
    }

    /// Dove un identificativo d'autore è comparso, in tutti i monitoraggi
    /// (NEXUM97-IDENTITY-02, ADR-0153, decisione 8): contenuto, monitoraggio e
    /// il suo nome, nome e username annunciati, istante di pubblicazione.
    ///
    /// **Non legge il testo dei messaggi**: i nomi osservati non ne hanno
    /// bisogno, e una lettura che non lo prende non può mostrarlo. Al più
    /// `limite` righe, dalla più antica.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn author_sightings(
        &self,
        identifier: &str,
        limite: u32,
    ) -> StorageResult<Vec<AuthorSighting>> {
        let mut statement = self.connection.prepare(
            "SELECT c.id, c.session_id, s.label, c.author, c.author_username, c.published_at
             FROM contents c JOIN sessions s ON s.id = c.session_id
             WHERE c.author_identifier = ?1
             ORDER BY c.published_at, c.id
             LIMIT ?2",
        )?;
        let righe = statement.query_map(rusqlite::params![identifier, limite], |row| {
            Ok(AuthorSighting {
                content: ContentId::new(row.get(0)?),
                session: SessionId::new(row.get(1)?),
                session_label: row.get(2)?,
                display_name: row.get(3)?,
                username: row.get(4)?,
                published_at: instant(row.get(5)?),
            })
        })?;
        let mut avvistamenti = Vec::new();
        for riga in righe {
            avvistamenti.push(riga?);
        }
        Ok(avvistamenti)
    }

    /// Elenca i contenuti di una sessione, in ordine di acquisizione.
    ///
    /// L'elenco comprende i contenuti di ogni livello, compreso lo 0.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// valore non conforme al dominio.
    pub fn session_contents(&self, session_id: SessionId) -> StorageResult<Vec<Content>> {
        let mut statement = self.connection.prepare(
            "SELECT id, session_id, source_id, remote_message_id, author, author_identifier, author_username, body, url,
                    published_at, acquired_at, acquisition_origin, analysis_level,
                    body_sha256, duplicate_of_id, engine_version
             FROM contents
             WHERE session_id = ?1
             ORDER BY acquired_at, id",
        )?;

        let rows = statement.query_map([session_id.get()], ContentRow::read)?;

        let mut contents = Vec::new();
        for row in rows {
            contents.push(row?.into_domain()?);
        }
        Ok(contents)
    }

    /// Quanti contenuti sono stati **acquisiti** dopo l'istante indicato.
    ///
    /// # Perché l'acquisizione e non la pubblicazione
    ///
    /// Perché la domanda è «che cosa ha fatto questa postazione», non «che cosa
    /// è stato detto nel mondo». Il recupero della cronologia acquisisce
    /// contenuti pubblicati mesi fa: contarli per data di pubblicazione
    /// mostrerebbe una giornata vuota subito dopo un recupero riuscito.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn contents_acquired_since(&self, instant: Timestamp) -> StorageResult<u64> {
        let quanti: i64 = self.connection.query_row(
            "SELECT count(*) FROM contents WHERE acquired_at >= ?1",
            [millis(instant)],
            |row| row.get(0),
        )?;
        Ok(u64::try_from(quanti).unwrap_or(0))
    }

    /// Il corpo e il livello registrato dei contenuti di una sessione.
    ///
    /// # A che cosa serve, e perché non restituisce `Content`
    ///
    /// Serve al Rule Lab, che confronta due configurazioni di dizionario su
    /// contenuti **già archiviati**. Gli servono tre cose per contenuto — chi
    /// è, che cosa dice, e che livello gli fu attribuito — e nient'altro:
    /// restituire l'intero `Content` porterebbe nel laboratorio l'autore, la
    /// fonte, l'URL e gli istanti, cioè materiale che il confronto non guarda e
    /// che qualcuno potrebbe finire per mostrare.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn session_bodies(
        &self,
        session_id: SessionId,
        limit: u32,
    ) -> StorageResult<Vec<(ContentId, String, u8)>> {
        let mut statement = self.connection.prepare(
            "SELECT id, body, analysis_level
             FROM contents
             WHERE session_id = ?1
             ORDER BY acquired_at, id
             LIMIT ?2",
        )?;

        let rows = statement.query_map(rusqlite::params![session_id.get(), limit], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;

        let mut contenuti = Vec::new();
        for row in rows {
            let (id, body, level) = row?;
            contenuti.push((ContentId::new(id), body, u8::try_from(level).unwrap_or(0)));
        }
        Ok(contenuti)
    }

    /// Le sessioni che hanno acquisito qualcosa dopo l'istante indicato.
    ///
    /// Serve a chi deve comporre qualcosa di **caro** — la correlazione dei
    /// grappoli, per esempio — solo dove c'è stata attività: il costo cresce
    /// così con ciò che è successo, non con la storia dell'ufficio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn sessions_active_since(&self, instant: Timestamp) -> StorageResult<Vec<SessionId>> {
        let mut statement = self.connection.prepare(
            "SELECT DISTINCT session_id FROM contents WHERE acquired_at >= ?1 ORDER BY session_id",
        )?;

        let rows = statement.query_map([millis(instant)], |row| row.get::<_, i64>(0))?;

        let mut sessioni = Vec::new();
        for row in rows {
            sessioni.push(SessionId::new(row?));
        }
        Ok(sessioni)
    }
}

/// Prima occorrenza dello stesso corpo in una sessione diversa.
///
/// La deduplicazione è per sessione: la ripetizione fra sessioni distinte viene
/// annotata e lasciata alla valutazione dell'operatore, non soppressa.
fn first_occurrence(
    transaction: &Transaction<'_>,
    digest: &Sha256Digest,
    session_id: SessionId,
    source_id: SourceId,
) -> StorageResult<Option<i64>> {
    // LA FONTE ENTRA NEL CONFRONTO, ED E' MULTI-02 A METTERCELA.
    //
    // Fino a qui la regola era «stesso corpo, sessione diversa», CIECA ALLA
    // FONTE. Con un monitoraggio solo non si vedeva; con piu' monitoraggi
    // (ADR-0065) produceva due comportamenti che nessuno aveva scelto:
    //
    //   - lo stesso testo pubblicato da DUE CANALI DIVERSI veniva annotato come
    //     duplicato, se i monitoraggi erano due;
    //   - lo stesso testo pubblicato da due canali diversi dentro LO STESSO
    //     monitoraggio non veniva annotato.
    //
    // Cioe' la stessa coppia di fatti riceveva o non riceveva l'annotazione a
    // seconda di come erano stati divisi i monitoraggi. E il primo dei due era
    // FALSO NEL MERITO: un testo inoltrato in due canali e' DUE PUBBLICAZIONI
    // di due fonti, e il prodotto lo afferma gia' altrove — la chiave di
    // idempotenza contiene la fonte e ne fa due eventi.
    //
    // L'annotazione serve a dire UNA cosa sola: questa riga c'e' due volte
    // perche' DUE MONITORAGGI GUARDANO LA STESSA FONTE. Perciò: stesso corpo,
    // stessa fonte, monitoraggio diverso (DEC-300).
    let existing: Option<i64> = transaction
        .query_row(
            "SELECT id FROM contents
             WHERE body_sha256 = ?1 AND source_id = ?2 AND session_id <> ?3
             ORDER BY id
             LIMIT 1",
            rusqlite::params![digest.as_str(), source_id.get(), session_id.get()],
            |row| row.get(0),
        )
        .optional()?;

    Ok(existing)
}

/// Un'osservazione di un autore, per i nomi osservati (ADR-0153).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorSighting {
    /// Quale contenuto.
    pub content: ContentId,
    /// In quale monitoraggio.
    pub session: SessionId,
    /// Il nome del monitoraggio, per chi legge.
    pub session_label: String,
    /// Il nome annunciato allora, se c'era.
    pub display_name: Option<String>,
    /// Lo username annunciato allora, se c'era.
    pub username: Option<String>,
    /// Quando il contenuto è stato pubblicato.
    pub published_at: Timestamp,
}
#[cfg(test)]
mod tests {
    use lisi_core::model::AcquisitionOrigin;
    use lisi_core::model::{ContentInsertion, NewSession, SessionDuration};
    use lisi_core::{ContentId, SourceId};

    use crate::error::StorageError;
    use crate::test_support::{
        actor, database, database_with_session, display_name, level, new_content, new_session,
        new_source, now,
    };

    /// **Ogni contenuto registrato porta la versione del motore.**
    ///
    /// # Perché la scrive la persistenza e non chi la chiama
    ///
    /// Perché se fosse un campo di `NewContent` esisterebbe un modo di
    /// registrare un contenuto senza la versione — o con quella sbagliata — e
    /// prima o poi qualcuno lo troverebbe. Qui non c'è nulla da ricordare.
    #[test]
    fn every_recorded_content_carries_the_engine_version() {
        let (mut database, source_id, session_id) = database_with_session();
        let content = new_content(session_id, source_id, "77", "un messaggio");

        let Ok(insertion) = database.insert_content(&content) else {
            panic!("il contenuto deve potersi registrare");
        };
        let Ok(stored) = database.content(insertion.content_id()) else {
            panic!("il contenuto deve potersi rileggere");
        };

        assert_eq!(
            stored.engine_version,
            Some(lisi_core::analysis::ENGINE_VERSION),
            "un contenuto registrato adesso e' stato analizzato dal motore di adesso"
        );
    }

    /// **La migrazione non attribuisce una versione ai contenuti di prima.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// I contenuti già archiviati furono analizzati da un motore di cui non si
    /// sa quale fosse. Scrivere loro accanto la versione corrente sarebbe
    /// comodo e falso: direbbe che qualcuno lo sa.
    #[test]
    fn the_migration_leaves_older_contents_without_an_engine_version() {
        let (mut database, source_id, session_id) = database_with_session();
        let content = new_content(session_id, source_id, "13", "prima di ENGINE-01");
        let Ok(insertion) = database.insert_content(&content) else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = insertion.content_id();

        // Si simula un contenuto di prima: la colonna torna a NULL, come la
        // migrazione l'ha lasciata sui contenuti gia' presenti.
        let Ok(_) = database.connection.execute(
            "UPDATE contents SET engine_version = NULL WHERE id = ?1",
            [content_id.get()],
        ) else {
            panic!("la preparazione deve riuscire");
        };

        let Ok(stored) = database.content(content_id) else {
            panic!("il contenuto deve potersi rileggere");
        };
        assert_eq!(
            stored.engine_version, None,
            "«non registrato» non deve diventare «la versione corrente»"
        );
    }

    #[test]
    fn a_content_is_written_and_read_back_unchanged() {
        let (mut database, source_id, session_id) = database_with_session();
        let content = new_content(session_id, source_id, "42", "primo messaggio");

        let Ok(insertion) = database.insert_content(&content) else {
            panic!("il contenuto deve potersi registrare");
        };
        assert!(insertion.is_new());

        let Ok(stored) = database.content(insertion.content_id()) else {
            panic!("il contenuto deve potersi rileggere");
        };
        assert_eq!(stored.session_id, session_id);
        assert_eq!(stored.source_id, source_id);
        assert_eq!(stored.remote_message_id, content.remote_message_id);
        assert_eq!(stored.body, content.body);
        assert_eq!(stored.published_at, content.published_at);
        assert_eq!(stored.acquired_at, content.acquired_at);
        assert_eq!(stored.analysis_level, content.analysis_level);
        assert_eq!(stored.body_sha256, content.body_digest());
        assert_eq!(stored.duplicate_of_id, None);
    }

    #[test]
    fn the_author_identifier_survives_the_round_trip() {
        let (mut database, source_id, session_id) = database_with_session();
        let mut content = new_content(session_id, source_id, "1", "messaggio");
        content.author_identifier = Some(String::from("1234567890"));

        let Ok(insertion) = database.insert_content(&content) else {
            panic!("il contenuto deve potersi registrare");
        };

        let Ok(stored) = database.content(insertion.content_id()) else {
            panic!("il contenuto deve potersi rileggere");
        };
        assert_eq!(stored.author_identifier.as_deref(), Some("1234567890"));

        let Ok(contents) = database.session_contents(session_id) else {
            panic!("lo storico deve potersi leggere");
        };
        assert_eq!(contents[0].author_identifier.as_deref(), Some("1234567890"));
    }

    #[test]
    fn what_was_recovered_is_stored_as_recovered_and_not_as_observed() {
        let (mut database, source_id, session_id) = database_with_session();
        let mut content = new_content(session_id, source_id, "1", "messaggio ritrovato");
        content.origin = AcquisitionOrigin::Recovered;

        let Ok(insertion) = database.insert_content(&content) else {
            panic!("il contenuto deve potersi registrare");
        };
        let Ok(stored) = database.content(insertion.content_id()) else {
            panic!("il contenuto deve potersi rileggere");
        };

        assert_eq!(stored.origin, AcquisitionOrigin::Recovered);
        assert!(
            !stored.origin.was_witnessed(),
            "l'archivio non deve affermare di aver osservato cio' che ha ritrovato"
        );
    }

    /// **Un recuperato non sostituisce ciò che era già in archivio** (PR-07,
    /// controllo negativo 2). La coda lo ferma prima, con la chiave di
    /// idempotenza; questa è la seconda difesa, e si prova da sola.
    #[test]
    fn a_recovered_copy_does_not_replace_what_was_already_stored() {
        let (mut database, source_id, session_id) = database_with_session();
        let osservato = new_content(session_id, source_id, "1", "testo di allora");
        let Ok(prima) = database.insert_content(&osservato) else {
            panic!("il contenuto deve potersi registrare");
        };

        let mut recuperato = new_content(session_id, source_id, "1", "testo di oggi");
        recuperato.origin = AcquisitionOrigin::Recovered;
        let Ok(seconda) = database.insert_content(&recuperato) else {
            panic!("un doppione non è un errore");
        };
        assert!(
            matches!(seconda, ContentInsertion::AlreadyPresent(id) if id == prima.content_id()),
            "il doppione deve risultare già presente"
        );

        let Ok(stored) = database.content(prima.content_id()) else {
            panic!("il contenuto deve potersi rileggere");
        };
        assert_eq!(stored.body.as_str(), "testo di allora");
        assert_eq!(stored.origin, AcquisitionOrigin::Observed);
    }

    #[test]
    fn a_content_from_the_live_path_reads_back_as_the_live_path() {
        // La colonna registra il PERCORSO da cui la riga e' entrata, e si
        // rilegge com'e' stata scritta. Che cosa quel percorso DIMOSTRI e'
        // un'altra domanda, e la risponde il criterio del modo di acquisizione
        // (PR-07, ADR-0123): fino a PR-07 questa prova diceva che «osservato»
        // per valore predefinito era il valore vero, ed e' proprio la premessa
        // che ADR-0123 ha verificato e respinto.
        let (mut database, source_id, session_id) = database_with_session();
        let content = new_content(session_id, source_id, "1", "messaggio");
        assert_eq!(content.origin, AcquisitionOrigin::Observed);

        let Ok(insertion) = database.insert_content(&content) else {
            panic!("il contenuto deve potersi registrare");
        };
        let Ok(stored) = database.content(insertion.content_id()) else {
            panic!("il contenuto deve potersi rileggere");
        };
        assert_eq!(stored.origin, AcquisitionOrigin::Observed);
        assert!(stored.origin.was_witnessed());
    }

    #[test]
    fn a_channel_message_is_stored_without_an_author_identifier() {
        let (mut database, source_id, session_id) = database_with_session();
        let content = new_content(session_id, source_id, "1", "messaggio di canale");
        assert_eq!(content.author_identifier, None);

        let Ok(insertion) = database.insert_content(&content) else {
            panic!("il contenuto deve potersi registrare");
        };

        let Ok(stored) = database.content(insertion.content_id()) else {
            panic!("il contenuto deve potersi rileggere");
        };
        // Assente, non stringa vuota: chi legge deve distinguere «nessun autore
        // individuale» da «autore con identificativo vuoto».
        assert_eq!(stored.author_identifier, None);
    }

    #[test]
    fn a_content_of_level_zero_is_recorded_like_any_other() {
        let (mut database, source_id, session_id) = database_with_session();
        let content = new_content(session_id, source_id, "1", "messaggio irrilevante");
        assert_eq!(content.analysis_level.get(), 0);

        let Ok(insertion) = database.insert_content(&content) else {
            panic!("il contenuto di livello 0 deve essere registrato");
        };

        let Ok(contents) = database.session_contents(session_id) else {
            panic!("lo storico deve potersi leggere");
        };
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0].id, insertion.content_id());
        assert_eq!(contents[0].analysis_level.get(), 0);
    }

    #[test]
    fn every_analysed_level_is_recorded() {
        let (mut database, source_id, session_id) = database_with_session();

        for value in 0..=4 {
            let mut content = new_content(session_id, source_id, &format!("m{value}"), "messaggio");
            content.analysis_level = level(value);
            let Ok(_) = database.insert_content(&content) else {
                panic!("il contenuto di livello {value} deve essere registrato");
            };
        }

        let Ok(contents) = database.session_contents(session_id) else {
            panic!("lo storico deve potersi leggere");
        };
        assert_eq!(contents.len(), 5);
    }

    #[test]
    fn acquiring_the_same_message_twice_does_not_create_a_second_row() {
        let (mut database, source_id, session_id) = database_with_session();
        let content = new_content(session_id, source_id, "42", "messaggio");

        let (Ok(first), Ok(second)) = (
            database.insert_content(&content),
            database.insert_content(&content),
        ) else {
            panic!("il ritentativo non deve essere un errore");
        };

        assert!(first.is_new());
        assert!(!second.is_new());
        assert_eq!(first.content_id(), second.content_id());
        assert!(matches!(second, ContentInsertion::AlreadyPresent(_)));

        let Ok(contents) = database.session_contents(session_id) else {
            panic!("lo storico deve potersi leggere");
        };
        assert_eq!(contents.len(), 1);
    }

    #[test]
    fn a_retry_does_not_overwrite_what_was_already_recorded() {
        let (mut database, source_id, session_id) = database_with_session();
        let first = new_content(session_id, source_id, "42", "testo originale");
        let Ok(recorded) = database.insert_content(&first) else {
            panic!("la prima acquisizione deve riuscire");
        };

        let mut altered = new_content(session_id, source_id, "42", "testo alterato");
        altered.analysis_level = level(4);
        let Ok(retry) = database.insert_content(&altered) else {
            panic!("il ritentativo non deve essere un errore");
        };
        assert!(!retry.is_new());

        let Ok(stored) = database.content(recorded.content_id()) else {
            panic!("il contenuto deve potersi rileggere");
        };
        assert_eq!(stored.body.as_str(), "testo originale");
        assert_eq!(stored.analysis_level.get(), 0);
    }

    #[test]
    fn a_content_cannot_be_linked_to_a_source_not_selected_for_the_session() {
        let (mut database, _selected, session_id) = database_with_session();
        let Ok(other) = database.insert_source(&new_source("canale_non_selezionato"), now()) else {
            panic!("la seconda fonte deve potersi registrare");
        };

        let content = new_content(session_id, other, "1", "messaggio");
        assert!(matches!(
            database.insert_content(&content),
            Err(StorageError::SourceNotSelectedForSession)
        ));

        let Ok(contents) = database.session_contents(session_id) else {
            panic!("lo storico deve potersi leggere");
        };
        assert!(contents.is_empty());
    }

    #[test]
    fn a_content_cannot_be_linked_to_a_source_that_does_not_exist() {
        let (mut database, _source_id, session_id) = database_with_session();
        let content = new_content(session_id, SourceId::new(999), "1", "messaggio");

        assert!(matches!(
            database.insert_content(&content),
            Err(StorageError::SourceNotSelectedForSession)
        ));
    }

    #[test]
    fn the_same_message_observed_by_two_sessions_is_recorded_by_both_and_annotated() {
        let mut database = database();
        let Ok(source_id) = database.insert_source(&new_source("canale_uno"), now()) else {
            panic!("la fonte deve potersi registrare");
        };
        let (Ok(first_session), Ok(second_session)) = (
            database.insert_session(&new_session(vec![source_id]), now()),
            database.insert_session(&new_session(vec![source_id]), now()),
        ) else {
            panic!("le due sessioni devono potersi creare");
        };

        let Ok(first) =
            database.insert_content(&new_content(first_session, source_id, "42", "stesso testo"))
        else {
            panic!("la prima acquisizione deve riuscire");
        };
        let Ok(second) = database.insert_content(&new_content(
            second_session,
            source_id,
            "42",
            "stesso testo",
        )) else {
            panic!("la seconda sessione deve poter registrare lo stesso messaggio");
        };

        assert!(first.is_new());
        assert!(
            second.is_new(),
            "ogni sessione documenta cio' che acquisisce"
        );
        assert_ne!(first.content_id(), second.content_id());

        let (Ok(first_stored), Ok(second_stored)) = (
            database.content(first.content_id()),
            database.content(second.content_id()),
        ) else {
            panic!("entrambi i contenuti devono potersi rileggere");
        };

        assert_eq!(first_stored.duplicate_of_id, None);
        assert_eq!(second_stored.duplicate_of_id, Some(first.content_id()));
        assert!(second_stored.is_duplicate());
        assert_eq!(first_stored.body_sha256, second_stored.body_sha256);
    }

    #[test]
    fn different_bodies_in_different_sessions_are_not_marked_as_duplicates() {
        let mut database = database();
        let Ok(source_id) = database.insert_source(&new_source("canale_uno"), now()) else {
            panic!("la fonte deve potersi registrare");
        };
        let (Ok(first_session), Ok(second_session)) = (
            database.insert_session(&new_session(vec![source_id]), now()),
            database.insert_session(&new_session(vec![source_id]), now()),
        ) else {
            panic!("le due sessioni devono potersi creare");
        };

        let Ok(_) =
            database.insert_content(&new_content(first_session, source_id, "1", "testo uno"))
        else {
            panic!("la prima acquisizione deve riuscire");
        };
        let Ok(second) =
            database.insert_content(&new_content(second_session, source_id, "2", "testo due"))
        else {
            panic!("la seconda acquisizione deve riuscire");
        };

        let Ok(stored) = database.content(second.content_id()) else {
            panic!("il contenuto deve potersi rileggere");
        };
        assert_eq!(stored.duplicate_of_id, None);
    }

    /// **Due fonti diverse sono due pubblicazioni, non un duplicato.**
    ///
    /// # La regola, e perché è cambiata
    ///
    /// Fino a MULTI-02 era «stesso corpo, sessione diversa», **cieca alla
    /// fonte**: con un monitoraggio solo non si vedeva, con più monitoraggi
    /// (ADR-0065) produceva due comportamenti che nessuno aveva scelto — lo
    /// stesso testo da **due canali diversi** annotato come duplicato se i
    /// monitoraggi erano due, e **non** annotato se il monitoraggio era uno.
    ///
    /// E il primo dei due era **falso nel merito**: un testo inoltrato in due
    /// canali è **due pubblicazioni di due fonti**, e il prodotto lo afferma già
    /// altrove — la chiave di idempotenza contiene la fonte e ne fa due eventi.
    ///
    /// Ora: **stesso corpo, stessa fonte, monitoraggio diverso** (DEC-300).
    #[test]
    fn due_fonti_diverse_sono_due_pubblicazioni_e_non_un_duplicato() {
        let mut database = database();
        let (Ok(prima_fonte), Ok(seconda_fonte)) = (
            database.insert_source(&new_source("canale_uno"), now()),
            database.insert_source(&new_source("canale_due"), now()),
        ) else {
            panic!("le due fonti devono potersi registrare");
        };
        let (Ok(prima_sessione), Ok(seconda_sessione)) = (
            database.insert_session(&new_session(vec![prima_fonte]), now()),
            database.insert_session(&new_session(vec![seconda_fonte]), now()),
        ) else {
            panic!("le due sessioni devono potersi creare");
        };

        let Ok(_) = database.insert_content(&new_content(
            prima_sessione,
            prima_fonte,
            "1",
            "stesso testo",
        )) else {
            panic!("la prima acquisizione deve riuscire");
        };
        let Ok(seconda) = database.insert_content(&new_content(
            seconda_sessione,
            seconda_fonte,
            "2",
            "stesso testo",
        )) else {
            panic!("la seconda acquisizione deve riuscire");
        };

        let Ok(conservata) = database.content(seconda.content_id()) else {
            panic!("il contenuto deve potersi rileggere");
        };
        assert_eq!(
            conservata.duplicate_of_id, None,
            "due canali diversi che pubblicano lo stesso testo sono DUE PUBBLICAZIONI: \
             annotarle come duplicato direbbe «e' lo stesso» proprio dove la cosa che \
             conta e' che due fonti diverse lo hanno pubblicato"
        );
    }

    /// **La stessa fonte, in due monitoraggi, resta un duplicato annotato.**
    ///
    /// È ciò che l'annotazione serve a dire, e nient'altro: questa riga c'è due
    /// volte perché **due monitoraggi guardano la stessa fonte** (ADR-0065 §2.2).
    #[test]
    fn la_stessa_fonte_in_due_monitoraggi_resta_annotata() {
        let mut database = database();
        let Ok(fonte) = database.insert_source(&new_source("canale_uno"), now()) else {
            panic!("la fonte deve potersi registrare");
        };
        let (Ok(prima_sessione), Ok(seconda_sessione)) = (
            database.insert_session(&new_session(vec![fonte]), now()),
            database.insert_session(&new_session(vec![fonte]), now()),
        ) else {
            panic!("le due sessioni devono potersi creare");
        };

        let Ok(_) =
            database.insert_content(&new_content(prima_sessione, fonte, "1", "stesso testo"))
        else {
            panic!("la prima acquisizione deve riuscire");
        };
        let Ok(seconda) =
            database.insert_content(&new_content(seconda_sessione, fonte, "1", "stesso testo"))
        else {
            panic!("la seconda acquisizione deve riuscire");
        };

        let Ok(conservata) = database.content(seconda.content_id()) else {
            panic!("il contenuto deve potersi rileggere");
        };
        assert!(
            conservata.duplicate_of_id.is_some(),
            "due monitoraggi sulla stessa fonte: la seconda riga porta il rimando alla prima"
        );
    }

    #[test]
    fn a_missing_content_is_reported_as_not_found() {
        let (database, _source_id, _session_id) = database_with_session();
        assert!(matches!(
            database.content(ContentId::new(404)),
            Err(StorageError::NotFound {
                entity: "contenuto",
                id: 404
            })
        ));
    }

    #[test]
    fn a_body_with_sql_metacharacters_is_stored_and_read_back_verbatim() {
        let (mut database, source_id, session_id) = database_with_session();
        let hostile = "Robert'); DROP TABLE contents; -- \u{1F600} \"virgolette\" \\barre\\";

        let Ok(insertion) =
            database.insert_content(&new_content(session_id, source_id, "1", hostile))
        else {
            panic!("il testo ostile deve essere trattato come dato");
        };

        let Ok(stored) = database.content(insertion.content_id()) else {
            panic!("il contenuto deve potersi rileggere");
        };
        assert_eq!(stored.body.as_str(), hostile);

        let Ok(contents) = database.session_contents(session_id) else {
            panic!("la tabella deve esistere ancora");
        };
        assert_eq!(contents.len(), 1);
    }

    #[test]
    fn a_multiline_body_keeps_its_line_breaks() {
        let (mut database, source_id, session_id) = database_with_session();
        let text = "prima riga\nseconda riga\r\nterza riga";

        let Ok(insertion) = database.insert_content(&new_content(session_id, source_id, "1", text))
        else {
            panic!("il corpo multilinea deve potersi registrare");
        };
        let Ok(stored) = database.content(insertion.content_id()) else {
            panic!("il contenuto deve potersi rileggere");
        };
        assert_eq!(stored.body.as_str(), text);
    }

    #[test]
    fn contents_of_a_session_do_not_leak_into_another() {
        let mut database = database();
        let Ok(source_id) = database.insert_source(&new_source("canale_uno"), now()) else {
            panic!("la fonte deve potersi registrare");
        };

        let first = NewSession {
            label: display_name("Prima sessione"),
            started_by: actor("operatore.prova"),
            duration: SessionDuration::Manual,
            source_ids: vec![source_id],
        };
        let (Ok(first_session), Ok(second_session)) = (
            database.insert_session(&first, now()),
            database.insert_session(&new_session(vec![source_id]), now()),
        ) else {
            panic!("le due sessioni devono potersi creare");
        };

        let Ok(_) = database.insert_content(&new_content(first_session, source_id, "1", "uno"))
        else {
            panic!("l'acquisizione deve riuscire");
        };

        assert_eq!(
            database
                .session_contents(first_session)
                .map(|c| c.len())
                .ok(),
            Some(1)
        );
        assert_eq!(
            database
                .session_contents(second_session)
                .map(|c| c.len())
                .ok(),
            Some(0)
        );
    }
}

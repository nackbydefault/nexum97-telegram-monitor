//! Pacchetti di report, artefatti e fotografia dei dati che li hanno prodotti.
//!
//! Motivato in ADR-0031, migrazione `0014_report_packages.sql`.
//!
//! # Che cosa questo modulo protegge
//!
//! Un pacchetto e' un insieme di documenti **piu'** la fotografia dei dati con
//! cui sono stati prodotti. La fotografia e' la ragione per cui esiste il
//! modulo: senza, alla domanda «con quali dati e' stato prodotto quel
//! documento?» si potrebbe rispondere soltanto «non e' piu' ricostruibile»,
//! perche' nel frattempo gli stati di revisione cambiano e i dizionari si
//! aggiornano (DEC-152).
//!
//! La fotografia e' **append-only per trigger**, come l'audit: il suo unico
//! mestiere e' dire come stavano le cose allora, e un aggiornamento successivo
//! lo distruggerebbe in silenzio.

use core::str::FromStr;

use lisi_core::digest::Sha256Digest;
use lisi_core::model::report::{
    NewReportArtifact, ReportArtifact, ReportContentSnapshot, ReportGenerationStatus, ReportId,
    ReportPackage, ReportRequest, ReportSelection, ReportSnapshot,
};
use lisi_core::model::report_template::{ReportTemplateProfile, TemplateEmblem, TemplateField};
use lisi_core::model::{AnalysisLevel, ReviewState};
use lisi_core::text::Actor;
use lisi_core::{
    ContentId, DictionaryVersionId, ReportArtifactId, ReportPackageId, SessionId, SourceId,
    Timestamp,
};
use rusqlite::{OptionalExtension as _, Row};

use crate::database::Database;
use crate::error::{ConstraintKind, StorageError, StorageResult, constraint_kind};
use crate::repository::{instant, millis};

/// I campi personali del profilo documentale, **cifrati** (ADR-0160).
///
/// Per l'archivio sono byte opachi: cifra e decifra il servizio, che conosce
/// l'utente Windows. `None` vale «campo non compilato».
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ProtectedProfileFields {
    /// Il firmatario, cifrato.
    pub signer_name: Option<Vec<u8>>,
    /// La qualifica, cifrata.
    pub signer_role: Option<Vec<u8>>,
    /// La riga «sede, indirizzo e recapiti», cifrata.
    pub header_line: Option<Vec<u8>>,
}

impl core::fmt::Debug for ProtectedProfileFields {
    /// Dice soltanto quali campi ci sono: i byte non servono a chi legge un
    /// registro, e non vi finiscono.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProtectedProfileFields")
            .field("signer_name", &self.signer_name.is_some())
            .field("signer_role", &self.signer_role.is_some())
            .field("header_line", &self.header_line.is_some())
            .finish()
    }
}

/// Che cosa ha fatto la conversione dei campi personali ancora in chiaro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlainConversion {
    /// Nessun campo in chiaro, o nessun profilo.
    NothingToDo,
    /// Tanti campi convertiti: il chiaro non c'è più.
    Converted(usize),
    /// La cifratura non è riuscita: nulla è stato scritto, si riprova.
    NotNow,
}

/// Riga grezza della tabella `report_packages`.
struct PackageRow {
    id: i64,
    report_id: String,
    session_id: i64,
    requested_by: String,
    status: String,
    requested_at: i64,
    completed_at: Option<i64>,
}

impl PackageRow {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            report_id: row.get(1)?,
            session_id: row.get(2)?,
            requested_by: row.get(3)?,
            status: row.get(4)?,
            requested_at: row.get(5)?,
            completed_at: row.get(6)?,
        })
    }
}

/// Riga grezza della tabella `report_artifacts`.
struct ArtifactRow {
    id: i64,
    package_id: i64,
    kind: String,
    file_name: String,
    size_bytes: i64,
    sha256: String,
}

impl ArtifactRow {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            package_id: row.get(1)?,
            kind: row.get(2)?,
            file_name: row.get(3)?,
            size_bytes: row.get(4)?,
            sha256: row.get(5)?,
        })
    }

    fn into_domain(self) -> StorageResult<ReportArtifact> {
        Ok(ReportArtifact {
            id: ReportArtifactId::new(self.id),
            package_id: ReportPackageId::new(self.package_id),
            kind: FromStr::from_str(&self.kind)?,
            file_name: self.file_name,
            // Un valore negativo non e' prodotto da questo codice: il CHECK
            // della tabella lo vieta. Se compare, il file e' stato alterato.
            size_bytes: u64::try_from(self.size_bytes).map_err(|_| StorageError::CorruptedRow {
                detail: "dimensione dell'artefatto negativa",
            })?,
            sha256: Sha256Digest::from_hex(&self.sha256)?,
        })
    }
}

impl Database {
    /// Apre un pacchetto, registrandone la selezione e la fotografia.
    ///
    /// Tutto in **una transazione**: un pacchetto con la fotografia a meta'
    /// sarebbe peggio di nessun pacchetto, perche' sembrerebbe spiegabile.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se la sessione non esiste e
    /// [`StorageError::DuplicateReportId`] se l'identificativo citabile e' gia'
    /// usato da un altro pacchetto.
    pub fn open_report_package(
        &mut self,
        package: &ReportRequest,
        snapshot: &ReportSnapshot,
    ) -> StorageResult<ReportPackageId> {
        let transaction = self.connection.transaction()?;

        let id: i64 = transaction
            .query_row(
                "INSERT INTO report_packages (
                     report_id, session_id, requested_by, status,
                     template_version, requested_at, completed_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)
                 RETURNING id",
                rusqlite::params![
                    package.report_id.as_str(),
                    package.session_id.get(),
                    package.requested_by.as_str(),
                    ReportGenerationStatus::Prepared.as_str(),
                    snapshot.template_version,
                    millis(package.requested_at),
                ],
                |row| row.get(0),
            )
            .map_err(|error| match constraint_kind(&error) {
                Some(ConstraintKind::ForeignKey) => StorageError::NotFound {
                    entity: "sessione",
                    id: package.session_id.get(),
                },
                Some(ConstraintKind::Unique) => StorageError::DuplicateReportId,

                _ => StorageError::Sqlite(error),
            })?;

        {
            let mut statement = transaction.prepare(
                "INSERT INTO report_content_snapshots (
                     package_id, content_id, analysis_level, review_state,
                     body_sha256, selected
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for content in &snapshot.contents {
                statement.execute(rusqlite::params![
                    id,
                    content.content_id.get(),
                    i64::from(content.level.get()),
                    content.review_state.map(ReviewState::as_str),
                    content.body_sha256.as_str(),
                    i64::from(content.selected),
                ])?;
            }
        }

        {
            let mut statement = transaction.prepare(
                "INSERT INTO report_snapshot_sources (package_id, source_id) VALUES (?1, ?2)",
            )?;
            for source in &snapshot.source_ids {
                statement.execute(rusqlite::params![id, source.get()])?;
            }
        }

        {
            let mut statement = transaction.prepare(
                "INSERT INTO report_snapshot_dictionary_versions (
                     package_id, dictionary_version_id
                 ) VALUES (?1, ?2)",
            )?;
            for version in &snapshot.dictionary_version_ids {
                statement.execute(rusqlite::params![id, version.get()])?;
            }
        }

        transaction.commit()?;
        Ok(ReportPackageId::new(id))
    }

    /// Registra un artefatto prodotto.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se il pacchetto non esiste e
    /// [`StorageError::DuplicateReportArtifact`] se quel genere di artefatto e'
    /// gia' registrato per quel pacchetto.
    pub fn record_report_artifact(
        &self,
        package_id: ReportPackageId,
        artifact: &NewReportArtifact,
        created_at: Timestamp,
    ) -> StorageResult<ReportArtifactId> {
        let id: i64 = self
            .connection
            .query_row(
                "INSERT INTO report_artifacts (
                     package_id, kind, file_name, size_bytes, sha256, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 RETURNING id",
                rusqlite::params![
                    package_id.get(),
                    artifact.kind.as_str(),
                    artifact.file_name,
                    i64::try_from(artifact.size_bytes).unwrap_or(i64::MAX),
                    artifact.sha256.as_str(),
                    millis(created_at),
                ],
                |row| row.get(0),
            )
            .map_err(|error| match constraint_kind(&error) {
                Some(ConstraintKind::ForeignKey) => StorageError::NotFound {
                    entity: "pacchetto",
                    id: package_id.get(),
                },
                Some(ConstraintKind::Unique) => StorageError::DuplicateReportArtifact,

                _ => StorageError::Sqlite(error),
            })?;

        Ok(ReportArtifactId::new(id))
    }

    /// Porta il pacchetto allo stato indicato.
    ///
    /// `Completed` richiede l'istante di completamento e nessun altro stato lo
    /// ammette: il vincolo e' nello schema, e qui si rispetta invece di
    /// aggirarlo.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se il pacchetto non esiste.
    pub fn set_report_package_status(
        &self,
        package_id: ReportPackageId,
        status: ReportGenerationStatus,
        completed_at: Option<Timestamp>,
    ) -> StorageResult<()> {
        let completion = match status {
            ReportGenerationStatus::Completed => completed_at.map(millis),
            _ => None,
        };

        let changed = self.connection.execute(
            "UPDATE report_packages SET status = ?2, completed_at = ?3 WHERE id = ?1",
            rusqlite::params![package_id.get(), status.as_str(), completion],
        )?;

        if changed == 0 {
            return Err(StorageError::NotFound {
                entity: "pacchetto",
                id: package_id.get(),
            });
        }
        Ok(())
    }

    /// Pacchetto con i suoi artefatti.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se il pacchetto non esiste.
    pub fn report_package(&self, package_id: ReportPackageId) -> StorageResult<ReportPackage> {
        let row = self
            .connection
            .query_row(
                "SELECT id, report_id, session_id, requested_by, status,
                        requested_at, completed_at
                 FROM report_packages WHERE id = ?1",
                [package_id.get()],
                PackageRow::read,
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound {
                    entity: "pacchetto",
                    id: package_id.get(),
                },
                other => StorageError::Sqlite(other),
            })?;

        Ok(ReportPackage {
            id: ReportPackageId::new(row.id),
            report_id: ReportId::try_new(&row.report_id)?,
            session_id: SessionId::new(row.session_id),
            requested_by: Actor::try_new(&row.requested_by)?,
            selection: self.report_selection(package_id)?,
            status: ReportGenerationStatus::from_str(&row.status)?,
            requested_at: instant(row.requested_at),
            completed_at: row.completed_at.map(instant),
            artifacts: self.report_artifacts(package_id)?,
        })
    }

    /// Artefatti di un pacchetto, in ordine di registrazione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// valore non conforme al dominio.
    pub fn report_artifacts(
        &self,
        package_id: ReportPackageId,
    ) -> StorageResult<Vec<ReportArtifact>> {
        let mut statement = self.connection.prepare(
            "SELECT id, package_id, kind, file_name, size_bytes, sha256
             FROM report_artifacts
             WHERE package_id = ?1
             ORDER BY id",
        )?;

        let rows = statement.query_map([package_id.get()], ArtifactRow::read)?;

        let mut artifacts = Vec::new();
        for row in rows {
            artifacts.push(row?.into_domain()?);
        }
        Ok(artifacts)
    }

    /// La selezione con cui il pacchetto e' stato prodotto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn report_selection(&self, package_id: ReportPackageId) -> StorageResult<ReportSelection> {
        let mut statement = self.connection.prepare(
            "SELECT content_id FROM report_content_snapshots
             WHERE package_id = ?1 AND selected = 1
             ORDER BY content_id",
        )?;

        let rows = statement.query_map([package_id.get()], |row| row.get::<_, i64>(0))?;

        let mut contents = Vec::new();
        for row in rows {
            contents.push(ContentId::new(row?));
        }
        Ok(ReportSelection::from_contents(contents))
    }

    /// La fotografia dei dati con cui il pacchetto e' stato prodotto.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se il pacchetto non esiste, o un
    /// errore se una riga contiene un valore non conforme al dominio.
    pub fn report_snapshot(&self, package_id: ReportPackageId) -> StorageResult<ReportSnapshot> {
        let (session_id, template_version, requested_at): (i64, i64, i64) = self
            .connection
            .query_row(
                "SELECT session_id, template_version, requested_at
                 FROM report_packages WHERE id = ?1",
                [package_id.get()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound {
                    entity: "pacchetto",
                    id: package_id.get(),
                },
                other => StorageError::Sqlite(other),
            })?;

        let mut contents = Vec::new();
        {
            let mut statement = self.connection.prepare(
                "SELECT content_id, analysis_level, review_state, body_sha256, selected
                 FROM report_content_snapshots
                 WHERE package_id = ?1
                 ORDER BY content_id",
            )?;
            let rows = statement.query_map([package_id.get()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?;

            for row in rows {
                let (content_id, level, review_state, body_sha256, selected) = row?;
                let level = u8::try_from(level).map_err(|_| StorageError::CorruptedRow {
                    detail: "livello di analisi della fotografia fuori scala",
                })?;
                contents.push(ReportContentSnapshot {
                    content_id: ContentId::new(content_id),
                    level: AnalysisLevel::try_new(level)?,
                    review_state: review_state
                        .as_deref()
                        .map(ReviewState::from_str)
                        .transpose()?,
                    body_sha256: Sha256Digest::from_hex(&body_sha256)?,
                    selected: selected != 0,
                });
            }
        }

        let source_ids = self.snapshot_ids(
            package_id,
            "SELECT source_id FROM report_snapshot_sources WHERE package_id = ?1 ORDER BY source_id",
        )?;
        let dictionary_version_ids = self.snapshot_ids(
            package_id,
            "SELECT dictionary_version_id FROM report_snapshot_dictionary_versions
             WHERE package_id = ?1 ORDER BY dictionary_version_id",
        )?;

        Ok(ReportSnapshot {
            taken_at: instant(requested_at),
            session_id: SessionId::new(session_id),
            source_ids: source_ids.into_iter().map(SourceId::new).collect(),
            dictionary_version_ids: dictionary_version_ids
                .into_iter()
                .map(DictionaryVersionId::new)
                .collect(),
            template_version: u32::try_from(template_version).map_err(|_| {
                StorageError::CorruptedRow {
                    detail: "versione del template della fotografia non interpretabile",
                }
            })?,
            contents,
        })
    }

    /// Pacchetti di una sessione, dal piu' recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn session_report_packages(
        &self,
        session_id: SessionId,
    ) -> StorageResult<Vec<ReportPackage>> {
        let mut identifiers = Vec::new();
        {
            let mut statement = self.connection.prepare(
                "SELECT id FROM report_packages
                 WHERE session_id = ?1
                 ORDER BY requested_at DESC, id DESC",
            )?;
            let rows = statement.query_map([session_id.get()], |row| row.get::<_, i64>(0))?;
            for row in rows {
                identifiers.push(ReportPackageId::new(row?));
            }
        }

        let mut packages = Vec::new();
        for id in identifiers {
            packages.push(self.report_package(id)?);
        }
        Ok(packages)
    }

    /// Il profilo documentale conservato, se l'operatore ha gia' risposto.
    ///
    /// # Che cosa distingue `None` da un profilo vuoto
    ///
    /// `None` significa che **la domanda non e' ancora stata posta**: al primo
    /// avvio il prodotto la pone. Un profilo con tutti i campi vuoti significa
    /// che gliela si e' posta e l'operatore ha scelto di non rispondere, che e'
    /// una risposta legittima e che il prodotto deve ricordare: senza questa
    /// distinzione richiederebbe gli stessi dati a ogni avvio a chi ha gia'
    /// detto di no (DEC-180).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// valore che il dominio non accetta.
    pub fn report_profile(&self) -> StorageResult<Option<ReportTemplateProfile>> {
        let row = self
            .connection
            .query_row(
                "SELECT version, organisation, office, header_line, recipient,
                        recipient_cc, place, signer_role, signer_name, footer_line,
                        subject_base, emblem
                 FROM report_profile WHERE id = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        (1..=10)
                            .map(|index| row.get::<_, Option<String>>(index))
                            .collect::<rusqlite::Result<Vec<_>>>()?,
                        row.get::<_, Option<Vec<u8>>>(11)?,
                    ))
                },
            )
            .optional()?;

        let Some((version, fields, emblem)) = row else {
            return Ok(None);
        };

        // Un valore conservato che il dominio non accetta piu' non si accomoda
        // in silenzio: e' un archivio manomesso o una regola cambiata, e in
        // entrambi i casi va detto.
        fn field(fields: &[Option<String>], index: usize) -> StorageResult<Option<TemplateField>> {
            fields[index]
                .as_deref()
                .map(TemplateField::try_new)
                .transpose()
                .map_err(StorageError::from)
        }
        let field = |index: usize| field(&fields, index);

        Ok(Some(ReportTemplateProfile {
            version: u32::try_from(version).map_err(|_| StorageError::CorruptedRow {
                detail: "versione del profilo documentale non interpretabile",
            })?,
            organisation: field(0)?,
            office: field(1)?,
            header_line: field(2)?,
            recipient: field(3)?,
            recipient_cc: field(4)?,
            place: field(5)?,
            signer_role: field(6)?,
            signer_name: field(7)?,
            footer_line: field(8)?,
            subject_base: field(9)?,
            emblem: emblem.map(TemplateEmblem::from_png).transpose()?,
        }))
    }

    /// Conserva il profilo documentale, facendone crescere la versione.
    ///
    /// Restituisce la versione assegnata. La prima e' **1**: la versione 0
    /// appartiene all'assenza del profilo, e non si conserva mai.
    ///
    /// # I campi personali (ADR-0160)
    ///
    /// Firmatario, qualifica e riga «sede, indirizzo e recapiti» si scrivono
    /// **soltanto cifrati**, in `protected`: un profilo che li porti in chiaro
    /// si rifiuta. Cifra il servizio, che conosce l'utente Windows; l'archivio
    /// conserva byte opachi e garantisce che il chiaro non entri.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::PlaintextPersonalField`] se uno dei tre
    /// campi personali arriva in chiaro, e un errore se la scrittura non
    /// riesce.
    pub fn save_report_profile(
        &self,
        profile: &ReportTemplateProfile,
        protected: &ProtectedProfileFields,
        actor: &Actor,
        now: Timestamp,
    ) -> StorageResult<u32> {
        for (campo, valore) in [
            ("firmatario", profile.signer_name.is_some()),
            ("qualifica", profile.signer_role.is_some()),
            ("sede, indirizzo e recapiti", profile.header_line.is_some()),
        ] {
            if valore {
                return Err(StorageError::PlaintextPersonalField { field: campo });
            }
        }

        // Una `fn` e non una chiusura: il compilatore non riesce a dedurre da
        // solo che il riferimento restituito viva quanto quello ricevuto.
        fn text(field: Option<&TemplateField>) -> Option<&str> {
            field.map(TemplateField::as_str)
        }

        // `version` non viene dal chiamante: la decide l'archivio, che e'
        // l'unico a sapere quante volte il profilo e' stato salvato. Un numero
        // proposto da fuori sarebbe un numero che due schermate diverse
        // possono proporre uguale.
        let version: i64 = self.connection.query_row(
            "INSERT INTO report_profile (
                 id, version, organisation, office, header_line, recipient,
                 recipient_cc, place, signer_role, signer_name, footer_line,
                 subject_base, emblem, updated_at, updated_by,
                 signer_name_protected, signer_role_protected, header_line_protected
             ) VALUES (
                 1,
                 COALESCE((SELECT version FROM report_profile WHERE id = 1), 0) + 1,
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16
             )
             ON CONFLICT (id) DO UPDATE SET
                 version = report_profile.version + 1,
                 organisation = excluded.organisation,
                 office = excluded.office,
                 header_line = excluded.header_line,
                 recipient = excluded.recipient,
                 recipient_cc = excluded.recipient_cc,
                 place = excluded.place,
                 signer_role = excluded.signer_role,
                 signer_name = excluded.signer_name,
                 footer_line = excluded.footer_line,
                 subject_base = excluded.subject_base,
                 emblem = excluded.emblem,
                 updated_at = excluded.updated_at,
                 updated_by = excluded.updated_by,
                 signer_name_protected = excluded.signer_name_protected,
                 signer_role_protected = excluded.signer_role_protected,
                 header_line_protected = excluded.header_line_protected
             RETURNING version",
            rusqlite::params![
                text(profile.organisation.as_ref()),
                text(profile.office.as_ref()),
                text(profile.header_line.as_ref()),
                text(profile.recipient.as_ref()),
                text(profile.recipient_cc.as_ref()),
                text(profile.place.as_ref()),
                text(profile.signer_role.as_ref()),
                text(profile.signer_name.as_ref()),
                text(profile.footer_line.as_ref()),
                text(profile.subject_base.as_ref()),
                profile.emblem.as_ref().map(TemplateEmblem::bytes),
                millis(now),
                actor.as_str(),
                protected.signer_name.as_deref(),
                protected.signer_role.as_deref(),
                protected.header_line.as_deref(),
            ],
            |row| row.get(0),
        )?;

        u32::try_from(version).map_err(|_| StorageError::CorruptedRow {
            detail: "versione del profilo documentale non interpretabile",
        })
    }

    /// I campi personali del profilo, cifrati, come l'archivio li conserva
    /// (ADR-0160).
    ///
    /// `None` se non c'è un profilo.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn report_profile_protected(&self) -> StorageResult<Option<ProtectedProfileFields>> {
        Ok(self
            .connection
            .query_row(
                "SELECT signer_name_protected, signer_role_protected, header_line_protected
                 FROM report_profile WHERE id = 1",
                [],
                |row| {
                    Ok(ProtectedProfileFields {
                        signer_name: row.get(0)?,
                        signer_role: row.get(1)?,
                        header_line: row.get(2)?,
                    })
                },
            )
            .optional()?)
    }

    /// Porta i campi personali ancora scritti in chiaro — un archivio di
    /// prima della migrazione 0062 — nelle colonne cifrate, e svuota quelle
    /// in chiaro (ADR-0160, decisione 4).
    ///
    /// `cifra` la fornisce il servizio, che conosce l'utente Windows; se
    /// restituisce `None` per un campo, **non si scrive nulla** e l'esito è
    /// [`PlainConversion::NotNow`]: meglio il chiaro di ieri che un campo
    /// perso.
    ///
    /// **La versione non cresce**: il contenuto del profilo non cambia, cambia
    /// soltanto come è conservato. La scrittura avviene con `secure_delete`,
    /// perché le pagine che contenevano il chiaro vengano riscritte invece di
    /// restare libere con il loro contenuto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura o la scrittura non riescono.
    pub fn protect_plain_profile_fields(
        &self,
        cifra: &dyn Fn(&str) -> Option<Vec<u8>>,
    ) -> StorageResult<PlainConversion> {
        let riga = self
            .connection
            .query_row(
                "SELECT signer_name, signer_role, header_line,
                        signer_name_protected, signer_role_protected, header_line_protected
                 FROM report_profile WHERE id = 1",
                [],
                |row| {
                    Ok((
                        [
                            row.get::<_, Option<String>>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, Option<String>>(2)?,
                        ],
                        [
                            row.get::<_, Option<Vec<u8>>>(3)?,
                            row.get::<_, Option<Vec<u8>>>(4)?,
                            row.get::<_, Option<Vec<u8>>>(5)?,
                        ],
                    ))
                },
            )
            .optional()?;
        let Some((chiari, mut cifrati)) = riga else {
            return Ok(PlainConversion::NothingToDo);
        };
        if chiari.iter().all(Option::is_none) {
            return Ok(PlainConversion::NothingToDo);
        }

        let mut convertiti = 0_usize;
        for (chiaro, cifrato) in chiari.iter().zip(cifrati.iter_mut()) {
            let Some(testo) = chiaro else {
                continue;
            };
            let Some(byte) = cifra(testo) else {
                return Ok(PlainConversion::NotNow);
            };
            *cifrato = Some(byte);
            convertiti += 1;
        }

        self.connection
            .execute_batch("PRAGMA secure_delete = ON;")?;
        let esito = self.connection.execute(
            "UPDATE report_profile SET
                 signer_name = NULL,
                 signer_role = NULL,
                 header_line = NULL,
                 signer_name_protected = ?1,
                 signer_role_protected = ?2,
                 header_line_protected = ?3
             WHERE id = 1",
            rusqlite::params![
                cifrati[0].as_deref(),
                cifrati[1].as_deref(),
                cifrati[2].as_deref(),
            ],
        );
        let ripristino = self.connection.execute_batch("PRAGMA secure_delete = OFF;");
        esito?;
        ripristino?;
        Ok(PlainConversion::Converted(convertiti))
    }

    /// Progressivo libero per comporre un identificativo citabile dell'anno.
    ///
    /// # Perche' si legge il massimo e non si conta
    ///
    /// Contare le righe darebbe lo stesso numero due volte appena un pacchetto
    /// venisse cancellato, e il secondo tentativo cadrebbe sul vincolo di
    /// unicita' di `report_id`. Il massimo gia' usato non ha questo difetto:
    /// cresce e basta, e i buchi restano buchi.
    ///
    /// # Che cosa questo numero non garantisce
    ///
    /// **Non e' una prenotazione.** Fra la lettura e l'inserimento un'altra
    /// esecuzione puo' aver preso lo stesso numero: la garanzia vera resta il
    /// vincolo `UNIQUE` della tabella, e chi chiama deve saper riprovare con il
    /// numero successivo. Una prenotazione richiederebbe una riga scritta prima
    /// di sapere se il pacchetto si fara' davvero, cioe' un identificativo
    /// consumato da una generazione mai avvenuta.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn next_report_sequence(&self, year: i32) -> StorageResult<u32> {
        let prefix = format!("R-{year}-");
        let mut statement = self
            .connection
            .prepare("SELECT report_id FROM report_packages WHERE report_id LIKE ?1 || '%'")?;

        let rows = statement.query_map([&prefix], |row| row.get::<_, String>(0))?;

        let mut highest = 0_u32;
        for row in rows {
            let report_id = row?;
            // Un identificativo che non ha la forma attesa non e' un errore da
            // propagare: e' un valore che questo conteggio non riguarda, e
            // fermarsi renderebbe impossibile produrre un report nuovo per
            // colpa di uno vecchio.
            if let Some(tail) = report_id.strip_prefix(&prefix)
                && let Ok(value) = tail.parse::<u32>()
            {
                highest = highest.max(value);
            }
        }

        Ok(highest.saturating_add(1))
    }

    /// Versioni di dizionario selezionate per una sessione.
    ///
    /// Serve a comporre la fotografia: quale vocabolario era in vigore quando
    /// i contenuti sono stati valutati. Senza, un dizionario aggiornato dopo
    /// renderebbe incomprensibili i livelli di un report vecchio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn session_dictionary_version_ids(
        &self,
        session_id: SessionId,
    ) -> StorageResult<Vec<DictionaryVersionId>> {
        let mut statement = self.connection.prepare(
            "SELECT version_id FROM session_dictionary_selections
             WHERE session_id = ?1
             ORDER BY version_id",
        )?;

        let rows = statement.query_map([session_id.get()], |row| row.get::<_, i64>(0))?;

        let mut versions = Vec::new();
        for row in rows {
            versions.push(DictionaryVersionId::new(row?));
        }
        Ok(versions)
    }

    /// Legge una colonna di identificativi della fotografia.
    fn snapshot_ids(&self, package_id: ReportPackageId, sql: &str) -> StorageResult<Vec<i64>> {
        let mut statement = self.connection.prepare(sql)?;
        let rows = statement.query_map([package_id.get()], |row| row.get::<_, i64>(0))?;
        let mut values = Vec::new();
        for row in rows {
            values.push(row?);
        }
        Ok(values)
    }
}

impl Database {
    /// Le relazioni più recenti, di qualunque sessione.
    ///
    /// Serve all'elenco che una postazione legge dall'Hub (TEAM-REPORT-01,
    /// ADR-0100, decisione 2): quella non sa quali sessioni esistano, e
    /// chiedere «le ultime» è la domanda che può fare.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn recent_report_packages(&self, limit: usize) -> StorageResult<Vec<ReportPackage>> {
        let mut identifiers = Vec::new();
        {
            let mut statement = self.connection.prepare(
                "SELECT id FROM report_packages
                 ORDER BY requested_at DESC, id DESC
                 LIMIT ?1",
            )?;
            let rows = statement.query_map([i64::try_from(limit).unwrap_or(i64::MAX)], |row| {
                row.get::<_, i64>(0)
            })?;
            for row in rows {
                identifiers.push(ReportPackageId::new(row?));
            }
        }

        let mut packages = Vec::new();
        for id in identifiers {
            packages.push(self.report_package(id)?);
        }
        Ok(packages)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::digest::Sha256Digest;
    use lisi_core::model::report::{
        NewReportArtifact, ReportArtifactKind, ReportContentSnapshot, ReportGenerationStatus,
        ReportId, ReportOutcome, ReportRequest, ReportSelection, ReportSnapshot,
    };
    use lisi_core::model::{AnalysisLevel, ReviewState};
    use lisi_core::{ContentId, ReportPackageId, SessionId, SourceId};

    use crate::error::StorageError;
    use crate::test_support::{actor, database_with_session, later};

    fn level(value: u8) -> AnalysisLevel {
        let Ok(level) = AnalysisLevel::try_new(value) else {
            panic!("il livello di prova deve essere valido");
        };
        level
    }

    fn snapshot(session_id: SessionId, selected: &[i64], monitored: &[i64]) -> ReportSnapshot {
        ReportSnapshot {
            taken_at: later(0),
            session_id,
            source_ids: vec![SourceId::new(1)],
            dictionary_version_ids: Vec::new(),
            template_version: 3,
            contents: monitored
                .iter()
                .map(|raw| ReportContentSnapshot {
                    content_id: ContentId::new(*raw),
                    level: level(u8::try_from(*raw % 5).unwrap_or(0)),
                    review_state: Some(ReviewState::New),
                    body_sha256: Sha256Digest::of_text(&format!("corpo {raw}")),
                    selected: selected.contains(raw),
                })
                .collect(),
        }
    }

    fn new_package(session_id: SessionId, sequence: u32) -> ReportRequest {
        ReportRequest {
            report_id: ReportId::from_sequence(2026, sequence),
            session_id,
            requested_by: actor("operatore.prova"),
            selection: ReportSelection::from_contents([ContentId::new(2)]),
            requested_kinds: vec![ReportArtifactKind::NarrativeDocx],
            template_version: 3,
            requested_at: later(0),
        }
    }

    #[test]
    fn a_package_is_opened_with_its_snapshot_and_read_back() {
        let (mut database, _source_id, session_id) = database_with_session();
        let taken = snapshot(session_id, &[2, 4], &[1, 2, 3, 4]);

        let Ok(package_id) = database.open_report_package(&new_package(session_id, 1), &taken)
        else {
            panic!("il pacchetto deve potersi aprire");
        };

        let Ok(package) = database.report_package(package_id) else {
            panic!("il pacchetto deve potersi rileggere");
        };
        assert_eq!(package.report_id.as_str(), "R-2026-000001");
        assert_eq!(package.status, ReportGenerationStatus::Prepared);
        assert!(package.completed_at.is_none());
        assert_eq!(package.outcome(), ReportOutcome::WithFindings);
        assert_eq!(
            package.selection.contents(),
            &[ContentId::new(2), ContentId::new(4)]
        );
    }

    // ------------------------------------------------- profilo documentale

    #[test]
    fn a_profile_that_was_never_saved_is_absent_and_not_empty() {
        // La distinzione che regge tutto: `None` significa che all'operatore
        // **non e' ancora stata posta la domanda**.
        let (database, _source_id, _session_id) = database_with_session();

        let Ok(profile) = database.report_profile() else {
            panic!("il profilo deve potersi leggere");
        };
        assert!(profile.is_none(), "senza salvataggi non c'e' alcun profilo");
    }

    #[test]
    fn a_saved_profile_comes_back_with_every_field() {
        use lisi_core::model::report_template::{ReportTemplateProfile, TemplateField};

        let (database, _source_id, _session_id) = database_with_session();
        let campo = |value: &str| TemplateField::try_new(value).ok();
        let profile = ReportTemplateProfile {
            version: 99,
            organisation: campo("Ente di prova"),
            office: campo("Ufficio di prova"),
            // I tre campi personali non si scrivono in chiaro (ADR-0160):
            // arrivano cifrati, qui con byte qualunque.
            header_line: None,
            recipient: campo("Al Responsabile"),
            recipient_cc: campo("SEDE"),
            place: campo("Città di prova"),
            signer_role: None,
            signer_name: None,
            footer_line: campo("riferimenti"),
            subject_base: campo("Relazione di servizio"),
            emblem: None,
        };

        let cifrati = super::ProtectedProfileFields {
            signer_name: Some(vec![1, 2, 3]),
            signer_role: Some(vec![4, 5]),
            header_line: None,
        };
        let Ok(version) =
            database.save_report_profile(&profile, &cifrati, &actor("operatore"), later(0))
        else {
            panic!("il profilo deve potersi salvare");
        };
        // La versione la decide l'archivio, non il chiamante: quel 99 non
        // arriva da nessuna parte.
        assert_eq!(version, 1);

        let Ok(Some(riletto)) = database.report_profile() else {
            panic!("il profilo salvato deve potersi rileggere");
        };
        assert_eq!(riletto.version, 1);
        assert_eq!(
            riletto.organisation.map(|f| f.as_str().to_owned()),
            Some(String::from("Ente di prova"))
        );
        assert_eq!(
            riletto.place.map(|f| f.as_str().to_owned()),
            Some(String::from("Città di prova"))
        );
        assert!(
            riletto.signer_name.is_none(),
            "il firmatario in chiaro non c'è"
        );
        let Ok(Some(riletti)) = database.report_profile_protected() else {
            panic!("i campi cifrati devono potersi rileggere");
        };
        assert_eq!(riletti, cifrati, "i byte cifrati tornano come sono");
    }

    /// **I campi personali di prima si convertono: il chiaro sparisce anche
    /// dai byte del file, e la versione non cresce** (ADR-0160, decisione 4;
    /// OPERATOR-DPAPI-01, criterio 2). Una cifratura che non riesce non
    /// tocca nulla.
    ///
    /// La cifratura qui è finta — i byte rovesciati — perché l'archivio non
    /// conosce DPAPI: quella vera la prova il servizio.
    #[test]
    fn i_campi_personali_di_prima_si_convertono_e_spariscono_dal_file() {
        use lisi_core::model::report_template::ReportTemplateProfile;

        const FIRMATARIO: &str = "Mario PROVAFIRMA";
        const RECAPITI: &str = "Via Sintetica 1, telefono 000 000000";

        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        let percorso = cartella.path().join("archivio.sqlite3");
        let contiene = |ago: &str| -> bool {
            let mut byte = std::fs::read(&percorso).unwrap_or_default();
            byte.extend(
                std::fs::read(cartella.path().join("archivio.sqlite3-wal")).unwrap_or_default(),
            );
            byte.windows(ago.len())
                .any(|finestra| finestra == ago.as_bytes())
        };

        {
            let Ok(database) = crate::database::Database::open(&percorso) else {
                panic!("l'archivio deve aprirsi");
            };
            let Ok(_) = database.save_report_profile(
                &ReportTemplateProfile::default(),
                &super::ProtectedProfileFields::default(),
                &actor("operatore"),
                later(0),
            ) else {
                panic!("il profilo deve salvarsi");
            };
            // Un archivio di prima della 0062: il chiaro nelle colonne di allora.
            if let Err(errore) = database.connection.execute(
                "UPDATE report_profile SET signer_name = ?1, header_line = ?2",
                rusqlite::params![FIRMATARIO, RECAPITI],
            ) {
                panic!("l'archivio di prima deve prepararsi: {errore}");
            }

            // Una cifratura che non riesce: nulla cambia.
            assert_eq!(
                database.protect_plain_profile_fields(&|_| None).ok(),
                Some(super::PlainConversion::NotNow)
            );
            let Ok(Some(ancora)) = database.report_profile() else {
                panic!("il profilo deve leggersi");
            };
            assert!(
                ancora.signer_name.is_some(),
                "una cifratura fallita ha tolto il chiaro"
            );
        }
        assert!(
            contiene(FIRMATARIO),
            "la prova non sta guardando i byte giusti"
        );

        {
            let Ok(database) = crate::database::Database::open(&percorso) else {
                panic!("l'archivio deve riaprirsi");
            };
            let rovescia = |testo: &str| Some(testo.bytes().rev().collect::<Vec<u8>>());
            assert_eq!(
                database.protect_plain_profile_fields(&rovescia).ok(),
                Some(super::PlainConversion::Converted(2))
            );
            assert_eq!(
                database.protect_plain_profile_fields(&rovescia).ok(),
                Some(super::PlainConversion::NothingToDo),
                "la conversione si fa una volta sola"
            );
            let Ok(Some(profilo)) = database.report_profile() else {
                panic!("il profilo deve leggersi");
            };
            assert!(profilo.signer_name.is_none() && profilo.header_line.is_none());
            assert_eq!(
                profilo.version, 1,
                "la conversione ha fatto crescere la versione"
            );
            let Ok(Some(cifrati)) = database.report_profile_protected() else {
                panic!("i campi cifrati devono leggersi");
            };
            assert_eq!(cifrati.signer_name, rovescia(FIRMATARIO));
            assert_eq!(cifrati.header_line, rovescia(RECAPITI));
            assert!(cifrati.signer_role.is_none());
        }
        for valore in [FIRMATARIO, RECAPITI] {
            assert!(
                !contiene(valore),
                "«{valore}» è rimasto nei byte dell'archivio"
            );
        }
    }

    /// **Un campo personale in chiaro non entra nell'archivio** (ADR-0160,
    /// decisione 3): il rifiuto è dell'archivio, e non lascia una riga.
    #[test]
    fn un_campo_personale_in_chiaro_si_rifiuta() {
        use lisi_core::model::report_template::{ReportTemplateProfile, TemplateField};

        let (database, _source_id, _session_id) = database_with_session();
        for profilo in [
            ReportTemplateProfile {
                signer_name: TemplateField::try_new("Nome COGNOME").ok(),
                ..ReportTemplateProfile::default()
            },
            ReportTemplateProfile {
                signer_role: TemplateField::try_new("Qualifica").ok(),
                ..ReportTemplateProfile::default()
            },
            ReportTemplateProfile {
                header_line: TemplateField::try_new("Via di Prova 1").ok(),
                ..ReportTemplateProfile::default()
            },
        ] {
            assert!(
                matches!(
                    database.save_report_profile(
                        &profilo,
                        &super::ProtectedProfileFields::default(),
                        &actor("operatore"),
                        later(0)
                    ),
                    Err(StorageError::PlaintextPersonalField { .. })
                ),
                "un campo personale in chiaro è stato accettato"
            );
        }
        assert!(
            matches!(database.report_profile(), Ok(None)),
            "il rifiuto ha lasciato una riga"
        );
    }

    #[test]
    fn saving_again_makes_the_version_grow_and_keeps_one_row() {
        // La versione cresce perche' la fotografia di un report registra con
        // quale profilo e' stato prodotto: senza, un profilo modificato
        // renderebbe inspiegabile un report vecchio.
        use lisi_core::model::report_template::{ReportTemplateProfile, TemplateField};

        let (database, _source_id, _session_id) = database_with_session();
        let mut profile = ReportTemplateProfile::default();

        let Ok(prima) = database.save_report_profile(
            &profile,
            &super::ProtectedProfileFields::default(),
            &actor("operatore"),
            later(0),
        ) else {
            panic!("il profilo deve potersi salvare");
        };
        profile.office = TemplateField::try_new("Ufficio nuovo").ok();
        let Ok(dopo) = database.save_report_profile(
            &profile,
            &super::ProtectedProfileFields::default(),
            &actor("operatore"),
            later(60),
        ) else {
            panic!("il profilo deve potersi risalvare");
        };

        assert_eq!(prima, 1);
        assert_eq!(dopo, 2);

        let Ok(Some(riletto)) = database.report_profile() else {
            panic!("il profilo deve potersi rileggere");
        };
        assert_eq!(riletto.version, 2);
        assert_eq!(
            riletto.office.map(|f| f.as_str().to_owned()),
            Some(String::from("Ufficio nuovo"))
        );
    }

    #[test]
    fn a_profile_saved_empty_is_present_and_means_the_operator_declined() {
        // Rispondere «non li inserisco» e' una risposta, e va ricordata:
        // senza, il prodotto richiederebbe gli stessi dati a ogni avvio a chi
        // ha gia' detto di no.
        use lisi_core::model::report_template::ReportTemplateProfile;

        let (database, _source_id, _session_id) = database_with_session();
        let Ok(_) = database.save_report_profile(
            &ReportTemplateProfile::default(),
            &super::ProtectedProfileFields::default(),
            &actor("operatore"),
            later(0),
        ) else {
            panic!("un profilo vuoto deve potersi salvare");
        };

        let Ok(Some(riletto)) = database.report_profile() else {
            panic!("il profilo vuoto deve comunque esistere");
        };
        assert!(riletto.is_empty(), "nessun campo e' stato compilato");
        assert_eq!(riletto.version, 1, "ma la domanda e' stata posta");
    }

    #[test]
    fn the_emblem_survives_a_round_trip_through_the_archive() {
        use lisi_core::model::report_template::{ReportTemplateProfile, TemplateEmblem};

        let mut png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        png.extend_from_slice(&13_u32.to_be_bytes());
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&40_u32.to_be_bytes());
        png.extend_from_slice(&50_u32.to_be_bytes());
        png.extend_from_slice(&[8, 6, 0, 0, 0]);

        let (database, _source_id, _session_id) = database_with_session();
        let profile = ReportTemplateProfile {
            emblem: TemplateEmblem::from_png(png).ok(),
            ..ReportTemplateProfile::default()
        };
        let Ok(_) = database.save_report_profile(
            &profile,
            &super::ProtectedProfileFields::default(),
            &actor("operatore"),
            later(0),
        ) else {
            panic!("il profilo con stemma deve potersi salvare");
        };

        let Ok(Some(riletto)) = database.report_profile() else {
            panic!("il profilo deve potersi rileggere");
        };
        let Some(emblem) = riletto.emblem else {
            panic!("lo stemma deve sopravvivere al salvataggio");
        };
        assert_eq!(emblem.width_px(), 40);
        assert_eq!(emblem.height_px(), 50);
    }

    #[test]
    fn the_first_report_of_a_year_takes_the_first_number() {
        let (database, _source_id, _session_id) = database_with_session();

        let Ok(sequence) = database.next_report_sequence(2026) else {
            panic!("il progressivo deve potersi leggere");
        };
        assert_eq!(sequence, 1);
    }

    #[test]
    fn the_next_number_comes_after_the_highest_already_used() {
        // Non un conteggio: contare le righe darebbe lo stesso numero due volte
        // appena un pacchetto venisse cancellato.
        let (mut database, _source_id, session_id) = database_with_session();
        let taken = snapshot(session_id, &[], &[1]);
        for sequence in [1, 7] {
            let Ok(_) = database.open_report_package(&new_package(session_id, sequence), &taken)
            else {
                panic!("il pacchetto deve potersi aprire");
            };
        }

        let Ok(sequence) = database.next_report_sequence(2026) else {
            panic!("il progressivo deve potersi leggere");
        };
        assert_eq!(sequence, 8, "il progressivo deve superare il massimo usato");
    }

    #[test]
    fn the_numbering_of_one_year_does_not_look_at_another() {
        let (mut database, _source_id, session_id) = database_with_session();
        let taken = snapshot(session_id, &[], &[1]);
        let Ok(_) = database.open_report_package(&new_package(session_id, 42), &taken) else {
            panic!("il pacchetto deve potersi aprire");
        };

        let Ok(sequence) = database.next_report_sequence(2027) else {
            panic!("il progressivo deve potersi leggere");
        };
        assert_eq!(sequence, 1);
    }

    #[test]
    fn a_package_without_a_selection_is_legitimate() {
        // La relazione a esito negativo si produce ugualmente: e' la Decisione
        // 4 di ADR-0031, e qui si verifica che l'archivio la ammetta.
        let (mut database, _source_id, session_id) = database_with_session();
        let taken = snapshot(session_id, &[], &[1, 2, 3]);

        let Ok(package_id) = database.open_report_package(&new_package(session_id, 2), &taken)
        else {
            panic!("il pacchetto senza selezione deve potersi aprire");
        };

        let Ok(package) = database.report_package(package_id) else {
            panic!("il pacchetto deve potersi rileggere");
        };
        assert!(package.selection.is_empty());
        assert_eq!(package.outcome(), ReportOutcome::NothingSelected);
    }

    #[test]
    fn the_snapshot_survives_a_change_to_the_archive() {
        // È la ragione per cui la fotografia esiste (DEC-152). Qui si simula
        // il passare del tempo cambiando i dati che la fotografia descrive, e
        // si verifica che la fotografia continui a dire come stavano allora.
        let (mut database, _source_id, session_id) = database_with_session();
        let taken = snapshot(session_id, &[2], &[1, 2, 3]);
        let Ok(package_id) = database.open_report_package(&new_package(session_id, 3), &taken)
        else {
            panic!("il pacchetto deve potersi aprire");
        };

        let Ok(reread) = database.report_snapshot(package_id) else {
            panic!("la fotografia deve potersi rileggere");
        };
        assert_eq!(reread.monitored_count(), 3);
        assert_eq!(reread.selected_count(), 1);
        assert_eq!(reread.excluded_count(), 2);
        assert_eq!(reread.template_version, 3);
        assert_eq!(reread.source_ids, vec![SourceId::new(1)]);
        assert_eq!(
            reread.selection(),
            ReportSelection::from_contents([ContentId::new(2)])
        );
    }

    #[test]
    fn the_snapshot_refuses_to_be_rewritten() {
        // Una fotografia che si potesse modificare non sarebbe una fotografia.
        let (mut database, _source_id, session_id) = database_with_session();
        let taken = snapshot(session_id, &[1], &[1, 2]);
        let Ok(package_id) = database.open_report_package(&new_package(session_id, 4), &taken)
        else {
            panic!("il pacchetto deve potersi aprire");
        };

        let outcome = database.connection.execute(
            "UPDATE report_content_snapshots SET selected = 0 WHERE package_id = ?1",
            [package_id.get()],
        );
        assert!(
            outcome.is_err(),
            "il trigger deve rifiutare la modifica della fotografia"
        );
    }

    #[test]
    fn two_packages_cannot_share_the_citable_identifier() {
        let (mut database, _source_id, session_id) = database_with_session();
        let taken = snapshot(session_id, &[], &[1]);
        let Ok(_) = database.open_report_package(&new_package(session_id, 5), &taken) else {
            panic!("il primo pacchetto deve potersi aprire");
        };

        assert!(matches!(
            database.open_report_package(&new_package(session_id, 5), &taken),
            Err(StorageError::DuplicateReportId)
        ));
    }

    #[test]
    fn a_package_never_contains_the_same_kind_twice() {
        let (mut database, _source_id, session_id) = database_with_session();
        let taken = snapshot(session_id, &[], &[1]);
        let Ok(package_id) = database.open_report_package(&new_package(session_id, 6), &taken)
        else {
            panic!("il pacchetto deve potersi aprire");
        };

        let artifact = NewReportArtifact {
            kind: ReportArtifactKind::NarrativeDocx,
            file_name: String::from("Relazione_R-2026-000006.docx"),
            size_bytes: 4096,
            sha256: Sha256Digest::of_text("documento"),
        };

        let Ok(_) = database.record_report_artifact(package_id, &artifact, later(1)) else {
            panic!("il primo artefatto deve potersi registrare");
        };
        assert!(matches!(
            database.record_report_artifact(package_id, &artifact, later(2)),
            Err(StorageError::DuplicateReportArtifact)
        ));
    }

    #[test]
    fn a_package_becomes_deliverable_only_when_completed() {
        let (mut database, _source_id, session_id) = database_with_session();
        let taken = snapshot(session_id, &[], &[1]);
        let Ok(package_id) = database.open_report_package(&new_package(session_id, 7), &taken)
        else {
            panic!("il pacchetto deve potersi aprire");
        };

        let Ok(()) = database.set_report_package_status(
            package_id,
            ReportGenerationStatus::Completed,
            Some(later(10)),
        ) else {
            panic!("il completamento deve potersi registrare");
        };

        let Ok(package) = database.report_package(package_id) else {
            panic!("il pacchetto deve potersi rileggere");
        };
        assert!(package.status.is_deliverable());
        assert_eq!(package.completed_at, Some(later(10)));
    }

    #[test]
    fn a_failed_package_carries_no_completion_instant() {
        // Il vincolo e' nello schema: uno stato diverso da 'completed' con un
        // istante di completamento sarebbe un pacchetto che dichiara di essere
        // finito e non lo e'.
        let (mut database, _source_id, session_id) = database_with_session();
        let taken = snapshot(session_id, &[], &[1]);
        let Ok(package_id) = database.open_report_package(&new_package(session_id, 8), &taken)
        else {
            panic!("il pacchetto deve potersi aprire");
        };

        let Ok(()) = database.set_report_package_status(
            package_id,
            ReportGenerationStatus::Failed,
            Some(later(10)),
        ) else {
            panic!("il fallimento deve potersi registrare");
        };

        let Ok(package) = database.report_package(package_id) else {
            panic!("il pacchetto deve potersi rileggere");
        };
        assert!(!package.status.is_deliverable());
        assert!(
            package.completed_at.is_none(),
            "un pacchetto non riuscito non ha un istante di completamento"
        );
    }

    #[test]
    fn an_unknown_package_is_reported_as_missing() {
        let (database, _source_id, _session_id) = database_with_session();
        assert!(matches!(
            database.report_package(ReportPackageId::new(999)),
            Err(StorageError::NotFound { .. })
        ));
    }

    #[test]
    fn the_packages_of_a_session_come_back_newest_first() {
        let (mut database, _source_id, session_id) = database_with_session();
        let taken = snapshot(session_id, &[], &[1]);

        let mut first = new_package(session_id, 10);
        first.requested_at = later(1);
        let mut second = new_package(session_id, 11);
        second.requested_at = later(5);

        let Ok(_) = database.open_report_package(&first, &taken) else {
            panic!("il primo pacchetto deve potersi aprire");
        };
        let Ok(_) = database.open_report_package(&second, &taken) else {
            panic!("il secondo pacchetto deve potersi aprire");
        };

        let Ok(packages) = database.session_report_packages(session_id) else {
            panic!("l'elenco deve potersi leggere");
        };
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].report_id.as_str(), "R-2026-000011");
    }

    #[test]
    fn a_snapshot_of_an_unknown_package_is_reported_as_missing() {
        let (database, _source_id, _session_id) = database_with_session();
        assert!(matches!(
            database.report_snapshot(ReportPackageId::new(4242)),
            Err(StorageError::NotFound { .. })
        ));
    }
}

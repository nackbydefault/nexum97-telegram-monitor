//! La copia cifrata dell'archivio, e la sua apertura (ENCRYPT-01, ADR-0175).
//!
//! # Perché esiste accanto alla copia di SEC-01
//!
//! La copia di [`crate::backup`] nasce del solo utente Windows, o non nasce:
//! su una chiavetta senza permessi si rifiuta. Questa nasce **cifrata**, e lì
//! i permessi non servono: chi trova il file senza la frase non legge niente.
//!
//! # Dove sta il chiaro
//!
//! La fotografia dell'archivio da cifrare nasce nella cartella di lavoro che
//! il chiamante indica — di norma la cartella dei dati, accanto all'archivio
//! vivo e con le sue protezioni — e si toglie appena cifrata, anche se
//! qualcosa va storto. Nella destinazione arriva soltanto il cifrato. La
//! verifica rilegge il cifrato **dalla destinazione**, lo decifra in memoria a
//! blocchi e ne confronta l'impronta con quella della fotografia: non scrive
//! chiaro da nessuna parte.
//!
//! # Aprire non è ripristinare
//!
//! [`BackupService::open_sealed_to`] produce una copia in chiaro del solo
//! utente, con la consegna di SEC-01, in una cartella che conserva i permessi.
//! Sostituire l'archivio vivo resta la procedura scritta nel foglio di ogni
//! copia: non è un pulsante.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use lisi_core::Timestamp;
use lisi_core::digest::{Sha256Digest, Sha256Writer};
use lisi_core::model::NewAuditEntry;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
pub use lisi_security::sealed_copy::{MIN_PHRASE_CHARS, Opener};
use lisi_security::sealed_copy::{SealedCopyError, Summary, open, seal};
use lisi_storage::Database;

use crate::backup::BackupService;
use crate::error::{ServiceError, ServiceResult};
use crate::protected_output::{Delivery, Existing};

/// Estensione della copia cifrata.
pub const SEALED_EXTENSION: &str = "nx97c";

/// Azione dell'audit di una copia cifrata scritta.
pub const SEALED_AUDIT_ACTION: &str = "copia_cifrata_prodotta";

/// Azione dell'audit di una copia cifrata non scritta o non aperta.
pub const SEALED_REFUSED_AUDIT_ACTION: &str = "copia_cifrata_rifiutata";

/// Azione dell'audit di una copia cifrata aperta.
pub const OPENED_AUDIT_ACTION: &str = "copia_cifrata_aperta";

/// Estensione dei file provvisori nella destinazione.
const PARTIAL_EXTENSION: &str = "parziale";

/// Ciò che si dice quando una copia aperta non si scrive per i permessi.
const NOT_OPENED: &str = "La copia aperta NON è stata scritta";

/// I file che `SQLite` può lasciare accanto a una fotografia o a una copia.
const JOURNAL_SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];

/// Che cosa è stato scritto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedBackup {
    /// La copia cifrata.
    pub archive: PathBuf,
    /// Il foglio accanto, che dice come si apre senza dire la frase.
    pub note: PathBuf,
    /// Byte dell'archivio in chiaro, cioè della fotografia cifrata.
    pub plaintext_bytes: u64,
    /// Impronta SHA-256 del file cifrato, scritta anche nel foglio.
    pub sealed_sha256: Sha256Digest,
    /// Se la copia si apre anche con l'utente Windows che l'ha fatta.
    pub user_key: bool,
}

impl SealedBackup {
    /// L'esito, in una frase che una persona legge.
    #[must_use]
    pub fn operator_message(&self) -> String {
        let mega = self.plaintext_bytes as f64 / (1024.0 * 1024.0);
        let mut testo = format!(
            "Copia cifrata scritta in «{}» ({mega:.0} MB di archivio). Il programma \
             l'ha riletta e aperta con esito positivo.",
            self.archive.display()
        );
        testo.push_str(
            " Si apre con la frase scelta adesso, su qualunque postazione con NEXUM/97. \
             La frase non è scritta da nessuna parte: senza la frase la copia non si apre.",
        );
        if self.user_key {
            testo.push_str(
                " Su questa postazione si apre anche senza frase, con lo stesso utente \
                 Windows.",
            );
        }
        testo
    }
}

/// Che cosa è stato aperto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedCopy {
    /// La copia in chiaro, del solo utente.
    pub archive: PathBuf,
    /// Byte della copia in chiaro.
    pub bytes: u64,
    /// Se la copia in chiaro si riapre ed è integra.
    pub verified: bool,
}

impl OpenedCopy {
    /// L'esito, in una frase che una persona legge.
    #[must_use]
    pub fn operator_message(&self) -> String {
        let rilettura = if self.verified {
            "Il programma l'ha riletta: è integra."
        } else {
            "La rilettura NON è riuscita: questa copia non va usata."
        };
        format!(
            "Copia aperta in «{}», leggibile dal solo utente Windows. {rilettura} \
             L'archivio in uso non è cambiato.",
            self.archive.display()
        )
    }
}

impl BackupService {
    /// Scrive una copia cifrata dell'archivio, e il suo foglio, nella cartella
    /// indicata.
    ///
    /// `work_directory` è dove nasce e muore la fotografia in chiaro: la
    /// cartella dei dati del programma, accanto all'archivio vivo.
    ///
    /// # Errori
    ///
    /// [`ServiceError::SealedCopyRefused`] per una frase troppo corta, una
    /// cartella che non esiste, un nome già presente, una fotografia che non
    /// si rilegge integra o un cifrato che non si decifra in ciò che era; un
    /// errore di archivio o di scrittura altrimenti. In ogni caso nella
    /// cartella scelta non resta nulla, e la fotografia è tolta.
    pub fn write_sealed_to(
        &self,
        directory: &Path,
        work_directory: &Path,
        phrase: &str,
        with_user_key: bool,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<SealedBackup> {
        let esito = self.seal_into(directory, work_directory, phrase, with_user_key, now);
        match esito {
            Ok(copia) => {
                self.database().append_audit(&NewAuditEntry {
                    actor: actor.clone(),
                    action: AuditAction::try_new(SEALED_AUDIT_ACTION)?,
                    entity: AuditEntity::try_new("archivio")?,
                    entity_id: None,
                    actor_mode: None,
                    detail: Some(AuditDetail::try_new(&format!(
                        "{} byte di archivio, cifrata e riletta, impronta del cifrato {}, {}",
                        copia.plaintext_bytes,
                        copia.sealed_sha256.as_str(),
                        if copia.user_key {
                            "si apre con la frase o con l'utente"
                        } else {
                            "si apre soltanto con la frase"
                        },
                    ))?),
                    recorded_at: now,
                })?;
                Ok(copia)
            }
            Err(errore) => {
                record(
                    self.database(),
                    actor,
                    now,
                    SEALED_REFUSED_AUDIT_ACTION,
                    &errore,
                );
                Err(errore)
            }
        }
    }

    fn seal_into(
        &self,
        directory: &Path,
        work_directory: &Path,
        phrase: &str,
        with_user_key: bool,
        now: Timestamp,
    ) -> ServiceResult<SealedBackup> {
        // LA FRASE PRIMA DI TUTTO: nessun byte si scrive per una frase che non
        // varrebbe.
        if phrase.chars().count() < MIN_PHRASE_CHARS {
            return Err(refused(format!(
                "la frase deve avere almeno {MIN_PHRASE_CHARS} caratteri"
            )));
        }
        if !directory.is_dir() {
            return Err(refused(format!(
                "«{}» non è una cartella",
                directory.display()
            )));
        }
        let radice = file_stem(now);
        let archivio = directory.join(format!("{radice}.{SEALED_EXTENSION}"));
        let foglio = directory.join(format!("{radice}.txt"));
        for definitivo in [&archivio, &foglio] {
            if definitivo.exists() {
                return Err(refused(format!(
                    "«{}» esiste già: una copia non ne sostituisce un'altra",
                    definitivo.display()
                )));
            }
        }

        // LA FOTOGRAFIA, accanto all'archivio vivo; si toglie comunque vada.
        let fotografia = Leftovers::new(
            work_directory.join(format!(".{radice}.fotografia.sqlite3")),
            true,
        );
        let esito = self.database().backup_to(fotografia.path())?;
        if !esito.verified {
            return Err(refused(String::from(
                "la fotografia dell'archivio non si rilegge integra",
            )));
        }
        let impronta_chiaro =
            Sha256Digest::of_reader(BufReader::new(File::open(fotografia.path()).map_err(io)?))
                .map_err(io)?;

        // IL CIFRATO, sotto un nome provvisorio nella destinazione.
        let provvisorio = Leftovers::new(
            directory.join(format!(".{radice}.{SEALED_EXTENSION}.{PARTIAL_EXTENSION}")),
            false,
        );
        let riassunto = {
            let uscita = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(provvisorio.path())
                .map_err(io)?;
            let mut scrittore = BufWriter::new(uscita);
            let riassunto = seal(
                BufReader::new(File::open(fotografia.path()).map_err(io)?),
                &mut scrittore,
                phrase,
                with_user_key,
            )
            .map_err(sealed_error)?;
            let uscita = scrittore
                .into_inner()
                .map_err(|errore| io(errore.into_error()))?;
            uscita.sync_all().map_err(io)?;
            riassunto
        };
        drop(fotografia);

        // LA VERIFICA, dalla destinazione e con la frase: nessun chiaro scritto.
        let mut impronta = Sha256Writer::new();
        let aperto: Summary = open(
            BufReader::new(File::open(provvisorio.path()).map_err(io)?),
            &mut impronta,
            &Opener::Phrase(phrase),
        )
        .map_err(sealed_error)?;
        if aperto != riassunto || impronta.finish() != impronta_chiaro {
            return Err(refused(String::from(
                "la copia cifrata, riletta, non è l'archivio da cui nasce",
            )));
        }
        let impronta_cifrato =
            Sha256Digest::of_reader(BufReader::new(File::open(provvisorio.path()).map_err(io)?))
                .map_err(io)?;

        // IL FOGLIO, poi i due arrivi: prima la copia, poi il foglio.
        let foglio_provvisorio = Leftovers::new(
            directory.join(format!(".{radice}.txt.{PARTIAL_EXTENSION}")),
            false,
        );
        let testo = crate::run_mode::marked_text(note_text(
            &archivio,
            riassunto.plaintext_bytes,
            &impronta_cifrato,
            with_user_key,
            now,
        ));
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(foglio_provvisorio.path())
                .map_err(io)?;
            file.write_all(testo.as_bytes()).map_err(io)?;
            file.sync_all().map_err(io)?;
        }
        provvisorio.arrive(&archivio)?;
        if let Err(errore) = foglio_provvisorio.arrive(&foglio) {
            // Una copia senza il suo foglio non resta: si toglie, e si dice.
            if let Err(resto) = std::fs::remove_file(&archivio) {
                tracing::warn!(%resto, "copia cifrata senza foglio non tolta");
            }
            return Err(errore);
        }

        Ok(SealedBackup {
            archive: archivio,
            note: foglio,
            plaintext_bytes: riassunto.plaintext_bytes,
            sealed_sha256: impronta_cifrato,
            user_key: with_user_key,
        })
    }

    /// Apre una copia cifrata in una copia in chiaro del solo utente, nella
    /// cartella indicata.
    ///
    /// # Errori
    ///
    /// [`ServiceError::SealedCopyRefused`] se il file non è una copia
    /// cifrata, se la chiave non si apre, se un blocco è alterato o se esiste
    /// già una copia con lo stesso nome; [`ServiceError::ProtectionNotGuaranteed`]
    /// se la cartella non conserva i permessi. Nella cartella scelta non resta
    /// nulla, nemmeno i blocchi decifrati prima di un rifiuto.
    pub fn open_sealed_to(
        &self,
        sealed: &Path,
        opener: &Opener<'_>,
        directory: &Path,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<OpenedCopy> {
        let esito = Self::open_into(sealed, opener, directory);
        match esito {
            Ok(copia) => {
                self.database().append_audit(&NewAuditEntry {
                    actor: actor.clone(),
                    action: AuditAction::try_new(OPENED_AUDIT_ACTION)?,
                    entity: AuditEntity::try_new("archivio")?,
                    entity_id: None,
                    actor_mode: None,
                    detail: Some(AuditDetail::try_new(&format!(
                        "{} byte, aperta {}, rilettura {}, del solo utente",
                        copia.bytes,
                        match opener {
                            Opener::Phrase(_) => "con la frase",
                            Opener::User => "con l'utente",
                        },
                        if copia.verified {
                            "riuscita"
                        } else {
                            "FALLITA"
                        },
                    ))?),
                    recorded_at: now,
                })?;
                Ok(copia)
            }
            Err(errore) => {
                record(
                    self.database(),
                    actor,
                    now,
                    SEALED_REFUSED_AUDIT_ACTION,
                    &errore,
                );
                Err(errore)
            }
        }
    }

    fn open_into(
        sealed: &Path,
        opener: &Opener<'_>,
        directory: &Path,
    ) -> ServiceResult<OpenedCopy> {
        let radice = sealed
            .file_stem()
            .and_then(|nome| nome.to_str())
            .map(|nome| format!("{nome}-aperta"))
            .ok_or_else(|| refused(String::from("il nome della copia non si legge")))?;
        let nome = format!("{radice}.sqlite3");
        if directory.join(&nome).exists() {
            return Err(refused(format!(
                "«{}» esiste già: una copia aperta non ne sostituisce un'altra",
                directory.join(&nome).display()
            )));
        }
        let ingresso = File::open(sealed).map_err(io)?;

        let mut consegna = Delivery::begin(directory, &radice, NOT_OPENED)?;
        // Un blocco decifrato e poi un blocco alterato lascerebbero mezzo
        // archivio: si toglie con il resto se la consegna non arriva.
        consegna.clean_also(&nome);
        for coda in JOURNAL_SUFFIXES {
            consegna.clean_also(&format!("{nome}{coda}"));
        }
        let percorso = consegna.staging_path(&nome);
        {
            let uscita = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&percorso)
                .map_err(io)?;
            let mut scrittore = BufWriter::new(uscita);
            open(BufReader::new(ingresso), &mut scrittore, opener).map_err(sealed_error)?;
            let uscita = scrittore
                .into_inner()
                .map_err(|errore| io(errore.into_error()))?;
            uscita.sync_all().map_err(io)?;
        }
        let bytes = std::fs::metadata(&percorso)
            .map(|dati| dati.len())
            .unwrap_or(0);
        let verified = Database::open(&percorso)
            .and_then(|copia| copia.verify_integrity())
            .is_ok_and(|rapporto| rapporto.is_healthy());
        consegna.adopt(&nome)?;
        let arrivati = consegna.deliver(Existing::Refuse)?;
        let archive = arrivati
            .files
            .into_iter()
            .next()
            .unwrap_or_else(|| directory.join(&nome));
        Ok(OpenedCopy {
            archive,
            bytes,
            verified,
        })
    }
}

/// Un file provvisorio che si toglie, se non arriva.
struct Leftovers {
    path: PathBuf,
    with_journal: bool,
    arrived: bool,
}

impl Leftovers {
    const fn new(path: PathBuf, with_journal: bool) -> Self {
        Self {
            path,
            with_journal,
            arrived: false,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// Porta il file al suo nome definitivo, che non deve esistere.
    fn arrive(mut self, definitivo: &Path) -> ServiceResult<()> {
        if definitivo.exists() {
            return Err(refused(format!(
                "«{}» esiste già: una copia non ne sostituisce un'altra",
                definitivo.display()
            )));
        }
        std::fs::rename(&self.path, definitivo).map_err(io)?;
        self.arrived = true;
        Ok(())
    }
}

impl Drop for Leftovers {
    fn drop(&mut self) {
        if self.arrived {
            return;
        }
        let mut da_togliere = vec![self.path.clone()];
        if self.with_journal {
            for coda in JOURNAL_SUFFIXES {
                let mut nome = self.path.clone().into_os_string();
                nome.push(coda);
                da_togliere.push(PathBuf::from(nome));
            }
        }
        for percorso in da_togliere {
            if percorso.exists()
                && let Err(resto) = std::fs::remove_file(&percorso)
            {
                tracing::warn!(%resto, "file provvisorio della copia cifrata non tolto");
            }
        }
    }
}

fn refused(reason: String) -> ServiceError {
    ServiceError::SealedCopyRefused { reason }
}

/// Un file che non si legge o non si scrive: il genere del guasto, mai il
/// percorso.
fn io(errore: std::io::Error) -> ServiceError {
    refused(format!(
        "un file non si è potuto leggere o scrivere ({})",
        errore.kind()
    ))
}

/// Un rifiuto della copia cifrata, in una frase per l'operatore.
fn sealed_error(errore: SealedCopyError) -> ServiceError {
    match errore {
        SealedCopyError::Io(errore) => io(errore),
        SealedCopyError::Security(errore) => ServiceError::from(errore),
        altro => refused(altro.to_string()),
    }
}

/// Registra il rifiuto: il fatto e il motivo, mai la frase.
fn record(database: &Database, actor: &Actor, now: Timestamp, action: &str, errore: &ServiceError) {
    let motivo = match errore {
        ServiceError::SealedCopyRefused { reason } => reason.clone(),
        altro => String::from(altro.kind()),
    };
    let registrato = AuditAction::try_new(action)
        .and_then(|action| {
            Ok((
                action,
                AuditEntity::try_new("archivio")?,
                AuditDetail::try_new(&motivo)?,
            ))
        })
        .map_err(ServiceError::from)
        .and_then(|(action, entity, detail)| {
            database
                .append_audit(&NewAuditEntry {
                    actor: actor.clone(),
                    action,
                    entity,
                    entity_id: None,
                    actor_mode: None,
                    detail: Some(detail),
                    recorded_at: now,
                })
                .map_err(ServiceError::from)
        });
    if let Err(guasto) = registrato {
        tracing::warn!(%guasto, "rifiuto della copia cifrata non registrato");
    }
}

/// Il nome della copia, con la data che si legge e che ordina.
fn file_stem(now: Timestamp) -> String {
    crate::run_mode::file_name(&format!(
        "nexum97-copia-cifrata-{}",
        now.to_file_stamp_utc()
    ))
}

/// Il testo del foglio: come si apre, senza la frase.
fn note_text(
    archive: &Path,
    plaintext_bytes: u64,
    sealed_sha256: &Sha256Digest,
    user_key: bool,
    now: Timestamp,
) -> String {
    let nome = archive
        .file_name()
        .and_then(|nome| nome.to_str())
        .unwrap_or("(nome non leggibile)");
    let utente = if user_key {
        "Sulla postazione che l'ha fatta si apre anche senza frase, con lo stesso\n\
         utente Windows.\n"
    } else {
        "Senza la frase non si apre, nemmeno sulla postazione che l'ha fatta.\n"
    };
    format!(
        "NEXUM/97 Telegram Monitor - copia cifrata dell'archivio\n\
         Ideazione e progettazione: Giuseppe LISI\n\
         \n\
         File:       {nome}\n\
         Archivio:   {plaintext_bytes} byte prima della cifratura\n\
         Prodotta:   {}\n\
         Impronta:   {} (SHA-256 del file cifrato)\n\
         \n\
         =================================================================\n\
         COME SI APRE\n\
         =================================================================\n\
         \n\
         Con NEXUM/97, «Apri una copia cifrata», e la frase scelta quando la\n\
         copia è stata fatta. {utente}\
         \n\
         La frase NON è scritta qui, né in nessun altro posto: il programma\n\
         non la conserva. Chi la perde perde la copia.\n\
         \n\
         Aprire non ripristina: produce una copia in chiaro, leggibile dal\n\
         solo utente Windows che la apre. Per rimetterla al posto\n\
         dell'archivio si segue la procedura di ripristino delle copie di\n\
         sicurezza scritta nel manuale dell'amministratore.\n\
         \n\
         =================================================================\n\
         CHE COSA QUESTA COPIA NON CONTIENE\n\
         =================================================================\n\
         \n\
         Le credenziali dell'account Telegram e la parola di sblocco della\n\
         postazione: restano su quella postazione e non si possono spostare.\n\
         Su una macchina nuova occorre rifare l'accesso a Telegram.\n\
         \n\
         =================================================================\n\
         CHE PROTEZIONE HA\n\
         =================================================================\n\
         \n\
         Il contenuto è cifrato: chi trova il file senza la frase non legge\n\
         niente, anche su una chiavetta senza permessi. Un byte cambiato o un\n\
         file tagliato non si aprono, e il programma lo dice.\n",
        now.to_readable_utc(),
        sealed_sha256.as_str(),
    )
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use lisi_core::Timestamp;
    use lisi_core::model::NewAuditEntry;
    use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
    use lisi_storage::Database;

    use super::{
        OPENED_AUDIT_ACTION, Opener, SEALED_AUDIT_ACTION, SEALED_REFUSED_AUDIT_ACTION, SealedBackup,
    };
    use crate::backup::BackupService;
    use crate::error::ServiceError;
    use crate::sources::open_in_memory_database;

    /// Una frase di prova, lunga abbastanza.
    const FRASE: &str = "una frase di prova abbastanza lunga";

    /// Una frase di prova diversa, lunga abbastanza.
    const ALTRA_FRASE: &str = "una seconda frase, diversa dalla prima";

    /// Un segno nell'archivio, per riconoscerlo dopo l'andata e il ritorno.
    const SEGNO: &str = "segno-di-prova-della-copia-cifrata";

    fn servizio() -> BackupService {
        let Ok(database) = open_in_memory_database() else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        let Ok(_) = database.append_audit(&NewAuditEntry {
            actor: attore(),
            action: azione("prova"),
            entity: entita(),
            entity_id: None,
            actor_mode: None,
            detail: AuditDetail::try_new(SEGNO).ok(),
            recorded_at: adesso(),
        }) else {
            panic!("il segno di prova deve potersi registrare");
        };
        BackupService::new(database)
    }

    fn azione(nome: &str) -> AuditAction {
        let Ok(azione) = AuditAction::try_new(nome) else {
            panic!("l'azione di prova deve essere valida");
        };
        azione
    }

    fn entita() -> AuditEntity {
        let Ok(entita) = AuditEntity::try_new("archivio") else {
            panic!("l'entità di prova deve essere valida");
        };
        entita
    }

    fn attore() -> Actor {
        let Ok(actor) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        actor
    }

    fn adesso() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn cartella() -> tempfile::TempDir {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        cartella
    }

    fn nomi_in(cartella: &Path) -> Vec<String> {
        let Ok(voci) = std::fs::read_dir(cartella) else {
            panic!("la cartella deve potersi elencare");
        };
        let mut nomi: Vec<String> = voci
            .filter_map(Result::ok)
            .map(|voce| voce.file_name().to_string_lossy().into_owned())
            .collect();
        nomi.sort();
        nomi
    }

    fn azioni(servizio: &BackupService) -> Vec<String> {
        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        voci.iter()
            .map(|voce| voce.action.as_str().to_owned())
            .collect()
    }

    fn dettagli(servizio: &BackupService) -> Vec<String> {
        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        voci.iter()
            .filter_map(|voce| voce.detail.as_ref())
            .map(|dettaglio| dettaglio.as_str().to_owned())
            .collect()
    }

    /// Una copia cifrata scritta in una cartella, con il lavoro in un'altra.
    fn sigilla(
        servizio: &BackupService,
        destinazione: &Path,
        lavoro: &Path,
        con_utente: bool,
    ) -> SealedBackup {
        match servizio.write_sealed_to(destinazione, lavoro, FRASE, con_utente, &attore(), adesso())
        {
            Ok(copia) => copia,
            Err(errore) => panic!("la copia cifrata deve potersi scrivere: {errore}"),
        }
    }

    /// Il segno di prova è nell'archivio aperto.
    fn contiene_il_segno(archivio: &Path) -> bool {
        let Ok(copia) = Database::open(archivio) else {
            panic!("la copia aperta deve potersi riaprire");
        };
        let Ok(voci) = copia.audit_entries() else {
            panic!("l'audit della copia aperta deve potersi leggere");
        };
        voci.iter().any(|voce| {
            voce.detail
                .as_ref()
                .is_some_and(|dettaglio| dettaglio.as_str() == SEGNO)
        })
    }

    /// **Andata e ritorno: la copia cifrata si apre con la frase, è integra e
    /// contiene ciò che c'era** (criteri 1 e 4).
    #[test]
    fn la_copia_cifrata_si_riapre_e_contiene_cio_che_c_era() {
        let (destinazione, lavoro, aperta) = (cartella(), cartella(), cartella());
        let servizio = servizio();
        let copia = sigilla(&servizio, destinazione.path(), lavoro.path(), false);
        assert!(copia.plaintext_bytes > 0);
        assert!(!copia.user_key);

        let aperto = match servizio.open_sealed_to(
            &copia.archive,
            &Opener::Phrase(FRASE),
            aperta.path(),
            &attore(),
            adesso(),
        ) {
            Ok(aperto) => aperto,
            Err(errore) => panic!("la copia cifrata deve potersi aprire: {errore}"),
        };
        assert!(aperto.verified);
        assert_eq!(aperto.bytes, copia.plaintext_bytes);
        assert!(contiene_il_segno(&aperto.archive));

        let azioni = azioni(&servizio);
        assert!(azioni.iter().any(|azione| azione == SEALED_AUDIT_ACTION));
        assert!(azioni.iter().any(|azione| azione == OPENED_AUDIT_ACTION));
    }

    /// **Nella destinazione arrivano la copia e il foglio, e nient'altro; la
    /// fotografia in chiaro non resta nella cartella di lavoro** (criterio 2).
    #[test]
    fn nella_destinazione_arrivano_soltanto_la_copia_e_il_foglio() {
        let (destinazione, lavoro) = (cartella(), cartella());
        let copia = sigilla(&servizio(), destinazione.path(), lavoro.path(), false);

        let mut attesi: Vec<String> = [&copia.archive, &copia.note]
            .iter()
            .filter_map(|percorso| percorso.file_name())
            .map(|nome| nome.to_string_lossy().into_owned())
            .collect();
        attesi.sort();
        assert_eq!(nomi_in(destinazione.path()), attesi);
        assert!(nomi_in(lavoro.path()).is_empty(), "la fotografia è rimasta");
        assert_eq!(
            copia
                .archive
                .extension()
                .and_then(|estensione| estensione.to_str()),
            Some(super::SEALED_EXTENSION)
        );
    }

    /// **Nel file cifrato non si legge l'archivio**: né l'intestazione di
    /// `SQLite`, né il segno scritto dentro (criterio 2).
    #[test]
    fn il_contenuto_dell_archivio_non_si_legge_nella_copia() {
        let (destinazione, lavoro) = (cartella(), cartella());
        let copia = sigilla(&servizio(), destinazione.path(), lavoro.path(), false);
        let Ok(byte) = std::fs::read(&copia.archive) else {
            panic!("la copia cifrata deve potersi leggere");
        };
        for chiaro in [b"SQLite format 3".as_slice(), SEGNO.as_bytes()] {
            assert!(
                !byte
                    .windows(chiaro.len())
                    .any(|finestra| finestra == chiaro),
                "nel cifrato si legge del chiaro"
            );
        }
        assert_eq!(
            lisi_core::digest::Sha256Digest::of_bytes(&byte),
            copia.sealed_sha256
        );
    }

    /// **Una frase corta non scrive niente, e il rifiuto si registra**
    /// (criterio 3).
    #[test]
    fn una_frase_corta_non_scrive_niente() {
        let (destinazione, lavoro) = (cartella(), cartella());
        let servizio = servizio();
        let esito = servizio.write_sealed_to(
            destinazione.path(),
            lavoro.path(),
            "troppo corta",
            false,
            &attore(),
            adesso(),
        );
        assert!(
            matches!(esito, Err(ServiceError::SealedCopyRefused { .. })),
            "{esito:?}"
        );
        assert!(nomi_in(destinazione.path()).is_empty());
        assert!(nomi_in(lavoro.path()).is_empty());
        assert!(
            azioni(&servizio)
                .iter()
                .any(|azione| azione == SEALED_REFUSED_AUDIT_ACTION)
        );
    }

    /// **Una copia non ne sostituisce un'altra, né all'andata né al ritorno.**
    #[test]
    fn una_copia_non_ne_sostituisce_un_altra() {
        let (destinazione, lavoro, aperta) = (cartella(), cartella(), cartella());
        let servizio = servizio();
        let copia = sigilla(&servizio, destinazione.path(), lavoro.path(), false);
        let Ok(prima) = std::fs::read(&copia.archive) else {
            panic!("la copia cifrata deve potersi leggere");
        };

        let di_nuovo = servizio.write_sealed_to(
            destinazione.path(),
            lavoro.path(),
            FRASE,
            false,
            &attore(),
            adesso(),
        );
        assert!(matches!(
            di_nuovo,
            Err(ServiceError::SealedCopyRefused { .. })
        ));
        assert_eq!(std::fs::read(&copia.archive).ok(), Some(prima));
        assert_eq!(nomi_in(destinazione.path()).len(), 2);

        let apri = || {
            servizio.open_sealed_to(
                &copia.archive,
                &Opener::Phrase(FRASE),
                aperta.path(),
                &attore(),
                adesso(),
            )
        };
        assert!(apri().is_ok());
        assert!(matches!(
            apri(),
            Err(ServiceError::SealedCopyRefused { .. })
        ));
        assert_eq!(nomi_in(aperta.path()).len(), 1);
    }

    /// **Una frase sbagliata non apre, e nella cartella scelta non resta
    /// niente** (criterio 5).
    #[test]
    fn una_frase_sbagliata_non_apre_e_non_lascia_niente() {
        let (destinazione, lavoro, aperta) = (cartella(), cartella(), cartella());
        let servizio = servizio();
        let copia = sigilla(&servizio, destinazione.path(), lavoro.path(), false);

        let esito = servizio.open_sealed_to(
            &copia.archive,
            &Opener::Phrase(ALTRA_FRASE),
            aperta.path(),
            &attore(),
            adesso(),
        );
        assert!(
            matches!(esito, Err(ServiceError::SealedCopyRefused { .. })),
            "{esito:?}"
        );
        assert!(
            nomi_in(aperta.path()).is_empty(),
            "{:?}",
            nomi_in(aperta.path())
        );
        assert!(
            azioni(&servizio)
                .iter()
                .any(|azione| azione == SEALED_REFUSED_AUDIT_ACTION)
        );
    }

    /// **Un byte cambiato in fondo non si apre, e i blocchi già decifrati
    /// prima del rifiuto non restano** (criterio 5).
    ///
    /// Il byte cambiato sta nell'ultimo blocco: i primi si decifrano e si
    /// scrivono, poi il rifiuto. Mezzo archivio in chiaro non deve restare.
    #[test]
    fn un_byte_cambiato_non_si_apre_e_non_lascia_mezzo_archivio() {
        let (destinazione, lavoro, aperta) = (cartella(), cartella(), cartella());
        let servizio = servizio();
        let copia = sigilla(&servizio, destinazione.path(), lavoro.path(), false);
        assert!(
            copia.plaintext_bytes > 2 * lisi_security::sealed_copy::CHUNK_BYTES as u64,
            "l'archivio di prova deve occupare più blocchi"
        );
        let Ok(mut byte) = std::fs::read(&copia.archive) else {
            panic!("la copia cifrata deve potersi leggere");
        };
        let ultimo = byte.len() - 20;
        byte[ultimo] ^= 0x01;
        let alterata: PathBuf = destinazione.path().join("alterata.nx97c");
        let Ok(()) = std::fs::write(&alterata, &byte) else {
            panic!("la copia alterata deve potersi scrivere");
        };

        let esito = servizio.open_sealed_to(
            &alterata,
            &Opener::Phrase(FRASE),
            aperta.path(),
            &attore(),
            adesso(),
        );
        assert!(
            matches!(esito, Err(ServiceError::SealedCopyRefused { .. })),
            "{esito:?}"
        );
        assert!(
            nomi_in(aperta.path()).is_empty(),
            "{:?}",
            nomi_in(aperta.path())
        );
    }

    /// **La frase non si scrive: né nel foglio, né nell'audit, né nel
    /// messaggio** (criterio 6).
    #[test]
    fn la_frase_non_si_scrive_da_nessuna_parte() {
        let (destinazione, lavoro, aperta) = (cartella(), cartella(), cartella());
        let servizio = servizio();
        let copia = sigilla(&servizio, destinazione.path(), lavoro.path(), false);
        let rifiuto = servizio.open_sealed_to(
            &copia.archive,
            &Opener::Phrase(ALTRA_FRASE),
            aperta.path(),
            &attore(),
            adesso(),
        );
        let Err(rifiuto) = rifiuto else {
            panic!("un'altra frase non deve aprire la copia");
        };

        let Ok(foglio) = std::fs::read_to_string(&copia.note) else {
            panic!("il foglio deve potersi leggere");
        };
        assert!(foglio.contains("COME SI APRE"), "{foglio}");
        assert!(foglio.contains(copia.sealed_sha256.as_str()), "{foglio}");
        assert!(foglio.contains("La frase NON è scritta qui"), "{foglio}");
        for testo in [
            foglio,
            copia.operator_message(),
            rifiuto.operator_message(),
            rifiuto.to_string(),
        ]
        .into_iter()
        .chain(dettagli(&servizio))
        {
            assert!(!testo.contains(FRASE), "la frase è scritta: {testo}");
            assert!(!testo.contains(ALTRA_FRASE), "la frase è scritta: {testo}");
        }
    }

    /// **Con la chiave dell'utente, la copia si apre senza frase sulla
    /// postazione che l'ha fatta** (criterio 4).
    #[cfg(windows)]
    #[test]
    fn con_la_chiave_dell_utente_si_apre_senza_frase() {
        let (destinazione, lavoro, aperta) = (cartella(), cartella(), cartella());
        let servizio = servizio();
        let copia = sigilla(&servizio, destinazione.path(), lavoro.path(), true);
        assert!(copia.user_key);
        assert!(copia.operator_message().contains("anche senza frase"));

        let aperto = match servizio.open_sealed_to(
            &copia.archive,
            &Opener::User,
            aperta.path(),
            &attore(),
            adesso(),
        ) {
            Ok(aperto) => aperto,
            Err(errore) => panic!("la copia deve aprirsi con l'utente: {errore}"),
        };
        assert!(aperto.verified);
        assert!(contiene_il_segno(&aperto.archive));
    }

    /// **La copia cifrata si scrive anche dove i permessi non reggono — è
    /// cifrata — ma lì non si apre in chiaro** (criteri 2 e 7; SEC-01).
    #[cfg(windows)]
    #[test]
    fn la_copia_cifrata_si_scrive_dove_i_permessi_non_reggono_ma_non_si_apre_li() {
        use crate::permessi_di_prova::cartella_che_rifiuta_i_permessi;

        let chiavetta = cartella_che_rifiuta_i_permessi();
        let lavoro = cartella();
        let servizio = servizio();
        let copia = sigilla(&servizio, chiavetta.path(), lavoro.path(), false);
        assert_eq!(nomi_in(chiavetta.path()).len(), 2);

        let esito = servizio.open_sealed_to(
            &copia.archive,
            &Opener::Phrase(FRASE),
            chiavetta.path(),
            &attore(),
            adesso(),
        );
        assert!(
            matches!(esito, Err(ServiceError::ProtectionNotGuaranteed { .. })),
            "{esito:?}"
        );
        assert_eq!(
            nomi_in(chiavetta.path()).len(),
            2,
            "{:?}",
            nomi_in(chiavetta.path())
        );
    }

    /// **La copia aperta è del solo utente, anche in una cartella che concede
    /// a tutti** (criterio 7; SEC-01). I permessi si leggono con .NET.
    #[cfg(windows)]
    #[test]
    fn la_copia_aperta_e_del_solo_utente_anche_in_una_cartella_aperta() {
        use crate::permessi_di_prova::{afferma_del_solo_utente, apri_come_nel_collaudo};

        let (destinazione, lavoro, aperta) = (cartella(), cartella(), cartella());
        apri_come_nel_collaudo(aperta.path());
        let servizio = servizio();
        let copia = sigilla(&servizio, destinazione.path(), lavoro.path(), false);
        let aperto = match servizio.open_sealed_to(
            &copia.archive,
            &Opener::Phrase(FRASE),
            aperta.path(),
            &attore(),
            adesso(),
        ) {
            Ok(aperto) => aperto,
            Err(errore) => panic!("la copia cifrata deve potersi aprire: {errore}"),
        };
        afferma_del_solo_utente(&aperto.archive);
        assert_eq!(
            nomi_in(aperta.path()).len(),
            1,
            "{:?}",
            nomi_in(aperta.path())
        );
    }
}

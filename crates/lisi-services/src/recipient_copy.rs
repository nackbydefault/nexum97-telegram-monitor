//! La copia cifrata di un pacchetto per chi lo riceve (ENCRYPT-02 parte 2,
//! ADR-0190, DEC-474).
//!
//! # L'ordine non è casuale
//!
//! 1. **Il pacchetto è integro** secondo il suo manifest: una copia di un
//!    pacchetto alterato non si fa.
//! 2. **Che cosa entra**: il manifest, i file che il manifest attesta, la sua
//!    firma e le copie firmate dei PDF quando ci sono. Nient'altro della
//!    cartella: un file che nessuno ha attestato non esce.
//! 3. **L'archivio zip**, in memoria, con i soli nomi dei file sotto il nome
//!    del pacchetto: nessun percorso della macchina.
//! 4. **La cifratura**, chiesta a Windows per il certificato di chi riceve
//!    (`lisi_platform::recipient_encryption`). Un rifiuto si registra con la
//!    sua frase.
//! 5. **La consegna**, del solo utente (SEC-02), nella cartella del pacchetto:
//!    il nome porta l'inizio dell'impronta del certificato, così due
//!    destinatari hanno due copie, e la stessa copia non si rifà sopra.
//! 6. **Il registro**: ogni tentativo su un pacchetto letto lascia una riga e
//!    una riga d'audit, anche un rifiuto.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use lisi_core::model::NewAuditEntry;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{Sha256Digest, Timestamp};
pub use lisi_platform::recipient_encryption::{RecipientCertificate, RecipientRefusal};
use lisi_storage::Database;
use lisi_storage::repository::recipient_copy::NewRecipientCopy;
pub use lisi_storage::repository::recipient_copy::StoredRecipientCopy;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipWriter};

use crate::document_signing::{signature_path, signed_pdf_name};
use crate::error::ServiceResult;
use crate::protected_output::{Delivery, Existing, record_refusal};
use crate::report_package::verify_package_manifest;

/// In fondo al nome della copia.
pub const RECIPIENT_COPY_SUFFIX: &str = ".zip.p7m";

/// Il pacchetto più grande che si cifra: Windows cifra in una volta sola, in
/// memoria.
pub const MAX_PACKAGE_BYTES: u64 = 512 * 1024 * 1024;

/// Il file di certificato più grande che si legge.
pub const MAX_CERTIFICATE_BYTES: u64 = 64 * 1024;

/// Il manifest più grande che si legge.
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Ciò che si dice quando la copia non si scrive per i permessi.
const COPY_NOT_WRITTEN: &str = "La copia per chi riceve NON è stata scritta";

/// Come si cifra: Windows, o una cifratura finta nelle prove.
type Cifratore = fn(&[u8], &[u8]) -> Result<Vec<u8>, RecipientRefusal>;

/// Com'è andata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientCopyOutcome {
    /// La copia è stata scritta.
    Written {
        /// Dove.
        copy: PathBuf,
        /// Per chi.
        subject: String,
        /// L'impronta della copia.
        sha256: Sha256Digest,
    },
    /// La copia non è stata scritta.
    NotWritten {
        /// Perché.
        reason: String,
    },
}

impl RecipientCopyOutcome {
    /// La frase per una persona.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match self {
            Self::Written { copy, subject, .. } => format!(
                "Copia cifrata per «{subject}» scritta: «{}». Si apre soltanto con la chiave \
                 di quel certificato.",
                copy.file_name()
                    .map(|nome| nome.to_string_lossy().into_owned())
                    .unwrap_or_default()
            ),
            Self::NotWritten { reason } => {
                format!("La copia per chi riceve non è stata scritta: {reason}")
            }
        }
    }
}

/// Legge il file del certificato di chi riceve, entro un limite.
///
/// # Errors
///
/// La frase per una persona, se il file non si legge o non è un certificato
/// che si possa usare.
pub fn read_certificate(file: &Path) -> Result<RecipientCertificate, String> {
    let troppo = || String::from("il file è troppo grande per essere un certificato");
    let dimensione = std::fs::metadata(file)
        .map_err(|errore| format!("il file non si legge: {errore}"))?
        .len();
    if dimensione > MAX_CERTIFICATE_BYTES {
        return Err(troppo());
    }
    let byte = std::fs::read(file).map_err(|errore| format!("il file non si legge: {errore}"))?;
    lisi_platform::recipient_encryption::read_recipient_certificate(&byte)
        .map_err(|rifiuto| rifiuto.operator_message())
}

/// Il servizio delle copie per chi riceve.
pub struct RecipientCopyService<'a> {
    database: &'a mut Database,
    encrypt: Cifratore,
}

impl<'a> RecipientCopyService<'a> {
    /// Il servizio, con la cifratura di Windows.
    #[must_use]
    pub fn new(database: &'a mut Database) -> Self {
        Self {
            database,
            encrypt: lisi_platform::recipient_encryption::encrypt_for_recipient,
        }
    }

    #[cfg(test)]
    fn with(database: &'a mut Database, encrypt: Cifratore) -> Self {
        Self { database, encrypt }
    }

    /// Le copie registrate, le più recenti prima.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn copies(&self, limit: usize) -> ServiceResult<Vec<StoredRecipientCopy>> {
        Ok(self.database.recipient_copies(limit)?)
    }

    /// Cifra il pacchetto del manifest indicato per il certificato di chi
    /// riceve, e lo consegna nella cartella del pacchetto.
    ///
    /// # Errori
    ///
    /// Un errore se l'archivio non si legge o non si scrive, o se la copia
    /// non arriva del solo utente. Ogni altro esito è un
    /// [`RecipientCopyOutcome`].
    pub fn encrypt_package(
        &mut self,
        manifest: &Path,
        recipient: &RecipientCertificate,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<RecipientCopyOutcome> {
        let Some(cartella) = manifest.parent() else {
            return Ok(non_scritta("l'elenco delle impronte non è in una cartella"));
        };
        let Some(nome_pacchetto) = cartella
            .file_name()
            .map(|nome| nome.to_string_lossy().into_owned())
        else {
            return Ok(non_scritta("la cartella del pacchetto non ha un nome"));
        };
        let byte_manifest = match leggi_entro(manifest, MAX_MANIFEST_BYTES) {
            Ok(byte) => byte,
            Err(motivo) => {
                return Ok(non_scritta(&format!(
                    "l'elenco delle impronte non si legge: {motivo}"
                )));
            }
        };
        let titolare = if recipient.subject.trim().is_empty() {
            String::from("(certificato senza nome)")
        } else {
            recipient
                .subject
                .chars()
                .filter(|carattere| !carattere.is_control())
                .take(512)
                .collect()
        };
        let riga = NewRecipientCopy {
            requested_by: actor.as_str().to_owned(),
            requested_at: now,
            package_name: nome_pacchetto.clone(),
            manifest_sha256: Sha256Digest::of_bytes(&byte_manifest).as_str().to_owned(),
            recipient_subject: titolare.clone(),
            recipient_sha256: esadecimale(&recipient.sha256),
            copy_name: None,
            copy_sha256: None,
            outcome: String::from("non_cifrata"),
            outcome_detail: None,
        };

        // 1. INTEGRO.
        let verifica = verify_package_manifest(manifest);
        if !verifica.is_intact() {
            return self.rifiuta(
                riga,
                &format!(
                    "il pacchetto non è integro, e non si cifra. {}",
                    verifica.operator_message()
                ),
                actor,
                now,
            );
        }

        // 2. CHE COSA ENTRA: soltanto ciò che il manifest attesta, e le sue
        // firme.
        let nome_manifest = manifest
            .file_name()
            .map(|nome| nome.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut nomi = vec![nome_manifest];
        for voce in &verifica.entries {
            nomi.push(voce.file_name.clone());
            let firmato = signed_pdf_name(&voce.file_name);
            if voce.file_name.ends_with(".pdf") && cartella.join(&firmato).is_file() {
                nomi.push(firmato);
            }
        }
        if let Some(firma) = signature_path(manifest)
            .file_name()
            .map(|nome| nome.to_string_lossy().into_owned())
            && cartella.join(&firma).is_file()
        {
            nomi.push(firma);
        }
        let mut file = Vec::with_capacity(nomi.len());
        let mut totale: u64 = 0;
        for nome in nomi {
            let byte = match leggi_entro(&cartella.join(&nome), MAX_PACKAGE_BYTES) {
                Ok(byte) => byte,
                Err(motivo) => {
                    return self.rifiuta(
                        riga,
                        &format!("«{nome}» non si legge: {motivo}"),
                        actor,
                        now,
                    );
                }
            };
            totale = totale.saturating_add(u64::try_from(byte.len()).unwrap_or(u64::MAX));
            if totale > MAX_PACKAGE_BYTES {
                return self.rifiuta(
                    riga,
                    "il pacchetto supera i 512 MiB che si cifrano in una volta",
                    actor,
                    now,
                );
            }
            file.push((nome, byte));
        }

        // 3. L'ARCHIVIO.
        let archivio = match zip_del_pacchetto(&nome_pacchetto, &file) {
            Ok(archivio) => archivio,
            Err(motivo) => {
                return self.rifiuta(
                    riga,
                    &format!("l'archivio non si compone: {motivo}"),
                    actor,
                    now,
                );
            }
        };
        drop(file);

        // 4. LA CIFRATURA.
        let cifrato = match (self.encrypt)(&archivio, &recipient.der) {
            Ok(cifrato) => cifrato,
            Err(rifiuto) => return self.rifiuta(riga, &rifiuto.operator_message(), actor, now),
        };
        drop(archivio);

        // 5. LA CONSEGNA.
        let nome_copia = format!(
            "{nome_pacchetto}.{}{RECIPIENT_COPY_SUFFIX}",
            &riga.recipient_sha256[..8]
        );
        if cartella.join(&nome_copia).exists() {
            return self.rifiuta(
                riga,
                "la copia per questo certificato c'è già, e non si rifà sopra",
                actor,
                now,
            );
        }
        let consegnata =
            Delivery::begin(cartella, &nome_copia, COPY_NOT_WRITTEN).and_then(|mut consegna| {
                consegna.write(&nome_copia, &cifrato)?;
                consegna.deliver(Existing::Refuse)
            });
        let consegnati = match consegnata {
            Ok(consegnati) => consegnati,
            Err(errore) => {
                record_refusal(
                    &*self.database,
                    actor,
                    now,
                    crate::protected_output::REFUSED_AUDIT_ACTION,
                    "pacchetto",
                    &errore,
                );
                self.rifiuta(riga, &errore.operator_message(), actor, now)?;
                return Err(errore);
            }
        };
        let copia = consegnati
            .files
            .into_iter()
            .next()
            .unwrap_or_else(|| cartella.join(&nome_copia));

        // 6. IL REGISTRO.
        let impronta = Sha256Digest::of_bytes(&cifrato);
        let mut riga = riga;
        riga.copy_name = Some(nome_copia);
        riga.copy_sha256 = Some(impronta.as_str().to_owned());
        riga.outcome = String::from("cifrata");
        let audit = audit_entry(
            actor,
            "copia_per_destinatario",
            &format!("{nome_pacchetto} per {titolare}"),
            now,
        )?;
        self.database.insert_recipient_copy(&riga, &audit)?;
        Ok(RecipientCopyOutcome::Written {
            copy: copia,
            subject: titolare,
            sha256: impronta,
        })
    }

    /// Scrive un tentativo non riuscito, e lo restituisce come esito.
    fn rifiuta(
        &mut self,
        mut riga: NewRecipientCopy,
        motivo: &str,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<RecipientCopyOutcome> {
        let motivo: String = motivo.chars().take(1000).collect();
        riga.outcome_detail = Some(motivo.clone());
        let audit = audit_entry(
            actor,
            "copia_per_destinatario_rifiutata",
            &format!("{}: {motivo}", riga.package_name),
            now,
        )?;
        self.database.insert_recipient_copy(&riga, &audit)?;
        Ok(non_scritta(&motivo))
    }
}

fn non_scritta(motivo: &str) -> RecipientCopyOutcome {
    RecipientCopyOutcome::NotWritten {
        reason: motivo.to_owned(),
    }
}

/// Legge un file entro un limite.
fn leggi_entro(file: &Path, limite: u64) -> Result<Vec<u8>, String> {
    let dimensione = std::fs::metadata(file)
        .map_err(|errore| errore.to_string())?
        .len();
    if dimensione > limite {
        return Err(String::from("è oltre la dimensione ammessa"));
    }
    std::fs::read(file).map_err(|errore| errore.to_string())
}

/// L'archivio zip del pacchetto: i file sotto il nome del pacchetto, con una
/// data fissa (la prima che il formato ammette), compressi.
fn zip_del_pacchetto(pacchetto: &str, file: &[(String, Vec<u8>)]) -> Result<Vec<u8>, String> {
    let mut archivio = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opzioni = SimpleFileOptions::default()
        .last_modified_time(DateTime::default())
        .unix_permissions(0o644)
        .compression_method(CompressionMethod::Deflated);
    for (nome, byte) in file {
        archivio
            .start_file(format!("{pacchetto}/{nome}"), opzioni)
            .map_err(|errore| errore.to_string())?;
        archivio
            .write_all(byte)
            .map_err(|errore| errore.to_string())?;
    }
    archivio
        .finish()
        .map(std::io::Cursor::into_inner)
        .map_err(|errore| errore.to_string())
}

fn esadecimale(byte: &[u8; 32]) -> String {
    byte.iter().map(|b| format!("{b:02x}")).collect()
}

fn audit_entry(
    actor: &Actor,
    action: &str,
    detail: &str,
    now: Timestamp,
) -> ServiceResult<NewAuditEntry> {
    let dettaglio: String = detail
        .chars()
        .filter(|carattere| !carattere.is_control())
        .take(240)
        .collect();
    Ok(NewAuditEntry {
        actor: actor.clone(),
        action: AuditAction::try_new(action)?,
        entity: AuditEntity::try_new("pacchetto")?,
        entity_id: None,
        actor_mode: None,
        detail: Some(AuditDetail::try_new(&dettaglio)?),
        recorded_at: now,
    })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use lisi_core::model::report::{ReportArtifactKind, ReportId};
    use lisi_core::text::Actor;
    use lisi_core::{Sha256Digest, Timestamp};
    use lisi_storage::Database;

    use super::{
        RecipientCertificate, RecipientCopyOutcome, RecipientCopyService, RecipientRefusal,
        read_certificate,
    };
    use crate::report_package::PackageWriter;

    /// La cifratura finta: dice di quale contenuto è, e lo porta con sé.
    fn cifra_finta(contenuto: &[u8], certificato: &[u8]) -> Result<Vec<u8>, RecipientRefusal> {
        let mut cifrato = b"cifrato per ".to_vec();
        cifrato.extend_from_slice(certificato);
        cifrato.push(b'\n');
        cifrato.extend_from_slice(contenuto);
        Ok(cifrato)
    }

    fn cifra_rifiutata(_: &[u8], _: &[u8]) -> Result<Vec<u8>, RecipientRefusal> {
        Err(RecipientRefusal::NotValidNow)
    }

    fn certificato(nome: &str) -> RecipientCertificate {
        let der = format!("certificato di {nome}").into_bytes();
        let mut sha256 = [0_u8; 32];
        let impronta = Sha256Digest::of_bytes(&der);
        for (indice, coppia) in impronta.as_str().as_bytes().chunks(2).enumerate().take(32) {
            sha256[indice] =
                u8::from_str_radix(std::str::from_utf8(coppia).unwrap_or("00"), 16).unwrap_or(0);
        }
        RecipientCertificate {
            subject: nome.to_owned(),
            issuer: String::from("Autorità di prova"),
            not_after_unix: 2_000_000_000,
            sha256,
            der,
        }
    }

    fn archivio() -> Database {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("l'archivio in memoria deve aprirsi");
        };
        database
    }

    fn persona() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("attore valido");
        };
        attore
    }

    fn adesso() -> Timestamp {
        Timestamp::from_millis(1_762_300_000_000)
    }

    fn cartella() -> tempfile::TempDir {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve crearsi");
        };
        cartella
    }

    /// Un pacchetto finito con un documento: il manifest e il documento.
    fn pacchetto(cartella: &Path) -> (PathBuf, PathBuf) {
        let Ok(mut scrittore) = PackageWriter::create(cartella, &ReportId::from_sequence(2026, 7))
        else {
            panic!("il pacchetto deve crearsi");
        };
        let documento = scrittore.layout().path(ReportArtifactKind::NarrativeDocx);
        let Ok(_) = scrittore.write(ReportArtifactKind::NarrativeDocx, b"relazione di prova")
        else {
            panic!("il documento deve scriversi");
        };
        let Ok(finito) = scrittore.finish(&persona(), adesso()) else {
            panic!("il pacchetto deve chiudersi");
        };
        (finito.manifest, documento)
    }

    fn esiti(database: &Database) -> Vec<String> {
        let Ok(copie) = database.recipient_copies(10) else {
            panic!("il registro si deve leggere");
        };
        copie.into_iter().map(|riga| riga.copy.outcome).collect()
    }

    #[test]
    fn la_copia_porta_il_pacchetto_attestato_e_si_registra() {
        let radice = cartella();
        let (manifest, documento) = pacchetto(radice.path());
        let cartella_pacchetto = manifest.parent().map(Path::to_path_buf).unwrap_or_default();
        // Un file che nessuno ha attestato non esce.
        let Ok(()) = std::fs::write(cartella_pacchetto.join("estraneo.txt"), b"non attestato")
        else {
            panic!("il file estraneo deve scriversi");
        };
        let mut database = archivio();
        let mut servizio = RecipientCopyService::with(&mut database, cifra_finta);
        let destinatario = certificato("Ufficio destinatario");

        let Ok(esito) = servizio.encrypt_package(&manifest, &destinatario, &persona(), adesso())
        else {
            panic!("il tentativo deve concludersi con un esito");
        };
        let RecipientCopyOutcome::Written {
            copy,
            subject,
            sha256,
        } = &esito
        else {
            panic!("la copia doveva scriversi: {esito:?}");
        };
        assert_eq!(subject, "Ufficio destinatario");
        assert_eq!(copy.parent(), Some(cartella_pacchetto.as_path()));
        let nome = copy
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        assert!(nome.ends_with(".zip.p7m"), "{nome}");
        let Ok(byte) = std::fs::read(copy) else {
            panic!("la copia si deve leggere");
        };
        assert_eq!(&Sha256Digest::of_bytes(&byte), sha256);
        assert!(byte.starts_with(b"cifrato per certificato di Ufficio destinatario\n"));
        let contiene = |testo: &str| byte.windows(testo.len()).any(|w| w == testo.as_bytes());
        let documento = documento
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        assert!(contiene(&documento), "il documento attestato entra");
        let nome_manifest = manifest
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        assert!(contiene(&nome_manifest), "il manifest entra");
        assert!(
            !contiene("estraneo.txt"),
            "ciò che non è attestato non entra"
        );
        assert!(
            !contiene(&radice.path().to_string_lossy()),
            "nessun percorso della macchina"
        );
        assert_eq!(esiti(&database), ["cifrata"]);
        assert!(!esito.operator_message().is_empty());
    }

    #[test]
    fn un_pacchetto_alterato_non_si_cifra() {
        let radice = cartella();
        let (manifest, documento) = pacchetto(radice.path());
        let Ok(()) = std::fs::write(&documento, b"relazione cambiata dopo") else {
            panic!("il documento deve potersi alterare");
        };
        let mut database = archivio();
        let mut servizio = RecipientCopyService::with(&mut database, cifra_finta);
        let Ok(esito) = servizio.encrypt_package(
            &manifest,
            &certificato("Ufficio destinatario"),
            &persona(),
            adesso(),
        ) else {
            panic!("il tentativo deve concludersi con un esito");
        };
        assert!(matches!(esito, RecipientCopyOutcome::NotWritten { .. }));
        assert_eq!(esiti(&database), ["non_cifrata"]);
    }

    #[test]
    fn due_destinatari_due_copie_e_nessuna_si_rifa_sopra() {
        let radice = cartella();
        let (manifest, _) = pacchetto(radice.path());
        let mut database = archivio();
        let mut servizio = RecipientCopyService::with(&mut database, cifra_finta);
        let primo = certificato("Primo ufficio");
        let secondo = certificato("Secondo ufficio");
        for (destinatario, scritta) in [(&primo, true), (&secondo, true), (&primo, false)] {
            let Ok(esito) = servizio.encrypt_package(&manifest, destinatario, &persona(), adesso())
            else {
                panic!("il tentativo deve concludersi con un esito");
            };
            assert_eq!(
                matches!(esito, RecipientCopyOutcome::Written { .. }),
                scritta,
                "{esito:?}"
            );
        }
        assert_eq!(esiti(&database), ["non_cifrata", "cifrata", "cifrata"]);
    }

    #[test]
    fn un_certificato_rifiutato_lascia_il_motivo_nel_registro() {
        let radice = cartella();
        let (manifest, _) = pacchetto(radice.path());
        let mut database = archivio();
        let mut servizio = RecipientCopyService::with(&mut database, cifra_rifiutata);
        let Ok(esito) = servizio.encrypt_package(
            &manifest,
            &certificato("Ufficio scaduto"),
            &persona(),
            adesso(),
        ) else {
            panic!("il tentativo deve concludersi con un esito");
        };
        let RecipientCopyOutcome::NotWritten { reason } = esito else {
            panic!("la copia non doveva scriversi");
        };
        assert_eq!(reason, RecipientRefusal::NotValidNow.operator_message());
        let Ok(copie) = servizio.copies(10) else {
            panic!("il registro si deve leggere");
        };
        assert_eq!(
            copie[0].copy.outcome_detail.as_deref(),
            Some(reason.as_str())
        );
        assert_eq!(copie[0].copy.copy_name, None);
    }

    #[test]
    fn un_file_che_non_e_un_certificato_si_dice() {
        let radice = cartella();
        let grande = radice.path().join("grande.cer");
        let Ok(()) = std::fs::write(&grande, vec![0_u8; 70 * 1024]) else {
            panic!("il file deve scriversi");
        };
        assert!(read_certificate(&grande).is_err_and(|frase| frase.contains("troppo grande")));
        assert!(read_certificate(&radice.path().join("manca.cer")).is_err());
    }
}

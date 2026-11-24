//! La firma dell'ufficio sui file che il programma consegna (SIGN-01 parte 2,
//! ADR-0181, DEC-463).
//!
//! # L'ordine non è casuale
//!
//! 1. **Prima di firmare, senza toccare Windows:** non in Esercitazione
//!    (DEC-463, decisione 9); un certificato scelto dall'amministratore
//!    (ADR-0181, decisione 3); il file si legge entro un limite; un pacchetto
//!    è integro secondo il suo manifest, e non è già firmato (decisione 6).
//! 2. **La firma**, chiesta a Windows con il certificato scelto
//!    (`lisi_platform::document_signing`). Un rifiuto di Windows si scrive nel
//!    registro con la sua frase.
//! 3. **La verifica**, sui byte da consegnare, con `detached_signature`: la
//!    firma è valida ed è del certificato scelto (decisione 7). Una firma che
//!    non si verifica non si consegna.
//! 4. **La consegna**, del solo utente (SEC-02): accanto al file, con lo
//!    stesso nome e `.p7s` in fondo (decisione 5). La relazione `.pdf` non ha
//!    una firma accanto ma una **copia firmata**, con la firma dentro e
//!    `.firmato.pdf` in fondo al nome (DEC-464, [`crate::pdf_signature`]): la
//!    firma si chiede senza istante, e si verifica rileggendola dalla copia.
//! 5. **Il registro:** ogni tentativo su un file letto lascia una riga e una
//!    riga d'audit, anche un rifiuto (decisione 8). Il registro dice il nome
//!    del file, mai la cartella.
//!
//! # Soltanto quando una persona lo chiede
//!
//! Nessuna firma parte da sola (ADR-0181, decisione 7): ogni funzione che
//! firma riceve chi l'ha chiesta.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use lisi_core::model::NewAuditEntry;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{OperatingMode, RestrictedAction, Sha256Digest, Timestamp};
use lisi_platform::DetachedVerdict;
use lisi_platform::detached_signature;
use lisi_platform::document_signing::{self as piattaforma, DetachedSignature, SigningRefusal};
pub use lisi_platform::document_signing::{RevocationKnowledge, SigningCertificate};
use lisi_storage::Database;
use lisi_storage::repository::document_signing::NewDocumentSignature;
pub use lisi_storage::repository::document_signing::{
    StoredDocumentSignature, StoredSigningCertificate,
};

use crate::error::{ServiceError, ServiceResult};
use crate::protected_output::{Delivery, Existing, record_refusal};
use crate::report_package::verify_package_manifest;

/// Dove sta la firma: accanto al file, con questo in fondo al nome.
pub const SIGNATURE_SUFFIX: &str = ".p7s";

/// Quanto può essere grande un manifest da firmare.
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;

/// Quanto può essere grande una relazione `.pdf` da firmare: lo stemma e
/// molte pagine ci stanno.
const MAX_PDF_BYTES: u64 = 64 * 1024 * 1024;

/// La copia firmata del PDF: accanto all'originale, con questo in fondo.
pub const SIGNED_PDF_SUFFIX: &str = ".firmato.pdf";

/// Quanto può essere grande una firma da rileggere.
const MAX_SIGNATURE_BYTES: u64 = 256 * 1024;

/// Ciò che si dice quando la firma non arriva per i permessi.
const SIGNATURE_NOT_WRITTEN: &str = "La firma NON è stata scritta";

/// La firma.
///
/// In produzione è sempre [`piattaforma::sign_detached`]: le prove ne passano
/// una che dice l'esito che serve, perché un certificato con la sua chiave
/// non si mette nell'archivio di Windows per una prova del servizio.
pub(crate) type Signer =
    fn(&[u8], &[u8; 32], Option<SystemTime>) -> Result<DetachedSignature, SigningRefusal>;

/// La verifica della firma separata: in produzione
/// [`detached_signature::verify_detached`].
pub(crate) type Verifier = fn(&[u8], &[u8]) -> DetachedVerdict;

/// I certificati con una chiave: in produzione
/// [`piattaforma::signing_certificates`].
pub(crate) type Lister = fn() -> Vec<SigningCertificate>;

/// Che cosa si firma.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedKind {
    /// Il manifest di un pacchetto di relazione.
    PackageManifest,
    /// Un dizionario esportato.
    ExportedDictionary,
    /// La relazione `.pdf` di un pacchetto: se ne firma una copia.
    ReportPdf,
}

impl SignedKind {
    /// La forma conservata nel registro.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PackageManifest => "manifest",
            Self::ExportedDictionary => "dizionario",
            Self::ReportPdf => "pdf",
        }
    }

    /// Quanto può essere grande il file.
    const fn limite(self) -> u64 {
        match self {
            Self::PackageManifest => MAX_MANIFEST_BYTES,
            Self::ExportedDictionary => lisi_core::model::dictionary::MAX_IMPORT_BYTES as u64,
            Self::ReportPdf => MAX_PDF_BYTES,
        }
    }
}

/// Che cosa esce da una firma, e su che cosa la firma si verifica.
struct Consegna<'b> {
    kind: SignedKind,
    cartella: &'b Path,
    /// Il nome del file che si consegna.
    nome: &'b str,
    /// I byte del file che si consegna.
    byte: &'b [u8],
    /// I byte che la firma copre.
    firmato: &'b [u8],
    /// La firma CMS.
    cms: &'b [u8],
    revocation: RevocationKnowledge,
}

/// Com'è andata una firma.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningOutcome {
    /// La firma è stata scritta accanto al file, e si è verificata.
    Signed {
        /// Il file della firma.
        signature: PathBuf,
        /// Il titolare del certificato.
        subject: String,
        /// Che cosa la postazione sa della revoca.
        revocation: RevocationKnowledge,
    },
    /// Il file non è stato firmato.
    NotSigned {
        /// Perché, in parole per l'operatore.
        reason: String,
    },
}

impl SigningOutcome {
    /// La frase per l'operatore.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match self {
            Self::Signed {
                signature,
                subject,
                revocation,
            } => {
                let nome = signature
                    .file_name()
                    .map(|nome| nome.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let revoca = match revocation {
                    RevocationKnowledge::NotRevoked => {
                        "Secondo le liste che la postazione ha, il certificato non è revocato."
                    }
                    RevocationKnowledge::Unknown => {
                        "La postazione non sa se il certificato è stato revocato: lo dice anche \
                         il registro."
                    }
                };
                if nome.ends_with(SIGNATURE_SUFFIX) {
                    format!(
                        "Firmato con il certificato di «{subject}». La firma sta in «{nome}», \
                         accanto al file. {revoca}"
                    )
                } else {
                    format!(
                        "Firmato con il certificato di «{subject}». La copia firmata è «{nome}», \
                         accanto al file. {revoca}"
                    )
                }
            }
            Self::NotSigned { reason } => format!("Il file non è stato firmato: {reason}"),
        }
    }
}

/// Che cosa si sa della firma accanto a un file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureCheck {
    /// Accanto al file non c'è una firma.
    Absent,
    /// La firma è valida.
    Valid {
        /// Se è del certificato scelto dall'ufficio.
        by_chosen_certificate: bool,
        /// L'impronta SHA-256 del certificato del firmatario.
        certificate_sha256: String,
    },
    /// La firma c'è e non è valida.
    NotValid {
        /// Perché, in parole per l'operatore.
        reason: String,
    },
}

impl SignatureCheck {
    /// La frase per l'operatore.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match self {
            Self::Absent => String::from("Accanto al file non c'è una firma."),
            Self::Valid {
                by_chosen_certificate: true,
                ..
            } => String::from("La firma è valida, ed è del certificato scelto dall'ufficio."),
            Self::Valid {
                by_chosen_certificate: false,
                ..
            } => String::from("La firma è valida, ma non è del certificato scelto dall'ufficio."),
            Self::NotValid { reason } => reason.clone(),
        }
    }
}

/// Il servizio della firma dell'ufficio.
pub struct DocumentSigningService<'a> {
    database: &'a mut Database,
    sign: Signer,
    verify: Verifier,
    list: Lister,
}

impl<'a> DocumentSigningService<'a> {
    /// Costruisce il servizio sull'archivio, con la firma, la verifica e
    /// l'elenco di Windows.
    #[must_use]
    pub fn new(database: &'a mut Database) -> Self {
        Self {
            database,
            sign: piattaforma::sign_detached,
            verify: detached_signature::verify_detached,
            list: piattaforma::signing_certificates,
        }
    }

    /// Costruisce il servizio con funzioni che dicono l'esito che serve.
    #[cfg(test)]
    pub(crate) fn with(
        database: &'a mut Database,
        sign: Signer,
        verify: Verifier,
        list: Lister,
    ) -> Self {
        Self {
            database,
            sign,
            verify,
            list,
        }
    }

    /// I certificati dell'archivio personale con una chiave, fra cui
    /// l'amministratore sceglie. Nessuna chiave si apre per elencarli.
    #[must_use]
    pub fn certificates(&self) -> Vec<SigningCertificate> {
        (self.list)()
    }

    /// Il certificato scelto, se c'è.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn chosen_certificate(&self) -> ServiceResult<Option<StoredSigningCertificate>> {
        Ok(self.database.signing_certificate()?)
    }

    /// Sceglie il certificato per impronta SHA-256, o lo toglie passando
    /// `None` o un'impronta vuota.
    ///
    /// L'impronta si può scrivere con maiuscole, spazi o due punti, come la
    /// mostrano gli strumenti di Windows. Deve essere quella di un certificato
    /// con una chiave dell'archivio personale di questo utente: il nome del
    /// titolare si prende da lì.
    ///
    /// # Errori
    ///
    /// [`ServiceError::ActionReservedToAdministrator`] in modalità operatore,
    /// [`ServiceError::SigningCertificateRefused`] per un'impronta non valida
    /// o di un certificato che non c'è, o un errore se la scrittura non
    /// riesce. Un rifiuto lascia il certificato di prima.
    pub fn choose_certificate(
        &mut self,
        sha256: Option<&str>,
        mode: OperatingMode,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        if !mode.allows(RestrictedAction::ChooseSigningCertificate) {
            return Err(ServiceError::ActionReservedToAdministrator {
                action: RestrictedAction::ChooseSigningCertificate,
            });
        }
        let rifiuto = |reason: &str| ServiceError::SigningCertificateRefused {
            reason: reason.to_owned(),
        };

        let pulita: String = sha256
            .unwrap_or_default()
            .chars()
            .filter(|carattere| !carattere.is_whitespace() && *carattere != ':')
            .collect();
        let scelto = if pulita.is_empty() {
            None
        } else {
            let Ok(impronta) = Sha256Digest::from_hex(&pulita.to_ascii_lowercase()) else {
                return Err(rifiuto(
                    "un'impronta è fatta di 64 cifre da 0 a 9 e lettere da a a f, quelle del certificato",
                ));
            };
            let impronta = impronta.as_str().to_owned();
            let Some(certificato) = (self.list)()
                .into_iter()
                .find(|certificato| esadecimale(&certificato.sha256) == impronta)
            else {
                return Err(rifiuto(
                    "nell'archivio personale di questo utente di Windows non c'è un certificato \
                     con questa impronta e con una chiave",
                ));
            };
            let titolare: String = certificato
                .subject
                .chars()
                .filter(|carattere| !carattere.is_control())
                .take(512)
                .collect();
            Some(StoredSigningCertificate {
                sha256: impronta,
                subject: if titolare.trim().is_empty() {
                    String::from("titolare senza nome")
                } else {
                    titolare
                },
            })
        };

        let audit = audit_entry(
            actor,
            "certificato_firma_scelto",
            if scelto.is_some() {
                "indicato"
            } else {
                "tolto"
            },
            Some(mode),
            now,
        )?;
        self.database
            .save_signing_certificate(scelto.as_ref(), actor, &audit)?;
        Ok(())
    }

    /// Le firme e i tentativi, dal più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn signatures(&self) -> ServiceResult<Vec<StoredDocumentSignature>> {
        Ok(self.database.document_signatures()?)
    }

    /// Firma il manifest di un pacchetto di relazione finito.
    ///
    /// # Errori
    ///
    /// [`ServiceError::SigningInExercise`] in Esercitazione,
    /// [`ServiceError::SigningCertificateMissing`] senza un certificato
    /// scelto: in entrambi i casi non si chiede niente a Windows. Un errore se
    /// l'archivio non si legge o non si scrive, o se la firma non arriva del
    /// solo utente. Ogni altro esito è un [`SigningOutcome`].
    pub fn sign_package(
        &mut self,
        manifest: &Path,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<SigningOutcome> {
        self.sign_file(
            SignedKind::PackageManifest,
            manifest,
            crate::run_mode::is_exercise(),
            actor,
            now,
        )
    }

    /// Firma un dizionario esportato. La firma di prima, se c'era, si
    /// sostituisce: l'esportazione ha sostituito il dizionario.
    ///
    /// # Errori
    ///
    /// Come [`Self::sign_package`].
    pub fn sign_exported_dictionary(
        &mut self,
        dictionary: &Path,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<SigningOutcome> {
        self.sign_file(
            SignedKind::ExportedDictionary,
            dictionary,
            crate::run_mode::is_exercise(),
            actor,
            now,
        )
    }

    /// Rilegge la firma accanto a un file: se manca, se è valida e di chi, o
    /// perché non lo è. Non scrive niente.
    #[must_use]
    pub fn check_signature(&self, file: &Path) -> SignatureCheck {
        let firma_percorso = signature_path(file);
        if !firma_percorso.exists() {
            return SignatureCheck::Absent;
        }
        let (Ok(firma), Ok(contenuto)) = (
            read_capped(&firma_percorso, MAX_SIGNATURE_BYTES),
            read_capped(file, SignedKind::ExportedDictionary.limite()),
        ) else {
            return SignatureCheck::NotValid {
                reason: String::from("La firma o il file non si leggono."),
            };
        };
        match (self.verify)(&contenuto, &firma) {
            DetachedVerdict::Verified { signer_certificate } => {
                let impronta = Sha256Digest::of_bytes(&signer_certificate)
                    .as_str()
                    .to_owned();
                let scelto = self
                    .database
                    .signing_certificate()
                    .ok()
                    .flatten()
                    .is_some_and(|scelto| scelto.sha256 == impronta);
                SignatureCheck::Valid {
                    by_chosen_certificate: scelto,
                    certificate_sha256: impronta,
                }
            }
            altro => SignatureCheck::NotValid {
                reason: altro.operator_message(),
            },
        }
    }

    /// Il percorso comune: controlli, firma, verifica, consegna, registro.
    pub(crate) fn sign_file(
        &mut self,
        kind: SignedKind,
        path: &Path,
        exercise: bool,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<SigningOutcome> {
        let (scelto, impronta_scelta) = self.prima_di_firmare(exercise)?;

        let (Some(cartella), Some(nome)) = (
            path.parent(),
            path.file_name()
                .map(|nome| nome.to_string_lossy().into_owned()),
        ) else {
            return Ok(non_firmato("il percorso non indica un file"));
        };
        let contenuto = match read_capped(path, kind.limite()) {
            Ok(byte) => byte,
            Err(motivo) => return Ok(non_firmato(&format!("«{nome}» non si legge: {motivo}"))),
        };
        let riga = NewDocumentSignature {
            requested_by: actor.as_str().to_owned(),
            requested_at: now,
            kind: kind.as_str().to_owned(),
            file_name: nome.clone(),
            file_sha256: Sha256Digest::of_bytes(&contenuto).as_str().to_owned(),
            certificate_sha256: scelto.sha256.clone(),
            revocation: None,
            outcome: String::from("non_firmato"),
            outcome_detail: None,
        };
        let nome_firma = format!("{nome}{SIGNATURE_SUFFIX}");

        if kind == SignedKind::PackageManifest {
            let verifica = verify_package_manifest(path);
            if !verifica.is_intact() {
                return self.rifiuta(
                    riga,
                    &format!(
                        "il pacchetto non è integro, e non si firma. {}",
                        verifica.operator_message()
                    ),
                    actor,
                    now,
                );
            }
            if cartella.join(&nome_firma).exists() {
                return self.rifiuta(
                    riga,
                    "il pacchetto è già firmato, e una firma non ne sostituisce un'altra",
                    actor,
                    now,
                );
            }
        }

        // L'istante si mette nella firma del file separato (CAdES B-B).
        let istante = SystemTime::UNIX_EPOCH
            + Duration::from_millis(u64::try_from(now.as_millis()).unwrap_or(0));
        let firmata = match (self.sign)(&contenuto, &impronta_scelta, Some(istante)) {
            Ok(firmata) => firmata,
            Err(rifiuto) => {
                return self.rifiuta(riga, &rifiuto.operator_message(), actor, now);
            }
        };

        self.verifica_e_consegna(
            Consegna {
                kind,
                cartella,
                nome: &nome_firma,
                byte: &firmata.signature,
                firmato: &contenuto,
                cms: &firmata.signature,
                revocation: firmata.revocation,
            },
            scelto,
            riga,
            actor,
            now,
        )
    }

    /// Firma una copia della relazione `.pdf` di un pacchetto finito, con la
    /// firma dentro (PAdES B-B, DEC-464). La relazione resta com'è; la copia
    /// sta accanto a lei, con `.firmato.pdf` in fondo al nome.
    ///
    /// # Errori
    ///
    /// Come [`Self::sign_package`].
    pub fn sign_report_pdf(
        &mut self,
        manifest: &Path,
        pdf_name: &str,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<SigningOutcome> {
        self.sign_pdf(
            manifest,
            pdf_name,
            crate::run_mode::is_exercise(),
            actor,
            now,
        )
    }

    /// Il percorso della copia firmata del PDF: controlli, preparazione,
    /// firma, verifica, consegna, registro.
    pub(crate) fn sign_pdf(
        &mut self,
        manifest: &Path,
        pdf_name: &str,
        exercise: bool,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<SigningOutcome> {
        let (scelto, impronta_scelta) = self.prima_di_firmare(exercise)?;

        // Soltanto un nome, accanto al manifest: mai un percorso.
        let nome_valido = Path::new(pdf_name)
            .file_name()
            .is_some_and(|nome| nome == pdf_name)
            && pdf_name.to_ascii_lowercase().ends_with(".pdf");
        let Some(cartella) = manifest.parent().filter(|_| nome_valido) else {
            return Ok(non_firmato("il nome non indica un PDF del pacchetto"));
        };
        let percorso = cartella.join(pdf_name);
        let contenuto = match read_capped(&percorso, SignedKind::ReportPdf.limite()) {
            Ok(byte) => byte,
            Err(motivo) => {
                return Ok(non_firmato(&format!("«{pdf_name}» non si legge: {motivo}")));
            }
        };
        let riga = NewDocumentSignature {
            requested_by: actor.as_str().to_owned(),
            requested_at: now,
            kind: SignedKind::ReportPdf.as_str().to_owned(),
            file_name: pdf_name.to_owned(),
            file_sha256: Sha256Digest::of_bytes(&contenuto).as_str().to_owned(),
            certificate_sha256: scelto.sha256.clone(),
            revocation: None,
            outcome: String::from("non_firmato"),
            outcome_detail: None,
        };

        let verifica = verify_package_manifest(manifest);
        if !verifica.is_intact() {
            return self.rifiuta(
                riga,
                &format!(
                    "il pacchetto non è integro, e il PDF non si firma. {}",
                    verifica.operator_message()
                ),
                actor,
                now,
            );
        }
        if !verifica
            .entries
            .iter()
            .any(|voce| voce.file_name == pdf_name)
        {
            return self.rifiuta(
                riga,
                "il PDF non è fra i documenti dell'elenco delle impronte del pacchetto",
                actor,
                now,
            );
        }
        let nome_copia = signed_pdf_name(pdf_name);
        if cartella.join(&nome_copia).exists() {
            return self.rifiuta(
                riga,
                "la copia firmata c'è già, e una firma non ne sostituisce un'altra",
                actor,
                now,
            );
        }

        let preparato = match crate::pdf_signature::prepare(&contenuto, now) {
            Ok(preparato) => preparato,
            Err(motivo) => return self.rifiuta(riga, &motivo.operator_message(), actor, now),
        };
        // Nessun istante nel CMS: dentro il PDF sta in `/M` (ADR-0181,
        // decisione 2).
        let firmata = match (self.sign)(&preparato.signed_content(), &impronta_scelta, None) {
            Ok(firmata) => firmata,
            Err(rifiuto) => {
                return self.rifiuta(riga, &rifiuto.operator_message(), actor, now);
            }
        };
        let copia = match preparato.fill(&firmata.signature) {
            Ok(copia) => copia,
            Err(motivo) => return self.rifiuta(riga, &motivo.operator_message(), actor, now),
        };
        // La verifica rilegge la firma dalla copia da consegnare, non da ciò
        // che si è appena chiesto: è la copia che esce.
        let Some(letta) = crate::pdf_signature::read_signature(&copia) else {
            return self.rifiuta(
                riga,
                "la firma scritta nella copia non si rilegge, e la copia non è stata consegnata",
                actor,
                now,
            );
        };
        self.verifica_e_consegna(
            Consegna {
                kind: SignedKind::ReportPdf,
                cartella,
                nome: &nome_copia,
                byte: &copia,
                firmato: &letta.signed_content,
                cms: &letta.cms,
                revocation: firmata.revocation,
            },
            scelto,
            riga,
            actor,
            now,
        )
    }

    /// Non in Esercitazione, e con un certificato scelto: prima di tutto, e
    /// senza chiedere niente a Windows.
    fn prima_di_firmare(
        &self,
        exercise: bool,
    ) -> ServiceResult<(StoredSigningCertificate, [u8; 32])> {
        if exercise {
            return Err(ServiceError::SigningInExercise);
        }
        let Some(scelto) = self.database.signing_certificate()? else {
            return Err(ServiceError::SigningCertificateMissing);
        };
        let Some(impronta) = byte_dell_impronta(&scelto.sha256) else {
            return Err(ServiceError::SigningCertificateMissing);
        };
        Ok((scelto, impronta))
    }

    /// La verifica, la consegna del solo utente e il registro: comuni a
    /// tutto ciò che si firma.
    fn verifica_e_consegna(
        &mut self,
        consegna: Consegna<'_>,
        scelto: StoredSigningCertificate,
        mut riga: NewDocumentSignature,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<SigningOutcome> {
        let Consegna {
            kind,
            cartella,
            nome: nome_uscita,
            byte,
            firmato,
            cms,
            revocation,
        } = consegna;

        // PRIMA DI CONSEGNARE, LA VERIFICA: valida, e del certificato scelto.
        match (self.verify)(firmato, cms) {
            DetachedVerdict::Verified { signer_certificate }
                if Sha256Digest::of_bytes(&signer_certificate).as_str() == scelto.sha256 => {}
            DetachedVerdict::Verified { .. } => {
                return self.rifiuta(
                    riga,
                    "la firma scritta non è del certificato scelto, e non è stata consegnata",
                    actor,
                    now,
                );
            }
            altro => {
                return self.rifiuta(
                    riga,
                    &format!(
                        "la firma scritta non si verifica, e non è stata consegnata. {}",
                        altro.operator_message()
                    ),
                    actor,
                    now,
                );
            }
        }

        let esistente = match kind {
            SignedKind::PackageManifest | SignedKind::ReportPdf => Existing::Refuse,
            SignedKind::ExportedDictionary => Existing::Replace,
        };
        let consegnata = Delivery::begin(cartella, nome_uscita, SIGNATURE_NOT_WRITTEN).and_then(
            |mut consegna| {
                consegna.write(nome_uscita, byte)?;
                consegna.deliver(esistente)
            },
        );
        let consegnati = match consegnata {
            Ok(consegnati) => consegnati,
            Err(errore) => {
                record_refusal(
                    &*self.database,
                    actor,
                    now,
                    crate::protected_output::REFUSED_AUDIT_ACTION,
                    "firma",
                    &errore,
                );
                self.rifiuta(riga, &errore.operator_message(), actor, now)?;
                return Err(errore);
            }
        };
        let firma = consegnati
            .files
            .into_iter()
            .next()
            .unwrap_or_else(|| cartella.join(nome_uscita));

        let revoca = match revocation {
            RevocationKnowledge::NotRevoked => "non_revocato",
            RevocationKnowledge::Unknown => "non_saputo",
        };
        riga.revocation = Some(revoca.to_owned());
        riga.outcome = String::from("firmato");
        let audit = audit_entry(
            actor,
            "documento_firmato",
            &format!("{}: {}, revoca {revoca}", kind.as_str(), riga.file_name),
            None,
            now,
        )?;
        self.database.insert_document_signature(&riga, &audit)?;
        Ok(SigningOutcome::Signed {
            signature: firma,
            subject: scelto.subject,
            revocation,
        })
    }

    /// Scrive un tentativo non riuscito, e lo restituisce come esito.
    fn rifiuta(
        &mut self,
        mut riga: NewDocumentSignature,
        motivo: &str,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<SigningOutcome> {
        let motivo: String = motivo.chars().take(1000).collect();
        riga.outcome_detail = Some(motivo.clone());
        let audit = audit_entry(
            actor,
            "documento_non_firmato",
            &format!("{}: {motivo}", riga.kind),
            None,
            now,
        )?;
        self.database.insert_document_signature(&riga, &audit)?;
        Ok(non_firmato(&motivo))
    }
}

/// Il percorso della firma accanto a un file.
#[must_use]
pub fn signature_path(file: &Path) -> PathBuf {
    let mut nome = file.as_os_str().to_owned();
    nome.push(SIGNATURE_SUFFIX);
    PathBuf::from(nome)
}

/// Il nome della copia firmata di un PDF: `relazione.pdf` diventa
/// `relazione.firmato.pdf`.
#[must_use]
pub fn signed_pdf_name(pdf_name: &str) -> String {
    let radice = pdf_name
        .len()
        .checked_sub(".pdf".len())
        .and_then(|fine| pdf_name.get(..fine))
        .unwrap_or(pdf_name);
    format!("{radice}{SIGNED_PDF_SUFFIX}")
}

fn non_firmato(motivo: &str) -> SigningOutcome {
    SigningOutcome::NotSigned {
        reason: motivo.to_owned(),
    }
}

/// L'impronta in esadecimale minuscolo.
fn esadecimale(byte: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    byte.iter().fold(String::with_capacity(64), |mut testo, b| {
        let _ = write!(testo, "{b:02x}");
        testo
    })
}

/// I byte di un'impronta scritta in esadecimale.
fn byte_dell_impronta(testo: &str) -> Option<[u8; 32]> {
    if testo.len() != 64 || !testo.is_ascii() {
        return None;
    }
    let mut byte = [0_u8; 32];
    for (indice, coppia) in byte.iter_mut().enumerate() {
        *coppia = u8::from_str_radix(testo.get(indice * 2..indice * 2 + 2)?, 16).ok()?;
    }
    Some(byte)
}

/// Legge un file, rifiutando quelli oltre il limite.
fn read_capped(path: &Path, limite: u64) -> Result<Vec<u8>, String> {
    let dati = std::fs::metadata(path).map_err(|errore| format!("{}", errore.kind()))?;
    if !dati.is_file() {
        return Err(String::from("non è un file"));
    }
    if dati.len() > limite {
        return Err(String::from("è più grande di quanto si firma"));
    }
    std::fs::read(path).map_err(|errore| format!("{}", errore.kind()))
}

/// Una riga d'audit di questo modulo.
fn audit_entry(
    actor: &Actor,
    action: &str,
    detail: &str,
    mode: Option<OperatingMode>,
    now: Timestamp,
) -> ServiceResult<NewAuditEntry> {
    // Un dettaglio lungo si accorcia: il registro ha la frase intera.
    let dettaglio: String = detail.chars().take(240).collect();
    Ok(NewAuditEntry {
        actor: actor.clone(),
        action: AuditAction::try_new(action)?,
        entity: AuditEntity::try_new("firma")?,
        entity_id: None,
        actor_mode: mode,
        detail: Some(AuditDetail::try_new(&dettaglio)?),
        recorded_at: now,
    })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::SystemTime;

    use lisi_core::model::report::{ReportArtifactKind, ReportId};
    use lisi_core::text::Actor;
    use lisi_core::{OperatingMode, RestrictedAction, Sha256Digest, Timestamp};
    use lisi_platform::DetachedVerdict;
    use lisi_platform::document_signing::{DetachedSignature, SigningRefusal};
    use lisi_storage::Database;

    use super::{
        DocumentSigningService, RevocationKnowledge, SignatureCheck, SignedKind,
        SigningCertificate, SigningOutcome, Verifier, byte_dell_impronta, signature_path,
    };
    use crate::error::ServiceError;
    use crate::report_package::PackageWriter;

    /// Il certificato di prova: bastano dei byte, perché la firma e la
    /// verifica sono finte.
    const CERTIFICATO: &[u8] = b"certificato di prova dell'ufficio";

    fn impronta_del_certificato() -> String {
        Sha256Digest::of_bytes(CERTIFICATO).as_str().to_owned()
    }

    fn elenco() -> Vec<SigningCertificate> {
        let Some(sha256) = byte_dell_impronta(&impronta_del_certificato()) else {
            panic!("l'impronta di prova è valida");
        };
        vec![SigningCertificate {
            subject: String::from("Ufficio di prova"),
            issuer: String::from("Autorità di prova"),
            not_after_unix: 2_000_000_000,
            sha256,
        }]
    }

    /// La firma finta: dice di quale contenuto è.
    fn firma_di(contenuto: &[u8]) -> Vec<u8> {
        let mut firma = b"firma:".to_vec();
        firma.extend_from_slice(Sha256Digest::of_bytes(contenuto).as_str().as_bytes());
        firma
    }

    fn firma_buona(
        contenuto: &[u8],
        _: &[u8; 32],
        _: Option<SystemTime>,
    ) -> Result<DetachedSignature, SigningRefusal> {
        Ok(DetachedSignature {
            signature: firma_di(contenuto),
            signer_certificate: CERTIFICATO.to_vec(),
            revocation: RevocationKnowledge::Unknown,
        })
    }

    fn firma_rifiutata(
        _: &[u8],
        _: &[u8; 32],
        _: Option<SystemTime>,
    ) -> Result<DetachedSignature, SigningRefusal> {
        Err(SigningRefusal::Revoked)
    }

    fn firma_vietata(
        _: &[u8],
        _: &[u8; 32],
        _: Option<SystemTime>,
    ) -> Result<DetachedSignature, SigningRefusal> {
        panic!("non si doveva chiedere niente a Windows");
    }

    fn verifica_buona(contenuto: &[u8], firma: &[u8]) -> DetachedVerdict {
        if firma == firma_di(contenuto).as_slice() {
            DetachedVerdict::Verified {
                signer_certificate: CERTIFICATO.to_vec(),
            }
        } else {
            DetachedVerdict::ContentMismatch
        }
    }

    fn verifica_d_altri(_: &[u8], _: &[u8]) -> DetachedVerdict {
        DetachedVerdict::Verified {
            signer_certificate: b"un altro certificato".to_vec(),
        }
    }

    fn verifica_fallita(_: &[u8], _: &[u8]) -> DetachedVerdict {
        DetachedVerdict::ContentMismatch
    }

    fn archivio() -> Database {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("l'archivio in memoria deve aprirsi");
        };
        database
    }

    fn persona() -> Actor {
        let Ok(attore) = Actor::try_new("amministratore.prova") else {
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

    /// Un pacchetto finito, con un documento: restituisce il manifest e il
    /// documento.
    fn pacchetto(cartella: &Path, numero: u32) -> (PathBuf, PathBuf) {
        let Ok(mut scrittore) =
            PackageWriter::create(cartella, &ReportId::from_sequence(2026, numero))
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

    fn scegli(servizio: &mut DocumentSigningService<'_>) {
        let Ok(()) = servizio.choose_certificate(
            Some(&impronta_del_certificato()),
            OperatingMode::Administrator,
            &persona(),
            adesso(),
        ) else {
            panic!("il certificato deve potersi scegliere");
        };
    }

    fn firma_il_manifest(
        servizio: &mut DocumentSigningService<'_>,
        manifest: &Path,
    ) -> SigningOutcome {
        let Ok(esito) = servizio.sign_file(
            SignedKind::PackageManifest,
            manifest,
            false,
            &persona(),
            adesso(),
        ) else {
            panic!("il tentativo deve concludersi con un esito");
        };
        esito
    }

    /// **La scelta del certificato è dell'amministratore** (DEC-463,
    /// decisione 1): l'operatore riceve il rifiuto dal servizio, e niente si
    /// scrive. L'impronta si scrive anche come la mostra Windows.
    #[test]
    fn la_scelta_del_certificato_e_dell_amministratore() {
        let mut database = archivio();
        let mut servizio =
            DocumentSigningService::with(&mut database, firma_vietata, verifica_buona, elenco);

        let come_windows = impronta_del_certificato()
            .to_ascii_uppercase()
            .as_bytes()
            .chunks(2)
            .map(|coppia| String::from_utf8_lossy(coppia).into_owned())
            .collect::<Vec<_>>()
            .join(":");
        assert!(matches!(
            servizio.choose_certificate(
                Some(&come_windows),
                OperatingMode::Operator,
                &persona(),
                adesso()
            ),
            Err(ServiceError::ActionReservedToAdministrator {
                action: RestrictedAction::ChooseSigningCertificate
            })
        ));
        assert_eq!(servizio.chosen_certificate().ok(), Some(None));

        let Ok(()) = servizio.choose_certificate(
            Some(&come_windows),
            OperatingMode::Administrator,
            &persona(),
            adesso(),
        ) else {
            panic!("l'amministratore sceglie");
        };
        let Ok(Some(scelto)) = servizio.chosen_certificate() else {
            panic!("il certificato scelto deve rileggersi");
        };
        assert_eq!(scelto.sha256, impronta_del_certificato());
        assert_eq!(scelto.subject, "Ufficio di prova");
    }

    /// **Si sceglie soltanto un certificato che c'è** (DEC-463, decisione 3):
    /// un'impronta storta o di un certificato assente si rifiuta, e resta il
    /// certificato di prima.
    #[test]
    fn un_certificato_che_non_c_e_non_si_sceglie() {
        let mut database = archivio();
        let mut servizio =
            DocumentSigningService::with(&mut database, firma_vietata, verifica_buona, elenco);
        scegli(&mut servizio);

        for sbagliata in ["f".repeat(64), String::from("non è un'impronta")] {
            assert!(
                matches!(
                    servizio.choose_certificate(
                        Some(&sbagliata),
                        OperatingMode::Administrator,
                        &persona(),
                        adesso()
                    ),
                    Err(ServiceError::SigningCertificateRefused { .. })
                ),
                "«{sbagliata}» va rifiutata"
            );
        }
        let Ok(Some(scelto)) = servizio.chosen_certificate() else {
            panic!("resta il certificato di prima");
        };
        assert_eq!(scelto.sha256, impronta_del_certificato());
    }

    /// **Senza certificato non si firma, e in Esercitazione neppure** (DEC-463,
    /// decisioni 3 e 9): a Windows non si chiede niente, il registro resta
    /// vuoto.
    #[test]
    fn senza_certificato_o_in_esercitazione_non_si_firma() {
        let cartella = cartella();
        let (manifest, _) = pacchetto(cartella.path(), 1);
        let mut database = archivio();
        let mut servizio =
            DocumentSigningService::with(&mut database, firma_vietata, verifica_buona, elenco);

        assert!(matches!(
            servizio.sign_file(
                SignedKind::PackageManifest,
                &manifest,
                false,
                &persona(),
                adesso()
            ),
            Err(ServiceError::SigningCertificateMissing)
        ));
        scegli(&mut servizio);
        assert!(matches!(
            servizio.sign_file(
                SignedKind::PackageManifest,
                &manifest,
                true,
                &persona(),
                adesso()
            ),
            Err(ServiceError::SigningInExercise)
        ));
        assert_eq!(servizio.signatures().map(|firme| firme.len()).ok(), Some(0));
        assert!(!signature_path(&manifest).exists());
    }

    /// **Un pacchetto si firma accanto al manifest** (DEC-463, decisioni 5, 7
    /// e 8): la firma è quella verificata, il registro dice il nome del file e
    /// che la revoca non si sa, e la firma si rilegge come dell'ufficio.
    #[test]
    fn un_pacchetto_si_firma_accanto_al_manifest() {
        let cartella = cartella();
        let (manifest, _) = pacchetto(cartella.path(), 2);
        let mut database = archivio();
        let mut servizio =
            DocumentSigningService::with(&mut database, firma_buona, verifica_buona, elenco);
        scegli(&mut servizio);

        let esito = firma_il_manifest(&mut servizio, &manifest);
        let SigningOutcome::Signed {
            signature,
            subject,
            revocation,
        } = &esito
        else {
            panic!("il pacchetto doveva firmarsi: {}", esito.operator_message());
        };
        assert_eq!(signature, &signature_path(&manifest));
        assert_eq!(subject, "Ufficio di prova");
        assert_eq!(*revocation, RevocationKnowledge::Unknown);
        assert!(esito.operator_message().contains("non sa se"));
        let (Ok(contenuto), Ok(firma)) = (std::fs::read(&manifest), std::fs::read(signature))
        else {
            panic!("manifest e firma devono leggersi");
        };
        assert_eq!(firma, firma_di(&contenuto));

        let Ok(firme) = servizio.signatures() else {
            panic!("il registro deve leggersi");
        };
        assert_eq!(firme.len(), 1);
        assert_eq!(firme[0].outcome, "firmato");
        assert_eq!(firme[0].kind, "manifest");
        assert_eq!(firme[0].revocation.as_deref(), Some("non_saputo"));
        assert_eq!(
            Some(firme[0].file_name.as_str()),
            manifest.file_name().and_then(|nome| nome.to_str())
        );
        assert_eq!(
            firme[0].file_sha256,
            Sha256Digest::of_bytes(&contenuto).as_str()
        );
        assert!(matches!(
            servizio.check_signature(&manifest),
            SignatureCheck::Valid {
                by_chosen_certificate: true,
                ..
            }
        ));
    }

    /// **Un pacchetto già firmato non si rifirma, e uno alterato non si
    /// firma** (DEC-463, decisione 6): entrambi lasciano una riga con il
    /// motivo, e la firma di prima resta com'era.
    #[test]
    fn un_pacchetto_gia_firmato_o_alterato_non_si_firma() {
        let cartella = cartella();
        let (manifest, documento) = pacchetto(cartella.path(), 3);
        let mut database = archivio();
        let mut servizio =
            DocumentSigningService::with(&mut database, firma_buona, verifica_buona, elenco);
        scegli(&mut servizio);

        assert!(matches!(
            firma_il_manifest(&mut servizio, &manifest),
            SigningOutcome::Signed { .. }
        ));
        let Ok(prima) = std::fs::read(signature_path(&manifest)) else {
            panic!("la firma deve leggersi");
        };
        let di_nuovo = firma_il_manifest(&mut servizio, &manifest);
        assert!(
            di_nuovo.operator_message().contains("già firmato"),
            "{}",
            di_nuovo.operator_message()
        );

        let Ok(()) = std::fs::write(&documento, b"relazione cambiata dopo") else {
            panic!("il documento deve potersi cambiare");
        };
        let alterato = firma_il_manifest(&mut servizio, &manifest);
        assert!(
            alterato.operator_message().contains("non è integro"),
            "{}",
            alterato.operator_message()
        );
        assert_eq!(std::fs::read(signature_path(&manifest)).ok(), Some(prima));

        let Ok(firme) = servizio.signatures() else {
            panic!("il registro deve leggersi");
        };
        let esiti: Vec<&str> = firme.iter().map(|firma| firma.outcome.as_str()).collect();
        assert_eq!(esiti, ["non_firmato", "non_firmato", "firmato"]);
    }

    /// **Una firma che non si verifica non si consegna** (DEC-463, decisione
    /// 7): né una che non corrisponde al file, né una valida di un altro
    /// certificato. Il registro dice perché.
    #[test]
    fn una_firma_che_non_si_verifica_non_si_consegna() {
        let casi: [(Verifier, &str); 2] = [
            (verifica_fallita, "non si verifica"),
            (verifica_d_altri, "non è del certificato scelto"),
        ];
        for (verifica, motivo) in casi {
            let cartella = cartella();
            let (manifest, _) = pacchetto(cartella.path(), 4);
            let mut database = archivio();
            let mut servizio =
                DocumentSigningService::with(&mut database, firma_buona, verifica, elenco);
            scegli(&mut servizio);

            let esito = firma_il_manifest(&mut servizio, &manifest);
            assert!(
                matches!(&esito, SigningOutcome::NotSigned { reason } if reason.contains(motivo)),
                "{}",
                esito.operator_message()
            );
            assert!(
                !signature_path(&manifest).exists(),
                "la firma non doveva arrivare"
            );
            let Ok(firme) = servizio.signatures() else {
                panic!("il registro deve leggersi");
            };
            assert_eq!(firme.len(), 1);
            assert_eq!(firme[0].revocation, None);
            assert!(
                firme[0]
                    .outcome_detail
                    .as_deref()
                    .is_some_and(|dettaglio| dettaglio.contains(motivo))
            );
        }
    }

    /// **Un rifiuto di Windows si scrive nel registro con la sua frase**
    /// (DEC-463, decisione 8).
    #[test]
    fn un_rifiuto_di_windows_si_scrive_nel_registro() {
        let cartella = cartella();
        let (manifest, _) = pacchetto(cartella.path(), 5);
        let mut database = archivio();
        let mut servizio =
            DocumentSigningService::with(&mut database, firma_rifiutata, verifica_buona, elenco);
        scegli(&mut servizio);

        let frase = SigningRefusal::Revoked.operator_message();
        assert_eq!(
            firma_il_manifest(&mut servizio, &manifest),
            SigningOutcome::NotSigned {
                reason: frase.clone()
            }
        );
        let Ok(firme) = servizio.signatures() else {
            panic!("il registro deve leggersi");
        };
        assert_eq!(firme.len(), 1);
        assert_eq!(firme[0].outcome_detail.as_deref(), Some(frase.as_str()));
        assert!(!signature_path(&manifest).exists());
    }

    /// **La firma di un dizionario esportato si sostituisce con lui, e si
    /// rilegge** (DEC-463, decisioni 6 e 10): una firma accanto a un file
    /// cambiato non è valida, e senza firma si dice che manca.
    #[test]
    fn il_dizionario_esportato_si_firma_e_la_firma_si_rilegge() {
        let cartella = cartella();
        let dizionario = cartella.path().join("parole.txt");
        let mut database = archivio();
        let mut servizio =
            DocumentSigningService::with(&mut database, firma_buona, verifica_buona, elenco);
        scegli(&mut servizio);
        let firma = |servizio: &mut DocumentSigningService<'_>, testo: &[u8]| {
            let Ok(()) = std::fs::write(&dizionario, testo) else {
                panic!("il dizionario deve scriversi");
            };
            let Ok(esito) = servizio.sign_file(
                SignedKind::ExportedDictionary,
                &dizionario,
                false,
                &persona(),
                adesso(),
            ) else {
                panic!("il tentativo deve concludersi con un esito");
            };
            assert!(
                matches!(esito, SigningOutcome::Signed { .. }),
                "{}",
                esito.operator_message()
            );
        };

        assert_eq!(
            servizio.check_signature(&dizionario),
            SignatureCheck::Absent
        );
        firma(&mut servizio, b"prima versione");
        firma(&mut servizio, b"seconda versione");
        assert_eq!(
            std::fs::read(signature_path(&dizionario)).ok(),
            Some(firma_di(b"seconda versione"))
        );
        assert!(matches!(
            servizio.check_signature(&dizionario),
            SignatureCheck::Valid {
                by_chosen_certificate: true,
                ..
            }
        ));

        let Ok(()) = std::fs::write(&dizionario, b"cambiato dopo la firma") else {
            panic!("il dizionario deve potersi cambiare");
        };
        assert!(matches!(
            servizio.check_signature(&dizionario),
            SignatureCheck::NotValid { .. }
        ));
        let Ok(firme) = servizio.signatures() else {
            panic!("il registro deve leggersi");
        };
        assert!(firme.iter().all(|firma| firma.kind == "dizionario"));
        assert_eq!(firme.len(), 2);
    }

    /// La firma finta di un PDF: con la forma DER che la rilettura cerca.
    fn cms_di(contenuto: &[u8]) -> Vec<u8> {
        let corpo = firma_di(contenuto);
        let mut cms = vec![0x30, u8::try_from(corpo.len()).unwrap_or(0)];
        cms.extend_from_slice(&corpo);
        cms
    }

    fn firma_pdf(
        contenuto: &[u8],
        _: &[u8; 32],
        istante: Option<SystemTime>,
    ) -> Result<DetachedSignature, SigningRefusal> {
        assert!(istante.is_none(), "nel CMS di un PDF non va l'istante");
        Ok(DetachedSignature {
            signature: cms_di(contenuto),
            signer_certificate: CERTIFICATO.to_vec(),
            revocation: RevocationKnowledge::NotRevoked,
        })
    }

    fn verifica_pdf(contenuto: &[u8], firma: &[u8]) -> DetachedVerdict {
        if firma == cms_di(contenuto).as_slice() {
            DetachedVerdict::Verified {
                signer_certificate: CERTIFICATO.to_vec(),
            }
        } else {
            DetachedVerdict::ContentMismatch
        }
    }

    /// Un pacchetto finito con una relazione `.pdf` vera: restituisce il
    /// manifest e la relazione.
    fn pacchetto_con_pdf(cartella: &Path, numero: u32) -> (PathBuf, PathBuf) {
        let relazione = crate::report_narrative::NarrativeReport {
            generated_at: adesso(),
            letterhead: crate::report_narrative::Letterhead {
                emblem: None,
                lines: Vec::new(),
            },
            footer: Vec::new(),
            blocks: vec![crate::report_narrative::Block::Paragraph(String::from(
                "Relazione di prova",
            ))],
        };
        let Ok(pdf) = crate::report_pdf::render(&relazione, crate::report_pdf::PdfKind::Narrative)
        else {
            panic!("la relazione deve scriversi");
        };
        let Ok(mut scrittore) =
            PackageWriter::create(cartella, &ReportId::from_sequence(2026, numero))
        else {
            panic!("il pacchetto deve crearsi");
        };
        let documento = scrittore.layout().path(ReportArtifactKind::NarrativePdf);
        let Ok(_) = scrittore.write(ReportArtifactKind::NarrativePdf, &pdf) else {
            panic!("la relazione deve scriversi nel pacchetto");
        };
        let Ok(finito) = scrittore.finish(&persona(), adesso()) else {
            panic!("il pacchetto deve chiudersi");
        };
        (finito.manifest, documento)
    }

    fn nome_di(percorso: &Path) -> String {
        percorso
            .file_name()
            .map(|nome| nome.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    fn firma_la_relazione(
        servizio: &mut DocumentSigningService<'_>,
        manifest: &Path,
        nome: &str,
    ) -> SigningOutcome {
        let Ok(esito) = servizio.sign_pdf(manifest, nome, false, &persona(), adesso()) else {
            panic!("il tentativo deve concludersi con un esito");
        };
        esito
    }

    /// **La relazione si firma in una copia accanto** (DEC-464, decisioni 1,
    /// 4 e 7): la relazione e il manifest restano com'erano, la copia comincia
    /// con i byte della relazione, la firma dentro si rilegge e copre la
    /// copia, il registro scrive il genere `pdf` e il nome della relazione.
    #[test]
    fn la_relazione_pdf_si_firma_in_una_copia_accanto() {
        let cartella = cartella();
        let (manifest, relazione) = pacchetto_con_pdf(cartella.path(), 31);
        let (Ok(prima), Ok(manifest_prima)) = (std::fs::read(&relazione), std::fs::read(&manifest))
        else {
            panic!("il pacchetto si legge");
        };
        let mut database = archivio();
        let mut servizio =
            DocumentSigningService::with(&mut database, firma_pdf, verifica_pdf, elenco);
        scegli(&mut servizio);

        let nome = nome_di(&relazione);
        let esito = firma_la_relazione(&mut servizio, &manifest, &nome);
        let SigningOutcome::Signed { signature, .. } = &esito else {
            panic!("la relazione si firma: {esito:?}");
        };
        assert_eq!(nome_di(signature), super::signed_pdf_name(&nome));
        assert!(nome_di(signature).ends_with(".firmato.pdf"));
        assert!(esito.operator_message().contains("copia firmata"));

        assert_eq!(std::fs::read(&relazione).ok(), Some(prima.clone()));
        assert_eq!(std::fs::read(&manifest).ok(), Some(manifest_prima));
        assert!(crate::report_package::verify_package_manifest(&manifest).is_intact());

        let Ok(copia) = std::fs::read(signature) else {
            panic!("la copia si legge");
        };
        assert!(copia.starts_with(&prima));
        let Some(letta) = crate::pdf_signature::read_signature(&copia) else {
            panic!("la firma dentro la copia si rilegge");
        };
        assert_eq!(letta.cms, cms_di(&letta.signed_content));

        let Ok(firme) = servizio.signatures() else {
            panic!("il registro si legge");
        };
        assert_eq!(firme.len(), 1);
        assert_eq!(firme[0].kind, "pdf");
        assert_eq!(firme[0].file_name, nome);
        assert_eq!(firme[0].outcome, "firmato");
        assert_eq!(
            firme[0].file_sha256,
            Sha256Digest::of_bytes(&prima).as_str()
        );
    }

    /// **Si firma soltanto la relazione del pacchetto, integro, una volta**
    /// (DEC-464, decisioni 1 e 6): un PDF fuori dal manifest, una copia già
    /// fatta, un pacchetto alterato si rifiutano e si scrivono; un nome con
    /// una cartella non si legge nemmeno; in Esercitazione non si chiede
    /// niente a Windows.
    #[test]
    fn un_pdf_fuori_dal_pacchetto_o_gia_firmato_non_si_firma() {
        let cartella = cartella();
        let (manifest, relazione) = pacchetto_con_pdf(cartella.path(), 32);
        let nome = nome_di(&relazione);
        let mut database = archivio();
        {
            let mut servizio =
                DocumentSigningService::with(&mut database, firma_vietata, verifica_pdf, elenco);
            scegli(&mut servizio);
            assert!(matches!(
                servizio.sign_pdf(&manifest, &nome, true, &persona(), adesso()),
                Err(ServiceError::SigningInExercise)
            ));
            for nome in ["..\\relazione.pdf", "manifest.txt"] {
                assert!(matches!(
                    firma_la_relazione(&mut servizio, &manifest, nome),
                    SigningOutcome::NotSigned { .. }
                ));
            }
            let Ok(prima) = std::fs::read(&relazione) else {
                panic!("la relazione si legge");
            };
            let accanto = manifest
                .parent()
                .unwrap_or(cartella.path())
                .join("altro.pdf");
            let Ok(()) = std::fs::write(accanto, &prima) else {
                panic!("il file si scrive");
            };
            let esito = firma_la_relazione(&mut servizio, &manifest, "altro.pdf");
            assert!(
                matches!(&esito, SigningOutcome::NotSigned { reason } if reason.contains("elenco delle impronte")),
                "{esito:?}"
            );
        }

        let mut servizio =
            DocumentSigningService::with(&mut database, firma_pdf, verifica_pdf, elenco);
        assert!(matches!(
            firma_la_relazione(&mut servizio, &manifest, &nome),
            SigningOutcome::Signed { .. }
        ));
        let esito = firma_la_relazione(&mut servizio, &manifest, &nome);
        assert!(
            matches!(&esito, SigningOutcome::NotSigned { reason } if reason.contains("c'è già")),
            "{esito:?}"
        );

        let (manifest, relazione) = pacchetto_con_pdf(cartella.path(), 33);
        let Ok(()) = std::fs::write(&relazione, b"%PDF-1.7 cambiata") else {
            panic!("la relazione si cambia");
        };
        let esito = firma_la_relazione(&mut servizio, &manifest, &nome_di(&relazione));
        assert!(
            matches!(&esito, SigningOutcome::NotSigned { reason } if reason.contains("integro")),
            "{esito:?}"
        );

        let Ok(firme) = servizio.signatures() else {
            panic!("il registro si legge");
        };
        let rifiuti = firme
            .iter()
            .filter(|firma| firma.outcome == "non_firmato")
            .count();
        assert_eq!(rifiuti, 3, "fuori dal manifest, già firmata, alterata");
        assert!(firme.iter().all(|firma| firma.kind == "pdf"));
    }

    /// **Una copia la cui firma non si verifica non si consegna** (DEC-464,
    /// decisione 7).
    #[test]
    fn una_copia_che_non_si_verifica_non_si_consegna() {
        let cartella = cartella();
        let (manifest, relazione) = pacchetto_con_pdf(cartella.path(), 34);
        let nome = nome_di(&relazione);
        let mut database = archivio();
        let mut servizio =
            DocumentSigningService::with(&mut database, firma_pdf, verifica_fallita, elenco);
        scegli(&mut servizio);

        let esito = firma_la_relazione(&mut servizio, &manifest, &nome);
        assert!(
            matches!(&esito, SigningOutcome::NotSigned { reason } if reason.contains("non si verifica")),
            "{esito:?}"
        );
        assert!(
            !relazione
                .with_file_name(super::signed_pdf_name(&nome))
                .exists()
        );
    }
}

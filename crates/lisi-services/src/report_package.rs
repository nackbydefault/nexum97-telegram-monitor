//! Il pacchetto sul disco: dove finiscono i file, e come si fa a fidarsene.
//!
//! Motivato in ADR-0031 Decisioni 2, 8 e 9. Copre i criteri 11, 12, 16, 17, 18,
//! 19 e 23 della Milestone 18.
//!
//! # Che cosa distingue un pacchetto da cinque file nella stessa cartella
//!
//! Un pacchetto e' consegnabile quando **si sa che e' completo**. Cinque
//! documenti scritti bene e un sesto interrotto a meta' non sono un pacchetto
//! incompleto: sono un pacchetto che *sembra* completo a chi apre la cartella e
//! conta i file. E' il difetto che il criterio 19 esiste per impedire.
//!
//! La difesa e' una regola sola, e sta scritta in [`PackageWriter::finish`]: **il
//! manifest e' l'ultimo file scritto**. Finche' non c'e', il pacchetto non e'
//! finito, e chiunque lo guardi lo sa senza doverlo chiedere. Se la generazione
//! si interrompe, [`PackageWriter::abort`] toglie cio' che aveva messo.
//!
//! # I nomi non si ripuliscono: si costruiscono
//!
//! Nessun nome di file qui deriva da testo dell'operatore. Ogni nome e'
//! `<genere>_<identificativo>.<estensione>`, dove il genere e' una costante e
//! l'identificativo ha un alfabeto di ventisette caratteri imposto dal tipo
//! ([`ReportId`]). Un attraversamento di percorso non e' filtrato: e'
//! **irrapresentabile**, perche' i caratteri con cui si scriverebbe non
//! attraversano il costruttore del tipo.
//!
//! # Niente rete
//!
//! In questo modulo non c'e' un client di rete, e non ce n'e' uno nel grafo che
//! ADR-0032 ha introdotto. Il criterio 23 e' soddisfatto per assenza, che e'
//! l'unico modo solido di soddisfarlo.

use std::path::{Path, PathBuf};

use crate::protected_output::ProtectedFolder;
use lisi_core::digest::Sha256Digest;
use lisi_core::model::report::{NewReportArtifact, ReportArtifactKind, ReportId};
use lisi_core::text::Actor;
use lisi_core::time::Timestamp;
use lisi_platform::launch_volume::LaunchVolume;
pub use lisi_security::owner_only::CurrentUser;

use crate::error::{ServiceError, ServiceResult};
use crate::export::VerificationStatus;

/// Attribuzione ripetuta in testa a ogni manifest.
///
/// La formula è quella unica di DEC-120, presa da dove vive: fino al 2026-10-03
/// qui ne stava una variante in minuscolo (FINAL-REVIEW-01, FR-029).
const ATTRIBUTION: &str = lisi_core::branding::ATTRIBUTION;

/// Dimensione massima di un manifest che si accetta di leggere.
///
/// Vale qui la ragione gia' scritta per il manifest del rapporto: e' testo
/// **non fidato**, depositato nella cartella da un'esecuzione precedente o da
/// un altro processo, e non deve poter essere letto per intero in memoria solo
/// perche' qualcuno lo ha reso enorme.
const MANIFEST_READ_CAP: u64 = 256 * 1024;

/// Dove vive un pacchetto e come si chiamano i suoi file.
///
/// Il pacchetto ha una **cartella propria**, intitolata al proprio
/// identificativo. Non e' un vezzo di ordine: e' cio' che rende possibile
/// consegnarlo copiando una cartella, e rende impossibile che l'annullamento di
/// una generazione tocchi file di un'altra.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageLayout {
    directory: PathBuf,
    report_id: ReportId,
}

impl PackageLayout {
    /// Calcola la disposizione dei file sotto la cartella indicata.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::ExportNotWritten`] se la cartella di
    /// destinazione non e' assoluta.
    ///
    /// # Perche' si pretende un percorso assoluto
    ///
    /// Un percorso relativo si risolve rispetto alla cartella di lavoro del
    /// processo, che non e' una decisione di chi consegna un documento: lo
    /// stesso pacchetto finirebbe in posti diversi a seconda di come
    /// l'applicazione e' stata avviata.
    pub fn new(parent: &Path, report_id: &ReportId) -> ServiceResult<Self> {
        if !parent.is_absolute() {
            return Err(ServiceError::ExportNotWritten {
                reason: String::from(
                    "la cartella di destinazione deve essere un percorso assoluto",
                ),
            });
        }

        let directory = parent.join(report_id.as_str());

        // L'identificativo ha gia' un alfabeto che non contiene separatori ne'
        // punti: questo controllo non puo' fallire, ed e' qui perche' se un
        // giorno quell'alfabeto si allargasse, fallirebbe qui invece che sul
        // disco di qualcuno.
        if !directory.starts_with(parent) {
            return Err(ServiceError::ExportNotWritten {
                reason: String::from("il nome del pacchetto uscirebbe dalla cartella scelta"),
            });
        }

        Ok(Self {
            directory,
            report_id: report_id.clone(),
        })
    }

    /// Cartella del pacchetto.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Identificativo del pacchetto.
    #[must_use]
    pub const fn report_id(&self) -> &ReportId {
        &self.report_id
    }

    /// Nome del file di un genere, senza percorso.
    #[must_use]
    pub fn file_name(&self, kind: ReportArtifactKind) -> String {
        // In Esercitazione il nome porta il prefisso (PR-13, ADR-0129).
        crate::run_mode::file_name(&format!(
            "{}_{}.{}",
            kind.file_stem(),
            self.report_id.as_str(),
            kind.extension()
        ))
    }

    /// Percorso completo del file di un genere.
    #[must_use]
    pub fn path(&self, kind: ReportArtifactKind) -> PathBuf {
        self.directory.join(self.file_name(kind))
    }
}

/// Esito della scrittura di un pacchetto completo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageOutcome {
    /// Cartella che contiene il pacchetto.
    pub directory: PathBuf,
    /// Percorso del manifest.
    pub manifest: PathBuf,
    /// Artefatti scritti, manifest **escluso**.
    pub artifacts: Vec<NewReportArtifact>,
    /// L'utente Windows che solo può aprire la cartella del pacchetto e i
    /// documenti che vi stanno: permessi applicati e riletti (SEC-01,
    /// ADR-0157). Un pacchetto che non lo è non esiste, perché non si scrive.
    pub owner: CurrentUser,
}

/// Ciò che si dice quando il pacchetto non si scrive per i permessi.
const NOT_WRITTEN: &str = "Il pacchetto della relazione NON è stato scritto";

/// Scrive gli artefatti di un pacchetto, e il manifest per ultimo.
///
/// Si usa in tre mosse: [`Self::create`], una [`Self::write`] per artefatto,
/// e [`Self::finish`]. Se qualcosa va storto, [`Self::abort`].
#[derive(Debug)]
pub struct PackageWriter {
    layout: PackageLayout,
    artifacts: Vec<NewReportArtifact>,
    written: Vec<PathBuf>,
    /// La cartella del pacchetto, del solo utente e tenuta aperta fino alla
    /// fine: nessuno la rinomina o la sostituisce mentre si scrive.
    folder: ProtectedFolder,
}

impl PackageWriter {
    /// Prepara la cartella del pacchetto.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::ExportNotWritten`] se la cartella esiste
    /// gia' o non si puo' creare.
    ///
    /// # Perche' una cartella esistente e' un rifiuto e non un riuso
    ///
    /// Riusarla significherebbe scrivere accanto a file che non abbiamo
    /// prodotto noi, e consegnarli dentro un pacchetto che dichiara di essere
    /// tutto nostro. Rifiutare costa all'operatore un secondo tentativo;
    /// riusare costa la fiducia nel manifest (criterio 17).
    ///
    /// # Perché la cartella è del solo utente (SEC-01, ADR-0157)
    ///
    /// I documenti riportano contenuti monitorati, e la cartella scelta con
    /// «Scegli la cartella…» può concedere la lettura a tutti gli utenti della
    /// postazione. La cartella del pacchetto si restringe al solo utente
    /// **appena creata**, prima del primo documento, che ne eredita i
    /// permessi. Nella cartella predefinita non cambia nulla: eredita già il
    /// solo utente.
    ///
    /// Restituisce [`ServiceError::ProtectionNotGuaranteed`] se la cartella
    /// non si può rendere del solo utente e verificare: la cartella appena
    /// creata, vuota, si toglie, e nessun documento si scrive (ADR-0157,
    /// integrazione del 2026-10-22).
    pub fn create(parent: &Path, report_id: &ReportId) -> ServiceResult<Self> {
        let layout = PackageLayout::new(parent, report_id)?;

        std::fs::create_dir_all(parent).map_err(|error| ServiceError::ExportNotWritten {
            reason: format!("{}: {error}", display(parent)),
        })?;

        // `create_dir` fallisce se la cartella esiste: e' esattamente il
        // comportamento voluto, e lo ottiene senza la finestra fra il controllo
        // e la creazione che avrebbe un `exists()` seguito da un `create`.
        let folder = ProtectedFolder::create(layout.directory(), NOT_WRITTEN, |error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                ServiceError::ExportNotWritten {
                    reason: format!(
                        "esiste già un pacchetto con l'identificativo {}",
                        report_id.as_str()
                    ),
                }
            } else {
                ServiceError::ExportNotWritten {
                    reason: format!("{}: {error}", display(layout.directory())),
                }
            }
        })?;
        // LA PROTEZIONE PRIMA DEL PRIMO DOCUMENTO, O NIENTE: una cartella che
        // non si restringe e' gia' stata tolta, e l'errore lo dice.

        Ok(Self {
            layout,
            artifacts: Vec::new(),
            written: Vec::new(),
            folder,
        })
    }

    /// Disposizione dei file del pacchetto.
    #[must_use]
    pub const fn layout(&self) -> &PackageLayout {
        &self.layout
    }

    /// Scrive un artefatto e ne restituisce la registrazione.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::ExportNotWritten`] se il file non si scrive —
    /// disco pieno, cartella non scrivibile, file gia' aperto da Word o da Excel
    /// — e [`ServiceError::DocumentGeneration`] se lo stesso genere e' gia'
    /// stato scritto in questo pacchetto.
    ///
    /// Nessuno di questi casi e' un `panic`: sono esiti dichiarati, ed e' il
    /// criterio 18.
    pub fn write(
        &mut self,
        kind: ReportArtifactKind,
        bytes: &[u8],
    ) -> ServiceResult<NewReportArtifact> {
        if kind == ReportArtifactKind::Manifest {
            return Err(ServiceError::DocumentGeneration {
                reason: String::from("il manifest lo scrive il pacchetto, per ultimo"),
            });
        }
        if self.artifacts.iter().any(|artifact| artifact.kind == kind) {
            return Err(ServiceError::DocumentGeneration {
                reason: format!("{} è già presente nel pacchetto", kind.as_str()),
            });
        }

        let path = self.layout.path(kind);
        write_file(&path, bytes)?;
        self.written.push(path);

        let artifact = NewReportArtifact {
            kind,
            file_name: self.layout.file_name(kind),
            size_bytes: bytes.len() as u64,
            sha256: Sha256Digest::of_bytes(bytes),
        };
        self.artifacts.push(artifact.clone());
        Ok(artifact)
    }

    /// Scrive il manifest e chiude il pacchetto.
    ///
    /// **E' l'ultimo file del pacchetto**, e la sua presenza e' il segnale che
    /// distingue un pacchetto completo da uno interrotto (criterio 19).
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::ExportNotWritten`] se il manifest non si
    /// scrive. In quel caso il pacchetto resta senza manifest, cioe'
    /// riconoscibile come incompleto.
    ///
    /// Restituisce [`ServiceError::ProtectionNotGuaranteed`] se, rilette prima
    /// del manifest, le autorizzazioni della cartella non sono più del solo
    /// utente: il pacchetto si toglie, perché un pacchetto completo e leggibile
    /// da altri è proprio ciò che SEC-01 esclude.
    pub fn finish(self, actor: &Actor, now: Timestamp) -> ServiceResult<PackageOutcome> {
        // IL SUCCESSO DELLA RESTRIZIONE ALL'INIZIO NON BASTA: si rilegge alla
        // fine, prima di dichiarare il pacchetto completo.
        if let Err(errore) = self.folder.seal() {
            let removed = self.abort();
            tracing::warn!(removed, "pacchetto tolto: permessi della cartella cambiati");
            return Err(errore);
        }

        let manifest_path = self.layout.path(ReportArtifactKind::Manifest);
        let manifest = render_package_manifest(
            self.layout.report_id(),
            &self.layout.file_name(ReportArtifactKind::Manifest),
            &self.artifacts,
            actor,
            now,
            lisi_platform::launch_volume::of_current_executable(),
        );

        write_file(&manifest_path, manifest.as_bytes())?;

        let owner = self.folder.owner().clone();
        self.folder.release();
        Ok(PackageOutcome {
            directory: self.layout.directory().to_path_buf(),
            manifest: manifest_path,
            artifacts: self.artifacts,
            owner,
        })
    }

    /// Toglie dal disco cio' che questo scrittore aveva messo.
    ///
    /// # Perche' non restituisce un errore
    ///
    /// Si chiama quando qualcosa e' **gia'** andato storto, e l'errore da
    /// riportare all'operatore e' quello, non l'esito della pulizia. Restituisce
    /// quanti file e' riuscito a togliere, cosi' che chi vuole registrarlo
    /// possa farlo senza doverlo dedurre.
    ///
    /// Toglie soltanto i file che ha scritto e la cartella che ha creato: se
    /// dentro ci fosse finito qualcos'altro, la cartella resta, e resta a
    /// ragione.
    pub fn abort(self) -> usize {
        let mut removed = 0;
        for path in &self.written {
            if std::fs::remove_file(path).is_ok() {
                removed += 1;
            }
        }
        // `remove_dir` non e' ricorsiva: se la cartella non e' vuota fallisce, e
        // il fallimento e' l'esito giusto. Una cancellazione ricorsiva qui
        // sarebbe una scopa che passa dove non le e' stato chiesto.
        let _ = self.folder.remove();
        removed
    }
}

/// Le righe che dicono con quale copia del programma è stato fatto un
/// documento: la versione sempre, e da dove è partito il programma se non da
/// un disco della postazione (PORTABLE-01, ADR-0176, decisione 5).
///
/// Una funzione sola per i tre manifest (pacchetto di relazione, pacchetto di
/// evidenze, esportazione): tre testi scritti a mano divergerebbero.
pub(crate) fn program_lines(launch: LaunchVolume) -> String {
    let mut righe = format!(
        "Programma:  NEXUM/97 {}\n",
        lisi_core::AppMetadata::current().version
    );
    if let Some(riga) = launch.document_line() {
        righe.push_str(&format!("Avvio:      {riga}\n"));
    }
    righe
}

/// Compone il manifest del pacchetto.
///
/// Dichiara **ogni** artefatto prodotto con nome, dimensione e impronta
/// (criterio 11) e porta l'identificativo del pacchetto (criterio 12).
///
/// Dice anche con quale copia del programma è stato fatto: la versione, e,
/// se il programma non è partito da un disco della postazione, da dove è
/// partito (PORTABLE-01, ADR-0176, decisione 5).
#[must_use]
pub fn render_package_manifest(
    report_id: &ReportId,
    manifest_name: &str,
    artifacts: &[NewReportArtifact],
    actor: &Actor,
    now: Timestamp,
    launch: LaunchVolume,
) -> String {
    let mut text = format!(
        "NEXUM/97 — manifest del pacchetto\n\
         {ATTRIBUTION}\n\n\
         Pacchetto:  {report_id}\n\
         Prodotto:   {instant}\n\
         Richiesto da: {actor}\n",
        report_id = report_id.as_str(),
        instant = now.to_readable_utc(),
        actor = actor.as_str(),
    );
    text.push_str(&program_lines(launch));
    text.push_str(&format!("Artefatti:  {count}\n\n", count = artifacts.len()));

    for artifact in artifacts {
        text.push_str(&format!(
            "File:       {name}\n\
             Genere:     {kind}\n\
             Dimensione: {size} byte\n\
             SHA-256:    {digest}\n\n",
            name = artifact.file_name,
            // IL TITOLO LEGGIBILE, non la chiave conservata: `relazione_docx`
            // è il nome con cui l'archivio ritrova l'artefatto, e in un
            // manifest in cui tutto il resto è italiano curato era l'unica
            // parola di macchina (FINAL-PRODUCT-REVIEW-01, FPR-04).
            kind = artifact.kind.operator_label(),
            size = artifact.size_bytes,
            digest = artifact.sha256.as_str(),
        ));
    }

    text.push_str(
        "Questo manifest è un'impronta, NON una firma.\n\
         Dice che i file indicati sono byte per byte quelli prodotti\n\
         dall'applicazione, a chi possiede insieme i file e questo manifest. Non\n\
         dice chi li ha prodotti, e non impedisce a nessuno di rifare insieme i\n\
         documenti e questo manifest: per quello servirebbe una chiave, e una\n\
         chiave conservata sulla stessa postazione del pacchetto non proverebbe\n\
         molto.\n\n\
         Il manifest è l'ultimo file scritto del pacchetto: se c'è, il\n\
         pacchetto è completo.\n\n\
         Per verificare, da PowerShell, dentro la cartella del pacchetto:\n\
         Get-FileHash -Algorithm SHA256 *\n",
    );

    // Il nome del manifest compare in fondo per chi lo ritrova staccato dalla
    // propria cartella: non serve a ritrovare i file, che si cercano accanto.
    text.push_str(&format!("\nQuesto file: {manifest_name}\n"));

    text
}

/// Che cosa il manifest dichiara di un artefatto.
///
/// Il manifest e' testo prodotto in un'altra esecuzione ed e' **non fidato**: si
/// estrae cio' che serve e si rifiuta cio' che non ha la forma attesa, senza
/// mai riecheggiarne il contenuto in un messaggio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageClaim {
    /// Nome del file dichiarato.
    pub file_name: String,
    /// Dimensione dichiarata, in byte.
    pub size_bytes: u64,
    /// Impronta dichiarata.
    pub sha256: Sha256Digest,
}

/// Verdetto su un singolo artefatto del pacchetto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageEntryVerification {
    /// Nome del file, come il manifest lo dichiara.
    pub file_name: String,
    /// Esito.
    pub status: VerificationStatus,
}

/// Verdetto complessivo su un pacchetto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageVerification {
    /// Identificativo dichiarato dal manifest, quando leggibile.
    pub report_id: Option<String>,
    /// Un verdetto per artefatto.
    pub entries: Vec<PackageEntryVerification>,
}

impl PackageVerification {
    /// Se ogni artefatto dichiarato risulta integro.
    ///
    /// Un pacchetto **senza artefatti dichiarati** non e' integro: un manifest
    /// vuoto non prova nulla, e rispondere «tutto a posto» a una domanda su
    /// niente sarebbe la risposta peggiore.
    #[must_use]
    pub fn is_intact(&self) -> bool {
        !self.entries.is_empty() && self.entries.iter().all(|entry| entry.status.is_intact())
    }

    /// Frase per l'operatore.
    #[must_use]
    pub fn operator_message(&self) -> String {
        let Some(report_id) = &self.report_id else {
            return String::from(
                "L'elenco delle impronte non è leggibile: senza le impronte dichiarate non c'è \
                 nulla con cui confrontare i file.",
            );
        };

        if self.entries.is_empty() {
            return format!(
                "L'elenco delle impronte del pacchetto {report_id} non dichiara alcun \
                 documento: non c'è nulla da verificare."
            );
        }

        let guasti = self
            .entries
            .iter()
            .filter(|entry| !entry.status.is_intact())
            .count();

        // Il singolare si scrive, non si arrotonda: «tutti i 1 documenti» e'
        // la frase che un operatore legge la prima volta che apre la schermata
        // Report, perche' oggi il pacchetto contiene un solo documento.
        let totale = self.entries.len();
        if guasti == 0 {
            if totale == 1 {
                format!(
                    "Il pacchetto {report_id} risulta integro: l'unico documento \
                     corrisponde all'impronta dell'elenco."
                )
            } else {
                format!(
                    "Il pacchetto {report_id} risulta integro: tutti i {totale} documenti \
                     corrispondono alle impronte dell'elenco."
                )
            }
        } else if guasti == 1 {
            format!(
                "ATTENZIONE: nel pacchetto {report_id}, un documento su {totale} non \
                 corrisponde all'elenco delle impronte. È stato alterato, sostituito o rimosso \
                 dopo la generazione."
            )
        } else {
            format!(
                "ATTENZIONE: nel pacchetto {report_id}, {guasti} documenti su {totale} non \
                 corrispondono all'elenco delle impronte. Sono stati alterati, sostituiti o \
                 rimossi dopo la generazione."
            )
        }
    }
}

/// Verifica un pacchetto contro il proprio manifest.
///
/// I percorsi dei file **non** vengono dal manifest come percorsi: si prende il
/// nome dichiarato, se ne tiene solo la parte finale e la si cerca **accanto al
/// manifest**. Un manifest che nominasse `..\\..\\Windows\\System32\\qualcosa`
/// non farebbe leggere quel file.
#[must_use]
pub fn verify_package_manifest(manifest_path: &Path) -> PackageVerification {
    let Some(directory) = manifest_path.parent() else {
        return PackageVerification {
            report_id: None,
            entries: Vec::new(),
        };
    };

    let Ok(text) = read_capped(manifest_path) else {
        return PackageVerification {
            report_id: None,
            entries: Vec::new(),
        };
    };

    let report_id = field(&text, "Pacchetto:");
    let claims = parse_package_manifest(&text);

    let entries = claims
        .into_iter()
        .map(|claim| {
            let path = directory.join(&claim.file_name);
            PackageEntryVerification {
                status: verify_one(&path, &claim),
                file_name: claim.file_name,
            }
        })
        .collect();

    PackageVerification { report_id, entries }
}

/// Confronta un file con cio' che il manifest dichiara.
fn verify_one(path: &Path, claim: &PackageClaim) -> VerificationStatus {
    let Ok(file) = std::fs::File::open(path) else {
        return VerificationStatus::ReportMissing;
    };
    let Ok(actual) = Sha256Digest::of_reader(std::io::BufReader::new(file)) else {
        return VerificationStatus::ReportMissing;
    };

    if actual == claim.sha256 {
        VerificationStatus::Intact
    } else {
        VerificationStatus::Altered {
            declared: claim.sha256.clone(),
            actual,
        }
    }
}

/// Estrae dal testo del manifest cio' che dichiara, artefatto per artefatto.
///
/// Una voce incompleta viene **saltata**, non indovinata: un artefatto senza
/// impronta non e' un artefatto da verificare a metа', e' un artefatto che il
/// manifest non dichiara.
fn parse_package_manifest(text: &str) -> Vec<PackageClaim> {
    let mut claims = Vec::new();
    let mut file_name: Option<String> = None;
    let mut size_bytes: Option<u64> = None;

    for line in text.lines() {
        let trimmed = line.trim();

        if let Some(value) = trimmed.strip_prefix("File:") {
            // Un «File:» nuovo prima che il precedente sia completo scarta il
            // precedente: era una voce monca.
            file_name = Some(value.trim().to_owned());
            size_bytes = None;
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("Dimensione:") {
            size_bytes = value
                .split_whitespace()
                .next()
                .and_then(|number| number.parse::<u64>().ok());
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("SHA-256:")
            && let (Some(name), Some(size)) = (file_name.as_ref(), size_bytes)
            && let Ok(digest) = Sha256Digest::from_hex(value.trim())
            && let Some(safe) = safe_leaf(name)
        {
            claims.push(PackageClaim {
                file_name: safe,
                size_bytes: size,
                sha256: digest,
            });
            file_name = None;
            size_bytes = None;
        }
    }

    claims
}

/// Tiene del nome dichiarato soltanto la parte finale, se e' un nome di file.
///
/// E' la difesa contro un manifest ostile: qualunque cosa somigli a un percorso
/// perde tutto cio' che sta prima dell'ultimo separatore, e cio' che resta deve
/// essere un nome semplice.
fn safe_leaf(declared: &str) -> Option<String> {
    let leaf = declared
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .trim();

    if leaf.is_empty() || leaf == "." || leaf == ".." || leaf.contains(':') {
        return None;
    }
    Some(leaf.to_owned())
}

/// Valore della prima riga che inizia con l'etichetta indicata.
fn field(text: &str, label: &str) -> Option<String> {
    text.lines()
        .find_map(|line| line.trim().strip_prefix(label))
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Legge un file di testo rifiutando quelli oltre il tetto.
fn read_capped(path: &Path) -> std::io::Result<String> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > MANIFEST_READ_CAP {
        return Err(std::io::Error::other(
            "manifest oltre la dimensione ammessa",
        ));
    }
    std::fs::read_to_string(path)
}

/// Scrive un file, traducendo il guasto in un esito dichiarato.
fn write_file(path: &Path, bytes: &[u8]) -> ServiceResult<()> {
    std::fs::write(path, bytes).map_err(|error| ServiceError::ExportNotWritten {
        reason: format!("{}: {error}", display(path)),
    })
}

/// Percorso reso testo, sostituendo cio' che non e' rappresentabile.
fn display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report_id() -> ReportId {
        ReportId::from_sequence(2026, 42)
    }

    fn operator() -> Actor {
        Actor::try_new("operatore").expect("attore valido")
    }

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_010_000_000)
    }

    fn artefatto(kind: ReportArtifactKind, nome: &str) -> NewReportArtifact {
        NewReportArtifact {
            kind,
            file_name: String::from(nome),
            size_bytes: 3,
            sha256: Sha256Digest::of_bytes(b"abc"),
        }
    }

    #[test]
    fn il_manifest_dichiara_il_genere_in_parole() {
        // Diceva «Genere: relazione_docx»: la chiave con cui l'archivio ritrova
        // l'artefatto, in un manifest dove tutto il resto e' italiano curato
        // (FINAL-PRODUCT-REVIEW-01, FPR-04). La parola e' quella che
        // l'interfaccia usa gia' per lo stesso artefatto: una sola, non una
        // quinta variante.
        let artefatti = [
            artefatto(ReportArtifactKind::NarrativeDocx, "Relazione.docx"),
            artefatto(ReportArtifactKind::AnalyticalXlsx, "Registro.xlsx"),
        ];
        let Ok(chi) = Actor::try_new("operatore") else {
            panic!("attore valido");
        };

        let manifest = render_package_manifest(
            &ReportId::from_sequence(2026, 1),
            "Manifest.txt",
            &artefatti,
            &chi,
            Timestamp::from_millis(1_760_000_000_000),
            LaunchVolume::Fixed,
        );

        assert!(manifest.contains(ReportArtifactKind::NarrativeDocx.operator_label()));
        assert!(manifest.contains(ReportArtifactKind::AnalyticalXlsx.operator_label()));
        for chiave in ["relazione_docx", "registro_xlsx"] {
            assert!(
                !manifest.contains(chiave),
                "il manifest porta ancora la chiave «{chiave}»:\n{manifest}"
            );
        }

        // Cio' che la verifica legge non e' cambiato: nome, dimensione,
        // impronta. Il «Genere» non entra in `PackageClaim`, e questa riga lo
        // dimostra invece di dichiararlo.
        assert!(manifest.contains("File:       Relazione.docx"));
        assert!(manifest.contains("Dimensione: 3 byte"));
    }

    /// **Il manifest dice con quale copia del programma è stato fatto**
    /// (PORTABLE-01, ADR-0176): la versione sempre; da dove è partito, se non
    /// da un disco della postazione. Ciò che la verifica legge non cambia.
    #[test]
    fn il_manifest_dice_da_dove_e_partito_il_programma() {
        let artefatti = [artefatto(
            ReportArtifactKind::NarrativeDocx,
            "Relazione.docx",
        )];
        let Ok(chi) = Actor::try_new("operatore") else {
            panic!("attore valido");
        };
        let componi = |avvio| {
            render_package_manifest(
                &ReportId::from_sequence(2026, 1),
                "Manifest.txt",
                &artefatti,
                &chi,
                Timestamp::from_millis(1_760_000_000_000),
                avvio,
            )
        };

        let versione = format!(
            "Programma:  NEXUM/97 {}",
            lisi_core::AppMetadata::current().version
        );
        let dal_disco = componi(LaunchVolume::Fixed);
        assert!(dal_disco.contains(&versione), "{dal_disco}");
        assert!(!dal_disco.contains("Avvio:"), "{dal_disco}");

        let dalla_chiavetta = componi(LaunchVolume::Removable);
        assert!(dalla_chiavetta.contains(&versione), "{dalla_chiavetta}");
        assert!(
            dalla_chiavetta.contains("Avvio:      Programma avviato da un supporto rimovibile"),
            "{dalla_chiavetta}"
        );
        assert!(
            componi(LaunchVolume::Undetermined).contains("Avvio:"),
            "non sapere deve parlare"
        );

        // La verifica legge le stesse voci, con o senza la riga.
        assert_eq!(
            parse_package_manifest(&dal_disco),
            parse_package_manifest(&dalla_chiavetta)
        );
        assert_eq!(parse_package_manifest(&dalla_chiavetta).len(), 1);
    }

    #[test]
    fn the_package_lives_in_a_folder_named_after_its_identifier() {
        let parent = tempfile::tempdir().expect("cartella temporanea");
        let layout = PackageLayout::new(parent.path(), &report_id()).expect("disposizione valida");

        assert_eq!(
            layout.directory(),
            parent.path().join("R-2026-000042").as_path()
        );
        assert_eq!(
            layout.file_name(ReportArtifactKind::NarrativeDocx),
            "Relazione_R-2026-000042.docx"
        );
        assert_eq!(
            layout.file_name(ReportArtifactKind::Manifest),
            "Manifest_R-2026-000042.txt"
        );
    }

    #[test]
    fn a_relative_destination_is_refused() {
        let error = PackageLayout::new(Path::new("documenti"), &report_id());
        assert!(
            error.is_err(),
            "un percorso relativo non deve essere accettato"
        );
    }

    #[test]
    fn a_hostile_identifier_cannot_even_be_built() {
        // Criterio 16 visto dove conta: l'attraversamento di percorso non e'
        // filtrato qui, e' irrappresentabile a monte.
        for ostile in [
            "../../Windows",
            "R-2026-000042/../altro",
            "R:\\altrove",
            "R 2026",
        ] {
            assert!(
                ReportId::try_new(ostile).is_err(),
                "«{ostile}» non deve poter diventare un identificativo"
            );
        }
    }

    #[test]
    fn an_existing_package_folder_is_refused_instead_of_reused() {
        // Criterio 17.
        let parent = tempfile::tempdir().expect("cartella temporanea");
        let first = PackageWriter::create(parent.path(), &report_id()).expect("primo pacchetto");
        drop(first);

        let second = PackageWriter::create(parent.path(), &report_id());
        assert!(
            second.is_err(),
            "una cartella gia' presente non deve essere riusata"
        );
    }

    #[test]
    fn the_manifest_is_the_last_file_written() {
        // Criterio 19: finche' il manifest non c'e', il pacchetto non e'
        // completo, e si vede guardando la cartella.
        let parent = tempfile::tempdir().expect("cartella temporanea");
        let mut writer = PackageWriter::create(parent.path(), &report_id()).expect("pacchetto");

        writer
            .write(ReportArtifactKind::NarrativeDocx, b"finto documento")
            .expect("scrittura");

        let manifest_path = writer.layout().path(ReportArtifactKind::Manifest);
        assert!(
            !manifest_path.exists(),
            "il manifest non deve esistere prima della chiusura"
        );

        let outcome = writer.finish(&operator(), now()).expect("chiusura");
        assert!(outcome.manifest.exists());
        assert_eq!(outcome.artifacts.len(), 1);
    }

    /// **SEC-01: la cartella del pacchetto e i suoi documenti sono del solo
    /// utente, anche in una cartella che concede a tutti** (criterio 8).
    ///
    /// La cartella scelta e' aperta come quella del collaudo; i permessi si
    /// leggono con .NET. La cartella del pacchetto ha un DACL protetto del
    /// solo utente; i documenti lo ereditano da lei, e nessuno di loro concede
    /// qualcosa ad altri.
    ///
    /// Vista rossa il 2026-10-22 sul codice di prima di SEC-01: i documenti
    /// concedevano l'accesso a `Users` e ad `Authenticated Users`.
    #[cfg(windows)]
    #[test]
    fn il_pacchetto_e_del_solo_utente_anche_in_una_cartella_aperta() {
        use crate::permessi_di_prova::{
            afferma_che_nessun_altro_apre, afferma_del_solo_utente, apri_come_nel_collaudo,
        };

        let parent = tempfile::tempdir().expect("cartella temporanea");
        apri_come_nel_collaudo(parent.path());

        let mut writer = PackageWriter::create(parent.path(), &report_id()).expect("pacchetto");
        let documento = writer.layout().path(ReportArtifactKind::NarrativeDocx);
        writer
            .write(ReportArtifactKind::NarrativeDocx, b"finto documento")
            .expect("scrittura");
        let outcome = writer.finish(&operator(), now()).expect("chiusura");

        afferma_del_solo_utente(&outcome.directory);
        afferma_che_nessun_altro_apre(&documento);
        afferma_che_nessun_altro_apre(&outcome.manifest);
        assert!(
            outcome.owner.sid.starts_with("S-1-5-"),
            "{:?}",
            outcome.owner
        );
    }

    /// **Una cartella che non conserva i permessi: nessun pacchetto e nessuna
    /// cartella** (SEC-01, criterio 8; ADR-0157 integrato il 2026-10-22).
    ///
    /// La cartella toglie all'utente il diritto di cambiare i permessi di ciò
    /// che vi crea (voce `OWNER RIGHTS`, S-1-3-4), come una chiavetta che non
    /// li conserva. Vista rossa sul codice recuperato dalla sessione SEC-01,
    /// che scriveva il pacchetto con un'avvertenza nel registro.
    #[cfg(windows)]
    #[test]
    fn un_pacchetto_che_non_si_puo_proteggere_non_si_scrive() {
        let parent = crate::permessi_di_prova::cartella_che_rifiuta_i_permessi();

        let esito = PackageWriter::create(parent.path(), &report_id());
        assert!(
            matches!(esito, Err(ServiceError::ProtectionNotGuaranteed { .. })),
            "un pacchetto che non si puo' proteggere e' stato aperto: {esito:?}"
        );
        let rimasti = std::fs::read_dir(parent.path()).expect("elenco").count();
        assert_eq!(
            rimasti, 0,
            "il rifiuto ha lasciato la cartella del pacchetto"
        );
    }

    #[test]
    fn an_interrupted_package_leaves_nothing_behind() {
        let parent = tempfile::tempdir().expect("cartella temporanea");
        let mut writer = PackageWriter::create(parent.path(), &report_id()).expect("pacchetto");
        let directory = writer.layout().directory().to_path_buf();

        writer
            .write(ReportArtifactKind::NarrativeDocx, b"finto documento")
            .expect("scrittura");
        let removed = writer.abort();

        assert_eq!(removed, 1);
        assert!(
            !directory.exists(),
            "la cartella del pacchetto interrotto deve sparire"
        );
    }

    #[test]
    fn aborting_does_not_remove_what_it_did_not_write() {
        // La pulizia non e' una scopa: toglie i propri file e la propria
        // cartella, e se dentro c'e' altro si ferma.
        let parent = tempfile::tempdir().expect("cartella temporanea");
        let mut writer = PackageWriter::create(parent.path(), &report_id()).expect("pacchetto");
        let directory = writer.layout().directory().to_path_buf();

        writer
            .write(ReportArtifactKind::NarrativeDocx, b"finto documento")
            .expect("scrittura");
        let estraneo = directory.join("appunti-di-qualcuno.txt");
        std::fs::write(&estraneo, b"non nostro").expect("file estraneo");

        writer.abort();

        assert!(
            directory.exists(),
            "la cartella con dentro altro deve restare"
        );
        assert!(estraneo.exists(), "un file non nostro non si tocca");
    }

    #[test]
    fn the_same_kind_cannot_be_written_twice() {
        let parent = tempfile::tempdir().expect("cartella temporanea");
        let mut writer = PackageWriter::create(parent.path(), &report_id()).expect("pacchetto");

        writer
            .write(ReportArtifactKind::NarrativeDocx, b"primo")
            .expect("scrittura");
        assert!(
            writer
                .write(ReportArtifactKind::NarrativeDocx, b"secondo")
                .is_err(),
            "un pacchetto non contiene due volte lo stesso genere"
        );
    }

    #[test]
    fn the_manifest_is_not_written_as_an_ordinary_artifact() {
        let parent = tempfile::tempdir().expect("cartella temporanea");
        let mut writer = PackageWriter::create(parent.path(), &report_id()).expect("pacchetto");

        assert!(
            writer
                .write(ReportArtifactKind::Manifest, b"finto")
                .is_err()
        );
    }

    #[test]
    fn a_write_that_cannot_succeed_is_a_declared_outcome_and_not_a_panic() {
        // Criterio 18. Disco pieno e file gia' aperto in Word producono un
        // errore di sistema al momento della scrittura: qui quell'errore si
        // provoca in modo riproducibile occupando il nome del file con una
        // cartella. Il percorso di codice che ne esce e' lo stesso.
        let parent = tempfile::tempdir().expect("cartella temporanea");
        let mut writer = PackageWriter::create(parent.path(), &report_id()).expect("pacchetto");

        let occupato = writer.layout().path(ReportArtifactKind::NarrativeDocx);
        std::fs::create_dir(&occupato).expect("ostacolo");

        let esito = writer.write(ReportArtifactKind::NarrativeDocx, b"relazione");
        assert!(
            matches!(esito, Err(ServiceError::ExportNotWritten { .. })),
            "la scrittura impossibile deve produrre un esito dichiarato"
        );

        // E il pacchetto non si e' chiuso lo stesso: nessun manifest.
        assert!(!writer.layout().path(ReportArtifactKind::Manifest).exists());
    }

    #[test]
    fn the_manifest_declares_every_artifact_and_the_package_identifier() {
        // Criteri 11 e 12.
        let parent = tempfile::tempdir().expect("cartella temporanea");
        let mut writer = PackageWriter::create(parent.path(), &report_id()).expect("pacchetto");

        writer
            .write(ReportArtifactKind::NarrativeDocx, b"relazione")
            .expect("scrittura");
        writer
            .write(ReportArtifactKind::PlainTxt, b"rapporto")
            .expect("scrittura");
        let outcome = writer.finish(&operator(), now()).expect("chiusura");

        let testo = std::fs::read_to_string(&outcome.manifest).expect("manifest leggibile");
        assert!(testo.contains("Pacchetto:  R-2026-000042"));
        for artifact in &outcome.artifacts {
            assert!(testo.contains(&artifact.file_name));
            assert!(testo.contains(artifact.sha256.as_str()));
            assert!(testo.contains(&format!("{} byte", artifact.size_bytes)));
        }
        assert!(
            testo.contains("NON una firma"),
            "il manifest deve dire che cosa non prova"
        );
    }

    #[test]
    fn a_written_package_verifies_as_intact() {
        let parent = tempfile::tempdir().expect("cartella temporanea");
        let mut writer = PackageWriter::create(parent.path(), &report_id()).expect("pacchetto");
        writer
            .write(ReportArtifactKind::NarrativeDocx, b"relazione")
            .expect("scrittura");
        writer
            .write(ReportArtifactKind::PlainTxt, b"rapporto")
            .expect("scrittura");
        let outcome = writer.finish(&operator(), now()).expect("chiusura");

        let verifica = verify_package_manifest(&outcome.manifest);
        assert_eq!(verifica.report_id.as_deref(), Some("R-2026-000042"));
        assert_eq!(verifica.entries.len(), 2);
        assert!(verifica.is_intact(), "{}", verifica.operator_message());
    }

    #[test]
    fn an_altered_file_is_reported_as_altered() {
        let parent = tempfile::tempdir().expect("cartella temporanea");
        let mut writer = PackageWriter::create(parent.path(), &report_id()).expect("pacchetto");
        writer
            .write(ReportArtifactKind::NarrativeDocx, b"relazione")
            .expect("scrittura");
        let outcome = writer.finish(&operator(), now()).expect("chiusura");

        let documento = outcome.directory.join(&outcome.artifacts[0].file_name);
        std::fs::write(&documento, b"relazione manomessa").expect("alterazione");

        let verifica = verify_package_manifest(&outcome.manifest);
        assert!(!verifica.is_intact());
        assert!(matches!(
            verifica.entries[0].status,
            VerificationStatus::Altered { .. }
        ));
        assert!(verifica.operator_message().contains("ATTENZIONE"));
    }

    #[test]
    fn a_removed_file_is_reported_as_missing() {
        let parent = tempfile::tempdir().expect("cartella temporanea");
        let mut writer = PackageWriter::create(parent.path(), &report_id()).expect("pacchetto");
        writer
            .write(ReportArtifactKind::NarrativeDocx, b"relazione")
            .expect("scrittura");
        let outcome = writer.finish(&operator(), now()).expect("chiusura");

        std::fs::remove_file(outcome.directory.join(&outcome.artifacts[0].file_name))
            .expect("rimozione");

        let verifica = verify_package_manifest(&outcome.manifest);
        assert!(!verifica.is_intact());
        assert_eq!(
            verifica.entries[0].status,
            VerificationStatus::ReportMissing
        );
    }

    #[test]
    fn a_package_with_one_document_is_described_in_the_singular() {
        // Oggi il pacchetto contiene un documento solo, quindi «tutti i 1
        // documenti» sarebbe la prima frase che un operatore legge nella
        // schermata Report. Trovato guardando la finestra, non da un test.
        let parent = tempfile::tempdir().expect("cartella temporanea");
        let mut writer = PackageWriter::create(parent.path(), &report_id()).expect("pacchetto");
        writer
            .write(ReportArtifactKind::NarrativeDocx, b"relazione")
            .expect("scrittura");
        let outcome = writer.finish(&operator(), now()).expect("chiusura");

        let messaggio = verify_package_manifest(&outcome.manifest).operator_message();
        assert!(messaggio.contains("l'unico documento"), "{messaggio}");
        assert!(!messaggio.contains(" 1 documenti"), "{messaggio}");
    }

    #[test]
    fn an_empty_manifest_is_not_intact() {
        let verifica = PackageVerification {
            report_id: Some(String::from("R-2026-000042")),
            entries: Vec::new(),
        };
        assert!(
            !verifica.is_intact(),
            "un manifest che non dichiara nulla non prova nulla"
        );
        assert!(
            verifica
                .operator_message()
                .contains("non dichiara alcun documento")
        );
    }

    #[test]
    fn a_hostile_manifest_cannot_point_outside_its_own_folder() {
        // Il manifest e' testo non fidato: un nome che somigli a un percorso
        // perde tutto cio' che sta prima dell'ultimo separatore.
        let claims = parse_package_manifest(
            "File:       ..\\..\\Windows\\System32\\drivers\\etc\\hosts\n\
             Dimensione: 10 byte\n\
             SHA-256:    0000000000000000000000000000000000000000000000000000000000000000\n",
        );

        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].file_name, "hosts");
        assert!(!claims[0].file_name.contains(".."));
    }

    #[test]
    fn an_incomplete_entry_is_skipped_instead_of_guessed() {
        let claims = parse_package_manifest(
            "File:       primo.docx\n\
             SHA-256:    0000000000000000000000000000000000000000000000000000000000000000\n\
             File:       secondo.txt\n\
             Dimensione: 4 byte\n\
             SHA-256:    1111111111111111111111111111111111111111111111111111111111111111\n",
        );

        // Il primo non dichiara la dimensione: non e' un artefatto da
        // verificare a meta'.
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].file_name, "secondo.txt");
    }

    #[test]
    fn a_manifest_that_cannot_be_read_says_so_instead_of_passing() {
        let parent = tempfile::tempdir().expect("cartella temporanea");
        let verifica = verify_package_manifest(&parent.path().join("non-esiste.txt"));

        assert!(verifica.report_id.is_none());
        assert!(!verifica.is_intact());
        assert!(verifica.operator_message().contains("non è leggibile"));
    }
}

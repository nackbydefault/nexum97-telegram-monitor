//! Esportazione dello storico di una sessione, con manifest di integrità.
//!
//! Produce due file: il **rapporto** in testo semplice e un **manifest** che ne
//! riporta il nome, la dimensione e l'impronta SHA-256. Di ogni esportazione
//! resta una riga in archivio e una voce di audit.
//!
//! # Che cosa il manifest è, e che cosa non è
//!
//! È un'impronta, non una firma. Dice che il file consegnato è **byte per
//! byte** quello prodotto dall'applicazione, a chi ha entrambi. Non dice chi lo
//! ha prodotto né impedisce a nessuno di rifare rapporto e manifest insieme:
//! per quello servirebbe una chiave, e una chiave conservata sulla stessa
//! postazione del documento non proverebbe granché. Il manifest lo scrive.
//!
//! # Perché la destinazione non la sceglie l'operatore
//!
//! I file finiscono in una cartella dell'applicazione, sotto il profilo
//! dell'utente. Non c'è un percorso digitabile, e quindi non c'è un percorso da
//! cui uscire: la superficie di attraversamento è chiusa alla fonte invece di
//! essere filtrata. Il **nome** del file dipende però dall'etichetta della
//! sessione, che l'operatore scrive: quella viene sanificata, e i test lo
//! verificano con separatori, risalite, nomi di dispositivo Windows e
//! caratteri di controllo.
//!
//! La cartella arriva come argomento invece di essere letta qui: così i test
//! scrivono in una cartella propria senza toccare quella dell'operatore, e
//! senza manipolare le variabili d'ambiente del processo, che in questo
//! workspace richiederebbe `unsafe`.
//!
//! # Un limite dichiarato
//!
//! PDF e XLSX non sono prodotti: richiedono una dipendenza, e aggiungerne una
//! è una decisione di catena di fornitura che non si prende di sfuggita. Il
//! testo semplice non ne richiede alcuna e si legge ovunque, anche fra dieci
//! anni. Quando arriveranno i formati tabellari servirà la neutralizzazione
//! delle formule, che qui non ha ancora un consumatore e non viene scritta in
//! anticipo per non lasciare in giro codice che nessuno esercita.

use std::path::{Path, PathBuf};

use lisi_core::model::report::ReportArtifactKind;
use lisi_core::model::{ExportDestination, ExportFormat, NewAuditEntry, NewExport, Session};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity, ExportPath};
use lisi_core::{ATTRIBUTION, SessionId, Sha256Digest, Timestamp};
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};
use crate::history::HistoryEntry;
use crate::participants::ParticipantList;
use crate::protected_output::{
    CurrentUser, Delivery, Existing, REFUSED_AUDIT_ACTION, record_refusal,
};
use crate::report_package::verify_package_manifest;

/// Cartella dei documenti prodotti, sotto la cartella dati dell'applicazione.
pub const EXPORT_DIRECTORY: &str = "export";

/// Suffisso del file manifest, accanto al rapporto `nome.txt`.
///
/// È l'unica fonte del nome: lo scrive chi produce e lo legge chi verifica, così
/// che il verificatore ritrovi il rapporto dal percorso del manifest e non dal
/// campo `File:`, che è testo non fidato.
pub const MANIFEST_SUFFIX: &str = ".manifest.txt";

/// Suffisso del rapporto in testo semplice.
const REPORT_SUFFIX: &str = ".txt";

/// Dimensione massima di un manifest che si accetta di leggere.
///
/// Un manifest prodotto qui è di poche centinaia di byte; il tetto è largo mille
/// volte tanto. Serve solo a impedire che un file enorme depositato nella
/// cartella da un altro processo — il manifest è testo **non fidato** — venga
/// letto per intero in memoria durante una verifica, come già fa il tetto
/// sull'import dei dizionari. Il rapporto, invece, ha dimensione legittima non
/// nota e si impronta a blocchi senza caricarlo tutto.
const MANIFEST_READ_CAP: u64 = 64 * 1024;

/// Lunghezza massima della parte di nome derivata dall'etichetta.
///
/// Il percorso completo su Windows ha un limite, e un'etichetta lunga
/// produrrebbe un nome che non si apre e nemmeno si copia.
const LABEL_CHARS: usize = 60;

/// Che cosa il rapporto deve contenere, oltre ai contenuti.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportOptions {
    /// Se il rapporto riporta l'identificativo Telegram di chi ha scritto.
    ///
    /// **Non è attivo per difetto.** Un rapporto che elenca persone è un
    /// documento diverso da uno che elenca contenuti, e chi lo firma deve
    /// deciderlo consapevolmente invece di trovarcelo. Il difetto sicuro è
    /// quello che non nomina nessuno.
    pub include_author_identifiers: bool,
}

impl ExportOptions {
    /// Le opzioni con cui un rapporto non nomina alcuna persona.
    #[must_use]
    pub const fn without_identifiers() -> Self {
        Self {
            include_author_identifiers: false,
        }
    }

    /// Le opzioni con cui il rapporto riporta gli identificativi degli autori.
    #[must_use]
    pub const fn with_identifiers() -> Self {
        Self {
            include_author_identifiers: true,
        }
    }

    /// Etichetta stabile per l'audit.
    ///
    /// Distingue i due atti: chi rilegge l'audit deve poter sapere se quel
    /// giorno è uscito dall'ufficio un documento che nomina persone.
    #[must_use]
    pub const fn audit_detail(self) -> &'static str {
        if self.include_author_identifiers {
            "txt_con_identificativi"
        } else {
            "txt"
        }
    }
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self::without_identifiers()
    }
}

/// Esito di un'esportazione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportOutcome {
    /// Percorso del rapporto prodotto.
    pub report: PathBuf,
    /// Percorso del manifest.
    pub manifest: PathBuf,
    /// Impronta del rapporto.
    pub digest: Sha256Digest,
    /// Contenuti documentati.
    pub entries: usize,
    /// L'utente Windows che solo può aprire rapporto e manifest (SEC-02).
    pub owner: CurrentUser,
}

impl ExportOutcome {
    /// Frase per l'operatore, con il percorso e il numero di contenuti.
    #[must_use]
    pub fn operator_message(&self) -> String {
        format!(
            "Rapporto prodotto con {} contenuti: {}. Accanto c'è l'elenco delle impronte. \
             Si aprono soltanto con l'utente Windows «{}».",
            self.entries,
            self.report.display(),
            self.owner.name
        )
    }
}

/// Servizio di esportazione.
#[derive(Debug)]
pub struct ExportService {
    database: Database,
}

impl ExportService {
    /// Crea il servizio attorno al database indicato.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Database sottostante, per i test e la diagnostica.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Restituisce il database, consumando il servizio.
    #[must_use]
    pub fn into_database(self) -> Database {
        self.database
    }

    /// Esporta in testo semplice i contenuti indicati di una sessione.
    ///
    /// L'esportazione riguarda **una sessione**, non lo storico intero: il
    /// documento risponde alla domanda «che cosa ha osservato questo
    /// monitoraggio», e un rapporto che mescolasse sessioni diverse non
    /// risponderebbe a nessuna domanda in particolare.
    ///
    /// I contenuti arrivano dal chiamante, che li ha letti da
    /// [`HistoryService`]: il rapporto documenta **ciò che è stato letto**, e
    /// rileggerli qui potrebbe produrre un documento diverso da quello che
    /// l'operatore aveva davanti.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la sessione non esiste, se la cartella non è
    /// scrivibile, se un file con lo stesso nome esiste già, o se la
    /// registrazione non riesce.
    #[expect(
        clippy::too_many_arguments,
        reason = "ogni argomento è una decisione distinta di chi produce il rapporto: \
                  quale sessione, quali contenuti, dove, chi, quando, con o senza \
                  identificativi, e con o senza l'elenco delle persone. Raggrupparli in \
                  una struttura nasconderebbe che sono sette scelte, non una"
    )]
    pub fn export_session(
        &self,
        session_id: SessionId,
        entries: &[HistoryEntry],
        directory: &Path,
        actor: &Actor,
        now: Timestamp,
        options: ExportOptions,
        participants: Option<&ParticipantList>,
    ) -> ServiceResult<ExportOutcome> {
        let session = self.database.session(session_id)?;

        std::fs::create_dir_all(directory).map_err(|error| ServiceError::ExportNotWritten {
            reason: error.to_string(),
        })?;

        let stem = file_stem(&session, now);
        let report_path = directory.join(format!("{stem}{REPORT_SUFFIX}"));
        let manifest_path = directory.join(format!("{stem}{MANIFEST_SUFFIX}"));

        // Un file gia' presente non viene sovrascritto: un rapporto consegnato
        // e poi sostituito in silenzio renderebbe il manifest una promessa
        // vuota, perche' l'impronta registrata non sarebbe piu' quella del
        // file che porta quel nome.
        for path in [&report_path, &manifest_path] {
            if path.exists() {
                return Err(ServiceError::ExportNotWritten {
                    reason: format!("esiste già un documento con il nome {}", display(path)),
                });
            }
        }

        // Con quali termini, dalla composizione comune ai quattro documenti
        // (ADR-0156): il rapporto non lo diceva affatto (BUG-REP-2).
        let configuration = crate::analysis_configuration::of_session(&self.database, session_id)?;

        // In Esercitazione la frase di SIC-17 apre il documento (PR-13).
        let report = crate::run_mode::marked_text(render_report(
            &session,
            entries,
            now,
            options,
            participants,
            &configuration,
        ));
        let bytes = report.into_bytes();
        let digest = Sha256Digest::of_bytes(&bytes);
        let manifest = render_manifest(&report_path, bytes.len(), &digest, actor, now);

        // DEL SOLO UTENTE, O NIENTE (SEC-02, ADR-0157): rapporto e manifest
        // nascono in una cartella di lavoro privata e arrivano verificati; se
        // la protezione non regge, nessuno dei due resta.
        let consegnati = Delivery::begin(directory, &stem, REPORT_NOT_WRITTEN)
            .and_then(|mut consegna| {
                consegna.write(&file_name_of(&report_path), &bytes)?;
                consegna.write(&file_name_of(&manifest_path), manifest.as_bytes())?;
                consegna.deliver(Existing::Refuse)
            })
            .inspect_err(|errore| {
                record_refusal(
                    &self.database,
                    actor,
                    now,
                    REFUSED_AUDIT_ACTION,
                    "rapporto",
                    errore,
                );
            })?;

        self.record(session_id, &report_path, &digest, actor, now, options)?;

        Ok(ExportOutcome {
            report: report_path,
            manifest: manifest_path,
            digest,
            entries: entries.len(),
            owner: consegnati.owner,
        })
    }

    /// Registra l'esportazione in archivio e nell'audit.
    fn record(
        &self,
        session_id: SessionId,
        path: &Path,
        digest: &Sha256Digest,
        actor: &Actor,
        now: Timestamp,
        options: ExportOptions,
    ) -> ServiceResult<()> {
        self.database.insert_export(&NewExport {
            session_id,
            format: ExportFormat::Txt,
            path: ExportPath::try_new(&display(path))?,
            sha256: digest.clone(),
            requested_by: actor.clone(),
            created_at: now,
        })?;

        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("export_prodotto")?,
            entity: AuditEntity::try_new("session")?,
            entity_id: Some(session_id.get()),
            // L'esportazione non e' un'azione riservata: attribuirle una
            // modalita' operativa direbbe che lo e'.
            actor_mode: None,
            // Produrre un documento che nomina persone e' un atto diverso dal
            // produrne uno che elenca contenuti: l'audit deve poter distinguere
            // i due, altrimenti non si puo' rispondere a «chi ha fatto uscire
            // dall'ufficio un elenco di identificativi, e quando».
            detail: Some(AuditDetail::try_new(options.audit_detail())?),
            recorded_at: now,
        })?;

        Ok(())
    }
}

/// Ciò che un manifest dichiara del rapporto che accompagna.
///
/// Il manifest è testo prodotto in un'altra esecuzione e va trattato come **non
/// fidato**: si estrae ciò che serve e si rifiuta ciò che non ha la forma
/// attesa, senza mai riecheggiarne il contenuto in un messaggio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestClaim {
    /// Nome del rapporto, come dichiarato dal manifest. Serve da riscontro, non
    /// da percorso: il rapporto si ritrova dal percorso del manifest.
    pub file_name: String,
    /// Dimensione dichiarata, in byte.
    pub size: usize,
    /// Impronta dichiarata.
    pub digest: Sha256Digest,
}

/// Verdetto della verifica di un rapporto contro il suo manifest.
///
/// Nessuno di questi è un errore: sono **constatazioni**. Una scansione
/// dell'intera cartella non deve fermarsi al primo manifest guasto, e ogni
/// rapporto merita il suo verdetto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationStatus {
    /// I byte del rapporto corrispondono all'impronta dichiarata.
    Intact,
    /// L'impronta ricalcolata non corrisponde: il rapporto è stato alterato o
    /// sostituito dopo l'esportazione.
    Altered {
        /// Impronta dichiarata dal manifest.
        declared: Sha256Digest,
        /// Impronta ricalcolata dai byte sul disco.
        actual: Sha256Digest,
    },
    /// Il manifest c'è, ma il rapporto che dovrebbe accompagnare non è accanto.
    ReportMissing,
    /// Il manifest non si legge o non ha la forma attesa: non c'è un'impronta
    /// dichiarata con cui confrontare.
    ManifestUnreadable,
}

impl VerificationStatus {
    /// Se il rapporto è risultato integro.
    #[must_use]
    pub const fn is_intact(&self) -> bool {
        matches!(self, Self::Intact)
    }

    /// Etichetta stabile per l'audit e la diagnostica.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Intact => "integro",
            Self::Altered { .. } => "alterato",
            Self::ReportMissing => "rapporto_mancante",
            Self::ManifestUnreadable => "manifest_illeggibile",
        }
    }
}

/// Esito completo della verifica di un manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    /// Nome del rapporto verificato, dalla convenzione dei nomi.
    pub report_name: String,
    /// Verdetto.
    pub status: VerificationStatus,
}

impl Verification {
    /// Frase per l'operatore, che dice l'esito e la sua portata.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match &self.status {
            VerificationStatus::Intact => format!(
                "«{}» risulta integro: il file sul disco corrisponde all'impronta dell'elenco.",
                self.report_name
            ),
            VerificationStatus::Altered { .. } => format!(
                "ATTENZIONE: «{}» non corrisponde al suo elenco delle impronte. Il rapporto è stato alterato \
                 o sostituito dopo l'esportazione.",
                self.report_name
            ),
            VerificationStatus::ReportMissing => format!(
                "Il rapporto «{}» dichiarato dall'elenco delle impronte non è nella cartella: \
                 non c'è nulla da verificare.",
                self.report_name
            ),
            VerificationStatus::ManifestUnreadable => format!(
                "L'elenco delle impronte di «{}» non è leggibile: senza un'impronta dichiarata \
                 non c'è nulla con cui confrontare.",
                self.report_name
            ),
        }
    }
}

/// Verifica un rapporto contro il manifest indicato, senza toccare l'archivio.
///
/// Il percorso del rapporto **non** viene dal campo `File:` del manifest — testo
/// non fidato che potrebbe nominare un file altrove sul disco — ma è derivato
/// dal percorso del manifest, per la convenzione con cui l'esportazione li
/// nomina. Il nome dichiarato serve solo da riscontro.
#[must_use]
/// Se un nome di file e' il manifest di un **pacchetto**.
///
/// # Due manifest, due nomi
///
/// L'esportazione sciolta scrive `<nome>.manifest.txt`; un pacchetto scrive
/// `Manifest_<numero>.txt`. Sono due convenzioni diverse, nate in momenti
/// diversi, ed entrambe legittime — ma la scansione ne conosceva una sola.
///
/// Il 2026-08-20 la schermata Verifica rispondeva «nessun rapporto da
/// verificare» **in qualunque cartella**, compresa quella del pacchetto:
/// scendere di un livello non bastava, perche' il file non veniva
/// riconosciuto nemmeno quando era li' davanti.
///
/// # Perche' il nome si ricompone invece di scriverlo
///
/// `"Manifest_"` scritto qui sarebbe una **terza** definizione dello stesso
/// nome, in un file che non c'entra con chi lo produce. Si ricompone dai
/// medesimi valori del dominio che `PackageLayout::file_name` usa per
/// scriverlo: se un giorno cambiano, cambiano insieme.
fn is_package_manifest(file_name: &str) -> bool {
    let stem = ReportArtifactKind::Manifest.file_stem();
    let extension = ReportArtifactKind::Manifest.extension();
    file_name.starts_with(&format!("{stem}_")) && file_name.ends_with(&format!(".{extension}"))
}

/// Traduce il verdetto su un pacchetto nelle righe della schermata.
///
/// **Una riga per documento, non una per pacchetto.** Chi verifica non vuole
/// sapere che «qualcosa non torna»: vuole sapere QUALE dei quattro documenti
/// non corrisponde, perche' e' quello che dovra' spiegare.
fn package_verifications(manifest_path: &Path) -> Vec<Verification> {
    let verdict = verify_package_manifest(manifest_path);
    let etichetta = verdict
        .report_id
        .clone()
        .unwrap_or_else(|| String::from("pacchetto senza numero leggibile"));

    if verdict.entries.is_empty() {
        // Un manifest che non dichiara nulla non e' un pacchetto integro: e'
        // un manifest che non si e' potuto leggere, e va detto invece di
        // sparire dall'elenco.
        return vec![Verification {
            report_name: etichetta,
            status: VerificationStatus::ManifestUnreadable,
        }];
    }

    verdict
        .entries
        .into_iter()
        .map(|entry| Verification {
            report_name: format!("{etichetta} · {}", entry.file_name),
            status: entry.status,
        })
        .collect()
}

pub fn verify_manifest_file(manifest_path: &Path) -> Verification {
    let report_name = report_name_for(manifest_path);

    // Un manifest oltre misura non viene nemmeno letto: è testo non fidato, e un
    // file enorme lasciato nella cartella non deve gonfiare la memoria.
    match std::fs::metadata(manifest_path) {
        Ok(metadata) if metadata.len() > MANIFEST_READ_CAP => {
            tracing::warn!(
                percorso = %manifest_path.display(),
                "manifest oltre la dimensione ammessa"
            );
            return Verification {
                report_name,
                status: VerificationStatus::ManifestUnreadable,
            };
        }
        Ok(_) => {}
        Err(_) => {
            return Verification {
                report_name,
                status: VerificationStatus::ManifestUnreadable,
            };
        }
    }

    let Ok(manifest_text) = std::fs::read_to_string(manifest_path) else {
        return Verification {
            report_name,
            status: VerificationStatus::ManifestUnreadable,
        };
    };

    let claim = match parse_manifest(&manifest_text) {
        Ok(claim) => claim,
        Err(reason) => {
            // `reason` è una costante, non un frammento del manifest: un manifest
            // manomesso non deve scegliere che cosa l'operatore legge.
            tracing::warn!(
                reason,
                percorso = %manifest_path.display(),
                "manifest non interpretabile"
            );
            return Verification {
                report_name,
                status: VerificationStatus::ManifestUnreadable,
            };
        }
    };

    // Il rapporto ha dimensione legittima non nota: si impronta a blocchi, senza
    // caricarlo per intero. Se non si apre o la lettura fallisce, non c'è nulla
    // da confrontare.
    let report_path = manifest_path.with_file_name(&report_name);
    let actual = match std::fs::File::open(&report_path)
        .and_then(|file| Sha256Digest::of_reader(std::io::BufReader::new(file)))
    {
        Ok(digest) => digest,
        Err(_) => {
            return Verification {
                report_name,
                status: VerificationStatus::ReportMissing,
            };
        }
    };

    let status = if actual == claim.digest {
        VerificationStatus::Intact
    } else {
        VerificationStatus::Altered {
            declared: claim.digest,
            actual,
        }
    };

    Verification {
        report_name,
        status,
    }
}

/// Nome del documento che un manifest accompagna, dalla convenzione dei nomi.
///
/// È `nome.txt` accanto a `nome.manifest.txt`. Se il file non ha il suffisso
/// atteso — non dovrebbe accadere, perché il chiamante filtra i manifest — si
/// ripiega sul nome del file stesso.
///
/// # Perché il `.txt` non si aggiunge sempre
///
/// Perché lo Storico non è più l'unico a scrivere un manifest: il pacchetto
/// STIX ne mette uno accanto a `nome.stix.json`, e aggiungere `.txt` a quel
/// nome cercherebbe un file che non esiste. La regola distingue i due casi
/// **senza conoscerli**: se ciò che resta togliendo il suffisso porta già
/// un'estensione, quello è il nome del documento; altrimenti è lo Storico, il
/// cui nome per costruzione non contiene punti — [`safe_name`] li sostituisce e
/// l'istante usa trattini.
fn report_name_for(manifest_path: &Path) -> String {
    let file = manifest_path
        .file_name()
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned());

    match file.strip_suffix(MANIFEST_SUFFIX) {
        Some(stem) if stem.contains('.') => String::from(stem),
        Some(stem) => format!("{stem}{REPORT_SUFFIX}"),
        None => file,
    }
}

/// Estrae dal testo di un manifest ciò che dichiara.
///
/// In caso di rifiuto il motivo è una **costante**: nessun frammento del
/// manifest, che è testo non fidato, finisce in un messaggio.
fn parse_manifest(text: &str) -> Result<ManifestClaim, &'static str> {
    let file_name = field(text, "File:").ok_or("manca il nome del file")?;

    let size = field(text, "Dimensione:")
        .and_then(|value| value.split_whitespace().next().map(str::to_owned))
        .and_then(|digits| digits.parse::<usize>().ok())
        .ok_or("dimensione mancante o illeggibile")?;

    let digest = field(text, "SHA-256:")
        .and_then(|value| Sha256Digest::from_hex(&value).ok())
        .ok_or("impronta mancante o illeggibile")?;

    Ok(ManifestClaim {
        file_name,
        size,
        digest,
    })
}

/// Valore della prima riga che inizia con l'etichetta indicata.
fn field(text: &str, label: &str) -> Option<String> {
    text.lines()
        .find_map(|line| line.trim_start().strip_prefix(label))
        .map(|value| value.trim().to_owned())
}

impl ExportService {
    /// Verifica un singolo rapporto esportato e registra l'esito nell'audit.
    ///
    /// # Errori
    ///
    /// Restituisce un errore solo se la registrazione nell'audit non riesce: il
    /// verdetto della verifica non è mai un errore, è un [`Verification`].
    pub fn verify_export(
        &self,
        manifest_path: &Path,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<Verification> {
        let verification = verify_manifest_file(manifest_path);
        self.record_verification(verification.status.label(), actor, now)?;
        Ok(verification)
    }

    /// Verifica ogni rapporto esportato nella cartella indicata.
    ///
    /// I risultati tornano ordinati per nome. Una cartella assente non è un
    /// errore: significa che nulla è stato ancora esportato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore solo se la registrazione nell'audit non riesce.
    pub fn verify_directory(
        &self,
        directory: &Path,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<Vec<Verification>> {
        let mut verifications = Vec::new();

        // Una cartella assente non è un errore: significa che nulla è stato
        // ancora esportato. La verifica si registra comunque, più sotto: che sia
        // stata tentata e non abbia trovato nulla è a sua volta un fatto d'audit.
        //
        // **SI SCENDE DI UN LIVELLO, E NON È UN DETTAGLIO.**
        //
        // Un pacchetto non è fatto di file sciolti nella cartella di
        // esportazione: è una sottocartella intitolata al numero del rapporto
        // — `R-2026-000001/` — con dentro i documenti e il manifest. Lo
        // compone `report_package.rs`, con `parent.join(report_id)`.
        //
        // Questa funzione guardava il solo livello superiore, dove i manifest
        // non sono mai stati. Dal giorno in cui i pacchetti hanno preso una
        // cartella propria, **la verifica non ha più potuto vedere nulla** e
        // rispondeva «nessun rapporto da verificare» a chi aveva appena
        // prodotto un pacchetto. Rilevato durante il pilot, il 2026-08-20.
        //
        // Un livello solo, non una discesa ricorsiva: i pacchetti stanno lì e
        // in nessun altro posto. Scendere all'infinito significherebbe
        // frugare in una cartella scelta dall'operatore — che può essere il
        // Desktop — leggendo cose che non ci riguardano.
        let mut da_guardare = vec![directory.to_path_buf()];
        if let Ok(entries) = std::fs::read_dir(directory) {
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    da_guardare.push(entry.path());
                }
            }
        }

        for cartella in &da_guardare {
            let Ok(entries) = std::fs::read_dir(cartella) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };

                if name.ends_with(MANIFEST_SUFFIX) {
                    verifications.push(verify_manifest_file(&path));
                } else if is_package_manifest(name) {
                    verifications.extend(package_verifications(&path));
                }
            }
        }
        verifications.sort_by(|left, right| left.report_name.cmp(&right.report_name));

        self.record_scan(&verifications, actor, now)?;
        Ok(verifications)
    }

    /// La cartella scelta dall'ufficio, o quella predefinita se non ne ha scelte.
    ///
    /// # Perche' il ripiego sta qui e non nell'interfaccia
    ///
    /// Perche' i punti che scrivono documenti sono piu' d'uno — il rapporto in
    /// testo, il pacchetto della schermata Report, la verifica che li rilegge —
    /// e ognuno che decidesse da se' dove guardare sarebbe un punto in cui la
    /// scelta dell'ufficio si puo' perdere. Con la risoluzione qui, esportare e
    /// verificare non possono guardare in due cartelle diverse.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scelta conservata non e' leggibile o non e'
    /// piu' accettabile, e se la cartella predefinita non e' determinabile.
    pub fn destination(&self) -> ServiceResult<PathBuf> {
        resolved_destination(&self.database)
    }

    /// Conserva la cartella scelta, o torna alla predefinita passando `None`.
    ///
    /// Nell'audit finisce **il percorso**, e qui e' giusto che ci finisca: non
    /// e' un dato dell'ufficio come il nome di chi firma, e' il luogo dove i
    /// documenti sono stati consegnati. Chi rilegge il registro per sapere dove
    /// e' finito un rapporto deve trovarlo li'.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura o la registrazione non riescono.
    pub fn save_destination(
        &self,
        destination: Option<&ExportDestination>,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.database
            .save_export_destination(destination, actor, now.as_millis())?;

        let detail = destination.map_or_else(
            || String::from("cartella predefinita della postazione"),
            |chosen| format!("cartella {}", chosen.as_str()),
        );

        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("export_cartella")?,
            entity: AuditEntity::try_new("export")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&detail)?),
            recorded_at: now,
        })?;
        Ok(())
    }

    /// Registra una singola verifica nell'audit.
    fn record_verification(
        &self,
        outcome: &str,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("export_verificato")?,
            entity: AuditEntity::try_new("export")?,
            entity_id: None,
            // La verifica non è un'azione riservata.
            actor_mode: None,
            detail: Some(AuditDetail::try_new(outcome)?),
            recorded_at: now,
        })?;
        Ok(())
    }

    /// Registra una scansione dell'intera cartella con il suo bilancio.
    ///
    /// Registra **anche** la scansione a mani vuote: che una verifica sia stata
    /// tentata e non abbia trovato rapporti è un fatto d'audit come gli altri.
    fn record_scan(
        &self,
        verifications: &[Verification],
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let detail = if verifications.is_empty() {
            String::from("nessun rapporto da verificare")
        } else {
            let intact = verifications
                .iter()
                .filter(|verification| verification.status.is_intact())
                .count();
            format!("{intact}/{} integri", verifications.len())
        };
        self.record_verification(&detail, actor, now)
    }
}

/// La cartella in cui i documenti vanno **davvero**: quella scelta, o la
/// predefinita se non ne e' stata scelta alcuna.
///
/// # Perche' una funzione libera e non un solo metodo del servizio
///
/// Perche' la schermata Report non possiede un [`ExportService`] — possiede un
/// servizio dei report — e senza questa funzione dovrebbe rifare la stessa
/// scelta per conto proprio. Due punti che decidono dove scrivere sono due punti
/// che un giorno decidono diversamente.
///
/// # Errori
///
/// Restituisce un errore se la scelta conservata non e' leggibile o non e' piu'
/// accettabile, e se la cartella predefinita non e' determinabile.
pub fn resolved_destination(database: &Database) -> ServiceResult<PathBuf> {
    match database.export_destination()? {
        Some(chosen) => Ok(chosen.into()),
        None => export_directory(),
    }
}

/// Cartella **predefinita** dei documenti prodotti.
///
/// E' quella che vale finche' l'ufficio non ne sceglie un'altra. Chi vuole la
/// cartella davvero in uso chiama [`ExportService::destination`], che tiene
/// conto della scelta conservata.
///
/// # Errori
///
/// Restituisce un errore se la cartella dati locale non è determinabile.
pub fn export_directory() -> ServiceResult<PathBuf> {
    let cartella =
        crate::data_directory::mode_directory().ok_or_else(|| ServiceError::ExportNotWritten {
            reason: String::from("cartella dati locale non determinabile"),
        })?;
    Ok(cartella.join(EXPORT_DIRECTORY))
}

/// Il nome del file, senza la cartella.
pub(crate) fn file_name_of(path: &Path) -> String {
    path.file_name()
        .map(|nome| nome.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Ciò che si dice quando il rapporto non si scrive per i permessi.
const REPORT_NOT_WRITTEN: &str = "Il rapporto NON è stato scritto";

/// Percorso reso testo, sostituendo ciò che non è rappresentabile.
pub(crate) fn display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Radice del nome dei file, derivata dall'etichetta e dall'istante.
///
/// L'istante rende il nome irripetibile senza doverlo numerare, e mette in
/// ordine cronologico i documenti di una cartella quando si guardano per nome.
pub(crate) fn file_stem(session: &Session, now: Timestamp) -> String {
    let label = safe_name(session.label.as_str());
    let instant = now
        .to_readable_utc()
        .replace([':', ' '], "-")
        .replace("-UTC", "Z");

    // In Esercitazione il nome porta il prefisso (PR-13, ADR-0129).
    crate::run_mode::file_name(&format!("nexum97-{label}-{instant}"))
}

/// Riduce un testo a un nome di file sicuro su Windows.
///
/// Non filtra: **ricostruisce**. Tiene lettere, cifre, trattini e trattini
/// bassi e sostituisce tutto il resto, così che nessuna sequenza speciale possa
/// sopravvivere per averla dimenticata in un elenco di caratteri vietati. Un
/// separatore, una risalita `..`, un nome di dispositivo o un carattere di
/// controllo non possono uscire da qui.
fn safe_name(raw: &str) -> String {
    let mut name = String::with_capacity(raw.len());
    let mut last_was_separator = false;

    for character in raw.chars().take(LABEL_CHARS) {
        if character.is_ascii_alphanumeric() {
            name.push(character.to_ascii_lowercase());
            last_was_separator = false;
        } else if character.is_alphabetic() {
            // Le lettere accentate restano leggibili: NTFS le accetta, e
            // toglierle renderebbe irriconoscibile un'etichetta italiana.
            name.extend(character.to_lowercase());
            last_was_separator = false;
        } else if !last_was_separator {
            name.push('-');
            last_was_separator = true;
        }
    }

    let trimmed = name.trim_matches('-');
    if trimmed.is_empty() {
        // Un'etichetta fatta di soli caratteri sostituiti lascerebbe un nome
        // vuoto, che non e' un nome.
        return String::from("sessione");
    }
    String::from(trimmed)
}

/// Compone il rapporto in testo semplice.
fn render_report(
    session: &Session,
    entries: &[HistoryEntry],
    now: Timestamp,
    options: ExportOptions,
    participants: Option<&ParticipantList>,
    configuration: &crate::analysis_configuration::AnalysisConfiguration,
) -> String {
    let mut report = String::new();

    report.push_str("NEXUM/97 — rapporto di monitoraggio\n");
    // L'attribuzione arriva dalla costante e non e' riscritta qui: il rapporto
    // e' un documento che esce dall'ufficio, e una formula copiata a mano e'
    // il modo in cui le quattro varianti erano nate (DEC-120).
    report.push_str(&format!("{ATTRIBUTION}\n\n"));
    report.push_str(&format!("Sessione: {}\n", session.label.as_str()));
    report.push_str(&format!("Avviata da: {}\n", session.started_by.as_str()));
    report.push_str(&format!("Stato: {}\n", session.state.label()));
    report.push_str(&format!(
        "Creata: {}\n",
        session.created_at.to_readable_utc()
    ));
    if let Some(started) = session.started_at {
        report.push_str(&format!("Avviata: {}\n", started.to_readable_utc()));
    }
    if let Some(ended) = session.ended_at {
        report.push_str(&format!("Conclusa: {}\n", ended.to_readable_utc()));
    }
    report.push_str(&format!("Rapporto prodotto: {}\n", now.to_readable_utc()));
    report.push_str(&format!("Contenuti documentati: {}\n", entries.len()));

    // Le stesse frasi della relazione, dell'allegato e del registro: un
    // livello o un riscontro si spiegano solo con i termini che li hanno
    // prodotti.
    report.push_str("\nCon quali termini il programma ha analizzato i contenuti:\n");
    for statement in configuration.statements() {
        report.push_str(&format!("{} {}\n", statement.lead, statement.body));
    }

    report.push_str(
        "\nOgni orario è in UTC. Il rapporto comprende anche i contenuti di livello 0,\n\
         cioè analizzati e risultati non rilevanti: elencare solo quelli segnalati\n\
         direbbe che il monitoraggio ha osservato solo quelli.\n",
    );

    report.push_str(
        "\nOgni contenuto dichiara il suo modo di acquisizione. «Dal vivo» significa\n\
         che la fonte era in ascolto quando il messaggio è stato pubblicato. «Recuperato»\n\
         significa che il messaggio è stato ritrovato dopo, leggendo ciò che la fonte\n\
         aveva già pubblicato: è attestato come pubblicato, non come sorvegliato.\n\
         «Non determinabile» significa che l'archivio non registra abbastanza per dirlo.\n",
    );

    // La scelta va **dichiarata in entrambi i casi**. Se il rapporto tacesse
    // quando gli identificativi sono esclusi, chi lo legge non potrebbe
    // distinguere «non c'erano autori» da «gli autori non sono stati riportati»
    // - e trarrebbe dalla loro assenza una conclusione che il documento non
    // autorizza.
    if options.include_author_identifiers {
        report.push_str(
            "\nSu richiesta di chi ha prodotto il rapporto, è riportato l'identificativo\n\
             Telegram dell'autore di ogni messaggio scritto da una persona. I messaggi\n\
             di canale non hanno un autore individuale e non ne portano alcuno.\n",
        );
    } else {
        report.push_str(
            "\nGli identificativi degli autori NON sono riportati: chi ha prodotto il\n\
             rapporto ha scelto di non includerli. La loro assenza da questo documento\n\
             non significa che non fossero noti.\n",
        );
    }

    render_participants(&mut report, options, participants);

    if entries.is_empty() {
        report.push_str(
            "\nNessun contenuto è stato acquisito in questa sessione.\n\
             Il rapporto lo documenta invece di restare vuoto.\n",
        );
        return report;
    }

    for (index, entry) in entries.iter().enumerate() {
        report.push_str(&format!("\n{}\n", "-".repeat(72)));
        report.push_str(&format!("[{}] {}\n", index + 1, entry.source_name.as_str()));
        report.push_str(&format!(
            "Acquisito: {}\n",
            entry.content.acquired_at.to_readable_utc()
        ));
        report.push_str(&format!(
            "Pubblicato: {}\n",
            entry.content.published_at.to_readable_utc()
        ));
        report.push_str(&format!("Livello: {}\n", entry.level()));
        report.push_str(&format!("Revisione: {}\n", entry.review_state().label()));

        // Si scrive **sempre**, per entrambi i casi, e non solo per i
        // recuperati. In un documento che può finire in mano a terzi, una riga
        // presente solo a volte si legge come un'anomalia di quel contenuto;
        // una riga sempre presente è una colonna del rapporto, e dice a chi
        // legge che la distinzione esiste ed è stata considerata ovunque.
        // Il modo ricavato dai fatti (PR-07, ADR-0123), con la stessa frase
        // dell'atto e della schermata: mai il percorso, che per un contenuto
        // osservato direbbe «dal vivo» anche dove nessuno ascoltava.
        report.push_str(&format!(
            "Modo di acquisizione: {}\n",
            crate::acquisition_mode::declared(&entry.mode)
        ));

        if options.include_author_identifiers {
            // Anche l'assenza si scrive, e si scrive **perche'** e' assente. In
            // un documento che puo' finire in mano a terzi, una riga mancante
            // si legge come una dimenticanza; una riga che dice «nessun autore
            // individuale» dice invece un fatto verificabile.
            match entry.content.author_identifier.as_deref() {
                Some(identifier) => {
                    report.push_str(&format!("Autore (identificativo Telegram): {identifier}\n"));
                    if let Some(username) = entry.content.author_username.as_deref() {
                        // Lo username si scrive **accanto** all'identificativo e
                        // mai al suo posto: puo' cambiare padrone, e un rapporto
                        // che lo desse per identita' attribuirebbe un messaggio
                        // a chi quello username ce l'ha adesso.
                        report.push_str(&format!("Autore (username, non identità): @{username}\n"));
                    }
                }
                None => report.push_str(
                    "Autore: nessun autore individuale (messaggio pubblicato dalla fonte).\n",
                ),
            }
        }

        // IL COLLEGAMENTO C'E', O SI DICE PERCHE' MANCA (ADR-0152, DG-02): una
        // riga assente si leggerebbe come una dimenticanza.
        report.push_str(&format!(
            "Collegamento: {}\n",
            crate::message_link::in_documents(
                entry
                    .content
                    .url
                    .as_ref()
                    .map(lisi_core::text::ContentUrl::as_str)
            )
        ));
        if entry.content.is_duplicate() {
            report
                .push_str("Nota: lo stesso testo era già stato osservato in un'altra sessione.\n");
        }

        let terms = entry.matched_terms();
        if terms.is_empty() {
            report.push_str("Riscontri: nessuno.\n");
        } else {
            report.push_str(&format!("Riscontri: {}\n", terms.join(", ")));
        }

        if entry.reason().is_empty() {
            report.push_str(
                "Motivazione: assente. La motivazione è conservata negli alert, che\n\
                 esistono dal livello 1 in su.\n",
            );
        } else {
            report.push_str(&format!("Motivazione: {}\n", entry.reason()));
        }

        report.push_str("Testo acquisito:\n");
        report.push_str(&indented_body(entry.content.body.as_str()));
    }

    report
}

/// Scrive nel rapporto l'elenco di chi ha scritto.
///
/// # Perché è legato agli identificativi e non è una scelta a sé
///
/// L'elenco **è** una lista di persone. Un rapporto che dichiara di non
/// riportare gli identificativi degli autori e poi allega l'elenco di chi ha
/// scritto direbbe una cosa e ne farebbe un'altra: la scelta di non nominare
/// nessuno sarebbe svuotata dalla pagina successiva.
///
/// # Perché l'elenco arriva dall'esterno invece di essere composto qui
///
/// Comporlo qui sarebbe stato più semplice — i contenuti ci sono già, e il
/// raggruppamento è una funzione pura. Ma l'elenco delle persone **non si
/// produce senza una ragione registrata nell'audit** (ADR-0024), e quella
/// regola vive in [`crate::participants::ParticipantService`]. Ricontrollarla
/// qui significherebbe averne due copie, e due copie della stessa regola prima
/// o poi divergono: quella che cede per prima è la strada per cui l'elenco esce
/// dall'ufficio senza che nessuno abbia dichiarato perché.
///
/// Chi non ha la ragione registrata passa `None` e il rapporto lo dice.
fn render_participants(
    report: &mut String,
    options: ExportOptions,
    participants: Option<&ParticipantList>,
) {
    if !options.include_author_identifiers {
        return;
    }

    let Some(list) = participants else {
        report.push_str(
            "\nL'elenco delle persone che hanno scritto NON è allegato: non è stata\n\
             registrata la ragione per cui l'ufficio compone elenchi di persone. La sua\n\
             assenza non significa che non ci fossero autori: gli autori dei singoli\n\
             messaggi sono riportati qui sotto, contenuto per contenuto.\n",
        );
        return;
    };

    report.push_str(&format!("\n{}\n", "=".repeat(72)));
    report.push_str("PERSONE CHE HANNO SCRITTO IN QUESTA SESSIONE\n");
    report.push_str(&format!("{}\n", "=".repeat(72)));

    report.push_str(
        "\nRicavato dai messaggi acquisiti: chi compare come autore, quante volte e in\n\
         quante fonti. NON è una lista chiesta a Telegram e non comprende chi non ha\n\
         mai scritto. Il raggruppamento è per identificativo e mai per nome: due\n\
         omonimi sono due persone, e chi cambia nome resta la stessa.\n",
    );

    report.push_str(&format!("\n{}\n", list.operator_message()));

    if list.participants.is_empty() {
        report.push_str(
            "\nNessun messaggio di questa sessione ha un autore individuale.\n\
             Il rapporto lo documenta invece di omettere la sezione.\n",
        );
        return;
    }

    for (index, person) in list.participants.iter().enumerate() {
        report.push_str(&format!("\n{}\n", "-".repeat(72)));
        report.push_str(&format!(
            "[{}] Identificativo Telegram: {}\n",
            index + 1,
            person.identifier.as_str()
        ));

        // Il nome e lo username si scrivono **accanto** all'identificativo e mai
        // al suo posto. Un nome puo' appartenere a due persone e uno username
        // puo' cambiare padrone: darli per identita' attribuirebbe messaggi a
        // chi quel nome ce l'ha adesso.
        match person.display_name.as_deref() {
            Some(name) => report.push_str(&format!("Nome mostrato (non identità): {name}\n")),
            None => report.push_str("Nome mostrato: assente nei messaggi acquisiti.\n"),
        }
        match person.username.as_deref() {
            Some(username) => {
                report.push_str(&format!("Username (non identità): @{username}\n"));
            }
            None => report.push_str("Username: assente nei messaggi acquisiti.\n"),
        }

        report.push_str(&format!("Messaggi acquisiti: {}\n", person.messages));
        report.push_str(&format!(
            "Fonti in cui ha scritto: {}\n",
            person.sources.len()
        ));
        report.push_str(&format!(
            "Prima comparsa: {}\n",
            person.first_seen.to_readable_utc()
        ));
        report.push_str(&format!(
            "Ultima comparsa: {}\n",
            person.last_seen.to_readable_utc()
        ));
    }

    report.push_str(&format!("\n{}\n", "=".repeat(72)));
    report.push_str("CONTENUTI ACQUISITI\n");
    report.push_str(&format!("{}\n", "=".repeat(72)));
}

/// Compone il manifest di integrità.
pub(crate) fn render_manifest(
    report: &Path,
    size: usize,
    digest: &Sha256Digest,
    actor: &Actor,
    now: Timestamp,
) -> String {
    let name = report.file_name().map_or_else(
        || display(report),
        |value| value.to_string_lossy().into_owned(),
    );

    format!(
        "NEXUM/97 — manifest di integrità\n\
         {ATTRIBUTION}\n\n\
         File:      {name}\n\
         Dimensione: {size} byte\n\
         SHA-256:   {digest}\n\
         Prodotto:  {instant}\n\
         Richiesto da: {actor}\n\
         {programma}\n\
         Questo manifest è un'impronta, NON una firma.\n\
         Dice che il file indicato è byte per byte quello prodotto\n\
         dall'applicazione, a chi possiede entrambi. Non dice chi lo ha\n\
         prodotto, e non impedisce a nessuno di rifare insieme il documento e\n\
         questo manifest: per quello servirebbe una chiave, e una chiave\n\
         conservata sulla stessa postazione del documento non proverebbe molto.\n\n\
         Per verificare, da PowerShell:\n\
         Get-FileHash -Algorithm SHA256 '{name}'\n",
        digest = digest.as_str(),
        instant = now.to_readable_utc(),
        actor = actor.as_str(),
        programma = crate::report_package::program_lines(
            lisi_platform::launch_volume::of_current_executable()
        ),
    )
}

/// Il testo di un contenuto, rientrato di due spazi riga per riga.
///
/// # Perché un ritorno a capo isolato è una riga (FINAL-REVIEW-01, FR-028)
///
/// `str::lines` toglie soltanto il `\r` di un `\r\n`: un `\r` isolato restava
/// dentro la riga, e il Blocco note lo mostra come un a capo. Un messaggio
/// ostile poteva così scrivere righe che, senza rientro, sembravano quelle
/// della relazione («[2] Fonte X», «Livello: 0»). I fratelli di questo
/// documento — la relazione in testo e il pacchetto di evidenze — lo
/// neutralizzano già.
fn indented_body(body: &str) -> String {
    let mut testo = String::new();
    for line in body.replace("\r\n", "\n").replace('\r', "\n").lines() {
        testo.push_str(&format!("  {line}\n"));
    }
    testo
}

#[cfg(test)]
mod tests {
    use lisi_core::model::AcquisitionOrigin;
    use lisi_core::model::dictionary::{
        ConfigurationResolver, MatchMode, ResolvedDictionaryConfiguration, TermProvenance,
    };
    use lisi_core::model::{NewSession, NewSource, SessionDuration, SourceKind};
    use lisi_core::text::{
        Actor, ContentBody, DisplayName, LanguageTag, RemoteMessageId, SourceIdentifier,
        TermCategory, TermText,
    };
    use std::path::{Path, PathBuf};

    use lisi_core::{SessionId, Timestamp};
    use lisi_storage::Database;

    use lisi_core::model::ExportDestination;

    use super::{
        ExportOptions, ExportService, ParticipantList, file_stem, report_name_for, safe_name,
    };
    use crate::analysis::{AnalysisService, NewContentDraft};
    use crate::history::{HistoryEntry, HistoryScope, HistoryService};
    use crate::sources::open_in_memory_database;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn operator() -> Actor {
        let Ok(value) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        value
    }

    fn configuration() -> ResolvedDictionaryConfiguration {
        let mut resolver = ConfigurationResolver::new();
        let (Ok(text), Ok(category), Ok(language)) = (
            TermText::try_new("molotov"),
            TermCategory::try_new("oggetto"),
            LanguageTag::try_new("it"),
        ) else {
            panic!("i valori del termine devono essere validi");
        };
        let Ok(()) = resolver.add(
            text,
            category,
            language,
            MatchMode::NormalizedWord,
            3,
            TermProvenance::ad_hoc(),
        ) else {
            panic!("il termine doveva essere accettato");
        };
        resolver.finish()
    }

    /// Archivio con una sessione dall'etichetta indicata e due contenuti.
    fn archive(label: &str) -> (Database, SessionId) {
        let Ok(mut database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };

        let (Ok(identifier), Ok(title), Ok(label)) = (
            SourceIdentifier::try_new("canale_uno"),
            DisplayName::try_new("Canale di prova"),
            DisplayName::try_new(label),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(source_id) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier,
                display_name: title,
                authorized_by: operator(),
                active: true,
            },
            now(),
        ) else {
            panic!("la fonte deve potersi registrare");
        };
        let Ok(session_id) = database.insert_session(
            &NewSession {
                label,
                started_by: operator(),
                duration: SessionDuration::Preset { seconds: 3_600 },
                source_ids: vec![source_id],
            },
            now(),
        ) else {
            panic!("la sessione deve potersi creare");
        };

        let configuration = configuration();
        let mut analysis = AnalysisService::new(database);
        for (index, body) in ["una molotov", "buongiorno a tutti"].iter().enumerate() {
            let Ok(index) = i64::try_from(index) else {
                panic!("l'indice deve stare in un intero");
            };
            let (Ok(remote), Ok(body)) = (
                RemoteMessageId::try_new(&format!("m{index}")),
                ContentBody::try_new(body),
            ) else {
                panic!("i valori del contenuto devono essere validi");
            };
            let Ok(_) = analysis.analyse_and_record(
                &NewContentDraft {
                    session_id,
                    source_id,
                    remote_message_id: remote,
                    author: None,
                    // Il primo contenuto e' scritto da una persona, il secondo
                    // e' pubblicato dalla fonte: il rapporto deve saper rendere
                    // entrambi i casi, e con due contenuti identici non si
                    // vedrebbe la differenza fra i due.
                    author_identifier: (index == 0).then(|| String::from("1234567890")),
                    author_username: None,
                    body,
                    url: None,
                    published_at: now(),
                    acquired_at: now(),
                    origin: AcquisitionOrigin::Observed,
                },
                &configuration,
                &operator(),
                now(),
            ) else {
                panic!("l'analisi deve riuscire");
            };
        }

        (analysis.into_database(), session_id)
    }

    /// Cartella temporanea in cui una prova può scrivere.
    ///
    /// I test **non devono scrivere** nella cartella dei documenti
    /// dell'operatore, e questo servizio scrive su disco per definizione. La
    /// cartella si passa come argomento invece di alterare `%LOCALAPPDATA%`
    /// del processo: in Rust 2024 quella modifica è `unsafe`, e questo crate
    /// vieta l'`unsafe`.
    fn temporary_directory(name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("nexum-export-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        directory
    }

    #[test]
    fn a_separator_cannot_survive_the_name() {
        // Non e' un filtro con un elenco di caratteri vietati: il nome viene
        // ricostruito, e cio' che non e' esplicitamente ammesso non passa.
        for dangerous in [
            "..\\..\\Windows\\System32",
            "../../etc/passwd",
            "C:\\Users\\pubblico",
            "nome\u{0}terminato",
            "  ...  ",
            "CON",
            "prova.txt.exe",
        ] {
            let safe = safe_name(dangerous);
            assert!(!safe.contains('\\'), "{dangerous} -> {safe}");
            assert!(!safe.contains('/'), "{dangerous} -> {safe}");
            assert!(!safe.contains(':'), "{dangerous} -> {safe}");
            assert!(!safe.contains(".."), "{dangerous} -> {safe}");
            assert!(!safe.starts_with('-') && !safe.ends_with('-'), "{safe}");
            assert!(!safe.is_empty());
            assert!(
                safe.chars().all(|c| !c.is_control()),
                "{dangerous} -> {safe}"
            );
        }
    }

    #[test]
    fn a_windows_device_name_is_not_left_alone() {
        // "CON" e i suoi simili sono nomi di dispositivo: un file che si
        // chiama cosi' non si apre. Il prefisso del prodotto li disinnesca,
        // perche' il nome finale non e' mai soltanto l'etichetta.
        let session_like = format!("nexum97-{}-x", safe_name("CON"));
        assert_ne!(session_like.to_lowercase(), "con");
        assert!(session_like.starts_with("nexum97-"));
    }

    #[test]
    fn an_accented_label_stays_readable() {
        assert_eq!(safe_name("Città di prova"), "città-di-prova");
    }

    #[test]
    fn a_label_of_only_forbidden_characters_still_produces_a_name() {
        assert_eq!(safe_name("///"), "sessione");
        assert_eq!(safe_name(""), "sessione");
    }

    #[test]
    fn the_name_carries_the_instant_and_has_no_spaces_or_colons() {
        let (database, session_id) = archive("Prova");
        let Ok(session) = database.session(session_id) else {
            panic!("la sessione deve potersi leggere");
        };

        let stem = file_stem(&session, now());
        assert!(!stem.contains(' '), "{stem}");
        assert!(!stem.contains(':'), "{stem}");
        assert!(stem.starts_with("nexum97-prova-2023-11-14"), "{stem}");
    }

    /// Servizio, storico e contenuti pronti per un'esportazione.
    ///
    /// Storico ed esportazione condividono lo **stesso** archivio in memoria,
    /// che l'uno presta all'altro: un archivio in memoria è privato della sua
    /// connessione, e due connessioni distinte vedrebbero due archivi vuoti.
    fn ready(label: &str) -> (ExportService, SessionId, Vec<HistoryEntry>) {
        let (database, session_id) = archive(label);
        let history = HistoryService::new(database);

        let Ok(entries) = history.entries(HistoryScope::Session(session_id)) else {
            panic!("lo storico deve potersi leggere");
        };

        (
            ExportService::new(history.into_database()),
            session_id,
            entries,
        )
    }

    /// **SEC-02: rapporto e manifest del solo utente, o niente** (ADR-0157).
    /// Vista rossa il 2026-10-22 con la protezione tolta (mutazione di SEC-02).
    #[cfg(windows)]
    #[test]
    fn il_rapporto_e_del_solo_utente_o_non_si_scrive() {
        let (service, session_id, entries) = ready("Monitoraggio di prova");
        crate::permessi_di_prova::prova_un_uscita("rapporto della sessione", |cartella| {
            service
                .export_session(
                    session_id,
                    &entries,
                    cartella,
                    &operator(),
                    now(),
                    ExportOptions::without_identifiers(),
                    None,
                )
                .map(|esito| vec![esito.report, esito.manifest])
        });
    }

    #[test]
    fn the_report_documents_every_content_and_the_manifest_matches_the_file() {
        let directory = temporary_directory("rapporto");
        let (service, session_id, entries) = ready("Monitoraggio di prova");

        let Ok(outcome) = service.export_session(
            session_id,
            &entries,
            &directory,
            &operator(),
            now(),
            ExportOptions::without_identifiers(),
            None,
        ) else {
            panic!("l'esportazione deve riuscire");
        };

        assert_eq!(outcome.entries, 2);

        let (Ok(report), Ok(manifest)) = (
            std::fs::read(&outcome.report),
            std::fs::read_to_string(&outcome.manifest),
        ) else {
            panic!("i due file devono esistere");
        };

        // Il manifest impronta i byte del file, non il testo da cui
        // provengono: e' cio' che rende la verifica ripetibile da chi riceve
        // il documento e non ha il testo originale.
        assert_eq!(
            lisi_core::Sha256Digest::of_bytes(&report),
            outcome.digest,
            "l'impronta deve essere quella del file scritto"
        );
        assert!(manifest.contains(outcome.digest.as_str()));
        assert!(
            manifest.contains("NON una firma"),
            "il limite va scritto nel documento, non solo nel codice"
        );

        let text = String::from_utf8_lossy(&report);
        assert!(text.contains("Livello: 3"));
        assert!(text.contains("Livello: 0"), "anche i non rilevanti");
        assert!(text.contains("una molotov"));
        assert!(text.contains("UTC"));

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn the_report_declares_how_each_content_was_acquired() {
        let directory = temporary_directory("origine");
        let (service, session_id, entries) = ready("Monitoraggio con origini");

        let Ok(outcome) = service.export_session(
            session_id,
            &entries,
            &directory,
            &operator(),
            now(),
            ExportOptions::without_identifiers(),
            None,
        ) else {
            panic!("l'esportazione deve riuscire");
        };

        let Ok(text) = std::fs::read_to_string(&outcome.report) else {
            panic!("il rapporto deve esistere");
        };

        // La spiegazione compare una volta, in testa: chi riceve il documento
        // deve sapere che la distinzione esiste prima di incontrarla.
        assert!(text.contains("«Recuperato»") && text.contains("«Non determinabile»"));
        // E ogni contenuto la dichiara, anche quello osservato: una riga
        // presente solo a volte si leggerebbe come un'anomalia di quel
        // contenuto invece che come una colonna del rapporto.
        assert_eq!(
            text.matches("Modo di acquisizione: ").count(),
            entries.len(),
            "una riga per contenuto"
        );
        // Il percorso non si scrive più come se fosse il modo: senza copertura
        // registrata, un contenuto osservato non è «dal vivo» (PR-07).
        assert!(!text.contains("Acquisizione: dal vivo"));
        assert!(text.contains("Modo di acquisizione non determinabile"));

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn without_the_choice_the_report_names_nobody_and_says_it() {
        let directory = temporary_directory("senza-identificativi");
        let (service, session_id, entries) = ready("Monitoraggio senza nomi");

        let Ok(outcome) = service.export_session(
            session_id,
            &entries,
            &directory,
            &operator(),
            now(),
            ExportOptions::without_identifiers(),
            None,
        ) else {
            panic!("l'esportazione deve riuscire");
        };

        let Ok(text) = std::fs::read_to_string(&outcome.report) else {
            panic!("il rapporto deve esistere");
        };

        assert!(
            !text.contains("1234567890"),
            "l'identificativo non deve comparire se non e' stato chiesto"
        );
        // Il silenzio non basta: senza questa frase chi legge non distingue
        // «non c'erano autori» da «gli autori non sono stati riportati».
        assert!(
            text.contains("NON sono riportati"),
            "il rapporto deve dichiarare l'esclusione"
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn with_the_choice_the_report_carries_the_identifiers_and_marks_what_has_none() {
        let directory = temporary_directory("con-identificativi");
        let (service, session_id, entries) = ready("Monitoraggio con nomi");

        let Ok(outcome) = service.export_session(
            session_id,
            &entries,
            &directory,
            &operator(),
            now(),
            ExportOptions::with_identifiers(),
            None,
        ) else {
            panic!("l'esportazione deve riuscire");
        };

        let Ok(text) = std::fs::read_to_string(&outcome.report) else {
            panic!("il rapporto deve esistere");
        };

        assert!(
            text.contains("Autore (identificativo Telegram): 1234567890"),
            "l'identificativo chiesto deve comparire"
        );
        // L'assenza si scrive, e si scrive perche' e' assente: in un documento
        // che puo' finire a terzi, una riga mancante si legge come una
        // dimenticanza invece che come un fatto.
        assert!(
            text.contains("nessun autore individuale"),
            "il contenuto senza autore deve dirlo, non tacere"
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    /// Elenco di prova con una persona sola.
    fn one_person() -> ParticipantList {
        ParticipantList {
            participants: vec![crate::participants::Participant {
                identifier: String::from("1234567890"),
                display_name: Some(String::from("Nome Mostrato")),
                username: Some(String::from("un_username")),
                messages: 2,
                sources: vec![lisi_core::SourceId::new(1)],
                first_seen: now(),
                last_seen: now(),
            }],
            examined: 2,
            without_author: 1,
        }
    }

    #[test]
    fn the_list_of_people_is_attached_only_to_a_report_that_names_them() {
        let directory = temporary_directory("persone-allegate");
        let (service, session_id, entries) = ready("Monitoraggio con elenco");

        let Ok(outcome) = service.export_session(
            session_id,
            &entries,
            &directory,
            &operator(),
            now(),
            ExportOptions::with_identifiers(),
            Some(&one_person()),
        ) else {
            panic!("l'esportazione deve riuscire");
        };

        let Ok(text) = std::fs::read_to_string(&outcome.report) else {
            panic!("il rapporto deve esistere");
        };

        assert!(
            text.contains("PERSONE CHE HANNO SCRITTO IN QUESTA SESSIONE"),
            "l'elenco chiesto deve comparire"
        );
        assert!(text.contains("Identificativo Telegram: 1234567890"));
        // Nome e username stanno **accanto** all'identificativo e mai al suo
        // posto: un nome puo' appartenere a due persone e uno username puo'
        // cambiare padrone.
        assert!(text.contains("Nome mostrato (non identità): Nome Mostrato"));
        assert!(text.contains("Username (non identità): @un_username"));
        assert!(text.contains("Messaggi acquisiti: 2"));
        // I contenuti senza autore individuale vanno dichiarati, altrimenti
        // l'elenco si legge come se coprisse tutto cio' che e' stato acquisito.
        assert!(text.contains("non hanno un autore individuale"));

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_report_that_names_nobody_carries_no_list_even_when_one_is_offered() {
        let directory = temporary_directory("persone-non-allegate");
        let (service, session_id, entries) = ready("Monitoraggio senza nomi");

        // Il caso che conta: l'elenco c'e' e viene comunque **scartato**. Un
        // documento che dichiara di non riportare gli identificativi e poi
        // allega l'elenco di chi ha scritto direbbe una cosa e ne farebbe
        // un'altra, e la scelta di non nominare nessuno sarebbe svuotata dalla
        // pagina successiva.
        let Ok(outcome) = service.export_session(
            session_id,
            &entries,
            &directory,
            &operator(),
            now(),
            ExportOptions::without_identifiers(),
            Some(&one_person()),
        ) else {
            panic!("l'esportazione deve riuscire");
        };

        let Ok(text) = std::fs::read_to_string(&outcome.report) else {
            panic!("il rapporto deve esistere");
        };

        assert!(
            !text.contains("PERSONE CHE HANNO SCRITTO"),
            "un rapporto che non nomina nessuno non puo' allegare un elenco di persone"
        );
        assert!(
            !text.contains("1234567890"),
            "nessun identificativo deve comparire in alcuna forma"
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_missing_list_is_declared_instead_of_being_passed_over_in_silence() {
        let directory = temporary_directory("persone-senza-ragione");
        let (service, session_id, entries) = ready("Monitoraggio senza ragione");

        // `None` è ciò che arriva quando la ragione per comporre elenchi di
        // persone non è stata registrata nell'audit (ADR-0024). Tacere
        // lascerebbe dedurre dall'assenza della sezione che non ci fossero
        // autori, che è una conclusione diversa e falsa.
        let Ok(outcome) = service.export_session(
            session_id,
            &entries,
            &directory,
            &operator(),
            now(),
            ExportOptions::with_identifiers(),
            None,
        ) else {
            panic!("l'esportazione deve riuscire");
        };

        let Ok(text) = std::fs::read_to_string(&outcome.report) else {
            panic!("il rapporto deve esistere");
        };

        assert!(
            text.contains("L'elenco delle persone che hanno scritto NON è allegato"),
            "l'assenza dell'elenco va dichiarata"
        );
        assert!(
            text.contains("non è stata\nregistrata la ragione"),
            "va detto anche perche' manca"
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn the_audit_distinguishes_a_report_that_names_people() {
        let directory = temporary_directory("audit-identificativi");
        let (service, session_id, entries) = ready("Monitoraggio tracciato");

        let Ok(_) = service.export_session(
            session_id,
            &entries,
            &directory,
            &operator(),
            now(),
            ExportOptions::with_identifiers(),
            None,
        ) else {
            panic!("l'esportazione deve riuscire");
        };

        let Ok(audit) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let produced = audit
            .iter()
            .find(|entry| entry.action.as_str() == "export_prodotto");
        let Some(produced) = produced else {
            panic!("l'esportazione deve lasciare una voce di audit");
        };

        // Far uscire dall'ufficio un elenco di identificativi e' un atto
        // diverso dall'esportare contenuti: se l'audit registrasse «txt» in
        // entrambi i casi non si potrebbe piu' sapere quale dei due e' avvenuto.
        assert_eq!(
            produced.detail.as_ref().map(|detail| detail.as_str()),
            Some("txt_con_identificativi")
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn an_empty_session_produces_a_report_that_says_so() {
        let directory = temporary_directory("vuota");
        let Ok(mut database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        let Ok(label) = DisplayName::try_new("Sessione senza contenuti") else {
            panic!("l'etichetta deve essere valida");
        };
        let Ok(session_id) = database.insert_session(
            &NewSession {
                label,
                started_by: operator(),
                duration: SessionDuration::Manual,
                source_ids: Vec::new(),
            },
            now(),
        ) else {
            panic!("la sessione deve potersi creare");
        };

        let service = ExportService::new(database);
        let Ok(outcome) = service.export_session(
            session_id,
            &[],
            &directory,
            &operator(),
            now(),
            ExportOptions::without_identifiers(),
            None,
        ) else {
            panic!("l'esportazione deve riuscire anche senza contenuti");
        };

        assert_eq!(outcome.entries, 0);
        let Ok(text) = std::fs::read_to_string(&outcome.report) else {
            panic!("il rapporto deve esistere");
        };
        assert!(text.contains("Nessun contenuto è stato acquisito"));

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn the_export_is_recorded_in_the_archive_and_in_the_audit() {
        let directory = temporary_directory("registro");
        let (service, session_id, entries) = ready("Registrata");

        let Ok(_) = service.export_session(
            session_id,
            &entries,
            &directory,
            &operator(),
            now(),
            ExportOptions::without_identifiers(),
            None,
        ) else {
            panic!("l'esportazione deve riuscire");
        };

        let Ok(exports) = service.database().session_exports(session_id) else {
            panic!("gli export devono potersi leggere");
        };
        assert_eq!(exports.len(), 1);
        assert!(exports[0].path.as_str().ends_with(".txt"));

        let Ok(recorded) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert!(
            recorded
                .iter()
                .any(|entry| entry.action.as_str() == "export_prodotto")
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn an_existing_document_is_not_overwritten() {
        // Un rapporto consegnato e poi sostituito in silenzio renderebbe vuota
        // la promessa del manifest.
        let directory = temporary_directory("collisione");
        let (service, session_id, entries) = ready("Ripetuta");

        let Ok(_) = service.export_session(
            session_id,
            &entries,
            &directory,
            &operator(),
            now(),
            ExportOptions::without_identifiers(),
            None,
        ) else {
            panic!("la prima esportazione deve riuscire");
        };
        // Stesso istante, quindi stesso nome: il secondo tentativo trova il
        // file e si ferma invece di sostituirlo.
        assert!(matches!(
            service.export_session(
                session_id,
                &entries,
                &directory,
                &operator(),
                now(),
                ExportOptions::without_identifiers(),
                None
            ),
            Err(crate::error::ServiceError::ExportNotWritten { .. })
        ));

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_label_that_tries_to_escape_writes_inside_the_directory_anyway() {
        // La prova che conta: non che il nome sia stato ripulito, ma che il
        // file sia finito **dentro** la cartella indicata.
        let directory = temporary_directory("risalita");
        let (service, session_id, entries) = ready("..\\..\\Windows\\System32\\evil");

        let Ok(outcome) = service.export_session(
            session_id,
            &entries,
            &directory,
            &operator(),
            now(),
            ExportOptions::without_identifiers(),
            None,
        ) else {
            panic!("l'esportazione deve riuscire");
        };

        assert_eq!(
            outcome.report.parent(),
            Some(directory.as_path()),
            "il documento deve stare nella cartella indicata: {}",
            outcome.report.display()
        );
        assert_eq!(outcome.manifest.parent(), Some(directory.as_path()));

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_rendered_manifest_parses_back_to_the_same_digest() {
        // Produttore e verificatore devono leggere lo stesso formato: se il
        // manifest cambia forma, questo test lo scopre prima del verificatore.
        let report = PathBuf::from("cartella").join("nexum97-prova.txt");
        let digest = lisi_core::Sha256Digest::of_bytes(b"contenuto di prova");
        let manifest = super::render_manifest(&report, 18, &digest, &operator(), now());

        let Ok(claim) = super::parse_manifest(&manifest) else {
            panic!("il manifest appena prodotto deve essere interpretabile");
        };
        assert_eq!(claim.digest, digest);
        assert_eq!(claim.size, 18);
        assert_eq!(claim.file_name, "nexum97-prova.txt");
    }

    #[test]
    fn a_report_and_its_manifest_verify_as_intact() {
        let directory = temporary_directory("verifica-integra");
        let (service, session_id, entries) = ready("Da verificare");

        let Ok(outcome) = service.export_session(
            session_id,
            &entries,
            &directory,
            &operator(),
            now(),
            ExportOptions::without_identifiers(),
            None,
        ) else {
            panic!("l'esportazione deve riuscire");
        };

        let Ok(verification) = service.verify_export(&outcome.manifest, &operator(), now()) else {
            panic!("la verifica deve poter registrare l'esito");
        };
        assert_eq!(verification.status, super::VerificationStatus::Intact);
        assert!(verification.operator_message().contains("integro"));

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_report_altered_after_export_is_detected() {
        // Il caso reale: un rapporto consegnato e poi cambiato. L'impronta
        // ricalcolata non corrisponde piu' a quella del manifest.
        let directory = temporary_directory("verifica-alterata");
        let (service, session_id, entries) = ready("Da alterare");

        let Ok(outcome) = service.export_session(
            session_id,
            &entries,
            &directory,
            &operator(),
            now(),
            ExportOptions::without_identifiers(),
            None,
        ) else {
            panic!("l'esportazione deve riuscire");
        };

        // Si aggiunge un byte al rapporto, lasciando intatto il manifest.
        let Ok(mut bytes) = std::fs::read(&outcome.report) else {
            panic!("il rapporto deve esistere");
        };
        bytes.push(b'!');
        let Ok(()) = std::fs::write(&outcome.report, &bytes) else {
            panic!("il rapporto deve potersi riscrivere");
        };

        let verification = super::verify_manifest_file(&outcome.manifest);
        assert!(
            matches!(
                verification.status,
                super::VerificationStatus::Altered { .. }
            ),
            "un rapporto alterato deve risultare alterato: {:?}",
            verification.status
        );
        assert!(verification.operator_message().contains("ATTENZIONE"));

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_missing_report_is_reported_not_a_crash() {
        let directory = temporary_directory("verifica-mancante");
        let (service, session_id, entries) = ready("Senza rapporto");

        let Ok(outcome) = service.export_session(
            session_id,
            &entries,
            &directory,
            &operator(),
            now(),
            ExportOptions::without_identifiers(),
            None,
        ) else {
            panic!("l'esportazione deve riuscire");
        };

        let Ok(()) = std::fs::remove_file(&outcome.report) else {
            panic!("il rapporto deve potersi rimuovere");
        };

        let verification = super::verify_manifest_file(&outcome.manifest);
        assert_eq!(
            verification.status,
            super::VerificationStatus::ReportMissing
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_malformed_manifest_is_unreadable_not_a_crash() {
        let directory = temporary_directory("verifica-malformata");
        let Ok(()) = std::fs::create_dir_all(&directory) else {
            panic!("la cartella deve potersi creare");
        };
        let manifest = directory.join("qualcosa.manifest.txt");
        let Ok(()) = std::fs::write(&manifest, "non e' un manifest\nsenza impronta\n") else {
            panic!("il manifest di prova deve potersi scrivere");
        };

        let verification = super::verify_manifest_file(&manifest);
        assert_eq!(
            verification.status,
            super::VerificationStatus::ManifestUnreadable
        );
        // Il nome atteso del rapporto si ricava comunque dalla convenzione.
        assert_eq!(verification.report_name, "qualcosa.txt");

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn the_file_field_of_a_manifest_is_not_used_as_a_path() {
        // Un manifest manomesso non deve poter dirigere la lettura altrove: il
        // rapporto si ritrova accanto al manifest, e il campo File: e' solo un
        // riscontro. Qui il campo punta a una risalita, ma la verifica impronta
        // il rapporto vicino e lo trova integro.
        let directory = temporary_directory("verifica-file-field");
        let Ok(()) = std::fs::create_dir_all(&directory) else {
            panic!("la cartella deve potersi creare");
        };

        let report = directory.join("innocuo.txt");
        let Ok(()) = std::fs::write(&report, b"contenuto vicino") else {
            panic!("il rapporto vicino deve potersi scrivere");
        };
        let digest = lisi_core::Sha256Digest::of_bytes(b"contenuto vicino");

        let manifest = directory.join("innocuo.manifest.txt");
        let doctored = format!(
            "File:      ..\\..\\Windows\\System32\\config\\SAM\n\
             Dimensione: 16 byte\n\
             SHA-256:   {digest}\n",
            digest = digest.as_str(),
        );
        let Ok(()) = std::fs::write(&manifest, doctored) else {
            panic!("il manifest manomesso deve potersi scrivere");
        };

        let verification = super::verify_manifest_file(&manifest);
        assert_eq!(
            verification.status,
            super::VerificationStatus::Intact,
            "la verifica deve impronta il rapporto vicino, non il file nominato dal campo File:"
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    /// **Il riconoscitore deve riconoscere cio' che il produttore produce.**
    ///
    /// E' l'invariante la cui assenza ha prodotto il difetto: la scansione
    /// cercava file che finiscono per `.manifest.txt`, il pacchetto ne scrive
    /// uno che comincia per `Manifest_`, e nessuno confrontava le due cose.
    /// La schermata rispondeva «nessun rapporto da verificare» in qualunque
    /// cartella, compresa quella del pacchetto.
    ///
    /// Il nome NON e' scritto a mano in questa prova: viene da
    /// `PackageLayout::file_name`, cioe' dalla funzione che lo produce
    /// davvero. Scriverlo a mano proverebbe che il riconoscitore riconosce
    /// cio' che la prova crede — che e' esattamente l'errore da cui questa
    /// prova protegge.
    #[test]
    fn il_riconoscitore_accetta_il_nome_che_il_produttore_scrive() {
        let parent = temporary_directory("nome-del-manifest");
        let Ok(report_id) = lisi_core::model::report::ReportId::try_new("R-2026-000042") else {
            panic!("l'identificativo di prova deve essere valido");
        };
        let Ok(layout) = crate::report_package::PackageLayout::new(&parent, &report_id) else {
            panic!("la disposizione del pacchetto deve potersi costruire");
        };

        let nome = layout.file_name(lisi_core::model::report::ReportArtifactKind::Manifest);

        assert!(
            super::is_package_manifest(&nome),
            "la scansione non riconosce «{nome}», che e' il nome che il \
             produttore scrive: la verifica non vedrebbe mai un pacchetto"
        );

        // Il controllo opposto: non deve accettare qualunque cosa. Un
        // riconoscitore troppo largo aprirebbe file che non sono manifest, in
        // una cartella che l'operatore ha scelto e che puo' contenere di tutto.
        for estraneo in [
            "Relazione_R-2026-000042.docx",
            "Manifesto.txt",
            "appunti.txt",
            "Manifest_R-2026-000042.pdf",
        ] {
            assert!(
                !super::is_package_manifest(estraneo),
                "«{estraneo}» non e' il manifest di un pacchetto e non va aperto"
            );
        }

        let _ = std::fs::remove_dir_all(&parent);
    }

    /// **Il difetto del 2026-08-20: un pacchetto sta in una SOTTOCARTELLA.**
    ///
    /// `report_package.rs` compone la destinazione come `parent.join(report_id)`:
    /// i documenti e il manifest finiscono in `R-2026-000001/`, non sciolti nella
    /// cartella di esportazione. La verifica guardava il solo livello superiore e
    /// rispondeva «nessun rapporto da verificare» a chi aveva appena prodotto un
    /// pacchetto.
    ///
    /// # Perche' le prove che c'erano non l'hanno vista
    ///
    /// Provavano `export_session`, che scrive file SCIOLTI: un percorso di
    /// esportazione diverso da quello che il prodotto usa per i pacchetti. Erano
    /// verdi, e lo sarebbero rimaste per sempre.
    ///
    /// **Una prova che esercita un percorso diverso da quello reale non e' una
    /// prova di quel percorso**, per quanto assomigli a cio' che si vuole
    /// verificare.
    ///
    /// Qui il pacchetto si ricrea spostando l'esportazione in una sottocartella,
    /// invece di scrivere un manifest a mano: un manifest scritto a mano
    /// verificherebbe il formato che la prova crede, non quello che il prodotto
    /// produce.
    #[test]
    fn a_manifest_inside_a_package_folder_is_found() {
        let directory = temporary_directory("verifica-sottocartella");
        let (service, session_id, entries) = ready("Sottocartella");

        let Ok(_) = service.export_session(
            session_id,
            &entries,
            &directory,
            &operator(),
            now(),
            ExportOptions::without_identifiers(),
            None,
        ) else {
            panic!("l'esportazione deve riuscire");
        };

        // I file si spostano tutti insieme: il manifest risolve i propri
        // documenti come fratelli, e separarli renderebbe il pacchetto
        // alterato invece che semplicemente altrove.
        let pacchetto = directory.join("R-2026-000042");
        std::fs::create_dir_all(&pacchetto).expect("la sottocartella deve nascere");
        let Ok(entries_su_disco) = std::fs::read_dir(&directory) else {
            panic!("la cartella deve potersi leggere");
        };
        for entry in entries_su_disco.flatten() {
            let path = entry.path();
            if path.is_file() {
                let Some(nome) = path.file_name() else {
                    continue;
                };
                std::fs::rename(&path, pacchetto.join(nome)).expect("lo spostamento deve riuscire");
            }
        }

        let Ok(verifications) = service.verify_directory(&directory, &operator(), now()) else {
            panic!("la scansione deve riuscire");
        };

        assert_eq!(
            verifications.len(),
            1,
            "il manifest sta in una sottocartella e la verifica non lo vede: \
             e' il difetto per cui la schermata Verifica rispondeva sempre \
             «nessun rapporto da verificare»"
        );
        assert!(
            verifications[0].status.is_intact(),
            "il pacchetto e' stato spostato intero: deve risultare integro"
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_directory_scan_verifies_each_report_and_records_the_balance() {
        let directory = temporary_directory("verifica-cartella");
        let (service, session_id, entries) = ready("Cartella");

        let Ok(_) = service.export_session(
            session_id,
            &entries,
            &directory,
            &operator(),
            now(),
            ExportOptions::without_identifiers(),
            None,
        ) else {
            panic!("l'esportazione deve riuscire");
        };

        let Ok(verifications) = service.verify_directory(&directory, &operator(), now()) else {
            panic!("la scansione deve riuscire");
        };
        assert_eq!(verifications.len(), 1);
        assert!(verifications[0].status.is_intact());

        let Ok(recorded) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert!(
            recorded
                .iter()
                .any(|entry| entry.action.as_str() == "export_verificato")
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_scan_of_a_missing_directory_is_empty_not_an_error() {
        let directory = temporary_directory("verifica-inesistente");
        let (service, ..) = ready("Vuota");

        let Ok(verifications) = service.verify_directory(&directory, &operator(), now()) else {
            panic!("una cartella assente non e' un errore");
        };
        assert!(verifications.is_empty());
    }

    #[test]
    fn even_an_empty_scan_leaves_a_trace_in_the_audit() {
        // Che una verifica sia stata tentata e non abbia trovato nulla e' a sua
        // volta un fatto: l'audit lo registra.
        let directory = temporary_directory("verifica-vuota-audit");
        let (service, ..) = ready("SenzaRapporti");

        let Ok(_) = service.verify_directory(&directory, &operator(), now()) else {
            panic!("la scansione a mani vuote deve riuscire");
        };

        let Ok(recorded) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert!(
            recorded
                .iter()
                .any(|entry| entry.action.as_str() == "export_verificato"),
            "anche una scansione senza rapporti va registrata"
        );
    }

    #[test]
    fn a_manifest_larger_than_the_cap_is_refused_as_unreadable() {
        // Un manifest e' di poche centinaia di byte; uno enorme, lasciato nella
        // cartella da un altro processo, non deve essere letto per intero. Oltre
        // il tetto e' rifiutato prima ancora di essere aperto in memoria.
        let directory = temporary_directory("verifica-gigante");
        let Ok(()) = std::fs::create_dir_all(&directory) else {
            panic!("la cartella deve potersi creare");
        };
        let manifest = directory.join("gonfio.manifest.txt");
        let oversized = "x".repeat((super::MANIFEST_READ_CAP as usize) + 1);
        let Ok(()) = std::fs::write(&manifest, oversized) else {
            panic!("il manifest gigante deve potersi scrivere");
        };

        let verification = super::verify_manifest_file(&manifest);
        assert_eq!(
            verification.status,
            super::VerificationStatus::ManifestUnreadable
        );

        let _ = std::fs::remove_dir_all(&directory);
    }
    #[test]
    fn without_a_choice_the_destination_is_the_default_folder() {
        // «Non scelta» e «predefinita» sono la stessa cosa, e il servizio non
        // deve costringere chi lo chiama a distinguerle.
        let service = ExportService::new(open_in_memory_database().expect("archivio in memoria"));
        let Ok(destination) = service.destination() else {
            panic!("la destinazione deve potersi risolvere");
        };
        let Ok(default) = super::export_directory() else {
            panic!("la cartella predefinita deve potersi determinare");
        };
        assert_eq!(destination, default);
    }

    #[test]
    fn a_chosen_folder_wins_over_the_default_one() {
        let service = ExportService::new(open_in_memory_database().expect("archivio in memoria"));
        let attore = Actor::try_new("operatore").expect("attore valido");
        let scelta = ExportDestination::try_new(r"C:\Documenti\Relazioni").expect("valido");

        let Ok(()) = service.save_destination(Some(&scelta), &attore, now()) else {
            panic!("il salvataggio deve riuscire");
        };
        assert_eq!(
            service.destination().ok(),
            Some(PathBuf::from(r"C:\Documenti\Relazioni"))
        );
    }

    #[test]
    fn going_back_to_the_default_folder_is_a_choice_like_the_others() {
        let service = ExportService::new(open_in_memory_database().expect("archivio in memoria"));
        let attore = Actor::try_new("operatore").expect("attore valido");
        let scelta = ExportDestination::try_new(r"C:\Documenti").expect("valido");
        let _ = service.save_destination(Some(&scelta), &attore, now());
        let _ = service.save_destination(None, &attore, now());

        let Ok(default) = super::export_directory() else {
            panic!("la cartella predefinita deve potersi determinare");
        };
        assert_eq!(service.destination().ok(), Some(default));
    }

    #[test]
    fn the_chosen_folder_reaches_the_audit_with_its_path() {
        // Il percorso nel registro non e' un dato dell'ufficio da proteggere:
        // e' il luogo dove i documenti sono stati consegnati, e chi rilegge per
        // sapere dove e' finito un rapporto deve trovarlo li'.
        let service = ExportService::new(open_in_memory_database().expect("archivio in memoria"));
        let attore = Actor::try_new("operatore").expect("attore valido");
        let scelta = ExportDestination::try_new(r"C:\Documenti\Relazioni").expect("valido");
        let _ = service.save_destination(Some(&scelta), &attore, now());

        let Ok(voci) = service.database().audit_entries() else {
            panic!("il registro deve potersi leggere");
        };
        assert!(
            voci.iter().any(|voce| {
                voce.action.as_str() == "export_cartella"
                    && voce
                        .detail
                        .as_ref()
                        .is_some_and(|d| d.as_str().contains(r"C:\Documenti\Relazioni"))
            }),
            "la scelta della cartella deve comparire nel registro con il percorso"
        );
    }

    /// **Il manifest di un pacchetto STIX nomina il proprio file, non un `.txt`.**
    ///
    /// La derivazione del nome era scritta quando lo Storico era l'unico a
    /// produrre un manifest. Ora ce ne sono due, e la regola deve distinguerli
    /// senza sapere chi siano.
    #[test]
    fn il_nome_del_documento_si_deriva_dal_nome_del_manifest() {
        assert_eq!(
            report_name_for(Path::new(
                "C:/x/nexum97-prova-2026-01-01T00-00-00Z.manifest.txt"
            )),
            "nexum97-prova-2026-01-01T00-00-00Z.txt"
        );
        assert_eq!(
            report_name_for(Path::new(
                "C:/x/nexum97-prova-2026-01-01T00-00-00Z.stix.json.manifest.txt"
            )),
            "nexum97-prova-2026-01-01T00-00-00Z.stix.json"
        );
    }
}

#[cfg(test)]
mod indented_body_tests {
    /// Ogni riga del testo acquisito è rientrata, anche dopo un `\r` isolato.
    #[test]
    fn a_bare_carriage_return_cannot_fake_a_report_line() {
        let testo = super::indented_body("ok\r[2] Fonte X\rLivello: 0\r\nfine");
        for riga in testo.lines() {
            assert!(riga.starts_with("  "), "riga senza rientro: {riga:?}");
            assert!(
                !riga.contains('\r'),
                "un ritorno a capo è rimasto: {riga:?}"
            );
        }
        assert_eq!(testo.lines().count(), 4);
    }
}
